# This is some old code used to try and extrapolate parameter cost
# from some sample measurements. In the end I decided to throw it
# all out and just do the following:
#
#   1. measure the maximum memory that can be used
#   2. scale t to get the desired duration
#
# This change is motivated by
#
#   1. the desire to have a more meaningful progress bar
#   2. the overhead for initial measurements was high
#   3. the CI system was slowed down by measurements
#   4. the estimations weren't even that accurate
#   5. code simplification

import time

from sbk import kdf
from sbk.params import *
from sbk.sys_info import *

KDF_MEASUREMENT_SIGNIFIGANCE_THRESHOLD: Seconds = 0.1


def _measure_scaled_params(baseline: Measurement) -> typ.List[Measurement]:
    measurements = [baseline]
    while len(measurements) < 4:
        baseline = measurements[0]

        if len(measurements) == 1:
            m = baseline.m * PARAM_SCALING
            t = baseline.t
        elif len(measurements) == 2:
            m = baseline.m
            t = baseline.t * PARAM_SCALING
        elif len(measurements) == 3:
            m = baseline.m * PARAM_SCALING
            t = baseline.t * PARAM_SCALING
        else:
            # To increase accuracy, repeat measurement with previous
            # parameters and use the lower measurement.
            measurement = measurements[len(measurements) % 4]

            m = measurement.m
            t = measurement.t

        kdf_params  = kdf.init_kdf_params(baseline.p, m, t)
        measurement = measure(kdf_params)
        measurements.append(measurement)

    return measurements


def _update_measurements(sys_info: SystemInfo) -> SystemInfo:
    # NOTE: choice of the baseline memory probably has the
    #   largest influence on the accuracy of cost estimation
    #   for parameters. Presumably you'd want to do something
    #   more clever than a cutoff. We might for example look
    #   to see if curve of the durations is past some inflection
    #   point that is presumably related to a bottleneck.

    p = sys_info.initial_p
    m = 1

    while True:
        kdf_params = kdf.init_kdf_params(p=p, m=m, t=2)
        p          = kdf_params.p
        m          = kdf_params.m
        sample     = measure(kdf_params)
        if sample.duration > KDF_MEASUREMENT_SIGNIFIGANCE_THRESHOLD:
            break
        else:
            m = math.ceil(m * 1.5)

    _dump_sys_info(sys_info)
    return sys_info


def update_measurements(sys_info: SystemInfo) -> SystemInfo:
    UpdateMeasurementsThread   = cli_util.EvalWithProgressbar[SystemInfo]
    update_measurements_thread = UpdateMeasurementsThread(
        target=_update_measurements, args=(sys_info,)
    )
    update_measurements_thread.start_and_wait(eta_sec=5, label="Calibration for KDF parameters")
    return update_measurements_thread.retval


def estimate_param_cost(
    tgt_kdf_params: kdf.KDFParams, sys_info: typ.Optional[SystemInfo] = None
) -> Seconds:
    """Estimate the runtime for parameters in seconds.

    This extrapolates based on a few short measurements and
    is not very precise (but good enough for a progress bar).
    """
    tgt_p, tgt_m, tgt_t, _ = tgt_kdf_params

    if tgt_m < 10 and tgt_t < 10:
        return 1.0

    if sys_info is None:
        _sys_info = load_sys_info()
        if len(_sys_info.measurements) < 4:
            _sys_info = update_measurements(_sys_info)
    else:
        _sys_info = sys_info

    assert len(_sys_info.measurements) >= 4

    measurements = _sys_info.measurements

    min_measurements: typ.Dict[kdf.KDFParams, float] = {}
    for measurement in measurements:
        key = kdf.init_kdf_params(measurement.p, measurement.m, measurement.t)
        if key in min_measurements:
            val = min_measurements[key]
            min_measurements[key] = min(measurement.duration, val)
        else:
            min_measurements[key] = measurement.duration

    measurements = [Measurement(p, m, t, h, d) for (p, m, t, h), d in min_measurements.items()]
    assert len(measurements) == 4

    # Bilinear Interpolation
    # https://stackoverflow.com/a/8662355/62997
    # https://en.wikipedia.org/wiki/Bilinear_interpolation#Algorithm

    m0 , _  , _  , m1  = [m for p, m, t, h, d in measurements]
    t0 , _  , _  , t1  = [t for p, m, t, h, d in measurements]
    d00, d01, d10, d11 = [d for p, m, t, h, d in measurements]

    s = [
        d00 * (m1    - tgt_m) * (t1    - tgt_t),
        d10 * (tgt_m - m0   ) * (t1    - tgt_t),
        d01 * (m1    - tgt_m) * (tgt_t - t0),
        d11 * (tgt_m - m0   ) * (tgt_t - t0),
    ]

    return max(0.0, sum(s) / ((m1 - m0) * (t1 - t0) + 0.0))


def get_default_params() -> kdf.KDFParams:
    sys_info = load_sys_info()
    p        = sys_info.initial_p
    m        = sys_info.initial_m

    t = 1
    while True:
        test_kdf_params = kdf.init_kdf_params(p=p, m=m, t=t)

        est_cost = estimate_param_cost(test_kdf_params)
        if est_cost > DEFAULT_KDF_TIME_SEC:
            return test_kdf_params
        else:
            t = math.ceil(t * 1.5)


def measure_in_thread(kdf_params: kdf.KDFParams, sys_info: SystemInfo) -> Measurement:
    eta                = estimate_param_cost(kdf_params, sys_info)
    MeasurementThread  = cli_util.EvalWithProgressbar[Measurement]
    measurement_thread = MeasurementThread(target=measure, args=(kdf_params,))
    measurement_thread.start_and_wait(eta_sec=eta, label="Evaluating KDF")
    return measurement_thread.retval


def main() -> None:
    logging.basicConfig(level=logging.DEBUG)
    os.environ['SBK_PROGRESS_BAR'] = "0"

    sys_info = fresh_sys_info()
    sys_info = update_measurements(sys_info)

    kdf_params = get_default_params()
    eta        = estimate_param_cost(kdf_params, sys_info)

    os.environ['SBK_PROGRESS_BAR'] = "1"
    log.info(f"estimated cost {eta}")
    measurement = measure_in_thread(kdf_params, sys_info)
    log.info(f"measured  cost {round(measurement.duration)}")


if __name__ == '__main__':
    main()
