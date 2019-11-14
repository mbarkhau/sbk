# This file is part of the sbk project
# https://gitlab.com/mbarkhau/sbk
#
# Copyright (c) 2019 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT
"""Logic related to KDF parameters."""

import os
import json
import math
import time
import struct
import typing as typ
import logging
import pathlib as pl

import argon2

from . import kdf
from . import primes
from . import cli_util

log = logging.getLogger(__name__)


# Some notes on parameter choices.
# https://tools.ietf.org/html/draft-irtf-cfrg-argon2-04#section-4
#
# parallelism: RFC reccomends 2x the number of cores.
#
# time_cost: As the time constraint is not such an issue for the
# intended use cases of SBK, you should be able to dedicate a few
# minutes of computation time to derive a secure key from relativly
# low amount of secret entropy (the brainkey).
#
# hash_type: Theoretically you should only use SBK on a trusted system
# in a trusted environment, so side channel attacks shouldn't be an
# issue and the benefits of using the argon2id are questionable.
# But the argument is similar to with time_cost, even if the extra time
# spent is pointless, it's not too much of a loss.
#
# memory_cost: The main constraint here is that later reconstruction
# of the secret will require a machine with at least as much memory as
# the one used during the initial derivation. Otherwise it should be
# chosen as large as possible.

Seconds = float

Flags = int

FLAG_IS_SEGWIT = 0b0001

RAW_SALT_LEN         = 12
PARAM_CFG_LEN        = 4
SALT_LEN             = PARAM_CFG_LEN + RAW_SALT_LEN
DEFAULT_BRAINKEY_LEN = 8
SHARE_X_COORD_LEN    = 1
DEFAULT_SHARE_LEN    = PARAM_CFG_LEN + SHARE_X_COORD_LEN + RAW_SALT_LEN + DEFAULT_BRAINKEY_LEN

PARAM_SCALING = 2
KDF_MEASUREMENT_SIGNIFIGANCE_THRESHOLD: Seconds = 0.1

DEFAULT_KDF_THREADS_RATIO = 2
DEFAULT_KDF_MEM_RATIO     = 0.9
DEFAULT_KDF_TIME_SEC      = 120

# Fallback value for systems on which total memory cannot be detected
FALLBACK_MEM_TOTAL_MB = int(os.getenv("SBK_FALLBACK_MEM_TOTAL_MB", "1024"))

DEFAULT_XDG_CONFIG_HOME = str(pl.Path("~").expanduser() / ".config")
XDG_CONFIG_HOME         = pl.Path(os.environ.get('XDG_CONFIG_HOME', DEFAULT_XDG_CONFIG_HOME))

SBK_APP_DIR_STR     = os.getenv('SBK_APP_DIR')
SBK_APP_DIR         = pl.Path(SBK_APP_DIR_STR) if SBK_APP_DIR_STR else XDG_CONFIG_HOME / "sbk"
SYSINFO_CACHE_FNAME = "sys_info_measurements.json"
SYSINFO_CACHE_FPATH = SBK_APP_DIR / SYSINFO_CACHE_FNAME


class Measurement(typ.NamedTuple):

    p: kdf.NumThreads
    m: kdf.MebiBytes
    t: kdf.Iterations
    h: kdf.HashAlgoVal

    duration: Seconds


def measure(kdf_params: kdf.KDFParams) -> Measurement:
    tzero = time.time()
    kdf.derive_key(b"dummy secret", b"saltsaltsaltsalt", kdf_params, hash_len=16)
    duration = round(time.time() - tzero, 5)

    log.debug(f"kdf parameter calibration {kdf_params} -> {round(duration * 1000)}ms")

    p, m, t, h = kdf_params
    return Measurement(p=p, m=m, t=t, h=h, duration=duration)


class SystemInfo(typ.NamedTuple):

    num_cores   : int
    total_mb    : kdf.MebiBytes
    initial_p   : kdf.NumThreads
    initial_m   : kdf.MebiBytes
    measurements: typ.List[Measurement]


def mem_total() -> kdf.MebiBytes:
    """Get total memory."""

    # Linux
    meminfo_path = pl.Path("/proc/meminfo")
    if meminfo_path.exists():
        try:
            with meminfo_path.open(mode="rb") as fobj:
                data = fobj.read()
            for line in data.splitlines():
                key, num, unit = line.decode("ascii").strip().split()
                if key == "MemTotal:":
                    return int(num) // 1024
        except Exception:
            log.error("Error while evaluating system memory", exc_info=True)

    return FALLBACK_MEM_TOTAL_MB


def _init_sys_info() -> SystemInfo:
    num_cores = len(os.sched_getaffinity(0))
    total_mb  = mem_total()

    initial_p = int(num_cores * DEFAULT_KDF_THREADS_RATIO)
    initial_m = int(total_mb  * DEFAULT_KDF_MEM_RATIO    ) // initial_p

    while True:
        try:
            kdf_params = kdf.init_kdf_params(p=initial_p, m=initial_m, t=1)
            initial_p  = kdf_params.p
            initial_m  = kdf_params.m
            log.debug(f"testing initial_p={initial_p}, initial_m={initial_m}")
            measure(kdf_params)
            log.debug(f"using initial_p={initial_p}, initial_m={initial_m}")
            break  # success
        except argon2.exceptions.HashingError as err:
            if "Memory allocation error" not in str(err):
                raise
            initial_m = (2 * initial_m) // 3

    return SystemInfo(
        num_cores, total_mb, initial_p=initial_p, initial_m=initial_m, measurements=[]
    )


_SYS_INFO: typ.Optional[SystemInfo] = None


def init_sys_info() -> SystemInfo:
    InitSysInfoThread    = cli_util.EvalWithProgressbar[SystemInfo]
    init_sys_info_thread = InitSysInfoThread(target=_init_sys_info, args=())
    init_sys_info_thread.start_and_wait(eta_sec=2, label="Memory test for KDF parameters")
    sys_info = init_sys_info_thread.retval
    _dump_sys_info(sys_info)
    return sys_info


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

    baseline     = sample
    measurements = _measure_scaled_params(baseline=baseline)
    sys_info     = sys_info._replace(measurements=measurements)
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


def _load_cached_sys_info() -> SystemInfo:
    cache_path = SYSINFO_CACHE_FPATH
    try:
        with cache_path.open(mode="rb") as fobj:
            sys_info_data = json.load(fobj)

        measurement_data = sys_info_data.pop('measurements')
        measurements     = [Measurement(**md) for md in measurement_data]
        sys_info         = SystemInfo(measurements=measurements, **sys_info_data)
    except Exception as ex:
        log.warning(f"Error reading cache file {cache_path}: {ex}")
        sys_info = init_sys_info()

    return sys_info


def load_sys_info(use_cache: bool = True) -> SystemInfo:
    global _SYS_INFO
    if _SYS_INFO:
        return _SYS_INFO

    if use_cache and SYSINFO_CACHE_FPATH.exists():
        sys_info = _load_cached_sys_info()
    else:
        sys_info = init_sys_info()

    _SYS_INFO = sys_info
    return sys_info


def _dump_sys_info(sys_info: SystemInfo) -> None:
    global _SYS_INFO
    _SYS_INFO = sys_info

    cache_path = SYSINFO_CACHE_FPATH
    try:
        cache_path.parent.mkdir(exist_ok=True, parents=True)
    except Exception as ex:
        log.warning(f"Unable to create cache dir {cache_path.parent}: {ex}")
        return

    measurements_data = [m._asdict() for m in sys_info.measurements]
    sys_info_data     = {
        'num_cores'   : sys_info.num_cores,
        'total_mb'    : sys_info.total_mb,
        'initial_p'   : sys_info.initial_p,
        'initial_m'   : sys_info.initial_m,
        'measurements': measurements_data,
    }

    try:
        with cache_path.open(mode="w", encoding="utf-8") as fobj:
            json.dump(sys_info_data, fobj, indent=4)
    except Exception as ex:
        log.warning(f"Error writing cache file {cache_path}: {ex}")
        return


class InitialParamConfig(typ.NamedTuple):

    version     : int
    flags       : Flags
    brainkey_len: int
    threshold   : int
    kdf_params  : kdf.KDFParams


def parse_initial_param_cfg(data: bytes) -> InitialParamConfig:
    fields_01, fields_23, fields_456 = struct.unpack("!BBH", data)

    version        = (fields_01 >> 4) & 0xF
    flags          = (fields_01 >> 0) & 0xF
    f_brainkey_len = (fields_23 >> 4) & 0xF
    f_threshold    = (fields_23 >> 0) & 0xF
    assert version == 0, version

    brainkey_len = (f_brainkey_len + 1) * 2
    threshold    = f_threshold + 1

    kdf_params = kdf.KDFParams.decode(fields_456)
    return InitialParamConfig(version, flags, brainkey_len, threshold, kdf_params)


class ParamConfig(typ.NamedTuple):

    version     : int
    flags       : Flags
    brainkey_len: int
    threshold   : int
    num_shares  : int
    kdf_params  : kdf.KDFParams
    sys_info    : SystemInfo

    @property
    def raw_salt_len(self) -> int:
        return RAW_SALT_LEN

    @property
    def master_key_len(self) -> int:
        # The master key is streched a bit and the remaining
        # byte is used to encode the x coordinate of the shares.
        return self.raw_salt_len + self.brainkey_len

    @property
    def share_len(self) -> int:
        return PARAM_CFG_LEN + SHARE_X_COORD_LEN + self.master_key_len

    @property
    def prime(self) -> int:
        master_key_bits = self.master_key_len * 8
        return primes.get_pow2prime(master_key_bits)

    @property
    def is_segwit(self) -> bool:
        return self.flags & FLAG_IS_SEGWIT == 1


def init_param_config(
    brainkey_len   : int,
    threshold      : int,
    num_shares     : typ.Optional[int] = None,
    is_segwit      : bool = True,
    kdf_parallelism: typ.Optional[int] = None,
    kdf_memory_cost: typ.Optional[int] = None,
    kdf_time_cost  : typ.Optional[int] = None,
) -> ParamConfig:
    _num_shares = threshold if num_shares is None else num_shares

    if threshold > _num_shares:
        err_msg = f"threshold must be <= num_shares, got {threshold} > {_num_shares}"
        raise ValueError(err_msg)

    kdf_params = get_default_params()
    kdf_params = kdf_params._replace_any(p=kdf_parallelism, m=kdf_memory_cost, t=kdf_time_cost)

    raw_salt_len = RAW_SALT_LEN
    assert raw_salt_len % 4 == 0
    assert 4 <= raw_salt_len <= 64, raw_salt_len

    assert brainkey_len % 2 == 0
    assert 2 <= brainkey_len <= 32, brainkey_len
    assert 1 <= threshold    <= 16, threshold

    version = 0
    flags   = 0b0000
    if is_segwit:
        flags |= FLAG_IS_SEGWIT
    else:
        assert flags & FLAG_IS_SEGWIT == 0

    assert 0b0000 <= flags <= 0b1111

    param_cfg = ParamConfig(
        version=version,
        flags=flags,
        brainkey_len=brainkey_len,
        threshold=threshold,
        num_shares=_num_shares,
        kdf_params=kdf_params,
        sys_info=load_sys_info(),
    )

    return param_cfg


def bytes2param_cfg(data: bytes, sys_info: typ.Optional[SystemInfo] = None) -> ParamConfig:
    """Deserialize ParamConfig.

    |        Field        |  Size  |                          Info                           |
    | ------------------- | ------ | ------------------------------------------------------- |
    | `f_version`         | 4 bit  | ...                                                     |
    | `f_brainkey_len`    | 4 bit  | max length: 2 * 2**4 = 32 bytes                         |
    | `f_threshold`       | 4 bit  | minimum shares required for recovery                    |
    |                     |        | max: 1..2**4 = 1..16                                    |
    | `f_flags`           | 4 bit  | (reserved, reserved, reserved, is_segwit)               |
    | `f_kdf_parallelism` | 4 bit  | `ceil(2 ** n)   = kdf_parallelism` in number of threads |
    | `f_kdf_mem_cost`    | 6 bit  | `ceil(1.5 ** n) = kdf_mem_cost` in MiB                  |
    | `f_kdf_time_cost`   | 6 bit  | `ceil(1.5 ** n) = kdf_time_cost` in iterations          |

       0 1 2 3 4 5 6 7 8 9 A B C D E F
     0 [ ver ] [salt ] [bkey ] [thres]
    16 [kdf_p] [ kdf_mem ] [kdf_time ]
    """
    assert len(data) == 4

    if sys_info is None:
        _sys_info = load_sys_info()
    else:
        _sys_info = sys_info

    p = parse_initial_param_cfg(data)

    # The param_cfg encoding doesn't include num_shares as it's
    # only required when originally generating the shares. The
    # minimum value is threshold, so that is what we set it to.
    num_shares = p.threshold

    return ParamConfig(
        version=p.version,
        flags=p.flags,
        brainkey_len=p.brainkey_len,
        threshold=p.threshold,
        num_shares=num_shares,
        kdf_params=p.kdf_params,
        sys_info=_sys_info,
    )


def param_cfg2bytes(param_cfg: ParamConfig) -> bytes:
    """Serialize ParamConfig.

    Since these fields are part of the salt, we try
    to keep the serialized param_cfg small and leave
    more room for randomness, hence the bit twiddling.
    """
    assert param_cfg.raw_salt_len % 4 == 0
    assert param_cfg.brainkey_len % 2 == 0

    f_brainkey_len = (param_cfg.brainkey_len // 2) - 1
    f_threshold    = param_cfg.threshold - 1

    fields_01 = 0
    fields_01 |= param_cfg.version << 4
    fields_01 |= param_cfg.flags

    fields_23 = 0
    fields_23 |= f_brainkey_len << 4
    fields_23 |= f_threshold

    fields_456     = param_cfg.kdf_params.encode()
    param_cfg_data = struct.pack("!BBH", fields_01, fields_23, fields_456)
    return param_cfg_data


def fresh_sys_info() -> SystemInfo:
    global _SYS_INFO
    _SYS_INFO = None

    if SYSINFO_CACHE_FPATH.exists():
        SYSINFO_CACHE_FPATH.unlink()

    return load_sys_info()


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
