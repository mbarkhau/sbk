# This file is part of the sbk project
# https://gitlab.com/mbarkhau/sbk
#
# Copyright (c) 2019 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT
"""Logic related to KDF parameters."""

import os
import enum
import json
import math
import time
import struct
import typing as typ
import logging

import argon2
import pathlib2 as pl

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


DEFAULT_KDF_THREADS_RATIO = 2
DEFAULT_KDF_MEM_RATIO     = 0.9
DEFAULT_KDF_TIME_SEC      = 120


class HashAlgo(enum.Enum):

    ARGON2_V19_D  = 0
    ARGON2_V19_I  = 1
    ARGON2_V19_ID = 2


HashAlgoVal = int

HASH_ALGO_NAMES = {
    HashAlgo.ARGON2_V19_I : 'argon2_v19_i',
    HashAlgo.ARGON2_V19_D : 'argon2_v19_d',
    HashAlgo.ARGON2_V19_ID: 'argon2_v19_id',
}

Seconds    = float
NumThreads = int
MebiBytes  = int
Iterations = int


class KDFParams(typ.NamedTuple):

    p_raw: NumThreads
    m_raw: MebiBytes
    t_raw: Iterations
    h    : HashAlgoVal

    @property
    def _field_values(self) -> typ.Tuple[int, int, int]:
        return (
            max(0, min(2 ** 4 - 1, round(math.log(self.p_raw) / math.log(2)))),
            max(0, min(2 ** 6 - 1, round(math.log(self.m_raw) / math.log(1.5)))),
            max(0, min(2 ** 6 - 1, round(math.log(self.t_raw) / math.log(1.5)))),
        )

    @property
    def _verified_values(self) -> typ.Tuple[NumThreads, MebiBytes, Iterations]:
        # Fail safe accessor to make sure we always initialized
        #   KDFParams with values that can be serialized correctly.
        f_p, f_m, f_t = self._field_values
        p = math.ceil(2 ** f_p)
        m = math.ceil(1.5 ** f_m)
        t = math.ceil(1.5 ** f_t)

        assert p == self.p_raw, (p, "vs", self.p_raw)
        assert m == self.m_raw, (m, "vs", self.m_raw)
        assert t == self.t_raw, (t, "vs", self.t_raw)
        return (p, m, t)

    def _replace_any(
        self, p: typ.Optional[int] = None, m: typ.Optional[int] = None, t: typ.Optional[int] = None
    ) -> 'KDFParams':
        updated = self

        if p:
            updated = updated._replace(p_raw=p)
        if m:
            updated = updated._replace(m_raw=m)
        if t:
            updated = updated._replace(t_raw=t)

        return init_kdf_params(p=updated.p_raw, m=updated.m_raw, t=updated.t_raw)

    def __repr__(self) -> str:
        return f"KDFParams(p={self.p_raw} m={self.m_raw:>3} t={self.t_raw})"

    @property
    def p(self) -> NumThreads:
        return self._verified_values[0]

    @property
    def m(self) -> NumThreads:
        return self._verified_values[1]

    @property
    def t(self) -> NumThreads:
        return self._verified_values[2]


def init_kdf_params(
    p: NumThreads, m: MebiBytes, t: Iterations, no_verify: bool = False
) -> KDFParams:
    # NOTE mb: It's important to ALWAYS and ONLY use kdf parameters that have gone through
    #   this function so we always do the kdf parameter normalization.
    # Only certain parameter values can be serialized.
    # Everything goes through this constructor to make sure
    # we only use valid values.
    h = HashAlgo.ARGON2_V19_ID.value

    _tmp_kdf_params = KDFParams(p, m, t, h)
    if no_verify:
        # The exception to the verification is when we use kdf parameters
        # for measurements, in which case we don't want the rounding to
        # mess with accuracy.
        return _tmp_kdf_params

    f_p, f_m, f_t = _tmp_kdf_params._field_values
    p = math.ceil(2 ** f_p)
    m = math.ceil(1.5 ** f_m)
    t = math.ceil(1.5 ** f_t)
    return KDFParams(p, m, t, h)


class Measurement(typ.NamedTuple):

    p: NumThreads
    m: MebiBytes
    t: Iterations
    h: HashAlgoVal

    duration: Seconds


class SystemInfo(typ.NamedTuple):

    num_cores   : int
    total_mb    : MebiBytes
    initial_p   : NumThreads
    initial_m   : MebiBytes
    measurements: typ.List[Measurement]


def mem_total() -> MebiBytes:
    """Get total memory."""

    # Linux
    meminfo_path = pl.Path("/proc/meminfo")
    if meminfo_path.exists():
        with meminfo_path.open(mode="rb") as fobj:
            for line in fobj:
                key, num, unit = line.decode("ascii").split()
                if key == "MemTotal:":
                    return int(num) // 1024

    return 128


def parse_argon2_type(h: HashAlgoVal) -> int:
    if h == HashAlgo.ARGON2_V19_D.value:
        return argon2.low_level.Type.D
    if h == HashAlgo.ARGON2_V19_I.value:
        return argon2.low_level.Type.I
    if h == HashAlgo.ARGON2_V19_ID.value:
        return argon2.low_level.Type.ID

    err_msg = f"Unknown hash_algo={h}"
    raise ValueError(err_msg)


def parse_argon2_version(h: HashAlgoVal) -> int:
    return 19


# The first of the parameters with the most memory that has an
# estimated duration above this threshold, is the one that is
# chosen as the default.


DEFAULT_XDG_CONFIG_HOME = str(pl.Path("~").expanduser() / ".config")
XDG_CONFIG_HOME         = pl.Path(os.environ.get('XDG_CONFIG_HOME', DEFAULT_XDG_CONFIG_HOME))

SBK_APP_DIR         = XDG_CONFIG_HOME / "sbk"
SYSINFO_CACHE_FNAME = "sys_info_measurements.json"


def measure(kdf_params: KDFParams) -> Measurement:
    p, m, t, h = kdf_params

    tzero = time.time()
    argon2.low_level.hash_secret_raw(
        secret=b"dummy secret",
        salt=b"saltsaltsaltsalt",
        memory_cost=m * 1024,
        time_cost=t,
        parallelism=p,
        hash_len=16,
        type=argon2.low_level.Type.ID,
    )
    duration = round(time.time() - tzero, 5)

    log.debug(f"kdf parameter calibration {kdf_params} -> {round(duration * 1000)}ms")
    return Measurement(p=p, m=m, t=t, h=h, duration=duration)


MaybeMeasurements = typ.Optional[typ.List[Measurement]]


def _measure_scaled_params(baseline: Measurement) -> typ.List[Measurement]:
    measurements = [baseline]
    while len(measurements) < 8:
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
            # repeat measurement with previous parameters
            measurement = measurements[len(measurements) % 4]

            m = measurement.m
            t = measurement.t

        kdf_params  = init_kdf_params(baseline.p, m, t, no_verify=True)
        measurement = measure(kdf_params)
        measurements.append(measurement)

    return measurements


def _init_sys_info() -> SystemInfo:
    num_cores = len(os.sched_getaffinity(0))
    total_mb  = mem_total()

    initial_p = int(num_cores * DEFAULT_KDF_THREADS_RATIO)
    initial_m = int(total_mb * DEFAULT_KDF_MEM_RATIO) // initial_p

    while True:
        try:
            kdf_params = init_kdf_params(p=initial_p, m=int(initial_m), t=1, no_verify=True)
            measure(kdf_params)
            break  # success
        except argon2.exceptions.HashingError as err:
            if "Memory allocation error" not in str(err):
                raise
            initial_m = int(initial_m / 1.5)

    # NOTE: choice of the baseline memory probably has the
    #   largest influence on the accuracy of cost estimation
    #   for parameters. Presumably you'd want to do something
    #   more clever than a cutoff. We might for example look
    #   to see if curve of the durations is past some inflection
    #   point that is presumably related to a bottleneck.

    m = 1

    while True:
        kdf_params = init_kdf_params(p=initial_p, m=m, t=1, no_verify=True)
        sample     = measure(kdf_params)
        if sample.duration > 0.2:
            break
        else:
            m = math.ceil(m * 1.5)

    kdf_params   = init_kdf_params(p=initial_p, m=m, t=2, no_verify=True)
    baseline     = measure(kdf_params)
    measurements = _measure_scaled_params(baseline)
    return SystemInfo(num_cores, total_mb, initial_p, initial_m, measurements)


_SYS_INFO: typ.Optional[SystemInfo] = None


def init_sys_info() -> SystemInfo:
    InitSysInfoThread    = cli_util.EvalWithProgressbar[SystemInfo]
    init_sys_info_thread = InitSysInfoThread(target=_init_sys_info, args=())
    init_sys_info_thread.start_and_wait(eta_sec=20, label="Calibrating KDF parameters.")
    return init_sys_info_thread.retval


PARAM_SCALING = 5


def estimate_param_cost(sys_info: SystemInfo, tgt_kdf_params: KDFParams) -> Seconds:
    """Estimate the runtime for parameters in seconds.

    This extrapolates based on a few short measurements and
    is not very precise (but good enough for a progress bar).
    """
    tgt_p, tgt_m, tgt_t, _ = tgt_kdf_params

    measurements = sys_info.measurements
    assert len(measurements) >= 8
    assert all(p == tgt_p for p, m, t, h, d in measurements)

    min_measurements: typ.Dict[KDFParams, float] = {}
    for measurement in measurements:
        key = KDFParams(measurement.p, measurement.m, measurement.t, measurement.h)
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

    m0 , _, _, m1 = [m for p, m, t, h, d in measurements]
    t0 , _, _, t1 = [t for p, m, t, h, d in measurements]
    d00, d01, d10, d11 = [d for p, m, t, h, d in measurements]

    s = [
        d00 * (m1 - tgt_m) * (t1 - tgt_t),
        d10 * (tgt_m - m0) * (t1 - tgt_t),
        d01 * (m1 - tgt_m) * (tgt_t - t0),
        d11 * (tgt_m - m0) * (tgt_t - t0),
    ]

    return sum(s) / ((m1 - m0) * (t1 - t0))


def get_default_params(sys_info: SystemInfo) -> KDFParams:
    p = sys_info.initial_p
    m = sys_info.initial_m

    t = 1
    while True:
        test_kdf_params = init_kdf_params(p=p, m=m, t=t)
        est_cost        = estimate_param_cost(sys_info, test_kdf_params)
        if est_cost > DEFAULT_KDF_TIME_SEC:
            return test_kdf_params
        else:
            t = math.ceil(t * 1.5)


def _load_cached_sys_info(cache_path: pl.Path) -> SystemInfo:
    try:
        with cache_path.open(mode="rb") as fobj:
            sys_info_data = json.load(fobj)

        measurement_data = sys_info_data.pop('measurements')
        measurements     = [Measurement(**md) for md in measurement_data]
        sys_info         = SystemInfo(measurements=measurements, **sys_info_data)
    except Exception as ex:
        log.warning(f"Error reading cache file {cache_path}: {ex}")
        sys_info = init_sys_info()

    _dump_sys_info(sys_info, cache_path)

    return sys_info


def load_sys_info(app_dir: pl.Path = SBK_APP_DIR, use_cache: bool = True) -> SystemInfo:
    global _SYS_INFO
    if _SYS_INFO:
        return _SYS_INFO

    cache_path = app_dir / SYSINFO_CACHE_FNAME

    if use_cache and cache_path.exists():
        sys_info = _load_cached_sys_info(cache_path)
    else:
        sys_info = init_sys_info()

    if not cache_path.exists():
        _dump_sys_info(sys_info, cache_path)

    _SYS_INFO = sys_info
    return sys_info


def _dump_sys_info(sys_info: SystemInfo, cache_path: pl.Path) -> None:
    try:
        cache_path.parent.mkdir(exist_ok=True)
    except Exception:
        log.warning(f"Unable to create cache dir {cache_path.parent}")
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


class ParamConfig(typ.NamedTuple):

    version     : int
    salt_len    : int
    brainkey_len: int
    threshold   : int
    num_shares  : int
    kdf_params  : KDFParams
    sys_info    : SystemInfo

    @property
    def master_key_len(self) -> int:
        # The master key is streched a bit and the remaining
        # byte is used to encode the x coordinate of the shares.
        return self.brainkey_len + self.salt_len

    @property
    def share_len(self) -> int:
        # +1 byte for the x-coordinate
        unpadded_len = self.brainkey_len + self.salt_len
        padded_len   = math.ceil((unpadded_len + 1) / 4) * 4
        return padded_len

    @property
    def prime(self) -> int:
        master_key_bits = self.master_key_len * 8
        return primes.get_pow2prime(master_key_bits)


def init_param_config(
    salt_len       : int,
    brainkey_len   : int,
    threshold      : int,
    num_shares     : typ.Optional[int] = None,
    kdf_parallelism: typ.Optional[int] = None,
    kdf_memory_cost: typ.Optional[int] = None,
    kdf_time_cost  : typ.Optional[int] = None,
) -> ParamConfig:
    _num_shares = threshold if num_shares is None else num_shares

    if threshold > _num_shares:
        err_msg = f"threshold must be <= num_shares, got {threshold} > {_num_shares}"
        raise ValueError(err_msg)

    sys_info = load_sys_info()

    kdf_params = get_default_params(sys_info)
    kdf_params = kdf_params._replace_any(p=kdf_parallelism, m=kdf_memory_cost, t=kdf_time_cost)
    assert salt_len     % 4 == 0
    assert brainkey_len % 2 == 0
    assert 4 <= salt_len <= 64, salt_len
    assert 2 <= brainkey_len <= 32, brainkey_len
    assert 1 <= threshold <= 16, threshold

    master_key_len = salt_len + brainkey_len
    assert master_key_len % 4 == 0, master_key_len

    return ParamConfig(
        version=0,
        salt_len=salt_len,
        brainkey_len=brainkey_len,
        threshold=threshold,
        num_shares=_num_shares,
        kdf_params=kdf_params,
        sys_info=sys_info,
    )


def bytes2param_cfg(data: bytes, sys_info: typ.Optional[SystemInfo] = None) -> ParamConfig:
    """Deserialize ParamConfig.

    |        Field        |  Size  |                          Info                           |
    | ------------------- | ------ | ------------------------------------------------------- |
    | `f_version`         | 4 bit  | ...                                                     |
    | `f_salt_len`        | 4 bit  | max length: 4 * 2**4 = 64 bytes                         |
    | `f_brainkey_len`    | 4 bit  | max length: 2 * 2**4 = 32 bytes                         |
    | `f_threshold`       | 4 bit  | minimum shares required for recovery                    |
    |                     |        | max: 1..2**4 = 1..16                                    |
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

    fields_0123, fields_456 = struct.unpack("!HH", data)

    version      = (fields_0123 >> 12) & 0xF
    salt_len     = (((fields_0123 >> 8) & 0xF) + 1) * 4
    brainkey_len = (((fields_0123 >> 4) & 0xF) + 1) * 2
    threshold    = ((fields_0123 >> 0) & 0xF) + 1

    # The param_cfg encoding doesn't include num_shares as it's
    # only required when originally generating the shares. The
    # minimum value is threshold, so that is what we set it to.
    num_shares = threshold

    assert version == 0, version

    f_p = (fields_456 >> 12) & 0xF
    f_m = (fields_456 >> 6) & 0x3F
    f_t = (fields_456 >> 0) & 0x3F

    p = math.ceil(2 ** f_p)
    m = math.ceil(1.5 ** f_m)
    t = math.ceil(1.5 ** f_t)

    kdf_params = init_kdf_params(p=p, m=m, t=t)

    return ParamConfig(
        version=version,
        salt_len=salt_len,
        brainkey_len=brainkey_len,
        threshold=threshold,
        num_shares=num_shares,
        kdf_params=kdf_params,
        sys_info=_sys_info,
    )


def param_cfg2bytes(param_cfg: ParamConfig) -> bytes:
    """Serialize ParamConfig.

    Since these fields are part of the salt,
    we try to keep the serialized param_cfg small
    and leave more room for randomness.
    """
    assert param_cfg.salt_len     % 4 == 0
    assert param_cfg.brainkey_len % 2 == 0

    fields_0123 = 0
    fields_0123 += param_cfg.version << 12
    fields_0123 += ((param_cfg.salt_len // 4) - 1) << 8
    fields_0123 += ((param_cfg.brainkey_len // 2) - 1) << 4
    fields_0123 += param_cfg.threshold - 1

    f_p, f_m, f_t = param_cfg.kdf_params._field_values

    fields_456 = 0
    fields_456 += f_p << 12
    fields_456 += f_m << 6
    fields_456 += f_t << 0

    param_cfg_data = struct.pack("!HH", fields_0123, fields_456)
    return param_cfg_data


def main() -> None:
    cach_path = SBK_APP_DIR / SYSINFO_CACHE_FNAME
    if cach_path.exists():
        cach_path.unlink()
    logging.basicConfig(level=logging.INFO)

    param_cfg = init_param_config(brainkey_len=8, salt_len=16, threshold=3, num_shares=3)

    param_cfg_data = param_cfg2bytes(param_cfg)
    assert bytes2param_cfg(param_cfg_data) == param_cfg

    eta = estimate_param_cost(param_cfg.sys_info, param_cfg.kdf_params)
    log.info(f"estimated cost {eta}")

    MeasurementThread  = cli_util.EvalWithProgressbar[Measurement]
    measurement_thread = MeasurementThread(target=measure, args=(param_cfg.kdf_params,))
    measurement_thread.start_and_wait(eta_sec=eta, label="Evaluating KDF")
    measurement = measurement_thread.retval
    log.info(f"measured  cost {round(measurement.duration)}")


if __name__ == '__main__':
    main()
