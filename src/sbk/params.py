# This file is part of the sbk project
# https://gitlab.com/mbarkhau/sbk
#
# Copyright (c) 2019 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT
"""Logic related to KDF parameters."""
import os
import time
import enum
import json
import logging
import typing as typ
import pathlib2 as pl

import argon2

from . import primes


log = logging.getLogger(__name__)


class HashAlgo(enum.Enum):

    ARGON2_V19_I  = 1
    ARGON2_V19_D  = 2
    ARGON2_V19_ID = 3


HASH_ALGO_NAMES = {
    HashAlgo.ARGON2_V19_I : 'argon2_v19_i',
    HashAlgo.ARGON2_V19_D : 'argon2_v19_d',
    HashAlgo.ARGON2_V19_ID: 'argon2_v19_id',
}


KibiBytes  = int
Iterations = int

KDFParamId  = int
KDFParamIds = typ.Sequence[KDFParamId]


class Params(typ.NamedTuple):

    threshold     : int
    num_pieces    : int
    pow2prime_idx : int
    kdf_param_id  : KDFParamId
    hash_len_bytes: int
    hash_algo     : HashAlgo
    memory_cost   : KibiBytes
    time_cost     : Iterations
    parallelism   : int


def init_params(
    threshold     : int,
    num_pieces    : int,
    kdf_param_id  : KDFParamId,
    hash_len_bytes: int,
) -> Params:
    if threshold > num_pieces:
        err_msg = (
            f"threshold must be <= num_pieces, got {threshold} > {num_pieces}"
        )
        raise ValueError(err_msg)

    # NOTE: we need one byte for the x value
    prime_bits    = hash_len_bytes * 8 - 8
    pow2prime_idx = primes.get_pow2prime_index(prime_bits)
    assert 0 < hash_len_bytes <= 64
    assert hash_len_bytes % 4 == 0, hash_len_bytes
    assert 0 <= pow2prime_idx < len(primes.POW2_PRIMES), pow2prime_idx
    assert kdf_param_id in PARAM_CONFIGS_BY_ID, kdf_param_id

    param_cfg = PARAM_CONFIGS_BY_ID[kdf_param_id]
    return Params(
        threshold=threshold,
        num_pieces=num_pieces,
        pow2prime_idx=pow2prime_idx,
        kdf_param_id=kdf_param_id,
        hash_len_bytes=hash_len_bytes,
        **param_cfg,
    )


INSECURE: KDFParamId = 1
INSECURE_PARAM_CONFIG = {
    'hash_algo'  : HashAlgo.ARGON2_V19_ID.value,
    'memory_cost': 1024,
    'time_cost'  : 1,
    'parallelism': 32,
}

# Some notes on parameter choices.
# https://tools.ietf.org/html/draft-irtf-cfrg-argon2-04#section-4
#
# time_cost: As the time constraint is not such an issue for the
# intended use cases of SBK, you should be able to dedicate a few
# minutes of computation time to derive a secure key from relativly
# low amount of secret entropy (the brainkey).
#
# hash_type: Theroetically you should only use SBK on a trusted system
# in a trusted environment, so side channel attacks shouldn't be an
# issue and the benefits of using the argon2id are questionable.
# But the argument is similar to with time_cost, even if the extra time
# spent is pointless, it's not too much of a loss.
#
# memory_cost: The main constraint here is that later reconstruction
# of the secret will require a machine with at least as much memory as
# the one used during the initial derivation.
#
# parallelism: I'm not totally clear on an appropriate choice for this.

ParamConfig = typ.Dict[str, typ.Any]

ParamsByConfigId = typ.Dict[KDFParamId, ParamConfig]

# In order to preserve compatability of generated keys, historical
# entries of PARAM_CONFIGS_BY_ID are hashed. This provides a safety
# net against inadvertant changes to the _init_configs function.
PARAM_CONFIG_HASHES = {
    0x7F007F007F007F007F00FF01FF0002: '67d43eafd309c50f112f368060ef5ba8be52c5fb'
}


def _init_configs() -> ParamsByConfigId:
    MB = 1024

    CONFIG_PARAMS: typ.List[typ.Dict[str, typ.Any]] = [
        {'ts': [1, 3, 10, 33, 100], 'p': 32, 'm':   400 * MB},
        {'ts': [1, 3, 10, 33, 100], 'p': 32, 'm':   800 * MB},
        {'ts': [1, 3, 10, 33, 100], 'p': 32, 'm':  1500 * MB},
        {'ts': [1, 3, 10, 33, 100], 'p': 32, 'm':  2500 * MB},
        {'ts': [1, 3, 10, 33, 100], 'p': 32, 'm':  6000 * MB},
        {'ts': [1, 3, 10, 33, 100], 'p': 32, 'm': 10000 * MB},
        {'ts': [1, 3, 10, 33, 100], 'p': 32, 'm': 13000 * MB},
        {'ts': [1, 3, 10, 33, 100], 'p': 32, 'm': 28000 * MB},
    ]

    BASE_PARAMS = {'hash_algo': HashAlgo.ARGON2_V19_ID.value}

    param_configs_by_id: ParamsByConfigId = {INSECURE: INSECURE_PARAM_CONFIG}

    for m_idx, cfg_params in enumerate(CONFIG_PARAMS):
        m_idx += 1
        for t_idx, time_cost in enumerate(cfg_params['ts']):
            params = BASE_PARAMS.copy()
            params['memory_cost'] = cfg_params['m']
            params['parallelism'] = cfg_params['p']
            params['time_cost'  ] = time_cost

            param_configs_by_id[m_idx * 5 + t_idx] = params

    assert min(param_configs_by_id) >= 0
    assert max(param_configs_by_id) < 256

    # import hashlib
    #
    # debug_bitfield = sum(
    #     1 << param_id for param_id in param_configs_by_id.keys()
    # )
    # print(hex(debug_bitfield))

    # checked_config_ids: typ.Set[KDFParamId] = set()
    # for ids_bitfield, expected_hash in PARAM_CONFIG_HASHES.items():
    #     params_configs_subset = {
    #         param_id: config
    #         for param_id, config in param_configs_by_id.items()
    #         if ids_bitfield & (1 << param_id) > 0
    #     }
    #     checked_config_ids.update(params_configs_subset.keys())
    #     params_str  = json.dumps(params_configs_subset, sort_keys=True)
    #     params_hash = hashlib.sha1(params_str.encode('ascii')).hexdigest()
    #     # print(params_hash)

    #     if params_hash != expected_hash:
    #         err_msg = (
    #             "Params hash changed! To prevent existing hashes from "
    #             "becomming invalid, it is vital that the parameters for "
    #             "a specific config does not change."
    #         )
    #         raise RuntimeError(err_msg)

    # if checked_config_ids != set(param_configs_by_id.keys()):
    #     raise RuntimeError("Unchecked param configs!")

    return param_configs_by_id


PARAM_CONFIGS_BY_ID = _init_configs()


def mem_total() -> KibiBytes:
    """Get total memory (linux only)."""
    # TODO: compat with macos?

    with open("/proc/meminfo", mode="rb") as fobj:
        for line in fobj:
            key, num, unit = line.decode("ascii").split()
            if key == "MemTotal:":
                return int(num)

    return 0


def get_avail_config_ids() -> KDFParamIds:
    """Get config_ids that can be used on the curren machine."""
    total_kb         = mem_total()
    config_ids       = []
    uniq_mem_configs = set()
    for param_id, config in PARAM_CONFIGS_BY_ID.items():
        if config['memory_cost'] < total_kb:
            config_ids.append(param_id)
            uniq_mem_configs.add((config['memory_cost'], config['parallelism']))

    return config_ids


Seconds = float

SecondsByConfigId = typ.Dict[KDFParamId, Seconds]


class Measurement(typ.NamedTuple):

    m: KibiBytes
    t: Iterations
    d: Seconds


class SystemInfo(typ.NamedTuple):

    total_kb        : KibiBytes
    num_measurements: int
    measurements    : typ.List[Measurement]


def estimate_config_cost(sys_info: SystemInfo) -> SecondsByConfigId:
    """Estimate the runtime of each config in seconds.

    This extrapolates based on a single short measurement
    and is very imprecise.
    """
    time_costs: SecondsByConfigId = {}

    measurements     = sys_info.measurements
    num_measurements = sys_info.num_measurements

    # Add artificial measurements if enough datapoints are not
    # collected yet.
    if 0 < num_measurements < 4:
        if num_measurements == 1:
            m, t, d = measurements[0]
            artificial_measurements = [
                Measurement(m * 2, t, d * 2),
                Measurement(m, t * 2, d * 2),
                Measurement(m * 2, t * 2, d * 4),
            ]
        elif num_measurements == 2:
            m, t, d = measurements[0]
            artificial_measurements = [
                Measurement(m, t * 2, d * 2),
                Measurement(m * 2, t * 2, d * 4),
            ]
        elif num_measurements == 3:
            m, t, d = measurements[0]
            artificial_measurements = [Measurement(m * 2, t * 2, d * 4)]
        measurements.extend(artificial_measurements)

    # Bilinear Interpolation
    # https://stackoverflow.com/a/8662355/62997
    # https://en.wikipedia.org/wiki/Bilinear_interpolation#Algorithm

    m0 , _  , _  , m1  = [m for m, t, d in measurements]
    t0 , _  , _  , t1  = [t for m, t, d in measurements]
    d00, d01, d10, d11 = [d for m, t, d in measurements]

    for param_id, config in PARAM_CONFIGS_BY_ID.items():
        m = config['memory_cost']
        t = config['time_cost']

        s = [
            d00 * (m1 - m ) * (t1 - t),
            d10 * (m  - m0) * (t1 - t),
            d01 * (m1 - m ) * (t  - t0),
            d11 * (m  - m0) * (t  - t0),
        ]

        est_cost = sum(s) / ((m1 - m0) * (t1 - t0))

        time_costs[param_id] = est_cost

        err_msg = "Estimation is hardcoded to parallelism=32"
        assert config['parallelism'] == 32, err_msg

    return time_costs


def parse_algo_type(hash_algo: int) -> int:
    if hash_algo == HashAlgo.ARGON2_V19_I.value:
        return argon2.low_level.Type.I
    if hash_algo == HashAlgo.ARGON2_V19_D.value:
        return argon2.low_level.Type.D
    if hash_algo == HashAlgo.ARGON2_V19_ID.value:
        return argon2.low_level.Type.ID

    err_msg = f"Unknown hash_algo={hash_algo}"
    raise ValueError(err_msg)


# The first of the parameters with the most memory that has an
# estimated duration above this threshold, is the one that is
# chosen as the default.


DEFAULT_PARAM_TIME_SEC_THRESHOLD  = 100
DEFAULT_PARAM_MEM_RATIO_THRESHOLD = 0.9

DEFAULT_XDG_CONFIG_HOME = str(pl.Path("~").expanduser() / ".config")
XDG_CONFIG_HOME         = pl.Path(
    os.environ.get('XDG_CONFIG_HOME', DEFAULT_XDG_CONFIG_HOME)
)

SBK_APP_DIR         = XDG_CONFIG_HOME / "sbk"
SYSINFO_CACHE_FNAME = "sys_info_cache.json"


def measure(mem_cost: int, time_cost: int) -> Seconds:
    tzero = time.time()
    argon2.low_level.hash_secret_raw(
        secret=b"test secret",
        salt=b"salt" * 4,
        memory_cost=mem_cost,
        time_cost=time_cost,
        parallelism=32,
        hash_len=16,
        type=argon2.low_level.Type.ID,
    )
    duration = time.time() - tzero
    log.info(f"progress bar calibration {int(duration * 1000)}")
    return duration


def eval_sys_info() -> SystemInfo:
    total_kb = mem_total()

    max_mem_cost = max(10000, total_kb // 20)

    t = 2
    m = max_mem_cost // 2
    d = measure(m, t)

    return SystemInfo(total_kb, 1, [Measurement(m, t, d)])


def dump_sys_info(sys_info: SystemInfo, cache_path: pl.Path) -> None:
    try:
        cache_path.parent.mkdir(exist_ok=True)
    except Exception:
        log.warning(f"Unable to create cache dir {cache_path.parent}")
        return

    sys_info_data = {
        'total_kb'        : sys_info.total_kb,
        'measurements'    : [m._asdict() for m in sys_info.measurements],
        'num_measurements': sys_info.num_measurements,
    }

    try:
        with cache_path.open(mode="w", encoding="utf-8") as fobj:
            json.dump(sys_info_data, fobj)
    except Exception as ex:
        log.warning(f"Error writing cache file {cache_path}: {ex}")
        return


_SYS_INFO: typ.Optional[SystemInfo] = None


def _load_cached_sys_info(cache_path: pl.Path) -> SystemInfo:
    try:
        with cache_path.open(mode="rb") as fobj:
            sys_info_data = json.load(fobj)

        measurement_data = sys_info_data['measurements']

        md = measurement_data[0]
        n  = sys_info_data.get('num_measurements', len(measurement_data))

        if n < 10:
            if n == 1:
                m = md['m'] * 2
                t = md['t']
            elif n == 2:
                m = md['m']
                t = md['t'] * 2
            elif n == 3:
                m = md['m'] * 2
                t = md['t'] * 2
            else:
                md = measurement_data[n % 4]
                m  = md['m']
                t  = md['t']

            md = {'m': m, 't': t, 'd': measure(m, t)}
            measurement_data.append(md)
            n += 1

        MeasurementKey = typ.Tuple[KibiBytes, Iterations]
        min_measurements: typ.Dict[MeasurementKey, float] = {}
        for md in measurement_data:
            key = (md['m'], md['t'])
            if key in min_measurements:
                val = min_measurements[key]
                min_measurements[key] = min(md['d'], val)
            else:
                min_measurements[key] = md['d']

        measurements = [
            Measurement(m, t, d) for (m, t), d in min_measurements.items()
        ]
        total_kb = typ.cast(KibiBytes, sys_info_data['total_kb'])
        sys_info = SystemInfo(total_kb, n, measurements)
        dump_sys_info(sys_info, cache_path)
    except Exception as ex:
        log.warning(f"Error reading cache file {cache_path}: {ex}")
        sys_info = eval_sys_info()
        dump_sys_info(sys_info, cache_path)

    return sys_info


def load_sys_info(
    app_dir: pl.Path = SBK_APP_DIR, ignore_cache: bool = False
) -> SystemInfo:
    global _SYS_INFO
    if _SYS_INFO:
        return _SYS_INFO

    cache_path = app_dir / SYSINFO_CACHE_FNAME

    if ignore_cache:
        sys_info = eval_sys_info()
    elif cache_path.exists():
        sys_info = _load_cached_sys_info(cache_path)
    else:
        sys_info = eval_sys_info()
        dump_sys_info(sys_info, cache_path)

    _SYS_INFO = sys_info
    return sys_info


class ParamContext(typ.NamedTuple):

    sys_info        : SystemInfo
    avail_configs   : ParamsByConfigId
    param_id_default: KDFParamId
    est_times_by_id : SecondsByConfigId


def get_param_ctx(app_dir: pl.Path) -> ParamContext:
    sys_info = load_sys_info(app_dir)

    avail_configs = {
        param_id: PARAM_CONFIGS_BY_ID[param_id]
        for param_id in get_avail_config_ids()
    }

    param_id_default = 1

    max_mem_kb = sys_info.total_kb * DEFAULT_PARAM_MEM_RATIO_THRESHOLD

    est_times_by_id = estimate_config_cost(sys_info)

    for current_config_id in sorted(avail_configs):
        current_config       = avail_configs[current_config_id]
        default_config       = avail_configs[param_id_default]
        current_est_time_sec = est_times_by_id[current_config_id]
        default_est_time_sec = est_times_by_id[param_id_default]

        if current_config['memory_cost'] > max_mem_kb:
            continue

        if current_config['memory_cost'] > default_config['memory_cost']:
            param_id_default = current_config_id
        else:
            if current_est_time_sec < default_est_time_sec:
                continue

            if current_est_time_sec > DEFAULT_PARAM_TIME_SEC_THRESHOLD:
                continue

            param_id_default = current_config_id

    return ParamContext(
        sys_info, avail_configs, param_id_default, est_times_by_id
    )
