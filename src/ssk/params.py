# This file is part of the ssk project
# https://gitlab.com/mbarkhau/ssk
#
# Copyright (c) 2019 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT
import time
import enum
import json
import hashlib
import typing as typ

import argon2


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


class Params(typ.NamedTuple):

    threshold     : int
    num_parts     : int
    config_id     : int
    hash_algo     : HashAlgo
    hash_len_bytes: int
    memory_cost   : KibiBytes
    time_cost     : Iterations
    parallelism   : int


ConfigId  = int
ConfigIds = typ.Sequence[ConfigId]

INSECURE: ConfigId = 0


# Some notes on parameter choices.
# https://tools.ietf.org/html/draft-irtf-cfrg-argon2-04#section-4
#
# time_cost: As the time constraint is not such an issue for the
# intended use cases of SSK, you should be able to dedicate a few
# minutes of computation time to derive a secure key from relativly
# low amount of secret entropy (the brainkey).
#
# hash_type: Theroetically you should only use SSK on a trusted system
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

ParamsByConfigId = typ.Dict[ConfigId, typ.Any]

PARAMS_CONFIGS_BY_ID: ParamsByConfigId = {
    INSECURE: {
        'hash_algo'     : HashAlgo.ARGON2_V19_ID.value,
        'hash_len_bytes': 16,
        'memory_cost'   : 1024,
        'time_cost'     : 1,
        'parallelism'   : 32,
    }
}


# In order to preserve compatability of generated keys, historical
# entries of PARAMS_CONFIGS_BY_ID are hashed. This provides a safety
# net against inadvertant changes to the _init_configs function.
PARAM_CONFIG_HASHES = {
    0x7F007F007F007F007F00FF01FF0001: 'd09fd6241e320c79472288c1db604d2c9fd69bdd'
}


def _init_configs():
    GB            = 1024 * 1024
    CONFIG_PARAMS = [
        {
            'ts': [2, 5, 10, 25, 50, 100, 250, 500, 1000],
            'p' : 32,
            'm' : 300 * 1024,
        },
        {'ts': [2, 5, 10, 25, 50, 100, 250, 500], 'p': 32, 'm': 1 * GB},
        {'ts': [2, 5, 10, 25, 50, 100, 250], 'p': 32, 'm':  3 * GB},
        {'ts': [2, 5, 10, 25, 50, 100, 250], 'p': 32, 'm':  6 * GB},
        {'ts': [2, 5, 10, 25, 50, 100, 250], 'p': 32, 'm': 12 * GB},
        {'ts': [2, 5, 10, 25, 50, 100, 250], 'p': 32, 'm': 24 * GB},
        {'ts': [2, 5, 10, 25, 50, 100, 250], 'p': 32, 'm': 48 * GB},
    ]

    BASE_PARAMS = {
        'hash_algo'     : HashAlgo.ARGON2_V19_ID.value,
        'hash_len_bytes': 16,
    }

    for m_idx, cfg_params in enumerate(CONFIG_PARAMS):
        m_idx += 1
        for t_idx, time_cost in enumerate(cfg_params['ts']):
            params = BASE_PARAMS.copy()
            params['memory_cost'] = cfg_params['m']
            params['parallelism'] = cfg_params['p']
            params['time_cost'  ] = time_cost

            PARAMS_CONFIGS_BY_ID[m_idx * 16 + t_idx] = params

    # debug_bitfield = sum(1 << config_id for config_id in PARAMS_CONFIGS_BY_ID.keys())
    # print(hex(debug_bitfield))

    checked_config_ids = set()
    for ids_bitfield, expected_hash in PARAM_CONFIG_HASHES.items():
        params_configs_by_id = {
            config_id: config
            for config_id, config in PARAMS_CONFIGS_BY_ID.items()
            if ids_bitfield & (1 << config_id) > 0
        }
        checked_config_ids.update(params_configs_by_id.keys())
        params_str  = json.dumps(params_configs_by_id, sort_keys=True)
        params_hash = hashlib.sha1(params_str.encode('ascii')).hexdigest()
        # print(params_hash)

        if params_hash != expected_hash:
            err_msg = (
                "Params hash changed! To prevent existing hashes from "
                "becomming invalid, it is vital that the parameters for "
                "a specific config does not change."
            )
            raise RuntimeError(err_msg)

    if checked_config_ids != set(PARAMS_CONFIGS_BY_ID.keys()):
        raise RuntimeError("Unchecked param configs!")


_init_configs()


def mem_total() -> KibiBytes:
    """Get total memory (linux only).

    >>> mem_total() > 0
    True
    """
    with open("/proc/meminfo", mode="rb") as fobj:
        for line in fobj:
            key, num, unit = line.decode("ascii").split()
            if key == "MemTotal:":
                return int(num)

    return 0


def get_avail_config_ids() -> ConfigIds:
    """Get config_ids that can be used on the curren machine.

    >>> avail_config_ids = get_avail_config_ids()
    >>> len(avail_config_ids) > 4
    True
    """
    total_kb         = mem_total()
    config_ids       = []
    uniq_mem_configs = set()
    for config_id, config in PARAMS_CONFIGS_BY_ID.items():
        if config['memory_cost'] < total_kb:
            config_ids.append(config_id)
            uniq_mem_configs.add((config['memory_cost'], config['parallelism']))

    return config_ids


Seconds = float

SecondsByConfigId = typ.Dict[ConfigId, Seconds]


def estimate_config_cost() -> SecondsByConfigId:
    """Estimate the runtime of each config in seconds.

    This extrapolates based on a single short measurement
    and is very imprecise.

    >>> costs = estimate_config_cost()
    >>> assert costs.keys() == PARAMS_CONFIGS_BY_ID.keys()
    >>> assert set(map(type, costs.values())) == {float}
    >>> assert round(costs[0]) == 0
    """
    baseline_memory_cost = 256 * 1024
    baseline_time_cost   = 3

    tzero = time.time()

    argon2.low_level.hash_secret_raw(
        secret=b"test secret",
        salt=b"salt" * 4,
        memory_cost=baseline_memory_cost,
        time_cost=baseline_time_cost,
        parallelism=32,
        hash_len=16,
        type=argon2.low_level.Type.ID,
    )
    est_baseline_cost = time.time() - tzero

    time_costs: SecondsByConfigId = {}

    for config_id, config in PARAMS_CONFIGS_BY_ID.items():
        mem_factor  = config['memory_cost'] / baseline_memory_cost
        time_factor = config['time_cost'  ] / baseline_time_cost
        est_cost    = est_baseline_cost * mem_factor * time_factor
        time_costs[config_id] = est_cost

        err_msg = "Estimation is hardcoded to parallelism=32"
        assert config['parallelism'] == 32, err_msg

    return time_costs


def new_params(threshold: int, num_parts: int, config_id: int) -> Params:
    if threshold > num_parts:
        err_msg = (
            f"threshold must be <= num_parts, got {threshold} > {num_parts}"
        )
        raise ValueError(err_msg)

    config = PARAMS_CONFIGS_BY_ID[config_id]

    return Params(
        threshold=threshold, num_parts=num_parts, config_id=config_id, **config
    )


def _parse_algo_type(hash_algo: int) -> int:
    if hash_algo == HashAlgo.ARGON2_V19_I.value:
        return argon2.low_level.Type.I
    if hash_algo == HashAlgo.ARGON2_V19_D.value:
        return argon2.low_level.Type.D
    if hash_algo == HashAlgo.ARGON2_V19_ID.value:
        return argon2.low_level.Type.ID

    err_msg = f"Unknown hash_algo={hash_algo}"
    raise ValueError(err_msg)


def _derive_key(secret_data: bytes, salt_data: bytes, config_id: int) -> bytes:
    config = PARAMS_CONFIGS_BY_ID[config_id]
    return argon2.low_level.hash_secret_raw(
        secret=secret_data,
        salt=salt_data,
        memory_cost=config['memory_cost'],
        time_cost=config['time_cost'],
        parallelism=config['parallelism'],
        hash_len=config['hash_len_bytes'],
        type=_parse_algo_type(config['hash_algo']),
    )


def derive_key(secret: str, salt_email: str, config_id: int) -> bytes:
    salt_data   = hashlib.sha256(salt_email).digest()
    secret_data = secret.encode('utf-8')
    return _derive_key(secret_data, salt_data, config_id)
