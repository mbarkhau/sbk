# This file is part of the sbk project
# https://gitlab.com/mbarkhau/sbk
#
# Copyright (c) 2019 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT
"""Logic related to KDF derivation."""
import argon2

from . import params


def derive_key(
    secret_data : bytes,
    salt_data   : bytes,
    kdf_param_id: params.KDFParamId,
    hash_len    : int,
) -> bytes:
    param_cfg = params.PARAM_CONFIGS_BY_ID[kdf_param_id]
    return argon2.low_level.hash_secret_raw(
        secret=secret_data,
        salt=salt_data,
        hash_len=hash_len,
        type=params.parse_algo_type(param_cfg['hash_algo']),
        memory_cost=param_cfg['memory_cost'],
        time_cost=param_cfg['time_cost'],
        parallelism=param_cfg['parallelism'],
    )
