# This file is part of the ssk project
# https://gitlab.com/mbarkhau/ssk
#
# Copyright (c) 2019 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT
"""Logic related to KDF derivation."""
import hashlib

import argon2

from . import params


def derive_key_raw(
    secret_data: bytes, salt_data: bytes, config_id: int
) -> bytes:
    config = params.PARAM_CONFIGS_BY_ID[config_id]
    return argon2.low_level.hash_secret_raw(
        secret=secret_data,
        salt=salt_data,
        memory_cost=config['memory_cost'],
        time_cost=config['time_cost'],
        parallelism=config['parallelism'],
        hash_len=config['hash_len_bytes'],
        type=params.parse_algo_type(config['hash_algo']),
    )


def derive_key(
    secret_data: bytes, salt_email: str, param_id: params.KDFParamId
) -> bytes:
    salt_email_data = salt_email.encode('utf-8')
    salt_data       = hashlib.sha256(salt_email_data).digest()
    return derive_key_raw(secret_data, salt_data, param_id)
