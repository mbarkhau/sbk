# This file is part of the sbk project
# https://gitlab.com/mbarkhau/sbk
#
# Copyright (c) 2019 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT
"""Logic related to KDF derivation."""
import argon2

from . import params


def derive_key(
    secret_data: bytes, salt_data: bytes, kdf_params: params.KDFParams, hash_len: int
) -> bytes:
    return argon2.low_level.hash_secret_raw(
        secret=secret_data,
        salt=salt_data,
        hash_len=hash_len,
        type=params.parse_argon2_type(kdf_params.h),
        memory_cost=kdf_params.m,
        time_cost=kdf_params.t,
        parallelism=kdf_params.p,
        version=params.parse_argon2_version(kdf_params.h),
    )
