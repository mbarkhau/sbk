# This file is part of the sbk project
# https://github.com/mbarkhau/sbk
#
# Copyright (c) 2019-2021 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT
#################################################
#     This is a generated file, do not edit     #
#################################################
from __future__ import annotations

import os
import sys
import pathlib as pl
import itertools as it
from typing import NewType
from typing import Callable
from typing import Sequence
from typing import NamedTuple
from collections.abc import Generator

gen = Generator
seq = Sequence
import struct

import sbk.common_types as ct

SBK_VERSION_V0        = 0
MIN_THRESHOLD         = 2
MAX_THRESHOLD         = 10
DEFAULT_RAW_SALT_LEN  = 7
PARANOID_RAW_SALT_LEN = 13
DEFAULT_BRAINKEY_LEN  = 6
PARANOID_BRAINKEY_LEN = 8
PARAM_DATA_LEN        = 2
SHARE_DATA_LEN        = 3
KDF_PARALLELISM       = 128
DEFAULT_KDF_T_TARGET  = 90
DEFAULT_THRESHOLD     = 3
DEFAULT_NUM_SHARES    = 5
ENV_RAW_SALT_LEN      = os.getenv('SBK_DEBUG_RAW_SALT_LEN')
ENV_BRAINKEY_LEN      = os.getenv('SBK_DEBUG_BRAINKEY_LEN')
RAW_SALT_LEN          = int(ENV_RAW_SALT_LEN) if ENV_RAW_SALT_LEN else DEFAULT_RAW_SALT_LEN
BRAINKEY_LEN          = int(ENV_BRAINKEY_LEN) if ENV_BRAINKEY_LEN else DEFAULT_BRAINKEY_LEN
MIN_ENTROPY           = int(os.getenv('SBK_MIN_ENTROPY'     , '16'))
MAX_ENTROPY_WAIT      = int(os.getenv('SBK_MAX_ENTROPY_WAIT', '10'))
DEFAULT_KDF_T_TARGET  = int(os.getenv('SBK_KDF_KDF_T' ) or DEFAULT_KDF_T_TARGET)
DEFAULT_THRESHOLD     = int(os.getenv('SBK_THRESHOLD' ) or DEFAULT_THRESHOLD)
DEFAULT_NUM_SHARES    = int(os.getenv('SBK_NUM_SHARES') or DEFAULT_NUM_SHARES)


class Parameters(NamedTuple):
    version   : int
    paranoid  : bool
    kdf_p     : ct.Parallelism
    kdf_m     : ct.MebiBytes
    kdf_t     : ct.Iterations
    threshold : int
    num_shares: int
    share_no  : int | None


def init_parameters(
    kdf_m     : ct.MebiBytes,
    kdf_t     : ct.Iterations,
    paranoid  : bool = False,
    threshold : int  = DEFAULT_THRESHOLD,
    num_shares: (int | None) = None,
    share_no  : (int | None) = None,
) -> Parameters:
    _num_shares = threshold if num_shares is None else num_shares
    if threshold > _num_shares:
        errmsg = f"threshold must be <= num_shares, got {threshold} > {_num_shares}"
        raise ValueError(errmsg)
    elif not MIN_THRESHOLD <= threshold <= MAX_THRESHOLD:
        errmsg = f"Invalid threshold {threshold}"
        raise ValueError(errmsg)
    else:
        return Parameters(
            version=SBK_VERSION_V0,
            paranoid=paranoid,
            kdf_p=KDF_PARALLELISM,
            kdf_m=kdf_m,
            kdf_t=kdf_t,
            threshold=threshold,
            num_shares=_num_shares,
            share_no=share_no,
        )


def params2bytes(params: Parameters) -> bytes:
    pass


def bytes2params(data: bytes) -> Parameters:
    pass


def master_key_len(params: Parameters) -> int:
    raise NotImplementedError
    if params.paranoid:
        return
    else:
        return
