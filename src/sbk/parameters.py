#################################################
#     This is a generated file, do not edit     #
#################################################

# This file is part of the sbk project
# https://github.com/mbarkhau/sbk
#
# Copyright (c) 2019-2022 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT
import os
import re
import sys
import json
import math
import time
import base64
import struct
import typing as typ
import hashlib
import logging
import pathlib as pl
import functools as ft
import itertools as it
import threading
import subprocess as sp
from typing import Any
from typing import Set
from typing import Dict
from typing import List
from typing import Type
from typing import Tuple
from typing import Union
from typing import Generic
from typing import NewType
from typing import TypeVar
from typing import Callable
from typing import Iterable
from typing import Iterator
from typing import Optional
from typing import Protocol
from typing import Sequence
from typing import Generator
from typing import NamedTuple

# from collections.abc import Generator, Iterator, Counter

# from typing import TypeAlias
TypeAlias = Any

import sbk.common_types as ct

logger = logging.getLogger(__name__)
SBK_VERSION_V0 = 0

# constrained by f_threshold (3bits)
MIN_THRESHOLD = 2
MAX_THRESHOLD = 10

KDF_PARALLELISM = ct.Parallelism(128)  # hardcoded
DEFAULT_KDF_T_TARGET = ct.Seconds(90)
DEFAULT_KDF_M_PERCENT = 100

DEFAULT_SSS_T = 3
DEFAULT_SSS_N = 5

V0_KDF_M_BASE = 1.5
V0_KDF_T_BASE = 4.0

V0_KDF_M_UNIT = 512  # megabytes
V0_KDF_T_UNIT = 1  # iterations
BRANKEY_HEADER_LEN = 1
SHARE_HEADER_LEN = 2

DEFAULT_RAW_SALT_LEN = 17
DEFAULT_RAW_SALT_LEN = 9
DEFAULT_BRAINKEY_LEN = 5
if "SBK_DEBUG_RAW_SALT_LEN" in os.environ:
    DEFAULT_RAW_SALT_LEN = int(os.environ["SBK_DEBUG_RAW_SALT_LEN"])

if "SBK_DEBUG_BRAINKEY_LEN" in os.environ:
    DEFAULT_BRAINKEY_LEN = int(os.environ["SBK_DEBUG_BRAINKEY_LEN"])

MIN_ENTROPY = int(os.getenv("SBK_MIN_ENTROPY", "16"))
MAX_ENTROPY_WAIT = int(os.getenv("SBK_MAX_ENTROPY_WAIT", "10"))

DEFAULT_KDF_T_TARGET = int(os.getenv("SBK_KDF_T_TARGET") or DEFAULT_KDF_T_TARGET)
DEFAULT_KDF_M_PERCENT = int(os.getenv("SBK_KDF_M_PERCENT") or DEFAULT_KDF_M_PERCENT)

DEFAULT_SSS_T = int(os.getenv("SBK_THRESHOLD") or DEFAULT_SSS_T)
DEFAULT_SSS_N = int(os.getenv("SBK_NUM_SHARES") or DEFAULT_SSS_N)


class Parameters(NamedTuple):

    version: int

    kdf_p: ct.Parallelism
    kdf_m: ct.MebiBytes
    kdf_t: ct.Iterations

    sss_x: int
    sss_t: int
    sss_n: int


class KDFParams(NamedTuple):
    kdf_p: ct.Parallelism
    kdf_m: ct.MebiBytes
    kdf_t: ct.Iterations


def param_coeffs(b: float) -> Tuple[int, int]:
    assert b > 1
    s = 1 / (b - 1)
    o = 1 - s

    v0 = b ** 0 * s + o
    v1 = b ** 1 * s + o
    assert v0 == 1
    assert 1.5 < v1 < 2.5
    return (s, o)


from math import log


def param_exp(n: int, b: float) -> int:
    s, o = param_coeffs(b)
    v = round(b ** n * s + o)
    return v


def param_log(v: int, b: float) -> int:
    s, o = param_coeffs(b)
    n = log((v - o) / s) / log(b)
    return min(max(round(n), 0), 2 ** 63)


def init_kdf_params(kdf_m: ct.MebiBytes, kdf_t: ct.Iterations) -> KDFParams:
    kdf_m_enc = param_log(kdf_m / V0_KDF_M_UNIT, V0_KDF_M_BASE)
    kdf_t_enc = param_log(kdf_t / V0_KDF_T_UNIT, V0_KDF_T_BASE)

    kdf_m = param_exp(kdf_m_enc, V0_KDF_M_BASE) * V0_KDF_M_UNIT
    kdf_t = param_exp(kdf_t_enc, V0_KDF_T_BASE) * V0_KDF_T_UNIT
    return KDFParams(KDF_PARALLELISM, kdf_m, kdf_t)


def init_parameters(
    kdf_m: ct.MebiBytes,
    kdf_t: ct.Iterations,
    sss_x: int,
    sss_t: int = DEFAULT_SSS_T,
    sss_n: int = -1,
) -> Parameters:
    kdf_params = init_kdf_params(kdf_m, kdf_t)
    if not MIN_THRESHOLD <= sss_t <= MAX_THRESHOLD:
        raise ValueError(f"Invalid threshold: {sss_t}")
    elif kdf_params.kdf_m % V0_KDF_M_UNIT != 0:
        errmsg = f"Invalid kdf_m: {kdf_params.kdf_m} % {V0_KDF_M_UNIT} != 0"
        raise ValueError(errmsg)
    else:
        return Parameters(
            version=SBK_VERSION_V0,
            kdf_p=kdf_params.kdf_p,
            kdf_m=kdf_params.kdf_m,
            kdf_t=kdf_params.kdf_t,
            sss_x=sss_x,
            sss_t=sss_t,
            sss_n=sss_n,
        )


def params2bytes(params: Parameters) -> bytes:
    assert params.version == 0

    kdf_m_enc = param_log(params.kdf_m / V0_KDF_M_UNIT, V0_KDF_M_BASE)
    kdf_t_enc = param_log(params.kdf_t / V0_KDF_T_UNIT, V0_KDF_T_BASE)

    assert params.version & 0b0011 == params.version
    assert kdf_m_enc & 0b0111 == kdf_m_enc
    assert kdf_t_enc & 0b0111 == kdf_t_enc

    if params.sss_x > 0:
        sss_x_enc = params.sss_x - 1
    else:
        sss_x_enc = 0
    sss_t_enc = params.sss_t - 2

    assert sss_x_enc & 0b0001_1111 == sss_x_enc
    assert sss_t_enc & 0b0000_0111 == sss_t_enc

    field0 = 0 | params.version << 0x00 | kdf_m_enc << 0x02 | kdf_t_enc << 0x05
    field1 = 0 | sss_x_enc << 0x00 | sss_t_enc << 0x05
    return struct.pack("<BB", field0, field1)


def bytes2params(data: bytes) -> Parameters:
    is_share_data = len(data) == 2
    if not is_share_data:
        data = data + b"\x00"  # append dummy sss_t and sss_x

    assert len(data) == 2, len(data)
    field0, field1 = struct.unpack("<BB", data)

    version = (field0 >> 0x00) & 0b0011
    kdf_m_enc = (field0 >> 0x02) & 0b0111
    kdf_t_enc = (field0 >> 0x05) & 0b0111

    sss_x_enc = (field1 >> 0x00) & 0b0001_1111
    sss_t_enc = (field1 >> 0x05) & 0b0000_0111

    assert version == SBK_VERSION_V0, f"Invalid version: {version}"

    kdf_m = param_exp(kdf_m_enc, V0_KDF_M_BASE) * V0_KDF_M_UNIT
    kdf_t = param_exp(kdf_t_enc, V0_KDF_T_BASE) * V0_KDF_T_UNIT
    if is_share_data:
        sss_x = sss_x_enc + 1
        sss_t = sss_t_enc + 2
    else:
        sss_x = -1
        sss_t = 2

    sss_n = sss_t
    return init_parameters(kdf_m, kdf_t, sss_x, sss_t, sss_n)


def validated_param_data(params: Parameters) -> bytes:
    # validate encoding round trip before we use params
    params_data = params2bytes(params)
    decoded_params = bytes2params(params_data)

    checks = {
        "threshold": params.sss_t == decoded_params.sss_t,
        "version": params.version == decoded_params.version,
        "kdf_p": params.kdf_p == decoded_params.kdf_p,
        "kdf_m": params.kdf_m == decoded_params.kdf_m,
        "kdf_t": params.kdf_t == decoded_params.kdf_t,
    }
    bad_checks = [name for name, is_ok in checks.items() if not is_ok]
    if any(bad_checks):
        raise ValueError(bad_checks)
    else:
        return params_data


class SecretLens(NamedTuple):
    raw_brainkey: int
    raw_share: int
    brainkey: int
    salt: int
    master_key: int
    share: int


def raw_secret_lens() -> SecretLens:
    raw_brainkey = DEFAULT_BRAINKEY_LEN
    salt = DEFAULT_RAW_SALT_LEN
    raw_share = raw_brainkey + salt

    brainkey = BRANKEY_HEADER_LEN + raw_brainkey
    master_key = raw_brainkey + salt
    share = SHARE_HEADER_LEN + raw_share
    return SecretLens(**locals())
