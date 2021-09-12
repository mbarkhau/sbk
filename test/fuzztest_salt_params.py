import os
import re
import sys
import json
import math
import time
import base64
import struct
import hashlib
import logging
import pathlib as pl
import functools as ft
import itertools as it
import threading
import subprocess as sp
from typing import Any
from typing import NewType
from typing import Callable
from typing import Optional
from typing import Sequence
from typing import NamedTuple
from collections.abc import Iterator
from collections.abc import Generator

import sbk.common_types as ct

logger = logging.getLogger(__name__)


class Parameters(NamedTuple):

    version : int
    paranoid: bool

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


SBK_VERSION_V0 = 0

# constrained by f_threshold (3bits)
MIN_THRESHOLD = 2
MAX_THRESHOLD = 10

KDF_PARALLELISM      = ct.Parallelism(128)  # hardcoded
DEFAULT_KDF_T_TARGET = ct.Seconds(90)

DEFAULT_SSS_T    = 3
DEFAULT_SSS_N    = 5
SALT_HEADER_LEN  = 2
SHARE_HEADER_LEN = 3

DEFAULT_RAW_SALT_LEN  = 7
PARANOID_RAW_SALT_LEN = 13

DEFAULT_BRAINKEY_LEN  = 6
PARANOID_BRAINKEY_LEN = 8
if 'SBK_DEBUG_RAW_SALT_LEN' in os.environ:
    DEFAULT_RAW_SALT_LEN  = int(os.environ['SBK_DEBUG_RAW_SALT_LEN'])
    PARANOID_RAW_SALT_LEN = int(os.environ['SBK_DEBUG_RAW_SALT_LEN'])

if 'SBK_DEBUG_BRAINKEY_LEN' in os.environ:
    DEFAULT_BRAINKEY_LEN  = int(os.environ['SBK_DEBUG_BRAINKEY_LEN'])
    PARANOID_BRAINKEY_LEN = int(os.environ['SBK_DEBUG_BRAINKEY_LEN'])

MIN_ENTROPY      = int(os.getenv('SBK_MIN_ENTROPY'     , "16"))
MAX_ENTROPY_WAIT = int(os.getenv('SBK_MAX_ENTROPY_WAIT', "10"))

DEFAULT_KDF_T_TARGET = int(os.getenv('SBK_KDF_T_TARGET') or DEFAULT_KDF_T_TARGET)

DEFAULT_SSS_T = int(os.getenv('SBK_THRESHOLD' ) or DEFAULT_SSS_T)
DEFAULT_SSS_N = int(os.getenv('SBK_NUM_SHARES') or DEFAULT_SSS_N)


def _param_coefficients(b: float) -> tuple[int, int]:
    assert b > 1
    s = int(1 / (b - 1))
    o = int(1 - s)

    v0 = b ** 0 * s + o
    v1 = b ** 1 * s + o
    assert v0 == 1
    assert 1.5 < v1 < 2.5
    return (s, o)


from math import log


def param_exp(n: int, b: float) -> int:
    s, o = _param_coefficients(b)
    v = round(b ** n * s + o)
    return v


def param_log(v: int, b: float) -> int:
    s, o = _param_coefficients(b)
    n = log((v - o) / s) / log(b)
    return min(max(round(n), 0), 2 ** 63)


def init_kdf_params(kdf_m: ct.MebiBytes, kdf_t: ct.Iterations) -> KDFParams:
    kdf_m_enc = param_log(kdf_m / 100, 1.125)
    kdf_t_enc = param_log(kdf_t, 1.125)

    kdf_m = param_exp(kdf_m_enc, 1.125) * 100
    kdf_t = param_exp(kdf_t_enc, 1.125)
    return KDFParams(KDF_PARALLELISM, kdf_m, kdf_t)


def init_parameters(
    paranoid: bool,
    kdf_m   : ct.MebiBytes,
    kdf_t   : ct.Iterations,
    sss_x   : int,
    sss_t   : int = DEFAULT_SSS_T,
    sss_n   : int = -1,
) -> Parameters:
    kdf_params = init_kdf_params(kdf_m, kdf_t)
    if not MIN_THRESHOLD <= sss_t <= MAX_THRESHOLD:
        raise ValueError(f"Invalid threshold: {sss_t}")
    elif kdf_params.kdf_m % 100 != 0:
        raise ValueError(f"Invalid kdf_m: {kdf_params.kdf_m} % 100 != 0")
    else:
        return Parameters(
            version=SBK_VERSION_V0,
            paranoid=paranoid,
            kdf_p=kdf_params.kdf_p,
            kdf_m=kdf_params.kdf_m,
            kdf_t=kdf_params.kdf_t,
            sss_x=sss_x,
            sss_t=sss_t,
            sss_n=sss_n,
        )


def params2bytes(params: Parameters) -> bytes:
    kdf_m_enc = param_log(params.kdf_m / 100, 1.125)
    kdf_t_enc = param_log(params.kdf_t, 1.125)
    sss_x_enc = params.sss_x - 1
    sss_t_enc = params.sss_t - 2

    assert params.version & 0b0000_0111 == params.version
    assert int(params.paranoid) & 0b0000_0001 == params.paranoid
    assert kdf_m_enc & 0b0011_1111 == kdf_m_enc
    assert kdf_t_enc & 0b0011_1111 == kdf_t_enc
    assert sss_x_enc & 0b0001_1111 == sss_x_enc
    assert sss_t_enc & 0b0000_0111 == sss_t_enc

    encoded_uint = (
        0
        | params.version << 0x00
        | int(params.paranoid) << 0x03
        | kdf_m_enc << 0x04
        | kdf_t_enc << 0x0A
        | sss_x_enc << 0x10
        | sss_t_enc << 0x15
    )
    encoded_data = struct.pack("<L", encoded_uint)
    assert encoded_data[-1:] == b"\x00", encoded_data[-1:]
    return encoded_data[:-1]


def bytes2params(data: bytes) -> Parameters:
    is_salt_data = len(data) == 2
    if is_salt_data:
        data = data + b"\x00"  # append dummy sss_t and sss_x

    assert len(data) == 3, len(data)
    (encoded_uint,) = struct.unpack("<L", data + b"\x00")

    version   = (encoded_uint >> 0x00) & 0b0000_0111
    paranoid  = (encoded_uint >> 0x03) & 0b0000_0001
    kdf_m_enc = (encoded_uint >> 0x04) & 0b0011_1111
    kdf_t_enc = (encoded_uint >> 0x0A) & 0b0011_1111
    sss_x_enc = (encoded_uint >> 0x10) & 0b0001_1111
    sss_t_enc = (encoded_uint >> 0x15) & 0b0000_0111

    assert version == SBK_VERSION_V0, version

    kdf_m = param_exp(kdf_m_enc, 1.125) * 100
    kdf_t = param_exp(kdf_t_enc, 1.125)
    if is_salt_data:
        sss_x = -1
        sss_t = 2
    else:
        sss_x = sss_x_enc + 1
        sss_t = sss_t_enc + 2

    sss_n = sss_t
    return init_parameters(bool(paranoid), kdf_m, kdf_t, sss_x, sss_t, sss_n)


class SecretLens(NamedTuple):
    raw_salt  : int
    brainkey  : int
    master_key: int
    raw_share : int
    salt      : int
    share     : int


def raw_secret_lens(paranoid: bool) -> SecretLens:
    if paranoid:
        raw_salt = PARANOID_RAW_SALT_LEN
        brainkey = PARANOID_BRAINKEY_LEN
    else:
        raw_salt = DEFAULT_RAW_SALT_LEN
        brainkey = DEFAULT_BRAINKEY_LEN

    raw_share = master_key = raw_salt + brainkey
    salt      = raw_salt  + SALT_HEADER_LEN
    share     = raw_share + SHARE_HEADER_LEN
    return SecretLens(raw_salt, brainkey, master_key, raw_share, salt, share)


def hex2bytes(hex_str: str) -> bytes:
    """Convert bytes to a hex string."""
    hex_str = hex_str.upper().zfill(2 * ((len(hex_str) + 1) // 2))
    return base64.b16decode(hex_str.encode('ascii'))


def bytes2hex(data: bytes) -> str:
    """Convert bytes to a hex string."""
    return base64.b16encode(data).decode('ascii').lower()


def bytes_hex(data: bytes) -> str:
    """Display bytes data in hex form, rather than ascii."""
    chars           = (data[i : i + 1] for i in range(len(data)))
    char_hex        = [bytes2hex(c).lower() for c in chars]
    char_hex_padded = (c + " " if (i + 1) % 2 == 0 else c for i, c in enumerate(char_hex))
    return "".join(char_hex_padded).strip()


def validate_params(in_params: Parameters) -> None:
    assert abs(in_params.kdf_m - kwargs['kdf_m']) / kwargs['kdf_m'] < 0.125
    assert abs(in_params.kdf_t - kwargs['kdf_t']) / kwargs['kdf_t'] < 0.125

    # round trip
    params_data = params2bytes(in_params)
    assert isinstance(params_data, bytes)
    assert len(params_data) == 3

    out_params = bytes2params(params_data[:2])
    assert out_params.version  == in_params.version
    assert out_params.paranoid == in_params.paranoid
    assert out_params.kdf_p    == in_params.kdf_p
    assert out_params.kdf_m    == in_params.kdf_m
    assert out_params.kdf_t    == in_params.kdf_t
    assert out_params.sss_x    == -1
    assert out_params.sss_t    == MIN_THRESHOLD


import random

rand = random.Random(0)

kwargs_range = {
    'paranoid': [True, False],
    'kdf_m'   : [rand.randint(1, 1000000) for _ in range(100)],
    'kdf_t'   : [rand.randint(1,   10000) for _ in range(100)],
    'sss_x'   : list(range(1, 2 ** 5)),
    'sss_t'   : list(range(2, 2 ** 3 + 2)),
}

for _ in range(100):
    kwargs    = {k: rand.choice(choices) for k, choices in kwargs_range.items()}
    in_params = init_parameters(**kwargs)
    validate_params(in_params)

print("ok")
