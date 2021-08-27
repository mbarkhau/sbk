# This file is part of the sbk project
# https://github.com/mbarkhau/sbk
#
# Copyright (c) 2019-2021 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT
"""Parameter encoding/decoding/initialization.

Data layout for reference.

|        Field        |  Size  |                          Info                            |
| ------------------- | ------ | -------------------------------------------------------- |
| `f_threshold`       | 8 bit  | minimum shares required for recovery                     |
|                     |        | max: 1..2**4 = 2..17                                     |
| `f_share_no`        | 8 bit  | For shares, the x-coordinate > 0                         |
| `f_version`         | 4 bit  | ...                                                      |
| `f_kdf_parallelism` | 4 bit  | `ceil(2 ** n)    = kdf_parallelism` in number of threads |
| `f_kdf_mem_cost`    | 6 bit  | `ceil(1.25 ** n) = kdf_mem_cost` in MiB                  |
| `f_kdf_time_cost`   | 6 bit  | `ceil(1.5  ** n) = kdf_time_cost` in iterations          |

0         7 8         15 16   19 20   23 24       30       32
[threshold] [ share_no ] [ ver ] [kdf_p] [ kdf_mem ] [ kdf_time]
    8bit       8bit       4bit     4bit      4bit        6bit

| `f_version`         | 4 bit  | ...                                                      |
| `f_kdf_mem_cost`    | 6 bit  | `ceil(1.125 ** n) = kdf_mem_cost` in 128 Mebibyte         |
| `f_kdf_time_cost`   | 6 bit  | `ceil(n + 1.25  ** n)  = kdf_time_cost` in iterations          |

0      3 4          9 10        15
[  ver ] [    mem   ] [   time   ]
  4bit       6bit         6bit

0         7 8         15
[threshold] [ share_no ]
    8bit       8bit

"""

import os
import struct
import typing as typ

from . import kdf
from . import primes

SBK_VERSION_V0 = 0

DEFAULT_RAW_SALT_LEN = 7
DEFAULT_BRAINKEY_LEN = 6

PARANOID_RAW_SALT_LEN = 13
PARANOID_BRAINKEY_LEN = 8

ENV_RAW_SALT_LEN = os.getenv('SBK_DEBUG_RAW_SALT_LEN')
ENV_BRAINKEY_LEN = os.getenv('SBK_DEBUG_BRAINKEY_LEN')

RAW_SALT_LEN = int(ENV_RAW_SALT_LEN) if ENV_RAW_SALT_LEN else DEFAULT_RAW_SALT_LEN
BRAINKEY_LEN = int(ENV_BRAINKEY_LEN) if ENV_BRAINKEY_LEN else DEFAULT_BRAINKEY_LEN

# linear fit evaluated with: python -m sbk.ui_common
RAW_SALT_MIN_ENTROPY = RAW_SALT_LEN * 0.19 + 0.3
BRAINKEY_MIN_ENTROPY = BRAINKEY_LEN * 0.19 + 0.3

PARAM_CFG_LEN  = 3
SHARE_DATA_LEN = 1
SALT_LEN       = PARAM_CFG_LEN + RAW_SALT_LEN

MASTER_KEY_LEN = RAW_SALT_LEN + BRAINKEY_LEN

SHARE_LEN = PARAM_CFG_LEN + SHARE_DATA_LEN + RAW_SALT_LEN + BRAINKEY_LEN

MIN_ENTROPY      = int(os.getenv('SBK_MIN_ENTROPY'     , "16"))
MAX_ENTROPY_WAIT = int(os.getenv('SBK_MAX_ENTROPY_WAIT', "10"))

DEFAULT_KDF_TARGET_DURATION = int(os.getenv('SBK_KDF_TARGET_DURATION', "90"))

DEFAULT_THRESHOLD  = int(os.getenv('SBK_THRESHOLD' , "3"))
DEFAULT_NUM_SHARES = int(os.getenv('SBK_NUM_SHARES', "5"))

# constrained by f_threshold (3bits)
MAX_THRESHOLD = 10


class ParamConfig(typ.NamedTuple):

    version   : int
    paranoid  : bool
    kdf_params: kdf.KDFParams
    threshold : int
    share_no  : typ.Optional[int]
    num_shares: int

    @property
    def prime(self) -> int:
        master_key_bits = MASTER_KEY_LEN * 8
        return primes.get_pow2prime(master_key_bits)


def init_param_config(
    kdf_params: kdf.KDFParams,
    threshold : int,
    share_no  : typ.Optional[int] = None,
    num_shares: typ.Optional[int] = None,
    paranoid  : bool = False,
) -> ParamConfig:
    _num_shares = threshold if num_shares is None else num_shares

    if threshold > _num_shares:
        errmsg = f"threshold must be <= num_shares, got {threshold} > {_num_shares}"
        raise ValueError(errmsg)
    elif not 1 <= threshold <= MAX_THRESHOLD:
        errmsg = f"Invalid threshold {threshold}"
        raise ValueError(errmsg)
    else:
        return ParamConfig(
            version=SBK_VERSION_V0,
            paranoid=paranoid,
            kdf_params=kdf_params,
            threshold=threshold,
            share_no=share_no,
            num_shares=_num_shares,
        )


def bytes2param_cfg(data: bytes) -> ParamConfig:
    """Deserialize ParamConfig from the Salt or a Share."""
    if len(data) < 3:
        errmsg = f"Invalid params len={len(data)}"
        raise ValueError(errmsg)

    # H: Unsigned Short (2 bytes)
    (fields,) = struct.unpack("!H", data[:2])

    # We don't include the share_no in the ParamConfig, it
    # is decoded separately for each share.
    # share_no = _fields_5

    version = (fields >> 5) & 0x7
    if version != SBK_VERSION_V0:
        raise ValueError(f"Unsupported Version {version}")

    paranoid = (fields >> 4) & 0x1

    f_threshold = (fields >> 0) & 0xF
    threshold   = f_threshold + 2

    # The param_cfg encoding doesn't include num_shares as it's
    # only required when originally generating the shares. The
    # minimum value is threshold, so that is what we set it to.
    num_shares = threshold

    kdf_params = kdf.KDFParams.decode(fields << 4)
    return ParamConfig(
        version=version,
        paranoid=paranoid,
        kdf_params=kdf_params,
        threshold=threshold,
        share_no=share_no,
        num_shares=num_shares,
    )


def param_cfg2bytes(param_cfg: ParamConfig) -> bytes:
    """Serialize ParamConfig.

    Since these fields are part of the salt, we try
    to keep the serialized param_cfg small and leave
    more room for randomness, hence the bit twiddling.
    """
    fields = 0
    fields |= param_cfg.version << 5
    fields |= f_threshold

    kdf_fields = param_cfg.kdf_params.encode()
    return struct.pack("!H", fields)
