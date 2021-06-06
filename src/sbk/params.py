# This file is part of the sbk project
# https://github.com/mbarkhau/sbk
#
# Copyright (c) 2019-2021 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT
"""Parameter encoding/decoding/initialization.

Data layout for reference.

|        Field        |  Size  |                          Info                            |
| ------------------- | ------ | -------------------------------------------------------- |
| `f_version`         | 4 bit  | ...                                                      |
| `f_threshold`       | 4 bit  | minimum shares required for recovery                     |
|                     |        | max: 1..2**4 = 1..16                                     |
| `f_share_no`        | 8 bit  | For shares, the x-coordinate > 0                         |
| `f_kdf_parallelism` | 4 bit  | `ceil(2 ** n)    = kdf_parallelism` in number of threads |
| `f_kdf_mem_cost`    | 6 bit  | `ceil(1.25 ** n) = kdf_mem_cost` in MiB                  |
| `f_kdf_time_cost`   | 6 bit  | `ceil(1.5  ** n) = kdf_time_cost` in iterations          |

0     3 4     7 8    11 12       17 18       23 24            31
[ ver ] [thres] [kdf_p] [ kdf_mem ] [ kdf_time] [   share_no   ]
 4bit    4bit    4bit      6bit        6bit          8bit
"""

import os
import struct
import typing as typ

from . import kdf
from . import primes

Flags = int

SBK_VERSION_V1 = 1

DEFAULT_RAW_SALT_LEN = 10
DEFAULT_BRAINKEY_LEN = 6

ENV_RAW_SALT_LEN = os.getenv('SBK_DEBUG_RAW_SALT_LEN')
ENV_BRAINKEY_LEN = os.getenv('SBK_DEBUG_BRAINKEY_LEN')

RAW_SALT_LEN = int(ENV_RAW_SALT_LEN) if ENV_RAW_SALT_LEN else DEFAULT_RAW_SALT_LEN
BRAINKEY_LEN = int(ENV_BRAINKEY_LEN) if ENV_BRAINKEY_LEN else DEFAULT_BRAINKEY_LEN

PARAM_CFG_LEN     = 3
SHARE_X_COORD_LEN = 1
SALT_LEN          = PARAM_CFG_LEN + RAW_SALT_LEN

MASTER_KEY_LEN = RAW_SALT_LEN + BRAINKEY_LEN

SHARE_LEN = PARAM_CFG_LEN + SHARE_X_COORD_LEN + RAW_SALT_LEN + BRAINKEY_LEN

MIN_ENTROPY      = int(os.getenv('SBK_MIN_ENTROPY'     , "16"))
MAX_ENTROPY_WAIT = int(os.getenv('SBK_MAX_ENTROPY_WAIT', "10"))

DEFAULT_KDF_TARGET_DURATION = int(os.getenv('SBK_KDF_TARGET_DURATION', "90"))

DEFAULT_THRESHOLD  = int(os.getenv('SBK_THRESHOLD' , "3"))
DEFAULT_NUM_SHARES = int(os.getenv('SBK_NUM_SHARES', "5"))

# constrained by f_threshold (4bits)
MAX_THRESHOLD = 16


class ParamConfig(typ.NamedTuple):

    version   : int
    threshold : int
    num_shares: int
    kdf_params: kdf.KDFParams

    @property
    def prime(self) -> int:
        master_key_bits = MASTER_KEY_LEN * 8
        return primes.get_pow2prime(master_key_bits)


def init_param_config(
    kdf_params: kdf.KDFParams,
    threshold : int,
    num_shares: typ.Optional[int] = None,
) -> ParamConfig:
    _num_shares = threshold if num_shares is None else num_shares

    if threshold > _num_shares:
        errmsg = f"threshold must be <= num_shares, got {threshold} > {_num_shares}"
        raise ValueError(errmsg)

    if not 1 <= threshold <= MAX_THRESHOLD:
        errmsg = f"Invalid threshold {threshold}"
        raise ValueError(errmsg)

    param_cfg = ParamConfig(
        version=SBK_VERSION_V1,
        threshold=threshold,
        num_shares=_num_shares,
        kdf_params=kdf_params,
    )

    return param_cfg


def bytes2param_cfg(data: bytes) -> ParamConfig:
    """Deserialize ParamConfig from the Salt or a Share."""
    if len(data) < 3:
        errmsg = f"Invalid params len={len(data)}"
        raise ValueError(errmsg)

    # B: Unsigned Char (1 byte)
    # H: Unsigned Short (2 bytes)
    fields_01, fields_234 = struct.unpack("!BH", data[:3])

    # We don't include the share_no in the ParamConfig, it
    # is decoded separately for each share.
    # share_no = _fields_5

    version     = (fields_01 >> 4) & 0xF
    f_threshold = (fields_01 >> 0) & 0xF
    if version != SBK_VERSION_V1:
        raise Exception(f"Unsupported Version {version}")

    threshold = f_threshold + 1

    # The param_cfg encoding doesn't include num_shares as it's
    # only required when originally generating the shares. The
    # minimum value is threshold, so that is what we set it to.
    num_shares = threshold

    kdf_params = kdf.KDFParams.decode(fields_234)
    return ParamConfig(version, threshold, num_shares, kdf_params)


def param_cfg2bytes(param_cfg: ParamConfig) -> bytes:
    """Serialize ParamConfig.

    Since these fields are part of the salt, we try
    to keep the serialized param_cfg small and leave
    more room for randomness, hence the bit twiddling.
    """
    f_threshold = param_cfg.threshold - 1

    fields_01 = 0
    fields_01 |= param_cfg.version << 4
    fields_01 |= f_threshold

    fields_234     = param_cfg.kdf_params.encode()
    param_cfg_data = struct.pack("!BH", fields_01, fields_234)
    return param_cfg_data
