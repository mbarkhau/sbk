# This file is part of the sbk project
# https://gitlab.com/mbarkhau/sbk
#
# Copyright (c) 2019 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT
"""Parameter encoding/decoding/initialization."""

import struct
import typing as typ

from . import kdf
from . import primes

Flags = int

FLAG_IS_SEGWIT = 0b0001

RAW_SALT_LEN         = 12
PARAM_CFG_LEN        = 4
SALT_LEN             = PARAM_CFG_LEN + RAW_SALT_LEN
DEFAULT_BRAINKEY_LEN = 6
SHARE_X_COORD_LEN    = 1
DEFAULT_SHARE_LEN    = PARAM_CFG_LEN + SHARE_X_COORD_LEN + RAW_SALT_LEN + DEFAULT_BRAINKEY_LEN


class ParamConfig(typ.NamedTuple):

    version     : int
    flags       : Flags
    brainkey_len: int
    threshold   : int
    num_shares  : int
    kdf_params  : kdf.KDFParams

    @property
    def raw_salt_len(self) -> int:
        return RAW_SALT_LEN

    @property
    def master_key_len(self) -> int:
        # The master key is streched a bit and the remaining
        # byte is used to encode the x coordinate of the shares.
        return self.raw_salt_len + self.brainkey_len

    @property
    def share_len(self) -> int:
        return PARAM_CFG_LEN + SHARE_X_COORD_LEN + self.master_key_len

    @property
    def prime(self) -> int:
        master_key_bits = self.master_key_len * 8
        return primes.get_pow2prime(master_key_bits)

    @property
    def is_segwit(self) -> bool:
        return self.flags & FLAG_IS_SEGWIT == 1


def init_param_config(
    brainkey_len: int,
    kdf_params  : kdf.KDFParams,
    threshold   : int,
    num_shares  : typ.Optional[int] = None,
    is_segwit   : bool = True,
) -> ParamConfig:
    _num_shares = threshold if num_shares is None else num_shares

    if threshold > _num_shares:
        err_msg = f"threshold must be <= num_shares, got {threshold} > {_num_shares}"
        raise ValueError(err_msg)

    raw_salt_len = RAW_SALT_LEN
    assert raw_salt_len % 2 == 0
    assert 4 <= raw_salt_len <= 64, raw_salt_len

    assert brainkey_len % 2 == 0
    assert 2 <= brainkey_len <= 32, brainkey_len
    assert 1 <= threshold    <= 16, threshold

    version = 0
    flags   = 0b0000
    if is_segwit:
        flags |= FLAG_IS_SEGWIT
    else:
        assert flags & FLAG_IS_SEGWIT == 0

    assert 0b0000 <= flags <= 0b1111

    param_cfg = ParamConfig(
        version=version,
        flags=flags,
        brainkey_len=brainkey_len,
        threshold=threshold,
        num_shares=_num_shares,
        kdf_params=kdf_params,
    )

    return param_cfg


"""
Data layout for reference.

|        Field        |  Size  |                          Info                           |
| ------------------- | ------ | ------------------------------------------------------- |
| `f_version`         | 4 bit  | ...                                                     |
| `f_flags`           | 4 bit  | (reserved, reserved, reserved, is_segwit)               |
| `f_brainkey_len`    | 4 bit  | max length: 2 * 2**4 = 32 bytes                         |
| `f_threshold`       | 4 bit  | minimum shares required for recovery                    |
|                     |        | max: 1..2**4 = 1..16                                    |
| `f_kdf_parallelism` | 4 bit  | `ceil(2 ** n)   = kdf_parallelism` in number of threads |
| `f_kdf_mem_cost`    | 6 bit  | `ceil(1.5 ** n) = kdf_mem_cost` in MiB                  |
| `f_kdf_time_cost`   | 6 bit  | `ceil(1.5 ** n) = kdf_time_cost` in iterations          |

0     3 4     7 8    11 12   15 16   19 20       25 26       31
[ ver ] [flags] [bkey ] [thres] [kdf_p] [ kdf_mem ] [kdf_time ]
 4bit    4bit    4bit    4bit    4bit      6bit        6bit
"""


def bytes2param_cfg(data: bytes) -> ParamConfig:
    """Deserialize ParamConfig."""
    assert len(data) >= 4
    fields_01, fields_23, fields_456 = struct.unpack("!BBH", data[:4])

    version        = (fields_01 >> 4) & 0xF
    flags          = (fields_01 >> 0) & 0xF
    f_brainkey_len = (fields_23 >> 4) & 0xF
    f_threshold    = (fields_23 >> 0) & 0xF
    assert version == 0, version

    brainkey_len = (f_brainkey_len + 1) * 2
    threshold    = f_threshold + 1

    # The param_cfg encoding doesn't include num_shares as it's
    # only required when originally generating the shares. The
    # minimum value is threshold, so that is what we set it to.
    num_shares = threshold

    kdf_params = kdf.KDFParams.decode(fields_456)
    return ParamConfig(version, flags, brainkey_len, threshold, num_shares, kdf_params)


def param_cfg2bytes(param_cfg: ParamConfig) -> bytes:
    """Serialize ParamConfig.

    Since these fields are part of the salt, we try
    to keep the serialized param_cfg small and leave
    more room for randomness, hence the bit twiddling.
    """
    assert param_cfg.raw_salt_len % 2 == 0
    assert param_cfg.brainkey_len % 2 == 0

    f_brainkey_len = (param_cfg.brainkey_len // 2) - 1
    f_threshold    = param_cfg.threshold - 1

    fields_01 = 0
    fields_01 |= param_cfg.version << 4
    fields_01 |= param_cfg.flags

    fields_23 = 0
    fields_23 |= f_brainkey_len << 4
    fields_23 |= f_threshold

    fields_456     = param_cfg.kdf_params.encode()
    param_cfg_data = struct.pack("!BBH", fields_01, fields_23, fields_456)
    return param_cfg_data
