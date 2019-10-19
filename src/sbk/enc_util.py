# This file is part of the SBK project
# https://gitlab.com/mbarkhau/sbk
#
# Copyright (c) 2019 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT

"""Helper functions related to data/type encoding/decoding."""

import math
import base64
import struct

from . import params
from . import primes
from . import polynom


def char_at(data: bytes, i: int) -> int:
    # for py2 compat
    return ord(data[i : i + 1])


def bytes2hex(data: bytes) -> str:
    """Convert bytes to a hex string."""
    return base64.b16encode(data).decode('ascii').lower()


def bytes2bytesrepr(data: bytes) -> str:
    r"""Same as bytes.__repr__ but uses \x even for valid ascii bytes."""
    hexstr = bytes2hex(data)
    return "".join(("\\x" + hexstr[i : i + 2] for i in range(0, len(hexstr), 2)))


def hex2bytes(hex_str: str) -> bytes:
    """Convert bytes to a hex string."""
    hex_str = hex_str.upper().zfill(2 * ((len(hex_str) + 1) // 2))
    return base64.b16decode(hex_str.encode('ascii'))


def bytes2int(data: bytes) -> int:
    r"""Convert bytes to (arbitrary sized) integers.

    Parsed in big-endian order.
    """
    # NOTE: ord(data[i : i + 1]) is done for backward compatability
    #   with python2. This is because data[i] and iteration over bytes
    #   has different semantics depending on the version of python.
    num = 0
    for i in range(len(data)):
        num = num << 8
        num = num | ord(data[i : i + 1])
    return num


def int2bytes(num: int, zfill_bytes: int = 1) -> bytes:
    """Convert (arbitrary sized) int to bytes.

    Serialized in big-endian order.
    Only integers >= 0 are allowed.
    """
    assert num >= 0

    parts = []
    while num:
        parts.append(struct.pack("<B", num & 0xFF))
        num = num >> 8

    while len(parts) < zfill_bytes:
        parts.append(b"\x00")

    return b"".join(reversed(parts))


def bytes_hex(data: bytes) -> str:
    """Display bytes data in hex form, rather than with glyphs.

    Random data lines up nicer with this.
    """
    chars           = (data[i : i + 1] for i in range(len(data)))
    char_hex        = [bytes2hex(c).lower() for c in chars]
    char_hex_padded = (c if i % 2 == 0 else c + " " for i, c in enumerate(char_hex))
    return "".join(char_hex_padded).strip()


def bytes_repr(data: bytes) -> str:
    r"""Display bytes data in the \x00 form, rather than with glyphs.

    Random data lines up nicer with this.
    """

    chars      = (data[i : i + 1] for i in range(len(data)))
    char_reprs = ["\\x" + bytes2hex(c).lower() for c in chars]
    return 'b"' + "".join(char_reprs) + '"'


def bytes2params(data: bytes) -> params.Params:
    """Deserialize Params."""
    field0_data = data[0:1]
    (field0,) = struct.unpack("B", field0_data)
    sbk_version        = field0 >> 4
    master_key_len_num = field0 & 0x0F

    if sbk_version == 0:
        (field1,) = struct.unpack("B", data[1:2])
        threshold_num = field1 >> 5
        kdf_param_id  = field1 & 0x1F
    elif sbk_version == 1:
        (field1, field2) = struct.unpack("BB", data[1:3])
        threshold_num = field1
        kdf_param_id  = field2
    else:
        raise Exception("Invalid/Unknown/Incompatible SBK Version")

    # decoded params doesn't include num_shares as it's only required
    # when originally generating the shares.
    num_shares = threshold_num + 1
    config     = params.PARAM_CONFIGS_BY_ID[kdf_param_id]

    master_key_len = (master_key_len_num + 1) * 4
    pow2prime_idx  = primes.get_pow2prime_index(master_key_len * 8)

    return params.Params(
        threshold=num_shares,
        num_shares=num_shares,
        pow2prime_idx=pow2prime_idx,
        kdf_param_id=kdf_param_id,
        master_key_len=master_key_len,
        **config,
    )


def params2bytes(p: params.Params) -> bytes:
    """Serialize Params.

    Since these fields are part of the salt,
    we try to keep the serialized params small
    and leave more room for randomness.
    """
    hash_len_num = p.key_len_bytes // 4 - 1
    assert 0 <= hash_len_num < 2 ** 4

    threshold_num = p.threshold - 1
    assert 0 <= threshold_num  < 2 ** 8
    assert 0 <= p.kdf_param_id < 2 ** 8

    if threshold_num < 2 ** 3 and p.kdf_param_id < 2 ** 5:
        sbk_version = 0
    else:
        sbk_version = 1

    field0 = (sbk_version << 4) + hash_len_num

    if sbk_version == 0:
        field1 = (threshold_num << 5) + p.kdf_param_id
        return struct.pack("BB", field0, field1)
    else:
        field1 = threshold_num
        field2 = p.kdf_param_id
        return struct.pack("BBB", field0, field1, field2)


def bytes2gfpoint(data: bytes, gf: polynom.GF) -> polynom.GFPoint:
    x_data = data[:1]
    y_data = data[1:]
    x      = bytes2int(x_data)
    y      = bytes2int(y_data)

    if y >= gf.p:
        raise Exception(f"Invalid prime for point with y >= {gf.p}")

    return polynom.Point(gf[x], gf[y])


def gfpoint2bytes(point: polynom.GFPoint) -> bytes:
    x = point.x.val
    if x == 0:
        # NOTE: for x=0 the y value is the secret
        raise Exception(f"Invalid point with x={x} == 0")
    if x >= 256:
        raise Exception(f"Invalid point with x={x} >= 256")

    bits        = int(math.ceil(math.log2(point.y.p)))
    zfill_bytes = bits // 8
    x_data      = int2bytes(x)
    y_data      = int2bytes(point.y.val, zfill_bytes)
    assert len(x_data) == 1
    return x_data + y_data
