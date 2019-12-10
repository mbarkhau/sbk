# This file is part of the SBK project
# https://gitlab.com/mbarkhau/sbk
#
# Copyright (c) 2019 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT

"""Helper functions related to data/type encoding/decoding."""

import math
import base64
import struct

from . import gf
from . import gf_poly


def char_at(data: bytes, i: int) -> int:
    # While SBK is not compatible with python2, this is one of the biggest
    # gochas if that were ever undertaken. I'd rather have it explicit.

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


def bytes2gfpoint(data: bytes, field: gf.Field) -> gf_poly.Point:
    x_data = data[:1]
    y_data = data[1:]

    x = bytes2int(x_data)
    y = bytes2int(y_data)

    if y >= field.order:
        raise ValueError(f"Invalid data for field with order={field.order}. Too large y={y}")

    return gf_poly.Point(field[x], field[y])


def gfpoint2bytes(point: gf_poly.Point) -> bytes:
    # NOTE: for x=0 or x=255 the y value may be the secret, which should not be serialized.
    x = point.x.val
    if not (0 < x < 255):
        raise ValueError(f"Invalid point with x={x}. Was not 0 < x < 255")

    num_bits  = math.ceil(math.log2(point.y.order))
    num_bytes = num_bits // 8
    x_data    = int2bytes(x)
    y_data    = int2bytes(point.y.val, num_bytes)
    assert len(x_data) == 1
    assert len(y_data) == num_bytes
    return x_data + y_data
