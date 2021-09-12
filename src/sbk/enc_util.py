# This file is part of the SBK project
# https://github.com/mbarkhau/sbk
#
# Copyright (c) 2019-2021 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT

"""Helper functions related to data/type encoding/decoding."""

import base64
import struct


def char_at(data: bytes, i: int) -> int:
    # While SBK is not compatible with python2, this is one of the biggest
    # gochas if that were ever undertaken. I'd rather have it explicit.

    # for py2 compat
    return ord(data[i : i + 1])


def hex2bytes(hex_str: str) -> bytes:
    """Convert bytes to a hex string."""
    hex_str = hex_str.upper().zfill(2 * ((len(hex_str) + 1) // 2))
    return base64.b16decode(hex_str.encode('ascii'))


def bytes2hex(data: bytes) -> str:
    """Convert bytes to a hex string."""
    return base64.b16encode(data).decode('ascii').lower()


def bytes_hex(data: bytes) -> str:
    """Display bytes data in hex form, rather than with glyphs.

    Random data lines up nicer with this.
    """
    chars           = (data[i : i + 1] for i in range(len(data)))
    char_hex        = [bytes2hex(c).lower() for c in chars]
    char_hex_padded = (c if i % 2 == 0 else c + " " for i, c in enumerate(char_hex))
    return "".join(char_hex_padded).strip()


def bytes2bytesrepr(data: bytes) -> str:
    r"""Same as bytes.__repr__ but uses \x even for valid ascii bytes."""
    hexstr = bytes2hex(data)
    return "".join(("\\x" + hexstr[i : i + 2] for i in range(0, len(hexstr), 2)))


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


def bytes_repr(data: bytes) -> str:
    r"""Display bytes data in the \x00 form, rather than with glyphs.

    Random data lines up nicer with this.
    """

    chars      = (data[i : i + 1] for i in range(len(data)))
    char_reprs = ["\\x" + bytes2hex(c).lower() for c in chars]
    return 'b"' + "".join(char_reprs) + '"'
