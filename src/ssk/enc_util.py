# This file is part of the ssk project
# https://gitlab.com/mbarkhau/ssk
#
# Copyright (c) 2019 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT
import struct
import base64
import typing as typ
import itertools as it

from . import params

adjectives = [
    "black",
    "blue",
    "dark",
    "evil",
    "fresh",
    "good",
    "green",
    "light",
    "new",
    "nobel",
    "old",
    "poor",
    "red",
    "rich",
    "white",
    "wise",
]

titles = [
    "cook",
    "doctor",
    "elder",
    "father",
    "girl",
    "king",
    "leader",
    "maid",
    "mayor",
    "mother",
    "nurse",
    "priest",
    "prince",
    "queen",
    "sister",
    "uncle",
]

places = [
    "beach",
    "bridge",
    "castle",
    "church",
    "farm",
    "forest",
    "garden",
    "ghetto",
    "hotel",
    "lake",
    "oasis",
    "opera",
    "river",
    "school",
    "temple",
    "zoo",
]


cities = [
    "athens",
    "berlin",
    "cairo",
    "delhi",
    "dubai",
    "dublin",
    "lagos",
    "london",
    "madrid",
    "moscow",
    "paris",
    "prague",
    "rome",
    "tokyo",
    "vienna",
    "york",
]


PERSON_PARTS = [
    f"The {adj.upper()} {title.upper()}"
    for adj, title in it.product(adjectives, titles)
]


PLACE_PARTS = [
    f" of the {place.upper()} in {city.upper()}.\n"
    for place, city in it.product(places, cities)
]

assert len(PERSON_PARTS) == 2 ** 8
assert len(PLACE_PARTS ) == 2 ** 8


Phrase = str


def encode(data: bytes) -> Phrase:
    if len(data) % 2 != 0:
        raise ValueError("len(data) must be divisible by 2.")

    corpus = [PERSON_PARTS, PLACE_PARTS]
    parts  = []
    for i in range(len(data)):
        part_char = data[i : i + 1]
        part_idx  = ord(part_char)
        part      = corpus[i % 2][part_idx]
        parts.append(part)

    return "".join(parts)


def decode(phrase: Phrase) -> bytes:
    filler = {"the", "of", "in", ""}
    parts  = phrase.replace(".", "").lower().split()
    parts  = [p for p in parts if p not in filler]
    corpus = [adjectives, titles, places, cities]

    data: typ.List[int] = []

    for i, part in enumerate(parts):
        part_idx = corpus[i % 4].index(part)
        if i % 2 == 0:
            data.append(part_idx << 4)
        else:
            data[-1] += part_idx

    return bytes(data)


def bytes2hex(data: bytes) -> str:
    r"""Convert bytes to a hex string.

    >>> bytes2hex('test data'.encode('ascii'))
    '746573742064617461'
    >>> bytes2hex(b'\x01\x23\x45\x67\x89\xAB\xCD\xEF')
    '0123456789ABCDEF'
    """
    return base64.b16encode(data).decode('ascii')


def hex2bytes(hex_str: str) -> bytes:
    r"""Convert bytes to a hex string.

    >>> hex2bytes('746573742064617461')
    b'test data'
    >>> expected = b'\x01\x23\x45\x67\x89\xAB\xCD\xEF'
    >>> hex2bytes("0123456789ABCDEF") == expected
    True
    """
    hex_str = hex_str.upper().zfill(2 * ((len(hex_str) + 1) // 2))
    return base64.b16decode(hex_str.encode('ascii'))


def bytes2int(data: bytes) -> int:
    r"""Convert bytes to (arbitrary sized) integers.

    Parsed in big-endian order.

    >>> bytes2int(b"")
    0
    >>> bytes2int(b"\x01")
    1
    >>> bytes2int(b"\xff")
    255
    >>> bytes2int(b"\x12\x34") == 0x1234
    True
    >>> num = 2**(128 + 8) - 2
    >>> data = b"\xff" * 16 + b"\xfe"
    >>> bytes2int(data) == num
    True
    """
    # NOTE: ord(data[i:i+1]) is done for python2 compatability as
    #   data[i] and iteration over bytes has different semantics
    #   depending on the version of python.
    num = 0
    for i in range(len(data)):
        num = num << 8
        num = num | ord(data[i : i + 1])
    return num


def int2bytes(num: int) -> bytes:
    r"""Convert (arbitrary sized) int to bytes.

    Serialized in big-endian order.
    Only positive integers can be encoded.

    >>> int2bytes(0)
    b''
    >>> int2bytes(1)
    b'\x01'
    >>> int2bytes(255)
    b'\xff'
    >>> int2bytes(0x1234) == b'\x12\x34'
    True
    >>> num = 2**(128 + 8) - 2
    >>> data = b"\xff" * 16 + b"\xfe"
    >>> int2bytes(num) == data
    True
    """
    assert num >= 0

    parts = []
    while num:
        parts.append(struct.pack("<B", num & 0xFF))
        num = num >> 8
    return b"".join(reversed(parts))


def bytes_repr(data: bytes) -> str:
    r"""Display bytes data in the \x00 form, rather than with glyphs.

    Random data lines up nicer with this.
    """

    chars      = (data[i : i + 1] for i in range(len(data)))
    char_reprs = ["\\x" + bytes2hex(c).lower() for c in chars]
    return 'b"' + "".join(char_reprs) + '"'


def params2bytes(p: params.Params) -> bytes:
    r"""Serialize Params.

    >>> p = params.new_params(12, 13, 16)
    >>> params2bytes(p)
    b'\x0c\x10'
    """
    assert p.config_id in params.PARAMS_CONFIGS_BY_ID
    return struct.pack("BB", p.threshold, p.config_id)


def bytes2params(data: bytes) -> params.Params:
    r"""Deserialize Params.

    >>> p = bytes2params(b'\x0C\x10')
    >>> p.threshold
    12
    >>> p.config_id
    16
    """
    threshold, config_id = struct.unpack("BB", data)

    num_parts = threshold
    config    = params.PARAMS_CONFIGS_BY_ID[config_id]

    return params.Params(
        threshold=threshold, num_parts=num_parts, config_id=config_id, **config
    )
