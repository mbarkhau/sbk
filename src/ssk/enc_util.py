# This file is part of the ssk project
# https://gitlab.com/mbarkhau/ssk
#
# Copyright (c) 2019 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT
"""Helper functions related to data/type encoding/decoding."""

import struct
import base64
import typing as typ
import itertools as it

from . import params

ADJECTIVES = [
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

TITLES = [
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

PLACES = [
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


CITIES = [
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

ADJ_LEN    = max(map(len, ADJECTIVES))
TITLE_LEN  = max(map(len, TITLES    ))
PLACES_LEN = max(map(len, PLACES    ))

PERSON_PARTS = [
    f"The {adj.upper():<{ADJ_LEN}} {title.upper():<{TITLE_LEN}}"
    for adj, title in it.product(ADJECTIVES, TITLES)
]


PLACE_PARTS = [
    f" of the {place.upper():<{PLACES_LEN}} in {city.upper()}.\n"
    for place, city in it.product(PLACES, CITIES)
]

assert len(PERSON_PARTS) == 2 ** 8
assert len(PLACE_PARTS ) == 2 ** 8


Phrase = str

TEST_PHRASE = "\n".join(
    [
        "The LIGHT GIRL   of the GARDEN in DUBLIN.",
        "The LIGHT FATHER of the GHETTO in DUBAI.",
        "The DARK  COOK   of the GARDEN in DUBAI.",
        "The GREEN DOCTOR of the GHETTO in DUBAI.",
        "The GREEN DOCTOR.",
    ]
)


def bytes2phrase(data: bytes) -> Phrase:
    r"""Encode data as a human readable phrases.

    >>> expected = TEST_PHRASE
    >>> bytes2phrase(b"test data") == expected
    True
    """

    corpus = [PERSON_PARTS, PLACE_PARTS]
    parts  = []
    for i in range(len(data)):
        part_char = data[i : i + 1]
        part_idx  = ord(part_char)
        part      = corpus[i % 2][part_idx]
        parts.append(part)

    phrase = "".join(parts)
    if len(data) % 2 != 0:
        phrase += "."

    return phrase.strip()


def phrase2bytes(phrase: Phrase) -> bytes:
    """Decode human readable phrases to bytes.

    >>> phrase2bytes(TEST_PHRASE)
    b'test data'
    """
    filler = {"the", "of", "in", ""}
    parts  = phrase.replace(".", "").lower().split()
    parts  = [p for p in parts if p not in filler]
    corpus = [ADJECTIVES, TITLES, PLACES, CITIES]

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
    assert p.kdf_param_id in params.PARAM_CONFIGS_BY_ID
    return struct.pack("BB", p.threshold, p.kdf_param_id)


def bytes2param_cfg(data: bytes) -> params.Params:
    r"""Deserialize Params.

    >>> p = bytes2param_cfg(b'\x0C\x10')
    >>> p.threshold
    12
    >>> p.param_id
    16
    """
    threshold, param_id = struct.unpack("BB", data)

    num_parts = threshold
    config    = params.PARAM_CONFIGS_BY_ID[param_id]

    return params.Params(
        threshold=threshold, num_parts=num_parts, param_id=param_id, **config
    )
