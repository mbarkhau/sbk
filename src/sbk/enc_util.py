# This file is part of the sbk project
# https://gitlab.com/mbarkhau/sbk
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
    "honest",
    "skinny",
    "ugly",
    "brave",
    "nobel",
    "young",
    "poor",
    "happy",
    "rich",
    "white",
    "wise",
]

TITLES = [
    "baker",
    "child",
    "doctor",
    "driver",
    "king",
    "lady",
    "leader",
    "mayor",
    "mother",
    "nurse",
    "priest",
    "prince",
    "queen",
    "sister",
    "waiter",
    "worker",
]

CITIES = [
    "berlin",
    "cairo",
    "chicago",
    "delhi",
    "dubai",
    "dublin",
    "lagos",
    "london",
    "madrid",
    "miami",
    "moscow",
    "paris",
    "prague",
    "sparta",
    "tokyo",
    "vienna",
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


ADJECTIVES.sort()
TITLES.sort()
CITIES.sort()
PLACES.sort()

ADJ_LEN    = max(map(len, ADJECTIVES))
TITLE_LEN  = max(map(len, TITLES    ))
PLACES_LEN = max(map(len, PLACES    ))
CITIES_LEN = max(map(len, CITIES    ))

PERSON_PARTS = [
    f"The {adj.upper():<{ADJ_LEN}} {title.upper():<{TITLE_LEN}}"
    for adj, title in it.product(ADJECTIVES, TITLES)
]


PLACE_PARTS = [
    f" at the {city.upper():<{CITIES_LEN}} {place.upper()}.\n"
    for city, place in it.product(CITIES, PLACES)
]

assert len(PERSON_PARTS) == 2 ** 8
assert len(PLACE_PARTS ) == 2 ** 8


Phrase = str

TEST_PHRASE_LINES = [
    "The HONEST KING   at the LAGOS   FOREST.",
    "The HONEST DRIVER at the LONDON  FARM.",
    "The BRAVE  BAKER  at the LAGOS   FARM.",
    "The HAPPY  CHILD  at the LONDON  FARM.",
    "The HAPPY  CHILD.",
]

TEST_PHRASE = "\n".join(TEST_PHRASE_LINES)


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
        phrase = phrase.strip() + "."

    return phrase.strip()


def phrase2bytes(phrase: Phrase) -> bytes:
    """Decode human readable phrases to bytes.

    >>> phrase2bytes(TEST_PHRASE)
    b'test data'
    """
    filler = {"the", "at", ""}
    parts  = phrase.replace(".", "").lower().split()
    parts  = [p for p in parts if p not in filler]
    corpus = [ADJECTIVES, TITLES, CITIES, PLACES]

    data: typ.List[int] = []

    for i, part in enumerate(parts):
        corpus_words = corpus[i % 4]
        part_idx     = corpus_words.index(part)
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
    '0123456789abcdef'
    """
    return base64.b16encode(data).decode('ascii').lower()


def hex2bytes(hex_str: str) -> bytes:
    r"""Convert bytes to a hex string.

    >>> hex2bytes('746573742064617461')
    b'test data'
    >>> expected = b'\x01\x23\x45\x67\x89\xAB\xCD\xEF'
    >>> hex2bytes("0123456789ABCDEF") == expected
    True
    >>> hex2bytes("0123456789abcdef") == expected
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


def bytes_hex(data: bytes) -> str:
    r"""Display bytes data in hex form, rather than with glyphs.

    Random data lines up nicer with this.
    """
    chars    = (data[i : i + 1] for i in range(len(data)))
    char_hex = [bytes2hex(c).lower() for c in chars]
    return "".join(
        c if i % 2 == 0 else c + " " for i, c in enumerate(char_hex)
    ).strip()


def bytes_repr(data: bytes) -> str:
    r"""Display bytes data in the \x00 form, rather than with glyphs.

    Random data lines up nicer with this.
    """

    chars      = (data[i : i + 1] for i in range(len(data)))
    char_reprs = ["\\x" + bytes2hex(c).lower() for c in chars]
    return 'b"' + "".join(char_reprs) + '"'


def params2bytes(p: params.Params) -> bytes:
    r"""Serialize Params.

    >>> p = params.init_params(12, 13, 16)
    >>> params2bytes(p)
    b'\x05\x0c\x10'
    """
    assert p.kdf_param_id in params.PARAM_CONFIGS_BY_ID
    assert p.ecc_len < 16
    sbk_version = 0
    ver_and_ecc = (sbk_version << 4) | p.ecc_len
    args        = (ver_and_ecc, p.threshold, p.kdf_param_id)
    return struct.pack("BBB", *args)


def bytes2params(data: bytes) -> params.Params:
    r"""Deserialize Params.

    >>> p = bytes2params(b'\x05\x0C\x10')
    >>> p.threshold
    12
    >>> p.kdf_param_id
    16
    >>> p.ecc_len
    5
    """
    ver_and_ecc, threshold, kdf_param_id = struct.unpack("BBB", data)
    ecc_len = ver_and_ecc & 0xF
    version = (ver_and_ecc >> 4) & 0xF
    assert version == 0

    num_pieces = threshold
    config     = params.PARAM_CONFIGS_BY_ID[kdf_param_id]

    return params.Params(
        threshold=threshold,
        num_pieces=num_pieces,
        kdf_param_id=kdf_param_id,
        ecc_len=ecc_len,
        **config,
    )
