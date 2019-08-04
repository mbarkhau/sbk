# This file is part of the sbk project
# https://gitlab.com/mbarkhau/sbk
#
# Copyright (c) 2019 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT
"""Helper functions related to data/type encoding/decoding."""

import re
import math
import struct
import base64
import typing as typ
import itertools as it

from . import ecc
from . import params
from . import polynom


ADJECTIVES = [
    "brave",
    "crazy",
    "dirty",
    "evil",
    "fancy",
    "funny",
    "guilty",
    "happy",
    "heavy",
    "honest",
    "lonely",
    "nobel",
    "polite",
    "pretty",
    "scary",
    "ugly",
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
    "oslo",
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
    "stage",
    "temple",
]


ADJECTIVES.sort()
TITLES.sort()
CITIES.sort()
PLACES.sort()

assert max(map(len, ADJECTIVES)) == 6
assert max(map(len, TITLES    )) == 6
assert max(map(len, PLACES    )) == 6
assert max(map(len, CITIES    )) == 6


PERSON_PARTS = [
    f"The {adj.upper():<6} {title.upper():<6}"
    for adj, title in it.product(ADJECTIVES, TITLES)
]


PLACE_PARTS = [
    f" at the {city.upper():<6} {place.upper()}.\n"
    for city, place in it.product(CITIES, PLACES)
]

assert len(PERSON_PARTS) == 2 ** 8
assert len(PLACE_PARTS ) == 2 ** 8

# Generate output for test/test_enc_util.py
# for person, place in zip(PERSON_PARTS, PLACE_PARTS):
#     print(person, place, end="")


def _char_at(data: bytes, i: int) -> int:
    # for py2 compat
    return ord(data[i : i + 1])


PhraseStr = str


def _bytes2phrase_parts(data: bytes) -> typ.Iterable[str]:
    corpus = [PERSON_PARTS, PLACE_PARTS]

    for i in range(len(data)):
        part_idx = _char_at(data, i)
        part     = corpus[i % 2][part_idx]
        yield part


def bytes2phrase(data: bytes) -> PhraseStr:
    r"""Encode data as a human readable phrases."""
    phrase = "".join(_bytes2phrase_parts(data))
    if len(data) % 2 != 0:
        phrase = phrase.strip() + "."
    return phrase.strip()


def phrase2bytes(phrase: PhraseStr) -> bytes:
    """Decode human readable phrases to bytes."""
    corpus = [ADJECTIVES, TITLES, CITIES, PLACES]

    filler = {"the", "at", ""}
    parts  = phrase.replace(".", "").lower().split()
    parts  = [p for p in parts if p not in filler]

    data: typ.List[int] = []
    for i, part in enumerate(parts):
        corpus_words = corpus[i % 4]
        part_idx     = corpus_words.index(part)
        if i % 2 == 0:
            data.append(part_idx << 4)
        else:
            data[-1] += part_idx

    # NOTE: python3 specific
    return bytes(data)


def bytes2hex(data: bytes) -> str:
    """Convert bytes to a hex string."""
    return base64.b16encode(data).decode('ascii').lower()


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
    char_hex_padded = (
        c if i % 2 == 0 else c + " " for i, c in enumerate(char_hex)
    )
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
    sbk_version, threshold, pow2prime_idx, kdf_param_id = struct.unpack(
        "BBBB", data
    )
    assert sbk_version == 0

    # decoded params doesn't include num_pieces as it's only required
    # when originally generating the pieces.
    num_pieces = threshold
    config     = params.PARAM_CONFIGS_BY_ID[kdf_param_id]

    return params.Params(
        threshold=threshold,
        num_pieces=num_pieces,
        pow2prime_idx=pow2prime_idx,
        kdf_param_id=kdf_param_id,
        **config,
    )


def params2bytes(p: params.Params) -> bytes:
    """Serialize Params."""
    assert p.kdf_param_id in params.PARAM_CONFIGS_BY_ID
    sbk_version = 0
    return struct.pack(
        "BBBB", sbk_version, p.threshold, p.pow2prime_idx, p.kdf_param_id
    )


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


PartIndex = int
PartVal   = bytes
Part      = typ.Tuple[PartIndex, PartVal]


IntCode       = str
IntCodes      = typ.Sequence[str]
MaybeIntCodes = typ.Sequence[typ.Optional[str]]
IntCodeParts  = typ.Sequence[Part]


def _bytes2intcode_parts(data: bytes) -> typ.Iterable[str]:
    for idx in range(len(data)):
        part_no = (idx % 34) + 4
        assert 4 <= part_no <= 37
        part_val = _char_at(data, idx)
        part_num = (part_no << 8) + part_val
        assert 1024 <= part_num <= 9983
        yield str(part_num)


def bytes2intcode(data: bytes) -> IntCode:
    """Encode data to intcode.

    The main purpose of the intcode format is to be
    compact, redundant and resilient to input errors.
    """
    data_with_ecc = ecc.encode(data)
    return "\n".join(_bytes2intcode_parts(data_with_ecc))


def _intcode2bytes_parts(intcodes: MaybeIntCodes) -> typ.Iterable[Part]:
    """Decode part index and part values.

    Since the range for part numbers is limited, we assume
    consecutive input for intcodes longer than 34 bytes.
    """
    part_no_offset = 0
    prev_part_no   = 3
    for part in intcodes:
        if part is None:
            continue

        part_num = int(part, 10)
        part_no  = part_num >> 8

        if part_no < prev_part_no:
            # assume the wrap around happened
            part_no_offset += 34

        prev_part_no = part_no

        part_val = bytes([part_num & 0xFF])
        idx      = (part_no_offset + part_no) - 4
        yield idx, part_val


def intcode_parts2packets(
    intcodes: IntCodes, packet_size: int
) -> typ.List[bytes]:
    num_packets = len(intcodes) // packet_size
    packets     = [b""] * num_packets
    for idx, part_val in _intcode2bytes_parts(intcodes):
        packets[idx // packet_size] += part_val
    return packets


def intcode_parts2bytes(intcodes: IntCodes, block_len: int) -> bytes:
    packet_size = block_len // 8  # aka. parts per packet
    packets     = intcode_parts2packets(intcodes, packet_size)

    # NOTE: It is unfortunate that missing one part makes
    #   the whole packet ivalid. A better ECC algo would
    #   make use of all available parts.
    maybe_packets: ecc.MaybePackets = [
        pkt if len(pkt) == packet_size else None for pkt in packets
    ]
    return ecc.decode_packets(maybe_packets)


def intcode2bytes(intcode: IntCode) -> bytes:
    intcodes = typ.cast(IntCodes, intcode.splitlines())
    return intcode_parts2bytes(intcodes, block_len=len(intcodes))


# https://regex101.com/r/iQKt5L/2
FORMATTED_LINE_PATTERN = r"""
[AB]\d:[ ]
    (\d{4})
    [ ]
    (\d{4})
\s+
The[ ]
    ([A-Z]+)\s+([A-Z]+)
\s+at[ ]the[ ]
    ([A-Z]+)\s+([A-Z]+)\.
\s+
[CD]\d:[ ]
    (\d{4})
    [ ]
    (\d{4})
"""


FORMATTED_LINE_RE = re.compile(FORMATTED_LINE_PATTERN, flags=re.VERBOSE)


Lines = typ.Iterable[str]


def format_secret(data: bytes, add_ecc=True) -> Lines:
    phrase = bytes2phrase(data)
    assert phrase2bytes(phrase) == data

    if add_ecc:
        intcode = bytes2intcode(data)
        assert intcode2bytes(intcode) == data
    else:
        # This allows the function to be used when
        # only part of the secret has been input.
        intcode = "\n".join(_bytes2intcode_parts(data))

    phrase_lines    = phrase.splitlines()
    split_offset    = len(phrase_lines) // 2
    phrases_padding = max(map(len, phrase_lines))

    intcodes   = intcode.splitlines()
    ecc_offset = len(intcodes) // 2

    for i, phrase_line in enumerate(phrase_lines):
        if i == split_offset:
            yield ""

        data_0 = intcodes[i * 2]
        data_1 = intcodes[i * 2 + 1]

        if add_ecc:
            ecc_0 = intcodes[ecc_offset + i * 2]
            ecc_1 = intcodes[ecc_offset + i * 2 + 1]
        else:
            ecc_0 = ecc_1 = ""

        marker_id = i % split_offset
        prefix_id = f"A{marker_id}" if i < split_offset else f"B{marker_id}"
        suffix_id = f"C{marker_id}" if i < split_offset else f"D{marker_id}"

        prefix   = f"{prefix_id}: {data_0} {data_1}"
        suffix   = f"{suffix_id}: {ecc_0} {ecc_1}"
        out_line = f"{prefix}   {phrase_line:<{phrases_padding}}   {suffix}"
        yield out_line


class ParsedSecret(typ.NamedTuple):
    phrases   : typ.List[str]
    data_codes: typ.List[str]
    ecc_codes : typ.List[str]


def parse_formatted_secret(text: str) -> ParsedSecret:
    phrases   : typ.List[str] = []
    data_codes: typ.List[str] = []
    ecc_codes : typ.List[str] = []

    for i, line in enumerate(text.splitlines()):
        if not line.strip():
            continue
        line_no = i + 1

        match = FORMATTED_LINE_RE.match(line.strip())
        if match is None:
            err_msg = f"Invalid input at line {line_no}: {line}"
            raise Exception(err_msg)

        (data_0, data_1, p0, p1, p2, p3, ecc_0, ecc_1) = match.groups()

        data_codes.extend([data_0, data_1])
        phrases.extend([p0, p1, p2, p3])
        ecc_codes.extend([ecc_0, ecc_1])

    return ParsedSecret(phrases, data_codes, ecc_codes)
