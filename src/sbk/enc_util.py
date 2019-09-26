# This file is part of the sbk project
# https://gitlab.com/mbarkhau/sbk
#
# Copyright (c) 2019 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT
"""Helper functions related to data/type encoding/decoding."""

import re
import math
import base64
import struct
import typing as typ
import itertools as it

import pylev

from . import ecc
from . import params
from . import primes
from . import polynom

ADJECTIVES = [
    "brave",
    "crazy",
    "dirty",
    "evil",
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
    "vapid",
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
    "prince",
    "queen",
    "sister",
    "tailor",
    "waiter",
    "worker",
]

CITIES = [
    "berlin",
    "cairo",
    "oslo",
    "delhi",
    "dublin",
    "lagos",
    "london",
    "madrid",
    "miami",
    "moscow",
    "paris",
    "prague",
    "sparta",
    "seoul",
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
    "museum",
    "oasis",
    "opera",
    "school",
    "stage",
    "temple",
]


ADJECTIVES.sort()
TITLES.sort()
CITIES.sort()
PLACES.sort()

WORDS = set(ADJECTIVES + TITLES + CITIES + PLACES)

for _w in WORDS:
    assert len(_w) <= 6, _w

assert len(WORDS) == 16 * 4


EMPTY_PHRASE_LINE = "The ______ ______ at the ______ ______."


PERSON_PARTS = [
    f"The {adj.upper():<6} {title.upper():<6}" for adj, title in it.product(ADJECTIVES, TITLES)
]


PLACE_PARTS = [
    f" at the {city.upper():<6} {place.upper()}.\n" for city, place in it.product(CITIES, PLACES)
]

assert len(PERSON_PARTS) == 2 ** 8
assert len(PLACE_PARTS ) == 2 ** 8

# If corpus words change, regenerate output for
#   test/test_enc_util.py@TEST_PHRASE_LINES
# for person_part, place_part in zip(PERSON_PARTS, PLACE_PARTS):
#     print(f'    "{person_part} {place_part.strip()}",')


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


def _phrase2parts(cleaned_parts: typ.List[str]) -> typ.Iterable[str]:
    corpus    = [ADJECTIVES, TITLES, CITIES, PLACES]
    all_words = set(sum(corpus, []))
    dist_fn   = pylev.damerau_levenshtein

    for i, part in enumerate(cleaned_parts):
        corpus_words = corpus[i % 4]
        if part in corpus_words:
            yield part
        else:
            dist_part_pairs = [
                (dist_fn(corpus_word, part), corpus_word) for corpus_word in corpus_words
            ]
            dist_part_pairs.sort()
            dist, corpus_word = dist_part_pairs[0]
            if dist <= 3:
                yield corpus_word
            elif part in all_words:
                errmsg = f"Invalid word order: {part}"
                raise ValueError(errmsg, part)
            else:
                errmsg = f"Unknown word: {part}"
                raise ValueError(errmsg, part)


def phrase2parts(phrase: PhraseStr) -> typ.List[str]:
    filler        = {"the", "at", "teh", "th", "atthe", "att", "he", "eat", ""}
    unclean_parts = phrase.replace(".", "").lower().split()
    cleaned_parts = [p for p in unclean_parts if p not in filler]

    return list(_phrase2parts(cleaned_parts))


def phrase2bytes(phrase: PhraseStr) -> bytes:
    """Decode human readable phrases to bytes."""
    corpus = [ADJECTIVES, TITLES, CITIES, PLACES]

    parts = phrase2parts(phrase)

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


def bytes2bytesrepr(data: bytes) -> str:
    """Same as bytes.__repr__ but uses \\x even for valid ascii bytes."""
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
    sbk_version  = field0 >> 4
    hash_len_num = field0 & 0x0F

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

    # decoded params doesn't include num_pieces as it's only required
    # when originally generating the pieces.
    num_pieces = threshold_num + 1
    config     = params.PARAM_CONFIGS_BY_ID[kdf_param_id]

    key_len_bytes = (hash_len_num + 1) * 4
    pow2prime_idx = primes.get_pow2prime_index(key_len_bytes * 8)

    return params.Params(
        threshold=num_pieces,
        num_pieces=num_pieces,
        pow2prime_idx=pow2prime_idx,
        kdf_param_id=kdf_param_id,
        key_len_bytes=key_len_bytes,
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


PartIndex = int
PartVal   = bytes
PartVals  = typ.Sequence[PartVal]

IntCode       = str
IntCodes      = typ.Sequence[IntCode]
MaybeIntCodes = typ.Sequence[typ.Optional[IntCode]]


def bytes2intcode_parts(data: bytes, idx_offset: int = 0) -> typ.Iterable[IntCode]:
    if len(data) % 2 != 0:
        errmsg = f"Invalid data, must be divisible by 2, got: {len(data)}"
        raise ValueError(errmsg)

    for i in range(len(data) // 2):
        idx     = idx_offset + i
        chk_idx = idx % 13

        byte0 = _char_at(data, i * 2 + 0)
        byte1 = _char_at(data, i * 2 + 1)

        bits = chk_idx << 16
        bits |= byte0 << 8
        bits |= byte1
        assert bits <= 999999
        yield f"{bits:06}"


def bytes2intcodes(data: bytes) -> IntCodes:
    """Encode data to intcode.

    The main purpose of the intcode format is to be
    compact, redundant and resilient to input errors.
    """
    data_with_ecc = ecc.encode(data)
    return list(bytes2intcode_parts(data_with_ecc))


def intcodes2parts(intcodes: MaybeIntCodes, idx_offset: int = 0) -> PartVals:
    """Decode and and validate intcodes to parts."""
    expected_chk_idx = idx_offset % 13
    chk_idx_offset   = idx_offset - expected_chk_idx

    part_vals = [b""] * (len(intcodes) * 2)

    for intcode in intcodes:
        next_chk_idx = (expected_chk_idx + 1) % 13
        if intcode:
            bits = int(intcode, 10)

            chk_idx = bits >> 16
            byte0   = (bits >> 8) & 0xFF
            byte1   = bits & 0xFF

            idx = chk_idx_offset + chk_idx

            if chk_idx != expected_chk_idx:
                raise ValueError("Invalid code: Bad order.")

            part_vals[idx * 2 + 0] = bytes([byte0])
            part_vals[idx * 2 + 1] = bytes([byte1])

        if next_chk_idx < expected_chk_idx:
            # Since the range for part numbers is
            # limited, we assume consecutive input
            # to validate chk_idx.
            #
            # chk_idx  ... 11, 12,  0,  1,  2 ...
            # part_idx ... 11, 12, 13, 14, 15 ...
            chk_idx_offset += 13

        expected_chk_idx = next_chk_idx

    return part_vals


def parts2packets(parts: PartVals, packet_len: int) -> ecc.MaybePackets:
    num_packets = len(parts) // packet_len
    assert num_packets == 8

    packets = [b""] * num_packets
    for idx, part_val in enumerate(parts):
        if part_val != b"":
            packets[idx // packet_len] += part_val

    # NOTE: It is unfortunate that only a full packet is
    #   considered valid. A better ECC algo would make
    #   use of all available data.

    return [(pkt if len(pkt) == packet_len else None) for pkt in packets]


def intcode_parts2bytes(intcodes: MaybeIntCodes) -> bytes:
    data_with_ecc = intcodes2parts(intcodes)
    block_len     = len(data_with_ecc)
    if block_len % 8 != 0:
        errmsg = f"Invalid len(data_with_ecc)={len(data_with_ecc)}, must be divisible by 8"
        raise ValueError(errmsg)

    packet_len    = block_len // 8  # aka. parts per packet
    maybe_packets = parts2packets(data_with_ecc, packet_len)

    return ecc.decode_packets(maybe_packets)


def intcodes2bytes(intcodes: IntCodes) -> bytes:
    return intcode_parts2bytes(intcodes)


def is_completed_intcodes(intcodes: MaybeIntCodes) -> bool:
    complete_intcodes = [intcode for intcode in intcodes if intcode]
    if len(complete_intcodes) < len(intcodes):
        return False

    try:
        intcode_parts2bytes(complete_intcodes)
        return True
    except ValueError:
        return False


# https://regex101.com/r/iQKt5L/3
FORMATTED_LINE_PATTERN = r"""
[AB]\d:[ ]
    (\d{6})
\s+
The[ ]
    ([A-Z]+)\s+([A-Z]+)
\s+at[ ]the[ ]
    ([A-Z]+)\s+([A-Z]+)\.
\s+
[CD]\d:[ ]
    (\d{6})
"""


FORMATTED_LINE_RE = re.compile(FORMATTED_LINE_PATTERN, flags=re.VERBOSE)


Lines = typ.Iterable[str]

PhraseLines = typ.Sequence[str]


def format_partial_secret_lines(phrase_lines: PhraseLines, intcodes: MaybeIntCodes) -> Lines:
    ecc_offset      = len(intcodes    ) // 2
    spacer_offset   = len(phrase_lines) // 2
    phrases_padding = max(map(len, phrase_lines))

    yield f"       Data      {'Phrases':^{phrases_padding}}         ECC"
    yield ""

    for i, pl in enumerate(phrase_lines):
        if i == spacer_offset:
            yield ""

        ecc_idx      = ecc_offset + i
        data_intcode = intcodes[i]
        ecc_intcode  = intcodes[ecc_idx]

        data = "______" if data_intcode is None else data_intcode
        ecc  = "______" if ecc_intcode  is None else ecc_intcode

        marker_id = i % spacer_offset
        prefix_id = f"A{marker_id}" if i < spacer_offset else f"B{marker_id}"
        suffix_id = f"C{marker_id}" if i < spacer_offset else f"D{marker_id}"

        prefix = f"{prefix_id}: {data} "
        suffix = f"{suffix_id}: {ecc} "

        phrase_line = EMPTY_PHRASE_LINE if pl is None else pl
        out_line    = f"{prefix}  {phrase_line:<{phrases_padding}}  {suffix}"
        yield out_line


def format_secret_lines(data: bytes, add_ecc=True) -> Lines:
    phrase = bytes2phrase(data)
    assert phrase2bytes(phrase) == data
    phrase_lines = phrase.splitlines()

    intcodes: MaybeIntCodes

    if add_ecc:
        intcodes = bytes2intcodes(data)
        assert intcodes2bytes(intcodes) == data
    else:
        # This allows the function to be used when
        # only part of the secret has been input.
        intcodes = list(bytes2intcode_parts(data))
        intcodes.extend([None] * len(intcodes))

    return format_partial_secret_lines(phrase_lines, intcodes)


def format_secret(data: bytes, add_ecc=True) -> str:
    return "\n".join(format_secret_lines(data, add_ecc))


class ParsedSecret(typ.NamedTuple):
    phrases   : typ.List[str]
    data_codes: typ.List[IntCode]
    ecc_codes : typ.List[IntCode]


def parse_formatted_secret(text: str) -> ParsedSecret:
    phrases   : typ.List[str    ] = []
    data_codes: typ.List[IntCode] = []
    ecc_codes : typ.List[IntCode] = []

    for i, line in enumerate(text.splitlines()):
        if line.strip().startswith("Data"):
            continue
        if not line.strip():
            continue
        line_no = i + 1

        match = FORMATTED_LINE_RE.match(line.strip())
        if match is None:
            err_msg = f"Invalid input at line {line_no}: {line}"
            raise Exception(err_msg)

        (data, p0, p1, p2, p3, ecc) = match.groups()

        data_codes.append(data)
        phrases.extend([p0, p1, p2, p3])
        ecc_codes.append(ecc)

    return ParsedSecret(phrases, data_codes, ecc_codes)
