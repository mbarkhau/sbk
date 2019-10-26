# This file is part of the SBK project
# https://gitlab.com/mbarkhau/sbk
#
# Copyright (c) 2019 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT

"""CLI parsing, encoding and formatting functions."""

import re
import time
import typing as typ
import threading

import click

from . import ecc
from . import enc_util
from . import mnemonic

EMPTY_PHRASE_LINE = "_________  _________"


# https://regex101.com/r/iQKt5L/5
FORMATTED_LINE_PATTERN = r"""
[AB]\d:[ ]
    (\d{3}-\d{3})
    \s+
    ([A-Za-z]+)\s+([A-Za-z]+)
    \s+
[CD]\d:[ ]
    (\d{3}-\d{3})
"""


FORMATTED_LINE_RE = re.compile(FORMATTED_LINE_PATTERN, flags=re.VERBOSE)


Lines = typ.Iterable[str]

PhraseLines = typ.Sequence[str]

PartIndex = int
PartVal   = bytes
PartVals  = typ.Sequence[PartVal]


BYTES_PER_INTCODE = 2

IntCode       = str
IntCodes      = typ.Sequence[IntCode]
MaybeIntCode  = typ.Optional[IntCode]
MaybeIntCodes = typ.Sequence[MaybeIntCode]


def bytes2intcode_parts(data: bytes, idx_offset: int = 0) -> typ.Iterable[IntCode]:
    if len(data) % 2 != 0:
        errmsg = f"Invalid data, must be divisible by 2, got: {len(data)}"
        raise ValueError(errmsg)

    for i in range(len(data) // 2):
        idx     = idx_offset + i
        chk_idx = idx % 13

        byte0 = enc_util.char_at(data, i * 2 + 0)
        byte1 = enc_util.char_at(data, i * 2 + 1)

        bits = chk_idx << 16
        bits |= byte0 << 8
        bits |= byte1
        assert bits <= 999999
        intcode = f"{bits:06}"
        yield intcode[:3] + "-" + intcode[3:]


def bytes2incode_part(data: bytes, idx_offset: int = 0) -> IntCode:
    assert len(data) == 2
    intcodes = list(bytes2intcode_parts(data, idx_offset))
    assert len(intcodes) == 1
    return intcodes[0]


def bytes2intcodes(data: bytes) -> IntCodes:
    """Encode data to intcode.

    The main purpose of the intcode format is to be
    compact, redundant and resilient to input errors.
    """
    data_with_ecc = ecc.encode(data)
    return list(bytes2intcode_parts(data_with_ecc))


def intcodes2parts(intcodes: MaybeIntCodes, idx_offset: int = 0) -> PartVals:
    """Decode and and validate intcodes to MaybeBytes."""
    expected_chk_idx = idx_offset % 13
    chk_idx_offset   = idx_offset - expected_chk_idx

    part_vals = [b""] * (len(intcodes) * 2)

    for idx, intcode in enumerate(intcodes):
        if intcode:
            intcode = intcode.replace("-", "").replace(" ", "")
            bits    = int(intcode, 10)

            chk_idx = bits >> 16
            byte0   = (bits >> 8) & 0xFF
            byte1   = bits & 0xFF

            if chk_idx != expected_chk_idx:
                raise ValueError("Invalid code: Bad order.")

            part_vals[idx * 2 + 0] = bytes([byte0])
            part_vals[idx * 2 + 1] = bytes([byte1])

        next_chk_idx = (expected_chk_idx + 1) % 13
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


# 060-691 096-369 172-944 227-441 292-977 358-513
# abacus adelaide avocado aspen beggar bahrain boat bohemia flute brussels peanut carolina

# 030-833 096-369 161-905 227-441 292-977 358-513
# 422-264 487-800 553-336 618-872 684-408 749-944
# kiwi iraq kiwi iraq kiwi iraq kiwi iraq kiwi iraq kiwi iraq


def maybe_intcodes2bytes(intcodes: MaybeIntCodes) -> bytes:
    data_with_ecc = intcodes2parts(intcodes)
    block_len     = len(data_with_ecc)
    if block_len % 8 != 0:
        errmsg = f"Invalid len(data_with_ecc)={block_len}, must be divisible by 8"
        raise ValueError(errmsg)

    packet_len    = block_len // 8  # aka. parts per packet
    maybe_packets = parts2packets(data_with_ecc, packet_len)
    return ecc.decode_packets(maybe_packets)


def intcodes2bytes(intcodes: IntCodes) -> bytes:
    return maybe_intcodes2bytes(intcodes)


def is_completed_intcodes(intcodes: MaybeIntCodes) -> bool:
    complete_intcodes = [intcode for intcode in intcodes if intcode]
    if len(complete_intcodes) < len(intcodes):
        return False

    try:
        maybe_intcodes2bytes(complete_intcodes)
        return True
    except ValueError:
        return False


def format_partial_secret_lines(phrase_lines: PhraseLines, intcodes: IntCodes) -> Lines:
    ecc_offset      = len(intcodes    ) // 2
    spacer_offset   = len(phrase_lines) // 2
    phrases_padding = max(map(len, phrase_lines))

    yield f"       Data  {'Phrases':^{phrases_padding}}    ECC"
    yield ""

    for i, line in enumerate(phrase_lines):
        if len(phrase_lines) > 4 and i == spacer_offset:
            yield ""

        ecc_idx      = ecc_offset + i
        data_intcode = intcodes[i]
        ecc_intcode  = intcodes[ecc_idx]

        marker_id = i % spacer_offset
        prefix_id = f"A{marker_id}" if i < spacer_offset else f"B{marker_id}"
        suffix_id = f"C{marker_id}" if i < spacer_offset else f"D{marker_id}"

        prefix = f"{prefix_id}: {data_intcode} "
        suffix = f"{suffix_id}: {ecc_intcode} "

        words_line = EMPTY_PHRASE_LINE if line is None else line
        out_line   = f"{prefix}  {words_line:<{phrases_padding}}  {suffix}"
        yield out_line


def format_secret_lines(data: bytes) -> Lines:
    """Format a completed secret."""
    phrase = mnemonic.bytes2phrase(data)
    assert mnemonic.phrase2bytes(phrase) == data

    intcodes = bytes2intcodes(data)
    assert intcodes2bytes(intcodes) == data

    phrase_lines = phrase.splitlines()
    return format_partial_secret_lines(phrase_lines, intcodes)


def format_secret(data: bytes) -> str:
    return "\n".join(format_secret_lines(data))


class ParsedSecret(typ.NamedTuple):
    words     : typ.List[str]
    data_codes: typ.List[IntCode]
    ecc_codes : typ.List[IntCode]


def parse_formatted_secret(text: str) -> ParsedSecret:
    words     : typ.List[str    ] = []
    data_codes: typ.List[IntCode] = []
    ecc_codes : typ.List[IntCode] = []

    for i, line in enumerate(text.splitlines()):
        line = line.strip().upper()
        if not line or line.startswith("DATA"):
            continue

        line_no = i + 1

        match = FORMATTED_LINE_RE.match(line)
        if match is None:
            err_msg = f"Invalid input at line {line_no}: {line}"
            raise Exception(err_msg)

        (data, w1, w2, ecc) = match.groups()

        data_codes.append(data)
        words.extend([w1, w2])
        ecc_codes.append(ecc)

    return ParsedSecret(words, data_codes, ecc_codes)


class Scheme(typ.NamedTuple):

    threshold : int
    num_shares: int


def parse_scheme(scheme: str) -> Scheme:
    if not re.match(r"^\d+of\d+$", scheme):
        errmsg = f"Invalid parameter for --scheme={scheme}. Try something like '3of5'"
        raise click.Abort(errmsg)

    threshold, num_shares = map(int, scheme.split("of"))
    if threshold > num_shares:
        errmsg = f"Invalid parameter for --scheme={scheme}"
        errmsg += ", num_shares must be larger than threshold"
        raise click.Abort(errmsg)

    return Scheme(threshold, num_shares)


T = typ.TypeVar('T')


class EvalWithProgressbar(threading.Thread, typ.Generic[T]):

    _return: typ.Optional[T]

    def __init__(self, target=None, args=(), kwargs=None) -> None:
        threading.Thread.__init__(self, target=target, args=args, kwargs=kwargs)
        self._target = target
        self._args   = args
        self._kwargs = kwargs
        self._return = None

    def run(self) -> None:
        tgt = self._target
        assert tgt is not None
        kwargs       = self._kwargs or {}
        self._return = tgt(*self._args, **kwargs)

    def join(self, *args) -> None:
        threading.Thread.join(self, *args)
        if self._return is None:
            raise Exception("Missing return value after Thread.join")

    @property
    def retval(self) -> T:
        rv = self._return
        assert rv is not None
        return rv

    def start_and_wait(self, eta_sec: float, label: str) -> None:
        # daemon means the thread is killed if user hits Ctrl-C
        self.daemon = True
        self.start()

        progress_bar = None

        tzero = time.time()
        total = int(eta_sec * 1000)

        step = 0.1

        while self.is_alive():
            time.sleep(step)
            tnow          = time.time()
            elapsed       = tnow    - tzero
            remaining     = eta_sec - elapsed
            remaining_pct = 100 * remaining / eta_sec

            if progress_bar is None and elapsed > 0.2:
                progress_bar = click.progressbar(label=label, length=total, show_eta=True)
                progress_bar.update(int(elapsed * 1000))
            elif progress_bar:
                if remaining_pct < 1:
                    progress_bar.update(int(step * 100))
                elif remaining_pct < 5:
                    progress_bar.update(int(step * 500))
                else:
                    progress_bar.update(int(step * 1000))

        if progress_bar:
            progress_bar.update(total)

        self.join()
        print()
