# This file is part of the SBK project
# https://gitlab.com/mbarkhau/sbk
#
# Copyright (c) 2019 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT

"""CLI parsing, encoding and formatting functions."""

import os
import re
import time
import typing as typ
import threading

import click

from . import ecc_rs
from . import enc_util

# https://regex101.com/r/iQKt5L/6
FORMATTED_LINE_PATTERN = r"""
[AB0-9]\d:[ ]
    (\d{3}-\d{3})
    \s+
    ([A-Za-z]+)\s+([A-Za-z]+)
    \s+
[CD0-9]\d:[ ]
    (\d{3}-\d{3})
"""


FORMATTED_LINE_RE = re.compile(FORMATTED_LINE_PATTERN, flags=re.VERBOSE)


Lines = typ.Iterable[str]

PhraseLines = typ.Sequence[str]

PartIndex = int
PartVal   = bytes
PartVals  = typ.Sequence[PartVal]
# A PartVal can be an empty string to mark its value
# is not known yet.


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
    """Parse a single intcode from two bytes."""
    assert len(data) == 2
    intcodes = list(bytes2intcode_parts(data, idx_offset))
    assert len(intcodes) == 1
    return intcodes[0]


def bytes2intcodes(data: bytes) -> IntCodes:
    """Encode data to intcode.

    The main purpose of the intcode format is to be
    compact, redundant and resilient to input errors.
    """
    total_len     = ((len(data) + 1) // 2) * 4
    ecc_len       = total_len - len(data)
    data_with_ecc = ecc_rs.encode(data, ecc_len=ecc_len)
    return list(bytes2intcode_parts(data_with_ecc))


def intcodes2parts(intcodes: MaybeIntCodes, idx_offset: int = 0) -> PartVals:
    """Decode and and validate intcodes to PartVals."""
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


def maybe_intcodes2bytes(intcodes: MaybeIntCodes, msg_len: typ.Optional[int] = None) -> bytes:
    data_with_ecc = intcodes2parts(intcodes)
    if msg_len is None:
        _msg_len = len(data_with_ecc) // 2
    else:
        _msg_len = msg_len

    assert all(len(part) <= 1 for part in data_with_ecc)
    maybe_packets = [part[0] if part else None for part in data_with_ecc]
    return ecc_rs.decode_packets(maybe_packets, _msg_len)


def intcodes2bytes(intcodes: IntCodes) -> bytes:
    return maybe_intcodes2bytes(intcodes)


class ParsedSecret(typ.NamedTuple):
    words     : typ.Tuple[str    , ...]
    data_codes: typ.Tuple[IntCode, ...]
    ecc_codes : typ.Tuple[IntCode, ...]


def parse_formatted_secret(text: str, strict: bool = True) -> ParsedSecret:
    words     : typ.List[str    ] = []
    data_codes: typ.List[IntCode] = []
    ecc_codes : typ.List[IntCode] = []

    for i, line in enumerate(text.splitlines()):
        line = line.strip().lower()
        if not line or line.startswith("data"):
            continue

        match = FORMATTED_LINE_RE.match(line.strip())
        if match is None:
            if strict:
                line_no = i + 1
                err_msg = f"Invalid input at line {line_no}: {repr(line)}"
                raise ValueError(err_msg)
            else:
                continue

        (data, w1, w2, ecc) = match.groups()

        data_codes.append(data)
        words.extend([w1, w2])
        ecc_codes.append(ecc)

    return ParsedSecret(tuple(words), tuple(data_codes), tuple(ecc_codes))


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

    if not threshold <= 16:
        errmsg = f"Invalid parameter for --scheme={scheme}"
        errmsg += f", threshold must be <= 16, but was {threshold}"
        raise click.Abort(errmsg)

    if not num_shares < 64:
        errmsg = f"Invalid parameter for --scheme={scheme}"
        errmsg += f", num_shares must be < 64, but was {num_shares}"
        raise click.Abort(errmsg)

    return Scheme(threshold, num_shares)


T = typ.TypeVar('T')


class ThreadRunner(threading.Thread, typ.Generic[T]):

    _exception: typ.Optional[Exception]
    _return   : typ.Optional[T]

    def __init__(self, target: typ.Callable[[], T]) -> None:
        threading.Thread.__init__(self, target=target)
        self._target    = target
        self._exception = None
        self._return    = None
        # daemon means the thread is killed if user hits Ctrl-C
        self.daemon = True

    def run(self) -> None:
        tgt = typ.cast(typ.Callable[[], T], self._target)
        assert tgt is not None
        try:
            self._return = tgt()
        except Exception as ex:
            self._exception = ex
            raise

    def join(self, *args) -> None:
        threading.Thread.join(self, *args)

        if self._exception:
            errmsg = f"Thread failed with {type(self._exception)}: {self._exception}"
            raise Exception(errmsg) from self._exception

        if self._return is None:
            raise Exception("Missing return value after Thread.join")

    @property
    def retval(self) -> T:
        rv = self._return
        # mypy pacification (join would already have raised Exception)
        assert rv is not None
        return rv

    def start_and_join(self) -> T:
        self.start()
        self.join()
        return self.retval


Seconds = float


def run_with_progress_bar(target: typ.Callable[[], T], eta_sec: float, label: str) -> T:
    runner = ThreadRunner[T](target)
    runner.start()
    if os.getenv('SBK_PROGRESS_BAR', "1") == '0':
        runner.join()
        return runner.retval

    total_ms = int(eta_sec * 1000)
    step_ms  = 100

    with click.progressbar(label=label, length=total_ms, show_eta=True) as bar:
        tzero = time.time()
        while runner.is_alive():
            time.sleep(step_ms / 1000)

            done_ms  = (time.time() - tzero) * 1000
            rest_ms  = max(0, total_ms - done_ms)
            rest_pct = 100 * rest_ms / total_ms if total_ms > 0 else 50

            # Lies, damn lies, and progress bars
            if rest_pct > 10:
                bar.update(step_ms)  # default
            elif rest_pct > 3:
                bar.update(step_ms // 2)  # slow down
            else:
                bar.update(step_ms // 10)  # just nudge

        bar.update(total_ms)

    runner.join()
    return runner.retval
