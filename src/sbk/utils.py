#################################################
#     This is a generated file, do not edit     #
#################################################

# This file is part of the sbk project
# https://github.com/mbarkhau/sbk
#
# Copyright (c) 2019-2021 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT
import os
import re
import sys
import json
import math
import time
import base64
import struct
import typing as typ
import hashlib
import logging
import pathlib as pl
import functools as ft
import itertools as it
import threading
import subprocess as sp
from typing import Any
from typing import Set
from typing import Dict
from typing import List
from typing import Type
from typing import Tuple
from typing import Union
from typing import Generic
from typing import NewType
from typing import TypeVar
from typing import Callable
from typing import Iterable
from typing import Iterator
from typing import Optional
from typing import Protocol
from typing import Sequence
from typing import Generator
from typing import NamedTuple

# from collections.abc import Generator, Iterator, Counter

# from typing import TypeAlias
TypeAlias = Any

import sbk.common_types as ct

logger = logging.getLogger(__name__)


def hex2bytes(hex_str: str) -> bytes:
    """Convert bytes to a hex string."""
    hex_str = hex_str.upper().zfill(2 * ((len(hex_str) + 1) // 2))
    return base64.b16decode(hex_str.encode('ascii'))


def bytes2hex(data: bytes) -> str:
    """Convert bytes to a hex string."""
    return base64.b16encode(data).decode('ascii').lower()


def bytes_hex(data: bytes) -> str:
    """Display bytes data in hex form, rather than ascii."""
    chars           = (data[i : i + 1] for i in range(len(data)))
    char_hex        = [bytes2hex(c).lower() for c in chars]
    char_hex_padded = (c + " " if (i + 1) % 2 == 0 else c for i, c in enumerate(char_hex))
    return "".join(char_hex_padded).strip()


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


class ProgressSmoother:

    increments: List[float]

    def __init__(self, progress_cb: ct.ProgressCallback) -> None:
        self.increments = [0]

        def fake_progress() -> None:
            step_duration = 0.1
            tzero         = time.time()
            while True:
                time.sleep(step_duration)
                if self.total_incr() == 0:
                    progress_cb(0.01)
                elif self.total_incr() >= 100:
                    progress_cb(100)
                    return
                else:
                    duration      = time.time() - tzero
                    steps         = duration / step_duration
                    incr_per_step = self.total_incr() / steps
                    progress_cb(incr_per_step)

        self._thread = threading.Thread(target=fake_progress)
        self._thread.start()

    def total_incr(self) -> float:
        return sum(self.increments) + max(self.increments) * 0.55

    def progress_cb(self, incr: ct.ProgressIncrement) -> None:
        self.increments.append(incr)

    def join(self) -> None:
        self._thread.join()
