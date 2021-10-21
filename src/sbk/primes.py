#################################################
#     This is a generated file, do not edit     #
#################################################

# This file is part of the sbk project
# https://github.com/mbarkhau/sbk
#
# Copyright (c) 2019-2021 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT
"""Prime constants for sbk.gf.GFNum and sbk.gf.Field."""
import os
import re
import sys
import json
import math
import time
import base64
import struct
import hashlib
import logging
import pathlib as pl
import functools as ft
import itertools as it
import threading
import subprocess as sp
from typing import Any
from typing import NewType
from typing import Callable
from typing import Optional
from typing import Sequence
from typing import TypeAlias
from typing import NamedTuple
from collections.abc import Iterator
from collections.abc import Generator

import sbk.common_types as ct

logger = logging.getLogger(__name__)
Pow2PrimeN: TypeAlias = int
Pow2PrimeK: TypeAlias = int
Pow2PrimeItem: TypeAlias = tuple[Pow2PrimeN, Pow2PrimeK]
Pow2PrimeItems: TypeAlias = Iterator[Pow2PrimeItem]

POW2_PRIME_PARAMS: dict[Pow2PrimeN, Pow2PrimeK] = {
    8: 5,
    16: 15,
    24: 3,
    32: 5,
    40: 87,
    48: 59,
    56: 5,
    64: 59,
    72: 93,
    80: 65,
    88: 299,
    96: 17,
    104: 17,
    112: 75,
    120: 119,
    128: 159,
    136: 113,
    144: 83,
    152: 17,
    160: 47,
    168: 257,
    176: 233,
    184: 33,
    192: 237,
    200: 75,
    208: 299,
    216: 377,
    224: 63,
    232: 567,
    240: 467,
    248: 237,
    256: 189,
    264: 275,
    272: 237,
    280: 47,
    288: 167,
    296: 285,
    304: 75,
    312: 203,
    320: 197,
    328: 155,
    336: 3,
    344: 119,
    352: 657,
    360: 719,
    368: 315,
    376: 57,
    384: 317,
    392: 107,
    400: 593,
    408: 1005,
    416: 435,
    424: 389,
    432: 299,
    440: 33,
    448: 203,
    456: 627,
    464: 437,
    472: 209,
    480: 47,
    488: 17,
    496: 257,
    504: 503,
    512: 569,
    520: 383,
    528: 65,
    536: 149,
    544: 759,
    552: 503,
    560: 717,
    568: 645,
    576: 789,
    584: 195,
    592: 935,
    600: 95,
    608: 527,
    616: 459,
    624: 117,
    632: 813,
    640: 305,
    648: 195,
    656: 143,
    664: 17,
    672: 399,
    680: 939,
    688: 759,
    696: 447,
    704: 245,
    712: 489,
    720: 395,
    728: 77,
    736: 509,
    744: 173,
    752: 875,
    760: 173,
    768: 825
    # 768:  825, 776: 1539, 784:  759, 792: 1299,  800:  105,
    # 808:   17, 816:  959, 824:  209, 832:  143,  840:  213,
    # 848:   17, 856:  459, 864:  243, 872:  177,  880:  113,
    # 888:  915, 896:  213, 904:  609, 912: 1935,  920:  185,
    # 928:  645, 936: 1325, 944:  573, 952:   99,  960:  167,
    # 968: 1347, 976: 2147, 984:  557, 992: 1779, 1000: 1245,
}


def pow2prime(n: Pow2PrimeN, k: Pow2PrimeK) -> int:
    if n % 8 == 0:
        return 2 ** n - k
    else:
        raise ValueError(f"Invalid n={n} (n % 8 != 0)")


POW2_PRIMES = [pow2prime(n, k) for n, k in sorted(POW2_PRIME_PARAMS.items())]
SMALL_PRIMES = [
    2,
    3,
    5,
    7,
    11,
    13,
    17,
    19,
    23,
    29,
    31,
    37,
    41,
    43,
    47,
    53,
    59,
    61,
    67,
    71,
    73,
    79,
    83,
    89,
    97,
    101,
    103,
    107,
    109,
    113,
    127,
    131,
    137,
    139,
    149,
    151,
    157,
    163,
    167,
    173,
    179,
    181,
    191,
    193,
    197,
    199,
    211,
    223,
    227,
    229,
    233,
    239,
    241,
    251,
    257,
    263,
    269,
    271,
    277,
    281,
    283,
    293,
    307,
]

PRIMES = sorted(set(SMALL_PRIMES + POW2_PRIMES))


def get_pow2prime_index(num_bits: int) -> int:
    if num_bits % 8 != 0:
        err = f"Invalid num_bits={num_bits}, not a multiple of 8"
        raise ValueError(err)

    target_exp = num_bits
    for p2pp_idx, param_exp in enumerate(POW2_PRIME_PARAMS):
        if param_exp >= target_exp:
            return p2pp_idx

    err = f"Invalid num_bits={num_bits}, no known 2**n-k primes "
    raise ValueError(err)


def get_pow2prime(num_bits: int) -> int:
    p2pp_idx = get_pow2prime_index(num_bits)
    return POW2_PRIMES[p2pp_idx]


def is_prime(n: int) -> bool:
    for p in PRIMES:
        if n == p:
            return True
        psq = p * p
        if n < psq and n % p == 0:
            return False

    # This is not an exhaustive test, it's only used used only to
    # catch programming errors, so we bail if can't say for sure that
    # n is prime.
    if n > max(SMALL_PRIMES) ** 2:
        raise NotImplementedError
    else:
        return True


from random import randrange

# Jim Sinclair
_mr_js_bases = {2, 325, 9375, 28178, 450775, 9780504, 1795265022}


def _miller_test_bases(n: int, k: int, accuracy: int = 100) -> Iterator[int]:
    if n < 2 ** 64:
        return _mr_js_bases
    else:
        random_bases = {randrange(2, n - 1) for _ in range(accuracy)}
        return _mr_js_bases | set(SMALL_PRIMES[:13]) | random_bases


def _is_composite(n: int, r: int, x: int) -> bool:
    for _ in range(r - 1):
        x = pow(x, 2, n)
        if x == n - 1:
            return False
    return True


def is_probable_prime(n: int, k: int = 100) -> bool:
    # Early exit if not prime
    for p in SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False

    r = 0
    d = n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for a in _miller_test_bases(n, k):
        x = pow(a, d, n)
        if x not in (1, n - 1) and _is_composite(n, r, x):
            return False

    return True


# Hardcoded digest of POW2_PRIME_PARAMS
_V1_PRIMES_VERIFICATION_SHA256 = (
    "8303b97ae70cb01e36abd0a625d7e8a427569cc656e861d90a94c3bc697923e7"
)


def validate_pow2_prime_params() -> None:
    sha256 = hashlib.sha256()
    for n, k in sorted(POW2_PRIME_PARAMS.items()):
        sha256.update(str((n, k)).encode("ascii"))

    digest = sha256.hexdigest()
    has_changed = (
        len(POW2_PRIME_PARAMS) != 96 or digest != _V1_PRIMES_VERIFICATION_SHA256
    )

    if has_changed:
        logger.error(f"Current  hash: {digest}")
        logger.error(f"Expected hash: {_V1_PRIMES_VERIFICATION_SHA256}")
        raise Exception("Integrity error: POW2_PRIMES changed!")


validate_pow2_prime_params()


def a014234_verify(a014234_content: str) -> Pow2PrimeItems:
    for line in a014234_content.splitlines():
        if not line.strip():
            continue

        n, p = map(int, line.strip().split())
        if n % 8 != 0:
            continue

        k = (2 ** n) - p
        assert pow2prime(n, k) == p

        if n <= 768:
            assert POW2_PRIME_PARAMS[n] == k

        yield (n, k)


def read_oeis_org_a014234() -> str:
    import time
    import pathlib as pl
    import tempfile
    import urllib.request

    cache_path = pl.Path(tempfile.gettempdir()) / "oeis_org_b014234.txt"
    min_mtime = time.time() - 10000
    if cache_path.exists() and cache_path.stat().st_mtime > min_mtime:
        with cache_path.open(mode="r") as fobj:
            content = fobj.read()
    else:
        a014234_url = "https://oeis.org/A014234/b014234.txt"
        with urllib.request.urlopen(a014234_url) as fobj:
            data = fobj.read()
        content = data.decode("utf-8")
        with cache_path.open(mode="w") as fobj:
            fobj.write(content)
    return content


def download_oeis_org_a014234() -> None:
    """Helper to verify local primes against https://oeis.org/A014234.

    $ source activate
    $ python -m sbk.primes
    """
    content = read_oeis_org_a014234()
    for exp, k in a014234_verify(content):
        verification_url = (
            f"https://www.wolframalpha.com/input/?i=factors(2%5E{exp}+-+{k})"
        )
        print(f"2**{exp:<4} - {k:<4}", verification_url)


if __name__ == "__main__":
    download_oeis_org_a014234()
