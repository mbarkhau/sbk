import os
import math
import random
import hashlib
import pathlib as pl
import warnings
import collections
from typing import List
from typing import Callable
from typing import Optional
from typing import Protocol

from . import common_types as ct

import argon2


def urandom(size: int) -> bytes:
    if os.getenv('SBK_DEBUG_RANDOM') == 'DANGER':
        # https://xkcd.com/221/
        return b"4" * size
    else:
        return os.urandom(size)


class DebugRandom:

    _state: int

    def __init__(self) -> None:
        self._state = 4294967291

    def randrange(self, stop: int):
        self._state = (self._state + 4294967291) % (2 ** 63)
        return self._state % stop


DEBUG_WARN_MSG = "Warning, SBK using debug random! This should only happen when debugging or testing."

_debug_rand = DebugRandom()
_rand       = random.SystemRandom()


class RandRanger(Protocol):
    def __call__(self, stop: int) -> int:
        ...


def reset_debug_random() -> None:
    if os.getenv('SBK_DEBUG_RANDOM') == 'DANGER':
        _debug_rand._state = 4294967291


def randrange(stop: int) -> int:
    if os.getenv('SBK_DEBUG_RANDOM') == 'DANGER':
        warnings.warn(DEBUG_WARN_MSG)
        result = _debug_rand.randrange(stop)
    else:
        result = _rand.randrange(stop)
    assert isinstance(result, int)
    return result


class PseudoRandRange:

    def __init__(self, data: bytes):
        assert len(data) >= 256

        self.values_state: List[int] = list(data)
        self.position: int = 0
        self.step: int = 0

    def __call__(self, stop: int) -> int:
        val = 0
        num_values = stop / 256

        for _ in range(int(num_values + 1)):
            self.step = self.step + 127
            offset = self.values_state[self.position % len(self.values_state)]
            new_pos = self.position + offset + self.step
            val += self.values_state[new_pos % len(self.values_state)]
            self.position = new_pos % (2 ** 31)

        return val % stop


class Argon2RandRange:

    def __init__(self, data: bytes) -> None:
        assert len(data) >= 256



# https://stackoverflow.com/a/47348423/62997
def entropy(data: bytes) -> float:
    probabilities     = [n_x / len(data) for x, n_x in collections.Counter(data).items()]
    entropy_fractions = [-p_x * math.log(p_x, 2) for p_x in probabilities]
    return sum(entropy_fractions)


def get_entropy_pool_size() -> int:
    path_linux = pl.Path("/proc/sys/kernel/random/entropy_avail")
    if path_linux.exists():
        with path_linux.open() as fobj:
            return int(fobj.read().strip())
    return -1


def init_randrange(raw_salt: Optional[ct.RawSalt] = None) -> RandRanger:
    if raw_salt is None:
        if os.getenv('SBK_DEBUG_RANDOM') == 'DANGER':
            reset_debug_random()

        return randrange
    else:
        return random.Random(raw_salt).randrange


def _debug_entropy_check() -> None:
    """Determine constans for sbk_random._check_entropy."""
    print(" N   MIN_E   low_e   headroom")

    a = 0.3
    b = 0.19

    for n in range(2, 13):
        min_e    = a + n * b
        fails    = 0
        low_e    = entropy(urandom(n))
        headroom = 999.0
        for _ in range(10_000):
            e = entropy(urandom(n))
            if e < low_e:
                low_e = (low_e + e) / 2
            if e < min_e:
                fails += 1

        headroom = low_e - min_e

        print(f"{n:>2} {min_e:7.3f} {low_e:7.3f} {headroom:7.3f} {fails:>6}")


if __name__ == '__main__':
    # _debug_entropy_check()
    rand = random.Random(0)
    data = rand.randbytes(256)
    prr  = random.Random(data).randrange

    vals = [prr(10000000) for _ in range(200)]

    for i, val in enumerate(vals):
        print(f"{val:07}", end=" ")
        if (i + 1) % 10 == 0:
            print()
    print()

    for i, val in enumerate(vals):
        print(f"{val:07}", end=" ")
        if (i + 1) % 12 == 0:
            print()
    print()

    for i, val in enumerate(vals):
        print(f"{val:07}", end=" ")
        if (i + 1) % 16 == 0:
            print()
    print()
