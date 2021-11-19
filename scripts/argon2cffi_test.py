import sys
import time
import argon2
from typing import Tuple, List


def _measure_argon2(
    t: int, m: float, p: int, l: int = 24, y: int = 2
) -> Tuple[str, float]:
    tzero = time.time()
    hash_encoded = argon2.low_level.hash_secret(
        b"password",
        b"somesalt",
        time_cost=t,
        memory_cost=int(2**m),
        parallelism=p,
        hash_len=l,
        type=argon2.Type(y),
    )
    duration = time.time() - tzero
    return (hash_encoded.decode("ascii"), duration)


def measure_argon2(*args, **kwargs) -> None:
    hash_encoded, duration = _measure_argon2(*args, **kwargs)
    print(f"Encoded:\t{hash_encoded}")
    print(f"{duration:.3f} seconds", end="   ")
    for _ in range(4):
        if duration > 3:
            return
        _, duration = _measure_argon2(*args, **kwargs)
        print(f"{duration:.3f} seconds", end="   ")


def main(args: List[str]) -> None:
    _t, t, _m, m, _p, p, _l, l, _y, y = args
    assert [_t, _m, _p, _l, _y] == ['-t', '-m', '-p', '-l', '-y']
    measure_argon2(int(t), float(m), int(p), int(l), int(y))


if __name__ == '__main__':
    main(sys.argv[1:])