import sys
import time
import argon2
def _measure_argon2(
    t: int, k: int, p: int, l: int = 24, v: int = 2
) -> tuple[str, float]:
    tzero = time.time()
    hash_encoded = argon2.low_level.hash_secret(
        b"password",
        b"somesalt",
        time_cost=t,
        memory_cost=k,
        parallelism=p,
        hash_len=l,
        type=argon2.Type(v),
    )
    duration = time.time() - tzero
    return (hash_encoded.decode("ascii"), duration)
def measure_argon2(*args, **kwargs) -> None:
    durations = []
    for _ in range(5):
        hash_encoded, duration = _measure_argon2(*args, **kwargs)
        durations.append(duration)
    print(f"Encoded:\t{hash_encoded}")
    print(f"{min(durations)} seconds")
def main(args: list[str]) -> None:
    _t, t, _k, k, _p, p, _l, l, _v, v = args
    assert [_t, _k, _p, _l, _v] == ['-t', '-k', '-p', '-l', '-v']
    measure_argon2(int(t), int(k), int(p), int(l), int(v))
if __name__ == '__main__':
    main(sys.argv[1:])