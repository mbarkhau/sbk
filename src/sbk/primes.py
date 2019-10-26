# This file is part of the sbk project
# https://gitlab.com/mbarkhau/sbk
#
# Copyright (c) 2019 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT

"""Prime constants."""

import random
import typing as typ
import hashlib

# https://oeis.org/A000040/list
SMALL_PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59]
SMALL_PRIMES += [ 61,  67,  71,  73,  79,  83,  89,  97, 101, 103, 107, 109, 113, 127]
SMALL_PRIMES += [131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191]
SMALL_PRIMES += [193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257]
SMALL_PRIMES += [263, 269, 271]

# For this application we want a known prime number as close as
# possible to our security level; e.g. desired security level of 128
# bits -- too large and all the ciphertext is large; too small and
# security is compromised

# MERSENNE_PRIME_EXPONENTS = [
#     2, 3, 5, 7, 13, 17, 19, 31, 61, 89, 107, 127, 521, 607, 1279
# ]


Pow2PrimeExp = int
Pow2PrimeK   = int


class Pow2PrimeParam(typ.NamedTuple):
    exp: Pow2PrimeExp
    k  : Pow2PrimeK


def pow2prime(exp: Pow2PrimeExp, k: Pow2PrimeK) -> int:
    if exp % 8 != 0:
        raise ValueError(f"Invalid exp={exp}, must be divisible by 8")

    return 2 ** exp - k


# Taken from https://primes.utm.edu/lists/2small/200bit.html
# Verified using https://www.wolframalpha.com/input/?i=factors(2%5E256+-+189)

POW2_PRIME_PARAMS: typ.List[Pow2PrimeParam] = [
    Pow2PrimeParam(exp=8  , k=5),
    Pow2PrimeParam(exp=16 , k=15),
    Pow2PrimeParam(exp=24 , k=3),
    Pow2PrimeParam(exp=32 , k=5),
    Pow2PrimeParam(exp=40 , k=87),
    Pow2PrimeParam(exp=48 , k=59),
    Pow2PrimeParam(exp=56 , k=5),
    Pow2PrimeParam(exp=64 , k=59),
    Pow2PrimeParam(exp=72 , k=93),
    Pow2PrimeParam(exp=80 , k=65),
    Pow2PrimeParam(exp=88 , k=299),
    Pow2PrimeParam(exp=96 , k=17),
    Pow2PrimeParam(exp=104, k=17),
    Pow2PrimeParam(exp=112, k=75),
    Pow2PrimeParam(exp=120, k=119),
    Pow2PrimeParam(exp=128, k=159),
    Pow2PrimeParam(exp=136, k=113),
    Pow2PrimeParam(exp=144, k=83),
    Pow2PrimeParam(exp=152, k=17),
    Pow2PrimeParam(exp=160, k=47),
    Pow2PrimeParam(exp=168, k=257),
    Pow2PrimeParam(exp=176, k=233),
    Pow2PrimeParam(exp=184, k=33),
    Pow2PrimeParam(exp=192, k=237),
    Pow2PrimeParam(exp=200, k=75),
    Pow2PrimeParam(exp=208, k=299),
    Pow2PrimeParam(exp=216, k=377),
    Pow2PrimeParam(exp=224, k=63),
    Pow2PrimeParam(exp=232, k=567),
    Pow2PrimeParam(exp=240, k=467),
    Pow2PrimeParam(exp=248, k=237),
    Pow2PrimeParam(exp=256, k=189),
    Pow2PrimeParam(exp=264, k=275),
    Pow2PrimeParam(exp=272, k=237),
    Pow2PrimeParam(exp=280, k=47),
    Pow2PrimeParam(exp=288, k=167),
    Pow2PrimeParam(exp=296, k=285),
    Pow2PrimeParam(exp=304, k=75),
    Pow2PrimeParam(exp=312, k=203),
    Pow2PrimeParam(exp=320, k=197),
    Pow2PrimeParam(exp=328, k=155),
    Pow2PrimeParam(exp=336, k=3),
    Pow2PrimeParam(exp=344, k=119),
    Pow2PrimeParam(exp=352, k=657),
    Pow2PrimeParam(exp=360, k=719),
    Pow2PrimeParam(exp=368, k=315),
    Pow2PrimeParam(exp=376, k=57),
    Pow2PrimeParam(exp=384, k=317),
    Pow2PrimeParam(exp=392, k=107),
    Pow2PrimeParam(exp=400, k=593),
]


_V1_SHA256 = "b21f53fb97812be4232fcadb0a8afad2672b6e7fe833d93760f0133a482d6e3c"


def validate_pow2_prime_params() -> None:
    """Make sure the parameters don't change inadvertantly.

    Since the prime used for GF is encoded as an index of
    POW2_PRIME_PARAMS, it is important that those indexes stay valid.
    """
    sha256 = hashlib.sha256()
    for p2pp in POW2_PRIME_PARAMS:
        sha256.update(str((p2pp.exp, p2pp.k)).encode('ascii'))

    has_changed = len(POW2_PRIME_PARAMS) != 50 or sha256.hexdigest() != _V1_SHA256

    if has_changed:
        raise Exception("Integrity error: POW2_PRIMES changed!")


validate_pow2_prime_params()


POW2_PRIMES = [pow2prime(exp, k) for exp, k in POW2_PRIME_PARAMS]

# NOTE: since the index into POW2_PRIMES is derived from the
#   serialized parameters, the format of which is limited in
#   space, we don't want to have more primes than can be
#   derived from that format.
assert len(POW2_PRIMES) < 256


# https://oeis.org/A132358
assert 251                                     in POW2_PRIMES
assert 65521                                   in POW2_PRIMES
assert 4294967291                              in POW2_PRIMES
assert 18446744073709551557                    in POW2_PRIMES
assert 340282366920938463463374607431768211297 in POW2_PRIMES

assert 281474976710597                                            in POW2_PRIMES
assert 79228162514264337593543950319                              in POW2_PRIMES
assert 1461501637330902918203684832716283019655932542929          in POW2_PRIMES
assert 6277101735386680763835789423207666416102355444464034512659 in POW2_PRIMES


PRIMES = sorted(set(SMALL_PRIMES + POW2_PRIMES))


def get_pow2prime_index(num_bits: int) -> int:
    if num_bits % 8 != 0:
        raise ValueError(f"Invalid num_bits={num_bits}, must be divisible by 8")

    target_exp = num_bits
    for p2pp_idx, param in enumerate(POW2_PRIME_PARAMS):
        if param.exp >= target_exp:
            return p2pp_idx

    raise ValueError(f"Invalid num_bits={num_bits}, no known 2**n-k primes ")


def get_pow2prime(num_bits: int) -> int:
    p2pp_idx = get_pow2prime_index(num_bits)
    return POW2_PRIMES[p2pp_idx]


def is_prime(n: int) -> bool:
    for p in PRIMES:
        if n == p:
            return True

        if n < (p * p) and n % p == 0:
            return False

    # This is not an exhaustive test, it's only used used only to
    # catch programming errors, so we bail if can't say for sure that
    # n is prime.
    if n > max(SMALL_PRIMES) ** 2:
        raise NotImplementedError

    return True


def _miller_test_bases(n: int, k: int) -> typ.Iterable[int]:
    bases = {2, 325, 9375, 28178, 450775, 9780504, 1795265022}  # Jim Sinclair

    if n > 2 ** 64:
        bases.update({2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41})
        bases.update(random.randrange(2, n - 1) for _ in range(k - len(bases)))

    return bases


def is_miller_rabin_prp(n: int, k: int = 100) -> bool:
    """Miller-Rabin Primality Test.

    Based on
     - https://gist.github.com/Ayrx/5884790
     - https://jeremykun.com/2013/06/16/miller-rabin-primality-test/
     - http://miller-rabin.appspot.com/
     - https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test#Miller_test
    """

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
        if x == 1 or x == n - 1:
            continue

        is_composite = True
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                is_composite = False
                break

        if is_composite:
            return False

    return True
