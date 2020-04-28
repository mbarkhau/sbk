# This file is part of the sbk project
# https://gitlab.com/mbarkhau/sbk
#
# Copyright (c) 2019 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT

"""Prime constants."""

import random
import typing as typ
import hashlib
import logging

log = logging.getLogger(__name__)


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


Pow2PrimeN = int
Pow2PrimeK   = int
Pow2PrimeItem = typ.Tuple[Pow2PrimeN, Pow2PrimeK]


# Taken from https://oeis.org/A014234
# Verified using https://primes.utm.edu/lists/2small/200bit.html
# Verified using https://www.wolframalpha.com/input/?i=factors(2%5E256+-+189)

POW2_PRIME_PARAMS: typ.Dict[Pow2PrimeN, Pow2PrimeK] = {
      8:    5,  16:   15,  24:    3,  32:    5,  40:   87,
     48:   59,  56:    5,  64:   59,  72:   93,  80:   65,
     88:  299,  96:   17, 104:   17, 112:   75, 120:  119,
    128:  159, 136:  113, 144:   83, 152:   17, 160:   47,
    168:  257, 176:  233, 184:   33, 192:  237, 200:   75,
    208:  299, 216:  377, 224:   63, 232:  567, 240:  467,
    248:  237, 256:  189, 264:  275, 272:  237, 280:   47,
    288:  167, 296:  285, 304:   75, 312:  203, 320:  197,
    328:  155, 336:    3, 344:  119, 352:  657, 360:  719,
    368:  315, 376:   57, 384:  317, 392:  107, 400:  593,
    408: 1005, 416:  435, 424:  389, 432:  299, 440:   33,
    448:  203, 456:  627, 464:  437, 472:  209, 480:   47,
    488:   17, 496:  257, 504:  503, 512:  569, 520:  383,
    528:   65, 536:  149, 544:  759, 552:  503, 560:  717,
    568:  645, 576:  789, 584:  195, 592:  935, 600:   95,
    608:  527, 616:  459, 624:  117, 632:  813, 640:  305,
    648:  195, 656:  143, 664:   17, 672:  399, 680:  939,
    688:  759, 696:  447, 704:  245, 712:  489, 720:  395,
    728:   77, 736:  509, 744:  173, 752:  875, 760:  173,
    768:  825,
}


def pow2prime(n: Pow2PrimeN, k: Pow2PrimeK) -> int:
    if n % 8 != 0:
        raise ValueError(f"Invalid n={n}, must be divisible by 8")

    return 2 ** n - k


POW2_PRIMES = [
    pow2prime(n, k)
    for n, k in sorted(POW2_PRIME_PARAMS.items())
]


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


_V1_PRIMES_VERIFICATION_SHA256 = "8303b97ae70cb01e36abd0a625d7e8a427569cc656e861d90a94c3bc697923e7"


def validate_pow2_prime_params() -> None:
    """Make sure the parameters don't change inadvertantly.

    Since the prime used for GF is encoded as an index of
    POW2_PRIME_PARAMS, it is important that those indexes stay valid.
    """
    sha256 = hashlib.sha256()
    for n, k in sorted(POW2_PRIME_PARAMS.items()):
        sha256.update(str((n, k)).encode('ascii'))

    digest      = sha256.hexdigest()
    has_changed = len(POW2_PRIME_PARAMS) != 96 or digest != _V1_PRIMES_VERIFICATION_SHA256

    if has_changed:
        log.error(f"Current  hash: {digest}")
        log.error(f"Expected hash: {_V1_PRIMES_VERIFICATION_SHA256}")
        raise Exception("Integrity error: POW2_PRIMES changed!")


validate_pow2_prime_params()


def get_pow2prime_index(num_bits: int) -> int:
    if num_bits % 8 != 0:
        err = f"Invalid num_bits={num_bits}, not a multiple of 8"
        raise ValueError(err)

    target_exp = num_bits
    for p2pp_idx, param in enumerate(POW2_PRIME_PARAMS):
        if param.exp >= target_exp:
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


def _is_composite(n: int, r: int, x: int) -> bool:
    for _ in range(r - 1):
        x = pow(x, 2, n)
        if x == n - 1:
            return False
    return True


def is_probable_prime(n: int, k: int = 100) -> bool:
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

        if _is_composite(n, r, x):
            return False

    return True


# lp: primes.oeis_org_a014234_verify
def a014234_verify(a014234_content: str) -> typ.Iterable[Pow2PrimeItem]:
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


# lp: primes.oeis_org_a014234_verify
def read_oeis_org_a014234() -> str:
    import time
    import tempfile
    import pathlib as pl
    import urllib.request

    cache_path = pl.Path(tempfile.gettempdir()) / "oeis_org_b014234.txt"
    if cache_path.exists() and cache_path.stat().st_mtime > time.time() - 10000:
        with cache_path.open(mode="r") as fobj:
            content = fobj.read()
    else:
        with urllib.request.urlopen("https://oeis.org/A014234/b014234.txt") as fobj:
            content = fobj.read()
        with cache_path.open(mode="w") as fobj:
            fobj.write(content)
    return content


# lp: primes.oeis_org_a014234_verify
def download_oeis_org_a014234() -> None:
    """Helper script to verify local primes against https://oeis.org/A014234.

    $ source activate
    $ python -m sbk.primes
    """
    content = read_oeis_org_a014234()
    for exp, k in a014234_verify(content):
        verification_url = f"https://www.wolframalpha.com/input/?i=factors(2%5E{exp}+-+{k})"
        print(f"2**{exp:<4} - {k:<4}", verification_url)


if __name__ == '__main__':
    download_oeis_org_a014234()
