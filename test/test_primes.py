import os
import pathlib as pl

import pytest

import sbk.primes


# lp: primes.test_primes_a014234
@pytest.mark.skipif("slow" in os.getenv('PYTEST_SKIP', ""), reason="Primes don't change")
@pytest.mark.parametrize("prime_idx", range(len(sbk.primes.POW2_PRIMES)))
def test_prime(prime_idx):
    n, k = sbk.primes.POW2_PRIME_PARAMS[prime_idx]
    prime = sbk.primes.POW2_PRIMES[prime_idx]
    assert sbk.primes.is_probable_prime(prime), (n, k)


# lp: primes.test_invalid_prime
def test_invalid_prime():
    try:
        # must be multiple of 8
        sbk.primes.get_pow2prime_index(3)
        assert False, "expected ValueError"
    except ValueError:
        pass

    try:
        # must be smaller than 2**768
        sbk.primes.get_pow2prime_index(2 ** 1000 - 1245)
        assert False, "expected ValueError"
    except ValueError:
        pass


# lp: primes.test_is_probable_prime
def test_is_probable_prime():
    assert sbk.primes.is_probable_prime(2 ** 127 -  1)
    assert sbk.primes.is_probable_prime(2 **  64 - 59)
    assert not sbk.primes.is_probable_prime(60)
    assert not sbk.primes.is_probable_prime( 7 * 73 * 103)
    assert not sbk.primes.is_probable_prime(89 * 683)


# lp: primes.test_a014234_verfiy
def test_a014234_verfiy():
    fixture = pl.Path(__file__).parent / "test_primes_a014234.txt"
    with fixture.open(mode="r") as fobj:
        content = fobj.read()

    p2p_primes = list(sbk.primes.a014234_verify(content))
    assert len(p2p_primes) >= 96


def test_primelist_validation():
    sbk.primes.validate_pow2_prime_params()
    original = sorted(sbk.primes.POW2_PRIME_PARAMS.items())
    try:
        sbk.primes.POW2_PRIME_PARAMS[-1] = (768, 1)
        sbk.primes.validate_pow2_prime_params()
        assert False, "expected Exception"
    except Exception as ex:
        assert "Integrity error" in str(ex)
    finally:
        sbk.primes.POW2_PRIME_PARAMS = original
