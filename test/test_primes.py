import os
import pathlib as pl

import pytest

import sbk.primes


@pytest.mark.skipif("slow" in os.getenv('PYTEST_SKIP', ""), reason="Primes don't change")
@pytest.mark.parametrize("prime_idx", range(len(sbk.primes.POW2_PRIMES)))
def test_prime(prime_idx):
    param = sbk.primes.POW2_PRIME_PARAMS[prime_idx]
    prime = sbk.primes.POW2_PRIMES[prime_idx]
    assert sbk.primes.is_miller_rabin_prp(prime), param


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


def test_is_miller_rabin_prp():
    assert sbk.primes.is_miller_rabin_prp(2 ** 127 -  1)
    assert sbk.primes.is_miller_rabin_prp(2 **  64 - 59)
    assert not sbk.primes.is_miller_rabin_prp(60)
    assert not sbk.primes.is_miller_rabin_prp( 7 * 73 * 103)
    assert not sbk.primes.is_miller_rabin_prp(89 * 683)


def test_primes_a014234():
    fixture = pl.Path(__file__).parent / "test_primes_a014234.txt"
    with fixture.open(mode="r") as fobj:
        content = fobj.read()

    p2p_primes = list(sbk.primes.a014234_verify(content))
    assert len(p2p_primes) >= 96


def test_primelist_validation():
    sbk.primes.validate_pow2_prime_params()
    original = list(sbk.primes.POW2_PRIME_PARAMS)
    try:
        sbk.primes.POW2_PRIME_PARAMS[-1] = sbk.primes.Pow2PrimeParam(exp=768, k=1)
        sbk.primes.validate_pow2_prime_params()
        assert False, "expected Exception"
    except Exception as ex:
        assert "Integrity error" in str(ex)
    finally:
        sbk.primes.POW2_PRIME_PARAMS = original
