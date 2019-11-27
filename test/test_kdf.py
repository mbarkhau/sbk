import random

import pytest

from sbk import kdf


def test_digest():
    kdf_params = kdf.init_kdf_params(p=1, m=8, t=1)

    secret_data = b"\x01\x23\x45\x67" * 4
    for hash_len in range(4, 50):
        res = kdf.digest(secret_data, kdf_params, hash_len)
        assert len(res) == hash_len


KDF_PARAMS_CASES = [
    (    1,       1,       1),
    (    2,       2,       2),
    (    4,       3,       3),
    (    8,       4,       4),
    (   16,       6,       6),
    (   32,       9,       9),
    (   64,      12,      12),
    (  128,      16,      16),
    (  256,      20,      20),
    (32768, 5097891, 5097891),
]


@pytest.mark.parametrize("p, m, t", KDF_PARAMS_CASES)
def test_kdf_params(p, m, t):
    kdf_params = kdf.init_kdf_params(p=p, m=m, t=t)
    assert kdf_params.p == p
    assert kdf_params.m == m
    assert kdf_params.t == t


def test_kdf_params_fuzz():
    for _ in range(100):
        p = random.randrange(1, int(2    ** (2 ** 4 - 1)))
        m = random.randrange(1, int(1.25 ** (2 ** 6 - 1)))
        t = random.randrange(1, int(1.25 ** (2 ** 6 - 1)))

        kdf_params = kdf.init_kdf_params(p=p, m=m, t=t)
        assert abs(kdf_params.p - p) / kdf_params.p < 1
        assert abs(kdf_params.m - m) / kdf_params.m < 0.5
        assert abs(kdf_params.t - t) / kdf_params.t < 0.5

        decoded = kdf.KDFParams.decode(kdf_params.encode())
        assert decoded == kdf_params
