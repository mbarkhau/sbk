import random

import pytest

from sbk import kdf


def test_digest_len():
    kdf_params = kdf.init_kdf_params(p=1, m=8, t=1)

    secret_data = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
    for hash_len in range(4, 50):
        res = kdf.digest(secret_data, kdf_params, hash_len)
        assert len(res) == hash_len


def test_digest_inputs():
    kdf_params = kdf.init_kdf_params(p=1, m=random.randint(1, 4) * 8, t=random.randint(1, 20))

    kdf_inputs = [
        b"\x00\x00\x00\x00\x00\x00\x00\x00",
        b"\x11\x11\x11\x11\x11\x11\x11\x11",
        b"\x22\x22\x22\x22\x22\x22\x22\x22",
        b"\x33\x33\x33\x33\x33\x33\x33\x33",
    ]

    digests = set()
    for kdf_input in kdf_inputs:
        res = kdf.digest(kdf_input, kdf_params, hash_len=32)
        digests.add(res)

    # digests should be unique for unique inputs
    assert len(digests) == len(kdf_inputs)


def test_digest_iters():
    all_kdf_params = set()
    while len(all_kdf_params) < 8:
        kdf_params = kdf.init_kdf_params(p=1, m=random.randint(1, 4) * 8, t=random.randint(1, 20))
        all_kdf_params.add(kdf_params)

    kdf_input = b"\x01\x23\x45\x67" * 4
    digests   = set()
    for kdf_params in all_kdf_params:
        res = kdf.digest(kdf_input, kdf_params, hash_len=32)
        digests.add(res)

    # digests should be unique for unique kdf_params
    assert len(digests) == len(all_kdf_params)


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
