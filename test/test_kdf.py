import random
import importlib

import pytest

from sbk import kdf


def test_digest_progress():
    increments = []

    def _progress_cb(incr) -> None:
        increments.append(incr)

    kdf_params  = kdf.init_kdf_params(p=1, m=10, t=100)
    secret_data = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
    kdf.digest(secret_data, kdf_params, 8, _progress_cb)

    assert len(increments) > 0
    assert increments[-1] == 100


def test_digest_len():
    kdf_params = kdf.init_kdf_params(p=1, m=10, t=1)

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
    for p in range(1, 4):
        for t in range(1, 8):
            kdf_params = kdf.init_kdf_params(p=p, m=10, t=t)
            all_kdf_params.add(kdf_params)

    kdf_input = b"\x01\x23\x45\x67" * 4
    digests   = set()
    for kdf_params in all_kdf_params:
        res = kdf.digest(kdf_input, kdf_params, hash_len=32)
        digests.add(res)

    # digests should be unique for unique kdf_params
    assert len(digests) == len(all_kdf_params)


# NOTE (mb 2021-05-29): As it is essential for us always use
#   the same parameters for a particular version (to ALWAYS
#   reproduce the same keys) we hard-code the values in this
#   test case. This way, we don't change the calculation of
#   the parameters by accident.

V0_KDF_PARAM_CASES = [
    (  1,     10,     1),
    (  2,     20,     2),
    (  4,     40,     4),
    (  6,     50,     5),
    ( 10,     60,     6),
    ( 15,     80,     8),
    ( 22,    100,    10),
    ( 34,    120,    12),
    (172,   2670,    14),
    (875, 133500, 13350),
]


@pytest.mark.parametrize("p, m, t", V0_KDF_PARAM_CASES)
def test_kdf_params(p, m, t):
    kdf_params = kdf.init_kdf_params(p=p, m=m, t=t)
    assert kdf_params.p == p
    assert kdf_params.m == m
    assert kdf_params.t == t


def test_kdf_params_fuzz():
    r = random.Random(0)

    for _ in range(100):
        p = r.randrange(1, int(kdf.P_BASE ** (2 ** 4 - 1))) * kdf.MIN_P
        m = r.randrange(1, int(kdf.M_BASE ** (2 ** 6 - 1))) * kdf.MIN_M
        t = r.randrange(1, int(kdf.T_BASE ** (2 ** 6 - 1))) * kdf.MIN_T

        kdf_params = kdf.init_kdf_params(p=p, m=m, t=t)
        decoded    = kdf.KDFParams.decode(kdf_params.encode())
        assert decoded == kdf_params

        dp = abs(kdf_params.p - p) / kdf_params.p
        dm = abs(kdf_params.m - m) / kdf_params.m
        dt = abs(kdf_params.t - t) / kdf_params.t

        assert dp <= 0.5
        assert dm <= 0.5
        assert dt <= 0.5


def test_argon2_fuzz():
    # Compare two implementations. Ostensibly they both use
    # the same implementation underneath, so there should
    # be absolutely no difference
    try:
        importlib.import_module('pyargon2')
    except ImportError:
        return

    r = random.Random(0)

    for _ in range(10):
        p = r.randrange(1,   4)
        m = r.randrange(1, 100)
        t = r.randrange(1,   4)

        kdf_params = kdf.init_kdf_params(p=p, m=m, t=t)

        test_data = str(r.random()) * 2

        hash_data_1 = kdf._hash_pyargon2(
            test_data,
            t=kdf_params.t,
            p=kdf_params.p,
            m=kdf_params.m,
        )

        hash_data_2 = kdf._hash_argon2_cffi(
            test_data.encode("utf-8"),
            t=kdf_params.t,
            p=kdf_params.p,
            m=kdf_params.m,
        )

        assert hash_data_1 == hash_data_2, kdf_params
