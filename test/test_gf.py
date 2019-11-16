import os
import random

import pytest

import sbk.gf_lut
import sbk.primes
from sbk.gf import *
from sbk.gf_poly import *
from sbk.gf_util import *


def test_mul_basic():
    cases = [
        (0x00, 0x00, 0x00),
        (0x00, 0x01, 0x00),
        (0x01, 0x00, 0x00),
        (0x03, 0x07, 0x09),
        (0x57, 0x83, 0xC1),
        (0x57, 0x13, 0xFE),
    ]
    for a, b, expected in cases:
        assert mul(a, b) == expected
        assert mul_slow(a, b) == expected


def test_mul_lut():
    for _ in range(10):
        a = random.randrange(256)
        b = random.randrange(256)
        assert mul_slow(a, b) == mul(a, b)


def test_lut_vs_slip0039_reference():
    # https://github.com/trezor/python-shamir-mnemonic/blob/bfde987bcb/shamir_mnemonic/__init__.py#L92
    def _precompute_exp_log():
        exp = [0 for i in range(255)]
        log = [0 for i in range(256)]

        poly = 1
        for i in range(255):
            exp[i   ] = poly
            log[poly] = i

            # Multiply poly by the polynomial x + 1.
            poly = (poly << 1) ^ poly

            # Reduce poly by x^8 + x^4 + x^3 + x + 1.
            if poly & 0x100:
                poly ^= 0x11B

        return exp, log

    _EXP_TABLE, _LOG_TABLE = _precompute_exp_log()
    assert _EXP_TABLE == sbk.gf_lut.EXP_LUT
    assert _LOG_TABLE == sbk.gf_lut.LOG_LUT


def test_mul_inverse_lut():
    for n in range(256):
        assert inverse_slow(n) == sbk.gf_lut.MUL_INVERSE_LUT[n], n


# Case 3: xgcd(240, 46)
# | i |     qi−1     |         ri        |        si       |          ti         |
# |---|--------------|-------------------|-----------------|---------------------|
# | 0 |              | 240               | 1               | 0                   |
# | 1 |              | 46                | 0               | 1                   |
# | 2 | 240 ÷ 46 = 5 | 240 − 5 × 46 = 10 | 1 − 5 × 0 = 1   | 0 − 5 × 1 = −5      |
# | 3 | 46 ÷ 10 = 4  | 46 − 4 × 10 = 6   | 0 − 4 × 1 = −4  | 1 − 4 × −5 = 21     |
# | 4 | 10 ÷ 6 = 1   | 10 − 1 × 6 = 4    | 1 − 1 × −4 = 5  | −5 − 1 × 21 = −26   |
# | 5 | 6 ÷ 4 = 1    | 6 − 1 × 4 = 2     | −4 − 1 × 5 = −9 | 21 − 1 × −26 = 47   |
# | 6 | 4 ÷ 2 = 2    | 4 − 2 × 2 = 0     | 5 − 2 × −9 = 23 | −26 − 2 × 47 = −120 |


def test_xgcd():
    assert xgcd(252, 105) == XGCDResult(g=21, s=-2, t=5)
    assert xgcd(105, 252) == XGCDResult(g=21, s=5, t=-2)
    assert xgcd(240, 46) == XGCDResult(g=2, s=-9, t=47)


def test_prod():
    assert prod([1]) == 1
    assert prod([2.0]) == 2.0
    assert prod([2, 3, 4]) == 24

    try:
        prod([])
        assert False, "expected ValueError"
    except ValueError as ex:
        assert "at least one value" in str(ex)


def test_point():
    p = Point(1, 2)
    assert repr(p)
    assert list(p) == [1, 2]
    assert p == Point(1, 2)

    try:
        Point(1, 2) == (1, 2)
    except NotImplementedError:
        pass


def alt_eval_at(coeffs, p):
    """An alternative implementation of eval for validation.

    https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing
    """

    def eval_fn(at_x):
        accu = 0
        for coeff in reversed(coeffs):
            accu *= at_x
            accu += coeff
            accu %= p
        return accu

    return eval_fn


def test_gfpoly_eval():
    gf7       = GFNum.field(7)
    coeffs    = [2, 3, 4]
    gf_coeffs = [gf7[2], gf7[3], gf7[4]]

    _eval_at1 = poly_eval_fn(gf7, gf_coeffs)
    _eval_at2 = alt_eval_at(coeffs, p=7)

    # 2*0° + 3*0¹ + 4*0² == (2 + 3 + 4) % 7 == 9 % 7 == 2
    assert _eval_at1(at_x=0) == (2 + 3 + 4) % 7
    assert _eval_at1(at_x=0) == _eval_at2(at_x=0)

    # 2*1° + 3*1¹ + 4*1² == (2 + 3 + 4) % 7 == 9 % 7 == 2
    assert _eval_at1(at_x=1) == (2 + 3 + 4) % 7
    assert _eval_at1(at_x=1) == _eval_at2(at_x=1)

    # 2*2° + 3*2¹ + 4*2² == (2 + 6 + 16) % 7 == 24 % 7 == 3
    assert _eval_at1(at_x=2) == (2 + 6 + 16) % 7
    assert _eval_at1(at_x=2) == _eval_at2(at_x=2)

    # 2*3° + 3*3¹ + 4*3² == (2 + 9 + 36) % 7 == 47 % 7 == 5
    assert _eval_at1(at_x=3) == (2 + 9 + 36) % 7
    assert _eval_at1(at_x=3) == _eval_at2(at_x=3)


def test_gfpoly_eval_fuzz():
    primes = sorted(sbk.primes.PRIMES)
    for _ in range(100):
        p     = random.choice(primes)
        field = GFNum.field(p)

        coeffs    = [random.randrange(p) for _ in range(random.randint(1, min(9, p)))]
        gf_coeffs = [field[coeff] for coeff in coeffs]

        _eval_at1 = poly_eval_fn(field, gf_coeffs)
        _eval_at2 = alt_eval_at(coeffs, p=p)
        for _ in range(10):
            x = random.randrange(p)
            assert _eval_at1(x) == _eval_at2(x)


def test_interpolate_deg1_float():
    def f(x: float) -> float:
        return 2 * x + 1

    points = [Point(x, f(x)) for x in [1.0, 2.0, 3.0]]

    at_x, at_y = points[-1]
    interp_y = interpolate(points[:-1], at_x=at_x)
    assert interp_y == at_y

    assert interpolate(points[:-1], at_x=0.5) == 2.00
    assert interpolate(points[1:], at_x=0.5) == 2.00


def test_interpolate_deg2_float():
    def f(x: float) -> float:
        xsq = x * x
        return 3 * xsq + 2 * x + 1

    points = [Point(x, f(x)) for x in [1.0, 2.0, 3.0, 4.0]]

    at_x, at_y = points[-1]
    interp_y = interpolate(points[:-1], at_x=at_x)
    assert interp_y == at_y

    assert interpolate(points[:-1], at_x=0.5) == f(0.5)
    assert interpolate(points[1:], at_x=0.5) == f(0.5)


def test_interpolate_overspecified():
    def f(x: float) -> float:
        xsq = x * x
        return 3 * xsq + 2 * x + 1

    points = [Point(x, f(x)) for x in [1.0, 2.0, 3.0, 4.0, 5.0, 6.0]]
    for at_x in [0.5, 1.5, 2.5, 3.5, 4.5, 5.5]:
        assert interpolate(points, at_x=at_x) == f(at_x)
        assert interpolate(points[:-2], at_x=at_x) == f(at_x)
        assert interpolate(points[2:], at_x=at_x) == f(at_x)


def test_gf_arithmetic():
    gf7 = GFNum.field(7)

    assert val_of(3  ) == 3
    assert val_of(3.0) == 3.0
    assert val_of(gf7[3]) == 3

    zero = gf7[0]
    one  = gf7[1]
    two  = gf7[2]
    five = gf7[5]

    assert gf7[0] == gf7[7]
    assert gf7[1] == gf7[8]

    assert one - one == zero
    assert two - two == zero

    assert one * two == two
    assert two * two + one == five
    assert two * two * two == gf7[1]

    assert two / one == two
    assert two / two == one


def test_interpolate_gf():
    gf7 = GFNum.field(7)

    points = [
        Point(gf7[1], gf7[0]),
        Point(gf7[2], gf7[1]),
        Point(gf7[3], gf7[4]),
        Point(gf7[4], gf7[9]),
    ]
    at_x, at_y = points[-1]
    interp_y = interpolate(points[:-1], at_x=at_x)
    assert interp_y == at_y

    assert interpolate(points[:-1], at_x=gf7[1] / gf7[2]) == gf7[1] / gf7[4]


def test_interpolate_fail():
    gf7    = GFNum.field(7)
    points = [
        Point(gf7[1], gf7[0]),
        Point(gf7[1], gf7[1]),
    ]

    try:
        interpolate([], at_x=gf7[1])
        assert False, "expected ValueError"
    except ValueError as ex:
        assert "fewer than two points" in str(ex)

    try:
        interpolate(points[:1], at_x=gf7[1])
        assert False, "expected ValueError"
    except ValueError as ex:
        assert "fewer than two points" in str(ex)

    try:
        interpolate(points, at_x=gf7[1])
        assert False, "expected ValueError"
    except ValueError as ex:
        assert "Points must be distinct" in str(ex)


def test_interpolate_attack():
    gf = GFNum.field(1021)

    points = [
        Point(gf[1], gf[0]),
        Point(gf[2], gf[1]),
        Point(gf[3], gf[4]),
    ]

    try:
        interpolate([Point(gf[0], gf[0])] + points, at_x=gf[0])
        assert False, "expected Exception"
    except Exception as ex:
        assert "Invalid share" in str(ex)
        assert "Possible attack" in str(ex)

    try:
        interpolate([Point(gf[255], gf[0])] + points, at_x=gf[0])
        assert False, "expected Exception"
    except Exception as ex:
        assert "Invalid share" in str(ex)
        assert "Possible attack" in str(ex)


def test_split_and_join_2of3():
    prime = min(p for p in sbk.primes.PRIMES if p > 10000000)
    field = GFNum.field(prime)

    secret = random.randrange(10000000)
    points = split(field, threshold=2, num_shares=3, secret=secret)
    assert [p.x.val for p in points] == [1, 2, 3]
    assert not any(p.y.val == secret for p in points)

    assert join(field, points=points, threshold=2) == secret

    sample1 = [points[0], points[1]]
    sample2 = [points[0], points[2]]
    sample3 = [points[1], points[2]]

    assert join(field, points=sample1, threshold=2) == secret
    assert join(field, points=sample2, threshold=2) == secret
    assert join(field, points=sample3, threshold=2) == secret


TEST_PRIME_INDEXES = random.sample([i for i, p in enumerate(sbk.primes.PRIMES) if p > 10], 10)


@pytest.mark.parametrize("prime_index", TEST_PRIME_INDEXES)
def test_split_and_join_fuzz(prime_index):
    prime      = sbk.primes.PRIMES[prime_index]
    secret     = random.randint(0, prime - 1)
    num_shares = random.randint(2, 7)
    threshold  = random.randint(2, num_shares)
    debug_info = {
        'threshold' : threshold,
        'num_shares': num_shares,
        'prime'     : prime,
        'secret'    : secret,
    }
    field     = GFNum.field(prime)
    points    = split(field=field, threshold=threshold, num_shares=num_shares, secret=secret)
    actual_xs = [p.x.val for p in points]
    actual_ys = [p.y.val for p in points]

    expected_xs = list(range(1, num_shares + 1))
    assert actual_xs == expected_xs, debug_info

    # we accept collisions for primes below 100k, everything else
    # is probably not a coincidence/is probably a bug.
    lt_100k = prime < 100_000
    assert lt_100k or secret not in actual_ys, debug_info

    recovered_secret = join(field=field, threshold=num_shares, points=points)
    assert recovered_secret == secret, debug_info

    for i in range(num_shares - threshold):
        debug_info['sample_size'] = threshold + i
        sample           = random.sample(points, threshold + i)
        recovered_secret = join(field=field, threshold=threshold, points=sample)
        assert recovered_secret == secret, debug_info
