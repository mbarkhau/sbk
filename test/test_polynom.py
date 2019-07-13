import random

from sbk.polynom import *


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
    assert xgcd(240,  46) == XGCDResult(g=2 , s=-9, t=47)


def test_prod():
    assert prod([1  ]) == 1
    assert prod([2.0]) == 2.0
    assert prod([2, 3, 4]) == 24


def test_ffpoly_init():
    x = FFPoly(2, 5, p=7)

    assert x.coeffs == (2, 5)

    assert x.p == 7


def alt_eval(coeffs, p):
    """An alternative implementation of eval for validation.

    https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing
    """

    def eval_fn(x):
        accu = 0
        for coeff in reversed(coeffs):
            accu *= x
            accu += coeff
            accu %= p
        return accu

    return eval_fn


def test_ffpoly_eval():
    a = FFPoly(2, 3, 4, p=7)
    e = alt_eval([2, 3, 4], p=7)

    # 2*0° + 3*0¹ + 4*0² == (2 + 3 + 4) % 7 == 9 % 7 == 2
    assert a(x=0) == (2 + 3 + 4) % 7
    assert a(x=0) == e(x=0)

    # 2*1° + 3*1¹ + 4*1² == (2 + 3 + 4) % 7 == 9 % 7 == 2
    assert a(x=1) == (2 + 3 + 4) % 7
    assert a(x=1) == e(x=1)

    # 2*2° + 3*2¹ + 4*2² == (2 + 6 + 16) % 7 == 24 % 7 == 3
    assert a(x=2) == (2 + 6 + 16) % 7
    assert a(x=2) == e(x=2)

    # 2*3° + 3*3¹ + 4*3² == (2 + 9 + 36) % 7 == 47 % 7 == 5
    assert a(x=3) == (2 + 9 + 36) % 7
    assert a(x=3) == e(x=3)


def test_ffpoly_eval_fuzz():
    primes = sorted(PRIMES)
    for _ in range(100):
        p      = random.choice(primes)
        coeffs = [random.randint(0, p - 1) for _ in range(random.randint(1, 9))]
        a      = FFPoly(*coeffs, p=p)
        e      = alt_eval(coeffs, p=p)
        for _ in range(10):
            x = random.randint(0, p - 1)
            assert a(x) == e(x)


def test_ffpoly_add_sub():
    a = FFPoly(2, 2, p=3)
    b = FFPoly(1, 2, p=3)
    assert (a + b) - b == a
    assert -a + b == b - a


def test_ffpoly_mul():
    a = FFPoly(2, 2, p=7)
    b = FFPoly(1, 2, p=7)
    c = FFPoly(2, 2 + 4, 4, p=7)

    assert a * b == c

    # a = FFPoly(2, 2, p=3)
    # b = FFPoly(1, 2, p=3)
    # c = FFPoly(1, 1, p=3)

    # assert a * b == c


def test_interpolate_deg1_float():
    points = [Point(0.0, 0.0), Point(1.0, 2.0), Point(2.0, 4.0)]
    at_x, at_y = points[-1]
    interp_y = interpolate(points[:-1], at_x)
    assert interp_y == at_y

    assert interpolate(points[:-1], x=0.5) == 1.00


def test_interpolate_deg2_float():
    points = [
        Point(0.0, 0.0),
        Point(1.0, 1.0),
        Point(2.0, 4.0),
        Point(3.0, 9.0),
    ]
    at_x, at_y = points[-1]
    interp_y = interpolate(points[:-1], at_x)
    assert interp_y == at_y

    assert interpolate(points[:-1], x=0.5) == 0.25


def test_gf_arithmetic():
    gf = GF(7)

    zero = gf[0]
    one = gf[1]
    two = gf[2]
    five = gf[5]

    assert gf[0] == gf[7]
    assert gf[1] == gf[8]

    assert one - one == zero
    assert two - two == zero

    assert one * two == two
    assert two * two + one == five
    assert two * two * two == gf[1]

    assert two / one == two
    assert two / two == one


def test_interpolate_gf():
    gf = GF(7)
    points = [
        Point(gf[0], gf[0]),
        Point(gf[1], gf[1]),
        Point(gf[2], gf[4]),
        Point(gf[3], gf[9]),
    ]
    at_x, at_y = points[-1]
    interp_y = interpolate(points[:-1], at_x)
    assert interp_y == at_y

    assert interpolate(points[:-1], x=gf[1] / gf[2]) == gf[1] / gf[4]
