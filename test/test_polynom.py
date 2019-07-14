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


def alt_eval_at(coeffs, p):
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
    gf7     = GF(7)
    poly    = [2, 3, 4]
    gf_poly = [gf7[2], gf7[3], gf7[4]]

    _eval_at1 = poly_eval_fn(gf_poly)
    _eval_at2 = alt_eval_at(poly, p=7)

    # 2*0° + 3*0¹ + 4*0² == (2 + 3 + 4) % 7 == 9 % 7 == 2
    assert _eval_at1(x=0) == (2 + 3 + 4) % 7
    assert _eval_at1(x=0) == _eval_at2(x=0)

    # 2*1° + 3*1¹ + 4*1² == (2 + 3 + 4) % 7 == 9 % 7 == 2
    assert _eval_at1(x=1) == (2 + 3 + 4) % 7
    assert _eval_at1(x=1) == _eval_at2(x=1)

    # 2*2° + 3*2¹ + 4*2² == (2 + 6 + 16) % 7 == 24 % 7 == 3
    assert _eval_at1(x=2) == (2 + 6 + 16) % 7
    assert _eval_at1(x=2) == _eval_at2(x=2)

    # 2*3° + 3*3¹ + 4*3² == (2 + 9 + 36) % 7 == 47 % 7 == 5
    assert _eval_at1(x=3) == (2 + 9 + 36) % 7
    assert _eval_at1(x=3) == _eval_at2(x=3)


def test_ffpoly_eval_fuzz():
    primes = sorted(PRIMES)
    for _ in range(100):
        p  = random.choice(primes)
        gf = GF(p)

        poly    = [random.randint(0, p - 1) for _ in range(random.randint(1, 9))]
        gf_poly = [gf[coeff] for coeff in poly]

        e1 = poly_eval_fn(gf_poly)
        e2 = alt_eval_at(poly, p=p)
        for _ in range(10):
            x = random.randint(0, p - 1)
            assert e1(x) == e2(x)


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
    gf7 = GF(7)

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
    gf     = GF(7)
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


def test_split_and_join_2of3():
    secret = random.randint(0, 10000000)
    prime  = min(p for p in PRIMES if p > 10000000)
    points = split(prime, threshold=2, num_pieces=3, secret=secret)
    assert [p.x.val for p in points] == [1, 2, 3]
    assert not any(p.y.val == secret for p in points)

    assert join(threshold=2, points=points) == secret

    sample1 = [points[0], points[1]]
    sample2 = [points[0], points[2]]
    sample3 = [points[1], points[2]]

    assert join(threshold=2, points=sample1) == secret
    assert join(threshold=2, points=sample2) == secret
    assert join(threshold=2, points=sample3) == secret


def test_split_and_join_fuzz():
    primes = sorted([p for p in PRIMES if p > 10])
    for _ in range(100):
        prime      = random.choice(primes)
        secret     = random.randint(0, prime - 1)
        num_pieces = random.randint(2, 7)
        threshold  = random.randint(2, num_pieces)
        debug_info = {
            'threshold' : threshold,
            'num_pieces': num_pieces,
            'prime'     : prime,
            'secret'    : secret,
        }
        points = split(
            prime=prime,
            threshold=threshold,
            num_pieces=num_pieces,
            secret=secret,
        )
        actual_xs = [p.x.val for p in points]
        actual_ys = [p.y.val for p in points]

        expected_xs = list(range(1, num_pieces + 1))
        assert actual_xs == expected_xs, debug_info

        # we accept collisions for primes below 100k, everything else
        # is probably not a coincidence/is probably a bug.
        lt_100k = prime < 100_000
        assert lt_100k or secret not in actual_ys, debug_info

        recovered_secret = join(threshold=num_pieces, points=points)
        assert recovered_secret == secret, debug_info

        for i in range(num_pieces - threshold):
            debug_info['sample_size'] = threshold + i
            sample           = random.sample(points, threshold + i)
            recovered_secret = join(threshold=threshold, points=sample)
            assert recovered_secret == secret, debug_info
