from sbk.polynom import *


# Case 3: egcd(240, 46)
# | i |     qi−1     |         ri        |        si       |          ti         |
# |---|--------------|-------------------|-----------------|---------------------|
# | 0 |              | 240               | 1               | 0                   |
# | 1 |              | 46                | 0               | 1                   |
# | 2 | 240 ÷ 46 = 5 | 240 − 5 × 46 = 10 | 1 − 5 × 0 = 1   | 0 − 5 × 1 = −5      |
# | 3 | 46 ÷ 10 = 4  | 46 − 4 × 10 = 6   | 0 − 4 × 1 = −4  | 1 − 4 × −5 = 21     |
# | 4 | 10 ÷ 6 = 1   | 10 − 1 × 6 = 4    | 1 − 1 × −4 = 5  | −5 − 1 × 21 = −26   |
# | 5 | 6 ÷ 4 = 1    | 6 − 1 × 4 = 2     | −4 − 1 × 5 = −9 | 21 − 1 × −26 = 47   |
# | 6 | 4 ÷ 2 = 2    | 4 − 2 × 2 = 0     | 5 − 2 × −9 = 23 | −26 − 2 × 47 = −120 |


def test_egcd():
    assert egcd(252, 105) == EGCDResult(g=21, s=-2, t=5)
    assert egcd(105, 252) == EGCDResult(g=21, s=5, t=-2)
    assert egcd(240,  46) == EGCDResult(g=2 , s=-9, t=47)


def test_prod():
    assert prod([1  ]) == 1
    assert prod([2.0]) == 2.0
    assert prod([2, 3, 4]) == 24


def test_ffpoly_add_sub():
    a = FFPoly(2.0, 2.0, p=3)
    b = FFPoly(1.0, 2.0, p=3)
    assert (a + b) - b == a
    assert -a + b == b - a


def test_ffpoly_mul():
    a = FFPoly(2.0, 2.0, p=3)
    b = FFPoly(1.0, 2.0, p=3)

    assert a * b ==


def test_ffpoly_div():
    a = FFPoly(2.0, 2.0, p=3)
    b = FFPoly(1.0, 2.0, p=3)
    c = FFPoly(1.0, 1.0, p=3)
    assert a / b == c


def test_interpolate_deg1_float():
    points = [Point(0.0, 0.0), Point(1.0, 2.0), Point(2.0, 4.0)]
    at_x, at_y = points[-1]
    interp_y = interpolate(points[:-1], at_x)
    assert interp_y == at_y

    assert interpolate(points[:-1], at_x=0.5) == 1.00


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

    assert interpolate(points[:-1], at_x=0.5) == 0.25


def test_interpolate_deg1_ffpoly():
    assert False


def test_interpolate_deg2_ffpoly():
    assert False
