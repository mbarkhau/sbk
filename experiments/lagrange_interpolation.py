# https://www.youtube.com/watch?v=kkMps3X_tEE

import typing as typ
import functools

FFPolyArithmeticMethod = typ.Callable[['FFPoly', 'FFPoly'], typ.Any]


# The Euclidean GCD algorithm is based on the principle that the
# greatest common divisor of two numbers does not change if the larger
# number is replaced by its difference with the smaller number. For
# example, 21 is the GCD of 252 and 105 (as 252 = 21 × 12 and 105 = 21
# × 5), and the same number 21 is also the GCD of 105 and 252 − 105 =
# 147. Since this replacement reduces the larger of the two numbers,
# repeating this process gives successively smaller pairs of numbers
# until the two numbers become equal. When that occurs, they are the
# GCD of the original two numbers.
#
# By reversing the steps, the GCD can be expressed as a sum of the two
# original numbers each multiplied by a positive or negative integer,
# e.g., 21 = 5 × 105 + (−2) × 252. The fact that the GCD can always be
# expressed in this way is known as Bézout's identity.


class EGCDResult(typ.NamedTuple):
    g: int
    s: int  # sometimes called x
    t: int  # sometimes called y


def egcd(a: int, b: int) -> EGCDResult:
    if a == 0:
        return EGCDResult(b, 0, 1)

    q = b // a
    r = b % a
    g, s, t = egcd(r, a)
    t   = t - q * s
    res = EGCDResult(g, t, s)
    assert res.s * a + res.t * b == res.g
    return res


assert egcd(252, 105) == (21, -2, 5)
assert egcd(105, 252) == (21, 5, -2)

# | i |     qi−1     |         ri        |        si       |          ti         |
# |---|--------------|-------------------|-----------------|---------------------|
# | 0 |              | 240               | 1               | 0                   |
# | 1 |              | 46                | 0               | 1                   |
# | 2 | 240 ÷ 46 = 5 | 240 − 5 × 46 = 10 | 1 − 5 × 0 = 1   | 0 − 5 × 1 = −5      |
# | 3 | 46 ÷ 10 = 4  | 46 − 4 × 10 = 6   | 0 − 4 × 1 = −4  | 1 − 4 × −5 = 21     |
# | 4 | 10 ÷ 6 = 1   | 10 − 1 × 6 = 4    | 1 − 1 × −4 = 5  | −5 − 1 × 21 = −26   |
# | 5 | 6 ÷ 4 = 1    | 6 − 1 × 4 = 2     | −4 − 1 × 5 = −9 | 21 − 1 × −26 = 47   |
# | 6 | 4 ÷ 2 = 2    | 4 − 2 × 2 = 0     | 5 − 2 × −9 = 23 | −26 − 2 × 47 = −120 |

assert egcd(240, 46) == (2, -9, 47)


def mod_inverse(k, prime):
    k = k % prime
    if k < 0:
        t = egcd(prime, -k).t
    else:
        t = egcd(prime, k).t
    return (prime + t) % prime


def check_arithmetic_args(fn: FFPolyArithmeticMethod) -> FFPolyArithmeticMethod:
    @functools.wraps(fn)
    def wrapper(self: 'FFPoly', other: 'FFPoly') -> 'FFPoly':
        assert self.p == other.p
        assert len(self.coeffs) == len(other.coeffs)
        return fn(self, other)

    return wrapper


class FFPoly:
    """Polynomial in a finite field."""

    coeffs: typ.Tuple[int]
    p     : int

    def __init__(self, *coeffs, p=2) -> None:
        self.coeffs = coeffs
        self.p      = p

    @check_arithmetic_args
    def __add__(self, other: 'FFPoly') -> 'FFPoly':
        coeffs = [(a + b) % self.p for a, b in zip(self.coeffs, other.coeffs)]
        return FFPoly(*coeffs, p=self.p)

    @check_arithmetic_args
    def __sub__(self, other: 'FFPoly') -> 'FFPoly':
        coeffs = [(a - b) % self.p for a, b in zip(self.coeffs, other.coeffs)]
        return FFPoly(*coeffs, p=self.p)

    def __neg__(self) -> 'FFPoly':
        coeffs = [(-c) % self.p for c in self.coeffs]
        return FFPoly(*coeffs, p=self.p)

    @check_arithmetic_args
    def __mul__(self, other: 'FFPoly') -> 'FFPoly':
        return FFPoly(*coeffs, p=self.p)

    @check_arithmetic_args
    def __div__(self, other: 'FFPoly') -> 'FFPoly':
        return FFPoly(*coeffs, p=self.p)

    @check_arithmetic_args
    def __eq__(self, other: 'FFPoly') -> bool:
        return self.p == other.p and self.coeffs == other.coeffs

    def __repr__(self) -> str:
        coeffs = ", ".join(map(str, self.coeffs))
        return f"FFPoly({coeffs}, p={self.p})"


a = FFPoly(2, 2, p=3)
b = FFPoly(1, 2, p=3)

print(a)
print(b)
print(a + b)
print(a - b)
assert (a + b) - b == a
assert -a + b == b - a

Num = typ.Union[int, FFPoly]


class Point(typ.NamedTuple):

    x: Num
    y: Num

    def __repr__(self) -> str:
        return f"Point(x={self.x}, y={self.y})"


def prod(vals: typ.Iterable[Num]) -> Num:
    accu = 1
    for val in vals:
        accu *= val
    return accu


def interpolate(points: typ.Iterable[Point], at_x=0) -> Num:
    # \delta_i(x) = \prod{ \frac{x - j}{i - j} }
    # \space
    # \text{for} \space j \in C, j \not= i

    x_vals = [p.x for p in points]
    if len(x_vals) != len(set(x_vals)):
        raise ValueError("Points must be distinct {points}")

    numer = []
    denum = []

    for cur_point in points:
        other_points = list(points)
        other_points.remove(cur_point)

        numer.append(prod(at_x        - o.x for o in other_points))
        denum.append(prod(cur_point.x - o.x for o in other_points))

    return sum([(p.y * numer[i]) / denum[i] for i, p in enumerate(points)])


points = [
    Point( 5,  3),
    Point( 7,  2),
    Point(12,  6),
    Point(30, 15),
]

print("???", interpolate(points))

points = [
    Point( 2, 10),
    Point( 3, 15),
    Point( 5, 25),
    Point( 8, 40),
    Point(12, 60),
]

print(points)

at_x = 4
at_y = interpolate(points, at_x=at_x)
print("???", at_y)

new_points = points + [Point(at_x, at_y)]

print("???", interpolate(points    , at_x=99))
print("???", interpolate(new_points, at_x=99))
