# This file is part of the ssk project
# https://gitlab.com/mbarkhau/ssk
#
# Copyright (c) 2019 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT
"""Polynomial calculation functions.

Mainly lagrange interpolation logic.

Helpful introduction: https://www.youtube.com/watch?v=kkMps3X_tEE
(Simple introduction to Shamir's Secret Sharing and Lagrange interpolation)
"""

import functools
import typing as typ


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
    """

    >>> egcd(252, 105)
    (21, -2, 5)
    >>> egcd(105, 252)
    (21, 5, -2)
    >>> egcd(240, 46)
    (2, -9, 47)
    """
    if a == 0:
        return EGCDResult(b, 0, 1)

    q = b // a
    r = b % a
    g, s, t = egcd(r, a)
    t   = t - q * s
    res = EGCDResult(g, t, s)
    assert res.s * a + res.t * b == res.g
    return res


# Case 3 from docstring egcd(240, 46)
# | i |     qi−1     |         ri        |        si       |          ti         |
# |---|--------------|-------------------|-----------------|---------------------|
# | 0 |              | 240               | 1               | 0                   |
# | 1 |              | 46                | 0               | 1                   |
# | 2 | 240 ÷ 46 = 5 | 240 − 5 × 46 = 10 | 1 − 5 × 0 = 1   | 0 − 5 × 1 = −5      |
# | 3 | 46 ÷ 10 = 4  | 46 − 4 × 10 = 6   | 0 − 4 × 1 = −4  | 1 − 4 × −5 = 21     |
# | 4 | 10 ÷ 6 = 1   | 10 − 1 × 6 = 4    | 1 − 1 × −4 = 5  | −5 − 1 × 21 = −26   |
# | 5 | 6 ÷ 4 = 1    | 6 − 1 × 4 = 2     | −4 − 1 × 5 = −9 | 21 − 1 × −26 = 47   |
# | 6 | 4 ÷ 2 = 2    | 4 − 2 × 2 = 0     | 5 − 2 × −9 = 23 | −26 − 2 × 47 = −120 |


def mod_inverse(k, prime):
    k = k % prime
    if k < 0:
        t = egcd(prime, -k).t
    else:
        t = egcd(prime, k).t
    return (prime + t) % prime


FFPolyArithmeticMethod = typ.Callable[['FFPoly', 'FFPoly'], 'FFPoly']


def check_arithmetic_args(fn: FFPolyArithmeticMethod) -> FFPolyArithmeticMethod:
    @functools.wraps(fn)
    def wrapper(self: 'FFPoly', other: 'FFPoly') -> 'FFPoly':
        assert self.p == other.p
        assert len(self.coeffs) == len(other.coeffs)
        return fn(self, other)

    return wrapper


class FFPoly:
    """Polynomial in a finite field.

    >>> a = FFPoly(2.0, 2.0, p=3)
    >>> b = FFPoly(1.0, 2.0, p=3)
    >>> (a + b) - b == a
    True
    >>> -a + b == b - a
    True
    """

    coeffs: typ.Tuple[float, ...]
    p     : int

    def __init__(self, *coeffs: float, p: int = 2) -> None:
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
        assert False
        return FFPoly(*[], p=self.p)

    @check_arithmetic_args
    def __div__(self, other: 'FFPoly') -> 'FFPoly':
        assert False
        return FFPoly(*[], p=self.p)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, FFPoly):
            raise NotImplemented

        return self.p == other.p and self.coeffs == other.coeffs

    def __repr__(self) -> str:
        coeffs = ", ".join(map(str, self.coeffs))
        return f"FFPoly({coeffs}, p={self.p})"


Num = typ.TypeVar('Num', float, FFPoly)


class Point(typ.Generic[Num]):

    x: Num
    y: Num

    def __init__(self, x: Num, y: Num) -> None:
        self.x = x
        self.y = y

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Point):
            raise NotImplemented

        return self.x == other.x and self.y == other.y

    def __repr__(self) -> str:
        return f"Point(x={self.x}, y={self.y})"


def addititve_identity(n: Num) -> Num:
    return n - n


def multiplicative_identity(n: Num) -> Num:
    if isinstance(n, int):
        return 1
    elif isinstance(n, float):
        return 1.0
    elif isinstance(n, FFPoly):
        coeffs = [1.0] * len(n.coeffs)
        return FFPoly(*coeffs, p=n.p)
    else:
        raise NotImplemented


def prod(vals: typ.Sequence[Num]) -> Num:
    assert len(vals) > 0

    accu = multiplicative_identity(vals[0])
    for val in vals:
        accu *= val
    return accu


PointNum = typ.TypeVar


def interpolate(points: typ.Sequence[Point[Num]], at_x=0) -> Num:
    """Interpolate y value at x for a polynomial.

    >>> # test polynomials are overspecified
    >>> deg1_points = [
    ...     Point(0.0, 0.0),
    ...     Point(1.0, 2.0),
    ...     Point(2.0, 4.0),
    ... ]
    >>> at_x, at_y = deg1_points[-1]
    >>> interp_y = interpolate(deg1_points[:-1], at_x)
    >>> (at_y, interp_y)
    (4.0, 4.0)

    >>> deg2_points = [
    ...     Point(0.0, 0.0),
    ...     Point(1.0, 1.0),
    ...     Point(2.0, 4.0),
    ...     Point(3.0, 9.0),
    ... ]
    >>> at_x, at_y = deg2_points[-1]
    >>> interp_y = interpolate(deg2_points[:-1], at_x)
    >>> (at_y, interp_y)
    (9.0, 9.0)

    >>> interpolate(deg2_points[:-1], at_x=0.5)
    0.25
    """
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

        cur_x = cur_point.x
        numer.append(prod([at_x  - o.x for o in other_points]))
        denum.append(prod([cur_x - o.x for o in other_points]))

    return sum([(p.y * numer[i]) / denum[i] for i, p in enumerate(points)])
