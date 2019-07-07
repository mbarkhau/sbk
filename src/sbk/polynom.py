# This file is part of the sbk project
# https://gitlab.com/mbarkhau/sbk
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
    """Extended euclidien greatest common denominator."""
    if a == 0:
        return EGCDResult(b, 0, 1)

    q = b // a
    r = b % a
    g, s, t = egcd(r, a)
    t   = t - q * s
    res = EGCDResult(g, t, s)
    assert res.s * a + res.t * b == res.g
    return res


# def mod_inverse(k, prime):
#     k = k % prime
#     if k < 0:
#         t = egcd(prime, -k).t
#     else:
#         t = egcd(prime, k).t
#     return (prime + t) % prime


FFPolyArithmeticMethod = typ.Callable[['FFPoly', 'FFPoly'], 'FFPoly']


def check_arithmetic_args(fn: FFPolyArithmeticMethod) -> FFPolyArithmeticMethod:
    @functools.wraps(fn)
    def wrapper(self: 'FFPoly', other: 'FFPoly') -> 'FFPoly':
        assert self.p == other.p
        assert len(self.coeffs) == len(other.coeffs)
        return fn(self, other)

    return wrapper


class FFPoly:
    """Polynomial in a finite field."""

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
        raise NotImplementedError
        return FFPoly(*[], p=self.p)

    @check_arithmetic_args
    def __div__(self, other: 'FFPoly') -> 'FFPoly':
        raise NotImplementedError
        return FFPoly(*[], p=self.p)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, FFPoly):
            raise NotImplementedError

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
            raise NotImplementedError

        return self.x == other.x and self.y == other.y

    def __repr__(self) -> str:
        return f"Point(x={self.x}, y={self.y})"

    def __iter__(self) -> typ.Iterable[Num]:
        yield self.x
        yield self.y


def prod(vals: typ.Sequence[Num]) -> Num:
    """Product of numbers.

    This is sometimes also denoted by Π (upper case PI).
    """
    if len(vals) == 0:
        raise ValueError("prod requires at least one value")

    val_iter = iter(vals)
    accu     = next(val_iter)
    for val in val_iter:
        accu *= val
    return accu


Points = typ.Sequence[Point[Num]]


def interpolate(points: Points, at_x: Num) -> Num:
    r"""Interpolate y value at x for a polynomial.

    # \delta_i(x) = \prod{ \frac{x - j}{i - j} }
    # \space
    # \text{for} \space j \in C, j \not= i
    """

    if len(points) < 2:
        raise ValueError("Cannot interpolate with fewer than two points")

    x_vals = [p.x for p in points]
    if len(x_vals) != len(set(x_vals)):
        raise ValueError("Points must be distinct {points}")

    def sum_parts() -> typ.Iterable[Num]:
        for p in points:
            other_points = list(points)
            other_points.remove(p)

            cur_x = p.x
            numer = prod([at_x  - o.x for o in other_points])
            denum = prod([cur_x - o.x for o in other_points])

            yield (p.y * numer) / denum

    parts = iter(sum_parts())
    rv    = next(parts)

    for p in parts:
        rv += p
    return rv
