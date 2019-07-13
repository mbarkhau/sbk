# This file is part of the sbk project
# https://gitlab.com/mbarkhau/sbk
#
# Copyright (c) 2019 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT

"""Polynomial calculation functions.

Mainly lagrange interpolation logic.

Helpful introduction: https://www.youtube.com/watch?v=kkMps3X_tEE
(Simple introduction to Shamir's Secret Sharing and Lagrange interpolation)

A helpful introduction to Galois Fields:
https://crypto.stackexchange.com/a/2718
"""

import functools
import typing as typ


# The Euclidean GCD algorithm is based on the principle that the
# greatest common divisor of two numbers does not change if the larger
# number is replaced by its difference with the smaller number. For
# example,
#
#   GCD(252) == 21  # 252 = 21 × 12
#   GCD(105) == 21  # 105 = 21 × 5
#
#   also
#
#   GCD(252 − 105) == 21
#   GCD(147) == 21
#
# Since this replacement reduces the larger of the two numbers,
# repeating this process gives successively smaller pairs of numbers
# until the two numbers become equal. When that occurs, they are the
# GCD of the original two numbers.
#
# By reversing the steps, the GCD can be expressed as a sum of the two
# original numbers each multiplied by a positive or negative integer,
# e.g., 21 = 5 × 105 + (−2) × 252. The fact that the GCD can always be
# expressed in this way is known as Bézout's identity.


class XGCDResult(typ.NamedTuple):
    g: int
    s: int  # sometimes called x
    t: int  # sometimes called y


XgcdFn = typ.Callable[[int, int], XGCDResult]


def check_xgcd(fn: XgcdFn) -> XgcdFn:
    @functools.wraps(fn)
    def wrapper(a: int, b: int) -> XGCDResult:
        res = fn(a, b)
        assert res.s * a + res.t * b == res.g
        return res

    return wrapper


@check_xgcd
def xgcd(a: int, b: int) -> XGCDResult:
    """Extended euclidien greatest common denominator."""
    if a == 0:
        return XGCDResult(b, 0, 1)
    else:
        g, s, t = xgcd(b % a, a)

        q = b // a
        return XGCDResult(g=g, s=t - q * s, t=s)


_SMALL_PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59]

PRIMES = set(_SMALL_PRIMES)

# For this application we want a known prime number as close as
# possible to our security level; e.g. desired security level of 128
# bits -- too large and all the ciphertext is large; too small and
# security is compromised

PRIMES.add(2 ** 521 -   1)  # 13th Mersenne Prime
PRIMES.add(2 ** 256 - 189)
PRIMES.add(2 ** 128 - 159)
PRIMES.add(2 ** 127 -   1)  # 12th Mersenne Prime
PRIMES.add(2 **  64 -  59)
PRIMES.add(2 **  32 -   5)
PRIMES.add(2 **  16 -  15)
PRIMES.add(2 **   8 -   5)


def _is_prime(n: int) -> bool:
    for p in PRIMES:
        if n == p:
            return True

        if n < (p * p) and n % p == 0:
            return False

    if n > max(_SMALL_PRIMES) ** 2:
        raise NotImplementedError

    return True


FFPolyArithmeticMethod = typ.Callable[['FFPoly', 'FFPoly'], 'FFPoly']


def check_ffpoly_compat(a: 'FFPoly', b: 'FFPoly', opname: str) -> None:
    msg_fmt = "Cannot do '{}' on FFPoly of different {}: {} vs {}."

    if a.p != b.p:
        raise ValueError(msg_fmt.format(opname, "characteristic", a.p, b.p))

    # if a.n != b.n:
    #     raise ValueError(msg_fmt.format(opname, "dimension", a.n, b.n))

    len_a = len(a.coeffs)
    len_b = len(b.coeffs)
    if len_a != len_b:
        raise ValueError(msg_fmt.format(opname, "degree", len_a, len_b))


def check_arithmetic_args(fn: FFPolyArithmeticMethod) -> FFPolyArithmeticMethod:
    opname = fn.__name__
    if opname.startswith("__") and fn.__name__.endswith("__"):
        opname = opname[2:-2]

    @functools.wraps(fn)
    def wrapper(self: 'FFPoly', other: 'FFPoly') -> 'FFPoly':
        check_ffpoly_compat(self, other, opname)
        return fn(self, other)

    return wrapper


Coefficients = typ.Sequence[int]

FFPolyOrNum = typ.Union['FFPoly', int]


class FFPoly:
    """Polynomial/Number in a finite field.

    This can also be thought of as simply as a number in a finite
    field.

    The coefficients are ordered in ascending powers of x, so
    FFPoly(2, 5, 3, p=7) is 2x° + 5x¹ + 3x²

    Note that the secret in this case is 2 (the 0th coefficient),
    which corresponds to the y value when we evaluate at x=0. This is
    also why other implementations call this value "intercept" or
    "y_intercept".
    """

    coeffs: Coefficients
    p     : int

    def __init__(self, *coeffs: int, p: int) -> None:
        # NOTE mb: In practice p is always prime, and the operations
        #   are implemented with the assumtion that it is. If p were
        #   not prime, then a multiplicative inverse would not exist
        #   in all cases.
        assert _is_prime(p)
        # NOTE mb: I'm not sure the algorithms work for anything
        #   other than n == 1.

        # aka. characteristic, aka. order
        self.p = p
        # Mod p is done so often as a last operation on the
        # coefficints, that we do it as part of the initialisation.
        self.coeffs = tuple(c % p for c in coeffs)

    def ffpoly(self, coeffs: Coefficients) -> 'FFPoly':
        return FFPoly(*coeffs, p=self.p)

    @check_arithmetic_args
    def __add__(self, other: 'FFPoly') -> 'FFPoly':
        coeffs = [a + b for a, b in zip(self.coeffs, other.coeffs)]
        return self.ffpoly(coeffs)

    @check_arithmetic_args
    def __sub__(self, other: 'FFPoly') -> 'FFPoly':
        coeffs = [a - b for a, b in zip(self.coeffs, other.coeffs)]
        return self.ffpoly(coeffs)

    def __neg__(self) -> 'FFPoly':
        return self.ffpoly([-c for c in self.coeffs])

    def __mul__(self, other: FFPolyOrNum) -> 'FFPoly':
        if isinstance(other, FFPoly):
            return self._ffpoly_mul(other)
        elif isinstance(other, int):
            return self._scalar_mul(other)
        else:
            raise NotImplementedError

    @check_arithmetic_args
    def _ffpoly_mul(self, other: 'FFPoly') -> 'FFPoly':
        new_coeffs = [0] * (len(self.coeffs) + 1)
        for i, a in enumerate(self.coeffs):
            for j, b in enumerate(other.coeffs):
                new_coeffs[i + j] += a * b
                # new_coeffs[i + j] = (a * b) % self.p

        # poly division
        return self.ffpoly(new_coeffs)

    def _scalar_mul(self, scalar: int) -> 'FFPoly':
        return self.ffpoly([c * scalar for c in self.coeffs])

    def __div__(self, other: 'FFPoly') -> 'FFPoly':
        check_ffpoly_compat(self, other, "div")
        raise NotImplementedError

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, FFPoly):
            raise NotImplementedError

        check_ffpoly_compat(self, other, "eq")
        return self.p == other.p and self.coeffs == other.coeffs

    def __call__(self, x: int) -> int:
        """Evaluate polynomial at x."""
        terms = [(coeff * x ** exp) for exp, coeff in enumerate(self.coeffs)]
        return sum(terms) % self.p

    def __repr__(self) -> str:
        coef_str = ", ".join(map(str, self.coeffs))
        return f"FFPoly({coef_str}, p={self.p})"


class GFNum:

    val: int
    p  : int

    def __init__(self, val: int, p: int) -> None:
        # NOTE mb: In practice p is always prime, and the operations
        #   are implemented with the assumtion that it is. If p were
        #   not prime, then a multiplicative inverse would not exist
        #   in all cases.
        assert _is_prime(p)
        self.val = val
        self.p   = p

    def gfnum(self, val: int) -> 'GFNum':
        return GFNum(val % self.p, p=self.p)

    def __add__(self, other: 'GFNum') -> 'GFNum':
        val = self.val + other.val
        return self.gfnum(val)

    def __sub__(self, other: 'GFNum') -> 'GFNum':
        val = self.val - other.val
        return self.gfnum(val)

    def __neg__(self) -> 'GFNum':
        return self.gfnum(-self.val)

    def __mul__(self, other: 'GFNum') -> 'GFNum':
        return self.gfnum(self.val * other.val)

    def _mod_inverse(self) -> 'GFNum':
        assert self.val >= 0
        if self.val < 0:
            t = xgcd(self.p, -self.val).t
        else:
            t = xgcd(self.p, self.val).t
        inv_val = self.p + t
        return self.gfnum(inv_val)

    def __truediv__(self, other: 'GFNum') -> 'GFNum':
        return self * other._mod_inverse()

    def __hash__(self) -> int:
        return hash(self.val) ^ hash(self.p)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, GFNum):
            raise NotImplementedError

        return self.val == other.val and self.p == other.p

    def __repr__(self) -> str:
        return f"GFNum({self.val}, p={self.p})"


class GF:

    p: int

    def __init__(self, p: int) -> None:
        assert _is_prime(p)
        self.p = p

    def __getitem__(self, val: int) -> GFNum:
        return GFNum(val % self.p, self.p)


Num = typ.TypeVar('Num', float, FFPoly, GFNum)


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

    accu = vals[0]
    for val in vals[1:]:
        accu *= val
    return accu


Points = typ.Sequence[Point[Num]]


def _interpolation_terms(points: Points, x: Num) -> typ.Iterable[Num]:
    for p in points:
        others = [o for o in points if o != p]

        numer = prod([x   - o.x for o in others])
        denum = prod([p.x - o.x for o in others])

        yield (p.y * numer) / denum


def interpolate(points: Points, x: Num) -> Num:
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

    # Start with addititve identity (aka. Zero, aka. 0.0).
    # Initialization is done with x - x (vs. just using literal 0.0),
    # so that the implementation also works for FFPoly.
    zero = x - x
    return sum(_interpolation_terms(points, x), zero)
