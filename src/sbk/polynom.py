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

import random
import itertools
import functools
import typing as typ

from . import primes


randint = functools.partial(random.SystemRandom().randint, 0)


Num = typ.TypeVar('Num', int, 'GFNum')


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


def xgcd(a: int, b: int) -> XGCDResult:
    """Extended euclidien greatest common denominator."""
    if a == 0:
        return XGCDResult(b, 0, 1)

    g, s, t = xgcd(b % a, a)

    q   = b // a
    res = XGCDResult(g=g, s=t - q * s, t=s)
    assert res.s * a + res.t * b == res.g
    return res


def val_of(other: Num) -> int:
    if isinstance(other, int):
        return other
    elif isinstance(other, GFNum):
        return other.val
    else:
        raise NotImplementedError


Coefficients = typ.Sequence[Num]


class GFNum:

    val: int
    p  : int

    def __init__(self, val: int, p: int) -> None:
        # NOTE mb: In practice p is always prime, and the operations
        #   are implemented with the assumtion that it is. If p were
        #   not prime, then a multiplicative inverse would not exist
        #   in all cases.
        assert primes.is_prime(p)
        self.p = p

        self.val = val

    def gfnum(self, val: int) -> 'GFNum':
        # Mod p is done so often as a last operation on the val, that
        # we do it as part of the initialisation.
        return GFNum(val % self.p, p=self.p)

    def __add__(self, other: Num) -> 'GFNum':
        other_val = val_of(other)
        return self.gfnum(self.val + other_val)

    def __sub__(self, other: Num) -> 'GFNum':
        other_val = val_of(other)
        return self.gfnum(self.val - other_val)

    def __neg__(self) -> 'GFNum':
        return self.gfnum(-self.val)

    def __mul__(self, other: Num) -> 'GFNum':
        other_val = val_of(other)
        return self.gfnum(self.val * other_val)

    def _mod_inverse(self) -> 'GFNum':
        assert self.val >= 0
        if self.val < 0:
            t = xgcd(self.p, -self.val).t
        else:
            t = xgcd(self.p, self.val).t
        inv_val = self.p + t
        return self.gfnum(inv_val)

    def __pow__(self, other: Num) -> 'GFNum':
        other_val = val_of(other)
        return self.gfnum(self.val ** other_val)

    def __truediv__(self, other: 'GFNum') -> 'GFNum':
        return self * other._mod_inverse()

    def __radd__(self, other: int) -> 'GFNum':
        return self.gfnum(other + self.val)

    def __rsub__(self, other: int) -> 'GFNum':
        return self.gfnum(other - self.val)

    def __rmul__(self, other: int) -> 'GFNum':
        return self.gfnum(other * self.val)

    def __hash__(self) -> int:
        return hash(self.val) ^ hash(self.p)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, GFNum):
            raise NotImplementedError
        if self.p != other.p:
            raise ValueError("Numbers inf different fields are not comparable")

        return self.val == other.val

    def __repr__(self) -> str:
        return f"GFNum({self.val}, p={self.p})"


class GF:

    p: int

    def __init__(self, p: int) -> None:
        # NOTE mb: In practice p is always prime, and the operations
        #   are implemented with the assumtion that it is. If p were
        #   not prime, then a multiplicative inverse would not exist
        #   in all cases.

        assert primes.is_prime(p)

        # aka. characteristic, aka. order
        self.p = p

    def __getitem__(self, val: int) -> GFNum:
        return GFNum(val % self.p, self.p)


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

    terms = iter(_interpolation_terms(points, x))
    accu  = next(terms)
    for term in terms:
        accu += term
    return accu


def poly_eval_fn(poly: typ.List[Num]) -> typ.Callable[[int], int]:
    """Return eunction to evaluate polynomial at x."""

    def eval_at(x: int) -> int:
        """Evaluate polynomial at x."""
        y = sum((coeff * x ** exp) for exp, coeff in enumerate(poly))
        return val_of(y)

    return eval_at


GFPoint = Point[GFNum]

GFPoints = typ.Sequence[GFPoint]


def _split(gf: GF, threshold: int, num_pieces: int, secret) -> GFPoints:
    # The coefficients of the polynomial are ordered in ascending
    # powers of x, so poly = [2, 5, 3] represents 2x° + 5x¹ + 3x²
    #
    # Note that the secret in the above case is 2 (the 0th
    # coefficient), which corresponds to the y value when we evaluate
    # at x=0. This is also why other implementations call this value
    # "intercept" or "y_intercept".
    poly = [gf[secret]]

    while len(poly) < threshold:
        poly.append(gf[randint(gf.p)])

    eval_at = poly_eval_fn(poly)

    points = [Point(gf[x], gf[eval_at(x)]) for x in range(1, num_pieces + 1)]
    assert len(points) == num_pieces

    # make sure we only return pieces that we can join again
    recoverd_secret = join(threshold, points)
    assert recoverd_secret == secret

    for points_subset in itertools.combinations(points, threshold):
        recoverd_secret = join(threshold, points_subset)
        assert recoverd_secret == secret

    return points


def split(
    prime: int, threshold: int, num_pieces: int, secret: int, randint=randint
) -> GFPoints:
    """Generate points of a split secret."""

    if num_pieces <= 1:
        raise ValueError("number of pieces too low, secret would be exposed")

    if num_pieces >= prime:
        raise ValueError(
            "number of pieces too high, cannot generate distinct points"
        )

    if threshold > num_pieces:
        raise ValueError("threshold too high, must be <= number of pieces")

    if secret < 0:
        raise ValueError("Invalid secret, must be a positive integer")

    if prime <= secret:
        raise ValueError(
            "Invalid prime for secret, must be greater than secret."
        )

    return _split(
        gf=GF(p=prime),
        threshold=threshold,
        num_pieces=num_pieces,
        secret=secret,
    )


def join(threshold: int, points: GFPoints) -> int:
    if len(points) < threshold:
        raise ValueError("Not enough pieces to recover secret")

    return val_of(interpolate(points, 0))
