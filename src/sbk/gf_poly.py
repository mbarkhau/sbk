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
and Reed-Solomon
https://research.swtch.com/field
"""

import random
import typing as typ
import itertools

from . import gf

_rand = random.SystemRandom()

Coefficients = typ.List[gf.GFNum]


class Point(typ.Generic[gf.Num]):

    x: gf.Num
    y: gf.Num

    def __init__(self, x: gf.Num, y: gf.Num) -> None:
        self.x = x
        self.y = y

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Point):
            raise NotImplementedError

        return self.x == other.x and self.y == other.y

    def __repr__(self) -> str:
        return f"Point(x={self.x}, y={self.y})"

    def __iter__(self) -> typ.Iterable[gf.Num]:
        yield self.x
        yield self.y


Points = typ.Sequence[Point[gf.Num]]


def prod(vals: typ.Sequence[gf.Num]) -> gf.Num:
    """Product of numbers.

    This is sometimes also denoted by Π (upper case PI).
    """
    if len(vals) == 0:
        # If we new the field, we could return gf[1]
        raise ValueError("prod requires at least one value")

    accu = vals[0]
    for val in vals[1:]:
        accu *= val
    return accu


def _interpolation_terms(points: Points, at_x: gf.Num) -> typ.Iterable[gf.Num]:
    for p in points:
        others = [o for o in points if o != p]

        numer = prod([at_x - o.x for o in others])
        denum = prod([p.x  - o.x for o in others])

        yield (p.y * numer) / denum


def interpolate(points: Points, at_x: gf.Num) -> gf.Num:
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

    # validate x coordinates
    for i, p in enumerate(points):
        if not 0 < p.x < 255:
            errmsg = f"Invalid share {i + 1} with x={p.x}. Possible attack."
            raise Exception(errmsg)

    terms = iter(_interpolation_terms(points, at_x=at_x))
    accu  = next(terms)
    for term in terms:
        accu += term
    return accu


def val_of(n: typ.Union[int, float, gf.GFNum, gf.GF256]) -> int:
    # Helper function to allow n to be a plain integer or float in tests.
    if isinstance(n, int):
        return n
    if isinstance(n, float):
        return int(n)

    assert isinstance(n, (gf.GFNum, gf.GF256))
    return n.val


def poly_eval_fn(field: gf.Field[gf.Num], coeffs: Coefficients) -> typ.Callable[[int], int]:
    """Return function to evaluate polynomial at x."""

    def eval_at(at_x: int) -> int:
        """Evaluate polynomial at x."""
        y = field[0]
        for exp, coeff in enumerate(coeffs):
            y += coeff * field[at_x] ** field[exp]

        return val_of(y)

    return eval_at


def _split(field: gf.Field[gf.GFNum], threshold: int, num_shares: int, secret) -> Points:
    # The coefficients of the polynomial are ordered in ascending
    # powers of x, so coeffs = [2, 5, 3] represents 2x° + 5x¹ + 3x²
    #
    # Note that the secret in the above case is 2 (the 0th
    # coefficient), which corresponds to the y value when we evaluate
    # at x=0. This is also why other implementations call this value
    # "intercept" or "y_intercept".
    coeffs: Coefficients = [field[secret]]

    while len(coeffs) < threshold:
        coeffs.append(field[_rand.randrange(field.order)])

    eval_at = poly_eval_fn(field, coeffs)

    points = [Point(field[x], field[eval_at(x)]) for x in range(1, num_shares + 1)]
    assert len(points) == num_shares

    # make sure we only return pieces that we can join again
    recoverd_secret = join(field, threshold, points)
    assert recoverd_secret == secret

    for points_subset in itertools.combinations(points, threshold):
        recoverd_secret = join(field, threshold, points_subset)
        assert recoverd_secret == secret

    return points


def split(field: gf.Field[gf.GFNum], threshold: int, num_shares: int, secret: int) -> Points:
    """Generate points of a split secret."""

    if num_shares <= 1:
        raise ValueError("number of pieces too low, secret would be exposed")

    if num_shares >= field.order:
        raise ValueError("number of pieces too high, cannot generate distinct points")

    if threshold > num_shares:
        raise ValueError("threshold too high, must be <= number of pieces")

    if secret < 0:
        raise ValueError("Invalid secret, must be a positive integer")

    # TODO: if field.order != 256
    # - 256 splits the secret up into bytes and encodes each separately.
    # - we could do this generally for any order, and chunk up the secret
    # - secret should perhaps be bytes instead of int
    if field.order <= secret:
        raise ValueError("Invalid prime for secret, must be greater than secret.")

    return _split(field=field, threshold=threshold, num_shares=num_shares, secret=secret)


def join(field: gf.Field[gf.Num], threshold: int, points: Points) -> int:
    if len(points) < threshold:
        raise ValueError("Not enough pieces to recover secret")

    return val_of(interpolate(points, at_x=field[0]))
