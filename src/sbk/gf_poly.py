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

import os
import random
import typing as typ
import warnings
import itertools

from . import gf
from . import gf_lut


class DebugRandom:

    _state: int

    def __init__(self) -> None:
        self._state = 4294967291

    def randrange(self, stop: int):
        self._state = (self._state + 4294967291) % 2 ** 63
        return self._state % stop


DEBUG_WARN_MSG = (
    "Warning, SBK using debug random! This should only happen when debugging or testing."
)

_debug_rand = DebugRandom()
_rand       = random.SystemRandom()


def randrange(stop: int) -> int:
    if os.getenv('SBK_DEBUG_RANDOM') == 'DANGER':
        warnings.warn(DEBUG_WARN_MSG)
        return _debug_rand.randrange(stop)
    else:
        return _rand.randrange(stop)


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


Points = typ.Tuple[Point[gf.Num], ...]


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


def _interpolation_terms_256(points: Points[gf.GF256], at_x: gf.GF256) -> typ.Iterable[gf.GF256]:
    # Specialization to speed up ecc_rs.decode_packets. This should return
    # the exact same result as _interpolation_terms  in principle.
    assert isinstance(at_x, gf.GF256)
    assert all(isinstance(p.x, gf.GF256) for p in points)
    assert all(isinstance(p.y, gf.GF256) for p in points)

    mul_lut = gf_lut.MUL_LUT
    inv_lut = gf_lut.MUL_INVERSE_LUT

    _points = tuple((p.x.val, p.y.val) for p in points)
    _xs     = tuple(px for px, py in _points)
    _at_x   = at_x.val

    for i, (px, py) in enumerate(_points):
        _other_xs = _xs[:i] + _xs[i + 1 :]
        assert len(_other_xs) == len(_points) - 1

        numer = 1
        for ox in _other_xs:
            numer = mul_lut[numer][_at_x ^ ox]

        denum = 1
        for ox in _other_xs:
            denum = mul_lut[denum][px ^ ox]

        assert 0 <= py    < 256, py
        assert 0 <= numer < 256, numer
        assert 0 <= denum < 256, denum

        numer2 = mul_lut[py    ][numer]
        d_inv  = inv_lut[denum]
        result = mul_lut[numer2][d_inv]
        yield gf.ALL_GF256[result]


def _interpolation_terms(points: Points, at_x: gf.Num) -> typ.Iterable[gf.Num]:
    for i, p in enumerate(points):
        others = points[:i] + points[i + 1 :]
        assert len(others) == len(points) - 1

        numer = prod(tuple(at_x - o.x for o in others))
        denum = prod(tuple(p.x  - o.x for o in others))

        yield (p.y * numer) / denum


def interpolate(points: Points, at_x: gf.Num) -> gf.Num:
    r"""Interpolate y value at x for a polynomial."""
    if len(points) < 2:
        raise ValueError("Cannot interpolate with fewer than two points")

    x_vals = tuple(p.x for p in points)
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


def _split(field: gf.Field[gf.Num], secret: int, threshold: int, num_shares: int) -> Points:
    # The coefficients of the polynomial are ordered in ascending
    # powers of x, so coeffs = [2, 5, 3] represents 2x° + 5x¹ + 3x²
    #
    # Note that the secret in the above case is 2 (the 0th
    # coefficient), which corresponds to the y value when we evaluate
    # at x=0. This is also why other implementations call this value
    # "intercept" or "y_intercept".
    coeffs: Coefficients = [field[secret]]

    while len(coeffs) < threshold:
        raw_coeff = randrange(field.order)
        coeffs.append(field[raw_coeff])

    eval_at = poly_eval_fn(field, coeffs)

    points = tuple(Point(field[x], field[eval_at(x)]) for x in range(1, num_shares + 1))
    assert len(points) == num_shares

    # make sure we only return pieces that we can join again
    recoverd_secret = join(field, points, threshold)
    assert recoverd_secret == secret

    for points_subset in itertools.combinations(points, threshold):
        recoverd_secret = join(field, points_subset, threshold)
        assert recoverd_secret == secret

    return points


def split(field: gf.Field[gf.Num], secret: int, threshold: int, num_shares: int) -> Points:
    """Generate points of a split secret."""

    if num_shares <= 1:
        raise ValueError("number of pieces too low, secret would be exposed")

    if num_shares >= field.order:
        raise ValueError("number of pieces too high, cannot generate distinct points")

    if threshold > num_shares:
        raise ValueError("threshold too high, must be <= number of pieces")

    if secret < 0:
        raise ValueError("Invalid secret, must be a positive integer")

    if field.order <= secret:
        raise ValueError("Invalid prime for secret, must be greater than secret.")

    return _split(field=field, secret=secret, threshold=threshold, num_shares=num_shares)


def join(field: gf.Field[gf.Num], points: Points, threshold: int) -> int:
    if len(points) < threshold:
        raise ValueError("Not enough pieces to recover secret")

    return val_of(interpolate(points, at_x=field[0]))
