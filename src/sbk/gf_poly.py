# This file is part of the sbk project
# https://github.com/mbarkhau/sbk
#
# Copyright (c) 2019-2022 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
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

import typing as typ
import warnings
import itertools
from typing import Any
from typing import Set
from typing import Dict
from typing import List
from typing import Tuple
from typing import Union
from typing import Generic
from typing import NewType
from typing import TypeVar
from typing import Callable
from typing import Iterable
from typing import Iterator
from typing import Optional
from typing import Protocol
from typing import Sequence
from typing import Generator
from typing import NamedTuple

from . import gf
from . import gf_lut
from . import sbk_random

Coefficients = List[gf.GF256]


class Point:

    x: gf.GF256
    y: gf.GF256

    def __init__(self, x: gf.GF256, y: gf.GF256) -> None:
        self.x = x
        self.y = y

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Point):
            result = self.x == other.x and self.y == other.y
            assert isinstance(result, bool)
            return result
        else:
            raise NotImplementedError

    def __repr__(self) -> str:
        return f"Point(x={self.x}, y={self.y})"

    def __iter__(self) -> Iterator[gf.GF256]:
        yield self.x
        yield self.y


Points = Tuple[Point, ...]


def prod(vals: Sequence[gf.GF256]) -> gf.GF256:
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


def _interpolation_terms_256(points: Points, at_x: gf.GF256) -> Iterator[gf.GF256]:
    # Specialization to speed up ecc_rs.decode_packets. This should return
    # the exact same result as _interpolation_terms in principle.
    assert isinstance(at_x, gf.GF256)
    assert all(isinstance(p.x, gf.GF256) for p in points)
    assert all(isinstance(p.y, gf.GF256) for p in points)

    mul_lut = gf_lut.MUL_LUT
    inv_lut = gf_lut.MUL_INVERSE_LUT

    if not mul_lut:
        gf_lut.init_mul_lut()

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


def _interpolation_terms(points: Points, at_x: gf.GF256) -> typ.Iterable[gf.GF256]:
    for i, p in enumerate(points):
        others = points[:i] + points[i + 1 :]
        assert len(others) == len(points) - 1

        numer = prod(tuple(at_x - o.x for o in others))
        denum = prod(tuple(p.x  - o.x for o in others))

        yield (p.y * numer) / denum


def interpolate(points: Points, at_x: gf.GF256) -> gf.GF256:
    r"""Interpolate y value at x for a polynomial."""
    if len(points) < 2:
        raise ValueError("Cannot interpolate with fewer than two points")

    x_vals = tuple(p.x for p in points)
    if len(x_vals) != len(set(x_vals)):
        raise ValueError("Points must be distinct {points}")

    # validate x coordinates
    for i, p in enumerate(points):
        is_primitive = isinstance(p.x, (int, float))
        is_valid_x   = p.x > 0 and (is_primitive or p.x.val < 255)
        if not is_valid_x:
            errmsg = f"Invalid share {i + 1} with x={p.x}. Possible attack."
            raise Exception(errmsg)

    terms = iter(_interpolation_terms(points, at_x=at_x))
    accu  = next(terms)
    for term in terms:
        accu += term
    return accu


def val_of(n: Union[int, float, gf.GFP, gf.GF256]) -> int:
    # Helper function to allow n to be a plain integer or float in tests.
    if isinstance(n, int):
        return n
    elif isinstance(n, float):
        return int(n)
    else:
        assert isinstance(n, (gf.GFP, gf.GF256))
        return n.val


def poly_eval_fn(field: gf.FieldGF256, coeffs: Coefficients) -> Callable[[int], int]:
    """Return function to evaluate polynomial at x."""

    def eval_at(at_x: int) -> int:
        """Evaluate polynomial at x."""
        y = field[0]
        for exp, coeff in enumerate(coeffs):
            y += coeff * field[at_x] ** field[exp]
        return val_of(y)

    return eval_at


def _split(
    field     : gf.FieldGF256,
    secret    : int,
    threshold : int,
    num_shares: int,
    make_coeff: Callable[[int], int],
) -> Points:
    # The coefficients of the polynomial are ordered in ascending
    # powers of x, so coeffs = [2, 5, 3] represents 2x° + 5x¹ + 3x²
    #
    # Note that the secret in the above case is 2 (the 0th
    # coefficient), which corresponds to the y value when we evaluate
    # at x=0. This is also why other implementations call this value
    # "intercept" or "y_intercept".
    coeffs: Coefficients = [field[secret]]

    while len(coeffs) < threshold:
        raw_coeff = make_coeff(field.order)
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


def split(
    field     : gf.FieldGF256,
    secret    : int,
    threshold : int,
    num_shares: int,
    make_coeff: Callable[[int], int],
) -> Points:
    """Generate points of a split secret."""

    if num_shares <= 1:
        raise ValueError("number of pieces too low, secret would be exposed")
    elif num_shares >= field.order:
        raise ValueError("number of pieces too high, cannot generate distinct points")
    elif threshold > num_shares:
        raise ValueError("threshold too high, must be <= number of pieces")
    elif secret < 0:
        raise ValueError("Invalid secret, must be a positive integer")
    elif field.order <= secret:
        raise ValueError("Invalid prime for secret, must be greater than secret.")
    else:
        return _split(
            field=field,
            secret=secret,
            threshold=threshold,
            num_shares=num_shares,
            make_coeff=make_coeff,
        )


def join(field: gf.FieldGF256, points: Points, threshold: int) -> int:
    if len(points) >= threshold:
        return val_of(interpolate(points, at_x=field[0]))
    else:
        raise ValueError("Not enough pieces to recover secret")
