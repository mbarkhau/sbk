# This file is part of the sbk project
# https://github.com/mbarkhau/sbk
#
# Copyright (c) 2019 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT

"""Main Galois Field Types and API."""

import typing as typ
import functools

from . import gf_lut
from . import primes
from . import gf_util

Num     = typ.TypeVar('Num', 'GFP', 'GF256')
NumType = typ.Type[Num]


@functools.total_ordering
class GFP:

    p  : int
    val: int

    def __init__(self, val: int, p: int) -> None:
        # NOTE mb: In practice p is always prime, and the operations are
        #   implemented with this assumtion. If p were not prime, then a
        #   multiplicative inverse would not exist in all cases.
        assert primes.is_prime(p)

        self.p   = p
        self.val = val % p

    @property
    def order(self) -> int:
        return self.p

    def _new_gf(self, val: int) -> 'GFP':
        # Mod p is done so often as a last operation on val,
        # so we do it here as part of the initialisation.
        return GFP(val % self.p, p=self.p)

    def __add__(self, other: Num) -> 'GFP':
        return self._new_gf(self.val + other.val)

    def __radd__(self, other: int) -> 'GFP':
        return self._new_gf(other) + self

    def __sub__(self, other: Num) -> 'GFP':
        return self._new_gf(self.val - other.val)

    def __rsub__(self, other: int) -> 'GFP':
        return self._new_gf(other) - self

    def __neg__(self) -> 'GFP':
        return self._new_gf(-self.val)

    def __mul__(self, other: Num) -> 'GFP':
        return self._new_gf(self.val * other.val)

    def __rmul__(self, other: int) -> 'GFP':
        return self._new_gf(other) * self

    def __pow__(self, other: Num) -> 'GFP':
        return self._new_gf(self.val ** other.val)

    def __truediv__(self, other: 'GFP') -> 'GFP':
        return self * other._mul_inverse()

    def _mul_inverse(self) -> 'GFP':
        assert self.val >= 0
        res     = gf_util.xgcd(self.p, self.val)
        inv_val = self.p + res.t
        return self._new_gf(inv_val)

    def _check_comparable(self, other: object) -> None:
        if isinstance(other, int):
            if not (0 <= other < self.p):
                errmsg = f"GF comparison with integer faild: 0 <= {other} < {self.p}"
                raise ValueError(errmsg)
            return

        if not isinstance(other, GFP):
            errmsg = f"Cannot compare {repr(self)} with {repr(other)}"
            raise NotImplementedError(errmsg)

        if hasattr(self, 'p') and self.p != other.p:
            errmsg = "Can only compare Numbers from the same finite field"
            raise ValueError(errmsg)

    def __hash__(self) -> int:
        return hash(self.val) ^ hash(self.p)

    def __eq__(self, other: object) -> bool:
        if self is other:
            return True

        if isinstance(other, GFP) and self.p == other.p:
            return self.val == other.val

        self._check_comparable(other)
        assert isinstance(other, int)
        return self.val == other

    def __lt__(self, other: object) -> bool:
        if self is other:
            return False

        if isinstance(other, GFP) and self.p == other.p:
            return self.val < other.val

        self._check_comparable(other)
        assert isinstance(other, int)
        return self.val < other

    def __repr__(self) -> str:
        return f"GFP({self.val:>3}, p={self.p})"


@functools.total_ordering
class GF256:

    val: int

    def __init__(self, val: int, order: int = 256) -> None:
        assert order == 256
        self.val = val

    @property
    def order(self) -> int:
        return 256

    def __add__(self, other: Num) -> 'GF256':
        val = self.val ^ other.val
        assert 0 <= val < 256
        return ALL_GF256[val]

    def __sub__(self, other: Num) -> 'GF256':
        val = self.val ^ other.val
        assert 0 <= val < 256
        return ALL_GF256[val]

    def __mul__(self, other: Num) -> 'GF256':
        a = self.val
        b = other.val
        assert 0 <= a < 256, a
        assert 0 <= b < 256, b

        mul_lut = gf_lut.MUL_LUT

        if not mul_lut:
            gf_lut.init_mul_lut()

        val = mul_lut[a][b]
        return ALL_GF256[val]

    def __pow__(self, other: Num) -> 'GF256':
        val = gf_util.pow_slow(self.val, other.val)
        assert 0 <= val < 256
        return ALL_GF256[val]

    def __truediv__(self, other: Num) -> 'GF256':
        inv = gf_lut.MUL_INVERSE_LUT[other.val]
        return self * ALL_GF256[inv]

    def _check_comparable(self, other: object) -> None:
        if isinstance(other, int):
            if not (0 <= other < 256):
                errmsg = f"GF comparison with integer faild: 0 <= {other} < 256"
                raise ValueError(errmsg)
            return

        if not isinstance(other, GF256):
            errmsg = f"Cannot compare {repr(self)} with {repr(other)}"
            raise NotImplementedError(errmsg)

    def __hash__(self) -> int:
        return hash(self.val)

    def __eq__(self, other: object) -> bool:
        if self is other:
            return True

        if isinstance(other, GF256):
            return self.val == other.val

        self._check_comparable(other)
        assert isinstance(other, int)
        return self.val == other

    def __lt__(self, other: object) -> bool:
        if self is other:
            return False

        if isinstance(other, GF256):
            return self.val < other.val

        self._check_comparable(other)
        assert isinstance(other, int)
        return self.val < other

    def __repr__(self) -> str:
        return f"GF256({self.val:>3})"


# Cache so we don't end up with millions of objects
# that all represent the same set of integers.
ALL_GF256 = [GF256(n) for n in range(256)]


class Field(typ.Generic[Num]):

    order  : int
    num_typ: NumType

    def __init__(self, order: int, num_typ: NumType) -> None:
        assert num_typ == GFP or num_typ == GF256

        # order, aka. characteristic, aka. prime
        self.order   = order
        self.num_typ = num_typ

    def __getitem__(self, val: int) -> Num:
        if self.order == 256:
            assert 0 <= val < 256
            return ALL_GF256[val]
        else:
            return self.num_typ(val, self.order)


GFNum = typ.Union[GFP, GF256]


def init_field(order: int) -> Field[GFNum]:
    if order == 256:
        return Field(256, GF256)
    else:
        return Field(order, GFP)
