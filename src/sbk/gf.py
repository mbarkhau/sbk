# This file is part of the sbk project
# https://gitlab.com/mbarkhau/sbk
#
# Copyright (c) 2019 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT

"""Main Galois Field Types and API."""

import typing as typ
import functools

from . import primes
from . import gf_util

Num     = typ.TypeVar('Num', 'GFNum', 'GF256')
NumType = typ.Type[Num]


class Field(typ.Generic[Num]):

    order  : int
    num_typ: NumType

    def __init__(self, order: int, num_typ: NumType) -> None:
        # order, aka. characteristic, aka. prime
        self.order   = order
        self.num_typ = num_typ

    def __getitem__(self, val: int) -> Num:
        return self.num_typ(val, self.order)


@functools.total_ordering
class GFNum:

    p  : int
    val: int

    @classmethod
    def field(cls: NumType, order: int) -> Field['GFNum']:
        return Field(order, cls)

    def __init__(self, val: int, p: int) -> None:
        # NOTE mb: In practice p is always prime, and the operations are
        #   implemented with this assumtion. If p were not prime, then a
        #   multiplicative inverse would not exist in all cases.
        assert primes.is_prime(p)

        self.p   = p
        self.val = val % p

    def _new_gf(self, val: int) -> 'GFNum':
        # Mod p is done so often as a last operation on val,
        # so we do it here as part of the initialisation.
        return GFNum(val % self.p, p=self.p)

    def __add__(self, other: Num) -> 'GFNum':
        return self._new_gf(self.val + other.val)

    def __radd__(self, other: int) -> 'GFNum':
        return self._new_gf(other) + self

    def __sub__(self, other: Num) -> 'GFNum':
        return self._new_gf(self.val - other.val)

    def __rsub__(self, other: int) -> 'GFNum':
        return self._new_gf(other) - self

    def __neg__(self) -> 'GFNum':
        return self._new_gf(-self.val)

    def __mul__(self, other: Num) -> 'GFNum':
        return self._new_gf(self.val * other.val)

    def __rmul__(self, other: int) -> 'GFNum':
        return self._new_gf(other) * self

    def __pow__(self, other: Num) -> 'GFNum':
        return self._new_gf(self.val ** other.val)

    def _mul_inverse(self) -> 'GFNum':
        assert self.val >= 0
        t       = gf_util.xgcd(self.p, self.val).t
        inv_val = self.p + t
        return self._new_gf(inv_val)

    def __truediv__(self, other: 'GFNum') -> 'GFNum':
        return self * other._mul_inverse()

    def __hash__(self) -> int:
        return hash(self.val) ^ hash(self.p)

    def _check_comparable(self, other: object) -> None:
        if isinstance(other, int):
            if not (0 <= other <= 256):
                errmsg = f"GF comparison with integer is only valid for 0 <= x <= 256"
                raise ValueError(errmsg)
            return

        if not isinstance(other, GFNum):
            errmsg = f"Cannot compare GFNum with {type(other)}"
            raise NotImplementedError(errmsg)

        if hasattr(self, 'p') and self.p != other.p:
            errmsg = "Can only compare Numbers from the same finite field"
            raise ValueError(errmsg)

    def __eq__(self, other: object) -> bool:
        self._check_comparable(other)
        if isinstance(other, int):
            return self.val == other

        assert isinstance(other, GFNum)
        return self.val == other.val

    def __ne__(self, other: object) -> bool:
        self._check_comparable(other)
        if isinstance(other, int):
            return self.val != other

        assert isinstance(other, GFNum)
        return self.val != other.val

    def __lt__(self, other: object) -> bool:
        self._check_comparable(other)
        if isinstance(other, int):
            return self.val < other

        assert isinstance(other, GFNum)
        return self.val < other.val

    def __repr__(self) -> str:
        return f"GFNum({self.val:>3}, p={self.p})"


_MUL_INV_LUT = [0] * 256


class GF256(GFNum):

    val: int

    @classmethod
    def field(cls: NumType, order: int = 256) -> Field[GFNum]:
        assert order == 256
        return Field(order, cls)

    def __init__(self, val: int, order: int = 256) -> None:
        assert order == 256
        self.val = val

    def __add__(self, other: Num) -> 'GF256':
        return GF256(self.val ^ other.val)

    def __sub__(self, other: Num) -> 'GF256':
        return GF256(self.val ^ other.val)

    def __mul__(self, other: Num) -> 'GF256':
        return GF256(gf_util.mul(self.val, other.val))

    def __pow__(self, other: Num) -> 'GF256':
        return GF256(gf_util.pow_slow(self.val, other.val))

    def _mul_inverse(self) -> 'GF256':
        v = self.val
        if v > 0 and _MUL_INV_LUT[v] == 0:
            _MUL_INV_LUT[v] = gf_util.inverse(v)

        return GF256(_MUL_INV_LUT[v])

    def __repr__(self) -> str:
        return f"GF256({self.val:>3})"
