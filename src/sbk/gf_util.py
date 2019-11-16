# This file is part of the sbk project
# https://gitlab.com/mbarkhau/sbk
#
# Copyright (c) 2019 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT

"""Galois Field arithmetic functions."""

import typing as typ

from . import gf_lut

# https://en.wikipedia.org/wiki/Finite_field_arithmetic#Rijndael's_finite_field
#
# x**8 + x**4 + x**3 + x + 1  (0b100011011 = 0x11B)
#
# Rijndael uses the characteristic 2 finite field with 256 elements, which can
# also be called the Galois field GF(2**8). It employs the following reducing
# polynomial for multiplication:
#
# For example, 0x53 * 0xCA = 0x01 in Rijndael's field because
#
# 0x53 = 0b01010011
# 0xCA = 0b11001010
#
#    (x6 + x4 + x + 1)(x7 + x6 + x3 + x)
# = (x13 + x12 + x9 + x7) + (x11 + x10 + x7 + x5) + (x8 + x7 + x4 + x2) + (x7 + x6 + x3 + x)
# = x13 + x12 + x9 + x11 + x10 + x5 + x8 + x4 + x2 + x6 + x3 + x
# = x13 + x12 + x11 + x10 + x9 + x8 + x6 + x5 + x4 + x3 + x2 + x
# and
#
# x13 + x12 + x11 + x10 + x9 + x8 + x6 + x5 + x4 + x3 + x2 + x
#     mod x8 + x4 + x3 + x1 + 1
# = (0b11111101111110 mod 100011011) = 0x3F7E mod 0x011B = 0x0001
#
# , which can be demonstrated through long division (shown using binary
# notation, since it lends itself well to the task. Notice that exclusive OR
# is applied in the example and not arithmetic subtraction, as one might use
# in grade-school long division.):
#
#         11111101111110 (mod) 100011011
#        ^10001101100000
#          1110000011110
#         ^1000110110000
#           110110101110
#          ^100011011000
#            10101110110
#           ^10001101100
#              100011010
#             ^100011011
#                      1

# The multiplicative inverse for an element a of a finite field can be calculated
# a number of different ways:
#
# Since the nonzero elements of GF(p^n) form a finite group with respect to multiplication,
# a^((p^n)−1) = 1 (for a != 0), thus the inverse of a is a^((p^n)−2).


RIJNDAEL_REDUCING_POLYNOMIAL = 0x011B


def div_slow(a: int, b: int) -> int:
    # long division
    val     = a
    divisor = b
    assert divisor > 0

    while divisor < val:
        divisor = divisor << 1

    mask = 1
    while mask < divisor:
        mask = mask << 1
    mask = mask >> 1

    while divisor > 0xFF:
        if (val & mask) > 0:
            val = val ^ divisor

        divisor = divisor >> 1
        mask    = mask    >> 1

    return val


DIV_LUT: typ.Dict[int, int] = {}


def div(a: int, b: int) -> int:
    assert 0 <= a < 65536, a
    assert 0 < b, b

    key = a * 65536 + b
    if key not in DIV_LUT:
        DIV_LUT[key] = div_slow(a, b)

    return DIV_LUT[key]


def div_by_rrp(val: int) -> int:
    return div(val, RIJNDAEL_REDUCING_POLYNOMIAL)


def mul_slow(a: int, b: int) -> int:
    res = 0
    while a > 0:
        if a & 1 != 0:
            res = res ^ b
        a = a // 2
        b = b * 2

    return div_by_rrp(res)


def mul(a: int, b: int) -> int:
    assert 0 <= a < 256, a
    assert 0 <= b < 256, b
    return gf_lut.MUL_LUT[a][b]


def pow_slow(a: int, b: int) -> int:
    res = 1
    n   = b
    while n > 0:
        res = mul(res, a)
        n -= 1
    return res


def inverse_slow(val: int) -> int:
    """Calculate multiplicative inverse in GF(256).

    Since the nonzero elements of GF(p^n) form a finite group with
    respect to multiplication,

      a^((p^n)−1) = 1         (for a != 0)

      thus the inverse of a is

      a^((p^n)−2).
    """
    if val == 0:
        return 0

    exp = 2 ** 8 - 2
    inv = pow_slow(val, exp)
    assert mul(val, inv) == 1
    return inv


def inverse(val: int) -> int:
    return gf_lut.MUL_INVERSE_LUT[val]


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
