import time


RIJNDAEL_REDUCING_POLYNOMIAL = 0x11B

assert RIJNDAEL_REDUCING_POLYNOMIAL == 0b100011011

a = 0x53
b = 0xCA

assert a == 0b01010011
assert b == 0b11001010


def _gf_div(a: int, b: int) -> int:
    val = a
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
        mask = mask >> 1

    return val


def _gf_div_by_rrp(val: int) -> int:
    divisor = RIJNDAEL_REDUCING_POLYNOMIAL << 8
    mask = 0x10000
    while divisor > 0xFF:
        if (val & mask) > 0:
            val = val ^ divisor

        divisor = divisor >> 1
        mask = mask >> 1

    return val


assert _gf_div_by_rrp(0x3F7E) == 0x1


def _gf_div_by_rrp(val: int) -> int:
    return _gf_div(val, RIJNDAEL_REDUCING_POLYNOMIAL)


assert _gf_div_by_rrp(0x3F7E) == 0x1
assert _gf_div(0x3F7E, RIJNDAEL_REDUCING_POLYNOMIAL) == 0x1


def _gf_mul(a: int, b: int) -> int:
    res = 0
    while a > 0:
        if a & 1 != 0:
            res = res ^ b
        a = a // 2
        b = b * 2

    return _gf_div_by_rrp(res)


def _gf_pow(a: int, b: int) -> int:
    n = b
    res = 1
    while n > 0:
        res = _gf_mul(res, a)
        n -= 1
    return res


def _gf_mul_inv(val: int) -> int:
    if val == 0:
        return 0

    # Since the nonzero elements of GF(p^n) form a finite group with
    # respect to multiplication,
    #
    #   a^((p^n)−1) = 1         (for a != 0)
    #
    #   thus the inverse of a is
    #
    #   a^((p^n)−2).
    exp = 2 ** 8 - 2
    inv = _gf_pow(val, exp)
    assert _gf_mul(val, inv) == 1
    return inv


tzero = time.time()
for v in range(256):
    inv = _gf_mul_inv(v)
    # print(hex(v)[2:].zfill(2), ":", hex(inv)[2:].zfill(2), end="   ")
    # if (v + 1) % 8 == 0:
    #     print()

print((time.time() - tzero) * 1000)

print("check")

assert gf_mul_inv(a) == b
print(b)
print(_gf_mul_inv(a))
assert gf_mul_inv(b) == a
print(a)
print(_gf_mul_inv(b))

print("success!")


# print("rr", bin(RIJNDAEL_REDUCING_POLYNOMIAL))
# print()

# print("#1", bin(_gf_div_by_rrp(0x3F7E)))
# print("#1", bin(_gf_div(0x3F7E, RIJNDAEL_REDUCING_POLYNOMIAL)))

# print("A=", bin(a))
# print("  ", bin(_gf_div(0x11d, b)))
# print()
# print("B=", bin(b))
# print("  ", bin(_gf_div(0x11d, a)))


# print("#_gf_mul", bin(_gf_mul(a, b)), hex(_gf_mul(a, b)))
# assert _gf_div_by_rrp(a) == b, _gf_div_by_rrp(a)
# assert _gf_div_by_rrp(b) == a, _gf_div_by_rrp(b)
