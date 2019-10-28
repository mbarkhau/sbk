import os

import pylev
import pytest

import sbk.gf
import sbk.primes
import sbk.gf_poly
from sbk.enc_util import *


def test_bytes2hex():
    assert bytes2hex(b"test data") == '746573742064617461'
    assert hex2bytes('746573742064617461') == b"test data"
    data = b"\x01\x23\x45\x67\x89\xAB\xCD\xEF"
    text = '0123456789aBcDeF'
    assert bytes2hex(data) == text.lower()
    assert hex2bytes(text) == data
    assert hex2bytes(text.upper()) == data
    assert hex2bytes(text.lower()) == data


def test_bytes2bytesrepr():
    data = b"\x01\x23\x45\x67\x89\xAB\xCD\xEF"
    assert bytes2bytesrepr(data) == r"\x01\x23\x45\x67\x89\xAB\xCD\xEF".lower()
    assert bytes2bytesrepr(b"09AZ") == r"\x30\x39\x41\x5A".lower()


def test_hex2bytes_fuzz():
    for i in range(100):
        data     = os.urandom(10)
        hex_text = bytes2hex(data)
        assert hex2bytes(hex_text) == data


def bytes2int_cases():
    yield (b"\x00"    , 0)
    yield (b"\x01"    , 1)
    yield (b"\xff"    , 255)
    yield (b"\x12\x34", 0x1234)

    bytes_val = b"\xff" * 16 + b"\xfe"
    int_val   = 2 ** (128 + 8) - 2
    yield (bytes_val, int_val)


@pytest.mark.parametrize("bytes_val, int_val", bytes2int_cases())
def test_bytes2int(bytes_val, int_val):
    assert bytes2int(bytes_val) == int_val
    assert int2bytes(int_val, zfill_bytes=len(bytes_val)) == bytes_val


def test_bytes2int_fuzz():
    for bytes_len in range(50):
        bytes_val = os.urandom(bytes_len)
        int_val   = bytes2int(bytes_val)
        assert int2bytes(int_val, zfill_bytes=bytes_len) == bytes_val

        bytes_val_zfilled = int2bytes(int_val, zfill_bytes=100)
        assert len(bytes_val_zfilled) == 100
        assert bytes2int(bytes_val_zfilled) == int_val

        # big endian
        assert bytes_val_zfilled.endswith(bytes_val)


def test_bytes2gfpoint():
    data_len = 32
    prime    = sbk.primes.get_pow2prime(data_len * 8 - 8)

    field = sbk.gf.GFNum.field(prime)
    x     = field[         7]
    y     = field[1234567890]

    in_point   = sbk.gf_poly.Point(x, y)
    point_data = gfpoint2bytes(in_point)
    assert len(point_data) == data_len
    assert bytes2gfpoint(point_data, field) == in_point
