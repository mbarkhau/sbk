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


BYTES_HEX_TEST_CASES = [
    [b"\x00\x00"                        , "0000"],
    [b"\xff\xff"                        , "ffff"],
    [b"\x01\x23\x45\x67\x89\xab\xcd\xef", "0123 4567 89ab cdef"],
    [b"\xef\xcd\xab\x89\x67\x45\x23\x01", "efcd ab89 6745 2301"],
]


@pytest.mark.parametrize("bytes_val, expected", BYTES_HEX_TEST_CASES)
def test_bytes_hex(bytes_val, expected):
    assert bytes_hex(bytes_val) == expected


BYTES_REPR_TEST_CASES = [
    [b"\x00\x00"                        , 'b"\\x00\\x00"'],
    [b"\xff\xff"                        , 'b"\\xff\\xff"'],
    [b"\x01\x23\x45\x67\x89\xab\xcd\xef", 'b"\\x01\\x23\\x45\\x67\\x89\\xab\\xcd\\xef"'],
    [b"\xef\xcd\xab\x89\x67\x45\x23\x01", 'b"\\xef\\xcd\\xab\\x89\\x67\\x45\\x23\\x01"'],
]


@pytest.mark.parametrize("bytes_val, expected", BYTES_REPR_TEST_CASES)
def test_bytes_repr(bytes_val, expected):
    assert bytes_repr(bytes_val) == expected


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


def test_bytes2gfpoint_fail():
    field = sbk.gf.GFNum.field(257)

    assert bytes2gfpoint(b"\x01\x00\x00\xff", field) == sbk.gf_poly.Point(field[1], field[255])
    assert bytes2gfpoint(b"\x01\x00\x01\x00", field) == sbk.gf_poly.Point(field[1], field[256])

    try:
        bytes2gfpoint(b"\x01\x00\x01\x01", field)
    except ValueError as ex:
        assert "Invalid data for field with order=257" in str(ex)


def test_gfpoint2bytes():
    field = sbk.gf.GFNum.field(257)

    point_data = gfpoint2bytes(sbk.gf_poly.Point(field[1], field[127]))
    assert point_data[:1] == b"\x01"
    assert point_data[1:] == b"\x7f"

    point_data = gfpoint2bytes(sbk.gf_poly.Point(field[254], field[127]))
    assert point_data[:1] == b"\xfe"
    assert point_data[1:] == b"\x7f"


def test_gfpoint2bytes_fail():
    field = sbk.gf.GFNum.field(257)
    gfpoint2bytes(sbk.gf_poly.Point(field[  1], field[101]))
    gfpoint2bytes(sbk.gf_poly.Point(field[254], field[101]))

    try:
        gfpoint2bytes(sbk.gf_poly.Point(field[0], field[101]))
    except ValueError as ex:
        assert "Invalid point with x=0. " in str(ex)

    try:
        gfpoint2bytes(sbk.gf_poly.Point(field[255], field[101]))
    except ValueError as ex:
        assert "Invalid point with x=255. " in str(ex)
