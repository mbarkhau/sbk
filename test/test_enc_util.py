import os
import string
import random
import itertools

import pylev
import pytest

import sbk.polynom as polynom
from sbk.enc_util import *


TEST_PHRASE_LINES = [
    "The BRAVE  BAKER  at the BERLIN BEACH.",
    "The BRAVE  CHILD  at the BERLIN BRIDGE.",
    "The BRAVE  DOCTOR at the BERLIN CASTLE.",
    "The BRAVE  DRIVER at the BERLIN CHURCH.",
    "The BRAVE  KING   at the BERLIN FARM.",
    "The BRAVE  LADY   at the BERLIN FOREST.",
    "The BRAVE  LEADER at the BERLIN GARDEN.",
    "The BRAVE  MAYOR  at the BERLIN GHETTO.",
    "The BRAVE  MOTHER at the BERLIN HOTEL.",
    "The BRAVE  NURSE  at the BERLIN LAKE.",
    "The BRAVE  PRIEST at the BERLIN MUSEUM.",
    "The BRAVE  PRINCE at the BERLIN OASIS.",
    "The BRAVE  QUEEN  at the BERLIN OPERA.",
    "The BRAVE  SISTER at the BERLIN SCHOOL.",
    "The BRAVE  WAITER at the BERLIN STAGE.",
    "The BRAVE  WORKER at the BERLIN TEMPLE.",
    "The CRAZY  BAKER  at the CAIRO  BEACH.",
    "The CRAZY  CHILD  at the CAIRO  BRIDGE.",
    "The CRAZY  DOCTOR at the CAIRO  CASTLE.",
    "The CRAZY  DRIVER at the CAIRO  CHURCH.",
    "The CRAZY  KING   at the CAIRO  FARM.",
    "The CRAZY  LADY   at the CAIRO  FOREST.",
    "The CRAZY  LEADER at the CAIRO  GARDEN.",
    "The CRAZY  MAYOR  at the CAIRO  GHETTO.",
    "The CRAZY  MOTHER at the CAIRO  HOTEL.",
    "The CRAZY  NURSE  at the CAIRO  LAKE.",
    "The CRAZY  PRIEST at the CAIRO  MUSEUM.",
    "The CRAZY  PRINCE at the CAIRO  OASIS.",
    "The CRAZY  QUEEN  at the CAIRO  OPERA.",
    "The CRAZY  SISTER at the CAIRO  SCHOOL.",
    "The CRAZY  WAITER at the CAIRO  STAGE.",
    "The CRAZY  WORKER at the CAIRO  TEMPLE.",
    "The DIRTY  BAKER  at the DELHI  BEACH.",
    "The DIRTY  CHILD  at the DELHI  BRIDGE.",
    "The DIRTY  DOCTOR at the DELHI  CASTLE.",
    "The DIRTY  DRIVER at the DELHI  CHURCH.",
    "The DIRTY  KING   at the DELHI  FARM.",
    "The DIRTY  LADY   at the DELHI  FOREST.",
    "The DIRTY  LEADER at the DELHI  GARDEN.",
    "The DIRTY  MAYOR  at the DELHI  GHETTO.",
    "The DIRTY  MOTHER at the DELHI  HOTEL.",
    "The DIRTY  NURSE  at the DELHI  LAKE.",
    "The DIRTY  PRIEST at the DELHI  MUSEUM.",
    "The DIRTY  PRINCE at the DELHI  OASIS.",
    "The DIRTY  QUEEN  at the DELHI  OPERA.",
    "The DIRTY  SISTER at the DELHI  SCHOOL.",
    "The DIRTY  WAITER at the DELHI  STAGE.",
    "The DIRTY  WORKER at the DELHI  TEMPLE.",
    "The EVIL   BAKER  at the DUBLIN BEACH.",
    "The EVIL   CHILD  at the DUBLIN BRIDGE.",
    "The EVIL   DOCTOR at the DUBLIN CASTLE.",
    "The EVIL   DRIVER at the DUBLIN CHURCH.",
    "The EVIL   KING   at the DUBLIN FARM.",
    "The EVIL   LADY   at the DUBLIN FOREST.",
    "The EVIL   LEADER at the DUBLIN GARDEN.",
    "The EVIL   MAYOR  at the DUBLIN GHETTO.",
    "The EVIL   MOTHER at the DUBLIN HOTEL.",
    "The EVIL   NURSE  at the DUBLIN LAKE.",
    "The EVIL   PRIEST at the DUBLIN MUSEUM.",
    "The EVIL   PRINCE at the DUBLIN OASIS.",
    "The EVIL   QUEEN  at the DUBLIN OPERA.",
    "The EVIL   SISTER at the DUBLIN SCHOOL.",
    "The EVIL   WAITER at the DUBLIN STAGE.",
    "The EVIL   WORKER at the DUBLIN TEMPLE.",
    "The FUNNY  BAKER  at the LAGOS  BEACH.",
    "The FUNNY  CHILD  at the LAGOS  BRIDGE.",
    "The FUNNY  DOCTOR at the LAGOS  CASTLE.",
    "The FUNNY  DRIVER at the LAGOS  CHURCH.",
    "The FUNNY  KING   at the LAGOS  FARM.",
    "The FUNNY  LADY   at the LAGOS  FOREST.",
    "The FUNNY  LEADER at the LAGOS  GARDEN.",
    "The FUNNY  MAYOR  at the LAGOS  GHETTO.",
    "The FUNNY  MOTHER at the LAGOS  HOTEL.",
    "The FUNNY  NURSE  at the LAGOS  LAKE.",
    "The FUNNY  PRIEST at the LAGOS  MUSEUM.",
    "The FUNNY  PRINCE at the LAGOS  OASIS.",
    "The FUNNY  QUEEN  at the LAGOS  OPERA.",
    "The FUNNY  SISTER at the LAGOS  SCHOOL.",
    "The FUNNY  WAITER at the LAGOS  STAGE.",
    "The FUNNY  WORKER at the LAGOS  TEMPLE.",
    "The GUILTY BAKER  at the LONDON BEACH.",
    "The GUILTY CHILD  at the LONDON BRIDGE.",
    "The GUILTY DOCTOR at the LONDON CASTLE.",
    "The GUILTY DRIVER at the LONDON CHURCH.",
    "The GUILTY KING   at the LONDON FARM.",
    "The GUILTY LADY   at the LONDON FOREST.",
    "The GUILTY LEADER at the LONDON GARDEN.",
    "The GUILTY MAYOR  at the LONDON GHETTO.",
    "The GUILTY MOTHER at the LONDON HOTEL.",
    "The GUILTY NURSE  at the LONDON LAKE.",
    "The GUILTY PRIEST at the LONDON MUSEUM.",
    "The GUILTY PRINCE at the LONDON OASIS.",
    "The GUILTY QUEEN  at the LONDON OPERA.",
    "The GUILTY SISTER at the LONDON SCHOOL.",
    "The GUILTY WAITER at the LONDON STAGE.",
    "The GUILTY WORKER at the LONDON TEMPLE.",
    "The HAPPY  BAKER  at the MADRID BEACH.",
    "The HAPPY  CHILD  at the MADRID BRIDGE.",
    "The HAPPY  DOCTOR at the MADRID CASTLE.",
    "The HAPPY  DRIVER at the MADRID CHURCH.",
    "The HAPPY  KING   at the MADRID FARM.",
    "The HAPPY  LADY   at the MADRID FOREST.",
    "The HAPPY  LEADER at the MADRID GARDEN.",
    "The HAPPY  MAYOR  at the MADRID GHETTO.",
    "The HAPPY  MOTHER at the MADRID HOTEL.",
    "The HAPPY  NURSE  at the MADRID LAKE.",
    "The HAPPY  PRIEST at the MADRID MUSEUM.",
    "The HAPPY  PRINCE at the MADRID OASIS.",
    "The HAPPY  QUEEN  at the MADRID OPERA.",
    "The HAPPY  SISTER at the MADRID SCHOOL.",
    "The HAPPY  WAITER at the MADRID STAGE.",
    "The HAPPY  WORKER at the MADRID TEMPLE.",
    "The HEAVY  BAKER  at the MIAMI  BEACH.",
    "The HEAVY  CHILD  at the MIAMI  BRIDGE.",
    "The HEAVY  DOCTOR at the MIAMI  CASTLE.",
    "The HEAVY  DRIVER at the MIAMI  CHURCH.",
    "The HEAVY  KING   at the MIAMI  FARM.",
    "The HEAVY  LADY   at the MIAMI  FOREST.",
    "The HEAVY  LEADER at the MIAMI  GARDEN.",
    "The HEAVY  MAYOR  at the MIAMI  GHETTO.",
    "The HEAVY  MOTHER at the MIAMI  HOTEL.",
    "The HEAVY  NURSE  at the MIAMI  LAKE.",
    "The HEAVY  PRIEST at the MIAMI  MUSEUM.",
    "The HEAVY  PRINCE at the MIAMI  OASIS.",
    "The HEAVY  QUEEN  at the MIAMI  OPERA.",
    "The HEAVY  SISTER at the MIAMI  SCHOOL.",
    "The HEAVY  WAITER at the MIAMI  STAGE.",
    "The HEAVY  WORKER at the MIAMI  TEMPLE.",
    "The HONEST BAKER  at the MOSCOW BEACH.",
    "The HONEST CHILD  at the MOSCOW BRIDGE.",
    "The HONEST DOCTOR at the MOSCOW CASTLE.",
    "The HONEST DRIVER at the MOSCOW CHURCH.",
    "The HONEST KING   at the MOSCOW FARM.",
    "The HONEST LADY   at the MOSCOW FOREST.",
    "The HONEST LEADER at the MOSCOW GARDEN.",
    "The HONEST MAYOR  at the MOSCOW GHETTO.",
    "The HONEST MOTHER at the MOSCOW HOTEL.",
    "The HONEST NURSE  at the MOSCOW LAKE.",
    "The HONEST PRIEST at the MOSCOW MUSEUM.",
    "The HONEST PRINCE at the MOSCOW OASIS.",
    "The HONEST QUEEN  at the MOSCOW OPERA.",
    "The HONEST SISTER at the MOSCOW SCHOOL.",
    "The HONEST WAITER at the MOSCOW STAGE.",
    "The HONEST WORKER at the MOSCOW TEMPLE.",
    "The LONELY BAKER  at the OSLO   BEACH.",
    "The LONELY CHILD  at the OSLO   BRIDGE.",
    "The LONELY DOCTOR at the OSLO   CASTLE.",
    "The LONELY DRIVER at the OSLO   CHURCH.",
    "The LONELY KING   at the OSLO   FARM.",
    "The LONELY LADY   at the OSLO   FOREST.",
    "The LONELY LEADER at the OSLO   GARDEN.",
    "The LONELY MAYOR  at the OSLO   GHETTO.",
    "The LONELY MOTHER at the OSLO   HOTEL.",
    "The LONELY NURSE  at the OSLO   LAKE.",
    "The LONELY PRIEST at the OSLO   MUSEUM.",
    "The LONELY PRINCE at the OSLO   OASIS.",
    "The LONELY QUEEN  at the OSLO   OPERA.",
    "The LONELY SISTER at the OSLO   SCHOOL.",
    "The LONELY WAITER at the OSLO   STAGE.",
    "The LONELY WORKER at the OSLO   TEMPLE.",
    "The NOBEL  BAKER  at the PARIS  BEACH.",
    "The NOBEL  CHILD  at the PARIS  BRIDGE.",
    "The NOBEL  DOCTOR at the PARIS  CASTLE.",
    "The NOBEL  DRIVER at the PARIS  CHURCH.",
    "The NOBEL  KING   at the PARIS  FARM.",
    "The NOBEL  LADY   at the PARIS  FOREST.",
    "The NOBEL  LEADER at the PARIS  GARDEN.",
    "The NOBEL  MAYOR  at the PARIS  GHETTO.",
    "The NOBEL  MOTHER at the PARIS  HOTEL.",
    "The NOBEL  NURSE  at the PARIS  LAKE.",
    "The NOBEL  PRIEST at the PARIS  MUSEUM.",
    "The NOBEL  PRINCE at the PARIS  OASIS.",
    "The NOBEL  QUEEN  at the PARIS  OPERA.",
    "The NOBEL  SISTER at the PARIS  SCHOOL.",
    "The NOBEL  WAITER at the PARIS  STAGE.",
    "The NOBEL  WORKER at the PARIS  TEMPLE.",
    "The POLITE BAKER  at the PRAGUE BEACH.",
    "The POLITE CHILD  at the PRAGUE BRIDGE.",
    "The POLITE DOCTOR at the PRAGUE CASTLE.",
    "The POLITE DRIVER at the PRAGUE CHURCH.",
    "The POLITE KING   at the PRAGUE FARM.",
    "The POLITE LADY   at the PRAGUE FOREST.",
    "The POLITE LEADER at the PRAGUE GARDEN.",
    "The POLITE MAYOR  at the PRAGUE GHETTO.",
    "The POLITE MOTHER at the PRAGUE HOTEL.",
    "The POLITE NURSE  at the PRAGUE LAKE.",
    "The POLITE PRIEST at the PRAGUE MUSEUM.",
    "The POLITE PRINCE at the PRAGUE OASIS.",
    "The POLITE QUEEN  at the PRAGUE OPERA.",
    "The POLITE SISTER at the PRAGUE SCHOOL.",
    "The POLITE WAITER at the PRAGUE STAGE.",
    "The POLITE WORKER at the PRAGUE TEMPLE.",
    "The PRETTY BAKER  at the SEOUL  BEACH.",
    "The PRETTY CHILD  at the SEOUL  BRIDGE.",
    "The PRETTY DOCTOR at the SEOUL  CASTLE.",
    "The PRETTY DRIVER at the SEOUL  CHURCH.",
    "The PRETTY KING   at the SEOUL  FARM.",
    "The PRETTY LADY   at the SEOUL  FOREST.",
    "The PRETTY LEADER at the SEOUL  GARDEN.",
    "The PRETTY MAYOR  at the SEOUL  GHETTO.",
    "The PRETTY MOTHER at the SEOUL  HOTEL.",
    "The PRETTY NURSE  at the SEOUL  LAKE.",
    "The PRETTY PRIEST at the SEOUL  MUSEUM.",
    "The PRETTY PRINCE at the SEOUL  OASIS.",
    "The PRETTY QUEEN  at the SEOUL  OPERA.",
    "The PRETTY SISTER at the SEOUL  SCHOOL.",
    "The PRETTY WAITER at the SEOUL  STAGE.",
    "The PRETTY WORKER at the SEOUL  TEMPLE.",
    "The SCARY  BAKER  at the SPARTA BEACH.",
    "The SCARY  CHILD  at the SPARTA BRIDGE.",
    "The SCARY  DOCTOR at the SPARTA CASTLE.",
    "The SCARY  DRIVER at the SPARTA CHURCH.",
    "The SCARY  KING   at the SPARTA FARM.",
    "The SCARY  LADY   at the SPARTA FOREST.",
    "The SCARY  LEADER at the SPARTA GARDEN.",
    "The SCARY  MAYOR  at the SPARTA GHETTO.",
    "The SCARY  MOTHER at the SPARTA HOTEL.",
    "The SCARY  NURSE  at the SPARTA LAKE.",
    "The SCARY  PRIEST at the SPARTA MUSEUM.",
    "The SCARY  PRINCE at the SPARTA OASIS.",
    "The SCARY  QUEEN  at the SPARTA OPERA.",
    "The SCARY  SISTER at the SPARTA SCHOOL.",
    "The SCARY  WAITER at the SPARTA STAGE.",
    "The SCARY  WORKER at the SPARTA TEMPLE.",
    "The UGLY   BAKER  at the TOKYO  BEACH.",
    "The UGLY   CHILD  at the TOKYO  BRIDGE.",
    "The UGLY   DOCTOR at the TOKYO  CASTLE.",
    "The UGLY   DRIVER at the TOKYO  CHURCH.",
    "The UGLY   KING   at the TOKYO  FARM.",
    "The UGLY   LADY   at the TOKYO  FOREST.",
    "The UGLY   LEADER at the TOKYO  GARDEN.",
    "The UGLY   MAYOR  at the TOKYO  GHETTO.",
    "The UGLY   MOTHER at the TOKYO  HOTEL.",
    "The UGLY   NURSE  at the TOKYO  LAKE.",
    "The UGLY   PRIEST at the TOKYO  MUSEUM.",
    "The UGLY   PRINCE at the TOKYO  OASIS.",
    "The UGLY   QUEEN  at the TOKYO  OPERA.",
    "The UGLY   SISTER at the TOKYO  SCHOOL.",
    "The UGLY   WAITER at the TOKYO  STAGE.",
    "The UGLY   WORKER at the TOKYO  TEMPLE.",
    "The VAPID  BAKER  at the VIENNA BEACH.",
    "The VAPID  CHILD  at the VIENNA BRIDGE.",
    "The VAPID  DOCTOR at the VIENNA CASTLE.",
    "The VAPID  DRIVER at the VIENNA CHURCH.",
    "The VAPID  KING   at the VIENNA FARM.",
    "The VAPID  LADY   at the VIENNA FOREST.",
    "The VAPID  LEADER at the VIENNA GARDEN.",
    "The VAPID  MAYOR  at the VIENNA GHETTO.",
    "The VAPID  MOTHER at the VIENNA HOTEL.",
    "The VAPID  NURSE  at the VIENNA LAKE.",
    "The VAPID  PRIEST at the VIENNA MUSEUM.",
    "The VAPID  PRINCE at the VIENNA OASIS.",
    "The VAPID  QUEEN  at the VIENNA OPERA.",
    "The VAPID  SISTER at the VIENNA SCHOOL.",
    "The VAPID  WAITER at the VIENNA STAGE.",
    "The VAPID  WORKER at the VIENNA TEMPLE.",
]

TEST_DATAS = [bytes([i]) + bytes([i]) for i in range(2 ** 8)]


corpus_distance_test_cases = [
    (ADJECTIVES, 3),
    (TITLES    , 3),
    (CITIES    , 3),
    (PLACES    , 3),
    (WORDS     , 2),
]


@pytest.mark.parametrize("corpus, min_dist", corpus_distance_test_cases)
def test_corpus_distances(corpus, min_dist):
    for w1, w2 in itertools.product(corpus, corpus):
        if w1 == w2:
            continue

        d = pylev.damerau_levenshtein(w1, w2)
        assert d >= min_dist, (w1, w2)


def test_phrase2parts_fuzzymatch():
    case     = "the uugly major atthe viena tempel"
    expected = ["ugly", "mayor", "vienna", "temple"]
    assert phrase2parts(case) == expected


def test_phrase_hardcoded():
    # NOTE mb: Hardcoded test case reduces the chance that the wordlists are
    #   changed by accident.

    for phrase, data in zip(TEST_PHRASE_LINES, TEST_DATAS):
        assert bytes2phrase(data  ) == phrase
        assert phrase2bytes(phrase) == data

    full_data   = b"".join(TEST_DATAS)
    full_phrase = "\n".join(TEST_PHRASE_LINES)

    assert bytes2phrase(full_data  ) == full_phrase
    assert phrase2bytes(full_phrase) == full_data


def test_phrase_fuzz():
    for i in range(1, 100):
        data   = os.urandom(i % 20)
        phrase = bytes2phrase(data)
        assert phrase2bytes(phrase) == data

        # provoke encoding errors
        assert phrase.encode('ascii').decode('ascii') == phrase


def test_bytes2hex():
    assert bytes2hex(b"test data") == '746573742064617461'
    assert hex2bytes('746573742064617461') == b"test data"
    data = b"\x01\x23\x45\x67\x89\xAB\xCD\xEF"
    text = '0123456789aBcDeF'
    assert bytes2hex(data) == text.lower()
    assert hex2bytes(text) == data
    assert hex2bytes(text.upper()) == data
    assert hex2bytes(text.lower()) == data


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


def test_params2bytes():
    p = params.init_params(
        threshold=12, num_pieces=14, kdf_param_id=16, hash_len_bytes=48
    )

    pow2prime_idx = primes.get_pow2prime_index(p.hash_len_bytes * 8)
    expected_data = b"\x0b\x0c\x10"

    assert params2bytes(p) == expected_data

    p = bytes2params(expected_data)

    assert p.threshold == 12
    assert p.num_pieces >= 12
    assert p.pow2prime_idx  == pow2prime_idx
    assert p.kdf_param_id   == 16
    assert p.hash_len_bytes == 48


def test_bytes2gfpoint():
    data_len = 32
    prime    = primes.get_pow2prime(data_len * 8 - 8)
    gf       = polynom.GF(p=prime)

    in_point   = polynom.Point(gf[7], gf[1234567890])
    point_data = gfpoint2bytes(in_point)
    assert len(point_data) == data_len
    assert bytes2gfpoint(point_data, gf) == in_point


def test_intcode_fuzz():
    bytes2intcode(os.urandom(8))
    for i in range(0, 50, 4):
        data_len = i % 20 + 4
        data     = os.urandom(data_len)
        intcode  = bytes2intcode(data)
        decoded  = intcode2bytes(intcode)
        assert decoded == data

        lines = intcode.splitlines()
        assert all(len(l) == 4 for l in lines)
        assert len(lines) == data_len * 2
        if intcode:
            assert "".join(lines).isdigit()


TEST_DATA = (string.ascii_letters + "0123456789").encode('ascii')


@pytest.mark.parametrize("data_len", range(16, 33, 4))
def test_intcode_fuzz_loss(data_len):
    for _ in range(5):
        data    = TEST_DATA[:data_len]
        intcode = bytes2intcode(data)
        decoded = intcode2bytes(intcode)
        assert decoded == data

        parts     = intcode.split("\n")
        block_len = len(parts)
        clear_idx = random.randrange(0, len(parts))
        parts[clear_idx] = None
        decoded = intcode_parts2bytes(parts)
        assert decoded == data


def test_intcode_order_fail():
    data    = os.urandom(8)
    intcode = bytes2intcode(data)
    codes   = intcode.splitlines()
    decoded = intcode2bytes("\n".join(codes))
    assert decoded == data

    codes[0], codes[-1] = codes[-1], codes[0]

    try:
        intcode2bytes("\n".join(codes))
        assert False
    except ValueError as err:
        assert "Bad order" in str(err)


def test_intcode_parity_fail():
    data    = os.urandom(8)
    intcode = bytes2intcode(data)
    codes   = intcode.splitlines()
    decoded = intcode2bytes("\n".join(codes))
    assert decoded == data

    i = random.randrange(8)

    broken_code = int(codes[i], 10) ^ 1
    codes[i] = f"{broken_code:04}"
    try:
        intcode2bytes("\n".join(codes))
        assert False
    except ValueError as err:
        assert "Bad parity" in str(err)


def test_format_secret():
    data_len    = 24
    block_len   = data_len * 2
    packet_size = block_len // 8

    data      = os.urandom(data_len)
    formatted = format_secret(data)

    parsed = parse_formatted_secret(formatted)

    assert phrase2bytes(" ".join(parsed.phrases)) == data
    packets = intcode_parts2packets(parsed.data_codes, packet_size)
    assert b"".join(packets) == data

    codes = parsed.data_codes + parsed.ecc_codes
    assert len(codes) == block_len
    decoded = intcode_parts2bytes(codes)
    assert decoded == data
