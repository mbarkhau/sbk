import io
import os
import sys
import random

import pytest

import sbk.ecc_rs
import sbk.enc_util

# import sbk.ecc_lt


TEST_INPUT  = "Hello, 世界!\n"
TEST_OUTPUT = "48656c6c6f2c20e4b896e7958c210a51ee32d3ac1bee26daac14d3b95428"


def test_rs_cli_basic_encode():
    encoded = sbk.ecc_rs._cli_encode(TEST_INPUT)
    assert encoded == TEST_OUTPUT


def test_rs_cli_basic_decode():
    decoded = sbk.ecc_rs._cli_decode(TEST_OUTPUT)
    assert decoded == TEST_INPUT


def test_rs_cli_erasures_decode():
    bad_block = "48656c6c6f2c20e4b896e7958c210a                              "
    decoded   = sbk.ecc_rs._cli_decode(bad_block)
    assert decoded == TEST_INPUT

    bad_block = "                              51ee32d3ac1bee26daac14d3b95428"
    decoded   = sbk.ecc_rs._cli_decode(bad_block)
    assert decoded == TEST_INPUT

    bad_block = "48656c6c6f2c20                              26daac14d3b95428"
    decoded   = sbk.ecc_rs._cli_decode(bad_block)
    assert decoded == TEST_INPUT


def test_rs_cli_corruption1_decode():
    bad_block = "00006c6c6f2c20e4b896e7958c210a51ee32d3ac1bee26daac14d3b95428"
    decoded   = sbk.ecc_rs._cli_decode(bad_block)
    assert decoded == TEST_INPUT


def test_rs_cli_corruption2_decode():
    encoded = sbk.ecc_rs._cli_encode("Hello!")
    try:
        bad_block_i = len(encoded) // 2
        bad_block   = ("0" * bad_block_i) + encoded[bad_block_i:]
        decoded     = sbk.ecc_rs._cli_decode(bad_block)
        assert False, "Exception expected"
    except ValueError as ex:
        if "too corrupt to recover" not in str(ex):
            raise

    bad_block_i = len(encoded) // 3
    bad_block   = ("0" * bad_block_i) + encoded[bad_block_i:]
    decoded     = sbk.ecc_rs._cli_decode(bad_block)
    assert decoded == "Hello!"


def _add_bad_symbols(block, errors=0, erasures=0):
    bad_block_data = list(block)
    err_indexes    = [random.randint(0, len(block) - 1) for _ in range(errors)]
    for i in err_indexes:
        bad_block_data[i] = 0
    del_indexes = []

    bad_block = bytes(bad_block_data)
    return bad_block, err_indexes, del_indexes


ALL_MSG_LENS = [2, 3, 4, 8, 12, 14, 24]

if "slow" in os.getenv('PYTEST_SKIP', ""):
    SLOW_MSG_LENS = [2, 3, 8, 14]
else:
    SLOW_MSG_LENS = ALL_MSG_LENS


@pytest.mark.parametrize("msg_len", ALL_MSG_LENS)
def test_rs_round_trip(msg_len):
    msg_in  = os.urandom(msg_len)
    block   = sbk.ecc_rs.encode(msg_in)
    ecc_len = len(block) - msg_len
    assert ecc_len >= msg_len
    assert len(block) % 4 == 0
    assert block.startswith(msg_in)
    msg_out = sbk.ecc_rs.decode(block, msg_len)
    assert msg_out == msg_in


@pytest.mark.parametrize("msg_len", SLOW_MSG_LENS)
def test_rs_erasure(msg_len):
    msg_in = os.urandom(msg_len)
    block  = sbk.ecc_rs.encode(msg_in)
    try:
        os.environ['SBK_VERIFY_ECC_RS_INTERPOLATION_TERMS'] = "1"
        for max_erasures in range(1, msg_len):
            packets = list(block)

            # erase some packets
            for _ in range(max_erasures):
                packets[random.randrange(0, len(block))] = None

            msg_out = sbk.ecc_rs.decode_packets(packets, msg_len)
            assert msg_out == msg_in
    finally:
        del os.environ['SBK_VERIFY_ECC_RS_INTERPOLATION_TERMS']


@pytest.mark.parametrize("msg_len", SLOW_MSG_LENS)
def test_rs_corruption(msg_len):
    msg_in = os.urandom(msg_len)
    block  = sbk.ecc_rs.encode(msg_in)

    for max_corruption in range(1, max(1, min(6, 2 * msg_len // 3))):
        packets = list(block)

        # corrupt some packets
        for _ in range(max_corruption):
            packets[random.randrange(0, len(block))] = 0xFF

        msg_out = sbk.ecc_rs.decode_packets(packets, msg_len)
        assert msg_out == msg_in


@pytest.mark.skip(reason="LT Codes only for documentation")
def test_lt_xor_bytes():
    cases = [
        (b"\x00\x00", b"\x00\x00", b"\x00\x00"),
        (b"\x12\x34", b"\x00\x00", b"\x12\x34"),
        (b"\x00\x00", b"\x12\x34", b"\x12\x34"),
        (b"\x01\x01", b"\x10\x10", b"\x11\x11"),
    ]
    for x, y, z in cases:
        assert sbk.ecc_lt.xor_bytes(x, y) == z


@pytest.mark.skip(reason="LT Codes only for documentation")
def test_lt_packet_block_indexes():
    _bi = sbk.ecc_lt.BlockIndex

    expected = [
        (_bi( 0,  6),),
        (_bi( 6, 12),),
        (_bi(12, 18),),
        (_bi(18, 24),),
        (_bi( 0,  6), _bi( 6, 12), _bi(12, 18)),
        (_bi( 0,  6), _bi( 6, 12), _bi(18, 24)),
        (_bi( 0,  6), _bi(12, 18), _bi(18, 24)),
        (_bi( 6, 12), _bi(12, 18), _bi(18, 24)),
    ]
    indexes = sbk.ecc_lt.packet_block_indexes(msg_len=24)
    assert indexes == expected


@pytest.mark.skip(reason="LT Codes only for documentation")
def test_lt_encode():
    message = b'a1b2c3d4'
    block   = sbk.ecc_lt.encode(message)
    assert len(block) == 16
    assert block.startswith(message)
    ecc_data = bytes(
        [
            ord(b'a') ^ ord(b'b') ^ ord(b'c'),
            ord(b'1') ^ ord(b'2') ^ ord(b'3'),
            ord(b'a') ^ ord(b'b') ^ ord(b'd'),
            ord(b'1') ^ ord(b'2') ^ ord(b'4'),
            ord(b'a') ^ ord(b'c') ^ ord(b'd'),
            ord(b'1') ^ ord(b'3') ^ ord(b'4'),
            ord(b'b') ^ ord(b'c') ^ ord(b'd'),
            ord(b'2') ^ ord(b'3') ^ ord(b'4'),
        ]
    )
    assert block == b'a1b2c3d4' + ecc_data


@pytest.mark.skip(reason="LT Codes only for documentation")
def test_lt_block2packets():
    msg     = b'0123456789ABCDEF'
    packets = sbk.ecc_lt.block2packets(msg)
    assert packets == [b'01', b'23', b'45', b'67', b'89', b'AB', b'CD', b'EF']


@pytest.mark.skip(reason="LT Codes only for documentation")
def test_lt_residual_xor():
    a_bi = sbk.ecc_lt.BlockIndex(0, 2)
    b_bi = sbk.ecc_lt.BlockIndex(2, 4)

    x_pbi = (a_bi,)
    y_pbi = (a_bi, b_bi)

    x = sbk.ecc_lt.Residual(b"\x00\x01", x_pbi)
    y = sbk.ecc_lt.Residual(b"\x02\x03", y_pbi)
    z = x ^ y

    assert len(x) == 1
    assert len(y) == 2
    assert len(z) == 1

    assert len(x.sources) == 1
    assert len(y.sources) == 1
    assert len(z.sources) == 2

    assert z.indexes == (b_bi,)
    assert z.data    == b"\x02\x02"


@pytest.mark.skip(reason="LT Codes only for documentation")
def test_lt_candidate_counts():
    message          = b'01234567'
    block            = sbk.ecc_lt.encode(message)
    packets          = sbk.ecc_lt.block2packets(block)
    indexed_packets  = {idx: pkt for idx, pkt in enumerate(packets)}
    candidate_counts = {}

    for i in range(5):
        candidates  = list(sbk.ecc_lt._iter_packet_candidates(indexed_packets))
        num_packets = len(indexed_packets)
        candidate_counts[num_packets] = len(candidates)
        del indexed_packets[i]

    assert candidate_counts == sbk.ecc_lt.CANDIDATE_COUNTS_BY_NUM_PACKETS


@pytest.mark.skip(reason="LT Codes only for documentation")
def test_lt_decode():
    message = b'01234567'
    block   = sbk.ecc_lt.encode(message)
    assert sbk.ecc_lt.decode(block) == message
    # Fuzz test
    for msg_len in range(4, 21, 4):
        message = os.urandom(msg_len)
        block   = sbk.ecc_lt.encode(message)
        decoded = sbk.ecc_lt.decode(block)
        assert decoded == message


@pytest.mark.skip(reason="LT Codes only for documentation")
def test_lt_decode_packets():
    message = b'01234567'
    block   = sbk.ecc_lt.encode(message)
    packets = sbk.ecc_lt.block2packets(block)
    decoded = sbk.ecc_lt.decode_packets(packets)

    assert decoded == message


@pytest.mark.skip(reason="LT Codes only for documentation")
def test_lt_decode_packets_corrupted():
    message = b'01234567'
    block   = sbk.ecc_lt.encode(message)
    packets = sbk.ecc_lt.block2packets(block)

    for i in range(len(packets)):
        partial_packets = packets[:]
        partial_packets[i] = None
        decoded = sbk.ecc_lt.decode_packets(partial_packets)
        assert decoded == message, f"invalid result: {decoded}"


@pytest.mark.skip(reason="LT Codes only for documentation")
def test_lt_decode_packets_missing():
    data    = os.urandom(12)
    block   = sbk.ecc_lt.encode(data)
    packets = sbk.ecc_lt.block2packets(block)

    for o in range(4):
        partial_packets = [p if i < 4 + o else None for i, p in enumerate(packets)]
        decoded         = sbk.ecc_lt.decode_packets(partial_packets)
        assert decoded == data

    partial_packets = [p if i < 4 else None for i, p in enumerate(packets)]
    decoded         = sbk.ecc_lt.decode_packets(partial_packets)
    assert decoded == data

    partial_packets = [p if i >= 4 else None for i, p in enumerate(packets)]
    decoded         = sbk.ecc_lt.decode_packets(partial_packets)
    assert decoded == data

    partial_packets = [p if i % 2 == 0 else None for i, p in enumerate(packets)]
    decoded         = sbk.ecc_lt.decode_packets(partial_packets)
    assert decoded == data

    partial_packets = [p if i % 2 == 1 else None for i, p in enumerate(packets)]
    decoded         = sbk.ecc_lt.decode_packets(partial_packets)
    assert decoded == data


def _lt_fuzz_iter():
    for msg_len in range(4, 21, 4):
        data    = os.urandom(msg_len)
        block   = sbk.ecc_lt.encode(data)
        packets = sbk.ecc_lt.block2packets(block)
        yield data, block, packets


@pytest.mark.skip(reason="LT Codes only for documentation")
def test_lt_decode_fuzz_basic():
    for data, block, packets in _lt_fuzz_iter():
        assert len(block) == len(data) * 2
        decoded = sbk.ecc_lt.decode(block)
        assert decoded == data
        decoded = sbk.ecc_lt.decode_packets(packets)
        assert decoded == data


@pytest.mark.skip(reason="LT Codes only for documentation")
def test_lt_decode_fuzz_missing_packets():
    for data, block, packets in _lt_fuzz_iter():
        for packet_err_count in [0, 1, 2, 3]:
            packets         = sbk.ecc_lt.block2packets(block)
            partial_packets = packets[:]
            for _ in range(packet_err_count):
                i = random.randint(0, 7)
                partial_packets[i] = None
            decoded = sbk.ecc_lt.decode_packets(partial_packets)
            assert decoded == data


@pytest.mark.skip(reason="LT Codes only for documentation")
def test_lt_decode_error_detect():
    for num_errs in [1, 2]:
        errors  = 0
        success = 0
        invalid = 0

        for data, block, packets in _lt_fuzz_iter():
            bad_block, err_indexes, del_indexes = _add_bad_symbols(block, num_errs)
            try:
                decoded = sbk.ecc_lt.decode(bad_block)
                if decoded == data:
                    success += 1
                else:
                    print(">> data ", sbk.enc_util.bytes_repr(data     ))
                    print(">> block", sbk.enc_util.bytes_repr(block    ))
                    print("<< data ", sbk.enc_util.bytes_repr(decoded  ))
                    print("<< block", sbk.enc_util.bytes_repr(bad_block))

                    print("!! error indexes  ", err_indexes)
                    print("!! deleted indexes", del_indexes)
                    invalid += 1
            except sbk.ecc_lt.DecodeError:
                errors += 1

        if num_errs == 1:
            assert errors == 0

        assert errors + success > 0
        assert invalid == 0


def test_main_test(capsys):
    # No validation, just excercising the code
    sbk.ecc_rs.main(args=['--test'])
    assert capsys.readouterr().out == "ok\n"


def test_main_profile(capsys):
    # No validation, just excercising the code
    sbk.ecc_rs.main(args=['--profile'])
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) > 20


def test_main_encode(capsys):
    buf = io.StringIO()
    buf.write("Hello, 世界!\n")
    buf.seek(0)
    sbk.ecc_rs.main(args=['--encode'], stdin=buf)
    assert (
        capsys.readouterr().out.strip()
        == "48656c6c6f2c20e4b896e7958c210a51ee32d3ac1bee26daac14d3b95428"
    )


def test_main_decode(capsys):
    buf = io.StringIO()
    buf.write("48656c6c6f2c20e4b896e7958c210a51ee32d3ac1bee26daac14d3b95428\n")
    buf.seek(0)
    sbk.ecc_rs.main(args=['--decode'], stdin=buf)
    assert capsys.readouterr().out.strip() == "Hello, 世界!"
