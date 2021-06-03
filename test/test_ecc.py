import io
import os
import random

import pytest

import sbk.ecc_rs
import sbk.enc_util

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
    assert capsys.readouterr().out.strip() == "48656c6c6f2c20e4b896e7958c210a51ee32d3ac1bee26daac14d3b95428"


def test_main_decode(capsys):
    buf = io.StringIO()
    buf.write("48656c6c6f2c20e4b896e7958c210a51ee32d3ac1bee26daac14d3b95428\n")
    buf.seek(0)
    sbk.ecc_rs.main(args=['--decode'], stdin=buf)
    assert capsys.readouterr().out.strip() == "Hello, 世界!"
