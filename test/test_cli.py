import os
import random
import string
import typing as typ
import contextlib

import click
import pytest

import sbk.ecc
import sbk.cli_io
from sbk.cli_util import *
from sbk.mnemonic import *


def test_intcode_fuzz():
    bytes2intcodes(os.urandom(8))

    for i in range(0, 50, 4):
        data_len = i % 20 + 4
        data     = os.urandom(data_len)
        intcodes = bytes2intcodes(data)
        decoded  = intcodes2bytes(intcodes)
        assert decoded == data
        for intcode in intcodes:
            assert intcode.count("-") == 1
            intcode = intcode.replace("-", "")
            assert len(intcode) == 6
            assert intcode.isdigit()

        # NOTE: each intcode encodes 2 bytes but there are 2x the intcodes to include the ecc data
        assert len(intcodes) == data_len


TEST_DATA = (string.ascii_letters + "0123456789").encode('ascii')


@pytest.mark.parametrize("data_len", range(16, 33, 4))
def test_intcode_fuzz_loss(data_len):
    for _ in range(5):
        data     = TEST_DATA[:data_len]
        intcodes = bytes2intcodes(data)
        decoded  = intcodes2bytes(intcodes)
        assert decoded == data

        parts     = intcodes[:]
        clear_idx = random.randrange(0, len(parts))
        parts[clear_idx] = None
        decoded = maybe_intcodes2bytes(parts)
        assert decoded == data


@pytest.mark.parametrize("data_len", range(4, 33, 4))
def test_intcode_order_fail(data_len):
    data     = os.urandom(data_len)
    intcodes = bytes2intcodes(data)
    decoded  = intcodes2bytes(intcodes)
    assert decoded == data

    for _ in range(len(data)):
        i = random.randint(0, data_len - 1)
        j = random.randint(0, data_len - 1)

        intcodes_kaputt = intcodes[:]
        intcodes_kaputt[i], intcodes_kaputt[j] = intcodes_kaputt[j], intcodes_kaputt[i]

        if i % 13 == j % 13:
            # In this case the ecc data should either save us or fail
            try:
                decoded = intcodes2bytes(intcodes_kaputt)
                assert decoded == data
            except sbk.ecc.DecodeError:
                pass
        else:
            try:
                intcodes2bytes(intcodes_kaputt)
                # should have raised ValueError
                assert False
            except ValueError as err:
                assert "Bad order" in str(err)


@pytest.mark.parametrize("data_len", list(range(4, 25, 4)))
def test_format_secret(data_len):
    block_len  = data_len * 2
    packet_len = block_len // 8

    data      = os.urandom(data_len)
    formatted = format_secret(data)
    parsed    = parse_formatted_secret(formatted)

    assert phrase2bytes(" ".join(parsed.words)) == data
    intcodes = parsed.data_codes + parsed.ecc_codes
    assert len(intcodes) * 2 == block_len
    decoded = maybe_intcodes2bytes(intcodes)
    assert decoded == data

    packets = intcodes2parts(parsed.data_codes)
    assert b"".join(packets[:data_len]) == data


@pytest.mark.parametrize("data_len", list(range(4, 25, 4)))
def test_partial_format_secret(data_len):
    data  = os.urandom(data_len)
    lines = [l for l in format_secret_lines(data) if l.strip()]
    lines = lines[1:]
    assert len(lines) == data_len // 2


def test_parse_formatted_secret():
    data      = b"\x00\x01\x02\x03\xfc\xfd\xfe\xff"
    formatted = format_secret(data)
    parsed    = parse_formatted_secret(formatted)
    assert parsed.words[0].lower() == "abacus"
    assert parsed.words[0].lower() == WORDLISTS[0][0]
    assert parsed.words[1].lower() == WORDLISTS[1][1]
    assert parsed.words[2].lower() == WORDLISTS[0][2]
    assert parsed.words[3].lower() == WORDLISTS[1][3]
    assert parsed.words[-4].lower() == WORDLISTS[0][-4]
    assert parsed.words[-3].lower() == WORDLISTS[1][-3]
    assert parsed.words[-2].lower() == WORDLISTS[0][-2]
    assert parsed.words[-1].lower() == WORDLISTS[1][-1]
    assert parsed.words[-1].lower() == "zimbabwe"

    assert len(parsed.data_codes) == 4
    assert len(parsed.ecc_codes ) == 4

    assert int(parsed.data_codes[0].replace("-", "")) & 0xFFFF == 0x0001
    assert int(parsed.data_codes[1].replace("-", "")) & 0xFFFF == 0x0203
    assert int(parsed.data_codes[2].replace("-", "")) & 0xFFFF == 0xFCFD
    assert int(parsed.data_codes[3].replace("-", "")) & 0xFFFF == 0xFEFF


def test_parse_scheme():
    assert parse_scheme("1of2"  ) == Scheme( 1,  2)
    assert parse_scheme("3of5"  ) == Scheme( 3,  5)
    assert parse_scheme("11of13") == Scheme(11, 13)

    try:
        parse_scheme("invalid")
        assert False, "expected click.Abort"
    except click.Abort:
        pass

    try:
        parse_scheme("11of5")
        assert False, "expected click.Abort"
    except click.Abort:
        pass


@contextlib.contextmanager
def io_playbook():
    _original_echo   = sbk.cli_io._echo
    _original_clear  = sbk.cli_io._clear
    _original_prompt = sbk.cli_io._prompt

    io_buf = []
    cursor = 0

    def _mock_echo(text: str) -> bool:
        io_buf.append("< " + text)
        return True

    def _mock_clear() -> bool:
        del io_buf[:]
        return True

    def _mock_prompt(text: str) -> str:
        io_buf.append("< " + text)
        input_text = "\n".join(input_buf)
        del prompt_results[:]
        return input_text

    def send(text: str):
        input_buf.append(maybe_input)

    def recv() -> str:
        output = "\n".join(io_buf)
        del io_buf[:]
        return output

    yield playbook

    sbk.cli_io._echo   = _original_echo
    sbk.cli_io._clear  = _original_clear
    sbk.cli_io._prompt = _original_prompt


def test_prompt_brainkey():
    with io_playbook() as pb:
        pb
        result = sbk.cli_io.prompt()
        pb.verify()
        assert result == b"\x12\x12\x12\x12\x12"
