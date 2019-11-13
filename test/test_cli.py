import os
import re
import math
import time
import random
import string
import typing as typ
import itertools

import click
import pytest
import click.testing

import sbk.cli
import sbk.cli_io
import sbk.ecc_rs
from sbk.cli_util import *
from sbk.mnemonic import *


@pytest.mark.skipif("slow" in os.getenv('PYTEST_SKIP', ""), reason="ECC recovery can be intense")
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


def test_bytes2incode_part():
    in_data = b"\x01\x23"
    intcode = bytes2incode_part(in_data)
    assert b"".join(intcodes2parts([intcode])) == in_data


TEST_DATA = (string.ascii_letters + "0123456789").encode('ascii')

DATA_LENS = [4, 12, 20]


@pytest.mark.skipif("slow" in os.getenv('PYTEST_SKIP', ""), reason="ECC recovery can be intense")
@pytest.mark.parametrize("data_len", DATA_LENS)
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


@pytest.mark.skipif("slow" in os.getenv('PYTEST_SKIP', ""), reason="ECC recovery can be intense")
@pytest.mark.parametrize("data_len", DATA_LENS)
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
            except sbk.ecc_rs.ECCDecodeError:
                pass
        else:
            try:
                intcodes2bytes(intcodes_kaputt)
                # should have raised ValueError
                assert False
            except ValueError as err:
                assert "Bad order" in str(err)


@pytest.mark.parametrize("data_len", DATA_LENS)
def test_format_secret(data_len):
    block_len = math.ceil((data_len * 2) / 4) * 4

    data      = os.urandom(data_len)
    formatted = sbk.cli_io.format_secret('salt', data)
    parsed    = parse_formatted_secret(formatted)

    assert phrase2bytes(" ".join(parsed.words)) == data
    intcodes = parsed.data_codes + parsed.ecc_codes
    assert len(intcodes) * 2 == block_len
    decoded = maybe_intcodes2bytes(intcodes)
    assert decoded == data

    packets = intcodes2parts(parsed.data_codes)
    assert b"".join(packets[:data_len]) == data


@pytest.mark.parametrize("data_len", DATA_LENS)
def test_partial_format_secret(data_len):
    data  = os.urandom(data_len)
    lines = [l for l in sbk.cli_io.format_secret_lines('salt', data) if l.strip()]
    assert len(lines) == data_len // 2


def test_parse_formatted_secret():
    data = b"\x00\x01\x02\x03\xfc\xfd\xfe\xff"

    formatted = sbk.cli_io.format_secret('salt', data)
    parsed    = parse_formatted_secret(formatted)

    assert parsed.words[0].lower() == "abraham"
    assert parsed.words[0].lower() == WORDLIST[0]
    assert parsed.words[1].lower() == WORDLIST[1]
    assert parsed.words[2].lower() == WORDLIST[2]
    assert parsed.words[3].lower() == WORDLIST[3]
    assert parsed.words[-4].lower() == WORDLIST[-4]
    assert parsed.words[-3].lower() == WORDLIST[-3]
    assert parsed.words[-2].lower() == WORDLIST[-2]
    assert parsed.words[-1].lower() == WORDLIST[-1]
    assert parsed.words[-1].lower() == "zimbabwe"

    assert len(parsed.data_codes) == 4
    assert len(parsed.ecc_codes ) == 4

    assert int(parsed.data_codes[0].replace("-", "")) & 0xFFFF == 0x0001
    assert int(parsed.data_codes[1].replace("-", "")) & 0xFFFF == 0x0203
    assert int(parsed.data_codes[2].replace("-", "")) & 0xFFFF == 0xFCFD
    assert int(parsed.data_codes[3].replace("-", "")) & 0xFFFF == 0xFEFF


def test_parse_scheme():
    assert parse_scheme("1of2"  ) == Scheme(1, 2)
    assert parse_scheme("3of5"  ) == Scheme(3, 5)
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


def test_progress_bar():
    # Doesn't test the output, just excercises the code to provoke
    # any runtime errors
    arg = os.urandom(4)

    def dummy_func(got_arg):
        time.sleep(0.1)
        return got_arg * 2

    tzero = time.time()
    t     = EvalWithProgressbar(target=dummy_func, args=(arg,))
    t.start_and_wait(eta_sec=0.1, label="Test")
    assert t.retval == (arg * 2)
    elapsed = time.time() - tzero
    assert 0.1 < elapsed < 0.3


DEBUG_RANDOM_SHARE_1 = [
    "000-305 081-920 131-487 253-640",
    "297-496 334-650 440-054 474-496",
    "581-782 644-003 717-580 745-532",
    "786-914",
]

DEBUG_RANDOM_SHARE_2 = [
    "000-305 081-920 131-595 231-772",
    "319-484 328-257 407-992 476-877",
    "560-377 619-283 700-900 756-803",
    "851-420",
]

DEBUG_RANDOM_SHARE_3 = [
    "000-305 081-920 131-959 209-905",
    "275-935 387-399 441-466 479-258",
    "538-972 594-563 684-220 768-075",
    "838-315",
]

DEBUG_RANDOM_SALT = [
    "000-305 081-920 144-436 209-972",
    "275-508 341-044 406-580 472-116",
]

DEBUG_RANDOM_BRAINKEY = [
    "013-364 078-900 144-436 209-972",
]


def test_cli_create_validation():
    argv = [
        "--scheme=2of3",
        "--memory-cost=1",
        "--time-cost=1",
    ]
    inputs = [
        "\n\n\n\n\n\n\n\n\n",  # confirmations
        "\n".join(DEBUG_RANDOM_SALT) + "\n",
        "accept\n",
        "\n".join(DEBUG_RANDOM_BRAINKEY) + "\n",
        "accept\n",
        "\n".join(DEBUG_RANDOM_SHARE_1) + "\n",
        "accept\n",
        "\n".join(DEBUG_RANDOM_SHARE_2) + "\n",
        "accept\n",
        "\n".join(DEBUG_RANDOM_SHARE_3) + "\n",
        "accept\n",
    ]
    env    = {'SBK_PROGRESS_BAR': '0', 'SBK_DEBUG_RANDOM': 'DANGER'}
    runner = click.testing.CliRunner()
    result = runner.invoke(sbk.cli.create, argv, input="".join(inputs), env=env)

    assert not result.exception
    assert result.exit_code == 0


def test_cli_create():
    argv = [
        "--scheme=2of3",
        "--brainkey-len=6",
        "--yes-all",
        "--parallelism=1",
        "--memory-cost=1",
        "--time-cost=1",
    ]
    env    = {'SBK_PROGRESS_BAR': '0'}
    runner = click.testing.CliRunner()
    result = runner.invoke(sbk.cli.create, argv, env=env)
    assert not result.exception
    assert result.exit_code == 0

    step_outputs = result.output.split("Step")

    assert len(step_outputs) == 6
    assert " Share 1/3" in step_outputs[1]
    assert " Share 2/3" in step_outputs[2]
    assert " Share 3/3" in step_outputs[3]
    assert " Salt" in step_outputs[4]
    assert " Brainkey" in step_outputs[5]

    share1   = parse_formatted_secret(step_outputs[1], strict=False)
    share2   = parse_formatted_secret(step_outputs[2], strict=False)
    share3   = parse_formatted_secret(step_outputs[3], strict=False)
    salt     = parse_formatted_secret(step_outputs[4], strict=False)
    brainkey = parse_formatted_secret(step_outputs[5], strict=False)

    assert len({share1, share2, share3, salt, brainkey}) == 5
    shares = [share1, share2, share3]
    random.shuffle(shares)

    for combo in itertools.combinations(shares, 2):
        recover_inputs = []
        for share in combo:
            recover_inputs.extend(
                [" ".join(share.words[:4]) + "\n", " ".join(share.words[4:]) + "\n", "accept\n",]
            )

        runner = click.testing.CliRunner()
        result = runner.invoke(sbk.cli.recover, input="".join(recover_inputs))
        assert not result.exception
        assert result.exit_code == 0

        secrets = result.output.split("RECOVERED SECRETS")[-1]
        assert "Salt" in secrets
        assert "Brainkey" in secrets

        salt_output, brainkey_output = secrets.lower().split("brainkey")
        recoverd_salt      = parse_formatted_secret(salt_output, strict=False)
        recovered_brainkey = parse_formatted_secret(brainkey_output, strict=False)

        assert salt     == recoverd_salt
        assert brainkey == recovered_brainkey


FULL_SALT_LINES = [
    "01: 000-034   abraham   bordeaux    09: 563-651",
    "02: 081-920   donut     adelaide    10: 605-856",
    "03: 180-251   rainbow   bavaria     11: 694-358",
    "04: 212-020   diesel    china       12: 769-089",
    "05: 308-920   pizza     oxford      13: 801-938",
    "06: 371-125   pelican   oregon      14: 007-134",
    "07: 396-714   battery   nevada      15: 083-252",
    "08: 475-210   donut     egypt       16: 167-533",
]


SALT_WORD_INPUTS = [
    "abacus    bordeaux   donut     adelaide\n",
    "rainbow   bavaria    diesel    china\n",
    "pizza     oxford     pelican   oregon\n",
    "battery   nevada     donut     egypt\n",
    "\n",
]


BRAINKEY_WORD_INPUTS = [
    "donut     adelaide\n",
    "rainbow   bavaria\n",
    "donut     egypt\n",
    "\n",
]


def test_cli_recover_salt_from_words():
    return
    runner = click.testing.CliRunner()
    result = runner.invoke(sbk.cli.recover_salt, input="".join(SALT_WORD_INPUTS))
    assert not result.exception
    assert result.exit_code == 0
    assert all(line in result.output for line in FULL_SALT_LINES)

    assert result.output.count("=> 01: ___-___") == 1
    assert result.output.count("=> 03: ___-___") == 1
    assert result.output.count("=> 05: ___-___") == 1
    assert result.output.count("=> 07: ___-___") == 1
    assert result.output.count("09: 563-651 <=") == 1


def test_cli_recover_salt_from_data():
    return
    inputs = [
        "000-034 081-920 180-251 212-020\n",
        "308-920 371-125 396-714 475-210\n",
        "\n",
    ]

    runner = click.testing.CliRunner()
    result = runner.invoke(sbk.cli.recover_salt, input="".join(inputs))
    assert not result.exception
    assert result.exit_code == 0
    assert all(line in result.output for line in FULL_SALT_LINES)
    # check cursor positions
    assert result.output.count("=> 01: ___-___") == 1
    assert result.output.count("=> 05: ___-___") == 1
    assert result.output.count("09: 563-651 <=") == 1


def test_cli_recover_salt_from_ecc():
    return
    inputs = [
        "next\nnext\nnext\nnext\n",
        "next\nnext\nnext\nnext\n",
        "563-651 605-856 694-358 769-089\n",
        "801-938 007-134 083-252 167-533\n",
        "accept\n",
    ]

    runner = click.testing.CliRunner()
    result = runner.invoke(sbk.cli.recover_salt, input="".join(inputs))
    assert not result.exception
    assert result.exit_code == 0

    assert all(line in result.output for line in FULL_SALT_LINES)


def test_cli_load_wallet():
    return
    wallet_names = ["default", "test1", "test2", "Hello, 世界!"] * 2
    inputs       = SALT_WORD_INPUTS + BRAINKEY_WORD_INPUTS

    all_seeds = []
    for name in wallet_names:
        args = ("--show-seed", "--yes-all", "--wallet-name", name)

        runner = click.testing.CliRunner()
        result = runner.invoke(sbk.cli.load_wallet, args=args, input="".join(inputs))

        assert not result.exception
        assert result.exit_code == 0

        commands, wallet_seed = result.output.lower().split("electrum wallet seed")
        all_seeds.append(wallet_seed.strip())

    # same name, same seed
    assert len(set(wallet_names)) == len(set(all_seeds))


def test_cli_kdf_info():
    runner = click.testing.CliRunner()
    result = runner.invoke(sbk.cli.kdf_info)

    assert not result.exception
    assert result.exit_code == 0
    assert "<- default" in result.output


def test_cli_kdf_test():
    args   = ("--memory-cost", "1", "--time-cost", "1")
    runner = click.testing.CliRunner()
    result = runner.invoke(sbk.cli.kdf_test, args=args)

    assert not result.exception
    assert result.exit_code == 0

    assert re.search(r"Estimated duration\s*:\s+\d+ sec", result.output)
    assert re.search(r"Actual duration\s*:\s+\d+ sec", result.output)
