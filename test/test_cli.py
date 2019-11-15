import os
import re
import math
import time
import random
import string
import typing as typ
import itertools
import collections

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


def test_threading():
    # Doesn't test the output, just excercises the code to provoke
    # any runtime errors
    arg = os.urandom(4)

    def dummy_func():
        time.sleep(0.1)
        return arg * 2

    tzero  = time.time()
    result = run_with_progress_bar(dummy_func, eta_sec=0.1, label="Test")
    assert result == arg * 2
    elapsed = time.time() - tzero
    assert 0.1 < elapsed < 0.3


DEBUG_NONRANDOM_OUTPUT = """
                     Share 1/3
   01: 000-305   academy   colombia    14: 037-658
   02: 081-920   dubai     abraham     15: 081-662
   03: 131-569   academy   vivaldi     16: 183-057
   04: 254-752   turkey    blood       17: 225-330
   05: 307-404   pumpkin   sparrow     18: 278-996
   06: 392-111   wizard    prophet     19: 385-574

   07: 442-499   school    london      20: 435-840
   08: 482-163   gotham    julius      21: 484-052
   09: 566-387   peugeot   julius      22: 571-535
   10: 591-028   airport   radio       23: 595-329
   11: 688-042   leibniz   popcorn     24: 711-418
   12: 722-449   albino    auburn      25: 731-805
   13: 826-795   orwell    porsche     26: 843-687

                     Share 2/3
   01: 000-305   academy   colombia    14: 038-962
   02: 081-920   dubai     abraham     15: 130-443
   03: 131-749   acrobat   pharaoh     16: 191-593
   04: 229-660   library   bhutan      17: 216-884
   05: 272-351   builder   trinidad    18: 297-526
   06: 373-017   pyramid   belfast     19: 357-771

   07: 444-225   simpson   edison      20: 405-759
   08: 518-842   valley    romania     21: 484-008
   09: 528-314   atlantic  romania     22: 573-246
   10: 611-375   geisha    clarinet    23: 615-865
   11: 696-851   paper     baghdad     24: 675-041
   12: 741-502   france    leather     25: 765-191
   13: 818-617   lasagna   rhubarb     26: 837-046

                     Share 3/3
   01: 000-305   academy   colombia    14: 026-666
   02: 081-920   dubai     abraham     15: 113-745
   03: 131-936   admiral   hawaii      16: 192-833
   04: 218-632   germany   america     17: 219-702
   05: 303-911   pelican   builder     18: 277-096
   06: 360-066   leather   lobster     19: 389-401

   07: 406-518   corsica   walnut      20: 410-147
   08: 493-053   madonna   yoghurt     21: 483-957
   09: 565-245   oxford    yoghurt     22: 543-569
   10: 615-599   hippo     prophet     23: 638-040
   11: 715-149   uruguay   mushroom    24: 671-464
   12: 746-075   heineken  gotham      25: 774-257
   13: 840-887   teacup    renault     26: 801-465

                       Salt
   01: 000-305   academy   colombia    09: 525-073
   02: 081-920   dubai     abraham     10: 650-518
   03: 144-436   cowboy    cowboy      11: 716-972
   04: 209-972   cowboy    cowboy      12: 753-341

   05: 275-508   cowboy    cowboy      13: 840-190
   06: 341-044   cowboy    cowboy      14: 005-891
   07: 406-580   cowboy    cowboy      15: 090-070
   08: 472-116   cowboy    cowboy      16: 187-496

                     Brainkey
   01: 013-364   cowboy    cowboy      05: 275-508
   02: 078-900   cowboy    cowboy      06: 341-044
   03: 144-436   cowboy    cowboy      07: 406-580
   04: 209-972   cowboy    cowboy      08: 472-116
"""


def _parse_output(output: str) -> typ.Dict[str, ParsedSecret]:
    secret_lines = collections.defaultdict(list)
    headline     = None
    for line in output.splitlines():
        if not line.strip():
            continue
        match = FORMATTED_LINE_RE.match(line.strip())
        if match is None:
            headline = line.strip()
        else:
            assert headline
            secret_lines[headline].append(line)

    return {
        headline.lower(): parse_formatted_secret("\n".join(lines))
        for headline, lines in secret_lines.items()
    }


def test_cli_create_validation():
    argv = [
        "--scheme=2of3",
        "--memory-cost=1",
        "--time-cost=1",
    ]
    debug_secrets = _parse_output(DEBUG_NONRANDOM_OUTPUT)
    inputs        = [
        "\n\n\n\n\n\n\n",  # confirmations
        "\n".join(debug_secrets['salt'].data_codes) + "\n",
        "accept\n",
        "\n".join(debug_secrets['brainkey'].data_codes) + "\n",
        "accept\n",
        "\n".join(debug_secrets["share 1/3"].data_codes) + "\n",
        "accept\n",
        "\n".join(debug_secrets["share 2/3"].data_codes) + "\n",
        "accept\n",
        "\n".join(debug_secrets["share 3/3"].data_codes) + "\n",
        "accept\n",
    ]
    env    = {'SBK_PROGRESS_BAR': '0', 'SBK_DEBUG_RANDOM': 'DANGER'}
    result = _run(sbk.cli.create, argv, input="".join(inputs), env=env)

    assert not result.exception
    assert result.exit_code == 0


def _run(*args, **kwargs):
    runner = click.testing.CliRunner()
    result = runner.invoke(*args, **kwargs)

    if result.exit_code != 0:
        print()
        lookback = collections.deque(maxlen=4)
        for line in result.output.splitlines():
            if line in lookback:
                continue
            else:
                print(line)
            lookback.append(line)

    assert not result.exception
    assert result.exit_code == 0

    return result


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
    result = _run(sbk.cli.create, argv, env=env)

    out_secrets = _parse_output(result.output)
    salt        = out_secrets['salt']
    brainkey    = out_secrets['brainkey']
    share1      = out_secrets["share 1/3"]
    share2      = out_secrets["share 2/3"]
    share3      = out_secrets["share 3/3"]
    assert len({share1, share2, share3, salt, brainkey}) == 5
    shares = [share1, share2, share3]
    random.shuffle(shares)

    for combo in itertools.combinations(shares, 2):
        recover_inputs = []
        for share in combo:
            recover_inputs.extend(
                [" ".join(share.words[:4]) + "\n", " ".join(share.words[4:]) + "\n", "accept\n",]
            )

        result = _run(sbk.cli.recover, input="".join(recover_inputs))

        secrets = result.output.split("RECOVERED SECRETS")[-1]
        assert "Salt" in secrets
        assert "Brainkey" in secrets

        salt_output, brainkey_output = secrets.lower().split("brainkey")
        recoverd_salt      = parse_formatted_secret(salt_output, strict=False)
        recovered_brainkey = parse_formatted_secret(brainkey_output, strict=False)

        assert salt     == recoverd_salt
        assert brainkey == recovered_brainkey


def test_cli_recover_salt_from_words():
    secrets     = _parse_output(DEBUG_NONRANDOM_OUTPUT)
    salt_inputs = (
        " ".join(secrets['salt'].words[:4]),
        " ".join(secrets['salt'].words[4:8]),
        " ".join(secrets['salt'].words[8:]),
        "accept",
        "",
    )
    result = _run(sbk.cli.recover_salt, input="\n".join(salt_inputs))

    # check cursor positions
    assert result.output.count("=> 01: ___-___") == 1
    assert result.output.count("=> 03: ___-___") == 1
    assert result.output.count("=> 05: ___-___") == 1
    assert result.output.count("09: 525-073 <=") == 1

    codes = secrets['salt'].data_codes + secrets['salt'].ecc_codes
    for i, code in enumerate(codes):
        assert f"{i + 1:02}: {code} " in result.output


def test_cli_recover_salt_from_data():
    secrets     = _parse_output(DEBUG_NONRANDOM_OUTPUT)
    salt_inputs = [
        " ".join(secrets['salt'].data_codes[:4]),
        " ".join(secrets['salt'].data_codes[4:]),
        "accept",
        "",
    ]

    result = _run(sbk.cli.recover_salt, input="\n".join(salt_inputs))

    # check cursor positions
    assert result.output.count("=> 01: ___-___") == 1
    assert result.output.count("=> 05: ___-___") == 1
    assert result.output.count("09: 525-073 <=") == 1

    codes = secrets['salt'].data_codes + secrets['salt'].ecc_codes
    for i, code in enumerate(codes):
        assert f"{i + 1:02}: {code} " in result.output


def test_cli_recover_salt_from_ecc():
    secrets = _parse_output(DEBUG_NONRANDOM_OUTPUT)
    inputs  = [
        "next\nnext\nnext\nnext",
        "next\nnext\nnext\nnext",
        " ".join(secrets['salt'].ecc_codes[:4]),
        " ".join(secrets['salt'].ecc_codes[4:]),
        "accept",
        "",
    ]

    result = _run(sbk.cli.recover_salt, input="\n".join(inputs))

    codes = secrets['salt'].data_codes + secrets['salt'].ecc_codes
    for i, code in enumerate(codes):
        assert f"{i + 1:02}: {code} " in result.output


def test_cli_load_wallet():
    secrets = _parse_output(DEBUG_NONRANDOM_OUTPUT)
    inputs  = (
        " ".join(secrets['salt'].words),
        "accept",
        " ".join(secrets['brainkey'].words[:4]),
        " ".join(secrets['brainkey'].words[4:]),
        "accept",
        "",
        "",
    )

    all_seeds    = []
    wallet_names = ["disabled", "Hello, 世界!"] * 2
    for name in wallet_names:
        args = ("--show-seed", "--yes-all", "--wallet-name", name)

        result = _run(sbk.cli.load_wallet, args=args, input="\n".join(inputs))

        commands, wallet_seed = result.output.lower().split("electrum wallet seed")
        all_seeds.append(wallet_seed.strip())

    # same name -> same seed
    assert len(set(wallet_names)) == len(set(all_seeds))


def test_cli_kdf_test():
    args   = ("--memory-cost", "1", "--time-cost", "1")
    result = _run(sbk.cli.kdf_test, args=args)
    assert re.search(r"Duration\s*:\s+\d+ sec", result.output)
