import io
import os
import re
import sys
import math
import time
import random
import string
import typing as typ
import itertools
import collections

import click
import pytest
import pexpect
import click.testing

import sbk.cli
import sbk.cli_io
import sbk.ecc_rs
from sbk import electrum_mnemonic
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
    lines = [
        l
        for l in sbk.cli_io.format_secret_lines('salt', data)
        if l.strip() and not l.strip().lower().startswith("data")
    ]
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

        Data          Mnemonic               ECC
   01: 000-289   academy   boeing      13: 839-540
   02: 065-536   abraham   abraham     14: 006-657
   03: 131-522   academy   seattle     15: 107-612
   04: 247-256   sheriff   theatre     16: 187-871

   05: 316-374   taiwan    tequila     17: 248-045
   06: 387-564   uruguay   veteran     18: 289-066
   07: 452-602   umbrella  whisky      19: 388-700
   08: 523-760   yoghurt   virginia    20: 437-022

   09: 560-014   muffin    nagasaki    21: 508-272
   10: 622-980   library   macbook     22: 558-874
   11: 696-210   oxford    netflix     23: 647-162
   12: 759-084   nintendo  champion    24: 692-246

                     Share 2/3

        Data          Mnemonic               ECC
   01: 000-289   academy   boeing      13: 787-724
   02: 065-536   abraham   abraham     14: 041-874
   03: 131-779   acrobat   server      15: 067-805
   04: 249-335   squid     warrior     16: 146-514

   05: 319-979   tsunami   vampire     17: 201-071
   06: 365-983   nintendo  oxford      18: 301-536
   07: 428-467   mosquito  queen       19: 372-128
   08: 507-303   salmon    pilot       20: 426-302

   09: 545-115   freddie   gotham      21: 496-647
   10: 607-567   embassy   forest      22: 574-163
   11: 686-435   kingdom   hendrix     23: 649-798
   12: 748-815   italy     atlantic    24: 662-138

                     Share 3/3

        Data          Mnemonic               ECC
   01: 000-289   academy   boeing      13: 803-620
   02: 065-536   abraham   abraham     14: 015-843
   03: 131-893   admiral   crown       15: 093-346
   04: 211-995   diesel    berlin      16: 156-457

   05: 263-689   albino    android     17: 241-425
   06: 346-183   escort    engine      18: 313-766
   07: 416-381   gorilla   lasagna     19: 353-780
   08: 488-547   kangaroo  hendrix     20: 421-591

   09: 585-441   vietnam   tsunami     21: 501-546
   10: 651-519   virginia  zimbabwe    22: 526-484
   11: 709-317   suzuki    sheriff     23: 653-787
   12: 773-351   sparrow   umbrella    24: 693-598


                       Salt

        Data          Mnemonic               ECC
   01: 000-289   academy   boeing      09: 585-354
   02: 065-536   abraham   abraham     10: 604-186
   03: 144-436   cowboy    cowboy      11: 697-429
   04: 209-972   cowboy    cowboy      12: 739-428

   05: 275-508   cowboy    cowboy      13: 845-213
   06: 341-044   cowboy    cowboy      14: 026-334
   07: 406-580   cowboy    cowboy      15: 103-947
   08: 472-116   cowboy    cowboy      16: 178-527

                     Brainkey

        Data          Mnemonic               ECC
   01: 013-364   cowboy    cowboy      04: 209-972
   02: 078-900   cowboy    cowboy      05: 275-508
   03: 144-436   cowboy    cowboy      06: 341-044
"""


def _parse_output(output: str) -> typ.Dict[str, ParsedSecret]:
    secret_lines = collections.defaultdict(list)
    headline     = None
    for line in output.splitlines():
        line = line.strip().lower()
        if not line or line.startswith("data") or "_" in line:
            continue

        match = FORMATTED_LINE_RE.search(line.strip())
        if match is None:
            headline = line.strip()
        else:
            assert headline
            secret_lines[headline].append(line)

    return {
        headline.lower(): parse_formatted_secret("\n".join(lines))
        for headline, lines in secret_lines.items()
    }


class Interaction(typ.NamedTuple):

    expect : typ.Optional[str]
    send   : typ.Optional[str]
    timeout: typ.Optional[float]


def interaction(expect=None, send=None, timeout=5) -> Interaction:
    return Interaction(expect, send, timeout)


class Result(typ.NamedTuple):

    output   : str
    exit_code: int


def _run(cli_fn, argv=(), env=None, playbook=[]) -> Result:
    subcommand = cli_fn.name.replace("_", "-")

    sub_env = os.environ.copy()
    sub_env['SBK_PROGRESS_BAR'] = "0"
    if env:
        sub_env.update(env)

    buf = io.BytesIO()

    cmd  = [sys.executable, "-m", "sbk.cli", subcommand] + list(argv)
    proc = pexpect.spawn(" ".join(cmd), env=sub_env, logfile=buf)

    remaining_playbook = collections.deque(playbook)
    try:
        while remaining_playbook:
            expect, send, timeout = remaining_playbook.popleft()
            if expect is not None:
                proc.expect(expect, timeout=timeout)
            if send is not None:
                proc.sendline(send)

        proc.read()
        proc.expect(pexpect.EOF, timeout=2)
    except pexpect.exceptions.TIMEOUT:
        buf.seek(0)
        output = buf.read().decode("utf-8")
        output, _ = re.subn("\x1b\\[\\d+m", "", output)
        print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
        print(output)
        print("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<")
        raise

    assert proc.exitstatus == 0, proc.exitstatus

    buf.seek(0)
    output = buf.read().decode("utf-8")
    output, _ = re.subn("\x1b\\[\\d+m", "", output)
    return Result(output, proc.exitstatus)


def test_cli_create_basic():
    argv = [
        "--scheme=2of3",
        "--brainkey-len=6",
        "--yes-all",
        "--parallelism=1",
        "--memory-cost=1",
        "--time-cost=1",
    ]
    env = {
        'SBK_PROGRESS_BAR': '0',
        # 'SBK_DEBUG_RANDOM': 'DANGER',
    }
    result = _run(sbk.cli.create, argv, env=env, playbook=[])

    # print("---------------------")
    # print(result.output)
    # print("---------------------")

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
        playbook = []
        for share in combo:
            share_interactions = [
                interaction(expect=r".*Enter code/words at 01: ", send=" ".join(share.words[:4])),
                interaction(expect=r".*Enter code/words at 03: ", send=" ".join(share.words[4:])),
                interaction(expect=r".*\(or Enter to Accept\): ", send="accept"),
            ]
            playbook.extend(share_interactions)

        result  = _run(sbk.cli.recover, playbook=playbook)
        secrets = result.output.split("RECOVERED SECRETS")[-1]

        assert "Salt" in secrets
        assert "Brainkey" in secrets

        salt_output, brainkey_output = secrets.lower().split("brainkey")
        recoverd_salt      = parse_formatted_secret(salt_output, strict=False)
        recovered_brainkey = parse_formatted_secret(brainkey_output, strict=False)

        assert salt     == recoverd_salt
        assert brainkey == recovered_brainkey


def test_cli_create_validation():
    debug_secrets  = _parse_output(DEBUG_NONRANDOM_OUTPUT)
    salt_codes     = " ".join(debug_secrets['salt'].data_codes)
    brainkey_codes = " ".join(debug_secrets['brainkey'].data_codes)
    share_1_codes  = " ".join(debug_secrets["share 1/3"].data_codes)
    share_2_codes  = " ".join(debug_secrets["share 2/3"].data_codes)
    share_3_codes  = " ".join(debug_secrets["share 3/3"].data_codes)
    playbook       = [
        interaction(expect=r".*Press enter to continue ", send=""),
        interaction(expect=r".*Share 1/3, press enter to continue\. ", send=""),
        interaction(expect=r".*Share 2/3, press enter to continue\. ", send=""),
        interaction(expect=r".*Share 3/3, press enter to continue\. ", send=""),
        interaction(expect=r".*Salt, press enter to continue ", send=""),
        interaction(expect=r".*Press enter to show your brainkey ", send=""),
        interaction(expect=r".*press enter to continue ", send=""),
        interaction(expect=r".*Enter code/words at 01: ", send=salt_codes),
        interaction(expect=r".*\(or Enter to Accept\): ", send="accept"),
        interaction(expect=r".*Enter code/words at 01: ", send=brainkey_codes,),
        interaction(expect=r".*\(or Enter to Accept\): ", send="accept"),
        interaction(expect=r".*Enter code/words at 01: ", send=share_1_codes,),
        interaction(expect=r".*\(or Enter to Accept\): ", send="accept"),
        interaction(expect=r".*Enter code/words at 01: ", send=share_2_codes,),
        interaction(expect=r".*\(or Enter to Accept\): ", send="accept"),
        interaction(expect=r".*Enter code/words at 01: ", send=share_3_codes,),
        interaction(expect=r".*\(or Enter to Accept\): ", send="accept"),
    ]

    argv   = ["--scheme=2of3", "--parallelism=1", "--memory-cost=1", "--time-cost=1"]
    env    = {'SBK_PROGRESS_BAR': '0', 'SBK_DEBUG_RANDOM': 'DANGER'}
    result = _run(sbk.cli.create, argv, env=env, playbook=playbook)

    validation_output  = result.output.split("Validation", 1)[-1]
    validation_secrets = _parse_output(validation_output)

    assert validation_secrets["validation for salt"] == debug_secrets['salt']
    assert validation_secrets["validation for brainkey"] == debug_secrets['brainkey']
    assert validation_secrets["validation for share 1/3"] == debug_secrets["share 1/3"]
    assert validation_secrets["validation for share 2/3"] == debug_secrets["share 2/3"]
    assert validation_secrets["validation for share 3/3"] == debug_secrets["share 3/3"]


def test_cli_recover_salt_from_words():
    secrets = _parse_output(DEBUG_NONRANDOM_OUTPUT)

    words1 = " ".join(secrets['salt'].words[:4])
    words3 = " ".join(secrets['salt'].words[4:8])
    words5 = " ".join(secrets['salt'].words[8:])

    playbook = [
        interaction(expect=r".*Enter code/words at 01: ", send=words1),
        interaction(expect=r".*Enter code/words at 03: ", send=words3),
        interaction(expect=r".*Enter code/words at 05: ", send=words5),
        interaction(expect=r".*\(or Enter to Accept\): ", send="accept"),
    ]
    result = _run(sbk.cli.recover_salt, playbook=playbook)

    # check cursor positions
    assert result.output.count("=> 01: ___-___") == 1
    assert result.output.count("=> 03: ___-___") == 1
    assert result.output.count("=> 05: ___-___") == 1
    assert result.output.count("09: 585-354 <=") == 1

    codes = secrets['salt'].data_codes + secrets['salt'].ecc_codes
    for i, code in enumerate(codes):
        assert f"{i + 1:02}: {code} " in result.output


def test_cli_recover_salt_from_data():
    secrets      = _parse_output(DEBUG_NONRANDOM_OUTPUT)
    salt_codes_1 = " ".join(secrets['salt'].data_codes[:4])
    salt_codes_2 = " ".join(secrets['salt'].data_codes[4:])
    playbook     = [
        interaction(expect=r".*Enter code/words at 01: ", send=salt_codes_1),
        interaction(expect=r".*Enter code/words at 05: ", send=salt_codes_2),
        interaction(expect=r".*\(or Enter to Accept\): ", send="accept"),
    ]
    result = _run(sbk.cli.recover_salt, playbook=playbook)

    # check cursor positions
    assert result.output.count("=> 01: ___-___") == 1
    assert result.output.count("=> 05: ___-___") == 1
    assert result.output.count("09: 585-354 <=") == 1

    codes = secrets['salt'].data_codes + secrets['salt'].ecc_codes
    for i, code in enumerate(codes):
        assert f"{i + 1:02}: {code} " in result.output


def test_cli_recover_salt_from_ecc():
    secrets  = _parse_output(DEBUG_NONRANDOM_OUTPUT)
    playbook = [
        interaction(expect=r".*Enter code/words at 01: ", send="next"),
        interaction(expect=r".*Enter code/words at 02: ", send="next"),
        interaction(expect=r".*Enter code/words at 03: ", send="next"),
        interaction(expect=r".*Enter code/words at 04: ", send="next"),
        interaction(expect=r".*Enter code/words at 05: ", send="next"),
        interaction(expect=r".*Enter code/words at 06: ", send="next"),
        interaction(expect=r".*Enter code/words at 07: ", send="next"),
        interaction(expect=r".*Enter code/words at 08: ", send="next"),
        interaction(expect=r".*Enter code at 09: ", send=" ".join(secrets['salt'].ecc_codes[:4])),
        interaction(expect=r".*Enter code at 13: ", send=" ".join(secrets['salt'].ecc_codes[4:])),
        interaction(expect=r".*\(or Enter to Accept\): ", send="accept"),
    ]
    result = _run(sbk.cli.recover_salt, playbook=playbook)

    codes = secrets['salt'].data_codes + secrets['salt'].ecc_codes
    for i, code in enumerate(codes):
        assert f"{i + 1:02}: {code} " in result.output


def test_cli_load_wallet():
    secrets        = _parse_output(DEBUG_NONRANDOM_OUTPUT)
    salt_words     = " ".join(secrets['salt'].words)
    brainkey_words = " ".join(secrets['brainkey'].words)
    playbook       = [
        interaction(expect=r".*Enter code/words at 01: ", send=salt_words),
        interaction(expect=r".*\(or Enter to Accept\): ", send="accept"),
        interaction(expect=r".*Enter code/words at 01: ", send=brainkey_words),
        interaction(expect=r".*\(or Enter to Accept\): ", send="accept"),
    ]

    all_seeds    = []
    wallet_names = ["disabled", "hello-world"] * 2
    for name in wallet_names:
        argv   = ("--show-seed", "--yes-all", "--wallet-name", f'"{name}"')
        result = _run(sbk.cli.load_wallet, argv=argv, playbook=playbook)

        commands, wallet_seed = result.output.lower().split("electrum wallet seed:")
        seed_words = wallet_seed.strip().split()
        assert len(seed_words) == 12, seed_words
        assert all(w in electrum_mnemonic.wordlist_indexes for w in seed_words)
        all_seeds.append(wallet_seed.strip())

    # same name -> same seed
    assert len(set(wallet_names)) == len(set(all_seeds))


def test_cli_kdf_test_implicit():
    argv   = ("--memory-cost", "1", "--target-duration", "1")
    result = _run(sbk.cli.kdf_test, argv=argv)
    assert re.search(r"Duration\s*:\s+\d+ sec", result.output)


def test_cli_kdf_test_explicit():
    argv   = ("--memory-cost", "1", "--time-cost", "1")
    result = _run(sbk.cli.kdf_test, argv=argv)
    assert re.search(r"Duration\s*:\s+\d+ sec", result.output)
