# pylint: disable=wildcard-import
# pylint: disable=unused-wildcard-import

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
import sbk.parameters
from sbk import electrum_mnemonic
from sbk.mnemonic import *
from sbk.ui_common import *


@pytest.mark.skipif("slow" in os.getenv('PYTEST_SKIP', ""), reason="ECC recovery can be intense")
def test_intcode_fuzz():
    bytes2intcodes(os.urandom(8))

    for i in range(0, 50, 4):
        data_len = i % 20 + 4
        data     = os.urandom(data_len)
        intcodes = bytes2intcodes(data)
        decoded  = intcodes2bytes(intcodes, data_len)
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
        decoded  = intcodes2bytes(intcodes, data_len)
        assert decoded == data

        parts     = intcodes[:]
        clear_idx = random.randrange(0, len(parts))
        parts[clear_idx] = None
        decoded = maybe_intcodes2bytes(parts, data_len)
        assert decoded == data


def test_intcode_odd_data_len():
    in_data = b"\x11\x00\x004444444444444"
    assert len(in_data) == sbk.parameters.DEFAULT_RAW_SALT_LEN
    expected_inputs = [
        "004-352",
        "065-588",
        "144-436",
        "209-972",
        "275-508",
        "341-044",
        "406-580",
        "472-116",
        "541-542",
        "620-229",
        "677-537",
        "772-367",
        "806-086",
        "003-160",
        "117-840",
        "144-371",
    ]

    inputs = bytes2intcodes(in_data)
    assert inputs == expected_inputs
    result = maybe_intcodes2bytes(inputs, msg_len=sbk.parameters.DEFAULT_RAW_SALT_LEN)
    assert result == in_data


@pytest.mark.skipif("slow" in os.getenv('PYTEST_SKIP', ""), reason="ECC recovery can be intense")
@pytest.mark.parametrize("data_len", DATA_LENS)
def test_intcode_order_fail(data_len):
    data     = os.urandom(data_len)
    intcodes = bytes2intcodes(data)
    decoded  = intcodes2bytes(intcodes, data_len)
    assert decoded == data

    for _ in range(len(data)):
        i = random.randint(0, data_len - 1)
        j = random.randint(0, data_len - 1)

        intcodes_kaputt = intcodes[:]
        intcodes_kaputt[i], intcodes_kaputt[j] = intcodes_kaputt[j], intcodes_kaputt[i]

        if i % 13 == j % 13:
            # In this case the ecc data should either save us or fail
            try:
                decoded = intcodes2bytes(intcodes_kaputt, data_len)
                assert decoded == data
            except sbk.ecc_rs.ECCDecodeError:
                pass
        else:
            try:
                intcodes2bytes(intcodes_kaputt, data_len)
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

    assert phrase2bytes(" ".join(parsed.words), msg_len=data_len) == data
    intcodes = parsed.data_codes + parsed.ecc_codes
    assert len(intcodes) * 2 == block_len
    decoded = maybe_intcodes2bytes(intcodes, data_len)
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

    assert parsed.words[0].lower() == "abacus"
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

    class Bar:
        def __init__(self, length):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def update(self, step_ms):
            pass

    tzero  = time.time()
    result = run_with_progress_bar(dummy_func, eta_sec=0.1, init_progressbar=Bar)
    assert result == arg * 2
    elapsed = time.time() - tzero
    assert 0.1 < elapsed < 0.3


DEBUG_NONRANDOM_OUTPUT = """
                     Share 1/3

        Data          Mnemonic               ECC
   01: 004-352   bicycle   abacus      02: 802-163
   03: 065-537   abacus    abraham     04: 051-183
   05: 180-933   salmon    satoshi     06: 079-837
   07: 252-115   teacup    squid       08: 166-340
   09: 317-161   surgeon   unesco      10: 261-881
   11: 388-327   victoria  ukraine     12: 306-464

   13: 457-469   wizard    yokohama    14: 337-714
   15: 520-331   vladimir  mozart      16: 419-340
   17: 560-769   mumbai    meatball    18: 509-915
   19: 623-775   mercury   oxford      20: 587-094
   21: 692-885   nairobi   necklace    22: 645-494
   23: 763-950   peugeot   darwin      24: 713-813

                     Share 2/3

     Data          Mnemonic               ECC
   01: 004-352   bicycle   abacus      02: 800-059
   03: 065-538   abacus    academy     04: 024-298
   05: 181-197   samurai   slippers    06: 084-694
   07: 260-065   watanabe  trumpet     08: 178-809
   09: 322-453   vampire   necklace    10: 205-545
   11: 368-521   oxford    moldova     12: 314-825

   13: 439-229   printer   rhubarb     14: 372-120
   15: 501-585   pepper    gymnast     16: 415-345
   17: 547-653   hunter    football    18: 484-605
   19: 610-169   gorilla   lebanon     20: 550-348
   21: 680-813   jigsaw    kidney      22: 621-201
   23: 726-863   bridge    gorilla     24: 712-000

                     Share 3/3

        Data          Mnemonic               ECC
   01: 004-352   bicycle   abacus      02: 836-611
   03: 065-539   abacus    acrobat     04: 010-729
   05: 144-700   donut     egypt       06: 090-406
   07: 203-526   buffalo   alcohol     08: 174-866
   09: 264-520   attorney  fujitsu     10: 237-328
   11: 345-946   freddie   hitachi     12: 322-919

   13: 425-332   lobster   kurosawa    14: 336-638
   15: 484-334   jigsaw    virginia    16: 411-226
   17: 582-128   trumpet   vladimir    18: 460-054
   19: 655-314   zimbabwe  spider      20: 529-850
   21: 705-996   satoshi   sisyphus    22: 596-940
   23: 756-633   mozart    normandy    24: 707-258

                       Salt

        Data          Mnemonic               ECC
   01: 004-352   bicycle   abacus      02: 541-542
   03: 065-588   abacus    dolphin     04: 620-229
   05: 144-436   dolphin   dolphin     06: 677-537
   07: 209-972   dolphin   dolphin     08: 772-367

   09: 275-508   dolphin   dolphin     10: 806-086
   11: 341-044   dolphin   dolphin     12: 003-160
   13: 406-580   dolphin   dolphin     14: 117-840
   15: 472-116   dolphin   dolphin     16: 144-371

                     Brainkey

        Data          Mnemonic               ECC
   01: 013-364   dolphin    dolphin      02: 209-972
   03: 078-900   dolphin    dolphin      04: 275-508
   05: 144-436   dolphin    dolphin      06: 341-044
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
        headline.lower(): parse_formatted_secret("\n".join(lines)) for headline, lines in secret_lines.items()
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


def _run(cli_fn, argv=(), env=None, playbook=()) -> Result:
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
                interaction(expect=r".*Enter code/words at 02: ", send=" ".join(share.words[4:])),
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
        interaction(expect=r".*Enter code/words at 01: ", send=brainkey_codes),
        interaction(expect=r".*\(or Enter to Accept\): ", send="accept"),
        interaction(expect=r".*Enter code/words at 01: ", send=share_1_codes),
        interaction(expect=r".*\(or Enter to Accept\): ", send="accept"),
        interaction(expect=r".*Enter code/words at 01: ", send=share_2_codes),
        interaction(expect=r".*\(or Enter to Accept\): ", send="accept"),
        interaction(expect=r".*Enter code/words at 01: ", send=share_3_codes),
        interaction(expect=r".*\(or Enter to Accept\): ", send="accept"),
    ]

    argv   = ["--scheme=2of3", "--parallelism=1", "--memory-cost=1", "--time-cost=1"]
    env    = {'SBK_PROGRESS_BAR': '0', 'SBK_DEBUG_RANDOM': 'DANGER'}
    result = _run(sbk.cli.create, argv, env=env, playbook=playbook)
    print(result.output)

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
    assert result.output.count("02: 541-542 <=") == 1

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
    assert result.output.count("02: 541-542 <=") == 1

    codes = secrets['salt'].data_codes + secrets['salt'].ecc_codes
    for i, code in enumerate(codes):
        assert f"{i + 1:02}: {code} " in result.output


def test_cli_recover_salt_from_ecc():
    secrets  = _parse_output(DEBUG_NONRANDOM_OUTPUT)
    playbook = [
        interaction(expect=r".*Enter code/words at 01: ", send="next"),
        interaction(expect=r".*Enter code/words at 03: ", send="next"),
        interaction(expect=r".*Enter code/words at 05: ", send="next"),
        interaction(expect=r".*Enter code/words at 07: ", send="next"),
        interaction(expect=r".*Enter code/words at 09: ", send="next"),
        interaction(expect=r".*Enter code/words at 11: ", send="next"),
        interaction(expect=r".*Enter code/words at 13: ", send="next"),
        interaction(expect=r".*Enter code/words at 15: ", send="next"),
        interaction(expect=r".*Enter code at 02: ", send=" ".join(secrets['salt'].ecc_codes[:4])),
        interaction(expect=r".*Enter code at 12: ", send=" ".join(secrets['salt'].ecc_codes[4:])),
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

        _commands, wallet_seed = result.output.lower().split("electrum wallet seed:")
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
