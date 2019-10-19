#!/usr/bin/env python
# This file is part of the SBK project
# https://gitlab.com/mbarkhau/sbk
#
# Copyright (c) 2019 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT

"""CLI/Imperative shell for SBK."""

import os
import random
import typing as typ
import hashlib
import subprocess as sp

import click
import pathlib2 as pl
import click_repl

import sbk

from . import kdf
from . import cli_io
from . import params
from . import primes
from . import polynom
from . import cli_util
from . import enc_util
from . import mnemonic
from . import electrum_mnemonic

# To enable pretty tracebacks:
#   echo "export ENABLE_BACKTRACE=1;" >> ~/.bashrc
if os.environ.get('ENABLE_BACKTRACE') == '1':
    try:
        import backtrace

        backtrace.hook(align=True, strip_path=True, enable_on_envvar_only=True)
    except ImportError:
        pass


def debug_urandom(size: int) -> bytes:
    # https://xkcd.com/221/
    return b"4" * size


if os.environ.get('SBK_DEBUG_RANDOM') == 'DANGER':
    polynom._rand = random.Random(0)  # type: ignore
    urandom       = debug_urandom
else:
    urandom = os.urandom


click.disable_unicode_literals_warning = True

APP_DIR          = pl.Path(click.get_app_dir("sbk"))
PARAM_CTX        = params.get_param_ctx(APP_DIR)
PARAM_ID_DEFAULT = PARAM_CTX.param_id_default


def _clean_help(helmsg: str) -> str:
    return " ".join(line.strip() for line in helmsg.splitlines() if line.strip())


# NOTE mb: Wrappers for click funtions for the idom: `yes_all or clear`
#   Maybe this should be rethought so the idom is not needed.


def echo(msg: str = "") -> bool:
    click.echo(msg)
    return True


def clear() -> bool:
    click.clear()
    return True


def confirm(msg: str) -> bool:
    res = click.prompt(msg.strip() + " [y/N]")
    if "y" not in res.lower():
        raise click.Abort()

    return True


def anykey_confirm(message: str) -> bool:
    click.prompt(
        message.strip(), default="", show_choices=False, show_default=False, prompt_suffix=""
    )
    return False


def _derive_key(brainkey_data: bytes, salt_data: bytes, label: str) -> bytes:
    param_cfg = enc_util.bytes2params(salt_data)
    eta_sec   = PARAM_CTX.est_times_by_id[param_cfg.kdf_param_id]
    hash_len  = param_cfg.key_len_bytes - 1

    kdf_args   = (brainkey_data, salt_data, kdf_params, hash_len)
    KDFThread  = cli_util.EvalWithProgressbar[bytes]
    kdf_thread = KDFThread(target=kdf.derive_key, args=kdf_args)
    kdf_thread.start_and_wait(eta_sec, label)
    hash_data = kdf_thread.retval

    # NOTE: We encode the x value of a point in the first byte, and
    #   since the key we derive (the y value) has to be smaller
    #   than the prime with key_len * 8 - 8 bits, we set the first
    #   byte here (the x value) to zero.
    key_data = b"\x00" + hash_data
    assert len(key_data) == param_cfg.key_len_bytes
    return key_data


MIN_TIME_SEC  = 10
MIN_MEM_RATIO = 0.1


SHOW_ALL_HELP = """
Show all available KDF parameter choices.

By default only shows reasonable
choices for the current system.
"""


SECURITY_WARNING_TEXT = """
The security of your system is important. Please make sure that:

 - You are the only person who can view your screen.

 - You are running a fresh and secure installation of Linux.

   Ideally you should boot from an USB Stick with a trusted
   installation of Linux. If you generate keys using your regular
   operating system, your keys may be leaked by a virus.

 - You are using trusted software.

   The software you are using may be from a scammer. They may have
   tricked you into downloading a hacked version of Linux, SBK or
   Electrum. You should only use software from trusted sources. If
   possible, you should verify signatures of your downloads.

 - You are disconnected from the network.

   If your computer has a network cable, unplug it. If your computer
   has WiFi, activate flight mode. If your computer was connected to a
   network during startup, disconnect now and reboot. Some kinds of
   attack depend on a network connection. If you are using insecure
   software (despite precautions), disconnecting from any networks
   (aka. air-gap) can sometimes prevent your keys from being leaked.

For more information on setting up a secure system see:

    https://www.schneier.com/blog/archives/2013/10/air_gaps.html
    https://tiny.cc/r9wbcz

    http://viccuad.me/blog/Revisited-secure-yourself-part-1-airgapped-computer-and-gpg-smartcards
    https://tiny.cc/eo0bcz

"""


SECURITY_WARNING_PROMPT = """
Do you believe your system is secure?
"""


SALT_INFO_TITLE = r'Step 1 of 5: Copy your "Salt".'

SBK_KEYGEN_TITLE = r"Step 2 of 5: Deriving Secret Key"

SBK_SHARE_TITLE = r"Step 3 of 5: Copy SBK-Share {share_no}/{num_shares}."

BRAINKEY_INFO_TITLE = r"Step 4 of 5: Copy Brainkey."

RECOVERY_VALIDATION_TITLE = r"Step 5 of 5: Validation"


SALT_INFO_TEXT = """
The purpose of the salt is to prevent a brute-force attack. By itself
a salt is useless, which means that it is not a big problem if the
salt is not kept secret and an attacker gets a hold of it. That being
said, there is no good reason to make it public either.

The main risk for the salt is that it is lost. Without the salt, your
secret key cannot be recovered. It is best to make a copy of the salt
for each trustee. This allows your trustees to recover your secret key
if they cannot access to your files.

Write in clear and readable letters, use non-erasable ink (ideally
archival ink). Take a picture and store the picture in your Dropbox,
Google Drive, One Drive or other backup location.

"""

SALT_INFO_PROMPT = "Press enter when you have copied the salt"

SBK_KEYGEN_TEXT = r"""
The SBK Secret Key is derived using the computationally and memory
intensive Argon2 KDF (Key Derivation Function). This ensures that your
brainkey is secure even if an attacker has access to the salt (for
example if they are a trustee).

    (Brainkey + Salt) -> Secret Key
"""

SBK_KEYGEN_PROMPT = "Key generation complete, press enter to continue"


SBK_SHARE_TEXT = r"""
Hide this "Share" in a safe place or give it to one of your
trustees. Your trustees should not only be trustworthy in the
sense that they will act in your best interests, they should also
be trustworthy in the sense that they are competent to keep this
SBK Piece safe and secret.
"""

RECOVERY_TEXT = r"""
Your "master seed" is recovered by collecting a minimum of
{threshold} shares.

                 Split Master Seed
          Split                    . Join
               \.-> Share 1 -./
   Master Seed -O-> Share 2  +-> Master Seed
                '-> Share 3 -'

   Master Seed + Salt -> Wallet
"""

SBK_SHARE_PROMPT = r"""
Please make a physical copy of Share {share_no}/{num_shares}.
"""

BRAINKEY_INFO_TEXT = r"""
Your "brainkey" and "salt" are combined to produce your "master seed".
Your master seed in turn is combined with your salt to recover your
"wallet".

    Brainkey + Salt -> Master Seed
    Master Seed + Salt -> Wallet

Put more simply, as long as you can remember your brainkey, and as
long as you have access to your salt, you will be able to recover your
wallet.

If you forget your brainkey, it will be lost forever. So, you should

 - memorize your brainkey very well,
 - regularly remember it so you don't forget it,
 - never tell it to anybody ever!
"""

# Secret Key + Salt -> Wallet

BRAINKEY_LAST_CHANCE_WARNING_TEXT = """
This is the last time your brainkey will be shown.

If you do not yet feel confident in your memory:

 1. Write down the brainkey only as a temporary memory aid.
 2. Do not use the generated wallet until you feel comfortable that
    you have have memorized your brainkey.
 3. Destroy the memory aid before you use the wallet.

Press enter to hide your brainkey and to continue
"""

KDF_PARAM_ID_HELP = "KDF difficulty selection. Use 'sbk kdf-info' to see valid options"

_kdf_param_id_option = click.option(
    '-p', '--kdf-param-id', default=PARAM_ID_DEFAULT, type=int, help=_clean_help(KDF_PARAM_ID_HELP)
)

DEFAULT_THRESHOLD = 3

DEFAULT_NUM_SHARES = 5

DEFAULT_SCHEME = f"{DEFAULT_THRESHOLD}of{DEFAULT_NUM_SHARES}"

SCHEME_OPTION_HELP = """
"""

_scheme_option = click.option(
    '-s',
    '--scheme',
    type=str,
    default=DEFAULT_SCHEME,
    show_default=True,
    help=_clean_help(SCHEME_OPTION_HELP),
)

THRESHOLD_OPTION_HELP = "Number of shares required to recover the key"


_threshold_option = click.option(
    '-t',
    '--threshold',
    type=int,
    default=DEFAULT_THRESHOLD,
    show_default=True,
    help=_clean_help(THRESHOLD_OPTION_HELP),
)

NUM_SHARES_OPTION_HELP = "Number of shares generate"

_num_shares_option = click.option(
    '-n',
    '--num-shares',
    type=int,
    default=DEFAULT_NUM_SHARES,
    show_default=True,
    help=_clean_help(NUM_SHARES_OPTION_HELP),
)

BRAINKEY_LEN_OPTION_HELP = "Length of the Brainkey (in words/bytes)"

DEFAULT_BRAINKEY_LEN = 4

_brainkey_lvl_option = click.option(
    '-b',
    '--brainkey-len',
    type=int,
    default=DEFAULT_BRAINKEY_LEN,
    show_default=True,
    help=_clean_help(BRAINKEY_LEN_OPTION_HELP),
)


SALT_LEN_OPTION_HELP = "Length of the Salt (in words/bytes)"

DEFAULT_SALT_LEN = 10

_salt_lvl_option = click.option(
    '-s',
    '--salt-len',
    type=int,
    default=DEFAULT_SALT_LEN,
    show_default=True,
    help=_clean_help(SALT_LEN_OPTION_HELP),
)

SHARE_LEN_OPTION_HELP = "Length of the share (in words/bytes) "

DEFAULT_SHARE_LEN = (DEFAULT_BRAINKEY_LEN + DEFAULT_SALT_LEN) * 2

_share_len_option = click.option(
    '--share-len',
    type=int,
    default=DEFAULT_SHARE_LEN,
    show_default=True,
    help=_clean_help(SHARE_LEN_OPTION_HELP),
)


YES_ALL_OPTION_HELP = "Enable non-interactive mode"

_yes_all_option = click.option(
    '-y', '--yes-all', type=bool, is_flag=True, default=False, help=_clean_help(YES_ALL_OPTION_HELP)
)


NON_SEGWIT_OPTION_HELP = "Create a non-segwit/legacy wallet."

_non_segwit_option = click.option(
    '--non-segwit', type=bool, is_flag=True, default=False, help=_clean_help(NON_SEGWIT_OPTION_HELP)
)


def _show_secret(label: str, data: bytes, codes: bool = True) -> None:
    if codes:
        assert len(data) % 4 == 0, len(data)
        output_lines = list(cli_util.format_secret_lines(data))
    else:
        output_lines = list(mnemonic.bytes2phrase(data).splitlines())

    len_padding = max(map(len, output_lines))

    echo(f"{label:^{len_padding}}")
    echo("\n".join(output_lines) + "\n\n")


SecretKey = bytes
ShareData = bytes


def _split_secret_key(
    secret_key: SecretKey, threshold: int, num_shares: int
) -> typ.Iterable[ShareData]:
    key_len = len(secret_key)
    assert secret_key[:1] == b"\x00"
    secret_int = enc_util.bytes2int(secret_key[1:])

    key_bits  = (key_len - 1) * 8
    prime     = primes.get_pow2prime(key_bits)
    gf_points = polynom.split(
        prime=prime, threshold=threshold, num_shares=num_shares, secret=secret_int
    )
    for gfpoint in gf_points:
        share_data = enc_util.gfpoint2bytes(gfpoint)
        assert len(share_data) == key_len, len(share_data)
        yield share_data


def _parse_command(in_val: str) -> typ.Optional[str]:
    in_val  = in_val.strip().lower()
    is_done = in_val in ('y', 'yes', 'd', 'done', 'a', 'accept')
    if is_done:
        return 'done'
    elif in_val in ('c', 'cancel', 'e', 'exit'):
        return 'cancel'
    elif in_val in ('p', 'prev'):
        return 'prev'
    elif in_val in ('n', 'next'):
        return 'next'
    else:
        return None


def _parse_input(idx: int, in_val: str) -> typ.Optional[typ.Tuple[str, bytes]]:
    maybe_code = in_val.replace(" ", "").replace("-", "")
    if maybe_code.isdigit():
        if len(maybe_code) < 6:
            echo("Invalid code. Missing digits.")
            return None

        if len(maybe_code) > 6:
            echo("Invalid code. Too many digits.")
            return None

        try:
            phrases = cli_util.intcodes2phrases([maybe_code], idx)
        except ValueError as err:
            echo(*err.args)
            echo(" Type 'skip' if you cannot read the code")
            return None

        line_data = b"".join(phrases)
    else:
        try:
            words = list(mnemonic.phrase2words(in_val))
        except ValueError as err:
            echo(f"Invalid Input: {err.args[1]}")
            return None

        if len(words) < 4:
            echo(f"Invalid Phrase. Missing words (expected 4)")
            return None

        if len(words) > 4:
            echo(f"Invalid Phrase. Too many words (expected 4)")
            return None

        line_data = mnemonic.phrase2bytes(" ".join(words))

    intcodes = list(cli_util.bytes2intcode_parts(line_data, idx))
    assert len(intcodes) == 1
    intcode = intcodes[0]

    return intcode, line_data


MaybeIntCodes = typ.List[typ.Optional[cli_util.IntCode]]


def _recover_full_data(intcodes: cli_util.MaybeIntCodes) -> typ.Optional[cli_util.IntCodes]:
    try:
        recovered_data = cli_util.intcode_parts2bytes(intcodes)
    except Exception:
        return None

    # abort if any recovered codes disagree with the input
    recovered_intcodes = cli_util.bytes2intcodes(recovered_data)
    if not all(recovered_intcodes):
        return None

    assert len(recovered_intcodes) == len(intcodes)

    for i, intcode in enumerate(intcodes):
        if intcode and intcode != recovered_intcodes[i]:
            return None

    return recovered_intcodes


def _line_marker(idx: int, key_len: int) -> str:
    marker_mod  = key_len // 4
    marker_char = "ABCD"[(idx // 2) // marker_mod]
    marker_id   = (idx // 2) % marker_mod
    return f"{marker_char}{marker_id}"


IntCodes    = typ.List[cli_util.IntCode]
PhraseLines = typ.List[str]


def _format_partial_secret(
    phrase_lines: PhraseLines, intcodes: cli_util.MaybeIntCodes, idx: int, key_len: int
) -> str:
    marker = _line_marker(idx, key_len)
    lines  = cli_util.format_partial_secret_lines(phrase_lines, intcodes)

    marked_lines = []
    l_idx        = 0
    for line in lines:
        if "at the" in line:
            if line.startswith(marker):
                marked_line = "=> " + line
            else:
                marked_line = "   " + line

            if idx >= key_len and idx % key_len == l_idx:
                marked_line += " <="

            l_idx += 2
        else:
            marked_line = ("   " + line).strip()

        marked_lines.append(marked_line)

    return "\n".join(marked_lines)


def _expand_codes_if_recoverable(
    intcodes: cli_util.MaybeIntCodes, key_len: int
) -> typ.Optional[typ.Tuple[IntCodes, PhraseLines]]:
    if len([ic for ic in intcodes if ic]) < key_len:
        return None

    maybe_recoverd_intcodes = _recover_full_data(intcodes)
    if maybe_recoverd_intcodes is None:
        return None

    recoverd_intcodes = list(maybe_recoverd_intcodes)

    data = cli_util.intcode_parts2bytes(recoverd_intcodes)

    recovered_phrase       = mnemonic.bytes2phrase(data)
    recovered_phrase_lines = recovered_phrase.splitlines()
    return recoverd_intcodes, recovered_phrase_lines


def _echo_state(
    intcodes    : cli_util.MaybeIntCodes,
    phrase_lines: PhraseLines,
    idx         : int,
    key_len     : int,
    header_text : str,
) -> str:
    clear()

    echo(header_text)

    echo()
    echo(_format_partial_secret(phrase_lines, intcodes, idx, key_len))
    echo()
    echo("Available commands:")
    echo()
    echo("    c/cancel: cancel recovery")
    echo("    p/prev  : move to previous code/phrase")
    echo("    n/next  : move to next code/phrase")

    if cli_util.is_completed_intcodes(intcodes):
        echo("    a/accept: accept input")

    echo()

    marker = _line_marker(idx, key_len)
    if idx < key_len:
        return f"Enter a command, data code or phrase {marker}"
    elif cli_util.is_completed_intcodes(intcodes):
        return f"Accept input (or continue entering update ECC {marker})"
    else:
        return f"Enter a command or ECC code for {marker}"


def _prompt_for_secret(header_text: str, key_len: int = 0) -> typ.Optional[cli_util.IntCodes]:
    block_len = key_len * 2

    phrase_lines    : PhraseLines = [cli_util.EMPTY_PHRASE_LINE] * (key_len // 2)
    intcodes        : typ.List[typ.Optional[str]] = [None] * block_len
    expanded_indexes: typ.Set[int] = set()

    idx           = 0
    prev_intcodes = list(intcodes)

    while True:
        if prev_intcodes != intcodes:
            expanded = _expand_codes_if_recoverable(intcodes, key_len)
            if expanded:
                exp_intcodes, exp_phrase_lines = expanded

                expanded_indexes = {
                    i for i, (a, b) in enumerate(zip(intcodes, exp_intcodes)) if a != b
                }

                intcodes     = list(exp_intcodes)
                phrase_lines = exp_phrase_lines

        prev_intcodes = list(intcodes)

        prompt_msg = _echo_state(intcodes, phrase_lines, idx, key_len, header_text)

        while True:
            in_val = click.prompt(prompt_msg)
            cmd    = _parse_command(in_val)
            if cmd == 'done' and cli_util.is_completed_intcodes(intcodes):
                return typ.cast(cli_util.IntCodes, intcodes)
            elif cmd == 'cancel':
                return None
            elif cmd == 'prev':
                idx = max(0, idx - 1)
                break
            elif cmd == 'next':
                idx = min(key_len - 1, idx + 1)
                break

            res = _parse_input(idx, in_val)
            if res is None:
                continue

            intcode, line_data = res

            for eidx in expanded_indexes:
                intcodes[eidx] = None
                phrase_lines[idx] = cli_util.EMPTY_PHRASE_LINE
            expanded_indexes.clear()

            if idx < key_len:
                phrase_line = mnemonic.bytes2phrase(line_data)
                phrase_lines[idx] = phrase_line

            intcodes[idx] = intcode
            idx += 1

            break


def _brainkey_prompt(key_len: int) -> typ.Optional[bytes]:
    header_text = """Step 2 of 2: Enter your "Brainkey".""" + "\n\tEnter BrainKey"

    phrase_lines: typ.List[str] = [cli_util.EMPTY_PHRASE_LINE] * (key_len // 2)

    idx = 0

    while any(line == cli_util.EMPTY_PHRASE_LINE for line in phrase_lines):
        phrase_no = idx // 2
        clear()

        echo(header_text)
        echo()

        for i, line in enumerate(phrase_lines):
            prefix = "=> " if i == phrase_no else "   "
            echo(prefix + line)

        echo()
        echo("    c/cancel: cancel brainkey input, use SBK Shares instead")
        echo("    p/prev  : move to previous code/phrase")
        echo("    n/next  : move to next code/phrase")
        echo()

        prompt_msg = f"Enter phrase {(phrase_no) + 1}"

        while True:
            in_val = click.prompt(prompt_msg)

            cmd = _parse_command(in_val)
            if cmd == 'cancel':
                return None
            elif cmd == 'prev':
                idx = max(0, idx - 2)
                break
            elif cmd == 'next':
                idx = min(key_len * 2 - 2, idx + 2)
                break

            res = _parse_input(idx, in_val)
            if res is None:
                continue

            _intcode, line_data = res

            phrase_line = mnemonic.bytes2phrase(line_data)
            phrase_lines[idx // 2] = phrase_line
            idx += 2

            break

    return mnemonic.phrase2bytes("\n".join(phrase_lines))


@click.group()
def cli() -> None:
    """CLI for SBK."""


@cli.command()
@click.version_option(version="v201906.0001-alpha")
def version() -> None:
    """Show version number."""
    echo(f"SBK version: {sbk.__version__}")


@cli.command()
@click.option('-a', '--show-all', is_flag=True, default=False, help=_clean_help(SHOW_ALL_HELP))
def kdf_info(show_all: bool = False) -> None:
    """Show info for each available parameter config."""
    min_mem_kb = PARAM_CTX.sys_info.total_kb * MIN_MEM_RATIO

    echo("Id  Mem[MB]  Iters  ~Time[Sec]  Algorithm")
    for kdf_param_id, config in PARAM_CTX.avail_configs.items():
        eta_sec        = round(PARAM_CTX.est_times_by_id[kdf_param_id], 1)
        memory_cost    = config['memory_cost']
        memory_cost_mb = int(memory_cost / 1024)
        time_cost      = config['time_cost']
        parts          = [
            f"{kdf_param_id:<3}",
            f"{memory_cost_mb:7}",
            f"{time_cost:6}",
            f"{eta_sec:11}",
            f"  argon2id",
        ]

        if kdf_param_id == PARAM_ID_DEFAULT:
            parts += ["<- default"]

        is_visible = memory_cost > min_mem_kb and eta_sec > MIN_TIME_SEC

        if is_visible or show_all or kdf_param_id == PARAM_CTX.param_id_default:
            echo(" ".join(parts))


def _validate_salt_len(salt_len: int) -> None:
    if salt_len < 1:
        echo("Minimum value for -s/--salt-len is 1")
        raise click.Abort()

    if salt_len > 16:
        echo("Maximum value for -s/--salt-len is 16")
        raise click.Abort()

    if salt_len % 4 != 0:
        echo(f"Invalid value -s/--salt-len={salt_len} must be a multiple of 4")
        raise click.Abort()


def _validate_brainkey_len(brainkey_len: int) -> None:
    if brainkey_len < 4:
        echo("Input Error: Minimum value for -b/--brainkey-len is 4")
        raise click.Abort()

    if brainkey_len > 32:
        echo("Input Error: Maximum value for -b/--brainkey-len is 32")
        raise click.Abort()

    if brainkey_len % 2 != 0:
        echo("Input Error: Parameter -b/--brainkey-len must be a multiple of 2")
        raise click.Abort()


@cli.command()
@_scheme_option
@_salt_lvl_option
@_brainkey_lvl_option
@_kdf_param_id_option
@_yes_all_option
def create(
    scheme      : str               = DEFAULT_SCHEME,
    salt_len    : int               = DEFAULT_SALT_LEN,
    brainkey_len: int               = DEFAULT_BRAINKEY_LEN,
    kdf_param_id: params.KDFParamId = PARAM_ID_DEFAULT,
    yes_all     : bool              = False,
) -> None:
    """Generate a new brainkey+salt and split them into shares."""
    _validate_salt_len(salt_len)
    _validate_brainkey_len(brainkey_len)

    threshold, num_shares = cli_util.parse_scheme(scheme)

    if kdf_param_id not in params.PARAM_CONFIGS_BY_ID:
        echo(f"Invalid --kdf-param-id={kdf_param_id}")
        echo("To see available parameters use: sbk kdf-info ")
        raise click.Abort()

    key_len = salt_len + brainkey_len
    key_len = (key_len + 3) // 4 * 4

    param_cfg  = params.init_params(threshold, num_shares, kdf_param_id, key_len)
    param_data = enc_util.params2bytes(param_cfg)

    yes_all or clear()
    yes_all or echo(SECURITY_WARNING_TEXT)
    yes_all or confirm(SECURITY_WARNING_PROMPT)

    # validate encoding round trip before we use the params
    decoded_param_cfg    = enc_util.bytes2params(param_data)
    is_param_recoverable = (
        param_cfg.threshold         == decoded_param_cfg.threshold
        and param_cfg.kdf_param_id  == decoded_param_cfg.kdf_param_id
        and param_cfg.key_len_bytes == decoded_param_cfg.key_len_bytes
    )

    if not is_param_recoverable:
        raise Exception("Integrity error. Aborting to prevent use of invald salt.")

    hasher = hashlib.sha256()
    hasher.update(urandom(salt_len * 2))

    # The main reason to combine these is just so that the user
    # has one less thing to know about. They always need both
    # the seed and the original parameters, so we just combine
    # them so they are always together.
    param_and_salt_data = (param_data + hasher.digest())[:salt_len]

    # salt
    yes_all or clear()

    echo(SALT_INFO_TITLE)
    _show_secret("Salt", param_and_salt_data)
    echo(SALT_INFO_TEXT)
    yes_all or anykey_confirm(SALT_INFO_PROMPT)

    hasher.update(urandom(brainkey_len))
    brainkey_data = hasher.digest()[:brainkey_len]

    yes_all or clear()
    yes_all or echo(SBK_KEYGEN_TITLE.strip())
    yes_all or echo(SBK_KEYGEN_TEXT)

    secret_key = _derive_key(brainkey_data, param_and_salt_data, label="Deriving Secret Key")
    assert len(secret_key) % 4 == 0, len(secret_key)

    echo("\n")
    yes_all or anykey_confirm(SBK_KEYGEN_PROMPT)

    share_datas = list(_split_secret_key(secret_key, threshold=threshold, num_shares=num_shares))

    for i, share_data in enumerate(share_datas):
        share_no = i + 1
        yes_all or clear()
        info             = {'share_no': share_no, 'threshold': threshold, 'num_shares': num_shares}
        sbk_share_title  = SBK_SHARE_TITLE.format(**info).strip()
        sbk_share_prompt = SBK_SHARE_PROMPT.format(**info)

        echo(sbk_share_title)
        echo(SBK_SHARE_TEXT)

        _show_secret(f"Secret Share {share_no}/{num_shares}", share_data)

        yes_all or anykey_confirm(sbk_share_prompt)

    # brainkey
    yes_all or clear()
    echo(BRAINKEY_INFO_TITLE.strip())
    echo(BRAINKEY_INFO_TEXT)

    yes_all or anykey_confirm("Press enter to show your brainkey")

    echo()

    _show_secret("Brainkey", brainkey_data, codes=False)

    yes_all or anykey_confirm(BRAINKEY_LAST_CHANCE_WARNING_TEXT)
    yes_all or clear()

    # wallet seed

    yes_all or clear()

    if not yes_all:
        _validate_copies(param_and_salt_data, share_datas)


def _validate_data(data: bytes, header_text: str) -> None:
    full_header_text = RECOVERY_VALIDATION_TITLE + "\n\n\t" + header_text
    data_len         = len(data)
    while True:
        recovered_intcodes = _prompt_for_secret(full_header_text, data_len)
        if recovered_intcodes is None:
            return

        recovered_data = cli_util.intcode_parts2bytes(recovered_intcodes)
        if data == recovered_data:
            return

        anykey_confirm("Invalid input. Data mismatch.")


def _validate_copies(salt_data: bytes, share_datas: typ.Sequence[ShareData]) -> None:
    _validate_data(salt_data, "Validate your copy of the Salt")

    num_shares = len(share_datas)

    for i, share_data in enumerate(share_datas):
        share_no   = i + 1
        title_text = f"Validate your copy of Share {share_no}/{num_shares}"
        _validate_data(share_data, title_text)


@cli.command()
def recover_params() -> None:
    cli_io.prompt(cli_io.INPUT_TYPE_PARAMS, data_len=4)


@cli.command()
@click.option('--salt-len', type=int, help=_clean_help(SALT_LEN_OPTION_HELP))
def recover_salt(salt_len: int = None) -> None:
    """Recover a partially readable Salt."""
    if salt_len is None:
        params_data = cli_io.prompt(cli_io.INPUT_TYPE_PARAMS, data_len=4)
        params      = enc_util.bytes2params(params_data)
        salt_len    = params.salt_len

    key_len = salt_len
    if key_len >= 4 and key_len % 4 == 0:
        cli_io.prompt(cli_io.INPUT_TYPE_SALT, data_len=key_len)
    else:
        click.echo(f"Invalid -s/--salt-len={key_len} must be divisible by 4.")
        raise click.Abort()


@cli.command()
@_share_len_option
def recover_share(share_len: int = DEFAULT_SHARE_LEN) -> None:
    """Recover a partially readable share."""
    key_len = share_len
    if key_len >= 4 and key_len % 4 == 0:
        cli_io.prompt(cli_io.INPUT_TYPE_SHARE, data_len=key_len)
    else:
        click.echo(f"Invalid --share-len={key_len} must be divisible by 4.")
        raise click.Abort()


def _join_shares(param_cfg: params.Params, share_datas: typ.List[ShareData]) -> SecretKey:
    prime      = primes.POW2_PRIMES[param_cfg.pow2prime_idx]
    gf         = polynom.GF(p=prime)
    points     = [enc_util.bytes2gfpoint(p, gf) for p in share_datas]
    secret_int = polynom.join(len(points), points)
    secret_key = b"\x00" + enc_util.int2bytes(secret_int)
    return secret_key


@cli.command()
@_salt_lvl_option
@_brainkey_lvl_option
@_yes_all_option
@_non_segwit_option
def load_wallet(
    salt_len    : int  = DEFAULT_SALT_LEN,
    brainkey_len: int  = DEFAULT_BRAINKEY_LEN,
    yes_all     : bool = False,
    non_segwit  : bool = False,
) -> None:
    """Open wallet using Salt and Brainkey or Salt and SBK Pieces."""
    salt_len = (salt_len + 3) // 4 * 4

    yes_all or clear()
    yes_all or echo(SECURITY_WARNING_TEXT)
    yes_all or confirm(SECURITY_WARNING_PROMPT)

    header_text   = """Enter your "Salt"."""
    salt_intcodes = _prompt_for_secret(header_text, salt_len)

    if salt_intcodes is None:
        click.echo("Salt is required")
        raise click.Abort()

    salt_data = cli_util.intcode_parts2bytes(salt_intcodes)
    param_cfg = enc_util.bytes2params(salt_data)

    if brainkey_len == 0:
        brainkey_data = None
    else:
        brainkey_data = _brainkey_prompt(brainkey_len)

    if brainkey_data is None:
        share_datas: typ.List[ShareData] = []
        while len(share_datas) < param_cfg.threshold:
            piece_num = len(share_datas) + 1
            header_text = f"""
            Enter your SBK-Piece {piece_num} of {param_cfg.threshold}.
            """.strip()
            sbk_piece_intcodes = _prompt_for_secret(header_text, param_cfg.key_len_bytes)
            if sbk_piece_intcodes:
                sbk_piece = cli_util.intcode_parts2bytes(sbk_piece_intcodes)
                share_datas.append(sbk_piece)

        secret_key = _join_shares(param_cfg, share_datas)
    else:
        secret_key = _derive_key(brainkey_data, salt_data, label="Deriving Secret Key")

    seed_type = 'standard' if non_segwit else 'segwit'

    int_seed    = enc_util.bytes2int(secret_key)
    wallet_seed = electrum_mnemonic.seed_raw2phrase(int_seed, seed_type)

    wallet_path = "/tmp/sbk_electrum_wallet"

    if os.path.exists(wallet_path):
        os.remove(wallet_path)

    try:
        cmd     = ["electrum", "restore", "--wallet", wallet_path, wallet_seed]
        retcode = sp.call(cmd)
        if retcode != 0:
            raise click.Abort("Error calling 'electrum restore'")

        cmd     = ["electrum", "gui", "--offline", "--wallet", wallet_path]
        retcode = sp.call(cmd)
        if retcode != 0:
            raise click.Abort("Error calling 'electrum restore'")
    finally:
        if os.path.exists(wallet_path):
            # TODO: bleachbit ?
            os.remove(wallet_path)


@cli.command()
@click.pass_context
def repl(ctx):
    """Start REPL (with completion)."""
    click.echo(cli.get_help(ctx))
    prompt_kwargs = {'message': "sbk> "}
    click_repl.repl(ctx, prompt_kwargs=prompt_kwargs)


if __name__ == '__main__':
    cli()
