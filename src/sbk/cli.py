#!/usr/bin/env python
# This file is part of the SBK project
# https://gitlab.com/mbarkhau/sbk
#
# Copyright (c) 2019 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT

"""CLI/Imperative shell for SBK."""
import os
import io
import sys
import math
import time
import hashlib
import threading
import typing as typ
import pathlib2 as pl
import itertools as it

import click
import qrcode

import sbk

from . import kdf
from . import params
from . import primes
from . import polynom
from . import enc_util


# To enable pretty tracebacks:
#   echo "export ENABLE_BACKTRACE=1;" >> ~/.bashrc
if os.environ.get('ENABLE_BACKTRACE') == '1':
    import backtrace

    backtrace.hook(align=True, strip_path=True, enable_on_envvar_only=True)


click.disable_unicode_literals_warning = True

APP_DIR          = pl.Path(click.get_app_dir("sbk"))
PARAM_CTX        = params.get_param_ctx(APP_DIR)
PARAM_ID_DEFAULT = PARAM_CTX.param_id_default


def _clean_help(helmsg: str) -> str:
    return " ".join(
        line.strip() for line in helmsg.splitlines() if line.strip()
    )


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
        message.strip(),
        default="",
        show_choices=False,
        show_default=False,
        prompt_suffix="",
    )
    return False


class ThreadWithReturnData(threading.Thread):

    _return: typ.Optional[bytes]

    def __init__(self, target=None, args=(), kwargs=None) -> None:
        threading.Thread.__init__(self, target=target, args=args, kwargs=kwargs)
        self._target = target
        self._args   = args
        self._kwargs = kwargs
        self._return = None

    def run(self) -> None:
        tgt = self._target
        assert tgt is not None
        kwargs       = self._kwargs or {}
        self._return = tgt(*self._args, **kwargs)

    def join(self, *args) -> None:
        threading.Thread.join(self, *args)
        if self._return is None:
            raise Exception("Missing return value after Thread.join")

    @property
    def retval(self) -> bytes:
        rv = self._return
        assert rv is not None
        return rv


def _derive_key(
    brainkey_data: bytes,
    salt_data    : bytes,
    kdf_param_id : params.KDFParamId,
    key_len      : int,
    label        : str,
) -> bytes:
    eta_sec = PARAM_CTX.est_times_by_id[kdf_param_id]

    # NOTE: Since we encode the x value of a point in the top byte,
    #   and since the key we derive (the y value) has to be smaller
    #   than the prime with key_len * 8 - 8 bits, we have to cut off
    #   the top byte here too.
    hash_len = key_len - 1

    kdf_args   = (brainkey_data, salt_data, kdf_param_id, hash_len)
    kdf_thread = ThreadWithReturnData(target=kdf.derive_key, args=kdf_args)
    # daemon means the thread is killed if user hits Ctrl-C
    kdf_thread.daemon = True
    kdf_thread.start()

    progress_bar = None

    tzero = time.time()
    total = int(eta_sec * 1000)

    step = 0.1

    while kdf_thread.is_alive():
        time.sleep(step)
        tnow          = time.time()
        elapsed       = tnow    - tzero
        remaining     = eta_sec - elapsed
        remaining_pct = 100 * remaining / eta_sec

        if progress_bar is None and elapsed > 0.2:
            progress_bar = click.progressbar(
                label=label, length=total, show_eta=True
            )
            progress_bar.update(int(elapsed * 1000))
        elif progress_bar:
            if remaining_pct < 10:
                progress_bar.update(int(step * 200))
            elif remaining_pct < 20:
                progress_bar.update(int(step * 400))
            elif remaining_pct < 50:
                progress_bar.update(int(step * 700))
            else:
                progress_bar.update(int(step * 1000))

    if progress_bar:
        progress_bar.update(total)

    kdf_thread.join()

    hash_data = kdf_thread.retval
    key_data  = b"\x00" + hash_data
    assert len(key_data) == key_len, len(key_data)
    return key_data


@click.group()
def cli() -> None:
    """Cli for SBK."""


@cli.command()
@click.version_option(version="v201906.0001-alpha")
def version() -> None:
    """Show version number."""
    echo(f"SBK version: {sbk.__version__}")


MIN_TIME_SEC  = 10
MIN_MEM_RATIO = 0.1


SHOW_ALL_HELP = """
Show all available KDF parameter choices.

By default only shows reasonable
choices for the current system.
"""


@cli.command()
@click.option(
    '-a',
    '--show-all',
    is_flag=True,
    default=False,
    help=_clean_help(SHOW_ALL_HELP),
)
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

    TODO TODO TODO TODO
    TODO TODO TODO TODO
    TODO TODO TODO TODO

"""


SECURITY_WARNING_PROMPT = """
Do you believe your system is secure?
"""


SALT_INFO_TITLE = r'Step 1 of 5: Copy your "salt".'

SBK_KEYGEN_TITLE = r"Step 2 of 5: Deriving Secret Key"

SBK_PIECE_TITLE = r"Step 3 of 5: Copy SBK Piece {piece_no}/{num_pieces}."

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
brainkey is secure even if an attacker gains access to the salt.

    (Brainkey + Salt) -> Secret Key
"""

SBK_KEYGEN_PROMPT = "Key generation complete, press enter to continue"


SBK_PIECE_TEXT = r"""
Give this "SBK Piece" one of your trustees. Your trustees should not
only be trustworthy in the sense that they will act in your best
interests, they should also be trustworthy in the sense that they are
competent to keep this SBK Piece safe and secret.
"""

RECOVERY_TEXT = r"""
Your "secret key" is recovered by collecting a minimum of {threshold}
pieces.

                   Split Secret Key
          Split                    . Recovery
               \.-> SBK Piece 1 -./
    Secret Key -O-> SBK Piece 2  +-> Secret Key
                '-> SBK Piece 3 -'

    Secret Key + Salt -> Wallet
"""

SBK_PIECE_PROMPT = r"""
Please make a physical copy of SBK Piece {piece_no}/{num_pieces}.
"""

BRAINKEY_INFO_TEXT = r"""
Your "brainkey" and "salt" are combined to produce your "secret key".
Your secret key in turn is combined with your salt to recover your
"wallet".

    Brainkey + Salt -> Secret Key
    Secret Key + Salt -> Wallet

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

RECOVERY_VALIDATION_TEXT = """
Finally, please verify the data you have copied.
"""


KDF_PARAM_ID_HELP = (
    "KDF difficulty selection. Use 'sbk kdf-info' to see valid options"
)

_kdf_param_id_option = click.option(
    '-p',
    '--kdf-param-id',
    default=PARAM_ID_DEFAULT,
    type=int,
    help=_clean_help(KDF_PARAM_ID_HELP),
)

EMAIL_OPTION_HELP = "Email which is used as a salt"

_email_option = click.option(
    '-e',
    '--email',
    type=str,
    required=True,
    help=_clean_help(EMAIL_OPTION_HELP),
)

THRESHOLD_OPTION_HELP = "Number of pieces required to recover the key"

DEFAULT_THRESHOLD = 2

_threshold_option = click.option(
    '-t',
    '--threshold',
    type=int,
    default=DEFAULT_THRESHOLD,
    show_default=True,
    help=_clean_help(THRESHOLD_OPTION_HELP),
)

NUM_PIECES_OPTION_HELP = "Number of pieces to split the key into"

DEFAULT_NUM_PIECES = 3

_num_pieces_option = click.option(
    '-n',
    '--num-pieces',
    type=int,
    default=DEFAULT_NUM_PIECES,
    show_default=True,
    help=_clean_help(NUM_PIECES_OPTION_HELP),
)

SALT_LEN_OPTION_HELP = "Length (in bytes) of the Salt"

DEFAULT_SALT_LEN = 192 // 8

_salt_len_option = click.option(
    '-s',
    '--salt-len',
    type=int,
    default=DEFAULT_SALT_LEN,
    show_default=True,
    help=_clean_help(SALT_LEN_OPTION_HELP),
)

KEY_LEN_OPTION_HELP = "Length (in bytes) of the Key/SBK Piece"

DEFAULT_KEY_LEN = 192 // 8

_key_len_option = click.option(
    '-k',
    '--key-len',
    type=int,
    default=DEFAULT_KEY_LEN,
    show_default=True,
    help=_clean_help(KEY_LEN_OPTION_HELP),
)

BRAINKEY_LEN_OPTION_HELP = "Length (in bytes) of the Brainkey"

DEFAULT_BRAINKEY_LEN = 48 // 8

_brainkey_len_option = click.option(
    '-b',
    '--brainkey-len',
    type=int,
    default=DEFAULT_BRAINKEY_LEN,
    show_default=True,
    help=_clean_help(BRAINKEY_LEN_OPTION_HELP),
)

YES_ALL_OPTION_HELP = "Enable non-interactive mode"

_yes_all_option = click.option(
    '-y',
    '--yes-all',
    type=bool,
    is_flag=True,
    default=False,
    help=_clean_help(YES_ALL_OPTION_HELP),
)


def _show_secret(label: str, data: bytes, qr: bool = False) -> None:
    assert len(data) % 4 == 0, len(data)
    output_lines = list(enc_util.format_secret_lines(data))

    if qr:
        qr_renderer = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr_renderer.add_data(data)
        buf = io.StringIO()
        qr_renderer.print_ascii(out=buf, invert=True)
        qr_lines = buf.getvalue().splitlines()
    else:
        qr_lines = []

    # TODO mb: Don't interleave if terminal is too narrow.
    len_padding = max(map(len, output_lines))

    output_lines = [
        ((a or "").ljust(len_padding)) + "     " + (b or "")
        for a, b in it.zip_longest(output_lines, qr_lines)
    ]

    echo(f"{label:^{len_padding}}")
    echo("\n".join(output_lines) + "\n\n")


def _split_secret_key(
    secret_key: bytes, threshold: int, num_pieces: int
) -> typ.Iterable[bytes]:
    key_len = len(secret_key)
    assert secret_key[0] == 0
    secret_int = enc_util.bytes2int(secret_key[1:])

    key_bits  = (key_len - 1) * 8
    prime     = primes.get_pow2prime(key_bits)
    gf_points = polynom.split(
        prime=prime,
        threshold=threshold,
        num_pieces=num_pieces,
        secret=secret_int,
    )
    for gfpoint in gf_points:
        sbk_piece_data = enc_util.gfpoint2bytes(gfpoint)
        assert len(sbk_piece_data) == key_len, len(sbk_piece_data)
        yield sbk_piece_data


@cli.command()
@_kdf_param_id_option
@_email_option
@_threshold_option
@_num_pieces_option
@_salt_len_option
@_key_len_option
@_brainkey_len_option
@_yes_all_option
def new_key(
    email       : str,
    kdf_param_id: params.KDFParamId = PARAM_ID_DEFAULT,
    threshold   : int               = DEFAULT_THRESHOLD,
    num_pieces  : int               = DEFAULT_NUM_PIECES,
    salt_len    : int               = DEFAULT_SALT_LEN,
    key_len     : int               = DEFAULT_KEY_LEN,
    brainkey_len: int               = DEFAULT_BRAINKEY_LEN,
    yes_all     : bool              = False,
) -> None:
    """Generate a new key and split it to pieces."""

    # length that use ecc must be multiples of 4
    # round up to nearest multiple.
    salt_len = (salt_len + 3) // 4 * 4
    key_len  = (key_len  + 3) // 4 * 4

    yes_all or clear()
    yes_all or echo(SECURITY_WARNING_TEXT)
    yes_all or confirm(SECURITY_WARNING_PROMPT)

    param_cfg  = params.init_params(threshold, num_pieces, kdf_param_id, key_len)
    param_data = enc_util.params2bytes(param_cfg)

    # validate encoding round trip before we use the params
    decoded_param_cfg    = enc_util.bytes2params(param_data)
    is_param_recoverable = (
        param_cfg.threshold          == decoded_param_cfg.threshold
        and param_cfg.kdf_param_id   == decoded_param_cfg.kdf_param_id
        and param_cfg.hash_len_bytes == decoded_param_cfg.hash_len_bytes
    )

    if not is_param_recoverable:
        raise Exception(
            "Integrity error. Aborting to prevent use of invald salt."
        )

    hasher = hashlib.sha256()
    hasher.update(email.encode("utf-8"))
    hasher.update(os.urandom(salt_len * 2))

    # The main reason to combine these is just so that the user
    # has one less thing to know about. They always need both
    # the seed and the original parameters, so we just combine
    # them so they are always together.
    param_and_salt_data = (param_data + hasher.digest())[:salt_len]

    # salt
    yes_all or clear()

    echo(SALT_INFO_TITLE)
    _show_secret("Salt", param_and_salt_data, qr=True)
    echo(SALT_INFO_TEXT)
    yes_all or anykey_confirm(SALT_INFO_PROMPT)

    hasher.update(os.urandom(brainkey_len))
    brainkey_data = hasher.digest()[:brainkey_len]

    yes_all or clear()
    yes_all or echo(SBK_KEYGEN_TITLE.strip())
    yes_all or echo(SBK_KEYGEN_TEXT)

    secret_key = _derive_key(
        brainkey_data,
        param_and_salt_data,
        kdf_param_id,
        key_len,
        label="Deriving Secret Key",
    )
    assert len(secret_key) % 4 == 0, len(secret_key)

    echo("\n")
    yes_all or anykey_confirm(SBK_KEYGEN_PROMPT)

    sbk_pieces = _split_secret_key(
        secret_key, threshold=threshold, num_pieces=num_pieces
    )

    # secret pieces
    for i, sbk_piece_data in enumerate(sbk_pieces):
        piece_no = i + 1
        yes_all or clear()
        info = {
            'piece_no'  : piece_no,
            'threshold' : threshold,
            'num_pieces': num_pieces,
        }
        sbk_piece_title  = SBK_PIECE_TITLE.format(**info).strip()
        sbk_piece_prompt = SBK_PIECE_PROMPT.format(**info)

        echo(sbk_piece_title)
        echo(SBK_PIECE_TEXT)

        _show_secret(f"Secret Piece {piece_no}/{num_pieces}", sbk_piece_data)

        yes_all or anykey_confirm(sbk_piece_prompt)

    # brainkey
    yes_all or clear()
    echo(BRAINKEY_INFO_TITLE.strip())
    echo(BRAINKEY_INFO_TEXT)

    yes_all or anykey_confirm("Press enter to show your brainkey")

    echo()

    _show_secret("Brainkey", brainkey_data)

    yes_all or anykey_confirm(BRAINKEY_LAST_CHANCE_WARNING_TEXT)
    yes_all or clear()

    # wallet seed

    yes_all or clear()

    # recovery test
    yes_all or clear()
    yes_all or echo(RECOVERY_VALIDATION_TITLE)
    yes_all or echo(RECOVERY_VALIDATION_TEXT)

    yes_all or anykey_confirm("noop")


@cli.command()
@_kdf_param_id_option
@_key_len_option
def derive_key(
    kdf_param_id: params.KDFParamId = PARAM_ID_DEFAULT,
    key_len     : int               = DEFAULT_KEY_LEN,
) -> None:
    """Derive secret key from a brainkey.

    You should avoid generating your own brainkey, as humans are
    notorious for generating data that can easilly be guessed by an
    attacker.
    """
    if sys.stdin.isatty():
        secret_text = click.prompt("Enter your secret")
    else:
        secret_text = sys.stdin.read()

    if kdf_param_id is None:
        kdf_param_id = PARAM_CTX.param_id_default

    if kdf_param_id not in params.PARAM_CONFIGS_BY_ID:
        err_msg = (
            f"Invalid argument '{kdf_param_id}' for -p/--kdf-param-id."
            f"\n\n\tUse 'sbk kdf-info' to see valid choices."
        )
        raise click.BadOptionUsage("--kdf-param-id", err_msg)

    secret_data = secret_text.encode("utf-8")
    salt_data   = b""  # TODO

    unsplit_key = _derive_key(
        secret_data, salt_data, kdf_param_id, key_len, "Deriving Secret Key"
    )
    key_phrase = enc_util.bytes2phrase(unsplit_key)

    echo("\n")
    echo(key_phrase)


def _parse_input(
    idx: int, in_val: str
) -> typ.Optional[typ.Tuple[str, str, bytes]]:
    maybe_code = in_val.replace(" ", "")
    if maybe_code.isdigit():
        if len(maybe_code) < 8:
            echo("Invalid code. Missing digits.")
            return None

        if len(maybe_code) > 8:
            echo("Invalid code. Too many digits.")
            return None

        c0 = maybe_code[:4]
        c1 = maybe_code[4:]

        try:
            parts = enc_util.intcodes2parts([c0, c1], idx)
            (p0_idx, p0_val), (p1_idx, p1_val) = parts
        except ValueError as err:
            echo(*err.args)
            echo(" Type 'skip' if you cannot read the code")
            return None

        line_data = p0_val + p1_val
    else:
        try:
            phrase_parts = enc_util.phrase2parts(in_val)
        except ValueError as err:
            echo(f"Unknown word: {err.args[1]}")
            return None

        if len(phrase_parts) < 4:
            echo(f"Invalid Phrase. Missing words (expected 4)")
            return None

        if len(phrase_parts) > 4:
            echo(f"Invalid Phrase. Too many words (expected 4)")
            return None

        line_data = enc_util.phrase2bytes(" ".join(phrase_parts))
        c0, c1 = enc_util.bytes2intcode_parts(line_data, idx)

    return c0, c1, line_data


@cli.command()
@_key_len_option
def recover_key(key_len: int = DEFAULT_KEY_LEN,) -> None:
    """Use Data and ECC codes to recover a Phrase."""
    # length that use ecc must be multiples of 4
    key_len = int(math.ceil(key_len / 4.0) * 4)

    block_len  = key_len * 2
    marker_mod = key_len // 4

    phrase_lines: typ.List[str] = [enc_util.EMPTY_PHRASE_LINE] * (key_len // 2)
    intcodes    : typ.List[typ.Optional[str]] = [None] * block_len

    idx = 0

    while idx < block_len:
        # data      = enc_util.intcode_parts2bytes(intcode_parts, block_len)
        # data      = b"\x00" * key_len
        lines     = enc_util.format_partial_secret_lines(phrase_lines, intcodes)
        formatted = "\n".join(lines)

        clear()
        echo()
        echo(formatted)
        echo()
        echo("Available commands:")
        echo()
        echo("    e/exit: abort recovery")
        echo("    s/skip: skip code/phrase if not legible")
        echo("    u/undo: undo previous code/phrase")
        echo()

        marker_char = "ABCD"[(idx // 2) // marker_mod]
        marker_id   = (idx // 2) % marker_mod
        marker      = f"{marker_char}{marker_id}"

        if idx < key_len:
            prompt_msg = f"Enter a command, data code or phrase {marker}"
        else:
            prompt_msg = f"Enter a command or ECC code for {marker}"

        while True:
            in_val = click.prompt(prompt_msg)
            in_val = in_val.strip().lower()
            if in_val in ('s', 'skip'):
                idx += 2
                break
            if in_val in ('e', 'exit'):
                return
            if in_val in ('u', 'undo'):
                idx = max(0, idx - 2)
                phrase_lines[idx // 2] = enc_util.EMPTY_PHRASE_LINE
                intcodes[idx] = None
                intcodes[idx + 1] = None
                break

            res = _parse_input(idx, in_val)
            if res is None:
                continue

            c0, c1, line_data = res

            if idx < key_len:
                phrase_line = enc_util.bytes2phrase(line_data)
                phrase_lines[idx // 2] = phrase_line
            else:
                # TODO: fill in ecc if possible
                pass

            intcodes[idx] = c0
            intcodes[idx + 1] = c1
            idx += 2
            break


# def split_key():
#     yes_all or clear()
#     yes_all or confirm(SECURITY_WARNING_TEXT)
#     yes_all or confirm(SECURITY_WARNING_PROMPT)


# def recover_key():
#     yes_all or clear()
#     yes_all or confirm(SECURITY_WARNING_TEXT)
#     yes_all or confirm(SECURITY_WARNING_PROMPT)


if __name__ == '__main__':
    cli()
