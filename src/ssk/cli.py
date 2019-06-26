#!/usr/bin/env python
# This file is part of the ssk project
# https://gitlab.com/mbarkhau/ssk
#
# Copyright (c) 2019 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT
"""CLI/Imperative shell for SSK."""
import os
import re
import sys
import time
import threading
import typing as typ
import pathlib2 as pl
import datetime as dt

import click

import ssk

from . import kdf
from . import params
from . import enc_util


# To enable pretty tracebacks:
#   echo "export ENABLE_BACKTRACE=1;" >> ~/.bashrc
if os.environ.get('ENABLE_BACKTRACE') == '1':
    import backtrace

    backtrace.hook(align=True, strip_path=True, enable_on_envvar_only=True)


click.disable_unicode_literals_warning = True

APP_DIR          = pl.Path(click.get_app_dir("ssk"))
PARAM_CTX        = params.get_param_ctx(APP_DIR)
DEFAULT_PARAM_ID = PARAM_CTX.default_param_id


def _clean_help(helmsg: str) -> str:
    return " ".join(
        line.strip() for line in helmsg.splitlines() if line.strip()
    )


class ThreadWithReturnData(threading.Thread):

    _return: typ.Optional[bytes]

    def __init__(self, target=None, args=(), kwargs={}):
        threading.Thread.__init__(self, target=target, args=args, kwargs=kwargs)
        self._target = target
        self._args   = args
        self._kwargs = kwargs
        self._return = None

    def run(self):
        if self._target is None:
            return
        self._return = self._target(*self._args, **self._kwargs)

    def join(self, *args) -> bytes:
        threading.Thread.join(self, *args)
        data = self._return
        if data is None:
            raise Exception("Missing return value after Thread.join")
        else:
            return data


def _derive_key(
    secret_data: bytes, salt_email: str, kdf_param_id: params.KDFParamId
) -> bytes:
    eta_sec = PARAM_CTX.est_times_by_id[kdf_param_id]

    kdf_args   = secret_data, salt_email, kdf_param_id
    kdf_thread = ThreadWithReturnData(target=kdf.derive_key, args=kdf_args)
    # daemon means the thread is killed if user hits Ctrl-C
    kdf_thread.daemon = True
    kdf_thread.start()

    progress_bar = None

    tzero = time.time()
    total = int(eta_sec * 1000)

    step = 0.2

    while kdf_thread.is_alive():
        time.sleep(step)
        tnow          = time.time()
        elapsed       = tnow    - tzero
        remaining     = eta_sec - elapsed
        remaining_pct = 100 * remaining / eta_sec

        if progress_bar is None and elapsed > 0.5:
            progress_bar = click.progressbar(
                label="Deriving key", length=total, show_eta=True
            )
            progress_bar.update(elapsed * 1000)
        elif progress_bar:
            if remaining_pct < 5:
                progress_bar.update(step * 100)
            elif remaining_pct < 10:
                progress_bar.update(step * 500)
            else:
                progress_bar.update(step * 1000)

    if progress_bar:
        progress_bar.update(total)

    key_data = kdf_thread.join()

    return key_data


@click.group()
def cli() -> None:
    """Cli for SSK."""


@cli.command()
@click.version_option(version="v201906.0001-alpha")
def version() -> None:
    """Show version number."""
    click.echo(f"ssk version: {ssk.__version__}")


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

    click.echo("Id  Mem[MB]  Iters  ~Time[Sec]  Algorithm")
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

        if kdf_param_id == DEFAULT_PARAM_ID:
            parts += ["<- default"]

        is_visible = memory_cost > min_mem_kb and eta_sec > MIN_TIME_SEC

        if is_visible or show_all or kdf_param_id == PARAM_CTX.default_param_id:
            click.echo(" ".join(parts))


EMAIL_OPTION_HELP = "Email which is used as a salt."

KDF_PARAM_ID_HELP = (
    "KDF difficulty selection. Use 'ssk kdf-info' to see valid options."
)

THRESHOLD_OPTION_HELP = "Minimum number of pieces required to recover the key."

NUM_PIECES_OPTION_HELP = "Total number of pieces to split the key into."

BRAINKEY_OPTION_HELP = "Generate a Brainkey."


SECRETS_WARNING_TEXT = """
You are generating new secret keys. Please make sure of the following:

 - Are you the only person who can view your screen?
 - Is this computer air-gapped? Your system should be disconnected
   from all networks and if it has a wifi device (idelly it shouldn't)
   you should enable flight mode.
 - Is this a fresh Linux installation? You should not use SSK on your
   regular computer, the security of which might be compromised or
   become compromised in the future.
 - Did you check the signatures of the software? You should verify
   that the software you are using came from trusted sources. This
   includes your linux distribution, the SSK executable and your
   wallet software.

For more information on setting up a secure air-gapped computing
system visit:
"""


BRAINKEY_WARNING_TEXT = """
Your brainkey will now be shown.

 - Do not write it down.
 - Memorize it very well.
 - Regularly remember it so you don't forget it.
 - Never ever tell it to anybody!
"""


EMAIL_PATTERN = r"""
    ^
    (?P<prefix>[a-zA-Z0-9_.-]+)
    (?P<tag>[a-zA-Z0-9_.+-]+)?
    @
    (?P<domain>
        [a-zA-Z0-9-]+
        \.
        [a-zA-Z0-9-.]+
    )
    $
"""

EMAIL_RE = re.compile(EMAIL_PATTERN, flags=re.VERBOSE)

INVALID_EMAIL_ERROR = """
A valid email is important to

    1. Supply entropy/salt that is unique to your key.
    2. So that each person with a peace of your secret knows how to
       contact you.

"""

def _random_email_tag() -> str:
    datestr = dt.date.today().strftime("%%Y")
    nonce = bytes2hex(os.urandom(8))
    return datestr + "_" + nonce



EMAIL_TAG_MISSING_WARNING = """
Your email does not have a +tag. Many email systems allow
you to add an arbitrary +tag. For example you can change
"{email}" to "{prefix}+{tag}@{domain} and you may still
get your email just fine. Adding such a random tag to your
email is highly recommended to prevent
"""


def _validate_email(email: str, yes_all: bool) -> None:
    email_match = EMAIL_RE.match(email)
    if email_match is None:
        click.echo(f"Invalid parameter for --email '{email}'.")
        click.echo(INVALID_EMAIL_ERROR)
        exit(1)

    if not email_match.group('tag'):
        click.echo(EMAIL_TAG_MISSING_WARNING.format(
            email=email,
            tag=_random_email_tag(),
            prefix=email_match.group('prefix'),
            domain=email_match.group('domain'),
        ))
        yes_all or click.confirm("Continue without +tag ?", abort=True)


_kdf_param_id_option = click.option(
    '-p',
    '--kdf-param-id',
    default=DEFAULT_PARAM_ID,
    type=int,
    help=_clean_help(KDF_PARAM_ID_HELP),
)

_email_option = click.option(
    '-e',
    '--email',
    type=str,
    required=True,
    help=_clean_help(EMAIL_OPTION_HELP),
)

_threshold_option = click.option(
    '-t',
    '--threshold',
    type=int,
    default=2,
    help=_clean_help(THRESHOLD_OPTION_HELP),
)

_num_pieces_option = click.option(
    '-n',
    '--num-pieces',
    type=int,
    default=3,
    help=_clean_help(NUM_PIECES_OPTION_HELP),
)

_brainkey_option = click.option(
    '-b',
    '--brainkey',
    type=bool,
    is_flag=True,
    default=False,
    help=_clean_help(BRAINKEY_OPTION_HELP),
)

_yes_all_option = click.option(
    '-y',
    '--yes-all',
    type=bool,
    is_flag=True,
    default=False,
    help=_clean_help(BRAINKEY_OPTION_HELP),
)

def anykey_confirm(message: str) -> None:
    click.prompt(
        message,
        default="",
        show_choices=False,
        show_default=False,
        prompt_suffix="",
    )

@cli.command()
@_email_option
@_kdf_param_id_option
@_threshold_option
@_num_pieces_option
@_brainkey_option
@_yes_all_option
def new_key(
    email       : str,
    kdf_param_id: params.KDFParamId = DEFAULT_PARAM_ID,
    threshold   : int               = 2,
    num_pieces  : int               = 3,
    brainkey    : bool              = False,
    yes_all     : bool              = False,
) -> None:
    """Generate a new key and split it to pieces."""
    _validate_email(email, yes_all)

    yes_all or click.clear()
    click.echo(SECRETS_WARNING_TEXT)

    yes_all or click.confirm("Is this system secure?", abort=True)
    yes_all or click.clear()

    if brainkey:
        brainkey_data   = os.urandom(6)
        brainkey_phrase = enc_util.bytes2phrase(brainkey_data)
        assert enc_util.phrase2bytes(brainkey_phrase) == brainkey_data

        click.echo(BRAINKEY_WARNING_TEXT)

        yes_all or anykey_confirm("Press enter to show your brainkey\n")

        click.echo("\t" + "\n\t".join(brainkey_phrase.splitlines()) + "\n")

        yes_all or anykey_confirm("Press enter to continue")
        yes_all or click.clear()

        unsplit_key    = _derive_key(brainkey_data, email, kdf_param_id)
    else:
        brainkey_data = os.urandom(16)

    yes_all or anykey_confirm("Press enter to show split peace 1.")
    yes_all or click.clear()

    param_cfg = params.PARAM_CONFIGS_BY_ID[kdf_param_id]

    p = params.Params(
        threshold,
        num_pieces,
        kdf_param_id,
        hash_algo=param_cfg['hash_algo'],
        hash_len_bytes=param_cfg['hash_len_bytes'],
        memory_cost=param_cfg['memory_cost'],
        time_cost=param_cfg['time_cost'],
        parallelism=param_cfg['parallelism'],
    )
    param_data   = enc_util.params2bytes(p)
    param_phrase = enc_util.bytes2phrase(param_data)
    key_phrase   = enc_util.bytes2phrase(unsplit_key)
    # print(param_phrase)


@cli.command()
def verify_key(email: str) -> None:
    pass


@cli.command()
@_email_option
@_kdf_param_id_option
def derive_key(email: str, kdf_param_id=DEFAULT_PARAM_ID) -> None:
    """Derive a key for an existing secret (brainkey).

    You should avoid generating your own brainkey, as humans are
    notorious for generating data that can easilly be guessed by an
    attacker.
    """
    if sys.stdin.isatty():
        secret_text = click.prompt("Enter your secret")
    else:
        secret_text = sys.stdin.read()

    if kdf_param_id is None:
        kdf_param_id = PARAM_CTX.default_param_id

    if kdf_param_id not in params.PARAM_CONFIGS_BY_ID:
        err_msg = (
            f"Invalid argument '{kdf_param_id}' for -p/--kdf-param-id."
            f"\n\n\tUse 'ssk kdf-info' to see valid choices."
        )
        raise click.BadOptionUsage("--kdf-param-id", err_msg)

    secret_data = secret_text.encode("utf-8")
    unsplit_key    = _derive_key(secret_data, email, kdf_param_id)
    key_phrase = enc_util.bytes2phrase(unsplit_key)

    click.echo("\n")
    click.echo(key_phrase)


# def split_key():
# def join_key():
