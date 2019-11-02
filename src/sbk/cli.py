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
import subprocess as sp

import click
import click_repl

import sbk

from . import gf
from . import kdf
from . import cli_io
from . import params
from . import gf_poly
from . import cli_util
from . import enc_util
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
    gf_poly._rand = random.Random(0)  # type: ignore
    urandom       = debug_urandom
else:
    urandom = os.urandom


click.disable_unicode_literals_warning = True


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


Salt      = bytes
BrainKey  = bytes
Share     = bytes
MasterKey = bytes


def _derive_key(
    param_cfg: params.ParamConfig, salt: Salt, brainkey: BrainKey, label: str
) -> MasterKey:
    eta_sec  = params.estimate_param_cost(param_cfg.sys_info, param_cfg.kdf_params)
    hash_len = param_cfg.master_key_len

    kdf_kwargs = {
        'salt_data'  : salt,
        'secret_data': brainkey,
        'kdf_params' : param_cfg.kdf_params,
        'hash_len'   : hash_len,
    }

    KDFThread  = cli_util.EvalWithProgressbar[bytes]
    kdf_thread = KDFThread(target=kdf.derive_key, kwargs=kdf_kwargs)
    kdf_thread.start_and_wait(eta_sec, label)
    master_key = kdf_thread.retval
    return master_key


SECURITY_WARNING_TEXT = """
Security Warning

Please ensure the following:

 - Only you can currently view your screen.
 - Your computer is not connected to any network.
 - Your computer is booted using a trusted installation of Linux.

For more information on setting up a secure air-gapped system
see: http://tiny.cc/sbk-airgap

                                  █████████████████████████████████
                                  █████████████████████████████████
    █▀▀▀▀▀█ █▄▄▀█▄▀   █▀▀▀▀▀█     ████ ▄▄▄▄▄ █ ▀▀▄ ▀▄███ ▄▄▄▄▄ ████
    █ ███ █   █▀▀█  ▀ █ ███ █     ████ █   █ ███ ▄▄ ██▄█ █   █ ████
    █ ▀▀▀ █ █▀▀█  █ ▄ █ ▀▀▀ █     ████ █▄▄▄█ █ ▄▄ ██ █▀█ █▄▄▄█ ████
    ▀▀▀▀▀▀▀ █ █▄█ █▄▀ ▀▀▀▀▀▀▀     ████▄▄▄▄▄▄▄█ █ ▀ █ ▀▄█▄▄▄▄▄▄▄████
    ██▀ ▄▀▀▄▀██    █▄▀██▀▄ ██     ████  ▄█▀▄▄▀▄  ████ ▀▄  ▄▀█  ████
    █▄▀▄ ▄▀▀ ▄ ▀ ▀██▄ ▄ ██▀ ▀     ████ ▀▄▀█▀▄▄█▀█▄█▄  ▀█▀█  ▄█▄████
    ▀█▀▄ ▀▀ ▀▀ ▀█▄ ▄▀▄██   ▄█     ████▄ ▄▀█▄▄█▄▄█▄ ▀█▀▄▀  ███▀ ████
    ▀▀█ █ ▀ ▀▀ ▄█▀██ █ █▀▀▀ ▀     ████▄▄ █ █▄█▄▄█▀ ▄  █ █ ▄▄▄█▄████
    ▀▀ ▀▀ ▀▀█ ▄ ▀ ▄▀█▀▀▀█ ▄▀▄     ████▄▄█▄▄█▄▄ █▀█▄█▀▄ ▄▄▄ █▀▄▀████
    █▀▀▀▀▀█ ▄▄ ▀▀ ▀▄█ ▀ █▀ ▄▀     ████ ▄▄▄▄▄ █▀▀█▄▄█▄▀ █▄█ ▄█▀▄████
    █ ███ █  ███▄  ██▀▀███▄█      ████ █   █ ██   ▀██  ▄▄   ▀ █████
    █ ▀▀▀ █ █▀▄▀  ▄▀██▄▄█  ▀▀     ████ █▄▄▄█ █ ▄▀▄██▀▄  ▀▀ ██▄▄████
    ▀▀▀▀▀▀▀ ▀▀▀▀▀   ▀▀   ▀  ▀     ████▄▄▄▄▄▄▄█▄▄▄▄▄███▄▄███▄██▄████
                                  █████████████████████████████████
                                  ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
"""


SECURITY_WARNING_PROMPT = """
Press enter to continue
"""


PARAMS_TITLE = r'Step 1 of 5: Copy "Parameters"'

SALT_TITLE = r'Step 2 of 5: Copy your "Salt".'

BRAINKEY_TITLE = r"Step 3 of 5: Copy Brainkey."

SHARE_TITLE = r"Step 4 of 5: Copy Share {share_no}/{num_shares}."

RECOVERY_VALIDATION_TITLE = r"Step 5 of 5: Validation"

PARAMS_INFO_TEXT = """
The "Parameters" encode values needed to recover your secrets. They are:

    - The threshold of Shares required for recovery
    - The length of the Brainkey and Salt
    - The cost parameters for the Argon2 KDF
"""


SALT_INFO_TEXT = """
You will need the salt to load your wallet with your brainkey. Please
write the salt down in clear writing and keep it in a secure location.

"""

PARAMS_PROMPT = 'Press enter when you have copied the "Parameters"'

SALT_PROMPT = 'Press enter when you have copied this "Salt"'

SBK_KEYGEN_TEXT = r"""
The Master Key is derived using the computationally and memory
intensive Argon2 KDF (Key Derivation Function). This ensures that your
brainkey is secure even if an attacker has access to the salt.

    (Salt + Brainkey) -> Master Key
"""

SBK_KEYGEN_PROMPT = "Key generation complete, press enter to continue"


SHARE_INFO_TEXT = r"""
Keep this "Share" hidden in a safe place or give it to a trustee
for them to keep safe. A trustee must trustworthy in two senses:

  1. They are trusted to not collude with others and steal from you.
  2. They are competent to keep this "Share" safe and secure.
"""

RECOVERY_TEXT = r"""
Your "Master Key" is recovered by collecting a minimum of
{threshold} shares.

                 Split Master Key
          Split                    . Join
               \.-> Share 1 -./
   Master Key  -O-> Share 2  +-> Master Key
                '-> Share 3 -'

   argon2_kdf(Master Key, Wallet Name) -> Wallet
"""

SHARE_PROMPT = r"""
Please make a physical copy of Share {share_no}/{num_shares}.
"""

BRAINKEY_INFO_TEXT = r"""
Your "Salt" and "Brainkey" are combined to produce your wallet seed.
As long as you have access to your "Salt" and as long as you can
remember your "Brainkey", you will be able to recover your wallet.

It is important that you
 - memorize your brainkey very well,
 - regularly remember it so you don't forget it,
 - never tell it to anybody, ever!
"""

# Salt + Brainkey + Wallet Name -> Wallet

BRAINKEY_LAST_CHANCE_WARNING_TEXT = """
This is the last time your brainkey will be shown.

If you don't yet feel confident in your memory:

 1. Write down the brainkey only as a temporary memory aid.
 2. Do not use the generated wallet until you feel
    comfortable that you have have memorized your brainkey.
 3. Destroy the memory aid before you use the wallet.

Press enter to hide your brainkey and to continue
"""

KDF_PARALLELISM_HELP = "Argon2 KDF Parallelism (Number of threads)"
KDF_MEMORY_COST_HELP = "Argon2 KDF Memory Cost (MB)"
KDF_TIME_COST_HELP   = "Argon2 KDF Time Cost (iterations)"


_kdf_parallelism_option = click.option('-p', '--parallelism', type=int, help=KDF_PARALLELISM_HELP)

_kdf_memory_cost_option = click.option('-m', '--memory-cost', type=int, help=KDF_MEMORY_COST_HELP)

_kdf_time_cost_option = click.option('-t', '--time-cost', type=int, help=KDF_TIME_COST_HELP)


DEFAULT_THRESHOLD = 2

DEFAULT_NUM_SHARES = 3

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

DEFAULT_BRAINKEY_LEN = 8

_brainkey_len_option = click.option(
    '-b',
    '--brainkey-len',
    type=int,
    default=DEFAULT_BRAINKEY_LEN,
    show_default=True,
    help=_clean_help(BRAINKEY_LEN_OPTION_HELP),
)


SALT_LEN_OPTION_HELP = "Length of the Salt (in words/bytes)"

DEFAULT_SALT_LEN = 20

_salt_len_option = click.option(
    '-s',
    '--salt-len',
    type=int,
    default=DEFAULT_SALT_LEN,
    show_default=True,
    help=_clean_help(SALT_LEN_OPTION_HELP),
)


SHARE_LEN_OPTION_HELP = "Length of the share (in words/bytes) "

SHARE_PADDING = 4

DEFAULT_SHARE_LEN = DEFAULT_SALT_LEN + DEFAULT_BRAINKEY_LEN + SHARE_PADDING

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


def _show_secret(label: str, data: bytes, data_type: str) -> None:
    output_lines = cli_io.format_secret_lines(data_type, data)

    len_padding = max(map(len, output_lines))

    echo(f"{label:^{len_padding}}")
    echo()
    echo("\n".join(output_lines) + "\n\n")


def _split_into_shares(
    param_cfg: params.ParamConfig, salt: Salt, brainkey: BrainKey, threshold: int, num_shares: int,
) -> typ.Iterable[Share]:
    master_key = salt + brainkey
    secret_int = enc_util.bytes2int(master_key)

    field    = gf.GFNum.field(param_cfg.prime)
    gfpoints = gf_poly.split(
        field=field, threshold=threshold, num_shares=num_shares, secret=secret_int
    )
    for gfpoint in gfpoints:
        share_data = enc_util.gfpoint2bytes(gfpoint)
        assert len(share_data) == param_cfg.share_len, len(share_data)
        yield share_data


@click.group()
def cli() -> None:
    """CLI for SBK."""


@cli.command()
@click.version_option(version="v201906.0001-alpha")
def version() -> None:
    """Show version number."""
    echo(f"SBK version: {sbk.__version__}")


@cli.command()
@_kdf_parallelism_option
@_kdf_memory_cost_option
@_kdf_time_cost_option
def kdf_info(
    parallelism: typ.Optional[params.NumThreads] = None,
    memory_cost: typ.Optional[params.MebiBytes ] = None,
    time_cost  : typ.Optional[params.Iterations] = None,
) -> None:
    """Show info for each available parameter config."""
    sys_info   = params.load_sys_info()
    kdf_params = params.get_default_params(sys_info)
    kdf_params = kdf_params._replace_any(p=parallelism, m=memory_cost, t=time_cost)

    echo("Estimated durations for KDF parameter choices")
    echo()

    high_m = kdf_params.m
    high_t = kdf_params.t * 5
    m      = high_m

    for _ in range(3):
        t = high_t
        for _ in range(9):
            t = int(t / 1.5)

            test_params = kdf_params._replace_any(m=int(m), t=int(t))

            suffix = "<- default" if test_params == kdf_params else ""
            prefix = f"-p={test_params.p:<3} -m={test_params.m:<5} -t={test_params.t:<4}"

            eta = params.estimate_param_cost(sys_info, test_params)
            echo(f"   {prefix} : {round(eta):>4} sec {suffix}")
        m = int(m / 1.5)
    return


@cli.command()
@_kdf_parallelism_option
@_kdf_memory_cost_option
@_kdf_time_cost_option
def kdf_test(
    parallelism: typ.Optional[params.NumThreads] = None,
    memory_cost: typ.Optional[params.MebiBytes ] = None,
    time_cost  : typ.Optional[params.Iterations] = None,
) -> None:
    sys_info   = params.load_sys_info()
    kdf_params = params.get_default_params(sys_info)
    kdf_params = kdf_params._replace_any(p=parallelism, m=memory_cost, t=time_cost)
    params_str = f"-p={kdf_params.p:<3} -m={kdf_params.m:<5} -t={kdf_params.t:<4}"

    echo()
    echo(f"Parameters after rounding: {params_str}")
    echo()

    eta = params.estimate_param_cost(sys_info, kdf_params)
    echo(f"Estimated duration: {round(eta):>4} sec")
    MeasurementThread  = cli_util.EvalWithProgressbar[params.Measurement]
    measurement_thread = MeasurementThread(target=params.measure, args=(kdf_params,))
    measurement_thread.start_and_wait(eta_sec=eta, label="Evaluating KDF")
    measurement = measurement_thread.retval
    echo(f"Actual auration   : {round(measurement.duration):>4} sec")


def _validate_salt_len(salt_len: int) -> None:
    if salt_len < 4:
        echo("Minimum value for -s/--salt-len is 4")
        raise click.Abort()

    if salt_len > 60:
        echo("Maximum value for -s/--salt-len is 60")
        raise click.Abort()

    if salt_len % 4 != 0:
        echo(f"Invalid value -s/--salt-len={salt_len} must be a multiple of 4")
        raise click.Abort()


def _validate_brainkey_len(brainkey_len: int) -> None:
    if brainkey_len < 2:
        echo("Input Error: Minimum value for -b/--brainkey-len is 2")
        raise click.Abort()

    if brainkey_len > 30:
        echo("Input Error: Maximum value for -b/--brainkey-len is 30")
        raise click.Abort()

    if brainkey_len % 2 != 0:
        echo("Input Error: Parameter -b/--brainkey-len must be a multiple of 2")
        raise click.Abort()


def _validate_data(data_type: str, data: bytes, header_text: str) -> None:
    full_header_text = RECOVERY_VALIDATION_TITLE + "\n\n\t" + header_text
    while True:
        recovered_data = cli_io.prompt(data_type, len(data), full_header_text)
        if data == recovered_data:
            return
        else:
            anykey_confirm("Invalid input. Data mismatch.")


def _validate_copies(
    param_cfg: params.ParamConfig, salt: Salt, brainkey: BrainKey, shares: typ.Sequence[Share]
) -> bool:
    param_cfg_data = params.param_cfg2bytes(param_cfg)
    title_text     = 'Validate your copy of the "Parameters"'
    _validate_data(cli_io.DATA_TYPE_PARAM_CFG, param_cfg_data, title_text)

    title_text = 'Validate your copy of the "Salt"'
    _validate_data(cli_io.DATA_TYPE_SALT, salt, title_text)

    title_text = 'Validate your memorized "Brainkey"'
    _validate_data(cli_io.DATA_TYPE_BRAINKEY, brainkey, title_text)

    title_text = 'Validate your copy of the "Salt"'
    _validate_data(cli_io.DATA_TYPE_SALT, salt, title_text)

    for i, share_data in enumerate(shares):
        share_no   = i + 1
        title_text = f"Validate your copy of Share {share_no}/{len(shares)}"
        _validate_data(cli_io.DATA_TYPE_SHARE, share_data, title_text)

    return True


def _validate_params(param_cfg: params.ParamConfig, param_cfg_data: bytes) -> None:
    # validate encoding round trip before we use param_cfg
    decoded_param_cfg    = params.bytes2param_cfg(param_cfg_data, param_cfg.sys_info)
    is_param_recoverable = (
        param_cfg.threshold        == decoded_param_cfg.threshold
        and param_cfg.version      == decoded_param_cfg.version
        and param_cfg.kdf_params   == decoded_param_cfg.kdf_params
        and param_cfg.brainkey_len == decoded_param_cfg.brainkey_len
        and param_cfg.salt_len     == decoded_param_cfg.salt_len
    )

    if not is_param_recoverable:
        raise Exception("Integrity error. Aborting to prevent use of invald salt.")


def _show_created_data(
    yes_all  : bool,
    param_cfg: params.ParamConfig,
    salt     : Salt,
    brainkey : BrainKey,
    shares   : typ.List[Share],
) -> None:
    param_cfg_data = params.param_cfg2bytes(param_cfg)
    _validate_params(param_cfg, param_cfg_data)

    yes_all or clear()
    yes_all or echo(SECURITY_WARNING_TEXT.strip())
    yes_all or anykey_confirm(SECURITY_WARNING_PROMPT)

    yes_all or clear()
    echo(PARAMS_TITLE)
    echo()
    echo(PARAMS_INFO_TEXT)
    echo()

    _show_secret("Parameters", param_cfg_data, cli_io.DATA_TYPE_PARAM_CFG)

    yes_all or anykey_confirm(PARAMS_PROMPT)

    # Salt
    yes_all or clear()

    echo(SALT_TITLE)
    echo()

    echo(SALT_INFO_TEXT)

    _show_secret("Salt", salt, cli_io.DATA_TYPE_SALT)

    yes_all or anykey_confirm(SALT_PROMPT)

    # Brainkey
    yes_all or clear()
    echo(BRAINKEY_TITLE.strip())
    echo(BRAINKEY_INFO_TEXT)

    yes_all or anykey_confirm("Press enter to show your brainkey")

    echo()

    _show_secret("Brainkey", brainkey, cli_io.DATA_TYPE_BRAINKEY)

    yes_all or anykey_confirm(BRAINKEY_LAST_CHANCE_WARNING_TEXT)

    # Shares
    for i, share_data in enumerate(shares):
        share_no = i + 1
        yes_all or clear()
        info = {
            'share_no'  : share_no,
            'threshold' : param_cfg.threshold,
            'num_shares': param_cfg.num_shares,
        }
        share_title = SHARE_TITLE.format(**info).strip()
        echo(share_title)
        echo(SHARE_INFO_TEXT)

        label = f"Secret Share {share_no}/{param_cfg.num_shares}"
        _show_secret(label, share_data, cli_io.DATA_TYPE_SALT)

        share_prompt = SHARE_PROMPT.format(**info)
        yes_all or anykey_confirm(share_prompt)


@cli.command()
@_scheme_option
@_salt_len_option
@_brainkey_len_option
@_yes_all_option
@_kdf_parallelism_option
@_kdf_memory_cost_option
@_kdf_time_cost_option
def create(
    scheme      : str  = DEFAULT_SCHEME,
    salt_len    : int  = DEFAULT_SALT_LEN,
    brainkey_len: int  = DEFAULT_BRAINKEY_LEN,
    yes_all     : bool = False,
    parallelism : typ.Optional[params.NumThreads] = None,
    memory_cost : typ.Optional[params.MebiBytes ] = None,
    time_cost   : typ.Optional[params.Iterations] = None,
) -> None:
    """Generate a new salt, brainkey and shares."""
    _validate_salt_len(salt_len)
    _validate_brainkey_len(brainkey_len)

    threshold, num_shares = cli_util.parse_scheme(scheme)

    param_cfg = params.init_param_config(
        salt_len, brainkey_len, threshold, num_shares, parallelism, memory_cost, time_cost,
    )

    assert param_cfg.threshold  == threshold
    assert param_cfg.num_shares == num_shares

    salt     = urandom(param_cfg.salt_len)
    brainkey = urandom(param_cfg.brainkey_len)

    shares = list(
        _split_into_shares(param_cfg, salt, brainkey, threshold=threshold, num_shares=num_shares)
    )

    recoverd_salt, recovered_brainkey = _join_shares(param_cfg, shares)

    assert recoverd_salt      == salt
    assert recovered_brainkey == brainkey

    # verify that derivation works before we show anything
    _derive_key(param_cfg, salt, brainkey, label="Deriving Master Key")

    _show_created_data(yes_all, param_cfg, salt, brainkey, shares)

    yes_all or _validate_copies(param_cfg, salt, brainkey, shares)


@cli.command()
def recover_params() -> None:
    cli_io.prompt(cli_io.DATA_TYPE_PARAM_CFG, data_len=4)


@cli.command()
@click.option('--salt-len', type=int, help=_clean_help(SALT_LEN_OPTION_HELP))
def recover_salt(salt_len: int = None) -> None:
    """Recover a partially readable Salt."""
    if salt_len is None:
        param_cfg_data = cli_io.prompt(cli_io.DATA_TYPE_PARAM_CFG, data_len=4)
        param_cfg      = params.bytes2param_cfg(param_cfg_data)
        salt_len       = param_cfg.salt_len

    key_len = salt_len
    if key_len >= 4 and key_len % 4 == 0:
        cli_io.prompt(cli_io.DATA_TYPE_SALT, data_len=key_len)
    else:
        click.echo(f"Invalid -s/--salt-len={key_len} must be divisible by 4.")
        raise click.Abort()


@cli.command()
@_share_len_option
def recover_share(share_len: int = DEFAULT_SHARE_LEN) -> None:
    """Recover a partially readable share."""
    key_len = share_len
    if key_len >= 4 and key_len % 4 == 0:
        cli_io.prompt(cli_io.DATA_TYPE_SHARE, data_len=key_len)
    else:
        click.echo(f"Invalid --share-len={key_len} must be divisible by 4.")
        raise click.Abort()


def _join_shares(
    param_cfg: params.ParamConfig, shares: typ.List[Share]
) -> typ.Tuple[Salt, BrainKey]:
    field  = gf.GFNum.field(order=param_cfg.prime)
    points = tuple(enc_util.bytes2gfpoint(p, field) for p in shares)

    secret_int = gf_poly.join(field, param_cfg.threshold, points)
    master_key = enc_util.int2bytes(secret_int)

    assert len(master_key) == param_cfg.master_key_len

    salt_end = param_cfg.salt_len
    bk_start = param_cfg.salt_len

    salt     = master_key[:salt_end]
    brainkey = master_key[bk_start:]

    assert len(salt    ) == param_cfg.salt_len
    assert len(brainkey) == param_cfg.brainkey_len
    return (salt, brainkey)


@cli.command()
@_yes_all_option
def join_shares() -> None:
    """Recover BrainKey and Salt by combining Shares."""
    header_text    = "Enter Parameters"
    param_cfg_data = cli_io.prompt(cli_io.DATA_TYPE_PARAM_CFG, 4, header_text)
    param_cfg      = params.bytes2param_cfg(param_cfg_data)

    shares: typ.List[Share] = []
    while len(shares) < param_cfg.threshold:
        share_num   = len(shares) + 1
        header_text = f"Enter Share {share_num} of {param_cfg.threshold}."
        share       = cli_io.prompt(cli_io.DATA_TYPE_SHARE, param_cfg.share_len, header_text)
        shares.append(share)

    salt, brainkey = _join_shares(param_cfg, shares)
    salt_lines     = cli_io.format_secret_lines(cli_io.DATA_TYPE_SALT    , salt)
    brainkey_lines = cli_io.format_secret_lines(cli_io.DATA_TYPE_BRAINKEY, brainkey)

    clear()

    echo("Salt")
    echo("\n".join(salt_lines))

    echo("Brainkey")
    echo("\n".join(brainkey_lines))


@cli.command()
@_yes_all_option
@_non_segwit_option
def load_wallet(yes_all: bool = False, non_segwit: bool = False) -> None:
    """Open wallet using Salt+Brainkey or Shares."""
    yes_all or clear()
    yes_all or echo(SECURITY_WARNING_TEXT)
    yes_all or anykey_confirm(SECURITY_WARNING_PROMPT)

    header_text    = "Enter Parameters"
    param_cfg_data = cli_io.prompt(cli_io.DATA_TYPE_PARAM_CFG, 4, header_text)
    param_cfg      = params.bytes2param_cfg(param_cfg_data)

    header_text = "Enter Salt"
    salt        = cli_io.prompt(cli_io.DATA_TYPE_SALT, param_cfg.salt_len, header_text)

    header_text = "Enter Brainkey"
    brainkey    = cli_io.prompt(cli_io.DATA_TYPE_BRAINKEY, param_cfg.brainkey_len, header_text)

    master_key = _derive_key(param_cfg, salt, brainkey, label="Deriving Master Key")

    seed_type = 'standard' if non_segwit else 'segwit'

    int_seed    = enc_util.bytes2int(master_key)
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
