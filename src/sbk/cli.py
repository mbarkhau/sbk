#!/usr/bin/env python
# This file is part of the SBK project
# https://gitlab.com/mbarkhau/sbk
#
# Copyright (c) 2019 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT

"""CLI/Imperative shell for SBK."""

import os
import typing as typ
import logging
import pathlib as pl
import tempfile
import subprocess as sp

import click
import click_repl

import sbk

from . import kdf
from . import cli_io
from . import params
from . import shamir
from . import cli_util
from . import enc_util
from . import electrum_mnemonic

# To enable pretty tracebacks:
#   echo "export ENABLE_BACKTRACE=1;" >> ~/.bashrc
if os.environ.get('NOPYTB') is None and os.environ.get('ENABLE_BACKTRACE') == '1':
    try:
        import backtrace

        backtrace.hook(align=True, strip_path=True, enable_on_envvar_only=True)
    except ImportError:
        pass


log = logging.getLogger(__name__)


def urandom(size: int) -> bytes:
    if os.getenv('SBK_DEBUG_RANDOM') == 'DANGER':
        # https://xkcd.com/221/
        return b"4" * size
    else:
        return os.urandom(size)


click.disable_unicode_literals_warning = True


# NOTE mb: Wrappers for click funtions. The bool return
#   value enables the idom: `yes_all or clear`


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
    msg = message.strip() + " "
    click.prompt(msg, default="", show_choices=False, show_default=False, prompt_suffix="")
    return False


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


SHARE_TITLE = r"Step 1 of 4: Copy Share {share_no}/{num_shares}"

SALT_TITLE = r"Step 2 of 4: Copy Salt"

BRAINKEY_TITLE = r"Step 3 of 4: Copy Brainkey"

VALIDATION_TITLE = r"Step 4 of 4: Validation"


SALT_INFO_TEXT = """
You will need the salt to load your wallet with your brainkey. Please
write the salt down in clear writing and keep it in a secure location.

"""

SALT_PROMPT = "When you have copied the Salt, press enter to continue "

SBK_KEYGEN_TEXT = r"""
The Master Key is derived using the computationally and memory
intensive Argon2 KDF (Key Derivation Function). This ensures that your
brainkey is secure even if an attacker has access to the salt.

    (Salt + Brainkey) -> Master Key
"""

SBK_KEYGEN_PROMPT = "Key generation complete, press enter to continue "


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
When you have copied Share {share_no}/{num_shares}, press enter to continue.
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

When you have copied your "Brainkey", press enter to continue
"""

KDF_PARALLELISM_HELP = "Argon2 KDF Parallelism (Number of threads)"
KDF_MEMORY_COST_HELP = "Argon2 KDF Memory Cost (MB)"
KDF_TIME_COST_HELP   = "Argon2 KDF Time Cost (iterations)"


_kdf_parallelism_option = click.option('-p', '--parallelism', type=int, help=KDF_PARALLELISM_HELP)

_kdf_memory_cost_option = click.option('-m', '--memory-cost', type=int, help=KDF_MEMORY_COST_HELP)

_kdf_time_cost_option = click.option('-t', '--time-cost', type=int, help=KDF_TIME_COST_HELP)


DEFAULT_THRESHOLD = 3

DEFAULT_NUM_SHARES = 5

DEFAULT_SCHEME = f"{DEFAULT_THRESHOLD}of{DEFAULT_NUM_SHARES}"

SCHEME_OPTION_HELP = "Threshold and total Number of shares (format: TofN)"

_scheme_option = click.option(
    '-s', '--scheme', type=str, default=DEFAULT_SCHEME, show_default=True, help=SCHEME_OPTION_HELP,
)


NUM_SHARES_OPTION_HELP = "Number of shares generate"

_num_shares_option = click.option(
    '-n',
    '--num-shares',
    type=int,
    default=DEFAULT_NUM_SHARES,
    show_default=True,
    help=NUM_SHARES_OPTION_HELP,
)


BRAINKEY_LEN_OPTION_HELP = "Length of the Brainkey (in words/bytes)"

_brainkey_len_option = click.option(
    '-b',
    '--brainkey-len',
    type=int,
    default=params.DEFAULT_BRAINKEY_LEN,
    show_default=True,
    help=BRAINKEY_LEN_OPTION_HELP,
)


YES_ALL_OPTION_HELP = "Enable non-interactive mode"

_yes_all_option = click.option(
    '-y', '--yes-all', type=bool, is_flag=True, default=False, help=YES_ALL_OPTION_HELP
)


NON_SEGWIT_OPTION_HELP = "Create a non-segwit/legacy wallet"

_non_segwit_option = click.option(
    '--non-segwit', type=bool, is_flag=True, default=False, help=NON_SEGWIT_OPTION_HELP
)


DEFAULT_WALLET_NAME = "disabled"

WALLET_NAME_OPTION_HELP = "Wallet name"

_wallet_name_option = click.option(
    '--wallet-name',
    type=str,
    default=DEFAULT_WALLET_NAME,
    show_default=True,
    help=WALLET_NAME_OPTION_HELP,
)


SHOW_SEED_OPTION_HELP = "Show wallet seed. Don't load electrum wallet"

_show_seed_option = click.option(
    '--show-seed', type=bool, is_flag=True, default=False, help=SHOW_SEED_OPTION_HELP
)


ONLINE_MODE_OPTION_HELP = "Start electrum gui in online mode (--offline is the default)"

_online_mode_option = click.option(
    "-o", '--online-mode', type=bool, is_flag=True, default=False, help=ONLINE_MODE_OPTION_HELP
)


Salt      = bytes  # prefixed with ParamConfig
BrainKey  = bytes
MasterKey = bytes


def _derive_key(
    param_cfg  : params.ParamConfig,
    salt       : Salt,
    brainkey   : BrainKey,
    label      : str,
    wallet_name: str = DEFAULT_WALLET_NAME,
) -> MasterKey:
    eta_sec          = params.estimate_param_cost(param_cfg.kdf_params)
    hash_len         = param_cfg.master_key_len
    wallet_name_data = wallet_name.encode('utf-8')

    kdf_kwargs = {
        'salt_data'  : salt,
        'secret_data': brainkey + wallet_name_data,
        'kdf_params' : param_cfg.kdf_params,
        'hash_len'   : hash_len,
    }

    KDFThread  = cli_util.EvalWithProgressbar[bytes]
    kdf_thread = KDFThread(target=kdf.derive_key, kwargs=kdf_kwargs)
    kdf_thread.start_and_wait(eta_sec, label)
    master_key = kdf_thread.retval
    return master_key


def _show_secret(label: str, data: bytes, data_type: str) -> None:
    output_lines = cli_io.format_secret_lines(data_type, data)
    len_padding  = max(map(len, output_lines))

    echo(f"{label:^{len_padding}}")
    echo()
    echo("\n".join(output_lines) + "\n\n")


@click.group()
def cli() -> None:
    """CLI for SBK v201906.0001-alpha."""


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
    parallelism: typ.Optional[kdf.NumThreads] = None,
    memory_cost: typ.Optional[kdf.MebiBytes ] = None,
    time_cost  : typ.Optional[kdf.Iterations] = None,
) -> None:
    """Show info for each available parameter config."""
    kdf_params = params.get_default_params()
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

            eta = params.estimate_param_cost(test_params)
            echo(f"   {prefix} : {round(eta):>4} sec {suffix}")
        m = int(m / 1.5)
    return


@cli.command()
@_kdf_parallelism_option
@_kdf_memory_cost_option
@_kdf_time_cost_option
def kdf_test(
    parallelism: typ.Optional[kdf.NumThreads] = None,
    memory_cost: typ.Optional[kdf.MebiBytes ] = None,
    time_cost  : typ.Optional[kdf.Iterations] = None,
) -> None:
    kdf_params = params.get_default_params()
    kdf_params = kdf_params._replace_any(p=parallelism, m=memory_cost, t=time_cost)
    params_str = f"-p={kdf_params.p:<3} -m={kdf_params.m:<5} -t={kdf_params.t:<4}"

    echo()
    echo(f"Parameters after rounding: {params_str}")
    echo()

    eta = params.estimate_param_cost(kdf_params)
    echo(f"Estimated duration: {round(eta):>4} sec")
    MeasurementThread  = cli_util.EvalWithProgressbar[params.Measurement]
    measurement_thread = MeasurementThread(target=params.measure, args=(kdf_params,))
    measurement_thread.start_and_wait(eta_sec=eta, label="Evaluating KDF")
    measurement = measurement_thread.retval
    echo(f"Actual duration   : {round(measurement.duration):>4} sec")


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


def _validate_data(data_type: str, header_text: str, data: bytes) -> None:
    full_header_text = VALIDATION_TITLE + "\n\n\t" + header_text
    while True:
        recovered_data = cli_io.prompt(data_type, full_header_text, data_len=len(data))
        if data == recovered_data:
            return
        else:
            anykey_confirm("Invalid input. Data mismatch.")


def _validate_copies(salt: Salt, brainkey: BrainKey, shares: typ.Sequence[shamir.Share]) -> bool:
    header_text = 'Validate your copy of the "Salt"'
    _validate_data(cli_io.DATA_TYPE_SALT, header_text, salt)

    header_text = 'Validate your memorized "Brainkey"'
    _validate_data(cli_io.DATA_TYPE_BRAINKEY, header_text, brainkey)

    for i, share_data in enumerate(shares):
        share_no    = i + 1
        header_text = f"Validate your copy of Share {share_no} of {len(shares)}"
        _validate_data(cli_io.DATA_TYPE_SHARE, header_text, share_data)

    return True


def _validated_param_data(param_cfg: params.ParamConfig) -> bytes:
    # validate encoding round trip before we use param_cfg
    param_cfg_data    = params.param_cfg2bytes(param_cfg)
    decoded_param_cfg = params.bytes2param_cfg(param_cfg_data, param_cfg.sys_info)
    checks            = {
        'threshold'   : param_cfg.threshold    == decoded_param_cfg.threshold,
        'version'     : param_cfg.version      == decoded_param_cfg.version,
        'kdf_params'  : param_cfg.kdf_params   == decoded_param_cfg.kdf_params,
        'brainkey_len': param_cfg.brainkey_len == decoded_param_cfg.brainkey_len,
        'salt_len'    : param_cfg.raw_salt_len == decoded_param_cfg.raw_salt_len,
    }
    bad_checks = [name for name, is_ok in checks.items() if not is_ok]
    if any(bad_checks):
        raise click.Abort(f"Integrity error -  Bad parameter fields: {bad_checks}")

    return param_cfg_data


def _show_created_data(
    yes_all  : bool,
    param_cfg: params.ParamConfig,
    salt     : Salt,
    brainkey : BrainKey,
    shares   : typ.List[shamir.Share],
) -> None:
    yes_all or clear()
    yes_all or echo(SECURITY_WARNING_TEXT.strip())
    yes_all or anykey_confirm(SECURITY_WARNING_PROMPT)

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

        share_label = f"Share {share_no}/{param_cfg.num_shares}"
        _show_secret(share_label, share_data, cli_io.DATA_TYPE_SHARE)

        share_prompt = SHARE_PROMPT.format(**info)
        yes_all or anykey_confirm(share_prompt)

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


@cli.command()
@_scheme_option
@_non_segwit_option
@_brainkey_len_option
@_yes_all_option
@_kdf_parallelism_option
@_kdf_memory_cost_option
@_kdf_time_cost_option
def create(
    scheme      : str  = DEFAULT_SCHEME,
    brainkey_len: int  = params.DEFAULT_BRAINKEY_LEN,
    non_segwit  : bool = False,
    yes_all     : bool = False,
    parallelism : typ.Optional[kdf.NumThreads] = None,
    memory_cost : typ.Optional[kdf.MebiBytes ] = None,
    time_cost   : typ.Optional[kdf.Iterations] = None,
) -> None:
    """Generate a new salt, brainkey and shares."""
    threshold, num_shares = cli_util.parse_scheme(scheme)
    _validate_brainkey_len(brainkey_len)
    is_segwit = not non_segwit

    param_cfg = params.init_param_config(
        brainkey_len=brainkey_len,
        threshold=threshold,
        num_shares=num_shares,
        is_segwit=is_segwit,
        kdf_parallelism=parallelism,
        kdf_memory_cost=memory_cost,
        kdf_time_cost=time_cost,
    )

    param_cfg_data = _validated_param_data(param_cfg)
    raw_salt       = urandom(param_cfg.raw_salt_len)
    salt           = param_cfg_data + raw_salt
    brainkey       = urandom(param_cfg.brainkey_len)

    shares = list(shamir.split(param_cfg, raw_salt, brainkey))

    recoverd_salt, recovered_brainkey = shamir.join(param_cfg, shares)

    assert recoverd_salt      == raw_salt
    assert recovered_brainkey == brainkey

    # verify that derivation works before we show anything
    _derive_key(param_cfg, salt, brainkey, label="Deriving Master Key")

    _show_created_data(yes_all, param_cfg, salt, brainkey, shares)

    yes_all or _validate_copies(salt, brainkey, shares)


@cli.command()
def recover_salt() -> None:
    """Recover a partially readable Salt."""
    param_and_salt_data = cli_io.prompt(cli_io.DATA_TYPE_SALT)
    param_cfg_data      = param_and_salt_data[: params.PARAM_CFG_LEN]
    param_cfg           = params.bytes2param_cfg(param_cfg_data)

    echo()
    echo("Decoded parameters".center(35))
    echo()
    echo(f"    salt length    : {param_cfg.raw_salt_len} bytes")
    echo(f"    brainkey length: {param_cfg.brainkey_len} bytes")
    echo(f"    share length   : {param_cfg.share_len} bytes")
    echo(f"    threshold      : {param_cfg.threshold}")
    echo(f"    kdf parallelism: {param_cfg.kdf_params.p}")
    echo(f"    kdf memory cost: {param_cfg.kdf_params.m} MiB")
    echo(f"    kdf time cost  : {param_cfg.kdf_params.t} Iterations")


@cli.command()
def recover() -> None:
    """Recover Salt and BrainKey by combining Shares."""
    param_cfg: typ.Optional[params.ParamConfig] = None
    shares   : typ.List[shamir.Share] = []

    while param_cfg is None or len(shares) < param_cfg.threshold:
        share_len: typ.Optional[int] = None
        share_num = len(shares) + 1

        if param_cfg is None:
            header_text = f"Enter Share {share_num}."
        else:
            header_text = f"Enter Share {share_num} of {param_cfg.threshold}."
            share_len   = param_cfg.share_len

        share = cli_io.prompt(cli_io.DATA_TYPE_SHARE, header_text=header_text, data_len=share_len)
        shares.append(share)

        param_cfg_data = share[: params.PARAM_CFG_LEN]
        cur_param_cfg  = params.bytes2param_cfg(param_cfg_data)
        if param_cfg is None:
            param_cfg = cur_param_cfg
        elif param_cfg != cur_param_cfg:
            raise click.Abort("Invalid share. Shares are perhaps for different wallets.")

    raw_salt, brainkey = shamir.join(param_cfg, shares)
    salt = param_cfg_data + raw_salt

    salt_lines     = cli_io.format_secret_lines(cli_io.DATA_TYPE_SALT    , salt)
    brainkey_lines = cli_io.format_secret_lines(cli_io.DATA_TYPE_BRAINKEY, brainkey)

    clear()
    echo("RECOVERED SECRETS".center(50))
    echo()
    echo("Salt".center(50))
    echo()
    echo("\n".join(salt_lines))

    echo()
    echo("Brainkey".center(50))
    echo()
    echo("\n".join(brainkey_lines))


def mk_tmp_wallet_fpath() -> pl.Path:
    tempdir = tempfile.tempdir
    try:
        uid_output = sp.check_output(["id", "-u"])
        uid        = int(uid_output.strip())
        uid_dir    = pl.Path(f"/run/user/{uid}")
        if uid_dir.exists():
            tempdir = str(uid_dir)
    except Exception as ex:
        log.warning(f"Error creating temp directory in /run/user/ : {ex}")

    _fd, wallet_fpath_str = tempfile.mkstemp(prefix="sbk_electrum_wallet_", dir=tempdir)
    wallet_fpath = pl.Path(wallet_fpath_str)
    return wallet_fpath


def _clean_wallet(wallet_fpath: pl.Path) -> None:
    if not os.path.exists(wallet_fpath):
        return

    garbage = os.urandom(4096)
    # On HDDs it may serve some marginal purpose.
    # On SSDs this may be pointless, due to wear leveling.
    size = wallet_fpath.stat().st_size
    with wallet_fpath.open(mode="wb") as fobj:
        for _ in range(0, size, 4096):
            fobj.write(garbage)
    wallet_fpath.unlink()
    assert not wallet_fpath.exists()


@cli.command()
@_wallet_name_option
@_show_seed_option
@_online_mode_option
@_yes_all_option
def load_wallet(
    wallet_name: str  = DEFAULT_WALLET_NAME,
    show_seed  : bool = False,
    online_mode: bool = False,
    yes_all    : bool = False,
) -> None:
    """Open wallet using Salt+Brainkey."""
    yes_all or clear()
    yes_all or echo(SECURITY_WARNING_TEXT)
    yes_all or anykey_confirm(SECURITY_WARNING_PROMPT)

    header_text    = "Enter Salt"
    salt           = cli_io.prompt(cli_io.DATA_TYPE_SALT, header_text=header_text)
    param_cfg_data = salt[: params.PARAM_CFG_LEN]
    param_cfg      = params.bytes2param_cfg(param_cfg_data)
    # raw_salt     = salt[params.PARAM_CFG_LEN:]

    header_text = "Enter Brainkey"
    brainkey    = cli_io.prompt(
        cli_io.DATA_TYPE_BRAINKEY, header_text=header_text, data_len=param_cfg.brainkey_len
    )

    yes_all or echo()
    master_key = _derive_key(
        param_cfg, salt, brainkey, label="Deriving Master Key", wallet_name=wallet_name
    )

    seed_type = 'segwit' if param_cfg.is_segwit else 'standard'

    int_seed    = enc_util.bytes2int(master_key)
    wallet_seed = electrum_mnemonic.seed_raw2phrase(int_seed, seed_type)

    wallet_fpath = mk_tmp_wallet_fpath()

    restore_cmd = ["electrum", "restore", "--wallet", str(wallet_fpath), wallet_seed]
    load_cmd    = ["electrum", "gui"    , "--wallet", str(wallet_fpath)]

    if not online_mode:
        load_cmd.append("--offline")

    if show_seed:
        _clean_wallet(wallet_fpath)
        echo("Electrum commands:")
        echo()
        echo("\t" + " ".join(restore_cmd))
        echo("\t" + " ".join(load_cmd   ))
        echo()
        echo("Electrum wallet seed: " + wallet_seed)
        return

    try:
        wallet_fpath.unlink()
        retcode = sp.call(restore_cmd)
        if retcode != 0:
            cmd_str = " ".join(restore_cmd[:-1] + ["<wallet seed hidden>"])
            raise click.Abort(f"Error calling '{cmd_str}'")

        retcode = sp.call(load_cmd)
        if retcode != 0:
            cmd_str = " ".join(load_cmd)
            raise click.Abort(f"Error calling '{cmd_str}'")
    finally:
        _clean_wallet(wallet_fpath)


@cli.command()
@click.pass_context
def repl(ctx):
    """Start REPL (with completion)."""
    click.echo(cli.get_help(ctx))
    prompt_kwargs = {'message': "sbk> "}
    click_repl.repl(ctx, prompt_kwargs=prompt_kwargs)


if __name__ == '__main__':
    cli()
