#!/usr/bin/env python3
# This file is part of the SBK project
# https://github.com/mbarkhau/sbk
#
# Copyright (c) 2019-2022 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT

"""CLI/Imperative shell for SBK."""

# pylint: disable=expression-not-assigned; because of idom: yes_all or ...

import sys
import time
import logging
from typing import Any
from typing import Set
from typing import Dict
from typing import List
from typing import Type
from typing import Tuple
from typing import Union
from typing import Generic
from typing import NewType
from typing import TypeVar
from typing import Callable
from typing import Iterable
from typing import Iterator
from typing import Optional
from typing import Protocol
from typing import Sequence
from typing import Generator
from typing import NamedTuple

import click

from . import cli_io
from . import shamir
from . import sys_info
from . import ui_common
from . import parameters
from . import sbk_random
from . import common_types as ct

try:
    import pretty_traceback

    pretty_traceback.install(envvar='ENABLE_PRETTY_TRACEBACK')
except ImportError:
    pass  # no need to fail because of missing dev dependency


click.disable_unicode_literals_warning = True  # type: ignore[attr-defined]


logger = logging.getLogger("sbk.cli")


class LogConfig(NamedTuple):
    fmt: str
    lvl: int


LOG_FORMAT_DEFAULT = "%(levelname)-7s - %(message)s"

LOG_FORMAT_VERBOSE = "%(asctime)s.%(msecs)03d %(levelname)-7s %(name)-16s - %(message)s"


def _parse_logging_config(verbosity: int) -> LogConfig:
    if verbosity == 0:
        return LogConfig(LOG_FORMAT_DEFAULT, logging.WARNING)
    elif verbosity == 1:
        return LogConfig(LOG_FORMAT_VERBOSE, logging.INFO)
    else:
        assert verbosity >= 2
        return LogConfig(LOG_FORMAT_VERBOSE, logging.DEBUG)


_PREV_VERBOSITY: int = -1


def _configure_logging(verbosity: int = 0) -> None:
    # pylint: disable=global-statement
    global _PREV_VERBOSITY

    if verbosity <= _PREV_VERBOSITY:
        # allow function to be called multiple times
        return

    _PREV_VERBOSITY = verbosity

    # remove previous logging handlers
    for handler in list(logging.root.handlers):
        logging.root.removeHandler(handler)

    log_cfg = _parse_logging_config(verbosity)
    logging.basicConfig(level=log_cfg.lvl, format=log_cfg.fmt, datefmt="%Y-%m-%dT%H:%M:%S")


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


def get_validated_salt_phrase(salt_phrase: Optional[str]) -> bytes:
    if salt_phrase is None:
        salt_phrase1 = click.prompt("Enter your Salt passphrase"  , hide_input=True)
        salt_phrase2 = click.prompt("Confirm your Salt passphrase", hide_input=True)
        if salt_phrase1 == salt_phrase2:
            return salt_phrase1.strip()
        else:
            echo(f"Mismatch of Salt passphrases")
            sys.exit(1)
    else:
        return salt_phrase.strip()


SHARE_TITLE = r"Step 1 of 4: Copy Share {share_no}/{num_shares}"

SALT_TITLE = r"Step 2 of 4: Copy Salt"

BRAINKEY_TITLE = r"Step 3 of 4: Copy Brainkey"

VALIDATION_TITLE = r"Step 4 of 4: Validation"


SALT_PROMPT = "When you have copied the Salt, press enter to continue "

SBK_KEYGEN_PROMPT = "Key generation complete, press enter to continue "

_opt_kdf_target_duration = click.option(
    '-d',
    '--target-duration',
    type=float,
    default=parameters.DEFAULT_KDF_T_TARGET,
    show_default=True,
    help="Target duration for Argon2 KDF (unless --time-cost is specified explicitly)",
)

_opt_kdf_memory_cost = click.option(
    '-m',
    '--memory-cost',
    'memory_cost',
    type=int,
    help="Argon2 KDF Memory Cost (MebiBytes)",
)

_opt_kdf_time_cost = click.option(
    '-t',
    '--time-cost',
    type=int,
    help="Argon2 KDF Time Cost (iterations)",
)


DEFAULT_SCHEME = f"{parameters.DEFAULT_SSS_T}of{parameters.DEFAULT_SSS_N}"


_opt_scheme = click.option(
    '-s',
    '--scheme',
    'scheme_arg',
    type=str,
    default=DEFAULT_SCHEME,
    show_default=True,
    help="Threshold and total Number of shares (format: TofN)",
)


_opt_salt = click.option(
    '--salt',
    'salt_phrase',
    type=str,
    default=None,
    show_default=True,
    help="User chosen salt phrase",
)


DEFAULT_SHARESET = 1


_opt_shareset = click.option(
    '--shareset',
    'shareset',
    type=int,
    default=DEFAULT_SHARESET,
    show_default=True,
    help="Name for a set of shares",
)


_opt_yes_all = click.option(
    '-y',
    '--yes-all',
    type=bool,
    is_flag=True,
    default=False,
    help="Enable non-interactive mode",
)


_opt_wallet_name = click.option(
    '--wallet-name',
    type=str,
    default=ui_common.DEFAULT_WALLET_NAME,
    show_default=True,
    help="Wallet name",
)


_opt_show_seed = click.option(
    '--show-seed',
    type=bool,
    is_flag=True,
    default=False,
    help="Show wallet seed. Don't load electrum wallet",
)


_opt_online_mode = click.option(
    '--online',
    type=bool,
    is_flag=True,
    default=False,
    help="Start electrum gui in online mode (--offline is the default)",
)


def _show_secret(label: str, secret_type: str, data: bytes) -> None:
    output_lines = cli_io.format_secret_lines(secret_type, data)

    len_padding = max(map(len, output_lines))
    echo(f"{label:^{len_padding}}")
    echo()
    echo("\n".join(output_lines) + "\n\n")


_opt_verbose = click.option(
    '-v',
    '--verbose',
    count=True,
    help="Control log level. -vv for debug level.",
)


@click.group(context_settings={'help_option_names': ["-h", "--help"]})
@_opt_verbose
def cli(verbose: int = 0) -> None:
    """CLI for SBK v201906.0001-alpha."""
    _configure_logging(verbose)


@cli.command()
@click.version_option(version="2022.1009-beta")
def version() -> None:
    """Show version number."""
    echo("SBK version: 2022.1009-beta")


@cli.command()
@_opt_kdf_target_duration
@_opt_kdf_memory_cost
@_opt_kdf_time_cost
@_opt_verbose
def kdf_test(
    target_duration: ct.Seconds = parameters.DEFAULT_KDF_T_TARGET,
    memory_cost    : Optional[ct.MebiBytes ] = None,
    time_cost      : Optional[ct.Iterations] = None,
    verbose        : int = 0,
) -> None:
    """Test KDF difficulty settings."""
    _configure_logging(verbose)
    params = ui_common.init_params(
        target_duration=target_duration,
        memory_cost=memory_cost,
        time_cost=time_cost,
        threshold=2,
        num_shares=2,
    )
    lens = parameters.raw_secret_lens()

    echo()
    echo(f"Using KDF Parameters: -m={params.kdf_m:<5} -t={params.kdf_t:<4}")
    echo()

    dummy_salt     = ct.Salt(b"\x00" * lens.raw_salt)
    dummy_brainkey = ct.BrainKey(b"\x00" * lens.brainkey)

    tzero = time.time()
    ui_common.derive_seed(params, dummy_salt, dummy_brainkey, label="kdf-test")
    duration = time.time() - tzero
    echo(f"Duration   : {round(duration):>4} sec")


def _validate_data(header_text: str, data: bytes, secret_type: str) -> None:
    full_header_text = VALIDATION_TITLE + "\n\n\t" + header_text
    while True:
        recovered_data = cli_io.prompt(secret_type, full_header_text)
        if data == recovered_data:
            return
        else:
            anykey_confirm("Invalid input. Data mismatch.")


def _validate_copies(
    params  : parameters.Parameters,
    brainkey: ct.BrainKey,
    shares  : ct.Shares,
) -> bool:
    header_text = "Validation for Brainkey"
    _validate_data(header_text, brainkey, cli_io.SECRET_TYPE_BRAINKEY)

    for i, share_data in enumerate(shares):
        share_no    = i + 1
        header_text = f"Validation for Share {share_no}/{len(shares)}"
        _validate_data(header_text, share_data, cli_io.SECRET_TYPE_SHARE)

    return True


def _show_created_data(
    yes_all : bool,
    params  : parameters.Parameters,
    brainkey: ct.BrainKey,
    shares  : ct.Shares,
) -> None:
    text = ui_common.SECURITY_WARNING_TEXT + ui_common.SECURITY_WARNING_QR_CODES
    yes_all or clear()
    yes_all or echo(text.strip())
    yes_all or anykey_confirm("Press enter to continue")

    # Shares
    for i, share_data in enumerate(shares):
        share_no = i + 1
        yes_all or clear()
        info = {
            'share_no'  : share_no,
            'threshold' : params.sss_t,
            'num_shares': params.sss_n,
        }
        share_title = SHARE_TITLE.format(**info).strip()
        echo(share_title)
        echo(ui_common.SHARE_INFO_TEXT)

        share_label = f"Share {share_no}/{params.sss_n}"
        _show_secret(share_label, cli_io.SECRET_TYPE_SHARE, share_data)

        share_prompt = ui_common.SHARE_PROMPT_TMPL.format(**info)
        # ui_common.share_data_to_text(params, share_data, share_no)
        yes_all or anykey_confirm(share_prompt)

    # Brainkey
    yes_all or clear()
    echo(BRAINKEY_TITLE.strip())
    echo(ui_common.BRAINKEY_INFO_TEXT)

    yes_all or anykey_confirm("Press enter to show your brainkey")

    echo()

    _show_secret("Brainkey", cli_io.SECRET_TYPE_BRAINKEY, brainkey)

    yes_all or anykey_confirm(ui_common.BRAINKEY_LAST_CHANCE_WARNING_TEXT)


@cli.command()
@_opt_salt
@_opt_scheme
@_opt_shareset
@_opt_yes_all
@_opt_kdf_target_duration
@_opt_kdf_memory_cost
@_opt_kdf_time_cost
@_opt_verbose
def create(
    salt_phrase    : Optional[str] = None,
    scheme_arg     : str        = DEFAULT_SCHEME,
    shareset       : int        = DEFAULT_SHARESET,
    yes_all        : bool       = False,
    target_duration: ct.Seconds = parameters.DEFAULT_KDF_T_TARGET,
    memory_cost    : Optional[ct.MebiBytes ] = None,
    time_cost      : Optional[ct.Iterations] = None,
    verbose        : int = 0,
) -> None:
    """Generate a brainkey and shares."""

    _configure_logging(verbose)

    # Considering that SBK may be run as the only software on a
    # on a linux live system, there may be an added risk that the
    # system has collected so little entropy directly after booting,
    # that the raw_salt and brainkey would be predictable.
    entropy_available = sbk_random.get_entropy_pool_size()
    if entropy_available < parameters.MIN_ENTROPY:
        echo(f"Not enough entropy: {entropy_available} < 16 bytes")
        sys.exit(1)

    scheme                = ui_common.parse_scheme(scheme_arg)
    validated_salt_phrase = get_validated_salt_phrase(salt_phrase)

    params = ui_common.init_params(
        target_duration=target_duration,
        memory_cost=memory_cost,
        time_cost=time_cost,
        threshold=scheme.threshold,
        num_shares=scheme.num_shares,
    )

    try:
        brainkey, salt, shares = ui_common.create_secrets(
            params=params,
            salt_phrase=validated_salt_phrase,
            shareset=shareset,
        )
    except ValueError as err:
        if err.args and isinstance(err.args[0], list):
            bad_checks = err.args[0]
            echo(f"Invalid parameters: '{bad_checks}'")
            raise click.Abort()
        else:
            raise

    has_manual_kdf_m = memory_cost is not None
    if has_manual_kdf_m:
        # Verify that derivation works before we show anything.
        # This is for manually chosen values of kdf_p and kdf_m,
        # because they may exceed what the system is capable of.
        # If we did not do this now the user might get an OOM
        # error later when they try to load the wallet.
        validation_kdf_params = parameters.init_kdf_params(kdf_m=params.kdf_m, kdf_t=1)

        ui_common.derive_seed(validation_kdf_params, brainkey, salt, label="KDF Validation ")
    else:
        # valid values for kdf_m and kdf_p were already tested as part of "KDF Calibration"
        pass

    _show_created_data(yes_all, params, brainkey, shares)

    yes_all or _validate_copies(params, brainkey, salt, shares)


@cli.command()
@_opt_salt
@_opt_scheme
@_opt_shareset
@_opt_verbose
def backup(
    salt_phrase: Optional[str] = None,
    scheme_arg : str = DEFAULT_SCHEME,
    shareset   : int = DEFAULT_SHARESET,
    verbose    : int = 0,
) -> None:
    """Generate shares from a salt, brainkey."""

    _configure_logging(verbose)

    scheme                = ui_common.parse_scheme(scheme_arg)
    validated_salt_phrase = get_validated_salt_phrase(salt_phrase)

    salt = ui_common.derive_salt(validated_salt_phrase)
    brainkey, params = get_validated_brainkey()

    params = params._replace(sss_t=scheme.threshold, sss_n=scheme.num_shares)
    shares = ui_common.derive_shares(params, salt, brainkey, shareset)

    brainkey_recovered, raw_salt_recovered = shamir.join(shares)

    _show_created_data(True, params, brainkey, shares)


@cli.command()
@_opt_verbose
def recover(verbose: int = 0) -> None:
    """Recover Salt and BrainKey by combining Shares."""
    _configure_logging(verbose)
    params: Optional[parameters.Parameters] = None
    shares: List[ct.Share] = []

    while params is None or len(shares) < params.sss_t:
        share_num = len(shares) + 1

        if params is None:
            header_text = f"Enter Share {share_num}."
        else:
            header_text = f"Enter Share {share_num} of {params.sss_t}."

        share = cli_io.prompt(cli_io.SECRET_TYPE_SHARE, header_text=header_text)
        shares.append(ct.Share(share))

        params_data = share[: parameters.SHARE_HEADER_LEN]
        cur_params  = parameters.bytes2params(params_data)
        if params is None:
            params = cur_params
        elif params != cur_params:
            echo("Invalid share. Shares are perhaps for different wallets.")
            raise click.Abort()

    assert params is not None

    raw_salt, brainkey = shamir.join(shares)
    salt = params_data + raw_salt

    salt_lines     = cli_io.format_secret_lines(cli_io.SECRET_TYPE_SALT    , salt)
    brainkey_lines = cli_io.format_secret_lines(cli_io.SECRET_TYPE_BRAINKEY, brainkey)

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


def get_validated_brainkey() -> tuple[ct.BrainKey, parameters.Parameters]:
    header_text  = "Enter Brainkey"
    raw_brainkey = cli_io.prompt(cli_io.SECRET_TYPE_BRAINKEY, header_text=header_text)
    brainkey     = ct.BrainKey(raw_brainkey)

    params_data = brainkey[: parameters.BRANKEY_HEADER_LEN]
    params      = parameters.bytes2params(params_data)
    return (brainkey, params)


@cli.command()
@_opt_salt
@_opt_wallet_name
@_opt_show_seed
@_opt_online_mode
@_opt_yes_all
@_opt_verbose
def load_wallet(
    salt_phrase: Optional[str] = None,
    wallet_name: str  = ui_common.DEFAULT_WALLET_NAME,
    show_seed  : bool = False,
    online     : bool = False,
    yes_all    : bool = False,
    verbose    : int  = 0,
) -> None:
    """Open wallet using Brainkey and Salt."""
    _configure_logging(verbose)
    offline = not online

    try:
        ui_common.validate_wallet_name(wallet_name)
    except ValueError as err:
        echo(err.args[0])
        raise click.Abort()

    text = ui_common.SECURITY_WARNING_TEXT + ui_common.SECURITY_WARNING_QR_CODES
    yes_all or clear()
    yes_all or echo(text.strip())
    yes_all or anykey_confirm("Press enter to continue")

    validated_salt_phrase = get_validated_salt_phrase(salt_phrase)

    salt = ui_common.derive_salt(validated_salt_phrase)
    brainkey, params = get_validated_brainkey()

    yes_all or echo()
    seed_data = ui_common.derive_seed(
        params,
        brainkey,
        salt,
        wallet_name=wallet_name,
        label="Deriving Wallet Seed",
    )

    if show_seed:
        wallet_fpath, restore_cmd, load_cmd = ui_common.wallet_commands(seed_data, offline)
        ui_common.clean_wallet(wallet_fpath)
        echo("Electrum commands:")
        echo()
        echo("\t" + " ".join(restore_cmd))
        echo("\t" + " ".join(load_cmd   ))
        echo()
        echo("Electrum wallet seed: " + ui_common.seed_data2phrase(seed_data))
    else:
        ui_common.load_wallet(seed_data, offline)


@cli.command()
@_opt_verbose
def qt_gui(verbose: int = 0) -> None:
    """Start sbk gui."""
    from . import gui

    _configure_logging(verbose)

    # load sys info before it's needed. This way it's available
    # by the time it is needed (for wallet creation or settings).
    runner = ui_common.ThreadRunner(sys_info.load_sys_info)
    runner.start()

    gui.run_gui()  # type: ignore


if __name__ == '__main__':
    cli()
