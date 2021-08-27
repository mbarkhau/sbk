#!/usr/bin/env python3
# This file is part of the SBK project
# https://github.com/mbarkhau/sbk
#
# Copyright (c) 2019-2021 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT

"""CLI/Imperative shell for SBK."""

# pylint: disable=expression-not-assigned; because of idom: yes_all or ...

import sys
import time
import typing as typ
import logging

import click

import sbk

from . import kdf
from . import cli_io
from . import params
from . import shamir
from . import ui_common
from . import common_types as ct

try:
    import pretty_traceback

    pretty_traceback.install(envvar='ENABLE_PRETTY_TRACEBACK')
except ImportError:
    pass  # no need to fail because of missing dev dependency


click.disable_unicode_literals_warning = True  # type: ignore[attr-defined]


logger = logging.getLogger("sbk.cli")


class LogConfig(typ.NamedTuple):
    fmt: str
    lvl: int


def _parse_logging_config(verbosity: int) -> LogConfig:
    if verbosity == 0:
        return LogConfig("%(levelname)-7s - %(message)s", logging.WARNING)

    log_format = "%(asctime)s.%(msecs)03d %(levelname)-7s " + "%(name)-16s - %(message)s"
    if verbosity == 1:
        return LogConfig(log_format, logging.INFO)

    assert verbosity >= 2
    return LogConfig(log_format, logging.DEBUG)


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


SHARE_TITLE = r"Step 1 of 4: Copy Share {share_no}/{num_shares}"

SALT_TITLE = r"Step 2 of 4: Copy Salt"

BRAINKEY_TITLE = r"Step 3 of 4: Copy Brainkey"

VALIDATION_TITLE = r"Step 4 of 4: Validation"


SALT_PROMPT = "When you have copied the Salt, press enter to continue "

SBK_KEYGEN_PROMPT = "Key generation complete, press enter to continue "


KDF_TARGET_DURATION_HELP = "Target duration for Argon2 KDF (unless --time-cost is specified explicitly)"
KDF_PARALLELISM_HELP     = "Argon2 KDF Parallelism (Number of threads)"
KDF_MEMORY_COST_HELP     = "Argon2 KDF Memory Cost per Thread (MebiBytes)"
KDF_TIME_COST_HELP       = "Argon2 KDF Time Cost (iterations)"


_kdf_target_duration_option = click.option(
    '-d',
    '--target-duration',
    type=float,
    default=params.DEFAULT_KDF_TARGET_DURATION,
    show_default=True,
    help=KDF_TARGET_DURATION_HELP,
)
_kdf_memory_cost_option = click.option(
    '-m', '--memory-cost', 'memory_per_thread', type=int, help=KDF_MEMORY_COST_HELP
)

_kdf_time_cost_option = click.option('-t', '--time-cost', type=int, help=KDF_TIME_COST_HELP)


DEFAULT_SCHEME = f"{params.DEFAULT_THRESHOLD}of{params.DEFAULT_NUM_SHARES}"

SCHEME_OPTION_HELP = "Threshold and total Number of shares (format: TofN)"

_scheme_option = click.option(
    '-s',
    '--scheme',
    'scheme_arg',
    type=str,
    default=DEFAULT_SCHEME,
    show_default=True,
    help=SCHEME_OPTION_HELP,
)


NUM_SHARES_OPTION_HELP = "Number of shares generate"

_num_shares_option = click.option(
    '-n',
    '--num-shares',
    type=int,
    default=params.DEFAULT_NUM_SHARES,
    show_default=True,
    help=NUM_SHARES_OPTION_HELP,
)


YES_ALL_OPTION_HELP = "Enable non-interactive mode"

_yes_all_option = click.option(
    '-y',
    '--yes-all',
    type=bool,
    is_flag=True,
    default=False,
    help=YES_ALL_OPTION_HELP,
)


WALLET_NAME_OPTION_HELP = "Wallet name"

_wallet_name_option = click.option(
    '--wallet-name',
    type=str,
    default=ui_common.DEFAULT_WALLET_NAME,
    show_default=True,
    help=WALLET_NAME_OPTION_HELP,
)


SHOW_SEED_OPTION_HELP = "Show wallet seed. Don't load electrum wallet"

_show_seed_option = click.option(
    '--show-seed', type=bool, is_flag=True, default=False, help=SHOW_SEED_OPTION_HELP
)


ONLINE_MODE_OPTION_HELP = "Start electrum gui in online mode (--offline is the default)"

_online_mode_option = click.option(
    '--online', type=bool, is_flag=True, default=False, help=ONLINE_MODE_OPTION_HELP
)


def _show_secret(label: str, data: bytes, secret_type: str) -> None:
    output_lines = cli_io.format_secret_lines(secret_type, data)

    len_padding = max(map(len, output_lines))
    echo(f"{label:^{len_padding}}")
    echo()
    echo("\n".join(output_lines) + "\n\n")


_opt_verbose = click.option('-v', '--verbose', count=True, help="Control log level. -vv for debug level.")


@click.group(context_settings={'help_option_names': ["-h", "--help"]})
@_opt_verbose
def cli(verbose: int = 0) -> None:
    """CLI for SBK v201906.0001-alpha."""
    _configure_logging(verbose)


@cli.command()
@click.version_option(version="2021.1002-beta")
def version() -> None:
    """Show version number."""
    echo(f"SBK version: {sbk.__version__}")


@cli.command()
@_kdf_target_duration_option
@_kdf_memory_cost_option
@_kdf_time_cost_option
@_opt_verbose
def kdf_test(
    target_duration  : kdf.Seconds = params.DEFAULT_KDF_TARGET_DURATION,
    memory_per_thread: typ.Optional[kdf.MebiBytes ] = None,
    time_cost        : typ.Optional[kdf.Iterations] = None,
    verbose          : int = 0,
) -> None:
    """Test KDF difficulty settings."""
    _configure_logging(verbose)
    param_cfg = ui_common.init_param_config(
        target_duration=target_duration,
        memory_per_thread=memory_per_thread,
        time_cost=time_cost,
        threshold=2,
        num_shares=2,
    )
    kdf_params = param_cfg.kdf_params

    params_str = f"-p={kdf_params.p:<3} -m={kdf_params.m:<5} -t={kdf_params.t:<4}"
    echo()
    echo(f"Using KDF Parameters: {params_str}")
    echo()

    dummy_salt     = ct.Salt(b"\x00" * params.RAW_SALT_LEN)
    dummy_brainkey = ct.BrainKey(b"\x00" * params.BRAINKEY_LEN)

    tzero = time.time()
    ui_common.derive_seed(param_cfg.kdf_params, dummy_salt, dummy_brainkey, label="kdf-test")
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


def _validate_copies(salt: ct.Salt, brainkey: ct.BrainKey, shares: ct.Shares) -> bool:
    header_text = "Validation for Salt"
    _validate_data(header_text, salt, cli_io.SECRET_TYPE_SALT)

    header_text = "Validation for Brainkey"
    _validate_data(header_text, brainkey, cli_io.SECRET_TYPE_BRAINKEY)

    for i, share_data in enumerate(shares):
        share_no    = i + 1
        header_text = f"Validation for Share {share_no}/{len(shares)}"
        _validate_data(header_text, share_data, cli_io.SECRET_TYPE_SHARE)

    return True


def _show_created_data(
    yes_all: bool, param_cfg: params.ParamConfig, salt: ct.Salt, brainkey: ct.BrainKey, shares: ct.Shares
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
            'threshold' : param_cfg.threshold,
            'num_shares': param_cfg.num_shares,
        }
        share_title = SHARE_TITLE.format(**info).strip()
        echo(share_title)
        echo(ui_common.SHARE_INFO_TEXT)

        share_label = f"Share {share_no}/{param_cfg.num_shares}"
        _show_secret(share_label, share_data, cli_io.SECRET_TYPE_SHARE)

        share_prompt = ui_common.SHARE_PROMPT_TMPL.format(**info)
        # ui_common.share_data_to_text(param_cfg, share_data, share_no)
        yes_all or anykey_confirm(share_prompt)

    # Salt
    yes_all or clear()

    echo(SALT_TITLE)
    echo()

    echo(ui_common.SALT_INFO_TEXT)

    _show_secret("Salt", salt, cli_io.SECRET_TYPE_SALT)

    yes_all or anykey_confirm(SALT_PROMPT)

    # Brainkey
    yes_all or clear()
    echo(BRAINKEY_TITLE.strip())
    echo(ui_common.BRAINKEY_INFO_TEXT)

    yes_all or anykey_confirm("Press enter to show your brainkey")

    echo()

    _show_secret("Brainkey", brainkey, cli_io.SECRET_TYPE_BRAINKEY)

    yes_all or anykey_confirm(ui_common.BRAINKEY_LAST_CHANCE_WARNING_TEXT)


@cli.command()
@_scheme_option
@_yes_all_option
@_kdf_target_duration_option
@_kdf_memory_cost_option
@_kdf_time_cost_option
@_opt_verbose
def create(
    scheme_arg       : str         = DEFAULT_SCHEME,
    yes_all          : bool        = False,
    target_duration  : kdf.Seconds = params.DEFAULT_KDF_TARGET_DURATION,
    memory_per_thread: typ.Optional[kdf.MebiBytes ] = None,
    time_cost        : typ.Optional[kdf.Iterations] = None,
    verbose          : int = 0,
) -> None:
    """Generate a new salt, brainkey and shares."""

    # Considering that SBK may be run as the only software on a
    # on a linux live system, there may be an added risk that the
    # system has collected so little entropy directly after booting,
    # that the raw_salt and brainkey would be predicatble.
    _configure_logging(verbose)

    entropy_available = ui_common.get_entropy_pool_size()
    if entropy_available < params.MIN_ENTROPY:
        echo(f"Not enough entropy: {entropy_available} < 16 bytes")
        sys.exit(1)

    scheme = ui_common.parse_scheme(scheme_arg)

    param_cfg = ui_common.init_param_config(
        target_duration=target_duration,
        parallelism=parallelism,
        memory_per_thread=memory_per_thread,
        time_cost=time_cost,
        threshold=scheme.threshold,
        num_shares=scheme.num_shares,
    )

    try:
        salt, brainkey, shares = ui_common.create_secrets(param_cfg)
    except ValueError as err:
        if err.args and isinstance(err.args[0], list):
            bad_checks = err.args[0]
            echo(f"Invalid parameters: '{bad_checks}'")
            raise click.Abort()
        else:
            raise
    has_manual_kdf_m = memory_per_thread is not None
    if has_manual_kdf_m:
        # Verify that derivation works before we show anything. This is for manually chosen values
        # of kdf_p and kdf_m, because they may exceed what the system is capable of. If we did not
        # do this now the user might get an OOM error later when they try to load the wallet.
        validation_kdf_params = param_cfg.kdf_params._replace_any(t=min(1, param_cfg.kdf_params.t))

        ui_common.derive_seed(validation_kdf_params, salt, brainkey, label="KDF Validation ")
    else:
        # valid values for kdf_m and kdf_p were already tested as part of "KDF Calibration"
        pass

    _show_created_data(yes_all, param_cfg, salt, brainkey, shares)

    yes_all or _validate_copies(salt, brainkey, shares)


@cli.command()
@_opt_verbose
def recover_salt(verbose: int = 0) -> None:
    """Recover a partially readable Salt."""
    _configure_logging(verbose)
    param_and_salt_data = cli_io.prompt(cli_io.SECRET_TYPE_SALT)
    param_cfg_data      = param_and_salt_data[: params.PARAM_CFG_LEN]
    param_cfg           = params.bytes2param_cfg(param_cfg_data)

    echo()
    echo("Decoded parameters".center(35))
    echo()
    echo(f"    threshold      : {param_cfg.threshold}")
    echo(f"    kdf parallelism: {param_cfg.kdf_params.p}")
    echo(f"    kdf memory cost: {param_cfg.kdf_params.m} MiB")
    echo(f"    kdf time cost  : {param_cfg.kdf_params.t} Iterations")


@cli.command()
@_opt_verbose
def recover(verbose: int = 0) -> None:
    """Recover Salt and BrainKey by combining Shares."""
    _configure_logging(verbose)
    param_cfg: typ.Optional[params.ParamConfig] = None
    shares   : typ.List[ct.Share] = []

    while param_cfg is None or len(shares) < param_cfg.threshold:
        share_num = len(shares) + 1

        if param_cfg is None:
            header_text = f"Enter Share {share_num}."
        else:
            header_text = f"Enter Share {share_num} of {param_cfg.threshold}."

        share = cli_io.prompt(cli_io.SECRET_TYPE_SHARE, header_text=header_text)
        shares.append(ct.Share(share))

        param_cfg_data = share[: params.PARAM_CFG_LEN]
        cur_param_cfg  = params.bytes2param_cfg(param_cfg_data)
        if param_cfg is None:
            param_cfg = cur_param_cfg
        elif param_cfg != cur_param_cfg:
            echo("Invalid share. Shares are perhaps for different wallets.")
            raise click.Abort()

    raw_salt, brainkey = shamir.join(param_cfg, shares)
    salt = param_cfg_data + raw_salt

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


@cli.command()
@_wallet_name_option
@_show_seed_option
@_online_mode_option
@_yes_all_option
@_opt_verbose
def load_wallet(
    wallet_name: str  = ui_common.DEFAULT_WALLET_NAME,
    show_seed  : bool = False,
    online     : bool = False,
    yes_all    : bool = False,
    verbose    : int  = 0,
) -> None:
    """Open wallet using Salt+Brainkey."""
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

    header_text    = "Enter Salt"
    salt           = cli_io.prompt(cli_io.SECRET_TYPE_SALT, header_text=header_text)
    param_cfg_data = salt[: params.PARAM_CFG_LEN]
    param_cfg      = params.bytes2param_cfg(param_cfg_data)
    # raw_salt     = salt[params.PARAM_CFG_LEN:]

    header_text = "Enter Brainkey"
    brainkey    = cli_io.prompt(cli_io.SECRET_TYPE_BRAINKEY, header_text=header_text)

    yes_all or echo()
    seed_data = ui_common.derive_seed(
        param_cfg.kdf_params,
        ct.Salt(salt),
        ct.BrainKey(brainkey),
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
def gui(verbose: int = 0) -> None:
    """Start sbk gui."""
    import sbk.gui

    _configure_logging(verbosity=0)
    sbk.gui.gui()


if __name__ == '__main__':
    cli()
