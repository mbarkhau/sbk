#!/usr/bin/env python
# This file is part of the ssk project
# https://gitlab.com/mbarkhau/ssk
#
# Copyright (c) 2019 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT
import os
import typing as typ

import click

import ssk
from . import params


# To enable pretty tracebacks:
#   echo "export ENABLE_BACKTRACE=1;" >> ~/.bashrc
if os.environ.get('ENABLE_BACKTRACE') == '1':
    import backtrace

    backtrace.hook(align=True, strip_path=True, enable_on_envvar_only=True)


click.disable_unicode_literals_warning = True


@click.group()
def cli() -> None:
    """Cli for SSK."""


@cli.command()
@click.version_option(version="v201906.0001-alpha")
def version() -> None:
    """Show version number."""
    print(f"ssk version: {ssk.__version__}")


# The first of the parameters with the most memory that has an
# estimated duration above this threshold, is the one that is
# chosen.

DEFAULT_PARAM_TIME_SEC_THRESHOLD  = 100
DEFAULT_PARAM_MEM_RATIO_THRESHOLD = 0.8


def _pick_default_config_id(
    avail_configs  : params.ParamsByConfigId,
    est_times_by_id: params.SecondsByConfigId,
) -> int:
    default_config_id = 0

    total_kb   = params.mem_total()
    max_mem_kb = total_kb * DEFAULT_PARAM_MEM_RATIO_THRESHOLD

    for current_config_id in sorted(avail_configs):
        current_config       = avail_configs[current_config_id]
        default_config       = avail_configs[default_config_id]
        current_est_time_sec = est_times_by_id[current_config_id]
        default_est_time_sec = est_times_by_id[default_config_id]

        if current_config['memory_cost'] > max_mem_kb:
            continue

        if current_config['memory_cost'] > default_config['memory_cost']:
            default_config_id = current_config_id
        else:
            if current_est_time_sec < default_est_time_sec:
                continue

            if current_est_time_sec > DEFAULT_PARAM_TIME_SEC_THRESHOLD:
                continue

            default_config_id = current_config_id

    return default_config_id


MIN_TIME_SEC  = 10
MIN_MEM_RATIO = 0.1


@cli.command()
@click.option(
    '-a',
    '--show-all',
    is_flag=True,
    default=False,
    help="Show all available parameters. The default only shows reasonable choices.",
)
def param_info(show_all: bool = False) -> None:
    """Show info for each available parameter config."""
    est_times_by_id = params.estimate_config_cost()
    avail_configs   = {
        config_id: params.PARAMS_CONFIGS_BY_ID[config_id]
        for config_id in params.get_avail_config_ids()
    }
    total_kb   = params.mem_total()
    min_mem_kb = total_kb * MIN_MEM_RATIO

    default_config_id = _pick_default_config_id(avail_configs, est_times_by_id)

    print("Id  Mem[MB]  Iters  ~Time[Sec]")
    for config_id, config in avail_configs.items():
        est_time_sec   = round(est_times_by_id[config_id], 1)
        memory_cost    = config['memory_cost']
        memory_cost_mb = int(memory_cost / 1024)
        time_cost      = config['time_cost']
        parts          = [
            f"{config_id:<3}",
            f"{memory_cost_mb:7}",
            f"{time_cost:6}",
            f"{est_time_sec:11}",
        ]

        if config_id == default_config_id:
            parts += ["<- default"]

        is_visible = memory_cost > min_mem_kb and est_time_sec > MIN_TIME_SEC

        if is_visible or show_all or config_id == default_config_id:
            print(" ".join(parts))


@cli.command()
def brainkey(param: typ.Optional[params.ConfigId] = None) -> None:
    pass
