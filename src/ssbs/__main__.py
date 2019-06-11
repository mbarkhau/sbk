#!/usr/bin/env python
# This file is part of the ssbs project
# https://gitlab.com/mbarkhau/ssbs
#
# Copyright (c) 2019 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT
import os
import click
import ssbs


# To enable pretty tracebacks:
#   echo "export ENABLE_BACKTRACE=1;" >> ~/.bashrc
if os.environ.get('ENABLE_BACKTRACE') == "1":
    import backtrace
    backtrace.hook(align=True, strip_path=True, enable_on_envvar_only=True)


click.disable_unicode_literals_warning = True


@click.group()
def cli() -> None:
    """ssbs cli."""


@cli.command()
@click.version_option(version="v201906.0001-alpha")
def version() -> None:
    """Show version number."""
    print(f"ssbs version: {ssbs.__version__}")
