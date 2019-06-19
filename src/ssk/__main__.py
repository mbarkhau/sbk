#!/usr/bin/env python
# This file is part of the ssk project
# https://gitlab.com/mbarkhau/ssk
#
# Copyright (c) 2019 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT
"""
__main__ module for SSK.

Enables use as module: $ python -m ssk
"""


if __name__ == '__main__':
    from . import cli

    cli.cli()
