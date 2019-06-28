#!/usr/bin/env python
# This file is part of the sbk project
# https://gitlab.com/mbarkhau/sbk
#
# Copyright (c) 2019 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT
"""
__main__ module for SBK.

Enables use as module: $ python -m sbk
"""


if __name__ == '__main__':
    from . import cli

    cli.cli()
