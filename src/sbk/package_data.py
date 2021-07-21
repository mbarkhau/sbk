# This file is part of the SBK project
# https://github.com/mbarkhau/sbk
#
# Copyright (c) 2019-2021 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT

"""Package data access helpers"""
import typing as typ

try:
    import importlib.resources as importlib_resources
except ImportError:
    # compat for py38 and lower
    import importlib_resources  # type: ignore


def path(filename: str) -> typ.ContextManager:
    return importlib_resources.path("sbk.assets", filename)


def read_binary(filename: str) -> bytes:
    return importlib_resources.read_binary("sbk.assets", filename)
    # with package_data.path("logo.svg") as path:
    #     with path.open("rb") as fobj:
    #         return fobj.read()
