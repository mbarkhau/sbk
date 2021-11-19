# This file is part of the SBK project
# https://github.com/mbarkhau/sbk
#
# Copyright (c) 2019-2021 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT

"""Package data access helpers"""
from typing import List
from typing import ContextManager

try:
    import importlib.resources as importlib_resources
except ImportError:
    # compat for py36 and lower
    import importlib_resources  # type: ignore


def path(filename: str) -> ContextManager:
    return importlib_resources.path("sbk.assets", filename)


def read_binary(filename: str) -> bytes:
    return importlib_resources.read_binary("sbk.assets", filename)


def read_wordlist(filename: str) -> List[str]:
    result = []
    with importlib_resources.path("sbk.wordlist", filename) as path:
        with path.open() as fobj:
            for line in fobj:
                for word in line.split():
                    word = word.strip()
                    if word:
                        result.append(word)
    return result
