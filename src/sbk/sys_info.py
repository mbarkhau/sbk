#################################################
#     This is a generated file, do not edit     #
#################################################

# This file is part of the sbk project
# https://github.com/mbarkhau/sbk
#
# Copyright (c) 2019-2022 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT
import os
import re
import sys
import json
import math
import time
import base64
import struct
import typing as typ
import hashlib
import logging
import pathlib as pl
import functools as ft
import itertools as it
import threading
import subprocess as sp
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

# from collections.abc import Generator, Iterator, Counter

# from typing import TypeAlias
TypeAlias = Any

import sbk.common_types as ct

logger = logging.getLogger(__name__)
from . import kdf
from . import parameters

DEFAULT_XDG_CONFIG_HOME = str(pl.Path("~").expanduser() / ".config")
XDG_CONFIG_HOME = pl.Path(os.environ.get("XDG_CONFIG_HOME", DEFAULT_XDG_CONFIG_HOME))

SBK_APP_DIR_STR = os.getenv("SBK_APP_DIR")
SBK_APP_DIR = pl.Path(SBK_APP_DIR_STR) if SBK_APP_DIR_STR else XDG_CONFIG_HOME / "sbk"
DEFAULT_LANG = ct.LangCode("en")
SUPPORTED_LANGUAGES = {"en"}

# PR welcome
# SUPPORTED_LANGUAGES |= {'es', 'pt', 'ru', 'fr', de', 'it', 'tr'}
#
# non-phonetic systems may be a design issue for wordlists
# SUPPORTED_LANGUAGES |= {'ar', 'ko', 'cn', 'jp'}

KB_LAYOUT_TO_LANG = {"us": "en"}
# Fallback value for systems on which total memory cannot be detected
FALLBACK_MEM_MB = int(os.getenv("SBK_FALLBACK_MEM_MB", "1024"))

# cache so we don't have to check usable memory every time
SYSINFO_CACHE_FPATH = SBK_APP_DIR / "sys_info_measurements.json"


def detect_lang() -> ct.LangCode:
    try:
        localectl_output = sp.check_output("localectl").decode("utf-8")
        lang = _parse_lang(localectl_output)
        kb_lang = _parse_keyboard_lang(localectl_output)
        return lang or kb_lang or DEFAULT_LANG
    except Exception:
        logger.warning("Fallback to default lang: en", exc_info=True)
        return ct.LangCode("en")


def _parse_lang(localectl_output: str) -> Optional[ct.LangCode]:
    lang_match = re.search(r"LANG=([a-z]+)", localectl_output)
    if lang_match:
        lang = lang_match.group(1)
        logger.debug(f"lang: {lang}")
        if lang in SUPPORTED_LANGUAGES:
            return ct.LangCode(lang)
    return None


def _parse_keyboard_lang(localectl_output: str) -> Optional[ct.LangCode]:
    keyboard_match = re.search(r"X11 Layout: ([a-z]+)", localectl_output)
    if keyboard_match:
        layout = keyboard_match.group(1)
        logger.debug(f"keyboard: {layout}")
        if layout in KB_LAYOUT_TO_LANG:
            return ct.LangCode(KB_LAYOUT_TO_LANG[layout])
    return None


class SystemInfo(NamedTuple):
    total_mb: ct.MebiBytes
    usable_mb: ct.MebiBytes


def _parse_meminfo(meminfo_text: str) -> Tuple[ct.MebiBytes, ct.MebiBytes]:
    total_mb = FALLBACK_MEM_MB
    avail_mb = FALLBACK_MEM_MB

    for line in meminfo_text.splitlines():
        if line.startswith("Mem"):
            key, num, unit = line.strip().split()
            if key == "MemTotal:":
                assert unit == "kB"
                total_mb = int(num) // 1024
            elif key == "MemAvailable:":
                assert unit == "kB"
                avail_mb = int(num) // 1024
    return (total_mb, avail_mb)


def memory_info() -> Tuple[ct.MebiBytes, ct.MebiBytes]:
    meminfo_path = pl.Path("/proc/meminfo")
    if meminfo_path.exists():
        try:
            with meminfo_path.open(mode="r", encoding="utf-8") as fobj:
                return _parse_meminfo(fobj.read())
        except Exception:
            logger.warning("Error while evaluating system memory", exc_info=True)
    return (FALLBACK_MEM_MB, FALLBACK_MEM_MB)


def max_usable_memory(avail_mb: int) -> int:
    check_mb = avail_mb
    while check_mb > parameters.V0_KDF_M_UNIT:
        logger.debug(f"testing check_mb={check_mb}")
        if is_usable_kdf_m(check_mb):
            break
        else:
            check_mb = int(check_mb * 0.75)  # try a bit less
    return check_mb


def is_usable_kdf_m(memory_mb: ct.MebiBytes) -> bool:
    retcode = sp.call([sys.executable, "-m", "sbk.kdf", str(memory_mb)])
    return retcode == 0


def _init_sys_info() -> SystemInfo:
    global _SYS_INFO_LOADING

    try:
        _SYS_INFO_LOADING = True
        total_mb, avail_mb = memory_info()

        # NOTE (mb 2022-07-02): This is too slow for initial
        #       boot, so we hardcode a value and deal with
        #       OOM issues later.
        # initial_mb = max(parameters.V0_KDF_M_UNIT, int(avail_mb * 0.9))
        # usable_mb = max_usable_memory(avail_mb=initial_mb)

        usable_mb = max(parameters.V0_KDF_M_UNIT, int(avail_mb * 0.9))
        nfo = SystemInfo(total_mb, usable_mb)
        _dump_sys_info(nfo)
        return nfo
    finally:
        _SYS_INFO_LOADING = False


def load_sys_info(use_cache: bool = True) -> SystemInfo:
    if not use_cache:
        return _init_sys_info()

    while _SYS_INFO_LOADING:
        time.sleep(0.1)

    cache_path = SYSINFO_CACHE_FPATH
    if not _SYS_INFO_KW and cache_path.exists():
        try:
            with cache_path.open(mode="rb") as fobj:
                _SYS_INFO_KW.update(json.load(fobj))
        except Exception as ex:
            logger.warning(f"Error reading cache file {cache_path}: {ex}")

    if _SYS_INFO_KW:
        return SystemInfo(
            total_mb=_SYS_INFO_KW["total_mb"],
            usable_mb=_SYS_INFO_KW["usable_mb"],
        )
    else:
        return _init_sys_info()


_SYS_INFO_LOADING: bool = False
_SYS_INFO_KW: Dict[str, int] = {}


def _dump_sys_info(sys_info: SystemInfo) -> None:
    _SYS_INFO_KW.update(
        {
            "total_mb": sys_info.total_mb,
            "usable_mb": sys_info.usable_mb,
        }
    )

    cache_path = SYSINFO_CACHE_FPATH
    try:
        cache_path.parent.mkdir(exist_ok=True, parents=True)
    except Exception as ex:
        logger.warning(f"Unable to create cache dir {cache_path.parent}: {ex}")
        return

    try:
        with cache_path.open(mode="w", encoding="utf-8") as fobj:
            json.dump(_SYS_INFO_KW, fobj, indent=4)
    except Exception as ex:
        logger.warning(f"Error writing cache file {cache_path}: {ex}")


def main() -> int:
    # xinclude: common.debug_logging
    print("lang: ", detect_lang())
    print("Mem Info:", memory_info())
    print("Memory Info (uncached):", _init_sys_info())
    print("Memory Info (cached)  :", load_sys_info())
    return 0


if __name__ == "__main__":
    main()
