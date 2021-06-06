# This file is part of the sbk project
# https://github.com/mbarkhau/sbk
#
# Copyright (c) 2019-2021 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT
"""Evaluate memory available on system (for kdf parameters)."""

# Some notes on parameter choices.
# https://tools.ietf.org/html/draft-irtf-cfrg-argon2-04#section-4
#
# parallelism: RFC reccomends 2x the number of cores.
#
# time_cost: As the time constraint is not such an issue for the
# intended use cases of SBK, you should be able to dedicate a few
# minutes of computation time to derive a secure key from relativly
# low amount of secret entropy (the brainkey).
#
# hash_type: Theoretically you should only use SBK on a trusted system
# in a trusted environment, so side channel attacks shouldn't be an
# issue and the benefits of using the argon2id are questionable.
# But the argument is similar to with time_cost, even if the extra time
# spent is pointless, it's not too much of a loss.
#
# memory_cost: The main constraint here is that later reconstruction
# of the secret will require a machine with at least as much memory as
# the one used during the initial derivation. Otherwise it should be
# chosen as large as possible.
import os
import re
import json
import time
import typing as typ
import logging
import pathlib as pl
import subprocess as sp

from . import kdf

logger = logging.getLogger("sbk.sys_info")


Seconds = float

DEFAULT_KDF_THREADS_RATIO = 2
DEFAULT_KDF_MEM_RATIO     = 0.9

# Fallback value for systems on which total memory cannot be detected
FALLBACK_MEM_TOTAL_MB = int(os.getenv("SBK_FALLBACK_MEM_TOTAL_MB", "1024"))

DEFAULT_XDG_CONFIG_HOME = str(pl.Path("~").expanduser() / ".config")
XDG_CONFIG_HOME         = pl.Path(os.environ.get('XDG_CONFIG_HOME', DEFAULT_XDG_CONFIG_HOME))

SBK_APP_DIR_STR     = os.getenv('SBK_APP_DIR')
SBK_APP_DIR         = pl.Path(SBK_APP_DIR_STR) if SBK_APP_DIR_STR else XDG_CONFIG_HOME / "sbk"
SYSINFO_CACHE_FNAME = "sys_info_measurements.json"
SYSINFO_CACHE_FPATH = SBK_APP_DIR / SYSINFO_CACHE_FNAME


def mem_total() -> kdf.MebiBytes:
    """Get total memory."""

    # Linux
    meminfo_path = pl.Path("/proc/meminfo")
    if meminfo_path.exists():
        try:
            with meminfo_path.open(mode="rb") as fobj:
                data = fobj.read()
            for line in data.splitlines():
                key, num, unit = line.decode("ascii").strip().split()
                if key == "MemTotal:":
                    assert unit == "kB"
                    return int(num) // 1024
        except Exception:
            logger.error("Error while evaluating system memory", exc_info=True)

    return FALLBACK_MEM_TOTAL_MB


class Measurement(typ.NamedTuple):

    p: kdf.NumThreads
    m: kdf.MebiBytes
    t: kdf.Iterations

    duration: Seconds


def _measure(kdf_params: kdf.KDFParams) -> Measurement:
    tzero = time.time()
    kdf.digest(b"saltsaltsaltsaltbrainkey", kdf_params, hash_len=16)
    duration = round(time.time() - tzero, 5)

    logger.debug(f"kdf parameter calibration {kdf_params} -> {round(duration * 1000)}ms")

    p, m, t = kdf_params
    return Measurement(p=p, m=m, t=t, duration=duration)


class SystemInfo(typ.NamedTuple):

    num_cores: int
    total_mb : kdf.MebiBytes
    initial_p: kdf.NumThreads
    initial_m: kdf.MebiBytes


_SYS_INFO: typ.Optional[SystemInfo] = None


def dump_sys_info(sys_info: SystemInfo) -> None:
    global _SYS_INFO
    _SYS_INFO = sys_info

    cache_path = SYSINFO_CACHE_FPATH
    try:
        cache_path.parent.mkdir(exist_ok=True, parents=True)
    except Exception as ex:
        logger.warning(f"Unable to create cache dir {cache_path.parent}: {ex}")
        return

    sys_info_data = {
        'num_cores': sys_info.num_cores,
        'total_mb' : sys_info.total_mb,
        'initial_p': sys_info.initial_p,
        'initial_m': sys_info.initial_m,
    }

    try:
        with cache_path.open(mode="w", encoding="utf-8") as fobj:
            json.dump(sys_info_data, fobj, indent=4)
    except Exception as ex:
        logger.warning(f"Error writing cache file {cache_path}: {ex}")
        return


def _load_cached_sys_info() -> SystemInfo:
    cache_path = SYSINFO_CACHE_FPATH
    try:
        with cache_path.open(mode="rb") as fobj:
            sys_info_data = json.load(fobj)
        nfo = SystemInfo(**sys_info_data)
    except Exception as ex:
        logger.warning(f"Error reading cache file {cache_path}: {ex}")
        nfo = init_sys_info()

    return nfo


def load_sys_info(use_cache: bool = True) -> SystemInfo:
    global _SYS_INFO
    if _SYS_INFO:
        return _SYS_INFO

    if use_cache and SYSINFO_CACHE_FPATH.exists():
        nfo = _load_cached_sys_info()
    else:
        nfo = init_sys_info()

    _SYS_INFO = nfo
    return nfo


def init_sys_info() -> SystemInfo:
    import argon2

    num_cores = len(os.sched_getaffinity(0))
    total_mb  = mem_total()

    initial_p = int(num_cores * DEFAULT_KDF_THREADS_RATIO)
    initial_m = int(total_mb  * DEFAULT_KDF_MEM_RATIO    ) // initial_p

    while True:
        try:
            kdf_params = kdf.init_kdf_params(p=initial_p, m=initial_m, t=1)
            initial_p  = kdf_params.p
            initial_m  = kdf_params.m
            logger.debug(f"testing initial_p={initial_p}, initial_m={initial_m}")
            _measure(kdf_params)
            logger.debug(f"using initial_p={initial_p}, initial_m={initial_m}")
            break  # success
        except argon2.exceptions.HashingError as err:
            if "Memory allocation error" not in str(err):
                raise
            initial_m = (2 * initial_m) // 3

    nfo = SystemInfo(num_cores, total_mb, initial_p, initial_m)
    dump_sys_info(nfo)
    return nfo


# NOTE (mb 2021-06-06):
# SBK tries to be as non-region specific as possible.
#   no en_US, en_GB, en_AU etc.etc. just en
#
# I'm also not sure we'll ever support non-phonetic systems,
# especiall for the wordlists.

# initially
SUPPORTED_LANGUAGES = {'en', 'de'}

# next (PR welcome)
# SUPPORTED_LANGUAGES |= {'es', 'pt', 'ru', 'fr', de', 'it', 'tr'}

# eventually/maybe (non-phonetic systems may be a design issue for wordlists)
# SUPPORTED_LANGUAGES |= {'ar', 'ko', 'cn', 'jp'}

LAYOUT_TO_LANG = {'us': 'en', 'de': 'de'}

LangCode = str


def detect_lang() -> LangCode:
    try:
        output_data = sp.check_output("localectl")
        output_text = output_data.decode("utf-8")

        # We only parse the first portion on purpose.
        lang_match = re.search(r"LANG=([a-z]+)", output_text)
        if lang_match is None:
            lang = "default"
        else:
            lang = lang_match.group(1)

        if lang != 'default' and lang in SUPPORTED_LANGUAGES:
            return lang

        keyboard_match = re.search(r"X11 Layout: ([a-z]+)", output_text)
        if keyboard_match is None:
            layout = "default"
        else:
            layout = keyboard_match.group(1)

        layout_lang = LAYOUT_TO_LANG.get(layout, layout)

        if layout_lang != 'default' and layout_lang in SUPPORTED_LANGUAGES:
            return layout_lang

    except Exception as ex:
        pass

    return "en"


if __name__ == '__main__':
    print("lang:", detect_lang())
