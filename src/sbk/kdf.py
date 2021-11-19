#################################################
#     This is a generated file, do not edit     #
#################################################

# This file is part of the sbk project
# https://github.com/mbarkhau/sbk
#
# Copyright (c) 2019-2021 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
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
import argon2

from sbk import utils
from sbk import parameters

HASH_LEN                           = 128
DIGEST_STEPS                       = 10
MEASUREMENT_SIGNIFICANCE_THRESHOLD = ct.Seconds(2)


def _digest(data: bytes, p: ct.Parallelism, m: ct.MebiBytes, t: ct.Iterations) -> bytes:
    result = argon2.low_level.hash_secret_raw(
        secret=data,
        salt=data,
        hash_len=HASH_LEN,
        parallelism=p,
        memory_cost=m * 1024,
        time_cost=t,
        type=argon2.low_level.Type.ID,
    )
    return typ.cast(bytes, result)


def digest(
    data       : bytes,
    kdf_params : parameters.KDFParams,
    hash_len   : int,
    progress_cb: ct.MaybeProgressCallback = None,
) -> bytes:
    _ps           : Optional[utils.ProgressSmoother]
    if progress_cb:
        _ps = utils.ProgressSmoother(progress_cb)
    else:
        _ps = None

    remaining_iters = kdf_params.kdf_t
    remaining_steps = min(remaining_iters, DIGEST_STEPS)

    progress_per_iter = 100 / kdf_params.kdf_t

    constant_kwargs = {
        'p': kdf_params.kdf_p,
        'm': kdf_params.kdf_m,
    }
    result = data

    while remaining_iters > 0:
        step_iters = max(1, round(remaining_iters / remaining_steps))
        result     = _digest(result, t=step_iters, **constant_kwargs)
        sys.stdout.flush()

        if _ps:
            _ps.progress_cb(step_iters * progress_per_iter)

        remaining_iters -= step_iters
        remaining_steps -= 1

    assert remaining_iters == 0, remaining_iters
    assert remaining_steps == 0, remaining_steps

    if _ps:
        _ps.join()

    return result[:hash_len]


def kdf_params_for_duration(
    baseline_kdf_params : parameters.KDFParams,
    target_duration     : ct.Seconds,
    max_measurement_time: ct.Seconds = 5,
) -> parameters.KDFParams:
    test_kdf_params = parameters.init_kdf_params(kdf_m=baseline_kdf_params.kdf_m, kdf_t=1)
    digest_kwargs   = {
        # we only vary t, the baseline should be chosen to max out the others
        'p': test_kdf_params.kdf_p,
        'm': test_kdf_params.kdf_m,
    }

    tgt_step_duration = target_duration / DIGEST_STEPS
    total_time        = 0.0

    while True:
        tzero = time.time()
        digest_kwargs['t'] = test_kdf_params.kdf_t
        _digest(b"\x00\x00\x00\x00\x00\x00\x00\x00\x00", **digest_kwargs)
        duration = time.time() - tzero
        total_time += duration

        iters_per_sec = test_kdf_params.kdf_t / duration
        step_iters    = tgt_step_duration * iters_per_sec * 1.25

        # t = test_kdf_params.kdf_t
        # print(f"< {duration:4.3f} t: {t} i/s: {iters_per_sec} tgt: {step_iters}")
        is_tgt_exceeded            = duration   > tgt_step_duration
        is_measurement_significant = duration   > MEASUREMENT_SIGNIFICANCE_THRESHOLD
        is_enough_already          = total_time > max_measurement_time
        if is_tgt_exceeded or is_measurement_significant or is_enough_already:
            new_t = round(step_iters * DIGEST_STEPS)
            return parameters.init_kdf_params(kdf_m=test_kdf_params.kdf_m, kdf_t=new_t)
        else:
            # min_iters is used to make sure we're always measuring with a higher value for t
            min_iters       = math.ceil(test_kdf_params.kdf_t * 1.25)
            min_t           = round(1.25 * MEASUREMENT_SIGNIFICANCE_THRESHOLD * iters_per_sec)
            new_t           = max(min_iters, min_t)
            test_kdf_params = parameters.init_kdf_params(kdf_m=test_kdf_params.kdf_m, kdf_t=new_t)


def main(args: List[str]) -> int:
    memory_mb = int(args[0])
    kdf_p, kdf_m, kdf_t = parameters.init_kdf_params(kdf_m=memory_mb, kdf_t=1)
    try:
        _digest(b"saltsaltsaltsaltbrainkey", kdf_p, kdf_m, kdf_t)
        return 0
    except argon2.exceptions.HashingError:
        return -1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
