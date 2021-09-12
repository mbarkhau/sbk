#################################################
#     This is a generated file, do not edit     #
#################################################

# This file is part of the sbk project
# https://github.com/mbarkhau/sbk
#
# Copyright (c) 2019-2021 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT
"""Types used across multiple modules."""

from typing import NewType
from typing import Callable
from typing import Optional
from typing import Sequence
from typing import NamedTuple

RawSalt = NewType('RawSalt', bytes)

# ParamConfig data + RawSalt
Salt = NewType('Salt', bytes)

BrainKey  = NewType('BrainKey' , bytes)
MasterKey = NewType('MasterKey', bytes)


class RawShare(NamedTuple):
    x_coord: int
    data   : bytes  # only the encoded GFPoint.y values


# ParamConfig data + RawShare.data
Share  = NewType('Share', bytes)
Shares = Sequence[Share]

SeedData = NewType('SeedData', bytes)

ElectrumSeed = NewType('ElectrumSeed', str)

LangCode = NewType('LangCode', str)

ProgressIncrement     = NewType('ProgressIncrement', float)
ProgressCallback      = Callable[[ProgressIncrement], None]
MaybeProgressCallback = Optional[ProgressCallback]

Parallelism = NewType('Parallelism', int)
MebiBytes   = NewType('MebiBytes'  , int)
Iterations  = NewType('Iterations' , int)
Seconds     = NewType('Seconds'    , float)
