# This file is part of the sbk project
# https://github.com/mbarkhau/sbk
#
# Copyright (c) 2019-2021 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT
#################################################
#     This is a generated file, do not edit     #
#################################################
"""Types used across multiple modules."""
from __future__ import annotations

from typing import NewType

RawSalt           = NewType('RawSalt'  , bytes)
Salt              = NewType('Salt'     , bytes)
BrainKey          = NewType('BrainKey' , bytes)
MasterKey         = NewType('MasterKey', bytes)
RawShare          = NewType('RawShare' , bytes)
Share             = NewType('Share'    , bytes)
Shares            = Sequence[Share]
SeedData          = NewType('SeedData'         , bytes)
ElectrumSeed      = NewType('ElectrumSeed'     , str)
ProgressIncrement = NewType('ProgressIncrement', float)
ProgressCallback  = Callable[[ProgressIncrement], None]
Parallelism       = NewType('Parallelism', int)
MebiBytes         = NewType('MebiBytes'  , int)
Iterations        = NewType('Iterations' , int)
Seconds           = NewType('Seconds'    , float)
