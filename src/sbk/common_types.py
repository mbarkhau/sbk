#################################################
#     This is a generated file, do not edit     #
#################################################

# This file is part of the sbk project
# https://github.com/mbarkhau/sbk
#
# Copyright (c) 2019-2022 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT
"""Types used across multiple modules."""

from typing import Any
from typing import Set
from typing import Dict
from typing import List
from typing import Tuple
from typing import NewType
from typing import Callable
from typing import Optional
from typing import Sequence
from typing import NamedTuple

# from typing import TypeAlias
TypeAlias = Any
RawSalt: TypeAlias = bytes

# ParamConfig data + RawSalt
Salt     : TypeAlias = bytes
BrainKey : TypeAlias = bytes
MasterKey: TypeAlias = bytes


class RawShare(NamedTuple):
    x_coord: int
    data   : bytes  # only the encoded GFPoint.y values


# ParamConfig data + RawShare.data
Share : TypeAlias = bytes
Shares: TypeAlias = Sequence[Share]

SeedData: TypeAlias = bytes

ElectrumSeed: TypeAlias = str

LangCode: TypeAlias = str

ProgressIncrement    : TypeAlias = float
ProgressCallback     : TypeAlias = Callable[[ProgressIncrement], None]
MaybeProgressCallback: TypeAlias = Optional[ProgressCallback]

Parallelism: TypeAlias = int
MebiBytes  : TypeAlias = int
Iterations : TypeAlias = int
Seconds    : TypeAlias = float
