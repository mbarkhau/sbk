# This file is part of the SBK project
# https://github.com/mbarkhau/sbk
#
# Copyright (c) 2019-2021 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT

"""Types used across multiple modules."""

import typing as typ

RawSalt = typ.NewType('RawSalt', bytes)

# ParamConfig data + RawSalt
Salt = typ.NewType('Salt', bytes)

BrainKey  = typ.NewType('BrainKey' , bytes)
MasterKey = typ.NewType('MasterKey', bytes)

# only the encoded GFPoint
RawShare = typ.NewType('RawShare', bytes)

# ParamConfig data + RawShare
Share  = typ.NewType('Share', bytes)
Shares = typ.Sequence[Share]

SeedData = typ.NewType('SeedData', bytes)

ElectrumSeed = typ.NewType('ElectrumSeed', str)
