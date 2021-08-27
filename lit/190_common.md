# Utilities and Boilerplate

```python
# def: boilerplate
#################################################
#     This is a generated file, do not edit     #
#################################################

# This file is part of the sbk project
# https://github.com/mbarkhau/sbk
#
# Copyright (c) 2019-2021 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT
```

## Build Helper Scripts

```bash
# file: scripts/lint.sh
set -e;
# black --quiet $@;
isort --quiet $@;
flake8 --ignore D,F,E402,W503 $@;
# pylint --errors-only $@;
```

## Imports

```python
# def: imports
import os
import sys
import math
import base64
import struct
import logging
import hashlib
import pathlib as pl
import itertools as it

from typing import NewType, Callable, Sequence, NamedTuple, Optional, Any
from collections.abc import Generator, Iterator

import sbk.common_types_new as ct
import sbk.utils_new as utils

logger = logging.getLogger(__name__)
```


## Module `sbk.common_types`

```python
# file: src/sbk/common_types_new.py
# dep: common.boilerplate
"""Types used across multiple modules."""

from typing import NewType, Sequence, Callable
# dep: types
```

```python
# def: types
RawSalt = NewType('RawSalt', bytes)

# ParamConfig data + RawSalt
Salt = NewType('Salt', bytes)

BrainKey  = NewType('BrainKey' , bytes)
MasterKey = NewType('MasterKey', bytes)

# only the encoded GFPoint
RawShare = NewType('RawShare', bytes)

# ParamConfig data + RawShare
Share  = NewType('Share', bytes)
Shares = Sequence[Share]

SeedData = NewType('SeedData', bytes)

ElectrumSeed = NewType('ElectrumSeed', str)

# include: kdf_types
```


## KDF Types

Types for progress bar. This provides the common API for Qt and CLI
based progress bar rendering, as we for the same kdf calculation code.

```python
# def: kdf_types
ProgressIncrement = NewType('ProgressIncrement', float)
ProgressCallback = Callable[[ProgressIncrement], None]

Parallelism = NewType('Parallelism', int)
MebiBytes   = NewType('MebiBytes', int)
Iterations  = NewType('Iterations', int)
Seconds     = NewType('Seconds', float)
```

