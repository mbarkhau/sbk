# Utilities and Boilerplate

```python
# def: boilerplate
#################################################
#     This is a generated file, do not edit     #
#################################################

# This file is part of the sbk project
# https://github.com/mbarkhau/sbk
#
# Copyright (c) 2019-2022 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT
```

## Build Helper Scripts

```bash
# file: scripts/lint.sh
#!/bin/bash
set -e;
black --quiet $@;
isort --quiet $@;
flake8 --ignore D,F,E203,E402,W503 $@;
# pylint --errors-only $@;
```


## Imports

We provide a whole set of imports that are commonly used. For any
individual module this may be excessive, but it greatly reduces
boilerplate throughout the program.

```python
# def: typing
import typing as typ
from typing import NewType, Callable, NamedTuple, Optional
from typing import Tuple, List, Dict, Set, Any
from typing import Generator, Iterator, Iterable, Sequence
from typing import Type, TypeVar, Generic, Union, Protocol
# from collections.abc import Generator, Iterator, Counter

# from typing import TypeAlias
TypeAlias = Any
```

```python
# def: imports
import os
import re
import sys
import math
import time
import json
import base64
import struct
import logging
import hashlib
import threading
import pathlib as pl
import functools as ft
import itertools as it
import subprocess as sp

# dep: typing
import sbk.common_types as ct

logger = logging.getLogger(__name__)
```

```python
# def: debug_logging
_logfmt = "%(asctime)s.%(msecs)03d %(levelname)-7s " + "%(name)-16s - %(message)s"
logging.basicConfig(level=logging.DEBUG, format=_logfmt, datefmt="%Y-%m-%dT%H:%M:%S")
```

## Module `sbk.common_types`

```python
# file: src/sbk/common_types.py
# dep: common.boilerplate
"""Types used across multiple modules."""

from typing import NewType, Sequence, Callable, Optional, NamedTuple
from typing import Tuple, List, Dict, Set, Any
# from typing import TypeAlias
TypeAlias = Any
# dep: types
```

```python
# def: types
RawSalt: TypeAlias = bytes

# ParamConfig data + RawSalt
Salt     : TypeAlias = bytes
BrainKey : TypeAlias = bytes
MasterKey: TypeAlias = bytes

class RawShare(NamedTuple):
    x_coord: int
    data   : bytes  # only the encoded GFPoint.y values

# ParamConfig data + RawShare.data
Share: TypeAlias  = bytes
Shares: TypeAlias = Sequence[Share]

SeedData: TypeAlias = bytes

ElectrumSeed: TypeAlias = str

LangCode: TypeAlias = str

# include: kdf_types
```


## Constants for Configuration

```python
# def: constants
DEFAULT_XDG_CONFIG_HOME = str(pl.Path("~").expanduser() / ".config")
XDG_CONFIG_HOME = pl.Path(os.environ.get('XDG_CONFIG_HOME', DEFAULT_XDG_CONFIG_HOME))

SBK_APP_DIR_STR = os.getenv('SBK_APP_DIR')
SBK_APP_DIR     = pl.Path(SBK_APP_DIR_STR) if SBK_APP_DIR_STR else XDG_CONFIG_HOME / "sbk"
```


## KDF Types

Types for progress bar. This provides the common API for Qt and CLI
based progress bar rendering, as we for the same kdf calculation code.

```python
# def: kdf_types
ProgressIncrement    : TypeAlias = float
ProgressCallback     : TypeAlias = Callable[[ProgressIncrement], None]
MaybeProgressCallback: TypeAlias = Optional[ProgressCallback]

Parallelism : TypeAlias = int
MebiBytes   : TypeAlias = int
Iterations  : TypeAlias = int
Seconds     : TypeAlias = float
```

