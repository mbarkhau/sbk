# Parameters Encoding/Decoding

## Overview

### Data layout

Each Salt and Share is prefixed with the encoded parameters. These
parameters are used to derive the wallet seed. For the salt, the
header is 2 bytes, for each share it is 3 bytes.


```bob
     share            "kdf_params"
.-------------. .---------------------.
1             1 0                             0
7 6 5 4 3 2 1 0 F E D C B A 9 8 7 6 5 4 3 2 1 0
+-------+ +---+ +---------+ +---------+ . +---+
+-------+ +---+ +---------+ +---------+ ' +---+
   :        :       :           :       :   :
   '        :       '           '       :   :
  "sss_x"   :     "kdf_t"    "kdf_m"    :   :
  "(5bits)" :     "(6bits)"  "(6bits)"  :   :
            '                           :   :
         "sss_t"              .~~~~~~~~~'   '
         "(3bits)"         "paranoid"     "version"
                           "(1bit)"       "(3bits)"
```


### Data Packing

A short interlude on how packing/unpacking binary data works. We want
to encode data in three bytes and our choice of endianness should
reflect the documented data layout.

```python
# exec
from struct import unpack

result, = unpack("!L", b"\x00\xFE\xDC\xBA")
assert (0xFE << 16) | (0xDC << 8) | (0xBA << 0) == result
```


### Module: `sbk.parameters`

```python
# file: src/sbk/parameters.py
# include: common.boilerplate
# dep: common.imports, constants, types, impl
```

```bash
# run: bash scripts/lint.sh src/sbk/parameters.py
# exit: 0
```


### Constants

```python
# def: parameters.constants
SBK_VERSION_V0 = 0

# constrained by f_threshold (3bits)
MIN_THRESHOLD = 2
MAX_THRESHOLD = 10

DEFAULT_RAW_SALT_LEN  = 7
PARANOID_RAW_SALT_LEN = 13

DEFAULT_BRAINKEY_LEN  = 6
PARANOID_BRAINKEY_LEN = 8

PARAM_DATA_LEN = 2
SHARE_DATA_LEN = 3

KDF_PARALLELISM = 128   # hardcoded
DEFAULT_KDF_T_TARGET = 90   # seconds

DEFAULT_SSS_T  = 3
DEFAULT_SSS_N = 5
```


### Dataclass: `Parameters`

```python
# def: types
class Parameters(NamedTuple):

    version   : int
    paranoid  : bool

    kdf_p: ct.Parallelism
    kdf_m: ct.MebiBytes
    kdf_t: ct.Iterations

    sss_x: int
    sss_t: int
    sss_n: int
```

The `sss_*` parameters may not always be available:
- `sss_x` may be `-1` when params were decoded from a salt
- `sss_n` are usually `-1` except when generating shares.
