# Parameters Encoding/Decoding

## Overview

### Data layout

Each Salt and Share is prefixed with the encoded parameters. These
parameters are used to derive the wallet seed. For the salt, the
header is 2 bytes, for each share it is 3 bytes.

```bob
              "kdf_params"           share
        .---------------------. .-------------.
0                             0 1             1
0 1 2 3 4 5 6 7 8 9 A B C D E F 0 1 2 3 4 5 6 7
+---+ . +---------+ +---------+ +-------+ +---+
+---+ ' +---------+ +---------+ +-------+ +---+
  :   :      :          :         :       :
  :   :      '          '         '       '
  :   :    "kdf_r"   "kdf_m"  "sss_x"   "sss_t"
  :   :    "(6bits)" "(6bits)""(5bits)" "(3bits)"
  '   '~~~~~~~.
"version"  "paranoid"
"(3bits)"  "(1bit)"
```


### Dataclass: `Parameters`

Throughout SBK, the decoded the parameters are passed with an instance
of `Parameters`.

```python
# def: type_parameters
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

The `paranoid` bit determines the length of the salt and brainkey. See
[Constants](#Constants).

The `sss_*` parameters may not always be available:
- `sss_x` may be `-1` when params were decoded from a salt
- `sss_n` are usually `-1` except when generating shares.

In addition we use a subset of the parameters for any context that is
strictly concerned with key derivation and has nothing to do with
shamir shares.

```python
# def: type_kdf_params
class KDFParams(NamedTuple):
    kdf_p: ct.Parallelism
    kdf_m: ct.MebiBytes
    kdf_t: ct.Iterations
```


### Module: `sbk.parameters`

```python
# file: src/sbk/parameters.py
# include: common.boilerplate
# dep: common.imports, constant*, type*, impl*
```

```bash
# run: bash scripts/lint.sh src/sbk/parameters.py
# exit: 0
```


### Constants

```python
# def: constants
SBK_VERSION_V0 = 0

# constrained by f_threshold (3bits)
MIN_THRESHOLD = 2
MAX_THRESHOLD = 10

KDF_PARALLELISM = ct.Parallelism(128)   # hardcoded
DEFAULT_KDF_T_TARGET = ct.Seconds(90)

DEFAULT_SSS_T = 3
DEFAULT_SSS_N = 5
```

A note in particular on the lengths for salt and brainkey. The length
of a share consists of the salt + brainkey + header. This gives us a
total of 16 bytes/words and 24 bytes/words in paranoid mode. The
values were chosen with the following priority of constraints:

1. Due to encoding constraints, the header length for a share is fixed
   at 3 bytes.
2. The main constraint on the brainkey is a minimum entropy to protect
   against a compromised salt. This must be balanced against the
   maximum number of words a human can be expected to memorize.
3. With the previous two constraints on the header and brainkey, any
   remaining constraints must be satisfied by the salt. The main
   constraint here is a minimum level of total entropy. This must be
   balanced against the tedium imposed on users.

The paranoid bit offers users a minimum level some control over the
tradeoff between entropy and convenience.

With entropy of 6 words/bytes = 48 bits
   is already quite low. This is only justified as the attack to
   defend against is the narrow case of a compromised salt. Even so, a
   lower entropy would be too much of a risk. For the paranoid mode,
   the main constraint is human memory 8 words/bytes = 64 bits on the
   high end of what a human can reasonably be expected to memorize.

The resulting total entropies we've chosen are 104bit and 168bit in
paranoid mode.

```python
# def: constants_lens
SALT_HEADER_LEN  = 2
SHARE_HEADER_LEN = 3

DEFAULT_RAW_SALT_LEN  = 7
PARANOID_RAW_SALT_LEN = 13

DEFAULT_BRAINKEY_LEN  = 6
PARANOID_BRAINKEY_LEN = 8
```
