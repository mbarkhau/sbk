# Parameters Encoding/Decoding

## Overview

### Data layout

Each Salt and Share is prefixed with the encoded parameters. These
parameters are used to derive the wallet seed. For the salt, the
header is 2 bytes, for each share it is 3 bytes.

```bob
              "kdf_params"          "share"
        .---------------------. .-------------.
        +                     + +             +
0                             0 1             1
0 1 2 3 4 5 6 7 8 9 A B C D E F 0 1 2 3 4 5 6 7
+-----+ +---------+ +---------+ +-------+ +---+
+-----+ +---------+ +---------+ +-------+ +---+
   !         !          !         !        !
   !         !          !         !        !
   !         '          '         '        '
   '       "kdf_r"   "kdf_m"  "sss_x"   "sss_t"
"version"  "(6bits)" "(6bits)""(5bits)" "(3bits)"
"(4bits)"
```


### Dataclass: `Parameters`

Throughout SBK, the decoded the parameters are passed with an instance
of `Parameters`.

```python
# def: type_parameters
class Parameters(NamedTuple):

    version   : int

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
total of 24 bytes/words. The values were chosen with the following
priority of constraints:

1. Due to encoding constraints, the header length for a share is fixed
   at 3 bytes.
2. The main constraint on the brainkey is a minimum entropy to protect
   against a compromised salt. This must be balanced against the
   maximum number of words a human can be expected to memorize.
3. With the previous two constraints on the header and brainkey, any
   remaining constraints must be satisfied by the salt. The main
   constraint here is a minimum level of total entropy.

With an entropy of 8 words/bytes = 64 bits, the brainkey is expensive
but perhaps not infeasible to brute force. This low value is only
justified as the attack to defend against is the narrow case of a
compromised salt. The wallet owner is intended ot be the only person
with access to the salt (treating it similarly to a traditional wallet
seed) and should be aware if it may have been compromised, giving them
enough time to create a new wallet.

The resulting total entropy is at least `13 + 8 = 15byte = 168bit`. The
headers are somewhat variable, but nonetheless predictable so they are
not counted as part of the entropy.

```python
# def: constants_lens
SALT_HEADER_LEN  = 2
SHARE_HEADER_LEN = 3

DEFAULT_RAW_SALT_LEN  = 13
DEFAULT_BRAINKEY_LEN  = 8

DEFAULT_RAW_SALT_LEN  = 5
DEFAULT_BRAINKEY_LEN  = 4
```
