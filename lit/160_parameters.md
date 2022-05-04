# Parameters Encoding/Decoding

## Overview

### Motivation

The machine generated part of the brainkey (the bk-passphrase) is
prefixed with the kdf parameters in an encoded form. These
parameters are used to derive the wallet seed.

The parameters used to derive a wallet seed are critical. We
would like to avoid usability issues such as with derivation
paths of deterministic wallets, which have implicit parameters
that [may differ from one wallet implementation to the
next][href_derivation_paths].

Since the user must remember these parameters, we piggy-back on
the other thing they must remember anyway, namely the
bk-passphrase. This way, they have no extra conceptual burden, no
separate thing they need to keep track of. The user documentation
should also not state this implementation detail to users, so as
to minimize cognitive load that might scare away marginal users.

As the parameters must be memorized, a compact encoding is
critical. For example, we reserve only two bits for a version
number, to allow for iteration of the implementation. If further
iterations are needed in the future, then user facing changes
will also be needed.

[href_derivation_paths]: https://walletsrecovery.org/


### Data layout

```bob
        kdf          share
    .---------. .-------------.
    +         + +             +
0 1 2 3 4 5 6 7 8 9 A B C D E F
+-+ +---+ +---+ +-------+ +---+
+-+ +---+ +---+ +-------+ +---+
 v    m     t       x       t'
```

|      | identifier | bits | description |
|------|------------|------|-------------|
| `v`  | `version`  | `2`  |             |
| `m`  | `kdf_m`    | `3`  |             |
| `t`  | `kdf_t`    | `3`  |             |
| `x`  | `sss_x`    | `5`  |             |
| `t'` | `sss_t`    | `3`  |             |


### Dataclass: `Parameters`

Throughout SBK, the decoded parameters are passed using an instance
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


### Constants for KDF

```python
# def: constants
SBK_VERSION_V0 = 0

# constrained by f_threshold (3bits)
MIN_THRESHOLD = 2
MAX_THRESHOLD = 10

KDF_PARALLELISM       = ct.Parallelism(128)   # hardcoded
DEFAULT_KDF_T_TARGET  = ct.Seconds(90)
DEFAULT_KDF_M_PERCENT = 100

DEFAULT_SSS_T = 3
DEFAULT_SSS_N = 5

V0_KDF_M_BASE = 1.5
V0_KDF_T_BASE = 4.0

V0_KDF_M_UNIT = 512     # megabytes
V0_KDF_T_UNIT = 1       # iterations
```


### Constants for Secrets

The length of a share consists of the ``parameters + brainkey +
salt_hash``. This gives us a total of 24 bytes/words. The values were
chosen with the following priority of constraints:

1. Due to encoding constraints, the header length for a share is fixed
   at 2 bytes.
2. The main constraint on the brainkey is a minimum entropy to protect
   against a compromised salt. This must be balanced against the
   maximum number of words a human can be expected to memorize.
3. With the previous two constraints on the header and brainkey, any
   remaining constraints must be satisfied by the salt. The main
   constraint here is a minimum level of total entropy.

With an entropy of at least 5 words/bytes = 40 bits, the brainkey
is expensive but perhaps not infeasible to brute force. This low
value is only justified as the attack to defend against is the
narrow case of a compromised salt. The wallet owner is intended
ot be the only person who knows the salt. Should they reveal the
salt by accident, they will still have time to transfer their
funds to a safe wallet.

The resulting total entropy is on the order of ``11 + 5 = 16byte =
128bit``, depending on how well the user chose their salt. The
header is not completely random, so we cannot count them as part
of the entropy.

```python
# def: constants_lens
BRANKEY_HEADER_LEN = 1
SHARE_HEADER_LEN   = 2

DEFAULT_RAW_SALT_LEN = 11
DEFAULT_BRAINKEY_LEN = 5
```
