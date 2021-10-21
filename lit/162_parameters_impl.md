## Data Packing

A short interlude on how we pack/unpack binary data. We want to encode
data in three bytes and our choice of endianness should make it easy
to reason about when looking at the previous data layout diagram.

```python
# exec
from struct import pack, unpack

numeric = (0xAB << 0) | (0xCD << 8) | (0xEF << 16)
data = b"\xAB\xCD\xEF\x00"

assert pack("<L", numeric) == data
assert unpack("<L", data)[0] == numeric
```

We use little endian encoding, so least significant bits are at lower
indexes, which at least in my mind is easier to reason about.


## Implementation

The main implementation of `src/sbk/parameters.py`.

```python
# def: impl
# dep: common.imports, type*, constant*, impl_*
```


### Debug Overrides

For development and debugging, our life will be easier if we can
override these values via environment variables. We intend only
default values to be used by an end user.

```python
# def: constant_overrides
if 'SBK_DEBUG_RAW_SALT_LEN' in os.environ:
    DEFAULT_RAW_SALT_LEN  = int(os.environ['SBK_DEBUG_RAW_SALT_LEN'])

if 'SBK_DEBUG_BRAINKEY_LEN' in os.environ:
    DEFAULT_BRAINKEY_LEN  = int(os.environ['SBK_DEBUG_BRAINKEY_LEN'])

MIN_ENTROPY      = int(os.getenv('SBK_MIN_ENTROPY'     , "16"))
MAX_ENTROPY_WAIT = int(os.getenv('SBK_MAX_ENTROPY_WAIT', "10"))

DEFAULT_KDF_T_TARGET = int(os.getenv('SBK_KDF_T_TARGET') or DEFAULT_KDF_T_TARGET)

DEFAULT_SSS_T = int(os.getenv('SBK_THRESHOLD') or DEFAULT_SSS_T)
DEFAULT_SSS_N = int(os.getenv('SBK_NUM_SHARES') or DEFAULT_SSS_N)
```


### Parameter Initialization

Parameters are initialized in two separate ways:

1. During initial generation of a salt or share.
2. When decoding a salt or share.

It is **critical** that we always initialize parameters in a
normalized form. We cannot use any value for `kdf_m` or `kdf_t`, as
not every possible value has an encoded representation. Before the kdf
parameters are used to derive a key, we must make sure the parameter
we used was parsed from a valid encoded form, which was then parsed by
`param_exp`.

```python
# def: impl_init_kdf_params
def init_kdf_params(kdf_m: ct.MebiBytes, kdf_t: ct.Iterations) -> KDFParams:
    kdf_m_enc = param_log(kdf_m / 100, 1.125)
    kdf_t_enc = param_log(kdf_t, 1.125)

    kdf_m = param_exp(kdf_m_enc, 1.125) * 100
    kdf_t = param_exp(kdf_t_enc, 1.125)
    return KDFParams(KDF_PARALLELISM, kdf_m, kdf_t)
```

The `Parameters` tuple is the dataclass used outside this module, but
it shouldn't be instantiated directly. Instead, all instances are
created via the `init_parameters` functioni, which ensures normalized
values are used for  `kdf_m` and `kdf_t`.

```python
# def: impl_init_parameters
def init_parameters(
    kdf_m   : ct.MebiBytes,
    kdf_t   : ct.Iterations,
    sss_x   : int,
    sss_t   : int = DEFAULT_SSS_T,
    sss_n   : int = -1,
) -> Parameters:
    kdf_params = init_kdf_params(kdf_m, kdf_t)
    if not MIN_THRESHOLD <= sss_t <= MAX_THRESHOLD:
        raise ValueError(f"Invalid threshold: {sss_t}")
    elif kdf_params.kdf_m % 100 != 0:
        raise ValueError(f"Invalid kdf_m: {kdf_params.kdf_m} % 100 != 0")
    else:
        return Parameters(
            version=SBK_VERSION_V0,
            kdf_p=kdf_params.kdf_p,
            kdf_m=kdf_params.kdf_m,
            kdf_t=kdf_params.kdf_t,
            sss_x=sss_x,
            sss_t=sss_t,
            sss_n=sss_n,
        )
```


### Parameter Encoding/Decoding

We test `params2bytes` and `bytes2params` together. We make sure that
the round trip doesn't lose relevant information and otherwise only do
sanity checks on the encoded representation of the parameters.

```python
# def: impl_params2bytes
def params2bytes(params: Parameters) -> bytes:
    kdf_m_enc = param_log(params.kdf_m / 100, 1.125)
    kdf_t_enc = param_log(params.kdf_t, 1.125)

    assert params.version & 0b0000_1111 == params.version
    assert kdf_m_enc      & 0b0011_1111 == kdf_m_enc
    assert kdf_t_enc      & 0b0011_1111 == kdf_t_enc

    if params.sss_x > 0:
        sss_x_enc = params.sss_x - 1
    else:
        sss_x_enc = 0
    sss_t_enc = params.sss_t - 2

    assert sss_x_enc      & 0b0001_1111 == sss_x_enc
    assert sss_t_enc      & 0b0000_0111 == sss_t_enc

    encoded_uint = (
        0
        | params.version << 0x00
        | kdf_m_enc      << 0x04
        | kdf_t_enc      << 0x0A
        | sss_x_enc      << 0x10
        | sss_t_enc      << 0x15
    )
    encoded_data = struct.pack("<L", encoded_uint)
    assert encoded_data[-1:] == b"\x00", encoded_data[-1:]
    return encoded_data[:-1]
```

```python
# def: impl_bytes2params
def bytes2params(data: bytes) -> Parameters:
    is_salt_data = len(data) == 2
    if is_salt_data:
        data = data + b"\x00"   # append dummy sss_t and sss_x

    assert len(data) == 3, len(data)
    encoded_uint, = struct.unpack("<L", data + b"\x00")

    version   = (encoded_uint >> 0x00) & 0b0000_1111
    kdf_m_enc = (encoded_uint >> 0x04) & 0b0011_1111
    kdf_t_enc = (encoded_uint >> 0x0A) & 0b0011_1111
    sss_x_enc = (encoded_uint >> 0x10) & 0b0001_1111
    sss_t_enc = (encoded_uint >> 0x15) & 0b0000_0111

    assert version == SBK_VERSION_V0, f"Invalid version: {version}"

    kdf_m = param_exp(kdf_m_enc, 1.125) * 100
    kdf_t = param_exp(kdf_t_enc, 1.125)
    if is_salt_data:
        sss_x = -1
        sss_t = 2
    else:
        sss_x = sss_x_enc + 1
        sss_t = sss_t_enc + 2

    sss_n = sss_t
    return init_parameters(kdf_m, kdf_t, sss_x, sss_t, sss_n)
```


### Fuzz Test Encode/Decode

This test shows that parameters are decoded accurately after a round
trip of encoding and decoding.

```python
# def: validate_share_params
# dep: impl, common.impl_hex
def validate_params(in_params: Parameters) -> None:
    assert abs(in_params.kdf_m - kwargs['kdf_m']) / kwargs['kdf_m'] < 0.125
    assert abs(in_params.kdf_t - kwargs['kdf_t']) / kwargs['kdf_t'] < 0.125

    # round trip
    params_data = params2bytes(in_params)
    out_params = bytes2params(params_data)

    is_stable_output = params2bytes(out_params) == params_data
    assert is_stable_output, out_params

    assert isinstance(params_data, bytes)
    assert len(params_data) == 3

    assert out_params.version  == in_params.version
    assert out_params.kdf_p    == in_params.kdf_p
    assert out_params.kdf_m    == in_params.kdf_m
    assert out_params.kdf_t    == in_params.kdf_t
    assert out_params.sss_x    == in_params.sss_x
    assert out_params.sss_t    == in_params.sss_t
```

The preceding validation also makes sure, after we have gone through
one round of encoding, the output is stable. That is to say, if we
encode the parameters again, we get the exact same encoded data as for
the original inputs (which usually involves some rounding).

Furthermore, we want to be sure, that the shorter two byte
representation used by the salt can be decoded with the relevant kdf
parameters.

```python
# def: validate_salt_params
# dep: impl, common.impl_hex
def validate_params(in_params: Parameters) -> None:
    assert abs(in_params.kdf_m - kwargs['kdf_m']) / kwargs['kdf_m'] < 0.125
    assert abs(in_params.kdf_t - kwargs['kdf_t']) / kwargs['kdf_t'] < 0.125

    # round trip
    params_data = params2bytes(in_params)
    assert isinstance(params_data, bytes)
    assert len(params_data) == 3

    out_params = bytes2params(params_data[:2])
    assert out_params.version  == in_params.version
    assert out_params.kdf_p    == in_params.kdf_p
    assert out_params.kdf_m    == in_params.kdf_m
    assert out_params.kdf_t    == in_params.kdf_t
    assert out_params.sss_x    == -1
    assert out_params.sss_t    == MIN_THRESHOLD
```


```python
# def: fuzztest_harness
import random

rand = random.Random(0)

kwargs_range = {
    'kdf_m'   : [rand.randint(1, 1000000) for _ in range(100)],
    'kdf_t'   : [rand.randint(1, 10000) for _ in range(100)],
    'sss_x'   : list(range(1, 2**5)),
    'sss_t'   : list(range(2, 2**3 + 2)),
}

for _ in range(100):
    kwargs = {
        k: rand.choice(choices)
        for k, choices in kwargs_range.items()
    }
    in_params = init_parameters(**kwargs)
    validate_params(in_params)

print("ok")
```

```python
# file: test/fuzztest_share_params.py
# dep: validate_share_params, fuzztest_harness
```

```python
# file: test/fuzztest_salt_params.py
# dep: validate_salt_params, fuzztest_harness
```

```python
# run: bash scripts/lint.sh test/fuzztest_*.py
# exit: 0
```

```python
# run: python test/fuzztest_share_params.py
ok
# exit: 0
```

```python
# run: python test/fuzztest_salt_params.py
ok
# exit: 0
```


## Utils

Parse various data lengths. An initial design intended these to be
variable, but that design was disregarded to simplify the initial
implementation. The `SecretLens` construct remains.

```python
# def: impl_len_utils
class SecretLens(NamedTuple):
    raw_salt  : int
    brainkey  : int
    master_key: int
    raw_share : int
    salt      : int
    share     : int


def raw_secret_lens() -> SecretLens:
    raw_salt = DEFAULT_RAW_SALT_LEN
    brainkey = DEFAULT_BRAINKEY_LEN

    raw_share  = raw_salt + brainkey
    master_key = raw_salt + brainkey
    salt  = SALT_HEADER_LEN  + raw_salt
    share = SHARE_HEADER_LEN + raw_share
    return SecretLens(raw_salt, brainkey, master_key, raw_share, salt, share)
```
