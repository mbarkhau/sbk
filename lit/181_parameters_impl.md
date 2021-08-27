## Implementation

The main implementation blocks referenced earlier for `src/sbk/parameters.py`.

```python
# def: parameters.impl
# dep: common.imports, types, constants, constant_overrides
# dep: kdf.log_and_exp
# dep: init_parameters, bytes2params, params2bytes, master_key_len
```


### Constant Overrides

For development and debugging, our life is easier if we can override
these values via environment variables. We intend only default values
to be used by an end user.

```python
# def: constant_overrides
if 'SBK_DEBUG_RAW_SALT_LEN' in os.environ:
    DEFAULT_RAW_SALT_LEN  = int(os.environ['SBK_DEBUG_RAW_SALT_LEN'])
    PARANOID_RAW_SALT_LEN = int(os.environ['SBK_DEBUG_RAW_SALT_LEN'])

if 'SBK_DEBUG_BRAINKEY_LEN' in os.environ:
    DEFAULT_BRAINKEY_LEN  = int(os.environ['SBK_DEBUG_BRAINKEY_LEN'])
    PARANOID_BRAINKEY_LEN = int(os.environ['SBK_DEBUG_BRAINKEY_LEN'])

MIN_ENTROPY      = int(os.getenv('SBK_MIN_ENTROPY'     , "16"))
MAX_ENTROPY_WAIT = int(os.getenv('SBK_MAX_ENTROPY_WAIT', "10"))

DEFAULT_KDF_T_TARGET = int(os.getenv('SBK_KDF_KDF_T') or DEFAULT_KDF_T_TARGET)

DEFAULT_SSS_T = int(os.getenv('SBK_THRESHOLD') or DEFAULT_SSS_T)
DEFAULT_SSS_N = int(os.getenv('SBK_NUM_SHARES') or DEFAULT_SSS_N)
```


### Parameter Initialization

Parameters are initialized in two separate ways:

1. During initial salt/share generation.
2. When decoding a salt/share.

It is **critical** that we always initialize parameters through this
function, and do not initialize a `Parameters` tuple directly. If
we would create a `Parameters` directly, we would risk using values
for `kdf_m` or `kdf_t` which cannot be encoded.

```python
# def: init_parameters
def init_parameters(
    kdf_m   : ct.MebiBytes,
    kdf_t   : ct.Iterations,
    sss_x   : int,
    sss_t   : int = DEFAULT_SSS_T,
    sss_n   : int = -1,
    paranoid: bool = False,
) -> Parameters:
    kdf_m_enc = kdf_log(kdf_m / 100, 1.125)
    kdf_m     = kdf_exp(kdf_m_enc, 1.125) * 100
    kdf_t_enc = kdf_log(kdf_t, 1.125)
    kdf_t     = kdf_exp(kdf_t_enc, 1.125)

    if not MIN_THRESHOLD <= sss_t <= MAX_THRESHOLD:
        raise ValueError(f"Invalid threshold: {sss_t}")
    elif kdf_m % 100 != 0:
        raise ValueError(f"Invalid kdf_m: {kdf_m} % 100 != 0")
    else:
        return Parameters(
            version=SBK_VERSION_V0,
            kdf_p=KDF_PARALLELISM,
            kdf_m=kdf_m,
            kdf_t=kdf_t,
            sss_x=sss_x,
            sss_t=sss_t,
            sss_n=sss_n,
            paranoid=paranoid,
        )
```


### Parameter Encoding/Decoding

We test `params2bytes` and `bytes2params` together. We make sure that
the round trip doesn't lose relevant information and otherwise only do
sanity check regarding the encoded data.

```python
# def: params2bytes
def params2bytes(params: Parameters) -> bytes:
    kdf_m_enc = kdf_log(params.kdf_m / 100, 1.125)
    kdf_t_enc = kdf_log(params.kdf_t, 1.125)
    sss_t_enc = params.sss_t - 2
    sss_x_enc = params.sss_x - 1

    assert params.version  & 0b0000_0111 == params.version
    assert params.paranoid & 0b0000_0001 == params.paranoid
    assert kdf_m_enc       & 0b0011_1111 == kdf_m_enc
    assert kdf_t_enc       & 0b0011_1111 == kdf_t_enc
    assert sss_t_enc       & 0b0000_0111 == sss_t_enc
    assert sss_x_enc       & 0b0001_1111 == sss_x_enc

    encoded_uint = (
        0
        | params.version   << 0x00
        | params.paranoid  << 0x03
        | kdf_m_enc        << 0x04
        | kdf_t_enc        << 0x0A
        | sss_t_enc        << 0x10
        | sss_x_enc        << 0x13
    )
    encoded_data = struct.pack("!L", encoded_uint)
    assert encoded_data[:1] == b"\x00", encoded_data[:1]
    return encoded_data[1:]
```

```python
# def: bytes2params
def bytes2params(data: bytes) -> Parameters:
    assert len(data) in (2, 3), len(data)
    if len(data) == 2:
        data = data + "\xFF"    # pseudo sss_t and sss_x

    encoded_uint, = struct.unpack("!L", b"\x00" + data)

    version   = (encoded_uint >> 0x00) & 0b0000_0111
    paranoid  = (encoded_uint >> 0x03) & 0b0000_0001
    kdf_m_enc = (encoded_uint >> 0x04) & 0b0011_1111
    kdf_t_enc = (encoded_uint >> 0x0A) & 0b0011_1111
    sss_t_enc = (encoded_uint >> 0x10) & 0b0000_0111
    sss_x_enc = (encoded_uint >> 0x13) & 0b0001_1111

    assert version == SBK_VERSION_V0, version

    kdf_m = kdf_exp(kdf_m_enc, 1.125) * 100
    kdf_t = kdf_exp(kdf_t_enc, 1.125)
    sss_t = sss_t_enc + 2
    sss_x = sss_x_enc + 1

    sss_n = sss_t
    return init_parameters(kdf_m, kdf_t, sss_x, sss_t, sss_n, bool(paranoid))
```


### Fuzz Test Encode/Decode

```python
# exec
# dep: parameters.impl, common.impl_hex
import random

rand = random.Random(0)

kwargs_range = {
    'kdf_m'   : [rand.randint(1, 1000000) for _ in range(100)],
    'kdf_t'   : [rand.randint(1, 10000) for _ in range(100)],
    'sss_x'   : list(range(1, 2**5)),
    'sss_t'   : list(range(2, 2**3 + 2)),
    'paranoid': [True, False],
}

for _ in range(100):
    kwargs = {
        k: rand.choice(choices)
        for k, choices in kwargs_range.items()
    }
    in_params = init_parameters(**kwargs)

    assert abs(in_params.kdf_m - kwargs['kdf_m']) / kwargs['kdf_m'] < 0.125
    assert abs(in_params.kdf_t - kwargs['kdf_t']) / kwargs['kdf_t'] < 0.125

    params_data = params2bytes(in_params)
    assert len(params_data) == 3

    out_params = bytes2params(params_data)
    assert in_params.version  == out_params.version
    assert in_params.paranoid == out_params.paranoid
    assert in_params.kdf_p    == out_params.kdf_p
    assert in_params.kdf_m    == out_params.kdf_m
    assert in_params.kdf_t    == out_params.kdf_t
    assert in_params.sss_x    == out_params.sss_x
    assert in_params.sss_t    == out_params.sss_t
```


## Master Key

```python
# def: master_key_len
def master_key_len(params: Parameters) -> int:
    raise NotImplementedError
    if params.paranoid:
        return
    else:
        return
```
