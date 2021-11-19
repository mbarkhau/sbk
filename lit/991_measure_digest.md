## Digest Measurement

```python
# def: measure_digest
import time
from typing import Tuple
import argon2
from argon2.low_level import ffi

Seconds = float


def measure_digest(p: int, m: int, t: int) -> Tuple[str, Seconds]:
    version = argon2.low_level.ARGON2_VERSION
    assert version == 19, version

    tzero = time.time()

    hash_len = 32
    password = b"\x01" * 32
    salt     = b"\x02" * 16
    secret   = b"\x03" * 8
    adata    = b"\x04" * 12

    # Make sure you keep FFI objects alive until *after* the core call!

    cpassword = ffi.new("uint8_t[]", password)
    csalt     = ffi.new("uint8_t[]", salt)
    csecret   = ffi.new("uint8_t[]", password)
    cadata    = ffi.new("uint8_t[]", adata)

    cout      = ffi.new("uint8_t[]", hash_len)
    ctx = ffi.new(
        "argon2_context *", dict(
            version=version,
            out=cout, outlen=hash_len,
            pwd=cpassword, pwdlen=len(password),
            salt=csalt, saltlen=len(salt),
            secret=csecret, secretlen=len(secret),
            ad=cadata, adlen=len(adata),
            t_cost=t,
            m_cost=m,
            lanes=p,
            threads=1,
            allocate_cbk=ffi.NULL, free_cbk=ffi.NULL,
            flags=argon2.low_level.lib.ARGON2_DEFAULT_FLAGS,
        )
    )

    argon2.low_level.core(ctx, argon2.low_level.Type.ID.value)

    result_data = bytes(ffi.buffer(ctx.out, ctx.outlen))

    duration = int((time.time() - tzero) * 1000)
    result = result_data.hex()

    return (result, duration)
```

We use a fairly low level and explicit api here mainly to validate against
the test vectors of the IETF test

```python
# exec
# dep: measure_digest

expected = '0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659'
result, _ = measure_digest(p=4, m=32, t=1)
assert len(result) == len(expected)
print(result, result == expected)
```

```python
# out
656d3661f9c30da2edd65a9b2a3ee3f02e3ce69df00e3c31d89cf9aecfda90f7 False
# exit: 0
```
