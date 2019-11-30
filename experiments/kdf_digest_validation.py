import time
import binascii

import argon2  # pip install argon2-cffi

from sbk import kdf

VERIFY = 0

if VERIFY:
    HASH_LEN = 1024  # for comparison with sbk
else:
    HASH_LEN = 32  # for comparison with https://antelle.net/argon2-browser/


def digest(data: bytes, p: int, m: int, t: int) -> bytes:
    constant_kwargs = {
        'hash_len'   : HASH_LEN,
        'memory_cost': m * 1024,
        'parallelism': p,
        'type'       : argon2.low_level.Type.ID,
        'version'    : argon2.low_level.ARGON2_VERSION,
    }
    result = data

    remaining_iters = t
    remaining_steps = min(remaining_iters, 10)
    while remaining_iters > 0:
        step_iters = max(1, round(remaining_iters / remaining_steps))
        print(f"remaining: {remaining_iters:>3} of {t}  -  next: {step_iters}")
        result = argon2.low_level.hash_secret_raw(
            secret=result, salt=result, time_cost=step_iters, **constant_kwargs
        )
        remaining_steps -= 1
        remaining_iters -= step_iters

    assert remaining_steps == 0, remaining_steps
    assert remaining_iters == 0, remaining_iters
    return result


kdf_params  = kdf.init_kdf_params(p=1, m=1, t=1)
digest_data = digest(b"test1234", p=kdf_params.p, m=kdf_params.m, t=kdf_params.t)
if VERIFY:
    assert digest_data == kdf.digest(b"test1234", kdf_params, hash_len=1024)
else:
    print(binascii.hexlify(digest_data))
    # remaining:   1 of 1  -  next: 1
    # b'f874b69ca85a76f373a203e7d55a2974c3dc50d94886383b8502aaeebaaf362d'


# This can be verified against https://antelle.net/argon2-browser/
#
# Params: pass=test1234, salt=test1234, time=1, mem=1024, hashLen=32, parallelism=1, type=0
# Encoded: $argon2d$v=19$m=1024,t=1,p=1$dGVzdDEyMzQ$O2GpxMquN/amTCVwe5GHPJr89BvBVnM0ylSHfzez4l8

kdf_params  = kdf.init_kdf_params(p=1, m=1, t=2)
digest_data = digest(b"test1234", p=kdf_params.p, m=kdf_params.m, t=kdf_params.t)
if VERIFY:
    assert digest_data == kdf.digest(b"test1234", kdf_params, hash_len=1024)
else:
    print(binascii.hexlify(digest_data))
    # remaining:   2 of 2  -  next: 1
    # remaining:   1 of 2  -  next: 1
    # b'47a5e595dc0183405f45c0b8c1efe267c01ae2b5bb97fa11a3a662d39352b9dd'


kdf_params  = kdf.init_kdf_params(p=1, m=1, t=87)
digest_data = digest(b"test1234", p=kdf_params.p, m=kdf_params.m, t=kdf_params.t)

if VERIFY:
    assert digest_data == kdf.digest(b"test1234", kdf_params, hash_len=1024)
else:
    print(binascii.hexlify(digest_data))
    # remaining:  87 of 87  -  next: 9
    # remaining:  78 of 87  -  next: 9
    # remaining:  69 of 87  -  next: 9
    # remaining:  60 of 87  -  next: 9
    # remaining:  51 of 87  -  next: 8
    # remaining:  43 of 87  -  next: 9
    # remaining:  34 of 87  -  next: 8
    # remaining:  26 of 87  -  next: 9
    # remaining:  17 of 87  -  next: 8
    # remaining:   9 of 87  -  next: 9
    # b'6cf1a22113182d8c66c8972e693b1cc3bb1d931a691265bad75e935b1254fccd'


constant_kwargs = {
    'hash_len'   : HASH_LEN,
    'memory_cost': 500 * 1024,
    'parallelism': 4,
    'type'       : argon2.low_level.Type.ID,
    'version'    : argon2.low_level.ARGON2_VERSION,
}


iters = 10

tzero  = time.time()
result = b"test1234"
for i in range(min(iters, 10)):
    result = argon2.low_level.hash_secret_raw(
        secret=result, salt=result, time_cost=max(1, iters // 10), **constant_kwargs
    )
duration2 = time.time() - tzero
print("2:", duration2 * 1000)

tzero  = time.time()
result = argon2.low_level.hash_secret_raw(
    secret=b"test1234", salt=b"test1234", time_cost=iters, **constant_kwargs
)
duration1 = time.time() - tzero
print("1:", duration1 * 1000)

print(100 * (duration2 - duration1) / duration1)
