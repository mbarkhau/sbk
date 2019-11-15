import os
import sys
import time
import base64

import argon2

secret = b"test secret"
salt   = b"salt" * 4


for mem in [1, 2, 4, 8]:
    tzero = time.time()
    r     = argon2.low_level.hash_secret_raw(
        secret=secret,
        salt=salt,
        memory_cost=int(mem * 1024 * 1024),
        time_cost=2,
        parallelism=16,
        hash_len=16,
        type=argon2.low_level.Type.ID,
    )

    print("????", mem, round((time.time() - tzero) * 1000, 3), "ms")


# print(base64.b16encode(r).decode("ascii"))

sys.exit(0)


h = argon2.low_level.hash_secret(
    secret=secret,
    salt=salt,
    memory_cost=102400,
    time_cost=2,
    parallelism=8,
    hash_len=16,
    type=argon2.low_level.Type.ID,
)


def verify(secret, raw_hash, salt, memory_cost, time_cost, parallelism):
    hash_algo_str = "argon2id"
    hash_version  = 19
    b64_salt      = base64.b64encode(salt).decode("ascii").rstrip("=")
    b64_hash_val  = base64.b64encode(raw_hash).decode("ascii").rstrip("=")

    hash_str = "".join(
        [
            "$" + hash_algo_str,
            "$v=" + str(hash_version),
            "$m=" + str(memory_cost),
            ",t=" + str(time_cost),
            ",p=" + str(parallelism),
            "$" + b64_salt,
            "$" + b64_hash_val,
        ]
    )
    hash_data = hash_str.encode("ascii")
    print("???", hash_data)
    return argon2.low_level.verify_secret(hash_data, secret, argon2.low_level.Type.ID)


print(base64.b64encode(r))
print(base64.b64encode(salt))

print("...", repr(h))

print(verify(secret, r, salt, memory_cost=102400, time_cost=2, parallelism=8))
