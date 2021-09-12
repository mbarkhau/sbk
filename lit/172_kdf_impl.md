## KDF - Implementation

```python
# file: src/sbk/kdf.py
# include: common.boilerplate
# dep: common.imports, imports, constants*, impl*, main
```

```bash
# run: bash scripts/lint.sh src/sbk/kdf.py
# exit: 0
```

The internal digest function uses the python
[argon2-cffi][href_rtd_argon2cffi] library. We determined earlier in
[[kdf_parameters]] that this implementation matched others both in
terms of its output and in terms of performance.

[href_rtd_argon2cffi]: https://argon2-cffi.readthedocs.io/en/stable/

```python
# def: imports
import argon2

from sbk import utils
from sbk import parameters
```

To implement a meaningful progress bar, we will split the digest into
steps. It would be nice if we had an easy way to hook into the argon2
implementation and inspect it or provide a callback which would give
us information about its progress. Instead we split the whole
calculation into steps and measure the time for each step to determine
the progress.

We will feed the hash output of one step into the following iteration
as input, the `HASH_LEN` is chosen to be much larger than the original
input. Without having done any investigation, my assumption is that
this makes loss of entropy between each iteration negligable and does
not e.g. reduce the search space for the final step so much that an
attacker could simply skip all but the last step. Feedback welcome.


```python
# def: constants
HASH_LEN = 128
DIGEST_STEPS = 10
MEASUREMENT_SIGNIFICANCE_THRESHOLD = ct.Seconds(2)
```

We wrap the internal function
[`hash_secret_raw`][href_rtd_argon2cffi_hash_secret_raw]. This way we
can use our own types throughout sbk and only do the mapping to argon2
conventions once.

[href_rtd_argon2cffi_hash_secret_raw]: https://argon2-cffi.readthedocs.io/en/stable/api.html#argon2.low_level.hash_secret_raw

```python
# def: impl_digest_step
def _digest(data: bytes, p: ct.Parallelism, m: ct.MebiBytes, t: ct.Iterations) -> bytes:
    return argon2.low_level.hash_secret_raw(
        secret=data,
        salt=data,
        hash_len=HASH_LEN,
        parallelism=p,
        memory_cost=m * 1024,
        time_cost=t,
        type=argon2.low_level.Type.ID,
    )
```

```python
# exec
# dep: common.imports, imports, constants, impl_digest_step
data = _digest(b"Not your keys, not your coins", p=128, m=32, t=8)
assert len(data) == HASH_LEN
while data:
    print(utils.bytes2hex(data[:32]))
    data = data[32:]
```

```python
# out
2d2eb3584a94cf592b9b2bbe0fa26b215fb9eb955d5cf6c46dbbdcf16b651f46
c74217a0d3c76a57c705edb5eb6db37cfe4963ca807b9302388c61434516abc4
4dd473a83ebab10b5708ae3c93b56bbdd09cf0852a1d6cb30847ce83ebfb18f9
243d249b4eb4e1da19ae0b97f6a2d89c824286d26c539443ecab0d7b7f191bbc
# exit: 0
```



```python
# def: impl_digest
def digest(
    data       : bytes,
    kdf_params : parameters.KDFParams,
    hash_len   : int,
    progress_cb: ct.MaybeProgressCallback = None,
) -> bytes:
    _ps           : typ.Optional[ProgressSmoother]
    if progress_cb:
        _ps = utils.ProgressSmoother(progress_cb)
    else:
        _ps = None

    remaining_iters   = kdf_params.kdf_t
    remaining_steps   = min(remaining_iters, DIGEST_STEPS)

    progress_per_iter = 100 / kdf_params.kdf_t

    constant_kwargs = {
        'p': kdf_params.kdf_p,
        'm': kdf_params.kdf_m,
    }
    result = data

    while remaining_iters > 0:
        step_iters = max(1, round(remaining_iters / remaining_steps))
        result     = _digest(result, t=step_iters, **constant_kwargs)
        sys.stdout.flush()

        if _ps:
            _ps.progress_cb(step_iters * progress_per_iter)

        remaining_iters -= step_iters
        remaining_steps -= 1

    assert remaining_iters == 0, remaining_iters
    assert remaining_steps == 0, remaining_steps

    if _ps:
        _ps.join()

    return result[:hash_len]
```

```python
# def: main
def main(args: list[str]) -> int:
    memory_mb  = int(args[0])
    kdf_p, kdf_m, kdf_t = parameters.init_kdf_params(kdf_m=memory_mb, kdf_t=1)
    try:
        _digest(b"saltsaltsaltsaltbrainkey", kdf_p, kdf_m, kdf_t)
        return 0
    except argon2.exceptions.HashingError:
        return -1
    return -1

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
```

The main function is used separately by `sbk.sys_info` to detect how
much memory we can use with the digest function.

```bash
# run: python -m sbk.kdf 100
# exit: 0
```


```python
# def: impl_kdf_params_for_duration
def kdf_params_for_duration(
    baseline_kdf_params : parameters.KDFParams,
    target_duration     : ct.Seconds,
    max_measurement_time: ct.Seconds = 5,
) -> parameters.KDFParams:
    test_kdf_params = parameters.init_kdf_params(kdf_m=baseline_kdf_params.kdf_m, kdf_t=1)
    digest_kwargs = {
        # we only vary t, the baseline should be chosen to max out the others
        'p': test_kdf_params.kdf_p,
        'm': test_kdf_params.kdf_m,
    }

    tgt_step_duration = target_duration / DIGEST_STEPS
    total_time        = 0.0

    while True:
        tzero = time.time()
        digest_kwargs['t'] = test_kdf_params.kdf_t
        _digest(b"\x00\x00\x00\x00\x00\x00\x00\x00\x00", **digest_kwargs)
        duration = time.time() - tzero
        total_time += duration

        iters_per_sec = test_kdf_params.kdf_t / duration
        step_iters    = tgt_step_duration * iters_per_sec * 1.25

        # t = test_kdf_params.kdf_t
        # print(f"< {duration:4.3f} t: {t} i/s: {iters_per_sec} tgt: {step_iters}")
        is_tgt_exceeded            = duration   > tgt_step_duration
        is_measurement_significant = duration   > MEASUREMENT_SIGNIFICANCE_THRESHOLD
        is_enough_already          = total_time > max_measurement_time
        if is_tgt_exceeded or is_measurement_significant or is_enough_already:
            new_t = round(step_iters * DIGEST_STEPS)
            return parameters.init_kdf_params(kdf_m=test_kdf_params.kdf_m, kdf_t=new_t)
        else:
            # min_iters is used to make sure we're always measuring with a higher value for t
            min_iters       = math.ceil(test_kdf_params.kdf_t * 1.25)
            min_t           = round(1.25 * MEASUREMENT_SIGNIFICANCE_THRESHOLD * iters_per_sec)
            new_t           = max(min_iters, min_t)
            test_kdf_params =  parameters.init_kdf_params(kdf_m=test_kdf_params.kdf_m, kdf_t=new_t)
```

