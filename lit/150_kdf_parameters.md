# KDF Parameter Investigation

As the KDF parameters are encoded in the salt (and shares), we want to
have an encoding that is compact. This means, where possible, we
should make parameters either static or implicit. Where not, the
primary purpose of variable parameters is to support future hardware
configurations, so that brute-force attacks continue to be infeasible.

The first two bytes of the salt are for parameter encoding, of which
the first 3bits are for a version number. There is an upgrade path
open if we want to use a more different approch to parameter encoding.

The parameters we're looking at are these:

- `p`: parallelism (number of lanes/threads)
- `m`: memory
- `t`: iterations
- `y`: hashType (0:i, 1:d, 2:id)

From the [IETF draft on Argon2][href_ietf_argon2], we adopt `y=2`
(Argon2id) without any further investigation, as it is declared the
primary variant.

[href_ietf_argon2]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-argon2/13/

!!! note "Side Channel Attacks"

    Considering that SBK is intended for offline use on a single
    system, rather than as part of an interactive client/server setup,
    the choice of `Argon2id` may not be optimal. The choice of
    `Argon2d` might be marginally better, as it would make brute force
    attacks more difficult, which are of greater concern. More
    investigation is welcome, even if only to quantify how marginal
    the benefit of an alternate choice is.


## Baseline Hashing Performance

As a baseline, we want to make sure that we are not measuring only a
particular implementation of argon2. We especially want to be sure
that the implementations we use are not slower than what an attacker
would have access to.

```bash
# run: bash -c 'apt-cache show argon2 | grep -E "(Package|Architecture|Version)"'
Package: argon2
Architecture: amd64
Version: 0~20171227-0.2
# exit: 0
```

```bash
# file: scripts/argon2cli_test.sh
echo -n "password" | argon2 somesalt $@ | grep -E "(Encoded|seconds)"
for ((i=0;i<2;i++)); do
    echo -n "password" | argon2 somesalt $@ | grep seconds
done
```

```bash
# run: bash scripts/argon2cli_test.sh -t 2 -m 16 -p 4 -l 24
Encoded:	$argon2i$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG
0.119 seconds
0.110 seconds
0.118 seconds
# exit: 0
```

This can be compared to the output of the reference implementation [gh/argon2][href_gh_phc_argon2].

[href_gh_phc_argon2]: https://github.com/P-H-C/phc-winner-argon2#command-line-utility

```python
# file: scripts/argon2cffi_test.py
import sys
import time
import argon2

def _measure_argon2(
    t: int, m: float, p: int, l: int = 24, y: int = 2
) -> tuple[str, float]:
    tzero = time.time()
    hash_encoded = argon2.low_level.hash_secret(
        b"password",
        b"somesalt",
        time_cost=t,
        memory_cost=int(2**m),
        parallelism=p,
        hash_len=l,
        type=argon2.Type(y),
    )
    duration = time.time() - tzero
    return (hash_encoded.decode("ascii"), duration)


def measure_argon2(*args, **kwargs) -> None:
    hash_encoded, duration = _measure_argon2(*args, **kwargs)
    print(f"Encoded:\t{hash_encoded}")
    print(f"{duration:.3f} seconds", end="   ")
    for _ in range(4):
        if duration > 3:
            return
        _, duration = _measure_argon2(*args, **kwargs)
        print(f"{duration:.3f} seconds", end="   ")


def main(args: list[str]) -> None:
    _t, t, _m, m, _p, p, _l, l, _y, y = args
    assert [_t, _m, _p, _l, _y] == ['-t', '-m', '-p', '-l', '-y']
    measure_argon2(int(t), float(m), int(p), int(l), int(y))

if __name__ == '__main__':
    main(sys.argv[1:])
```

```bash
# run: python3 scripts/argon2cffi_test.py -t 2 -m 16 -p 4 -l 24 -y 1
Encoded:	$argon2i$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG
0.034 seconds   0.040 seconds   0.047 seconds   0.035 seconds   0.035 seconds
# exit: 0
```

It appears that the python [argon2-cffi][href_pypi_argon2cffi]
implementation is significantly faster, which is perhaps mostly due to
cli invokation overhead or due to multithreadding. As we care about
performance on the order of at least a few seconds, we measure a more
expensive call and also limit parallelism to 1, to make sure that both
implementations only use one core.

[href_pypi_argon2cffi]: https://pypi.org/project/argon2-cffi/

```bash
# run: bash scripts/argon2cli_test.sh -t 3 -m 17 -p 1 -l 24 -id
# timeout: 100
Encoded:	$argon2id$v=19$m=131072,t=3,p=1$c29tZXNhbHQ$mKtFTe5acsEv/wtRdOwuOxxX2QmF8+hu
0.329 seconds
0.312 seconds
0.313 seconds
# exit: 0
```

```bash
# run: python3 scripts/argon2cffi_test.py -t 3 -m 17 -p 1 -l 24 -y 2
# timeout: 100
Encoded:	$argon2id$v=19$m=131072,t=3,p=1$c29tZXNhbHQ$mKtFTe5acsEv/wtRdOwuOxxX2QmF8+hu
0.287 seconds   0.280 seconds   0.277 seconds   0.314 seconds   0.289 seconds
# exit: 0
```

With these settings the implementations seem comparable, let's try
with a higher degree of parallelism.

```bash
# run: bash scripts/argon2cli_test.sh -t 3  -m 17 -p 8 -l 24 -id
# timeout: 100
Encoded:	$argon2id$v=19$m=131072,t=3,p=8$c29tZXNhbHQ$0g5ayzO4asYRYEIckSx6gB21upJ11Gih
0.318 seconds
0.319 seconds
0.315 seconds
# exit: 0
```

```bash
# run: python3 scripts/argon2cffi_test.py -t 3 -m 17 -p 8 -l 24 -y 2
# timeout: 100
Encoded:	$argon2id$v=19$m=131072,t=3,p=8$c29tZXNhbHQ$0g5ayzO4asYRYEIckSx6gB21upJ11Gih
0.082 seconds   0.074 seconds   0.071 seconds   0.072 seconds   0.073 seconds
# exit: 0
```

It appears that the the argon2cffi implementation does use multiple
cores, where the cli implementation does not.


## Cost of Threading

If we can establish that `-p=1024` parallel lanes contributes
insignificant overhead compared to just `-p=1` (given large enough
value for `-m`), then perhaps we won't have to encode the parameter `p`
in the salt.

```bash
# run: python3 scripts/argon2cffi_test.py -t 3 -m 20 -p 8 -l 24 -y 2
# timeout: 100
Encoded:	$argon2id$v=19$m=1048576,t=3,p=8$c29tZXNhbHQ$rPe+PH3lwPgbjSq65GVqTLxDkmSCtetd
0.570 seconds   0.566 seconds   0.597 seconds   0.569 seconds   0.579 seconds
# exit: 0
```

```bash
# run: python3 scripts/argon2cffi_test.py -t 3 -m 20 -p 128 -l 24 -y 2
# timeout: 100
Encoded:	$argon2id$v=19$m=1048576,t=3,p=128$c29tZXNhbHQ$b9PXPtsjVyrVQQLCK5+ZpQ0qzoAVX763
0.678 seconds   0.727 seconds   0.677 seconds   0.647 seconds   0.654 seconds
# exit: 0
```

```bash
# run: python3 scripts/argon2cffi_test.py -t 3 -m 20 -p 1024 -l 24 -y 2
# timeout: 100
Encoded:	$argon2id$v=19$m=1048576,t=3,p=1024$c29tZXNhbHQ$w1lfUA36hCMZgJ37QjHmkm5FTx4giq7G
1.087 seconds   0.863 seconds   0.907 seconds   0.931 seconds   0.772 seconds
# exit: 0
```

Regarding the choice of `-p`, the [Argon2 Spec (2015)][href_argon2_spec] says:

> Argon2 may use up to $`2^{24}`$ threads in parallel, although in our
> experiments 8 threads already exhaust the available bandwidth and
> computing power of the machine.

[href_argon2_spec]: https://www.password-hashing.net/argon2-specs.pdf

There does appear to be an overhead to the use of large values for
`-p`, which an adversary may not have. If we consider any time on hash
computation as a given, we should prefer to spend it on further
iterations rather than on concurrency overhead, that can perhaps be
mitigated by differen hardware choices.

At least for `-p=128` however, the overhead is quite low. Since users
of SBK are unlikely to use hardware which will be underutilized with
such a large value, it should be a fair trade-off to hard-code
`-p=128` for `version=0`.

!!! note "Feedback Welcome"

    If you know of hardware for which (or any other reason why) this
    value of `-p` is inappropriate, please open an issue on GitHub.


## Memory and Time Parameters

!!! note "Memory Swapping"

    On systems with swap the, behaviour of argon2 appears to be that
    it will exit with status: 137. At least on the systems we have
    tested it does not appear to use swap. Regardless, SBK Live does
    not create a swap partition.

For `version=0`, if we would like to protect against brute force As an
arbitary choice for the lowest value for `-m`, a lower bound of 100
Mebibyte and `1.125` as a base. Systems which support such a small
value have been readilly available for over a decade, so this choice
is already quite low.
$`100 \space MB \times 8 \times 1.125^{63} \approx 1300 \space GB`$

For the parameter `-t` (number of iterations) we have a lower bound
simply of 1 and use `1.125` as a base, which gives us an upper bound
of $`5 \times 1.125^{63} \approx 134k`$ iterations.

```bash
# run: python3 scripts/argon2cffi_test.py -t 1000 -m 16.6 -p 8 -l 24 -y 2
# timeout: 100
Encoded:	$argon2id$v=19$m=99334,t=1000,p=8$c29tZXNhbHQ$yXZeXaquxQcv/bLPKtfccNQyBZN/64rM
15.904 seconds
# exit: 0
```

```bash
# run: bash -c "lscpu | grep -i core"
Thread(s) per core:              2
Core(s) per socket:              4
Model name:                      Intel(R) Core(TM) i7-8705G CPU @ 3.10GHz
# exit: 0
```

With this mid-range processer from 2018, using `-m=100MB` we can
extrapolate that 130k iterations would take on the order of 30
minutes. This should suffice to make use of future hardware, given
that much higher values will typically be used for `-m`.


## Further reading

- [Practical Cryptography for Developers - Argon2](https://cryptobook.nakov.com/mac-and-key-derivation/argon2)
- [ory.sh - Choose Argon2 Parameters](https://www.ory.sh/choose-recommended-argon2-parameters-password-hashing/)
- [twelve21.io - Parameters for Argon2](https://www.twelve21.io/how-to-choose-the-right-parameters-for-argon2/)
