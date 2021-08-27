# Primes where p < 2^n for GF(p)

As mentioned in [[030_user_guide]], the Galois Field we use can either be of
the form $` GF(p) `$ (where $`p`$ is a prime number) or $` GF(p^n) `$
(and a reducing polynomial). This chapter concerns the prime numbers
needed for  $` GF(p) `$ .

While we don't use $` GF(p) `$ in practice, the arithmetic in $` GF(p) `$
is less complicated, so SBK includes a GF implementation for
use with a prime number. In other words, this chapter is to help validate
the GF logic on more simple case, it is not a functional part of the
implementation of SBK.


## API of `sbk.primes`

The API of this module has two functions.

```python
def get_pow2prime(num_bits: int) -> int:
    ...
```

`get_pow2prime` returns the largest prime number for which
$` 2^n - k \le 2^{num\_bits} `$.

When we create a $` GF(p) `$, we want to pick a prime that is
appropriate for the amount of data we want to encode. If we want to
encode a secret which has 128 bits, then we should pick a prime that
is very close to $`2^{128}`$ . If we picked a larger prime, then the
points we generate would be larger than needed, which would mean a
longer mnemonic to write down, without any additional security (i.e.
for no good reason). If we picked a smaller prime, then security
would be compromised.

If we don't want to deal with such large primes, we need to chunk the
secret and encode points separately. This is what we do in practice
anyway [[user_guide#What is an SBK Share]], where each byte of a share
represents a point in $` GF(2^8) `$, but again, that is an extra
complication. The use of larger primes allows us to validate with a
simplified implementation.

```python
def is_prime(n: int) -> bool:
    ...
```

The main thing to know about `is_prime` is that it does not perform
and exhaustive test of primality. It will return `True` or `False` if
the primality of `n` can be determined with certainty, otherwise it
will `raise NotImplementedError`. This function is only used for
sanity checks, so it's fine that it only works with the subset of
primes we're actually interested in.


## Implementation of `sbk.primes`

We generate a python module and a test script.

```python
# file: src/sbk/primes_new.py
# include: common.boilerplate
"""Prime constants for sbk.gf.GFNum and sbk.gf.Field."""
# include: common.imports
# dep: constants
# dep: get_pow2prime
# dep: is_prime
# dep: is_probable_prime
# dep: validate_pow2_prime_params
# dep: a014234_verify
# dep: read_oeis_org_a014234
# dep: download_oeis_org_a014234
```

```bash
# run: bash scripts/lint.sh src/sbk/primes_new.py
# exit: 0
```


### Constants

We start with a static/hardcoded definition of the primes we care
about. We only care about exponents $`n`$ which are mutliples of 8
because we will only be encoding secrets with a length in bytes.

```python
# def: constants
# dep: pow2primes, small_primes
```

```python
# def: pow2prime_params
Pow2PrimeN     = NewType('Pow2PrimeN', int)
Pow2PrimeK     = NewType('Pow2PrimeK', int)
Pow2PrimeItem  = tuple[Pow2PrimeN, Pow2PrimeK]
Pow2PrimeItems = Iterator[Pow2PrimeItem]

POW2_PRIME_PARAMS: dict[Pow2PrimeN, Pow2PrimeK] = {
      8:    5,  16:   15,  24:    3,  32:    5,   40:   87,
     48:   59,  56:    5,  64:   59,  72:   93,   80:   65,
     88:  299,  96:   17, 104:   17, 112:   75,  120:  119,
    128:  159, 136:  113, 144:   83, 152:   17,  160:   47,
    168:  257, 176:  233, 184:   33, 192:  237,  200:   75,
    208:  299, 216:  377, 224:   63, 232:  567,  240:  467,
    248:  237, 256:  189, 264:  275, 272:  237,  280:   47,
    288:  167, 296:  285, 304:   75, 312:  203,  320:  197,
    328:  155, 336:    3, 344:  119, 352:  657,  360:  719,
    368:  315, 376:   57, 384:  317, 392:  107,  400:  593,
    408: 1005, 416:  435, 424:  389, 432:  299,  440:   33,
    448:  203, 456:  627, 464:  437, 472:  209,  480:   47,
    488:   17, 496:  257, 504:  503, 512:  569,  520:  383,
    528:   65, 536:  149, 544:  759, 552:  503,  560:  717,
    568:  645, 576:  789, 584:  195, 592:  935,  600:   95,
    608:  527, 616:  459, 624:  117, 632:  813,  640:  305,
    648:  195, 656:  143, 664:   17, 672:  399,  680:  939,
    688:  759, 696:  447, 704:  245, 712:  489,  720:  395,
    728:   77, 736:  509, 744:  173, 752:  875,  760:  173,
    768:  825
    # 768:  825, 776: 1539, 784:  759, 792: 1299,  800:  105,
    # 808:   17, 816:  959, 824:  209, 832:  143,  840:  213,
    # 848:   17, 856:  459, 864:  243, 872:  177,  880:  113,
    # 888:  915, 896:  213, 904:  609, 912: 1935,  920:  185,
    # 928:  645, 936: 1325, 944:  573, 952:   99,  960:  167,
    # 968: 1347, 976: 2147, 984:  557, 992: 1779, 1000: 1245,
}
```

If we *do* ever want to serialize a share that uses $` GF(p) `$, then
we will somehow have to encode which prime is used. That would be
done most easilly as an index of `POW2_PRIMES` using only one byte.

```python
# exec
# dep: common.imports, pow2prime_params
assert len(POW2_PRIME_PARAMS) < 256
```


Evaluate of the parameters into the actual `POW2_PRIMES`.

```python
# def: pow2primes
# dep: pow2prime_params
def pow2prime(n: Pow2PrimeN, k: Pow2PrimeK) -> int:
    if n % 8 == 0:
        return 2 ** n - k
    else:
        raise ValueError(f"Invalid n={n} (n % 8 != 0)")


POW2_PRIMES = [
    pow2prime(n, k)
    for n, k in sorted(POW2_PRIME_PARAMS.items())
]
```


Now we can provide accessor methods to get the appropriate prime for
a given length of data. In some cases we may not want to store the
actual prime itself, but rather we can just store the much smaller
index the prime in `POW2_PRIME_PARAMS`.

```python
# def: get_pow2prime
def get_pow2prime_index(num_bits: int) -> int:
    if num_bits % 8 != 0:
        err = f"Invalid num_bits={num_bits}, not a multiple of 8"
        raise ValueError(err)

    target_exp = num_bits
    for p2pp_idx, param_exp in enumerate(POW2_PRIME_PARAMS):
        if param_exp >= target_exp:
            return p2pp_idx

    err = f"Invalid num_bits={num_bits}, no known 2**n-k primes "
    raise ValueError(err)


def get_pow2prime(num_bits: int) -> int:
    p2pp_idx = get_pow2prime_index(num_bits)
    return POW2_PRIMES[p2pp_idx]
```


### Basic Validation

Our main concern here is that we define a constant that isn't
actually a prime (presumably by accident), so let's start with some
basic sanity checks based on [numbers we know to be prime](https://oeis.org/A132358).

```python
# exec
# dep: common.imports, pow2primes
known_primes = [
    251,
    65521,
    4294967291,
    18446744073709551557,
    340282366920938463463374607431768211297,
    281474976710597,
    79228162514264337593543950319,
    1461501637330902918203684832716283019655932542929,
    6277101735386680763835789423207666416102355444464034512659,
]
missing_primes = set(known_primes) - set(POW2_PRIMES)
assert not any(missing_primes)
```

We use the small primes for the `basic_prime_test` and as bases for
the Miller-Rabin test. I'm not actually sure that prime bases are any
better for the MR test than random numbers, it's just a visible
pattern from the [wikipedia article][href_wiki_mrtest_bases].

Primes [oeis.org/A000040](https://oeis.org/A000040/list)

```python
# def: small_primes
SMALL_PRIMES = [
      2,   3,   5,   7,  11,  13,  17,  19,  23,
     29,  31,  37,  41,  43,  47,  53,  59,  61,
     67,  71,  73,  79,  83,  89,  97, 101, 103,
    107, 109, 113, 127, 131, 137, 139, 149, 151,
    157, 163, 167, 173, 179, 181, 191, 193, 197,
    199, 211, 223, 227, 229, 233, 239, 241, 251,
    257, 263, 269, 271, 277, 281, 283, 293, 307,
]

PRIMES = sorted(set(SMALL_PRIMES + POW2_PRIMES))
```

[href_wiki_mrtest_bases]: https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test#Testing_against_small_sets_of_bases


### Primality Testing

All the primes we actually use are constants and are well known. The
primality testing code here is for verification and as a safety net
against accidental changes. We start with the most basic test if `n`
is a prime.

```python
# def: is_prime
# dep: constants
def is_prime(n: int) -> bool:
    for p in PRIMES:
        if n == p:
            return True
        psq = p * p
        if n < psq and n % p == 0:
            return False

    # This is not an exhaustive test, it's only used used only to
    # catch programming errors, so we bail if can't say for sure that
    # n is prime.
    if n > max(SMALL_PRIMES) ** 2:
        raise NotImplementedError
    else:
        return True
```

The MR test is only used for validation of the constants declared in
`POW2_PRIMES`. The implementation was developed using the following
resources:

- [en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test#Miller_test](https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test#Miller_test)
- [jeremykun.com/2013/06/16/miller-rabin-primality-test/](https://jeremykun.com/2013/06/16/miller-rabin-primality-test/)
- [miller-rabin.appspot.com/](http://miller-rabin.appspot.com/)
- [gist.github.com/Ayrx/5884790](https://gist.github.com/Ayrx/5884790)

```python
# def: is_probable_prime
# include: _miller_test_bases, _is_composite
def is_probable_prime(n: int, k: int = 100) -> bool:
    # Early exit if not prime
    for p in SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False

    r = 0
    d = n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for a in _miller_test_bases(n, k):
        x = pow(a, d, n)
        if x not in (1, n - 1) and _is_composite(n, r, x):
            return False

    return True
```


```python
# def: _miller_test_bases
from random import randrange

# Jim Sinclair
_mr_js_bases = {2, 325, 9375, 28178, 450775, 9780504, 1795265022}


def _miller_test_bases(n: int, k: int, accuracy: int = 100) -> Iterator[int]:
    if n < 2 ** 64:
        return _mr_js_bases
    else:
        random_bases = {randrange(2, n - 1) for _ in range(accuracy)}
        return (_mr_js_bases | set(SMALL_PRIMES[:13]) | random_bases)
```


```python
# def: _is_composite
def _is_composite(n: int, r: int, x: int) -> bool:
    for _ in range(r - 1):
        x = pow(x, 2, n)
        if x == n - 1:
            return False
    return True
```

Basic test of is_probable_prime.

```python
# def: test_setup
# dep: common.imports, constants, pow2primes, is_probable_prime
```

```python
# exec
# dep: test_setup
assert is_probable_prime(2 ** 127 -  1)
assert is_probable_prime(2 **  64 - 59)
assert not is_probable_prime(60)

# http://oeis.org/A020230
assert not is_probable_prime(7 * 73 * 103)
assert not is_probable_prime(89 * 683)
assert not is_probable_prime(42420396931)
```

Test the constants with `is_probable_prime`.

```python
# exec
# dep: test_setup
for i, (n, k) in enumerate(POW2_PRIME_PARAMS.items()):
    prime = POW2_PRIMES[i]
    assert prime == 2 ** n - k, (i, n, k)
    assert is_probable_prime(prime), (n, k)
```


### Validation

Here we want to make sure the parameters don't change inadvertantly. If we encode any shares that use these primes, we want to be sure that we can decode them later on. We could encode the prime we use for the share (or the parameters `n` and `k`, but the smallest encoding uses only the index of the prime in the `POW2_PRIMES` list. For such an encoding to work, we have to be sure that we preserve the same primes at the same indexs, otherwise a share would become useless or the user would have to know which version of the software was used to create some old shares.

For the verification, we simply greate a string representation of the `POW2_PRIME_PARAMS` and hard-code its digest, which should never change.


```python
# def: validate_pow2_prime_params
# Hardcoded digest of POW2_PRIME_PARAMS
_V1_PRIMES_VERIFICATION_SHA256 = "8303b97ae70cb01e36abd0a625d7e8a427569cc656e861d90a94c3bc697923e7"


def validate_pow2_prime_params() -> None:
    sha256 = hashlib.sha256()
    for n, k in sorted(POW2_PRIME_PARAMS.items()):
        sha256.update(str((n, k)).encode('ascii'))

    digest      = sha256.hexdigest()
    has_changed = len(POW2_PRIME_PARAMS) != 96 or digest != _V1_PRIMES_VERIFICATION_SHA256

    if has_changed:
        logger.error(f"Current  hash: {digest}")
        logger.error(f"Expected hash: {_V1_PRIMES_VERIFICATION_SHA256}")
        raise Exception("Integrity error: POW2_PRIMES changed!")


validate_pow2_prime_params()
```

With this test, we verify that any manipulation the `POW2_PRIME_PARAMS` list will cause the digest to change.

```python
# def: test_primelist_validation
def test_primelist_validation():
    sbk.primes.validate_pow2_prime_params()
    _original = sorted(sbk.primes.POW2_PRIME_PARAMS.items())
    try:
        sbk.primes.POW2_PRIME_PARAMS[-1] = (768, 1)
        sbk.primes.validate_pow2_prime_params()
        assert False, "expected Exception"
    except Exception as ex:
        assert "Integrity error" in str(ex)
    finally:
        sbk.primes.POW2_PRIME_PARAMS = _original
```

Finally we perform some validation against oeis.org. This is where the parameters for `n` and `k` originally came from, so it is mainly a validation in the sense that it help to convince you that no mistake was made.

The format from aeis.org is a text file where each line consists of `n` and the largest prime `p` such that $` p \lt 2^n `$.

```bash
# run: bash -c "head test/test_primes_a014234.txt | tr ' ' ':' | tr '\n' ' '"
1:2 2:3 3:7 4:13 5:31 6:61 7:127 8:251 9:509 10:1021
# exit: 0
```

We can calculate $` k = 2^n - p `$ , e.g. $` 2^{8} - 251 = 5 `$ . Assuming we have the content of such a file, we can use it to verify the constants of `POW2_PRIME_PARAMS`.

```python
# def: a014234_verify
def a014234_verify(a014234_content: str) -> Pow2PrimeItems:
    for line in a014234_content.splitlines():
        if not line.strip():
            continue

        n, p = map(int, line.strip().split())
        if n % 8 != 0:
            continue

        k = (2 ** n) - p
        assert pow2prime(n, k) == p

        if n <= 768:
            assert POW2_PRIME_PARAMS[n] == k

        yield (n, k)
```

For the tests we'll be nice and not download the file for every test run and instead use a local copy. Note that the `a014234_verify` uses assertions internally and the assertions of the test itself just make sure that the content had some entries that were yielded (which wouldn't be the case if `content` were empty for example).


```python
# def: test_a014234_verfiy
def test_a014234_verfiy():
    fixture = pl.Path(__file__).parent / "test_primes_a014234.txt"
    with fixture.open(mode="r") as fobj:
        content = fobj.read()

    p2p_primes = list(sbk.primes.a014234_verify(content))
    assert len(p2p_primes) >= 96, "not enough entries in content"
```

So that you don't need to run the test suite, the `sbk.primes` module is has a `main` funciton which downloads the A014234 dataset...

```python
# def: read_oeis_org_a014234
def read_oeis_org_a014234() -> str:
    import time
    import tempfile
    import pathlib as pl
    import urllib.request

    cache_path = pl.Path(tempfile.gettempdir()) / "oeis_org_b014234.txt"
    min_mtime = time.time() - 10000
    if cache_path.exists() and cache_path.stat().st_mtime > min_mtime:
        with cache_path.open(mode="r") as fobj:
            content = fobj.read()
    else:
        a014234_url = "https://oeis.org/A014234/b014234.txt"
        with urllib.request.urlopen(a014234_url) as fobj:
            data = fobj.read()
        content = data.decode("utf-8")
        with cache_path.open(mode="w") as fobj:
            fobj.write(content)
    return content
```

..., runs it throught the `a014234_verify` validation and generates urls for wolframalpha.com, that you can use to double check the constants.


```python
# def: download_oeis_org_a014234
def download_oeis_org_a014234() -> None:
    """Helper to verify local primes against https://oeis.org/A014234.

    $ source activate
    $ python -m sbk.primes
    """
    content = read_oeis_org_a014234()
    for exp, k in a014234_verify(content):
        verification_url = f"https://www.wolframalpha.com/input/?i=factors(2%5E{exp}+-+{k})"
        print(f"2**{exp:<4} - {k:<4}", verification_url)

if __name__ == '__main__':
    download_oeis_org_a014234()
```

Truncated output of running the `main` function.

```bash
# run: bash -c "python src/sbk/primes_new.py | tail"
2**928  - 645  https://www.wolframalpha.com/input/?i=factors(2%5E928+-+645)
2**936  - 1325 https://www.wolframalpha.com/input/?i=factors(2%5E936+-+1325)
2**944  - 573  https://www.wolframalpha.com/input/?i=factors(2%5E944+-+573)
2**952  - 99   https://www.wolframalpha.com/input/?i=factors(2%5E952+-+99)
2**960  - 167  https://www.wolframalpha.com/input/?i=factors(2%5E960+-+167)
2**968  - 1347 https://www.wolframalpha.com/input/?i=factors(2%5E968+-+1347)
2**976  - 2147 https://www.wolframalpha.com/input/?i=factors(2%5E976+-+2147)
2**984  - 557  https://www.wolframalpha.com/input/?i=factors(2%5E984+-+557)
2**992  - 1779 https://www.wolframalpha.com/input/?i=factors(2%5E992+-+1779)
2**1000 - 1245 https://www.wolframalpha.com/input/?i=factors(2%5E1000+-+1245)
# exit: 0
```
