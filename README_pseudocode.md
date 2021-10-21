!!! warning "THIS IS OUTDATED"

    Things that have changed: Header encoding. In theory it's
    pseudocode, but it shouldn't show things differently than how the
    final implementation works.


## High Level Pseudocode

To conclude the technical overview, here is some pseudocode covering all the basic parts of SBK. It is based on the actual implementation, but it is simplified and abreviated.


### Parameters

```python
# src/sbk/params.py

class ParamConfig:
    """Parameters required for key derivation and recovery."""

    version     : int
    threshold   : int 
    num_shares  : Optional[int] 

    # Argon2 parameters
    kdf_parallelism: int   
    kdf_memory_cost: int  
    kdf_time_cost  : int 

    @staticmethod
    def decode(self, data: bytes) -> Params:
        """Deserialize ParamConfig from the Salt or a Share."""
        fields_01, fields_234, fields_5 = struct.unpack("!BHB", data[:4])
        ...
        version      = (fields_01 >> 4) & 0xF
        f_threshold  = (fields_01 >> 0) & 0xF
        threshold    = f_threshold + 1
        share_no     = fields_5
        ...
        return Params(...)

    def encode(self) -> bytes:
        """Returns 4 byte representation of params."""
        ...
        f_threshold    = self.threshold - 1

        fields_01 = 0
        fields_01 |= self.version << 4
        fields_01 |= f_threshold
        ...
        return struct.pack('!BBH', fields_01, field234, fields_5)

    ...
```

### Mnemonic

```python
# src/sbk/mnemonic.py
import pylev

WORDLIST_STR = """
abraham    academy    acrobat    admiral    airport    alaska     albino     amazon
america    android    antenna    apollo     aquarium   artist     athens     atlantic
...
"""

WORDLIST = WORDLIST_STR.split()
WORDSET = set(WORDLIST)

assert len(WORDLIST) == 256
assert len(WORDSET) == 256


def bytes2phrase(data: bytes) -> str:
    return " ".join(WORDLIST[d] for d in data)


def _fuzzy_match(word: str) -> str:
    if word in WORDSET:
        return word

    dist, closest_word = min([
        (pylev.damerau_levenshtein(word, wl_word), wl_word)
        for wl_word in WORDLIST
    ])
    assert dist < 4
    return closest_word


def phrase2bytes(phrase: str, msg_len: int) -> bytes:
    """Decode human readable phrases to bytes."""
    data: list[int] = []
    for word in phrase.split():
        word = _fuzzy_match(word)
        data.append(WORDLIST.index(word))
    return bytes(data)[:msg_len]
```

```python
# src/sbk/kdf.py
import argon2

def kdf(master_key: bytes, param_cfg: params.ParamConfig) -> bytes:
    """"Key Derivation Function."""
    return argon2.hash_secret(master_key, m=param_cfg.kdf_memory_cost, t=param_cfg.kdf_time_cost)
```

Polynomial Interpolation using [Lagrange Polynomials][href_wiki_lagrange_polynomial]

[href_wiki_lagrange_polynomial]: https://en.wikipedia.org/wiki/Lagrange_polynomial

```python
# src/sbk/shamir.py
import random

MasterKey = bytes
PointData = bytes

def _interpolate_terms(points: Point, at_x: int) -> Iterable[int]:
    for i, p in enumerate(points):
        others = points[:i] + points[i + 1 :]
        numer = prod(at_x - o.x for o in others)
        denum = prod(p.x  - o.x for o in others)
        yield (p.y * numer) / denum


def join(shares: List[PointData], param_cfg: params.ParamConfig) -> MasterKey:
    points = [Point.decode(s) for in shares]
    assert not any(p.x == 0 for p in points)            # points with x=0 can be an attack
    assert len({p.x for p in points}) == len(points)    # no points with same x
    secret = sum(_interpolate_terms(points, at_x=0))
    return int2bytes(secret, zfill=param_cfg.master_key_len)


def _eval_at(coeffs: List[int], at_x: int) -> int:
    """Evaluate polynomial at x.

    coeffs = [2, 5, 3] represents 2x° + 5x¹ + 3x²
    """
    return sum(coeff * at_x ** exponent for exponent, coeff in enumerate(coeffs))


def split(master_key: MasterKey, param_cfg: params.ParamConfig) -> List[PointData]:
    secret: int = bytes2int(master_key)
    coeffs = [secret] + [random_coeff() for _ in range(param_cfg.threshold - 1)]
    x_coords = range(1, param_cfg.num_shares + 1)
    y_coords = [_eval_at(coeffs, x) for x in x_coords]
    return [Point(x, y).encode() for x, y in zip(x_coords, y_coords)]
```

```python
# src/sbk/cli.py
SALT_LEN = 10
BRAINKEY_LEN = 6

@cli.command()
def create(scheme: str = "3of5", brainkey_len: int = BRAINKEY_LEN, ...) -> None:
    threshold, num_shares = parse_scheme(scheme)

    param_cfg = params.ParamConfig(...)
    param_cfg_data: bytes = param_cfg.encode()

    raw_salt = os.urandom(SALT_LEN)
    salt = param_cfg_data + raw_salt
    salt_text = mnemonic_encode(salt)
    print("Write down salt:", salt_text)

    brainkey = os.urandom(brainkey_len)
    brainkey_text = mnemonic_encode(brainkey)
    print("Memorize brainkey:", brainkey_text)

    master_key = raw_salt + brainkey
    sbk_shares = shamir.split(master_key, params)
    for i, share in enumerate(sbk_shares):
        share_text = mnemonic_encode(share)
        print(f"Write down share {i + 1}: {share_text}")


@cli.command()
def recover() -> None:
    ...


@cli.command()
def load_wallet() -> None:
    param_cfg = params.ParamConfig.decode(salt[:4])
    raw_salt = salt[4:]
    # derive the master seed
    master_key = raw_salt + brainkey
    master_seed = kdf(master_key, param_cfg)


# user runtime directory provided by pam_systemd
# http://man7.org/linux/man-pages/man8/pam_systemd.8.html
uid = pwd.getpwnam(os.environ['USER']).pw_uid
wallet_path = f"/run/user/{uid}/sbk_electrum_wallet_{nonce}"
```
