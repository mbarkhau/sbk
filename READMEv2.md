<p align="center">
<img alt="SBK Logo" src="https://mbarkhau.keybase.pub/sbk/logo_128.png" height="128" />
</p>

# SBK: Split Bitcoin Keys

With SBK you can create cold-storage Bitcoin wallets that are highly secure. This means:

 - Your coins are safe, even if your house burns down in a fire and all of your documents and devices are destroyed.
 - Your coins are safe, even if a theif takes all your documents or hacker copies all of your files.
 - Your coins are safe, even if you trusted somebody you shouldn't have (not too often though).
 - Your coins are safe, even if something happens to you, your family will still be able to recover your coins.

All of this is only true of course, as long as you follow the reccomended procedures. They can be a bit tedious, but they are simple and well documented.


## How SBK Works

SBK has two ways to load/recover your wallet.

 1. A Brainkey+Salt: A Brainkey is passphrase which is known only to you and is not stored on any computer or written on any piece of paper, it is stored only in your brain. (This method uses an additional secret called a "Salt", which *is written on paper*, but more on that later).
 2. SBK-Shares: A set of phrases which are a backup with which your wallet can be recovered. The [Shamir's Secret Sharing][href_wiki_sss] algorithm is used to generate these. You can distribute these SBK-Shares in secure locations or give them to people you trust. Each share is useless by itself and not all of them are required for recovery, so you don't have to trust a person completely and your wallet will still be recoverable even if a few of your SBK-Shares are lost.

Using the Brainkey, you have direct access to your wallet, independent of any third party and without risk of loss due to a single point of failure. If you forget your Brainkey or your Salt is destroyed, you or your family can collect the SBK-Shares and recover your wallet from this backup.

SBK is not itself a wallet, it only creates and recovers wallet seeds. SBK currently supports only the [Electrum Bitcoin Wallet][href_electrum_org].

[href_wiki_sss]: https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing

[href_electrum_org]: https://electrum.org/

> DISCLAIMER 
>
>  - SBK is still in alpha development and has not had sufficient review
>    for serious use! 
>  - The design of serialized data is not finalized, so any keys you generate
>    using this alpha version will very probably not wor with future versions
>    of SBK.
>  - Do not use this software for any purpose other than to review and provide
>    feedback or contributions.
>  - The SBK project is not associated with the Electrum Bitoin Wallet or
>    Electrum Technologies GmbH in any way .
>  - The SBK project is not associated with SatoshiLabs s.r.o. in any way.

Project/Repo:

[![MIT License][license_img]][license_ref]
[![Supported Python Versions][pyversions_img]][pyversions_ref]
[![PyCalVer v201906.0001-alpha][version_img]][version_ref]
[![PyPI Version][pypi_img]][pypi_ref]
[![PyPI Downloads][downloads_img]][downloads_ref]

Code Quality/CI:

[![Build Status][build_img]][build_ref]
[![Type Checked with mypy][mypy_img]][mypy_ref]
[![Code Coverage][codecov_img]][codecov_ref]
[![Code Style: sjfmt][style_img]][style_ref]


|                 Name                |        role       |  since  | until |
|-------------------------------------|-------------------|---------|-------|
| Manuel Barkhau (mbarkhau@gmail.com) | author/maintainer | 2019-06 | -     |


<!--
  To update the TOC:
  $ pip install md-toc
  $ md_toc -i gitlab README.md
-->


[](TOC)

[](TOC)


# Implementation

## High Level Overview: Splitting and Joining Keys

If you are not a programmer, please forgive me starting with a technical description of SBK. The top priority at this point is to help other programmers so they can review the software. For now the documentation is geared towards programmers rather than novices and end users.

Without further ado, here is the basic idea. 

 1. Randomly generate your secrets: the Salt and your Brainkey. You always need both to load your wallet. Write down the Salt and keep it safe and secure, commit the Brainkey to your memory.
 2. Split the secrets into multiple SBK-Shares (eg. 5 of which a minimum threshold of 3 for recovery). You should keep each in a secure and physically separate location.
 3. Join a minimum of the SBK-Shares together in order to retreive your Salt and Brainkey. You only need to do this if either are lost/forgotten.
 4. Using your Salt, Brainkey and an optional `wallet-name`, you derive a wallet seed, which is used to load your wallet with Electrum.

<img alt="SBK Dataflow Diagram" src="https://mbarkhau.keybase.pub/sbk/sbk_dataflow_diagram.svg" height="650" />

Apart from giving a general overview, this doesn't tell you much of course. Some of the boxes might as well be labled with "Magic". The next few sections will explain the terms "Shamir's Secret Sharing" (SSS) and "Key Derivation Function" (KDF) in more detail.

## Shamirs Secret Sharing

### Prelude: Naive Key Splitting

It's fairly obvoius why you might want to split a secret key into multiple parts: Anybody who finds or steals the full key will have access to your wallet. To reduce your risk if being robbed, you can split the key into multiple parts. 

If for example you have a wallet seed of 12 words "abcd efgh ijkl", you could split it into fragments: "1: abcd", "2: efgh", "3: ijkl". This way each cannot be used by itself and to recover your wallet. The downside is that you increase the risk of losing your wallet: If you lose even one fragment, you lose the whole wallet.

To reduce this risk, you might want to add redundancy by making a copy of your each fragment: "4: abcd", "5: efgh", "6: ijkl".

There are two downsides to this approach:

 1. Some of the fragments are identical or have overlapping parts of the secret. and so the redundancy is not as great as you might hope. This means that two fragments could be lost and if they are the only ones with that part of the secret (for exapmle fragment 1 and 4), then you may have lost your wallet.
 2. If a fragment falls in the hands of an attacker, they can try to guess the remaining 8 words, which is a factor of 2048**4 = 17.592.186.044.416 fewer combinations to search through than if they knew nothing about your wallet seed. If you have trusted people who turn end up colluding with each other (which they have a financial incentive to do) then, then they only have 2048**4 combinations left to search through.

There may be slightly more clever schemes along these lines, but fortunately there is a better alternative: Keys can be split into shares in a way that each share is completely independent of every other. This means that e.g. in a 3 of 5 scheme, any 2 can be lost and the remaining 3 can be used to recover the original key (solving problem 1.). In this scheme each individual share does not contain any useful information by itself, so that an attacker gains no advantage if they have fewer shares than the minimum threshold (solving problem 2.). This scheme is called Shamir's Secret Sharing.


### SSS: Shamir's Secret Sharing

To get an intuition of how SSS works, it is enough to recall high-school calculus.

Consider a point `A(x=1, y=a)` on the cartesian plane:

<img alt="Cartesian plane with single point A" src="https://mbarkhau.keybase.pub/sbk/sss_diagram_1.svg" height="220" />

Now consider a polinomial of degree 1 (aka. a linear equation, aka. a line) which goes through point A.

<img alt="Cartesian plane with line sloping down through points S, A and B" src="https://mbarkhau.keybase.pub/sbk/sss_diagram_2.svg" height="220" />

There are further points `S(x=0, y=s)` and `B(x=2, y=b)` through which the line goes. Recall that a polinomial of degree 1 is fully specified if you have any two distinct points through which it goes. In other words, if you have `A` and `B`, you can derive the parameters `j` and `k` in the equation `y = jx + k` and solve for `x=0` to get the `y` value of `S`. If you have *only* A or *only* B on the other hand, then there are an infinite number of lines you could draw through either. In other words, it is impossible to derive `S` from `A` individually, or from `B` individually. To take this further, we could have a point `C` and we could recover `S` if we had any two of `A`, `B` and `C`.

Similarly, for a polynomial of degree 2 (aka. a quadratic equation, aka. a parabola), we need at least three points through which the parabola goes, for it to be fully specified.

<img alt="Cartesian plane with parabola through points S, A, B and C" src="https://mbarkhau.keybase.pub/sbk/sss_diagram_3.svg" height="220" />

> Aside: Please forgive the limitations of the diagram software, the graph
> is supposed to represent a parabola with minimum roughly at `x=3`.

Using this insight, we can 

 1. Encode our brainkey as a number and generate `S(x=0, y=brainkey)`
 2. Generate random parameters `i`, `j`, `k`, ... for a polynomial which goes
    through `S`
 3. Calculate 5 points `A`, `B`, `C`, `D` and `E` which lie on the polynomial.
 4. Use polynomial interpolation to recover `S` using any 3 of `A` - `E`

The degree of the polynomial allows us control of the minimum number of points required to recover the secret (the threshold). Calculating additional/redundant points allows us to protect against the loss of any individual point.


### SSS: Some Implementation Details

There is more to story of course. I don't claim to understand in full how the attack works, but in the preceeding simplified/naive scheme there is some information leakage. Perhaps an attacker who knows fewer points than the threshold could narrow down their search space, because they know for example that the polynomial is continuous. I'm taking the cryptographer/mathematicians word that this is the case and that the solution to is to use finite field arithmetic.

Rather than doing calculations in the traditional cartesian plane, they are done in `GF(p)` or `GF(p^n)` (typically `GF(2^8) == GF(256)`. The current implementation of SBK uses `GF(p)` with a value for `p` that corresponds to the level of entropy of the brainkey. For a `--level=4` (64 bit) `brainkey` this would be `GF(2^64 - 59) == GF(18446744073709551557)`. Other Shamir's Secret Sharing schemes have chosen `GF(256)`. 

I did not choose this approach for SBK since:

 1. Implementing finite field arithmetic for `GF(p^n) | n > 1` rather than
    `GF(p)` was too complicated for me when I last attempted it. Arithmetic with
    `GF(p)` is easier to understand and should be easier to review.
 2. Since a computationally and memory intensive KDF is used to harden the
    Brainkey, low powered embedded systems are not a target for SBK.
 3. Python has native support for big integers, so arithmetic with large values
    is not an issue, which would otherwise be a motivation to use `GF(256)`.
    Since SBK uses Electrum (implemented with python), it is not an extra
    dependency to require a python interpreter. 

## Data Format

### Terms and Notation

|       Term        |                         Meaning                          |
| ----------------- | -------------------------------------------------------- |
| `brainkey`        |                                                          |
| `salt`            |                                                          |
| `&vert;&vert;`    | Concatenation: "abc" &vert;&vert; "def" -> "abcdef"      |
| `master_key`      | `master_key = brainkey &vert;&vert; salt`                |
| `salt_len`        |                                                          |
| `brainkey_len`    |                                                          |
| `master_key_len`  | `salt_len + brainkey_len`                                |
| `num_shares`      | The number of shamir shares to generate                  |
|                   | from the `master_key`.                                   |
| `threshold`       |                                                          |
| `wallet_name`     |                                                          |
| `prime`           | the prime number for GF(p). This is an index             |
|                   | into an array of predefined primes. The appropriate      |
|                   | prime is chosen based on the length of the `master_key`. |
| `kdf`             | Key Derivation Function. The algorithm used is           |
|                   | [Argon2](#key_derivation_using_argon2).                  |
| `kdf_parallelism` |                                                          |
| `kdf_mem_cost`    |                                                          |
| `kdf_time_cost`   |                                                          |
| `version`         |                                                          |


### Parameter Data

Before a brainkey or salt can be entered, their size must be known. Before a wallet can be loaded, the parameters used for key derivation must be known. These parameters must be entered first, whenever a wallet is loaded or recovered. The parameter data is encoded in 6 words and consists of the following parameters: 

|        Field        |  Size  |                          Info                           |
| ------------------- | ------ | ------------------------------------------------------- |
| `f_version`         | 4 bit  | ...                                                     |
| `f_brainkey_len`    | 4 bit  | max length: 2 * 2**4 = 32 bytes                         |
| `f_salt_len`        | 4 bit  | max length: 4 * 2**4 = 64 bytes                         |
| `f_threshold`       | 4 bit  | minimum shares required for recovery                    |
|                     |        | max length: 2**4 = 16 bytes                             |
| `f_kdf_parallelism` | 4 bit  | `ceil(2 ** n)   = kdf_parallelism` in number of threads |
| `f_kdf_mem_cost`    | 6 bit  | `ceil(1.5 ** n) = kdf_mem_cost` in MiB                  |
| `f_kdf_time_cost`   | 6 bit  | `ceil(1.5 ** n) = kdf_time_cost` in iterations          |

```
   0123456687ABCDEF
 0 [vv][bl][sl][th]
16 [kp][ km ][ kt ]
```


> Asside: While the threshold is encoded, the number of shares is not. It is not
> needed for recovery and is only used when shares are first being created.

> Asside: The brainkey must have a length which is a multiple of 2 and the salt
> must have a length which is a multiple of 4. This allows us to use 4 bits for
> each and have brainkey of length 32 and salt of length 64.

The parameters should be included with every share and also with the salt. 


### Share Data

Shares are generated based on the `master_key`, which is a concatenation of the
`brainkey` and the `salt`. The `master_key` represents the y coordinate at x=255. The x-coordinate for shares only has 4 bits available, so it will always be the case that `0 <= x < 128`. This prevents the [forced secret attack as described in point 3 of the "Design Rational" of SLIP-0039][href_slip0039_forced_secret].

| Field | Size  | Info |
| ----- | ----- | ---- |
| `x`   | 7bits |      |
| `y`   | 4bits |      |


[href_slip0039_forced_secret]: https://github.com/satoshilabs/slips/blob/master/slip-0039.md#design-rationale


## Key Derivation using Argon2

Every wallet seed generated by SBK is ultimately derived from a random `salt` (with significant default entropy of `--salt-len=20` or ~160bits) and a random `brainkey` (with relatively low default entropy of `--brainkey-len=8` or 64bits). SBK uses the [Argon2][href_github_phc_winner_argon2] [key derivation/password hashing function][href_wiki_kdf] with parameters chosen so that the key derivation process takes on the order of a few minutes. This means that even for a relatively short and more easilly memorized `brainkey`, it will not be feasable to brute-force your wallet. Your wallet will be protected for decades to come, even assuming an attacker gains access to your `salt` and even assuming the forseeable evolutions in computing technology[^fnote_quantum_resistance]. The price is that you have to wait for your wallet to load, so you will probably want an additional hot wallet for smaller and more frequent transactions.

Some back of the envelope calculations to illustrate the diffuculty of a brute force attack: If we assume the attacker has gained access to your `salt`, then they will have a 50% chance of loading your wallet if they can calculate 2^63 hashes. Let's assume you used an average computer from 2012 as your airgapped computer and the Argon2 parameters which SBK chose were `time_cost=25` and `memory_cost=1024MB`. This might take 1-2 minutes to calculate, but on my more modern system, each hash with these parameters takes ca. 15 seconds. For easy math and to be conservative, let's assume that an attacker has access to future hardware that can calculate these hashes in 1 second, further assume that they have unlimited access to 1 million systems of this caliber (and more money to spend on electricity than they could ever get from your wallet). After `2**63 / (1_000_000 * 86400 * 365.25) = 292271` years they would have 50:50 chance to have cracked your wallet. It would be cheaper for them to knock down your door. Beware of shorter keys lengths though: if you use a brainkey of only `--brainkey-len=6` (48 bits), the same attacker would need less than 5 years, at `--brainkey-len=4` (32 bits), they would need only `2**31 / (1_000_000 * 60) = 36` minutes.

All of this is assuming of course, that they somehow gained access to your `salt`. It may be ok for you to use a lower `--brainkey-len` for your `brainkey` if you can satisfy one of these conditions: 

 - You are confident that your `salt` will never be found by anybody other than you.
 - If your `salt` is found by anybody, then you have some way to know that this happened. If you can make sure of this, then you will at least have enough time to move your funds to a new wallet. 

Even so, I would reccomend a brainkey of at least `--level=3` (48bits).

If you do not wish to ever use the `salt+brainkey` method to load your wallet, then you can simply discard them during the initial generation. To recover your wallet, your only option will then be to collect and join the SBK-Shares. If you find yourself the the subject of a [$5 wrench attack][href_xkcd_538], you can plausibly deny that you memorized the `brainkey` and say that your attackers will have to go to the locations where you put and people/institutions to whom you gave the SBK-Shares. Non-state attackers may find it difficult to convince a bank to open safety deposit box. Assuming state attackers can even find out who your trustees are, they may find it difficult to convince enough of them to betray you.

[href_github_phc_winner_argon2]: https://github.com/P-H-C/phc-winner-argon2

[href_xkcd_538]: https://xkcd.com/538/

[^fnote_quantum_resistance]: Even with access to a quantum computer, it is my understanding that there are no algorithms which improve on a brute-force attack by more than a factor of two. While the seed derivation may be quantum resistant, the existing caveats wrt. [quantum resistance of Bitcoin][href_bitcoin_it_quantum_resistance] itself still apply.

[href_wiki_kdf]: https://en.wikipedia.org/wiki/Key_derivation_function

[href_bitcoin_it_quantum_resistance]: https://en.bitcoin.it/wiki/Quantum_computing_and_Bitcoin#Mitigations


## Wallet Name/Phassphrase

While we're on the topic of [plausible deniability][href_wiki_plausible_deniability]: You can use a single `salt+brainkey` to generate multiple wallet seeds. To do this, provide an additional `wallet-name` for each wallet. One of these wallets (usually the unnamed default wallet) might not be your main wallet, but rather it can be a decoy. If you are under duress and forced to divulge your `salt+brainkey`, then the attackers will probably start by loading the default wallet and if they are happy enough with what they find, they may never be the wiser and let you free. Or if they press you further, you can give them a different `wallet-name` which is perhaps also a decoy. 

This is a powerful feature, but it can also put you at a great risk of loss. Since the `wallet-name` is effectively a passphrase, it suffers from the same problem as all passphrases: they can be forgotten. One of the main purposes of SBK is to protect you from loss. If you introduce a single point of failure, then you have negated much of this protection. A `wallet-name` that is only known to you can be forgotten. A secret written on a single piece of paper might be destroyed.

If you use a `wallet-name`, I reccomend to not make it too complicated: Simple words, all in lower case, no punctuation. Everybody who might be involved in the recovery process, should either 

 1. Have access to the wallet names
 2. Have a guaranteed to work way to gain access to the wallet names at the appropriate time.

You might satisfy 1. for example by writing all wallet names down on each SBK-Share or by sending them to those who will be responsible for your estate.

[href_wiki_plausible_deniability]: https://en.wikipedia.org/wiki/Plausible_deniability


## Encoding Secrets: Mnemonics and Intcodes

> Aside: The work done in this section preceeded the release of Trezor Shamir Backup, which has many similarities to it. Shamir Backup uses [Reed Solomon Codes][href_wiki_rscodes] to generate a checksum for error detection. SBK uses more simple [Luby Transform Codes][href_wiki_ltcodes] to implement forward error correction. The wordlists of both are composed with similar considerations for length, edit distance and phonetic distinctness.

The main reasons to introduce a new encoding are:

 1. To aid in memorization of the `brainkey`
 2. Provide protection against input errors
 3. Provide [forward error correction][href_wiki_fec] 

In addition to the mnemonic encoding, the `salt` and the `sbk-shares` use a more compact encoding of the same data in the form of numeric `intcodes`. These encode not only the same raw data as the mnemonic encoding, but also positional indexes and an error correction code to provide additional protection against degradation. This more compact encoding can be entered more quickly with a keypad and is also better suited for use with fire resistent physical storage media, such as [billfodl](https://billfodl.com/], [cryptosteel](https://cryptosteel.com) or punch stamps used with sheet metal.

```
     Data                       Phrases                      ECC
A0: 260-366   The BRAVE  KING   at the LONDON GARDEN.   C0: 393-499
A1: 179-279   The HONEST DRIVER at the SEOUL  TEMPLE.   C1: 247-686
A2: 568-746   The SCARY  MOTHER at the MIAMI  CASTLE.   C2: 436-261
B0: 882-669   The UGLY   DOCTOR at the VIENNA FOREST.   D0: 603-993
B1: 406-997   The LONELY LEADER at the SEOUL  SCHOOL.   D1: 105-856
B2: 618-612   The EVIL   PRINCE at the CAIRO  OPERA.    D2: 935-672
```

This corresponds to these raw bytes: `\x04\x56\x83\xcf\xd8\x72\xe2\xf5\x96\xcd\x3a\x1c`.

[href_wiki_rscodes]: https://en.wikipedia.org/wiki/Reed%E2%80%93Solomon_error_correction

[href_wiki_ltcodes]: https://en.wikipedia.org/wiki/Luby_transform_code

[href_wiki_fec]: https://en.wikipedia.org/wiki/Forward_error_correction


### Mnemonic for Memory

> Caveat: All of this is based on conjecture. It may be that memorizing fewer words from larger wordlists is easier, however larger wordlists come at the price of edit/levenshtein distance, word length, phonetic distinctiveness and ease of use for non-native speakers of English.

From personal experience I know that it is possible to remember phone numbers, mathematical constants, poems and even my old ICQ number even after multiple decades. In light of this, a brainkey can be a reasonable choice to generate a wallet, as long as

 1. you regularly recall the brainkey, so that your brain becomes habituated to it and
 2. the brainkey is not a single point of failure.

SBK uses the same mnemonic phrases both for SBK-Shares as well as for the `salt` and `brainkey`. The format is designed with the following in mind:

 - Human memory is not good at remembering random abstract words, it is better at remembering concrete objects, people and places
 - Human memory fills in gaps (often incorrectly) so ambiguous words must be avoided. 

There are two wordlists, which are used in alternation. 

 1. The first wordlist is composed of nouns which are physical entities, such as animals, famous people, and movable objects or materials. Consider that the very first word humans ever spoke may have been have been the equivalent of "mother" or "snake", rather than words for abstract concepts such as "agency" or "ambition". 
 2. The second wordlist is composed of locations and organizations. Generally speaking, a place where an entity might come from, where it might be located or to which it might belong.

> Some words on the wordlist may be provocotive/obscene, such as "viagra" and "saddam", but they are used precisely for that reason: provocative words are more memorable than boring words, as I'm sure many parents with potty-mouthed children will attest. 

This allows you to use the [Method of Loci][href_wiki_method_of_loki] or for you to construct a story as a memory aid around your brainkey. Here is an example of a phrase:

    pineapple kinshasa, shampoo liverpool.

This structure aims to take advantage of ability of humans to remember what has been very important to us throughout history: stories about people and places. As an example, you might have a `brainkey` with `--level=4`, which encodes 64 bits of entropy in 4 phrases.

    The BRAVE  CHILD  at the MADRID STAGE.
    The HAPPY  SISTER at the SEOUL  GHETTO.
    The DIRTY  BAKER  at the LONDON TEMPLE.
    The HONEST TAILOR at the SPARTA BEACH.

Sparta doesn't really exist anymore of course, and even when it did, it wasn't next to the ocean, so I'd be surprised if there was anything one might call a beach. A ghetto doesn't sound like something I that exists in Seoul, but then again I've never been there so maybe it's this Gangnam thing from the song? Anyway, these are words chosen at random, so they may not make any sense. What they allow you to do though, is to make sense of them by constructing a stories with quirky characters in strange places. 

[href_wiki_method_of_loki]: https://en.wikipedia.org/wiki/Method_of_loci


### Integer Codes

Each intcode consists of 6 decimal digits and represents two bytes of data. The data of each code can be obtained by parsing the code as a decimal integer masking with `& 0xFFFF`. The index of each code can be obtained by bit shifting with `>> 16`. Each intcode is formatted as two tripplets, such as `117-502` and `768-702`. The dash do not need to be entered, they are only to make the code easier to read.

```
117502 & 0xFFFF == 0xCAFE
117502 >> 16 == 1
768702 & 0xFFFF == 0xBABE
768702 >> 16 == 11
```

The encoding for a single intcode has the following layout:

```
ii: index
b0: data byte0
b1: data byte1 

[       ~20 bits       ]
iiii b0b0 b0b0 b1b1 b1b1
```

The eagle-eyed may observe that `2 ** 20 == 1048576`, which is slightly larger than `10 ** 7 - 1 == 999999`. So while the binary representation consumes 20 bits, the decimal representation never exceets 6 digits.

Since recovery involves the input of multiple `sbk-shares` and the key derivation takes time, a lack of protection against intput errors would make it time consuming to discover which `sbk-share` was entered incorrectly. To mitigate such issues, each incode encodes it's position to protect against words being skipped or entered in the wrong order. The maximum index is 13 which is adequate to check for skipped inputs even before the ECC data has been endered.


### FEC: Luby Transform Codes

> Aside: 


As `sbk-shares` may be stored for long periods and could deteriorate or be partially destroyed through bad handling, adding forward error correction provodes some protection and gives a better chance of recovery.

TODO: implementation details

## High Level Pseudocode

> [..] Show me your [datastructures],
>   and I won’t usually need your flowcharts;
>   they’ll be obvious. 
>   
>   — Fred Brooks

To conclude the technical overview, here is some pseudocode with more details of the data layout.

```python
class Params:
    """Parameters required for key derivation and recovery."""

    version         : int   # 3 bits
    shamir_threshold: int   # 5 bits (32 shares)
    # Key length in bytes must be a multiple of 4. It is
    # used to 
    key_len_num     : int   # 4 bits
    kdf_index       : int   # 

    # Derived fields: These can be derived from the above,
    # using pre-defined constants in SBK.
    key_length_bytes: int
    shamir_prime    : int   # Based on the key length
    memory_cost     : int   # Argon2 memory_cost
    time_cost       : int   # Argon2 time_cost

    def encode(self) -> bytes:
        """Returns 2 byte representation of params."""
        ...
        return struct.pack('BB', field0, field1)

    @staticmethod
    def decode(self, params_data: bytes) -> Params:
        """Returns 2 byte representation of params."""
        field0, field1 = struct.unpack('BB', params_data)
        ...
        return Params(...)


def kdf(secret: bytes, salt: bytes, params: Params) -> bytes:
    """"Key Derivation Function using argon2."""
    return argon2(
        secret=brainkey,
        salt=salt,
        memory_cost=params.memory_cost,
        time_cost=params.time_cost,
        hash_len=params.key_length,
    )

# 8 bytes/64 bits
#
# This should be small enough to memorize, and
# given the use of Argon2 with a large seed, is
# large enough to be safe from brute force.
KEY_LEN_BYTES = 8
SALT_LEN_BYTES = 24

brainkey = os.urandom(KEY_LEN_BYTES)
brainkey_mnemonic = mnemonic_encode(brainkey)

print(f"Memorize brainkey: {brainkey_mnemonic}")

params = Params(...)
param_data: bytes = params.encode()

# The salt is actually both the salt as well
# as the serialized parameters.
raw_salt = os.urandom(SALT_LEN_BYTES)
salt = param_data + raw_salt

salt_text = mnemonic_encode(salt)
print(f"Write down salt: {salt_text}")

# derive the master key
master_seed = kdf(brainkey, salt, params)

sbk_shares = shamir_split(
    master_seed,
    params.threshold,
    params.num_shares,
    params.shamir_prime,
)
for i, share in enumerate(sbk_shares):
    share_text = mnemonic_encode(share)
    print(f"Write down share {i + 1}: {share_text}")
```


## Platform Security

A broad set of software is required to run SBK. This starts with the browser you use to download software, goes on to the PGP software you use to verify your downloads and includes further:

 - The Electrum wallet
 - The libraries bundled with SBK
 - The Operating System (eg. Debian 10 used for the iso image)

The security of the software you use can be thought of in these terms:

 1. Trustworthy: The software (the whole stack!) was created without malicious intent by maintainers who know what they are doing.
 2. Authentic: The files you downloaded are the same ones that were created by the people you trust to not have malicious intent (as opposed to by a phishing scammer that tricked you by being the first link on google).
 3. Available: If the software you use to create your wallet is gone, then your coins might be gone too.

### Is SBK Trustworthy?

The main way to judge if software is trustworthy is to look at how widely it is used and how old it is. The more people who use it and the longer they have been using it, the more people who have looked at it who would have found issues if there were any. In essence, you're trusting an open source process, rather than any particular person.

### Is Your SBK Download Authentic?

### Will SBK Remain Available?

Just because your humble author is trustworthy today, doesn't mean they will be trustworthy tomorrow. They might be put under duress, they might aquire an expensive hobby etc. One thing you can do to reduce this concern is to keep a copy of the original software that is available today, for example by distributing it on USB Sticks with each share that you create. If the downloads are no longer available,  

Beyond concerns that all of this software is free from malicious code, there is also the concern that one part of these will no longer be available in the future or that security issues are discovered but no developers are willing to fix them in a timely manner. 


## Future Work

### Vendoring

### SLIP0039

Notwithstanding the reasons for custom implementation choices for SSS, it is worth following parts of SLIP0039. Particularly from the perspective of code review, an implementation that is not bespoke to SBK will probably receive more review and may have a better chance of being correct. Contributions are most welcome (and given the existing work done in the context SLIP0039 such contributions should be relatively simple).

I consider some aspects of SLIP0039 to be overly complicated for the purposes of SBK, these include:

 - Groups: Groups can be used to generate shares with different levels of trust. More shares would be required for groups that are trusted less. For the sake of simplicity, this feature is not implemented with SBK. To the extent that SLIP0039 is followed, the group parameters are chosen to correspond to single group splitting at the second level, i.e. GT = 1, G = 1, T₁ = T and N₁ = N.
 - Master Secret Encryption: SBK does not support migrating BIP-32 wallets so there is no need to implement a mechannism to split a user chosen master secret. 
 - Encoding: Since SLIP0039 does not use a `brainkey+salt` but rather it splits a master secret, it encodes parameters as part of each share.
 - Checksums: Shares are tedious enough to copy and enter as it is, so if a user is going to copy redundent data, it is preferable that this data be used for forward error correction rather than mere error detection.

[href_pointsoftware_ssssbs]: http://www.pointsoftware.ch/en/secret-sharing-step-by-step/

### Distruibution

 - Signatures


# User Guide

> Always remember: Your keys, your coins; not your keys, not your coins.
> 
> The security of your wallet begins and ends with you. There are no banks to take care
> of your security, there are no institutions to run to if something goes wrong.
>
>  - If you are a trustee, don't trust anybody who asks you to hand them your
>    `sbk-share`.
>  - If you are the owners agent, familiarize yourself with and adhere to the recovery
>    protocol.
>  - If you are the owner, trust as few people as possible and only trust people who you
>    regard as not only righteous but also competent.

While we started with the technical aspects of SBK, compared with the human aspects of security, they are almost ancilarry. When talking about security for this kind of system, the most difficult are all the parts that humans can mess up. This starts with simple things like prevending transcription and input errors and ends with more philosophical questions like "who can you trust?".

Throughout this guide, I will assume the most paranoid position I can imagine. This may seem over the top for your situation, . 

Further Reading: [Social Key Recovery][href_github_skr]

[href_github_skr]: https://github.com/WebOfTrustInfo/rwot8-barcelona/blob/master/topics-and-advance-readings/social-key-recovery.md


## Trustee Guide

### Integrity and Seals

Imagine for example the owners agent is attempting to collect your `sbk-peice` without you noticing.


## Agent Guide

The agent acts on behalf of the owner if they cannot act themselves. This may be the case if the owner has died or has been incapacited in some way. The agent of the owner is responsible to act on their behalf according to their will (if provided) or in their best interests.

The primary responsibility of an agent is to recover the wallets of the owner without compromising their security. The agent is the person who is most likely to be in a position to steal the owners coins and so their actions deserve special scruitiny. Trustees should be especially weary of an agent who asks them to simply hand over their `sbk-share`. A trustee should be the only person to unsealing and input their `sbk-share` on 

The trustees should be watching and scruitinizing you. Provide them with any information they ask for, do not ask them for any information whatsoever. 

 - There should be a mutual understanding among all participants what will happen to the coins. If wallet balances are already known, you should prepare a payment request for each transaction that is to occur. 
 - 


## Owner Guide


### Paper Backup

Justification of
 - Ceremony
 - Format

### Airgapped Computer

 - Hardware Choices
 - Iso Image
 - Verify Signatures

### Recovery form SBK-Shares: Risks


### Recovery form SBK-Shares: Guide

There are three areas of risk to be aware of:

 - Lost of Secrets
 - Game theoretical risks
    - Holdouts
    - Decoy `sbk-shares`
    - Insecure hardware
 - Compromised Software

> Aside: SBK exists in part to provide documentation to the owners trustees and agents, who may be laypeople wrt. cryptocurrency.




# Unsorted


## Related Work and Alternatives

 - Why not Multisig?

Considering that SBK is not yet ready to be used, here are some other related projects that may serve your purposes better for the time being.

### Warp Wallet

Warp [href_keybase_warp]

[href_keybase_warp]: https://keybase.io/warp/

### Trezor Shamir Backup

A project with similar functionality was recently released by SatoshiLabs: [Shamir Backup][href_satoshilabs_sharmirbackup_overview]. The standardization efforts by SatoshiLabs are great I hope future versions SBK can implemenet them.

The main reasons to consider SBK are:

 - SBK does not require a hardware wallet
 - SBK wallets can be restored with a brainkey

If neither of these are an issue for you, I highly reccomend you buy a [Trezor Model T][href_trezor_modelt] and use it to [create a Shamir Backup][href_satoshilabs_sharmirbackup_wiki].


[href_satoshilabs_sharmirbackup_overview]: https://blog.trezor.io/shamir-backup-a-new-security-standard-3aa42a6ebb5f

[href_trezor_modelt]: https://shop.trezor.io/product/trezor-model-t?offer_id=15&aff_id=3376

[href_satoshilabs_sharmirbackup_wiki]: https://wiki.trezor.io/User_manual-Creating_a_wallet_with_Shamir_Backup




[href_pai_ssss]: http://point-at-infinity.org/ssss/)
[href_ssss_js]: https://github.com/gburca/ssss-js

[repo_ref]: https://gitlab.com/mbarkhau/sbk

[build_img]: https://gitlab.com/mbarkhau/sbk/badges/master/pipeline.svg
[build_ref]: https://gitlab.com/mbarkhau/sbk/pipelines

[codecov_img]: https://gitlab.com/mbarkhau/sbk/badges/master/coverage.svg
[codecov_ref]: https://mbarkhau.gitlab.io/sbk/cov

[license_img]: https://img.shields.io/badge/License-MIT-blue.svg
[license_ref]: https://gitlab.com/mbarkhau/sbk/blob/master/LICENSE

[mypy_img]: https://img.shields.io/badge/mypy-checked-green.svg
[mypy_ref]: https://mbarkhau.gitlab.io/sbk/mypycov

[style_img]: https://img.shields.io/badge/code%20style-%20sjfmt-f71.svg
[style_ref]: https://gitlab.com/mbarkhau/straitjacket/

[pypi_img]: https://img.shields.io/badge/PyPI-wheels-green.svg
[pypi_ref]: https://pypi.org/project/sbk/#files

[downloads_img]: https://pepy.tech/badge/sbk/month
[downloads_ref]: https://pepy.tech/project/sbk

[version_img]: https://img.shields.io/static/v1.svg?label=PyCalVer&message=v201906.0001-alpha&color=blue
[version_ref]: https://pypi.org/project/pycalver/

[pyversions_img]: https://img.shields.io/pypi/pyversions/sbk.svg
[pyversions_ref]: https://pypi.python.org/pypi/sbk
