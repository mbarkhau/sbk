# Implementation Overview

For the time being, the documentation is mainly for contributors rather than users. You can skip ahead to the [User Guide](#user-guide) if implementation details are not important to you.

> *Aside*: If you are doing code review, please be aware that some portions of the
>   implementation, which might otherwise be deleted, are preserved for future didactic
>   use as I rewrite SBK into a literate program. This relates in particular to the
>   [Luby Transform][href_wiki_ltcodes] based ECC in `sbk/ecc_lt.py` and the $`GF(p)`$
>   arithmetic in `sbk/gf.py`.

[href_wiki_ltcodes]: https://en.wikipedia.org/wiki/Luby_transform_code


## High Level Overview: Generating, Joining and Using Keys


<!-- TODO: alt="SBK Data-flow Diagram" -->

```bob
                    "1. Generate Keys"      "3. Load Wallet"

                     .---------------.    .---------------.
                     |  "Random Data"|    |  "Wallet Name"|
                     '-------o-------'    '-------o-------'
                             |                    |
                     .-------+-------.            |
                  .--o      Salt     o--.         V
  +---------+    /   +---------------+   \    +--------+
  |  Split  |<--+----o    Brainkey   o----+-->+  KDF   |
  +----*----+        '-------+-------'        +---*----+
       |                     ^                    |
       V                     |                    |
.-------------.              |                    V
|    Shares   +-.       +----*----+        .-------------.
'-+-----------' o------>+   Join  |        |    Wallet   |
  '-------------'       +---------+        '-------------'

 "2. Recover Keys"
```

This diagram can only tell so much of course (some of the boxes might as well be labeled with "magic"). The next few sections explain in a little more detail how each step works.


### Key Generation

Steps involved in key generation:

 1. Invoke the `sbk create` command.
 2. Optionally specify `--scheme` (default is `"3of5"`, for a total of 5 shares, any 3 of which are enough for recovery).
 3. Optionally specify `kdf-parameters`. These are `-p / --parallelism`, `-m / --memory-cost` and `-t --time-cost`. If not specified, these are chosen automatically based on the available memory and processing resources of your system.
 4. The `salt` and `brainkey` are randomly generated.
 5. The `shares` are generated from the `salt` and `brainkey`.
 6. The mnemonic encoding for each of the above secrets is shown for the user to copy onto paper (or memorize in the case of the `brainkey`).


### Key Recovery

Let's assume that you've already forgotten your `brainkey`, or that your handwriting is so bad that you can't read your `salt` anymore. To recover both, you can join/combine the backup `shares`:

 1. Invoke the `sbk recover` command.
 2. Enter as many `shares` as required.
 3. The `shares` are joined using Shamir's Secret Sharing and the resulting secret is split into the `salt` and `brainkey`.
 4. Write down `salt` and `brainkey`.

Note that the wallet is not loaded directly, instead the recovery produces the `salt` and `brainkey`. Loading the wallet is a separate step.


### Loading Wallet

You can load the wallet if you have the `salt` and `brainkey`, either directly as the owner, or after you have recovered them from the backup `shares`.

 1. Invoke the `sbk load-wallet` command.
 2. Optionally specify a `--wallet-name`.
 2. Enter the `salt` and `brainkey`.
 4. The `wallet-seed` is derived using the KDF.
 5. The Electrum Wallet file is created in a temporary directory (in memory only if supported).
 6. The Electrum GUI is started in offline mode (use `--online` if you are not using an air-gapped computer).
 7. Use wallet/sign transactions...
 8. Once you close the wallet, all wallet files are [overwritten and deleted][href_wiki_data_remanence].

[href_wiki_data_remanence]: https://en.wikipedia.org/wiki/Data_remanence


## Shamir's Secret Sharing

This section describes how the `shares` are generated.

> Aside: Since the writing of this section, two nice introduction videos to secret sharing have been published. One is [
Secret Sharing Explained Visually
 by Art of the Problem](https://www.youtube.com/watch?v=iFY5SyY3IMQ) and another is [How to keep an open secret with mathematics.
 by Matt Parker/standupmaths](https://www.youtube.com/watch?v=K54ildEW9-Q).


### Prelude: Naive Key Splitting

It's fairly obvious why you might want to split a secret key into multiple parts: Anybody who finds or steals the full key will have access to your wallet. To reduce the risk if being robbed, you can split the key into multiple parts. If somebody finds such a fragment, it will not be enough to access your wallet.

If for example you have a wallet seed of 12 bytes `"abcd efgh ijkl"` (with 96 bits of entropy), you could split it into fragments: `"1: abcd"`, `"2: efgh"`, `"3: ijkl"`. This way each fragment (by itself) is not enough to recover your wallet. The downside is that you increase the risk of losing your wallet: If you lose even one fragment, you also lose the wallet.

To reduce this risk, you might want to add redundancy by making more fragments: `"4: cdef"`, `"5: ghij"`, `"6: klab"`. Now if fragment 1 is lost, you may still have access to fragment 4 and 6 from which you can still recover the secret.

There are two downsides to this approach:

 1. Some of the fragments may be identical or have overlapping parts, so the redundancy is not as great as you might hope: Two fragments could be lost and if they are the only ones with a specific part of the secret (for example fragment 1 and 4 are the only ones with the bytes `cd`), then you may have lost your wallet, even though you have 4 other fragments that are perfectly preserved.
 2. If a fragment falls in the hands of an attacker, they can try to guess the remaining 8 bytes, which leaves a search space of $` 2^{64} `$ as opposed to the full $` 2^{96} `$. If you have wrongfully trusted two people, and they collude with each other (which they have a financial incentive to do), then they may have only $` 2^{32} `$ combinations left for their brute-force search.

There may be slightly more clever schemes along these lines, but I won't go into them, as this was just to serve as a motivation for the more complex but better alternative used by SBK: Shamir's Secret Sharing.


### SSS: Shamir's Secret Sharing

With SSS, a key can be split into `shares` such that each `share` is completely independent of every other. Assuming `--scheme=3of5`:

 1. Any two `shares` can be lost and the remaining three are enough to recover the original key.
 2. Any individual `share` (or subset of `shares` below the `threshold`) is useless. This means that access to fewer than three `shares` does not provide an attacker with any advantage if they attempt to brute-force a wallet seed.

To get an intuition of how SSS works and why it is secure, it is enough to recall some high-school calculus.

Consider a point `S(x=0, y=s)` on the Cartesian plane, where the coordinate `y=s` is your secret encoded as a number:

<!-- TODO: alt="Cartesian plane with single point S" -->

```bob
    Y ^
      !
      !
  .~  *~~ "S(x=0, y=s)"
  |   !
  |   !
  |   !
  '   !
 y=s  !
  .   !
  |   !
  |   !
  '~  +~~~~~~~~~~~~~~~~~~~>
      0  1  2  3  4  5    X
```

Now consider $` y = jx + k `$, a polynomial of degree 1 (aka. a linear equation, aka. a line equation) which goes through point `S` and further points `A(x=1, y=a)` and `B(x=2, y=b)`.

<!-- TODO: alt="Cartesian plane with line sloping down through points S, A and B" -->

```bob
    Y ^
      !
     \!
  .~  *~~ "S(x=0, y=s)"
  |   !\
  |   ! \
  |   !  *~~ "A(x=1, y=a)"
  '   !   \
 y=s  !    *~~ "B(x=2, y=b)"
  .   !     \
  |   !      \~~"y = jx + k"
  |   !       \
  '~  +~~~~~~~~~~~~~~~~~~~>
      0  1  2  3  4  5    X
```


Note that the parameter `j` is generated randomly and `k` is our secret `s`, so that if `x=0` then `y=s`. Recall that a polynomial of degree 1 is fully specified if you have any two distinct points through which it goes. In other words, if you know `A` and `B`, you can derive the parameters `j` and `k` of the equation `y = jx + k` and solve for `x=0` to recover `y=s`. If on the other hand, you have *only* `A` or *only* `B`, then there are an infinite number of lines which go through either. In other words, it is impossible to derive `S` from `A` alone or from `B` alone. To complete the picture, we could generate a further point `C`, so that we only require any two of `A`, `B` and `C` in order to recover `S`. This allows us to create a `2of3` scheme.

Similarly we can create a `3ofN` scheme with a polynomial of degree 2 (aka. a quadratic equation, aka. a parabola), a `4ofN` scheme with a polynomial of degree 3 (aka. a cubic equation) and so on.

<!-- TODO: alt="Cartesian plane with parabola through points S, A, B and C" -->

```bob
    Y ^
      !
     \!
  .~  *~~ "S(x=0, y=s)"
  |   !\                /
  |   ! \              *~~ "C(x=2, y=c)"
  |   !  *~~ "A(...)" /
  '   !   \          /
 y=s  !    \        *~~ "B(x=2, y=b)"
  .   !     \      /
  |   !      \    /~~"y = ix² + jx + k"
  |   !       '--'
  '~  +~~~~~~~~~~~~~~~~~~~>
      0  1  2  3  4  5    X
```

!!! caption ""
    Please forgive the limitations of the diagram software, the graph
    is supposed to represent a parabola with minimum roughly at `x=3`.

Using this approach, we can

 1. Encode a `secret` as a point: `S(x=0, y=secret)`
 2. For a polynomial $` y = ix^2 + jx + k `$ which goes through `S`, we choose `k=secret` and random values for `i` and `j`.
 3. Calculate 5 points `A`, `B`, `C`, `D` and `E` which lie on the polynomial (but which **crucially are not** at `x=0`, which would cause the secret to be leaked).
 4. Use polynomial interpolation to recover `S` using any 3 of `A`, `B`, `C`, `D` or `E`.

The degree of the polynomial allows us control of the minimum number (aka. the `threshold`) of points/`shares` required to recover the secret. Calculating redundant `shares` allows us to protect against the loss of any individual `share`.


### SSS: Choice of Galois Field

There is more to the story of course. My understanding is that the preceding scheme (which uses the traditional Cartesian plane) does not offer complete information security. Some information about the secret is leaked with each `share` and while an attacker who knows fewer points than the `threshold` may not be able to instantly determine the secret, they could at least derive some information to reduce their search space. I'm taking the cryptographer/mathematicians by their word that the solution is to use [finite field arithmetic][href_wiki_galois_field].

Rather than calculating inside the Cartesian plane, we use either $` GF(p) `$ ( $`p`$ being a prime number ) or $` GF(p^n) `$ ( $` p^n `$ being a power of a prime number, typically $` GF(2^8)`$ aka. $` GF(256)`$ ). In a previous iteration of SBK, $` GF(p) `$ was used, with a value for $`p`$ that corresponds to the level of entropy of the `brainkey`. The list of primes was from the largest that could satisfy $` 2^{n}-k \le 2^n `$ [oeis.org/A014234][href_oeis_a014234]. For the default secret length of 20 byte/160 bit this would have been $` GF(2^{160 - 47}) `$. As you may see, this number exceeds the native integer representation of most computer architectures, which is one of the main reasons this approach typically isn't used.

In principle it would have been fine[^fnote_gfp_bignum] for SBK to use $` GF(p) `$, but since other implementations typically use $` GF(256) `$ and innovation in cryptography is usually not a good thing, this is what SBK now also uses. The specific field used by SBK has been broadly studied already, which should make validation easier, even though the requirement for polynomial division makes arithmetic a bit harder to follow. The specific field uses the Rijndael irreducible polynomial $` x^8 + x^4 + x^3 + x + 1 `$, which is the same as [SLIP0039][href_wiki_slip0039_sss] and (perhaps more importantly) [AES/Rijndael][href_doi_org_rijndael][^fnote_gf_rijndeal_validation].

[href_wiki_galois_field]: https://en.wikipedia.org/wiki/Finite_field

[href_oeis_a014234]: https://oeis.org/A014234

[href_wiki_slip0039_sss]: https://github.com/satoshilabs/slips/blob/master/slip-0039.md#shamirs-secret-sharing

[href_doi_org_rijndael]: https://doi.org/10.6028/NIST.FIPS.197


[^fnote_gfp_bignum]: Reasons it may have been fine to use $`GF(p)`$

    - A common reason to use $`GF(256)`$ is to be compatible with low-end systems. Since SBK uses a computationally and memory intensive KDF, systems with constrained CPU and RAM defeat the purpose of SBK and are not a target. Such systems would either take a long time to derive a hardened `wallet-seed` or these seeds would be cracked more easily by machines that are much more powerful and easily obtained.
    - $`GF(256)`$ uses arithmetic that is natively supported by practically every programming language and hardware platform. Depending on the size of $`p`$, a $`GF(p)`$ field requires support for big integers. Python has native support for big integers, so arithmetic with large values is not an issue for SBK. Since SBK uses Electrum (which is implemented with python), it is not an extra dependency for SBK to require a python interpreter.
    - Implementing finite field arithmetic for $`GF(p)`$ is slightly easier to understand and should be easier to review.

[^fnote_gf_rijndeal_validation]: I was quite happy to see the same numbers pop out as for [the reference implementation of SLIP0039](https://github.com/trezor/python-shamir-mnemonic/)


## Implementation Details

### Terms and Notation

|   Term/Notation   |                                              Meaning                                              |
|-------------------|---------------------------------------------------------------------------------------------------|
| `version`         | Version number to support iteration of the data format.                                           |
| `flags`           | A bit-field for options (eg. segwit)                                                              |
| `brainkey_len`    | Length of the `brainkey` in bytes.<br/>min: 2, max: 32, default: 8                                |
| `threshold`       | Minimum number of shares required for recovery.<br/>min: 1, max: 16, default: 3                   |
| `num_shares`      | The number of shamir shares to generate from the `master_key`.                                    |
| KDF               | Key Derivation Function.<br/>The algorithm used by SBK is [Argon2](#key_derivation_using_argon2). |
| `kdf_parallelism` | The degree parallelism/number of threads used by the KDF.                                         |
| `kdf_mem_cost`    | Amount of memory in MiB filled by the KDF.                                                        |
| `kdf_time_cost`   | Number of passes over the memory used by the KDF.                                                 |
| `parameters`      | 4 byte encoding of parameters required by `sbk load-wallet`.                                      |
| &#124;&#124;      | Concatenation operator: `"abc"` &#124;&#124; `"def"` -> `"abcdef"`                                |
| `raw_salt`        | 12 bytes of random data<br/>(main source of entropy for the `wallet_seed`).                       |
| `salt`            | `salt` = `parameters` &#124;&#124; `raw_salt`                                                     |
| `brainkey`        | Random data memorized by the owner of the wallet.                                                 |
| `shares_input`    | `shares_input` = `raw_salt` &#124;&#124; `brainkey`                                               |
| `raw_share`       | Encoded points in $`GF(256)`$.<br/>See [Share Data](#share-data)                                  |
| `share`           | `share` = `parameters` &#124;&#124; `raw_share`                                                   |
| `master_key`      | `master_key` = `salt` &#124;&#124; `brainkey`                                                     |
| `is_segwit`       | Determines the electrum seed type (default: `true`)                                               |
| `wallet_name`     | Identifier to generate multiple wallets from a single `master_key`.                               |
| `kdf_input`       | `kdf_input` = `master_key` &#124;&#124; `wallet_name`                                             |
| `wallet_seed`     | The Electrum seed derived from the `kdf_input`.                                                   |

For those keeping track, by default the total entropy used to generate the wallet seed is `12 + 8 == 16 bytes == 160 bits`. The 4 bytes of the `parameters` are not counted as they are somewhat predictable.


### Parameters

Any change in the parameters used to derive the wallet seed would result in a different wallet seed. This means that the parameters are just as important to keep safe as the `salt` itself. So we must either encode the parameters and keep them together with the `salt`, or we have to make them hard-coded constants in SBK itself. The latter would not allow you to choose a difficulty that is appropriate to your machine and level of paranoia, so parameters are not hard-coded. Instead they are encoded as a prefix of the `salt` and of every `share`. The downside of this is that there is more data that you have to copy and enter manually. This is why the encoding is kept as compact as possible (4 bytes == 4words == 2 x 6 digits).

Here is the data layout of these 4 bytes:

```
offset  0       4       8       12      16      20          26        31
        [ ver  ][flags ][bk_len][thresh][kdf_p ][ kdf_mem  ][ kdf_time ]
```

> Aside: The `salt_len` is not an encoded parameter. Instead it is hard-coded to 12 bytes (96 bits). You can alleviate entropy paranoia by choosing a larger value for `--brainkey-len`.
>
> Aside: While the `threshold` is encoded, `num_shares` is not, as it is only used once when the `shares` are first created. It is not needed for recovery, so it is not encoded in the `parameters`.

The bean counters among you may have notice that 4 bytes is not enough to encode the complete range of valid parameters which the KDF would accept in theory. For example, the `kdf_time_cost`, which corresponds to the "Number of iterations *t*" in [section 3.1 of the Argon 2 Spec][href_github_phc_winner_argon2] with a valid range of `1..2**32 − 1` would by itself already require 32 bits, much more than the 6bits available in the above encoding.

Since the distinction between 1000 iterations and 1001 iterations is not critical, the kdf parameters are not encoded exactly, but using a logarithmic scale. This log base is chosen so that the difficulty can be controlled reasonably well (increments of 1.25x) while still being able to represent values that are sufficiently large (`kdf_mem_cost` up to 5 Terabyte per thread; `kdf_time_cost` up to 5 million iterations). If you specified `--time-cost=1000` for example, this would be rounded to `floor(1.25**25 * 4 - 3) == 1055`.


|      Field Name     |  Size |              Value               |      Range (inclusive)      |
|---------------------|-------|----------------------------------|-----------------------------|
| `f_version`         | 4 bit | Hard-coded to `0`.               |                             |
| `f_flags`           | 4 bit | (-, -, -, `is_segwit`)           |                             |
| `f_brainkey_len`    | 4 bit | `brainkey_len // 2 - 1`          | 2, 4, 6..32                 |
| `f_threshold`       | 4 bit | `threshold - 1`                  | 1..16                       |
| `f_kdf_parallelism` | 4 bit | `log2(kdf_parallelism)`          | 1, 2, 4, 8..32768           |
| `f_kdf_mem_cost`    | 6 bit | `log(kdf_mem_cost) / log(1.25)`  | 1, 2, 3, 4, 6, 9, 12, 16... |
| `f_kdf_time_cost`   | 6 bit | `log(kdf_time_cost) / log(1.25)` | 1, 2, 3, 4, 6, 9, 12, 16... |


### Share Data

<!-- TODO: alt="Data layout for Shares"  -->

```bob
           "byte offset"     0   1   2   3   4   5   6   7
                           .-------------------------------.
 "raw_salt || brainkey"    | A ! B ! C ! D ! E ! F ! G ! H |
                           '-o---o---o---o---o---o---o---o-'
                             |   |   |   |   |   |   |   |
              "Split"        V   V   V   V   V   V   V   V
                           .-+---+---+---+---+---+---+---+-.
       "Raw Share x=1"     | F ! A ! Y ! U ! K ! T ! E ! M |
                           '-------------------------------'
                           .-------------------------------.
       "Raw Share x=2"     | T ! O ! H ! N ! T ! D ! V ! W |
                           '-------------------------------'
                           .-------------------------------.
       "Raw Share x=3"     | Q ! B ! D ! P ! K ! J ! D ! Z |
                           '-o---o---o---o---o---o---o---o-'
                             |   |   |   |   |   |   |   |
               "Join"        V   V   V   V   V   V   V   V
                           .-+---+---+---+---+---+---+---+-.
 "raw_salt || brainkey"    | A ! B ! C ! D ! E ! F ! G ! H |
                           '-------------------------------'
```

Shares are generated from the `shares_input` (`raw_salt || brainkey`). The split algorithm is applied to each byte separately and the points that make up each `raw_share` all have a common x-coordinate. In the preceding diagram for example, the first raw share would be 8 bytes represented here as `FAYUKTEM`, each letter representing the encoded y-coordinate for a byte. In order to recover the byte at `offset=7` of the `master_key`, we would use the join algorithm with the points `P(x=1, y=M)`, `P(x=2, y=W)` and `P(x=3, y=Z)`, to produce `P(x=0, y=H)`, where `H` represents the last byte of the `master_key`.

<!-- TODO: alt="Data layout for Shares"  -->
```bob
         Parameters "X"       "Share Data"         "ECC Data"
        .---------..---..-------------------..-------------------.
Share 1 | 0 1 2 3 || 1 ||  F A Y U K T E M  ||  K D X U Q B D P  |
        '---------''---''-------------------''-------------------'
```

The "full" `share` also includes the serialized parameters as a prefix in the first four bytes, and it also includes ECC data of the same length as the `raw_share`. The ECC code used is a Reed-Solomon code.

> Aside: When parsing a share it is critical to verify that `x != 0` to prevent a [forced secret attack, as described in point 3 of the "Design Rational" of SLIP-0039][href_slip0039_forced_secret].

[href_slip0039_forced_secret]: https://github.com/satoshilabs/slips/blob/master/slip-0039.md#design-rationale


## Wallet Name/Passphrase

A `--wallet-name` is effectively a passphrase, so it suffers from the same problem as all passphrases: they can be forgotten. One of the main purposes of SBK is to protect your wallet from being lost through any single point of failure:

 - If you lose the `salt`, you have a backup.
 - If you forget your `brainkey` you have a backup.
 - If a `share` is partially unreadable, the error correction data provides redundancy.
 - If a `share` is destroyed completely, there is redundancy in the form of other shares.

Please remember that you are at a much greater risk of loosing your bitcoin through a user error than you are from hacking or theft. The use of a `--wallet-name` can make all of SBK's protections null and void, if you use it to inadvertently introduce a single point of failure:

 - If you forget the `--wallet-name` and you're the only person who ever knew it, then your wallet will be lost.
 - If you write it down on a single piece of paper, and that piece of paper is destroyed, then your wallet will be lost.

To avoid such a single point of failure, the default value for `--wallet-name` is hard-coded to `disabled` (literally). There are some legitimate reasons to use a `--wallet-name`, but if you do use it, do not treat it as a password. Instead, write it down in clear handwriting and make sure it is available when your wallet has to be recovered, for example by writing the wallet name(s) on some or all of the shares.

Since the `--wallet-name` is chosen by you and since it is not encoded using a mnemonic or ECC data, there is a greater risk that it may not be possible to decipher your handwriting. To reduce this risk, the set of valid characters is restricted. Valid characters are lower-case letters `"a-z"`, digits `"0-9"` and the dash `"-"` character. In other words, the `--wallet-name` must match the following regular expression: [`^[a-z0-9\-]+$`](https://regex101.com/r/v9eqiM/2).

For more information on the risks and responsible use of a wallet passphrase, [the trezor blog has a a good entry][href_trezor_passphrase] for the equivalent passphrase feature of their wallet.

[href_trezor_passphrase]: https://blog.trezor.io/passphrase-the-ultimate-protection-for-your-accounts-3a311990925b


## Key Derivation

The purpose of the [Key Derivation Function][href_wiki_kdf] is to make a brute-force attack incredibly expensive. The purpose of the `salt` is to make each brute-force attack specific to a particular wallet. Using a KDF together with a `salt` makes it practically impossible to brute-force your wallet and if an attacker has access to your `salt`, then you will at least have some time to move your coins before their attack succeeds (assuming you didn't use a weak `brainkey`, eg. by setting `--brainkey-len=4`).

The KDF used by SBK is [Argon2][href_github_phc_winner_argon2], which is designed to be ASIC-resistant, GPU-resistant and SBK chooses parameters to use as much memory as is available on your air-gapped computer. This approach mitigates the advantage an attacker has from investing in specialized hardware. The price you pay for this added security is that you have to wait a minute or two every time you want to load your wallet. This shouldn't be too much of an issue if you access your cold-storage wallet only every few weeks or months.

[href_wiki_kdf]: https://en.wikipedia.org/wiki/Key_derivation_function

[href_github_phc_winner_argon2]: https://github.com/P-H-C/phc-winner-argon2


### Brute Force Attack Hypothetical

Some back of the envelope calculations to illustrate the difficulty of a brute-force attack: If we assume the attacker has gained access to your `salt`, then they will have a 50% chance of loading your wallet if they can calculate $` 2^{47} `$ hashes. Let's assume you used an average computer from 2012 as your air-gapped computer and the Argon2 parameters which SBK chose were `-p=2`, `-m=539` and `-t=26`. This might take 1-2 minutes to calculate on the old machine, but on a more modern system it may take only 10 seconds. For easy math and to be conservative, let's assume that an attacker has access to future hardware that can calculate one of these hashes in 1 second, further assume that they have unlimited access to 1000 systems of this caliber (and more money to spend on electricity than they could ever get from your wallet). After $` \frac{2^{47}}{1000 \times 86400 \times 365} = `$ 4500 years they would have 50:50 chance to have cracked your wallet. It would be cheaper for them to find you and persuade you to talk. Beware of shorter keys lengths though: if you use `--brainkey-len=4` (32 bits), the same attacker would need only $` \frac{2^{31}}{1000 \times 86400} = `$ 25 days.

All of this is assuming of course, that the attacker has somehow gained access to your `salt`. It may be OK for you to use a value lower than `--brainkey-len=8`, as long as you can satisfy one of the following conditions:
 - You are confident that your `salt` will *never* be found by an attacker.
 - If your `salt` is found, then you have some way to know that this happened, so that you will at least have enough time to move your coins to a new wallet.
 - You regularly generate a new wallet and move all your coins, so every `salt` becomes obsolete before any brute-force attack has enough time to succeed.


### Parameter Choices

There is no correct choice when it comes to picking parameters, there are only trade-offs. To a certain extent you can trade-off entropy with KDF difficulty: If you are willing/able to memorize a longer brainkey (with more entropy), you could reduce the KDF difficulty and thereby reduce your your hardware requirements and/or time to wait loading your wallet. If you are very confident that your salt will never be found, you could have a very short `brainkey`.

The default KDF difficulty and key lengths used by SBK are chosen based on the following reasoning: The main constraint is the ability of a human to memorize words. The brainkey length is chosen to be as short as possible, while still being able to offer some protection against a brute-force attack. Since the risk of you forgetting your brainkey is probably much higher than your risk of being subject to a brute-force attack, it is more important to mitigate the former risk than the latter. If your situation is different, and you are worried about the risk of a brute-force attack, then you could choose `--brainkey-len=8` to increase the entropy of your `brainkey` and/or choose `--target-duration=600` to increase the KDF difficulty.


### KDF Implementation

Waiting 1-2 minutes for the key derivation is somewhat inconvenient, but it would be an even worse experience if you didn't even have a progress indicator and your machine appeared to be locked up while the KDF calculation was in progress. As a concession to usability, SBK has a wrapper function called `digest`, the main purpose of which is to implement a meaningful progress bar:

```python
import argon2     # pip install argon2-cffi

def digest(data: bytes, p: int, m: int, t: int, digest_len: int=32) -> bytes:
    constant_kwargs = {
        'hash_len'   : 1024,
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
        # progress indicator
        print(f"remaining: {remaining_iters:>3} of {t}  -  next: {step_iters}")

        result = argon2.low_level.hash_secret_raw(
            secret=result, salt=result, time_cost=step_iters, **constant_kwargs
        )
        remaining_steps -= 1
        remaining_iters -= step_iters

    assert remaining_steps == 0, remaining_steps
    assert remaining_iters == 0, remaining_iters
    return result[:digest_len]
```

Invocation with `t=1` produces the same result as using argon2 directly:

```python
>>> digest_data = digest(b"test1234", p=1, m=1, t=1)
remaining:   1 of 1  -  next: 1
>>> import binascii
>>> print(binascii.hexlify(digest_data))
b'f874b69ca85a76f373a203e7d55a2974c3dc50d94886383b8502aaeebaaf362d'
```

You can verify this using [antelle.net/argon2-browser/](https://antelle.net/argon2-browser/) for example (note however that `m=1` in SBK is m=1024 in argon2).

```
Params: pass=test1234, salt=test1234, time=1, mem=1024, hashLen=32, parallelism=1, type=0
Encoded: $argon2d$v=19$m=1024,t=1,p=1$dGVzdDEyMzQ$O2GpxMquN/amTCVwe5GHPJr89BvBVnM0ylSHfzez4l8
Hash: f874b69ca85a76f373a203e7d55a2974c3dc50d94886383b8502aaeebaaf362d
```

Invocation with `t>1` will split the iterations up to a maximum of 10 steps.

```
>>> digest_data = digest(b"test1234", p=1, m=1, t=87)
remaining:  87 of 87  -  next: 9
remaining:  78 of 87  -  next: 9
remaining:  69 of 87  -  next: 9
remaining:  60 of 87  -  next: 9
remaining:  51 of 87  -  next: 8
remaining:  43 of 87  -  next: 9
remaining:  34 of 87  -  next: 8
remaining:  26 of 87  -  next: 9
remaining:  17 of 87  -  next: 8
remaining:   9 of 87  -  next: 9
>>> print(binascii.hexlify(digest_data))
b'6cf1a22113182d8c66c8972e693b1cc3bb1d931a691265bad75e935b1254fccd'
```

This implementation is an unfortunate compromise. A better implementation would require an adjustment to the Argon2 library, which would be more effort. I would [greatly appreciate feedback](https://gitlab.com/mbarkhau/sbk/issues/1) on the effect this approach has on the strength of the KDF and if there is a better approach. My assessment so far is that using `t >= 20` has a comparable cost to plain argon2, with the wrapper adding very minimal overhead. The worst case is for `t=10` where the overhead of the wrapper ranges from 50-60%. This is plausible if we assume that the overhead is amortized the more iterations we do within argon2. I assume that low overhead compared to plain argon2 also means that there is very little room for an attacker to optimize and therefore that this approach is safe.

Another potential shortcoming that is perhaps much worse is a loss of entropy that may happen with each step. Between each step, the result is 1024 bytes long, which is hopefully sufficient for this to not be a concern. I am open to suggestions for a better construction.


## Encoding Secrets: Mnemonics and Intcodes

> Aside: The work done in this section preceded the release of Trezor Shamir Backup/SLIP0039, which has many
> similarities to it. The wordlists of both are composed with similar considerations for length, edit distance and
> phonetic distinctness.


### Prelude on Physical Deterioration

The most diligently implemented software cannot protect your secrets from physical deterioration and destruction. There are books, scrolls and tablets that have been preserved for centuries, provided they were protected from weather, fluctuations in humidity, exposure to light, from insects and if they used materials that did not break down in chemical reactions.

If you want your shares to survive until they are needed, there are simple ways to protect them from deterioration. Here are some inexpensive suggestions, ordered by increasing level of paranoia:

 - Write clear, non-cursive and readable characters.
 - Use a pen with archival ink. Ideally, such ink is inert, dries quickly and does not smear.
 - Use [acid-free paper][href_wiki_acid_free_paper].
 - Use a [pouch laminator][href_wiki_puche_laminator] to create protective seal against the elements.
 - Use a number punch set to [punch the share data onto a metal plate][href_yt_metal_stamp]. Such a plate can survive a house fire much better than paper. Even with the better heat resistance, it is best to store such plates as close to the ground as possible, where the heat from a fire is much lower.
 - Use a hole punch in a to mark the share data into a metal plate. This is can be slightly harder to read but it is easier to punch a hole in metal than to stamp a pattern, so you can use metals that are harder and more resistant to high temperatures.
 - Use [various metal seed storage products][href_loppnet_metal_seed_storage], which can survive hotter fires (no affiliation).

[href_wiki_acid_free_paper]: https://en.wikipedia.org/wiki/Acid-free_paper

[href_wiki_puche_laminator]: https://en.wikipedia.org/wiki/Pouch_laminator

[href_yt_metal_stamp]: https://www.youtube.com/watch?v=TrB62cPPNxc

[href_loppnet_metal_seed_storage]: https://blog.lopp.net/metal-bitcoin-seed-storage-stress-test-round-iii/


### Mnemonic for Memory

From personal experience I know that it is possible to remember phone numbers, mathematical constants, poems or an old ICQ number even after multiple decades. In light of this, a `brainkey` can be a reasonable choice to generate a wallet, provided you are diligent and regularly practice recall of the `brainkey`, so you build up a habit.

SBK uses a mnemonic encoding that is designed to help with memorization of the `brainkey`. The format is designed with the following in mind:

 - Human memory can remember concrete objects, people and places more easily than abstract words.
 - Human memory fills in gaps (often incorrectly) so ambiguous words must be avoided.

The technical criteria for the wordlist are:

 - The wordlist has 256 words.
 - All words must be at least 5 characters long.
 - All words must be at most 7 characters long.
 - All words must have a unique 3 character prefix.
 - The damerau levenshtein edit distance of any two words must be at least 4.

The wordlist is composed only of commonly used concrete nouns such as animals, creatures, famous people, characters, physical objects, materials, substances and well known places/organizations. The wordlist does not contain any abstract words, adjectives, adverbs. Consider that the very first word humans ever spoke may have been have been the equivalent of "mother" or "snake", rather than words for abstract concepts such as "agency" or "ambition".

> Aside: Some words on the wordlist may be provocative/obscene, such as "viagra" and "saddam", but they are used partially for that reason: provocative words are more memorable than plain and boring words, as I'm sure many parents with potty-mouthed children can attest.

Using such words makes it easier to use the [Method of Loci][href_wiki_method_of_loki] or to construct a story as a memory aid. As an example, given the following brainkey:

```
sunlight  origami   leibniz   gotham
geisha    barbeque  ontario   vivaldi
```

You might construct a picture in your mind of a beam of *sunlight* which falls on a piece of *origami* that was folded by *Leibniz* while he was in *Gotham* city. A *geisha* looks upon it as she eats her *barbeque* in *ontario* and listens to *vivalidi*. Please consider in an hour or two if it is easier for you to recall the previous picture or these random digits: 053-404 098-139 152-596 236-529. Both these digits and the previous set of words are encodings of the same raw data: `b"\x6f\x56\x7f\x5b"`

I hope this illustrates of ability of humans to remember what has been very important to us throughout history: stories about people and places.

[href_wiki_method_of_loki]: https://en.wikipedia.org/wiki/Method_of_loci

> Caveat: The choices for the current wordlist are probably not optimal as I have not done exhaustive tests. It may be for example, that it is easier to memorize fewer words from a larger wordlist. The price for this is that a larger wordlist leads to smaller levenshtein/edit distances between words, to longer word lengths, to less phonetic distinctiveness and the to a larger burden on non-native speakers of English (because less frequently used words must be used to fill out the wordlist).
>
> Improving the wordlist is a rabbit hole that involves trade-offs and diminishing returns, so I'm leaving it as is for now, but it is subject to change before final release, so your `brainkey` may become invalid!


### Integer Codes

In addition to the mnemonic encoding, SBK uses a numeric encoding, consisting of two triplets of decimal digits: `053-404`. These have some benefits compared to the mnemonic encoding:

 - They encode their position in the secret to protect against transposition errors during input.
 - They can be used to detect input errors as they are a redundant encoding.
 - They are used to encode not only the raw data, but also ECC data.
 - They can be entered with one hand on a keypad while reading off a piece of paper.
 - They are better suited for use with a punch/stamping set (which may consist only of decimal digits).

The primary purpose of this encoding is to give protection against incorrectly entered `shares`. Since the recovery process requires you to enter multiple `shares` and since the key derivation can take quite some, it is important to detect such input errors early. Without such protection, you could only detect an incorrect input when you see that you have loaded the wrong (ie. an empty) wallet. To make matters worse, this would be long after the input error happened and you would have no indication as to which words were entered incorrectly.

This is how the full `brainkey` is displayed by SBK.

```
     Data          Mnemonic               ECC
01: 021-729   geisha    tsunami     04: 258-287
02: 066-639   airport   forest      05: 308-329
03: 187-708   toronto   diesel      06: 361-894
```

The "Data" and "Mnemonic" sections both encode the same raw data: `b"\x6f\x56\x7f\x5b"`. The `intcodes` under the "ECC" label encode data for [forward error correction][href_wiki_fec]. To recover your wallet, it is enough to enter either the "Mnemonic", the "Data" or at least half of any of the `intcodes` (either from the "Data" and/or "ECC" sections). If enough has been entered, SBK will fill in the missing values and you can compare what has been filled in with your physical copy. If what has been filled in does not exactly match your copy, then you have made an input error somewhere.

The data portion of each `intcode` can be obtained by parsing it as a decimal integer and masking with `& 0xFFFF`.

```python
intcode = int("187-708".replace("-", ""))
assert intcode == 187708
assert intcode == 0x2DD3C
assert intcode & 0xFFFF == 0xDD3C
```

The position/index of each code can be obtained by bit shifting with `>> 16`.

```python
assert  21_729 >> 16 == 0
assert  66_639 >> 16 == 1
assert 187_708 >> 16 == 2
assert 361_894 >> 16 == 5
```

You may observe that a larger position/index would require more than 6 digits to represent. To ensure the decimal representation never uses more than 6 digits, the position index is limited using `% 13`:

```
assert 25 << 16 | 0xffff == 1703_935
assert (25 % 13) << 16 | 0xffff == 851_967
```

[href_wiki_fec]: https://en.wikipedia.org/wiki/Forward_error_correction


### FEC: Forward Error Correction

As a `share` may be needed only years after it was created, there is a risk that it may become partially unreadable due to physical deterioration. An FEC code is used to have a better chance to recover such a `share`, so long as it is still partially intact.

SBK uses a [Reed Solomon][href_wiki_rscodes] Error Correction Code, implemented in `sbk/ecc_rs.py`. There is a minimal cli program which can be used to test it in isolation.

```shell
$ echo -n "WXYZ" | python -m sbk.ecc_rs --encode
5758595afbdc95be
$ echo "5758595afbdc95be" | python -m sbk.ecc_rs --decode
WXYZ
$ python -c "print('\x57\x58\x59\x5a')"
WXYZ
```

|    Term    |       Value        |                        Description                         |
|------------|--------------------|------------------------------------------------------------|
| `message`  | `WXYZ`/`5758595a`  | ASCII and hex representation of the input message          |
| `ecc_data` | `fbdc95be`         | Redundant Error Correction Data, derived from the message. |
| `block`    | `5758595afbdc95be` | Hex representation of `message` &#124;&#124; `block`       |

As you can see, the `ecc_data` is a suffix added to the original message. My understanding is that this is called a [systematic form encoding][href_wiki_rs_systematic]. This RS implementation used by SBK uses a variable length polynomial with coefficients derived from the input message. In our example, using the message `5758595a`, the polynomial is defined using four data points and four additional error correction points:

```
        Data                   ECC
Point(x=0, y=0x57)    Point(x=4, y=0xfb)
Point(x=1, y=0x58)    Point(x=5, y=0xdc)
Point(x=2, y=0x59)    Point(x=6, y=0x95)
Point(x=3, y=0x5a)    Point(x=7, y=0xbe)
```

Each byte of the input message is interpreted as the y-coordinate of a point which lies on the polynomial, with the x-coordinate being the position in the block. Arithmetic is done using $`GF(256)`$, just as for the Shamir's secret sharing, which allows for much of the implementation of `sbk/gf.py` and `sbk/gf_poly.py` to be reused.

With this approach, we can recover the original message even if only half of the block is available:

```
$ echo "5758595a        " | python -m sbk.ecc_rs --decode
WXYZ
$ echo "        fbdc95be" | python -m sbk.ecc_rs --decode
WXYZ
$ echo "5758        95be" | python -m sbk.ecc_rs --decode
WXYZ
```

Note that the missing/erased portions of the message are explicitly marked with whitespace. An erasure is easier to recover from than corruption. If a byte of data is incorrect rather than missing, at least one further correct byte is needed in order to recover the original message. Corruption is corrected in a process of trial and error, in which the most probable polynomial for the given set of points is determined.

```
$ echo "00000000fbdc95be" | python -m sbk.ecc_rs --decode
Traceback (most recent call last):
...
__main__.ECCDecodeError: Message too corrupt to recover.
$ echo "57000000fbdc95be" | python -m sbk.ecc_rs --decode
WXYZ
```

[href_wiki_rscodes]: https://en.wikipedia.org/wiki/Reed%E2%80%93Solomon_error_correction

[href_wiki_rs_systematic]: https://en.wikipedia.org/wiki/Reed%E2%80%93Solomon_error_correction#Systematic_encoding_procedure:_The_message_as_an_initial_sequence_of_values
