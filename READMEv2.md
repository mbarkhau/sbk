<p align="center">
<img alt="SBK Logo" src="https://mbarkhau.keybase.pub/sbk/logo_128.png" height="128" />
</p>

# SBK: Split Bitcoin Keys

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

<!--TOC-->

- [SBK: Split Bitcoin Keys](#sbk-split-bitcoin-keys)
- [Introduction](#introduction)
  - [How SBK Works](#how-sbk-works)
- [Implementation Overview](#implementation-overview)
  - [High Level Overview: Generating, Splitting and Joining Keys](#high-level-overview-generating-splitting-and-joining-keys)
    - [Key Generation](#key-generation)
    - [Key Recovery](#key-recovery)
    - [Loading Wallet](#loading-wallet)
  - [Shamirs Secret Sharing](#shamirs-secret-sharing)
    - [Prelude: Naive Key Splitting](#prelude-naive-key-splitting)
    - [SSS: Shamir's Secret Sharing](#sss-shamirs-secret-sharing)
    - [SSS: Field Choice](#sss-field-choice)
  - [Implementation Details](#implementation-details)
    - [Terms and Notation](#terms-and-notation)
    - [Parameters](#parameters)
    - [Share Data](#share-data)
  - [Key Derivation](#key-derivation)
  - [Wallet Name/Phassphrase](#wallet-namephassphrase)
  - [Encoding Secrets: Mnemonics and Intcodes](#encoding-secrets-mnemonics-and-intcodes)
    - [Mnemonic for Memory](#mnemonic-for-memory)
    - [Integer Codes](#integer-codes)
    - [FEC: Forward Error Correction using Reed-Solomon Codes](#fec-forward-error-correction-using-reed-solomon-codes)
  - [Platform Security](#platform-security)
    - [Is SBK Trustworthy?](#is-sbk-trustworthy)
    - [Is Your SBK Download Authentic?](#is-your-sbk-download-authentic)
    - [Will SBK Remain Available?](#will-sbk-remain-available)
  - [Future Work](#future-work)
    - [Vendoring](#vendoring)
    - [SLIP0039](#slip0039)
    - [Distruibution](#distruibution)
- [User Guide](#user-guide)
  - [Trustee Guide](#trustee-guide)
    - [Integrity and Seals](#integrity-and-seals)
  - [Agent Guide](#agent-guide)
  - [Owner Guide](#owner-guide)
    - [Paper Backup](#paper-backup)
    - [Air Gap Computer](#air-gap-computer)
  - [Recovery Protocol](#recovery-protocol)
    - [Recovery from Shares: Risks](#recovery-from-shares-risks)
    - [Recovery from Shares: Guide](#recovery-from-shares-guide)
- [Unsorted](#unsorted)
  - [misc ](#misc-)
  - [Related Work and Alternatives](#related-work-and-alternatives)
    - [Warp Wallet](#warp-wallet)
    - [Trezor Shamir Backup](#trezor-shamir-backup)

<!--TOC-->

# Introduction

With SBK you can create Bitcoin wallets that are highly secure. This means:

 - Your coins are safe, even if your house burns down in a fire and all of your documents and devices are destroyed.
 - Your coins are safe, even if all your documents are stolen or hacker copies all of your files.
 - Your coins are safe, even if you trusted a person you shouldn't have.
 - Your coins are safe, even if something happens to you (at least your family will still be able to recover your coins).

The use case of SBK is for cold wallets, not for regularly used hot wallets that you might have on your phone. While it can be tedious (though not difficult) to load a wallet created with SBK, the extra effort is justified by the greater safety and the infrequent access.

> Aside: SBK is quite similar to [warp wallet][href_warp_wallet], except that it has an additional backup using Shamir's Secret Sharing.

[href_warp_wallet]: https://keybase.io/warp/warp_1.0.9_SHA256_a2067491ab582bde779f4505055807c2479354633a2216b22cf1e92d1a6e4a87.html


## How SBK Works

<p align="center">
<img alt="SBK Dataflow Diagram" src="https://mbarkhau.keybase.pub/sbk/sbk_overview.svg" height="256" />
</p>

SBK has two ways to recover/load your wallet, one as a backup and the other for normal use:

 1. `Shares`: A single `share` is one part of a backup of your wallet. When you combine enough `shares` together (e.g. 3 of 5 in total), you can recover your `salt` and `brainkey`. The [Shamir's Secret Sharing][href_wiki_sss] algorithm is used to generate the `shares`, which you can distribute in secure locations or give to people you trust. Each `share` is useless by itself, so you don't have to trust a person completely. Not every `share` is required for recovery, so even if a few of them are lost or destroyed, you can still recover wallet.
 2. `Salt` + `Brainkey`: The `Salt` is a secret, very similar to a traditional 12-word wallet seed. It is written on a piece of paper and kept in a secure location, accessible only to you. By itself, the `salt` is not enough to load your wallet. To do that you must also know your `brainkey`. A `brainkey` is passphrase which *only you know* and which is not stored on any computer or written on any piece of paper. In other words, the `brainkey` is only in your brain. 

Using the `salt` and `brainkey`, you have direct access to your wallet, independent of any third party and without risk of theft (though the [$5 wrench attack][href_xkcd_538] is still a risk of course). This is in contrast to a typical 12-word wallet seed written on a piece of paper, which represents a single point of failure. If such a seed is lost, stolen or destroyed, your coins are gone with it. In contrast to this, if you forget your `brainkey` or if your lose your `salt`, then you can still recover them from your backup `shares`.

SBK is not itself a wallet, it only creates and recovers the seed for your wallet. SBK currently supports the [Electrum Bitcoin Wallet][href_electrum_org].

[href_wiki_sss]: https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing

[href_xkcd_538]: https://xkcd.com/538/

[href_electrum_org]: https://electrum.org/

> *DISCLAIMERS*
>
>  - As of November 2019, SBK is still in the experimental, pre-alpha, evaluation only,
>    developmental prototype phase (is that enough hedging for ya? :-P). It is not yet
>    suitable for serious use! If you do use it, assume that all of your coins will be
>    lost.
>  - Do not use this software for any purpose other than to review, provide feedback or
>    to make contributions.
>  - The SBK project is not associated with the Electrum Bitoin Wallet or
>    Electrum Technologies GmbH.
>  - The SBK project is not associated with SatoshiLabs s.r.o.

# Implementation Overview

For the time being, the documentation is mainly for contributors rather than users. You can skip ahead to the [User Guide](#user-guide) if implementation details are not important to you.

> *Aside*: If you are doing code review, please be aware that some portions of the 
>   implementation, which might otherwise be deleted, are preserved for future didactic 
>   use as I rewrite SBK into a literate program. This relates in particular to the 
>   Luby Transform based ECC and the `GF(p)` arithmetic.


## High Level Overview: Generating, Splitting and Joining Keys

<p align="center">
<img alt="SBK Dataflow Diagram" src="https://mbarkhau.keybase.pub/sbk/sbk_dataflow_diagram.svg" height="650" />
</p>

This diagram can only tell so much of course (some of the boxes might as well be labled with "magic"). The next few sections explain in a little more detail how each step works.


### 1. Key Generation

Steps involved in key generation: 

 1. Invoke the `sbk create` command.
 2. Optionally specify `--sheme` (default is `"3of5"`, for a total of 5 shares, any 3 of which are enough for recovery).
 3. Optionally specify `kdf-parameters`. If not specified, these are determined automatically based on the available memory and processing resources, so that key derivation will take ca. two minutes.
 4. The `salt` and `brainkey` are randomly generated.
 5. The `shares` are generated from the `salt` and `brainkey`.
 6. The mnemonic encoding for each of the above secrets is shown for the user to copy (or memorize in the case of
    the `brainkey`).


### 2. Key Recovery

Let's assume that you've already forgotten your `brainkey`, or that your handwriting is so bad that you can't read your `salt` anymore. To recover both, you can join/combine the backup `shares`:

 1. Invoke the `sbk recover` command.
 2. Enter as many `shares` as required.
 3. The `shares` are joined using Shamir's Secret Sharing and the resulting secret is split into the `salt` and `brainkey`.
 4. Write down `salt` and `brainkey`.

Note that the wallet is not loaded directly, instead the recovery produces the `salt` and `brainkey`. Loading the wallet is a separate step.

> Aside: If you recover your own wallet and you collect the `shares` personally, it *may* be safe to continue to use the wallet and to not generate new keys. If you are *not* the owner however, and the recovery process involves the cooperation of some trustees, then there is a higher risk of that they collude to gain access to more `shares` than just their own. In this case it is best to prepare a new wallet in advance and move all coins to it as soon as possible. For more information, see the [Recovery Protocol](#recovery_protocol)


### 3. Loading Wallet

You can load the wallet if you have the `salt` and `brainkey`, either directly as the owner, or after they have been recovered them from the backup `shares`. 

 1. Invoke the `sbk load-wallet` command.
 2. Optionally specify a `--wallet-name`. 
 2. Enter the `salt` and `brainkey`.
 4. The `wallet-seed` is derived using the KDF.
 5. The Electrum Wallet file is created in a temporary directory (in memory only if supported).
 6. The Electrum GUI is started in offline mode (use `-o`/`--online` if you are not using an air-gapped computer).
 7. Use wallet/sign transactions...
 8. Once you close the wallet, all wallet files are [overwritten and deleted][href_wiki_data_remanence].

[href_wiki_data_remanence]: https://en.wikipedia.org/wiki/Data_remanence


## Shamirs Secret Sharing

This seciton describes how the `shares` are generated.


### Prelude: Naive Key Splitting

It's fairly obvoius why you might want to split a secret key into multiple parts: Anybody who finds or steals the full key will have access to your wallet. To reduce the risk if being robbed, you can split the key into multiple parts. 

If for example you have a wallet seed of 12 bytes `"abcd efgh ijkl"` (with 96 bits of entropy), you could split it into fragments: `"1: abcd"`, `"2: efgh"`, `"3: ijkl"`. This way each fragment (by itself) is not enough to recover your wallet. The downside is that you increase the risk of losing your wallet: If you lose even one fragment, you also lose the wallet.

To reduce this risk, you might want to add redundancy by making more fragments: `"4: cdef"`, `"5: ghij"`, `"6: klab"`. Now if fragment 1 is lost, you may still have access to fragment 4 and 6 from which you can still recover the secret.

There are two downsides to this approach:

 1. Some of the fragments may be identical or have overlapping parts, so the redundancy is not as great as you might hope: Two fragments could be lost and if they are the only ones with a specific part of the secret (for example fragment 1 and 4 are the only ones with the bytes `cd`), then you may have lost your wallet, even though you have 4 other fragments that are perfectly preserved.
 2. If a fragment falls in the hands of an attacker, they can try to guess the remaining 8 bytes, which leaves a search space of `2**64` as opposed to the full `2**96`. If you have wrongfully trusted two people, and they collude with each other (which they have a financial incentive to do), then they may have only `2**32` combinations left for their brute-force search.

There may be slightly more clever schemes along these lines, but I won't go into them, as this was just to serve as a motivation for the more complex alternative: Shamir's Secret Sharing.


### SSS: Shamir's Secret Sharing

With SSS, a key can be split into `shares` such that each `share` is completely independent of every other. Assuming `--scheme=3of5`:

 1. Any two `shares` can be lost and the remaining three are enough to recover the original key.
 2. Any individual `share` (or subset of `shares` below the `threshold`) is useless. This means that access to fewer than three `shares` does not provide an attacker with any advantage if they attempt to brute-force a wallet seed.

To get an intuition of how SSS works, it is enough to recall some high-school calculus.

Consider a point `S(x=0, y=s)` on the cartesian plane, where the coordinate `y=s` is your secret encoded as a number:

<img alt="Cartesian plane with single point S" src="https://mbarkhau.keybase.pub/sbk/sss_diagram_1.svg" height="220" />

Now consider `y = jx + k`, a polinomial of degree 1 (aka. a linear equation, aka. a line equation) which goes through point `S` and further points `A(x=1, y=a)` and `B(x=2, y=b)`.

<img alt="Cartesian plane with line sloping down through points S, A and B" src="https://mbarkhau.keybase.pub/sbk/sss_diagram_2.svg" height="220" />

Note that the parameter `j` is generated randomly and `k` is our secret `s`, so that if `x=0` then `y=s`. Recall that a polynomial of degree 1 is fully specified if you have any two distinct points through which it goes. In other words, if you know `A` and `B`, you can derive the parameters `j` and `k` of the equation `y = jx + k` and solve for `x=0` to recover `y=s`. If on the other hand, you have *only* `A` or *only* `B`, then there are an infinite number of lines which go through either. In other words, it is impossible to derive `S` from `A` individually or from `B` individually. To complete the picture, we could generate a further point `C`, so that we only require any two of `A`, `B` and `C` in order to recover `S`. This allows us to create a `2of3` scheme.

Similarly we can create a `3ofN` scheme with a polynomial of degree 2 (aka. a quadratic equation, aka. a parabola), a `4ofN` scheme with a polynomial of degree 3 (aka. a cubic equation) and so on.

<img alt="Cartesian plane with parabola through points S, A, B and C" src="https://mbarkhau.keybase.pub/sbk/sss_diagram_3.svg" height="220" />

> Aside: Please forgive the limitations of the diagram software, the graph
> is supposed to represent a parabola with minimum roughly at `x=3`.

Using this approach, we can 

 1. Encode a `secret` as a point: `S(x=0, y=secret)`
 2. For a polynomial `y = ix² + jx + k` which goes through `S`, we choose `k=secret` and random values for `i` and `j`.
 3. Calculate 5 points `A`, `B`, `C`, `D` and `E` which lie on the polynomial (but which **crucially are not** at `x=0`, which would cause the secret to be leaked).
 4. Use polynomial interpolation to recover `S` using any 3 of `A`, `B`, `C`, `D` or `E`.

The degree of the polynomial allows us control of the minimum number (aka. the `threshold`) of points/`shares` required to recover the secret. Calculating redundant `shares` allows us to protect against the loss of any individual `share`.


### SSS: Choice of Galois Field 

There is more to the story of course. My understanding is that the preceding scheme (which uses the traditional cartesian plane) does not offer complete information security. Some information about the secret is leaked with each `share` and while an attacker who knows fewer points than the `threshold` may not be able to instantly determine the secret, they could at least derive some information to reduce their search space. I'm taking the cryptographer/mathematicians by their word that the solution is to use [finite field arithmetic][href_wiki_galois_field].

Rather than calculating inside the cartesian plane, we use either `GF(p)` (`p` being a prime number) or `GF(p**n)` (`p**n` being a power of a prime number, typically `GF(2**8) == GF(256)`. In a previous iteration of SBK, `GF(p)` was used, with a value for `p` (chosen from [oeis.org/A014234][href_oeis_a014234]) that corresponds to the level of entropy of the `brainkey`. For the default secret length of 20 byte/160 bit this would have been `GF(2**160 - 47) == GF(1461501637330902918203684832716283019655932542929)`. As you can see, this is a very large number, which is why this approach typically isn't used. 

In principle it would have been fine[^fnote_gfp_bignum] for SBK to use `GF(p)`, but since other implementations typically use `GF(256)` and innovation in cryptography is usually not a good thing, this is what SBK now also uses. The specific field used by SBK has been broadly studied already, which should make validation easier, even though the requirement for polynomial division makes arithmetic a bit harder to follow. The specific field uses the Rijndael irreducible polynomial `x**8 + x**4 + x**3 + x + 1`, which is the same as [SLIP0039][href_wiki_slip0039_sss] and (perhaps more importantly) [AES/Rijndael][href_doi_org_rijndael][^fnote_gf_rijndeal_validation]. 

[href_wiki_galois_field]: https://en.wikipedia.org/wiki/Finite_field

[href_oeis_a014234]: https://oeis.org/A014234

[href_wiki_slip0039_sss]: https://github.com/satoshilabs/slips/blob/master/slip-0039.md#shamirs-secret-sharing

[href_doi_org_rijndael]: https://doi.org/10.6028/NIST.FIPS.197

<!-- 
TODO: better footnotes

[^fnote_gfp_bignum]: Resons it may have been fine to use `GF(p)`
 1. A common reason to use `GF(256)` is to be compatible with low-end systems. Since SBK uses a computationally and memory intensive KDF, systems with constrained CPU and RAM defeat the purpose of SBK and are not a target. Such systems would either take a long time to derive a hardened `wallet-seed` or these seeds would be cracked more easily by machines that are much more powerful and easily obtained.
 2. `GF(256)` uses arithmetic that is natively supported by practically every programming language and hardware platform. Depending on the size of `p`, a `GF(p)` field requires support for big integers. Python has native support for big integers, so arithmetic with large values is not an issue for SBK. Since SBK uses Electrum (which is implemented with python), it is not an extra dependency for SBK to require a python interpreter.
 3. Implementing finite field arithmetic for `GF(p)` is slightly easier to understand and should be easier to review.

[^fnote_gf_rijndeal_validation]: I was quite happy to see the same numbers pop out as for [the reference implementation of SLIP0039](https://github.com/trezor/python-shamir-mnemonic/)
-->


## Implementation Details

### Terms and Notation

|   Term/Notation   |                                            Meaning                                            |
|-------------------|-----------------------------------------------------------------------------------------------|
| `version`         | Version number to support iteration of the data format.                                       |
| `flags`           | A bitfield for options (eg. segwit)                                                           |
| `brainkey_len`    | Length of the `brainkey` in bytes. min: 2, max: 32, default: 8                                |
| `threshold`       | Minimum number of shares required for recovery. min: 1, max: 16, default: 3                   |
| `num_shares`      | The number of shamir shares to generate from the `master_key`.                                |
| KDF               | Key Derivation Function. The algorithm used by SBK is [Argon2](#key_derivation_using_argon2). |
| `kdf_parallelism` | The degree parallelism/number of threads used by the KDF.                                     |
| `kdf_mem_cost`    | Amount of memory in MiB filled by the KDF.                                                    |
| `kdf_time_cost`   | Number of passes over the memory used by the KDF.                                             |
| `parameters`      | 4 byte encoding of parameters required by `sbk load-wallet`.                                  |
| &vert;&vert;      | Concatenation operator: `"abc"` &vert;&vert; `"def"` -> `"abcdef"`                            |
| `raw_salt`        | 12 bytes of random data (main source of entropy for the `wallet_seed`).                       |
| `salt`            | `salt` = `parameters` &vert;&vert; `raw_salt`                                                 |
| `brainkey`        | Random data memorized by the owner of the wallet.                                             |
| `shares_input`    | `shares_input` = `raw_salt` &vert;&vert; `brainkey`                                           |
| `raw_share`       | Encoded points in `GF(256)`. See [Share Data][#share-data]                                    |
| `share`           | `share` = `parameters` &vert;&vert; `raw_share`                                               |
| `master_key`      | `master_key` = `salt` &vert;&vert; `brainkey`                                                 |
| `is_segwit`       | Determines the electrum seed type (default: `true`)                                           |
| `wallet_name`     | Identifier to generate multiple wallets from a single `master_key`.                           |
| `kdf_input`       | `kdf_input` = `master_key` &vert;&vert; `wallet_name`                                         |
| `wallet_seed`     | The Electrum seed derived from the `kdf_input`.                                               |

For those keeping track, the total entropy used to generate the wallet seed is `12 + 8 == 16 bytes == 160 bits`. The 4 bytes of the `parameters` are not counted as they are somewhat predictable.


### Parameters

Any change in the parameters used to derive the wallet seed would result in a different wallet seed, so they are just as important to keep safe as the `salt`. This means that we must either encode the parameters and keep them together with the `salt`, or we have to make them hardcoded constants in SBK itself. The latter would not allow you to choose a difficulty that is appropriate to your machine and level of paranoia, so parameters are not hardcoded. Instead they are encoded as a prefix of the `salt` and also of every `share`. The downside of this is that there is more data you have to enter manually, so the encoding is kept as compact as possible (4 bytes == 4words == 2 x 6 digits).

```
offset  0           4           8           12          16          20                26              31
        [ version  ][  flags   ][ bkey_len ][ threshld ][ kdf_para ][   kdf_memory   ][   kdf_time     ]
```

> Aside: The `salt_len` is not an encoded parameter. Instead it is hardcoded to 12 bytes (96 bits). Entropy paranoia can be aleviated by choosing a larger value for `--brainkey-len`.

> Aside: While the `threshold` is encoded, `num_shares` is not, as it is only used once when the `shares` are first created. It is not needed for recovery, so it is not encoded in the `parameters`.

The bean counters among you may have notice that 4 bytes is not enough to encode the complete range of valid parameters which the KDF would accept in theory. For example, the `kdf_time_cost`, which corresponds to the "Number of iterations *t*" in [section 3.1 of the Argon 2 Spec][href_github_phc_winner_argon2] with a valid range of `1..2**32 − 1` would by itself already require 32 bits, much more than the 6bits available in the above encoding. 

Since the distinction between 1000 iterations and 1001 iterations is not critical, the kdf parameters are not encoded exactly, but using a logarithmic scale. This log base is chosen so that the difficulty can be controlled reasonably well (increments of 1.25x) while still being able to represent values that are sufficiently large (`kdf_mem_cost` up to 5 Terabyte per thread; `kdf_time_cost` up to 5 million iterations). If you specified `--time-cost=1000` for example, this would be rounded to `floor(1.25**25 * 4 - 3) == 1055`. 


|      Field Name     |  Size |              Value               |      Range (inclusive)      |
|---------------------|-------|----------------------------------|-----------------------------|
| `f_version`         | 4 bit | Hardcoded to `0`.                |                             |
| `f_flags`           | 4 bit | (-, -, -, `is_segwit`)           |                             |
| `f_brainkey_len`    | 4 bit | `brainkey_len // 2 - 1`          | 2, 4, 6..32                 |
| `f_threshold`       | 4 bit | `threshold - 1`                  | 1..16                       |
| `f_kdf_parallelism` | 4 bit | `log2(kdf_parallelism)`          | 1, 2, 4, 8..32768           |
| `f_kdf_mem_cost`    | 6 bit | `log(kdf_mem_cost) / log(1.25)`  | 1, 2, 3, 4, 6, 9, 12, 16... |
| `f_kdf_time_cost`   | 6 bit | `log(kdf_time_cost) / log(1.25)` | 1, 2, 3, 4, 6, 9, 12, 16... |


### Share Data

<p align="center">
<img alt="Data layout for Shares" src="https://mbarkhau.keybase.pub/sbk/raw_share_diagram.svg" height="320" />
<p>

Shares are generated from the `shares_input` (`raw_salt || brainkey`). The split algorithm is applied to each byte separately and the points that make up each `raw_share` all share a common x-coordinate. In the preceeding diagram for example, the first raw share would be 8 bytes represented here as `FAYUKTEM`, each letter representing the encoded y-coordinate for a byte. In order to recover the byte at `offset=7` of the `master_key`, we would use the join algorithm with the points `P(x=1, y=M)`, `P(x=2, y=W)` and `P(x=3, y=Z)`, to produce `P(x=0, y=H)`, where `H` represents the last byte of the `master_key`.

<p align="center">
<img alt="Data layout for Shares" src="https://mbarkhau.keybase.pub/sbk/share_diagram.svg" height="80" />
<p>

The "full" `share` also includes the serialized parameters as a prefix in the first four bytes, and it also includes ECC data of the same length as the `raw_share`. The ECC code used is a Reed-Solomon code.

> Aside: When parsing a share it is critical to verify that `x != 0` to prevent a [forced secret attack, as described in point 3 of the "Design Rational" of SLIP-0039][href_slip0039_forced_secret].

[href_slip0039_forced_secret]: https://github.com/satoshilabs/slips/blob/master/slip-0039.md#design-rationale


## Wallet Name/Phassphrase

A `--wallet-name` is effectively a passphrase, so it suffers from the same problem as all passphrases: they can be forgotten. One of the main purposes of SBK is to protect you from losing your wallet by avoiding any single point of failure: If you lose the `salt`, you have a backup; if you forget your `brainkey` you have a backup; if a `share` is partially unreadable, there is redundancy in the form of error correction data; if a `share` is destroyed completely, there is redundency in the form of other shares. If you use a `--wallet-name`, it is easy to nullify all of these measures and inadvertantly introduce a single point of failure. If you forget the `--wallet-name` and you're the only person who ever knew it, then your wallet will be lost. If you write it down on a single piece of paper, without any form of backup, then your wallet will be lost.

To avoid such a single point of failure, the default value for `--wallet-name` is hardcoded to `disabled` (literally). There are legitimate reasons to use a `--wallet-name`, but you should write it down in clear handwriting and make sure it is available when your wallet has to be recovered, for example by writing the wallet name(s) on some or all of the shares. 

Since the `--wallet-name` is chosen by you and since it is not encoded using a mnemonic or ECC data, there is a greater risk that it may not be possible to decipher your handwriting. To reduce this risk, the set of valid characters for is restricted. Valid characters are lower-case letters `"a-z"`, digits `"0-9"` and the dash `"-"` character. In other words, the `--wallet-name` must match the following regular expression: [`^[a-z0-9\-]+$`](https://regex101.com/r/v9eqiM/2).


### Decoy Wallets

One of the legitimate uses for a `--wallet-name` is to enable [plausible deniability][href_wiki_plausible_deniability] against an attacker who is in a position to extort you. If the attacker has access to the `salt` and if they can coerce you to reveal your `brainkey`, then they may be satisfied when they load a wallet and find some coins. If you have set this up in advance, the wallet they load may in fact only be a decoy. Your main wallet would use a custom `--wallet-name`, which they do not know about and which you can plausibly deny the existence of.

[href_wiki_plausible_deniability]: https://en.wikipedia.org/wiki/Plausible_deniability

While we're on the topic of plausible deniability; another approach you can take is to simply discard your `salt` and `brainkey` and to rely only the backup `shares`. If an attacker knows for certain that you have an SBK wallet, but they cannot find the `salt`, then you can plausibly claim, that you have thrown it away and that you never intended to access the wallet for years to come, so the backup `shares` were perfectly adequate. This is a plausible scenario if for example you were leaving the wallet as an inheritance, with your will containing the people and locations where shares can be found. The attacker would then have to extend their attack to recovering the shares, possibly involving more people, more time and more risk for them. The downside of actually throwing away your `salt` and `brainkey` is that you may now require the cooperation of some trustees who are then in a position to blackmail you.


## Key Derivation

The purpose of the [Key Derivation Function][href_wiki_kdf] is to make a brute-force attack incredibly expensive. The purpose of the `salt` is to make each brute-force attack specific to a particular wallet. Using a KDF together with a `salt` makes it practically impossible to brute-force your wallet and if an attacker has access to your `salt`, then you will at least have some time to move your coins before their attack succeeds (assuming you didn't use a weak `brainkey`, eg. by setting `--brainkey-len=4`).

The KDF used by SBK is [Argon2][href_github_phc_winner_argon2], which is designed to be ASIC-resistant, GPU-resistant and SBK chooses parameters to use as much memory as is available on your air-gapped computer. This approach mitigates the advantage an attacker has from investing in specialized hardware. The price you pay for this added security is that you have to wait a minute or two every time you want to load your wallet. This shouldn't be too much of an issue if you access your cold-storage wallet only every few weeks or months.

[href_wiki_kdf]: https://en.wikipedia.org/wiki/Key_derivation_function

[href_github_phc_winner_argon2]: https://github.com/P-H-C/phc-winner-argon2


### Brute Force Attack Hypothetical 

Some back of the envelope calculations to illustrate the diffuculty of a brute-force attack: If we assume the attacker has gained access to your `salt`, then they will have a 50% chance of loading your wallet if they can calculate 2^63 hashes. Let's assume you used an average computer from 2012 as your air-gapped computer and the Argon2 parameters which SBK chose were `-p=2`, `-m=539` and `-t=26`. This might take 1-2 minutes to calculate on the old machine, but on a more modern system it may take only 10 seconds. For easy math and to be conservative, let's assume that an attacker has access to future hardware that can calculate these hashes in 1 second, further assume that they have unlimited access to 1 million systems of this caliber (and more money to spend on electricity than they could ever get from your wallet). After `2**63 / (1_000_000 * 86400 * 365.25) = 292271` years they would have 50:50 chance to have cracked your wallet. It would be cheaper for them to knock down your door. Beware of shorter keys lengths though: if you use a `brainkey` of only `--brainkey-len=6` (48 bits), the same attacker would need less than 5 years, at `--brainkey-len=4` (32 bits), they would need only `2**31 / (1_000_000 * 60) = 36` minutes.

All of this is assuming of course, that the attacker has somehow gained access to your `salt`. It may be ok for you to use a value lower than `--brainkey-len=8`, as long as you can satisfy one of the following conditions: 
 - You are confident that your `salt` will *never* be found by an attacker.
 - If your `salt` is found, then you have some way to know that this happened, so that you will at least have enough time to move your coins to a new wallet. 
 - You regularly generate a new wallet and move all your coins, so every `salt` becomes obsolete before an attacker has a chance to succeed.


### KDF Implementation

Waiting 1-2 minutes for the key derivation is somewhat inconvenient, but it would be an even worse experience if you had no progress indicator and your machine appeared to be locked up. As a consession to usability, SBK has a wrapper function called `digest` that can be used to implement a meaningful progress bar:

```python
import argon2     # pip install argon2-cffi

def digest(data: bytes, p: int, m: int, t: int) -> bytes:
    constant_kwargs = {
        'hash_len'   : 32,
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
    return result
```

Invokation with `t=1` produces the same result as using argon2 directly:

```python
>>> import binascii
>>> digest_data = digest(b"test1234", p=1, m=1, t=1)
remaining:   1 of 1  -  next: 1
>>> print(binascii.hexlify(digest_data))
b'f874b69ca85a76f373a203e7d55a2974c3dc50d94886383b8502aaeebaaf362d'
```

You can verify this using [antelle.net/argon2-browser/](https://antelle.net/argon2-browser/) for example (note however that `m=1` in SBK is m=1024 in argon2).

```
Params: pass=test1234, salt=test1234, time=1, mem=1024, hashLen=32, parallelism=1, type=0
Encoded: $argon2d$v=19$m=1024,t=1,p=1$dGVzdDEyMzQ$O2GpxMquN/amTCVwe5GHPJr89BvBVnM0ylSHfzez4l8
Hash: f874b69ca85a76f373a203e7d55a2974c3dc50d94886383b8502aaeebaaf362d
```

Invokation with `t>1` will split the iterations up to a maximum of 10 steps.

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

I would [greatly appreciate feedback](https://gitlab.com/mbarkhau/sbk/issues/1) on the effect this approach has on the strength of the KDF and if there is a better approach. My assesmet so far is that using `t >= 20` has a comparable cost to plain argon2, with the wrapper adding very minimal overhead. The worst case is for `t=10` where the overhead of the wrapper ranges from 50-60%. This is plausible if we assume that the overhead is amortized the more iterations we do within argon2. I assume that low overhead compared to plain argon2 also means that there is very little room for an attacker to optimize and therefore that this approach is safe. 


## Encoding Secrets: Mnemonics and Intcodes

> Aside: The work done in this section preceeded the release of Trezor Shamir Backup, which has many
> similarities to it. The wordlists of both are composed with similar considerations for length, edit distance and
> phonetic distinctness. The most significant difference is the greter redundancy in the mnemonic encoding of SBK as
> compared with SLIP0039, both in terms of two separate encodings for the same data as well as the error correction
> codes.


### Prelude on Phsyical Deterioration

The most diligently implemented software cannot protect your secrets from physical deterioration and distruction. We do have physical artifacts that have been preserved for centuries, provided they were protected from weather, fluctuations in humidity, exposure to light, from insects and if they used materials that did not break down in chemical reactions.

If you want enough of your shares to survive until they are needed, there are simple ways to protect them from deterioration. Here are some inexpensive suggestions, ordered by increasing level of paranoia:

 - Write clear, non-cursive and readable characters.
 - Use a pen archival ink that is inert, fast drying and does not smear.
 - Use a [pouch laminator][href_wiki_puche_laminator] to protect against the elements.
 - Use a letter punch to stamp the share on a metal plate.
 - Use [acid-free paper][href_wiki_acid_free_paper].

The first point may be confusing to you if you assumed you would use a printer to create the shares. If you still trust printer manufactururs to create products that perform even the most rudimentary of their advertised functions, namely creating a faithful physical copy, then you may find [David Kriesel's][href_dkriesel_xerox_fail] [work on such products](https://www.youtube.com/watch?v=c0O6UXrOZJo) enlightning. This is to speak nothing of their ability to create a device that is connected to a network without introducing security vulnerabilities. 

Suffice it to say, don't trust your printer farther than you can throw it. SBK provides templates in [A4 format][href_sbk_template_a4] and [US-Letter format][href_sbk_template_us_letter] for you to print, but these are only to make it easier for you to create shares. You will have to manually write down all of the data for your `salt` and `shares`.


[href_wiki_acid_free_paper]: https://en.wikipedia.org/wiki/Acid-free_paper

[href_wiki_puche_laminator]: https://en.wikipedia.org/wiki/Pouch_laminator

[href_dkriesel_xerox_fail]: http://www.dkriesel.com/en/blog/2013/0802_xerox-workcentres_are_switching_written_numbers_when_scanning

[href_sbk_template_a4]: https://mbarkhau.keybase.pub/sbk/template_a4.pdf

[href_sbk_template_us_letter]: https://mbarkhau.keybase.pub/sbk/template_us_letter.pdf


###

The main reasons to introduce a new encoding are:

 1. To aid in memorization of the `brainkey`
 2. Provide protection against input errors
 3. Provide [forward error correction][href_wiki_fec] 

In addition to the mnemonic encoding, the `salt` and the `shares` use a more compact encoding of the same data in the form of numeric `intcodes`. These encode not only the same raw data as the mnemonic encoding, but also positional indexes and an error correction code to provide additional protection against degradation. This more compact encoding can be entered more quickly with a keypad and is also better suited for use with fire resistent physical storage media, such as [billfodl](https://billfodl.com/], [cryptosteel](https://cryptosteel.com) or punch stamps used with sheet metal. 

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

From personal experience I know that it is possible to remember phone numbers, mathematical constants, poems and even my old ICQ number even after multiple decades. In light of this, a `brainkey` can be a reasonable choice to generate a wallet, as long as

 1. you regularly recall the `brainkey`, so that your brain becomes habituated to it and
 2. the `brainkey` is not a single point of failure.

SBK uses the same mnemonic phrases both for `shares` as well as for the `salt` and `brainkey`. The format is designed with the following in mind:

 - Human memory is not good at remembering random abstract words, it is better at remembering concrete objects, people and places
 - Human memory fills in gaps (often incorrectly) so ambiguous words must be avoided. 

There are two wordlists, which are used in alternation. 

 1. The first wordlist is composed of nouns which are physical entities, such as animals, famous people, and movable objects or materials. Consider that the very first word humans ever spoke may have been have been the equivalent of "mother" or "snake", rather than words for abstract concepts such as "agency" or "ambition". 
 2. The second wordlist is composed of locations and organizations. Generally speaking, a place where an entity might come from, where it might be located or to which it might belong.

> Some words on the wordlist may be provocotive/obscene, such as "viagra" and "saddam", but they are used precisely for that reason: provocative words are more memorable than boring words, as I'm sure many parents with potty-mouthed children will attest. 

This allows you to use the [Method of Loci][href_wiki_method_of_loki] or for you to construct a story as a memory aid around your `brainkey`. Here is an example of a phrase:

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

Since recovery involves the input of multiple `shares` and the key derivation takes time, a lack of protection against intput errors would make it time consuming to discover which `share` was entered incorrectly. To mitigate such issues, each incode encodes it's position to protect against words being skipped or entered in the wrong order. The maximum index is 13 which is adequate to check for skipped inputs even before the ECC data has been endered.


### FEC: Forward Error Correction using Reed-Solomon Codes

`Shares` may be stored for long periods and could deteriorate, they may be partially destroyed through neglect, or they may be partially unreadable by anybody but the author. An FEC code is used to have a better chance to recover such `shares` and also so that users can verify the correctness of what they have entered.





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

SLIP0039 does not cover some of my design goals for SBK and covers others that I do not consider to be important. This notwithstanding, it is worth following parts of SLIP0039, in particular so that it is easier to validate different but comparable implementations. The less that is bespoke about SBK, the higher the probability that issues are found and that it is safe to use. Contributions are most welcome (and given the existing reference implementation for SLIP0039, such contributions may be straightforward).

Some aspects of SLIP0039 are out of scope of SBK:

 - Checksums: Shares can be quite tedious to copy and enter. Given that humans are prone to error when performing the tedious task of writing, reading and entering random data, SBK uses extra data for Forward Error Correction. In other words, rather than dedicate data to a checksum which can only tell when something is wrong, it dedicates data to an FEC code which can correct invalid inputs.
 - Groups: Groups can be used to generate shares with different levels of trust. More shares would be required for groups that are trusted less. For the sake of simplicity, this feature is not implemented with SBK. To the extent that SLIP0039 is followed, the group parameters are chosen to correspond to single group splitting at the second level, i.e. GT = 1, G = 1, T₁ = T and N₁ = N. If you trust some people more than others, you can choose a higher threshold, generate more shares and give multiple shares to those you trust more.
 - Master Secret Encryption: SBK does not support migrating BIP-32 wallets so there is no need to implement a mechannism to split a user chosen master secret. 
 - Encoding: Since SLIP0039 does not use a `salt+brainkey` but rather it splits a master_secret, it encodes parameters as part of each share. SBK

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
>    `share`.
>  - If you are the owners agent, familiarize yourself with and adhere to the recovery
>    protocol.
>  - If you are the owner, trust as few people as possible and only trust people who you
>    regard as not only in terms of how righteous but also competent.

While we started with the technical aspects of SBK, compared with the human aspects of security, they are almost ancilarry. When talking about security for this kind of system, the most difficult are all the parts that humans can mess up. This starts with simple things like prevending transcription and input errors and ends with more philosophical questions like "who can you trust?".

Throughout this guide, I will assume the most paranoid position I can imagine. This may seem over the top for your situation, . 

Further Reading: [Social Key Recovery][href_github_skr]

[href_github_skr]: https://github.com/WebOfTrustInfo/rwot8-barcelona/blob/master/topics-and-advance-readings/social-key-recovery.md


## Trustee Guide

### Integrity and Seals

Imagine for example the owners agent is attempting to collect your `share` without you noticing.


## Agent Guide

The agent acts on behalf of the owner if they cannot act themselves. This may be the case if the owner has died or has been incapacited in some way. The agent of the owner is responsible to act on their behalf according to their will (if provided) or in their best interests.

The primary responsibility of an agent is to recover the wallets of the owner without compromising their security. The agent is the person who is most likely to be in a position to steal the owners coins and so their actions deserve special scruitiny. Trustees should be especially weary of an agent who asks them to simply hand over their `share`. A trustee should be the only person to unsealing and input their `share` on 

The trustees should be watching and scruitinizing you. Provide them with any information they ask for, do not ask them for any information whatsoever. 

 - There should be a mutual understanding among all participants what will happen to the coins. If wallet balances are already known, you should prepare a payment request for each transaction that is to occur. 
 - 


## Owner Guide


### Paper Backup

Justification of
 - Ceremony
 - Format

### Air Gap Computer

 - Hardware Choices
 - Iso Image
 - Verify Signatures
 - Networking


   If your computer has a network cable, unplug it. If your computer
   has WiFi, turn it off/use flight mode. Some kinds of
   attack depend on a network connection. If you are using insecure
   software (despite precautions), disconnecting from any networks
   (aka. air-gap) can sometimes prevent your keys from being leaked.


   If your computer has a network cable, unplug it. If your computer
   has WiFi, turn it off/use flight mode. Some kinds of
   attack depend on a network connection. If you are using insecure
   software (despite precautions), disconnecting from any networks
   (aka. air-gap) can sometimes prevent your keys from being leaked.


   If your computer has a network cable, unplug it. If your computer
   has WiFi, turn it off/use flight mode. Some kinds of
   attack depend on a network connection. If you are using insecure
   software (despite precautions), disconnecting from any networks
   (aka. air-gap) can sometimes prevent your keys from being leaked.

https://www.schneier.com/blog/archives/2013/10/air_gaps.html

 http://viccuad.me/blog/Revisited-secure-yourself-part-1-airgapped-computer-and-gpg-smartcards
    https://tiny.cc/eo0bcz-

## Recovery Protocol

### Recovery from Shares: Risks


### Recovery from Shares: Guide

There are three areas of risk to be aware of:

 - Lost of Secrets
 - Game theoretical risks
    - Holdouts
    - Decoy `shares`
    - Insecure hardware
 - Compromised Software

> Aside: SBK exists in part to provide documentation to the owners trustees and agents, who may be laypeople wrt. cryptocurrency.




# Unsorted

## misc 

 1. Specify `--scheme=TofN` parameter (the default is `--scheme=3of5`). The maximum value for `T` (the `threshold`) is 16 and the maximum value for `N` (the total number of shares) is 250. 
 2. Optionally specify `kdf-parameters` appropriate the current system and/or level of paranoia. The default parameters for the [Argon2][href_github_phc_winner_argon2] [key derivation function](#key-derivation) are determined automatically based on the available memory and processor. The automatically chosen parameters target a runtime of about 1-2 minutes for the wallet seed to be calculated.
 3. The `raw_salt` is generated randomly. The previously specified `parameters` are encoded in the first few bytes to form the `salt`, which is written down and kept in a safe and secure location. The `salt` should be treated similarly to a typical 12-word wallet seed. 
 4. The `brainkey` is generated randomly. It should be committed to memory by practicing regular [active recall][href_wiki_active_recall] over the course of a few days and every few weeks from there on forward.
 5. The `shares` are generated by concatenating the `raw_salt` and `brainkey`, which is then split using Shamir's Secret Sharing. The `parameters` are also encoded in the first few bytes of every share. Shares should be copied onto paper (using the provided templates) and sealed so that [tampering can be detected][href_wiki_tampering]. Shares should be kept in physically distributed locations and they should be accessible only to the owner or to people trusted by the owner.

[href_wiki_active_recall]: https://en.wikipedia.org/wiki/Active_recall

[href_wiki_tampering]: https://en.wikipedia.org/wiki/Tamper-evident_technology


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
 - SBK wallets can be restored with a `brainkey`

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
