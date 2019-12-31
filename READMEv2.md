<p align="center">
<a href="https://gitlab.com/mbarkhau/sbk"><img alt="SBK Logo" src="https://mbarkhau.keybase.pub/sbk/logo_128.png" height="128" /></a>
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
  $ md_toc --in-place READMEv2.md gitlab
-->

<!--TOC-->

- [SBK: Split Bitcoin Keys](#sbk-split-bitcoin-keys)
- [Introduction](#introduction)
  - [How SBK Works](#how-sbk-works)
- [Implementation Overview](#implementation-overview)
  - [High Level Overview: Generating, Splitting and Joining Keys](#high-level-overview-generating-splitting-and-joining-keys)
    - [1. Key Generation](#1-key-generation)
    - [2. Key Recovery](#2-key-recovery)
    - [3. Loading Wallet](#3-loading-wallet)
  - [Shamir's Secret Sharing](#shamirs-secret-sharing)
    - [Prelude: Naive Key Splitting](#prelude-naive-key-splitting)
    - [SSS: Shamir's Secret Sharing](#sss-shamirs-secret-sharing)
    - [SSS: Choice of Galois Field ](#sss-choice-of-galois-field-)
  - [Implementation Details](#implementation-details)
    - [Terms and Notation](#terms-and-notation)
    - [Parameters](#parameters)
    - [Share Data](#share-data)
  - [Wallet Name/Passphrase](#wallet-namepassphrase)
    - [Decoy Wallets](#decoy-wallets)
  - [Key Derivation](#key-derivation)
    - [Brute Force Attack Hypothetical ](#brute-force-attack-hypothetical-)
    - [Parameter Choices](#parameter-choices)
    - [KDF Implementation](#kdf-implementation)
  - [Encoding Secrets: Mnemonics and Intcodes](#encoding-secrets-mnemonics-and-intcodes)
    - [Prelude on Physical Deterioration](#prelude-on-physical-deterioration)
    - [Mnemonic for Memory](#mnemonic-for-memory)
    - [Integer Codes](#integer-codes)
    - [FEC: Forward Error Correction](#fec-forward-error-correction)
    - [Implementation Postscript](#implementation-postscript)
  - [Security](#security)
    - [Is SBK Trustworthy?](#is-sbk-trustworthy)
    - [Is Your SBK Download Authentic?](#is-your-sbk-download-authentic)
    - [Will SBK Remain Available?](#will-sbk-remain-available)
  - [Future Work](#future-work)
    - [SLIP0039](#slip0039)
    - [Distribution](#distribution)
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

With SBK you can create highly secure Bitcoin wallets. This means:

 - Your coins are safe, even if your house burns down in a fire and all of your documents and devices are destroyed.
 - Your coins are safe, even if all your documents are stolen or hacker copies all of your files.
 - Your coins are safe, even if you trusted some people you shouldn't have (not too many though).
 - Your coins are safe, even if something happens to you (at least your family can still recover your coins).

You can use SBK to generate bitcoin wallet keys that are completely under your control. The goal of SBK is to enable most people to live up to the security mantra of bitcoin: [Your keys, your coins; not your keys, not your coins][href_yt_aantonop].

> Aside: SBK is quite similar to [warp wallet][href_warp_wallet] with an additional backup using Shamir's Secret Sharing.

[href_yt_aantonop]: https://www.youtube.com/watch?v=AcrEEnDLm58

[href_warp_wallet]: https://keybase.io/warp/warp_1.0.9_SHA256_a2067491ab582bde779f4505055807c2479354633a2216b22cf1e92d1a6e4a87.html


## How SBK Works

<p align="center">
<img alt="SBK Data-flow Diagram" src="https://mbarkhau.keybase.pub/sbk/sbk_overview.svg" height="256" />
</p>

SBK has two ways for you to open your wallet, one as a backup and the other for normal use:

 1. `Shares`: A single `share` is one part of a backup of your wallet. When you combine enough `shares` together (e.g. 3 of 5 in total), you can recover your wallet. The [Shamir's Secret Sharing][href_wiki_sss] algorithm is used to generate the `shares`, which you can distribute in secure locations or give to people you trust. Each `share` is useless by itself, so you don't have to trust a person completely. Not every `share` is required for recovery, so even if a few of them are lost or destroyed, you can still recover your wallet.
 2. `Salt` + `Brainkey`: The `Salt` is a secret, very similar to a traditional 12-word wallet seed. It is written on a piece of paper and kept in a secure location, accessible only to you. By itself, the `salt` is not enough to load your wallet. To do that you must also know your `brainkey`. A `brainkey` is passphrase which *only you know* and which is not stored on any computer or written on any piece of paper. In other words, the `brainkey` is only in your brain. 

Using the `salt` and `brainkey`, you have direct access to your wallet, independent of any third party and without risk of theft (though the [$5 wrench attack][href_xkcd_538] is still a risk of course). This is in contrast to a typical 12-word wallet seed written on a piece of paper, which represents a single point of failure. If such a seed is lost, stolen or destroyed, your coins are gone with it. In contrast to this, if you forget your `brainkey` or if your lose your `salt`, then you can still recover your wallet from your backup `shares`.

SBK is not itself a wallet, it only creates and recovers your wallet seeds. SBK currently supports the [Electrum Bitcoin Wallet][href_electrum_org].

[href_wiki_sss]: https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing

[href_xkcd_538]: https://xkcd.com/538/

[href_electrum_org]: https://electrum.org/

> *DISCLAIMERS*
>
>  - As of December 2019, SBK is still in the experimental, pre-alpha, evaluation only,
>    developmental prototype phase (is that enough hedging for ya? :-P). It is not yet
>    suitable for serious use! If you do use it, assume that all of your coins will be
>    lost.
>  - The authors of SBK (or any other wallet software licensed under the 
>    [MIT License][href_mit_license]) have no responsibility to help you recover your 
>    wallet and cannot be held liable if your funds are lost or stolen.
>  - Do not use this software for any purpose other than to review, provide feedback or
>    to make contributions.
>  - The SBK project is not associated with the Electrum Bitcoin Wallet or
>    Electrum Technologies GmbH.
>  - The SBK project is not associated with SatoshiLabs s.r.o.

[href_mit_license]: https://choosealicense.com/licenses/mit/


# User Guide

The great thing about bitcoin is that *you have complete control* of your own money: you are your own bank. The terrible thing about bitcoin is that *you are responsibile* for your own money: you are your own bank. Unlike traditional financial systems, if your bitcoin is lost or stolen, you will have no recourse to any institution whatsoever. No government, no bank, no company, nor any programmer has any obligation or even any ability to help you if something goes wrong. The goal of SBK is to make it easier for you to bear this burden of responsibility and to minimize the chance that you lose control of your coins.

Before we go over how to use SBK, it will be easier for you to understand the steps you will need to take, if you have a clear understanding of the risks involved, how SBK is designed to minimize them and what you can do to minimize them yourself.


## Convenience vs Tedium

SBK is not the most convenient way to create a bitcoin wallet: the price of the extra security provided by SBK is that it is a bit more tedious to use than other approaches. The indended use-case of an SBK wallet is for infrequently accessed funds in cold storage, for example a wallet that you use for long-term savings (i.e. a savings account). If you want to access some of your bitcoin more frequently, you may want to use a separate hot wallet with a lower balance. Such a wallet may be less secure, but is more convenient to use and it only has as much as you can afford to lose (ie. pocket change).


## Safe, Secret and Secure

 - Safe 
 - Secret
 - Secure


## Weighing Risks

 - Mistake (aka. User Error, aka. being human)
 - Scam
 - Disaster, Bug 


The software required to load your wallet may no longer be available. SBK is hosted both on gitlab.com/mbarkhau/sbk and also on github.com/mbarkhau/sbk and you can download stand-alone versions of SBK that can be run from an USB-Stick.



Whenever you use any any bitcoin wallet, you are exposed to various risks:

 1. You might make a mistake: You might forget a critical password, you might write down a secret phrase incorrectly, you might load your wallet on an insecure system etc.
 2. You can fall prey to a scam: This can happen if you download your wallet software from an untrustworthy source, ie. from the website of a malicious programmer or scammer, rather than from the website of the original author.
 3. The wallet software may have a bug: Your wallet may be generated in a way that it cannot be recovered or in a way that can be exploited by others to steal your funds. (As of this writing, such bugs may be the greatest risk when using SBK).

For most people, the greatest risk is usually the first: Important but complicated steps are either skipped or not done with dilligence, so that your keys are lost or stolen. This is due to a combination of factors:

You can lose your funds through a lack of diligence when using your wallet. This can happen if you do not keep your keys secret, for example by loading your wallet on an insecure system, you may lose your keys in an accident or you may simply forget a critical password.

 - Complicated and tedious 
 - Lack of justification 
 - Steps are complicated and tedious. If the extra effort is not justified, and if the consequences of skipping them are Without an understanding of  Due to a lack of understanding of security practices, the consequences of which are either years in the future or appear to be , important steps are skipped . causes leads to the inability to dilligently first and it is the risk that SBK is primarilly designed to address. Far more funds are lost or stolen due to improper handling of keys, than are lost due to hacking or bugs. The goal of SBK is therefore to:

SBK is by no means free from tedium. It can be a considerable effort to prepare a secure computer, to manually copy dozens and dozens of words and numbers with dilligence and to . The documentation of SBK is written to help you judge if this effort is justified for you.

 - Minimize the risk of you losing your keys.
 - Minimize the risk of your keys being exposed to vulnerable computer systems.
 - Minimize the involvement of third parties who might steal your keys.
 - Minimize the trust placed in any individual third party.

For more information on how to minimize the risk of downloading a mallicious version of SBK, please review the section on [software verification](#software-verification).


## Roles 

There are different roles that you might play in connection with an SBK wallet:

 - Owner: You have some funds that you want to protect from loss and theft. You generate the wallet keys, create the backup shares and make preparations so that your wallet can be recovered in the case of a disaster.
 - Agent: The owner has entrusted you to act on their behalf, for example in case they have become infirm or incapacitated, or to carry out their final will.
 - Trustee: The owner has entrusted you with a backup `share` that you should keep safe, secret and secure. If anything happens to your `share`, you should inform the owner as soon as possible.

No matter your role, you should be aware that the security of a wallet depends on your dilligence. SBK may be built with redundancy to protect a wallet from being lost, but it would be foolish of you to rely on that protection. If enough trustees neglect their responsibilities, then the backup shares will be worthless.


## Owner Guide

Before you create a wallet, you should make some preparations. You should:

 1. Consider how to distribute your backup shares so that you minimise your vulnrability to bad actors.
 2. Prepare materials to create shares. Ideally a share should survive a fire and it should have a tamper-evident seal.

We will start with the considerations wrt. bad actors. There are some risks that you will have to weigh, depending on your situtation.

 - Risk of Extortion: A person who has a share can assume that you have at least some bitcoin. Even if they are trustworthy and would never try to threaten and extort you, they might be careless about this information. Giving somebody one of your shares can be the equivalent of painting a target on your back and somebody might knock down your door in the middle of the night. 
 - Holdouts: A person who has a share might get the idea that you depend on them. This means that they could refuse to return the share to you unless you compensate them somehow.

There are two ways to protect yourself from extortion:

 - Only use the backup shares and make sure a share from at least one person or institution is required. If the only way for you to recover your wallet is by using the backup shares, then it is not enough for extorionist to threaten you. They must also threaten the additional person or institution, which puts them at a much greater risk of being apprehended. To maintain the plausability of this, it is best if you do 

 
 - In your safe at home.
 - In safety deposit boxes.
 - In secret and inaccessible locations.
 - With trusted family or friends.

There are a two main considerations when you choose where/with whom to leave your backup shares.

 - You want to ensure that 
 - 

Presumably you will only give a share to a person whom you can trust, so the following two issues of collusion and extortion should hopefully not be an issue. To preempt such issues however, you should make the following clear to any trustee:

 - You have plenty of other backup shares to resort to. If they do not return their share to you upon request, there are others you can access and there is no point in them attempting to extort you.
 - It is pointless for them to collude and gather shares. You have not given enough shares to people with whom they could collude, so any such attempt would be fruitless.
 - If they do attempt to collude, it is enough for even just one trustee to warn you (the owner), so that you can create a new wallet and move all your funds away from the wallet they are trying to steal from.

You should not give your friends and family enough shares so that they could collude to steal from you. You should make it clear to them that such collusion will be fruitless so that they are not even tempted.

Ideally you will have access to enough backup shares so that you. This


### Creating Shares

It may appear strange that the supposed money of the future requires you to write dozens and dozens of words onto paper. Don't we have printers to save us from this kind of tedious and error prone work?

If you still trust printer manufacturers to create products that perform even the most rudimentary of their advertised functions, namely creating faithful physical copies, then you may find it enlightening to review [some of the work](https://www.youtube.com/watch?v=c0O6UXrOZJo) of [David Kriesel's][href_dkriesel_xerox_fail]. If printer manufacturers cannot even do this job right, how much confidence should we place in their ability to create devices that cannot be exploited while being connected to a network. 

Suffice it to say, I recommend you do not trust your printer farther than you can throw it. SBK provides templates in [A4 format][href_sbk_template_a4] and [US-Letter format][href_sbk_template_us_letter] for you to print, but these do not contain any secret information and are only to make it easier for you to create shares. You will have to manually write down all of the data for your `salt` and `shares`.


[href_dkriesel_xerox_fail]: http://www.dkriesel.com/en/blog/2013/0802_xerox-workcentres_are_switching_written_numbers_when_scanning

[href_sbk_template_a4]: https://mbarkhau.keybase.pub/sbk/template_a4.pdf

[href_sbk_template_us_letter]: https://mbarkhau.keybase.pub/sbk/template_us_letter.pdf



### Decoy Wallets

One of the legitimate uses for a `--wallet-name` is to enable [plausible deniability][href_wiki_plausible_deniability] against an attacker who is in a position to extort you. If the attacker has access to the `salt` and if they can coerce you to reveal your `brainkey`, then they may be satisfied when they load a wallet and find some coins. If you have set this up in advance, the wallet they load may in fact only be a decoy. Your main wallet would use a custom `--wallet-name`, which they do not know about and which you can plausibly deny the existence of.

[href_wiki_plausible_deniability]: https://en.wikipedia.org/wiki/Plausible_deniability

While we're on the topic of plausible deniability; another approach you can take is to simply discard your `salt` and `brainkey` and to rely only the backup `shares`. If an attacker knows for certain that you have an SBK wallet, but they cannot find the `salt`, then you can plausibly claim, that you have thrown it away and that you never intended to access the wallet for years to come, so the backup `shares` were perfectly adequate. This is a plausible scenario if for example you were leaving the wallet as an inheritance, with your will containing the people and locations where shares can be found. The attacker would then have to extend their attack to recovering the shares, possibly involving more people, more time and more risk for them. The downside of actually throwing away your `salt` and `brainkey` is that you may now require the cooperation of the trustees and you may be faced with a holdout.


## Agent Guide

> Aside: If you recover your own wallet and you collect the `shares` personally, it *may* be safe to continue to use the wallet and to not generate new keys. If you are *not* the owner however, and the recovery process involves the cooperation of some trustees, then there is a higher risk that some of them will collude to gain access to more `shares` than just their own. In this case it is best to prepare a new wallet in advance and move all coins to it as soon as possible. For more information, see the [Recovery Protocol](#recovery_protocol)


## Trustee Guide

TODO


## Checklist

 - ☐ Print templates for N shares and 1 salt
 - ☐ Install Electrum Wallet on your phone



## Software Verification

TODO


# Implementation Overview

For the time being, the documentation is mainly for contributors rather than users. You can skip ahead to the [User Guide](#user-guide) if implementation details are not important to you.

> *Aside*: If you are doing code review, please be aware that some portions of the 
>   implementation, which might otherwise be deleted, are preserved for future didactic 
>   use as I rewrite SBK into a literate program. This relates in particular to the 
>   [Luby Transform][href_wiki_ltcodes] based ECC in `sbk/ecc_lt.py` and the `GF(p)` arithmetic in `sbk/gf.py`.

[href_wiki_ltcodes]: https://en.wikipedia.org/wiki/Luby_transform_code


## High Level Overview: Generating, Splitting and Joining Keys

<p align="center">
<img alt="SBK Data-flow Diagram" src="https://mbarkhau.keybase.pub/sbk/sbk_dataflow_diagram.svg" height="650" />
</p>

This diagram can only tell so much of course (some of the boxes might as well be labeled with "magic"). The next few sections explain in a little more detail how each step works.


### 1. Key Generation

Steps involved in key generation: 

 1. Invoke the `sbk create` command.
 2. Optionally specify `--scheme` (default is `"3of5"`, for a total of 5 shares, any 3 of which are enough for recovery).
 3. Optionally specify `kdf-parameters`. These are `-p / --parallelism`, `-m / --memory-cost` and `-t --time-cost`. If not specified, these are chosen automatically based on the available memory and processing resources of your system.
 4. The `salt` and `brainkey` are randomly generated.
 5. The `shares` are generated from the `salt` and `brainkey`.
 6. The mnemonic encoding for each of the above secrets is shown for the user to copy onto paper (or memorize in the case of the `brainkey`).


### 2. Key Recovery

Let's assume that you've already forgotten your `brainkey`, or that your handwriting is so bad that you can't read your `salt` anymore. To recover both, you can join/combine the backup `shares`:

 1. Invoke the `sbk recover` command.
 2. Enter as many `shares` as required.
 3. The `shares` are joined using Shamir's Secret Sharing and the resulting secret is split into the `salt` and `brainkey`.
 4. Write down `salt` and `brainkey`.

Note that the wallet is not loaded directly, instead the recovery produces the `salt` and `brainkey`. Loading the wallet is a separate step.


### 3. Loading Wallet

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

> Aside: Since the writing of this section, a nice introduction to secret sharing was published by [standupmaths](https://www.youtube.com/watch?v=K54ildEW9-Q)

### Prelude: Naive Key Splitting

It's fairly obvious why you might want to split a secret key into multiple parts: Anybody who finds or steals the full key will have access to your wallet. To reduce the risk if being robbed, you can split the key into multiple parts. If somebody finds such a fragment, it will not be enough to access your wallet.

If for example you have a wallet seed of 12 bytes `"abcd efgh ijkl"` (with 96 bits of entropy), you could split it into fragments: `"1: abcd"`, `"2: efgh"`, `"3: ijkl"`. This way each fragment (by itself) is not enough to recover your wallet. The downside is that you increase the risk of losing your wallet: If you lose even one fragment, you also lose the wallet.

To reduce this risk, you might want to add redundancy by making more fragments: `"4: cdef"`, `"5: ghij"`, `"6: klab"`. Now if fragment 1 is lost, you may still have access to fragment 4 and 6 from which you can still recover the secret.

There are two downsides to this approach:

 1. Some of the fragments may be identical or have overlapping parts, so the redundancy is not as great as you might hope: Two fragments could be lost and if they are the only ones with a specific part of the secret (for example fragment 1 and 4 are the only ones with the bytes `cd`), then you may have lost your wallet, even though you have 4 other fragments that are perfectly preserved.
 2. If a fragment falls in the hands of an attacker, they can try to guess the remaining 8 bytes, which leaves a search space of `2**64` as opposed to the full `2**96`. If you have wrongfully trusted two people, and they collude with each other (which they have a financial incentive to do), then they may have only `2**32` combinations left for their brute-force search.

There may be slightly more clever schemes along these lines, but I won't go into them, as this was just to serve as a motivation for the more complex but better alternative used by SBK: Shamir's Secret Sharing.


### SSS: Shamir's Secret Sharing

With SSS, a key can be split into `shares` such that each `share` is completely independent of every other. Assuming `--scheme=3of5`:

 1. Any two `shares` can be lost and the remaining three are enough to recover the original key.
 2. Any individual `share` (or subset of `shares` below the `threshold`) is useless. This means that access to fewer than three `shares` does not provide an attacker with any advantage if they attempt to brute-force a wallet seed.

To get an intuition of how SSS works and why it is secure, it is enough to recall some high-school calculus.

Consider a point `S(x=0, y=s)` on the Cartesian plane, where the coordinate `y=s` is your secret encoded as a number:

<img alt="Cartesian plane with single point S" src="https://mbarkhau.keybase.pub/sbk/sss_diagram_1.svg" height="220" />

Now consider `y = jx + k`, a polynomial of degree 1 (aka. a linear equation, aka. a line equation) which goes through point `S` and further points `A(x=1, y=a)` and `B(x=2, y=b)`.

<img alt="Cartesian plane with line sloping down through points S, A and B" src="https://mbarkhau.keybase.pub/sbk/sss_diagram_2.svg" height="220" />

Note that the parameter `j` is generated randomly and `k` is our secret `s`, so that if `x=0` then `y=s`. Recall that a polynomial of degree 1 is fully specified if you have any two distinct points through which it goes. In other words, if you know `A` and `B`, you can derive the parameters `j` and `k` of the equation `y = jx + k` and solve for `x=0` to recover `y=s`. If on the other hand, you have *only* `A` or *only* `B`, then there are an infinite number of lines which go through either. In other words, it is impossible to derive `S` from `A` alone or from `B` alone. To complete the picture, we could generate a further point `C`, so that we only require any two of `A`, `B` and `C` in order to recover `S`. This allows us to create a `2of3` scheme.

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

There is more to the story of course. My understanding is that the preceding scheme (which uses the traditional Cartesian plane) does not offer complete information security. Some information about the secret is leaked with each `share` and while an attacker who knows fewer points than the `threshold` may not be able to instantly determine the secret, they could at least derive some information to reduce their search space. I'm taking the cryptographer/mathematicians by their word that the solution is to use [finite field arithmetic][href_wiki_galois_field].

Rather than calculating inside the Cartesian plane, we use either `GF(p)` (`p` being a prime number) or `GF(p**n)` (`p**n` being a power of a prime number, typically `GF(2**8) == GF(256)`. In a previous iteration of SBK, `GF(p)` was used, with a value for `p` (chosen from [oeis.org/A014234][href_oeis_a014234]) that corresponds to the level of entropy of the `brainkey`. For the default secret length of 20 byte/160 bit this would have been `GF(2**160 - 47) == GF(1461501637330902918203684832716283019655932542929)`. As you can see, this is a very large number, which is why this approach typically isn't used. 

In principle it would have been fine[^fnote_gfp_bignum] for SBK to use `GF(p)`, but since other implementations typically use `GF(256)` and innovation in cryptography is usually not a good thing, this is what SBK now also uses. The specific field used by SBK has been broadly studied already, which should make validation easier, even though the requirement for polynomial division makes arithmetic a bit harder to follow. The specific field uses the Rijndael irreducible polynomial `x**8 + x**4 + x**3 + x + 1`, which is the same as [SLIP0039][href_wiki_slip0039_sss] and (perhaps more importantly) [AES/Rijndael][href_doi_org_rijndael][^fnote_gf_rijndeal_validation]. 

[href_wiki_galois_field]: https://en.wikipedia.org/wiki/Finite_field

[href_oeis_a014234]: https://oeis.org/A014234

[href_wiki_slip0039_sss]: https://github.com/satoshilabs/slips/blob/master/slip-0039.md#shamirs-secret-sharing

[href_doi_org_rijndael]: https://doi.org/10.6028/NIST.FIPS.197

<!-- 
TODO: better footnotes

[^fnote_gfp_bignum]: Reasons it may have been fine to use `GF(p)`
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
| `flags`           | A bit-field for options (eg. segwit)                                                          |
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

For those keeping track, by default the total entropy used to generate the wallet seed is `12 + 8 == 16 bytes == 160 bits`. The 4 bytes of the `parameters` are not counted as they are somewhat predictable.


### Parameters

Any change in the parameters used to derive the wallet seed would result in a different wallet seed. This means that the parameters are just as important to keep safe as the `salt` itself. So we must either encode the parameters and keep them together with the `salt`, or we have to make them hard-coded constants in SBK itself. The latter would not allow you to choose a difficulty that is appropriate to your machine and level of paranoia, so parameters are not hard-coded. Instead they are encoded as a prefix of the `salt` and also of every `share`. The downside of this is that there is more data you have to copy and enter manually. This is why the encoding is kept as compact as possible (4 bytes == 4words == 2 x 6 digits).

```
offset  0       4       8       12      16      20          26        31
        [ ver  ][flags ][bk_len][thresh][kdf_p ][ kdf_mem  ][ kdf_time ]
```

> Aside: The `salt_len` is not an encoded parameter. Instead it is hard-coded to 12 bytes (96 bits). You can alleviate entropy paranoia by choosing a larger value for `--brainkey-len`.

> Aside: While the `threshold` is encoded, `num_shares` is not, as it is only used once when the `shares` are first created. It is not needed for recovery, so it is not encoded in the `parameters`.

The bean counters among you may have notice that 4 bytes is not enough to encode the complete range of valid parameters which the KDF would accept in theory. For example, the `kdf_time_cost`, which corresponds to the "Number of iterations *t*" in [section 3.1 of the Argon 2 Spec][href_github_phc_winner_argon2] with a valid range of `1..2**32 − 1` would by itself already require 32 bits, much more than the 6bits available in the above encoding. 

Since the distinction between 1000 iterations and 1001 iterations is not critical, the kdf parameters are not encoded exactly, but using a logarithmic scale. This log base is chosen so that the difficulty can be controlled reasonably well (increments of 1.25x) while still being able to represent values that are sufficiently large (`kdf_mem_cost` up to 5 Terabyte per thread; `kdf_time_cost` up to 5 million iterations). If you specified `--time-cost=1000` for example, this would be rounded to `floor(1.25**25 * 4 - 3) == 1055`. 


|      Field Name     |  Size |              Value               |      Range (inclusive)      |
|---------------------|-------|----------------------------------|-----------------------------|
| `f_version`         | 4 bit | Hard-coded to `0`.                |                             |
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

Shares are generated from the `shares_input` (`raw_salt || brainkey`). The split algorithm is applied to each byte separately and the points that make up each `raw_share` all share a common x-coordinate. In the preceding diagram for example, the first raw share would be 8 bytes represented here as `FAYUKTEM`, each letter representing the encoded y-coordinate for a byte. In order to recover the byte at `offset=7` of the `master_key`, we would use the join algorithm with the points `P(x=1, y=M)`, `P(x=2, y=W)` and `P(x=3, y=Z)`, to produce `P(x=0, y=H)`, where `H` represents the last byte of the `master_key`.

<p align="center">
<img alt="Data layout for Shares" src="https://mbarkhau.keybase.pub/sbk/share_diagram.svg" height="80" />
<p>

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

Some back of the envelope calculations to illustrate the difficulty of a brute-force attack: If we assume the attacker has gained access to your `salt`, then they will have a 50% chance of loading your wallet if they can calculate 2^47 hashes. Let's assume you used an average computer from 2012 as your air-gapped computer and the Argon2 parameters which SBK chose were `-p=2`, `-m=539` and `-t=26`. This might take 1-2 minutes to calculate on the old machine, but on a more modern system it may take only 10 seconds. For easy math and to be conservative, let's assume that an attacker has access to future hardware that can calculate one of these hashes in 1 second, further assume that they have unlimited access to 1000 systems of this caliber (and more money to spend on electricity than they could ever get from your wallet). After `2**47 / (1000 * 86400 * 365) = 4500` years they would have 50:50 chance to have cracked your wallet. It would be cheaper for them to find you and persuade you to talk. Beware of shorter keys lengths though: if you use `--brainkey-len=4` (32 bits), the same attacker would need only `2**31 / (1000 * 86400) = 25` days.

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

The primary purpose of this encoding is to give protection against incorrectly entered `shares`. Since the recovery process requires you to enter multiple `shares` and since the key derivation can take quite some, it is important to detect such input errors early. Without such protection, you could only detect an incorrect input when you see that you have loaded the wrong (ie. an empty) wallet. To make matters worse, this would be long after the input error happened and you would have no indication as to which of the secrets was entered incorrectly.

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
| `block`    | `5758595afbdc95be` | Hex representation of `message` &vert;&vert; `block`       |

As you can see, the `ecc_data` is a suffix added to the original message. My understanding is that this is called a [systematic form encoding][href_wiki_rs_systematic]. This RS implementation used by SBK uses a variable length polynomial with coefficients derived from the input message. In our example, using the message `5758595a`, the polynomial is be defined using four data points and four additional error correction points:

```
        Data                   ECC
Point(x=0, y=0x57)    Point(x=4, y=0xfb)
Point(x=1, y=0x58)    Point(x=5, y=0xdc)
Point(x=2, y=0x59)    Point(x=6, y=0x95)
Point(x=3, y=0x5a)    Point(x=7, y=0xbe)
```

Each byte of the input message is interpreted as the y-coordinate of a point which lies on the polynomial, with the x-coordinate being the position in the block. Arithmetic is done using `GF(256)`, just as for the Shamir's secret sharing, which allows for much of the implementation of `sbk/gf.py` and `sbk/gf_poly.py` to be reused. 

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
