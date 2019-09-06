# [Split Bitcoin Keys][repo_ref]

## DISCLAIMER

SBK is still in development and has not had sufficient review to be trusted! Do not use this software for any purpose other than to review and provide feedback or if you would like to contribute. Use this software only if you are prepared to lose access to a wallet that you create with it. For further information about risks of using this software, see [risks and mitigations](#risks_and_mitigations)


## Update 2019-09-05

A project with similar functionality was recently released by SatoshiLabs: [Shamir Backup][href_satoshilabs_sharmirbackup_overview]. The standardization efforts by SatoshiLabs are great I hope future versions SBK can implemenet them.

The main reasons to continue this project are:

 - SBK does not require a hardware
 - SBK wallets can be restored with a brainkey

If neither of these are an issue for you, I highly reccomend you buy a [Trezor Model T][href_trezor_modelt] and use it to [create a Shamir Backup][href_satoshilabs_sharmirbackup_wiki].

[href_satoshilabs_sharmirbackup_overview]: https://blog.trezor.io/shamir-backup-a-new-security-standard-3aa42a6ebb5f

[href_trezor_modelt]: https://shop.trezor.io/product/trezor-model-t?offer_id=15&aff_id=3376

[href_satoshilabs_sharmirbackup_wiki]: https://wiki.trezor.io/User_manual-Creating_a_wallet_with_Shamir_Backup


# Overview

SBK is intended for highly secure cold-storage Bitcoin wallets. Secure means:

 - Your house can burn down, buring your wallet seed and destroying all of your devices and you will still be able to access your coins.
 - A theif/hacker might steal all your documents and copy all your files and they will still not be able steal your coins.
 - You may trust some people wrongfully (not too many though) and they will still not be able steal your coins.
 - Something might happen to you and it will nonetheless be possible for the beneficiaries of your estate to access coins.

SBK is not wallet software itself, instead SBK is only used to generate and recover wallet seeds.

> Aside: SBK currently only supports [Electrum][href_electrum_org]). The SBK project is
> not associated in any way with the Electrum Bitoin Wallet or Electrum Technologies
> GmbH.


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

## Introduction

SBK has two methods to recover a wallet seed:

 A. Salt + SBK-Pieces: This method is a backup in case the brainkey is forgotten and so the wallet can be recovered by beneficiaries of the owners estate.
 B. Salt + Brainkey: This method is intended for regular use by the owner of the wallet.

> Aside: SBK exists in part to provide the executor of a will (who may be a layperson wrt. Bitcoin), a well documented resource on how to recover

Neither of the above two methods are particularly complicated, they are somewhat tedious however, especially method A. For regular daily use, it is a reasonable convenience/security trade-off to have a hot-wallet with small and only access your cold-storage wallet a few times per year.

With SBK your wallet seed is split into multiple pieces using the well known [Shamir's Secret Sharing algorithm][href_wiki_sss]. You can later join these pieces back together and recover the original wallet seed. This protects your wallet from:

 1. Loss: If any individual piece is lost, the remaining pieces are still sufficient to recover the wallet seed.
 2. Theft: If any individual piece is found, stolen or otherwise compromised, your wallet is still safe, as any individual piece is useless by itself.

> Aside: For the purposes of illustration I will continue in the examples here with a 3 of 5 scheme. That is to say, five SBK-Pieces are generated in total, of which at least three are required in order to recover the wallet seed and of which no more than two may be lost before the wallet seed cannot be recovered.

If a piece is either lost or stolen, you should create a new key as soon as possible (and move your coins to a new wallet).

[href_electrum_org]: https://electrum.org/
[href_wiki_sss]: https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing

# Format

The format is designed to be

 1. As easy to memorise as possible.
 2. Simple and easy to understand
 3. Have redundancy in case of
 4. Robust against typos


## Mnemonic Phrases

SBK uses the same mnemonic phrase format both to encode SBK-Pieces and Brainkeys. The formats is designed with the following in mind:

 - Human memory is lossy
 - Human memory fills in gaps (often incorrectly)
 - Human memory is built to remember people and places

I know from personal experience that I can remember phone numbers, mathematical constants, poems and even my ICQ number over the course of multiple decades. In light of this, a brainkey can be a reasonable choice to generate a wallet. As long as you exercise dilligence by recalling the brainkey once a month or more often, you will be able to access your wallet even after years and without having to resort to your backups.

> Aside: The susceptability of brainkeys to brute force attacks is the subject of the section on [Key Derivation](#key_derivation), this section is strictly about the mnemonic encoding used by SBK.


### Method of Loci/Mind Palace

Instead of random words from a dictionary, SBK uses phrases composed of words from the folliwing categories and in the following order: Adjective, Person, City, Place. Here is an example:

    The SCARY MAYOR at the PRAGUE BRIDGE.

This structure aims to take advantage of ability of humans to remember what has been very important to us throughout history: people and places. This structure allows you to build a story or narrative as a memory aid. As an example, you might have a brainkey like this, which encodes 6 * 8 = 48 bits of entropy.

    The BRAVE  CHILD  at the MADRID STAGE.
    The HAPPY  SISTER at the SEOUL  GHETTO.
    The DIRTY  BAKER  at the LONDON TEMPLE.


### Encoding

Each pair of words encodes a single byte. There are four wordlists, each with 16 short and common English words. The minimum edit distance of each word in a wordlist is 3 and the minimum edit distance for all 16 * 4 = 64 words is 2. This hopefully means that the encoding is resilient to input errors, so that even if "MAYOR" is mistyped or misremembered as "MAJOR", and even words are remembered in the incorrect order, there is a fighting chance that the brainkey can nonetheless be recovered.



## Key Derivation

Every wallet seed generated by SBK is ultimately derived from a random seed (with significant entropy) and a random brainkey (with relatively low entropy). SBK uses the [Argon2][href_github_phc_winner_argon2] [key derivation/password hashing function][href_wiki_kdf] so that even for a relatively short and more easilly remembered brainkey, it will not be practically feasable to brute force a wallet seed generated by SBK, even for decades to come[^fnote_quantum_resistance] and even assuming an attacker has access to the salt. The default brainkey size is 8 bytes which are encoded as 16 words.

If the use of such a small brainkey is concerning to you (even despite the use of a KDF) or if you simply do not wish to ever use the brainkey method to recover your wallet, then you can generate a new wallet using a large brainkey (eg. with `--brainkey=32` for 256bits of randomness) and simply discard it immediately. With this approach, the only method to recover your wallet will with the SBK-Pieces. Incidentally, if you find yourself the the subject of a [$5 wrench attack][href_xkcd_538], you can plausibly deny that you memorised the brainkey and say that your attackers will have to go to the people and institutions where you have distributed the SBK-Pieces.

[href_xkcd_538]: https://xkcd.com/538/

[^fnote_quantum_resistance]: Even with access to a quantum computer, it is my understanding that there are no algorithms which improve on a brute-force attack by more than a factor of two. While the seed derivation may be quantum resistant, the existing caveats wrt. [quantum resistance of Bitcoin][href_bitcoin_it_quantum_resistance] itself still apply.

[href_github_phc_winner_argon2]: https://github.com/P-H-C/phc-winner-argon2
[href_wiki_kdf]: https://en.wikipedia.org/wiki/Key_derivation_function
[href_bitcoin_it_quantum_resistance]: https://en.bitcoin.it/wiki/Quantum_computing_and_Bitcoin#Mitigations


## Error Correction

Errors are corrected through redundancy, which is done at multiple
levels.

 1. Overall Redundancy: The choice of the minimum number of
    shares in relation to the total number of shares, gives a
    configurable level of redundancy to the owner. The number of shares
    that can be lost, while still being able to recover the original
    secret is up to them.

 2. Single Share Redundancy: At the level of the share, there are
    4 bytes dedicated to a checksum. This checksum is however not used
    simply to validate the input, but rather it is used to determine
    which guesses at the full share are valid. If the individual share
    is partially corrupted, the share decode step will go through
    quite a few possible combinations of words, in order to recover
    the full share. The lost words can be marked, so that the recovery
    of these will be attempted first. The recovery of up to three
    missing or incorrect words is possible, given enough time.

 3. Codeword Redundancy: At the level of each byte of data,
    the list words is chosen so that each word distinctive,
    from others in the wordlist. This allows typos or spelling
    errors can be caught and corrected.

Quite frankly, I'm not smart enough to implement error correction
using Reed Solomon or LDPC. Fortunately there is a computationally
expensive brute force method to correct errors: Use a large
cryptographic checksum and simply guess at the answer. Incidentally
this may actually be optimal as far as the shannon limit is
concerned.


# Risks and Mitigations

There are three areas of risk to be aware of:

 - Lost of Secrets
 - Game theoretical risks
 - Compromised Software


## Lost of Secrets





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

