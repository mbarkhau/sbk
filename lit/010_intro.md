# SBK: Split Bitcoin Keys


!!! disclaimer "Disclaimers"
    - I acknowledge the concerns expressed in [Shamir Secret Snakeoil][href_btcwiki_sss] and to that end, I have placed this disclaimer as the first thing for you to read. The primary alternative suggested in the wiki article is to use [n of m multisig transactions][href_btcwiki_multisig], which is a feature supported by many wallets, [including electrum][href_electrum_multisig]. Depending on your situation, you may indeed find this to have a preferable trade-off of usability, privacy and security.
    - As of January 2020, SBK is still in the experimental, pre-alpha, evaluation only, developmental prototype phase (hedge, hedge, hedge). At this point the primary reason for the software to be publicly available is for security review.
    - For the moment not even the primary author of SBK is using it for any substantial amount of bitcoin. If you do use it, assume that all of your bitcoin will be lost.
    - [The software is provided under the MIT License, "as is", without warranty of any kind, express or implied…][href_sbk_license]. In particular, the author of SBK cannot be held liable for funds that are lost or stolen. The author of SBK has neither any responsibility, nor any means to help you recover your wallet.

[href_btcwiki_sss]: https://en.bitcoin.it/wiki/Shamir_Secret_Snakeoil

[href_btcwiki_multisig]: https://en.bitcoin.it/wiki/Multisignature

[href_electrum_multisig]: https://electrum.readthedocs.io/en/latest/multisig.html

[href_sbk_license]: https://gitlab.com/mbarkhau/sbk/blob/master/LICENSE


## Introduction

SBK is program that you can use to generate and recover a Bitcoin Wallet. The goal of SBK is to keep your Bitcoin safe and secure. This means:

 - Your wallet is safe, even if your house burns down in a fire and all of your documents and devices are destroyed.
 - Your wallet is safe, even if all your documents are stolen or a hacker copies all of your files.
 - Your wallet is safe, even if you trusted some people you shouldn't have (not too many though).
 - Your wallet is safe, even if something happens to you (at least your family can still recover your coins).

The goal of SBK is to enable most people to live up to the security mantra of Bitcoin: [Your keys, your coins; not your keys, not your coins][href_yt_aantonop].

SBK is not a service, it is Free Open Source Software. The only thing that SBK does is to generate and recover the keys to your wallet (i.e. the wallet seed). SBK is not a wallet itself, it only creates and recovers the keys for such wallets. The [Electrum Bitcoin Wallet][href_electrum_org][^fnote_disclaimer_electrum] is currently the only supported wallet.

> Aside: SBK may at some point be implemented as a plugin for Electrum. You are welcome to contribute at [gitlab.com/sbk][href_gitlab_sbk].
> <hr/>
> Aside: SBK has similarities to [warp wallet][href_warp_wallet], except that it has an additional backup using Shamir's Secret Sharing. It is also similar to [Shamir Backup][href_trezorio_shamir_backup] developed by SatoshiLabs s.r.o.[^fnote_disclaimer_satoshilabs], except that it uses a brainkey.


[href_yt_aantonop]: https://www.youtube.com/watch?v=AcrEEnDLm58

[href_electrum_org]: https://electrum.org

[href_gitlab_sbk]: https://gitlab.com/mbarkhau/sbk

[href_warp_wallet]: https://keybase.io/warp/warp_1.0.9_SHA256_a2067491ab582bde779f4505055807c2479354633a2216b22cf1e92d1a6e4a87.html

[href_trezorio_shamir_backup]: https://wiki.trezor.io/Shamir_Backup

[^fnote_disclaimer_electrum]: The SBK project is not associated with the Electrum Bitcoin Wallet or Electrum Technologies GmbH.

[^fnote_disclaimer_satoshilabs]: The SBK project is not associated with SatoshiLabs s.r.o.


## Your Keys, Your Coins

In the broadest sense, there are two ways for you to lose control of your coins:

 1. Leak: Your keys can be **leaked** and somebody else will take your coins.
 2. Loss: Your keys can be **lost** and your wallet has effectively become a black hole.

Your keys might be leaked,

 - if you use a web wallet from an untrustworthy or negligent service provider,
 - if you use a computer that is connected to the internet and has a security vulnerability,
 - if your wallet uses a written seed phrase that a thief gains access to,
 - if you sell your computer or a hard drive, from which your wallet was not erased securely,
 - if your seed was generated in a predictable way, due to a software bug or a lack of entropy.

Your keys might be lost if they are vulnerable to any single point of failure. This might be the case,

 - if your written seed phrase is destroyed (e.g. in a fire),
 - if you encrypted your wallet and forget the password,
 - if you have your keys, but you no longer have access to the software needed to use them.

SBK is designed to protect against and mitigate these risks as much as possible. Most of the design choices are made with protection against human failure in mind. The primary ways that this is accomplished is through *redundancy* and *ritual*.


## How SBK Works

```bob
                   "Recovery from 3 of 5 Backup Shares"
  .---------------.        .
  |   "Share 1/5" O---.    :                "Load Wallet (Regular Use)"
  '---------------'    \   :                         :
  .---------------.     \  :  .----------------.     :  .------------.
  |   "Share 2/5" O------+--->|      Salt      O---+--->|   Wallet   |
  '---------------'     /     +----------------+  /     '------------'
  .---------------.    /      |    Brainkey    O-'
  |   "Share 3/5" O---'       '----------------'
  '---------------'                   :
  .---------------.  :                :
  |   "Share 4/5" +~~.           "Known only to Owner"
  '---------------'  :
  .---------------.  :  "Distributed at Secure Locations"
  |   "Share 5/5" +~~~~~"and/or with Trusted People"
  '---------------'
```

SBK has two ways for you to open your wallet, one as a backup and the other for normal use:

 1. `Shares`: A single `share` is one part of a backup of your wallet, written on a piece of paper or in some other physical form. When you combine enough `shares` together (e.g. 3 of 5 in total), you can recover your wallet. In such a scheme, any individual `share` is neither necessary nor sufficient to recover your wallet. This property is made possible by the [Shamir's Secret Sharing][href_wiki_sss] algorithm, which is used to generate the `shares`. You can distribute these in secure locations or give to people whom you trust. Each `share` is useless by itself, so you don't have to place complete trust in any individual, location or institution. Not every `share` is required for recovery, so even if a few of them are lost or destroyed, you can still recover your wallet.
 2. `Salt` + `Brainkey`: The `Salt` is a secret, very similar to a traditional 12-word wallet seed. It is written on a piece of paper and kept in a secure location, accessible only to you (the owner of the wallet). By itself, the `salt` is not enough to load your wallet. To do that you must also know your `brainkey`. A `brainkey` is passphrase which *only you know* and which is not stored on any computer or written on any piece of paper. In other words, the `brainkey` is only in your brain.

Using the `salt` and `brainkey`, you have direct access to your wallet, independent of any third party and with minimal risk of theft. The greatest risk you are exposed to here is that somebody might steal your `salt` and then additionally coerce you to reveal your `brainkey` (i.e. a [$5 wrench attack][href_xkcd_538]). This is in contrast to a typical 12-word wallet seed written on a piece of paper, which represents a single point of failure: If such a seed is lost, stolen or destroyed, your wallet is gone with it. In contrast to this, if you either forget your `brainkey` or if your lose your `salt`, then you can still recover your wallet from your backup `shares`.

Put differently, the regular way for you to access your wallet is secured by two factors: something you have (your `salt`) and something you know (your `brainkey`). To protect against loss of either one of these (as well as your untimely demise), you have a backup that is distributed in vaults, safes, safety deposit boxes and/or with family and friends.


[href_wiki_sss]: https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing

[href_xkcd_538]: https://xkcd.com/538/
