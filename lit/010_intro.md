# SBK: Split Bitcoin Keys

## Disclaimers

!!! warning "No Warranty"

    [The software is provided under the MIT License, "as is", without warranty of any kind, express or implied…][href_sbk_license]. In particular, the author(s) of SBK cannot be held liable for any funds that are lost or stolen. The author(s) of SBK have no responsibility (and very likely no ability) to help with wallet recovery.

[href_sbk_license]: https://gitlab.com/mbarkhau/sbk/blob/master/LICENSE


!!! warning "Alternative: Multisig"

    I acknowledge the concerns expressed in [Shamir Secret
    Snakeoil][href_btcwiki_sss] and to that end, I have placed these
    disclaimers as the first thing for you to read. Further info see the chapter on [Tradeoffs](090_tradeoffs.html)

[href_btcwiki_sss]: https://en.bitcoin.it/wiki/Shamir_Secret_Snakeoil


!!! warning "Project Status: Alpha"

    As of January 2020, SBK is still in the experimental, pre-alpha, evaluation only, developmental prototype phase (hedge, hedge, hedge). At this point the primary reason for the software to be publicly available is for review.

    For the moment not even the primary author of SBK is using it for any substantial amount of bitcoin. If you do use it, assume that all of your bitcoin will be lost.

    If you are looking for viable present day alternatives, please review [How To Store Bitcoin Safely][href_yt_held_storing_btc] by Dan Held.

[href_yt_held_storing_btc]: https://www.youtube.com/watch?v=5WWfQM0SFXQ



## Introduction

SBK is a tool to generate and recover Bitcoin Wallets. The goal of SBK is to keep your bitcoin[^fnote_bitcoin_project_vs_money] safe and secure. This means:

[^fnote_bitcoin_project_vs_money]: Throughout the documentation I will use upper case "Bitcoin" to mean the project and lower case "bitcoin" to mean a quantity of the digital asset.

 - Your wallet is safe, even if your house burns down in a fire and all of your documents and devices are destroyed.
 - Your wallet is safe, even if all your documents are stolen or a hacker copies every file from your computer
 - Your wallet is safe, even if you trusted some people you shouldn't have (not too many though).
 - Your wallet is safe, even if something happens to you (at least your family can still recover your bitcoin).

The goal of SBK is to enable most people to live up to the security mantra of Bitcoin: [Your keys, your coins; not your keys, not your coins][href_yt_aantonop].

[href_yt_aantonop]: https://www.youtube.com/watch?v=AcrEEnDLm58

SBK is Free Open Source Software. SBK is not a service, not a company and certainly not yet another token[^fnote_shitbucks]. The only purpose of SBK is to generate and recover the keys to your wallet (i.e. the wallet seed). SBK is not a wallet itself, it only creates and recovers the keys for such wallets. The [Electrum Bitcoin Wallet][href_electrum_org][^fnote_disclaimer_electrum][^fnote_electrum_plugin] is currently the only supported wallet.

[href_electrum_org]: https://electrum.org

[^fnote_shitbucks]: This project has nothing to do with an ERC20 token that apparently exists. I will not even dignify it with a link.

[^fnote_disclaimer_electrum]: The SBK project is not associated with the Electrum Bitcoin Wallet or Electrum Technologies GmbH.

[^fnote_electrum_plugin]: SBK may well at some point be implemented as an Electrum plugin. You are welcome to contribute at [github.com/mbarkhau/sbk][href_github_sbk].

[href_github_sbk]: https://github.com/mbarkhau/sbk


## The Many Ways to Lose Your Coins

In the broadest sense, there are two ways for you to lose control of your bitcoin:

 1. Loss: Your keys can be **lost**[^fnote_lost_bitcoin] and your wallet has effectively become a black hole.
 2. Theft: Your keys can be leaked and somebody else will **steal** your bitcoin.

[^fnote_lost_bitcoin]: Nothing of value has truly been lost, but your purchasing power has been redistributed to the remaining holders of bitcoin.

Your keys may be **lost** if they are vulnerable to any single point of failure (SPoF). This might be the case if:

 - Your 12-24 word written seed phrase is destroyed (e.g. due to fire or water damage).
 - You forget the password that you used to encrypt your wallet.
 - Your hard-drive fails and have no backup or seed phrase to recover.
 - You have your keys, but you no longer have access to the software needed to use them.

Somebody might **steal** your keys if:

 - You use a web wallet from an untrustworthy or negligent service provider or exchange.
 - You use a computer that is connected to the Internet and has a vulnerable back-door
 - Your wallet uses a written seed phrase, which a thief can find.
 - You sell your computer or a hard drive, from which you didn't erase your wallet in a secure way.
 - Your seed was generated in a predictable way, due to a software bug or a lack of entropy.

SBK is designed to protect against and mitigate these risks as much as possible. Most of the design choices are made to protect against the many kinds of human failure. Use of SBK may be tedious, but be aware that the design choices have one primary purpose: Peace of Mind. Yes it may be tedious to write down dozens and dozens of words once, but you won't lie awake at night with worry.


## How SBK Works

```bob
                      "Recover"                 "Load"
.---------------.        :       "You Have"       :
|   "Share 1/5" O---.    :          :             :
'---------------'    \   :  .-------+--------.    :
.---------------.     \  :  |      Salt      O--. :  .------------.
|   "Share 2/5" O------+--->|~~~~~~~~~~~~~~~~|  +--->|   Wallet   |
'---------------'     /     |    Brainkey    O--'    '------------'
.---------------.    /      '-------+--------'
|   "Share 3/5" O---'               :
'---------------'  :             "You Know"
.---------------.  :
|   "Share 4/5" +~~+
'---------------'  :
.---------------.  :~~"Distributed Backup"
|   "Share 5/5" +~~'
'---------------'
```

SBK has two ways for you to access your wallet, one for normal use and the other as a backup:

 1. `Salt` + `Brainkey`: The `Salt` is a secret, very similar to a traditional 12-word wallet seed. It is written on a piece of paper and kept in a secure location, only you (the wallet *owner*) **have** access to. By itself, the `salt` is not enough to load your wallet. To load your wallet, you must also **know** your `brainkey`. A `brainkey` is passphrase which *only you know* and which is not stored on any computer or written on any piece of paper. In other words, the `brainkey` is in your brain and *only* in your brain.
 2. `Shares`: A single `share` is one part of a backup of your wallet, written on a piece of paper or in some other physical form. When you combine enough `shares` together (e.g. 3 of 5 in total), you can recover your wallet. In such a scheme, any individual `share` is neither necessary nor sufficient to recover your wallet. This property is made possible by the [Shamir's Secret Sharing][href_wiki_sss] algorithm, which is used to generate the `shares`. You can distribute these in secure locations or give them to people whom you trust. Each `share` is useless by itself, so you don't have to place complete trust in any individual, location or institution. Not every `share` is required for recovery, so even if a few of them are lost or destroyed, you can still recover your wallet.

[href_wiki_sss]: https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing


Using the `salt` and `brainkey`, you have direct access to your wallet, independent of any third party and with minimal risk of theft. The greatest risk you are exposed to here is that somebody might steal your `salt` and then additionally coerce you to reveal your `brainkey` (i.e. a [$5 wrench attack][href_xkcd_538]). This is in contrast to a typical 12-word wallet seed written on a piece of paper, which represents a single point of failure: If such a seed is lost, stolen or destroyed, your wallet is gone with it. In contrast to this, if you either forget your `brainkey` or if your lose your `salt`, then you can still recover your wallet from your backup `shares`.

[href_xkcd_538]: https://xkcd.com/538/

Put differently, the regular way for you to access your wallet is secured by two factors: something you **have** (your `salt`) and something you **know** (your `brainkey`). To protect against loss of either one of these (as well as your untimely demise), you have a backup that is distributed in vaults, safety deposit boxes, hiding places and/or with trusted family and friends.
