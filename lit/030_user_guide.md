# SBK - User Guide

The great thing about Bitcoin is that *you have complete control* of your own money: you are your own bank. The terrible thing about Bitcoin is that *you are responsible* for your own money: you are your own bank.

Unlike traditional financial systems, if your bitcoin is lost or stolen, you have no recourse to any institution whatsoever. No government, no bank, no company and no programmer has any obligation or even any ability to help you if something goes wrong.

The goal of SBK is to make it more easy for you to bear this burden of responsibility. SBK is designed for individuals who want to take **personal custody**[^fnote_joint_custody] of their bitcoin while mitigating the risk of loss or theft.

[^fnote_joint_custody]: SBK is not designed for institutions where more than one person will usually have joint custody over bitcoin belonging to a treasury. For this use-case you should look into a multi-signature setup.


## Roles

```bob
    Owner                   Agent
     .-. +----+              .-. +----+
     '-' |Keys|~~~.          '-' |~~~~|
     /|\ '----'   :          /|\ |~~~~|
      |  Personal :           |  +----+
     / \ Custody  :          / \ Recovery
                  V Backup       Instructions
        _ Vault   . Shares
       |s|~~~~~~~~:
       '-'        :     Trustee   Trustee  "Bad Guy"
        _ Lockbox :     _ .-.     _ .-.      |-|
       |s|~~~~~~~~:    |s|'-'    |s|'-'      '-'
       '-'        :    '-'/|\    '-'/|\      /|\
        _ Bank    :     :  |      :  |        |
       |s|~~~~~~~~:     : / \     : / \      / \
       '-'        '~~~~~~~~~~~~~~~'
```

There are four different roles involved with an SBK wallet:

 1. **Owner**: You own some bitcoin that you want to protect from loss and theft.
 2. **Agent**: The owner has instructed you to act on their behalf, should they not be able to.
 3. **Trustee**: The owner has given you an SBK share, which is part of a backup of their wallet.
 4. **Bad Guy**: You know of

No matter your role, you should make an effort to be dilligent. SBK may be built with redundancy, but it would be foolish to lean too much on that protection. If enough trustees neglect their responsibilities (e.g. by assuming that there are other trustees who are diligent enough), then the backup shares may become worthless and the wallet will be lost. Do not succumb to the moral hazard of trusting that others will do it better than you. Who knows, perhaps the last will of the owner has a clause regarding those who were negligent...

## Tasks

### Owner

As the owner of an SBK wallet, you generate the salt and brainkey, create the backup shares and make preparations so that your wallet can be recovered in a worst-case scenario.


### Agent

As the agent of the owner, it is your responsibility to facilitate the recoverery their wallet and
This may include the recovery of the owners wallet (in cooperation with the trustees) and the distribution of the bitcoin according to the wishes of the owner.


### Truestee

A person or institution who has custody of an SBK share, which is part of a wallet backup.
You should keep this share *safe*, *secret* and *secure* so that it will be available if the owners wallet has to be recovered.


## Minimal Owners Guide

I will start with a bare-bones guide for how to use SBK. It is written with the assumption that you are mostly worried that your wallet will be lost, for example due to a fire, software virus, hardware failure or your untimely demise.

If all you want is a geographically distributed backup of your wallet (to protect against loss and accidents), then this minimal guide may be enough for you. If you are additionally worried that some people that you currently trust might betray you (which is where things get complicated), then you should continue reading the full user guide.


### Deciding on a Scheme

The first thing to do, as an owner, is to decide on a "scheme". This is the threshold `T` and number of backup shares `N`, controlled using `--scheme=TofN` when you initially create your wallet. The first parameter `T` is the *threshold*, which is the minimum number of shares that are required to recover your wallet. The second parameter `N` is the total number of shares that are created.

The default scheme is `3of5`. With this scheme:

 - To recover your wallet, you will need at least 3 backup shares.
 - You will not be able to recover your wallet, if more than 2 shares are lost or destroyed.

For `T` parameter in `--scheme=TofN`, you should consider the worst-case scenarios:

- How many backup shares could be destroyed at once?
- How many backup shares could bad actor collect?

You may well have geographically distribute your backup shares, but if they're written on paper and kept in an area that is prone to be flooded, then you may lose too many of them at once. If the child of a trustee can find a share in their houshold and in addition is at some point a guest in your house, where they also find a backup share, then it would be better if you have a threshold set to `T=3` or higher.

For the parameter `N` (the total number of shares), you should consider how many SBK shares you expect will be lost in a worst-case scenario. If you expect the recovery to be done years after the wallet was created, then you should assume that some of the shares will be lost, forgotten about or destroyed, even despite your best efforts and your trustees to choose secure locations.

If you expect at most 2 shares to be lost, then you should choose `N=T+2`. This means, if you have decided on `T=3` then you should choose `N=5`. With this scheme, if either your salt or brainkey are lost and also two backup shares are lost, then the remaining three shares will still be enough to recover your wallet.


!!! aside "T=1 is Stupid"

    If you were not worried that any share would ever fall into the hands of a bad actor, then you could set a threshold to `T=1`. In that case however, you may as well not bother to use SBK and instead just create a normal Bitcoin wallet with the usual 12-word wallet seed. For any redundency you need, you can just make duplicate copies of the seed.



### Preparation and Materials

Once you've decided on a scheme and after you have made plans about where you will keep your backup shares and who will be your trustees and agents, it's time to prepare some materials. To create a wallet, you will need the following:

 - A download of the [bootable sbklive_x64.iso image][href_sbk_download_sbklive_x64].
 - A USB flash drive or SD card with at least 2GB
 - A PC/Laptop
 - A program to create a bootable flash drive, such as [rufus.ie][href_rufus_ie] on Windows or [USB-creator on Ubuntu][href_usb_creator].
 - A printer (with ink and paper of course)
 - A ballpoint pen (or anything similar as long as the ink is not erasable)
 - A stapler or adhesive tape

There are more materials that you could prepare to make your shares more robust, but this will do for now to understand the basic idea.


[href_sbk_download_sbklive_x64]: TODO

[href_rufus_ie]: https://rufus.ie/

[href_usb_creator]: https://ubuntu.com/tutorials/tutorial-create-a-usb-stick-on-ubuntu


### Air-Gapped System

Ideally you should use a computer that is dedicated to your wallet and nothing else. Every other use case, especially anything that involves a connection to the internet will increase the risk to your wallet. For use with SBK this computer should satisfy the following:

 - It has no network card or wifi card (over which any keys could be transmitted to a bad actor).
 - It has no HDD or SSD drive (on which keys could be stored and read back from by a bad actor who has access to it later).
 - It has the fastest CPU and most Memory money can buy (so that you can run the key derivation with the highest difficulty).

To be practical, for this minimal guide at least, I'm going to assume that your system doesn't satisfy any of these recommendations. Instead I will assume that you will use your current computer but booted from a flash drive using the SBK live distribution. You and that it can at least satisfy the following reduced requirements:

 - You have disconnected any network cable before you boot into SBK.
 - You don't connect to any WiFi network and enable airplane mode as soon as possible.
 - You boot from a flash drive using the SBK Linux live distribution.
 - You use the flash drive *only* for SBK.
 - You never connect the flash drive to any other system.
 - You disconnect the flash drive from your computer before you boot back into your regular OS.

SBK does not have any persistence and should in theory run on a system that does not have any disk and is booted from a read-only medium. If you're using an SD card, you may want to switch it to read-only after you've written the SBK live image to it. The files that SBK creates will only ever be written to RAM (which is presumably volatile), so when you boot up your regular operating system again, there should be no trace of your wallet on any HDD or SSD. If we presume your regular OS to have security issues, then there should not be any files from your wallet that could possibly be leaked.

!!! aside "Flash"

    All data that is currently on your flash drive will be erased, so you should make a copy of any files you want to keep.

!!! warning "Cold Boot Attack"

    The previous contents of RAM can still be [readable after a reboot][href_wiki_cold_boot]. While it is not reccomended to use SBK on a computer that you will later use for other purposes, if you do, the Tails image which SBK is uses features [memory erasure][href_tails_memory_erasure]. For this to work propperly, you should do a clean shutdown, rather than a hard reset of your computer.

[href_wiki_cold_boot]: https://en.wikipedia.org/wiki/Cold_boot_attack

[href_tails_memory_erasure]: https://tails.boum.org/contribute/design/memory_erasure/


## Extended Instructions

These instructions are written with the assumption that you have a high level of paranoia. You may even want to get some tinfoil out of your cupboard (though you won't be using it to make any hats).


### Safe, Secret and Secure

The most important thing to understand, is that your wallet is generated using what is effectively a very large random number[^fnote_large_number], known as a *wallet seed*. Anybody who has this random number also has your wallet and can take your bitcoin. If you lose this random number, your wallet is gone. With SBK you can create such a wallet seed in a way that allows you to keep it *safe*, *secret* and *secure*.

[^fnote_large_number]: Much larger than most people can (or at least are willing to) memorize in their head.

When you initially create a wallet, you will usually be instructed to write down your wallet seed on a piece of paper (for example in the form of a 12-word phrase) and to put it in a safe place. There are some disadvantages to this approach:

 - Safety: The piece of paper may be destroyed (eg. in a fire) or become unreadable (eg. due to damage by water), so without a high degree of diligence on your part, such a wallet seed can be unsafe.
 - Secrecy: You may not be the only one who has access to your computer or to the place you decide to keep your wallet seed. A hacker or a thief could gain access to your wallet seed and steal your bitcoin. Even a curious child, without any ill intent, might find your wallet seed and take a picture of it to ask "what is this?" on the internet, so that your wallet seed is the leaked to the public. If your lucky, an honest person will find it first, take the bitcoin before anybody else can and contact you to give them back. If you're not lucky, they don't contact you... In other words, a wallet seed can be difficult to keep secret.
 - Security: The highest degree of vigilance is difficult to maintain over a long period of time. Even if you have kept your wallet seed safe and secret until now, that does not mean it will be safe and secret in the future. A wallet seed represents a single point of failure, which means you have to constantly think about its security.

This last point is perhaps the greatest benefit of SBK: You can worry much less. Yes, vigilance is still required, but not so much that any one mistake is a catastrophe and mostly on specific occasions which you can prepare for:

 - When you create your wallet.
 - When you access your wallet.
 - When shares are distributed to trustees.
 - When shares are collected from trustees.
 - When your wallet is recovered from shares.

Adding redundancy and making sure there is no single point of failure means that you have a much lower risk to lose your wallet due to a mistake, an accident or a disaster. In other words, SBK is designed with the assumption that you are human.


## Weighing Risks

The greatest risk to your funds is human error (rather than for example a software bug), but it's worth breaking down what these errors typically look like:

 - Bad IT Security: For convenience you may prefer to use your regular Windows based, network connected computer, or your regular smartphone not realizing that it has a back-door or may eventually have a back-door when it is infected with a virus. An attacker can then read the wallet files from your computer or use a keyboard logger to eavesdrop your wallet seed as you type it.
 - Lack of Knowledge: You may have a poor understanding of how to use your wallet. You might for example not know the difference between [the PIN to your wallet and your wallet seed][href_twitter_pschiff_idiot]. Without appreciating this difference, you may never write down your wallet seed and lose your bitcoin when you switch to a new device or directly after you close the wallet software.
 - Misplaced Trust: If you don't trust your technical abilities, you may prefer to trust others to do this for you. The trouble is that the people you trust may turn out to [either be scammers or grossly negligent][href_wiki_emptygox].

[href_twitter_pschiff_idiot]: https://twitter.com/PeterSchiff/status/1220135541330542592

[href_wiki_emptygox]: https://en.m.wikipedia.org/wiki/Mt._Gox

To address these issues, SBK includes:

 - A step by step guide on how to set up a secure air-gapped system.
 - A step by step guide on how to use your wallet in a safe way.
 - A design that does not require trust in any individual or organization[^fnote_software_trust].

The software required to load your wallet may no longer be available. SBK is hosted both on gitlab.com/mbarkhau/sbk and also on github.com/mbarkhau/sbk and you can download stand-alone versions of SBK that can be run from an USB-Stick.

[^fnote_software_trust]: You do need to trust the development process for the wallet software that you use. SBK is Open Source and will also provide a bounty once a final version is released.


### Web Wallets: Leaked by Design

The most common case for a leaked coin is a web wallet, where your keys are in a certain sense leaked by design. The service provider of your wallet has control over your keys or if they don't then they might send you a software update to leak your keys. Note that this is not simply a question of whether or not you can trust in the good intentions and well aligned business interests of the service provider of a wallet, it is also a question of how competent they are to protect a massive honey pot (your wallet and those of all of their other users) from attackers (who might even be employees of the company) that what to take your keys.

SBK is not a service provider, has no access to your keys and can be audited for


### Leaked over the Network

If the computer which you use to access your wallet is connected to the internet, then there is a chance that your keys will either be sent to an attacker or somehow be made public. This can happen for example if your computer is infected by a virus or malware. It may also happen if an unscrupulous associate of the NSA feels like exploiting one of the back-doors ([which is an area of research for them][href_nsa_cve_2020_0601]) but have not yet published.

[href_nsa_cve_2020_0601]: https://media.defense.gov/2020/Jan/14/2002234275/-1/-1/0/CSA-WINDOWS-10-CRYPT-LIB-20190114.PDF


### Leaked by Bug


These keys are only ever on a system that you control and which you ideally never connect to a network (air-gap). This makes it next to impossible for your keys to be ever be leaked or stolen. You don't have to trust any third party service provider with your keys and the backup for your keys is distributed, without any single point of failure.


> Aside: This is the main risk that SBK is subject to. The way keys are generated by SBK might be predictable in some subtle way, or the way in which Electrum it creates signatures might allow



Whenever you use any any bitcoin wallet, you are exposed to various risks:

 1. You might make a mistake: You might forget a critical password, you might write down a secret phrase incorrectly, you might load your wallet on an insecure system etc.
 2. You can fall prey to a scam: This can happen if you download your wallet software from an untrustworthy source, ie. from the website of a malicious programmer or scammer, rather than from the website of the original author.
 3. The wallet software may have a bug: Your wallet may be generated in a way that it cannot be recovered or in a way that can be exploited by others to steal your funds. (As of this writing, such bugs may be the greatest risk when using SBK).

For most people, the greatest risk is usually the first: Important but complicated steps are either skipped or not done with diligence, so that your keys are lost or stolen. This is due to a combination of factors:

You can lose your funds through a lack of diligence when using your wallet. This can happen if you do not keep your keys secret, for example by loading your wallet on an insecure system, you may lose your keys in an accident or you may simply forget a critical password.

 - Complicated and tedious
 - Lack of justification
 - Steps are complicated and tedious. If the extra effort is not justified, and if the consequences of skipping them are Without an understanding of  Due to a lack of understanding of security practices, the consequences of which are either years in the future or appear to be , important steps are skipped . causes leads to the inability to diligently first and it is the risk that SBK is primarily designed to address. Far more funds are lost or stolen due to improper handling of keys, than are lost due to hacking or bugs. The goal of SBK is therefore to:

SBK is by no means free from tedium. It can be a considerable effort to prepare a secure computer, to manually copy dozens and dozens of words and numbers with diligence and to . The documentation of SBK is written to help you judge if this effort is justified for you.

 - Minimize the risk of you losing your keys.
 - Minimize the risk of your keys being exposed to vulnerable computer systems.
 - Minimize the involvement of third parties who might steal your keys.
 - Minimize the trust placed in any individual third party.

For more information on how to minimize the risk of downloading a malicious version of SBK, please review the section on [software verification](#software-verification).



### Software Verification

TODO


### Security vs Usability

SBK is not the most convenient way to create a Bitcoin wallet. If you follow the recommended approach, during setup you will have to:

 - [Prepare an air-gapped system](#setting-up-an-air-gapped-system) with SBK installed
 - create `shares` and transcribe them onto paper,
 - transcribe your `salt` and memorize your `brainkey`,
 - distribute the shares
 - provide [minimal instruction][#instructions-for-trustees] to any trustees

In addition, every time you want to use your wallet, you will have to

 - manually enter a 12 word `salt` every time you use it,
 - remember and manually enter your 6 word `brainkey`.

The price of the extra security provided by SBK is that it is a bit more tedious to use than other approaches. The intended use-case of an SBK wallet is for an infrequently accessed wallet, sometimes referred to as ["cold storage"][href_btcwiki_cold_storage]. This is suitable if you intend to use bitcoin for long-term savings. If you intend to spend some of your bitcoin more frequently, you may want to use a separate ["hot wallet"][href_btcwiki_hot_wallet] which has only a smaller balance that you can afford to lose. This approach minimizes the risk to your funds also minimizes the tedium of using SBK.

[href_btcwiki_cold_storage]: https://en.bitcoin.it/wiki/Cold_storage

[href_btcwiki_hot_wallet]: https://en.bitcoin.it/wiki/Hot_wallet



## Trustee Guide

The most common and least complicated role is that of the *trustee*, so that is the role that I will explain first.


### What is an SBK Share

The owner of an SBK wallet trusts that you have their best interests at heart and that you can help them to avoid losing their bitcoin. To that end, they are entrusting you with part of a backup for their wallet, which is called an *SBK Share*. Such a share is a page of paper on which the following information is written:

 - Minimal usage instructions
 - A QR-Code that links to the extended instructions (this page)
 - The name of the trustee (presumably you)
 - Contact information of the owner
 - The codewords of the SBK Share

The codewords may not be visible, as the template for an SBK Share is designed to be folded and sealed, such that they cannot be read without the seal being broken.

### Tamper Evident Seal

The share may be sealed with tape, staples, glue
tamper-evident


### What to do with the SBK Share


### Secrecy

They receive an SBK share from the owner, which is piece of paper that has been folded and sealed.


### How to Verify an Agent

The owner may chose their agent and trustees, so that they do not know each other, which may reduce the risk that they will collude with each other to steal from the owner. In this case the owner may also give an *Agent Verification Token* to the trustee, in addition to their SBK share. They may also  to to put in their safe or some other secure location to which only they have access.



## Owners Guide

Before you create a wallet, you should make some preparations. You should:

 1. Consider how to distribute your backup shares so that you minimize your vulnerability to bad actors.
 2. Prepare materials to create shares. Ideally a share should survive a fire and it should have a tamper-evident seal.

We will start with the considerations wrt. bad actors. There are some risks that you will have to weigh, depending on your situation.

 - Risk of Extortion: A person who has a share can assume that you have at least some bitcoin. Even if they are trustworthy and would never try to threaten and extort you, they might be careless about this information. Giving somebody one of your shares can be the equivalent of painting a target on your back and somebody might knock down your door in the middle of the night.
 - Holdouts: A person who has a share might get the idea that you depend on them. This means that they could refuse to return the share to you unless you compensate them somehow.

There are two ways to protect yourself from extortion:

 - Only use the backup shares and make sure a share from at least one person or institution is required. If the only way for you to recover your wallet is by using the backup shares, then it is not enough for extortionist to threaten you. They must also threaten the additional person or institution, which puts them at a much greater risk of being apprehended. To maintain the plausibility of this, it is best if you do


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

### Setting Up an Air-Gapped System

 using [an iso-image][href_sbk_downloads]

[href_sbk_downloads]: https://sbk.dev/downloads/


### Creating Shares

It may appear strange that the supposed money of the future requires you to write dozens and dozens of words onto paper. Don't we have printers to save us from this kind of tedious and error prone work?

If you still trust printer manufacturers to create products that perform even the most rudimentary of their advertised functions, namely creating faithful physical copies, then you may find it enlightening to review [some of the work](https://www.youtube.com/watch?v=c0O6UXrOZJo) of [David Kriesel's][href_dkriesel_xerox_fail]. If printer manufacturers cannot even do this job right, how much confidence should we place in their ability to create devices that cannot be exploited while being connected to a network.

Suffice it to say, I recommend you do not trust your printer farther than you can throw it. SBK provides templates in [A4 format][href_share_template_a4] and [US-Letter format][href_share_template_usletter] for you to print, but these do not contain any secret information and are only to make it easier for you to create shares. You will have to manually write down all of the data for your `salt` and `shares`.


[href_dkriesel_xerox_fail]: http://www.dkriesel.com/en/blog/2013/0802_xerox-workcentres_are_switching_written_numbers_when_scanning

[href_share_template_a4]: https://sbk.dev/downloads/template_a4.pdf

[href_share_template_usletter]: https://sbk.dev/downloads/template_us_letter.pdf



### Decoy Wallets

One of the legitimate uses for a `--wallet-name` is to enable [plausible deniability][href_wiki_plausible_deniability] against an attacker who is in a position to extort you. If the attacker has access to the `salt` and if they can coerce you to reveal your `brainkey`, then they may be satisfied when they load a wallet and find some bitcoin. If you have set this up in advance, the wallet they load may in fact only be a decoy. Your main wallet would use a custom `--wallet-name`, which they do not know about and which you can plausibly deny the existence of.

[href_wiki_plausible_deniability]: https://en.wikipedia.org/wiki/Plausible_deniability

While we're on the topic of plausible deniability; another approach you can take is to simply discard your `salt` and `brainkey` and to rely only the backup `shares`. If an attacker knows for certain that you have an SBK wallet, but they cannot find the `salt`, then you can plausibly claim, that you have thrown it away and that you never intended to access the wallet for years to come, so the backup `shares` were perfectly adequate. This is a plausible scenario if for example you were leaving the wallet as an inheritance, with your will containing the people and locations where shares can be found. The attacker would then have to extend their attack to recovering the shares, possibly involving more people, more time and more risk for them. The downside of actually throwing away your `salt` and `brainkey` is that you may now require the cooperation of the trustees and you may be faced with a holdout.


## Agent Guide

As the trusted agent of the owner, it is your responsibility to act on their behalf and in their interest, not as you see it but as they seen it or would have seen it. Part of this responsibility is to prepare yourself in advance and not react in an ad-hoc way only when a worst-case scenario is already underway. This guide is written to help you with this preparation.

### Where are the Shares

!!! aside "Secrets: Salts and Shares"

    Since you and the agent should treat `salt` and `shares` in a very similar way, in this section I will refer to them both under the common term *secrets*.

Before the event that you have to act, the owner should give you instructions and over time they should keep you updated of any changes to these instructions. These you on a few things

 - how to secure any secrets and keep you updated if any chances to these circumstances. This may include information as to the whereabouts of the secrets, or information about how this information can be obtained. It should also include information about how you may authenticate yourself to any trustee, so that you can both be assured of each others p


### Secure Insecure Shares

Your first concern as the agent should be to secure any secrets that were under the control of the owner. Should the owner become incapacitated, there may be a newly added risk to such secrets. It might be the case for example, that the owner has a `salt` or some `shares` in their possession or in their home, which are now accessible to relatives or caretakers that may not be trusted by the owner. There may be keys to a safe or safety deposit box with such secrets. You as the trusted agent should secure any and all of these as soon as possible. While these secrets were not under your control and you therefore must presume them to have been copied/compromised, this step is nonetheless important in order to minimize risk.


### Preparation

The first step in the recovery process is not to collect the shares or even to contact any of the trustees. The shares are presumed to be safe in their current locations and the recovery process introduces a risk that this will no longer be the case. To minimize this risk the first step should be to make preparations so that the recovery can be done in a deliberate and orderly manner.


### Fund Transfer Preparation

The first question that needs to be answered, is what is to be done.


### Collecting Shares


> Aside: If you recover your own wallet and you collect the `shares` personally, it *may* be safe to continue to use the wallet and to not generate new keys. If you are *not* the owner however, and the recovery process involves the cooperation of some trustees, then there is a higher risk that some of them will collude to gain access to more `shares` than just their own. In this case it is best to prepare a new wallet in advance and move all coins to it as soon as possible. For more information, see the [Recovery Protocol](#recovery_protocol)



## Checklist

 - ☐ Print templates for N shares and 1 salt
 - ☐ Install Electrum Wallet on your phone

