# SBK: Split Bitcoin keys

With SBK you can create highly secure cold-storage Bitcoin wallets.

Secure means:

 - Your coins are safe, even if your house burns down and all of your documents and devices are destroyed.
 - Your coins are safe, even if a theif steals all your documents or hacker copies all of your files.
 - Your coins are safe, even if you trusted somebody you shouldn't have (not too often though).
 - Your coins are safe, even if something happens to you. At least your family will be able to recover your coins.

All of this is only true of course, as long as you follow the reccomended procedures.

SBK has two ways to open/recover your wallet.

 - A Brainkey: A passphrase which is known only to you and is not stored on any computer or written on any piece of paper. 
 - SBK-Shares: A set of phrases which are a backup of the brainkey. The [Shamir's Secret Sharing][href_wiki_sss] algorithm is used to generate these.

Using the Brainkey, you have convenient access your wallet (relatively speaking, considering it's a cold-storage wallet) and using the SBK-Shares you have a backup in case something goes wrong.

SBK is not itself a wallet, it only creates and recovers wallet seeds. SBK currently supports only the [Electrum Bitcoin Wallet][href_electrum_org].

[href_wiki_sss]: https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing

[href_electrum_org]: https://electrum.org/

> DISCLAIMER 
>
>  - SBK is still in development and has not had sufficient review
>    for serious use! Do not use this software for any purpose other
>    than to review and provide feedback or contributions.
>  - The SBK project is not associated in any way with the
>    Electrum Bitoin Wallet or Electrum Technologies GmbH.

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



# Technical Overview

## High Level Idea: Splitting and Joining Keys

If you are not a programmer, please forgive me starting with a technical description of SBK. The top priority at this point is to help other programmers so they can review the software. For now the documentation is geared towards programmers rather than novices and end users.

Without further ado, here is the basic idea. 

 1. Randomly generate your secrets: the Salt and your Brainkey. You always need both to load your wallet. Write down the Salt and keep it safe and secure, commit the Brainkey to your memory.
 2. Split the secrets into multiple SBK-Pieces (eg. 5 of which a minimum threshold of 3 for recovery). You should keep each in a secure and physically separate location.
 3. Join a minimum of the SBK-Pieces together in order to retreive your Salt and Brainkey. You only need to do this if either are lost/forgotten.
 4. Using your Salt, Brainkey and an optional `wallet-name`, you derive a wallet seed, which is used to load your wallet with Electrum.

<img alt="SBK Dataflow Diagram" src="https://mbarkhau.keybase.pub/sbk/sbk_dataflow_diagram.svg" height="650" />

Apart from giving a general overview, this doesn't tell you much of course. Some of the boxes might as well be labled with "Magic". The next few sections will explain the terms "Shamir's Secret Sharing" (SSS) and "Key Derivation Function" (KDF) in more detail.


## Prelude to SSS: Naive Key Splitting

It's fairly obvoius why you might want to split a secret key into multiple parts: Anybody who finds or steals the full key will have access to your wallet. To reduce your risk if being robbed, you can split the key into multiple parts. 

If for example you have a wallet seed of 12 words "abcd efgh ijkl", you could split it into fragments: "1: abcd", "2: efgh", "3: ijkl". This way each cannot be used by itself and to recover your wallet. The downside is that you increase the risk of losing your wallet: If you lose even one fragment, you lose the whole wallet.

To reduce this risk, you might want to add redundancy by making a copy of your each fragment: "4: abcd", "5: efgh", "6: ijkl".

There are two downsides to this approach:

 1. Some of the fragments are identical or have overlapping parts of the secret. and so the redundancy is not as great as you might hope. This means that two fragments could be lost and if they are the only ones with that part of the secret (for exapmle fragment 1 and 4), then you may have lost your wallet.
 2. If a fragment falls in the hands of an attacker, they can try to guess the remaining 8 words, which is a factor of 2048**4 = 17.592.186.044.416 fewer combinations to search through than if they knew nothing about your wallet seed. If you have trusted people who turn end up colluding with each other (which they have a financial incentive to do) then, then they only have 2048**4 combinations left to search through.

There may be slightly more clever schemes along these lines, but fortunately there is a better alternative: Keys can be split into pieces in a way that each piece is completely independent of every other. This means that e.g. in a 3 of 5 scheme, any 2 can be lost and the remaining 3 can be used to recover the original key (solving problem 1.). In this scheme each individual piece does not contain any useful information by itself, so that an attacker gains no advantage if they have fewer pieces than the minimum threshold (solving problem 2.). This scheme is called Shamir's Secret Sharing.


## SSS: Shamir's Secret Sharing

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
 2. Generate random parameters `i`, `j`, `k`, ... for a polynomial which goes through `S`
 3. Calculate 5 points `A`, `B`, `C`, `D` and `E` which lie on the polynomial
 4. Use polynomial interpolation to recover `S` using any 3 of `A` - `E`

The degree of the polynomial allows us control of the minimum number of points required to recover the secret (the threshold). Calculating additional/redundant points allows us to protect against the loss of any individual point.


## SSS: Some Implementation Details

There is more to story of course. I don't claim to understand in full how the attack works, but in the preceeding simplified/naive scheme there is some information leakage. Perhaps an attacker who knows fewer points than the threshold could narrow down their search space, because they know for example that the polynomial is continuous. I'm taking the cryptographer/mathematicians word that this is the case and that the solution to is to use finite field arithmetic.

Rather than doing calculations in the traditional cartesian plane, they are done in `GF(p)` or `GF(p^n)` (typically `GF(2^8) == GF(256)`. The current implementation of SBK uses `GF(p)` with a value for `p` that corresponds to the level of entropy of the brainkey. For a `--level=4` (64 bit) `brainkey` this would be `GF(2^64 - 59) == GF(18446744073709551557)`. Other Shamir's Secret Sharing schemes have chosen `GF(256)`. 

I did not choose this approach for SBK since:

 1. Implementing finite field arithmetic for `GF(p^n) | n > 1` rather than `GF(p)` was too complicated for me when I last attempted it. Arithmetic with `GF(p)` is easier to understand and should be easier to review.
 2. Since a computationally and memory intensive KDF is used to harden the Brainkey, low powered embedded systems are not a target for SBK.
 3. Python has native support for big integers, so arithmetic with large values is not an issue, which would otherwise be a motivation to use `GF(256)`. Since SBK uses Electrum (implemented with python), it is not an extra dependency to require a python interpreter. 

Notwithstanding these points, it may be worth it to implement SLIP0039. Particularly from the perspective of code review, an implementation that is not bespoke to SBK will probably receive more review and may have a better chance of being correct. Contributions are most welcome (and given the existing work done in the context SLIP0039 such contributions should be relatively simple).

[href_pointsoftware_ssssbs]: http://www.pointsoftware.ch/en/secret-sharing-step-by-step/


## Key Derivation using Argon2

Every wallet seed generated by SBK is ultimately derived from a random `seed` (with significant default entropy of `--seed-level=10` or ~160bits) and a random `brainkey` (with relatively low default entropy of `--level=4` or 64bits). SBK uses the [Argon2][href_github_phc_winner_argon2] [key derivation/password hashing function][href_wiki_kdf] with parameters chosen so that the key derivation process takes on the order of a few minutes. This means that even a relatively short and more easilly memorized `brainkey`, it will not be feasable to brute force a wallet seed generated by SBK. Your wallet will be protected for decades to come, even assuming an attacker gains access to your `salt` and even assuming the forseeable evolutions in computing technology[^fnote_quantum_resistance]. The price is that you have to wait for your wallet to load, so you will probably want an additional hot wallet for smaller and more frequent transactions.

Some back of the envelope calculations to illustrate the diffuculty of a brute force attack on an SBK-Wallet: If we assume the attacker has gained access to your salt, then they have to calculate 2^63 hashes to have a 50% chance of loading your wallet. Let's assume you used an average computer from 2012 as your airgapped computer and the Argon2 parameters which SBK chose were `time_cost=25` and `memory_cost=1024MB`. This might take 1-2 minutes to calculate, but on my more modern system, each hash with these parameters takes ca. 15 seconds. For easy math let's assume that an attacker has access to future hardware that can calculate these hashes in 1 second, further assume that they have unlimited access to 1 million such systems (and more money to spend than they could ever get from your wallet). After `2**63 / (1_000_000 * 86400 * 365.25) = 292271` years you would still have a 50% chance that your wallet had not been cracked. It seems it would be cheaper for them to knock down some doors. Beware of shorter keys lengths though: if you use a brainkey of only `--level=3` (48 bits), the same attacker would need less than 5 years, at `--level=2` (32 bits), they would need only `2**31 / (1_000_000 * 60) = 36` minutes.

All of this is assuming of course, that they somehow gained access to your `salt`. It may be ok for you to use a lower `--level` for your `brainkey` if you can satisfy one of these conditions: 

 - You are confident that your `salt` will never be found by anybody other than you.
 - If your `salt` is found by anybody, then you have some way to know that this happened. If you can make sure of this, then you will at least have enough time to move your funds to a new wallet. 

Even so, I would reccomend a brainkey of at least `--level=3` (48bits).

If you do not wish to ever use the `salt+brainkey` method to load your wallet, then you can simply discard them during the initial generation. To recover your wallet, your only option will then be to collect and join the SBK-Pieces. If you find yourself the the subject of a [$5 wrench attack][href_xkcd_538], you can plausibly deny that you memorized the `brainkey` and say that your attackers will have to go to the locations where you put and people/institutions to whom you gave the SBK-Pieces. Non-state attackers may find it difficult to convince a bank to open safety deposit box. Assuming state attackers can even find out who your trustees are, they may find it difficult to convince enough of them to betray you.

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

You might satisfy 1. for example by writing all wallet names down on each SBK-Piece or by sending them to those who will be responsible for your estate.

[href_wiki_plausible_deniability]: https://en.wikipedia.org/wiki/Plausible_deniability


## Encoding Secrets: Mnemonics and Intcodes

> Aside: The work done in this section preceeded the release of Trezor Shamir Backup, which has similar features based on similar reasoning. The forward error correction used is based on [Reed Solomon Codes][href_wiki_rscodes], which are superiour to the more simple [Luby Transform Codes][href_wiki_ltcodes] used in the current implementation of SBK.

The main reason to introduce a new encoding is to 

 1. To aid in memorization of the `brainkey`
 2. Provide protection against input errors
 3. Provide [forward error correction][href_wiki_fec] 

In addition to the mnemonic encoding, the `sbk-pieces` use a more compact encoding of the same data in the form of `intcodes`. In addition to the raw data encoded with the mnemonics, this encoding the same data as the `brainkey` but are more compact and provide the additional failsafe.

[href_wiki_rscodes]: https://en.wikipedia.org/wiki/Reed%E2%80%93Solomon_error_correction

[href_wiki_ltcodes]: https://en.wikipedia.org/wiki/Luby_transform_code

[href_wiki_fec]: https://en.wikipedia.org/wiki/Forward_error_correction


### Mnemonics Designed for Memory

> Caveat: All of this is based on conjecture and personal experience, I have no research to back up if this approach is actually better than memorizing 8 random words from a wordlist of 256.

SBK uses the same mnemonic phrases both for SBK-Pieces as well as for the `salt` and `brainkey`. The format is designed with the following in mind:

 - Human memory is better at remembering people, places and stories than random data
 - Human memory fills in gaps (often incorrectly) so ambiguous words must be avoided

I know from personal experience that I can remember phone numbers, mathematical constants, poems and even my old ICQ number after multiple decades. In light of this, a brainkey can be a reasonable choice to generate a wallet, as long the brain becomes accustomed to the regular recall of the information. 

How much dilligence you exercise to remember your `brainkey` is up to you, but as an aid to your memory, instead of using large list of common words from the dictionary, SBK uses words from the folliwing categories and in the following order: Adjective, Person, City, Place.

This allows you to use the [Method of Loci][href_wiki_method_of_loki] or for you to construct a story as a memory aid around your brainkey. Here is an example of a phrase:

    The SCARY MAYOR at the PRAGUE BRIDGE.

This structure aims to take advantage of ability of humans to remember what has been very important to us throughout history: stories about people and places. As an example, you might have a `brainkey` with `--level=4`, which encodes 64 bits of entropy in 4 phrases.

    The BRAVE  CHILD  at the MADRID STAGE.
    The HAPPY  SISTER at the SEOUL  GHETTO.
    The DIRTY  BAKER  at the LONDON TEMPLE.
    The HONEST TAILOR at the SPARTA BEACH.

Sparta doesn't really exist anymore of course, and even when it did, it wasn't next to the ocean, so I'd be surprised if there was anything one might call a beach. A ghetto doesn't sound like something I that exists in Seoul, but then again I've never been there so maybe it's this Gangnam thing from the song? Anyway, these are words chosen at random, so they may not make any sense. What they allow you to do though, is to make sense of them by constructing a stories with quirky characters in strange places. 

[href_wiki_method_of_loki]: https://en.wikipedia.org/wiki/Method_of_loci


### Integer Codes

In addition to the mnemonic encoding, SBK uses a more 

Since recovery involves the input of multiple `sbk-pieces` and the key derivation takes time, a lack of protection against intput errors would make it time consuming to discover which `sbk-piece` was entered incorrectly. SBK also encodes the correct order of inputs in each `sbk-piece` to protect against words being skipped or entered in the wrong order.

TODO: implementation details


### FEC: Luby Transform Codes

> Aside: 

As `sbk-pieces` may be stored for long periods and could deteriorate or be partially destroyed through bad handling, adding forward error correction provodes some protection and gives a better chance of recovery.

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
for i, piece in enumerate(sbk_shares):
    piece_text = mnemonic_encode(piece)
    print(f"Write down piece {i + 1}: {piece_text}")
```


# User Guide

> Always remember: Your keys, your coins; not your keys, not your coins.
> 
> The security of your wallet begins and ends with you. There are no banks to take care of your security, there are no institutions to run to if something goes wrong. 
>
>  - If you are a trustee, don't trust anybody who asks you to hand them your `sbk-piece`.
>  - If you are the owners agent, familiarize yourself with and adhere to the recovery protocol.
>  - If you are the owner, trust as few people as possible and only trust people who you regard as not only righteous but also competent.

While we started with the technical aspects of SBK, compared with the human aspects of security, they are almost ancilarry. When talking about security for this kind of system, the most difficult are all the parts that humans can mess up. This starts with simple things like prevending transcription and input errors and ends with more philosophical questions like "who can you trust?".

Throughout this guide, I will assume the most paranoid position I can imagine. This may seem over the top for your situation, . 

[href_github_skr]: https://github.com/WebOfTrustInfo/rwot8-barcelona/blob/master/topics-and-advance-readings/social-key-recovery.md


## Trustee Guide

### Integrity and Seals

Imagine for example the owners agent is attempting to collect your `sbk-peice` without you noticing.


## Agent Guide

The agent acts on behalf of the owner if they cannot act themselves. This may be the case if the owner has died or has been incapacited in some way. The agent of the owner is responsible to act on their behalf according to their will (if provided) or in their best interests.

The primary responsibility of an agent is to recover the wallets of the owner without compromising their security. The agent is the person who is most likely to be in a position to steal the owners coins and so their actions deserve special scruitiny. Trustees should be especially weary of an agent who asks them to simply hand over their `sbk-piece`. A trustee should be the only person to unsealing and input their `sbk-piece` on 

The trustees should be watching and scruitinizing you. Provide them with any information they ask for, do not ask them for any information whatsoever. 

 - There should be a mutual understanding among all participants what will happen to the coins
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

### Recovery form SBK-Pieces: Risks


### Recovery form SBK-Pieces: Guide

There are three areas of risk to be aware of:

 - Lost of Secrets
 - Game theoretical risks
    - Holdouts
    - 
 - Compromised Software

> Aside: SBK exists in part to provide documentation to the owners trustees and agents, who may be laypeople wrt. cryptocurrency.




# Unsorted

## Future Work

 - Vendoring
 - SLIP0039


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
