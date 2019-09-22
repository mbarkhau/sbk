


`IANYMIGOAYDAYR`: I am not your mother, I only give advice, your decisions are your responsibility.


## Introduction

SBK has two ways to keep your keys safe.

 - A Brainkey which only you know
 - A backup using [Shamir's Secret Sharing][href_wiki_sss]

Here is some pseudocode to show how the wallet seed and backup sbk-pieces are derived:

```python
# 64 bits (small enough to memorize)
brainkey = os.urandom(8)
brainkey_mnemonic = mnemonic_encode(brainkey)
print(f"Memorize brainkey: {brainkey_mnemonic}")

class Params:

    version         : int
    key_length      : int
    shamir_threshold: int
    shamir_prime    : int
    memory_cost     : int
    time_cost       : int


def kdf(secret: bytes, salt: bytes, params: Params) -> bytes:
    """"Key Derivation Function using argon2."""
    return argon2(
        secret=brainkey,
        salt=salt,
        memory_cost=params.memory_cost,
        time_cost=params.time_cost,
        hash_len=params.key_length,
    )

params = Params(...)
param_data: bytes = params.encode()

# The salt is actually both the salt as well
# as the serialized parameters.
raw_salt = os.urandom(18)
salt = param_data + raw_salt

salt_text = mnemonic_encode(salt)
print(f"Write down salt: {salt_text}")

# derive the master key
master_seed = kdf(brainkey, salt, params)

sbk_pieces = shamir_split(
    master_seed,
    params.threshold,
    params.num_pieces,
    params.shamir_prime,
)
for i, piece in enumerate(sbk_pieces):
    piece_text = mnemonic_encode(piece)
    print(f"Write down piece {i + 1}: {piece_text}")
```

There are two methods to restore a Bitcoin wallet using SBK:

 A. Salt + SBK-Pieces: This method is a backup in case the brainkey is lost or forgotten.
 B. Salt + Brainkey: This method is intended for regular use.

Wallet recovery using Method A (Salt + SBK-Pieces):

```python
salt_text: str = input("Enter salt> ")
salt: bytes = mnemonic_decode(salt_text)
params = Params.parse(salt)

pieces: List[bytes] = []
while len(pieces) < params.threshold:
    piece_text = input("Enter SBK-Piece> ")
    piece = mnemonic_decode(piece_text)
    pieces.append(piece)

master_seed = shamir_join(pieces, params)
wallet_name_text: str = intput("Enter (optional) wallet name> ")
wallet_name = wallet_name_text.encode("utf-8")
wallet_seed = kdf(master_seed, wallet_name, params)
```

Wallet recovery using Method B (Salt + Brainkey):

```python
salt: bytes = input("Enter salt> ")
params = Params.parse(salt)

brainkey: bytes = input("Enter brainkey> ")
master_seed = kdf(brainkey, salt, params)

wallet_name_text: str = intput("Enter (optional) wallet name> ")
wallet_name = wallet_name_text.encode("utf-8")
wallet_seed = kdf(master_seed, wallet_name, params)
```

### Terms

The above code uses some concepts that deserve elaboration. Each will be explained in more detail, but 

 - Brainkey: This is a relatively small piece of data, short enough to be memorized by a person, ie. to be held in their brain. This is a bit like a password for your wallet, except that the password technically not not used to decrypt anyting, instead it is used to deterministically (re)create your wallet. The main problem with a brainkey is that attackers might be able to do a brute force search for all wallets generated with such small brainkeys. If such attacks can be effectively mitigated and if the brainkey is not used for anything other than for the wallet, the owner can be certain that 
 - Key Derivation Function (KDF):
 - Salt: 
 - Shamir Split/Join:
 - Parameters: 
    - Threshold
    - Shamir Prime
    - Memory/Time Cost
# Since the params and the salt are both required
# for any recovery, we combine them so they are
# always kept together.
 - SBK-Piece:
 - Mnemonic:
 - Secret Key:
 - Wallet name: The wallet name is a convenient way to generate multiple wallets from the same brainkey. You can treat this as a passphrase, on the other hand, a passphrase is another single point of failure in the same way that a traditional 12 word wallet seed is. If you are going to write this phrase down only once and put it in a safe, you might as well skip the use of SBK and just write down a traditional wallet seed instead.
 - This is an added factor of protection. Please be aware that such a passphrase suffers from all of the problems of a brainkey, but has none of the protections. There is no backup and there is no protection against typos. 

## Passphrase Reccomendations

 If you use passphrases, I would reccomend to write them down and make multiple copies and keep some of those copies in places . IANYMIGOAYDAYR. The balance here is between the risk of these passphrases being lost and the risk of being forced to grant access 

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

> Aside: SBK exists in part to provide the executor of a will (who may be a layperson wrt. Bitcoin), a well documented resource on how to recover


## Lost of Secrets


## Ranty Pitch

There is moniker in the Bitcoin/Crypto community that goes something like this: If you're not the one or not the only one who has the private keys to your wallet, then you don't own your bitcoin and you're doing it wrong and you should feel bad and you only have yourself to blame if your coins get stolen.

This advice is fine as far as it goes. It falls short of course in that it doesn't say what a good way is to "be your own bank". You forget your wallet phrase or it gets destroyed: "well, that's just too bad, you should have been more responsible". You used your wallet on a windows machine and your wallet got swept by a virus: "well that's just too bad you shouldn't keep your wallet on an insecure system like windows". You used a paper wallet but for some reason it was empty after you only took a little bit form it, "well that's just too bad, you should have known about change addresses and used better wallet software".

I view all of this as an tech-elitism or a revenge of the nerds: "You're not tech savey enough to be your own bank? Well tough luck dudebro, I guess you're to stupid to be a part of the crypto revolution. Oh, you're coins got stolen by a frappuccino slurping frenchman? Well tough luck jock, serves you right for trusting the same exchange everybody else was using."

The goal of the SBK project is to be your own bank for mere mortals. In principle it is quite similar to [How Jason Bourne Stores His Bitcoin](http://maxtaco.github.io/bitcoin/2014/01/16/how-jason-bourne-stores-his-bitcoin/) by [Max Krohn](http://maxtaco.github.io/)

The main arguments against this approach are:

https://news.ycombinator.com/item?id=7083393

 - Why not Multisig
 - [Brute force attack (by wrench)](https://xkcd.com/538/)
 - Loss of access to the SBK software or the Air Gapped Machine (AGM)
    - Perhaps use M-Disc
    - Documentation of Format




## Related Work

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


