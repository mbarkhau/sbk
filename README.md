


`IANYMIGOAYDAYR`: I am not your mother, I only give advice, your decisions are your responsibility.


## Introduction

SBK has two ways to keep your keys safe.

 - A Brainkey which only you know
 - A backup using [Shamir's Secret Sharing][href_wiki_sss]


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

Neither of the above two methods are particularly complicated, they are somewhat tedious however, especially method A. For regular daily use, it is a reasonable convenience/security trade-off to have a hot-wallet with small and only access your cold-storage wallet a few times per year.

With SBK your wallet seed is split into multiple pieces using the well known [Shamir's Secret Sharing algorithm][href_wiki_sss]. You can later join these pieces back together and recover the original wallet seed. This protects your wallet from:

 1. Loss: If any individual piece is lost, the remaining pieces are still sufficient to recover the wallet seed.
 2. Theft: If any individual piece is found, stolen or otherwise compromised, your wallet is still safe, as any individual piece is useless by itself.

> Aside: For the purposes of illustration I will continue in the examples here with a 3 of 5 scheme. That is to say, five SBK-Pieces are generated in total, of which at least three are required in order to recover the wallet seed and of which no more than two may be lost before the wallet seed cannot be recovered.

If a piece is either lost or stolen, you should create a new key as soon as possible (and move your coins to a new wallet).


### Encoding

Each pair of words encodes a single byte. There are four wordlists, each with 16 short and common English words. The minimum edit distance of each word in a wordlist is 3 and the minimum edit distance for all 16 * 4 = 64 words is 2. This hopefully means that the encoding is resilient to input errors, so that even if "MAYOR" is mistyped or misremembered as "MAJOR", and even words are remembered in the incorrect order, there is a fighting chance that the brainkey can nonetheless be recovered.



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


## Ranty Pitch

There is moniker in the Bitcoin/Crypto community that goes something like this: If you're not the one or not the only one who has the private keys to your wallet, then you don't own your bitcoin and you're doing it wrong and you should feel bad and you only have yourself to blame if your coins get stolen.

This advice is fine as far as it goes. It falls short of course in that it doesn't say what a good way is to "be your own bank". You forget your wallet phrase or it gets destroyed: "well, that's just too bad, you should have been more responsible". You used your wallet on a windows machine and your wallet got swept by a virus: "well that's just too bad you shouldn't keep your wallet on an insecure system like windows". You used a paper wallet but for some reason it was empty after you only took a little bit form it, "well that's just too bad, you should have known about change addresses and used better wallet software".

I view all of this as an tech-elitism or a revenge of the nerds: "You're not tech savey enough to be your own bank? Well tough luck dudebro, I guess you're to stupid to be a part of the crypto revolution. Oh, you're coins got stolen by a frappuccino slurping frenchman? Well tough luck jock, serves you right for trusting the same exchange everybody else was using."

The goal of the SBK project is to be your own bank for mere mortals. In principle it is quite similar to [How Jason Bourne Stores His Bitcoin](http://maxtaco.github.io/bitcoin/2014/01/16/how-jason-bourne-stores-his-bitcoin/) by [Max Krohn](http://maxtaco.github.io/)

The main arguments against this approach are:

https://news.ycombinator.com/item?id=7083393

 - Loss of access to the SBK software or the Air Gapped Machine (AGM)
    - Perhaps use M-Disc
    - Documentation of Format




