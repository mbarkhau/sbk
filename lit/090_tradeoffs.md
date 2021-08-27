# Tradeoffs

The use-case for SBK is the sovereign individual. Nothing epitimizes
this more than a brainkey. SBK is first and foremost about direct and
individual control of bitcoin, and secondarilly about Shamir's Secret
Sharing, which is only for backup purposes, not a means to distribute
keys. If your use-case matches this, then many criticisms of SSS are
not applicable. This chapter will concern itself nonetheless with
these criticisms.

In broad terms, SBK is a step up from a wallet seed, it is a
pure-software alternative/complement to a hardware wallet but it does
not offer all the benefits of a multisig setup. By all means use a
multisig setup, in which SBK may play a role and thereby reduce your
risk from depending on any individual vendor, software stack or
hardware system.


## Single Point of Failure

If you are concerned about a compromised device, despite all
precautions to validate your SBK Live download and boot on an
air-gapped system, then by all means, use a multisig setup to mitigate
this risk. Sign substantial transactions on separate computers in
separate locations using sofware from separate vendors that was
separately downloaded and validated.


## Software Implementation Bugs

Previous implementations of SSS in the Bitcoin wallets have suffered
from broken implementations. This criticism can be leveled against any
hardware and software wallet and bugs can be fixed. If complex
implementations are an issue, then this criticism is much more
applicaple to hardware wallets.

We are making an effort to accomidate validation of the implementation
and audit of artifacts. As of this writing, these concerns are valid,
at some point however, such concerns should be regarded as FUD by
vendors who perhaps have a conflict of interest to disuade you from
using pure Open Source non-custodial solutions from which they don't
earn any money.


## Social Recovery Complexities

Much of the criticisms of SSS key recovery revolve around bad actors
who can forge shares and gain access to the other shares during a
colaborative recovery process. If you can declare can declare a single
person as the sole custodial of the inheritence, to whom all shares
are given, then these criticisms do not apply. The custodial can
determine for themselves which shares are invalid, as an invalid share
will not produce a valid wallet.

If you use SBK with a multi-sig setup, and instruct mutliple
custodials to do separate wallet recoveries, then these criticisms do
not apply.

All risks regarding relative trustworthiness and holdouts are equally
applicable to multisig setups, where some parties might refuse to sign
transactions.


## Inability to Verify Share Integrity

Each SBK share has error correction data based on a Reed-Solomon Code.
This serves the dual purpose to protect against corruption and bad
handwriting as well as to verify the correctness of the share.

To verify authenticity of a share, without revealing the share itself
would be an improvement over what is currently implemented. It would
make the life of a custodial easier and expand the use-cases for SBK
if each share could be verified without revealing the share itself.


## Side Channel Attacks

Such attacks are mitigated substantially when you use the SBK Live
distribution and do not have your computer connected to a network
(either via cable or wifi) when you boot SBK Live to access your
wallet. For EMI/DPA attacks to work, the attacker must have had access
to your computer or be in close proximity and presumably have you as a
specific target. Here again, the answer is multisig, with or without
SBK.


[href_keys_casa_sssss]

>  Key splitting can function as an alternative to multisig, but after
>  researching its practical application at Casa, we rejected
>  implementing Shamir's Secret Sharing Scheme because it exposes
>  clients to many more risks.

[href_security_nihilism]: https://news.ycombinator.com/item?id=27897975

[href_keys_casa_sssss]: https://blog.keys.casa/shamirs-secret-sharing-security-shortcomings/

[href_clavestone]: https://medium.com/clavestone/bitcoin-multisig-vs-shamirs-secret-sharing-scheme-ea83a888f033

