# This file is part of the sbk project
# https://github.com/mbarkhau/sbk
#
# Large portions of this module are based on the
# electrum implementation itself in particular on:
# https://github.com/spesmilo/electrum/blob/master/electrum/mnemonic.py
#
# Changes are limited to minimal type checking, automatic
# formatting and the hardcoded wordlists.
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2016 Thomas Voegtlin
#
# SPDX-License-Identifier: MIT
"""Electrum mnemonic encoding and decoding functions.

These are replicated so that SBK can invoke "electrum restore <mnemonic>".
"""
# pylint:disable=too-many-lines; tis waht it is

import os
import hmac
import string
import typing as typ
import hashlib
import binascii

from . import common_types as ct
from . import package_data

wordlist     = package_data.read_wordlist("electrum_english.txt")
old_wordlist = package_data.read_wordlist("electrum_old.txt")

wordlist_indexes     = {w: i for i, w in enumerate(wordlist    )}
old_wordlist_indexes = {w: i for i, w in enumerate(old_wordlist)}

N = len(old_wordlist)
assert N == 1626


# Note about US patent no 5892470: Here each word does not represent a given digit.
# Instead, the digit represented by a word is variable, it depends on the previous word.
#
# US patent no 5892470 has expired in the meantime.

Mnemonic = typ.List[str]


def old_mn_encode(message: str) -> Mnemonic:
    assert len(message) % 8 == 0
    out: Mnemonic = []
    for i in range(len(message) // 8):
        word = message[8 * i : 8 * i + 8]
        x    = int(word, 16)
        w1   = x % N
        w2   = ((x // N) + w1) % N
        w3   = ((x // N // N) + w2) % N
        out += [old_wordlist[w1], old_wordlist[w2], old_wordlist[w3]]
    return out


def old_mn_decode(wlist: Mnemonic) -> str:
    out = ''
    for i in range(len(wlist) // 3):
        word1, word2, word3 = wlist[3 * i : 3 * i + 3]
        w1 = old_wordlist_indexes[word1]
        w2 = (old_wordlist_indexes[word2]) % N
        w3 = (old_wordlist_indexes[word3]) % N
        x  = w1 + N * ((w2 - w1) % N) + N * N * ((w3 - w2) % N)
        out += "%08x" % x
    return out


RawSeed    = int
SeedPhrase = str


def mnemonic_decode(seed: SeedPhrase) -> RawSeed:
    n = len(wordlist)
    i = 0

    words = seed.split()
    while words:
        w = words.pop()
        k = wordlist_indexes[w]
        i = i * n + k
    return i


def mnemonic_encode(i: RawSeed) -> SeedPhrase:
    n = len(wordlist)

    words = []
    while i:
        x = i % n
        i = i // n
        words.append(wordlist[x])
    return " ".join(words)


VALID_CHARS = set(string.ascii_lowercase + " ")


def normalize_text(seed: str) -> str:
    # lower
    seed = seed.lower()
    # normalize whitespaces
    seed = " ".join(seed.strip().split())
    assert all(c in VALID_CHARS for c in seed)
    return seed


# The hash of the mnemonic seed must begin with this
SEED_PREFIX     = '01'  # Standard wallet (aka. legacy)
SEED_PREFIX_SW  = '100'  # Segwit wallet
SEED_PREFIX_2FA = '101'  # Two-factor authentication


def seed_prefix(seed_type: str) -> str:
    if seed_type == 'standard':
        return SEED_PREFIX
    elif seed_type == 'segwit':
        return SEED_PREFIX_SW
    elif seed_type == '2fa':
        return SEED_PREFIX_2FA
    else:
        raise ValueError("Invalid seed type", seed_type)


bfh = bytes.fromhex
hfu = binascii.hexlify


def bh2u(x: bytes) -> str:
    """Convert bytes to hex str.

    str with hex representation of a bytes-like object

    >>> x = bytes((1, 2, 10))
    >>> bh2u(x).upper()
    '01020A'

    :param x: bytes
    :rtype: str
    """
    return hfu(x).decode('ascii')


def is_old_seed(seed: str) -> bool:
    # pylint: disable=broad-except; vendored from electrum
    seed  = normalize_text(seed)
    words = seed.split()

    try:
        # checks here are deliberately left weak for legacy reasons, see #3149
        old_mn_decode(words)
        uses_only_old_words = True
    except Exception:
        uses_only_old_words = False
    try:
        seed_data = bfh(seed)
        is_hex    = len(seed_data) == 16 or len(seed_data) == 32
    except Exception:
        is_hex = False

    return is_hex or (uses_only_old_words and (len(words) in (12, 24)))


def is_new_seed(x: str, prefix: str = SEED_PREFIX) -> bool:
    x = normalize_text(x)

    message   = x.encode('utf8')
    hmac_data = hmac.new(b"Seed version", message, hashlib.sha512).digest()
    return bh2u(hmac_data).startswith(prefix)


def raw_seed2phrase(int_seed: RawSeed) -> ct.ElectrumSeed:
    # based on Mnemonic.make_seed
    prefix = seed_prefix('segwit')

    nonce = 0
    while True:
        nonce += 1
        i = int_seed + nonce

        seed = mnemonic_encode(i)
        if not is_new_seed(seed, prefix) or is_old_seed(seed):
            continue

        if i != mnemonic_decode(seed):
            raise Exception("Cannot extract same entropy from mnemonic!")

        return ct.ElectrumSeed(seed)


def bytes2int(data: bytes) -> int:
    return int(binascii.hexlify(data), 16)


RandomFn = typ.Callable[[int], bytes]


def gen_raw_seed(num_bits: int, random_fn: RandomFn = os.urandom) -> RawSeed:
    if num_bits % 8 != 0:
        raise ValueError("Argument 'num_bits' must be divisible by 8.")
    if num_bits < 1:
        raise ValueError("Argument 'num_bits' must be > 0.")

    num_bytes = num_bits // 8

    data = random_fn(num_bytes)
    return bytes2int(data)
