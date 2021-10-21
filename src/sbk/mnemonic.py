# This file is part of the SBK project
# https://github.com/mbarkhau/sbk
#
# Copyright (c) 2019-2021 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT

"""Wordlists for SBK."""

import os
import struct
import typing as typ

import pylev

from . import enc_util
from . import package_data

WORDLIST = package_data.read_wordlist("sbk_en_v0.txt")
WORDSET  = set(WORDLIST)

assert len(WORDLIST) == 256
assert len(WORDSET ) == 256
assert sorted(WORDLIST) == WORDLIST
assert all(5 <= len(w) <= 8 for w in WORDLIST)
assert len({w[:3] for w in WORDLIST}) == 256

WORD_INDEXES   = {w: i for i, w in enumerate(WORDLIST)}
wordlist_index = WORD_INDEXES.__getitem__

assert wordlist_index("abacus"  ) == 0
assert wordlist_index("zimbabwe") == 255
assert wordlist_index(WORDLIST[127]) == 127


PhraseStr = str


def byte2word(data: bytes) -> str:
    assert len(data) == 1
    word_idx = enc_util.char_at(data, 0)
    return WORDLIST[word_idx]


def _bytes2phrase_words(data: bytes) -> typ.Iterable[str]:
    for i in range(len(data)):
        word_idx = enc_util.char_at(data, i)
        word     = WORDLIST[word_idx]
        yield word.ljust(9)


def bytes2phrase(data: bytes) -> PhraseStr:
    """Encode data as a human readable phrases."""
    if len(data) % 2 != 0:
        errmsg = f"Invalid len(data), must be multiple of 2, was {len(data)}"
        raise ValueError(errmsg)

    words = iter(_bytes2phrase_words(data))

    word_pairs = []
    try:
        while True:
            word_pair = next(words) + " " + next(words)
            word_pairs.append(word_pair)
    except StopIteration:
        return "\n".join(word_pairs)


def fuzzy_match(word: str) -> str:
    def dist_fn(wl_word: str) -> int:
        dist = pylev.damerau_levenshtein(word, wl_word)
        assert isinstance(dist, int)
        return dist

    dist, wl_word = min((dist_fn(wl_word), wl_word) for wl_word in WORDLIST)
    if dist < 4:
        return wl_word
    else:
        errmsg = f"Unknown word: {word}"
        raise ValueError(errmsg, word)


def phrase2words(phrase: PhraseStr) -> typ.Iterable[str]:
    for word in phrase.split():
        word = word.strip().lower()
        if word not in WORDSET:
            word = fuzzy_match(word)
        yield word


def _phrase2bytes(phrase: PhraseStr) -> typ.Iterable[bytes]:
    for word in phrase2words(phrase):
        yield struct.pack("B", wordlist_index(word))


def phrase2bytes(phrase: PhraseStr, msg_len: int) -> bytes:
    """Decode human readable phrases to bytes."""
    return b"".join(_phrase2bytes(phrase))[:msg_len]


def main() -> None:
    test_data = os.urandom(8)
    print(bytes2phrase(test_data))


if __name__ == '__main__':
    main()
