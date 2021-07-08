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

WORDLIST_STR = """
abacus     abraham    academy    acrobat    admiral    albino     alcohol    aquarium
atlantic   attorney   augustus   avocado    bazooka    beehive    beirut     benjamin
bible      bicycle    bismarck   blanket    boeing     bohemia    bolivia    bridge
broccoli   brussels   budapest   buffalo    button     cabbage    caesar     captain
carolina   caucasus   cherry     church     cinnamon   claudius   coconut    coffee
computer   cookie     coupon     cowboy     crystal    cyprus     darwin     dentist
deputy     detroit    diploma    doctor     dolphin    donut      dortmund   dracula
dublin     eagle      earpiece   edison     egypt      elephant   elvis      embassy
ethiopia   fairy      ferrari    firefly    flower     football   france     freddie
fujitsu    galileo    gameboy    geisha     ghost      glasgow    google     gorilla
gotham     gymnast    halifax    harvard    hawaii     headset    heineken   helsinki
hendrix    hepburn    hitachi    hunter     hyundai    indiana    iphone     island
jacket     jakarta    jericho    jigsaw     joystick   judge      jukebox    julius
kabul      kafka      kangaroo   kashmir    keyboard   kidney     kimono     knight
koala      kodak      kolkata    kosovo     kurosawa   laptop     latvia     lawyer
leather    lebanon    leibniz    lenin      library    lobster    lunatic    macbook
mason      meatball   mechanic   medusa     mercury    messi      michigan   miller
miyazaki   moldova    movie      mozart     muffin     muhammad   mumbai     mushroom
myanmar    nagasaki   nairobi    nanjing    napoleon   necklace   needle     netflix
newton     normandy   obelix     onion      ontario    oregon     orwell     oxford
package    pakistan   pancake    papaya     peanut     pelican    penguin    pepper
peugeot    picasso    pigeon     pilot      pistol     pizza      plumber    podium
popcorn    potato     present    printer    prophet    pumpkin    pyramid    python
queen      rabbit     radio      renault    reporter   rhubarb    romania    ronaldo
rousseau   saddam     salmon     samurai    santiago   satoshi    sausage    school
server     sheriff    siemens    simpson    sisyphus   slippers   slovakia   socrates
soldier    sparrow    spider     squid      sultan     sunlight   surgeon    suzuki
teacup     temple     tequila    texas      titanic    tobacco    toilet     tokyo
trinidad   trumpet    tshirt     tunisia    turtle     tuxedo     twitter    ukraine
ulysses    unesco     uruguay    vampire    victoria   violin     virginia   vivaldi
vladimir   volcano    voyager    waffle     walnut     warrior    wasabi     watanabe
webcam     whisky     wizard     xerox      yoghurt    yokohama   zambia     zimbabwe
"""


WORDLIST = WORDLIST_STR.split()
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


def phrase2bytes(phrase: PhraseStr) -> bytes:
    """Decode human readable phrases to bytes."""
    return b"".join(_phrase2bytes(phrase))


def main() -> None:
    test_data = os.urandom(8)
    print(bytes2phrase(test_data))


if __name__ == '__main__':
    main()
