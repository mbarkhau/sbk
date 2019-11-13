# This file is part of the SBK project
# https://gitlab.com/mbarkhau/sbk
#
# Copyright (c) 2019 Manuel Barkhau (mbarkhau@gmail.com) - MIT License
# SPDX-License-Identifier: MIT

"""Wordlists for SBK."""

import os
import re
import struct
import typing as typ

import pylev

from . import enc_util

WORDLIST_STR = """
abraham    academy    acrobat    admiral    airport    alaska     albino     amazon
america    android    antenna    apollo     aquarium   artist     athens     atlantic
attorney   auburn     austria    baghdad    barbeque   basket     bazooka    beehive
beggar     belfast    benjamin   berlin     bhutan     bicycle    bishop     bitcoin
blood      boeing     bridge     broccoli   brussels   buddha     buffalo    builder
caesar     canada     captain    caucasus   champion   chicago    church     clarinet
coconut    colombia   computer   corsica    cowboy     crown      crystal    cyprus
damascus   deputy     detroit    diamond    diesel     diploma    doctor     dolphin
dubai      edison     egypt      einstein   elephant   embassy    emperor    engine
escort     ethiopia   fairy      ferrari    firefly    flower     football   forest
france     freddie    gameboy    gandhi     geisha     georgia    germany    ghost
glasgow    google     gorilla    gotham     guitar     gymnast    hannibal   harvard
hawaii     headset    heineken   hendrix    hippo      hogwarts   hospital   hotel
hubble     hyundai    ironman    island     istanbul   italy      jakarta    jericho
jigsaw     joystick   jukebox    julius     kangaroo   karachi    kashmir    kennedy
keyboard   kingdom    kodak      kyoto      laptop     lasagna    leather    leibniz
leonardo   library    lobster    london     macbook    madonna    mechanic   mercedes
messi      mosquito   movie      muffin     muhammad   mushroom   nagasaki   nairobi
namibia    necklace   netflix    newton     nigeria    nintendo   norway     obama
octopus    office     okinawa    ontario    origami    orwell     ostrich    oxford
package    pakistan   paper      pelican    peugeot    pharaoh    picasso    pilot
plumber    podium     popcorn    porsche    potato     present    princess   prophet
pumpkin    pyramid    python     queen      radio      rainbow    redneck    renault
reporter   rhubarb    romania    rousseau   saddam     salmon     samurai    satoshi
school     scorpion   seattle    server     shanghai   sheriff    siemens    simpson
slippers   smith      socrates   soldier    sparrow    squid      stone      student
sunlight   surgeon    suzuki     taiwan     teacup     temple     tequila    texas
theatre    titanic    tobacco    tokyo      tolstoy    toronto    toshiba    trinidad
trumpet    tsunami    tunisia    turkey     tuscany    tuxedo     ukraine    umbrella
uranium    uruguay    valley     vampire    veteran    viagra     vietnam    village
virginia   vivaldi    vladimir   volcano    voyager    waffle     walnut     warrior
watanabe   webcam     whisky     wizard     xerox      yoghurt    yokohama   zimbabwe
"""


WORDLIST = list(sorted(re.findall(r"[a-z]+", WORDLIST_STR)))

WORDSET = set(WORDLIST)


PhraseStr = str


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


def _fuzzy_match(word: str) -> str:
    def dist_fn(corpus_word: str) -> int:
        return pylev.damerau_levenshtein(word, corpus_word)

    dist, corpus_word = min((dist_fn(corpus_word), corpus_word) for corpus_word in WORDLIST)
    if dist >= 4:
        errmsg = f"Unknown word: {word}"
        raise ValueError(errmsg, word)

    return corpus_word


def _phrase2words(words: typ.List[str]) -> typ.Iterable[str]:
    for word in words:
        word = word.strip().lower()
        if word not in WORDSET:
            word = _fuzzy_match(word)
        yield word


def phrase2words(phrase: PhraseStr) -> typ.Iterable[str]:
    return _phrase2words(phrase.split())


def phrase2bytes(phrase: PhraseStr) -> bytes:
    """Decode human readable phrases to bytes."""
    data: typ.List[bytes] = []
    for word in phrase2words(phrase):
        word_idx = WORDLIST.index(word)
        data.append(struct.pack("B", word_idx))

    return b"".join(data)


def main() -> None:
    test_data = os.urandom(8)
    print(bytes2phrase(test_data))


if __name__ == '__main__':
    main()
