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

ENTITY_WORDLIST_STR = """
abacus     acid       admiral    alcohol    angel      antenna    artichoke  asterix
avocado    baby       balloon    banana     barbie     battery    bazooka    beehive
beggar     bell       bible      bicycle    bishop     bitcoin    blanket    blood
boat       boxer      brain      bride      broccoli   buddha     buffalo    bullet
burger     button     cabbage    caesar     cake       camera     canvas     captain
cassette   chair      cherry     chief      chocolate  cinnamon   coconut    coffee
columbus   computer   confucius  cookie     coupon     cowboy     crown      crystal
darwin     dentist    devil      diamond    diesel     dildo      disc       dollar
donut      dragon     eagle      earpiece   edison     einstein   elephant   elvis
engineer   escort     euro       falcon     father     fire       flag       flower
flute      football   freddie    galileo    gameboy    gandhi     garlic     geisha
ghost      gift       gorilla    guitar     gymnast    hammer     hannibal   heart
hepburn    hippo      holmes     honey      horse      hunter     husky      iphone
ironman    jacket     jellyfish  jesus      jewel      jigsaw     joystick   judge
jukebox    kafka      kangaroo   kebab      kennedy    keyboard   kidney     kimono
kiwi       knight     koala      kurosawa   lambo      laptop     lasagna    lawyer
leibniz    lenin      letter     lincoln    lobster    luigi      macbook    madonna
manatee    mario      mason      meatball   mechanic   medusa     messi      miller
mirror     miyazaki   moses      motor      mozart     muffin     muhammad   murderer
mushroom   napoleon   necklace   needle     newton     ninja      obama      obelix
octopus    olive      onion      orange     ostrich    pancake    papaya     parrot
peanut     pelican    penguin    pepper     petrol     pharaoh    photo      piano
picasso    pigeon     pilot      pineapple  pirate     pistol     pizza      plumber
popcorn    potato     printer    prophet    pumpkin    pyramid    python     rabbit
rainbow    raspberry  raven      razor      rhino      rock       rolex      ronaldo
rousseau   saddam     salad      samurai    santa      satoshi    sausage    scorpion
server     shampoo    sheriff    shrimp     sinatra    sisyphus   skull      smith
socrates   spider     spoon      squid      stalin     steak      stone      sultan
sushi      swan       teacup     tequila    tiger      tobacco    tofu       toilet
torch      troll      trumpet    tshirt     turtle     tuxedo     umbrella   unicorn
vader      viagra     violin     vladimir   vodka      waffle     walnut     wasabi
webcam     witch      wizard     wolf       xbox       yoghurt    zebra      zombie
"""

LOCATION_WORDLIST_STR = """
adelaide   adidas     africa     alaska     alberta    amazon     anatolia   angola
ankara     antwerp    arabia     arctic     argentina  arizona    armenia    asia
aspen      atari      athens     atlanta    auburn     austria    babylon    baghdad
bahrain    bangkok    barcelona  bavaria    beijing    belgium    berlin     boeing
bohemia    bolivia    bordeaux   boston     botswana   brazil     britain    brooklyn
brussels   budapest   bulgaria   burma      cairo      calgary    cambodia   canada
carolina   castle     caucasus   chechnya   china      cisco      columbia   congo
cornwall   crete      crimea     croatia    cuba       cyprus     dakota     damascus
dayton     delhi      denmark    detroit    disney     dortmund   dresden    dublin
ebay       edinburgh  egypt      england    estonia    ethiopia   europe     facebook
fairfax    fiji       finland    florida    france     fujitsu    galway     gdansk
georgia    germany    ghetto     glasgow    google     gotham     greece     guatemala
haiti      halifax    hamburg    harvard    havana     hawaii     helsinki   himalaya
hitachi    hogwarts   holland    honolulu   hungary    ibiza      idaho      india
iowa       iraq       ireland    israel     istanbul   italy      ithaca     jakarta
jamaica    japan      jerusalem  jordan     kabul      kalahari   kansas     karachi
kashmir    kentucky   kiev       kinshasa   kolkata    konami     korea      kosovo
krakow     kuwait     kyoto      lagos      latvia     lebanon    lisbon     liverpool
london     madrid     malta      manhattan  maryland   mecca      melbourne  mercury
mexico     miami      michigan   milan      moldova    montana    morocco    moscow
mumbai     munich     myanmar    nagasaki   nairobi    nanjing    narnia     nassau
nepal      netflix    nevada     newport    nigeria    nike       nokia      norway
odessa     ohio       okinawa    omaha      ontario    oregon     orlando    ottawa
oxford     pacific    pakistan   palermo    paris      paypal     pluto      police
pompeii    portugal   prague     quebec     rhodes     romania    russia     sahara
santiago   scotland   seattle    seoul      serbia     seville    shanghai   shenzhen
sicily     siemens    slovakia   sony       spain      stanford   stockholm  sudan
suffolk    sussex     suzuki     sweden     sydney     tacoma     taiwan     tasmania
tehran     texas      thailand   tibet      tokyo      toledo     toronto    toulouse
trenton    trinidad   troy       tunisia    tuscany    uganda     ukraine    unesco
unicef     uruguay    utah       valencia   venice     vietnam    virginia   warsaw
yahoo      yemen      yokohama   youtube    zagreb     zambia     zanzibar   zimbabwe
"""

ENTITY_WORDLIST   = list(re.findall(r"[a-z]+", ENTITY_WORDLIST_STR  ))
LOCATION_WORDLIST = list(re.findall(r"[a-z]+", LOCATION_WORDLIST_STR))

WORDLISTS = [ENTITY_WORDLIST, LOCATION_WORDLIST]
WORDSETS  = [set(ENTITY_WORDLIST), set(LOCATION_WORDLIST)]

ALL_WORDS = set(sum(WORDLISTS, []))


PhraseStr = str


def _bytes2phrase_words(data: bytes) -> typ.Iterable[str]:
    for i in range(len(data)):
        wordlist = WORDLISTS[i % 2]
        word_idx = enc_util.char_at(data, i)
        word     = wordlist[word_idx]
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


def _fuzzy_match(word: str, wordlist: typ.List[str]) -> str:
    is_on_other_wordlist = word in ALL_WORDS and word not in wordlist
    if is_on_other_wordlist:
        errmsg = f"Invalid word order: {word}"
        raise ValueError(errmsg, word)

    def dist_fn(corpus_word: str) -> int:
        return pylev.damerau_levenshtein(word, corpus_word)

    dist, corpus_word = min((dist_fn(corpus_word), corpus_word) for corpus_word in wordlist)
    if dist >= 3:
        errmsg = f"Unknown word: {word}"
        raise ValueError(errmsg, word)

    return corpus_word


def _phrase2words(words: typ.List[str]) -> typ.Iterable[str]:
    for i, word in enumerate(words):
        word = word.strip().lower()
        if word not in WORDSETS[i % 2]:
            word = _fuzzy_match(word, WORDLISTS[i % 2])
        yield word


def phrase2words(phrase: PhraseStr) -> typ.Iterable[str]:
    return _phrase2words(phrase.split())


def phrase2bytes(phrase: PhraseStr) -> bytes:
    """Decode human readable phrases to bytes."""
    corpus = [ENTITY_WORDLIST, LOCATION_WORDLIST]

    data: typ.List[bytes] = []
    for i, word in enumerate(phrase2words(phrase)):
        wordlist = corpus[i % 2]
        word_idx = wordlist.index(word)
        data.append(struct.pack("B", word_idx))

    return b"".join(data)


def main() -> None:
    test_data = os.urandom(8)
    print(bytes2phrase(test_data))


if __name__ == '__main__':
    main()
