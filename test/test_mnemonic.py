import os
import random
import hashlib
import itertools

import pylev
import pytest

from sbk.mnemonic import *


def _print_words(wl):
    for i, word in enumerate(sorted(wl)):
        print(f"{word:<9} ", end=" ")
        if (i + 1) % 8 == 0:
            print()
    print()


@pytest.mark.parametrize("wordlist", [ENTITY_WORDLIST, LOCATION_WORDLIST])
def test_wordlist_constraints(wordlist):
    if sorted(wordlist) != wordlist:
        _print_words(wordlist)
        raise Exception("Wordlist not sorted!")

    # whitespace check
    assert [w.strip().replace(" ", "").lower() for w in wordlist] == wordlist
    # length check
    assert all(4 <= len(w) <= 9 for w in wordlist)
    # unique 3 letter prefixes
    assert len({w[:3] for w in wordlist}) == 256
    # no duplicates
    assert len(set(wordlist)) == 256


@pytest.mark.skipif("slow" in os.getenv('PYTEST_SKIP', ""), reason="Basically this can't fail")
@pytest.mark.parametrize("wordlist", [ENTITY_WORDLIST, LOCATION_WORDLIST])
def test_wordlist_distances(wordlist):
    for w1, w2 in itertools.product(wordlist, wordlist):
        if w1 == w2:
            continue
        d = pylev.damerau_levenshtein(w1, w2)
        assert d >= 3, (w1, w2)


def test_wordlists():
    wl1 = set(ENTITY_WORDLIST)
    wl2 = set(LOCATION_WORDLIST)
    assert len(wl1 & wl2) == 0


def test_bytes2phrase_fail():
    try:
        bytes2phrase(b"\x00")
        assert False, "Expected ValueError"
    except ValueError:
        pass


def test_phrase2bytes_fail():
    assert phrase2bytes("abacus adelaide") == b"\x00\x00"
    assert phrase2bytes("abakus adilaide") == b"\x00\x00"

    try:
        phrase2bytes("abbakuss adilaid")
        assert False, "Expected ValueError"
    except ValueError as ex:
        assert "Unknown word" in str(ex)

    try:
        phrase2bytes("adelaide abacus")
        assert False, "Expected ValueError"
    except ValueError as ex:
        assert "Invalid word order" in str(ex)


def test_fuzz_bytes2phrase():
    for i in range(2, 100, 2):
        data   = os.urandom(i % 20)
        phrase = bytes2phrase(data)
        assert phrase2bytes(phrase) == data

        # provoke encoding errors
        assert phrase.encode('ascii').decode('ascii') == phrase


def test_fuzz_phrase2bytes():
    for i in range(1, 100):
        words_1 = random.sample(ENTITY_WORDLIST  , 8)
        words_2 = random.sample(LOCATION_WORDLIST, 8)
        words   = "\n".join(w1.ljust(9) + " " + w2.ljust(9) for w1, w2 in zip(words_1, words_2))

        data = phrase2bytes(words)
        assert len(data) == 16
        assert bytes2phrase(data) == words


@pytest.mark.parametrize("num_typos, max_fail_ratio", [(1, 0.0), (2, 0.1)])
def test_fuzz_phrase2words_fuzzymatch(num_typos, max_fail_ratio):
    def _sim_typo(word, num_typos):
        for i in range(num_typos):
            word = word[:i] + random.choice(word) + word[i + 1 :]
        return word

    ok   = 0
    fail = 0
    for i in range(5):
        words_1 = random.sample(ENTITY_WORDLIST  , 8)
        words_2 = random.sample(LOCATION_WORDLIST, 8)

        expected_phrase = "\n".join(
            w1.ljust(9) + " " + w2.ljust(9) for w1, w2 in zip(words_1, words_2)
        )
        typo_words = "\n".join(
            _sim_typo(w1, num_typos=num_typos).ljust(9)
            + " "
            + _sim_typo(w2, num_typos=num_typos).ljust(9)
            for w1, w2 in zip(words_1, words_2)
        )
        data          = phrase2bytes(typo_words)
        result_phrase = bytes2phrase(data)

        result_words   = result_phrase.replace("\n", " ").split()
        expected_words = expected_phrase.replace("\n", " ").split()

        for result_word, expected_word in zip(result_words, expected_words):
            if result_word == expected_word:
                ok += 1
            else:
                fail += 1

    assert ok + fail == 80
    assert fail <= 80 * max_fail_ratio


def test_phrase_hardcoded():
    # this is to prevent accidental changes to the wordlists
    wl_text = " ".join(ENTITY_WORDLIST + LOCATION_WORDLIST)
    assert wl_text.count(" ") == 511
    wl_digest = hashlib.sha1(wl_text.encode("ascii")).hexdigest()
    assert wl_digest == "d424a4ea958c8dc7d04cc9ac77028ade6b877c45"
