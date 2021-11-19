# pylint: disable=wildcard-import
# pylint: disable=unused-wildcard-import

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


def test_wordlist_constraints():
    if sorted(WORDLIST) != WORDLIST:
        _print_words(WORDLIST)
        raise Exception("Wordlist not sorted!")

    # whitespace check
    assert [w.strip().replace(" ", "").lower() for w in WORDLIST] == WORDLIST
    # length check
    assert all(5 <= len(w) <= 8 for w in WORDLIST)
    # unique 3 letter prefixes
    assert len({w[:3] for w in WORDLIST}) == 256
    # no 3 letter prefix a substring of another word
    assert all(w1 == w2 or w1[:3] not in w2 for w1, w2 in itertools.product(WORDLIST, WORDLIST))
    # no duplicates
    assert len(set(WORDLIST)) == 256


@pytest.mark.skipif("slow" in os.getenv('PYTEST_SKIP', ""), reason="Basically this can't fail")
def test_wordlist_distances():
    for w1, w2 in itertools.product(WORDLIST, WORDLIST):
        if w1 != w2:
            d = pylev.damerau_levenshtein(w1, w2)
            assert d >= 3, (w1, w2)


def test_bytes2phrase_fail():
    try:
        bytes2phrase(b"\x00")
        assert False, "Expected ValueError"
    except ValueError:
        pass


def test_phrase2bytes_fail():
    assert phrase2bytes("abacus abraham"   , msg_len=2) == b"\x00\x01"
    assert phrase2bytes("abbakus abbrahame", msg_len=2) == b"\x00\x01"

    try:
        phrase2bytes("abbakuss xanadu", msg_len=2)
        assert False, "Expected ValueError"
    except ValueError as ex:
        assert "Unknown word" in str(ex)


def test_fuzz_bytes2phrase():
    for i in range(2, 100, 2):
        msg_len = i % 20
        data    = os.urandom(msg_len)
        phrase  = bytes2phrase(data)
        assert phrase2bytes(phrase, msg_len=msg_len) == data

        # provoke encoding errors
        assert phrase.encode('ascii').decode('ascii') == phrase


def test_fuzz_phrase2bytes():
    for _ in range(1, 100):
        words_1 = random.sample(WORDLIST, 8)
        words_2 = random.sample(WORDLIST, 8)
        words   = "\n".join(w1.ljust(9) + " " + w2.ljust(9) for w1, w2 in zip(words_1, words_2))

        data = phrase2bytes(words, msg_len=16)
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
    for _ in range(5):
        words_1 = random.sample(WORDLIST, 8)
        words_2 = random.sample(WORDLIST, 8)

        expected_phrase = "\n".join(w1.ljust(9) + " " + w2.ljust(9) for w1, w2 in zip(words_1, words_2))
        typo_words      = "\n".join(
            _sim_typo(w1, num_typos=num_typos).ljust(9) + " " + _sim_typo(w2, num_typos=num_typos).ljust(9)
            for w1, w2 in zip(words_1, words_2)
        )
        data          = phrase2bytes(typo_words, msg_len=16)
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
    wl_text = " ".join(WORDLIST)
    assert wl_text.count(" ") == 255
    wl_digest = hashlib.sha1(wl_text.encode("ascii")).hexdigest()
    assert wl_digest == "0f897109a5bf74607418c64c6dd85baaa2c210d2"
