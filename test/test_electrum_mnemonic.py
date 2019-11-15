import math
import random

from sbk.electrum_mnemonic import *

TEST_SEED_RAW = 5156716845057080301961779124221036524964

TEST_SEED = " ".join(
    [
        "region",
        "critic",
        "option",
        "whip",
        "repair",
        "age",
        "tobacco",
        "divide",
        "reveal",
        "chest",
        "saddle",
        "venue",
    ]
)


def test_is_seed_type():
    assert is_new_seed(TEST_SEED, prefix=SEED_PREFIX_SW)
    assert not is_new_seed(TEST_SEED, prefix=SEED_PREFIX)
    # assert is_old_seed(TEST_SEED)
    # assert not is_old_seed(TEST_SEED)


def test_mnemonic():
    raw    = TEST_SEED_RAW
    phrase = TEST_SEED
    assert mnemonic_decode(phrase) == raw
    assert mnemonic_encode(raw   ) == phrase

    expected = TEST_SEED
    assert mnemonic_encode(TEST_SEED_RAW) == expected


def test_electrum_mnemonic():
    raw_seed = gen_raw_seed(num_bits=128)
    assert 0 <= raw_seed < 2 ** 128

    try:
        gen_raw_seed(num_bits=127)
        assert False, "expected ValueError"
    except ValueError as ex:
        assert "divisible by 8" in str(ex)

    try:
        gen_raw_seed(num_bits=0)
        assert False, "expected ValueError"
    except ValueError as ex:
        assert "must be > 0" in str(ex)


def test_raw_seed2phrase():
    raw_seed = gen_raw_seed(128)
    phrase   = raw_seed2phrase(raw_seed)
    assert len(phrase.split(" ")) == 12
