import math

from sbk.electrum_mnemonic import *

TEST_SEED_RAW = 51567168450570803019617791242210365249640000000000

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
    assert is_new_seed(test_seed, prefix=SEED_PREFIX_SW)
    assert not is_new_seed(test_seed, prefix=SEED_PREFIX)
    assert is_old_seed(test_seed, prefix=SEED_PREFIX_SW)
    assert not is_old_seed(test_seed, prefix=SEED_PREFIX)


def test_mnemonic():
    raw    = TEST_SEED_RAW
    phrase = " ".join(TEST_SEED)
    assert mnemonic_decode(phrase) == raw
    assert mnemonic_encode(raw   ) == phrase

    expected = " ".join(TEST_SEED)
    assert mnemonic_encode(TEST_SEED_RAW) == expected


print(mnemonic_decode(test_seed))

seed = seed_raw2phrase()


print(160 / 8)

for _ in range(20):
    i = gen_int_seed(160)
    print(i)
    print(mnemonic_encode(i))
