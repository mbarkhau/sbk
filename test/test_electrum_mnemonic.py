import math

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


def main():
    raw = mnemonic_decode(TEST_SEED)
    print(raw)

    seed = seed_raw2phrase(raw)

    print(160 / 8)

    for _ in range(20):
        i = gen_int_seed(160)
        print(i)
        print(mnemonic_encode(i))


if __name__ == '__main__':
    main()
