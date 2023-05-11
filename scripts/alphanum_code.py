"""
Encodings that can be spoken by humans.

Each word encodes 8bits of data and ~6 bits for error correction.
Each word has structure CCNN (2 upper-case letters and 2 decimal digits).
Each letter has one or two sylables
Verbally ambiguous character are omitted.
No sylables are reapeated.

The idea is to have something which a human
can memorize, assuming that recall of words
is easier when there is a rhythm to it.
"""

import math
import random


letters = sorted(set("ABCDEFGHJKLMNOPQRSTUVXYZ"))


def _iter_codewords_llldd():
    for l1 in letters:
        for l2 in letters:
            if l1 == l2:
                continue
            for l3 in letters:
                if l1 == l3 or l2 == l3:
                    continue
                for d in [2,3,4,5,6,8,9]:
                    for n in [1,2,3,4,5,6,8,9]:
                        yield f"{l1}{l2}{l3}{d}{n}"


def _iter_codewords_lldd():
    for l1 in letters:
        for l2 in letters:
            if l1 == l2:
                continue
            for d in [2,3,4,5,6,8,9]:
                for n in [1,2,3,4,5,6,8,9]:
                    yield f"{l1}{l2}{d}{n}"


def _iter_codewords_ldd():
    for l1 in letters:
        for d in [2,3,4,5,6,8,9]:
            for n in [1,2,3,4,5,6,8,9]:
                yield f"{l1}{d}{n}"


codewords = list(_iter_codewords_ldd())
codewords = list(_iter_codewords_lldd())
codewords = list(_iter_codewords_llldd())
num_words = len(codewords)

print(" ".join(random.sample(codewords, 16)))
print(" ".join(random.sample(codewords, 16)))
print(" ".join(random.sample(codewords, 16)))
print(" ".join(random.sample(codewords, 16)))
print(" ".join(random.sample(codewords, 16)))
print(" ".join(random.sample(codewords, 16)))

print(num_words, math.log(num_words) / math.log(2))
