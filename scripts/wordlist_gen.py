#!/usr/bin/env python3
# flake8: noqa
# type: ignore
"""

Usage: scripts/wordlist_gen.py

"""

import io
import re
import sys
import json
import math
import curses
import typing as typ
import pathlib as pl
import collections
import itertools

import pylev


# The technical criteria for the wordlist are:
#
#  - The wordlist has 256 words.
#  - All words must be at least 5 characters long.
#  - All words must be at most 8 characters long.
#  - All words must have a unique 3 character prefix.
#  - The 3 character prefix of a word may not be a part of may other word.
#  - The damerau levenshtein edit distance of any two words must be at least 3.


REPLACEMENTS = {
    "ä": "ae",
    "ü": "ue",
    "ö": "oe",
    "ß": "ss",
}


def read_wordlist(filepath: str) -> typ.Iterator[str]:
    with pl.Path(filepath).open(mode="r", encoding="utf-8") as fobj:
        for line in fobj:
            if line.startswith("#"):
                continue

            word = line.strip()
            word = word.lower()
            prefilter_word = (
                " " in word
                or len(word) < 5
                or len(word) > 8
            )
            if prefilter_word:
                continue

            for search, replacement in REPLACEMENTS.items():
                word = word.replace(search, replacement)
            yield word


def main(args: list[str]) -> None:
    if "--help" in args:
        print(__doc__)
        return

    include_path = args[0]
    for word in read_wordlist(include_path):
        print(word)

    return


if __name__ == '__main__':
    main(sys.argv[1:])
