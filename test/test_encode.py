import os

import ssk.enc_util


def test_phrase_round_trip():
    for i in range(100):
        data   = os.urandom(10)
        phrase = ssk.enc_util.bytes2phrase(data)
        assert ssk.enc_util.phrase2bytes(phrase) == data
