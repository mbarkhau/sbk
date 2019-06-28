import os

import sbk.enc_util


def test_phrase_round_trip():
    for i in range(100):
        data   = os.urandom(10)
        phrase = sbk.enc_util.bytes2phrase(data)
        assert sbk.enc_util.phrase2bytes(phrase) == data
