from sbk import kdf
from sbk import params


def test_derive_key():
    secret_data = b"\x01\x23\x45\x67"
    salt_data   = b"\x01\x23\x45\x67" * 2
    for hash_len in range(4, 50):
        res = kdf.derive_key(secret_data, salt_data, params.INSECURE, hash_len)
        assert len(res) == hash_len
