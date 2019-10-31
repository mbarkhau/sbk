from sbk import kdf
from sbk import params


def test_derive_key():
    secret_data = b"\x01\x23\x45\x67"
    salt_data   = b"\x01\x23\x45\x67" * 2
    kdf_params  = params.init_kdf_params(p=1, m=8, t=1)
    for hash_len in range(4, 50):
        res = kdf.derive_key(secret_data, salt_data, kdf_params, hash_len)
        assert len(res) == hash_len
