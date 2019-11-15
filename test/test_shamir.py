import os

import pytest

import sbk.kdf
import sbk.params
import sbk.shamir
import sbk.enc_util


@pytest.mark.parametrize("use_gf_p", [True, False])
def test_split(use_gf_p):
    kdf_params = sbk.kdf.init_kdf_params(p=1, m=1, t=1)
    param_cfg  = sbk.params.init_param_config(
        brainkey_len=8, threshold=2, num_shares=3, kdf_params=kdf_params
    )
    param_cfg_data = sbk.params.param_cfg2bytes(param_cfg)
    x_coord_index  = len(param_cfg_data)

    raw_salt = os.urandom(sbk.params.RAW_SALT_LEN)
    brainkey = os.urandom(param_cfg.brainkey_len)

    shares = list(sbk.shamir.split(param_cfg, raw_salt, brainkey, use_gf_p=use_gf_p))
    assert len(shares) == 3
    assert all(share.startswith(param_cfg_data) for share in shares)
    assert {share[x_coord_index] for share in shares} == {1, 2, 3}


@pytest.mark.parametrize("use_gf_p", [True, False])
def test_join(use_gf_p):
    kdf_params = sbk.kdf.init_kdf_params(p=1, m=1, t=1)
    param_cfg  = sbk.params.init_param_config(
        brainkey_len=8, threshold=2, num_shares=3, kdf_params=kdf_params
    )
    param_cfg_data = sbk.params.param_cfg2bytes(param_cfg)

    raw_salt_in = os.urandom(sbk.params.RAW_SALT_LEN)
    brainkey_in = os.urandom(param_cfg.brainkey_len)

    shares = list(sbk.shamir.split(param_cfg, raw_salt_in, brainkey_in, use_gf_p=use_gf_p))
    raw_salt_out, brainkey_out = sbk.shamir.join(param_cfg, shares, use_gf_p=use_gf_p)

    assert raw_salt_in == raw_salt_out
    assert brainkey_in == brainkey_out


EDGE_CASES = [
    (1, b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", b"\x00\x00\x00\x00\x00\x00\x00\x00"),
    (0, b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", b"\x00\x00\x00\x00\x00\x00\x00\x00"),
    (1, b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00"),
    (0, b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00"),
]


@pytest.mark.parametrize("use_gf_p, raw_salt_in, brainkey_in", EDGE_CASES)
def test_shamir_edgecases(use_gf_p, raw_salt_in, brainkey_in):
    kdf_params = sbk.kdf.init_kdf_params(p=1, m=1, t=1)
    param_cfg  = sbk.params.init_param_config(
        brainkey_len=len(brainkey_in), threshold=7, num_shares=11, kdf_params=kdf_params
    )

    shares = list(sbk.shamir.split(param_cfg, raw_salt_in, brainkey_in, use_gf_p=use_gf_p))
    raw_salt_out, brainkey_out = sbk.shamir.join(param_cfg, shares, use_gf_p=use_gf_p)

    assert raw_salt_in == raw_salt_out
    assert brainkey_in == brainkey_out
