import os
import random

import pytest

from sbk import kdf
from sbk import params
from sbk import sys_info


def test_mem_total():
    assert sys_info.mem_total() > 0


@pytest.mark.skipif("slow" in os.getenv('PYTEST_SKIP', ""), reason="Calibration is expensive")
def test_load_sys_info(capsys):
    if sys_info.SYSINFO_CACHE_FPATH.exists():
        sys_info.SYSINFO_CACHE_FPATH.unlink()

    nfo = sys_info.load_sys_info(use_cache=False)
    assert nfo.num_cores > 0
    assert nfo.total_mb  > 0
    assert nfo.initial_p > 0
    assert nfo.initial_m > 0

    assert sys_info.load_sys_info() is nfo
    assert sys_info._load_cached_sys_info() == nfo


def test_param_cfg2bytes_overflow():
    kdf_params = kdf.init_kdf_params(p=1, m=1, t=1)
    max_kwargs = {'brainkey_len': 32, 'threshold': 16}
    params.init_param_config(num_shares=1000, kdf_params=kdf_params, **max_kwargs)

    for key in max_kwargs:
        overflow_kwargs = max_kwargs.copy()
        overflow_kwargs[key] += 1
        try:
            params.init_param_config(
                num_shares=1000, kdf_params=kdf_params, is_segwit=True, **overflow_kwargs
            )
            assert False, f"expected exception for overflow of {key}"
        except AssertionError:
            pass


def test_param_cfg2bytes():
    kdf_params = kdf.init_kdf_params(p=1, m=1, t=1)
    in_p       = params.init_param_config(
        brainkey_len=32, threshold=16, num_shares=1000, is_segwit=True, kdf_params=kdf_params,
    )

    assert in_p.brainkey_len == 32
    assert in_p.threshold    == 16
    assert in_p.num_shares   == 1000

    result_data = params.param_cfg2bytes(in_p)

    assert isinstance(result_data, bytes)
    assert len(result_data) == 4

    out_p = params.bytes2param_cfg(result_data)

    assert out_p.num_shares >= in_p.threshold
    assert out_p.threshold    == in_p.threshold
    assert out_p.prime        == in_p.prime
    assert out_p.raw_salt_len == in_p.raw_salt_len
    assert out_p.brainkey_len == in_p.brainkey_len
    assert out_p.kdf_params   == in_p.kdf_params

    # fields 0123
    assert result_data[:2] == b"\x01\xff"
    # fields 456
    assert result_data[2:] == b"\x00\x00"


def test_param_cfg2bytes_fuzz():
    kdf_params = kdf.init_kdf_params(p=1, m=1, t=1)
    for _ in range(100):
        brainkey_len = random.randrange(1, 16) * 2
        threshold    = random.randrange(1, 16)
        is_segwit    = bool(random.random() < 0.5)

        in_p = params.init_param_config(
            brainkey_len=brainkey_len,
            threshold=threshold,
            num_shares=1000,
            is_segwit=is_segwit,
            kdf_params=kdf_params,
        )

        result_data = params.param_cfg2bytes(in_p)

        assert isinstance(result_data, bytes)
        assert len(result_data) == 4

        out_p = params.bytes2param_cfg(result_data)

        assert out_p.brainkey_len == in_p.brainkey_len
        assert out_p.threshold    == in_p.threshold
        assert out_p.is_segwit    == is_segwit

        assert out_p.num_shares >= in_p.threshold
        assert out_p.prime        == in_p.prime
        assert out_p.raw_salt_len == in_p.raw_salt_len
        assert out_p.kdf_params   == in_p.kdf_params
