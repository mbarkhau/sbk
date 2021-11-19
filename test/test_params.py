import os
import random

import pytest

from sbk import kdf
from sbk import sys_info
from sbk import parameters


def test_mem_total():
    assert sys_info.mem_total() > 0


@pytest.mark.skipif("slow" in os.getenv('PYTEST_SKIP', ""), reason="Calibration is expensive")
def test_load_sys_info():
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
    kdf_params = kdf.init_kdf_params(m=1, t=1)
    parameters.init_param_config(threshold=16, num_shares=1000, kdf_params=kdf_params)

    try:
        parameters.init_param_config(threshold=17, num_shares=1000, kdf_params=kdf_params)
        assert False, "expected exception for overflow of 'threshold'"
    except ValueError:
        pass  # expected


def test_param_cfg2bytes():
    kdf_params = kdf.init_kdf_params(m=10, t=1)
    in_params  = parameters.init_param_config(
        threshold=16,
        num_shares=1000,
        kdf_params=kdf_params,
    )

    assert in_params.threshold  == 16
    assert in_params.num_shares == 1000

    result_data = parameters.param_cfg2bytes(in_params)

    assert isinstance(result_data, bytes)
    assert len(result_data) == 3

    out_params = parameters.bytes2param_cfg(result_data)

    assert out_params.num_shares >= in_params.threshold
    assert out_params.threshold  == in_params.threshold
    assert out_params.prime      == in_params.prime
    assert out_params.kdf_params == in_params.kdf_params

    # fields 01
    assert result_data[:1] == b"\x1F"
    # fields 234
    assert result_data[1:] == b"\x00\x00"


def test_param_cfg2bytes_fuzz():
    kdf_params = kdf.init_kdf_params(m=10, t=1)
    for _ in range(100):
        threshold = random.randrange(2, 10)

        in_params = parameters.init_param_config(
            threshold=threshold,
            num_shares=1000,
            kdf_params=kdf_params,
        )

        result_data = parameters.param_cfg2bytes(in_params)

        assert isinstance(result_data, bytes)
        assert len(result_data) == 3

        out_params = parameters.bytes2param_cfg(result_data)

        assert out_params.threshold == in_params.threshold

        assert out_params.num_shares >= in_params.threshold
        assert out_params.prime      == in_params.prime
        assert out_params.kdf_params == in_params.kdf_params


def test_curve_params():
    bases = [
        (2     ,  1, 0),
        (1.5   ,  2, - 1),
        (1.25  ,  4, - 3),
        (1.125 ,  8, - 7),
        (1.0625, 16, -15),
    ]

    for base, expected_s, expected_o in bases:
        s, o = parameters.param_coeffs(base)

        assert s == expected_s
        assert o == expected_o

        assert parameters.param_exp(0, base) == 1
        assert parameters.param_exp(1, base) == 2

        prev_raw_val = -1
        for field_val in range(0, 2 ** 6):
            raw_val = parameters.param_exp(field_val, base)
            assert raw_val > prev_raw_val
            prev_raw_val = raw_val

            out_field_val = parameters.param_log(raw_val      , base)
            raw_val_2     = parameters.param_exp(out_field_val, base)
            assert raw_val_2 == raw_val
            eps = abs(field_val - out_field_val)
            assert eps < 0.0001, (base, field_val, out_field_val)
