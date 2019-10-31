import os
import random

import pytest

from sbk.params import *


def test_mem_total():
    assert mem_total() > 0


@pytest.mark.skipif("slow" in os.getenv('PYTEST_SKIP', ""), reason="Calibration is expensive")
def test_estimate_param_cost():
    sys_info = load_sys_info()

    cost1 = estimate_param_cost(sys_info, init_kdf_params(p=sys_info.initial_p, m=10, t=1))
    cost2 = estimate_param_cost(sys_info, init_kdf_params(p=sys_info.initial_p, m=10, t=2))
    cost3 = estimate_param_cost(sys_info, init_kdf_params(p=sys_info.initial_p, m=20, t=1))
    cost4 = estimate_param_cost(sys_info, init_kdf_params(p=sys_info.initial_p, m=20, t=2))

    assert all(isinstance(c, float) for c in [cost1, cost2, cost3, cost4])
    assert round(cost1) == 0
    assert cost2 > cost1
    assert cost3 > cost1
    assert cost4 > cost3


def test_param_cfg2bytes_overflow():
    max_kwargs = {'salt_len': 64, 'brainkey_len': 32, 'threshold': 16}
    init_param_config(num_shares=1000, **max_kwargs)

    for key in max_kwargs:
        overflow_kwargs = max_kwargs.copy()
        overflow_kwargs[key] += 1
        try:
            init_param_config(num_shares=1000, **overflow_kwargs)
            assert False, f"expected exception for overflow of {key}"
        except AssertionError:
            pass


def test_param_cfg2bytes():
    in_p = init_param_config(
        salt_len=64,
        brainkey_len=32,
        threshold=16,
        num_shares=1000,
        kdf_parallelism=1,
        kdf_memory_cost=1,
        kdf_time_cost=1,
    )

    assert in_p.salt_len     == 64
    assert in_p.brainkey_len == 32
    assert in_p.threshold    == 16
    assert in_p.num_shares   == 1000

    result_data = param_cfg2bytes(in_p)

    assert isinstance(result_data, bytes)
    assert len(result_data) == 4

    out_p = bytes2param_cfg(result_data)

    assert out_p.num_shares >= in_p.threshold
    assert out_p.threshold    == in_p.threshold
    assert out_p.prime        == in_p.prime
    assert out_p.salt_len     == in_p.salt_len
    assert out_p.brainkey_len == in_p.brainkey_len
    assert out_p.kdf_params   == in_p.kdf_params

    # fields 0123
    assert result_data[:2] == b"\x0f\xff"
    # fields 456
    assert result_data[2:] == b"\x00\x00"


def test_kdf_params2bytes():
    non_kdf_params = {'salt_len': 64, 'brainkey_len': 32, 'threshold': 16, 'num_shares': 1000}

    for _ in range(100):
        p = random.randrange(1, int(2   ** (2 ** 4 - 1)))
        m = random.randrange(1, int(1.5 ** (2 ** 6 - 1)))
        t = random.randrange(1, int(1.5 ** (2 ** 6 - 1)))

        kdf_params = init_kdf_params(p=p, m=m, t=t)
        assert abs(kdf_params.p - p) / kdf_params.p < 0.5
        assert abs(kdf_params.m - m) / kdf_params.m < 0.5
        assert abs(kdf_params.t - t) / kdf_params.t < 0.5

        param_cfg = init_param_config(
            kdf_parallelism=p, kdf_memory_cost=m, kdf_time_cost=t, **non_kdf_params
        )
        assert param_cfg.kdf_params == kdf_params

        param_cfg_data = param_cfg2bytes(param_cfg)
        out_param_cfg  = bytes2param_cfg(param_cfg_data)
        assert out_param_cfg.kdf_params == kdf_params
