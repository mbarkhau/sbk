import os
import random

import pytest

from sbk import kdf
from sbk import params


def test_mem_total():
    assert params.mem_total() > 0


@pytest.mark.skipif("slow" in os.getenv('PYTEST_SKIP', ""), reason="Calibration is expensive")
def test_fresh_sys_info(capsys):
    sys_info = params.fresh_sys_info()
    assert sys_info.num_cores > 0
    assert sys_info.total_mb  > 0
    assert sys_info.initial_p > 0
    assert sys_info.initial_m > 0
    assert len(sys_info.measurements) == 0

    sys_info = update_measurements(sys_info)
    assert len(sys_info.measurements) >= 8

    assert params._load_cached_sys_info() == sys_info


@pytest.mark.skipif("slow" in os.getenv('PYTEST_SKIP', ""), reason="Calibration is expensive")
def test_estimate_param_cost():
    sys_info = params.load_sys_info()

    cost1 = params.estimate_param_cost(kdf.init_kdf_params(p=sys_info.initial_p, m=10, t=1))
    cost2 = params.estimate_param_cost(kdf.init_kdf_params(p=sys_info.initial_p, m=10, t=2))
    cost3 = params.estimate_param_cost(kdf.init_kdf_params(p=sys_info.initial_p, m=20, t=1))
    cost4 = params.estimate_param_cost(kdf.init_kdf_params(p=sys_info.initial_p, m=20, t=2))

    assert all(isinstance(c, float) for c in [cost1, cost2, cost3, cost4])
    assert round(cost1) == 0
    assert cost2 > cost1
    assert cost3 > cost1
    assert cost4 > cost3


@pytest.mark.skipif("slow" in os.getenv('PYTEST_SKIP', ""), reason="Measurement is expensive")
def test_measurement(capsys):
    kdf_params = params.get_default_params()

    tgt_eta = 2
    while True:
        eta = params.estimate_param_cost(kdf_params)
        if eta < tgt_eta:
            break
        kdf_params = kdf_params._replace_any(m=kdf_params.m / 1.5, t=kdf_params.t / 1.5)

    sys_info    = params.load_sys_info()
    measurement = params.measure_in_thread(kdf_params, sys_info)

    # measurement isn't so precise
    eta_lo = eta / 10
    eta_hi = eta * 10
    assert eta_lo < measurement.duration < eta_hi, measurement


def test_param_cfg2bytes_overflow():
    max_kwargs = {'brainkey_len': 32, 'threshold': 16}
    params.init_param_config(num_shares=1000, **max_kwargs)

    for key in max_kwargs:
        overflow_kwargs = max_kwargs.copy()
        overflow_kwargs[key] += 1
        try:
            params.init_param_config(num_shares=1000, is_segwit=True, **overflow_kwargs)
            assert False, f"expected exception for overflow of {key}"
        except AssertionError:
            pass


def test_param_cfg2bytes():
    in_p = params.init_param_config(
        brainkey_len=32,
        threshold=16,
        num_shares=1000,
        is_segwit=True,
        kdf_parallelism=1,
        kdf_memory_cost=1,
        kdf_time_cost=1,
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
    for _ in range(100):
        brainkey_len = random.randrange(1, 16) * 2
        threshold    = random.randrange(1, 16)
        is_segwit    = bool(random.random() < 0.5)

        in_p = params.init_param_config(
            brainkey_len=brainkey_len,
            threshold=threshold,
            num_shares=1000,
            is_segwit=is_segwit,
            kdf_parallelism=1,
            kdf_memory_cost=1,
            kdf_time_cost=1,
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
