from sbk.params import *


def test_mem_total():
    assert mem_total() > 0


def test_get_avail_config_ids():
    avail_config_ids = get_avail_config_ids()
    assert len(avail_config_ids) > 4


def test_estimate_config_cost():
    sys_info = load_sys_info()
    costs    = estimate_config_cost(sys_info)
    assert costs.keys() == PARAM_CONFIGS_BY_ID.keys()
    assert set(map(type, costs.values())) == {float}
    assert round(costs[INSECURE]) == 0


def test_params2bytes():
    p = init_params(threshold=12, num_pieces=14, kdf_param_id=16, key_len_bytes=48)

    pow2prime_idx = primes.get_pow2prime_index(p.key_len_bytes * 8)
    result_data   = params2bytes(p)

    assert result_data == b"\x1b\x0b\x10"

    p = bytes2params(result_data)

    assert p.threshold == 12
    assert p.num_pieces >= 12
    assert p.pow2prime_idx == pow2prime_idx
    assert p.kdf_param_id  == 16
    assert p.key_len_bytes == 48
