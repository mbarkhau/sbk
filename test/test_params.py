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
