"""One number that is not a number stops no loop.

A threshold stored as text raised at the comparison in the alert loop and took every later rule of every cluster with it,
each round. A check_interval stored as text ended the daemon loop of its cluster for good. The forms send numbers, the API
took anything.
"""
import types
from unittest.mock import MagicMock, patch

import pytest

import pegaprox.background.alerts as al
from pegaprox.core.manager import PegaProxManager


@pytest.fixture
def admin(api, seed, db):
    mgr = api.make_fake_manager(cluster_id='c1', get_node_status={'n1': {'status':'online','cpu_percent':99,'mem_used':1,'mem_total':2}})
    mgr.config = types.SimpleNamespace(name='c1', check_interval=300, host='h', enabled=True)
    api.set_manager('c1', mgr)
    return api.as_user(seed.user('adm', role='admin')), mgr


RULE = {'name': 'r', 'metric': 'cpu', 'operator': '>', 'channels': [], 'target_type':'cluster'}


@pytest.mark.parametrize('bad', ['80', 'high', None, True, [80]])
def test_a_threshold_that_is_no_number_is_refused(admin, bad):
    c, _ = admin
    assert c.post('/api/clusters/c1/alerts', json=dict(RULE, threshold=bad)).status_code == 400
    assert c.post('/api/alerts', json=dict(RULE, threshold=bad)).status_code == 400


def test_a_number_still_goes_through(admin):
    c, _ = admin
    r = c.post('/api/clusters/c1/alerts', json=dict(RULE, threshold=85.5))
    assert r.status_code == 200 and r.get_json()['alert']['threshold'] == 85.5


def test_an_update_is_checked_too(admin):
    c, _ = admin
    made = c.post('/api/clusters/c1/alerts', json=dict(RULE, threshold=85)).get_json()['alert']['id']
    assert c.put(f'/api/clusters/c1/alerts/{made}', json={'threshold': 'x'}).status_code == 400
    assert c.put(f'/api/clusters/c1/alerts/{made}', json={'threshold': 70}).status_code == 200


def _rules(*thresholds):
    return {'enabled': True, 'alerts': [dict(RULE, id=f'r{i}', enabled=True, cluster_id='c1', threshold=t, target_id='', severity='auto')
                                         for i, t in enumerate(thresholds)]}


@pytest.mark.parametrize('stored', ['80', 'high', None])
def test_a_bad_rule_already_stored_does_not_stop_the_rules_after_it(admin, stored):
    seen = []
    with patch.object(al, 'load_alerts_config', return_value=_rules(stored, 10)), \
            patch.object(al, 'dispatch_alert', return_value=(False, False, [], [])), \
            patch.object(al, '_record_eval', side_effect=lambda alert_id, **kw: seen.append(alert_id)):
        al.check_and_send_alerts()  # raised TypeError at the comparison
    assert 'r1' in seen, seen


@pytest.mark.parametrize('bad', ['300', 'abc', None, 0, -5, True, 90000])
def test_a_check_interval_out_of_range_is_refused(admin, bad):
    c, mgr = admin
    with patch('pegaprox.api.clusters.save_config'):
        assert c.patch('/api/clusters/c1/config', json={'check_interval': bad}).status_code == 400
    assert mgr.config.check_interval == 300


def test_a_good_check_interval_is_taken(admin):
    c, mgr = admin
    with patch('pegaprox.api.clusters.save_config'):
        assert c.patch('/api/clusters/c1/config', json={'check_interval': 60}).status_code == 200
    assert mgr.config.check_interval == 60


# inf and a value past threading.TIMEOUT_MAX raise in the wait (or hang under gevent), 0.001 spins
@pytest.mark.parametrize('stored', ['300', None, 0, float('inf'), 1e10, 0.001])
def test_one_stored_before_this_does_not_end_the_daemon_loop(stored):
    waits = []
    loop = MagicMock()
    loop.stop_event = types.SimpleNamespace(is_set=lambda: bool(waits), wait=lambda seconds=None: waits.append(seconds))
    loop.config = types.SimpleNamespace(name='c1', enabled=True, check_interval=stored)
    with patch('pegaprox.core.manager.ha') as ha:
        ha.is_active.return_value = False
        PegaProxManager.daemon_loop(loop)
    assert waits == [300]
