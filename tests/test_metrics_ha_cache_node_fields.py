"""GET /api/clusters/<id>/metrics without a connection and without a cached answer builds
its nodes from the HA loop's last look. Those entries had status, cpu, memory and disk
only: no score, no cpu_percent or mem_percent, no offline flag. The Modern node card
formats the score of every node that is not offline and threw on them, which took the
whole dashboard down while the cluster was out of reach.

The route now hands out the entries get_node_status() builds from the same HA view when
it is disconnected, marked from_ha_cache.
"""
import datetime

import pytest

from pegaprox.core.manager import PegaProxManager

SEEN = datetime.datetime(2026, 11, 3, 4, 5, 6)
LIVE_FIELDS = ('status', 'cpu_percent', 'mem_percent', 'mem_used', 'mem_total', 'disk_percent',
               'disk_used', 'disk_total', 'netin', 'netout', 'score', 'uptime', 'offline', 'last_seen')


def _ha_view():
    return {'pve1': {'status': 'online', 'last_seen': SEEN},
            'pve2': {'status': 'online'},
            'pve3': {'status': 'offline', 'last_seen': SEEN}}


@pytest.fixture
def admin(api, seed):
    return api.as_user(seed.user('admin1', role='admin'))


def _fake(api, connected=False):
    mgr = api.make_fake_manager('c1')
    mgr.is_connected = connected
    mgr._cached_metrics = None
    mgr.ha_node_status = _ha_view()
    return api.set_manager('c1', mgr)


def _disconnected_manager():
    mgr = object.__new__(PegaProxManager)
    mgr.is_connected = False
    mgr.session = None
    mgr.ha_node_status = _ha_view()
    return mgr


def test_every_node_from_the_ha_cache_carries_the_fields_of_a_live_entry(api, admin):
    _fake(api)
    r = admin.get('/api/clusters/c1/metrics')
    assert r.status_code == 200, r.get_data(as_text=True)
    body = r.get_json()
    assert set(body) == {'pve1', 'pve2', 'pve3'}
    for name, entry in body.items():
        missing = [f for f in LIVE_FIELDS if f not in entry]
        assert not missing, (name, missing)
        assert isinstance(entry['score'], (int, float)), (name, entry)
        assert entry['from_ha_cache'] is True, name
    assert [n for n, e in sorted(body.items()) if e['offline']] == ['pve3']
    assert body['pve1']['last_seen'] == SEEN.isoformat() and body['pve2']['last_seen'] is None


def test_the_route_and_a_disconnected_manager_answer_the_same_nodes(api, admin):
    _fake(api)
    got = admin.get('/api/clusters/c1/metrics').get_json()
    want = _disconnected_manager().get_node_status()
    assert want, 'the manager has no HA fallback to compare with'
    assert got == {n: dict(e, from_ha_cache=True) for n, e in want.items()}


def test_a_failed_live_read_falls_back_to_the_same_entries(api, admin):
    mgr = _fake(api, connected=True)
    mgr.get_node_status.side_effect = RuntimeError('PVE went away')
    body = admin.get('/api/clusters/c1/metrics').get_json()
    assert all(isinstance(e.get('score'), (int, float)) and e['from_ha_cache'] for e in body.values()), body


def test_without_an_ha_view_the_route_still_says_it_is_offline(api, admin):
    mgr = _fake(api)
    mgr.ha_node_status = {}
    r = admin.get('/api/clusters/c1/metrics')
    assert r.status_code == 503 and r.get_json()['offline'] is True
