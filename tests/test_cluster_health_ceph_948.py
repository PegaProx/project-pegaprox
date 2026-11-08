"""Ceph in the cluster health score (#948).

GET /api/clusters/<id>/health scored nodes, storage, replication and the backup SLA, so a
cluster with Ceph in HEALTH_ERR (OSDs of a whole host down, half the objects degraded)
still came out at the top. Now Ceph is a factor of its own on a cluster that has it:
HEALTH_WARN takes 15 points off and holds the score at 75 at most, HEALTH_ERR takes 50
off and holds it at 25 - 'good' at best with a warning, 'critical' with an error.

The status is the read the ceph_health alert and the Ceph overview share
(alert_events.ceph_status). A poll never waits for it: a missing or old read starts in
the background and the poll scores what is there. A cluster without a Ceph storage whose
Ceph never answered is not asked at all and scores exactly as before.

The clusters are faked at the API paths they are asked; the background read is held
back by the tests and run when they say so, except in the one test that lets the real
thread run.
NS Oct 2026
"""
import time

import pytest

import pegaprox.api.clusters as clusters_mod
from pegaprox.background import alert_events
from pegaprox.core.cache import StorageDataCache

CID = 'cluster_1'
ROUTE = f'/api/clusters/{CID}/health'
CEPH = '/cluster/ceph/status'
STORAGE = '/cluster/resources?type=storage'


class _Resp:
    def __init__(self, code, data):
        self.status_code, self._data = code, data

    def json(self):
        return {'data': self._data}


class _Cluster:
    host, api_port, is_connected = '10.0.0.1', 8006, True

    def __init__(self, storage, ceph=(404, None), nodes=None, cluster_type='proxmox'):
        self.cluster_type = cluster_type
        self.paths = {STORAGE: (200, storage), CEPH: ceph}
        self.nodes = dict(nodes or {'pve1': {'status': 'online'}, 'pve2': {'status': 'online'}})
        self.calls = []
        self.slow = {}

    def _api_get(self, url, timeout=10):
        path = url.split('/api2/json', 1)[1]
        self.calls.append(path)
        if path in self.slow:
            time.sleep(self.slow[path])
        hit = self.paths.get(path, (404, None))
        if isinstance(hit, Exception):
            raise hit
        return _Resp(*hit)

    def get_node_status(self):
        return dict(self.nodes)

    def get_replication_status(self):
        return []

    def get_storage_list(self, node):
        return [{'storage': 'local', 'active': True, 'used': 10, 'total': 100}]

    def count(self, path):
        return self.calls.count(path)


def _stor(node, storage, plugintype, used=10, total=100):
    return {'id': f'storage/{node}/{storage}', 'type': 'storage', 'node': node, 'storage': storage,
            'status': 'available', 'plugintype': plugintype, 'disk': used, 'maxdisk': total}


PLAIN = [_stor('pve1', 'local-lvm', 'lvmthin'), _stor('pve2', 'local-lvm', 'lvmthin')]
HCI = PLAIN + [_stor('pve1', 'ceph-vm', 'rbd'), _stor('pve2', 'ceph-vm', 'rbd')]
NEAR_FULL = [_stor('pve1', 'local-lvm', 'lvmthin', used=92), _stor('pve1', 'ceph-vm', 'rbd')]


def _ceph(state, checks=(), osds=(6, 6)):
    return {'health': {'status': state, 'checks': {
                name: {'severity': sev, 'summary': {'message': msg}} for name, sev, msg in checks}},
            'osdmap': {'num_osds': osds[0], 'num_up_osds': osds[1], 'num_in_osds': osds[0]},
            'pgmap': {'num_pgs': 128}}


OK = _ceph('HEALTH_OK')
WARN = _ceph('HEALTH_WARN', [('OSD_NEARFULL', 'HEALTH_WARN', '1 nearfull osd(s)')])
# what the report showed: one host's OSDs down, PGs degraded, size 2
ERR = _ceph('HEALTH_ERR', [('OSD_DOWN', 'HEALTH_WARN', '3 osds down'),
                           ('OSD_HOST_DOWN', 'HEALTH_WARN', '1 host (3 osds) down'),
                           ('PG_DAMAGED', 'HEALTH_ERR', 'Possible data damage: 1 pg inconsistent')],
            osds=(6, 3))


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    monkeypatch.setattr(clusters_mod, '_health_storage_cache', StorageDataCache())
    monkeypatch.setattr(clusters_mod, '_health_ceph_reads', set())
    for name in ('_ceph', '_ceph_locks', '_status'):
        monkeypatch.setattr(alert_events, name, {})


class _Held(list):
    """The background reads the health check started, held until run() lets them go."""

    def run(self):
        while self:
            self.pop(0)()


@pytest.fixture
def held(monkeypatch):
    reads = _Held()
    monkeypatch.setattr(clusters_mod, '_health_ceph_spawn', reads.append)
    return reads


@pytest.fixture
def client(api, seed):
    return api.as_user(seed.user('root', role='admin', tenant_id='default'))


def _cluster(api, storage=HCI, ceph=None, **kw):
    return api.set_manager(CID, _Cluster(storage, (200, ceph) if isinstance(ceph, dict) else (ceph or (404, None)), **kw))


def _health(client):
    r = client.get(ROUTE)
    assert r.status_code == 200, r.get_data(as_text=True)
    body = r.get_json()
    body.pop('computed_at')
    return body


def _factor(body):
    return next((f for f in body['factors'] if f['key'] == 'ceph'), None)


def _warm(client, held):
    """The first poll starts the read, the next one scores it."""
    _health(client)
    assert len(held) == 1
    held.run()
    return _health(client)


# --- a cluster without Ceph ---------------------------------------------------------------------

@pytest.mark.parametrize('nodes,storage,score,band', [
    (None, PLAIN, 100, 'excellent'),
    ({'pve1': {'status': 'online'}, 'pve2': {'status': 'offline', 'offline': True}},
     [_stor('pve1', 'local-lvm', 'lvmthin', used=92)], 60, 'warning'),
])
def test_a_cluster_without_ceph_scores_and_is_read_as_before(api, client, held, nodes, storage, score, band):
    mgr = _cluster(api, storage=storage, nodes=nodes)
    for _ in range(3):
        body = _health(client)
        assert (body['score'], body['band']) == (score, band)
        assert [f['key'] for f in body['factors']] == ['nodes', 'storage']
    # the one storage read, cached; no Ceph status asked, no node probed, nothing started
    assert mgr.calls == [STORAGE]
    assert held == [] and alert_events._ceph == {}


def test_ceph_storage_of_an_outside_ceph_scores_as_before_and_is_asked_once(api, client, held):
    # an RBD storage on monitors outside the cluster: no node of it answers a Ceph status
    mgr = _cluster(api, storage=HCI, ceph=(500, None))
    first = _health(client)
    held.run()
    assert mgr.calls == [STORAGE, CEPH, '/nodes/pve1/ceph/status', '/nodes/pve2/ceph/status']
    for _ in range(3):
        body = _health(client)
        assert body == first and _factor(body) is None
        assert (body['score'], body['band']) == (100, 'excellent')
    # not before CEPH_RETRY: the cluster is not probed on every poll
    assert held == [] and mgr.count(CEPH) == 1


def test_an_xcpng_pool_is_not_asked_for_ceph(api, client, held):
    mgr = api.set_manager(CID, _Cluster(HCI, (200, ERR), cluster_type='xcpng'))
    alert_events._ceph[CID] = {'absent_until': 0, 'node': None, 'seen': True, 'last': (time.time(), ERR)}
    body = _health(client)
    assert _factor(body) is None and body['score'] == 100
    assert held == [] and mgr.count(CEPH) == 0


# --- what each state does to the score ----------------------------------------------------------

def test_health_ok_takes_nothing_off(api, client, held):
    _cluster(api, ceph=OK)
    body = _warm(client, held)
    assert (body['score'], body['band']) == (100, 'excellent')
    assert _factor(body) == {'key': 'ceph', 'label': 'Ceph', 'value': 'HEALTH_OK', 'delta': 0,
                             'severity': 'ok', 'status': 'HEALTH_OK', 'checks': [], 'cap': 100}
    assert body['issues'] == []


@pytest.mark.parametrize('storage,before,after,band', [
    (HCI, 100, 75, 'good'),          # held at 75: out of 'excellent'
    (NEAR_FULL, 85, 70, 'good'),     # 15 off what the storage left
])
def test_health_warn_lowers_the_score_and_keeps_it_out_of_excellent(api, client, held, storage, before, after, band):
    _cluster(api, storage=storage, ceph=WARN)
    cold = _health(client)
    assert cold['score'] == before and _factor(cold) is None
    held.run()
    body = _health(client)
    assert (body['score'], body['band']) == (after, band)
    f = _factor(body)
    assert (f['status'], f['severity'], f['value'], f['cap']) == ('HEALTH_WARN', 'warning', 'HEALTH_WARN: 1 check', 75)
    # the drill-down adds up: what the factors took off is what the score lost
    assert f['delta'] == after - before
    assert sum(x['delta'] for x in body['factors']) == body['score'] - 100
    assert 'Ceph reports HEALTH_WARN: OSD_NEARFULL' in body['issues']


def test_health_err_is_critical_on_an_otherwise_perfect_cluster(api, client, held):
    # the report: two nodes online, storage fine, Ceph in HEALTH_ERR - and the score said 92
    _cluster(api, ceph=ERR)
    body = _warm(client, held)
    assert (body['score'], body['band']) == (25, 'critical')
    assert _factor(body) == {
        'key': 'ceph', 'label': 'Ceph', 'value': 'HEALTH_ERR: 3 checks, 3/6 OSDs up', 'delta': -75,
        'severity': 'critical', 'status': 'HEALTH_ERR',
        'checks': ['PG_DAMAGED', 'OSD_DOWN', 'OSD_HOST_DOWN'], 'cap': 25}
    assert body['issues'] == ['Ceph reports HEALTH_ERR: PG_DAMAGED, OSD_DOWN, OSD_HOST_DOWN']


@pytest.mark.parametrize('offline', [0, 1, 2, 3])
@pytest.mark.parametrize('storage', [HCI, NEAR_FULL])
def test_whatever_else_the_cluster_shows_ceph_decides_the_grade(api, client, held, offline, storage):
    nodes = {f'pve{i}': ({'status': 'offline', 'offline': True} if i <= offline else {'status': 'online'})
             for i in range(1, 5)}
    mgr = _cluster(api, storage=storage, nodes=nodes, ceph=OK)
    before = _health(client)['score']        # the read not back yet: the score without Ceph
    held.run()
    for ceph, check in ((OK, lambda s, band: s == before),
                        (WARN, lambda s, band: band != 'excellent' and s <= max(0, min(75, before - 15))),
                        (ERR, lambda s, band: band == 'critical' and s <= max(0, min(25, before - 50)))):
        alert_events._ceph[CID]['last'] = (time.time(), ceph)
        body = _health(client)
        assert check(body['score'], body['band']), (ceph['health']['status'], before, body['score'], body['band'])
    assert mgr.count(CEPH) == 1 and held == []


def test_a_status_without_a_known_state_shows_and_takes_nothing_off(api, client, held):
    _cluster(api, ceph={'health': {}, 'osdmap': {}})
    body = _warm(client, held)
    assert body['score'] == 100
    assert _factor(body) == {'key': 'ceph', 'label': 'Ceph', 'value': 'unknown', 'delta': 0,
                             'severity': 'unknown', 'status': None, 'checks': [], 'cap': 100}


# --- the read: shared, in the background, never waited for -------------------------------------

def test_a_cold_cache_starts_one_read_and_scores_without_ceph_meanwhile(api, client, held):
    mgr = _cluster(api, ceph=ERR)
    for _ in range(3):        # three tabs, the read not back yet
        body = _health(client)
        assert _factor(body) is None and (body['score'], body['band']) == (100, 'excellent')
    # nothing was asked inside a poll, and one read waits for all of them
    assert mgr.count(CEPH) == 0 and len(held) == 1
    held.run()
    assert mgr.count(CEPH) == 1 and clusters_mod._health_ceph_reads == set()
    assert _health(client)['band'] == 'critical'


def test_the_read_is_shared_with_the_alert_and_the_ceph_overview(api, client, held):
    mgr = _cluster(api, ceph=ERR)
    _warm(client, held)
    for _ in range(3):
        assert _health(client)['score'] == 25
    # the alert tick within CEPH_FRESH takes the same read
    assert alert_events._read_ceph(CID, mgr, time.time())['health']['status'] == 'HEALTH_ERR'
    assert mgr.count(CEPH) == 1 and held == []


def test_a_read_the_alert_made_scores_a_cluster_without_ceph_storage(api, client, held):
    # Ceph without an RBD or CephFS storage on it: the alert tick found it, the poll takes that
    mgr = _cluster(api, storage=PLAIN, ceph=WARN)
    assert alert_events.ceph_status(CID, mgr, max_age=alert_events.CEPH_FRESH)[0] == 'ok'
    body = _health(client)
    assert body['score'] == 75 and _factor(body)['status'] == 'HEALTH_WARN'
    assert mgr.count(CEPH) == 1 and held == []


def test_an_old_read_still_counts_while_a_new_one_runs(api, client, held):
    mgr = _cluster(api, ceph=ERR)
    _warm(client, held)
    st = alert_events._ceph[CID]
    st['last'] = (time.time() - alert_events.CEPH_FRESH - 5, st['last'][1])
    body = _health(client)
    assert body['band'] == 'critical' and len(held) == 1
    mgr.paths[CEPH] = (200, OK)
    held.run()
    assert mgr.count(CEPH) == 2
    assert _health(client)['score'] == 100 and _factor(_health(client))['status'] == 'HEALTH_OK'


def test_ceph_that_stopped_answering_holds_the_score_at_good(api, client, held):
    # monitors that lost quorum fail the status call itself: once the last good read is older
    # than the server serves it and the reads since have failed, the silence is a warning
    mgr = _cluster(api, ceph=ERR)
    _warm(client, held)
    mgr.paths[CEPH] = (500, None)
    st = alert_events._ceph[CID]
    st['last'] = (time.time() - clusters_mod._HEALTH_CEPH_SERVE_MAX - 1, st['last'][1])
    body = _health(client)
    held.run()
    body = _health(client)
    assert (body['score'], body['band']) == (75, 'good')
    f = _factor(body)
    assert (f['value'], f['delta'], f['severity'], f['status'], f['cap']) == ('not answering', -25, 'warning', None, 75)
    assert f['silent'] is True and 'Ceph status unreadable for more than 5 minutes' in body['issues']
    # it had Ceph, so it is asked again on the next poll rather than after CEPH_RETRY
    assert mgr.count(CEPH) == 2 and len(held) == 1
    # and it scores what it says as soon as it answers again
    mgr.paths[CEPH] = (200, OK)
    held.run()
    body = _health(client)
    assert body['score'] == 100 and _factor(body)['status'] == 'HEALTH_OK' and 'silent' not in _factor(body)


def test_an_old_read_that_worked_is_not_taken_for_silence(api, client, held):
    # nobody looked for an hour and the last read worked: the first poll has nothing recent to
    # score, which is unknown, not a Ceph that stopped answering
    mgr = _cluster(api, ceph=ERR)
    _warm(client, held)
    st = alert_events._ceph[CID]
    st['last'] = (time.time() - 3600, st['last'][1])
    body = _health(client)
    assert _factor(body)['severity'] == 'unknown' and body['score'] == 100
    held.run()
    assert _health(client)['band'] == 'critical' and mgr.count(CEPH) == 2


def test_a_malformed_ceph_status_drops_the_factor_not_the_route(api, client, held):
    _cluster(api, ceph=dict(ERR, quorum_names=5, pgmap={'pgs_by_state': 7}))
    _health(client)
    held.run()
    body = _health(client)
    assert _factor(body) is None and (body['score'], body['band']) == (100, 'excellent')


@pytest.mark.parametrize('who', ['pool', 'guest'])
def test_a_confined_caller_gets_nothing_of_the_ceph(api, seed, client, held, who):
    # Ceph is the cluster's storage: a pool or a guest grant does not cover it, and the Ceph
    # overview answers 'confined' to the same callers
    _cluster(api, ceph=ERR)
    assert _warm(client, held)['band'] == 'critical'    # there is a status to give away
    if who == 'pool':
        from test_audit_bola_high_2026_09 import _seed_pool_membership
        seed.tenant('t_confined', [])
        seed.pool(CID, 'pool1', 'pooled', ['vm.view'])
        _seed_pool_membership(CID, {102: ('lxc', 'pool1')})
        caller = api.as_user(seed.user('pooled', role='user', tenant_id='t_confined'))
    else:
        seed.tenant('acme', [CID])
        seed.vm_acl(CID, 103, users=['portal'])
        caller = api.as_user(seed.user('portal', role='user', tenant_id='acme'))
    r = caller.get(ROUTE)
    assert r.status_code == 200, r.get_data(as_text=True)
    body = r.get_json()
    assert _factor(body) is None and not any('Ceph' in i for i in body['issues'])
    for word in ('HEALTH_ERR', 'PG_DAMAGED', 'OSD'):
        assert word not in r.get_data(as_text=True)
    # nor does their poll start a read
    st = alert_events._ceph[CID]
    st['last'] = (time.time() - alert_events.CEPH_FRESH - 5, st['last'][1])
    assert caller.get(ROUTE).status_code == 200 and held == []


def test_a_read_that_fails_to_run_is_tried_again(api, client, held, monkeypatch):
    _cluster(api, ceph=ERR)

    def boom(*a, **kw):
        raise RuntimeError('lost the connection')
    monkeypatch.setattr(alert_events, 'ceph_status', boom)
    _health(client)
    held.run()
    assert clusters_mod._health_ceph_reads == set()
    _health(client)
    assert len(held) == 1


def test_a_spawn_that_fails_leaves_no_read_marked_running(api, client, monkeypatch):
    _cluster(api, ceph=ERR)

    def refuse(fn):
        raise RuntimeError("can't start new thread")
    monkeypatch.setattr(clusters_mod, '_health_ceph_spawn', refuse)
    assert _health(client)['score'] == 100
    assert clusters_mod._health_ceph_reads == set()


def test_the_background_read_runs_in_a_thread_of_its_own(api, client):
    # a Ceph status that takes its time (monitors out of quorum): the poll does not wait for it
    mgr = _cluster(api, ceph=ERR)
    mgr.slow = {CEPH: 1.5}
    started = time.monotonic()
    assert _factor(_health(client)) is None
    assert time.monotonic() - started < 1.0
    deadline = time.time() + 5
    while time.time() < deadline and alert_events.ceph_reading(CID) is None:
        time.sleep(0.05)
    assert alert_events.ceph_reading(CID) is not None
    assert _health(client)['band'] == 'critical' and mgr.count(CEPH) == 1
