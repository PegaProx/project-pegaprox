"""The EVPN prerequisite check probes at most 8 nodes of a cluster at once and ends by
one deadline.

It used to go cluster by cluster and put a probe per online node into the shared request
pool in one go, while SSH fan-outs go through run_per_node, 8 per cluster. Each probe
looked the node address up inside its SSH budget and again after it, a probe that raised
came back as a timeout, and with the clusters one after another the request grew with
every member. Now the clusters run side by side, each with 8 probes at a time, every
probe has its own time limit and the request one deadline. The address is looked up once,
before the SSH read, and the read takes it from the cache. A node in circuit-breaker
backoff gets neither and says so.
MK Nov 2026
"""
import time
import types

import pytest

import pegaprox.utils.ssh as sshmod
from pegaprox.api import multi_sdn as msdn

GOOD_OUTPUT = '\n'.join(['pve=pve-manager/8.4-1', 'frr_pkg=1', 'frr_py=1', 'frr_srv=active',
                         'ifup2=1', 'src_d=1', 'fwd=1', 'ntp=yes'])
URL = '/api/multi-sdn/prerequisites'


@pytest.fixture(autouse=True)
def _own_address_cache(monkeypatch):
    monkeypatch.setattr(sshmod, '_node_ip_cache', {})


def _cluster(api, cid, count, node_ip='10.0.0.5'):
    m = api.make_fake_manager(cid, _get_node_ip=node_ip)
    m.id = cid
    m.nodes = {f'pve{i}': {'status': 'online'} for i in range(1, count + 1)}
    m.config = types.SimpleNamespace(name=cid)
    m.is_connected = True
    return api.set_manager(cid, m)


@pytest.fixture
def admin(api, seed):
    return api.as_user(seed.user('evpnadm', role='admin'))


class _Probes:
    """A stand-in for the SSH read that counts how many run at once."""

    def __init__(self, seconds=0.0, slow=None):
        self.seconds, self.slow = seconds, slow or {}
        self.active, self.peak, self.calls = 0, 0, []
        self.clusters, self.cluster_peak = {}, 0

    def __call__(self, mgr, node, cmd, timeout=20):
        cid = mgr.cluster_id
        self.calls.append((cid, node))
        self.active += 1
        self.peak = max(self.peak, self.active)
        self.clusters[cid] = self.clusters.get(cid, 0) + 1
        self.cluster_peak = max(self.cluster_peak, sum(1 for v in self.clusters.values() if v))
        try:
            time.sleep(self.slow.get(node, self.seconds))
        finally:
            self.active -= 1
            self.clusters[cid] -= 1
        return 0, GOOD_OUTPUT, ''


def _checks(r):
    assert r.status_code == 200, r.get_data(as_text=True)[:300]
    return {(c['cluster_id'], c['node']): c for c in r.get_json()['checks']}


def test_200_nodes_finish_within_the_deadline_8_at_a_time(api, admin, monkeypatch):
    monkeypatch.setattr(msdn, '_PREREQ_DEADLINE', 30, raising=False)
    _cluster(api, 'big', 200)
    probes = _Probes(seconds=0.01)
    monkeypatch.setattr(sshmod, '_pve_node_exec', probes)

    started = time.monotonic()
    checks = _checks(admin.post(URL, json={'cluster_ids': ['big']}))
    assert time.monotonic() - started < 30
    assert len(checks) == 200 and len(probes.calls) == 200
    assert all(i['status'] == 'ok' for c in checks.values() for i in c['items'])
    assert probes.peak == 8


def test_the_clusters_are_probed_side_by_side(api, admin, monkeypatch):
    for cid in ('east', 'west', 'north'):
        _cluster(api, cid, 4)
    probes = _Probes(seconds=0.2)
    monkeypatch.setattr(sshmod, '_pve_node_exec', probes)

    checks = _checks(admin.post(URL, json={'cluster_ids': ['east', 'west', 'north']}))
    assert len(checks) == 12
    assert probes.cluster_peak == 3
    # the answer keeps the caller's order
    assert [c for c, _n in checks][::4] == ['east', 'west', 'north']


def test_one_deadline_ends_the_request_for_every_cluster(api, admin, monkeypatch):
    monkeypatch.setattr(msdn, '_PREREQ_DEADLINE', 0.5, raising=False)
    for cid in ('a', 'b', 'c'):
        _cluster(api, cid, 2)
    probes = _Probes(seconds=0.01, slow={'pve2': 3})
    monkeypatch.setattr(sshmod, '_pve_node_exec', probes)

    started = time.monotonic()
    checks = _checks(admin.post(URL, json={'cluster_ids': ['a', 'b', 'c']}))
    assert time.monotonic() - started < 2.5
    for cid in ('a', 'b', 'c'):
        assert checks[(cid, 'pve1')]['items'][0]['status'] == 'ok'
        assert all(i['status'] == 'unknown' and i['detail'] == 'timeout'
                   for i in checks[(cid, 'pve2')]['items'])


def test_a_hanging_node_gives_its_slot_back(api, admin, monkeypatch):
    monkeypatch.setattr(msdn, '_PREREQ_NODE_TIMEOUT', 0.3, raising=False)
    _cluster(api, 'hang', 16)
    probes = _Probes(seconds=0.02, slow={'pve3': 5})
    monkeypatch.setattr(sshmod, '_pve_node_exec', probes)

    started = time.monotonic()
    checks = _checks(admin.post(URL, json={'cluster_ids': ['hang']}))
    assert time.monotonic() - started < 3
    assert all(i['detail'] == 'timeout' for i in checks[('hang', 'pve3')]['items'])
    assert all(checks[('hang', f'pve{n}')]['items'][0]['status'] == 'ok' for n in range(1, 17) if n != 3)


def test_a_probe_that_raises_is_an_error_not_a_timeout(api, admin, monkeypatch):
    _cluster(api, 'err', 2)
    monkeypatch.setattr(sshmod, '_pve_node_exec', _Probes())
    real = msdn._check_node_prereqs

    def _check(mgr, node):
        if node == 'pve1':
            raise RuntimeError('unexpected output layout')
        return real(mgr, node)
    monkeypatch.setattr(msdn, '_check_node_prereqs', _check)

    checks = _checks(admin.post(URL, json={'cluster_ids': ['err']}))
    broken = checks[('err', 'pve1')]['items']
    assert all(i['status'] == 'unknown' for i in broken)
    assert broken[0]['detail'].startswith('error') and 'unexpected output layout' in broken[0]['detail']
    assert checks[('err', 'pve2')]['items'][0]['status'] == 'ok'


def test_a_failing_cluster_is_an_error_too(api, admin, monkeypatch):
    m = _cluster(api, 'odd', 1)

    def _unreadable(self):
        raise RuntimeError('node list unreadable')
    type(m).nodes = property(_unreadable)   # a MagicMock has a class of its own
    r = admin.post(URL, json={'cluster_ids': ['odd']})
    assert r.status_code == 200, r.get_data(as_text=True)[:300]
    err = r.get_json()['errors']
    assert len(err) == 1 and err[0]['cluster_id'] == 'odd'
    assert err[0]['reason'].startswith('error') and 'node list unreadable' in err[0]['reason']


def test_the_address_is_looked_up_once_before_the_ssh_read(api, admin, monkeypatch):
    m = _cluster(api, 'addr', 3)
    events = []

    def _ip(node):
        events.append(('lookup', node))
        return '10.0.0.5'
    m._get_node_ip.side_effect = _ip

    def _exec(mgr, node, cmd, timeout=20):
        # the read finds it in its own cache and does not look it up again
        assert sshmod._node_ip_cache[(mgr.id, node)][0] == '10.0.0.5'
        events.append(('ssh', node))
        return 0, GOOD_OUTPUT, ''
    monkeypatch.setattr(sshmod, '_pve_node_exec', _exec)

    r = admin.post(URL, json={'cluster_ids': ['addr']})
    checks = _checks(r)
    for n in ('pve1', 'pve2', 'pve3'):
        assert [e for e in events if e[1] == n] == [('lookup', n), ('ssh', n)]
        assert checks[('addr', n)]['items'][0]['status'] == 'ok'
    assert r.get_json()['node_ips'] == {'addr:pve1': '10.0.0.5', 'addr:pve2': '10.0.0.5',
                                        'addr:pve3': '10.0.0.5'}


def test_a_fresh_cached_address_needs_no_lookup(api, admin, monkeypatch):
    m = _cluster(api, 'warm', 1)
    sshmod._node_ip_cache[('warm', 'pve1')] = ('10.9.9.9', time.time())
    monkeypatch.setattr(sshmod, '_pve_node_exec', _Probes())

    checks = _checks(admin.post(URL, json={'cluster_ids': ['warm']}))
    assert not m._get_node_ip.called
    assert checks[('warm', 'pve1')]['mgmt_ip'] == '10.9.9.9'


def test_a_node_without_an_address_gets_no_ssh_read(api, admin, monkeypatch):
    _cluster(api, 'noip', 1, node_ip=None)
    probes = _Probes()
    monkeypatch.setattr(sshmod, '_pve_node_exec', probes)

    checks = _checks(admin.post(URL, json={'cluster_ids': ['noip']}))
    assert probes.calls == []
    items = checks[('noip', 'pve1')]['items']
    assert all(i['status'] == 'unknown' and 'cannot resolve' in i['detail'] for i in items)


def test_a_node_in_backoff_says_so_and_gets_no_lookup(api, admin, monkeypatch):
    m = _cluster(api, 'cold', 2)
    m._is_node_blocked.side_effect = lambda node: (True, 42) if node == 'pve1' else (False, 0)
    # like the real one, the lookup answers nothing for a node in backoff
    m._get_node_ip.side_effect = lambda node: None if node == 'pve1' else '10.0.0.5'
    probes = _Probes()
    monkeypatch.setattr(sshmod, '_pve_node_exec', probes)

    checks = _checks(admin.post(URL, json={'cluster_ids': ['cold']}))
    items = checks[('cold', 'pve1')]['items']
    assert all(i['status'] == 'unknown' for i in items)
    assert items[0]['detail'] == "node 'pve1' in circuit-breaker backoff (42s remaining)"
    assert [c[1] for c in probes.calls] == ['pve2']
    assert [c.args[0] for c in m._get_node_ip.call_args_list] == ['pve2']
    assert checks[('cold', 'pve2')]['items'][0]['status'] == 'ok'
