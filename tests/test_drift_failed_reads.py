"""A read that failed must not turn into removals.

get_vm_resources() answered [] for a timeout of cluster/resources as well as for a
cluster without guests, and at 10k guests that read can outlast its 10s timeout. The
drift scan took the empty list at its word and reported every guest baseline removed,
with an alert. The storage, cluster options and per-node network reads had the same
shape: an error status read like an empty answer.

The guest list goes through the real PegaProxManager.get_vm_resources against a fake
session, so the test sees what the manager really hands back. Everything else is a
fake PVE in the style of test_drift_offline_node_runtime.py; events and baselines land
in the throwaway test database.
"""
import json
import logging
import re

import pytest
import requests

import pegaprox.globals as ppglobals
from pegaprox.api import drift
from pegaprox.core.manager import PegaProxManager

CL = 'c_reads'


class _Resp:
    def __init__(self, status, data):
        self.status_code = status
        self._data = data

    def json(self):
        return {'data': self._data}


class _Session:
    def __init__(self, pve):
        self.pve = pve

    def get(self, url, params=None, timeout=None):
        assert url.endswith('/cluster/resources') and params == {'type': 'vm'}, url
        fail = self.pve.fail.get('guests')
        if fail == 'timeout':
            raise requests.exceptions.Timeout('read timed out (10k guests)')
        if fail:
            return _Resp(fail, None)
        return _Resp(200, [dict(g, status='running') for g in self.pve.guests])


class _Pve:
    host, api_port = 'pve.test', 8006
    cluster_type = 'proxmox'
    # the manager's own guest list read, failure handling included
    get_vm_resources = PegaProxManager.get_vm_resources

    def __init__(self):
        self.is_connected = True
        self.session = object()
        self._ip_cache, self._disk_cache = {}, {}
        self._consecutive_failures = 0
        # read -> status to answer instead ('timeout' raises): 'guests', 'storage',
        # 'options', 'net:<node>', 'cfg:<type>/<vmid>'
        self.fail = {}
        self.down = set()
        self.guests = [{'vmid': 101, 'node': 'n1', 'type': 'qemu'},
                       {'vmid': 102, 'node': 'n1', 'type': 'qemu'},
                       {'vmid': 150, 'node': 'n2', 'type': 'lxc'}]
        self.cfg = {('qemu', 101): {'cores': 2, 'memory': 2048},
                    ('qemu', 102): {'cores': 4, 'memory': 4096},
                    ('lxc', 150): {'cores': 1, 'memory': 512, 'hostname': 'ct150'}}
        self.nics = {'n1': {'vmbr0': {}}, 'n2': {'vmbr0': {}, 'eno1': {}}}
        self.storages = [{'storage': 'local', 'type': 'dir'}, {'storage': 'nfs1', 'type': 'nfs'}]

    def _create_session(self):
        return _Session(self)

    @property
    def nodes(self):
        return {n: {'node': n, 'status': 'offline' if n in self.down else 'online'}
                for n in ('n1', 'n2')}

    def get_node_status(self):
        return {n: {'status': d['status']} for n, d in self.nodes.items()}

    def _answer(self, key, data):
        fail = self.fail.get(key)
        if fail == 'timeout':
            raise requests.exceptions.Timeout(key)
        return _Resp(fail, None) if fail else _Resp(200, data)

    def _api_get(self, url, **kw):
        if url.endswith('/cluster/options'):
            return self._answer('options', {'keyboard': 'en-us'})
        if url.endswith('/api2/json/storage'):
            return self._answer('storage', [dict(s) for s in self.storages])
        m = re.search(r'/nodes/([^/]+)/network$', url)
        if m:
            if m.group(1) in self.down:
                return _Resp(595, None)
            return self._answer(f'net:{m.group(1)}', [dict({'iface': i, 'type': 'bridge'}, **x)
                                                      for i, x in self.nics[m.group(1)].items()])
        m = re.search(r'/nodes/([^/]+)/(qemu|lxc)/(\d+)/config$', url)
        if m:
            if m.group(1) in self.down:
                return _Resp(595, None)
            key = (m.group(2), int(m.group(3)))
            if key not in self.cfg:
                return _Resp(500, None)
            return self._answer(f'cfg:{key[0]}/{key[1]}', dict(self.cfg[key]))
        return _Resp(404, None)


GUESTS = {'qemu/101', 'qemu/102', 'lxc/150'}


@pytest.fixture
def pve(db, monkeypatch):
    from pegaprox.background import alerts, guest_index
    sent = []
    monkeypatch.setattr('pegaprox.utils.webhooks.send_to_channels',
                        lambda payload, **kw: sent.append(payload))
    monkeypatch.setattr(alerts, '_notification_handlers', [])
    p = _Pve()
    p.sent = sent
    ppglobals.cluster_managers[CL] = p
    # options, two storages, three NICs, three guests
    assert drift._scan_cluster(CL, autobaseline=True)['seeded_baselines'] == 9
    yield p
    ppglobals.cluster_managers.pop(CL, None)
    guest_index.clear()


def _rows(db, status=None):
    q = 'SELECT kind, scope, severity, status, diff FROM drift_events WHERE cluster_id=?'
    args = [CL]
    if status:
        q += ' AND status=?'
        args.append(status)
    out = []
    for r in db.conn.execute(q + ' ORDER BY id', args).fetchall():
        d = dict(r)
        d['op'] = json.loads(d['diff'])[0]['op']
        out.append(d)
    return out


def _removed(db):
    return {(r['kind'], r['scope']) for r in _rows(db) if r['op'] == 'removed'}


# -- the manager tells a failed read from an empty answer ---------------------------------

@pytest.mark.parametrize('fail', ['timeout', 500, 'disconnected'])
def test_a_guest_list_that_did_not_answer_says_so(fail):
    p = _Pve()
    if fail == 'disconnected':
        p.is_connected = False
    else:
        p.fail['guests'] = fail
    got = p.get_vm_resources()
    assert got == [] and isinstance(got, list), 'every other caller still gets an empty list'
    assert getattr(got, 'unavailable', False) is True


def test_a_cluster_without_guests_is_an_answer():
    p = _Pve()
    p.guests = []
    got = p.get_vm_resources()
    assert got == [] and not getattr(got, 'unavailable', False)


# -- the guest list --------------------------------------------------------------------

@pytest.mark.parametrize('fail', ['timeout', 500])
def test_a_guest_list_that_fails_reports_no_guest_removed(pve, db, fail):
    pve.fail['guests'] = fail
    pve.storages[1]['type'] = 'cifs'   # the reads that answered are still compared
    res = drift._scan_cluster(CL)

    assert res.get('ok') is True, res
    assert res['removed'] == []
    assert _removed(db) == set()
    assert res['unread'] == ['vm_config']
    assert res['suppressed_unread'] == len(GUESTS)
    assert [(e['kind'], e['scope']) for e in res['events']] == [('storage', 'nfs1')]
    # the guest baselines are untouched, so the next good scan compares against them
    assert {s for k, s in drift._load_baselines(CL) if k == 'vm_config'} == GUESTS
    # one alert, for the storage change only
    assert len(pve.sent) == 1 and pve.sent[0]['message'].startswith('1 config drift')


def test_the_scan_says_what_it_did_not_read(pve, db, caplog):
    pve.fail['guests'] = 'timeout'
    with caplog.at_level(logging.WARNING):
        drift._scan_cluster(CL)
    said = [r.getMessage() for r in caplog.records if CL in r.getMessage()]
    assert any('not read' in m and 'vm_config' in m for m in said), said


def test_guests_really_gone_are_still_removed(pve, db):
    """A cluster whose guests were all deleted answers an empty list: that is news."""
    pve.guests = []
    res = drift._scan_cluster(CL)
    assert set(res['removed']) == GUESTS
    assert _removed(db) == {('vm_config', g) for g in GUESTS}
    assert not res.get('unread') and not res.get('suppressed_unread')


def test_the_guest_list_failing_again_does_not_read_it_a_second_time(pve, db):
    """The node lookup for missing guests reads the guest list too; after it just
    failed (10s gone already) that second read is not made."""
    pve.fail['guests'] = 'timeout'
    calls = []
    real = pve.get_vm_resources
    pve.get_vm_resources = lambda *a, **kw: calls.append(kw) or real(*a, **kw)
    drift._scan_cluster(CL)
    assert len(calls) == 1, calls


def test_an_outage_row_stays_open_while_the_guest_list_cannot_be_read(pve, db):
    """The node is still down: a scan that could not read the guest list has nothing
    to say about the container on it, neither removed nor back."""
    pve.down.add('n2')
    drift._scan_cluster(CL)
    unknown = [(r['kind'], r['scope']) for r in _rows(db, 'open') if r['op'] == 'unknown']
    assert ('vm_config', 'lxc/150') in unknown

    pve.fail['guests'] = 'timeout'
    res = drift._scan_cluster(CL)
    assert res['removed'] == []
    still = [(r['kind'], r['scope']) for r in _rows(db, 'open') if r['op'] == 'unknown']
    assert ('vm_config', 'lxc/150') in still
    assert _removed(db) == set()


# -- the other reads --------------------------------------------------------------------

@pytest.mark.parametrize('read,kind,scopes', [
    ('storage', 'storage', {'local', 'nfs1'}),
    ('options', 'cluster_options', {'global'}),
])
@pytest.mark.parametrize('fail', ['timeout', 500])
def test_a_cluster_wide_read_that_fails_reports_nothing_removed(pve, db, read, kind, scopes, fail):
    pve.fail[read] = fail
    res = drift._scan_cluster(CL)
    assert res['removed'] == [], res
    assert _removed(db) == set()
    assert res['unread'] == [kind]
    assert {s for k, s in drift._load_baselines(CL) if k == kind} == scopes


def test_a_storage_really_gone_is_still_removed(pve, db):
    pve.storages = pve.storages[:1]
    res = drift._scan_cluster(CL)
    assert res['removed'] == ['nfs1']


@pytest.mark.parametrize('fail', ['timeout', 500])
def test_a_network_read_failing_on_an_online_node_reports_no_nic_removed(pve, db, fail):
    pve.fail['net:n2'] = fail
    res = drift._scan_cluster(CL)
    assert res['removed'] == []
    assert _removed(db) == set()
    # not an outage either: the node answers, only this read did not
    assert res['suppressed_offline'] == 0 and _rows(db) == []
    assert res['unread'] == ['network'] and res['suppressed_unread'] == 2


def test_no_node_list_reports_no_nic_removed(pve, db, monkeypatch):
    monkeypatch.setattr(_Pve, 'nodes', property(lambda self: {}))
    res = drift._scan_cluster(CL)
    assert res['removed'] == []
    assert 'network' in res['unread']


@pytest.mark.parametrize('fail', ['timeout', 500])
def test_one_guest_config_that_fails_is_not_removed(pve, db, fail):
    pve.fail['cfg:qemu/102'] = fail
    pve.cfg[('qemu', 101)]['memory'] = 8192
    res = drift._scan_cluster(CL)
    assert res['removed'] == []
    assert [e['scope'] for e in res['events']] == ['qemu/101']
    assert res['unread'] == ['vm_config'] and res['suppressed_unread'] == 1


def test_an_offline_node_still_reads_as_an_outage(pve, db):
    """Its reads fail too; the outage row of #968 comes first."""
    pve.down.add('n2')
    res = drift._scan_cluster(CL)
    assert res['suppressed_offline'] == 3 and not res.get('suppressed_unread')
    assert {r['op'] for r in _rows(db)} == {'unknown'}


# -- reset baseline ---------------------------------------------------------------------

def test_a_baseline_reset_keeps_what_it_could_not_read(api, seed, pve, db):
    pve.fail['guests'] = 'timeout'
    pve.cfg[('qemu', 101)]['memory'] = 8192   # never read, so never the new baseline
    admin = api.as_user(seed.user('drift_admin', role='admin'))
    r = admin.post(f'/api/clusters/{CL}/drift/baseline')
    assert r.status_code == 200, r.get_data(as_text=True)[:300]

    base = drift._load_baselines(CL)
    assert {s for k, s in base if k == 'vm_config'} == GUESTS
    assert base[('vm_config', 'qemu/101')]['snapshot']['memory'] == 2048
    assert {s for k, s in base if k == 'storage'} == {'local', 'nfs1'}
    body = r.get_json()
    assert body['kept_unread'] == len(GUESTS) and body['unread'] == ['vm_config']

    # once the list answers again the change made meanwhile is reported
    pve.fail.clear()
    res = drift._scan_cluster(CL)
    assert [e['summary'] for e in res['events']] == ['vm_config qemu/101: memory']


def test_a_baseline_reset_with_everything_read_starts_over(api, seed, pve, db):
    pve.guests = pve.guests[:1]
    admin = api.as_user(seed.user('drift_admin', role='admin'))
    r = admin.post(f'/api/clusters/{CL}/drift/baseline')
    assert r.status_code == 200
    assert not r.get_json().get('kept_unread')
    assert {s for k, s in drift._load_baselines(CL) if k == 'vm_config'} == {'qemu/101'}
