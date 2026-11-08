"""A node that is down must not have its guests and NICs reported as removed (#968).

Driven through the real _fetch_state against a fake PVE that behaves like one with a
node down: /nodes still lists it as offline, its network and guest config reads answer
595, and cluster/resources keeps listing its guests with status unknown. A guest config
has no node key, so the baseline alone cannot say where a guest lived. Events and
baselines land in the throwaway test database.
"""
import json
import re

import pytest

import pegaprox.globals as ppglobals
from pegaprox.api import drift

CL = 'c_off'


class _Resp:
    def __init__(self, status, data):
        self.status_code = status
        self._data = data

    def json(self):
        return {'data': self._data}


class _Pve:
    host, api_port = 'pve.test', 8006
    cluster_type = 'proxmox'

    def __init__(self):
        self.is_connected = True
        self.down = set()
        self.api_down = False
        self.status_reads = 0
        self.guests = [{'vmid': 101, 'node': 'n1', 'type': 'qemu'},
                       {'vmid': 150, 'node': 'n2', 'type': 'lxc'}]
        self.cfg = {('qemu', 101): {'cores': 2, 'memory': 2048},
                    ('lxc', 150): {'cores': 1, 'memory': 512, 'hostname': 'ct150'}}
        self.nics = {'n1': {'vmbr0': {}}, 'n2': {'vmbr0': {}, 'eno1': {}}}

    @property
    def nodes(self):
        return {n: {'node': n, 'status': 'offline' if n in self.down else 'online'}
                for n in ('n1', 'n2')}

    def get_node_status(self):
        self.status_reads += 1
        if self.api_down:
            return {}
        return {n: {'status': d['status']} for n, d in self.nodes.items()}

    def get_vm_resources(self, max_age=0.0):
        if self.api_down:
            return []
        return [dict(g, status='unknown' if g['node'] in self.down else 'running')
                for g in self.guests]

    def _api_get(self, url, **kw):
        if self.api_down:
            raise ConnectionError('no route to host')
        if url.endswith('/cluster/options'):
            return _Resp(200, {'keyboard': 'en-us'})
        if url.endswith('/api2/json/storage'):
            return _Resp(200, [{'storage': 'local', 'type': 'dir'}])
        m = re.search(r'/nodes/([^/]+)/network$', url)
        if m:
            if m.group(1) in self.down:
                return _Resp(595, None)
            return _Resp(200, [dict({'iface': i, 'type': 'bridge'}, **extra)
                               for i, extra in self.nics[m.group(1)].items()])
        m = re.search(r'/nodes/([^/]+)/(qemu|lxc)/(\d+)/config$', url)
        if m:
            if m.group(1) in self.down:
                return _Resp(595, None)
            return _Resp(200, dict(self.cfg[(m.group(2), int(m.group(3)))]))
        return _Resp(404, None)


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
    drift._scan_cluster(CL, autobaseline=True)
    assert len(drift._load_baselines(CL)) == 7
    yield p
    ppglobals.cluster_managers.pop(CL, None)
    guest_index.clear()


def _rows(db, status=None):
    q = 'SELECT id, kind, scope, severity, status, diff FROM drift_events WHERE cluster_id=?'
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


def test_a_guest_and_nics_on_an_offline_node_are_not_reported_removed(pve, db):
    pve.down.add('n2')
    res = drift._scan_cluster(CL)

    assert res['removed'] == []
    assert res['suppressed_offline'] == 3
    rows = _rows(db)
    assert {(r['kind'], r['scope']) for r in rows} == {
        ('vm_config', 'lxc/150'), ('network', 'n2/vmbr0'), ('network', 'n2/eno1')}
    assert {r['op'] for r in rows} == {'unknown'}
    assert {r['severity'] for r in rows} == {'info'}
    # the stored row and the scan's answer name the same kind
    assert {(e['kind'], e['node_offline']) for e in res['events']} == {
        ('vm_config', 'n2'), ('network', 'n2')}


def test_a_guest_gone_from_the_guest_list_is_removed_even_with_its_node_down(pve, db):
    """Not listed in cluster/resources means pmxcfs has no config for it: really gone."""
    pve.down.add('n2')
    pve.guests = [g for g in pve.guests if g['vmid'] != 150]
    res = drift._scan_cluster(CL)
    assert res['removed'] == ['lxc/150']
    assert [r['op'] for r in _rows(db) if r['scope'] == 'lxc/150'] == ['removed']


def test_a_guest_deleted_on_an_online_node_is_still_removed(pve, db):
    pve.guests = [g for g in pve.guests if g['vmid'] != 101]
    res = drift._scan_cluster(CL)
    assert res['removed'] == ['qemu/101']
    assert res['suppressed_offline'] == 0


def test_an_outage_is_said_once_and_cleared_when_the_node_is_back(pve, db):
    pve.down.add('n2')
    drift._scan_cluster(CL)
    second = drift._scan_cluster(CL)
    assert second['events_count'] == 0 and second['suppressed_offline'] == 3
    assert len(_rows(db, 'open')) == 3

    pve.down.clear()
    back = drift._scan_cluster(CL)
    assert back['events_count'] == 0
    assert _rows(db, 'open') == []
    assert {r['status'] for r in _rows(db)} == {'superseded'}


def test_a_scope_really_gone_is_removed_once_the_node_is_back(pve, db):
    pve.down.add('n2')
    drift._scan_cluster(CL)
    pve.down.clear()
    del pve.nics['n2']['eno1']   # went away while the node was down
    res = drift._scan_cluster(CL)
    assert res['removed'] == ['n2/eno1']
    assert [(r['scope'], r['op']) for r in _rows(db, 'open')] == [('n2/eno1', 'removed')]


def test_an_api_that_does_not_answer_reports_nothing_removed(pve, db):
    pve.api_down = True
    res = drift._scan_cluster(CL)
    assert res.get('status') == 'skipped', res
    assert _rows(db) == []
    assert pve.sent == []


def _only_nics_on_n2(pve):
    """Migrate the container off n2 first, so an n2 outage only hides its NICs."""
    pve.guests[1]['node'] = 'n1'
    assert drift._scan_cluster(CL)['events_count'] == 0


def test_presence_unknown_alone_sends_no_notification(pve, db):
    _only_nics_on_n2(pve)
    pve.down.add('n2')
    res = drift._scan_cluster(CL)
    assert res['events_count'] == 2 and res['removed'] == []
    assert pve.sent == []


def test_a_real_change_next_to_an_outage_still_notifies_for_itself(pve, db):
    _only_nics_on_n2(pve)
    pve.down.add('n2')
    pve.cfg[('qemu', 101)]['memory'] = 4096
    res = drift._scan_cluster(CL)
    assert res['events_count'] == 3 and res['removed'] == []
    assert len(pve.sent) == 1
    assert pve.sent[0]['message'].startswith('1 config drift')
    assert pve.sent[0]['severity'] == 'warning'


def test_a_clean_scan_does_not_read_node_status(pve, db):
    before = pve.status_reads
    res = drift._scan_cluster(CL)
    assert res['events_count'] == 0
    assert pve.status_reads == before


# -- acknowledge with promote, through the route --

def _admin(api, seed):
    return api.as_user(seed.user('drift_admin', role='admin'))


def test_promote_of_a_presence_unknown_row_keeps_the_baseline(api, seed, pve, db):
    """The row keeps its real kind in the database, so the guard has to read the diff.
    Promoting it after the node is back must not take the live config as the new
    baseline, or the change made meanwhile is never reported."""
    pve.down.add('n2')
    drift._scan_cluster(CL)
    row = next(r for r in _rows(db) if r['scope'] == 'n2/eno1')
    assert (row['kind'], row['op']) == ('network', 'unknown')

    pve.down.clear()
    pve.nics['n2']['eno1'] = {'address': '10.9.9.9'}   # changed while it was away
    r = _admin(api, seed).post(f'/api/drift/events/{row["id"]}/acknowledge',
                               json={'promote': True})
    assert r.status_code == 200, r.get_data(as_text=True)[:300]

    assert 'address' not in drift._load_baselines(CL)[('network', 'n2/eno1')]['snapshot']
    res = drift._scan_cluster(CL)
    assert [(e['scope'], e['summary']) for e in res['events']] == [
        ('n2/eno1', 'network n2/eno1: address')]


def test_promote_of_a_real_change_still_rebaselines(api, seed, pve, db):
    pve.cfg[('lxc', 150)]['cores'] = 4
    drift._scan_cluster(CL)
    row = next(r for r in _rows(db) if r['scope'] == 'lxc/150')
    assert row['op'] == 'changed'
    r = _admin(api, seed).post(f'/api/drift/events/{row["id"]}/acknowledge',
                               json={'promote': True})
    assert r.status_code == 200
    assert drift._load_baselines(CL)[('vm_config', 'lxc/150')]['snapshot']['cores'] == 4
