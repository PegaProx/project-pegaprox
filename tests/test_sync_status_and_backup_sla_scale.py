"""ISO sync status and Backup SLA read their nodes in bounded parallel.

Both routes walked every online node and every storage one after the other, with no
deadline: at 200 nodes one answer took minutes, and the Backup SLA read a shared PBS
store once per node. A read that failed was dropped without a word, so a node whose
content read failed showed every ISO as missing (and "sync all" copied to it), and a
backup store that did not answer made its guests "no backup".

  a) the reads overlap, never more than the bound at a time, and the whole read ends
     within its deadline; what did not finish is named, never counted as empty.
  b) ISO sync: a node that was not read is left out of nodes and matrix and named in
     unread with the reason. No status at all is an error.
  c) Backup SLA: a shared store is read once (the next node that has it when that read
     fails), a local one on its node; a failed read is listed in unread; a node list
     that failed is an error, not "every guest without a backup".

The PVE answers are scripted, each one takes 0.1 s (a gevent sleep, the route runs on
the hub as in production).

MK Nov 2026
"""
import json
import time

import gevent
import pytest

CLUSTER = 'cluster_1'
LATENCY = 0.1


class _Resp:
    def __init__(self, status, data):
        self.status_code = status
        self._data = data
        self.text = json.dumps({'data': data} if status == 200 else {'message': str(data)})

    def json(self):
        return {'data': self._data}


class _Pve:
    """Scripted PVE: `answer(path)` -> (status, data); counts the reads in flight."""

    def __init__(self, answer):
        self.answer = answer
        self.calls = []
        self.now = 0
        self.peak = 0

    def get(self, url, params=None, timeout=None, **kw):
        path = url.split('/api2/json', 1)[1]
        self.calls.append(path)
        self.now += 1
        self.peak = max(self.peak, self.now)
        try:
            got = self.answer(path)
            gevent.sleep(got[2] if len(got) > 2 else LATENCY)
            return _Resp(got[0], got[1])
        finally:
            self.now -= 1


# --- ISO sync ----------------------------------------------------------------------------------

def _sync_mgr(nodes, answer):
    from pegaprox.core.manager import PegaProxManager
    import logging
    pve = _Pve(answer)

    class _Mgr(PegaProxManager):
        host, api_port = 'pve.test', 8006   # properties over the config on the real one

        def __init__(self):
            pass
    m = _Mgr()
    m.is_connected = True
    m.logger = logging.getLogger('test.sync')
    m.get_node_status = lambda: {n: {'status': 'online'} for n in nodes}
    m._api_get = lambda url, **kw: pve.get(url, **kw)

    class _S:
        get = staticmethod(pve.get)
    m._create_session = lambda: _S()
    return m, pve


def _iso_answer(broken=(), slow=()):
    def answer(path):
        node = path.split('/')[2]
        if path.endswith('/storage'):
            return 200, [{'storage': 'local', 'content': 'iso,vztmpl', 'active': 1, 'shared': 0},
                         {'storage': 'nfs', 'content': 'iso', 'active': 1, 'shared': 1}]
        if node in broken:
            return 500, "storage 'local' is not online"
        if node in slow:
            return 200, [], 5
        return 200, [{'volid': 'local:iso/debian.iso', 'size': 10}]
    return answer


def test_the_sync_status_reads_its_nodes_in_parallel_within_the_bound():
    nodes = [f'pve{i}' for i in range(24)]
    m, pve = _sync_mgr(nodes, _iso_answer())
    t0 = time.monotonic()
    status = m.get_content_sync_status('iso')
    took = time.monotonic() - t0
    # 48 reads of 0.1 s one after the other are 4.8 s
    assert took < 2.0, f'{took:.1f} s'
    assert 1 < pve.peak <= getattr(m, 'SYNC_STATUS_WORKERS', 8), pve.peak
    assert sorted(status['nodes']) == sorted(nodes)
    assert status['unread'] == {}
    assert all(status['matrix']['local:debian.iso'].values())
    # the shared store is not part of the sync
    assert not [c for c in pve.calls if '/storage/nfs/' in c]


def test_a_node_that_was_not_read_is_left_out_and_named():
    m, _ = _sync_mgr(['pve1', 'pve2', 'pve3'], _iso_answer(broken=('pve2',)))
    status = m.get_content_sync_status('iso')
    assert status['nodes'] == ['pve1', 'pve3']
    assert set(status['matrix']['local:debian.iso']) == {'pve1', 'pve3'}
    assert 'HTTP 500' in status['unread']['pve2']


def test_the_sync_status_ends_within_its_deadline(monkeypatch):
    from pegaprox.core.manager import PegaProxManager
    monkeypatch.setattr(PegaProxManager, 'SYNC_STATUS_DEADLINE', 0.6, raising=False)
    m, _ = _sync_mgr(['pve1', 'pve2'], _iso_answer(slow=('pve2',)))
    t0 = time.monotonic()
    status = m.get_content_sync_status('iso')
    assert time.monotonic() - t0 < 2.5
    assert status['nodes'] == ['pve1']
    assert 'in time' in status['unread']['pve2']


@pytest.fixture
def admin(api, seed):
    return api.as_user(seed.user('root_admin', role='admin'))


def test_the_route_answers_no_status_as_an_error(api, admin):
    from pegaprox.core.manager import PegaProxManager
    m, _ = _sync_mgr(['pve1'], _iso_answer())
    m.is_connected = False
    fake = api.make_fake_manager(CLUSTER)
    fake.get_content_sync_status = PegaProxManager.get_content_sync_status.__get__(m, PegaProxManager)
    api.set_manager(CLUSTER, fake)
    r = admin.get(f'/api/clusters/{CLUSTER}/iso-sync/status?content=iso')
    assert r.status_code == 503, r.get_data(as_text=True)
    assert (r.get_json()['code'], r.get_json()['offline']) == ('PVE_UNREACHABLE', True)
    # counter-check
    m.is_connected = True
    r = admin.get(f'/api/clusters/{CLUSTER}/iso-sync/status?content=iso')
    assert r.status_code == 200
    assert r.get_json()['nodes'] == ['pve1']


# --- Backup SLA --------------------------------------------------------------------------------

NOW = int(time.time())


def _sla_cluster(api, nodes, answer, guests=(100, 101, 102)):
    m = api.make_fake_manager(CLUSTER)
    m.is_connected = True
    m.host, m.api_port = 'pve.test', 8006
    m.config.backup_sla_max_age_hours = 24
    m.id = CLUSTER
    m.get_vm_resources.return_value = [{'type': 'qemu', 'vmid': v, 'node': nodes[0], 'name': f'g{v}'} for v in guests]
    pve = _Pve(answer)

    class _S:
        get = staticmethod(pve.get)
    m._create_session = lambda: _S()
    api.set_manager(CLUSTER, m)
    return pve


def _sla_answer(nodes, shared_fails_on=(), local_fails_on=(), node_list=None, slow_store=None):
    def answer(path):
        if path == '/nodes':
            return node_list or (200, [{'node': n, 'status': 'online'} for n in nodes])
        node = path.split('/')[2]
        if path.endswith('/storage'):
            return 200, [{'storage': 'pbs', 'type': 'pbs', 'content': 'backup', 'shared': 1, 'active': 1},
                         {'storage': 'local', 'type': 'dir', 'content': 'backup,iso', 'shared': 0, 'active': 1}]
        store = path.split('/')[4]
        if store == slow_store:
            return 200, [], 5
        if store == 'pbs':
            if node in shared_fails_on:
                return 500, 'pbs is not online'
            return 200, [{'volid': 'pbs:backup/vm/100/2026-11-03T00:00:00Z', 'vmid': 100, 'ctime': NOW - 3600}]
        if node in local_fails_on:
            return 500, "storage 'local' is not online"
        if node == nodes[0]:
            return 200, [{'volid': 'local:backup/vzdump-qemu-101-2026_11_03.vma.zst', 'vmid': 101, 'ctime': NOW - 7200}]
        return 200, []
    return answer


def _states(body):
    return {v['vmid']: v['sla_status'] for v in body['vms']}


def test_a_shared_store_is_read_once_not_on_every_node(api, admin):
    nodes = [f'pve{i}' for i in range(12)]
    pve = _sla_cluster(api, nodes, _sla_answer(nodes))
    r = admin.get(f'/api/clusters/{CLUSTER}/backup-sla')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert len([c for c in pve.calls if '/storage/pbs/content' in c]) == 1
    assert len([c for c in pve.calls if '/storage/local/content' in c]) == len(nodes)
    body = r.get_json()
    assert _states(body) == {'100': 'ok', '101': 'ok', '102': 'no-backup'}
    assert body['unread'] == []


def test_the_backup_scan_overlaps_its_reads_within_the_bound(api, admin):
    from pegaprox.api import clusters
    nodes = [f'pve{i}' for i in range(20)]
    pve = _sla_cluster(api, nodes, _sla_answer(nodes))
    t0 = time.monotonic()
    assert admin.get(f'/api/clusters/{CLUSTER}/backup-sla').status_code == 200
    took = time.monotonic() - t0
    # one after the other: 1 + 20 storage lists + 21 stores at 0.1 s, 4.2 s
    assert took < 2.0, f'{took:.1f} s'
    assert 1 < pve.peak <= getattr(clusters, '_SLA_WORKERS', 8), pve.peak


def test_a_store_that_failed_is_named_and_the_shared_one_is_tried_on_the_next_node(api, admin):
    nodes = ['pve1', 'pve2', 'pve3']
    _sla_cluster(api, nodes, _sla_answer(nodes, shared_fails_on=('pve1',), local_fails_on=('pve1',)))
    body = admin.get(f'/api/clusters/{CLUSTER}/backup-sla').get_json()
    # the PBS backup of 100 was found through pve2
    assert _states(body)['100'] == 'ok'
    assert body['unread'] == [{'storage': 'local', 'node': 'pve1', 'error': 'HTTP 500'}]


def test_a_failed_node_list_is_an_error_not_guests_without_backups(api, admin):
    nodes = ['pve1']
    _sla_cluster(api, nodes, _sla_answer(nodes, node_list=(500, 'cluster not ready')))
    r = admin.get(f'/api/clusters/{CLUSTER}/backup-sla')
    assert r.status_code == 502, r.get_data(as_text=True)
    assert r.get_json()['code'] == 'PVE_READ_FAILED'
    assert 'vms' not in r.get_json()


def test_the_backup_scan_ends_within_its_deadline(api, admin, monkeypatch):
    from pegaprox.api import clusters
    monkeypatch.setattr(clusters, '_SLA_DEADLINE', 0.8, raising=False)
    nodes = ['pve1', 'pve2']
    _sla_cluster(api, nodes, _sla_answer(nodes, slow_store='pbs'))
    t0 = time.monotonic()
    body = admin.get(f'/api/clusters/{CLUSTER}/backup-sla').get_json()
    assert time.monotonic() - t0 < 3
    assert {'storage': 'pbs', 'node': None, 'error': 'did not answer in time'} in body['unread']
    assert _states(body)['101'] == 'ok'
