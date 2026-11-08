"""A guest id that went to a new guest shows nothing of the guest that had it before.

The guest search index keeps the notes, MACs and configured IPs of each guest by its
id, and PVE hands a freed id to the next new guest. The search checks access on the
guests as they are now, so an entry read from the old guest was handed to whoever may
see the new one, for up to an hour. An entry now keeps the name its config had: the
search skips an entry whose guest goes by another name, and the refresher reads that
guest again first. PegaProx drops the entry itself where it deletes a guest, creates
or clones one, or restores a backup onto an id. A config without a name says nothing,
so its entry stays as before.
MK Oct 2026
"""
import re
import time
from unittest.mock import MagicMock

import pytest

import pegaprox.globals as ppglobals
import pegaprox.utils.rbac as rbac

OLD = {'name': 'old-secret-db', 'net0': 'virtio=BC:24:11:AA:BB:01,bridge=vmbr0',
       'ipconfig0': 'ip=10.9.9.9/24', 'description': 'root pw hint: hunter2, rotate monthly'}
NEW = {'name': 'mallory-new', 'net0': 'virtio=BC:24:11:EE:EE:07,bridge=vmbr0',
       'description': 'build box'}


def _row(vmid=100, name='mallory-new', vm_type='qemu', **kw):
    return dict({'vmid': vmid, 'name': name, 'node': 'n1', 'type': vm_type, 'status': 'running',
                 'tags': ''}, **kw)


def _manager(api, rows):
    m = api.make_fake_manager(cluster_id='cluster_1', get_vm_resources=[dict(r) for r in rows])
    m.is_connected = True
    m.config.name = 'cluster_1'
    m.nodes = {}
    api.set_manager('cluster_1', m)
    return m


def _pool_user(seed):
    seed.tenant('tenant_x', clusters=['cluster_1'])
    u = seed.user('mallory', role='viewer', tenant_id='tenant_x')
    seed.pool('cluster_1', 'pool_1', 'mallory', ['pool.view', 'vm.view'])
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache['cluster_1'] = {'data': {'100:qemu': 'pool_1'},
                                                    'timestamp': time.time(), 'refreshing': False}
    return u


def _search(client, q):
    r = client.get('/api/global/search', query_string={'q': q})
    assert r.status_code == 200, r.get_data(as_text=True)
    return [(x['vmid'], x['match_field'], x.get('match_value')) for x in r.get_json()['results']]


# -- the search ----------------------------------------------------------------------------------

def test_a_new_guest_on_an_old_id_shows_nothing_of_the_old_one(api, seed):
    from pegaprox.background import guest_index
    guest_index.ingest('cluster_1', 'qemu', 100, dict(OLD))
    # the old 100 was deleted outside PegaProx, mallory's new guest took the id
    _manager(api, [_row()])
    mallory = api.as_user(_pool_user(seed))
    admin = api.as_user(seed.user('root', role='admin'))
    for client in (mallory, admin):
        for q in ('notes:pw', 'hunter2', 'ip:10.9', '10.9.9.9', 'mac:bc:24:11:aa', 'BC:24:11:AA:BB:01'):
            assert _search(client, q) == [], q
    # counterproof: the new guest's own config is found once it is read
    guest_index.ingest('cluster_1', 'qemu', 100, dict(NEW))
    assert _search(mallory, 'notes:build') == [(100, 'notes', 'build box')]
    assert _search(mallory, 'mac:ee:ee:07') == [(100, 'mac', 'BC:24:11:EE:EE:07')]
    assert _search(mallory, 'notes:pw') == []


def test_the_same_guest_is_still_found_by_its_notes(api, seed):
    from pegaprox.background import guest_index
    admin = api.as_user(seed.user('root', role='admin'))
    guest_index.ingest('cluster_1', 'qemu', 100, dict(OLD))
    guest_index.ingest('cluster_1', 'lxc', 900, {'hostname': 'Cache01', 'description': 'redis cache'})
    _manager(api, [_row(name='old-secret-db'), _row(900, 'cache01', 'lxc')])
    assert _search(admin, 'hunter2')[0][:2] == (100, 'notes')
    assert _search(admin, 'ip:10.9') == [(100, 'ip', '10.9.9.9')]
    # a container goes by its hostname, and case does not count
    assert _search(admin, 'notes:redis') == [(900, 'notes', 'redis cache')]


def test_a_config_without_a_name_keeps_its_entry(api, seed):
    """A config that sets no name says nothing about whose it is: PVE shows the guest as
    'VM <id>' or 'CT<id>', and the entry is used as before."""
    from pegaprox.background import guest_index
    admin = api.as_user(seed.user('root', role='admin'))
    guest_index.ingest('cluster_1', 'qemu', 100, {'description': 'nameless notes'})
    guest_index.ingest('cluster_1', 'lxc', 900, {'description': 'nameless ct'})
    guest_index.ingest('cluster_1', 'qemu', 101, {'description': 'renamed in the list'})
    _manager(api, [_row(name='VM 100'), _row(900, 'CT900', 'lxc'), _row(101, 'db01'),
                   _row(102, '')])
    assert sorted(_search(admin, 'notes:nameless')) == [(100, 'notes', 'nameless notes'),
                                                        (900, 'notes', 'nameless ct')]
    assert _search(admin, 'notes:renamed') == [(101, 'notes', 'renamed in the list')]
    # a row without a name says nothing either
    guest_index.ingest('cluster_1', 'qemu', 102, dict(OLD))
    assert _search(admin, 'notes:hunter2') == [(102, 'notes', OLD['description'])]
    # but a named config and a guest that now has none are two guests: PVE shows the
    # default only for a config without a name
    guest_index.ingest('cluster_1', 'qemu', 100, dict(OLD))
    assert [h for h in _search(admin, 'notes:hunter2') if h[0] == 100] == []


def test_the_guest_page_filter_skips_the_old_guest_too(index):
    from pegaprox.api.clusters import _guest_text_filter
    index.ingest('c1', 'qemu', 100, dict(OLD))
    row = {'cluster_id': 'c1', 'cluster_name': 'c1', 'vmid': 100, 'name': 'mallory-new', 'type': 'qemu',
           'node': 'n1', 'status': 'running', 'pool': '', 'ip_addresses': [], 'tags': []}
    for q in ('notes:hunter2', 'ip:10.9', 'mac:bc:24:11:aa'):
        assert _guest_text_filter([row], q) == [], q
    # counterproof: the guest the entry was read from still matches
    same = dict(row, name='old-secret-db')
    for q in ('notes:hunter2', 'ip:10.9', 'mac:bc:24:11:aa'):
        assert _guest_text_filter([same], q) == [same], q


# -- the refresher ------------------------------------------------------------------------------

class _Resp:
    def __init__(self, status, data):
        self.status_code, self._data = status, data

    def json(self):
        return {'data': self._data}


class _Pve:
    cluster_type = 'proxmox'
    host, api_port = 'pve.test', 8006

    def __init__(self, guests, configs):
        self.is_connected = True
        self.guests, self.configs = guests, configs
        self.nodes = {}
        self.reads = []
        self.broken = set()

    def get_vm_resources(self, max_age=0.0):
        return [dict(g) for g in self.guests]

    def _api_get(self, url, **kw):
        m = re.search(r'/nodes/([^/]+)/(qemu|lxc)/(\d+)/config$', url)
        key = (m.group(2), int(m.group(3)))
        self.reads.append(key)
        if key in self.broken:
            return _Resp(500, None)
        return _Resp(200, dict(self.configs[key]))


@pytest.fixture
def index():
    from pegaprox.background import guest_index
    guest_index.clear()
    saved = dict(ppglobals.cluster_managers)
    ppglobals.cluster_managers.clear()
    yield guest_index
    ppglobals.cluster_managers.clear()
    ppglobals.cluster_managers.update(saved)
    guest_index.clear()


def test_the_next_pass_reads_a_reused_id_first(index):
    index.ingest('c1', 'qemu', 100, dict(OLD))
    index.ingest('c1', 'qemu', 101, {'name': 'other', 'description': 'other notes'})
    pve = _Pve([_row(100), _row(101, 'other')],
               {('qemu', 100): dict(NEW), ('qemu', 101): {'name': 'other'}})
    ppglobals.cluster_managers['c1'] = pve
    # both entries are young; the one of the old 100 is not kept until it is stale
    assert index.refresh_pass(budget=5) == 1
    assert pve.reads == [('qemu', 100)]
    got = index.snapshot('c1')
    assert got[('qemu', 100)]['notes'] == 'build box'
    assert got[('qemu', 101)]['notes'] == 'other notes'
    # counterproof: a young entry of the guest it was read from is left alone
    assert index.refresh_pass(budget=5) == 0


def test_a_failed_read_of_a_reused_id_keeps_nothing_of_the_old_guest(index):
    index.ingest('c1', 'qemu', 100, dict(OLD))
    pve = _Pve([_row(100)], {('qemu', 100): dict(NEW)})
    pve.broken.add(('qemu', 100))
    ppglobals.cluster_managers['c1'] = pve
    assert index.refresh_pass() == 1
    entry = index.snapshot('c1')[('qemu', 100)]
    assert entry['notes'] == '' and entry['macs'] == [] and entry['ips'] == []
    # and it waits for its turn like any failed read, it is not tried every pass
    assert index.refresh_pass() == 0


def test_an_empty_guest_list_still_drops_nothing(index):
    index.ingest('c1', 'qemu', 100, dict(OLD))
    pve = _Pve([], {})
    ppglobals.cluster_managers['c1'] = pve
    index.refresh_pass()
    assert index.snapshot('c1')[('qemu', 100)]['notes'] == OLD['description']
    # a list with the guest under its own name keeps it too
    pve.guests = [_row(100, 'old-secret-db')]
    index.refresh_pass()
    assert ('qemu', 100) in index.snapshot('c1') and pve.reads == []


# -- where PegaProx itself frees or fills an id ----------------------------------------------------

def test_drop_forgets_that_one_guest(index):
    index.ingest('c1', 'qemu', 100, dict(OLD))
    index.ingest('c1', 'lxc', 100, {'description': 'ct'})
    index.ingest('c2', 'qemu', 100, {'description': 'other cluster'})
    index.drop('c1', 'qemu', '100')
    assert sorted(index.snapshot('c1')) == [('lxc', 100)]
    assert ('qemu', 100) in index.snapshot('c2')
    # never raises: its callers delete and create guests
    index.drop('c1', 'qemu', None)
    index.drop('c1', 'qemu', 'abc')
    index.drop('nope', 'qemu', 100)


def _real_manager(monkeypatch):
    import pegaprox.core.manager as mgrmod
    from pegaprox.models.tasks import PegaProxConfig
    m = mgrmod.PegaProxManager('c1', PegaProxConfig({'name': 't', 'host': 'h', 'user': 'root@pam',
                                                     'pass': 'x'}))
    m.is_connected = True
    m.session = True
    answer = {'status': 200}

    def resp(data='UPID:n1:x'):
        r = MagicMock()
        r.status_code = answer['status']
        r.text = 'refused'
        r.json.return_value = {'data': data}
        return r
    session = MagicMock()
    session.get.side_effect = lambda *a, **k: resp({'status': 'stopped'})
    session.delete.side_effect = lambda *a, **k: resp()
    monkeypatch.setattr(m, '_create_session', lambda: session)
    monkeypatch.setattr(m, '_api_post', lambda *a, **k: resp())
    monkeypatch.setattr(m, '_wait_for_task', lambda *a, **k: True)
    monkeypatch.setattr(m, 'sanitize_boot_order', lambda *a, **k: {})
    return m, answer


def test_deleting_creating_and_cloning_drop_the_entry(index, db, monkeypatch):
    m, answer = _real_manager(monkeypatch)
    for vm_type, vmid in (('qemu', 100), ('qemu', 101), ('lxc', 102), ('qemu', 103), ('qemu', 104)):
        index.ingest('c1', vm_type, vmid, dict(OLD))

    assert m.delete_vm('n1', 100, 'qemu')['success']
    assert m.create_vm('n1', {'vmid': 101, 'name': 'fresh', 'storage': 'local', 'cores': 1,
                              'memory': 512, 'disk_size': '8', 'ostype': 'l26'})['success']
    assert m.create_container('n1', {'vmid': 102, 'hostname': 'fresh', 'template': 'local:vztmpl/d.tar.zst',
                                     'storage': 'local'})['success']
    assert m.clone_vm('n1', 900, 'qemu', newid=103, name='fresh')['success']
    assert sorted(index.snapshot('c1')) == [('qemu', 104)]

    # counterproof: what PVE refused leaves the entry where it is
    index.ingest('c1', 'qemu', 100, dict(OLD))
    answer['status'] = 500
    assert not m.delete_vm('n1', 100, 'qemu')['success']
    assert not m.clone_vm('n1', 900, 'qemu', newid=104, name='fresh')['success']
    assert sorted(index.snapshot('c1')) == [('qemu', 100), ('qemu', 104)]


def _restore_manager(api, status):
    m = _manager(api, [_row(name='old-secret-db')])
    m.id = 'cluster_1'
    r = MagicMock()
    r.status_code = status
    r.text = 'refused'
    r.json.return_value = {'data': 'UPID:n1:restore'}
    m._create_session.return_value.post.return_value = r
    m._api_post.return_value = r
    return m


def test_a_restore_onto_an_id_drops_its_entry(api, seed):
    from pegaprox.background import guest_index
    admin = api.as_user(seed.user('root', role='admin'))
    for vmid in (100, 101):
        guest_index.ingest('cluster_1', 'qemu', vmid, dict(OLD))

    # refused by PVE: the entry stays
    _restore_manager(api, 500)
    r = admin.post('/api/clusters/cluster_1/vms/n1/qemu/100/backups/restore',
                   json={'volid': 'local:backup/vzdump-qemu-100-2026_10_01-00_00_00.vma.zst'})
    assert r.status_code == 500
    assert ('qemu', 100) in guest_index.snapshot('cluster_1')

    _restore_manager(api, 200)
    r = admin.post('/api/clusters/cluster_1/vms/n1/qemu/100/backups/restore',
                   json={'volid': 'local:backup/vzdump-qemu-100-2026_10_01-00_00_00.vma.zst'})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert sorted(guest_index.snapshot('cluster_1')) == [('qemu', 101)]

    r = admin.post('/api/clusters/cluster_1/backup-restore',
                   json={'volid': 'pbs:backup/vm/100/2026-10-01T00:00:00Z', 'target_node': 'n1',
                         'target_vmid': 101, 'mode': 'overwrite'})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert guest_index.snapshot('cluster_1') == {}
