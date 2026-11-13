"""ESXi bulk migration: several guests of one ESXi server moved to Proxmox, a few at a time.

POST /api/vmware/<id>/bulk-migrate checks every guest like a dry run of the single migrate
route and hands them to a run on the server (core/esxi_bulk.py). GET /api/vmware/bulk-migrate
and /<run_id> follow it, POST .../cancel starts no further guest.

The ESXi server and the Proxmox target only exist in this file. A started guest is a real
V2PMigrationTask whose job is replaced by one that only records it: the test moves its
phase and ends it. The worker polls every few milliseconds here.

MK Oct 2026
"""
import json
import logging
import threading
import time
import types

import pytest

from pegaprox.core import esxi_bulk as ebulk

GiB = 1024 ** 3
PW = 'S3cret-ESXi-pw!'


def _wait(cond, seconds=5.0, what='condition'):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if cond():
            return
        time.sleep(0.01)
    assert cond(), f'timed out waiting for {what}'


# --------------------------------------------------------------------------- the fakes

def _vm(name, disks=(8,), nics=1, power='POWERED_ON'):
    return {'name': name, 'power': power,
            'disks': [{'key': str(2000 + i), 'label': f'Hard disk {i + 1}', 'capacity_bytes': int(g * GiB),
                       'capacity_gb': float(g), 'thin': False,
                       'vmdk_file': f"[ds1] {name}/{name}{'_%d' % i if i else ''}.vmdk"}
                      for i, g in enumerate(disks)],
            'nics': [{'type': 'VirtualVmxnet3', 'pve_model': 'vmxnet3', 'mac_address': f'00:50:56:aa:00:{i:02x}',
                      'network': f'VM Network {i}', 'label': f'Network adapter {i + 1}'} for i in range(nics)]}


class Esxi:
    """The ESXi API of a server with a few guests. Records which guests were read."""

    def __init__(self, vms):
        self.host = 'esx1.lab'
        self.name = 'esx01'
        self.linked_clusters = []
        self.vms = vms
        self.reads = []
        self.lock = threading.Lock()

    def ensure_connected(self):
        return True

    def get_vm(self, vm_id):
        with self.lock:
            self.reads.append(vm_id)
        v = self.vms.get(vm_id)
        if v is None:
            return {'error': 'VM not found'}
        return {'data': {'name': v['name'], 'power_state': v['power'], 'guest_OS': 'Linux',
                         'cpu': {'count': 2, 'sockets': 1, 'cores_per_socket': 2},
                         'memory': {'size_MiB': 2048},
                         'hardware': {'firmware': 'bios', 'has_tpm': False, 'disk_bus': 'scsi'},
                         'nics': [dict(n) for n in v['nics']],
                         'disks': {d['key']: {'capacity': d['capacity_bytes']} for d in v['disks']}}}

    def get_vm_disks_for_export(self, vm_id):
        v = self.vms.get(vm_id)
        if v is None:
            return {'error': 'VM not found'}
        return {'data': {'vm_id': vm_id, 'name': v['name'], 'power_state': v['power'],
                         'disks': [dict(d) for d in v['disks']],
                         'total_disk_gb': sum(d['capacity_gb'] for d in v['disks'])}}


class _Resp:
    def __init__(self, data, status=200):
        self.status_code = status
        self._data = data
        self.text = json.dumps(data)

    def json(self):
        return {'data': self._data}


NETWORK = [{'iface': 'vmbr0', 'type': 'bridge'}, {'iface': 'vmbr1', 'type': 'bridge'},
           {'iface': 'eno1', 'type': 'eth'}]
STORAGES = [
    {'storage': 'local-lvm', 'type': 'lvmthin', 'content': 'images,rootdir', 'active': 1, 'enabled': 1,
     'avail': 500 * GiB},
    {'storage': 'fast-lvm', 'type': 'lvm', 'content': 'images', 'active': 1, 'enabled': 1, 'avail': 20 * GiB},
    {'storage': 'tank', 'type': 'zfspool', 'content': 'images', 'active': 1, 'enabled': 1, 'avail': 20 * GiB},
    {'storage': 'local', 'type': 'dir', 'content': 'iso,vztmpl', 'active': 1, 'enabled': 1, 'avail': 50 * GiB},
]


class Pve:
    host = 'pve1.lab'
    api_port = 8006
    cluster_type = 'proxmox'

    def __init__(self):
        self.nodes = {'pve1': {}, 'pve2': {}}
        self.is_connected = True
        self.config = types.SimpleNamespace(name='lab')
        self.network = [dict(n) for n in NETWORK]
        self.storages = [dict(s) for s in STORAGES]
        self.gets = []

    def _api_get(self, url, **kw):
        self.gets.append(url)
        if url.endswith('/nodes/pve1/network'):
            return _Resp(self.network) if self.network != 'fail' else _Resp(None, 500)
        if url.endswith('/cluster/sdn/vnets'):
            return _Resp(None, 404)
        if url.endswith('/nodes/pve1/storage'):
            return _Resp(self.storages) if self.storages != 'fail' else _Resp(None, 500)
        return _Resp({})


class Runner:
    """Stands in for _run_v2p_migration: records the task. The real job gets its VMID and
    creates the VM shell first (phase planning); here that is over at once unless held."""

    def __init__(self):
        self.tasks = []
        self.lock = threading.Lock()
        self.hold_planning = False

    def __call__(self, task):
        with self.lock:
            self.tasks.append(task)
        if not self.hold_planning:
            task.phase = 'pre_sync'

    def names(self):
        with self.lock:
            return [t.vm_name for t in self.tasks]

    def task(self, name):
        with self.lock:
            return next(t for t in self.tasks if t.vm_name == name)

    def end(self, name, status='completed', error=None):
        t = self.task(name)
        t.error = error
        t.phase = status if status != 'failed' else 'failed'
        t.status = status

    def end_all(self):
        with self.lock:
            tasks = list(self.tasks)
        for t in tasks:
            if t.status == 'running':
                t.status = t.phase = 'completed'


@pytest.fixture
def env(api, seed, monkeypatch):
    import pegaprox.globals as g
    import pegaprox.api.vmware as vmwareapi
    from pegaprox.utils import rbac
    monkeypatch.setattr(ebulk, 'POLL_SECONDS', 0.02)
    ebulk.reset_for_tests()
    rbac.invalidate_vm_acls_cache()
    esxi = Esxi({'vm-1': _vm('web01'), 'vm-2': _vm('db01', disks=(8, 4), nics=2), 'vm-3': _vm('app01'),
                 'vm-4': _vm('mail01')})
    pve = Pve()
    api.set_manager('pve-cl', pve)
    g.vmware_managers['vw1'] = esxi
    runner = Runner()
    monkeypatch.setattr(vmwareapi, '_run_v2p_migration', runner)
    monkeypatch.setattr(vmwareapi, '_vmware_migrations', {})
    admin = api.as_user(seed.user('root', role='admin'))

    def post(client=None, **kw):
        return (client or admin).post('/api/vmware/vw1/bulk-migrate', json=_body(**kw))

    ns = types.SimpleNamespace(api=api, seed=seed, esxi=esxi, pve=pve, runner=runner, admin=admin, post=post,
                               module=vmwareapi, rbac=rbac)
    yield ns
    # no run may outlive its test: it would start guests on the next test's managers
    for run in ebulk.runs():
        ebulk.cancel(run, 'teardown')
    deadline = time.time() + 5
    while time.time() < deadline and any(r.state == 'running' for r in ebulk.runs()):
        runner.end_all()
        time.sleep(0.02)
    ebulk.reset_for_tests()
    rbac.invalidate_vm_acls_cache()
    g.vmware_managers.pop('vw1', None)


def _body(**kw):
    b = {'vms': ['vm-1', 'vm-2'], 'target_cluster': 'pve-cl', 'target_node': 'pve1',
         'target_storage': 'local-lvm', 'transfer_mode': 'offline', 'esxi_password': PW}
    b.update(kw)
    return {k: v for k, v in b.items() if v is not None}


def _started(r):
    assert r.status_code == 202, r.get_data(as_text=True)
    return r.get_json()['run']


def _view(client, run_id):
    r = client.get(f'/api/vmware/bulk-migrate/{run_id}')
    assert r.status_code == 200, r.get_data(as_text=True)
    return r.get_json()['run']


def _states(client, run_id):
    return {it['vm_id']: it['state'] for it in _view(client, run_id)['items']}


def _over(run_id):
    run = ebulk.get(run_id)
    return run is not None and run.state != 'running'


def _audit(seed, action=None):
    q = 'SELECT user, action, details FROM audit_log'
    rows = seed.db.conn.execute(q + (' WHERE action = ?' if action else '') + ' ORDER BY id',
                                (action,) if action else ()).fetchall()
    return [tuple(r) for r in rows]


# --------------------------------------------------------------------------- the check

def test_a_dry_run_checks_every_guest_against_one_read_of_the_node_and_starts_nothing(env):
    r = env.post(dry_run=True, esxi_password=None,
                 vms=['vm-1', {'vm_id': 'vm-2', 'nic_map': [{'index': 1, 'bridge': 'vmbr1', 'vlan': 30}],
                               'disk_map': [{'index': 1, 'storage': 'fast-lvm'}]}])
    assert r.status_code == 200, r.get_data(as_text=True)
    d = r.get_json()
    assert d['dry_run'] is True and d['ok'] is True and d['errors'] == []
    items = {it['vm_id']: it for it in d['items']}
    assert items['vm-1']['name'] == 'web01' and items['vm-1']['ok'] is True
    assert items['vm-1']['custom_network'] is False and items['vm-2']['custom_network'] is True
    assert [(n['bridge'], n['vlan']) for n in items['vm-2']['nics']] == [('vmbr0', None), ('vmbr1', 30)]
    assert [(x['storage'], x['skip']) for x in items['vm-2']['disks']] == [('local-lvm', False), ('fast-lvm', False)]
    assert {b['name'] for b in d['available']['bridges']} == {'vmbr0', 'vmbr1'}
    assert {s['storage'] for s in d['available']['storages']} == {'local-lvm', 'fast-lvm', 'tank'}
    # the storages the guests use together
    assert {s['storage']: (s['needed_bytes'], s['guests']) for s in d['storages']} == {
        'local-lvm': (16 * GiB, 2), 'fast-lvm': (4 * GiB, 1)}
    # one read of the node's network and storage for every guest of the request
    assert sum(1 for u in env.pve.gets if u.endswith('/nodes/pve1/storage')) == 1
    assert sum(1 for u in env.pve.gets if u.endswith('/nodes/pve1/network')) == 1
    time.sleep(0.1)
    assert env.runner.tasks == [] and ebulk.runs() == []


def test_a_dry_run_never_echoes_the_password_it_was_handed(env):
    r = env.post(dry_run=True)
    assert r.status_code == 200 and r.get_json()['ok'] is True
    assert PW not in r.get_data(as_text=True)
    assert ebulk.runs() == []


def test_a_guest_the_caller_may_not_migrate_refuses_the_whole_submit_and_is_never_read(env):
    bob = env.seed.user('bob', role='user')
    env.seed.vm_acl('vmware:vw1', 'vm-1', ['bob'], inherit_role=False, permissions=['vmware.vm.migrate'])
    env.rbac.invalidate_vm_acls_cache()
    c = env.api.as_user(bob)
    r = env.post(c)
    assert r.status_code == 400, r.get_data(as_text=True)
    d = r.get_json()
    items = {it['vm_id']: it for it in d['items']}
    assert items['vm-2']['errors'] == ['Permission denied: vmware.vm.migrate']
    assert items['vm-1']['ok'] is True and '1 of 2 guests' in d['error']
    assert 'vm-2' not in env.esxi.reads
    time.sleep(0.1)
    assert env.runner.tasks == [] and ebulk.runs() == []
    # the guest bob may migrate goes on its own
    run = _started(env.post(c, vms=['vm-1']))
    _wait(lambda: env.runner.names() == ['web01'], what='the migration of web01')
    assert run['user'] == 'bob'


def test_a_caller_who_may_migrate_none_of_them_reads_nothing(env):
    bob = env.seed.user('bob', role='user')
    env.seed.vm_acl('vmware:vw1', 'vm-1', ['bob'], inherit_role=False, permissions=['vmware.vm.migrate'])
    env.rbac.invalidate_vm_acls_cache()
    r = env.post(env.api.as_user(bob), dry_run=True, vms=['vm-2', 'vm-3'])
    assert r.status_code == 403, r.get_data(as_text=True)
    assert env.esxi.reads == [] and env.pve.gets == []


def test_removing_the_source_needs_manage_on_each_guest(env):
    bob = env.seed.user('bob', role='user')
    for vm in ('vm-1', 'vm-2'):
        env.seed.vm_acl('vmware:vw1', vm, ['bob'], inherit_role=False,
                        permissions=['vmware.vm.migrate'] + (['vmware.vm.manage'] if vm == 'vm-1' else []))
    env.rbac.invalidate_vm_acls_cache()
    r = env.post(env.api.as_user(bob), remove_source=True, dry_run=True)
    items = {it['vm_id']: it for it in r.get_json()['items']}
    assert items['vm-1']['ok'] is True
    assert items['vm-2']['errors'] == ['Permission denied: removing the source guest needs vmware.vm.manage on it']


@pytest.mark.parametrize('extra', [
    {'vms': []},
    {'vms': 'vm-1'},
    {'vms': ['vm-1/../x']},
    {'vms': ['vm-1;reboot']},
    {'vms': ['-vm1']},
    {'vms': ['vm-1', 'vm-1']},
    {'vms': [{'vm_id': 'vm-1', 'esxi_datastore': 'ds1'}]},
    {'vms': [f'vm-{i}' for i in range(201)]},
    {'width': 0}, {'width': 6}, {'width': True}, {'width': '2'},
    {'esxi_datastore': 'ds1'}, {'esxi_vm_dir': 'x'}, {'sockets': 4}, {'selected_nics': []},
    {'nic_map': [{'index': 0, 'bridge': 'vmbr1'}]},
    {'network_bridge': 'vmbr0,firewall=0'}, {'network_bridge': 'vmbr0\nreboot'},
    {'target_storage': 'local;reboot'}, {'target_storage': '$(id)'},
    {'target_node': 'pve1;reboot'}, {'target_cluster': ['pve-cl']},
    {'esxi_user': '-oProxyCommand=x'}, {'esxi_host': 'evil.example'},
    {'net_vlan_tag': '5;reboot'}, {'net_vlan_tag': 4095},
    {'transfer_mode': 'rsync'}, {'remove_source': 'yes'}, {'verify': 'yes'}, {'bios': 'x'},
    {'disk_format': 'vmdk'}, {'confirmation_timeout': -1},
    {'dry_run': 'yes'}, {'esxi_password': ['pw']},
])
def test_what_could_reach_a_shell_or_a_config_line_is_refused_at_the_door(env, extra):
    r = env.post(**extra)
    assert r.status_code == 400, (extra, r.get_data(as_text=True))
    assert env.esxi.reads == [] and env.pve.gets == [], 'read something before the shape was checked'
    time.sleep(0.05)
    assert env.runner.tasks == [] and ebulk.runs() == []


@pytest.mark.parametrize('maps', [
    {'nic_map': [{'index': 0, 'bridge': 'vmbr0,firewall=0'}]},
    {'nic_map': [{'index': 0, 'bridge': 'vmbr0', 'vlan': '5;reboot'}]},
    {'disk_map': [{'index': 1, 'storage': 'local-lvm;reboot'}]},
    {'disk_map': [{'index': 0, 'skip': True}]},
])
def test_a_guests_own_choices_that_do_not_parse_fail_that_guest_before_anything_is_read(env, maps):
    r = env.post(vms=[dict(vm_id='vm-2', **maps)])
    assert r.status_code == 400, r.get_data(as_text=True)
    (it,) = r.get_json()['items']
    assert it['errors'][0].startswith('Invalid migration options')
    assert env.esxi.reads == [] and env.pve.gets == []


def test_choices_that_parse_but_do_not_exist_on_the_node_fail_that_guest(env):
    r = env.post(vms=['vm-1', {'vm_id': 'vm-2', 'nic_map': [{'index': 1, 'bridge': 'vmbr9'}],
                               'disk_map': [{'index': 1, 'storage': 'local'}]}])
    assert r.status_code == 400
    items = {it['vm_id']: it for it in r.get_json()['items']}
    assert items['vm-1']['ok'] is True
    assert any("'vmbr9' does not exist" in e for e in items['vm-2']['errors'])
    assert any("'local' does not take disk images" in e for e in items['vm-2']['errors'])


def test_guests_that_fit_a_storage_one_by_one_but_not_together_are_refused(env):
    # 8 GiB each, 20 GiB free: every guest fits alone, three do not
    r = env.post(dry_run=True, vms=['vm-1', 'vm-3', 'vm-4'], target_storage='fast-lvm')
    d = r.get_json()
    assert all(it['ok'] for it in d['items'])
    assert d['ok'] is False
    assert any("the 3 guests placed on it need 24.0 GiB together" in e for e in d['errors'])
    r = env.post(vms=['vm-1', 'vm-3', 'vm-4'], target_storage='fast-lvm')
    assert r.status_code == 400 and 'do not fit the target together' in r.get_json()['error']
    # two of them fit
    assert env.post(dry_run=True, vms=['vm-1', 'vm-3'], target_storage='fast-lvm').get_json()['ok'] is True
    # a pool that compresses may still take them: a warning, not a refusal
    d = env.post(dry_run=True, vms=['vm-1', 'vm-3', 'vm-4'], target_storage='tank').get_json()
    assert d['ok'] is True and any('may still fit if the pool compresses' in w for w in d['warnings'])


def test_a_guest_another_run_or_a_migration_has_already_is_refused(env):
    env.runner.hold_planning = True
    run = _started(env.post(vms=['vm-1', 'vm-2']))
    _wait(lambda: env.runner.names() == ['web01'])
    d = env.post(dry_run=True, vms=['vm-2', 'vm-3']).get_json()
    items = {it['vm_id']: it for it in d['items']}
    assert items['vm-2']['errors'] == ['Another bulk migration has this guest already']
    assert items['vm-3']['ok'] is True
    # a migration started on its own (the wizard) has a guest as well
    env.module._vmware_migrations['m-own'] = types.SimpleNamespace(vmware_id='vw1', vm_id='vm-3', status='running')
    d = env.post(dry_run=True, vms=['vm-3', 'vm-4']).get_json()
    items = {it['vm_id']: it for it in d['items']}
    assert items['vm-3']['errors'] == ['A migration of this guest is running'] and items['vm-4']['ok'] is True
    env.module._vmware_migrations['m-own'].status = 'completed'
    assert env.post(dry_run=True, vms=['vm-3']).get_json()['ok'] is True
    assert run['id']


def test_an_unreadable_target_node_refuses_the_check(env):
    env.pve.storages = 'fail'
    r = env.post(dry_run=True)
    assert r.status_code == 502


def test_a_target_the_caller_is_confined_in_is_refused(env, monkeypatch):
    monkeypatch.setattr(env.module, 'caller_is_scoped', lambda *a, **k: True)
    r = env.post(dry_run=True)
    assert r.status_code == 403 and env.pve.gets == [] and env.esxi.reads == []


def test_a_target_node_outside_the_cluster_is_refused(env):
    r = env.post(dry_run=True, target_node='pve9')
    assert r.status_code == 400 and 'not a node of the target cluster' in r.get_json()['error']


def test_a_start_needs_the_password_a_dry_run_does_not(env):
    r = env.post(esxi_password=None)
    assert r.status_code == 400 and 'esxi_password is required' in r.get_json()['error']
    assert env.post(dry_run=True, esxi_password=None).status_code == 200


# --------------------------------------------------------------------------- the run

def test_the_run_starts_width_guests_at_a_time_as_normal_migrations(env):
    r = env.post(vms=['vm-1', 'vm-2', 'vm-3'], width=2,
                 verify='full', start_after=False)
    run = _started(r)
    assert PW not in r.get_data(as_text=True)
    assert run['width'] == 2 and run['user'] == 'root' and run['mine'] is True
    assert run['settings']['target_storage'] == 'local-lvm' and 'esxi_password' not in run['settings']
    _wait(lambda: len(env.runner.names()) == 2, what='two migrations')
    time.sleep(0.15)
    assert env.runner.names() == ['web01', 'db01'], 'more than width at once'
    # each one is a normal migration: listed there, with the run's settings and the password
    listed = {m['id']: m for m in env.admin.get('/api/vmware/migrations').get_json()}
    items = {it['vm_id']: it for it in _view(env.admin, run['id'])['items']}
    for vm, name in (('vm-1', 'web01'), ('vm-2', 'db01')):
        t = env.runner.task(name)
        assert items[vm]['state'] == 'migrating' and items[vm]['migration_id'] == t.id
        assert listed[t.id]['vm_name'] == name and listed[t.id]['config']['verify'] == 'full'
        assert t.esxi_password == PW and 'esxi_password' not in t.config
        assert t.target_storage == 'local-lvm' and t.start_after is False and t.transfer_mode == 'offline'
        assert t.esxi_host == 'esx1.lab'
    assert [n['mac_address'] for n in env.runner.task('db01').selected_nics] == ['00:50:56:aa:00:00',
                                                                                 '00:50:56:aa:00:01']
    assert ebulk.get(run['id']).password() == PW, 'dropped while a guest is still to start'
    env.runner.end('web01')
    _wait(lambda: len(env.runner.names()) == 3, what='the third migration')
    # nothing left to start: the run drops the password while two still migrate
    _wait(lambda: ebulk.get(run['id']).password() is None, what='the password dropped')
    assert _view(env.admin, run['id'])['holds_password'] is False
    env.runner.end('db01', 'failed', 'qemu-img: read error')
    env.runner.end('app01')
    _wait(lambda: _over(run['id']), what='the end of the run')
    view = _view(env.admin, run['id'])
    assert view['state'] == 'done' and view['counts'] == {'done': 2, 'failed': 1}
    assert {it['vm_id']: (it['state'], it['note']) for it in view['items']} == {
        'vm-1': ('done', ''), 'vm-2': ('failed', 'qemu-img: read error'), 'vm-3': ('done', '')}


def test_the_next_guest_waits_until_the_one_before_has_its_vm_on_the_target(env, monkeypatch):
    env.runner.hold_planning = True
    run = _started(env.post(vms=['vm-1', 'vm-2', 'vm-3'], width=3))
    _wait(lambda: env.runner.names() == ['web01'])
    time.sleep(0.2)
    # two jobs asking /cluster/nextid at once get the same VMID
    assert env.runner.names() == ['web01']
    env.runner.task('web01').phase = 'pre_sync'
    _wait(lambda: env.runner.names() == ['web01', 'db01'])
    # a planning that hangs holds the others back for SETTLE_SECONDS, not for ever
    monkeypatch.setattr(ebulk, 'SETTLE_SECONDS', 0.1)
    _wait(lambda: env.runner.names() == ['web01', 'db01', 'app01'])
    assert _states(env.admin, run['id']) == {'vm-1': 'migrating', 'vm-2': 'migrating', 'vm-3': 'migrating'}


def test_each_guest_is_asked_again_right_before_it_starts(env):
    bob = env.seed.user('bob', role='user')
    for vm in ('vm-1', 'vm-2', 'vm-3'):
        env.seed.vm_acl('vmware:vw1', vm, ['bob'], inherit_role=False, permissions=['vmware.vm.migrate'])
    env.rbac.invalidate_vm_acls_cache()
    c = env.api.as_user(bob)
    run = _started(env.post(c, vms=['vm-1', 'vm-2', 'vm-3'], width=1))
    _wait(lambda: env.runner.names() == ['web01'])
    # while web01 migrates, the grant on db01 goes, and app01's NIC bridge leaves the node
    env.seed.vm_acl('vmware:vw1', 'vm-2', ['bob'], inherit_role=False, permissions=['vmware.vm.view'])
    env.rbac.invalidate_vm_acls_cache()
    env.pve.network = [n for n in env.pve.network if n['iface'] != 'vmbr0']
    env.runner.end('web01')
    _wait(lambda: _over(run['id']), what='the end of the run')
    assert env.runner.names() == ['web01']
    view = _view(env.admin, run['id'])
    notes = {it['vm_id']: (it['state'], it['note']) for it in view['items']}
    assert notes['vm-2'] == ('skipped', 'Permission denied: vmware.vm.migrate')
    assert notes['vm-3'][0] == 'failed' and 'no longer fits the target node' in notes['vm-3'][1]
    assert "'vmbr0' does not exist" in notes['vm-3'][1]


def test_an_account_switched_off_starts_nothing_more(env):
    env.seed.user('bob', role='user')
    c = env.api.as_user(env.seed.user('bob', role='user'))
    run = _started(env.post(c, vms=['vm-1', 'vm-2'], width=1))
    _wait(lambda: env.runner.names() == ['web01'])
    env.seed.user('bob', role='user', enabled=False)
    env.runner.end('web01')
    _wait(lambda: _over(run['id']))
    assert env.runner.names() == ['web01']
    item = next(it for it in _view(env.admin, run['id'])['items'] if it['vm_id'] == 'vm-2')
    assert item['state'] == 'skipped' and 'may no longer act' in item['note']


def test_a_revoked_api_token_starts_nothing_more(env):
    from pegaprox.utils.auth import create_api_token, revoke_api_token
    env.seed.user('ops', role='admin')
    tok = create_api_token('ops', 'automation', role='admin')
    headers = {'Authorization': f"Bearer {tok['token']}"}
    r = env.api.anon().post('/api/vmware/vw1/bulk-migrate', json=_body(vms=['vm-1', 'vm-2']), headers=headers)
    run = _started(r)
    _wait(lambda: env.runner.names() == ['web01'])
    tid = env.seed.db.conn.execute('SELECT id FROM api_tokens WHERE username = ?', ('ops',)).fetchone()[0]
    assert revoke_api_token(tid, 'ops')
    env.runner.end('web01')
    _wait(lambda: _over(run['id']))
    assert env.runner.names() == ['web01']
    assert next(it for it in ebulk.get(run['id']).items_copy() if it['vm_id'] == 'vm-2')['state'] == 'skipped'


def test_cancel_starts_nothing_more_drops_the_password_and_lets_the_running_one_finish(env):
    env.runner.hold_planning = True
    run = _started(env.post(vms=['vm-1', 'vm-2', 'vm-3'], width=1))
    _wait(lambda: env.runner.names() == ['web01'])
    r = env.admin.post(f"/api/vmware/bulk-migrate/{run['id']}/cancel")
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['run']['may_cancel'] is False
    assert ebulk.get(run['id']).password() is None
    assert env.admin.post(f"/api/vmware/bulk-migrate/{run['id']}/cancel").status_code == 409
    _wait(lambda: _states(env.admin, run['id']) == {'vm-1': 'migrating', 'vm-2': 'cancelled', 'vm-3': 'cancelled'})
    # the migration that started is not touched and the run follows it to its end
    assert env.runner.task('web01').status == 'running' and ebulk.get(run['id']).state == 'running'
    env.runner.task('web01').phase = 'pre_sync'
    time.sleep(0.15)
    assert env.runner.names() == ['web01']
    env.runner.end('web01')
    _wait(lambda: _over(run['id']))
    view = _view(env.admin, run['id'])
    assert view['state'] == 'cancelled' and view['cancelled_by'] == 'root'
    assert view['counts'] == {'done': 1, 'cancelled': 2}
    (line,) = _audit(env.seed, 'vmware.bulk_migration.cancelled')
    assert '2 guest(s) not started' in line[2]


def test_only_who_started_it_and_an_admin_see_or_cancel_a_run(env):
    bob = env.api.as_user(env.seed.user('bob', role='user'))
    carol = env.api.as_user(env.seed.user('carol', role='user'))
    ann = env.api.as_user(env.seed.user('ann', role='admin'))
    env.runner.hold_planning = True
    run = _started(env.post(bob, vms=['vm-1', 'vm-2'], width=1))
    assert carol.get(f"/api/vmware/bulk-migrate/{run['id']}").status_code == 404
    assert carol.post(f"/api/vmware/bulk-migrate/{run['id']}/cancel").status_code == 404
    assert carol.get('/api/vmware/bulk-migrate').get_json() == {'runs': []}
    assert [x['id'] for x in bob.get('/api/vmware/bulk-migrate').get_json()['runs']] == [run['id']]
    assert [x['id'] for x in ann.get('/api/vmware/bulk-migrate?vmware_id=vw1').get_json()['runs']] == [run['id']]
    assert ann.get('/api/vmware/bulk-migrate?vmware_id=other').get_json() == {'runs': []}
    assert 'items' not in bob.get('/api/vmware/bulk-migrate').get_json()['runs'][0]
    assert _view(ann, run['id'])['mine'] is False
    assert ann.post(f"/api/vmware/bulk-migrate/{run['id']}/cancel").status_code == 200
    assert ebulk.get(run['id']).cancelled_by == 'ann'


def test_runs_per_server_and_per_user_are_capped(env, monkeypatch):
    env.runner.hold_planning = True
    monkeypatch.setattr(ebulk, 'RUNNING_PER_USER', 1)
    _started(env.post(vms=['vm-1']))
    r = env.post(vms=['vm-2'])
    assert r.status_code == 409 and 'You have 1 bulk migrations running' in r.get_json()['error']
    monkeypatch.setattr(ebulk, 'RUNNING_PER_USER', 5)
    monkeypatch.setattr(ebulk, 'RUNNING_PER_SERVER', 1)
    bob = env.api.as_user(env.seed.user('bob', role='user'))
    r = env.post(bob, vms=['vm-3'])
    assert r.status_code == 409 and 'from this ESXi server already' in r.get_json()['error']
    # a dry run is a check, not a run
    assert env.post(bob, vms=['vm-3'], dry_run=True).status_code == 200


def test_the_password_shows_up_in_no_answer_no_audit_line_and_no_log(env, caplog):
    caplog.set_level(logging.DEBUG)
    r = env.post(vms=['vm-1', 'vm-2'], width=2)
    run = _started(r)
    texts = [r.get_data(as_text=True)]
    _wait(lambda: len(env.runner.names()) == 2)
    texts.append(env.admin.get(f"/api/vmware/bulk-migrate/{run['id']}").get_data(as_text=True))
    texts.append(env.admin.get('/api/vmware/bulk-migrate').get_data(as_text=True))
    texts.append(env.admin.get('/api/vmware/migrations').get_data(as_text=True))
    env.runner.end_all()
    _wait(lambda: _over(run['id']))
    texts.append(env.admin.get(f"/api/vmware/bulk-migrate/{run['id']}").get_data(as_text=True))
    texts += [' '.join(map(str, row)) for row in _audit(env.seed)]
    texts += [rec.getMessage() for rec in caplog.records]
    texts.append(repr(ebulk.get(run['id'])) + json.dumps(ebulk.get(run['id']).view(ebulk.get(run['id']).items_copy())))
    assert not [t for t in texts if PW in t]
    assert ebulk.get(run['id'])._password is None
    starts = _audit(env.seed, 'vmware.migration.started')
    assert len(starts) == 2 and all(f"(bulk run {run['id']}" in s[2] for s in starts)
    (begin,) = _audit(env.seed, 'vmware.bulk_migration.started')
    assert 'web01, db01' in begin[2] and '2 at a time' in begin[2]
    (end,) = _audit(env.seed, 'vmware.bulk_migration.finished')
    assert 'done: done 2' in end[2] or 'done 2' in end[2]


# --------------------------------------------------------------------------- the worker alone

class Fleet:
    """starter and lookup for core/esxi_bulk.py without the API: a started guest is a task
    whose status the test sets"""

    def __init__(self, fail=(), boom=()):
        self.tasks, self.order, self.fail, self.boom = {}, [], set(fail), set(boom)
        self.passwords = []

    def start(self, run, item):
        if item['vm_id'] in self.boom:
            raise RuntimeError(f'secret detail {PW}')
        if item['vm_id'] in self.fail:
            return {'state': 'failed', 'note': 'The plan no longer fits the target node: x'}
        self.passwords.append(run.password())
        mid = f"m-{item['vm_id']}"
        self.tasks[mid] = types.SimpleNamespace(status='running', phase='pre_sync', progress=5, proxmox_vmid=101,
                                                error=None)
        self.order.append(item['vm_id'])
        return {'migration_id': mid, 'name': item['name']}

    def lookup(self, mid):
        return self.tasks.get(mid)

    def end(self, vm_id, status='completed', error=None):
        t = self.tasks[f'm-{vm_id}']
        t.status, t.error = status, error


@pytest.fixture
def core(monkeypatch):
    import pegaprox.globals as g
    from pegaprox.core import ha
    monkeypatch.setattr(ebulk, 'POLL_SECONDS', 0.01)
    monkeypatch.setitem(g.vmware_managers, 'vw1', object())
    monkeypatch.setitem(g.cluster_managers, 'pve-cl', object())
    monkeypatch.setattr('pegaprox.utils.audit.log_audit', lambda *a, **k: None)
    active = {'on': True}
    monkeypatch.setattr(ha, 'is_active', lambda: active['on'])
    ebulk.reset_for_tests()
    runs = []

    def make(n=3, width=1, fleet=None):
        fleet = fleet or Fleet()
        items = [ebulk.new_item(f'vm-{i}', f'g{i}') for i in range(n)]
        run = ebulk.EsxiBulkRun('vw1', 'esx01', 'root', {}, '127.0.0.1',
                                {'target_cluster': 'pve-cl', 'target_node': 'pve1', 'esxi_password': 'x'},
                                width, items, PW)
        ebulk.register(run)
        t = threading.Thread(target=ebulk.work, args=(run, fleet.start, fleet.lookup), daemon=True)
        t.start()
        runs.append((run, fleet, t))
        return run, fleet

    yield types.SimpleNamespace(make=make, active=active)
    for run, fleet, t in runs:
        ebulk.cancel(run, 'teardown')
        for task in fleet.tasks.values():
            task.status = 'completed'
        t.join(5)
    ebulk.reset_for_tests()


def _items(run):
    return {it['vm_id']: it['state'] for it in run.items_copy()}


def test_the_settings_of_a_run_never_hold_the_password(core):
    run, _fleet = core.make(n=1)
    assert 'esxi_password' not in run.settings


def test_width_holds_and_an_ending_migration_lets_the_next_one_in(core):
    run, fleet = core.make(n=5, width=2)
    _wait(lambda: fleet.order == ['vm-0', 'vm-1'])
    time.sleep(0.1)
    assert fleet.order == ['vm-0', 'vm-1']
    fleet.end('vm-1')
    _wait(lambda: fleet.order == ['vm-0', 'vm-1', 'vm-2'])
    assert _items(run)['vm-1'] == 'done'
    fleet.end('vm-0', 'failed', 'boom')
    fleet.end('vm-2', 'cancelled')
    _wait(lambda: len(fleet.order) == 5)
    fleet.end('vm-3')
    fleet.tasks.pop('m-vm-4')      # the migration vanished from the registry
    _wait(lambda: run.state != 'running')
    assert _items(run) == {'vm-0': 'failed', 'vm-1': 'done', 'vm-2': 'cancelled', 'vm-3': 'done',
                           'vm-4': 'unknown'}
    assert run.state == 'done' and run.password() is None
    by = {it['vm_id']: it for it in run.items_copy()}
    assert by['vm-0']['note'] == 'boom' and by['vm-1']['proxmox_vmid'] == 101 and by['vm-1']['progress'] == 5
    assert 'left running' in by['vm-2']['note']
    assert all(p == PW for p in fleet.passwords)


def test_a_guest_that_does_not_start_does_not_stop_the_others(core):
    run, fleet = core.make(n=3, width=1, fleet=Fleet(fail={'vm-0'}, boom={'vm-1'}))
    _wait(lambda: fleet.order == ['vm-2'])
    fleet.end('vm-2')
    _wait(lambda: run.state != 'running')
    by = {it['vm_id']: it for it in run.items_copy()}
    assert by['vm-0']['state'] == 'failed' and 'no longer fits' in by['vm-0']['note']
    # an exception says only where to look, never what it carried
    assert by['vm-1'] == {**by['vm-1'], 'state': 'failed',
                          'note': 'The migration could not be started - see the PegaProx log'}
    assert by['vm-2']['state'] == 'done'


def test_the_password_goes_once_the_last_guest_started(core):
    run, fleet = core.make(n=2, width=2)
    _wait(lambda: len(fleet.order) == 2)
    _wait(lambda: run.password() is None, what='the password dropped')
    assert run.state == 'running'
    assert run.view(run.items_copy())['holds_password'] is False


def test_a_cancel_drops_the_password_at_once_and_ends_what_waits(core):
    run, fleet = core.make(n=3, width=1)
    _wait(lambda: fleet.order == ['vm-0'])
    assert ebulk.cancel(run, 'root') is True
    assert run.password() is None
    assert ebulk.cancel(run, 'root') is False
    _wait(lambda: _items(run) == {'vm-0': 'migrating', 'vm-1': 'cancelled', 'vm-2': 'cancelled'})
    fleet.end('vm-0')
    _wait(lambda: run.state != 'running')
    assert run.state == 'cancelled' and fleet.order == ['vm-0']
    assert ebulk.cancel(run, 'root') is False


def test_a_standby_starts_nothing_more(core):
    run, fleet = core.make(n=3, width=1)
    _wait(lambda: fleet.order == ['vm-0'])
    core.active['on'] = False
    _wait(lambda: run.state != 'running')
    assert run.state == 'stopped' and 'standby' in run.reason
    assert _items(run) == {'vm-0': 'unknown', 'vm-1': 'cancelled', 'vm-2': 'cancelled'}
    assert run.password() is None and fleet.order == ['vm-0']


def test_the_registry_caps_running_runs_and_forgets_old_ones(monkeypatch):
    ebulk.reset_for_tests()
    monkeypatch.setattr(ebulk, 'RUNNING_PER_SERVER', 2)
    monkeypatch.setattr(ebulk, 'RUNNING_PER_USER', 2)

    # each run its own guest: one guest is in one run at a time (test_esxi_followups.py)
    def mk(server='vw1', user='root', vm='vm-1'):
        return ebulk.EsxiBulkRun(server, 's', user, {}, '', {}, 1, [ebulk.new_item(vm)], PW)
    a, b = ebulk.register(mk()), ebulk.register(mk(user='bob', vm='vm-2'))
    with pytest.raises(ebulk.TooMany):
        ebulk.register(mk(user='carol', vm='vm-3'))
    assert ebulk.room('vw2', 'carol') is None
    ebulk.register(mk(server='vw2'))
    with pytest.raises(ebulk.TooMany):
        ebulk.register(mk(server='vw3'))     # root has two going
    a.state, a.finished = 'done', time.time() - ebulk.KEEP_SECONDS - 1
    assert ebulk.get(a.id) is a
    assert a not in ebulk.runs() and ebulk.get(a.id) is None
    assert ebulk.busy_vm_ids('vw1') == {'vm-2'}
    b.items[0]['state'] = 'done'
    assert ebulk.busy_vm_ids('vw1') == set()
    ebulk.reset_for_tests()


def test_the_caller_is_judged_as_the_account_stands_now(api, seed, monkeypatch):
    import pegaprox.utils.auth as auth
    seed.user('bob', role='user')
    run = ebulk.EsxiBulkRun('vw1', 's', 'bob', {}, '', {}, 1, [], PW)
    assert ebulk.caller(run)['username'] == 'bob'
    seed.user('bob', role='user', enabled=False)
    assert ebulk.caller(run) is None
    gone = ebulk.EsxiBulkRun('vw1', 's', 'nobody', {}, '', {}, 1, [], PW)
    assert ebulk.caller(gone) is None
    seed.user('ops', role='admin')
    tok = ebulk.EsxiBulkRun('vw1', 's', 'ops', {'api_token': True, 'role': 'viewer', 'token_id': 7}, '', {}, 1, [], PW)
    for alive, want in ((True, True), (False, False), (None, False)):
        monkeypatch.setattr(auth, 'api_token_alive', lambda tid, a=alive: a)
        assert (ebulk.caller(tok) is not None) is want, alive
    # a token acts with its own role, not its owner's
    monkeypatch.setattr(auth, 'api_token_alive', lambda tid: True)
    assert ebulk.caller(tok)['effective_role'] == 'viewer'


def test_the_single_route_and_the_bulk_check_share_one_body_validator():
    import inspect
    import pegaprox.api.vmware as vmwareapi
    single = inspect.getsource(vmwareapi.start_vmware_migration)
    assert '_migrate_body_refusal(vmware_id, data, dry_run)' in single
    assert '_migrate_body_refusal(vmware_id, s, dry_run)' in inspect.getsource(vmwareapi._bulk_settings)
    assert '_migrate_body_refusal(run.vmware_id, body, False)' in inspect.getsource(vmwareapi._bulk_start_item)
    assert chr(0x2014) not in inspect.getsource(ebulk)


# --------------------------------------------------------------------------- the dialog, rendered

from test_ha_ui import browser  # noqa: E402,F401 (a fixture: headless Chromium, skips without Playwright)

EVMS = [{'vm': 'vm-1', 'name': 'legacy01', 'power_state': 'POWERED_ON', 'cpu_count': 2,
         'memory_size_MiB': 4096, 'guest_OS': 'UBUNTU_64', 'host': 'esx01.lab'},
        {'vm': 'vm-2', 'name': 'legacy02', 'power_state': 'POWERED_OFF', 'cpu_count': 1,
         'memory_size_MiB': 2048, 'guest_OS': 'UBUNTU_64', 'host': 'esx01.lab'}]
PLAN = {'source': {'name': 'legacy01', 'nics': [], 'disks': []}, 'method': 'test', 'requirements': [],
        'targets': [{'cluster_id': 'c1', 'cluster_name': 'Testi', 'nodes': ['pve1'],
                     'storages': {'pve1': ['local-lvm', 'fast-lvm']}}]}


def _item(vm_id, name, nics=1, disks=1, errors=()):
    return {'vm_id': vm_id, 'name': name, 'ok': not errors, 'errors': list(errors), 'warnings': [],
            'custom_network': False, 'custom_storage': False, 'verify': 'sample', 'transfer_mode': 'vmkfstools_clone',
            'nics': [{'index': i, 'net': f'net{i}', 'label': f'Network adapter {i + 1}', 'source_network': f'VM Net {i}',
                      'skip': False, 'bridge': 'vmbr0', 'vlan': None} for i in range(nics)],
            'disks': [{'index': i, 'label': f'Hard disk {i + 1}', 'size_bytes': 8 * GiB, 'boot': i == 0, 'skip': False,
                       'storage': 'local-lvm'} for i in range(disks)],
            'storages': []}


CHECK = {'dry_run': True, 'ok': True, 'errors': [], 'warnings': [], 'width': 2,
         'items': [_item('vm-1', 'legacy01'), _item('vm-2', 'legacy02', nics=2, disks=2)],
         'storages': [{'storage': 'local-lvm', 'type': 'lvmthin', 'needed_bytes': 24 * GiB,
                       'avail_bytes': 500 * GiB, 'guests': 2, 'ok': True}],
         'target': {'cluster': 'c1', 'node': 'pve1', 'storage': 'local-lvm'},
         'available': {'bridges': [{'name': 'vmbr0', 'kind': 'bridge'}, {'name': 'vmbr1', 'kind': 'bridge'},
                                   {'name': 'dmz10', 'kind': 'vnet'}],
                       'storages': [{'storage': 'local-lvm', 'type': 'lvmthin', 'avail_bytes': 500 * GiB},
                                    {'storage': 'fast-lvm', 'type': 'lvm', 'avail_bytes': 100 * GiB}]}}
RUN = {'id': 'r1', 'vmware_id': 'v1', 'vmware_name': 'esx01', 'user': 'admin', 'mine': True, 'width': 2,
       'settings': {'target_cluster': 'c1', 'target_node': 'pve1', 'target_storage': 'local-lvm'},
       'state': 'running', 'reason': '', 'cancelled_by': '', 'holds_password': True, 'created': 1760000000,
       'finished': None, 'total': 2, 'counts': {'migrating': 1, 'wait': 1}, 'current': ['vm-1'], 'may_cancel': True,
       'items': [{'vm_id': 'vm-1', 'name': 'legacy01', 'state': 'migrating', 'note': '', 'migration_id': 'ab12cd34',
                  'proxmox_vmid': 120, 'phase': 'awaiting_confirmation', 'progress': 80, 'began': 1760000001,
                  'ended': None, 'custom_network': False, 'custom_storage': False},
                 {'vm_id': 'vm-2', 'name': 'legacy02', 'state': 'wait', 'note': '', 'migration_id': None,
                  'proxmox_vmid': None, 'phase': None, 'progress': 0, 'began': None, 'ended': None,
                  'custom_network': True, 'custom_storage': True}]}
BULK = '/api/vmware/v1/bulk-migrate'


@pytest.fixture
def dialog(browser):
    from test_ha_ui import _App, _FakeServer, ESXI_READS, SSE_TOKEN
    apps = []

    def _open(check=None, role='standalone'):
        extra = {**ESXI_READS, **SSE_TOKEN,
                 ('GET', '/api/vmware/v1/vms'): (200, EVMS),
                 ('GET', '/api/vmware/v1/vms/vm-1/migration-plan'): (200, PLAN),
                 ('POST', BULK): (200, check or CHECK),
                 ('GET', '/api/vmware/bulk-migrate/r1'): (200, {'run': RUN}),
                 ('POST', '/api/vmware/bulk-migrate/r1/cancel'): (200, {'run': dict(RUN, may_cancel=False,
                                                                                    cancelled_by='admin')}),
                 ('POST', '/api/vmware/migrations/ab12cd34/confirm-cutover'): (200, {'message': 'ok'}),
                 ('GET', '/api/vmware/migrations'): (200, [])}
        app = _App(browser, _FakeServer(role=role, layout='modern', extra=extra))
        apps.append(app)
        page = app.page
        page.on('dialog', lambda d: d.accept())
        page.get_by_text('esx01').first.click()
        page.get_by_text('legacy02').first.wait_for(timeout=8000)
        return app, page
    yield _open
    for app in apps:
        app.ctx.close()


def _bodies(app):
    return app.server.bodies.get(BULK, [])


def _wait_bodies(app, page, n):
    for _ in range(50):
        if len(_bodies(app)) >= n:
            break
        page.wait_for_timeout(100)
    assert len(_bodies(app)) >= n, _bodies(app)


def _pick_targets(page):
    dlg = page.locator('[data-esxi-bulk]')
    dlg.locator('select', has=page.locator('option', has_text='Testi')).select_option('c1')
    dlg.locator('select', has=page.locator('option', has_text='pve1')).select_option('pve1')
    dlg.locator('select', has=page.locator('option', has_text='fast-lvm')).select_option('local-lvm')
    return dlg


def test_runtime_pick_guests_check_give_one_its_own_network_review_and_start_what_was_checked(dialog):
    app, page = dialog()
    page.locator('[data-esxi-bulk-pick="vm-1"]').check()
    page.locator('[data-esxi-bulk-pick="vm-2"]').check()
    page.get_by_text('Selected: 2').first.wait_for(timeout=2000)
    page.locator('[data-esxi-bulk-bar] button', has_text='Migrate to Proxmox').click()
    dlg = page.locator('[data-esxi-bulk]')
    dlg.wait_for(timeout=3000)
    dlg.locator('option', has_text='Testi').first.wait_for(state='attached', timeout=5000)
    _pick_targets(page)
    dlg.locator('select').nth(3).select_option('3')      # migrations at once
    dlg.locator('input[type="password"]').fill('pw-1')
    dlg.locator('button', has_text='Check the guests').click()
    _wait_bodies(app, page, 1)
    first = _bodies(app)[0]
    assert first['dry_run'] is True and 'esxi_password' not in first
    assert first['vms'] == ['vm-1', 'vm-2'] and first['width'] == 3
    assert (first['target_cluster'], first['target_node'], first['target_storage']) == ('c1', 'pve1', 'local-lvm')

    # the guests step: legacy02 gets its own bridge on its second NIC and leaves its second disk behind
    page.locator('[data-esxi-bulk-guest="vm-2"] button').first.click()
    guest = page.locator('[data-esxi-bulk-guest="vm-2"]')
    guest.locator('select', has=page.locator('option', has_text='dmz10 (vnet)')).nth(1).select_option('vmbr1')
    skips = guest.locator('label', has_text='Skip')
    assert skips.count() == 3                     # two NICs, the second disk (the boot disk has none)
    skips.nth(2).locator('input').check()
    page.get_by_text('own network or storage').first.wait_for(timeout=2000)
    dlg.locator('button', has_text='Review and start').click()
    _wait_bodies(app, page, 2)
    review = _bodies(app)[-1]
    assert review['dry_run'] is True and 'esxi_password' not in review
    assert review['vms'] == ['vm-1', {'vm_id': 'vm-2',
                                      'nic_map': [{'index': 0, 'skip': False}, {'index': 1, 'skip': False, 'bridge': 'vmbr1'}],
                                      'disk_map': [{'index': 0, 'skip': False}, {'index': 1, 'skip': True}]}]
    page.get_by_text('Every guest fits the target node.').first.wait_for(timeout=5000)
    start = dlg.locator('[data-esxi-bulk-start]')
    assert start.is_enabled()

    app.server.extra[('POST', BULK)] = (202, {'run': RUN})
    start.click()
    _wait_bodies(app, page, 3)
    sent = dict(_bodies(app)[-1])
    assert sent.pop('esxi_password') == 'pw-1'
    expect = dict(review)
    expect.pop('dry_run')
    assert sent == expect, 'Start sent something other than what the review checked'

    # the run: a line per guest, the switchover gate of the one waiting there, and cancel
    page.locator('[data-esxi-bulk-item="vm-1"]').get_by_text('Awaiting Confirmation').wait_for(timeout=5000)
    page.locator('[data-esxi-bulk-item="vm-2"]').get_by_text('waiting').wait_for(timeout=2000)
    page.get_by_text('Migration ab12cd34 / VM 120').first.wait_for(timeout=2000)
    page.locator('[data-esxi-bulk-item="vm-1"] button', has_text='Commit switchover now').click()
    for _ in range(30):
        if ('POST', '/api/vmware/migrations/ab12cd34/confirm-cutover') in app.server.calls:
            break
        page.wait_for_timeout(100)
    assert ('POST', '/api/vmware/migrations/ab12cd34/confirm-cutover') in app.server.calls
    page.locator('[data-esxi-bulk-cancel]').click()
    page.get_by_text('Cancelled by admin').first.wait_for(timeout=5000)
    assert ('POST', '/api/vmware/bulk-migrate/r1/cancel') in app.server.calls
    assert not app.errors, app.errors


def test_runtime_a_guest_that_does_not_fit_keeps_start_off_until_it_is_left_out_and_checked_again(dialog):
    bad = dict(CHECK, ok=False, items=[_item('vm-1', 'legacy01'),
                                       _item('vm-2', 'legacy02', errors=["NIC 1: bridge 'vmbr0' does not exist on the target node"])])
    app, page = dialog(check=bad)
    page.locator('[data-esxi-bulk-all]').check()
    page.get_by_text('Selected: 2').first.wait_for(timeout=2000)
    page.locator('[data-esxi-bulk-bar] button', has_text='Migrate to Proxmox').click()
    dlg = page.locator('[data-esxi-bulk]')
    dlg.locator('option', has_text='Testi').first.wait_for(state='attached', timeout=5000)
    _pick_targets(page)
    dlg.locator('input[type="password"]').fill('pw-1')
    dlg.locator('button', has_text='Check the guests').click()
    _wait_bodies(app, page, 1)
    page.get_by_text('Problems: 1').first.wait_for(timeout=3000)
    dlg.locator('button', has_text='Review and start').click()
    page.get_by_text('Not every guest fits').first.wait_for(timeout=3000)
    page.locator('[data-esxi-bulk-review="vm-2"]').get_by_text("bridge 'vmbr0' does not exist").wait_for(timeout=2000)
    start = dlg.locator('[data-esxi-bulk-start]')
    assert start.is_disabled()
    n = len(_bodies(app))
    page.locator('[data-esxi-bulk-review="vm-2"] button', has_text='Leave out').click()
    # leaving one out is another request: the old check no longer counts
    page.get_by_text('The settings changed since this check').first.wait_for(timeout=2000)
    assert start.is_disabled() and start.inner_text().strip() == 'Start migrations (1)'
    app.server.extra[('POST', BULK)] = (200, dict(CHECK, items=[_item('vm-1', 'legacy01')]))
    dlg.locator('button', has_text='Check again').click()
    _wait_bodies(app, page, n + 1)
    assert _bodies(app)[-1]['vms'] == ['vm-1']
    page.get_by_text('Every guest fits the target node.').first.wait_for(timeout=3000)
    assert start.is_enabled()
    assert not [b for b in _bodies(app) if not b.get('dry_run')], 'started without a click'
    assert not app.errors, app.errors


def test_runtime_a_standby_offers_no_selection(dialog):
    app, page = dialog(role='standby')
    assert page.locator('[data-esxi-bulk-pick]').count() == 0
    assert page.locator('[data-esxi-bulk-all]').count() == 0
    assert not app.errors, app.errors


def test_what_acts_in_the_dialog_stays_on_the_active_and_the_bundle_was_rebuilt():
    import os
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, 'web', 'src', 'dashboard.js'), encoding='utf-8') as fh:
        dash = fh.read()
    comp = dash[dash.index('function EsxiBulkMigrate('):dash.index('function EsxiBulkRuns(')]
    # a standby of an HA group starts, cancels and confirms nothing from here
    assert "if (haReadOnly || !current || !check?.ok || !password) return;" in comp
    assert "if (haReadOnly || !run || !confirm(t('esxiBulkCancelConfirm'))) return;" in comp
    assert comp.count('if (haReadOnly) return;') == 1
    for button in ('data-esxi-bulk-start', 'data-esxi-bulk-cancel', "cutover(it.migration_id, 'confirm-cutover')"):
        at = comp.index(button)
        assert '!haReadOnly && (' in comp[max(0, at - 700):at], button
    # the password goes to the start only, never into a check
    assert "if (dryRun) body.dry_run = true;\n                else body.esxi_password = password;" in comp
    assert chr(0x2014) not in comp
    with open(os.path.join(root, 'web', 'index.html'), encoding='utf-8') as fh:
        bundle = fh.read()
    for needle in ('function EsxiBulkMigrate(', 'function EsxiBulkRuns(', 'esxiBulkSelected', 'data-esxi-bulk-pick'):
        assert needle in bundle, needle
