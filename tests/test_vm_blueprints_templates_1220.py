"""Blueprints from an existing PVE template, Windows among them (#1220).

The template library holds Linux cloud images only. A blueprint can also start from a
template already on a cluster: it is picked per cluster at the first deploy there and
remembered. For a Windows template PVE writes a configdrive2 for cloudbase-init, which
signs in with its own Admin user: PVE drops the Cloud-Init user and the search domains
for Windows and keeps the password in plain text in the VM config. So a Windows blueprint
keeps neither user nor keys, each deploy sends a password, and the node has to run a
qemu-server that does Windows Cloud-Init (8.2.4).

The clone is a new guest under the caller's VMID; the template is only read. So the
caller has to be allowed to clone that template, a confined caller places nothing, and
whose VMID range the template sits in does not matter.

Every deploy also checks that the bridges of the blueprint's NICs exist on the node (or
are SDN VNets) before anything is cloned, and the recent deploys can be read across all
the clusters a caller may see.

MK Nov 2026
"""
import json
import os
import re
import sys
import types
from unittest.mock import MagicMock

import pytest

import pegaprox.api.blueprints as bpmod
from pegaprox.core import ha

KEY = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl ops@lab'

LINUX_T = {
    'name': 'debian from tpl', 'source_kind': 'template', 'os': 'linux', 'cores': 2, 'memory': 2048,
    'disk_gb': 20, 'nics': [{'bridge': 'vmbr0'}], 'ciuser': 'ops', 'sshkeys': KEY, 'ip_mode': 'dhcp',
}
WIN_T = {
    'name': 'win server', 'source_kind': 'template', 'os': 'windows', 'cores': 4, 'memory': 8192,
    'disk_gb': 80, 'nics': [], 'ciuser': 'admin', 'sshkeys': KEY, 'searchdomain': 'corp.example',
    'ciupgrade': False, 'ip_mode': 'dhcp', 'nameserver': '10.0.0.53',
}


def _linux_cfg(vmid, storage='local-lvm', cloudinit=True, size='8G'):
    cfg = {'ostype': 'l26', 'boot': 'order=scsi0;ide2;net0', 'template': 1,
           'scsi0': f'{storage}:base-{vmid}-disk-0,size={size}', 'net0': 'virtio=AA:BB,bridge=vmbr0'}
    if cloudinit:
        cfg['ide2'] = f'{storage}:vm-{vmid}-cloudinit,media=cdrom'
    return cfg


def _win_cfg(vmid, storage='ceph', ostype='win11'):
    return {'ostype': ostype, 'boot': 'order=ide0;virtio0;net0', 'template': 1,
            'ide0': 'none,media=cdrom', 'virtio0': f'{storage}:base-{vmid}-disk-0,size=60G',
            'efidisk0': f'{storage}:base-{vmid}-disk-1,size=4M',
            'tpmstate0': f'{storage}:base-{vmid}-disk-2,size=4M,version=v2.0',
            'ide2': f'{storage}:vm-{vmid}-cloudinit,media=cdrom', 'net0': 'virtio,bridge=vmbr0'}


class _Resp:
    def __init__(self, code=200, data=None, text=''):
        self.status_code, self._data, self.text = code, data, text

    def json(self):
        return {'data': self._data}


_OURS = os.path.join('pegaprox', 'api', 'blueprints.py')


def _asked_by_blueprints():
    # the app's background loops read through the same fake; only what the blueprint
    # code asks counts (its config reads run in pool greenlets, its frames are on their stack)
    f = sys._getframe(2)
    while f is not None:
        if f.f_code.co_filename.endswith(_OURS):
            return True
        f = f.f_back
    return False


def _res(vmid, node, template=1, kind='qemu'):
    return {'vmid': vmid, 'node': node, 'type': kind, 'template': template, 'name': f'tpl-{vmid}'}


def _cluster(resources=(), configs=None, shared=('ceph',), bridges=('vmbr0', 'vmbr1'), vnets=(),
             qemu_server='8.3.0', qemu_candidate='9.9.9', fail=(), nodes=('pve1', 'pve2')):
    """A PVE cluster that answers the reads a blueprint makes, by path; `fail` names the
    paths (by their end) that answer 403. /apt/versions answers as PVE does: OldVersion is
    the installed qemu-server (none when it is not installed), Version apt's candidate."""
    m = MagicMock(name='mgr')
    m.cluster_type = 'proxmox'
    m.host, m.api_port = '10.0.0.1', 8006
    m.config = types.SimpleNamespace(name='lab')
    m.nodes = {n: {'node': n, 'status': 'online'} for n in nodes}
    m.get_vm_resources.return_value = list(resources)
    m.get_next_vmid.return_value = {'success': True, 'vmid': 100}
    configs = configs or {}
    m.reads = []

    def get(url, **kw):
        path = url.split('/api2/json', 1)[1]
        if _asked_by_blueprints():
            m.reads.append(path)
        if any(path.endswith(f) for f in fail):
            return _Resp(403, text='Permission check failed')
        if path == '/storage':
            return _Resp(data=[{'storage': s, 'shared': 1} for s in shared]
                         + [{'storage': 'local-lvm', 'shared': 0}, {'storage': 'local', 'shared': 0}])
        if path.endswith('/network'):
            return _Resp(data=[{'iface': b, 'type': 'bridge'} for b in bridges]
                         + [{'iface': 'eno1', 'type': 'eth'}, {'iface': 'bond0', 'type': 'bond'}])
        if path == '/cluster/sdn/vnets':
            return _Resp(data=[{'vnet': v, 'zone': 'z1'} for v in vnets])
        if path.endswith('/apt/versions'):
            qs = {'Package': 'qemu-server', 'Version': qemu_candidate, 'CurrentState': 'NotInstalled'}
            if qemu_server:
                qs.update(OldVersion=qemu_server, CurrentState='Installed')
            return _Resp(data=[{'Package': 'pve-manager', 'Version': '8.3.0', 'OldVersion': '8.3.0'}, qs])
        cm = re.search(r'/qemu/(\d+)/config$', path)
        if cm and int(cm.group(1)) in configs:
            return _Resp(data=configs[int(cm.group(1))])
        return _Resp(500, text='no such thing')
    m._api_get.side_effect = get
    return m


@pytest.fixture
def admin(api, seed):
    return api.as_user(seed.user('root', role='admin'))


@pytest.fixture
def no_thread(monkeypatch):
    started = []

    class _T:
        def __init__(self, target=None, args=(), **kw):
            self.args = args

        def start(self):
            started.append(self.args)
    monkeypatch.setattr(bpmod.threading, 'Thread', _T)
    return started


def _create(client, body, **over):
    return client.post('/api/blueprints', json=dict(body, **over))


def _standard():
    """pve1 and pve2; Linux templates on pve1 (local), on pve2 (local, and on ceph), one
    without a Cloud-Init drive, a Windows one on ceph; a VM and a container template that
    are no candidates."""
    res = [_res(9100, 'pve1'), _res(9101, 'pve2'), _res(9102, 'pve2'), _res(9103, 'pve1'),
           _res(9200, 'pve2'), _res(9300, 'pve1', template=0), _res(9400, 'pve1', kind='lxc')]
    cfgs = {9100: _linux_cfg(9100), 9101: _linux_cfg(9101), 9102: _linux_cfg(9102, storage='ceph'),
            9103: _linux_cfg(9103, cloudinit=False), 9200: _win_cfg(9200),
            9300: _linux_cfg(9300)}
    return res, cfgs


@pytest.fixture
def lab(api, admin):
    res, cfgs = _standard()
    m = api.set_manager('c1', _cluster(res, cfgs))
    linux = _create(admin, LINUX_T).get_json()['blueprint']['id']
    win = _create(admin, WIN_T).get_json()['blueprint']['id']
    return types.SimpleNamespace(mgr=m, linux=linux, win=win, admin=admin)


def _deploy(client, bid, **over):
    body = dict({'cluster_id': 'c1', 'node': 'pve1', 'storage': 'local-lvm', 'name': 'web-01'}, **over)
    return client.post(f'/api/blueprints/{bid}/deploy', json=body)


def _maps(db):
    return [tuple(r) for r in db.conn.execute(
        'SELECT blueprint_id, cluster_id, vmid, updated_by FROM blueprint_templates ORDER BY cluster_id').fetchall()]


# --- saving -----------------------------------------------------------------------------

def test_a_windows_template_blueprint_keeps_nothing_windows_would_drop(admin):
    r = _create(admin, WIN_T, template_id='debian-12')
    assert r.status_code == 201, r.get_json()
    got = r.get_json()['blueprint']
    assert (got['source_kind'], got['os'], got['template_id'], got['templates']) == ('template', 'windows', '', {})
    # cloudbase-init has its own Admin user, PVE drops the search domains for Windows
    assert (got['ciuser'], got['sshkeys'], got['searchdomain'], got['ciupgrade']) == ('', '', '', True)
    assert got['nics'] == [] and got['nameserver'] == '10.0.0.53'
    assert got['template_missing'] is False and got['template_name'] == ''


def test_a_linux_template_blueprint_keeps_its_cloud_init(admin):
    got = _create(admin, LINUX_T).get_json()['blueprint']
    assert (got['source_kind'], got['os'], got['ciuser'], got['sshkeys']) == ('template', 'linux', 'ops', KEY)


def test_a_library_blueprint_is_always_linux(admin):
    got = _create(admin, {'name': 'lib', 'template_id': 'debian-12', 'os': 'windows'}).get_json()['blueprint']
    assert (got['source_kind'], got['os'], got['template_id']) == ('library', 'linux', 'debian-12')
    # the defaults a deploy dialog starts from: packages upgraded, the VM started
    assert got['ciupgrade'] is True and got['start'] is True
    assert got['nics'] == [{'bridge': 'vmbr0', 'vlan': None, 'model': 'virtio', 'firewall': False}]


@pytest.mark.parametrize('over,field', [
    ({'source_kind': 'iso'}, 'source_kind'),
    ({'os': 'macos'}, 'os'),
    ({'nics': [{'bridge': 'vmbr0'}] * 5}, 'nics'),
    ({'nics': {'bridge': 'vmbr0'}}, 'nics'),
    ({'sshkeys': 'not a key'}, 'sshkeys'),
])
def test_a_template_blueprint_is_checked_at_the_field(admin, over, field):
    r = _create(admin, LINUX_T, **over)
    assert r.status_code == 400 and r.get_json()['field'] == field, r.get_json()


def test_only_a_template_source_keeps_the_templates_own_nics(admin):
    assert _create(admin, LINUX_T, nics=[]).get_json()['blueprint']['nics'] == []
    assert _create(admin, {'name': 'x', 'source_kind': 'template'}).get_json()['blueprint']['nics'] == []
    r = _create(admin, {'name': 'lib', 'template_id': 'debian-12', 'nics': []})
    assert r.status_code == 400 and r.get_json()['field'] == 'nics'


# --- the database -----------------------------------------------------------------------

def test_an_existing_database_gets_the_columns_and_the_table(db):
    db.conn.execute('DROP TABLE blueprint_templates')
    db.conn.execute('ALTER TABLE vm_blueprints DROP COLUMN source_kind')
    db.conn.execute('ALTER TABLE vm_blueprints DROP COLUMN os')
    db.conn.execute("INSERT INTO vm_blueprints (id, name, template_id, created_at) "
                    "VALUES ('bp-old', 'old', 'debian-12', '2026-11-01')")
    db.conn.commit()
    db._init_db()
    row = db.conn.execute("SELECT source_kind, os FROM vm_blueprints WHERE id = 'bp-old'").fetchone()
    assert tuple(row) == ('library', 'linux')
    assert db.conn.execute('SELECT COUNT(*) FROM blueprint_templates').fetchone()[0] == 0


def test_the_remembered_templates_are_shared_with_the_standbys():
    assert 'blueprint_templates' in ha.SYNC_TABLES and 'blueprint_templates' not in ha.LOCAL_TABLES
    assert 'blueprint_deployments' in ha.LOCAL_TABLES


# --- what a template config says --------------------------------------------------------

@pytest.mark.parametrize('raw,disk', [
    ({'boot': 'order=ide2;scsi1;virtio0', 'ide2': 'local:iso/x.iso,media=cdrom',
      'scsi1': 'local-lvm:vm-1-cloudinit,media=cdrom', 'virtio0': 'ceph:base-1-disk-0,size=9G'}, 'virtio0'),
    ({'boot': 'c', 'bootdisk': 'scsi0', 'scsi0': 'local-lvm:base-1-disk-0,size=3G',
      'ide2': 'local-lvm:vm-1-cloudinit,media=cdrom'}, 'scsi0'),
    ({'boot': 'order=net0', 'sata0': 'local-lvm:base-1-disk-0,size=3G', 'ide0': 'none,media=cdrom'}, 'sata0'),
    ({'ide2': 'local-lvm:vm-1-cloudinit,media=cdrom', 'ide0': 'local:iso/a.iso,media=cdrom'}, None),
])
def test_the_disk_to_grow_is_the_first_boot_disk(raw, disk):
    assert bpmod.boot_disk(raw) == disk


def test_a_template_is_shared_only_with_every_volume_on_shared_storage():
    facts = bpmod.template_facts(_win_cfg(9200), {'ceph'})
    assert (facts['windows'], facts['cloudinit'], facts['boot_disk'], facts['shared']) == (True, True, 'virtio0', True)
    assert facts['disk_storages'] == ['ceph']
    # an ISO in a CD-ROM drive on a node's own storage stops a clone onto another node too
    with_iso = dict(_win_cfg(9200), ide0='local:iso/virtio-win.iso,media=cdrom')
    assert bpmod.template_facts(with_iso, {'ceph'})['shared'] is False
    # so does the Cloud-Init drive, and a disk of the host
    assert bpmod.template_facts(dict(_win_cfg(9200), ide2='local-lvm:vm-9200-cloudinit,media=cdrom'),
                                {'ceph'})['shared'] is False
    assert bpmod.template_facts(dict(_win_cfg(9200), scsi3='/dev/sdb,size=1T'), {'ceph'})['shared'] is False
    plain = bpmod.template_facts({'scsi0': 'local-lvm:base-1-disk-0,size=3G'}, set())
    assert (plain['ostype'], plain['windows'], plain['cloudinit']) == ('other', False, False)


# --- the probe --------------------------------------------------------------------------

def test_the_probe_lists_the_templates_whose_os_fits(lab):
    r = lab.admin.get(f'/api/clusters/c1/blueprints/{lab.linux}/template?node=pve1')
    assert r.status_code == 200, r.get_json()
    got = r.get_json()
    assert got['source_kind'] == 'template' and got['mapped'] is None
    rows = {t['vmid']: t for t in got['templates']}
    # no VM that is no template, no container, no Windows template for a Linux blueprint
    assert sorted(rows) == [9100, 9101, 9102, 9103]
    assert rows[9100] == {'vmid': 9100, 'name': 'tpl-9100', 'node': 'pve1', 'ostype': 'l26', 'windows': False,
                          'cloudinit': True, 'boot_disk': 'scsi0', 'disk_storages': ['local-lvm'],
                          'shared': False, 'usable_on_node': True}
    assert rows[9101]['usable_on_node'] is False
    assert rows[9102]['shared'] is True and rows[9102]['usable_on_node'] is True
    assert rows[9103]['cloudinit'] is False
    win = lab.admin.get(f'/api/clusters/c1/blueprints/{lab.win}/template?node=pve1').get_json()
    assert [(t['vmid'], t['ostype'], t['windows'], t['usable_on_node']) for t in win['templates']] == \
        [(9200, 'win11', True, True)]


def test_the_probe_shows_only_templates_the_caller_may_clone(api, seed, lab, db):
    db.conn.execute("INSERT INTO blueprint_templates VALUES (?, 'c1', 9100, 'root', '2026-11-08')", (lab.linux,))
    db.conn.commit()
    assert lab.admin.get(f'/api/clusters/c1/blueprints/{lab.linux}/template?node=pve1').get_json()['mapped'] == 9100
    # vm.create, but cloning is not theirs
    vic = api.as_user(seed.user('vic', role='viewer', permissions=['vm.create']))
    got = vic.get(f'/api/clusters/c1/blueprints/{lab.linux}/template?node=pve1').get_json()
    assert got == {'source_kind': 'template', 'mapped': None, 'templates': []}


def test_a_confined_caller_gets_no_template_list(api, seed, lab):
    ann = seed.user('ann', permissions=['vm.create'])
    seed.vm_acl('c1', 100, ['ann'], permissions=['vm.view'])
    r = api.as_user(ann).get(f'/api/clusters/c1/blueprints/{lab.linux}/template?node=pve1')
    assert r.status_code == 403
    assert not any('/config' in p for p in lab.mgr.reads)


def test_the_probe_reads_fifty_configs_and_the_remembered_one_always(api, admin, db):
    res = [_res(v, 'pve1') for v in range(9100, 9160)]
    m = api.set_manager('c1', _cluster(res, {v: _linux_cfg(v) for v in range(9100, 9160)}))
    bid = _create(admin, LINUX_T).get_json()['blueprint']['id']
    db.conn.execute("INSERT INTO blueprint_templates VALUES (?, 'c1', 9159, 'root', '2026-11-08')", (bid,))
    db.conn.commit()
    got = admin.get(f'/api/clusters/c1/blueprints/{bid}/template?node=pve1').get_json()
    assert len([p for p in m.reads if p.endswith('/config')]) == 50
    assert len(got['templates']) == 50 and 9159 in [t['vmid'] for t in got['templates']]


# --- deploy from a template -------------------------------------------------------------

def test_a_template_deploy_clones_it_and_remembers_it(lab, db, no_thread):
    r = _deploy(lab.admin, lab.linux, vmid=150, template_vmid=9100)
    assert r.status_code == 202, r.get_json()
    assert r.get_json()['build_needed'] is False and r.get_json()['warnings'] == []
    args = no_thread[0]
    assert args[7] == {'vmid': 9100, 'node': 'pve1', 'storage': '', 'shared': False} and args[8] is None
    assert _maps(db) == [(lab.linux, 'c1', 9100, 'root')]
    row = dict(db.conn.execute('SELECT * FROM blueprint_deployments').fetchone())
    assert (row['template_vmid'], row['step'], row['log']) == (9100, 'clone', '')
    # the next deploy onto this cluster starts from it without being told
    r = _deploy(lab.admin, lab.linux, vmid=151, name='web-02')
    assert r.status_code == 202 and no_thread[1][7]['vmid'] == 9100
    listed = lab.admin.get('/api/blueprints').get_json()['blueprints']
    assert {b['id']: b['templates'] for b in listed} == {lab.linux: {'c1': 9100}, lab.win: {}}


def test_a_template_on_shared_storage_serves_another_node(lab, no_thread):
    r = _deploy(lab.admin, lab.linux, vmid=150, template_vmid=9102, storage='ceph')
    assert r.status_code == 202, r.get_json()
    assert no_thread[0][7] == {'vmid': 9102, 'node': 'pve2', 'storage': '', 'shared': True}


def test_a_clone_onto_another_node_needs_a_shared_target_storage(lab, db, no_thread):
    # qemu-server refuses a clone onto another node into storage that is not shared,
    # which would only show in the job after the 202
    r = _deploy(lab.admin, lab.linux, vmid=150, template_vmid=9102, storage='local-lvm')
    assert r.status_code == 400 and r.get_json()['field'] == 'storage', r.get_json()
    assert 'pve2' in r.get_json()['error'] and 'local-lvm' in r.get_json()['error']
    assert no_thread == [] and _maps(db) == []
    # on its own node any storage does
    r = _deploy(lab.admin, lab.linux, vmid=150, node='pve2', template_vmid=9102, storage='local-lvm')
    assert r.status_code == 202, r.get_json()


@pytest.mark.parametrize('tv,field,word', [
    (None, 'template_vmid', 'pick'),          # nothing sent, nothing remembered
    ('abc', 'template_vmid', 'VMID'),
    (True, 'template_vmid', 'VMID'),
    (9999, 'template_vmid', 'no VM template'),
    (9300, 'template_vmid', 'no VM template'),  # a VM, no template
    (9400, 'template_vmid', 'no VM template'),  # a container template
    (9200, 'template_vmid', 'Windows'),         # a Windows template for a Linux blueprint
    (9103, 'template_vmid', 'Cloud-Init'),
    (9101, 'node', 'pve2'),                     # on pve2, its disks only there
])
def test_a_template_that_would_not_work_is_refused_before_anything_happens(lab, db, no_thread, tv, field, word):
    over = {} if tv is None else {'template_vmid': tv}
    r = _deploy(lab.admin, lab.linux, vmid=150, **over)
    assert r.status_code == 400, r.get_json()
    assert r.get_json()['field'] == field and word in r.get_json()['error']
    assert no_thread == [] and _maps(db) == []


@pytest.mark.parametrize('field', ['template_vmid', 'vmid'])
def test_a_digit_that_is_no_ascii_digit_is_refused_at_the_field(lab, no_thread, field):
    # a superscript two passes str.isdigit(), int() refuses it
    r = _deploy(lab.admin, lab.linux, **dict({'template_vmid': 9100, 'vmid': 150}, **{field: '\u00b2'}))
    assert r.status_code == 400 and r.get_json()['field'] == field and no_thread == []


def test_an_unreadable_template_config_is_no_go(lab, no_thread):
    lab.mgr.get_vm_resources.return_value = [_res(9500, 'pve1')]
    r = _deploy(lab.admin, lab.linux, vmid=150, template_vmid=9500)
    assert r.status_code == 502 and r.get_json()['field'] == 'template_vmid' and no_thread == []


def test_a_caller_who_may_not_clone_the_template_is_refused(api, seed, lab, db, no_thread):
    vic = api.as_user(seed.user('vic', role='viewer', permissions=['vm.create']))
    r = _deploy(vic, lab.linux, vmid=150, template_vmid=9100)
    assert r.status_code == 400 and r.get_json()['field'] == 'template_vmid', r.get_json()
    assert 'clone' in r.get_json()['error'] and no_thread == []
    # nor through the template the blueprint remembers
    db.conn.execute("INSERT INTO blueprint_templates VALUES (?, 'c1', 9100, 'root', '2026-11-08')", (lab.linux,))
    db.conn.commit()
    assert _deploy(vic, lab.linux, vmid=150).status_code == 400 and no_thread == []


def test_a_confined_caller_deploys_no_template(api, seed, lab, no_thread):
    ann = seed.user('ann', permissions=['vm.create'])
    seed.vm_acl('c1', 9100, ['ann'], inherit_role=False, permissions=['vm.view', 'vm.clone'])
    r = _deploy(api.as_user(ann), lab.linux, vmid=150, template_vmid=9100)
    assert r.status_code == 403 and no_thread == []


@pytest.fixture
def tenant(seed):
    import pegaprox.utils.rbac as rbac
    seed.db.save_tenant('t_a', {'id': 't_a', 'name': 'A', 'clusters': ['c1'],
                                'vmid_range_start': 200, 'vmid_range_end': 299})
    rbac.invalidate_tenants_cache()
    yield
    rbac.invalidate_tenants_cache()


def test_the_template_may_sit_outside_the_tenants_range_the_clone_does_not(api, seed, lab, db, tenant, no_thread):
    tim = api.as_user(seed.user('tim', tenant_id='t_a', permissions=['vm.create', 'cluster.view']))
    assert _deploy(tim, lab.linux, vmid=150, template_vmid=9100).status_code == 403
    r = _deploy(tim, lab.linux, template_vmid=9100)
    assert r.status_code == 202, r.get_json()
    assert 200 <= r.get_json()['vmid'] <= 299 and no_thread[0][7]['vmid'] == 9100
    # tim may not change root's blueprint, so the pick was for this deploy only
    assert _maps(db) == []


def test_the_creator_remembers_the_template_for_the_cluster(api, seed, lab, db, no_thread):
    ann = api.as_user(seed.user('ann', permissions=['vm.create']))
    bid = _create(ann, LINUX_T).get_json()['blueprint']['id']
    assert _deploy(ann, bid, vmid=150, template_vmid=9102, storage='ceph').status_code == 202
    assert _maps(db) == [(bid, 'c1', 9102, 'ann')]


def test_the_templates_a_blueprint_remembers_go_where_they_no_longer_fit(lab, db, no_thread):
    assert _deploy(lab.admin, lab.linux, vmid=150, template_vmid=9100).status_code == 202
    keep = lab.admin.put(f'/api/blueprints/{lab.linux}', json=dict(LINUX_T, cores=8))
    assert keep.get_json()['blueprint']['templates'] == {'c1': 9100}
    gone = lab.admin.put(f'/api/blueprints/{lab.linux}', json=dict(LINUX_T, os='windows'))
    assert gone.get_json()['blueprint']['templates'] == {} and _maps(db) == []
    assert _deploy(lab.admin, lab.win, vmid=151, template_vmid=9200, node='pve2', cipassword='S3cret!').status_code == 202
    assert lab.admin.delete(f'/api/blueprints/{lab.win}').status_code == 200
    assert _maps(db) == []


def test_the_remembered_templates_show_only_clusters_the_caller_reaches(api, seed, lab, db, tenant):
    db.conn.executemany("INSERT INTO blueprint_templates VALUES (?, ?, ?, 'root', '2026-11-08')",
                        [(lab.linux, 'c1', 9100), (lab.linux, 'c9', 777)])
    db.conn.commit()
    tim = api.as_user(seed.user('tim', tenant_id='t_a', permissions=['vm.create', 'cluster.view']))
    mine = {b['id']: b['templates'] for b in tim.get('/api/blueprints').get_json()['blueprints']}
    assert mine[lab.linux] == {'c1': 9100}
    every = {b['id']: b['templates'] for b in lab.admin.get('/api/blueprints').get_json()['blueprints']}
    assert every[lab.linux] == {'c1': 9100, 'c9': 777}


def test_the_remembered_templates_show_only_the_ones_the_caller_may_clone(api, seed, lab, db):
    db.conn.execute("INSERT INTO blueprint_templates VALUES (?, 'c1', 9100, 'root', '2026-11-08')", (lab.linux,))
    db.conn.commit()
    # an ACL on VM 100 lets ann reach the cluster, not template 9100
    ann = seed.user('ann', permissions=['vm.create', 'vm.view'])
    seed.vm_acl('c1', 100, ['ann'], permissions=['vm.view'])
    # vm.create, but cloning is not vic's
    vic = seed.user('vic', role='viewer', permissions=['vm.create'])
    for name, who in (('ann', ann), ('vic', vic)):
        mine = {b['id']: b['templates'] for b in api.as_user(who).get('/api/blueprints').get_json()['blueprints']}
        assert mine[lab.linux] == {}, (name, mine)
    every = {b['id']: b['templates'] for b in lab.admin.get('/api/blueprints').get_json()['blueprints']}
    assert every[lab.linux] == {'c1': 9100}


# --- Windows ------------------------------------------------------------------------------

def test_a_windows_deploy_needs_the_admin_password(lab, no_thread):
    r = _deploy(lab.admin, lab.win, node='pve2', template_vmid=9200)
    assert r.status_code == 400 and r.get_json()['field'] == 'cipassword' and no_thread == []
    r = _deploy(lab.admin, lab.win, node='pve2', template_vmid=9200, cipassword='S3cret!')
    assert r.status_code == 202, r.get_json()
    assert no_thread[0][10] == 'S3cret!'


def test_a_long_windows_name_goes_through_with_a_warning(lab, db, no_thread):
    r = _deploy(lab.admin, lab.win, node='pve2', template_vmid=9200, cipassword='pw', name='win-fileserver-01')
    assert r.status_code == 202, r.get_json()
    assert len(r.get_json()['warnings']) == 1 and '15' in r.get_json()['warnings'][0]
    log = db.conn.execute('SELECT log FROM blueprint_deployments').fetchone()[0]
    assert 'warning: Windows keeps the first 15 characters' in log
    # Linux has no such limit
    assert _deploy(lab.admin, lab.linux, vmid=160, template_vmid=9100,
                   name='linux-fileserver-01').get_json()['warnings'] == []


@pytest.mark.parametrize('version,code', [('8.2.3', 409), ('8.1.10', 409), ('7.4.3', 409),
                                          ('8.2.4', 202), ('8.2.10', 202), ('9.0.1', 202)])
def test_windows_cloud_init_needs_qemu_server_8_2_4_on_the_node(api, admin, no_thread, version, code):
    res, cfgs = _standard()
    m = api.set_manager('c1', _cluster(res, cfgs, qemu_server=version))
    bid = _create(admin, WIN_T).get_json()['blueprint']['id']
    r = _deploy(admin, bid, node='pve2', template_vmid=9200, cipassword='pw')
    assert r.status_code == code, r.get_json()
    if code == 409:
        assert '8.2.4' in r.get_json()['error'] and version in r.get_json()['error'] and no_thread == []
    assert '/nodes/pve2/apt/versions' in m.reads


def test_an_unread_qemu_server_version_is_a_warning(api, admin, no_thread):
    res, cfgs = _standard()
    api.set_manager('c1', _cluster(res, cfgs, fail=('/apt/versions',)))
    bid = _create(admin, WIN_T).get_json()['blueprint']['id']
    r = _deploy(admin, bid, node='pve2', template_vmid=9200, cipassword='pw')
    assert r.status_code == 202 and 'qemu-server' in ' '.join(r.get_json()['warnings'])


def test_the_qemu_server_floor_is_the_installed_version_not_the_pending_upgrade(api, admin, no_thread):
    # pveupdate refreshes the package index every day: a node on 8.1 lists 8.2 as Version
    res, cfgs = _standard()
    m = api.set_manager('c1', _cluster(res, cfgs, qemu_server='8.1.10', qemu_candidate='8.2.7'))
    assert bpmod.qemu_server_version(m, 'pve2') == (8, 1, 10)
    bid = _create(admin, WIN_T).get_json()['blueprint']['id']
    r = _deploy(admin, bid, node='pve2', template_vmid=9200, cipassword='pw')
    assert r.status_code == 409 and '8.1.10' in r.get_json()['error'] and no_thread == [], r.get_json()


def test_a_qemu_server_apt_only_offers_has_no_version(api, admin, no_thread):
    res, cfgs = _standard()
    m = api.set_manager('c1', _cluster(res, cfgs, qemu_server=None, qemu_candidate='8.3.0'))
    assert bpmod.qemu_server_version(m, 'pve2') is None
    bid = _create(admin, WIN_T).get_json()['blueprint']['id']
    r = _deploy(admin, bid, node='pve2', template_vmid=9200, cipassword='pw')
    assert r.status_code == 202 and 'could not be read' in ' '.join(r.get_json()['warnings']), r.get_json()


def test_a_linux_deploy_does_not_ask_for_the_qemu_server(lab, no_thread):
    assert _deploy(lab.admin, lab.linux, vmid=150, template_vmid=9100).status_code == 202
    assert not any(p.endswith('/apt/versions') for p in lab.mgr.reads)


def _row(**over):
    f = dict(WIN_T, **over)
    return {'name': f['name'], 'cores': f['cores'], 'memory': f['memory'], 'cpu': f.get('cpu', ''),
            'nics': json.dumps(f['nics']), 'ip_mode': f['ip_mode'], 'ciuser': f.get('ciuser', ''),
            'sshkeys': f.get('sshkeys', ''), 'nameserver': f.get('nameserver', ''),
            'searchdomain': f.get('searchdomain', ''), 'ciupgrade': int(f.get('ciupgrade', True)),
            'tags': '', 'disk_gb': f['disk_gb'], 'template_id': '', 'start': 1,
            'source_kind': f['source_kind'], 'os': f['os']}


def test_windows_gets_no_cloud_init_user_keys_search_domain_or_upgrade():
    # whatever the row says, a Windows clone is not sent what PVE would drop for it
    cfg = bpmod.vm_config(_row(), cipassword='pw')
    assert cfg == {'cores': 4, 'memory': 8192, 'ipconfig0': 'ip=dhcp', 'cipassword': 'pw',
                   'nameserver': '10.0.0.53'}
    linux = bpmod.vm_config(_row(os='linux'), cipassword='pw')
    assert linux['ciuser'] == 'admin' and linux['searchdomain'] == 'corp.example' and linux['ciupgrade'] == 0


def test_the_templates_own_nics_get_the_address_of_the_first():
    dhcp = bpmod.vm_config(_row(os='linux'))
    assert dhcp['ipconfig0'] == 'ip=dhcp' and not any(k.startswith('net') or k == 'ipconfig1' for k in dhcp)
    static = bpmod.vm_config(_row(ip_mode='static'), ipconfig0='ip=10.0.0.5/24,gw=10.0.0.1')
    assert static['ipconfig0'] == 'ip=10.0.0.5/24,gw=10.0.0.1'
    assert not any(k.startswith('net') or k == 'ipconfig1' for k in static)
    two = bpmod.vm_config(_row(nics=[{'bridge': 'vmbr0', 'model': 'virtio'}, {'bridge': 'vmbr1', 'model': 'e1000'}]))
    assert (two['net0'], two['net1'], two['ipconfig1']) == ('virtio,bridge=vmbr0', 'e1000,bridge=vmbr1', 'ip=dhcp')


# --- the quota ----------------------------------------------------------------------------

def test_the_quota_counts_the_vcpus_the_clone_runs(api, admin, no_thread, monkeypatch):
    # the clone keeps the template's sockets and runs sockets x cores, which is what every
    # other quota count of a qemu guest adds up
    import pegaprox.api.helpers as helpers
    res, cfgs = _standard()
    cfgs[9100] = dict(_linux_cfg(9100), sockets=4)
    api.set_manager('c1', _cluster(res, cfgs))
    seen = []
    monkeypatch.setattr(helpers, 'tenant_quota_gate', lambda user, what, adds, **kw: seen.append(adds) or (None, None))
    bid = _create(admin, LINUX_T).get_json()['blueprint']['id']
    assert _deploy(admin, bid, vmid=150, template_vmid=9100).status_code == 202
    assert seen[-1]['cores'] == 2 * 4 and seen[-1]['vms'] == 1
    # a template that names no sockets has one
    assert _deploy(admin, bid, vmid=151, name='web-02', node='pve2', template_vmid=9101).status_code == 202
    assert seen[-1]['cores'] == 2


# --- the bridges --------------------------------------------------------------------------

def test_a_bridge_the_node_does_not_have_is_refused_by_name(api, admin, db, no_thread):
    res, cfgs = _standard()
    m = api.set_manager('c1', _cluster(res, cfgs, bridges=('vmbr0',), vnets=('vnet10',)))
    bid = _create(admin, LINUX_T, nics=[{'bridge': 'vmbr0'}, {'bridge': 'vmbr7'}]).get_json()['blueprint']['id']
    r = _deploy(admin, bid, vmid=150, template_vmid=9100)
    assert r.status_code == 400 and r.get_json()['field'] == 'nics', r.get_json()
    assert 'vmbr7' in r.get_json()['error'] and 'pve1' in r.get_json()['error'] and 'vmbr0' not in r.get_json()['error']
    assert no_thread == [] and _maps(db) == []
    assert '/nodes/pve1/network' in m.reads and '/cluster/sdn/vnets' in m.reads


def test_a_library_deploy_checks_its_bridges_too(api, admin, no_thread):
    api.set_manager('c1', _cluster([], {}, bridges=('vmbr0',)))
    bid = _create(admin, {'name': 'lib', 'template_id': 'debian-12', 'nics': [{'bridge': 'vmbr9'}]}).get_json()['blueprint']['id']
    r = _deploy(admin, bid, vmid=150)
    assert r.status_code == 400 and 'vmbr9' in r.get_json()['error'] and no_thread == []


def test_an_sdn_vnet_is_a_bridge_too(api, admin, no_thread):
    res, cfgs = _standard()
    api.set_manager('c1', _cluster(res, cfgs, bridges=('vmbr0',), vnets=('vnet10',)))
    bid = _create(admin, LINUX_T, nics=[{'bridge': 'vnet10'}]).get_json()['blueprint']['id']
    r = _deploy(admin, bid, vmid=150, template_vmid=9100)
    assert r.status_code == 202 and r.get_json()['warnings'] == [], r.get_json()


@pytest.mark.parametrize('fail,word', [(('/network',), 'network of pve1'), (('/sdn/vnets',), 'SDN VNets')])
def test_a_bridge_list_that_cannot_be_read_is_a_warning(api, admin, db, no_thread, fail, word):
    res, cfgs = _standard()
    api.set_manager('c1', _cluster(res, cfgs, bridges=('vmbr0',), fail=fail))
    bid = _create(admin, LINUX_T, nics=[{'bridge': 'vmbr5'}]).get_json()['blueprint']['id']
    r = _deploy(admin, bid, vmid=150, template_vmid=9100)
    assert r.status_code == 202, r.get_json()
    assert word in r.get_json()['warnings'][0] and 'vmbr5' in r.get_json()['warnings'][0]
    assert word in db.conn.execute('SELECT log FROM blueprint_deployments').fetchone()[0]


def test_the_templates_own_nics_need_no_bridge_check(lab, no_thread):
    r = _deploy(lab.admin, lab.win, node='pve2', template_vmid=9200, cipassword='pw')
    assert r.status_code == 202
    assert not any(p.endswith('/network') for p in lab.mgr.reads)


# --- the job --------------------------------------------------------------------------------

def _job(api, db, raw, row, template):
    m = MagicMock(name='mgr')
    m.host, m.api_port = '10.0.0.1', 8006
    m.clone_vm.return_value = {'success': True, 'data': 'UPID:pve1:clone'}
    m._wait_for_task.return_value = True
    m._api_post.return_value = _Resp()
    m.get_vm_config.return_value = {'success': True, 'config': {'raw': raw}}
    m.resize_vm_disk.return_value = {'success': True}
    m.vm_action.return_value = {'success': True}
    api.set_manager('c1', m)
    db.conn.execute("INSERT INTO blueprint_deployments (id, blueprint_id, cluster_id, node, status) "
                    "VALUES ('d1', 'b1', 'c1', 'pve1', 'queued')")
    db.conn.commit()
    bpmod.run_deploy('d1', 'c1', row, 'pve1', 'local-lvm', 150, 'win-01', template, None, '', 'pw', True, 'root')
    return m, dict(db.conn.execute("SELECT * FROM blueprint_deployments WHERE id = 'd1'").fetchone())


def test_a_windows_clone_grows_its_boot_disk_and_keeps_its_nics(api, db):
    raw = dict(_win_cfg(150), virtio0='ceph:vm-150-disk-0,size=60G', net1='e1000,bridge=vmbr1',
               ipconfig1='ip=10.1.0.5/24')
    m, row = _job(api, db, raw, _row(), {'vmid': 9200, 'node': 'pve2', 'storage': '', 'shared': True})
    assert row['status'] == 'completed', row['log']
    kw = m.clone_vm.call_args.kwargs
    assert (kw['node'], kw['vmid'], kw['target_node'], kw['full']) == ('pve2', 9200, 'pve1', True)
    sent = m._api_post.call_args.kwargs['data']
    assert 'delete' not in sent and not any(k.startswith('net') for k in sent)
    assert not {'ciuser', 'sshkeys', 'searchdomain', 'ciupgrade'} & set(sent)
    # the boot order names the CD-ROM first; the disk behind it is the one that grows
    m.resize_vm_disk.assert_called_once_with('pve1', 150, 'qemu', 'virtio0', '80G')
    assert 'pw' not in row['log']


def test_a_blueprint_with_its_own_nics_removes_the_templates_others(api, db):
    raw = dict(_linux_cfg(150), net1='virtio,bridge=vmbr1', net2='e1000,bridge=vmbr2', ipconfig1='ip=dhcp',
               scsi0='local-lvm:vm-150-disk-0,size=30G')
    m, row = _job(api, db, raw, _row(os='linux', nics=[{'bridge': 'vmbr0', 'model': 'virtio'}], disk_gb=20),
                  {'vmid': 9100, 'node': 'pve1', 'storage': '', 'shared': False})
    sent = m._api_post.call_args.kwargs['data']
    assert sent['delete'] == 'ipconfig1,net1,net2' and sent['net0'] == 'virtio,bridge=vmbr0'
    assert "the template's ipconfig1, net1, net2 removed" in row['log']
    assert not m.resize_vm_disk.called and 'already 30.0 GB' in row['log']


# --- recent deploys across the clusters -----------------------------------------------------

def _dep(db, dep_id, cluster, vmid, at):
    db.conn.execute("INSERT INTO blueprint_deployments (id, blueprint_id, cluster_id, node, vmid, status, "
                    "started_at) VALUES (?, 'b1', ?, 'pve1', ?, 'completed', ?)", (dep_id, cluster, vmid, at))
    db.conn.commit()


def test_the_recent_deploys_of_every_cluster_the_caller_sees(api, seed, admin, db, tenant):
    _dep(db, 'a', 'c1', 201, '2026-11-08T10:00')
    _dep(db, 'b', 'c2', 202, '2026-11-08T12:00')
    _dep(db, 'c', 'c1', 203, '2026-11-08T11:00')
    rows = admin.get('/api/blueprints/deployments').get_json()['deployments']
    assert [(r['id'], r['cluster_id']) for r in rows] == [('b', 'c2'), ('c', 'c1'), ('a', 'c1')]
    tim = api.as_user(seed.user('tim', tenant_id='t_a', permissions=['cluster.view']))
    assert [r['id'] for r in tim.get('/api/blueprints/deployments').get_json()['deployments']] == ['c', 'a']
    # one cluster as before
    assert [r['id'] for r in admin.get('/api/blueprints/deployments?cluster_id=c2').get_json()['deployments']] == ['b']
    assert tim.get('/api/blueprints/deployments?cluster_id=c2').status_code == 403


def test_the_cross_cluster_list_asks_for_each_cluster_before_its_rows(api, seed, admin, db, tenant, monkeypatch):
    """The per-guest cut on its own would drop c2's rows for tim as well; the cluster gate
    is the first line and must hold without it."""
    _dep(db, 'a', 'c1', 201, '2026-11-08T10:00')
    _dep(db, 'b', 'c2', 202, '2026-11-08T12:00')
    monkeypatch.setattr(bpmod, 'scope_vm_rows', lambda cid, rows: rows)
    tim = api.as_user(seed.user('tim', tenant_id='t_a', permissions=['cluster.view']))
    assert [r['id'] for r in tim.get('/api/blueprints/deployments').get_json()['deployments']] == ['a']


def test_the_recent_deploys_across_clusters_stop_at_a_hundred(admin, db):
    for i in range(70):
        _dep(db, f'x{i}', 'c1', 300 + i, f'2026-11-07T{i // 60:02d}:{i % 60:02d}')
        _dep(db, f'y{i}', 'c2', 400 + i, f'2026-11-08T{i // 60:02d}:{i % 60:02d}')
    rows = admin.get('/api/blueprints/deployments').get_json()['deployments']
    assert len(rows) == 100 and rows[0]['id'] == 'y69' and rows[69]['id'] == 'y0' and rows[70]['id'] == 'x69'


def test_a_confined_callers_cross_cluster_list_is_cut_to_their_guests(api, seed, admin, db):
    _dep(db, 'mine', 'c1', 501, '2026-11-08T10:00')
    _dep(db, 'other', 'c1', 502, '2026-11-08T11:00')
    ann = seed.user('ann', permissions=['cluster.view'])
    seed.vm_acl('c1', 501, ['ann'])
    rows = api.as_user(ann).get('/api/blueprints/deployments').get_json()['deployments']
    assert [r['id'] for r in rows] == ['mine']
