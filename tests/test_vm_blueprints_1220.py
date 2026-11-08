"""VM blueprints: a library image plus hardware and Cloud-Init, deployed in one step onto
any managed PVE cluster (#1220).

Templates in PVE belong to one cluster, so every cluster needed its own copy and the
hardware and Cloud-Init settings were typed again for each VM. A blueprint points at the
template library's image instead: a deploy clones the template the library built from it
on that node or on shared storage, or has the library build one there first, then sets
the blueprint's CPU, memory, NICs, Cloud-Init and disk size on the clone.

The deploy creates a guest under a VMID, so it asks what the library's deploy and the
create route ask: no confined caller places one, a tenant stays inside its VMID range and
quota. A blueprint never stores a password.

MK Nov 2026
"""
import json
import types
from unittest.mock import MagicMock
from urllib.parse import unquote

import pytest

import pegaprox.api.blueprints as bpmod
import pegaprox.api.templates_lib as tpl

KEY = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl ops@lab'
GOOD = {
    'name': 'web small', 'description': 'nginx box', 'template_id': 'debian-12',
    'cores': 2, 'memory': 4096, 'disk_gb': 32, 'cpu': 'x86-64-v2-AES',
    'nics': [{'bridge': 'vmbr0', 'vlan': 20, 'model': 'virtio', 'firewall': True},
             {'bridge': 'vmbr1', 'vlan': None, 'model': 'e1000', 'firewall': False}],
    'ciuser': 'ops', 'sshkeys': KEY, 'ip_mode': 'dhcp', 'nameserver': '10.0.0.53 10.0.0.54',
    'searchdomain': 'lab.example', 'ciupgrade': False, 'tags': ['web', 'prod'], 'start': True,
}


class _Resp:
    def __init__(self, code=200, data=None, text=''):
        self.status_code, self._data, self.text = code, data, text

    def json(self):
        return {'data': self._data}


def _mgr(resources=(), shared=(), nodes=('pve1', 'pve2'), cluster_type='proxmox'):
    m = MagicMock(name='mgr')
    m.cluster_type = cluster_type
    m.host, m.api_port = '10.0.0.1', 8006
    m.config = types.SimpleNamespace(name='lab')
    m.nodes = {n: {'node': n, 'status': 'online'} for n in nodes}
    m.get_vm_resources.return_value = list(resources)
    m.get_next_vmid.return_value = {'success': True, 'vmid': 100}
    storages = _Resp(data=[{'storage': s, 'shared': 1} for s in shared] + [{'storage': 'local-lvm', 'shared': 0}])
    # the bridges the deploy looks for before it starts (GOOD names vmbr0 and vmbr1)
    network = _Resp(data=[{'iface': 'vmbr0', 'type': 'bridge'}, {'iface': 'vmbr1', 'type': 'OVSBridge'}])
    m._api_get.side_effect = lambda url, **kw: network if url.endswith('/network') else storages
    return m


def _template(vmid, node):
    return {'vmid': vmid, 'node': node, 'type': 'qemu', 'template': 1, 'name': f'tpl-{vmid}'}


def _built(db, vmid, node, storage, status='completed', cluster='c1', template_id='debian-12'):
    db.conn.execute('''INSERT INTO cloud_init_deployments (id, cluster_id, node, template_id, vmid,
                       storage, status, started_at, finished_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    (f'b{vmid}{node}', cluster, node, template_id, vmid, storage, status,
                     '2026-11-01T10:00', f'2026-11-01T10:{vmid % 60:02d}'))
    db.conn.commit()


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


def _create(client, **over):
    return client.post('/api/blueprints', json=dict(GOOD, **over))


# --- saving -----------------------------------------------------------------------------

def test_a_blueprint_is_saved_and_listed_as_sent(admin):
    r = _create(admin)
    assert r.status_code == 201, r.get_json()
    got = r.get_json()['blueprint']
    for key in ('name', 'template_id', 'cores', 'memory', 'disk_gb', 'cpu', 'nics', 'ciuser', 'sshkeys',
                'ip_mode', 'nameserver', 'searchdomain', 'ciupgrade', 'tags', 'start'):
        assert got[key] == GOOD[key], key
    assert got['template_name'] == 'Debian 12 (Bookworm)' and got['template_missing'] is False
    assert got['can_edit'] is True and got['created_by'] == 'root'
    listed = admin.get('/api/blueprints').get_json()['blueprints']
    assert [b['id'] for b in listed] == [got['id']]


@pytest.mark.parametrize('over,field', [
    ({'template_id': 'nope'}, 'template_id'),
    ({'name': ''}, 'name'),
    ({'cores': 0}, 'cores'),
    ({'cores': True}, 'cores'),
    ({'memory': 'lots'}, 'memory'),
    ({'disk_gb': -1}, 'disk_gb'),
    ({'cpu': 'host,flags=+aes'}, 'cpu'),
    ({'nics': []}, 'nics'),
    ({'nics': [{'bridge': 'vmbr0'}] * 5}, 'nics'),
    ({'nics': [{'bridge': 'vmbr0 ; reboot'}]}, 'nics'),
    ({'nics': [{'bridge': 'vmbr0', 'vlan': 5000}]}, 'nics'),
    ({'nics': [{'bridge': 'vmbr0', 'model': 'ne2k'}]}, 'nics'),
    ({'ciuser': '-root'}, 'ciuser'),
    ({'sshkeys': 'not a key'}, 'sshkeys'),
    ({'sshkeys': '-----BEGIN OPENSSH PRIVATE KEY-----'}, 'sshkeys'),
    ({'ip_mode': 'auto'}, 'ip_mode'),
    ({'nameserver': '10.0.0.300'}, 'nameserver'),
    ({'searchdomain': 'bad_domain!'}, 'searchdomain'),
    ({'tags': ['Web Server']}, 'tags'),
    ({'start': 'yes'}, 'start'),
    ({'cores': '\u00b2'}, 'cores'),       # a superscript two: isdigit() says yes, int() says no
])
def test_a_blueprint_the_server_would_send_wrong_is_refused_at_the_field(admin, over, field):
    r = _create(admin, **over)
    assert r.status_code == 400, r.get_json()
    assert r.get_json()['field'] == field


def test_a_private_key_pasted_by_mistake_is_named_as_such(admin):
    r = _create(admin, sshkeys=KEY + '\n-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk=\n')
    assert r.status_code == 400 and 'private key' in r.get_json()['error']


def test_a_password_is_never_stored(admin, seed):
    r = _create(admin, cipassword='secret')
    assert r.status_code == 201
    cols = [c[1] for c in seed.db.conn.execute('PRAGMA table_info(vm_blueprints)').fetchall()]
    assert not any('pass' in c for c in cols)
    assert 'cipassword' not in r.get_json()['blueprint']


def test_only_the_creator_or_an_admin_changes_a_blueprint(api, seed, admin):
    ann = api.as_user(seed.user('ann', permissions=['vm.create']))
    bob = api.as_user(seed.user('bob', permissions=['vm.create']))
    bid = _create(ann).get_json()['blueprint']['id']
    listed = bob.get('/api/blueprints').get_json()['blueprints']
    assert listed[0]['can_edit'] is False
    assert bob.put(f'/api/blueprints/{bid}', json=dict(GOOD, name='mine now')).status_code == 403
    assert bob.delete(f'/api/blueprints/{bid}').status_code == 403
    assert ann.put(f'/api/blueprints/{bid}', json=dict(GOOD, cores=4)).get_json()['blueprint']['cores'] == 4
    assert admin.delete(f'/api/blueprints/{bid}').status_code == 200
    assert admin.get('/api/blueprints').get_json()['blueprints'] == []


def test_without_vm_create_there_are_no_blueprints(api, seed):
    viewer = api.as_user(seed.user('val', permissions=['vm.view']))
    assert viewer.get('/api/blueprints').status_code == 403
    assert _create(viewer).status_code == 403


def test_a_blueprint_whose_image_left_the_library_says_so(admin, seed):
    bid = _create(admin).get_json()['blueprint']['id']
    seed.db.conn.execute("UPDATE vm_blueprints SET template_id = 'custom-gone-abc' WHERE id = ?", (bid,))
    seed.db.conn.commit()
    got = admin.get('/api/blueprints').get_json()['blueprints'][0]
    assert got['template_missing'] is True and got['template_name'] == ''


# --- what the clone gets ----------------------------------------------------------------

def _row(**over):
    f = dict(GOOD, **over)
    return {'name': f['name'], 'cores': f['cores'], 'memory': f['memory'], 'cpu': f['cpu'],
            'nics': json.dumps(f['nics']), 'ip_mode': f['ip_mode'], 'ciuser': f['ciuser'],
            'sshkeys': f['sshkeys'], 'nameserver': f['nameserver'], 'searchdomain': f['searchdomain'],
            'ciupgrade': int(f['ciupgrade']), 'tags': ';'.join(f['tags']), 'disk_gb': f['disk_gb'],
            'template_id': f['template_id'], 'start': int(f['start'])}


def test_the_clone_gets_the_blueprint_in_pve_parameters():
    cfg = bpmod.vm_config(_row(), cipassword='pw')
    assert cfg['cores'] == 2 and cfg['memory'] == 4096 and cfg['cpu'] == 'x86-64-v2-AES'
    assert cfg['net0'] == 'virtio,bridge=vmbr0,tag=20,firewall=1'
    assert cfg['net1'] == 'e1000,bridge=vmbr1'
    assert cfg['ipconfig0'] == cfg['ipconfig1'] == 'ip=dhcp'
    # PVE takes the keys URL-encoded; a raw space is refused there
    assert ' ' not in cfg['sshkeys'] and unquote(cfg['sshkeys']).strip() == KEY
    assert cfg['ciupgrade'] == 0 and cfg['tags'] == 'web;prod' and cfg['cipassword'] == 'pw'
    assert (cfg['ciuser'], cfg['nameserver'], cfg['searchdomain']) == ('ops', '10.0.0.53 10.0.0.54', 'lab.example')


def test_static_and_none_and_the_defaults_pve_has_anyway():
    static = bpmod.vm_config(_row(ip_mode='static', ciupgrade=True, cpu=''), ipconfig0='ip=10.0.0.5/24,gw=10.0.0.1')
    assert static['ipconfig0'] == 'ip=10.0.0.5/24,gw=10.0.0.1' and 'ipconfig1' not in static
    assert 'ciupgrade' not in static and 'cpu' not in static and 'cipassword' not in static
    none = bpmod.vm_config(_row(ip_mode='none'))
    assert not any(k.startswith('ipconfig') for k in none)


@pytest.mark.parametrize('raw,ok', [
    ('ip=10.0.0.5/24,gw=10.0.0.1', True),
    ('ip=10.0.0.5/24', True),
    ('ip6=2001:db8::5/64,gw6=2001:db8::1', True),
    ('ip=10.0.0.5/24,gw=10.0.1.1', False),        # gateway outside the network
    ('ip=10.0.0.5,gw=10.0.0.1', False),           # no prefix
    ('ip=2001:db8::5/64', False),                 # v6 under the v4 key
    ('gw=10.0.0.1', False),
    ('ip=10.0.0.5/24,gw=10.0.0.1,foo=1', False),
    ('ip=dhcp', False),
    ('', False),
])
def test_a_static_address_is_an_address_with_prefix_and_a_gateway_inside(raw, ok):
    if ok:
        assert bpmod._ipconfig(raw) == raw
    else:
        with pytest.raises(bpmod._Bad):
            bpmod._ipconfig(raw)


@pytest.mark.parametrize('drive,gb', [('local-lvm:vm-101-disk-0,size=3584M', 3.5),
                                      ('ceph:vm-1-disk-0,discard=on,size=10G', 10),
                                      ('local:101/x.qcow2,size=2T,ssd=1', 2048), ('nothing', None)])
def test_the_disk_size_is_read_from_the_drive_line(drive, gb):
    assert bpmod.disk_gb_of(drive) == gb


# --- which template ---------------------------------------------------------------------

def test_the_template_on_the_node_itself_comes_first(db):
    _built(db, 9001, 'pve2', 'ceph', status='completed')
    _built(db, 9002, 'pve1', 'local-lvm')
    m = _mgr([_template(9001, 'pve2'), _template(9002, 'pve1')], shared=['ceph'])
    assert bpmod.find_template(m, 'c1', 'debian-12', 'pve1') == \
        {'vmid': 9002, 'node': 'pve1', 'storage': 'local-lvm', 'shared': False}


def test_a_template_on_shared_storage_serves_another_node(db):
    _built(db, 9001, 'pve2', 'ceph')
    m = _mgr([_template(9001, 'pve2')], shared=['ceph'])
    assert bpmod.find_template(m, 'c1', 'debian-12', 'pve1')['vmid'] == 9001


@pytest.mark.parametrize('case', ['local-elsewhere', 'gone', 'no-longer-template', 'failed-build',
                                  'other-image', 'other-cluster'])
def test_no_template_means_one_gets_built(db, case):
    _built(db, 9001, 'pve2', 'local-lvm', status='failed' if case == 'failed-build' else 'completed',
           template_id='ubuntu-2404' if case == 'other-image' else 'debian-12',
           cluster='c2' if case == 'other-cluster' else 'c1')
    res = {'gone': [], 'no-longer-template': [dict(_template(9001, 'pve2'), template=0)]}.get(
        case, [_template(9001, 'pve2')])
    assert bpmod.find_template(_mgr(res), 'c1', 'debian-12', 'pve1') is None


# --- deploy -----------------------------------------------------------------------------

@pytest.fixture
def lab(api, admin):
    m = api.set_manager('c1', _mgr([_template(9002, 'pve1')]))
    bid = _create(admin).get_json()['blueprint']['id']
    return types.SimpleNamespace(mgr=m, bid=bid, admin=admin)


def _deploy(client, bid, **over):
    body = dict({'cluster_id': 'c1', 'node': 'pve1', 'storage': 'local-lvm', 'name': 'web-01'}, **over)
    return client.post(f'/api/blueprints/{bid}/deploy', json=body)


def test_a_deploy_clones_the_existing_template(lab, db, no_thread):
    _built(db, 9002, 'pve1', 'local-lvm')
    r = _deploy(lab.admin, lab.bid, vmid=150)
    assert r.status_code == 202, r.get_json()
    assert r.get_json()['build_needed'] is False and r.get_json()['vmid'] == 150
    args = no_thread[0]
    assert args[7] == {'vmid': 9002, 'node': 'pve1', 'storage': 'local-lvm', 'shared': False} and args[8] is None
    row = dict(db.conn.execute('SELECT * FROM blueprint_deployments').fetchone())
    assert (row['vmid'], row['template_vmid'], row['status'], row['name']) == (150, 9002, 'queued', 'web-01')


def test_a_deploy_without_a_template_builds_one_through_the_library(lab, db, no_thread):
    r = _deploy(lab.admin, lab.bid, vmid=150)
    assert r.status_code == 202 and r.get_json()['build_needed'] is True
    build = no_thread[0][8]
    assert build['vmid'] != 150 and build['name'] == 'tpl-debian-12'
    lib = dict(db.conn.execute('SELECT * FROM cloud_init_deployments WHERE id = ?', (build['dep_id'],)).fetchone())
    # the library lists the build like its own
    assert (lib['node'], lib['template_id'], lib['vmid'], lib['status']) == ('pve1', 'debian-12', build['vmid'], 'queued')


def test_a_shared_template_elsewhere_serves_a_shared_target_storage_only(api, admin, db, no_thread):
    # PVE clones onto another node into shared storage only; into the node's own storage
    # the node gets a template of its own first
    _built(db, 9001, 'pve2', 'ceph')
    api.set_manager('c1', _mgr([_template(9001, 'pve2')], shared=['ceph']))
    bid = _create(admin).get_json()['blueprint']['id']
    r = _deploy(admin, bid, vmid=150, storage='ceph')
    assert r.status_code == 202 and r.get_json()['build_needed'] is False, r.get_json()
    assert no_thread[0][7]['vmid'] == 9001 and no_thread[0][8] is None
    r = _deploy(admin, bid, vmid=151, name='web-02')
    assert r.status_code == 202 and r.get_json()['build_needed'] is True, r.get_json()
    assert no_thread[1][7] is None and no_thread[1][8]['vmid'] not in (151, 9001)


@pytest.mark.parametrize('over,code,field', [
    ({'node': 'pve9'}, 400, 'node'),
    ({'node': 'pve1;reboot'}, 400, 'node'),
    ({'storage': 'local lvm'}, 400, 'storage'),
    ({'name': 'web_01'}, 400, 'name'),
    ({'vmid': 'abc'}, 400, 'vmid'),
    ({'vmid': 50}, 400, 'vmid'),
    ({'ipconfig0': 'ip=10.0.0.5/24'}, 400, 'ipconfig0'),   # the blueprint says dhcp
    ({'start': 'yes'}, 400, 'start'),
    ({'cipassword': 'a\nb'}, 400, 'cipassword'),
])
def test_a_deploy_body_is_checked_before_anything_happens(lab, no_thread, over, code, field):
    r = _deploy(lab.admin, lab.bid, **over)
    assert r.status_code == code, r.get_json()
    assert r.get_json().get('field') == field
    assert no_thread == [] and not lab.mgr.clone_vm.called


def test_a_static_blueprint_needs_the_address(lab, admin, no_thread):
    bid = _create(admin, ip_mode='static').get_json()['blueprint']['id']
    assert _deploy(admin, bid).get_json()['field'] == 'ipconfig0'
    r = _deploy(admin, bid, ipconfig0='ip=10.0.0.5/24,gw=10.0.0.1')
    assert r.status_code == 202 and no_thread[0][9] == 'ip=10.0.0.5/24,gw=10.0.0.1'


def test_a_taken_vmid_and_a_gone_image_are_conflicts(lab, db, no_thread):
    lab.mgr.get_vm_resources.return_value = [_template(9002, 'pve1'), {'vmid': 150, 'type': 'qemu'}]
    assert _deploy(lab.admin, lab.bid, vmid=150).status_code == 409
    db.conn.execute("UPDATE vm_blueprints SET template_id = 'custom-gone-abc'")
    db.conn.commit()
    assert _deploy(lab.admin, lab.bid, vmid=151).status_code == 409
    assert no_thread == []


def test_other_cluster_types_are_not_deployed_to(api, lab, no_thread):
    api.set_manager('x1', _mgr(cluster_type='xcpng'))
    assert _deploy(lab.admin, lab.bid, cluster_id='x1').status_code == 400


@pytest.fixture
def tenant(seed):
    import pegaprox.utils.rbac as rbac
    seed.db.save_tenant('t_a', {'id': 't_a', 'name': 'A', 'clusters': ['c1'],
                                'vmid_range_start': 200, 'vmid_range_end': 299})
    rbac.invalidate_tenants_cache()
    yield
    rbac.invalidate_tenants_cache()


def test_a_tenant_deploys_inside_its_range_only(api, seed, lab, db, tenant, no_thread):
    _built(db, 9002, 'pve1', 'local-lvm')
    tim = api.as_user(seed.user('tim', tenant_id='t_a', permissions=['vm.create', 'cluster.view']))
    assert _deploy(tim, lab.bid, vmid=150).status_code == 403
    r = _deploy(tim, lab.bid)
    assert r.status_code == 202, r.get_json()
    assert 200 <= r.get_json()['vmid'] <= 299


def test_a_template_built_for_a_tenant_lands_in_its_range_too(api, seed, lab, tenant, no_thread):
    tim = api.as_user(seed.user('tim', tenant_id='t_a', permissions=['vm.create', 'cluster.view']))
    r = _deploy(tim, lab.bid)
    assert r.status_code == 202, r.get_json()
    build = no_thread[0][8]
    assert 200 <= build['vmid'] <= 299 and build['vmid'] != r.get_json()['vmid']


def test_a_caller_confined_to_their_own_guests_places_none(api, seed, lab, no_thread):
    ann = seed.user('ann', permissions=['vm.create'])
    seed.vm_acl('c1', 100, ['ann'], permissions=['vm.view'])
    r = _deploy(api.as_user(ann), lab.bid, vmid=150)
    assert r.status_code == 403 and no_thread == []


# --- the job ----------------------------------------------------------------------------

def _job_mgr():
    m = _mgr()
    m.clone_vm.return_value = {'success': True, 'data': 'UPID:pve1:clone'}
    m._wait_for_task.return_value = True
    m._api_post.return_value = _Resp()
    # the shape get_vm_config answers in: parsed, PVE's own keys under 'raw'
    m.get_vm_config.return_value = {'success': True, 'config': {
        'disks': [], 'raw': {'scsi0': 'local-lvm:vm-150-disk-0,size=3584M'}}}
    m.resize_vm_disk.return_value = {'success': True}
    m.vm_action.return_value = {'success': True}
    return m


def _job(api, db, template=None, build=None, start=True, row=None):
    m = api.set_manager('c1', _job_mgr())
    db.conn.execute("INSERT INTO blueprint_deployments (id, blueprint_id, cluster_id, node, status) "
                    "VALUES ('d1', 'b1', 'c1', 'pve1', 'queued')")
    db.conn.commit()
    bpmod.run_deploy('d1', 'c1', row or _row(), 'pve1', 'local-lvm', 150, 'web-01', template, build,
                     '', 'pw', start, 'root')
    return m, dict(db.conn.execute("SELECT * FROM blueprint_deployments WHERE id = 'd1'").fetchone())


def test_the_job_clones_configures_grows_and_starts(api, db):
    m, row = _job(api, db, template={'vmid': 9002, 'node': 'pve1', 'storage': 'local-lvm', 'shared': False})
    assert row['status'] == 'completed' and row['progress'] == 100, row['log']
    kw = m.clone_vm.call_args.kwargs
    assert (kw['node'], kw['vmid'], kw['newid'], kw['full'], kw['target_node'], kw['target_storage']) == \
        ('pve1', 9002, 150, True, None, 'local-lvm')
    url, sent = m._api_post.call_args.args[0], m._api_post.call_args.kwargs['data']
    assert url.endswith('/nodes/pve1/qemu/150/config') and sent['net0'] == 'virtio,bridge=vmbr0,tag=20,firewall=1'
    m.resize_vm_disk.assert_called_once_with('pve1', 150, 'qemu', 'scsi0', '32G')
    m.vm_action.assert_called_once_with('pve1', 150, 'qemu', 'start')
    assert 'pw' not in row['log']


def test_a_template_on_shared_storage_elsewhere_clones_across(api, db):
    m, row = _job(api, db, template={'vmid': 9001, 'node': 'pve2', 'storage': 'ceph', 'shared': True}, start=False)
    kw = m.clone_vm.call_args.kwargs
    assert (kw['node'], kw['target_node']) == ('pve2', 'pve1')
    m._wait_for_task.assert_called_once_with('pve2', 'UPID:pve1:clone', timeout=3600)
    assert not m.vm_action.called and row['status'] == 'completed'


def test_a_larger_image_keeps_its_disk(api, db):
    m, row = _job(api, db, template={'vmid': 9002, 'node': 'pve1', 'storage': 'x', 'shared': False},
                  row=_row(disk_gb=2))
    assert not m.resize_vm_disk.called and 'the image is already 3.5 GB' in row['log']


def test_the_job_builds_the_template_first_with_the_library(api, db, monkeypatch):
    calls = []

    def built(dep_id, cluster_id, node, template_id, storage, vmid, name):
        calls.append((cluster_id, node, template_id, storage, vmid, name))
        db.conn.execute("UPDATE cloud_init_deployments SET status = 'completed' WHERE id = ?", (dep_id,))
        db.conn.commit()
    monkeypatch.setattr(tpl, '_run_deploy', built)
    _built(db, 9003, 'pve1', 'local-lvm', status='queued')
    db.conn.execute("UPDATE cloud_init_deployments SET id = 'lib1' WHERE vmid = 9003")
    db.conn.commit()
    m, row = _job(api, db, build={'dep_id': 'lib1', 'vmid': 9003, 'name': 'tpl-debian-12'})
    assert calls == [('c1', 'pve1', 'debian-12', 'local-lvm', 9003, 'tpl-debian-12')]
    assert m.clone_vm.call_args.kwargs['vmid'] == 9003 and row['status'] == 'completed'


def test_a_failed_build_stops_before_the_clone(api, db, monkeypatch):
    monkeypatch.setattr(tpl, '_run_deploy', lambda *a: db.conn.execute(
        "UPDATE cloud_init_deployments SET status = 'failed', error = 'download failed' WHERE id = 'lib1'"))
    _built(db, 9003, 'pve1', 'local-lvm', status='queued')
    db.conn.execute("UPDATE cloud_init_deployments SET id = 'lib1' WHERE vmid = 9003")
    db.conn.commit()
    m, row = _job(api, db, build={'dep_id': 'lib1', 'vmid': 9003, 'name': 'tpl-debian-12'})
    assert row['status'] == 'failed' and 'download failed' in row['error']
    assert not m.clone_vm.called


@pytest.mark.parametrize('where', ['clone', 'wait', 'config', 'resize', 'start'])
def test_a_refusal_on_the_way_fails_the_deployment_and_says_where(api, db, monkeypatch, where):
    m = _job_mgr()
    if where == 'clone':
        m.clone_vm.return_value = {'success': False, 'error': 'storage full'}
    elif where == 'wait':
        m._wait_for_task.return_value = False
    elif where == 'config':
        m._api_post.return_value = _Resp(400, text='bad net0')
    elif where == 'resize':
        m.resize_vm_disk.return_value = {'success': False, 'error': 'no space'}
    else:
        m.vm_action.return_value = {'success': False, 'error': 'no quorum'}
    monkeypatch.setattr(bpmod, 'cluster_managers', {'c1': m})
    db.conn.execute("INSERT INTO blueprint_deployments (id, blueprint_id, cluster_id, node, status) "
                    "VALUES ('d1', 'b1', 'c1', 'pve1', 'queued')")
    db.conn.commit()
    bpmod.run_deploy('d1', 'c1', _row(), 'pve1', 'local-lvm', 150, 'web-01',
                     {'vmid': 9002, 'node': 'pve1', 'storage': 'x', 'shared': False}, None, '', '', True, 'root')
    row = dict(db.conn.execute("SELECT * FROM blueprint_deployments WHERE id = 'd1'").fetchone())
    assert row['status'] == 'failed' and row['error']
    assert row['step'] == {'clone': 'clone', 'wait': 'clone', 'config': 'configure',
                           'resize': 'resize', 'start': 'start'}[where]


# --- reading deployments ----------------------------------------------------------------

def test_deployments_are_read_per_cluster_the_caller_sees(api, seed, lab, db, no_thread):
    _built(db, 9002, 'pve1', 'local-lvm')
    dep = _deploy(lab.admin, lab.bid, vmid=150).get_json()['deployment_id']
    rows = lab.admin.get('/api/blueprints/deployments?cluster_id=c1').get_json()['deployments']
    assert [r['id'] for r in rows] == [dep] and 'log' not in rows[0]
    one = lab.admin.get(f'/api/blueprints/deployments/{dep}').get_json()
    assert one['id'] == dep and 'log' in one
    assert lab.admin.get('/api/blueprints/deployments/nope').status_code == 404
    seed.tenant('t_b', clusters=['c9'])
    other = api.as_user(seed.user('olga', tenant_id='t_b', permissions=['cluster.view']))
    assert other.get(f'/api/blueprints/deployments/{dep}').status_code in (403, 404)
    assert other.get('/api/blueprints/deployments?cluster_id=c1').status_code in (403, 404)


def test_the_template_probe_answers_per_node(lab, db):
    _built(db, 9002, 'pve1', 'local-lvm')
    r = lab.admin.get(f'/api/clusters/c1/blueprints/{lab.bid}/template?node=pve1').get_json()
    assert r == {'source_kind': 'library', 'build_needed': False,
                 'template': {'vmid': 9002, 'node': 'pve1', 'storage': 'local-lvm', 'shared': False}}
    r = lab.admin.get(f'/api/clusters/c1/blueprints/{lab.bid}/template?node=pve2').get_json()
    assert r == {'source_kind': 'library', 'template': None, 'build_needed': True}
    assert lab.admin.get(f'/api/clusters/c1/blueprints/{lab.bid}/template?node=pve9').status_code == 400
