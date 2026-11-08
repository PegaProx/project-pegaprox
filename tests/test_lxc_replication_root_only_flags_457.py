"""Cross-cluster replication of a container with feature flags only root@pam may set (#457).

A run remote-migrates a clone, and the target creates the container with the API token
the job made there. pve-container checks that write in check_ct_modify_config_perm
(the mtunnel 'config' command) and lets only root@pam through: on a new unprivileged
container every flag but a lone nesting, on a privileged one every flag. The job is
still created; its answer, the preflight of the dialog and a failed run say why.

The PVE side, as pve-container (master and stable-bookworm) and pve-guest-common have it:
  raise_perm_exc("changing feature flags (except nesting) is only allowed for root\\@pam")
  -> "403 Permission check failed (changing feature flags (except nesting) ...)"
  the tunnel: "error - tunnel command 'config' failed - failed to handle 'config' command - ..."
  AbstractMigrate logs "migration aborted (duration ...): <that>" and the task status is
  just "migration aborted", so the reason is only in the log.

MK Oct 2026
"""
import json
import os

import pytest

import pegaprox.api.vms as vms
import pegaprox.globals as ppglobals

from test_ha_ui import CLUSTER, _App, _FakeServer, browser  # noqa: F401

SRC, TGT = 'cluster_1', 'cluster_2'
CT = 105
# the line a failed run leaves in the source task log (pve-guest-common AbstractMigrate)
REFUSED_LINE = ("2026-10-25 10:00:03 ERROR: migration aborted (duration 00:00:03): error - tunnel command "
                "'config' failed - failed to handle 'config' command - 403 Permission check failed "
                "(changing feature flags (except nesting) is only allowed for root@pam)")
PRIVILEGED_LINE = ("2026-10-25 10:00:03 ERROR: migration aborted (duration 00:00:03): error - tunnel command "
                   "'config' failed - failed to handle 'config' command - 403 Permission check failed "
                   "(changing feature flags for privileged container is only allowed for root@pam)")


class _R:
    def __init__(self, status=200, data=None, **top):
        self.status_code = status
        self._body = dict({'data': data}, **top)
        self.text = json.dumps(self._body)

    def json(self):
        return self._body


def _pending_rows(features=None, unprivileged=True, pending=None):
    rows = [{'key': 'arch', 'value': 'amd64'}, {'key': 'hostname', 'value': 'zt01'},
            {'key': 'digest', 'value': 'abc'}]
    if unprivileged:
        rows.append({'key': 'unprivileged', 'value': 1})
    if features is not None:
        row = {'key': 'features', 'value': features}
        if pending is not None:
            row['pending'] = pending
        rows.append(row)
    return rows


class _Session:
    def __init__(self, mgr):
        self.mgr = mgr

    def get(self, url, **kw):
        self.mgr.reads.append(url.split('/api2/json', 1)[1])
        if url.endswith(f'/nodes/pve1/lxc/{CT}/pending'):
            return _R(200, _pending_rows(**self.mgr.ct))
        return _R(500, None)


def _manager(api, cid, ct=None, kind='lxc'):
    m = api.make_fake_manager(cid)
    m.is_connected = True
    m.host, m.api_port = f'{cid}.example', 8006
    m.reads = []
    m.ct = ct or {}
    m.get_vm_resources.return_value = [{'vmid': CT, 'node': 'pve1', 'type': kind, 'name': 'zt01'},
                                       {'vmid': 100, 'node': 'pve1', 'type': 'qemu', 'name': 'web01'}]
    m._create_session.side_effect = lambda *a, **k: _Session(m)
    return api.set_manager(cid, m)


@pytest.fixture
def admin(api, seed):
    return api.as_user(seed.user('root', role='admin'))


def _create(client, **body):
    data = {'source_cluster': SRC, 'target_cluster': TGT, 'vmid': CT, 'vm_type': 'lxc',
            'target_storage': 'local-lvm', 'schedule': '0 */6 * * *', 'retention': 3}
    data.update(body)
    return client.post('/api/cross-cluster-replications', json=data)


# --- which flags only root@pam may set --------------------------------------------------------

@pytest.mark.parametrize('features,unprivileged,expected', [
    ('', True, []),
    (None, True, []),
    ('nesting=1', True, []),
    ('nesting=0', True, []),
    ('mknod=1', True, ['mknod']),
    ('keyctl=1,nesting=1', True, ['keyctl']),
    ('fuse=1', True, ['fuse']),
    ('mount=nfs', True, ['mount=nfs']),
    ('mount=nfs;cifs,nesting=1', True, ['mount=nfs;cifs']),
    ('force_rw_sys=1', True, ['force_rw_sys']),
    # PVE goes by the keys: a flag written as off is still a flag on a new container
    ('nesting=1,keyctl=0', True, ['keyctl=0']),
    # a privileged container: every flag, nesting too
    ('nesting=1', False, ['nesting']),
    ('nesting=1,mknod=1', False, ['nesting', 'mknod']),
])
def test_the_flags_only_root_may_set_on_a_new_container(features, unprivileged, expected):
    assert vms._lxc_root_only_features(features, unprivileged) == expected


# --- the job answer ----------------------------------------------------------------------------

@pytest.mark.parametrize('features,flags', [
    ('mknod=1', 'mknod'),
    ('keyctl=1,nesting=1', 'keyctl'),
    ('fuse=1', 'fuse'),
    ('mount=nfs', 'mount=nfs'),
    ('nesting=1,keyctl=1,fuse=1,mknod=1,mount=nfs;cifs', 'keyctl, fuse, mknod, mount=nfs;cifs'),
])
def test_creating_the_job_answers_with_the_warning(api, admin, db, features, flags):
    src = _manager(api, SRC, ct={'features': features})
    _manager(api, TGT)
    r = _create(admin)
    assert r.status_code == 200, r.get_data(as_text=True)[:400]
    body = r.get_json()
    assert body['success'] is True
    (warn,) = body['warnings']
    assert warn['code'] == 'LXC_ROOT_ONLY_FEATURES' and warn['level'] == 'warning'
    assert warn['args'] == {'vmid': CT, 'flags': flags}
    assert f'({flags})' in warn['text'] and 'root@pam' in warn['text'] and 'API token' in warn['text']
    # a warning, not a refusal: the job is there and enabled
    row = db.query_one('SELECT vm_type, enabled FROM cross_cluster_replications WHERE id = ?', (body['id'],))
    assert (row['vm_type'], row['enabled']) == ('lxc', 1)
    # one read of the container, the node from the live view
    assert src.reads == [f'/nodes/pve1/lxc/{CT}/pending']
    audit = db.query_one("SELECT details FROM audit_log WHERE action = 'replication.created'")
    assert f'feature flags {flags} need root@pam' in audit['details']


@pytest.mark.parametrize('ct', [{'features': 'nesting=1'}, {}, {'features': ''}],
                         ids=['nesting only', 'no features', 'empty'])
def test_no_warning_for_nesting_alone_or_no_flags(api, admin, ct):
    src = _manager(api, SRC, ct=ct)
    _manager(api, TGT)
    r = _create(admin)
    assert r.status_code == 200, r.data
    assert 'warnings' not in r.get_json()
    assert src.reads == [f'/nodes/pve1/lxc/{CT}/pending']


def test_a_privileged_container_warns_for_nesting_too(api, admin):
    _manager(api, SRC, ct={'features': 'nesting=1', 'unprivileged': False})
    _manager(api, TGT)
    (warn,) = _create(admin).get_json()['warnings']
    assert warn['args']['flags'] == 'nesting'


def test_a_flag_that_waits_for_the_next_start_counts_too(api, admin):
    """The clone copies what runs, the later runs what the container has after its restart."""
    _manager(api, SRC, ct={'features': 'nesting=1', 'pending': 'nesting=1,mknod=1'})
    _manager(api, TGT)
    (warn,) = _create(admin).get_json()['warnings']
    assert warn['args']['flags'] == 'mknod'


def test_a_vm_is_not_read(api, admin):
    src = _manager(api, SRC, ct={'features': 'mknod=1'})
    _manager(api, TGT)
    r = _create(admin, vmid=100, vm_type='qemu')
    assert r.status_code == 200, r.data
    assert 'warnings' not in r.get_json()
    assert src.reads == [] and not src.get_vm_resources.called


def test_a_job_inside_one_cluster_is_not_read(api, admin):
    """A local job clones and migrates within the cluster: no flag is written anew."""
    src = _manager(api, SRC, ct={'features': 'mknod=1'})
    r = _create(admin, target_cluster=SRC, target_node='pve2')
    assert r.status_code == 200, r.data
    assert 'warnings' not in r.get_json() and src.reads == []


def test_an_unreadable_container_still_gets_its_job(api, admin, db):
    src = _manager(api, SRC, ct={'features': 'mknod=1'})
    src.get_vm_resources.return_value = []      # not in the live view, and no node said
    _manager(api, TGT)
    r = _create(admin)
    assert r.status_code == 200 and 'warnings' not in r.get_json(), r.data
    assert src.reads == []
    # the node the dialog sends is used when the live view has no row
    r = _create(admin, source_node='pve1')
    assert r.get_json()['warnings'][0]['args']['flags'] == 'mknod'
    # and one that is no node name goes nowhere
    src.reads.clear()
    r = _create(admin, source_node='pve1/../../access')
    assert 'warnings' not in r.get_json() and src.reads == []


# --- the preflight of the dialog --------------------------------------------------------------

PF = '/api/cross-cluster-replications/preflight'


def test_the_preflight_names_the_flags(api, admin, db):
    src = _manager(api, SRC, ct={'features': 'mknod=1,nesting=1'})
    r = admin.post(PF, json={'source_cluster': SRC, 'vmid': CT, 'vm_type': 'lxc', 'source_node': 'pve1'})
    assert r.status_code == 200, r.data
    (warn,) = r.get_json()['warnings']
    assert warn['code'] == 'LXC_ROOT_ONLY_FEATURES' and warn['args'] == {'vmid': CT, 'flags': 'mknod'}
    assert src.reads == [f'/nodes/pve1/lxc/{CT}/pending']
    # it writes nothing
    assert db.query_one('SELECT COUNT(*) AS n FROM cross_cluster_replications')['n'] == 0


@pytest.mark.parametrize('body', [
    {'vmid': 100, 'vm_type': 'qemu'},
    {'vmid': CT, 'vm_type': 'lxc', 'target_cluster': SRC},
], ids=['a VM', 'inside one cluster'])
def test_the_preflight_reads_nothing_it_does_not_need(api, admin, body):
    src = _manager(api, SRC, ct={'features': 'mknod=1'})
    r = admin.post(PF, json=dict({'source_cluster': SRC}, **body))
    assert r.status_code == 200, r.data
    assert r.get_json() == {'warnings': []}
    assert src.reads == [] and not src.get_vm_resources.called


def test_the_preflight_has_the_gates_of_the_create_route(api, seed):
    src = _manager(api, SRC, ct={'features': 'mknod=1'})
    body = {'source_cluster': SRC, 'vmid': CT, 'vm_type': 'lxc'}
    viewer = api.as_user(seed.user('vic', role='viewer'))
    assert viewer.post(PF, json=body).status_code == 403
    assert api.anon().post(PF, json=body).status_code == 401
    # cluster.config, but the guest is a co-tenant's
    seed.tenant('tenant_a', clusters=[SRC, TGT])
    alice = api.as_user(seed.user('alice', role='user', tenant_id='tenant_a', permissions=['cluster.config']))
    seed.vm_acl(SRC, 100, ['alice'], permissions=['vm.migrate', 'vm.view'])
    assert alice.post(PF, json=body).status_code == 403
    assert src.reads == []
    admin = api.as_user(seed.user('root', role='admin'))
    assert admin.post(PF, json=dict(body, source_cluster='nope')).status_code == 404
    assert admin.post(PF, json={'source_cluster': SRC}).status_code == 400
    assert admin.post(PF, json=dict(body, vmid='x')).status_code == 400


@pytest.mark.parametrize('confined_on_target', [True, False], ids=['confined on the target', 'not'])
def test_the_preflight_refuses_a_target_the_caller_is_confined_to(api, seed, confined_on_target):
    # the container is theirs; a target they only reach through a VM of it is not theirs to
    # aim a job at, the create route refuses that and so does this
    _manager(api, SRC, ct={'features': 'mknod=1'})
    _manager(api, TGT)
    seed.tenant('tenant_a', clusters=[SRC, TGT])
    seed.vm_acl(SRC, CT, ['bob'], permissions=['vm.migrate', 'vm.view'])
    if confined_on_target:
        seed.vm_acl(TGT, 300, ['bob'], permissions=['vm.view'])
    bob = api.as_user(seed.user('bob', role='user', tenant_id='tenant_a', permissions=['cluster.config']))
    r = bob.post(PF, json={'source_cluster': SRC, 'target_cluster': TGT, 'vmid': CT, 'vm_type': 'lxc'})
    if confined_on_target:
        assert r.status_code == 403 and 'target cluster' in r.get_json()['error'], r.data
    else:
        assert r.status_code == 200 and r.get_json()['warnings'], r.data



@pytest.mark.parametrize('route', [PF, '/api/cross-cluster-replications'], ids=['preflight', 'create'])
@pytest.mark.parametrize('body', [
    {'source_cluster': [SRC], 'target_cluster': TGT, 'vmid': CT},
    {'source_cluster': {'id': SRC}, 'target_cluster': TGT, 'vmid': CT},
    {'source_cluster': SRC, 'target_cluster': [TGT], 'vmid': CT},
], ids=['source a list', 'source an object', 'target a list'])
def test_a_cluster_id_that_is_no_string_is_a_bad_request(api, admin, route, body):
    _manager(api, SRC, ct={'features': 'mknod=1'})
    _manager(api, TGT)
    r = admin.post(route, json=dict(body, vm_type='lxc'))
    assert r.status_code == 400, r.data


def test_the_create_route_wants_an_object(api, admin):
    assert admin.post('/api/cross-cluster-replications', json=[SRC, TGT]).status_code == 400

# --- a run Proxmox refused ----------------------------------------------------------------------

class _Cluster:
    """One side of a full run of CT 105, GETs by path, the migration log as PVE serves it."""

    def __init__(self, node, guests=None, log=None, clone_cfg=None):
        self.host, self.api_port, self.is_connected = f'{node}.example', 8006, True
        self.node, self.guests = node, guests or {}
        self.log = log or []
        self.clone_cfg = clone_cfg or {}
        self.log_reads = []
        self.migrations, self.tokens_deleted = [], []

    def _api_get(self, url, params=None, **kw):
        path = url.split('/api2/json', 1)[1]
        if path == '/cluster/resources':
            return _R(200, [{'vmid': v, 'node': self.node, 'type': 'lxc', 'status': 'stopped'}
                            for v in self.guests])
        if path == '/cluster/nextid':
            return _R(200, '9100')
        if path == '/storage':
            return _R(200, [{'storage': 'fast', 'type': 'lvmthin'}])
        if path == f'/nodes/{self.node}/lxc/9100/config':
            return _R(200, dict({'rootfs': 'fast:vm-9100-disk-0,size=8G'}, **self.clone_cfg))
        if path == f'/nodes/{self.node}/tasks/UPID:{self.node}:0001:0002:0003:vzmigrate:9100:root@pam:/log':
            self.log_reads.append(dict(params or {}))
            start, limit = int(params['start']), int(params['limit'])
            lines = [{'n': i + 1, 't': t} for i, t in enumerate(self.log)][start:start + limit]
            return _R(200, lines, total=len(self.log))
        return _R(404)

    def _api_post(self, url, data=None, **kw):
        return _R(200, 'UPID:post')

    def _api_delete(self, url, params=None, **kw):
        return _R(200, 'UPID:delete')

    def _get_vm_storage(self, node, vmid, vm_type):
        return 'fast'

    def create_api_token(self, name):
        return {'success': True, 'token_id': 'root@pam!xcrepl', 'token_value': 'secret'}

    def delete_api_token(self, name):
        self.tokens_deleted.append(name)

    def get_cluster_fingerprint(self):
        return {'success': True, 'host': self.host, 'fingerprint': 'AA:BB'}

    def remote_migrate_vm(self, **kw):
        self.migrations.append(kw.get('vmid'))
        return {'success': True, 'task': f'UPID:{self.node}:0001:0002:0003:vzmigrate:9100:root@pam:'}


# a long transfer before the config step: the reason is at the end, past the first page
_TRANSFER = [f'2026-10-25 10:00:0{i % 10} transferred {i} MiB of 4096 MiB' for i in range(400)]


@pytest.fixture
def run(db, monkeypatch):
    said = []
    # the migration task ends 'migration aborted' (TASK ERROR), the rest went through
    monkeypatch.setattr(vms, '_wait_for_task',
                        lambda mgr, upid, **k: (False, 'migration aborted') if 'vzmigrate' in str(upid)
                        else (True, 'OK'))
    monkeypatch.setattr(vms, '_capture_vm_identity', lambda *a, **k: {})
    monkeypatch.setattr(vms, '_cleanup_snapshot', lambda *a, **k: None)
    monkeypatch.setattr(vms, '_enforce_retention', lambda *a, **k: None)
    monkeypatch.setattr(vms, '_update_repl_status', lambda _db, job_id, status, error='':
                        said.append((status, error)))

    def go(log, vm_type='lxc', clone_cfg=None):
        src = _Cluster('pve1', guests={CT: 'stopped'}, log=log, clone_cfg=clone_cfg)
        tgt = _Cluster('pve2')
        monkeypatch.setitem(ppglobals.cluster_managers, 'src', src)
        monkeypatch.setitem(ppglobals.cluster_managers, 'tgt', tgt)
        vms._execute_replication({'id': 'j1', 'vmid': CT, 'vm_type': vm_type, 'source_cluster': 'src',
                                  'target_cluster': 'tgt', 'target_storage': 'far', 'target_node': 'pve2',
                                  'mode': 'full'})
        return src, said
    return go


def test_a_run_refused_for_its_flags_says_so(run):
    src, said = run(_TRANSFER + [REFUSED_LINE, 'TASK ERROR: migration aborted'],
                    clone_cfg={'features': 'nesting=1,mknod=1', 'unprivileged': 1})
    assert src.migrations == [9100]
    (status, error), = said
    assert status == 'error'
    assert error.startswith(f'Proxmox refused to create the replica of CT {CT} on the target: '
                            f'its feature flags (mknod) can only be set by root@pam'), error
    assert 'API token' in error
    assert '(Proxmox: changing feature flags (except nesting) is only allowed for root@pam)' in error
    assert 'Migration task failed' not in error
    # its length first, then the end of it
    assert src.log_reads == [{'start': 0, 'limit': 1}, {'start': len(_TRANSFER) + 2 - 60, 'limit': 60}]


def test_a_privileged_container_names_every_flag(run):
    _src, said = run([PRIVILEGED_LINE], clone_cfg={'features': 'nesting=1'})
    (status, error), = said
    assert 'its feature flags (nesting) can only be set by root@pam' in error
    assert '(Proxmox: changing feature flags for privileged container is only allowed for root@pam)' in error


def test_a_run_that_failed_for_something_else_keeps_the_proxmox_status(run):
    src, said = run(['ERROR: migration aborted (duration 00:00:01): storage migration failed - no space left'],
                    clone_cfg={'features': 'mknod=1', 'unprivileged': 1})
    assert said == [('error', 'Migration task failed: migration aborted')]
    assert len(src.log_reads) == 2


def test_a_vm_run_does_not_read_the_log(run):
    src, said = run([REFUSED_LINE], vm_type='qemu')
    assert said == [('error', 'Migration task failed: migration aborted')]
    assert src.log_reads == []


def test_an_unreadable_log_keeps_the_proxmox_status(monkeypatch):
    class _Down:
        host, api_port = 'pve1.example', 8006

        def _api_get(self, url, **kw):
            raise ConnectionError('gone')
    assert vms._root_only_features_refusal(_Down(), 'pve1', 'UPID:pve1:1:2:3:vzmigrate:9100:root@pam:',
                                           CT, {}) is None
    # nor does a node or an UPID that is none reach the URL
    assert vms._task_log_tail(_Down(), 'pve1/../x', 'UPID:pve1:1') == []
    assert vms._task_log_tail(_Down(), 'pve1', 'UPID:a/b') == []


# --- the dialogs -----------------------------------------------------------------------------

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LANGS = ['de', 'en', 'zh', 'pl', 'fr', 'es', 'pt', 'ko', 'it']


def _src(name):
    with open(os.path.join(ROOT, 'web', 'src', name), encoding='utf-8') as fh:
        return fh.read()


def test_both_create_dialogs_show_the_warning():
    modals, config = _src('vm_modals.js'), _src('vm_config.js')
    assert 'function XReplFeatureWarning({ authFetch, sourceCluster, vmid, vmType, node })' in modals
    assert '`${API_URL}/cross-cluster-replications/preflight`' in modals
    # the group settings dialog, with the CT picked there
    group = modals[modals.index('function GroupSettingsModal('):]
    assert 'vmid={xReplForm.vmid}' in group and 'vmType={xReplForm.vm_type}' in group
    # the VM configuration dialog, inside the form that opens with Add DR Job
    form = config[config.index('{/* MK: inline form for new cross-cluster job */}'):]
    form = form[:form.index("{t('create')}")]
    assert ('<XReplFeatureWarning authFetch={authFetch} sourceCluster={clusterId} vmid={vm.vmid} '
            'vmType={vm.type} node={vm.node} />') in form


def test_the_text_is_there_in_every_language():
    import re
    tr = _src('translations.js')
    found = re.findall(r"^\s*xReplRootOnlyFeatures: '(.*)',$", tr, re.M)
    assert len(found) == len(LANGS)
    for text in found:
        assert '{vmid}' in text and '{flags}' in text and 'root@pam' in text and 'API' in text
    assert '\u2014' not in ''.join(found)


# --- runtime: the dialog in the browser --------------------------------------------------------

LXC_ROW = {'vmid': CT, 'name': 'zt01', 'type': 'lxc', 'status': 'running', 'node': 'pve1',
           'cpu': 0.01, 'cpu_percent': 1, 'maxcpu': 1, 'mem': 268435456, 'maxmem': 536870912,
           'mem_percent': 50, 'disk': 0, 'maxdisk': 8589934592, 'uptime': 3600}
LXC_CONFIG = {'general': {'hostname': 'zt01', 'description': '', 'tags': ''},
              'resources': {'cores': 1, 'memory': 512, 'swap': 512, 'cpulimit': 0, 'cpuunits': 100},
              'disks': [{'id': 'rootfs', 'value': 'local-lvm:vm-105-disk-0,size=8G', 'storage': 'local-lvm',
                         'size': '8G', 'volume': 'vm-105-disk-0'}],
              'networks': [{'id': 'net0', 'value': 'name=eth0,bridge=vmbr0,hwaddr=AA:BB:CC:DD:EE:01,ip=dhcp',
                            'bridge': 'vmbr0', 'name': 'eth0', 'hwaddr': 'AA:BB:CC:DD:EE:01'}],
              'options': {'onboot': 0, 'ostype': 'debian', 'unprivileged': 1},
              'raw': {'hostname': 'zt01', 'features': 'nesting=1,mknod=1', 'unprivileged': 1, 'digest': 'x'},
              'status': {'status': 'running'}, 'vmid': CT, 'node': 'pve1', 'type': 'lxc',
              'lock': {'locked': False}}


def _warning_body(features):
    """What the real preflight answers for a container with these flags."""
    class _M:
        cluster_type, host, api_port = 'proxmox', 'pve1.example', 8006

        def get_vm_resources(self, max_age=0):
            return [{'vmid': CT, 'node': 'pve1', 'type': 'lxc'}]

        def _create_session(self):
            return self

        def get(self, url, **kw):
            return _R(200, _pending_rows(features=features))
    warn = vms._xcrepl_feature_warning(_M(), CT)
    return {'warnings': [warn] if warn else []}


def _open_ct_config(browser, features, resources=None):
    remote = dict(CLUSTER, id='c2', name='Remote', display_name='Remote', host='10.0.0.2')
    server = _FakeServer(role='active', layout='modern', clusters=[CLUSTER, remote],
                         resources=resources or [LXC_ROW],
                         extra={('GET', f'/api/clusters/c1/vms/pve1/lxc/{CT}/config'): (200, LXC_CONFIG),
                                ('GET', '/api/cross-cluster-replications'): (200, []),
                                ('POST', PF): (200, _warning_body(features))})
    app = _App(browser, server)
    page = app.page
    page.get_by_text('Testi').first.click()
    page.locator('button', has_text='Resources').first.click()
    page.get_by_text('zt01').first.wait_for(timeout=5000)
    page.wait_for_timeout(300)
    page.locator('button[title="Configuration"]').first.click()
    page.locator('button', has_text='Replication').first.wait_for(timeout=8000)
    page.locator('button', has_text='Replication').first.click()
    page.locator('button', has_text='Add DR Job').first.click()
    return app


def test_runtime_the_dialog_warns_before_create(browser):
    app = _open_ct_config(browser, 'nesting=1,mknod=1')
    try:
        page = app.page
        box = page.locator('[data-xrepl-features-warning]')
        box.wait_for(timeout=5000)
        text = box.inner_text()
        assert f'CT {CT} has feature flags (mknod) that Proxmox only lets root@pam set' in text, text
        assert 'The job can still be created.' in text
        # the form is still there to fill in, Create included
        assert page.locator('button', has_text='Create').count() >= 1
        assert app.server.bodies[PF] == [{'source_cluster': 'c1', 'vmid': CT, 'vm_type': 'lxc',
                                          'source_node': 'pve1'}]
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


def test_runtime_no_warning_for_nesting_alone(browser):
    app = _open_ct_config(browser, 'nesting=1')
    try:
        page = app.page
        page.get_by_text('New Cross-Cluster Replication').first.wait_for(timeout=5000)
        deadline = 0
        while ('POST', PF) not in app.server.calls and deadline < 20:
            page.wait_for_timeout(100)
            deadline += 1
        assert ('POST', PF) in app.server.calls
        page.wait_for_timeout(300)
        assert page.locator('[data-xrepl-features-warning]').count() == 0
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


def test_runtime_the_group_dialog_warns_once_the_container_is_picked(browser):
    """The group settings: source cluster and guest picked in the form, a VM is not asked about."""
    vm_row = dict(LXC_ROW, vmid=100, name='web01', type='qemu')
    grouped = [dict(CLUSTER, group_id='g1'),
               dict(CLUSTER, id='c2', name='Remote', display_name='Remote', host='10.0.0.2', group_id='g1')]
    server = _FakeServer(role='active', layout='modern', clusters=grouped, resources=[LXC_ROW, vm_row],
                         extra={('GET', '/api/cluster-groups'): (200, [{'id': 'g1', 'name': 'DR-Group',
                                                                         'color': '#E86F2D'}]),
                                ('GET', '/api/clusters/c1/vms'): (200, {'vms': [vm_row, LXC_ROW]}),
                                ('GET', '/api/cross-cluster-replications'): (200, []),
                                ('POST', PF): (200, _warning_body('mknod=1,fuse=1'))})
    app = _App(browser, server)
    try:
        page = app.page
        page.get_by_text('DR-Group').first.click()
        page.locator('button[title="Settings"]').last.click()
        page.locator('button', has_text='Cross-Cluster Replication').first.click()
        page.locator('button', has_text='Add DR Job').first.click()
        form = page.locator('div', has=page.locator('h5', has_text='New Cross-Cluster Replication')).last
        form.locator('select').first.select_option('c1')
        vm_select = form.locator('select').nth(1)
        vm_select.locator('option[value="100"]').wait_for(state='attached', timeout=5000)
        vm_select.select_option('100')
        page.wait_for_timeout(500)
        assert ('POST', PF) not in app.server.calls
        assert page.locator('[data-xrepl-features-warning]').count() == 0
        vm_select.select_option(str(CT))
        box = page.locator('[data-xrepl-features-warning]')
        box.wait_for(timeout=5000)
        assert f'CT {CT} has feature flags (mknod, fuse) that Proxmox only lets root@pam set' in box.inner_text()
        assert app.server.bodies[PF] == [{'source_cluster': 'c1', 'vmid': CT, 'vm_type': 'lxc',
                                          'source_node': 'pve1'}]
        # another guest picked: the warning goes with it
        vm_select.select_option('100')
        page.wait_for_timeout(300)
        assert page.locator('[data-xrepl-features-warning]').count() == 0
        assert not app.errors, app.errors
    finally:
        app.ctx.close()
