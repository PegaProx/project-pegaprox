# -*- coding: utf-8 -*-
"""Low findings on the migration paths, Oct 2026. NS

* (#984) confirm-cutover on a run started with remove_source asks vmware.vm.manage, the
  right the start asked for the deletion it sets off.
* (#1046) a config restore drops the cached tenants, so a cluster it takes away is gone
  at once and not after the next restart.
* (#1079) the PVE-to-XCP-ng runner destroys the source only while the VMID still names
  the guest it copied.
* the ESXi-to-XCP-ng runner checks the datastore and path parts of the VMDK backing like
  its ESXi-to-PVE twin does.
* (#1029, #1117, #1112, #1123, #1090) what the V2P engine leaves on the PVE node: the
  ESXi key and credential files, the datastore mount, the host-key policy of the node's
  ssh, the helper scripts it runs as root, and the ISO it loop-mounts.

The node side is driven with recording fakes. Commands that only write files run for
real in a sandbox where /tmp and /run are directories under tmp_path; nothing that would
reach a host runs.
"""
import ast
import os
import pathlib
import re
import stat
import subprocess
import types
from unittest.mock import MagicMock

import pytest

import pegaprox.core.v2p as v2p
import pegaprox.core.xhm as xhm
import pegaprox.globals as ppglobals

_V2P_SRC = pathlib.Path(v2p.__file__).read_text(encoding='utf-8')


# --------------------------------------------------------------------------- (#984)

def _cutover_task(remove_source):
    t = types.SimpleNamespace(vmware_id='esxi1', vm_id='vm-7', target_cluster='cluster_1',
                              vm_name='app-01', phase='awaiting_confirmation',
                              remove_source=remove_source)
    t.to_dict = lambda: {'id': 'mig9', 'phase': t.phase}
    return t


@pytest.fixture
def cutover(api, seed):
    """An ESXi server the caller's tenant owns, and a run parked at the cutover gate."""
    seed.tenant('tenant_x', clusters=['cluster_1'])
    m = api.make_fake_manager(cluster_id='cluster_1')
    m.is_connected = True
    api.set_manager('cluster_1', m)
    ppglobals.vmware_managers['esxi1'] = types.SimpleNamespace(linked_clusters=['cluster_1'],
                                                              host='10.0.0.5')
    from pegaprox.api import vmware as vmw_mod

    def _park(remove_source):
        t = _cutover_task(remove_source)
        vmw_mod._vmware_migrations['mig9'] = t
        return t

    try:
        yield _park
    finally:
        vmw_mod._vmware_migrations.pop('mig9', None)
        ppglobals.vmware_managers.pop('esxi1', None)


def _operator(seed, name):
    """A co-operator: migrate on the ESXi guests of the tenant, no manage."""
    return seed.user(name, role='viewer', tenant_id='tenant_x',
                     permissions=['vmware.vm.migrate'])


def test_confirming_a_removing_cutover_needs_vmware_vm_manage(api, seed, cutover):
    t = cutover(remove_source=True)
    r = api.as_user(_operator(seed, 'coop')).post('/api/vmware/migrations/mig9/confirm-cutover')
    assert r.status_code == 403, r.get_data(as_text=True)
    assert not getattr(t, '_cutover_confirmed', False)


def test_an_acl_that_grants_migrate_only_does_not_confirm_it_either(api, seed, cutover):
    t = cutover(remove_source=True)
    seed.vm_acl('vmware:esxi1', 'vm-7', ['portal'], inherit_role=False,
                permissions=['vmware.vm.view', 'vmware.vm.migrate'])
    u = seed.user('portal', role='user', tenant_id='tenant_x')
    assert api.as_user(u).get('/api/vmware/migrations/mig9').status_code == 200
    r = api.as_user(u).post('/api/vmware/migrations/mig9/confirm-cutover')
    assert r.status_code == 403, r.get_data(as_text=True)
    assert not getattr(t, '_cutover_confirmed', False)


def test_a_cutover_that_keeps_the_source_still_needs_only_migrate(api, seed, cutover):
    t = cutover(remove_source=False)
    r = api.as_user(_operator(seed, 'coop')).post('/api/vmware/migrations/mig9/confirm-cutover')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert t._cutover_confirmed is True


def test_the_default_user_role_confirms_a_removing_cutover(api, seed, cutover):
    """The shipped user role holds vmware.vm.manage."""
    t = cutover(remove_source=True)
    u = seed.user('owner', role='user', tenant_id='tenant_x')
    r = api.as_user(u).post('/api/vmware/migrations/mig9/confirm-cutover')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert t._cutover_confirmed is True


def test_an_admin_confirms_a_removing_cutover(api, seed, cutover):
    t = cutover(remove_source=True)
    admin = seed.user('root', role='admin', tenant_id='tenant_x')
    assert api.as_user(admin).post('/api/vmware/migrations/mig9/confirm-cutover').status_code == 200
    assert t._cutover_confirmed is True


def test_cancel_stays_open_to_the_migrate_holder(api, seed, cutover):
    """Cancelling leaves the source running, so it needs nothing beyond the run itself."""
    t = cutover(remove_source=True)
    r = api.as_user(_operator(seed, 'coop')).post('/api/vmware/migrations/mig9/cancel-cutover')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert t._cutover_cancelled is True


# --------------------------------------------------------------------------- (#1046)

_ADMIN_PW = 'Restore-Admin-pw-42!'
_BACKUP_PW = 'backup-pw-1046'


def _admin_with_password(api, seed):
    from pegaprox.utils.auth import hash_password
    user = seed.user('root', role='admin')
    salt, pw_hash = hash_password(_ADMIN_PW)
    row = seed.db.get_user('root')
    row.update(password_salt=salt, password_hash=pw_hash)
    seed.db.save_user('root', row)
    return api.as_user(user)


def _restore(client, tenants, dry_run=False):
    import io
    import json
    import pegaprox.api.settings as settings_api
    data = {'version': 'test', 'export_date': '2026-10-06T10:00:00', 'tenants': tenants}
    blob = settings_api._encrypt_backup(json.dumps(data), _BACKUP_PW)
    r = client.post('/api/config/restore', content_type='multipart/form-data',
                    data={'user_password': _ADMIN_PW, 'backup_password': _BACKUP_PW,
                          'dry_run': 'true' if dry_run else 'false',
                          'backup_file': (io.BytesIO(blob), 'x.pegabackup')})
    assert r.status_code == 200, r.get_data(as_text=True)
    return r.get_json()


def _clusters_of(user):
    from pegaprox.utils.rbac import get_user_clusters
    return set(get_user_clusters(user) or [])


def test_a_restore_that_takes_a_cluster_from_a_tenant_takes_it_at_once(api, seed):
    seed.tenant('acme', clusters=['c1', 'c2'])
    bob = seed.user('bob', role='user', tenant_id='acme')
    admin = _admin_with_password(api, seed)
    assert 'c2' in _clusters_of(bob)          # read once: the cache now holds acme

    res = _restore(admin, {'acme': {'name': 'acme', 'clusters': ['c1']}})

    assert res['restored']['tenants'] == 1
    assert _clusters_of(bob) == {'c1'}


def test_a_restore_that_gives_a_tenant_a_cluster_gives_it_at_once(api, seed):
    seed.tenant('acme', clusters=['c1'])
    bob = seed.user('bob', role='user', tenant_id='acme')
    admin = _admin_with_password(api, seed)
    assert _clusters_of(bob) == {'c1'}

    _restore(admin, {'acme': {'name': 'acme', 'clusters': ['c1', 'c3']}})

    assert _clusters_of(bob) == {'c1', 'c3'}


def test_a_dry_run_restore_changes_nothing(api, seed):
    seed.tenant('acme', clusters=['c1', 'c2'])
    bob = seed.user('bob', role='user', tenant_id='acme')
    admin = _admin_with_password(api, seed)

    _restore(admin, {'acme': {'name': 'acme', 'clusters': []}}, dry_run=True)

    assert _clusters_of(bob) == {'c1', 'c2'}


# --------------------------------------------------------------------------- (#1079)

_SRC_CFG = {'name': 'db01', 'memory': '2048', 'cores': '2', 'sockets': '1', 'ostype': 'l26',
            'scsi0': 'local-lvm:vm-100-disk-0,size=1G',
            'smbios1': 'uuid=11111111-2222-3333-4444-555555555555',
            'vmgenid': 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
            'meta': 'creation-qemu=9.0.2,ctime=1759000000'}

# what PVE hands a guest created later under the freed VMID
_NEWCOMER = dict(_SRC_CFG, name='someone-else',
                 smbios1='uuid=99999999-8888-7777-6666-555555555555',
                 vmgenid='ffffffff-0000-1111-2222-333333333333',
                 meta='creation-qemu=9.0.2,ctime=1759999999')


class _Chan:
    def exit_status_ready(self):
        return False

    def recv_exit_status(self):
        return 0


class _Export:
    """The stdout of the dd on the PVE node: a few bytes, then the end."""

    def __init__(self):
        self.channel = _Chan()
        self._left = [b'x' * 64]

    def read(self, n=-1):
        return self._left.pop() if self._left else b''


class _Ssh:
    def exec_command(self, cmd, timeout=None):
        return MagicMock(), _Export(), types.SimpleNamespace(read=lambda: b'')

    def close(self):
        pass


def _xapi():
    x = MagicMock(name='xapi')
    x.SR.get_all.return_value = ['sr']
    x.SR.get_record.return_value = {'name_label': 'sr1', 'uuid': 'sr-uuid'}
    x.VDI.create.return_value = 'vdi'
    x.VDI.get_uuid.return_value = 'vdi-uuid'
    x.VM.get_all.return_value = ['tpl']
    x.VM.get_is_a_template.return_value = True
    x.VM.get_name_label.return_value = 'Other install media'
    x.VM.clone.return_value = 'newvm'
    x.VM.get_VBDs.return_value = []
    x.VM.get_uuid.return_value = 'new-uuid'
    x.VM.get_power_state.return_value = 'Running'
    return x


@pytest.fixture
def pve_to_xcp(db, monkeypatch):
    """Runs _run_pve_to_xcpng against fakes. `later` is the source config the second read
    (the one before the destroy) returns."""

    def _run(later, remove_source=True):
        reads = [{'success': True, 'config': {'raw': dict(_SRC_CFG)}}, later]
        src = types.SimpleNamespace(
            is_connected=True, id='pve1',
            config=types.SimpleNamespace(ssh_user='root', ssh_key='', ssh_port=22, pass_='pw',
                                         user='root@pam'),
            get_vm_config=lambda node, vmid, kind: reads.pop(0) if reads else later)
        tgt = types.SimpleNamespace(is_connected=True, id='xcp1', host='xcp', _api=_xapi,
                                    _session=types.SimpleNamespace(_session='s'),
                                    config=types.SimpleNamespace(ssl_verification=False))
        monkeypatch.setitem(xhm.cluster_managers, 'pve1', src)
        monkeypatch.setitem(xhm.cluster_managers, 'xcp1', tgt)
        node_cmds = []

        def _node(mgr, node, cmd, timeout=600, **kw):
            node_cmds.append(cmd)
            if cmd.startswith('pvesm path'):
                return 0, '/dev/pve/vm-100-disk-0\n', ''
            return 0, '', ''

        def _put(method, url, data=None, **kw):
            while data.read(1 << 20):
                pass
            return types.SimpleNamespace(status_code=200)

        monkeypatch.setattr(xhm, '_pve_node_exec', _node)
        monkeypatch.setattr(xhm, '_resolve_pve_node_ip', lambda m, n: '10.0.0.9')
        monkeypatch.setattr(xhm, 'ssh_password_for', lambda c: 'pw')
        monkeypatch.setattr(xhm, '_connect_ssh', lambda *a, **k: _Ssh())
        monkeypatch.setattr(xhm.ha_transport, 'http', _put)
        monkeypatch.setattr(xhm.time, 'sleep', lambda s: None)
        # the source only goes once the target runs, so it is started and runs here
        task = xhm.XHMigrationTask('t1079', 'pve_to_xcpng', 'pve1', 'pve-a', '100', 'xcp1', '',
                                   'sr1', config={'remove_source': remove_source,
                                                  'start_after': True})
        xhm._run_pve_to_xcpng(task)
        return task, [c for c in node_cmds if 'qm destroy' in c]

    return _run


def test_a_vmid_that_now_names_another_guest_is_not_destroyed(pve_to_xcp):
    task, destroys = pve_to_xcp(later={'success': True, 'config': {'raw': dict(_NEWCOMER)}})
    assert task.phase == 'completed', task.log_lines[-5:]
    assert destroys == [], destroys
    assert any('left in place' in line for line in task.log_lines)


def test_a_source_that_is_gone_is_not_destroyed_either(pve_to_xcp):
    task, destroys = pve_to_xcp(later={'success': False, 'error': 'no such VM'})
    assert destroys == []


def test_the_copied_guest_is_still_removed(pve_to_xcp):
    task, destroys = pve_to_xcp(later={'success': True, 'config': {'raw': dict(_SRC_CFG)}})
    assert task.phase == 'completed', task.log_lines[-5:]
    assert destroys == ['qm destroy 100 --purge']


def test_without_remove_source_nothing_is_destroyed(pve_to_xcp):
    _, destroys = pve_to_xcp(later={'success': True, 'config': {'raw': dict(_SRC_CFG)}},
                             remove_source=False)
    assert destroys == []


# --------------------------------------------------------------------------- ESXi to XCP-ng

def _esxi_src(vmdk):
    disks = {'data': {'name': 'vm1', 'disks': [
        {'vmdk_file': vmdk, 'capacity_bytes': 1 << 30, 'capacity_gb': 1}]}}
    return types.SimpleNamespace(is_connected=True, host='10.0.0.5',
                                 config=types.SimpleNamespace(ssh_user='root', pass_='pw'),
                                 get_vm_disks_for_export=lambda vmid: disks)


@pytest.fixture
def esxi_to_xcp(db, monkeypatch, tmp_path):
    def _run(vmdk):
        argvs = []

        def _sub(argv, **kw):
            argvs.append(list(argv))
            # stop at qemu-img: the scp line is what we came for
            return types.SimpleNamespace(returncode=1 if argv[0] == 'qemu-img' else 0,
                                         stderr=b'', stdout=b'')

        monkeypatch.setattr(subprocess, 'run', _sub)
        xapi = _xapi()
        monkeypatch.setitem(ppglobals.cluster_managers, 'esxi1', _esxi_src(vmdk))
        monkeypatch.setitem(ppglobals.cluster_managers, 'xcp1', types.SimpleNamespace(
            is_connected=True, host='xcp', _api=lambda: xapi,
            _session=types.SimpleNamespace(_session='s'),
            config=types.SimpleNamespace(ssl_verification=False)))
        task = xhm.XHMigrationTask('t38', 'esxi_to_xcpng', 'esxi1', '', '5', 'xcp1', '', 'sr1')
        task.scratch = str(tmp_path / 'scratch')
        xhm._run_esxi_to_xcpng(task)
        return task, argvs, xapi

    return _run


@pytest.mark.parametrize('vmdk', ['[ds1] ../other/other.vmdk', '[ds1] vm1/../../x/x.vmdk',
                                  '[..] vm1/vm1.vmdk', "[ds1] vm1/a'b.vmdk"])
def test_a_backing_path_with_a_non_name_part_stops_before_anything_runs(esxi_to_xcp, vmdk):
    task, argvs, xapi = esxi_to_xcp(vmdk)
    assert task.phase == 'failed'
    assert 'Unsafe ESXi path component' in (task.error or '')
    assert argvs == []
    xapi.VDI.create.assert_not_called()


def test_a_normal_backing_path_still_copies(esxi_to_xcp):
    task, argvs, xapi = esxi_to_xcp('[ds1] vm1/vm1.vmdk')
    scp = [a for a in argvs if 'scp' in a]
    assert scp and scp[0][-2] == "root@10.0.0.5:'/vmfs/volumes/ds1/vm1/vm1-flat.vmdk'", argvs


# --------------------------------------------------------------------------- the PVE node

class _Sandbox:
    """Stands in for _pve_node_exec. A command that runs a script (bash, nohup) is
    recorded with the file it points at as it was then. A command that writes a file
    runs for real with /tmp and /run mapped under `root`, so what a write creates, where
    and with which mode is real. Everything else is recorded and answered."""

    RUNS = re.compile(r'^\s*(?:\S+=\S*\s+)*(?:bash|nohup)\s')
    WRITES = re.compile(r'mktemp |cat > |base64 -d > ')

    def __init__(self, root, answers=None):
        self.root = pathlib.Path(root)
        (self.root / 'tmp').mkdir(parents=True, exist_ok=True)
        (self.root / 'run').mkdir(parents=True, exist_ok=True)
        self.cmds = []
        self.ran = []           # (command, path it runs, that file's mode and text then)
        self.answers = answers or {}

    def local(self, path):
        return path.replace('/tmp/', f'{self.root}/tmp/').replace('/run/', f'{self.root}/run/')

    def node(self, path):
        return path.replace(f'{self.root}/tmp/', '/tmp/').replace(f'{self.root}/run/', '/run/')

    def __call__(self, mgr, node, cmd, timeout=600, **kw):
        self.cmds.append(cmd)
        for prefix, answer in self.answers.items():
            if cmd.startswith(prefix):
                return answer
        if self.RUNS.match(cmd):
            m = re.search(r'(?:bash|nohup)\s+(?:bash\s+)?(/\S+)', cmd)
            path = m.group(1) if m else ''
            lp = pathlib.Path(self.local(path))
            seen = (stat.S_IMODE(lp.stat().st_mode), lp.read_text()) if lp.exists() else None
            self.ran.append((cmd, path, seen))
            return 0, 'DELTA_DONE errors=0\nfallback loader installed\n', ''
        if not self.WRITES.search(cmd):
            return 0, '', ''
        p = subprocess.run(['bash', '-c', self.local(cmd)], capture_output=True, text=True)
        return p.returncode, self.node(p.stdout), p.stderr

    def plant(self, node_path, text='echo planted-by-a-local-account\n'):
        """A file a local account created first, owned by it: root cannot write it
        (protected_regular), which a read-only mode reproduces for the same user."""
        lp = pathlib.Path(self.local(node_path))
        lp.write_text(text)
        lp.chmod(0o444)
        return text


def _v2p_task(tid='ab12cd34', vmid=101):
    t = object.__new__(v2p.V2PMigrationTask)
    t.id, t.log_lines, t.esxi_password, t.phase, t.progress = tid, [], 'S3cr3t!pw', 'transfer', 0
    t.target_node, t.target_storage, t.proxmox_vmid = 'pve-a', 'local-lvm', vmid
    t.config = {}
    # a real run records the volume disk 0 went to; the fixes no longer guess it from the VMID
    t._disk_vols = {0: f'local-lvm:vm-{vmid}-disk-0'}
    return t


def _assert_ran_only_what_it_wrote(box, planted_path, planted_text, marker):
    assert box.ran, box.cmds
    for cmd, path, seen in box.ran:
        assert path != planted_path, f"the run used the name a local account can take: {cmd}"
        assert seen is not None, f"the run points at nothing that was written: {cmd}"
        mode, text = seen
        assert text != planted_text and marker in text, cmd
        assert mode & 0o077 == 0, f"{path} was {oct(mode)} while it ran"
    assert pathlib.Path(box.local(planted_path)).read_text() == planted_text


def test_the_efi_fallback_never_runs_a_planted_script(monkeypatch, tmp_path):
    """(#1123) the script name was /tmp/v2p-efi-fallback-<vmid>.sh, and the VMID is no
    secret. A local account that created it first had its own file run as root."""
    box = _Sandbox(tmp_path, answers={'pvesm path': (0, '/dev/pve/vm-101-disk-0\n', '')})
    monkeypatch.setattr(v2p, '_pve_node_exec', box)
    planted = '/tmp/v2p-efi-fallback-101.sh'
    text = box.plant(planted)

    v2p._register_uefi_fallback_loader(None, _v2p_task())

    _assert_ran_only_what_it_wrote(box, planted, text, 'bootmgfw.efi')


def test_the_delta_sync_runs_its_own_script_and_keeps_the_password_out_of_tmp(monkeypatch, tmp_path):
    """(#1123, #1029) the transfer script and the password file were named after the task
    id, which the /tmp/v2p-<id> mount next to them gives away."""
    # MK Oct 2026 (#1124) - the read-back after the transfer finds block 1 as ESXi has it
    box = _Sandbox(tmp_path, answers={'for i in 1; do dd if=': (0, 'bbb\n', '')})
    monkeypatch.setattr(v2p, '_pve_node_exec', box)
    monkeypatch.setattr(v2p, '_ssh_exec', lambda *a, **k: (0, 'aaa\nbbb\n', ''))
    t = _v2p_task()
    script_name = f'/tmp/v2p-{t.id}-delta-0.sh'
    text = box.plant(script_name)
    pass_name = f'/tmp/v2p-{t.id}-delta-pass'
    pathlib.Path(box.local(pass_name)).write_text('')
    pathlib.Path(box.local(pass_name)).chmod(0o666)      # theirs, and writable for root

    ok = v2p._delta_sync_blocks(None, t, '10.0.0.5', 'root', 'S3cr3t!pw', '/vmfs/volumes/ds/x-flat.vmdk',
                                '/dev/pve/vm-101-disk-0', 2 * 256 * 1024 * 1024, 0,
                                pve_checksums=['aaa', 'ccc'])

    assert ok
    _assert_ran_only_what_it_wrote(box, script_name, text, 'DELTA_DONE')
    assert pathlib.Path(box.local(pass_name)).read_text() == '', 'the password went into their file'
    writes = [c for c in box.cmds if 'base64 -d >' in c]
    assert writes and all(w.startswith('umask 077;') and ' > /run/' in w for w in writes), writes


def test_the_script_writer_makes_a_new_private_file_and_says_where(monkeypatch, tmp_path):
    box = _Sandbox(tmp_path)
    monkeypatch.setattr(v2p, '_pve_node_exec', box)
    body = "#!/bin/bash\ncat << 'PYSV'\ninner heredoc\nPYSV\necho done\n"

    paths = {v2p._write_node_script(None, 'n', body, 'copy-101-0') for _ in range(5)}

    assert None not in paths and len(paths) == 5
    for p in paths:
        assert re.fullmatch(r'/tmp/v2p-copy-101-0-[A-Za-z0-9]{10}', p), p
        lp = pathlib.Path(box.local(p))
        assert lp.read_text() == body
        assert stat.S_IMODE(lp.stat().st_mode) == 0o600
        # still found by the pgrep fallback of the background copy
        assert 'v2p-copy-101-0' in p


def test_the_script_writer_gives_nothing_back_when_the_write_failed(monkeypatch):
    monkeypatch.setattr(v2p, '_pve_node_exec', lambda *a, **k: (1, '', 'No space left on device'))
    assert v2p._write_node_script(None, 'n', 'echo x', 'efi-fallback-1') is None
    # and output that is not what mktemp prints is not taken for a path
    monkeypatch.setattr(v2p, '_pve_node_exec', lambda *a, **k: (0, '/tmp/v2p-x.sh; id\n', ''))
    assert v2p._write_node_script(None, 'n', 'echo x', 'efi-fallback-1') is None


def _flat(node):
    """A command argument as text; an interpolation becomes {its source}."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return ''.join(v.value if isinstance(v, ast.Constant) else '{%s}' % ast.unparse(v.value)
                       for v in node.values)
    if isinstance(node, ast.BinOp):
        return _flat(node.left) + _flat(node.right)
    if isinstance(node, ast.Name):
        return '{%s}' % node.id
    return ''


def _run_sites():
    """(function, variable) for every script path a node command runs with bash/nohup."""
    tree = ast.parse(_V2P_SRC)
    sites = []
    for fn in ast.walk(tree):
        if not isinstance(fn, ast.FunctionDef):
            continue
        assigns = {}
        for n in ast.walk(fn):
            if isinstance(n, ast.Assign):
                for tgt in n.targets:
                    if isinstance(tgt, ast.Name):
                        assigns.setdefault(tgt.id, []).append(n.value)
        for call in ast.walk(fn):
            if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
                    and call.func.id == '_pve_node_exec' and len(call.args) >= 3):
                continue
            for var in re.findall(r'(?:^|[;&|\s}])(?:nohup\s+(?:bash\s+)?|bash\s+)\{(\w+)\}',
                                  _flat(call.args[2])):
                if var in assigns:
                    sites.append((fn.name, var, assigns[var]))
    return sites


def test_every_script_the_node_runs_comes_from_the_private_writer():
    """(#1123) one way to stage a script, and every bash/nohup that runs one uses it."""
    sites = _run_sites()
    assert len(sites) >= 8, sites
    for fn, var, values in sites:
        for v in values:
            assert (isinstance(v, ast.Call) and isinstance(v.func, ast.Name)
                    and v.func.id == '_write_node_script'), f"{fn}: {var} = {ast.unparse(v)}"


def _code_strings():
    """Every string literal in v2p.py that is not a docstring."""
    tree = ast.parse(_V2P_SRC)
    docs = set()
    for n in ast.walk(tree):
        if isinstance(n, (ast.Module, ast.FunctionDef, ast.ClassDef)) and n.body:
            first = n.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                docs.add(id(first.value))
    return [n.value for n in ast.walk(tree)
            if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docs]


def test_the_esxi_key_is_never_made_readable_to_other_accounts():
    """(#1029) chmod 644 left the passphrase-less ESXi root key readable to every local
    account on the node for the whole migration."""
    offenders = [s for s in _code_strings() if re.search(r'chmod\s+(-R\s+)?0?6[0-7][4-7]\b', s)]
    assert offenders == []


def test_the_https_fallback_keeps_its_credentials_in_run():
    """(#1029) the basic-auth file and the cookie jar (an ESXi session, written by curl
    with the default umask) sat under /tmp names built from the task id."""
    fn = next(n for n in ast.walk(ast.parse(_V2P_SRC))
              if isinstance(n, ast.FunctionDef) and n.name == '_ssh_pipe_transfer')
    paths = {t.id: _flat(n.value) for n in ast.walk(fn) if isinstance(n, ast.Assign)
             for t in n.targets if isinstance(t, ast.Name) and t.id in ('auth_file', 'cookie_jar')}
    assert set(paths) == {'auth_file', 'cookie_jar'}
    assert all(p.startswith('/run/') for p in paths.values()), paths
    writes = [_flat(c.args[2]) for c in ast.walk(fn)
              if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)
              and c.func.id == '_pve_node_exec' and len(c.args) >= 3
              and '{auth_file}' in _flat(c.args[2]) and 'base64 -d' in _flat(c.args[2])]
    assert writes and all(w.startswith('umask 077;') and '{cookie_jar}' in w for w in writes)


def test_the_datastore_mount_is_root_only():
    """(#1117) allow_other opened the sshfs mount of the whole datastore to every local
    account, and user_allow_other was switched on in /etc/fuse.conf for good measure."""
    offenders = [s for s in _code_strings() if 'allow_other' in s or 'fuse.conf' in s]
    assert offenders == []


def test_node_side_ssh_follows_strict_host_keys():
    """(#1112) every node-side ssh/sshfs takes its policy from one place, and QEMU's ssh
    driver checks the host key instead of accepting any."""
    strs = _code_strings()
    assert not [s for s in strs if re.search(r'StrictHostKeyChecking[= ]accept-new', s)]
    assert not [s for s in strs if 'host-key-check.mode=none' in s or '"none"' in s]


def test_strict_mode_reaches_the_node_and_the_default_stays_tofu(monkeypatch, tmp_path):
    def _delta_script():
        box = _Sandbox(tmp_path / str(len(os.listdir(tmp_path))))
        monkeypatch.setattr(v2p, '_pve_node_exec', box)
        monkeypatch.setattr(v2p, '_ssh_exec', lambda *a, **k: (0, 'aaa\n', ''))
        v2p._delta_sync_blocks(None, _v2p_task(), '10.0.0.5', 'root', 'pw', '/vmfs/volumes/ds/x-flat.vmdk',
                               '/dev/pve/vm-101-disk-0', 256 * 1024 * 1024, 0, pve_checksums=['zzz'])
        return box.ran[0][2][1]

    monkeypatch.delenv('PEGAPROX_SSH_STRICT_HOST_KEYS', raising=False)
    assert 'StrictHostKeyChecking=accept-new' in _delta_script()

    monkeypatch.setenv('PEGAPROX_SSH_STRICT_HOST_KEYS', '1')
    script = _delta_script()
    assert 'StrictHostKeyChecking=yes' in script and 'accept-new' not in script


# --------------------------------------------------------------------------- (#1090)

@pytest.mark.parametrize('path', [
    '/var/lib/vz/template/iso/virtio-win.iso',
    '/var/lib/vz/template/iso/virtio-win-0.1.262.iso',
    '/mnt/pve/iso store/template/iso/virtio-win (stable).ISO',
    '/var/lib/pegaprox/virtio-win.iso',
])
def test_an_iso_path_is_accepted(path):
    from pegaprox.utils.sanitization import validate_node_iso_path
    assert validate_node_iso_path(path)


@pytest.mark.parametrize('path', [
    '/var/lib/vz/images/101/vm-101-disk-0.raw', '/dev/pve/vm-101-disk-0', '/dev/sda',
    'virtio-win.iso', '../virtio-win.iso', '/var/lib/vz/../../etc/x.iso', '/x.iso\n',
    "/x.iso'; id; '", '/a/b.iso/..', '', None, ['/x.iso'], '/x.iso.raw',
], ids=repr)
def test_anything_else_is_not(path):
    from pegaprox.utils.sanitization import validate_node_iso_path
    assert not validate_node_iso_path(path)


def _virtio_task(iso):
    t = _v2p_task()
    t.install_virtio_drivers, t.virtio_iso_path, t.ostype = True, iso, ''
    return t


def _virtio_box(tmp_path):
    return _Sandbox(tmp_path, answers={
        'pvesm path': (0, '/dev/pve/vm-101-disk-0\n', ''),
        'pvesm status': (0, 'lvm\n', ''),
        'test -f': (0, '', ''),
        'python3 -c': (0, '', ''),
        'command -v': (0, '', ''),
    })


def test_a_disk_image_is_not_loop_mounted_as_the_virtio_iso(monkeypatch, tmp_path):
    box = _virtio_box(tmp_path)
    monkeypatch.setattr(v2p, '_pve_node_exec', box)
    pve = types.SimpleNamespace(host='h', api_port=8006,
                                _api_get=lambda *a, **k: types.SimpleNamespace(status_code=500))
    image = '/var/lib/vz/images/202/vm-202-disk-0.raw'

    assert v2p._inject_virtio_drivers(pve, _virtio_task(image)) is False
    assert not [c for c in box.cmds if image in c], box.cmds


def test_a_named_iso_is_still_used_and_mounted_as_a_cd_filesystem(monkeypatch, tmp_path):
    box = _virtio_box(tmp_path)
    monkeypatch.setattr(v2p, '_pve_node_exec', box)
    pve = types.SimpleNamespace(host='h', api_port=8006,
                                _api_get=lambda *a, **k: types.SimpleNamespace(status_code=500))
    iso = '/var/lib/vz/template/iso/virtio-win-0.1.262.iso'

    v2p._inject_virtio_drivers(pve, _virtio_task(iso))

    staged = [c for c in box.cmds if 'ISO_MNT' in c]
    assert staged, box.cmds
    assert f"ISO={iso}\n" in staged[0]
    mount =[ln for ln in staged[0].splitlines() if '"$ISO_MNT" ||' in ln and 'mount' in ln]
    assert mount and mount[0].startswith('mount -t iso9660,udf -o ro,loop '), mount


@pytest.fixture
def v2p_start(api, seed):
    api.set_manager('cluster_1', api.make_fake_manager('cluster_1'))
    ppglobals.vmware_managers['esxi1'] = types.SimpleNamespace(linked_clusters=[], host='10.0.0.5')
    admin = api.as_user(seed.user('root', role='admin'))

    def _post(**extra):
        body = {'target_cluster': 'cluster_1', 'target_node': 'pve-a',
                'target_storage': 'local-lvm', 'install_virtio_drivers': True}
        body.update(extra)
        return admin.post('/api/vmware/esxi1/vms/vm-7/migrate', json=body)

    try:
        yield _post
    finally:
        ppglobals.vmware_managers.pop('esxi1', None)


def test_the_start_refuses_a_virtio_path_that_is_no_iso(v2p_start):
    r = v2p_start(virtio_iso_path='/var/lib/vz/images/202/vm-202-disk-0.raw')
    assert r.status_code == 400
    assert 'virtio_iso_path' in r.get_json()['error']


def test_the_start_takes_an_iso_path_and_an_empty_one(v2p_start):
    # no esxi_password: the start stops at that check, after the ISO path has passed
    for iso in ('/var/lib/vz/template/iso/virtio-win.iso', ''):
        r = v2p_start(virtio_iso_path=iso)
        assert r.status_code == 400
        assert 'esxi_password' in r.get_json()['error'], r.get_json()
