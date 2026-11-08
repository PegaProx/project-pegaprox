# -*- coding: utf-8 -*-
"""Every XHM way to an ESXi guest, and what the ESXi runners feed qemu-img (#1039, #1106).
NS Oct 2026.

test_sec_migrations_xhm_esxi.py checks _may_migrate_source on its own. Here the same
decision is driven through each place that reaches it - plan, start, the removal gate,
the migration list and detail, the SSE frame - with the vmid spellings int() accepts, and
the two ESXi runners are run far enough to see the qemu-img line they build.
"""
import subprocess
import types

import pytest

import pegaprox.api.xhm as xhm_api
import pegaprox.core.xhm as xhm_core
import pegaprox.globals as ppglobals


ESXI, TGT = 'esxi1', 'cluster_2'
PLAN = f'/api/xhm/plan?source_cluster={ESXI}&target_cluster={TGT}&source_vmid='
START = '/api/xhm/migrate'


@pytest.fixture
def esxi_src(api, monkeypatch):
    """A standalone ESXi host where XHM finds it, unlinked, plus a Proxmox target.
    The plan function and the runner are stubbed: the gates are the subject."""
    api.set_manager(ESXI, api.make_fake_manager(ESXI, cluster_type='esxi'))
    api.set_manager(TGT, api.make_fake_manager(TGT))
    ppglobals.vmware_managers[ESXI] = types.SimpleNamespace(linked_clusters=[], host='10.0.0.5')
    reg = {}
    monkeypatch.setattr(ppglobals, '_xhm_migrations', reg)
    monkeypatch.setattr(xhm_api, '_xhm_migrations', reg)
    monkeypatch.setattr(xhm_api, 'plan_esxi_to_pve', lambda *a: {'plan': 'ok'})
    ran = []
    monkeypatch.setattr(xhm_api, '_run_esxi_to_pve', lambda task: ran.append(task))
    return types.SimpleNamespace(registry=reg, ran=ran)


def _start_body(vmid='5', **kw):
    b = {'source_cluster': ESXI, 'source_vmid': vmid, 'target_cluster': TGT,
         'target_storage': 'local-lvm', 'target_node': 'pve1'}
    b.update(kw)
    return b


def _viewer_with(seed, name, perms, denied=None):
    return seed.user(name, role='viewer', permissions=list(perms), denied=denied or [])


# --------------------------------------------------------------------------- plan + start

@pytest.mark.parametrize('route', ['plan', 'start'])
def test_vm_migrate_alone_does_not_reach_an_esxi_guest(api, seed, esxi_src, route):
    u = api.as_user(_viewer_with(seed, 'mig', ['vm.migrate']))
    r = u.get(PLAN + '5') if route == 'plan' else u.post(START, json=_start_body())
    assert r.status_code == 403, r.get_data(as_text=True)
    assert esxi_src.ran == [] and esxi_src.registry == {}


@pytest.mark.parametrize('route', ['plan', 'start'])
def test_vmware_vm_migrate_reaches_it(api, seed, esxi_src, route):
    u = api.as_user(_viewer_with(seed, 'mig', ['vm.migrate', 'vmware.vm.migrate']))
    r = u.get(PLAN + '5') if route == 'plan' else u.post(START, json=_start_body())
    assert r.status_code in (200, 202), r.get_data(as_text=True)


@pytest.mark.parametrize('vmid', ['7', '07', ' 7', '7\n'], ids=repr)
def test_an_esxi_acl_confines_whatever_the_spelling(api, seed, esxi_src, vmid):
    seed.vm_acl(f'vmware:{ESXI}', 5, ['portal'])
    u = api.as_user(seed.user('portal', role='user'))
    assert u.post(START, json=_start_body(vmid=vmid)).status_code == 403
    assert u.get(PLAN + vmid.strip()).status_code == 403
    assert esxi_src.registry == {}


@pytest.mark.parametrize('vmid', ['5', '05', ' 5', '+5', 5], ids=repr)
def test_the_acl_holder_gets_their_guest_under_the_checked_id(api, seed, esxi_src, vmid):
    seed.vm_acl(f'vmware:{ESXI}', 5, ['portal'])
    u = api.as_user(seed.user('portal', role='user'))
    r = u.post(START, json=_start_body(vmid=vmid))
    assert r.status_code == 202, r.get_data(as_text=True)
    assert r.get_json()['task']['source_vmid'] == '5', 'the runner got another id than the gate checked'


@pytest.mark.parametrize('vmid', ['abc', '', [5], {'v': 5}, '5;id'], ids=repr)
def test_a_non_number_esxi_vmid_never_starts(api, seed, esxi_src, vmid):
    admin = api.as_user(seed.user('root', role='admin'))
    r = admin.post(START, json=_start_body(vmid=vmid))
    assert r.status_code == 400, r.get_data(as_text=True)
    assert esxi_src.registry == {}


@pytest.mark.parametrize('flag', [True, 1, 'false', '0', [1]], ids=repr)
def test_removing_an_esxi_source_needs_vmware_vm_manage(api, seed, esxi_src, flag):
    u = api.as_user(_viewer_with(seed, 'mig', ['vm.migrate', 'vmware.vm.migrate']))
    r = u.post(START, json=_start_body(remove_source=flag))
    assert r.status_code == 403, r.get_data(as_text=True)
    assert esxi_src.registry == {}


def test_with_vmware_vm_manage_removal_is_accepted(api, seed, esxi_src):
    u = api.as_user(_viewer_with(seed, 'mig', ['vm.migrate', 'vmware.vm.migrate',
                                               'vmware.vm.manage']))
    assert u.post(START, json=_start_body(remove_source=True)).status_code == 202


def test_a_viewer_token_of_an_admin_starts_nothing(api, seed, esxi_src):
    from pegaprox.utils.auth import create_api_token
    seed.user('root', role='admin')
    with api.app.test_request_context('/'):
        tok = create_api_token('root', 'ro', role='viewer')['token']
    r = api.anon().post(START, json=_start_body(), headers={'Authorization': f'Bearer {tok}'})
    assert r.status_code == 403
    assert esxi_src.registry == {}


def test_a_tenant_that_does_not_own_the_esxi_host_is_refused(api, seed, esxi_src):
    seed.tenant('acme', clusters=[TGT])
    u = api.as_user(seed.user('acme_ops', role='user', tenant_id='acme'))
    assert u.post(START, json=_start_body()).status_code == 403
    assert esxi_src.registry == {}


# --------------------------------------------------------------------------- list, detail, SSE

@pytest.fixture
def esxi_run(esxi_src):
    t = types.SimpleNamespace(id='m1', source_cluster=ESXI, source_vmid='5',
                              target_cluster=TGT, to_dict=lambda: {'id': 'm1'})
    esxi_src.registry['m1'] = t
    return t


def test_the_list_and_detail_hide_an_esxi_run_without_vmware_vm_migrate(api, seed, esxi_run):
    u = api.as_user(_viewer_with(seed, 'mig', ['vm.migrate']))
    assert u.get('/api/xhm/migrations').get_json() == []
    assert u.get('/api/xhm/migrations/m1').status_code == 404


def test_the_list_and_detail_show_it_with_the_right(api, seed, esxi_run):
    u = api.as_user(_viewer_with(seed, 'mig', ['vm.migrate', 'vmware.vm.migrate']))
    assert u.get('/api/xhm/migrations').get_json() == [{'id': 'm1'}]
    assert u.get('/api/xhm/migrations/m1').status_code == 200


def test_the_list_hides_another_acl_holders_run(api, seed, esxi_run):
    seed.vm_acl(f'vmware:{ESXI}', 6, ['portal'])
    u = api.as_user(seed.user('portal', role='user'))
    assert u.get('/api/xhm/migrations').get_json() == []


def test_the_sse_frame_follows_the_same_gate(api, seed, esxi_run):
    from pegaprox.utils.realtime import _sse_may_see_object_frame
    _viewer_with(seed, 'nomig', ['vm.migrate'])
    _viewer_with(seed, 'mig', ['vm.migrate', 'vmware.vm.migrate'])
    assert _sse_may_see_object_frame('nomig', 'xhm_migration_log', {'id': 'm1'}) is False
    assert _sse_may_see_object_frame('mig', 'xhm_migration_log', {'id': 'm1'}) is True


# --------------------------------------------------------------------------- the runners (#1106)
# The file both ESXi runners copy is the -flat extent. Read with -f vmdk, a descriptor
# placed under that name was parsed as root - on the PVE node, or on the PegaProx host
# for the XCP-ng direction - and its extent paths followed.

_DISKS = {'data': {'name': 'vm1', 'disks': [
    {'vmdk_file': '[ds1] vm1/vm1.vmdk', 'capacity_bytes': 1 << 30, 'capacity_gb': 1}]}}


def _esxi_mgr():
    return types.SimpleNamespace(is_connected=True, host='10.0.0.5',
                                 config=types.SimpleNamespace(ssh_user='root', pass_='pw'),
                                 get_vm_disks_for_export=lambda vmid: _DISKS)


class _Chan:
    def __init__(self, rc): self._rc = rc
    def recv_exit_status(self): return self._rc
    def shutdown_write(self): pass


class _Out:
    def __init__(self, data=b'', rc=0):
        self._d, self.channel = data, _Chan(rc)
    def read(self): return self._d
    def write(self, *_): pass
    def flush(self): pass


class _FakeSSH:
    def __init__(self, mounted):
        self.mounted, self.cmds = mounted, []

    def exec_command(self, cmd, timeout=None):
        self.cmds.append(cmd)
        if cmd.startswith('ls '):
            out = _Out(b'vm1-flat.vmdk' if self.mounted else b'')
        elif cmd.startswith('pvesm alloc'):
            out = _Out(b"successfully created 'local:vm-9001-disk-0'")
        elif cmd.startswith('pvesm path'):
            out = _Out(b'/dev/pve/vm-9001-disk-0')
        elif 'qemu-img convert' in cmd:
            out = _Out(rc=1)             # stop here; the line is what we came for
        else:
            out = _Out()
        return _Out(), out, _Out()

    def close(self): pass


@pytest.mark.parametrize('mounted', [True, False], ids=['sshfs', 'scp-fallback'])
def test_esxi_to_pve_reads_the_flat_extent_as_raw(db, monkeypatch, mounted):
    ssh = _FakeSSH(mounted)
    monkeypatch.setitem(ppglobals.cluster_managers, ESXI, _esxi_mgr())
    monkeypatch.setitem(ppglobals.cluster_managers, TGT, types.SimpleNamespace(
        is_connected=True, host='pve', api_port=8006,
        config=types.SimpleNamespace(ssh_user='root', ssh_key='', ssh_port=22)))
    monkeypatch.setattr(xhm_core, '_resolve_pve_node_ip', lambda m, n: '10.0.0.9')
    monkeypatch.setattr(xhm_core, '_next_pve_vmid', lambda m: 9001)
    monkeypatch.setattr(xhm_core, 'ssh_password_for', lambda c: 'x')
    monkeypatch.setattr(xhm_core, '_connect_ssh', lambda *a, **k: ssh)
    task = xhm_core.XHMigrationTask('t1', 'esxi_to_pve', ESXI, '', '5', TGT, 'pve1', 'local')

    xhm_core._run_esxi_to_pve(task)

    convs = [c for c in ssh.cmds if 'qemu-img convert' in c]
    assert convs, ssh.cmds
    assert all('-f raw' in c and '-f vmdk' not in c for c in convs), convs


def test_esxi_to_xcpng_reads_the_flat_extent_as_raw(db, monkeypatch, tmp_path):
    argvs = []

    def _run(argv, **kw):
        argvs.append(list(argv))
        return types.SimpleNamespace(returncode=1 if argv[0] == 'qemu-img' else 0,
                                     stderr=b'', stdout=b'')

    monkeypatch.setattr(subprocess, 'run', _run)
    xapi = types.SimpleNamespace(
        SR=types.SimpleNamespace(get_all=lambda: ['sr'], get_record=lambda r: {'name_label': 'sr1'}),
        VDI=types.SimpleNamespace(create=lambda rec: 'vdi', get_uuid=lambda r: 'u1',
                                  destroy=lambda r: None))
    monkeypatch.setitem(ppglobals.cluster_managers, ESXI, _esxi_mgr())
    monkeypatch.setitem(ppglobals.cluster_managers, TGT, types.SimpleNamespace(
        is_connected=True, host='xcp', _api=lambda: xapi,
        _session=types.SimpleNamespace(_session='s'),
        config=types.SimpleNamespace(ssl_verification=False)))
    task = xhm_core.XHMigrationTask('t2', 'esxi_to_xcpng', ESXI, '', '5', TGT, '', 'sr1')
    task.scratch = str(tmp_path / 'scratch')

    xhm_core._run_esxi_to_xcpng(task)

    qimg = [a for a in argvs if a[0] == 'qemu-img']
    assert qimg, argvs
    a = qimg[0]
    assert a[a.index('-f') + 1] == 'raw', a
