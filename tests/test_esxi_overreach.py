# ESXi migration against overreach: the per-NIC / per-disk choices, verify, dry_run and bulk runs
# looked at by a caller who wants more than they were given, or a check that says more than
# it looked at.
#
# - verify=full on a folder copy: the boot disk's folder listing is not the VM's disk list. A
#   disk on another datastore was left out, a VM running on its own snapshot was copied from
#   its stale base, and the full check passed over both because it compares what was copied.
# - the tenant quota of a single migration: a sizing value that is no number made the footprint
#   raise, the quota gate counts that as "could not check" and lets it through, while the
#   value still reached the VM create (a list is sent as its one item).
# - a bulk run taken into the registry but never launched kept the ESXi password and its
#   per-user and per-server slot until a restart, and its guests stayed "busy".

import types

import pytest

import pegaprox.core.v2p as v2p
from pegaprox.core import esxi_bulk as ebulk

from test_esxi_mapping_verify import Run, route, _ssh_pipe  # noqa: F401 (fixture)
from test_esxi_bulk import env, PW  # noqa: F401 (fixture)
from test_tenant_quota_beyond_create import _users, _tenant, _mgr, CL, GB


def _fullchecks(r):
    return [c for c in r.nodecmds() if c.startswith('bash /tmp/v2p-fullcheck-')]


def _boot_folder(r, monkeypatch, names):
    """The descriptors `ls -1` finds in [ds1] app01, whatever the VM's disks say."""
    inner = v2p._ssh_exec

    def shell(host, user, pw, cmd, timeout=30):
        if cmd.startswith('ls -1'):
            r.log.append(('esxi_ssh', cmd))
            return 0, ''.join(f'/vmfs/volumes/ds1/app01/{n}\n' for n in names), ''
        return inner(host, user, pw, cmd, timeout=timeout)
    monkeypatch.setattr(v2p, '_ssh_exec', shell)


def _untouched(r):
    assert not any(c.startswith('pvesm alloc') for c in r.nodecmds())
    assert not [e for e in r.log if e[:3] == ('esxi_api', 'power', 'stop')]
    assert not [e for e in r.log if e[0] == 'pve_api' and e[1].endswith('/status/start')]


# --------------------------------------------------------------------------- verify=full

def test_full_verify_on_offline_refuses_a_vm_with_a_disk_outside_the_boot_folder(monkeypatch):
    """The folder copy only finds app01.vmdk; disk 1 lives on ds2. Copying disk 0, checking
    disk 0 and calling that a full check of the migration is a silent skip."""
    r = Run(monkeypatch, mode='offline', ndisks=2, config={'verify': 'full'})
    r.esxi.disks[1]['vmdk_file'] = '[ds2] other/app01_1.vmdk'
    _boot_folder(r, monkeypatch, ['app01.vmdk'])
    r.go()
    assert r.task.status == 'failed', 'a migration with a disk left out passed the full check'
    # refused like any folder copy that would leave the disk out (test_esxi_followups.py)
    assert 'disk 2 (Hard disk 2)' in r.task.error and 'Live Clone' in r.task.error
    _untouched(r)
    assert _fullchecks(r) == []


def test_full_verify_on_offline_refuses_a_vm_that_runs_on_its_own_snapshot(monkeypatch):
    """The VM's disk is app01-000001.vmdk; the listing drops -0000 deltas and hands over the
    base app01.vmdk. A copy of the base matches the base block for block, and is not the
    disk the VM has."""
    r = Run(monkeypatch, mode='offline', ndisks=1, config={'verify': 'full'})
    r.esxi.disks[0]['vmdk_file'] = '[ds1] app01/app01-000001.vmdk'
    _boot_folder(r, monkeypatch, ['app01.vmdk'])
    r.go()
    assert r.task.status == 'failed', 'a copy of the stale base passed the full check'
    _untouched(r)


def test_full_verify_on_auto_does_not_fall_back_to_a_folder_copy_that_misses_a_disk(monkeypatch):
    r = Run(monkeypatch, mode='auto', ndisks=2, config={'verify': 'full'}, clone_snap_fails=True)
    r.esxi.disks[1]['vmdk_file'] = '[ds2] other/app01_1.vmdk'
    _boot_folder(r, monkeypatch, ['app01.vmdk'])
    r.go()
    assert r.task.status == 'failed'
    # Auto tried its clone first: the text says the source runs as it did, _untouched proves it
    assert 'the source VM runs as it did' in r.task.error
    _untouched(r)


def test_full_verify_on_the_live_clone_still_takes_a_disk_from_another_datastore(monkeypatch):
    """The clone reads each disk from its own backing: nothing to refuse there."""
    r = Run(monkeypatch, mode='vmkfstools_clone', ndisks=2, config={'verify': 'full'})
    r.esxi.disks[1]['vmdk_file'] = '[ds2] other/app01_1.vmdk'
    _boot_folder(r, monkeypatch, ['app01.vmdk'])
    r.go()
    assert r.task.status == 'completed', r.task.error
    assert len(_fullchecks(r)) == 2


def test_full_verify_copies_the_disks_of_the_vm_in_its_order(monkeypatch):
    """With every disk in the folder the copy runs, in the VM's disk order and without a
    leftover descriptor that belongs to no disk of the VM."""
    r = Run(monkeypatch, mode='offline', ndisks=2, config={'verify': 'full'})
    _boot_folder(r, monkeypatch, ['app01.vmdk', 'app01_1.vmdk', 'app01-old.vmdk'])
    r.go()
    assert r.task.status == 'completed', r.task.error
    copies = [c for c in r.nodecmds() if _ssh_pipe(c)]
    assert len(copies) == 2 and not any('app01-old' in c for c in r.nodecmds())
    assert len(_fullchecks(r)) == 2


def test_without_full_verify_the_folder_copy_does_not_leave_the_disk_out_either(monkeypatch):
    """It used to: the guest came up with one disk of two and the run said completed."""
    r = Run(monkeypatch, mode='offline', ndisks=2)
    r.esxi.disks[1]['vmdk_file'] = '[ds2] other/app01_1.vmdk'
    _boot_folder(r, monkeypatch, ['app01.vmdk'])
    r.go()
    assert r.task.status == 'failed' and 'Live Clone' in r.task.error
    _untouched(r)


# --------------------------------------------------------------------------- the tenant quota

@pytest.fixture
def landing(api, seed, monkeypatch):
    """A tenant at its ceiling (test_tenant_quota_beyond_create): any guest landing from
    ESXi is one too many."""
    import pegaprox.globals as g
    import pegaprox.api.vmware as vmwareapi
    us = _users(seed)
    _tenant(seed.db)
    # a node of the target cluster: the route refuses any other before it counts the quota
    _mgr(api).nodes = {'pve1': {'node': 'pve1', 'status': 'online'}}
    esx = types.SimpleNamespace(
        host='10.0.0.9', linked_clusters=[], ensure_connected=lambda: None,
        get_vm=lambda vid: {'data': {'name': 'web', 'cpu': {'count': 2, 'sockets': 1, 'cores_per_socket': 2},
                                     'memory': {'size_MiB': 2048},
                                     'disks': {'2000': {'capacity': 10 * GB}}}})
    g.vmware_managers['esxi1'] = esx
    started = []
    monkeypatch.setattr(vmwareapi, '_run_v2p_migration', lambda task: started.append(task))
    monkeypatch.setattr(vmwareapi, '_vmware_migrations', {})
    client = api.as_user(us['tenant'])

    def post(**extra):
        body = {'target_cluster': CL, 'target_node': 'pve1', 'target_storage': 'local-lvm',
                'esxi_password': 'x'}
        body.update(extra)
        return client.post('/api/vmware/esxi1/vms/vm-1/migrate', json=body)
    try:
        yield types.SimpleNamespace(post=post, migrations=vmwareapi._vmware_migrations)
    finally:
        g.vmware_managers.pop('esxi1', None)


@pytest.mark.parametrize('extra', [
    {'sockets': [64]}, {'cores_per_socket': [64]}, {'memory': [262144]},
    {'memory': 'current=262144'}, {'sockets': 'x'}, {'memory': {'size': 1}}, {'sockets': True},
    {'memory': 2048.5}, {'sockets': -2},
])
def test_a_sizing_value_that_is_no_number_does_not_slip_past_the_quota(landing, extra):
    r = landing.post(**extra)
    assert r.status_code in (400, 403), r.get_data(as_text=True)
    assert landing.migrations == {}, 'a migration started past the tenant quota'


@pytest.mark.parametrize('extra', [{}, {'sockets': 2, 'cores_per_socket': 2, 'memory': 2048},
                                   {'sockets': '2', 'memory': '4096'}, {'sockets': 0, 'memory': 0}])
def test_sizing_as_the_wizard_sends_it_is_still_counted(landing, extra):
    r = landing.post(**extra)
    assert r.status_code == 403 and 'quota' in r.get_json()['error'].lower(), r.get_data(as_text=True)


# --------------------------------------------------------------------------- the NIC list

def test_a_nic_list_longer_than_a_guest_can_have_is_refused_before_the_plan(route):
    """selected_nics is the list nic_map counts, and the plan builds a row per entry: 10 MB
    of [{}, {}, ...] was a few million rows in one request. A guest has net0 to net31."""
    r = route.post(dry_run=True, selected_nics=[{}] * 33, nic_map=[{'index': 0, 'bridge': 'vmbr1'}])
    assert r.status_code == 400, r.get_data(as_text=True)[:300]
    assert route.pve.gets == []
    r = route.post(selected_nics=[{}] * 5000)
    assert r.status_code == 400
    # what a guest can have still goes through
    r = route.post(dry_run=True, selected_nics=[{}] * 32, nic_map=[{'index': 31, 'bridge': 'vmbr1'}])
    assert r.status_code == 200 and len(r.get_json()['nics']) == 32, r.get_data(as_text=True)[:300]


# --------------------------------------------------------------------------- bulk runs

def test_a_run_that_could_not_be_launched_keeps_no_password_no_slot_and_no_guest(env, monkeypatch):
    monkeypatch.setattr(ebulk, 'RUNNING_PER_USER', 1)

    def no_thread(*a, **k):
        raise RuntimeError("can't start new thread")
    monkeypatch.setattr(ebulk, 'launch', no_thread)
    try:
        status = env.post(vms=['vm-1']).status_code
    except RuntimeError:
        status = None
    left = ebulk.runs()
    assert [run.state for run in left if run.state == 'running'] == [], 'a run nobody works on stays running'
    assert all(run._password is None for run in left), 'the ESXi password stayed on a dead run'
    assert ebulk.busy_vm_ids('vw1') == set()
    assert ebulk.room('vw1', 'root') is None
    assert status is not None and status >= 500
    assert env.runner.tasks == []
