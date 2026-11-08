"""What a restore test still lets through: a copy that boots with a way into production, a
copy left behind (unisolated, protected, still running, moved by our own balancer), a guest
removed that was not the test's own, a check command shown to a caller it is masked from,
a kept test guest outside the tenant quota.

Driven against a fake Proxmox VE that behaves as PVE does where it matters here: a restore
makes the guest from the backup's config (what the restore call sets on top of it wins), the
guest is locked until the restore task is over, a locked, running or protected guest is not
destroyed, PVE HA starts a guest it manages once it exists and is unlocked, and a host
directory, shared memory or raw LXC entry in the config is what the guest gets at start.
"""
import json
import time
import types

import pytest

import pegaprox.core.backup_verify as bv
from pegaprox.core import recovery

from test_restore_test_isolation import LXC_CONFIG, QEMU_CONFIG, TEST_VMID, _params, _plan, clock  # noqa: F401

# what a restore call carries that is no setting of the guest
_RESTORE_ARGS = {'vmid', 'archive', 'ostemplate', 'restore', 'force', 'unique', 'start', 'storage',
                 'pool', 'bwlimit', 'live-restore'}


class _Resp:
    def __init__(self, status, data=None, text=''):
        self.status_code, self._data, self.text = status, data, text

    def json(self):
        return {'data': self._data}


class _ProcessDied(BaseException):
    """The PegaProx process goes away (restart, update, OOM) while a restore runs."""


def unisolated(cfg):
    """Why a guest config would boot with a way out: onboot set, a NIC not down."""
    why = []
    if str(cfg.get('onboot', '0')) not in ('0', ''):
        why.append('onboot')
    for k, v in cfg.items():
        if k.startswith('net') and k[3:].isdigit() and 'link_down=1' not in str(v).split(','):
            why.append(k)
    return why


class _Cluster:
    host, api_port = '10.0.0.1', 8006

    def __init__(self, kind='qemu', backup=None, restore_waits=1, die_in_restore=False, ha=(),
                 ha_readable=True, refuse_link_down=False, put_applies=True, readback=None,
                 stop_takes=0.0, clock=None, after_start=None):
        self.kind = kind
        self.backup = dict(backup if backup is not None else (QEMU_CONFIG if kind == 'qemu' else LXC_CONFIG))
        self.restore_waits, self.die_in_restore = restore_waits, die_in_restore
        self.ha, self.ha_readable = set(ha), ha_readable
        self.refuse_link_down, self.put_applies, self.readback = refuse_link_down, put_applies, readback
        self.stop_takes, self.clock, self.after_start = stop_takes, clock, after_start
        self.guests, self.running, self.locked = {}, set(), set()
        self.stopping = {}          # vmid -> when its stop is over
        self.tasks = {}             # upid -> [kind, vmid, waits left]
        self.calls = []
        self.config_at_start = None
        self.ha_started_with = None
        self.config_reads = 0
        self._n = 0

    # --- helpers ---------------------------------------------------------------------------

    def _now(self):
        return self.clock.now if self.clock else time.time()

    def _upid(self, what, vmid):
        self._n += 1
        return f'UPID:pve1:{self._n:08X}:0002:00000003:{what}:{vmid}:root@pam:'

    def _guest_path(self, path):
        parts = path.split('/')
        # /nodes/pve1/<kind>/<vmid>[/...]
        if len(parts) >= 5 and parts[1] == 'nodes' and parts[3] in ('qemu', 'lxc') and parts[4].isdigit():
            return int(parts[4]), '/'.join(parts[5:])
        return None, None

    def _is_running(self, vmid):
        done = self.stopping.get(vmid)
        if done is not None and self._now() >= done:
            self.running.discard(vmid)
            self.stopping.pop(vmid, None)
        return vmid in self.running

    def _restore_over(self, vmid):
        self.locked.discard(vmid)
        cfg = self.guests.get(vmid)
        if cfg is not None and (f'vm:{vmid}' in self.ha or f'ct:{vmid}' in self.ha):
            # the HA manager starts what it manages as soon as it can
            self.running.add(vmid)
            self.ha_started_with = dict(cfg)

    def finish(self):
        """Every restore task still running ends now: PVE carries on after PegaProx gave up."""
        for upid, (what, vmid, _left) in list(self.tasks.items()):
            if what == 'restore' and vmid in self.locked:
                self._restore_over(vmid)

    # --- the API ---------------------------------------------------------------------------

    def _path(self, url):
        return url.split('/api2/json', 1)[1]

    def _api_get(self, url, timeout=None, params=None):
        path = self._path(url)
        self.calls.append(('GET', path, params))
        if path == '/cluster/nextid':
            return _Resp(200, str(TEST_VMID))
        if path == '/cluster/ha/resources':
            if not self.ha_readable:
                return _Resp(500, None, 'cfs-lock timeout')
            return _Resp(200, [{'sid': s} for s in sorted(self.ha)])
        if path == '/nodes/pve1/vzdump/extractconfig':
            # the backup's config as the guest had it, before any restore
            return _Resp(200, ''.join(f'{k}: {v}\n' for k, v in self.backup.items() if not isinstance(v, list))
                         + ''.join(f'{a}: {b}\n' for a, b in self.backup.get('lxc') or []))
        vmid, rest = self._guest_path(path)
        if vmid is not None and rest == 'config':
            cfg = self.guests.get(vmid)
            if cfg is None:
                return _Resp(500, None, f"Configuration file 'nodes/pve1/qemu-server/{vmid}.conf' does not exist")
            self.config_reads += 1
            out = dict(cfg, lock='create') if vmid in self.locked else dict(cfg)
            if self.readback and self.config_reads == 2:
                return _Resp(200, self.readback(out))
            return _Resp(200, out)
        if vmid is not None and rest == 'status/current':
            if vmid not in self.guests:
                return _Resp(500, None, 'does not exist')
            return _Resp(200, {'status': 'running', 'uptime': 30} if self._is_running(vmid) else {'status': 'stopped'})
        return _Resp(200, {})

    def _api_post(self, url, data=None, timeout=None, **kw):
        path = self._path(url)
        self.calls.append(('POST', path, dict(data or {})))
        if path == f'/nodes/pve1/{self.kind}':
            vmid = int(data['vmid'])
            if vmid in self.guests:
                return _Resp(500, None, f'unable to restore VM {vmid} - VM {vmid} already exists on node')
            cfg = dict(self.backup)
            cfg.update({k: str(v) for k, v in (data or {}).items() if k not in _RESTORE_ARGS})
            self.guests[vmid] = cfg
            self.locked.add(vmid)
            upid = self._upid('qmrestore' if self.kind == 'qemu' else 'vzrestore', vmid)
            self.tasks[upid] = ['restore', vmid, self.restore_waits]
            return _Resp(200, upid)
        vmid, rest = self._guest_path(path)
        if vmid is not None and rest == 'status/start':
            if vmid not in self.guests:
                return _Resp(500, None, 'does not exist')
            if vmid in self.locked:
                return _Resp(500, None, f'VM {vmid} is locked (create)')
            if self._is_running(vmid):
                return _Resp(500, None, f'VM {vmid} already running')
            self.running.add(vmid)
            self.config_at_start = dict(self.guests[vmid])
            if self.after_start:
                self.after_start(self, vmid)
            return _Resp(200, self._upid('qmstart', vmid))
        if vmid is not None and rest == 'status/stop':
            if vmid in self.locked:
                return _Resp(500, None, f'VM {vmid} is locked (create)')
            upid = self._upid('qmstop', vmid)
            if self.stop_takes:
                self.stopping[vmid] = self._now() + self.stop_takes
                self.tasks[upid] = ['stop', vmid, 0]
            else:
                self.running.discard(vmid)
            return _Resp(200, upid)
        if vmid is not None and rest == 'agent/ping':
            return _Resp(200, None)
        return _Resp(200, self._upid('other', vmid or 0))

    def _api_put(self, url, data=None, **kw):
        path = self._path(url)
        body = dict(data or {})
        self.calls.append(('PUT', path, body))
        vmid, rest = self._guest_path(path)
        if vmid is None or rest != 'config' or vmid not in self.guests:
            return _Resp(500, None, 'does not exist')
        if vmid in self.locked:
            return _Resp(500, None, f'VM {vmid} is locked (create)')
        if self.refuse_link_down and any('link_down' in str(v) for v in body.values()):
            return _Resp(400, None, 'parameter verification failed: net0: property is not defined in schema: link_down')
        if 'lxc' in str(body.get('delete', '')).split(','):
            return _Resp(400, None, "parameter verification failed: delete: unable to delete 'lxc'")
        if not self.put_applies:
            return _Resp(200, None)
        cfg = self.guests[vmid]
        for k, v in body.items():
            if k == 'delete':
                for gone in str(v).split(','):
                    cfg.pop(gone, None)
            else:
                cfg[k] = str(v)
        return _Resp(200, None)

    def _api_delete(self, url, params=None, **kw):
        path = self._path(url)
        self.calls.append(('DELETE', path, params))
        if path.startswith('/nodes/pve1/tasks/'):
            upid = path.rsplit('/', 1)[1]
            what, vmid, _left = self.tasks.get(upid, (None, None, None))
            if what == 'restore' and vmid in self.locked:
                # an aborted restore takes its half-made guest with it
                self.locked.discard(vmid)
                self.guests.pop(vmid, None)
            return _Resp(200, None)
        vmid, rest = self._guest_path(path)
        if vmid is None or rest != '' or vmid not in self.guests:
            return _Resp(500, None, 'does not exist')
        if vmid in self.locked:
            return _Resp(500, None, f'VM {vmid} is locked (create)')
        if self._is_running(vmid):
            return _Resp(500, None, f'VM {vmid} is running - destroy failed')
        if str(self.guests[vmid].get('protection', '0')) == '1':
            return _Resp(500, None, f"can't remove VM {vmid} - protection mode enabled")
        self.guests.pop(vmid)
        return _Resp(200, self._upid('qmdestroy', vmid))

    def _wait_for_task(self, node, upid, timeout=600):
        task = self.tasks.get(upid)
        if task is None:
            return True
        what, vmid, left = task
        if what == 'restore':
            if self.die_in_restore:
                raise _ProcessDied()
            task[2] = left - 1
            if task[2] > 0:
                return False          # timed out; the task runs on
            if vmid in self.locked:
                self._restore_over(vmid)
            return True
        if what == 'stop':
            self.running.discard(vmid)
            self.stopping.pop(vmid, None)
        return True

    def get_vm_resources(self, max_age=0):
        return [{'vmid': 100, 'type': self.kind, 'node': 'pve1', 'tags': 'prod'}]


@pytest.fixture(autouse=True)
def _own_registry(monkeypatch):
    # a run cut off by _ProcessDied stays 'running' in the registry
    monkeypatch.setattr(bv, '_active_verifications', {})


# --- isolation: what the test guest boots with ---------------------------------------------

@pytest.mark.parametrize('key,value', [
    # a directory of the node, shared read-write through a cluster directory mapping (PVE 8.4+)
    ('virtiofs0', 'dirid=prod-data,cache=auto'),
    # named shared memory: /dev/shm/pve-shm-looking-glass is the original's region
    ('ivshmem', 'size=32,name=looking-glass'),
    # raw QEMU arguments: a user-mode NIC that no netN names
    ('args', '-netdev user,id=n9 -device virtio-net-pci,netdev=n9'),
    # host-side code of the original, run for the copy at pre-start and post-start
    ('hookscript', 'local:snippets/net-up.pl'),
])
def test_the_test_guest_boots_without_what_ties_the_original_to_its_host(clock, db, key, value):
    pve = _Cluster(backup=dict(QEMU_CONFIG, **{key: value}))
    st = bv.run_verification(pve, _params())
    started = pve.config_at_start
    assert started is None or key not in started, (
        f"the test guest booted with {key}: {started.get(key)!r} ({st['status']})")


def test_raw_lxc_entries_of_a_container_never_boot_with_the_copy(clock, db):
    """Restored as root@pam, a container keeps its raw lxc.* lines (PVE skips them only
    for a restricted user): a bind mount of a node directory and a second NIC on vmbr0
    that no netN names. The API cannot delete them, so such a copy must not boot."""
    raw = [['lxc.mount.entry', '/srv/prod-db srv/db none bind,create=dir 0 0'],
           ['lxc.net.1.type', 'veth'], ['lxc.net.1.link', 'vmbr0'], ['lxc.net.1.flags', 'up'],
           ['lxc.cgroup2.devices.allow', 'c 195:* rwm']]
    pve = _Cluster(kind='lxc', backup=dict(LXC_CONFIG, lxc=raw))
    st = bv.run_verification(pve, _params('lxc'))
    started = pve.config_at_start
    assert started is None or not started.get('lxc'), (
        f"the container copy booted with its raw entries {started.get('lxc')} ({st['status']})")


def test_which_raw_lxc_lines_keep_a_copy_from_booting():
    inside = [['lxc.apparmor.profile', 'unconfined'], ['lxc.cap.drop', ''], ['lxc.idmap', 'u 0 100000 65536'],
              ['lxc.cgroup2.cpuset.cpus', '0-3'], ['lxc.prlimit.nofile', '65536']]
    reach = [['lxc.mount.auto', 'proc:rw sys:rw'], ['lxc.net.0.type', 'none'], ['lxc.namespace.share.net', '1'],
             ['lxc.cgroup2.devices.allow', 'a'], ['lxc.hook.pre-start', '/root/up.sh'],
             ['lxc.console.logfile', '/var/log/ct.log'], ['lxc.include', '/etc/extra.conf']]
    assert bv.raw_lxc_reach({'lxc': inside}) == []
    assert bv.raw_lxc_reach({'lxc': inside + reach}) == sorted(k for k, _v in reach)
    # a shape Proxmox does not send is no proof of anything
    assert bv.raw_lxc_reach({'lxc': 'lxc.mount.entry: /srv x none bind 0 0'}) != []


def test_a_read_back_without_the_nics_is_no_proof_they_are_down(clock, db):
    """The read-back is there for a write that did not take. One that answers without the
    NICs (or with nothing) passed as 'nothing unisolated' and the copy booted as restored."""
    pve = _Cluster(put_applies=False, readback=lambda cfg: None)
    bv.run_verification(pve, _params())
    started = pve.config_at_start
    assert started is None or not unisolated(started), f'booted with {unisolated(started)} up'


def test_an_unreadable_ha_list_does_not_count_as_no_ha(clock, db):
    """A stale HA resource on the VMID nextid hands out starts the copy the moment its
    restore is over, before it is isolated; a failed read of the list waved it through."""
    pve = _Cluster(ha={f'vm:{TEST_VMID}'}, ha_readable=False)
    bv.run_verification(pve, _params())
    ran = pve.ha_started_with
    assert ran is None or not unisolated(ran), f'PVE HA started the copy with {unisolated(ran)} on the network'


# --- the copy left behind ------------------------------------------------------------------

@pytest.mark.parametrize('isolation_refused', [False, True])
def test_a_protected_original_leaves_no_copy_behind(clock, db, isolation_refused):
    """protection=1 comes with the backup. Nothing clears it, so the destroy is refused on
    every run, the run still says passed, and where the isolation was refused (link_down
    unknown to this PVE) the copy stays with onboot=1 and its NICs up."""
    pve = _Cluster(backup=dict(QEMU_CONFIG, protection='1'), refuse_link_down=isolation_refused)
    st = bv.run_verification(pve, _params())
    left = pve.guests.get(TEST_VMID)
    assert left is None, (f"run {st['status']}: copy {TEST_VMID} left behind"
                          + (f" with {unisolated(left)} not isolated" if unisolated(left) else ''))


def test_a_restore_that_outlasts_the_wait_leaves_no_unisolated_copy(clock, db):
    """A restore that takes longer than the 600 s wait (any large guest): the run gives up,
    the emergency stop and destroy are refused while the restore holds its lock, the log
    says 'deleted' anyway, and when the restore ends PVE holds a full copy with onboot=1,
    the original's NICs up and its passthrough devices."""
    pve = _Cluster(restore_waits=2)
    st = bv.run_verification(pve, _params())
    assert st['status'] == 'error'
    pve.finish()
    left = pve.guests.get(TEST_VMID)
    assert left is None or not unisolated(left), (
        f'copy {TEST_VMID} left with {unisolated(left)} not isolated; the log says: {st["logs"][-1]}')


def test_a_process_gone_during_the_restore_leaves_no_unisolated_copy(clock, db):
    """From the moment PVE accepts the restore until _isolate, the copy exists as the backup
    has it (onboot=1, NICs up). Nothing records the test VMID before the run ends, so a
    restart in that window (the restore is the longest step) leaves it for good, and the
    next reboot of the node boots it next to the original with the original's IP."""
    pve = _Cluster(die_in_restore=True)
    with pytest.raises(_ProcessDied):
        bv.run_verification(pve, _params())
    pve.finish()
    left = pve.guests.get(TEST_VMID)
    assert left is None or not unisolated(left), f'copy {TEST_VMID} left with {unisolated(left)} not isolated'


def test_the_cleanup_waits_for_the_stop_before_the_destroy(clock, db):
    """The stop task is not waited for: five seconds later the destroy of a guest still
    running is refused and the copy stays, the run passed all the same."""
    pve = _Cluster(stop_takes=12, clock=clock)
    st = bv.run_verification(pve, _params())
    assert st['status'] == 'passed'
    assert TEST_VMID not in pve.guests, f"copy {TEST_VMID} left running; cleanup_ok={st['cleanup_ok']}"


def test_the_cleanup_removes_only_its_own_test_guest(clock, db):
    """The copy is stopped and removed by hand while the run waits for it to boot, and the
    next create takes the lowest free VMID: the test's. The cleanup destroyed that guest,
    purge and unreferenced disks, without looking whether it still was the test guest."""
    def someone_else(pve, vmid):
        pve.running.discard(vmid)
        pve.guests[vmid] = {'name': 'build01', 'tags': 'ci', 'onboot': '1',
                            'net0': 'virtio=BC:24:11:00:00:99,bridge=vmbr0',
                            'scsi0': f'local-lvm:vm-{vmid}-disk-0,size=64G'}
    pve = _Cluster(after_start=someone_else)
    bv.run_verification(pve, _params())
    assert pve.guests.get(TEST_VMID, {}).get('name') == 'build01', (
        f'the cleanup destroyed guest {TEST_VMID} that was no test guest any more: '
        f"{[c for c in pve.calls if c[0] == 'DELETE']}")


# --- the routes ----------------------------------------------------------------------------

SECRET = 'PGPASSWORD=s3cr3t-db-pass pg_isready -h 127.0.0.1'


@pytest.fixture
def report(api, seed, monkeypatch):
    import test_recovery_report as rr
    monkeypatch.setattr(recovery, '_backups', {})
    rr._manager(api)
    return types.SimpleNamespace(api=api, seed=seed, admin=api.as_user(seed.user('root', role='admin')), rr=rr)


def test_a_confined_caller_never_reads_the_check_command(report, db):
    """The command is masked for everybody but an admin (settings, report, plan of a guest:
    command '' and command_set). The checks of the last test that passed and of the history
    carry it as their target and go out unmasked on the guest's report."""
    recovery.save_rule('c1', 'guest', '100', {'command': SECRET}, 'root')
    checks = [{'check': 'command', 'target': SECRET, 'ok': True, 'detail': 'exit code 0'}]
    recovery.note_result({'cluster_id': 'c1', 'vmid': 100, 'status': 'passed', 'id': 't1',
                          'backup_ts': int(time.time()) - 3600, 'measured_seconds': 200.0, 'checks': checks})
    db.execute("INSERT INTO backup_verifications (id, cluster_id, vmid, started_at, status, details) "
               "VALUES ('t1', 'c1', 100, '2026-10-09T04:00:00', 'passed', ?)",
               (json.dumps({'checks': checks, 'source': 'schedule',
                            'logs': [f'Check command {SECRET}: ok (exit code 0)']}),))
    c = report.rr._who(report, 'acl_confined')
    r = c.get('/api/clusters/c1/recovery-report/100')
    assert r.status_code == 200, r.data
    body = r.get_json()
    assert body['checks']['command'] == '' and body['checks']['command_set'] is True
    assert 's3cr3t' not in r.get_data(as_text=True), [
        k for k in ('guest', 'history') if 's3cr3t' in json.dumps(body[k])]


def test_a_test_guest_kept_through_backup_verify_counts_against_the_quota(api, seed, monkeypatch):
    """backup-restore mode 'test' keeps the test guest only within the tenant quota.
    backup-verify with auto_cleanup false keeps it too (restored at nextid, in no pool,
    running, isolated) and asks nobody: a tenant at its ceiling adds a guest per call."""
    import test_tenant_quota_beyond_create as tq
    us = tq._users(seed)
    tq._tenant(seed.db)
    tq._mgr(api, backup_cfg='cores: 1\nmemory: 512\nscsi0: local-lvm:x,size=4G\n')
    seen = []
    monkeypatch.setattr(bv, 'start_verification', lambda mgr, data: seen.append(dict(data)) or 'task1')
    c = api.as_user(us['tenant'])
    volid = 'pbs:backup/vm/100/2026-10-01T00:00:00Z'
    r = c.post(f'/api/clusters/{tq.CL}/backup-restore',
               json={'volid': volid, 'target_node': 'pve1', 'target_vmid': 100, 'mode': 'test'})
    assert r.status_code == 403 and 'quota' in r.get_json()['error'].lower()
    r = c.post(f'/api/clusters/{tq.CL}/backup-verify',
               json={'node': 'pve1', 'vmid': 100, 'backup_volid': volid, 'auto_cleanup': False})
    kept = [s for s in seen if s.get('auto_cleanup') is False]
    assert r.status_code == 403 or not kept, (r.status_code, kept)


def test_a_manual_restore_test_names_its_guest_once(report, monkeypatch):
    seen = []
    monkeypatch.setattr(bv, 'start_verification', lambda mgr, data: seen.append(dict(data)) or 'task1')
    volid = 'pbs:backup/vm/100/2026-10-01T00:00:00Z'
    r = report.admin.post('/api/clusters/c1/backup-verify', json={'node': 'pve1', 'vmid': '100', 'backup_volid': volid})
    assert r.status_code == 200, r.data
    assert seen[0]['vmid'] == 100
    # "100" and 100 are one guest for the check that lets one copy of it run at a time
    monkeypatch.setattr(bv, '_active_verifications', {})
    bv._register({'cluster_id': 'c1', 'vmid': 100})
    with pytest.raises(Exception, match='already running'):
        bv._register({'cluster_id': 'c1', 'vmid': '100'})


def test_a_confined_caller_tests_a_restore_on_its_own_nodes_and_the_set_storage(report, monkeypatch):
    seen = []
    monkeypatch.setattr(bv, 'start_verification', lambda mgr, data: seen.append(dict(data)) or 'task1')
    report.seed.tenant('t_confined', [])
    report.seed.vm_acl('c1', 100, ['portal'], permissions=['vm.view', 'vm.backup'])
    c = report.api.as_user(report.seed.user('portal', role='user', tenant_id='t_confined', permissions=['vm.backup']))
    body = {'vmid': 100, 'backup_volid': 'pbs:backup/vm/100/2026-10-01T00:00:00Z', 'storage': 'big-ssd'}
    # VM 100 lives on pve1: pve2 is no node of theirs
    r = c.post('/api/clusters/c1/backup-verify', json=dict(body, node='pve2'))
    assert r.status_code == 403 and 'node' in r.get_json()['error'], r.data
    assert seen == []
    assert c.post('/api/clusters/c1/backup-verify', json=dict(body, node='pve1')).status_code == 200
    assert 'storage' not in seen[0]
    # counterproof: an admin picks both
    assert report.admin.post('/api/clusters/c1/backup-verify', json=dict(body, node='pve2')).status_code == 200
    assert seen[1]['storage'] == 'big-ssd' and seen[1]['node'] == 'pve2'


def test_the_verification_routes_do_not_show_the_command_either(report, db):
    """The same caller with vm.backup on its guest: the settings mask the command, the
    status and history of a verification hand it back in the checks and the logs."""
    recovery.save_rule('c1', 'guest', '100', {'command': SECRET}, 'root')
    checks = [{'check': 'command', 'target': SECRET, 'ok': True, 'detail': 'exit code 0'}]
    db.execute("INSERT INTO backup_verifications (id, cluster_id, vmid, started_at, status, details) "
               "VALUES ('t1', 'c1', 100, '2026-10-09T04:00:00', 'passed', ?)",
               (json.dumps({'checks': checks, 'source': 'schedule',
                            'logs': [f'Check command {SECRET}: ok (exit code 0)']}),))
    report.seed.tenant('t_confined', [])
    report.seed.vm_acl('c1', 100, ['portal'], permissions=['vm.view', 'backup.view', 'vm.backup'])
    c = report.api.as_user(report.seed.user('portal', role='user', tenant_id='t_confined',
                                            permissions=['backup.view', 'vm.backup']))
    settings = c.get('/api/clusters/c1/recovery-settings').get_json()
    assert settings['guests'][0]['command'] == '' and settings['guests'][0]['command_set'] is True
    leaked = []
    for path in ('/api/clusters/c1/backup-verify/history?vmid=100', '/api/clusters/c1/backup-verify/t1'):
        r = c.get(path)
        assert r.status_code == 200, (path, r.data)
        if 's3cr3t' in r.get_data(as_text=True):
            leaked.append(path)
    assert leaked == []


def test_the_copy_is_isolated_by_the_restore_call_itself(clock, db):
    """onboot, protection, the tag, the run's mark and every NIC down without its MAC go
    with the restore, so the copy is isolated from the moment Proxmox creates it."""
    pve = _Cluster(backup=dict(QEMU_CONFIG, protection='1'))
    st = bv.run_verification(pve, _params())
    sent = next(c[2] for c in pve.calls if c[0] == 'POST' and c[1] == '/nodes/pve1/qemu')
    assert sent['onboot'] == 0 and sent['protection'] == 0 and 'pegaprox-verify' in sent['tags']
    assert sent['description'] == bv.mark_of(st['id'])
    assert sent['net0'] == 'virtio,bridge=vmbr0,firewall=1,tag=20,link_down=1'
    assert sent['net1'] == 'e1000,bridge=vmbr1,link_down=1'
    assert sent['unique'] == 1 and sent['start'] == 0


def test_an_unreadable_ha_list_restores_nothing(clock, db):
    pve = _Cluster(ha_readable=False)
    st = bv.run_verification(pve, _params())
    assert st['status'] == 'error' and 'HA resources could not be read' in st['error']
    assert not [c for c in pve.calls if c[0] == 'POST' and c[1] == '/nodes/pve1/qemu']


@pytest.mark.parametrize('readback,why', [
    (lambda cfg: None, 'could not read the test guest back'),
    (lambda cfg: {k: v for k, v in cfg.items() if k != 'net1'}, 'read back without net1'),
])
def test_a_read_back_that_proves_nothing_never_boots(clock, db, readback, why):
    pve = _Cluster(readback=readback)
    st = bv.run_verification(pve, _params())
    assert st['status'] == 'error' and why in st['error']
    assert pve.config_at_start is None and TEST_VMID not in pve.guests


def test_a_restore_past_its_wait_is_stopped_and_its_copy_removed(clock, db):
    pve = _Cluster(restore_waits=2)
    st = bv.run_verification(pve, _params())
    assert ('DELETE', f"/nodes/pve1/tasks/{st['restore_upid']}", None) in pve.calls
    pve.finish()
    assert TEST_VMID not in pve.guests and st['cleanup_ok'] is True


def test_a_restore_that_cannot_be_stopped_is_not_logged_as_deleted(clock, db):
    """The stop of the restore task is refused and Proxmox holds the guest locked: the log
    says what is so, the copy waits for the sweep, isolated by the restore call."""
    class Unstoppable(_Cluster):
        def _api_delete(self, url, params=None, **kw):
            if '/tasks/' in url:
                self.calls.append(('DELETE', self._path(url), params))
                return _Resp(500, None, 'permission denied')
            return super()._api_delete(url, params=params, **kw)
    pve = Unstoppable(restore_waits=2)
    pve.is_connected = True
    st = bv.run_verification(pve, _params())
    assert st['status'] == 'error' and 'was not removed: Proxmox holds it locked (create)' in st['error']
    assert not [ln for ln in st['logs'] if 'deleted' in ln]
    assert db.conn.execute('SELECT phase FROM backup_verifications').fetchone()['phase'] == 'leftover'
    pve.finish()
    assert not unisolated(pve.guests[TEST_VMID])
    assert bv.sweep({'c1': pve}) == 1 and TEST_VMID not in pve.guests


def test_a_container_copy_is_stopped_the_way_pct_takes_it(clock, db):
    """A container's stop has no timeout parameter; Proxmox refuses the call with one and
    the destroy of the running copy after it."""
    pve = _Cluster(kind='lxc')
    st = bv.run_verification(pve, _params('lxc'))
    assert st['status'] == 'passed' and TEST_VMID not in pve.guests
    assert ('POST', f'/nodes/pve1/lxc/{TEST_VMID}/status/stop', {}) in pve.calls


def test_an_unreadable_backup_config_restores_nothing(clock, db):
    class NoConfig(_Cluster):
        def _api_get(self, url, timeout=None, params=None):
            if url.endswith('/vzdump/extractconfig'):
                self.calls.append(('GET', self._path(url), params))
                return _Resp(500, None, 'unable to read config')
            return super()._api_get(url, timeout, params)
    pve = NoConfig()
    st = bv.run_verification(pve, _params())
    assert st['status'] == 'error' and 'config in the backup' in st['error']
    assert not pve.guests and not [c for c in pve.calls if c[0] == 'POST' and c[1] == '/nodes/pve1/qemu']


def test_protection_is_cleared_before_the_destroy_where_the_restore_kept_it(clock, db):
    """A Proxmox that took protection from the backup in spite of the restore call: the
    removal clears it on its own before the destroy."""
    class KeepsProtection(_Cluster):
        def _api_post(self, url, data=None, timeout=None, **kw):
            r = super()._api_post(url, data=data, timeout=timeout, **kw)
            if self._path(url) == '/nodes/pve1/qemu' and r.status_code == 200:
                self.guests[int(data['vmid'])]['protection'] = '1'
            return r
    pve = KeepsProtection(backup=dict(QEMU_CONFIG, protection='1'))
    st = bv.run_verification(pve, _params())
    assert st['status'] == 'passed' and st['cleanup_ok'] is True and TEST_VMID not in pve.guests
    assert ('PUT', f'/nodes/pve1/qemu/{TEST_VMID}/config', {'delete': 'protection'}) in pve.calls


class _RefusesDestroy(_Cluster):
    refuse = True

    def _api_delete(self, url, params=None, **kw):
        if self.refuse and self._path(url) == f'/nodes/pve1/qemu/{TEST_VMID}':
            self.calls.append(('DELETE', self._path(url), params))
            return _Resp(500, None, "can't lock file '/var/lock/qemu-server/lock-105.conf' - got timeout")
        return super()._api_delete(url, params=params, **kw)


def test_a_destroy_proxmox_refuses_fails_the_run_and_the_sweep_finishes_it(clock, db):
    pve = _RefusesDestroy()
    pve.is_connected = True
    st = bv.run_verification(pve, _params())
    assert st['status'] == 'error' and st['cleanup_ok'] is False
    assert f'test guest {TEST_VMID} was not removed' in st['error'] and 'got timeout' in st['error']
    # the report says it: the guest's last test did not pass
    mark = recovery.load_marks('c1')[100]
    assert mark['last_result'] == 'error' and 'was not removed' in mark['fail_cause']
    row = db.conn.execute('SELECT phase, cleanup_ok FROM backup_verifications WHERE id = ?', (st['id'],)).fetchone()
    assert row['phase'] == 'leftover' and row['cleanup_ok'] == 0
    # still refused: tried again later, nothing settled
    assert bv.sweep({'c1': pve}) == 0 and TEST_VMID in pve.guests
    pve.refuse = False
    assert bv.sweep({'c1': pve}) == 1 and TEST_VMID not in pve.guests
    row = db.conn.execute('SELECT phase, cleanup_ok, details FROM backup_verifications WHERE id = ?',
                          (st['id'],)).fetchone()
    assert row['phase'] == 'done' and row['cleanup_ok'] == 1
    assert 'removed afterwards' in json.loads(row['details'])['logs'][-1]
    assert bv.sweep({'c1': pve}) == 0


def test_the_sweep_removes_the_copy_of_a_run_a_restart_cut_off(clock, db):
    pve = _Cluster(die_in_restore=True)
    pve.is_connected = True
    with pytest.raises(_ProcessDied):
        bv.run_verification(pve, _params())
    row = db.conn.execute('SELECT id, status, test_vmid, details FROM backup_verifications').fetchone()
    assert row['status'] == 'running' and row['test_vmid'] == TEST_VMID
    assert json.loads(row['details'])['restore_upid'].startswith('UPID:pve1:')
    # a run of this process is not touched
    assert bv.sweep({'c1': pve}) == 0 and TEST_VMID in pve.guests
    bv._active_verifications.clear()          # the restart
    assert bv.sweep({'c1': pve}) == 1
    assert TEST_VMID not in pve.guests
    assert ('DELETE', f"/nodes/pve1/tasks/{json.loads(row['details'])['restore_upid']}", None) in pve.calls
    row = db.conn.execute('SELECT status, phase, error FROM backup_verifications').fetchone()
    assert row['status'] == 'error' and row['phase'] == 'done' and 'stopped while the test ran' in row['error']
    assert recovery.load_marks('c1')[100]['last_result'] == 'error'


def test_the_sweep_leaves_a_guest_that_is_not_the_runs_own(clock, db):
    pve = _Cluster(die_in_restore=True)
    pve.is_connected = True
    with pytest.raises(_ProcessDied):
        bv.run_verification(pve, _params())
    pve.finish()
    pve.guests[TEST_VMID] = {'name': 'build01', 'tags': 'ci'}
    bv._active_verifications.clear()
    assert bv.sweep({'c1': pve}) == 1
    assert pve.guests[TEST_VMID]['name'] == 'build01'
    assert not [c for c in pve.calls if c[0] == 'DELETE' and c[1] == f'/nodes/pve1/qemu/{TEST_VMID}']
    row = db.conn.execute('SELECT status, error FROM backup_verifications').fetchone()
    assert row['status'] == 'error' and 'left alone' in row['error']


def test_the_active_route_masks_the_command_too(report, db, monkeypatch):
    checks = [{'check': 'command', 'target': SECRET, 'ok': False, 'detail': 'exit code 1'}]
    run = {'id': 't9', 'cluster_id': 'c1', 'vmid': 100, 'status': 'running', 'checks': checks,
           'logs': [f'[04:00:00] Check command {SECRET}: FAILED (exit code 1)',
                    f'[04:00:01] Check failed: command {SECRET} - exit code 1']}
    monkeypatch.setattr(bv, 'get_active_verifications', lambda: {'t9': run})
    monkeypatch.setattr(bv, 'get_verification', lambda tid: run if tid == 't9' else None)
    report.seed.tenant('t_confined', [])
    report.seed.vm_acl('c1', 100, ['portal'], permissions=['vm.view', 'backup.view', 'vm.backup'])
    c = report.api.as_user(report.seed.user('portal', role='user', tenant_id='t_confined',
                                            permissions=['backup.view', 'vm.backup']))
    for path in ('/api/clusters/c1/backup-verify/active', '/api/clusters/c1/backup-verify/t9'):
        r = c.get(path)
        assert r.status_code == 200 and 's3cr3t' not in r.get_data(as_text=True), (path, r.data)
    got = c.get('/api/clusters/c1/backup-verify/t9').get_json()
    assert got['checks'][0]['target'] == '' and got['logs'][0].endswith('Check command ***: FAILED (exit code 1)')
    # an admin reads what ran
    r = report.admin.get('/api/clusters/c1/backup-verify/t9')
    assert r.get_json()['checks'][0]['target'] == SECRET
    assert run['checks'][0]['target'] == SECRET          # the registry's own copy is untouched


def test_the_balancer_leaves_a_test_guest_where_its_run_looks_for_it():
    """The run addresses its copy on the node it restored it on, for the boot wait, the
    checks and the cleanup. Our own balancer took a running pegaprox-verify guest like any
    other: moved during the run, the checks fail on a backup that is fine and the stop and
    destroy go to a node it is no longer on, so the copy keeps running."""
    import test_balancer_history as tbh
    m = tbh._manager([tbh._guest(TEST_VMID, tags='pegaprox-verify;prod;web')])
    picked = m.find_migration_candidate('pve1', 'pve2')
    assert picked is None, f"the balancer picked test guest {picked and picked.get('vmid')}"


def test_a_test_guest_takes_no_pin_or_group_from_the_original(db):
    """The copy carries the original's tags: a plb_pin_ tag of the original had the pin
    reconcile move the copy mid-test, a plb_affinity_ tag put it in the original's group."""
    import test_proxlb_pins as tp
    m = tp._manager([tp._guest(30021, node=tp.I1, tags=tp.PIN_A1 + ';plb_affinity_web'),
                     tp._guest(30022, node=tp.I1, tags=tp.PIN_A1 + ';plb_affinity_web'),
                     tp._guest(TEST_VMID, node=tp.I1, tags=f'pegaprox-verify;{tp.PIN_A1};plb_affinity_web')])
    derived = m._derive_proxlb_tag_rules()
    assert TEST_VMID not in derived['pins'] and set(derived['pins']) == {30021, 30022}
    assert all(str(TEST_VMID) not in r['vms'] for r in derived['rules'])
