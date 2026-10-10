"""A restore test never boots the restored copy on the production network, and checks it.

core/backup_verify.py restored the backup with the original's MAC addresses and booted it
with every NIC on the original's bridge: the copy came up next to the guest it was taken
from, same MAC, same IP. Only a caller-chosen network_bridge moved it, and that was any
bridge the caller named. Now, before the start, every NIC is set link_down (or moved to
the cluster's isolated test bridge), onboot is off, passthrough devices and bind mounts go,
the disks are left out of backup jobs and the guest is tagged pegaprox-verify; the config
is read back, and a test guest that is not isolated is removed without booting.

After the boot: the guest agent, the TCP ports that must listen and a command, through the
guest agent (the NICs are down), in a container through pct exec on its node, or reported
as skipped where the node has no shell for us. What restore, boot and checks took is held
against the RTO, and the guest's mark (restore_test_marks) takes the result.

Driven against a fake Proxmox VE that keeps the test guest's config and records every call.
MK Oct 2026
"""
import threading
import time
import types

import pytest

import pegaprox.core.backup_verify as bv
from pegaprox.core import recovery

TEST_VMID = 105
QEMU_CONFIG = {
    'name': 'web01', 'onboot': 1, 'agent': '1', 'tags': 'prod;web',
    'net0': 'virtio=BC:24:11:00:00:01,bridge=vmbr0,firewall=1,tag=20',
    'net1': 'e1000=BC:24:11:00:00:02,bridge=vmbr1',
    'scsi0': 'local-lvm:vm-105-disk-0,size=32G',
    'ide2': 'none,media=cdrom',
    'hostpci0': '0000:01:00.0,pcie=1', 'usb0': 'host=1234:5678',
    'serial0': 'socket', 'serial1': '/dev/ttyS1',
}
LXC_CONFIG = {
    'hostname': 'ct1', 'onboot': 1, 'tags': 'db',
    'net0': 'name=eth0,bridge=vmbr0,hwaddr=BC:24:11:00:00:03,ip=10.0.0.5/24,gw=10.0.0.1,type=veth',
    'rootfs': 'local-lvm:vm-105-disk-0,size=8G',
    'mp0': '/srv/shared,mp=/data', 'mp1': 'local-lvm:vm-105-disk-1,mp=/var/lib/db,backup=1',
    'dev0': '/dev/ttyUSB0',
}
SS_OUT = ('LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*\nLISTEN 0 511 [::]:80 [::]:*\n'
          'ESTAB 0 0 10.0.0.5:22 10.0.0.9:50422\n')
WIN_OUT = ('\r\nActive Connections\r\n\r\n  Proto  Local Address    Foreign Address  State\r\n'
           '  TCP    0.0.0.0:3389     0.0.0.0:0        ABHOEREN\r\n'
           '  TCP    10.0.0.5:49711   10.0.0.9:443     HERGESTELLT\r\n')


class _Resp:
    def __init__(self, status, data=None, text=''):
        self.status_code, self._data, self.text = status, data, text

    def json(self):
        return {'data': self._data}


class _Clock:
    """time as the engine sees it: sleeping moves it on."""

    def __init__(self):
        self.now = 1_790_000_000.0

    def time(self):
        return self.now

    def sleep(self, s):
        self.now += s


class _PVE:
    host, api_port = '10.0.0.1', 8006

    def __init__(self, kind='qemu', config=None, put_ok=True, ha=(), agent=True, listeners=SS_OUT,
                 linux=True, exit_code=0, boot=True, clock=None, restore_takes=0):
        self.kind, self.put_ok, self.ha, self.agent = kind, put_ok, list(ha), agent
        self.listeners, self.linux, self.exit_code, self.boot = listeners, linux, exit_code, boot
        self.clock, self.restore_takes = clock, restore_takes
        self.config = dict(config if config is not None else (QEMU_CONFIG if kind == 'qemu' else LXC_CONFIG))
        self.calls = []
        self.config_at_start = None
        self.execs = {}
        self.exec_cmds = []

    def _path(self, url):
        return url.split('/api2/json', 1)[1]

    def _api_get(self, url, timeout=None, params=None):
        path = self._path(url)
        self.calls.append(('GET', path, params))
        if path == '/cluster/nextid':
            return _Resp(200, str(TEST_VMID))
        if path == '/cluster/ha/resources':
            return _Resp(200, [{'sid': s} for s in self.ha])
        if path.endswith(f'/{TEST_VMID}/config'):
            return _Resp(200, dict(self.config))
        if path.endswith('/status/current'):
            return _Resp(200, {'status': 'running', 'uptime': 30} if self.boot else {'status': 'stopped'})
        if path.endswith('/agent/exec-status'):
            code, out = self.execs[int(params['pid'])]
            return _Resp(200, {'exited': 1, 'exitcode': code, 'out-data': out})
        return _Resp(200, {})

    def _api_post(self, url, data=None, timeout=None, **kw):
        path = self._path(url)
        self.calls.append(('POST', path, data))
        if path == f'/nodes/pve1/{self.kind}':
            if self.clock:
                self.clock.now += self.restore_takes
            return _Resp(200, 'UPID:pve1:0001:0002:00000003:restore::root@pam:')
        if path.endswith('/status/start'):
            self.config_at_start = dict(self.config)
            return _Resp(200, 'UPID:pve1:0001:0002:00000004:start::root@pam:')
        if path.endswith('/agent/ping'):
            return _Resp(200 if self.agent else 500, None, '' if self.agent else 'QEMU guest agent is not running')
        if path.endswith('/agent/exec'):
            argv = list(data['command'])
            self.exec_cmds.append(argv)
            if argv[0] == 'sh' and not self.linux:
                return _Resp(500, None, 'Agent error: Failed to execute child process "sh"')
            pid = len(self.execs) + 1
            if 'netstat' in argv[-1] or 'ss -Hltn' in argv[-1]:
                self.execs[pid] = (0, self.listeners)
            else:
                self.execs[pid] = (self.exit_code, '')
            return _Resp(200, {'pid': pid})
        return _Resp(200, 'UPID:pve1:0001:0002:00000005:other::root@pam:')

    def _api_put(self, url, data=None, **kw):
        self.calls.append(('PUT', self._path(url), dict(data or {})))
        if not self.put_ok:
            return _Resp(400, None, "parameter verification failed: link_down: property is not defined")
        for k, v in (data or {}).items():
            if k == 'delete':
                for gone in v.split(','):
                    self.config.pop(gone, None)
            else:
                self.config[k] = str(v)
        return _Resp(200, None)

    def _api_delete(self, url, **kw):
        self.calls.append(('DELETE', self._path(url), kw.get('params')))
        return _Resp(200, 'UPID:pve1:0001:0002:00000006:destroy::root@pam:')

    def _wait_for_task(self, node, upid, timeout=600):
        return True

    def get_vm_resources(self, max_age=0):
        return [{'vmid': 100, 'type': self.kind, 'node': 'pve1', 'tags': 'prod'}]

    def index(self, method, suffix):
        return next(i for i, c in enumerate(self.calls) if c[0] == method and c[1].endswith(suffix))


@pytest.fixture
def clock(monkeypatch):
    c = _Clock()
    monkeypatch.setattr(bv, 'time', types.SimpleNamespace(time=c.time, sleep=c.sleep, strftime=time.strftime))
    return c


def _plan(**kw):
    p = {'isolation': 'link_down', 'test_bridge': '', 'test_storage': '', 'boot_timeout': 120,
         'agent': 'auto', 'ports': [], 'command': '', 'rto_seconds': 0}
    p.update(kw)
    return p


def _params(kind='qemu', **kw):
    volid = 'pbs:backup/vm/100/2026-10-01T02:00:00Z' if kind == 'qemu' else 'pbs:backup/ct/100/2026-10-01T02:00:00Z'
    p = {'cluster_id': 'c1', 'node': 'pve1', 'vmid': 100, 'vm_name': 'web01', 'backup_volid': volid,
         'plan': _plan()}
    p.update(kw)
    return p


# --- what isolation changes ----------------------------------------------------------------

def test_every_nic_goes_down_and_whatever_reaches_the_host_goes():
    changes, deletes, disks = bv.isolation_changes(QEMU_CONFIG, 'qemu', _plan())
    assert changes['net0'] == 'virtio=BC:24:11:00:00:01,bridge=vmbr0,firewall=1,tag=20,link_down=1'
    assert changes['net1'] == 'e1000=BC:24:11:00:00:02,bridge=vmbr1,link_down=1'
    assert changes['onboot'] == 0 and changes['tags'] == 'pegaprox-verify;prod;web'
    # a passthrough device would be taken from the original; a socket serial stays
    assert deletes == ['hostpci0', 'serial1', 'usb0']
    # the disks stay out of backup jobs, the CD drive is no disk
    assert disks == {'scsi0': 'local-lvm:vm-105-disk-0,size=32G,backup=0'}


def test_on_the_test_bridge_the_vlan_goes_and_the_link_stays_up():
    changes, _d, _x = bv.isolation_changes(QEMU_CONFIG, 'qemu', _plan(isolation='bridge', test_bridge='vmbr99'))
    assert changes['net0'] == 'virtio=BC:24:11:00:00:01,bridge=vmbr99,firewall=1'
    assert changes['net1'] == 'e1000=BC:24:11:00:00:02,bridge=vmbr99'


def test_a_container_loses_its_bind_mounts_and_devices():
    changes, deletes, disks = bv.isolation_changes(LXC_CONFIG, 'lxc', _plan())
    assert changes['net0'].endswith(',type=veth,link_down=1')
    assert deletes == ['dev0', 'mp0']
    assert disks == {'mp1': 'local-lvm:vm-105-disk-1,mp=/var/lib/db,backup=0'}


def test_a_nic_that_is_not_down_counts_as_on_the_network():
    plan = _plan()
    assert bv.unisolated_nics(QEMU_CONFIG, plan) == ['net0', 'net1']
    down = {k: v + ',link_down=1' for k, v in QEMU_CONFIG.items() if k.startswith('net')}
    assert bv.unisolated_nics(down, plan) == []
    bridge = _plan(isolation='bridge', test_bridge='vmbr99')
    assert bv.unisolated_nics({'net0': 'virtio=x,bridge=vmbr99,tag=5'}, bridge) == ['net0']
    assert bv.unisolated_nics({'net0': 'virtio=x,bridge=vmbr99'}, bridge) == []


def test_listening_ports_from_ss_netstat_and_windows():
    assert bv.parse_listening(SS_OUT) == {22, 80}
    assert bv.parse_listening('tcp 0 0 0.0.0.0:5432 0.0.0.0:* LISTEN\ntcp 0 0 10.0.0.5:22 10.0.0.9:5000 ESTABLISHED') == {5432}
    # a German Windows says ABHOEREN, not LISTENING: the foreign 0.0.0.0:0 tells it
    assert bv.parse_listening(WIN_OUT) == {3389}


# --- the run -------------------------------------------------------------------------------

def test_the_nics_are_down_before_the_test_guest_boots(clock, db):
    pve = _PVE()
    st = bv.run_verification(pve, _params())
    assert st['status'] == 'passed', st['logs']
    restore = pve.calls[pve.index('POST', '/nodes/pve1/qemu')][2]
    # new MAC addresses, no start with the restore
    assert restore['unique'] == 1 and restore['start'] == 0 and restore['archive'].endswith('02:00:00Z')
    assert 'storage' not in restore           # the backup's own storages
    isolate = pve.index('PUT', f'/qemu/{TEST_VMID}/config')
    start = pve.index('POST', '/status/start')
    assert isolate < start
    at_start = pve.config_at_start
    assert all('link_down=1' in at_start[k] for k in ('net0', 'net1'))
    assert at_start['onboot'] == '0' and 'pegaprox-verify' in at_start['tags']
    assert not {'hostpci0', 'usb0', 'serial1'} & set(at_start)
    assert at_start['scsi0'].endswith(',backup=0')
    assert st['isolated'] is True and st['isolation'] == 'link_down'


def test_a_refused_isolation_never_boots_and_removes_the_copy(clock, db):
    pve = _PVE(put_ok=False)
    st = bv.run_verification(pve, _params())
    assert st['status'] == 'error' and 'could not isolate' in st['error']
    assert not [c for c in pve.calls if c[1].endswith('/status/start')]
    assert ('DELETE', f'/nodes/pve1/qemu/{TEST_VMID}', {'purge': 1, 'destroy-unreferenced-disks': 1}) in pve.calls


def test_a_vmid_with_an_ha_resource_is_not_restored_to(clock, db):
    pve = _PVE(ha=[f'vm:{TEST_VMID}'])
    st = bv.run_verification(pve, _params())
    assert st['status'] == 'error' and 'HA resource' in st['error']
    assert not [c for c in pve.calls if c[0] == 'POST' and c[1] == '/nodes/pve1/qemu']


def test_a_caller_bridge_is_not_taken(clock, db):
    """network_bridge from the caller used to move the NICs to whatever it named."""
    pve = _PVE()
    st = bv.run_verification(pve, _params(network_bridge='vmbr0'))
    assert st['status'] == 'passed'
    assert all('link_down=1' in pve.config_at_start[k] for k in ('net0', 'net1'))


def test_the_cluster_test_bridge(clock, db):
    pve = _PVE()
    st = bv.run_verification(pve, _params(plan=_plan(isolation='bridge', test_bridge='vmbr99')))
    assert st['status'] == 'passed'
    assert pve.config_at_start['net0'] == 'virtio=BC:24:11:00:00:01,bridge=vmbr99,firewall=1'


def test_a_container_is_restored_as_one(clock, db, monkeypatch):
    from pegaprox.utils import ssh
    monkeypatch.setattr(ssh, '_pve_node_exec', lambda m, n, cmd, timeout=600, **k: (0, '', ''))
    pve = _PVE(kind='lxc')
    st = bv.run_verification(pve, _params('lxc', vm_type='qemu'))
    assert st['status'] == 'passed', st['logs']
    restore = pve.calls[pve.index('POST', '/nodes/pve1/lxc')][2]
    assert restore['ostemplate'].startswith('pbs:backup/ct/100/') and restore['restore'] == 1
    assert restore['unique'] == 1 and 'archive' not in restore
    assert 'link_down=1' in pve.config_at_start['net0'] and 'mp0' not in pve.config_at_start


# --- the checks ------------------------------------------------------------------------------

def test_agent_ports_and_command_through_the_guest_agent(clock, db):
    pve = _PVE()
    st = bv.run_verification(pve, _params(plan=_plan(ports=[22, 443], command='systemctl is-active nginx')))
    checks = {(c['check'], c['target']): c for c in st['checks']}
    assert checks[('agent', '')]['ok'] is True
    assert checks[('port', '22')]['ok'] is True
    assert checks[('port', '443')]['ok'] is False and checks[('port', '443')]['detail'] == 'nothing listens'
    assert checks[('command', 'systemctl is-active nginx')]['ok'] is True
    assert st['status'] == 'failed' and st['cause'] == 'port 443: nothing listens'
    assert ['sh', '-c', 'systemctl is-active nginx'] in pve.exec_cmds


def test_a_windows_guest_answers_through_netstat(clock, db):
    pve = _PVE(linux=False, listeners=WIN_OUT)
    st = bv.run_verification(pve, _params(plan=_plan(ports=[3389], command='sc query Spooler')))
    assert st['status'] == 'passed', st['checks']
    assert ['cmd.exe', '/c', 'netstat -an -p tcp'] in pve.exec_cmds
    assert ['cmd.exe', '/c', 'sc query Spooler'] in pve.exec_cmds


def test_a_command_that_fails_fails_the_test(clock, db):
    pve = _PVE(exit_code=3)
    st = bv.run_verification(pve, _params(plan=_plan(command='curl -sf http://127.0.0.1/health')))
    assert st['status'] == 'failed' and st['cause'] == 'check command: exit code 3'


def test_an_agent_that_never_answers(clock, db):
    pve = _PVE(agent=False)
    st = bv.run_verification(pve, _params(plan=_plan(ports=[22])))
    assert st['status'] == 'failed'
    kinds = {c['check']: c for c in st['checks']}
    assert kinds['agent']['ok'] is False and kinds['port']['ok'] is False
    # waited for it, then gave up: the clock moved by about AGENT_WAIT
    assert sum(1 for c in pve.calls if c[1].endswith('/agent/ping')) >= bv.AGENT_WAIT // 5


def test_auto_asks_the_agent_only_where_the_guest_has_one(clock, db):
    pve = _PVE(config=dict(QEMU_CONFIG, agent='0'), agent=False)
    st = bv.run_verification(pve, _params())
    assert st['status'] == 'passed' and st['checks'] == []
    pve = _PVE(config=dict(QEMU_CONFIG, agent='0'), agent=False)
    st = bv.run_verification(pve, _params(plan=_plan(agent='require')))
    assert st['status'] == 'failed'


def test_container_checks_go_through_pct_exec(clock, db, monkeypatch):
    from pegaprox.utils import ssh
    sent = []

    def node_exec(m, node, cmd, timeout=600, **k):
        sent.append((node, cmd))
        if 'ss -Hltn' in cmd:
            return 0, SS_OUT, ''
        if 'pg_isready' in cmd:
            return 1, '', ''
        return 0, '', ''
    monkeypatch.setattr(ssh, '_pve_node_exec', node_exec)
    pve = _PVE(kind='lxc')
    st = bv.run_verification(pve, _params('lxc', plan=_plan(ports=[22, 5432], command='pg_isready')))
    checks = {(c['check'], c['target']): c['ok'] for c in st['checks']}
    assert checks == {('booted', ''): True, ('port', '22'): True, ('port', '5432'): False, ('command', 'pg_isready'): False}
    assert sent[0] == ('pve1', f"pct exec {TEST_VMID} -- sh -c true")
    assert ('pve1', f"pct exec {TEST_VMID} -- sh -c pg_isready") in sent


def test_a_container_without_a_node_shell_is_booted_only(clock, db, monkeypatch):
    from pegaprox.utils import ssh
    monkeypatch.setattr(ssh, '_pve_node_exec', lambda m, n, cmd, timeout=600, **k: (
        1, '', "cannot run node commands on 'pve1': no SSH password is stored for this cluster"))
    pve = _PVE(kind='lxc')
    st = bv.run_verification(pve, _params('lxc', plan=_plan(ports=[22], command='true')))
    assert st['status'] == 'passed'
    skipped = [c for c in st['checks'] if c['ok'] is None]
    assert len(skipped) == 2 and 'no shell into the container' in skipped[0]['detail']


# --- RTO and the guest's mark ----------------------------------------------------------------

def test_restore_boot_and_checks_are_held_against_the_rto(clock, db):
    pve = _PVE(clock=clock, restore_takes=300)
    st = bv.run_verification(pve, _params(plan=_plan(rto_seconds=600)))
    assert st['status'] == 'passed' and 300 <= st['measured_seconds'] < 600 and st['rto_met'] is True
    pve = _PVE(clock=clock, restore_takes=900)
    st = bv.run_verification(pve, _params(plan=_plan(rto_seconds=600)))
    assert st['status'] == 'passed' and st['rto_met'] is False


def test_the_guest_mark_takes_each_result(clock, db):
    st = bv.run_verification(_PVE(), _params(plan=_plan(ports=[22])))
    mark = recovery.load_marks('c1')[100]
    assert mark['last_result'] == 'passed' and mark['ok_at'] and mark['last_task'] == st['id']
    assert mark['ok_backup_ts'] == recovery.backup_time('pbs:backup/vm/100/2026-10-01T02:00:00Z')
    assert [c['target'] for c in mark['ok_checks'] if c['check'] == 'port'] == ['22']
    bv.run_verification(_PVE(put_ok=False), _params())
    mark = recovery.load_marks('c1')[100]
    assert mark['last_result'] == 'error' and mark['ok_at'] and 'could not isolate' in mark['fail_cause']
    row = db.conn.execute('SELECT status, details FROM backup_verifications ORDER BY started_at').fetchall()
    assert [r['status'] for r in row] == ['passed', 'error']


def test_the_rules_of_the_guest_apply_without_a_plan(clock, db):
    recovery.save_rule('c1', 'cluster', '', {'isolation': 'bridge', 'test_bridge': 'vmbr99', 'rto_minutes': 30}, 'root')
    recovery.save_rule('c1', 'tag', 'prod', {'ports': [22]}, 'root')
    pve = _PVE()
    params = _params()
    params.pop('plan')
    st = bv.run_verification(pve, params)
    assert st['status'] == 'passed' and st['rto_seconds'] == 1800
    assert 'bridge=vmbr99' in pve.config_at_start['net0']
    assert [c['target'] for c in st['checks'] if c['check'] == 'port'] == ['22']


def test_a_task_is_followed_by_its_own_status_not_the_cluster_list(monkeypatch):
    """The wait looked for the restore's UPID among the last 50 tasks of the whole cluster;
    on a busy cluster it was never there, and the restore counted as failed at the timeout."""
    upid = 'UPID:pve3:0001:0002:00000003:qmrestore:105:root@pam:'

    class Busy:
        asked = []

        def _wait_for_task(self, node, task, timeout=600):
            self.asked.append((node, task))
            return True

        def get_tasks(self, limit=50):
            return [{'upid': f'UPID:pve9:{i}', 'status': 'OK'} for i in range(limit)]
    monkeypatch.setattr(bv, 'time', types.SimpleNamespace(time=time.time, sleep=lambda s: None, strftime=time.strftime))
    busy = Busy()
    assert bv._wait_task(busy, upid, timeout=30) is True
    assert busy.asked == [('pve3', upid)]


def test_the_started_thread_runs_the_same(db, monkeypatch):
    monkeypatch.setattr(bv, 'time', types.SimpleNamespace(time=time.time, sleep=lambda s: None, strftime=time.strftime))
    pve = _PVE()
    task_id = bv.start_verification(pve, _params())
    for t in threading.enumerate():
        if t.name == f'verify-{task_id}':
            t.join(10)
    assert bv.get_verification(task_id)['status'] == 'passed'
    assert 'link_down=1' in pve.config_at_start['net0']
