"""The optional in-guest Windows preparation (core/v2p_guestprep.py).

MK Nov 2026 - with a Windows login, PegaProx prepares the guest in ESXi before the copy as well.
It never fails a migration: whatever stops it before the guest is released (tools, login, UAC,
policy, any step) falls back to the offline preparation. After the release a failed run brings
the source back on ESXi with the tools installer mounted. The guest session, the node and ESXi
are fakes here.
"""
import json
import re
import shlex
import types

import pytest

import pegaprox.core.v2p as v2p
from pegaprox.core import v2p_guestprep as gp, v2p_winprep
from pegaprox.core.esxi_guestops import GuestOpsError

PW = 'Pa55-W0rd"&!'
WORK = 'C:\\ProgramData\\KVMMigration'
PROBE = {'ok': True, 'elevated': True, 'build': 20348, 'ubr': 2700, 'product': 'Windows Server 2022 Standard',
         'product_type': 3, 'arch': 'AMD64', 'ps_version': '5.1', 'free_mb': 9000, 'execution_policy': 'RemoteSigned',
         'execution_policy_blocked': False, 'tools_uninstall': True, 'pending_reboot': False,
         'adapters': [{'mac': '00:50:56:AA:BB:CC', 'static': True, 'ipv4': ['10.0.0.5/24']}]}
NETCONFIG = {'version': 1, 'source': 'guest', 'run': 't1', 'adapters': [
    {'mac': '00:50:56:AA:BB:CC', 'setting_id': '{11111111-2222-3333-4444-555555555555}', 'index': 12, 'dhcp': False,
     'instance': r'PCI\VEN_15AD&DEV_07B0&SUBSYS_07B015AD&REV_01\FF565000CCBBAAFE00',
     'ipv4': [{'ip': '10.0.0.5', 'prefix': 24}], 'gateway': [{'ip': '10.0.0.1', 'metric': 0}], 'dns': ['10.0.0.2']},
    {'mac': '00:50:56:AA:BB:DD', 'setting_id': '{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}', 'index': 13, 'dhcp': True,
     'ipv4': [], 'gateway': [], 'dns': []}]}
LISTING = ('DRIVER vioscsi 2k22/amd64\nFILE 1234 vioscsi/2k22/amd64/vioscsi.sys\nFILE 100 vioscsi/2k22/amd64/vioscsi.inf\n'
           'DRIVER NetKVM 2k22/amd64\nFILE 999 NetKVM/2k22/amd64/netkvm.sys\nFILE 5000000 virtio-win-guest-tools.exe\n'
           'FILE 3000 guest-agent/qemu-ga-x86_64.msi\nV2P_GP_LIST_END\n')


class Session:
    """GuestSession as the flow uses it, with the guest's answers"""
    instances = []

    def __init__(self, mgr, vm_id, user, password, guest=None):
        self.guest = guest
        self.user, self.password = user, password
        self.closed = False
        Session.instances.append(self)

    def _go(self, name, *a):
        self.guest.calls.append((name,) + a)
        f = self.guest.fail.get(name)
        if f:
            raise f

    def validate(self):
        self._go('validate')

    def env(self, *names):
        self._go('env')
        return {'PROGRAMDATA': 'C:\\ProgramData', 'SYSTEMROOT': 'C:\\Windows'}

    def temp_dir(self, prefix):
        self._go('temp_dir')
        return 'C:\\Users\\ADMINI~1\\AppData\\Local\\Temp\\pegaprox-1'

    def mkdir(self, path):
        self._go('mkdir', path)

    def put(self, path, data):
        self._go('put', path)
        if any(path.endswith(s) for s in self.guest.put_fails):
            raise GuestOpsError('other', 'the upload into the guest answered HTTP 500')
        self.guest.files[path] = data

    def upload_ticket(self, path, size):
        self._go('upload_ticket', path)
        self.guest.tickets += 1
        return f'https://esx1.lab/guestFile?id={self.guest.tickets}&token=tkt{self.guest.tickets}'

    def get(self, path, cap):
        self._go('get', path)
        name = path.rsplit('\\', 1)[-1]
        v = self.guest.reads.get(name)
        return v.encode() if isinstance(v, str) else v

    def start(self, program, args, cwd):
        self._go('start', program, args)
        return 100 + len(self.guest.calls)

    def wait_exit(self, pid, seconds, poll=3):
        last = [c for c in self.guest.calls if c[0] == 'start'][-1]
        return self.guest.probe_code if '-Mode Probe' in last[2] else self.guest.start_code

    def remove_dir(self, path):
        self._go('remove_dir', path)

    def close(self):
        self.closed = True
        self.password = None


class Guest:
    def __init__(self):
        self.calls, self.files, self.fail, self.put_fails, self.tickets = [], {}, {}, [], 0
        self.probe_code, self.start_code = 0, 0
        self.reads = {'probe.json': json.dumps(PROBE),
                      'status.json': json.dumps({'run': 't1', 'stage': 'ready', 'ok': True,
                                                 'steps': [{'name': 'drivers into the Driver Store', 'ok': True}]}),
                      'netconfig.json': json.dumps(NETCONFIG),
                      'migrate.log': '=== run t1 ===\nstep: drivers\n  ok: drivers: done\n'}

    def names(self):
        return [c[0] for c in self.calls]


class Esxi:
    host, port, ssl_verify = 'esx1.lab', 443, False

    def __init__(self, power='POWERED_ON', off_after_go=True):
        self.power, self.off_after_go = power, off_after_go
        self.actions = []
        self.state = {'power_state': 'POWERED_ON', 'tools_running': True, 'ops_ready': True,
                      'family': 'windowsGuest', 'full_name': 'Microsoft Windows Server 2022', 'soap': True}

    def guest_state(self, vm_id):
        return {'data': dict(self.state)}

    def get_vm(self, vm_id):
        return {'data': {'power_state': self.power}}

    def vm_power_action(self, vm_id, action):
        self.actions.append(action)
        self.power = 'POWERED_ON' if action == 'start' else 'POWERED_OFF'
        return {'data': {}}

    def mount_tools_installer(self, vm_id):
        self.actions.append('mount_tools')
        return {'data': 'ok'}

    def unmount_tools_installer(self, vm_id):
        self.actions.append('unmount_tools')
        return {'data': 'ok'}


class Clock:
    def __init__(self):
        self.t = 0.0

    def sleep(self, s):
        self.t += max(s, 0.01)

    def monotonic(self):
        return self.t


@pytest.fixture
def lab(monkeypatch):
    import time
    guest, esxi = Guest(), Esxi()
    clock = Clock()
    monkeypatch.setattr(time, 'sleep', clock.sleep)
    monkeypatch.setattr(time, 'monotonic', clock.monotonic)
    Session.instances = []
    monkeypatch.setattr(gp, 'GuestSession', lambda *a: Session(*a, guest=guest))
    monkeypatch.setattr(gp, 'pinned_key', lambda host, port, verify: 'sha256//PINPINPIN=')
    node = types.SimpleNamespace(cmds=[], stdin={}, conf={'net0': 'virtio=BC:24:11:00:00:01,bridge=vmbr0'})

    def node_exec(mgr, n, cmd, timeout=60, **kw):
        node.cmds.append(cmd)
        if kw.get('stdin_data') is not None:
            path = re.search(r'cat > (\S+)', cmd).group(1)
            node.stdin[shlex.split(path)[0]] = kw['stdin_data']
            return 0, '', ''
        if cmd.startswith('qm config'):
            return 0, ''.join(f'{k}: {v}\n' for k, v in node.conf.items()), ''
        if ' list ' in cmd:
            return 0, LISTING, ''
        if ' put ' in cmd:
            cfg = node.stdin[shlex.split(cmd)[3]]
            return 0, ''.join('V2P_PUT 200\n' for _ in re.findall(r'^url = ', cfg, re.M)) + 'V2P_CURL_RC=0\n', ''
        return 0, '', ''
    monkeypatch.setattr(v2p, '_pve_node_exec', node_exec)
    monkeypatch.setattr(v2p, '_write_node_script', lambda *a, **k: '/tmp/v2p-guestprep-0000000001')
    monkeypatch.setattr(v2p, '_ensure_node_packages', lambda *a, **k: (True, []))
    monkeypatch.setattr(v2p, '_node_cannot_reach', lambda *a, **k: '')
    cfg = {'esxi_password': 'pw', 'transfer_mode': 'vmkfstools_clone', 'guest_prep': True,
           'guest_user': 'Administrator', 'guest_password': PW, 'preserve_mac': False}
    task = v2p.V2PMigrationTask('t1', 'vw1', 'vm-42', 'pve-cl', 'pve1', 'local-lvm', vm_name='app01', config=cfg)
    task.proxmox_vmid = 120
    task._winprep = {'windows': True, 'on': True, 'state': 'planned', 'iso': '/var/lib/vz/template/iso/virtio-win.iso'}
    task._source_nics = [{'mac_address': '00:50:56:aa:bb:cc'}]
    task.install_virtio_drivers = True
    return types.SimpleNamespace(guest=guest, esxi=esxi, node=node, task=task, pve=object())


# --------------------------------------------------------------------------- the table of driver folders

@pytest.mark.parametrize('build,ptype,primary', [
    (26100, 1, 'w11/amd64'), (26100, 3, '2k25/amd64'), (20348, 3, '2k22/amd64'), (17763, 1, 'w10/amd64'),
    (17763, 2, '2k19/amd64'), (14393, 3, '2k16/amd64'), (14393, 1, 'w10/amd64'), (9600, 1, 'w8.1/amd64'),
    (9600, 3, '2k12R2/amd64'), (9200, 3, '2k12/amd64'), (22631, 1, 'w11/amd64'), (19045, 1, 'w10/amd64'),
])
def test_a_client_and_a_server_of_one_build_take_their_own_driver_folder(build, ptype, primary):
    assert gp.driver_folders(build, ptype)[0] == primary


# --------------------------------------------------------------------------- probe

def test_the_probe_checks_the_guest_with_one_login_and_the_script_from_a_private_folder(lab):
    assert gp.probe(lab.esxi, lab.pve, lab.task) is True
    st = lab.task._guest_prep
    assert st['state'] == 'checked' and st['build'] == 20348 and st['work'] == WORK
    assert lab.guest.names().count('validate') == 1
    tmp = 'C:\\Users\\ADMINI~1\\AppData\\Local\\Temp\\pegaprox-1'
    assert lab.guest.files[tmp + '\\Prepare-KvmMigration.ps1'] == gp.script_bytes()
    start = [c for c in lab.guest.calls if c[0] == 'start'][0]
    assert start[1] == 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'
    assert start[2] == (f'-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{tmp}\\Prepare-KvmMigration.ps1" '
                        f'-Mode Probe -WorkDir "{WORK}"')
    assert ('remove_dir', tmp) in lab.guest.calls and all(s.closed for s in Session.instances)
    assert lab.task.warnings == []


@pytest.mark.parametrize('change,word', [
    ({'probe_code': 10}, 'elevated'),
    ({'probe': {'build': 7601}}, '9200'),
    ({'probe': {'arch': 'ARM64'}}, 'ARM64'),
    ({'probe': {'free_mb': 100}}, 'MB free'),
    ({'probe': {'execution_policy_blocked': True}}, 'AllSigned'),
    ({'state': {'tools_running': False}}, 'not running'),
    ({'state': {'soap': False}}, 'SOAP'),
    ({'state': {'power_state': 'POWERED_OFF'}}, 'not running'),
    ({'login': True}, 'refused the Windows login'),
    ({'probe_code': 1, 'no_probe': True}, 'execution policy'),
])
def test_a_guest_that_cannot_be_prepared_falls_back_to_the_offline_preparation(lab, change, word):
    if 'probe_code' in change:
        lab.guest.probe_code = change['probe_code']
    if 'probe' in change:
        lab.guest.reads['probe.json'] = json.dumps(dict(PROBE, **change['probe']))
    if change.get('no_probe'):
        lab.guest.reads.pop('probe.json')
    if 'state' in change:
        lab.esxi.state.update(change['state'])
    if change.get('login'):
        lab.guest.fail['validate'] = GuestOpsError('login', 'the guest refused the Windows login')
    task = lab.task
    task.install_virtio_drivers = False
    assert gp.probe(lab.esxi, lab.pve, task) is False
    assert task._guest_prep['state'] == 'fallback' and task.guest_prep is False
    assert task._guest_password == '' and task.guest_user == ''
    assert task.install_virtio_drivers is True, 'the offline preparation takes over'
    assert any(word in w and 'prepared on Proxmox VE after the copy instead' in w for w in task.warnings), task.warnings
    assert lab.guest.names().count('validate') <= 1
    assert not [c for c in lab.guest.calls if c[0] == 'put' and 'go.flag' in c[1]]


# --------------------------------------------------------------------------- stage 1

def _checked(lab):
    assert gp.probe(lab.esxi, lab.pve, lab.task) is True
    return lab.task._guest_prep


def test_stage_one_uploads_from_the_node_with_the_urls_on_stdin_and_a_pinned_key(lab):
    _checked(lab)
    assert gp.prepare(lab.esxi, lab.pve, lab.task) is True
    put = [c for c in lab.node.cmds if ' put ' in c][0]
    assert 'guestFile' not in put and 'tkt' not in put
    cfg = list(lab.node.stdin.values())[0]
    assert cfg.count('url = "https://esx1.lab/guestFile?id=') == 5 and 'upload-file = "vioscsi/2k22/amd64/vioscsi.sys"' in cfg
    script = gp._node_script('/var/lib/vz/template/iso/virtio-win.iso')
    assert '-k --pinnedpubkey "$3"' in script and shlex.split(put)[-2] == 'sha256//PINPINPIN='
    assert '--insecure' not in script and script.count(' -k ') == 1
    # the secret file is gone right after its curl run
    assert any(c.startswith('rm -f ') and '/run/pegaprox-v2p-t1-guestprep-urls' in c for c in lab.node.cmds)
    assert lab.task._guest_prep['state'] == 'prepared'


def test_stage_one_puts_firstboot_and_its_data_and_no_login_into_the_guest(lab):
    _checked(lab)
    gp.prepare(lab.esxi, lab.pve, lab.task)
    files = lab.guest.files
    assert files[WORK + '\\firstboot.cmd'] == v2p_winprep.firstboot_bytes()
    cfg = json.loads(files[WORK + '\\pegaprox.json'])
    assert cfg['run'] == 't1' and 'Administrator' not in json.dumps(cfg) and PW not in json.dumps(cfg)
    data = files[WORK + '\\firstboot-data.cmd'].decode()
    assert 'set "KM_NIC1_SRCMAC=005056aabbcc"' in data and 'set "KM_NIC1_MAC=bc2411000001"' in data
    assert 'set "KM_NICS=1"' in data and 'set "KM_TOOLS_UNINSTALL=0"' in data
    start = [c for c in lab.guest.calls if c[0] == 'start'][-1]
    assert '-Mode Start' in start[2] and f'-File "{WORK}\\Prepare-KvmMigration.ps1"' in start[2]
    for s in Session.instances:
        assert s.closed


def test_a_failed_stage_one_calls_the_guest_off_and_falls_back(lab):
    _checked(lab)
    lab.guest.reads['status.json'] = json.dumps({'run': 't1', 'stage': 'failed', 'error': 'pnputil exit code 5'})
    assert gp.prepare(lab.esxi, lab.pve, lab.task) is False
    assert WORK + '\\abort.flag' in lab.guest.files
    assert lab.task._guest_prep['state'] == 'fallback'
    assert any('pnputil exit code 5' in w and 'stage 1 in the guest' in w for w in lab.task.warnings)
    assert gp.go(lab.esxi, lab.pve, lab.task) == 'skipped' and lab.esxi.actions == []


# --------------------------------------------------------------------------- the switchover

class Waits:
    def __init__(self, esxi, answers):
        self.esxi, self.answers, self.calls = esxi, list(answers), []

    def __call__(self, mgr, vm_id, want, timeout, poll=2):
        self.calls.append((want, timeout))
        ok = self.answers.pop(0) if self.answers else True
        if ok:
            self.esxi.power = want
        return ok


def _prepared(lab):
    _checked(lab)
    assert gp.prepare(lab.esxi, lab.pve, lab.task) is True


def test_go_lets_the_guest_shut_itself_down_and_forgets_the_login(lab, monkeypatch):
    _prepared(lab)
    waits = Waits(lab.esxi, [True])
    monkeypatch.setattr(v2p, '_wait_power_state', waits)
    assert gp.go(lab.esxi, lab.pve, lab.task) == 'off'
    assert WORK + '\\go.flag' in lab.guest.files and lab.esxi.actions == []
    assert waits.calls == [('POWERED_OFF', gp.OFF_SECONDS)]
    assert lab.task._guest_password == '' and lab.task.guest_user == ''
    assert lab.task._guest_prep['state'] == 'shut_down'


def test_a_guest_that_does_not_shut_down_is_powered_off_with_a_warning(lab, monkeypatch):
    _prepared(lab)
    monkeypatch.setattr(v2p, '_wait_power_state', Waits(lab.esxi, [False, True]))
    assert gp.go(lab.esxi, lab.pve, lab.task) == 'forced'
    assert lab.esxi.actions == ['stop'] and any('powered off' in w for w in lab.task.warnings)


def test_a_go_that_does_not_reach_the_guest_falls_back_to_the_normal_stop(lab, monkeypatch):
    _prepared(lab)
    lab.guest.put_fails.append('go.flag')
    assert gp.go(lab.esxi, lab.pve, lab.task) == 'skipped'
    assert WORK + '\\abort.flag' in lab.guest.files and lab.task._guest_prep['state'] == 'fallback'
    assert v2p._source_off_for_cutover(lab.esxi, lab.pve, lab.task) is False


def test_the_cutover_helper_says_whether_the_prepared_guest_is_off(lab, monkeypatch):
    _prepared(lab)
    monkeypatch.setattr(v2p, '_wait_power_state', Waits(lab.esxi, [True]))
    assert v2p._source_off_for_cutover(lab.esxi, lab.pve, lab.task) is True
    off = v2p.V2PMigrationTask('t2', 'vw1', 'vm-1', 'c', 'n', 's', config={'esxi_password': 'x'})
    assert v2p._source_off_for_cutover(lab.esxi, lab.pve, off) is False


def test_a_waiting_guest_is_called_off_when_the_run_is_cancelled(lab):
    _prepared(lab)
    gp.abort_if_pending(lab.esxi, lab.task)
    assert WORK + '\\abort.flag' in lab.guest.files and lab.task._guest_prep['state'] == 'aborted'


# --------------------------------------------------------------------------- the way back

class _Pve:
    host, api_port = 'pve1.lab', 8006

    def __init__(self, running):
        self.running = running

    def _api_get(self, url, **kw):
        return types.SimpleNamespace(status_code=200, json=lambda: {'data': {'status': 'running' if self.running else 'stopped'}})


def _released(lab, monkeypatch):
    _prepared(lab)
    monkeypatch.setattr(v2p, '_wait_power_state', Waits(lab.esxi, [True, True, True]))
    assert gp.go(lab.esxi, lab.pve, lab.task) == 'off'
    lab.esxi.actions.clear()


def test_a_run_that_failed_after_the_release_brings_the_source_back_with_its_tools_installer(lab, monkeypatch):
    _released(lab, monkeypatch)
    started = []
    monkeypatch.setattr(gp, '_unmount_when_back', lambda *a, **k: started.append(a))
    import threading
    monkeypatch.setattr(threading, 'Thread', lambda target, args, daemon: types.SimpleNamespace(
        start=lambda: target(*args)))
    gp.roll_back(lab.esxi, _Pve(running=False), lab.task)
    assert lab.esxi.actions == ['start', 'mount_tools'] and started
    assert lab.task._guest_prep['state'] == 'rolled_back'
    gp.roll_back(lab.esxi, _Pve(running=False), lab.task)
    assert lab.esxi.actions == ['start', 'mount_tools'], 'only once'


def test_the_installer_is_unmounted_once_the_tools_run_again(lab, monkeypatch):
    lab.esxi.state['tools_running'] = True
    assert gp._unmount_when_back(lab.esxi, lab.task, wait=60, poll=1) is True
    assert lab.esxi.actions == ['unmount_tools']


def test_the_source_stays_off_when_the_target_may_run(lab, monkeypatch):
    _released(lab, monkeypatch)
    gp.roll_back(lab.esxi, _Pve(running=True), lab.task)
    assert lab.esxi.actions == [] and any('stays off' in line for line in lab.task.log_lines)


def test_nothing_is_rolled_back_when_the_guest_was_never_released(lab, monkeypatch):
    _prepared(lab)
    gp.roll_back(lab.esxi, _Pve(running=False), lab.task)
    assert lab.esxi.actions == []


def test_the_run_rolls_back_wherever_it_failed(lab, monkeypatch):
    src = open(v2p.__file__, encoding='utf-8').read()
    fn = src.split('def _run_v2p_migration(task):', 1)[1].split('\ndef ', 1)[0]
    fin = fn[fn.rindex('    finally:'):]
    assert "if task.status in ('failed', 'cancelled'):" in fin and '_guest_prep_rollback(task)' in fin


def test_an_unexpected_error_falls_back_too_and_never_fails_the_run(lab, monkeypatch):
    lab.guest.fail['env'] = RuntimeError('pyVmomi said something odd')
    assert gp.probe(lab.esxi, lab.pve, lab.task) is False
    assert lab.task._guest_prep['state'] == 'fallback'
    assert any('RuntimeError' in w for w in lab.task.warnings)
    lab.guest.fail.pop('env')
    lab.task._guest_prep.update(on=True, state='planned')
    lab.task.guest_prep = True
    assert gp.probe(lab.esxi, lab.pve, lab.task) is True
    monkeypatch.setattr(gp, '_parse_listing', lambda *a: (_ for _ in ()).throw(KeyError('x')))
    assert gp.prepare(lab.esxi, lab.pve, lab.task) is False
    assert WORK + '\\abort.flag' in lab.guest.files and lab.task._guest_prep['state'] == 'fallback'
