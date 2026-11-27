"""The two-stage boot of a migrated Windows guest (core/v2p_twostage.py).

MK Nov 2026 - Windows 8 and later do not bind vioscsi at an early boot from offline registry
changes alone (Server 2025 stopped with INACCESSIBLE_BOOT_DEVICE in May). The guest boots once
with the boot disk on SATA and a VirtIO SCSI device present, PegaProx checks through the guest
agent that vioscsi is bound and starts at boot, and moves the boot disk to scsi0. It is on by
default for every Windows guest with drivers, runs with start_after off too, and every failure
ends on SATA with a warning, never a failed migration.

Qm is qm on the node for one VM (set, delete, config, disk unlink, the sed that drops a stale
unusedN line), Pve the Proxmox API with the guest agent. Both are used by the end-to-end runs of
test_v2p_windows_auto.py as well.
"""
import re
import shlex
import time
import types

import pytest

import pegaprox.core.v2p as v2p
from pegaprox.core import v2p_twostage as ts

VMID = 120
BOOT_VOL = 'local-lvm:vm-120-disk-1'
DATA_VOL = 'local-lvm:vm-120-disk-2'
_DRIVE = re.compile(r'^(scsi|sata|ide|virtio)\d+$')


class Qm:
    """qm for one VM on the node, keeping its config as PVE does: a deleted disk becomes
    unusedN (and stays when the volume is attached again), a new 'storage:1' is allocated"""

    def __init__(self, conf=None, fail=()):
        self.conf = dict(conf or {})
        self.cmds = []
        self.fail = list(fail)
        self._n = 50

    def handle(self, cmd):
        c = cmd.replace(' 2>&1', '').strip()
        m = re.fullmatch(r"sed -i '/\^(unused\d+): /d' /etc/pve/qemu-server/(\d+)\.conf", c)
        if m:
            self.cmds.append(c)
            self.conf.pop(m.group(1), None)
            return 0, ''
        if not c.startswith('qm '):
            return None
        self.cmds.append(c)
        for f in self.fail:
            if f in c:
                return 255, f'qm said no: {f}'
        args = shlex.split(c)[1:]
        if args[0] == 'config':
            return 0, ''.join(f'{k}: {v}\n' for k, v in self.conf.items())
        if args[:2] == ['disk', 'unlink']:
            for k in args[args.index('--idlist') + 1].split(','):
                self.conf.pop(k, None)
            return 0, ''
        if args[0] == 'set':
            it = iter(args[2:])
            for opt in it:
                key, val = opt[2:], next(it)
                if key == 'delete':
                    for k in val.split(','):
                        v = self.conf.pop(k, None)
                        if v and _DRIVE.match(k) and 'media=cdrom' not in v:
                            n = 0
                            while f'unused{n}' in self.conf:
                                n += 1
                            self.conf[f'unused{n}'] = v.split(',')[0]
                elif _DRIVE.match(key) and re.fullmatch(r'[\w.-]+:\d+', val):
                    self._n += 1
                    self.conf[key] = f"{val.split(':')[0]}:vm-{VMID}-disk-{self._n},size=1G"
                else:
                    self.conf[key] = val
            return 0, ''
        return 0, ''

    def disks(self):
        return {k: v.split(',')[0] for k, v in self.conf.items() if _DRIVE.match(k) and 'media=cdrom' not in v}


class Resp:
    def __init__(self, data, status=200, text=''):
        self.status_code, self._data, self.text = status, data, text

    def json(self):
        return {'data': self._data}


class Pve:
    """The Proxmox API of the target with the guest agent: which boots it answers in, what
    reg.exe says about the storage driver, the files it hands out"""
    host = 'pve1.lab'
    api_port = 8006

    def __init__(self, qm, agent_boots=(1, 2, 3), bound=1, start=0, start_fails=(), files=None, log=None):
        self.qm = qm
        self.agent_boots = set(agent_boots)
        self.bound, self.start = bound, start
        self.start_fails = set(start_fails)
        self.files = dict(files or {})
        self.log = log if log is not None else []
        self.running = False
        self.boots = []        # the boot order at each start
        self.execs = []
        self.shutdowns = 0
        self.stops = 0
        self.nodes = {'pve1': {}}
        self.is_connected = True

    def _api_post(self, url, data=None, **kw):
        self.log.append(('pve_api', url.split('/api2/json', 1)[-1], sorted((data or {}).items())
                         if isinstance(data, dict) else data))
        if url.endswith('/status/start'):
            if len(self.boots) + 1 in self.start_fails:
                self.boots.append(None)
                return Resp(None, 500, 'start refused')
            self.running = True
            self.boots.append(self.qm.conf.get('boot'))
            return Resp(f'UPID:pve1:1:2:qmstart:{VMID}:root@pam:')
        if url.endswith('/status/shutdown'):
            self.shutdowns += 1
            self.running = False
            return Resp('UPID:pve1:1:2:qmshutdown')
        if url.endswith('/status/stop'):
            self.stops += 1
            self.running = False
            return Resp('UPID:pve1:1:2:qmstop')
        if url.endswith('/agent/ping'):
            ok = self.running and len(self.boots) in self.agent_boots
            return Resp({}) if ok else Resp(None, 500, 'QEMU guest agent is not running')
        if url.endswith('/agent/exec'):
            self.execs.append(list(data['command']))
            argv = self.execs[-1]
            if argv[:2] == ['sc.exe', 'config']:
                self.start = 0
            return Resp({'pid': len(self.execs)})
        return Resp('UPID:pve1:1:2:create')

    def _api_get(self, url, params=None, **kw):
        if url.endswith('/cluster/nextid'):
            return Resp(VMID)
        if '/tasks/' in url:
            return Resp({'status': 'stopped', 'exitstatus': 'OK'})
        if url.endswith('/status/current'):
            return Resp({'status': 'running' if self.running else 'stopped'})
        if url.endswith('/agent/exec-status'):
            argv = self.execs[int(params['pid']) - 1]
            return Resp({'exited': 1, 'exitcode': 0, 'out-data': self._out(argv)})
        if url.endswith('/agent/file-read'):
            c = self.files.get(params['file'])
            return Resp({'content': c}) if c is not None else Resp(None, 500, 'no such file')
        return Resp({})

    def _out(self, argv):
        if argv[:2] == ['reg.exe', 'query'] and argv[-1] == 'Start':
            return f'\r\nHKEY_LOCAL_MACHINE\\{argv[2][5:]}\r\n    Start    REG_DWORD    0x{self.start:x}\r\n'
        if argv[:2] == ['reg.exe', 'query'] and argv[-1] == 'Count':
            return f'\r\nHKEY_LOCAL_MACHINE\\{argv[2][5:]}\r\n    Count    REG_DWORD    0x{self.bound:x}\r\n'
        if argv[:2] == ['cmd.exe', '/c']:
            return 'C:\r\n'
        return ''


class Clock:
    def __init__(self):
        self.t = 1000.0

    def sleep(self, s):
        self.t += max(float(s), 0.01)

    def monotonic(self):
        return self.t


def _task(two_stage=True, start_after=True, disks=1, source_scsihw='pvscsi', bus_switched=False, **staged):
    cfg = {'esxi_password': 'pw', 'transfer_mode': 'offline', 'start_after': start_after}
    t = v2p.V2PMigrationTask('t1', 'vw1', 'vm-42', 'pve-cl', 'pve1', 'local-lvm', vm_name='app01', config=cfg)
    t.proxmox_vmid = VMID
    t._attach_bus, t._attach_scsihw = 'scsi', 'virtio-scsi-single'
    t._scsihw_switched = source_scsihw not in ts.VIRTIO_SCSI
    t._source_scsihw = source_scsihw
    t._source_bus = 'sata' if bus_switched else 'scsi'
    t._bus_switched = bus_switched
    t._two_stage = dict(ts.decide({}, windows=True, transfer_mode='offline', drivers=two_stage),
                        state='planned', boot_disk=None)
    t._virtio_staged = dict({'drivers': True, 'driver_msi': True, 'agent_msi': True, 'first_boot': True}, **staged)
    t._winprep = {'windows': True, 'on': True, 'state': 'staged', 'summary': {'build': 20348}}
    return t


def _conf(disks=1):
    c = {'scsihw': 'virtio-scsi-single', 'boot': 'order=scsi0;net0', 'net0': 'virtio=BC:24:11:00:00:01,bridge=vmbr0',
         'scsi0': f'{BOOT_VOL},iothread=1,discard=on', 'ide2': 'none,media=cdrom', 'agent': 'enabled=1'}
    if disks > 1:
        c['scsi1'] = f'{DATA_VOL},iothread=1,discard=on'
    return c


@pytest.fixture
def lab(monkeypatch):
    clock = Clock()
    monkeypatch.setattr(time, 'sleep', clock.sleep)
    monkeypatch.setattr(time, 'monotonic', clock.monotonic)

    def make(disks=1, fail=(), **pve_kw):
        qm = Qm(_conf(disks), fail=fail)
        pve = Pve(qm, **pve_kw)
        node_cmds = []

        def node(mgr, n, cmd, timeout=60, **kw):
            node_cmds.append(cmd)
            got = qm.handle(cmd)
            return (got[0], got[1], '') if got is not None else (0, '', '')
        monkeypatch.setattr(v2p, '_pve_node_exec', node)
        rebuilt = []
        monkeypatch.setattr(v2p, '_rebuild_sector_args', lambda *a: rebuilt.append(a) or (True, '', None))
        return types.SimpleNamespace(qm=qm, pve=pve, node_cmds=node_cmds, rebuilt=rebuilt)
    return make


# --------------------------------------------------------------------------- the rule

@pytest.mark.parametrize('cfg,kw,on,why', [
    ({}, {}, True, 'a Windows guest'),
    ({'two_stage_boot': True}, {}, True, 'turned on'),
    ({'two_stage_boot': False}, {}, False, 'turned off'),
    ({}, {'windows': False}, False, 'not a Windows guest'),
    ({}, {'transfer_mode': 'sshfs_boot'}, False, 'live mirror'),
    ({}, {'disk_bus_req': 'sata'}, False, 'SATA'),
    ({}, {'scsihw_req': 'pvscsi'}, False, 'pvscsi'),
    ({}, {'scsihw_req': 'virtio-scsi-pci'}, True, 'a Windows guest'),
    ({}, {'agent': False}, False, 'guest agent'),
    ({}, {'drivers': False}, False, 'drivers'),
])
def test_it_is_on_for_every_windows_guest_with_drivers_unless_something_rules_it_out(cfg, kw, on, why):
    args = dict(windows=True, transfer_mode='offline', disk_bus_req='', scsihw_req='', agent=True, drivers=True)
    args.update(kw)
    d = ts.decide(cfg, **args)
    assert d['on'] is on and why in d['why']
    assert d['final_bus'] == 'scsi'
    assert ts.decide({}, **dict(args, disk_bus_req='virtio'))['final_bus'] == 'virtio'


@pytest.mark.parametrize('body,word', [
    ({'two_stage_boot': True, 'transfer_mode': 'sshfs_boot'}, 'Live Mirror'),
    ({'two_stage_boot': True, 'disk_bus': 'ide'}, 'IDE'),
    ({'two_stage_boot': True, 'scsihw': 'lsi'}, 'lsi'),
    ({'two_stage_boot': True, 'agent': False}, 'agent'),
    ({'two_stage_boot': True, 'install_virtio_drivers': False}, 'drivers'),
])
def test_an_explicit_true_that_cannot_run_is_refused_with_the_reason(body, word):
    assert word in ts.refusal(body)


def test_absent_or_false_or_a_runnable_true_is_no_refusal():
    for body in ({}, {'two_stage_boot': None}, {'two_stage_boot': False, 'transfer_mode': 'sshfs_boot'},
                 {'two_stage_boot': True, 'install_virtio_drivers': False, 'guest_prep': True}):
        assert ts.refusal(body) is None


def test_ide_is_only_for_windows_before_8():
    assert ts.first_bus(20348) == 'sata' and ts.first_bus(7601) == 'ide' and ts.first_bus(None, 'win7') == 'ide'
    assert ts.first_bus(None, 'win11') == 'sata'


# --------------------------------------------------------------------------- stage

def test_stage_puts_the_boot_disk_on_sata_without_iothread_and_adds_the_temp_disk(lab):
    lb = lab(disks=1)
    t = _task()
    t.disk_iothread = True
    assert ts.stage(lb.pve, t) is True
    d = lb.qm.disks()
    assert d['sata0'] == BOOT_VOL and 'scsi0' not in d
    assert 'iothread' not in lb.qm.conf['sata0'] and lb.qm.conf['boot'] == 'order=sata0'
    assert 'scsi30' in d and t._two_stage['temp'] == 'scsi30'
    assert not [k for k in lb.qm.conf if k.startswith('unused')], 'the stale unusedN line stayed'
    assert t._two_stage['state'] == 'first_boot_staged' and t._two_stage['boot_disk'] == 'sata0'
    assert lb.rebuilt == []


def test_stage_needs_no_temp_disk_when_a_data_disk_stays_on_virtio_scsi(lab):
    lb = lab(disks=2)
    t = _task()
    t._sector_args = True
    assert ts.stage(lb.pve, t) is True
    assert lb.qm.disks() == {'sata0': BOOT_VOL, 'scsi1': DATA_VOL}
    assert t._two_stage['temp'] is None and len(lb.rebuilt) == 1


@pytest.mark.parametrize('staged,why', [
    ({'drivers': False}, 'were not injected'),
    ({'driver_msi': False}, 'driver package'),
    ({'first_boot': False}, 'first boot'),
    ({'agent_msi': False}, 'guest agent package'),
])
def test_without_the_drivers_the_guest_keeps_the_controller_of_the_source(lab, staged, why):
    lb = lab()
    t = _task(**staged)
    assert ts.stage(lb.pve, t) is False
    assert lb.qm.conf['scsihw'] == 'pvscsi' and lb.qm.disks() == {'scsi0': BOOT_VOL}
    assert t._two_stage['state'] == 'dropped' and why in t._two_stage['why']
    assert any('Two-stage boot left out' in w and 'pvscsi' in w for w in t.warnings)


def test_a_source_on_sata_gets_its_bus_back_when_the_drivers_did_not_come(lab):
    lb = lab(disks=2)
    t = _task(bus_switched=True, drivers=False)
    assert ts.stage(lb.pve, t) is False
    assert lb.qm.disks() == {'sata0': BOOT_VOL, 'sata1': DATA_VOL} and lb.qm.conf['boot'] == 'order=sata0'
    assert not [k for k in lb.qm.conf if k.startswith('unused')]


def test_a_move_qm_refuses_puts_the_disk_back_and_keeps_the_source_controller(lab):
    lb = lab(fail=['--sata0'])
    t = _task()
    assert ts.stage(lb.pve, t) is False
    assert lb.qm.disks()['scsi0'] == BOOT_VOL and lb.qm.conf['scsihw'] == 'pvscsi'
    assert not [k for k in lb.qm.conf if k.startswith('unused')]


# --------------------------------------------------------------------------- boot

FB = '{"version":1,"run":"t1","platform":"kvm","state":"applied","boots":1,"tools":"removed","devices":"removed",' \
     '"adapters":[{"n":1,"ip":"10.0.0.5","index":"12","by":"mac","applied":true}]}'
FILES = {r'C:\ProgramData\KVMMigration\firstboot.json': FB,
         r'C:\ProgramData\KVMMigration\migrate.log': 'x === first boot on Proxmox VE, run t1, boot 1 ===\r\nx step drivers: ok\r\n'}


def _staged(lb, **kw):
    t = _task(**kw)
    assert ts.stage(lb.pve, t) is True
    return t


def test_boot_checks_the_driver_switches_to_scsi_and_boots_again(lab):
    lb = lab(files=FILES)
    t = _staged(lb)
    assert ts.boot(lb.pve, t) == ('running', '')
    assert lb.pve.boots == ['order=sata0', 'order=scsi0']
    d = lb.qm.disks()
    assert d == {'scsi0': BOOT_VOL} and 'iothread=1' in lb.qm.conf['scsi0']
    assert any(c == f'qm disk unlink {VMID} --idlist scsi30 --force' for c in lb.qm.cmds)
    assert lb.pve.shutdowns == 1 and lb.pve.stops == 0
    regs = [e for e in lb.pve.execs if e[0] == 'reg.exe']
    assert ['reg.exe', 'query', r'HKLM\SYSTEM\CurrentControlSet\Services\vioscsi', '/v', 'Start'] in regs
    assert ['reg.exe', 'query', r'HKLM\SYSTEM\CurrentControlSet\Services\vioscsi\Enum', '/v', 'Count'] in regs
    assert t._two_stage['state'] == 'switched' and t._two_stage['boot_disk'] == 'scsi0' and t.warnings == []
    log = '\n'.join(t.log_lines)
    assert 'static IPv4 10.0.0.5 is on interface 12 (matched by mac)' in log and 'step drivers: ok' in log


def test_a_bound_driver_that_starts_on_demand_is_set_to_boot_start(lab):
    lb = lab(files=FILES, start=3)
    t = _staged(lb)
    assert ts.boot(lb.pve, t) == ('running', '')
    assert ['sc.exe', 'config', 'vioscsi', 'start=', 'boot'] in lb.pve.execs
    assert t._two_stage['state'] == 'switched'


def test_no_agent_in_the_first_boot_keeps_sata_and_still_starts_the_guest(lab):
    lb = lab(disks=2, agent_boots=())
    t = _staged(lb)
    assert ts.boot(lb.pve, t) == ('running', '')
    assert lb.qm.disks() == {'sata0': BOOT_VOL, 'sata1': DATA_VOL}, 'the data disk stayed on a driver nobody saw'
    assert lb.qm.conf['boot'] == 'order=sata0' and lb.pve.boots == ['order=sata0', 'order=sata0']
    assert t._two_stage['state'] == 'kept_sata' and t.status == 'running'
    assert any('did not answer' in w and 'INACCESSIBLE_BOOT_DEVICE' in w for w in t.warnings)


def test_a_driver_that_never_binds_keeps_sata_with_a_clean_shutdown(lab):
    lb = lab(files=FILES, bound=0)
    t = _staged(lb)
    assert ts.boot(lb.pve, t) == ('running', '')
    assert lb.qm.disks() == {'sata0': BOOT_VOL} and lb.pve.shutdowns == 1
    assert any('vioscsi is not bound to any device' in w for w in t.warnings)


def test_a_second_boot_that_does_not_come_up_goes_back_to_sata(lab):
    lb = lab(files=FILES, agent_boots=(1,))
    t = _staged(lb)
    assert ts.boot(lb.pve, t) == ('running', '')
    assert lb.pve.boots == ['order=sata0', 'order=scsi0', 'order=sata0']
    assert lb.qm.disks() == {'sata0': BOOT_VOL} and lb.pve.stops == 1
    assert t._two_stage['state'] == 'kept_sata'
    assert any('second boot on VirtIO SCSI did not come up' in w and 'back on sata0' in w for w in t.warnings)


def test_with_start_after_off_it_still_switches_and_ends_with_the_vm_stopped(lab):
    lb = lab(files=FILES)
    t = _staged(lb, start_after=False)
    assert ts.boot(lb.pve, t) == ('stopped', '')
    assert lb.pve.boots == ['order=sata0', 'order=scsi0'] and lb.pve.running is False
    assert t._two_stage['state'] == 'switched'


def test_a_refused_first_start_is_the_callers_failure_only_when_it_wanted_the_guest_started(lab):
    lb = lab(start_fails=(1,))
    t = _staged(lb)
    assert ts.boot(lb.pve, t)[0] == 'failed'
    lb = lab(start_fails=(1,))
    t = _staged(lb, start_after=False)
    assert ts.boot(lb.pve, t) == ('stopped', '')
    assert any('first start on SATA failed' in w for w in t.warnings)
    assert 'scsi30' not in lb.qm.conf


# --------------------------------------------------------------------------- Live Mirror

def test_live_mirror_skips_it_and_restores_the_controller_and_the_nics(lab):
    lb = lab()
    t = _task()
    t._nics_switched, t._source_nic_model = True, 'vmxnet3'
    ts.not_with_live_mirror(lb.pve, t)
    assert t._two_stage['state'] == 'skipped' and lb.qm.conf['scsihw'] == 'pvscsi'
    assert lb.qm.conf['net0'] == 'vmxnet3=BC:24:11:00:00:01,bridge=vmbr0'


def test_live_mirror_after_the_in_guest_preparation_keeps_virtio(lab):
    lb = lab()
    t = _task()
    t._nics_switched, t._source_nic_model = True, 'vmxnet3'
    t._guest_prep = {'on': True, 'state': 'shut_down'}
    ts.not_with_live_mirror(lb.pve, t)
    assert lb.qm.conf['scsihw'] == 'virtio-scsi-single' and lb.qm.conf['net0'].startswith('virtio=')


# --------------------------------------------------------------------------- the downtime

def test_the_guest_counts_as_up_from_its_first_start_not_from_the_switch(lab, monkeypatch):
    # the switchover's downtime ends when the guest serves again: with its first boot on SATA
    lb = lab(files=FILES)
    t = _staged(lb)
    starts = []
    real_post = lb.pve._api_post

    def post(url, data=None, **kw):
        if url.endswith('/status/start'):
            starts.append(time.monotonic())
        return real_post(url, data=data, **kw)
    lb.pve._api_post = post
    monkeypatch.setattr(time, 'time', time.monotonic)      # the lab's clock
    real_fb = ts._firstboot
    monkeypatch.setattr(ts, '_firstboot', lambda p, task, wait: time.sleep(900) or real_fb(p, task, wait))
    assert ts.boot(lb.pve, t) == ('running', '')
    assert len(starts) == 2 and starts[0] <= t._two_stage['up_at'] < starts[0] + 60 < starts[1]
    assert t._two_stage['state'] == 'switched'


# --------------------------------------------------------------------------- the NICs after the injection

@pytest.mark.parametrize('staged,prepared,virtio', [
    ({}, False, True),
    ({'drivers': False}, False, False),
    ({'driver_msi': False}, False, False),         # no package: nothing installs NetKVM
    ({'first_boot': False}, False, False),         # no first boot task: nothing runs the package
    ({'first_boot': False, 'driver_msi': False}, True, True),     # the drivers are in the guest already
])
def test_virtio_nics_stay_only_when_the_guest_gets_netkvm(lab, staged, prepared, virtio):
    from pegaprox.core import v2p_winprep
    lb = lab()
    t = _task(**staged)
    t._nics_switched, t._source_nic_model = True, 'vmxnet3'
    if prepared:
        t._guest_prep = {'on': True, 'state': 'shut_down'}
    v2p_winprep.after_injection(lb.pve, t)
    assert lb.qm.conf['net0'] == ('virtio=BC:24:11:00:00:01,bridge=vmbr0' if virtio
                                  else 'vmxnet3=BC:24:11:00:00:01,bridge=vmbr0')
    assert any('VirtIO network left out' in w for w in t.warnings) is not virtio
