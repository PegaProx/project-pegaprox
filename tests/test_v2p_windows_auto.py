"""A Windows guest from ESXi, migrated fully automatically and without a login (MK Nov 2026).

Whole runs of _run_v2p_migration against the hosts of test_v2p_tpm_and_folder_copy.py, with the
guest reported as Windows, qm kept as a config (test_v2p_two_stage_boot.Qm) and the Proxmox API
answering for the guest agent: the preset switches the injection on, the VM is made for VirtIO,
the node gets the first boot helper and firstboot.cmd, the two-stage boot ends on scsi0. Where
the drivers cannot come, the guest keeps what the source had and the run says so.
"""
import json
import re
import time

import pytest

import pegaprox.core.v2p as v2p
from pegaprox.core import v2p_packages as pk
import test_v2p_tpm_and_folder_copy as farm
from test_v2p_two_stage_boot import Qm, Pve, Resp

VMID = farm.VMID
FB = {'version': 1, 'run': 't1', 'platform': 'kvm', 'state': 'applied', 'boots': 1, 'tools': 'removed',
      'devices': 'removed', 'adapters': [{'n': 1, 'ip': '10.0.0.5', 'index': '12', 'by': 'mac', 'applied': True}]}
WINPREP = {'build': 20348, 'product': 'Windows Server 2022 Standard', 'server': True, 'source': 'offline',
           'tools_code': True, 'locked': True, 'service': ['ControlSet001'], 'stale': 0, 'old_devices': 1,
           'adapters': [{'mac': '005056aabbcc', 'target_mac': 'bc2411000001', 'ipv4': ['10.0.0.5/24'],
                         'gateway': ['10.0.0.1'], 'desc': 'vmxnet3 Ethernet Adapter'}], 'files': []}


def _injection_out(winprep=WINPREP, agent=True, driver=True):
    """What the injection prints; the node helper prints MSI_STAGED for the packages it copied,
    only when it went through"""
    lines = ['WIN_PART=/dev/loop0p2', 'WDIR=Windows', 'VER_BUILD=20348', 'COPIED vioscsi (x)']
    if not driver:
        lines.append('MSI_MISSING (skipping bulk install)')
    if not agent:
        lines.append('GUEST_AGENT_MSI_MISSING (skipping the guest agent)')
    if winprep:
        lines += ['MSI_STAGED virtio-win-gt-x64.msi'] if driver else []
        lines += ['MSI_STAGED qemu-ga-x86_64.msi'] if agent else []
        lines += ['WINPREP ' + json.dumps(winprep), 'WINPREP_OK']
    else:
        lines.append('WINPREP_FAILED boom')
    lines.append('INJECTION_OK')
    return '\n'.join(lines) + '\n'


def _pve_net(line):
    """A net line as qm config shows it after the create: model=MAC first, a MAC made up where
    the create named none"""
    parts = str(line).split(',')
    mac = next((p.split('=', 1)[1] for p in parts if p.startswith('macaddr=')), 'BC:24:11:00:00:01')
    rest = [p for p in parts[1:] if not p.startswith('macaddr=')]
    return ','.join([f'{parts[0]}={mac.upper()}'] + rest)


class Win:
    """One run of a Windows guest. iso: 'there', 'download' (missing, the download works),
    'none' (missing, the download fails)"""

    def __init__(self, monkeypatch, mode='offline', iso='there', guest='windows2019srv_64Guest', inject=None,
                 **config):
        self.r = r = farm.Run(monkeypatch, mode=mode, ndisks=1, tpm=False)
        for k, v in config.items():
            r.task.config[k] = v
            setattr(r.task, k, v)
        if 'install_virtio_drivers' in config:
            r.task._virtio_explicit = True
        self.qm = Qm()
        self.pve = Pve(self.qm, files={r'C:\ProgramData\KVMMigration\firstboot.json': json.dumps(FB),
                                       r'C:\ProgramData\KVMMigration\migrate.log':
                                           '=== first boot on Proxmox VE, run t1, boot 1 ===\r\nstep drivers: msiexec exit code 0\r\n'},
                       log=r.log)
        self.iso = iso
        self.inject_out = _injection_out() if inject is None else inject
        self.scripts = {}
        real_get_vm = r.esxi.get_vm

        def get_vm(vm_id):
            d = real_get_vm(vm_id)
            d['data']['guest_id'], d['data']['guest_OS'] = guest, 'Microsoft Windows Server 2019 (64-bit)'
            return d
        r.esxi.get_vm = get_vm
        real_post = self.pve._api_post

        def post(url, data=None, **kw):
            if url.endswith('/nodes/pve1/qemu') and isinstance(data, dict):
                self.created = dict(data)
                self.qm.conf.update({k: _pve_net(v) if re.fullmatch(r'net\d+', k) else str(v)
                                     for k, v in data.items() if k != 'vmid'})
            return real_post(url, data=data, **kw)
        self.pve._api_post = post
        monkeypatch.setattr(v2p, 'cluster_managers', {'pve-cl': self.pve})
        real_node = r.node

        def node(mgr, n, cmd, timeout=600, **kw):
            got = self.qm.handle(cmd)
            if got is not None:
                r.log.append(('node', n, cmd))
                return got[0], got[1], ''
            m = re.match(r"umask 077; f=\$\(mktemp (/tmp/v2p-[a-z0-9-]+-)XXXXXXXXXX\)", cmd)
            if m:
                body = cmd.split("<< 'V2P_NODE_SCRIPT'\n", 1)[-1].rsplit('V2P_NODE_SCRIPT\n', 1)[0]
                out = real_node(mgr, n, cmd, timeout, **kw)
                self.scripts[out[1].strip()] = body
                return out
            if cmd.startswith('test -f ') and 'virtio-win.iso' in cmd and 'fedorapeople.org' not in cmd:
                r.log.append(('node', n, cmd))
                return (0 if self.iso == 'there' else 1), '', ''
            if 'fedorapeople.org' in cmd:
                r.log.append(('node', n, cmd))
                if self.iso == 'download':
                    self.iso = 'there'
                    return 0, f'V2P_DL OK {"ab" * 32} 734003200 /var/lib/vz/template/iso/virtio-win.iso\nINSTALLED virtio-win.iso\n', ''
                return 0, 'the download of x failed (exit code 6, 0 bytes): could not resolve\nFAILED virtio-win.iso\n', ''
            if re.search(r'bash /tmp/v2p-virtio-inject-\S+ 2>&1', cmd):
                r.log.append(('node', n, cmd))
                return 0, self.inject_out, ''
            return real_node(mgr, n, cmd, timeout, **kw)
        monkeypatch.setattr(v2p, '_pve_node_exec', node)

    def go(self):
        self.r.go()
        return self

    @property
    def task(self):
        return self.r.task

    def cmds(self):
        return self.r.nodecmds()


def test_a_windows_guest_is_prepared_offline_and_ends_on_virtio_scsi(monkeypatch):
    w = Win(monkeypatch).go()
    t = w.task
    assert t.status == 'completed', t.error
    assert t.install_virtio_drivers is True
    # the VM was made for VirtIO, the copy attached on scsi0
    assert w.created['scsihw'] == 'virtio-scsi-single' and w.created['net0'].startswith('virtio,')
    # the injection got the helper, firstboot.cmd and the MACs of the NICs
    inject = [s for p, s in w.scripts.items() if 'virtio-inject' in p][0]
    assert 'WINPREP=/tmp/v2p-winprep-' in inject and 'FB64=/tmp/v2p-firstboot-' in inject
    assert re.search(r"NICS='?[0-9a-f]{12}=", inject), inject[:400]
    helper = [s for p, s in w.scripts.items() if 'winprep' in p][0]
    assert 'def data_cmd(' in helper
    # the two-stage boot: first from sata0, then from scsi0, temp disk gone
    assert w.pve.boots == ['order=sata0', 'order=scsi0']
    assert set(w.qm.disks()) == {'scsi0'} and w.qm.conf['boot'] == 'order=scsi0'
    assert t._two_stage['state'] == 'switched' and t.warnings == []
    d = t.to_dict()
    assert d['two_stage'] == {'on': True, 'state': 'switched', 'boot_disk': 'scsi0', 'why': ''}
    assert d['windows_prep']['state'] == 'staged' and d['windows_prep']['first_boot'] == 'applied'
    log = '\n'.join(t.log_lines)
    assert 'static IPv4 10.0.0.5/24 (gateway 10.0.0.1) goes to the NIC with MAC bc2411000001' in log
    assert '[first boot] step drivers: msiexec exit code 0' in log


def test_with_start_after_off_the_two_stage_boot_still_runs_and_the_vm_ends_stopped(monkeypatch):
    w = Win(monkeypatch, start_after=False).go()
    assert w.task.status == 'completed'
    assert w.pve.boots == ['order=sata0', 'order=scsi0'] and w.pve.running is False
    assert w.task._two_stage['state'] == 'switched'


def test_a_missing_iso_is_downloaded_first_and_its_sha256_logged(monkeypatch):
    w = Win(monkeypatch, iso='download').go()
    assert w.task.status == 'completed'
    dl = [c for c in w.cmds() if 'fedorapeople.org' in c]
    assert len(dl) == 1 and '--proto =https' in dl[0] and ' -k' not in dl[0] and '--insecure' not in dl[0]
    assert any('sha256 ' + 'ab' * 32 in line for line in w.task.log_lines)
    assert w.task._two_stage['state'] == 'switched'


def test_a_failed_download_leaves_the_guest_on_the_source_controller_with_a_warning(monkeypatch):
    w = Win(monkeypatch, iso='none').go()
    t = w.task
    assert t.status == 'completed'
    assert w.created['scsihw'] == 'pvscsi' and w.created['net0'].startswith('vmxnet3,')
    assert t.install_virtio_drivers is False and t._two_stage['on'] is False
    assert not [c for c in w.cmds() if 'virtio-inject' in c]
    assert any('could not be downloaded' in x and 'source' in x for x in t.warnings)


def test_a_run_that_may_not_install_does_not_download(monkeypatch):
    w = Win(monkeypatch, iso='none', allow_package_install=False)
    monkeypatch.setattr(v2p, '_node_packages_refusal', lambda *a: None)
    w.go()
    assert not [c for c in w.cmds() if 'fedorapeople.org' in c]
    assert any('may not download it' in x for x in w.task.warnings)


def test_install_virtio_drivers_false_keeps_the_guest_as_the_source_had_it(monkeypatch):
    w = Win(monkeypatch, install_virtio_drivers=False).go()
    assert w.task.status == 'completed'
    assert w.created['scsihw'] == 'pvscsi' and w.created['net0'].startswith('vmxnet3,')
    assert not [c for c in w.cmds() if 'virtio-inject' in c] and w.pve.boots == ['order=scsi0']


def test_a_linux_guest_is_not_touched(monkeypatch):
    w = Win(monkeypatch, guest='debian12_64Guest').go()
    assert w.task.status == 'completed'
    assert w.created['scsihw'] == 'pvscsi' and w.task.install_virtio_drivers is False
    assert not [c for c in w.cmds() if 'virtio' in c and 'inject' in c]


def test_an_injection_that_failed_puts_the_source_nics_and_controller_back(monkeypatch):
    w = Win(monkeypatch, inject='NTFS_MOUNT_FAILED\n').go()
    t = w.task
    assert t.status == 'completed'
    assert w.qm.conf['scsihw'] == 'pvscsi' and w.qm.conf['net0'].startswith('vmxnet3=')
    assert w.pve.boots == ['order=scsi0'] and t._two_stage['state'] == 'dropped'
    assert any('VirtIO drivers were not injected' in x for x in t.warnings)
    assert any('VirtIO network left out' in x for x in t.warnings)


def test_a_first_boot_that_could_not_be_staged_puts_the_source_nics_back(monkeypatch):
    w = Win(monkeypatch, inject=_injection_out(winprep=None)).go()
    t = w.task
    assert t.status == 'completed' and t._two_stage['state'] == 'dropped'
    assert any('the first boot could not be staged' in x for x in t.warnings)
    # NetKVM comes with the package the first boot installs: without that boot nothing would
    # install it, the guest would have no network on a VirtIO NIC
    assert w.qm.conf['net0'] == 'vmxnet3=00:50:56:AA:00:01,bridge=vmbr0' and w.qm.conf['scsihw'] == 'pvscsi'
    assert any('VirtIO network left out (the first boot of the guest could not be staged)' in x for x in t.warnings)
    assert w.pve.boots == ['order=scsi0']


def test_an_iso_without_the_driver_package_puts_the_source_nics_back(monkeypatch):
    w = Win(monkeypatch, inject=_injection_out(driver=False)).go()
    t = w.task
    assert t.status == 'completed' and t._two_stage['state'] == 'dropped'
    assert w.qm.conf['net0'].startswith('vmxnet3=') and w.qm.conf['scsihw'] == 'pvscsi'
    assert any('VirtIO network left out (the driver package of the ISO was not staged' in x for x in t.warnings)
    # the first boot itself still runs: the address and the guest tools are handled on the source NIC model
    assert t._winprep['state'] == 'staged'


def test_a_folder_the_node_moved_aside_is_named_in_a_warning(monkeypatch):
    w = Win(monkeypatch, inject=_injection_out(winprep=dict(WINPREP, moved_aside=['KVMMigration.untrusted-t1']))).go()
    assert w.task.status == 'completed' and w.task._two_stage['state'] == 'switched'
    assert any('moved it aside as KVMMigration.untrusted-t1' in x and 'nothing in it was used' in x
               for x in w.task.warnings), w.task.warnings
    assert w.qm.conf['net0'].startswith('virtio=')


def _slow_first_boot_run(monkeypatch, mode):
    w = Win(monkeypatch, mode=mode)
    clock, real_time = w.r.clock, time.time
    # wall time follows the run's clock: every sleep of the harness moves it on
    monkeypatch.setattr(time, 'time', lambda: real_time() + (clock.now - 1000.0))
    from pegaprox.core import v2p_twostage
    real_fb = v2p_twostage._firstboot

    def slow_first_boot(pve_mgr, task, wait):
        clock.sleep(900)      # drivers, guest agent, the network: a first boot takes its time
        return real_fb(pve_mgr, task, wait)
    monkeypatch.setattr(v2p_twostage, '_firstboot', slow_first_boot)
    return w.go()


def test_the_downtime_of_a_live_clone_runs_until_the_guest_is_up_on_virtio(monkeypatch):
    # a lab run of Windows Server 2025 logged 162s: the time to the first start on SATA. The
    # guest was away for 643s, its first boot sets the address late and goes down for the switch
    w = _slow_first_boot_run(monkeypatch, 'vmkfstools_clone')
    t = w.task
    assert t.status == 'completed' and t._two_stage['state'] == 'switched'
    assert t.total_downtime_seconds >= 900, t.total_downtime_seconds
    # the detail view prints the figure as it is, every digit of the float
    assert t.total_downtime_seconds == round(t.total_downtime_seconds, 1)
    line = next(ln for ln in t.log_lines if 'SWITCHOVER DONE' in ln)
    assert f'(downtime {t.total_downtime_seconds:.1f}s: the target VM started after ' in line
    assert 'the first boot of the guest and its switch to VirtIO took the rest' in line


def test_the_downtime_of_a_presync_run_takes_in_the_start_and_the_first_boot(monkeypatch):
    w = _slow_first_boot_run(monkeypatch, 'auto')
    t = w.task
    assert t.status == 'completed' and t._two_stage['state'] == 'switched', t.error
    assert t.total_downtime_seconds >= 900, t.total_downtime_seconds
    assert not any('downtime ended with its first boot' in ln for ln in t.log_lines)


def test_the_downtime_of_an_offline_copy_runs_from_the_stop_until_the_guest_is_up(monkeypatch):
    # a lab run of the offline copy (Windows Server 2025, in-guest preparation) ended without any
    # downtime, the mode with the most of it: the copy, the first boot and the switch to VirtIO
    w = _slow_first_boot_run(monkeypatch, 'offline')
    t = w.task
    assert t.status == 'completed' and t._two_stage['state'] == 'switched', t.error
    assert t.total_downtime_seconds >= 900, t.total_downtime_seconds
    assert t.total_downtime_seconds == round(t.total_downtime_seconds, 1)
    assert t.downtime_start is not None and t.downtime_end is not None
    assert any(ln.endswith(f'(offline copy, downtime {t.total_downtime_seconds:.0f}s)') for ln in t.log_lines), \
        t.log_lines[-3:]


@pytest.mark.parametrize('mode', ['vmkfstools_clone', 'snapshot_zero'])
def test_a_snapshot_mode_run_of_a_source_that_was_off_has_no_downtime(monkeypatch, mode):
    # a lab bulk run of a Debian guest that was off said "downtime ~31.0s"
    import test_v2p_tpm_and_folder_copy as farm
    r = farm.Run(monkeypatch, mode=mode, power='POWERED_OFF').go()
    assert r.task.status == 'completed', r.task.error
    assert r.task.total_downtime_seconds is None
    assert any('the source VM was off already: no downtime counted' in ln for ln in r.task.log_lines)
    assert any(ln.endswith(f'COMPLETED ({mode}): app01 -> VMID {r.task.proxmox_vmid}') for ln in r.task.log_lines), \
        r.task.log_lines[-3:]


def test_an_offline_copy_of_a_source_that_was_off_has_no_downtime(monkeypatch):
    import test_v2p_tpm_and_folder_copy as farm
    r = farm.Run(monkeypatch, mode='offline', power='POWERED_OFF').go()
    assert r.task.status == 'completed', r.task.error
    assert r.task.total_downtime_seconds is None
    assert any(ln.endswith('(offline copy)') for ln in r.task.log_lines)


def test_the_package_plan_of_a_windows_run_downloads_the_iso_but_never_needs_it():
    plan = dict(pk.package_plan('offline', True, '', virtio_iso=True))
    assert plan['virtio_iso'] is False and plan['virtio'] is True
    assert 'virtio_iso' not in dict(pk.package_plan('sshfs_boot', True, '', virtio_iso=True))
    assert 'virtio-win.iso' not in pk.apt_command(['virtio-win.iso', 'curl'])
    assert 'fedorapeople.org' in pk.missing_message('pve1', [('virtio-win.iso', 'virtio_iso')])


@pytest.mark.parametrize('mode', ['vmkfstools_clone', 'auto'])
def test_the_other_copy_modes_end_on_virtio_scsi_too(monkeypatch, mode):
    w = Win(monkeypatch, mode=mode).go()
    t = w.task
    assert t.status == 'completed', (t.error, t.log_lines[-15:])
    assert [c for c in w.cmds() if 'virtio-inject' in c]
    assert w.pve.boots[-2:] == ['order=sata0', 'order=scsi0']
    assert set(w.qm.disks()) == {'scsi0'} and t._two_stage['state'] == 'switched'
