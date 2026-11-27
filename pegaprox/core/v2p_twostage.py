# -*- coding: utf-8 -*-
"""Two-stage boot of a migrated Windows guest: the boot disk on SATA first, then VirtIO.

MK Nov 2026 - a Windows guest moved straight onto VirtIO SCSI blue-screened with
INACCESSIBLE_BOOT_DEVICE (Server 2025 in May): Windows 8 and later do not bind vioscsi at
early boot from offline registry edits alone, which is why the scsihw switch after the driver
injection was turned off. What works is one boot with the boot disk on SATA (AHCI, inbox
storahci) while a VirtIO SCSI device is present: Plug and Play installs vioscsi for it in that
boot. After that the boot disk can move to SCSI.

    stage()  post-copy, the VM stopped: the boot disk <final>0 -> sata0 (ide0 below build 9200),
             the other disks stay on the final bus, a 1 GiB temp disk scsi30 (virtio15) when no
             other disk is there, so the VM has a VirtIO controller in the first boot
    boot()   replaces the start: first boot, the guest agent, then the agent is asked whether
             vioscsi starts at boot and is bound to a device (Services\\vioscsi\\Enum\\Count),
             a clean shutdown, sata0 -> scsi0, the temp disk destroyed, second boot

It is on by default for every Windows guest whose VirtIO drivers will be there, and it runs
with start_after off too (the VM is shut down at the end then). Once the first start ran
nothing here fails the migration: a guest that did not bind the driver or did not come up from
SCSI stays (or goes back) on SATA, with a warning in the result.
The guest commands are fixed argument lists through the guest agent, no shell, no PowerShell.
"""

import re
import shlex
import time

FINAL = {'scsi': {'service': 'vioscsi', 'temp': 'scsi30', 'label': 'VirtIO SCSI'},
         'virtio': {'service': 'viostor', 'temp': 'virtio15', 'label': 'VirtIO Block'}}
# the first boot runs the MSI installs of the injection before the guest agent starts
AGENT_FIRST_SECONDS = 900
AGENT_SECOND_SECONDS = 600
BIND_SECONDS = 600
# the first boot task installs the drivers and the agent, waits up to 10 min for the NICs and
# uninstalls the ESXi guest tools: the guest is not shut down under it before this
FIRSTBOOT_SECONDS = 1200
SHUTDOWN_SECONDS = 300
SATA_PORTS = 6
POLL_SECONDS = 10
# reads of the start type of a bound driver before it counts as not read
START_READS = 3
VIRTIO_SCSI = ('virtio-scsi-single', 'virtio-scsi-pci')
# ostypes of the Windows releases before 8 / 2012, whose msahci is often not a boot driver
_OLD_WINDOWS = ('win7', 'w2k8', 'wxp', 'w2k', 'wvista')
_REG_RE = re.compile(r'\b(Start|Count)\s+REG_DWORD\s+0x([0-9a-fA-F]+)')
_DRIVE_RE = re.compile(r'^(scsi|virtio|sata|ide)(\d+)$')


# --------------------------------------------------------------------------- the rule

def is_windows(ostype='', guest_id='', guest_os=''):
    """A Windows guest: the ostype override, else ESXi's guest id, else the guest's name"""
    o = str(ostype or '').lower()
    if o and o != 'auto':
        return o.startswith('win') or o in _OLD_WINDOWS
    from pegaprox.core.xhm import _ESXI_TO_PVE_OSTYPE
    mapped = str(_ESXI_TO_PVE_OSTYPE.get(str(guest_id or ''), '') or '')
    if mapped:
        return mapped.startswith('win') or mapped in _OLD_WINDOWS
    return 'windows' in str(guest_os or '').lower()


def decide(cfg, *, windows, transfer_mode, disk_bus_req='', scsihw_req='', agent=True, drivers=True):
    """{'on', 'explicit', 'why', 'final_bus'} of a migration's two-stage boot. Pure: the route,
    the dry run and the task ask the same thing. Absent, it is on for every Windows guest whose
    VirtIO drivers will be there (the owner's rule: fully automatic); false turns it off."""
    want = (cfg or {}).get('two_stage_boot')
    explicit = isinstance(want, bool)
    bus = str(disk_bus_req or '').lower()
    hw = str(scsihw_req or '').lower()
    final = 'virtio' if bus == 'virtio' else 'scsi'

    def out(on, why):
        return {'on': on, 'explicit': explicit, 'why': why, 'final_bus': final}
    if want is False:
        return out(False, 'turned off')
    if not windows:
        return out(False, 'not a Windows guest')
    if str(transfer_mode or '') == 'sshfs_boot':
        return out(False, 'the live mirror boots the guest itself')
    if bus in ('sata', 'ide'):
        return out(False, f'the disks stay on {bus.upper()}')
    if hw and hw != 'auto' and hw not in VIRTIO_SCSI:
        return out(False, f'the SCSI controller {hw} was chosen')
    if agent is False:
        return out(False, 'it needs the guest agent, which is turned off')
    if not drivers:
        return out(False, 'the VirtIO drivers will not be there')
    return out(True, 'turned on' if want is True else 'a Windows guest')


def refusal(cfg):
    """Why an explicit two_stage_boot true cannot be, from the body alone (the route's 400),
    None when it can or is not asked for"""
    cfg = cfg or {}
    if cfg.get('two_stage_boot') is not True:
        return None
    if str(cfg.get('transfer_mode') or '') == 'sshfs_boot':
        return ('two_stage_boot does not run with Live Mirror (sshfs_boot): the mirror boots the guest itself. '
                'Use Live Clone, Snapshot-Iterative, Auto or Offline Copy.')
    bus = str(cfg.get('disk_bus') or '').lower()
    if bus in ('sata', 'ide'):
        return f'two_stage_boot ends on VirtIO SCSI or VirtIO Block, disk_bus {bus} keeps the disks on {bus.upper()}.'
    hw = str(cfg.get('scsihw') or '').lower()
    if hw and hw != 'auto' and hw not in VIRTIO_SCSI:
        return f'two_stage_boot ends on VirtIO SCSI, scsihw {hw} was chosen.'
    if cfg.get('agent') is False:
        return 'two_stage_boot checks the guest through the guest agent, which agent false turns off.'
    if cfg.get('install_virtio_drivers') is False and cfg.get('guest_prep') is not True:
        return ('two_stage_boot needs the VirtIO drivers in the guest: leave install_virtio_drivers on, or '
                'prepare the guest in ESXi (guest_prep).')
    return None


def first_bus(build=None, ostype=''):
    """'sata' (AHCI, storahci), 'ide' for Windows before 8 / 2012 only"""
    try:
        if build and int(build) < 9200:
            return 'ide'
    except (TypeError, ValueError):
        pass
    return 'ide' if str(ostype or '').lower() in _OLD_WINDOWS else 'sata'


def _ostype_of(explicit, guest_id):
    o = str(explicit or '').lower()
    if o and o != 'auto':
        return o
    from pegaprox.core.xhm import _ESXI_TO_PVE_OSTYPE
    return str(_ESXI_TO_PVE_OSTYPE.get(str(guest_id or ''), '') or '')


def plan_view(vm_detail, data, kept_disks=1, drivers=True):
    """What the review shows: {on, why, first_bus, final_bus, scsihw, temp_disk, drivers_from,
    errors, warnings}. An explicit true that the rule turns off is an error."""
    vd = (vm_detail.get('data') or {}) if isinstance(vm_detail, dict) else {}
    gp = data.get('guest_prep') is True
    win = is_windows(data.get('ostype') or '', vd.get('guest_id'), vd.get('guest_OS'))
    d = decide(data, windows=win, transfer_mode=data.get('transfer_mode') or 'auto',
               disk_bus_req=data.get('disk_bus'), scsihw_req=data.get('scsihw'),
               agent=data.get('agent', True) is not False, drivers=drivers)
    req_hw = str(data.get('scsihw') or '')
    hw = vd.get('hardware') or {}
    view = {'on': d['on'], 'why': d['why'], 'first_bus': first_bus(None, _ostype_of(data.get('ostype'), vd.get('guest_id'))),
            'final_bus': d['final_bus'],
            'scsihw': req_hw if req_hw not in ('', 'auto') else ('virtio-scsi-single' if d['on'] or gp
                                                                else str(hw.get('scsi_controller_pve') or '')),
            'temp_disk': bool(d['on']) and int(kept_disks or 0) <= 1,
            'drivers_from': 'guest_prep' if gp else 'injection', 'errors': [], 'warnings': []}
    if data.get('two_stage_boot') is True and not d['on']:
        view['errors'].append(f"two_stage_boot: {d['why']}")
    return view


def plan(pve_mgr, task, vm_detail, drivers=True):
    """The planning step (core/v2p_winprep.plan asks, after it knows whether the drivers will
    be there): the decision, logged."""
    d = decide(getattr(task, 'config', None) or {},
               windows=bool((getattr(task, '_winprep', None) or {}).get('windows')) or
               is_windows(getattr(task, 'ostype', ''), (vm_detail or {}).get('guest_id'),
                          (vm_detail or {}).get('guest_OS') or (vm_detail or {}).get('guest_os')),
               transfer_mode=task.transfer_mode, disk_bus_req=getattr(task, 'disk_bus', ''),
               scsihw_req=getattr(task, 'scsihw_override', ''), agent=getattr(task, 'agent', True) is not False,
               drivers=drivers)
    d.update(state='planned' if d['on'] else 'off', boot_disk=None)
    task._two_stage = d
    if d['on']:
        task.log(f"Two-stage boot planned: the first boot with the boot disk on SATA, then {d['final_bus']}0 on "
                 f"{FINAL[d['final_bus']]['label']}")
    elif d['explicit'] or d['why'] not in ('not a Windows guest',):
        task.log(f"Two-stage boot off: {d['why']}")


# --------------------------------------------------------------------------- the node

def _vmid(task):
    return int(task.proxmox_vmid)


def _qm(pve_mgr, task, args, timeout=60):
    from pegaprox.core import v2p
    rc, out, err = v2p._pve_node_exec(pve_mgr, task.target_node, f'qm {args} 2>&1', timeout=timeout)
    return rc, str(out or err or '').strip()


def qm_config(pve_mgr, task):
    """{key: value} of qm config, None when it could not be read"""
    rc, out = _qm(pve_mgr, task, f'config {_vmid(task)}', timeout=20)
    if rc != 0 or not out:
        return None
    conf = {}
    for line in out.splitlines():
        k, sep, v = line.partition(':')
        if sep and k.strip() and ' ' not in k.strip():
            conf[k.strip()] = v.strip()
    return conf


def _volid(value):
    return str(value or '').split(',', 1)[0].strip() or None


def _disks_on(conf, bus):
    return [k for k, v in (conf or {}).items()
            if _DRIVE_RE.match(k) and k.startswith(bus) and 'media=cdrom' not in v]


def _drop_stale_unused(pve_mgr, task, conf, volid):
    """An unusedN line that still names the volume the boot disk now is: the config line goes,
    the volume stays (qm set --delete unusedN would destroy it)"""
    from pegaprox.core import v2p
    for k, v in (conf or {}).items():
        if re.fullmatch(r'unused\d+', k) and _volid(v) == volid:
            v2p._pve_node_exec(pve_mgr, task.target_node,
                               f"sed -i '/^{k}: /d' /etc/pve/qemu-server/{_vmid(task)}.conf", timeout=10)


def _attach(pve_mgr, task, bus, volid):
    hw = getattr(task, '_attach_scsihw', '') if bus == 'scsi' else ''
    opts = task._disk_attach_opts(bus=bus, hw=hw)
    return _qm(pve_mgr, task, f'set {_vmid(task)} --{bus}0 {shlex.quote(volid)}{opts} --boot order={bus}0')


def _move_boot_disk(pve_mgr, task, src, dst):
    """(True, '') once the boot disk's volume is <dst>0, else (False, what qm said); a move
    that failed half way puts the disk back on <src>0"""
    ts = task._two_stage
    volid = ts['volid']
    rc, said = _qm(pve_mgr, task, f'set {_vmid(task)} --delete {src}0')
    if rc != 0:
        return False, said[-300:]
    rc, said = _attach(pve_mgr, task, dst, volid)
    conf = qm_config(pve_mgr, task)
    if rc == 0 and conf and _volid(conf.get(f'{dst}0')) == volid:
        _drop_stale_unused(pve_mgr, task, conf, volid)
        return True, ''
    _attach(pve_mgr, task, src, volid)
    _drop_stale_unused(pve_mgr, task, qm_config(pve_mgr, task), volid)
    return False, (said or 'the volume is not attached there')[-300:]


def _drop_temp(pve_mgr, task):
    ts = task._two_stage
    temp = ts.get('temp')
    if not temp:
        return
    rc, said = _qm(pve_mgr, task, f'disk unlink {_vmid(task)} --idlist {temp} --force')
    if rc != 0:
        from pegaprox.core.v2p import _result_warning
        _result_warning(task, f"Two-stage boot: the temporary disk {temp} could not be removed ({said[-200:]}); "
                              f"remove it from the VM's hardware")
    else:
        task.log(f'  Temporary disk {temp} removed')
    ts['temp'] = None


def _sector_args(pve_mgr, task):
    if getattr(task, '_sector_args', False):
        from pegaprox.core import v2p
        v2p._rebuild_sector_args(pve_mgr, task.target_node, _vmid(task))


def _move_all(pve_mgr, task, src, dst):
    """Every disk on <src>N to <dst>N, the same N; the names of those that did not move"""
    conf = qm_config(pve_mgr, task) or {}
    failed = []
    for key in sorted(_disks_on(conf, src), key=lambda k: int(_DRIVE_RE.match(k).group(2))):
        n = _DRIVE_RE.match(key).group(2)
        volid = _volid(conf.get(key))
        rc, _said = _qm(pve_mgr, task, f'set {_vmid(task)} --delete {key}')
        if rc != 0:
            failed.append(key)
            continue
        hw = getattr(task, '_attach_scsihw', '') if dst == 'scsi' else ''
        opts = task._disk_attach_opts(bus=dst, hw=hw)
        rc, _said = _qm(pve_mgr, task, f'set {_vmid(task)} --{dst}{n} {shlex.quote(volid)}{opts}')
        if rc != 0:
            _qm(pve_mgr, task, f'set {_vmid(task)} --{key} {shlex.quote(volid)}{task._disk_attach_opts()}')
            failed.append(key)
        _drop_stale_unused(pve_mgr, task, qm_config(pve_mgr, task), volid)
    _qm(pve_mgr, task, f'set {_vmid(task)} --boot order={dst}0')
    return failed


def keep_source_controller(pve_mgr, task, why):
    """Two-stage boot is not done: the controller, and the disk bus where the run changed it
    for the two-stage boot, go back to what the source had."""
    from pegaprox.core import v2p
    ts = getattr(task, '_two_stage', None) or {}
    hw = getattr(task, '_source_scsihw', '') or ''
    notes = []
    if getattr(task, '_scsihw_switched', False) and hw and hw not in VIRTIO_SCSI:
        rc, said = _qm(pve_mgr, task, f'set {_vmid(task)} --scsihw {shlex.quote(hw)}')
        if rc == 0:
            notes.append(hw)
            task._attach_scsihw, task._scsihw_switched = hw, False
        else:
            notes.append(f'setting {hw} failed: {said[-120:]}')
    src_bus = str(getattr(task, '_source_bus', '') or '')
    final = ts.get('final_bus') or 'scsi'
    if getattr(task, '_bus_switched', False) and src_bus in ('sata', 'ide', 'scsi', 'virtio') and src_bus != final:
        failed = _move_all(pve_mgr, task, final, src_bus)
        notes.append(f"disks on {src_bus.upper()}" + (f", {', '.join(failed)} could not move" if failed else ''))
        if not failed:
            task._attach_bus, task._bus_switched = src_bus, False
    ts.update(on=False, state='dropped', why=str(why)[:200])
    task._two_stage = ts
    note = f" ({'; '.join(notes)})" if notes else ''
    v2p._result_warning(task, f"Two-stage boot left out: {why}. The guest keeps the controller of the source{note}.")


def not_with_live_mirror(pve_mgr, task):
    """Live Mirror (Auto falling back to it included) boots the guest itself, before anything
    could be staged: the controller and the NICs of the source, unless the in-guest
    preparation put the drivers in place"""
    from pegaprox.core import v2p, v2p_winprep
    ts = getattr(task, '_two_stage', None)
    gp = getattr(task, '_guest_prep', None) or {}
    prepared = gp.get('state') == 'shut_down'
    if isinstance(ts, dict) and ts.get('on'):
        ts.update(on=False, state='skipped', why='Live Mirror boots the guest itself')
        v2p._result_warning(task, 'Two-stage boot does not run with Live Mirror.')
    hw = getattr(task, '_source_scsihw', '') or ''
    if not prepared and getattr(task, '_scsihw_switched', False) and hw and hw not in VIRTIO_SCSI:
        _qm(pve_mgr, task, f'set {_vmid(task)} --scsihw {shlex.quote(hw)}')
        task._attach_scsihw, task._scsihw_switched = hw, False
        task.log(f'  The controller is {hw} again, as on the source')
    if not prepared:
        v2p_winprep.keep_source_nics(pve_mgr, task, 'Live Mirror boots the guest before the drivers are staged')


def sata_first_boot_planned(task):
    """The first boot on Proxmox VE may have the boot disk on SATA: the two-stage boot, or Live
    Mirror booting a guest prepared in ESXi (live_first_sata), which Auto falls back to when
    its pre-sync fails. The in-guest preparation sets storahci to boot start for it; on a
    guest that never boots on SATA that changes nothing."""
    if (getattr(task, '_two_stage', None) or {}).get('on'):
        return True
    return str(getattr(task, 'transfer_mode', '') or '') in ('sshfs_boot', 'auto')


def live_first_sata(task, scsi_prefix):
    """MK Nov 2026 - Live Mirror boots a Windows guest prepared in ESXi with its boot disk on
    SATA and the other disks on VirtIO SCSI, as the first boot of the two-stage boot does.
    The drivers in the Driver Store and vioscsi at boot start are not enough: Windows Server
    2025 stopped with INACCESSIBLE_BOOT_DEVICE on a lab run when the boot disk was on VirtIO
    SCSI from the start, then booted on SATA and bound vioscsi to the controller next to it."""
    from pegaprox.core import v2p_winprep
    gp = getattr(task, '_guest_prep', None) or {}
    return (bool(v2p_winprep.state(task).get('windows')) and gp.get('state') == 'shut_down'
            and 'virtio-scsi' in str(scsi_prefix or ''))


def live_switch(pve_mgr, task):
    """After Live Mirror moved the disks of a guest booted by live_first_sata: 'scsi' when
    vioscsi is bound and starts at boot (the next start has the boot disk on VirtIO SCSI),
    'sata' when the boot disk has to stay on SATA. The guest keeps running either way."""
    from pegaprox.core import v2p
    svc = FINAL['scsi']['service']
    vmid = _vmid(task)
    task.log('  Checking the guest before the boot disk moves to VirtIO SCSI for the next start...')
    if not agent_ping(pve_mgr, task, AGENT_FIRST_SECONDS):
        v2p._result_warning(task, f'The guest agent of VM {vmid} did not answer within {AGENT_FIRST_SECONDS // 60} '
                                  f'min of its start on Proxmox VE: open its console. The boot disk stays on '
                                  f'SATA (sata0); move it to VirtIO SCSI once Windows runs.')
        return 'sata'
    fb = None
    try:
        from pegaprox.core import v2p_winprep
        fb = v2p_winprep.read_first_boot(pve_mgr, task, FIRSTBOOT_SECONDS)
        if fb:
            v2p_winprep.log_first_boot(pve_mgr, task, fb)
    except Exception as e:
        task.log(f'  The first boot report could not be read: {e}')
    if not fb:
        v2p._result_warning(task, f'Windows: the first boot task did not report within {FIRSTBOOT_SECONDS // 60} '
                                  f'min, the static IPv4 may not be on the new adapters; see '
                                  f'C:\\ProgramData\\KVMMigration\\migrate.log in the guest.')
    bound, start = _bind_state(pve_mgr, task, svc, BIND_SECONDS)
    if bound and start != 0:
        agent_exec(pve_mgr, task, ['sc.exe', 'config', svc, 'start=', 'boot'])
        bound, start = _bind_state(pve_mgr, task, svc, 30)
    if not bound or start != 0:
        seen = f'{svc} is not bound to any device' if not bound else f'{svc} does not start at boot (Start {start})'
        v2p._result_warning(task, f'Live Mirror: {seen}. The boot disk stays on SATA (sata0).')
        return 'sata'
    task.log(f'  {svc} is bound and starts at boot: the boot disk is on VirtIO SCSI from the next start on')
    return 'scsi'


def _drivers_missing(task):
    gp = getattr(task, '_guest_prep', None) or {}
    if gp.get('state') == 'shut_down':
        return ''
    vs = getattr(task, '_virtio_staged', None) or {}
    if not vs.get('drivers'):
        return 'the VirtIO drivers were not injected'
    # the node helper copies the packages and stages the first boot: its failure is both
    if not vs.get('first_boot'):
        return 'the first boot of the guest could not be staged'
    if not vs.get('driver_msi'):
        return 'the driver package of the ISO was not staged for the first boot'
    if not vs.get('agent_msi'):
        return 'the guest agent package was missing on the ISO'
    return ''


def stage(pve_mgr, task):
    """Post-copy, the VM stopped: the layout of the first boot. True when boot() takes over
    the start, False when the run starts the guest as it always did."""
    ts = getattr(task, '_two_stage', None)
    if not (isinstance(ts, dict) and ts.get('on')):
        return False
    final = ts['final_bus']
    why = _drivers_missing(task)
    if why:
        keep_source_controller(pve_mgr, task, why)
        return False
    build = (getattr(task, '_guest_probe', None) or {}).get('build') or \
        ((getattr(task, '_winprep', None) or {}).get('summary') or {}).get('build')
    first = first_bus(build, getattr(task, 'ostype', ''))
    conf = qm_config(pve_mgr, task)
    volid = _volid((conf or {}).get(f'{final}0'))
    if not volid:
        keep_source_controller(pve_mgr, task, f'the VM has no {final}0 to move (qm config)')
        return False
    ts.update(volid=volid, first_bus=first, temp=None)
    ok, said = _move_boot_disk(pve_mgr, task, final, first)
    if not ok:
        keep_source_controller(pve_mgr, task, f'the boot disk could not be moved to {first}0 ({said})')
        return False
    conf = qm_config(pve_mgr, task) or {}
    others = [k for k in _disks_on(conf, final) if k != f'{final}0']
    if not others:
        temp = FINAL[final]['temp']
        rc, said = _qm(pve_mgr, task, f'set {_vmid(task)} --{temp} {shlex.quote(task.target_storage)}:1')
        conf = qm_config(pve_mgr, task) or {}
        if rc != 0 or not _volid(conf.get(temp)):
            _move_boot_disk(pve_mgr, task, first, final)
            keep_source_controller(pve_mgr, task, f'the temporary {temp} could not be added ({said[-200:]})')
            return False
        ts['temp'] = temp
    _sector_args(pve_mgr, task)
    ts.update(state='first_boot_staged', boot_disk=f'{first}0')
    task.log(f"Two-stage boot: boot disk on {first}0 for the first boot, {len(others)} disk(s) on "
             f"{FINAL[final]['label']}{', temporary disk ' + ts['temp'] if ts['temp'] else ''}")
    return True


# --------------------------------------------------------------------------- the guest agent
# after backup_verify's helpers (private there)

def _base(pve_mgr, task):
    return (f"https://{pve_mgr.host}:{pve_mgr.api_port}/api2/json/nodes/{task.target_node}"
            f"/qemu/{_vmid(task)}")


def agent_ping(pve_mgr, task, wait, poll=5):
    deadline = time.monotonic() + wait
    while True:
        try:
            r = pve_mgr._api_post(f'{_base(pve_mgr, task)}/agent/ping', timeout=15)
            if r.status_code == 200:
                return True
        except Exception:
            pass
        if time.monotonic() >= deadline:
            return False
        time.sleep(poll)


def agent_exec(pve_mgr, task, argv, wait=60):
    """(exitcode, stdout) of a command the guest agent ran, None when it could not run it"""
    base = _base(pve_mgr, task)
    try:
        # an array parameter: one 'command' per argument
        r = pve_mgr._api_post(f'{base}/agent/exec', data={'command': list(argv)}, timeout=15)
        if r.status_code != 200:
            return None
        pid = (r.json().get('data') or {}).get('pid')
    except Exception:
        return None
    if pid is None:
        return None
    deadline = time.monotonic() + wait
    while True:
        try:
            r = pve_mgr._api_get(f'{base}/agent/exec-status', params={'pid': pid}, timeout=15)
            if r.status_code == 200:
                d = r.json().get('data') or {}
                if d.get('exited'):
                    return int(d.get('exitcode') or 0), str(d.get('out-data') or '')
        except Exception:
            pass
        if time.monotonic() >= deadline:
            return None
        time.sleep(2)


def agent_file_read(pve_mgr, task, path):
    """The text of a file in the guest, None when the agent did not hand it out"""
    try:
        r = pve_mgr._api_get(f'{_base(pve_mgr, task)}/agent/file-read', params={'file': path}, timeout=30)
        if r.status_code != 200:
            return None
        d = r.json().get('data') or {}
        content = d.get('content')
        return str(content) if content is not None else None
    except Exception:
        return None


def _reg_dword(res, name):
    if not res or res[0] != 0:
        return None
    for k, v in _REG_RE.findall(res[1]):
        if k == name:
            return int(v, 16)
    return None


def _bind_state(pve_mgr, task, svc, wait):
    """(bound, start) of the storage driver: bound once Services\\<svc>\\Enum\\Count is 1 or
    more, the number of devices bound to it in this boot"""
    key = f'HKLM\\SYSTEM\\CurrentControlSet\\Services\\{svc}'
    deadline = time.monotonic() + wait
    start = None
    while True:
        start = _reg_dword(agent_exec(pve_mgr, task, ['reg.exe', 'query', key, '/v', 'Start']), 'Start')
        count = _reg_dword(agent_exec(pve_mgr, task, ['reg.exe', 'query', key + '\\Enum', '/v', 'Count']), 'Count')
        if count and count >= 1:
            # MK Nov 2026 - a read the agent did not answer is no start type: seen on a real
            # Server 2025, whose first read came back empty right after the agent came up
            for _ in range(START_READS):
                if start is not None:
                    break
                time.sleep(POLL_SECONDS)
                start = _reg_dword(agent_exec(pve_mgr, task, ['reg.exe', 'query', key, '/v', 'Start']), 'Start')
            return True, start
        if time.monotonic() >= deadline:
            return False, start
        time.sleep(POLL_SECONDS)


def _wait_stopped(pve_mgr, task, wait):
    from pegaprox.core.v2p import _pve_vm_status
    deadline = time.monotonic() + wait
    while _pve_vm_status(pve_mgr, task.target_node, _vmid(task)) != 'stopped':
        if time.monotonic() >= deadline:
            return False
        time.sleep(3)
    return True


def _shutdown(pve_mgr, task):
    """A clean shutdown through the guest agent, True once the VM is stopped"""
    try:
        pve_mgr._api_post(f'{_base(pve_mgr, task)}/status/shutdown', data={'timeout': SHUTDOWN_SECONDS},
                          timeout=30)
    except Exception:
        pass
    return _wait_stopped(pve_mgr, task, SHUTDOWN_SECONDS + 30)


def _stop(pve_mgr, task):
    try:
        pve_mgr._api_post(f'{_base(pve_mgr, task)}/status/stop', timeout=30)
    except Exception:
        pass
    return _wait_stopped(pve_mgr, task, 120)


def _down(pve_mgr, task):
    if not _shutdown(pve_mgr, task):
        from pegaprox.core.v2p import _result_warning
        _result_warning(task, f'Two-stage boot: the guest did not shut down within {SHUTDOWN_SECONDS}s and was '
                              f'powered off.')
        _stop(pve_mgr, task)


def _end(pve_mgr, task):
    """The run's own choice for the end, after a boot that stays on the first bus"""
    from pegaprox.core import v2p
    if not getattr(task, 'start_after', True):
        return 'stopped', ''
    outcome, why = v2p._start_target_vm(pve_mgr, task)
    if outcome == 'running':
        return 'running', ''
    v2p._result_warning(task, f"The guest did not start again on {task._two_stage.get('boot_disk')} ({why}): "
                              f"start it on Proxmox.")
    return 'stopped', ''


def _others_to_first(pve_mgr, task):
    """The data disks leave the final bus as well when its driver is not known to work: a guest
    whose vioscsi never bound would not see them. SATA has six ports; IDE is left alone."""
    ts = task._two_stage
    final, first = ts['final_bus'], ts['first_bus']
    if first != 'sata':
        return
    conf = qm_config(pve_mgr, task) or {}
    keys = [k for k in _disks_on(conf, final) if k != ts.get('temp')]
    if not keys or any(int(_DRIVE_RE.match(k).group(2)) >= SATA_PORTS for k in keys) or \
            any(f'{first}{_DRIVE_RE.match(k).group(2)}' in conf for k in keys):
        if keys:
            task.log(f"  {', '.join(sorted(keys))} stay on {final} (no free SATA port of the same number)")
        return
    for key in sorted(keys):
        n = _DRIVE_RE.match(key).group(2)
        volid = _volid(conf.get(key))
        if _qm(pve_mgr, task, f'set {_vmid(task)} --delete {key}')[0] != 0:
            continue
        if _qm(pve_mgr, task, f'set {_vmid(task)} --{first}{n} {shlex.quote(volid)}'
                              f'{task._disk_attach_opts(bus=first, hw="")}')[0] != 0:
            _qm(pve_mgr, task, f'set {_vmid(task)} --{key} {shlex.quote(volid)}{task._disk_attach_opts()}')
        _drop_stale_unused(pve_mgr, task, qm_config(pve_mgr, task), volid)
    task.log(f"  The data disk(s) {', '.join(sorted(keys))} moved to {first.upper()} as well")


def _kept(task, msg):
    from pegaprox.core.v2p import _result_warning
    ts = task._two_stage
    ts.update(state='kept_sata', boot_disk=f"{ts['first_bus']}0", why=str(msg)[:300])
    _result_warning(task, msg)


def _firstboot(pve_mgr, task, wait):
    """The outcome of the first boot task (firstboot.cmd), within `wait`: the network and the
    tools uninstall run in that boot, the guest is not shut down under them"""
    from pegaprox.core import v2p_winprep
    st = v2p_winprep.state(task)
    if st.get('state') != 'staged' or st.get('first_boot'):
        return
    fb = v2p_winprep.read_first_boot(pve_mgr, task, wait)
    if fb:
        v2p_winprep.log_first_boot(pve_mgr, task, fb)
    else:
        task.log(f'  The first boot task did not report within {wait // 60} min, going on')


def boot(pve_mgr, task):
    """Replaces the start when stage() returned True: ('running' | 'stopped', '') once the
    first start ran, whatever happened after it; ('failed' | 'unknown', why) when the first
    start did not, for the caller's rollback as before."""
    from pegaprox.core import v2p
    ts = task._two_stage
    final, first = ts['final_bus'], ts['first_bus']
    svc, label = FINAL[final]['service'], FINAL[final]['label']
    task.log(f'Two-stage boot: first boot from {first}0')
    outcome, why = v2p._start_target_vm(pve_mgr, task)
    if outcome == 'running':
        # the first start: the run says how much of the downtime came after it (the first
        # boot and the switch to VirtIO), the downtime itself runs until the switch is done
        ts['up_at'] = time.time()
    if outcome != 'running':
        if outcome == 'failed':
            _drop_temp(pve_mgr, task)
            _sector_args(pve_mgr, task)
            ts.update(state='kept_sata', boot_disk=f'{first}0', why=f'the first start failed: {why}'[:300])
            if not getattr(task, 'start_after', True):
                # without the two-stage boot this run would not have started the guest at all
                v2p._result_warning(task, f'Two-stage boot: the first start on {first.upper()} failed ({why}). The boot '
                                          f'disk stays on {first}0 and the VM is stopped; start it on Proxmox.')
                return 'stopped', ''
        return outcome, why

    task.log(f'  Waiting for the guest agent (up to {AGENT_FIRST_SECONDS // 60} min, the first boot installs the drivers)')
    if not agent_ping(pve_mgr, task, AGENT_FIRST_SECONDS):
        _stop(pve_mgr, task)
        _drop_temp(pve_mgr, task)
        _others_to_first(pve_mgr, task)
        _sector_args(pve_mgr, task)
        _kept(task, f'The guest agent did not answer within {AGENT_FIRST_SECONDS // 60} min of the first boot on '
                    f'{first.upper()}. The boot disk stays on {first}0 and {label} was not switched on. Open the '
                    f'console: if Windows runs, install the guest agent and move the disk to {final.upper()} by hand; '
                    f'if it stopped with INACCESSIBLE_BOOT_DEVICE, attach the boot disk on IDE.')
        return _end(pve_mgr, task)

    _firstboot(pve_mgr, task, FIRSTBOOT_SECONDS)
    bound, start = _bind_state(pve_mgr, task, svc, BIND_SECONDS)
    if bound and start != 0:
        if start is None:
            task.log(f'  {svc} is bound, its start type could not be read, setting it to boot start')
        else:
            task.log(f'  {svc} is bound but does not start at boot (Start {start}), setting it to boot start')
        agent_exec(pve_mgr, task, ['sc.exe', 'config', svc, 'start=', 'boot'])
        bound, start = _bind_state(pve_mgr, task, svc, 30)
    if not bound or start != 0:
        seen = f'{svc} is not bound to any device' if not bound else f'{svc} does not start at boot (Start {start})'
        _down(pve_mgr, task)
        _drop_temp(pve_mgr, task)
        _others_to_first(pve_mgr, task)
        _sector_args(pve_mgr, task)
        _kept(task, f'Two-stage boot: {seen}. The boot disk stays on {first}0 and {label} was not switched on.')
        return _end(pve_mgr, task)
    task.log(f'  {svc} is bound and starts at boot, shutting the guest down for the switch')

    _down(pve_mgr, task)
    ok, said = _move_boot_disk(pve_mgr, task, first, final)
    _drop_temp(pve_mgr, task)
    _sector_args(pve_mgr, task)
    if not ok:
        _kept(task, f'Two-stage boot: moving the boot disk to {final}0 failed ({said}). It stays on {first}0.')
        return _end(pve_mgr, task)

    outcome, why = v2p._start_target_vm(pve_mgr, task)
    if outcome == 'running' and agent_ping(pve_mgr, task, AGENT_SECOND_SECONDS):
        ts.update(state='switched', boot_disk=f'{final}0', why='')
        task.log(f'Two-stage boot done: boot disk on {label} ({final}0)')
        if not getattr(task, 'start_after', True):
            _down(pve_mgr, task)
            return 'stopped', ''
        return 'running', ''
    reason = why if outcome != 'running' else f'no guest agent within {AGENT_SECOND_SECONDS // 60} min'
    _stop(pve_mgr, task)
    _move_boot_disk(pve_mgr, task, final, first)
    _sector_args(pve_mgr, task)
    ts.update(state='kept_sata', boot_disk=f'{first}0', why=str(reason)[:300])
    started = getattr(task, 'start_after', True)
    v2p._result_warning(task, f"The second boot on {label} did not come up ({reason}); the boot disk is back on "
                              f"{first}0{' and the guest was started from there' if started else ''}.")
    return _end(pve_mgr, task)
