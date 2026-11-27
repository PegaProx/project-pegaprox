# -*- coding: utf-8 -*-
"""The fully automatic preparation of a Windows guest in an ESXi migration, without a login.

MK Nov 2026 - a Windows guest moved from ESXi needed hands before and after the move: the
VirtIO drivers in, the static address carried over to the new adapter and taken off the old
one, the ESXi guest tools out, the disks on VirtIO SCSI. PegaProx does all of it now, by
default, with nothing typed in:

  planning   plan()            the Windows preset: the driver injection on, virtio-win.iso
                               found on the target node or downloaded there (a package plan
                               item, #1252), the two-stage boot decided (core/v2p_twostage.py),
                               VirtIO SCSI single and VirtIO NICs for the VM where the drivers
                               will be there
  post-copy  the injection     core/v2p.py's _inject_virtio_drivers stages the drivers, the
                               packages and, through v2p_winprep_node.py on the node, the saved
                               network, firstboot.cmd and its one-shot SYSTEM service
             after_injection() no driver package or no first boot task (no NetKVM at the first
                               boot): the NICs go back to the model of the source
  first boot firstboot.cmd     drivers, guest agent, network, old adapters, ESXi guest tools
             first_boot_report()  its firstboot.json, read through the guest agent

The source VM on ESXi is not touched on this path: giving up the migration needs nothing but
powering the source on again. The in-guest preparation over the ESXi guest operations
(core/v2p_guestprep.py) is an optional addition when a Windows login is given.
"""

import json
import os
import re
import shlex
import time

from pegaprox.core import v2p_winprep_node as node_helper

FIRSTBOOT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'v2p_firstboot.cmd')
HELPER_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'v2p_winprep_node.py')
WORK_DIR = node_helper.WORK_DIR
LOG_PREFIX = '[first boot] '
FIRSTBOOT_STATES = ('applied', 'partial', 'failed', 'restored')
# the ESXi NIC models a guest loses with the ESXi guest tools
ESXI_NIC_MODELS = ('vmxnet3',)
_NET_RE = re.compile(r'^net(\d+)$')

_cache = {}


def firstboot_bytes():
    """v2p_firstboot.cmd as the guest gets it: CRLF line ends (cmd's goto and call find
    labels reliably only then), whatever git did to the file. ASCII, checked."""
    if 'fb' not in _cache:
        with open(FIRSTBOOT_FILE, 'rb') as fh:
            raw = fh.read()
        raw.decode('ascii')
        _cache['fb'] = raw.replace(b'\r\n', b'\n').replace(b'\n', b'\r\n')
    return _cache['fb']


def helper_source():
    """The source of v2p_winprep_node.py, the program the node runs"""
    if 'helper' not in _cache:
        with open(HELPER_FILE, 'r', encoding='utf-8') as fh:
            _cache['helper'] = fh.read()
    return _cache['helper']


def is_windows(ostype='', guest_id='', guest_os=''):
    from pegaprox.core.v2p_twostage import is_windows as _w
    return _w(ostype, guest_id, guest_os)


def state(task):
    st = getattr(task, '_winprep', None)
    if not isinstance(st, dict):
        st = task._winprep = {'windows': False, 'on': False, 'state': 'off', 'iso': None, 'why': ''}
    return st


# --------------------------------------------------------------------------- planning

def ensure_iso(pve_mgr, task):
    """The virtio-win.iso on the target node, downloaded into its ISO storage when there is
    none and the run may install. None when there is none afterwards (warning given)."""
    from pegaprox.core import v2p, v2p_packages as pk
    try:
        iso, searched = v2p._find_virtio_iso(pve_mgr, task)
    except ValueError as e:
        v2p._result_warning(task, f"Windows preparation left out: {e}")
        return None
    if iso:
        return iso
    node = task.target_node
    if getattr(task, 'virtio_iso_path', ''):
        v2p._result_warning(task, f"Windows preparation left out: {task.virtio_iso_path} is not on node {node}. "
                                  f"The guest keeps the disk controller and NICs of the source.")
        return None
    if not v2p._package_installs_allowed(task):
        v2p._result_warning(task, f"Windows preparation left out: no virtio-win.iso on node {node} (searched: "
                                  f"{', '.join(searched)}) and this migration may not download it. The guest keeps "
                                  f"the disk controller and NICs of the source.")
        return None
    task.log(f"Windows: no virtio-win.iso on {node}, downloading it from fedorapeople.org into "
             f"{pk.VIRTIO_ISO_DIR} (HTTPS, certificate checked)")
    rc, out, err = v2p._pve_node_exec(pve_mgr, node, pk.download_script('virtio-win.iso'), timeout=3600)
    got = pk.parse_download(out)
    if got:
        sha, size, path = got
        task.log(f"Windows: virtio-win.iso downloaded to {path} ({size / 1024 ** 2:.0f} MiB, sha256 {sha})")
        return path
    verdict, _n, said = pk.parse_ensure(rc, out, ['virtio-win.iso'])
    if verdict == 'PRESENT':
        iso, _s = v2p._find_virtio_iso(pve_mgr, task)
        if iso:
            return iso
    why = ' '.join(str(said or err or '').split())[-300:] or f'exit code {rc}'
    v2p._result_warning(task, f"Windows preparation left out: virtio-win.iso could not be downloaded to {node} "
                              f"({why}). The guest keeps the disk controller and NICs of the source; put the ISO "
                              f"into {pk.VIRTIO_ISO_DIR} and migrate again for the automatic preparation.")
    return None


def plan(pve_mgr, task, vm):
    """The Windows preset of the planning step, before the package check (it may switch the
    injection on) and before the VM exists. vm: the ESXi detail of the guest."""
    from pegaprox.core import v2p_twostage
    st = state(task)
    hw = (vm or {}).get('hardware') or {}
    win = is_windows(getattr(task, 'ostype', ''), (vm or {}).get('guest_id'),
                     (vm or {}).get('guest_OS') or (vm or {}).get('guest_os'))
    st['windows'] = win
    task._source_scsihw = str(hw.get('scsi_controller_pve') or '')
    task._source_bus = str(hw.get('disk_bus') or 'scsi')
    task._source_nic_model = str(hw.get('nic_type_pve') or 'e1000')
    if not win:
        task._two_stage = {'on': False, 'explicit': False, 'state': 'off', 'why': 'not a Windows guest',
                           'final_bus': 'scsi', 'boot_disk': None}
        if getattr(task, 'install_virtio_drivers', False):
            task.log("VirtIO driver injection asked for, the guest does not look like Windows")
        return
    mirror = task.transfer_mode == 'sshfs_boot'
    if not getattr(task, '_virtio_explicit', False) and not mirror:
        task.install_virtio_drivers = True
    gp = bool(getattr(task, 'guest_prep', False))
    wants = (task.install_virtio_drivers and not mirror) or gp
    if wants:
        iso = ensure_iso(pve_mgr, task)
        st['iso'] = iso
        if not iso:
            task.install_virtio_drivers = False
            if gp:
                gps = getattr(task, '_guest_prep', None)
                if isinstance(gps, dict):
                    gps.update(on=False, state='off', why='no virtio-win.iso on the node')
                task.guest_prep = False
            wants = False
    st['on'] = bool(wants)
    st['state'] = 'planned' if wants else 'off'
    v2p_twostage.plan(pve_mgr, task, vm, drivers=bool(wants))
    ts = task._two_stage
    if wants:
        task.log(f"Windows guest: prepared automatically on Proxmox VE (VirtIO drivers and guest agent from "
                 f"{st['iso']}, static IPv4 carried over, ESXi guest tools removed at the first boot"
                 f"{', two-stage boot' if ts.get('on') else ''}{', in-guest preparation first' if gp else ''})")
    elif mirror and not gp:
        task.log("Windows guest on Live Mirror: the guest boots on the target before anything can be staged, it "
                 "keeps the disk controller and NICs of the source")


def wants_virtio_hardware(task):
    """Whether the VM is created with VirtIO SCSI single and VirtIO NICs: the drivers will be
    there before its first boot (the two-stage boot, or the in-guest preparation)"""
    ts = getattr(task, '_two_stage', None) or {}
    gp = getattr(task, '_guest_prep', None) or {}
    return bool(ts.get('on')) or (bool(gp.get('on')) and bool(getattr(task, 'guest_prep', False)))


# --------------------------------------------------------------------------- the injection

def nic_pairs(pve_mgr, task):
    """'srcmac=tgtmac,...' for the node: each source NIC's MAC and the MAC of its netN on
    Proxmox, in the order of the source NICs (a skipped one has no netN)"""
    from pegaprox.core.v2p_twostage import qm_config
    conf = qm_config(pve_mgr, task) or {}
    out = []
    for idx, nic in enumerate(getattr(task, '_source_nics', None) or []):
        line = conf.get(f'net{idx}')
        if line is None:
            continue
        m = re.search(r'([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})', line)
        src = nic.get('mac_address') if isinstance(nic, dict) else ''
        out.append(f"{node_helper.norm_mac(src)}={node_helper.norm_mac(m.group(1) if m else '')}")
    return ','.join(out)


def uninstall_tools_ok(task):
    """The first boot may uninstall the ESXi guest tools: the VM keeps no device that runs on
    one of their drivers (pvscsi, vmxnet3). firstboot.cmd asks the guest again at that boot."""
    hw = str(getattr(task, '_attach_scsihw', '') or '')
    model = str(getattr(task, '_net_model', '') or '')
    return hw != 'pvscsi' and model not in ESXI_NIC_MODELS


def parse_result(task, out):
    """The WINPREP line of the node script into the task log; True when the first boot is staged"""
    from pegaprox.core.v2p import _result_warning
    st = state(task)
    text = str(out or '')
    for line in text.splitlines():
        s = line.strip()
        if s.startswith('WINPREP_FAILED'):
            st.update(state='failed', why=s[len('WINPREP_FAILED'):].strip()[:300])
            _result_warning(task, f"Windows preparation: the first boot could not be staged ({st['why']}). The "
                                  f"drivers are copied, no first boot task is registered: the guest keeps the NICs and "
                                  f"the disk controller of the source, its static IPv4 and the ESXi guest tools stay "
                                  f"as they were.")
            return False
        if s.startswith('WINPREP {'):
            try:
                got = json.loads(s[len('WINPREP '):])
            except ValueError:
                continue
            st.update(state='staged', summary=got)
            src = 'the in-guest preparation' if got.get('source') == 'guest' else 'the copied registry'
            task.log(f"[Windows] {got.get('product') or 'Windows'} (build {got.get('build')}); network from {src}")
            for a in got.get('adapters') or []:
                to = f"the NIC with MAC {a['target_mac']}" if a.get('target_mac') else 'the NIC in the same order'
                task.log(f"[Windows]   static IPv4 {', '.join(a.get('ipv4') or [])} (gateway "
                         f"{', '.join(a.get('gateway') or []) or 'none'}) goes to {to} at the first boot")
            if not got.get('adapters'):
                task.log("[Windows]   no adapter with a static IPv4 address, nothing to carry over")
            if got.get('stale'):
                task.log(f"[Windows]   {got['stale']} static adapter(s) of hardware the guest no longer has stay as they are")
            task.log(f"[Windows]   ESXi guest tools: "
                     f"{'uninstalled at the first boot' if got.get('tools_code') else 'no uninstall entry found, they stay'}"
                     f"; {got.get('old_devices', 0)} old network device(s) to remove; first boot service in "
                     f"{', '.join(got.get('service') or []) or 'no control set'}")
            if 'san_policy' in got and got['san_policy'] != 1:
                from pegaprox.core.v2p_winprep_node import SAN_POLICIES
                was = SAN_POLICIES.get(got['san_policy'], f"{got['san_policy']}") if got['san_policy'] is not None \
                    else 'the default of the edition'
                task.log(f"[Windows]   SAN policy {was} set to OnlineAll: the data disks come up online on their "
                         f"new controller, not offline and read-only")
            if got.get('moved_aside'):
                _result_warning(task, f"Windows: C:\\ProgramData\\{WORK_DIR} of the guest was there already and not "
                                      f"locked to SYSTEM and the Administrators (made by a user of the guest, or a link). "
                                      f"PegaProx moved it aside as {', '.join(got['moved_aside'])} and made its own; "
                                      f"nothing in it was used. Look at what it holds.")
            return True
    st.update(state='failed', why='the node script did not report')
    return False


def nic_driver_missing(task):
    """Why the guest would have no driver for a VirtIO NIC at its first boot, '' when it has
    one. NetKVM comes with the driver package the first boot task installs: the injection only
    copies its files, nothing registers them."""
    gp = getattr(task, '_guest_prep', None) or {}
    if gp.get('state') == 'shut_down':
        return ''
    vs = getattr(task, '_virtio_staged', None) or {}
    if not vs.get('drivers'):
        return 'the VirtIO drivers were not staged'
    if not vs.get('first_boot'):
        return 'the first boot of the guest could not be staged'
    if not vs.get('driver_msi'):
        return 'the driver package of the ISO was not staged for the first boot'
    return ''


def after_injection(pve_mgr, task):
    """Post-copy, right after the driver injection: a guest that gets no NetKVM at its first
    boot gets the NIC model of the source back (its disks: v2p_twostage.stage)"""
    st = state(task)
    if not getattr(task, '_nics_switched', False):
        return
    why = nic_driver_missing(task)
    if not why:
        return
    if not (getattr(task, '_virtio_staged', None) or {}).get('drivers'):
        st['state'] = 'dropped'
    keep_source_nics(pve_mgr, task, why)


def keep_source_nics(pve_mgr, task, why):
    """The NICs the run made VirtIO for the drivers get the model of the source again, MAC,
    bridge and the rest of the line as they are"""
    from pegaprox.core import v2p
    from pegaprox.core.v2p_twostage import qm_config, _qm
    if not getattr(task, '_nics_switched', False):
        return
    model = str(getattr(task, '_source_nic_model', '') or 'e1000')
    if not v2p.valid_nic_model(model):
        model = 'e1000'
    conf = qm_config(pve_mgr, task) or {}
    done = []
    for key, line in sorted(conf.items()):
        if not _NET_RE.match(key) or not line.startswith('virtio'):
            continue
        rest = line[len('virtio'):]
        rc, said = _qm(pve_mgr, task, f'set {int(task.proxmox_vmid)} --{key} {shlex.quote(model + rest)}')
        if rc == 0:
            done.append(key)
        else:
            task.log(f"  {key}: setting the model {model} failed ({said[-160:]})")
    task._nics_switched = False
    task._net_model = model
    if done:
        v2p._result_warning(task, f"VirtIO network left out ({why}): {', '.join(done)} use {model} of the source again.")


# --------------------------------------------------------------------------- the first boot

def _system_drive(pve_mgr, task):
    from pegaprox.core.v2p_twostage import agent_exec
    got = agent_exec(pve_mgr, task, ['cmd.exe', '/c', 'echo', '%SystemDrive%'], wait=30)
    drive = str(got[1] if got else '').strip()
    return drive if re.fullmatch(r'[A-Za-z]:', drive) else 'C:'


def work_path(pve_mgr, task):
    st = state(task)
    if not st.get('work'):
        st['work'] = f"{_system_drive(pve_mgr, task)}\\ProgramData\\{WORK_DIR}"
    return st['work']


def read_first_boot(pve_mgr, task, wait):
    """firstboot.json of this run once it has a state, None when it did not come within wait"""
    from pegaprox.core.v2p_twostage import agent_file_read
    path = work_path(pve_mgr, task) + '\\firstboot.json'
    deadline = time.monotonic() + wait
    while True:
        raw = agent_file_read(pve_mgr, task, path)
        fb = None
        if raw:
            try:
                fb = json.loads(raw.lstrip('\ufeff'))
            except ValueError:
                fb = None
        if isinstance(fb, dict) and fb.get('run') == str(task.id) and fb.get('state') in FIRSTBOOT_STATES:
            return fb
        if time.monotonic() >= deadline:
            return None
        time.sleep(10)


def log_first_boot(pve_mgr, task, fb):
    """The outcome of the first boot into the task log, what did not work as warnings, and the
    lines of migrate.log of that boot"""
    from pegaprox.core.v2p import _result_warning
    from pegaprox.core.v2p_twostage import agent_file_read
    st = state(task)
    st['first_boot'] = fb.get('state')
    bad = []
    for a in fb.get('adapters') or []:
        if not isinstance(a, dict):
            continue
        if a.get('applied'):
            task.log(f"{LOG_PREFIX}static IPv4 {a.get('ip')} is on interface {a.get('index')} (matched by {a.get('by')})")
        else:
            bad.append(f"{a.get('ip')} ({a.get('why') or 'not applied'})")
    task.log(f"{LOG_PREFIX}ESXi guest tools: {fb.get('tools')}; old network devices: {fb.get('devices')}")
    if bad:
        retry = ' The first boot task tries again at the next boot.' if fb.get('state') == 'partial' else ''
        _result_warning(task, f"Windows: the static IPv4 could not be put back for {'; '.join(bad)}.{retry} The saved "
                              f"addresses are in {work_path(pve_mgr, task)}\\netconfig.json.")
    if fb.get('tools') in ('disabled',):
        _result_warning(task, "Windows: the ESXi guest tools could not be uninstalled at the first boot, their service "
                              "is disabled. Uninstall them under Apps.")
    raw = agent_file_read(pve_mgr, task, work_path(pve_mgr, task) + '\\migrate.log')
    if raw:
        # what stage 2 of an in-guest preparation wrote after stage 1 was copied
        from pegaprox.core import v2p_guestprep
        v2p_guestprep.take_stage2_lines(task, raw)
        lines = raw.splitlines()
        at = max((i for i, ln in enumerate(lines) if f'run {task.id}' in ln and '===' in ln), default=None)
        for ln in (lines[at + 1:] if at is not None else [])[-200:]:
            if ln.strip():
                task.log(LOG_PREFIX + ln.strip()[:400])


def no_report(task, why):
    """MK Nov 2026 - the first boot task's report did not come: a warning of the run, not a log
    line under COMPLETED. A lab run ended without a warning while the guest had no network."""
    from pegaprox.core.v2p import _result_warning
    task.log(f"{LOG_PREFIX}{why}")
    _result_warning(task, f"Windows: {why}, so whether the static IPv4 is on the new adapters is not known. "
                          f"Check the guest's network; its log is C:\\ProgramData\\{WORK_DIR}\\migrate.log.")


def first_boot_report(pve_mgr, task, agent_wait=300, wait=600):
    """After a start without the two-stage boot: what the first boot task did. Never fails the run."""
    st = state(task)
    if st.get('state') != 'staged' or st.get('first_boot'):
        return
    from pegaprox.core.v2p_twostage import agent_ping
    if not agent_ping(pve_mgr, task, agent_wait):
        no_report(task, f'the guest agent did not answer within {agent_wait // 60} min')
        return
    fb = read_first_boot(pve_mgr, task, wait)
    if fb:
        log_first_boot(pve_mgr, task, fb)
    else:
        no_report(task, f'the first boot task did not report within {wait // 60} min')


def view(task):
    """What to_dict shows"""
    st = state(task)
    return {'windows': bool(st.get('windows')), 'on': bool(st.get('on')), 'state': str(st.get('state') or 'off'),
            'first_boot': st.get('first_boot'), 'why': str(st.get('why') or '')}
