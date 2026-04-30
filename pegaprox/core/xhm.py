# -*- coding: utf-8 -*-
"""
Cross-Hypervisor Migration engine - Proxmox <-> XCP-ng
NS: Mar 2026 - separate module because v2p.py is already 3800 lines
and this is bidirectional, not just one direction.
"""

import logging
import threading
import time
import uuid
import os
import re
from datetime import datetime

from pegaprox.globals import cluster_managers, _xhm_migrations
from pegaprox.utils.ssh import _ssh_exec, _pve_node_exec
from pegaprox.utils.realtime import broadcast_sse

logger = logging.getLogger(__name__)

# MK: Mar 2026 - hardware mapping tables for cross-hypervisor translation
# Proxmox ostype -> XCP-ng template name
_PVE_TO_XCP_OSTYPE = {
    'l26': 'Other install media',
    'l24': 'Other install media',
    'win10': 'Windows 10 (64-bit)',
    'win11': 'Windows 11 (64-bit)',
    'w2k19': 'Windows Server 2019 (64-bit)',
    'w2k22': 'Windows Server 2022',
    'w2k16': 'Windows Server 2016 (64-bit)',
    'w2k12': 'Windows Server 2012 (64-bit)',
    'w2k8': 'Windows Server 2008 (64-bit)',
    'other': 'Other install media',
    'solaris': 'Other install media',  # no solaris template in XCP-ng
}

# XCP-ng platform flags -> Proxmox ostype
# viridian=true means Windows, otherwise assume Linux
# NS: this is a heuristic, not perfect but good enough for 99% of cases
_XCP_VIRIDIAN_OSTYPE = 'win10'
_XCP_DEFAULT_OSTYPE = 'l26'

# NIC model mapping
_PVE_NIC_TO_XCP = {
    'virtio': 'e1000',  # no virtio on XCP-ng HVM
    'e1000': 'e1000',
    'vmxnet3': 'e1000',
    'rtl8139': 'rtl8139',
    'e1000e': 'e1000',
}
_XCP_NIC_TO_PVE = {
    'netfront': 'virtio',
    'e1000': 'e1000',
    'rtl8139': 'rtl8139',
}

# NS: Mar 2026 - ESXi guest OS -> Proxmox ostype
# MK: Apr 2026 — comprehensive ESXi guestId → PVE ostype mapping (#222)
# verified against VMware GuestOsIdentifier enum + PVE ostype list
_ESXI_TO_PVE_OSTYPE = {
    # Linux — all modern kernels
    'ubuntu64Guest': 'l26', 'ubuntu32Guest': 'l26',
    'debian10_64Guest': 'l26', 'debian11_64Guest': 'l26', 'debian12_64Guest': 'l26', 'debian13_64Guest': 'l26',
    'centos7_64Guest': 'l26', 'centos8_64Guest': 'l26', 'centos9_64Guest': 'l26',
    'rhel7_64Guest': 'l26', 'rhel8_64Guest': 'l26', 'rhel9_64Guest': 'l26', 'rhel10_64Guest': 'l26',
    'fedora64Guest': 'l26', 'fedoraGuest': 'l26',
    'sles15_64Guest': 'l26', 'sles16_64Guest': 'l26', 'sles12_64Guest': 'l26',
    'oracleLinux64Guest': 'l26', 'oracleLinux7_64Guest': 'l26', 'oracleLinux8_64Guest': 'l26', 'oracleLinux9_64Guest': 'l26',
    'rockylinux_64Guest': 'l26', 'almalinux_64Guest': 'l26', 'amazonlinux2_64Guest': 'l26', 'amazonlinux3_64Guest': 'l26',
    'asianux8_64Guest': 'l26', 'coreos64Guest': 'l26', 'flatcar64Guest': 'l26',
    'otherLinux64Guest': 'l26', 'otherLinuxGuest': 'l26', 'otherLinux24xGuest': 'l24', 'otherLinux26xGuest': 'l26',
    # Windows
    'windows11_64Guest': 'win11',
    'windows2022srvNext_64Guest': 'win11', 'windows2022srv_64Guest': 'win11',  # Server 2022/2025 → win11
    'windows9_64Guest': 'win10', 'windows9Guest': 'win10',
    'windows2019srv_64Guest': 'win10', 'windows2019srvNext_64Guest': 'win10', 'windows2016srv_64Guest': 'win10',
    'windows8_64Guest': 'win8', 'windows8Guest': 'win8', 'windows8srv_64Guest': 'win8',
    'windows7_64Guest': 'win7', 'windows7Guest': 'win7', 'windows7srv_64Guest': 'win7',
    'winVista64Guest': 'wvista', 'winVistaGuest': 'wvista',
    'winLonghorn64Guest': 'w2k8', 'winLonghornGuest': 'w2k8',
    'winXPPro64Guest': 'wxp', 'winXPProGuest': 'wxp',
    'win2000ProGuest': 'w2k', 'win2000ServGuest': 'w2k', 'win2000AdvServGuest': 'w2k',
    'winNetStandard64Guest': 'w2k3', 'winNetEnterprise64Guest': 'w2k3',
    # Other
    'solaris11_64Guest': 'solaris', 'solaris10_64Guest': 'solaris',
    'freebsd64Guest': 'other', 'freebsd13_64Guest': 'other', 'freebsd14_64Guest': 'other',
    'otherGuest64': 'other', 'otherGuest': 'other',
}
_ESXI_TO_XCP_OSTYPE = {
    'ubuntu64Guest': 'Other install media', 'debian10_64Guest': 'Other install media',
    'centos7_64Guest': 'Other install media', 'rhel8_64Guest': 'Other install media',
    'windows9_64Guest': 'Windows 10 (64-bit)', 'windows11_64Guest': 'Windows 11 (64-bit)',
    'windows2019srv_64Guest': 'Windows Server 2019 (64-bit)',
    'windows2019srvNext_64Guest': 'Windows Server 2022',
    'windows2022srvNext_64Guest': 'Windows Server 2022',
}
# ESXi NIC model translation
_ESXI_NIC_TO_PVE = {'vmxnet3': 'virtio', 'e1000': 'e1000', 'e1000e': 'e1000e', 'pcnet32': 'e1000'}
_ESXI_NIC_TO_XCP = {'vmxnet3': 'e1000', 'e1000': 'e1000', 'e1000e': 'e1000', 'pcnet32': 'rtl8139'}

# chunk size for streaming disk data
_CHUNK_SIZE = 4 * 1024 * 1024  # 4 MB


class _StreamBody:
    """Wraps SSH stdout as file-like with known size so requests
    doesn't add Transfer-Encoding: chunked (XAPI can't handle it)."""
    def __init__(self, stream, size, progress_fn=None):
        self._stream = stream
        self._size = size
        self._read = 0
        self._progress_fn = progress_fn

    def read(self, n=-1):
        chunk = self._stream.read(n if n > 0 else _CHUNK_SIZE)
        if chunk and self._progress_fn:
            self._read += len(chunk)
            self._progress_fn(self._read)
        return chunk

    def __len__(self):
        return self._size


class XHMigrationTask:
    """Tracks a cross-hypervisor migration (Proxmox <-> XCP-ng).

    Phases: planning -> transfer -> creating -> attaching -> completed/failed
    """

    def __init__(self, mid, direction, source_cluster, source_node, source_vmid,
                 target_cluster, target_node, target_storage, vm_name='', config=None):
        self.id = mid
        self.direction = direction  # 'pve_to_xcpng' or 'xcpng_to_pve'
        self.source_cluster = source_cluster
        self.source_node = source_node
        self.source_vmid = source_vmid
        self.target_cluster = target_cluster
        self.target_node = target_node
        self.target_storage = target_storage
        self.vm_name = vm_name
        self.config = config or {}
        self.phase = 'planning'
        self.status = 'running'
        self.progress = 0
        self.started_at = datetime.now()
        self.completed_at = None
        self.error = None
        self.target_vmid = None
        self.disk_progress = {}
        self.phase_times = {}
        self.log_lines = []
        self.cancel_event = threading.Event()
        # options
        self.network_map = self.config.get('network_map', {})
        self.start_after = self.config.get('start_after', True)
        self.remove_source = self.config.get('remove_source', False)
        self._last_sse_progress = 0
        self._last_sse_log = 0

    def log(self, msg):
        ts = datetime.now().strftime('%H:%M:%S')
        entry = f"[{ts}] {msg}"
        self.log_lines.append(entry)
        logger.info(f"[XHM:{self.id}] {msg}")
        try:
            now = time.time()
            if now - self._last_sse_log > 1:
                self._last_sse_log = now
                broadcast_sse('xhm_migration_log', {
                    'id': self.id, 'line': entry,
                    'progress': self.progress, 'phase': self.phase
                })
        except:
            pass

    def set_phase(self, phase, error=None):
        # close previous phase timing
        if self.phase in self.phase_times:
            start = datetime.fromisoformat(self.phase_times[self.phase]['start'])
            self.phase_times[self.phase]['end'] = datetime.now().isoformat()
            self.phase_times[self.phase]['duration'] = round((datetime.now() - start).total_seconds(), 1)
        self.phase = phase
        self.phase_times[phase] = {'start': datetime.now().isoformat(), 'end': None, 'duration': None}

        if error:
            self.error = error
            self.status = 'failed'
            self.log(f"FAILED: {error}")

        if phase == 'completed':
            self.status = 'completed'
            self.completed_at = datetime.now()
            self.progress = 100
        elif phase == 'failed':
            self.status = 'failed'
            self.completed_at = datetime.now()

        self.log(f"Phase: {phase}")
        self._broadcast_status()

    def update_progress(self, disk_key, copied, total):
        self.disk_progress[disk_key] = {
            'copied': copied, 'total': total,
            'pct': round(copied / total * 100, 1) if total > 0 else 0
        }
        # overall progress: transfer phase is 10-80%, rest is planning/creating/attaching
        tc = sum(d['copied'] for d in self.disk_progress.values())
        tt = sum(d['total'] for d in self.disk_progress.values())
        if tt > 0 and self.phase == 'transfer':
            self.progress = 10 + min(69, round((tc / tt) * 70))
        try:
            now = time.time()
            if now - self._last_sse_progress > 2:
                self._last_sse_progress = now
                self._broadcast_status()
        except:
            pass

    def _broadcast_status(self):
        try:
            broadcast_sse('xhm_migration', {
                'id': self.id, 'phase': self.phase, 'status': self.status,
                'progress': self.progress, 'vm_name': self.vm_name,
                'direction': self.direction,
                'error': self.error, 'disk_progress': self.disk_progress,
                'target_vmid': self.target_vmid,
            })
        except:
            pass

    def to_dict(self):
        return {
            'id': self.id,
            'direction': self.direction,
            'source_cluster': self.source_cluster,
            'source_vmid': self.source_vmid,
            'target_cluster': self.target_cluster,
            'target_node': self.target_node,
            'target_storage': self.target_storage,
            'vm_name': self.vm_name,
            'target_vmid': self.target_vmid,
            'phase': self.phase,
            'status': self.status,
            'progress': self.progress,
            'error': self.error,
            'started_at': self.started_at.isoformat(),
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'disk_progress': self.disk_progress,
            'phase_times': self.phase_times,
            'log': self.log_lines[-30:],
            'config': {
                'start_after': self.start_after,
                'remove_source': self.remove_source,
                'network_map': self.network_map,
            },
        }


# ============================================================
# Planning functions
# ============================================================

def plan_xcpng_to_pve(source_cluster_id, source_vmid, target_cluster_id):
    """Build a migration plan for XCP-ng -> Proxmox."""
    src = cluster_managers.get(source_cluster_id)
    if not src or getattr(src, 'cluster_type', '') != 'xcpng':
        return {'error': 'Source XCP-ng cluster not found'}

    tgt = cluster_managers.get(target_cluster_id)
    if not tgt or getattr(tgt, 'cluster_type', 'proxmox') == 'xcpng':
        return {'error': 'Target must be a Proxmox cluster'}

    if not src.is_connected:
        return {'error': 'Source XCP-ng not connected'}
    if not tgt.is_connected:
        return {'error': 'Target Proxmox not connected'}

    vm_cfg = src.get_vm_config(None, source_vmid)
    if not vm_cfg.get('success'):
        return {'error': vm_cfg.get('error', 'Failed to get VM config')}

    cfg = vm_cfg['config']

    # must be halted
    if cfg.get('power_state', '').lower() not in ('halted', 'stopped'):
        return {'error': 'VM must be stopped before cross-hypervisor migration'}

    # check if HVM (PV VMs can't be migrated to KVM)
    platform = cfg.get('platform', {})
    # PV VMs have no HVM_boot_policy or have PV_bootloader set
    # we check boot_params which is set for PV
    if cfg.get('boot_params') and not platform.get('device_model', ''):
        return {'error': 'PV (paravirtualized) VMs cannot be migrated to KVM. Only HVM VMs are supported.'}

    # map hardware
    is_windows = platform.get('viridian', '').lower() == 'true'
    pve_ostype = _XCP_VIRIDIAN_OSTYPE if is_windows else _XCP_DEFAULT_OSTYPE

    # BIOS mode
    boot_policy = ''
    try:
        api = src._api()
        ref = src._resolve_vm(source_vmid)
        boot_policy = api.VM.get_HVM_boot_policy(ref)
    except:
        pass
    pve_bios = 'ovmf' if 'uefi' in boot_policy.lower() else 'seabios'

    # disks (skip empty/CD)
    disks_info = []
    total_bytes = 0
    for d in cfg.get('disks', []):
        disks_info.append({
            'id': d.get('id', ''),
            'name': d.get('name', ''),
            'uuid': d.get('uuid', ''),
            'size': d.get('size', 0),
            'size_gb': round(d.get('size', 0) / (1024**3), 1),
            'bootable': d.get('bootable', False),
        })
        total_bytes += d.get('size', 0)

    # networks
    nets_info = []
    for n in cfg.get('networks', []):
        pve_model = _XCP_NIC_TO_PVE.get('e1000', 'virtio')  # default virtio on PVE
        nets_info.append({
            'id': n.get('id', ''),
            'mac': n.get('mac', ''),
            'network': n.get('network', ''),
            'bridge': n.get('bridge', ''),
            'target_model': pve_model,
        })

    # available PVE targets
    pve_targets = _get_pve_targets(tgt)

    estimated_seconds = max(30, int(total_bytes / (100 * 1024 * 1024)))  # ~100MB/s estimate

    return {
        'source': {
            'name': cfg.get('name', ''),
            'vcpus': cfg.get('vcpus', 1),
            'memory_mb': round(cfg.get('memory', 0) / (1024 * 1024)),
            'memory': cfg.get('memory', 0),
            'disks': disks_info,
            'networks': nets_info,
            'ostype': pve_ostype,
            'bios': pve_bios,
            'is_windows': is_windows,
            'platform': platform,
        },
        'targets': pve_targets,
        'estimated_seconds': estimated_seconds,
        'direction': 'xcpng_to_pve',
    }


def plan_pve_to_xcpng(source_cluster_id, source_node, source_vmid, target_cluster_id):
    """Build a migration plan for Proxmox -> XCP-ng."""
    src = cluster_managers.get(source_cluster_id)
    if not src or getattr(src, 'cluster_type', 'proxmox') == 'xcpng':
        return {'error': 'Source must be a Proxmox cluster'}

    tgt = cluster_managers.get(target_cluster_id)
    if not tgt or getattr(tgt, 'cluster_type', '') != 'xcpng':
        return {'error': 'Target XCP-ng cluster not found'}

    if not src.is_connected:
        return {'error': 'Source Proxmox not connected'}
    if not tgt.is_connected:
        return {'error': 'Target XCP-ng not connected'}

    # get PVE VM config
    result = src.get_vm_config(source_node, int(source_vmid), 'qemu')
    if not result.get('success'):
        return {'error': result.get('error', 'Failed to get VM config')}

    cfg = result.get('config', {})
    raw = cfg.get('raw', cfg)

    # check stopped
    status_ok = False
    try:
        st_url = f"https://{src.host}:8006/api2/json/nodes/{source_node}/qemu/{source_vmid}/status/current"
        st_resp = src._api_get(st_url)
        if st_resp.status_code == 200:
            st_data = st_resp.json().get('data', {})
            if st_data.get('status') == 'stopped':
                status_ok = True
    except:
        pass
    if not status_ok:
        return {'error': 'VM must be stopped before cross-hypervisor migration'}

    vm_name = raw.get('name', f'vm-{source_vmid}')
    memory_bytes = int(raw.get('memory', 1024)) * 1024 * 1024  # PVE stores MB
    vcpus = int(raw.get('cores', 1)) * int(raw.get('sockets', 1))
    ostype = raw.get('ostype', 'l26')

    # parse disks from PVE config
    disks = []
    total_bytes = 0
    disk_keys = []
    for key, val in raw.items():
        if not isinstance(val, str):
            continue
        # match scsi0, virtio0, sata0, ide0 etc.
        m = re.match(r'^(scsi|virtio|sata|ide)(\d+)$', key)
        if not m:
            continue
        # skip cdrom
        if 'media=cdrom' in val or 'none' in val.split(',')[0]:
            continue
        # parse volume id and size
        parts = val.split(',')
        vol_id = parts[0].strip()
        size_str = ''
        for p in parts[1:]:
            p = p.strip()
            if p.startswith('size='):
                size_str = p.split('=')[1]
        size_bytes = _parse_pve_size(size_str) if size_str else 0
        disks.append({
            'key': key,
            'volume': vol_id,
            'size': size_bytes,
            'size_gb': round(size_bytes / (1024**3), 1) if size_bytes else 0,
            'bus': m.group(1),
            'index': int(m.group(2)),
        })
        total_bytes += size_bytes
        disk_keys.append(key)

    # sort by bus priority: scsi first, then virtio, sata, ide
    bus_order = {'scsi': 0, 'virtio': 1, 'sata': 2, 'ide': 3}
    disks.sort(key=lambda d: (bus_order.get(d['bus'], 9), d['index']))

    # parse networks
    nets = []
    for key, val in raw.items():
        m = re.match(r'^net(\d+)$', key)
        if not m or not isinstance(val, str):
            continue
        # parse model and bridge from value like "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0"
        parts_dict = {}
        model = 'virtio'
        mac = ''
        for p in val.split(','):
            p = p.strip()
            if '=' in p:
                k, v = p.split('=', 1)
                parts_dict[k.strip()] = v.strip()
                # first key=val where key is a NIC model
                if k.strip() in ('virtio', 'e1000', 'e1000e', 'vmxnet3', 'rtl8139'):
                    model = k.strip()
                    mac = v.strip()
        xcp_model = _PVE_NIC_TO_XCP.get(model, 'e1000')
        nets.append({
            'id': key,
            'model': model,
            'mac': mac,
            'bridge': parts_dict.get('bridge', 'vmbr0'),
            'target_model': xcp_model,
        })

    # bios
    bios = raw.get('bios', 'seabios')
    xcp_template = _PVE_TO_XCP_OSTYPE.get(ostype, 'Other install media')

    # XCP-ng targets
    xcpng_targets = _get_xcpng_targets(tgt)
    estimated_seconds = max(30, int(total_bytes / (100 * 1024 * 1024)))

    return {
        'source': {
            'name': vm_name,
            'vcpus': vcpus,
            'memory_mb': int(raw.get('memory', 1024)),
            'memory': memory_bytes,
            'disks': disks,
            'networks': nets,
            'ostype': ostype,
            'bios': bios,
            'xcp_template': xcp_template,
        },
        'targets': xcpng_targets,
        'estimated_seconds': estimated_seconds,
        'direction': 'pve_to_xcpng',
    }


def _parse_pve_size(s):
    """Parse PVE size string like '32G', '500M', '1T' to bytes."""
    s = s.strip().upper()
    multipliers = {'K': 1024, 'M': 1024**2, 'G': 1024**3, 'T': 1024**4}
    for suffix, mult in multipliers.items():
        if s.endswith(suffix):
            try:
                return int(float(s[:-1]) * mult)
            except ValueError:
                return 0
    try:
        return int(s)
    except ValueError:
        return 0


def _get_pve_targets(pve_mgr):
    """List available Proxmox nodes + storages for migration target."""
    targets = []
    nodes = list(pve_mgr.nodes.keys()) if pve_mgr.nodes else []
    node_storages = {}
    node_bridges = {}
    for n in nodes:
        try:
            sr = pve_mgr._api_get(f"https://{pve_mgr.host}:8006/api2/json/nodes/{n}/storage")
            if sr.status_code == 200:
                node_storages[n] = [s['storage'] for s in sr.json().get('data', [])
                                    if s.get('active') and 'images' in s.get('content', '')]
            else:
                node_storages[n] = []
        except:
            node_storages[n] = []
        # bridges
        try:
            nr = pve_mgr._api_get(f"https://{pve_mgr.host}:8006/api2/json/nodes/{n}/network")
            if nr.status_code == 200:
                node_bridges[n] = [iface['iface'] for iface in nr.json().get('data', [])
                                   if iface.get('type') == 'bridge' and iface.get('active')]
            else:
                node_bridges[n] = ['vmbr0']
        except:
            node_bridges[n] = ['vmbr0']

    targets.append({
        'cluster_id': pve_mgr.id,
        'cluster_name': pve_mgr.config.name,
        'type': 'proxmox',
        'nodes': nodes,
        'storages': node_storages,
        'bridges': node_bridges,
    })
    return targets


def _get_xcpng_targets(xcpng_mgr):
    """List available XCP-ng SRs + networks."""
    storages = xcpng_mgr.get_storages()
    networks = xcpng_mgr.get_networks()
    # filter to disk-capable SRs
    disk_srs = [s for s in storages if s.get('type') not in ('iso', 'udev', 'cd')]

    return [{
        'cluster_id': xcpng_mgr.id,
        'cluster_name': xcpng_mgr.config.name,
        'type': 'xcpng',
        'storages': [{'name': s['storage'], 'uuid': s.get('uuid', ''), 'type': s.get('type', ''),
                       'avail': s.get('avail', 0), 'total': s.get('total', 0)} for s in disk_srs],
        'networks': [{'name': n.get('name', ''), 'uuid': n.get('uuid', ''),
                       'bridge': n.get('iface', '')} for n in networks],
    }]


# ============================================================
# Migration engines
# ============================================================

def _run_xcpng_to_pve(task):
    """XCP-ng -> Proxmox: export raw VDI, stream via PegaProx, qm importdisk on target.

    NS: this is the "easy" direction because XCP-ng has a clean HTTP export_raw_vdi
    endpoint and Proxmox qm importdisk handles format conversion.
    """
    import requests as _req

    try:
        src_mgr = cluster_managers.get(task.source_cluster)
        tgt_mgr = cluster_managers.get(task.target_cluster)

        if not src_mgr or not src_mgr.is_connected:
            task.set_phase('failed', 'Source XCP-ng cluster not connected')
            return
        if not tgt_mgr or not tgt_mgr.is_connected:
            task.set_phase('failed', 'Target Proxmox cluster not connected')
            return

        # === PLANNING ===
        task.set_phase('planning')
        task.progress = 2

        api = src_mgr._api()
        if not api:
            task.set_phase('failed', 'Cannot connect to XCP-ng XAPI')
            return

        vm_ref = src_mgr._resolve_vm(task.source_vmid)
        power = api.VM.get_power_state(vm_ref)
        if power != 'Halted':
            task.set_phase('failed', f'VM is {power}, must be Halted')
            return

        vm_rec = api.VM.get_record(vm_ref)
        task.vm_name = task.vm_name or vm_rec.get('name_label', '')
        task.log(f"Source VM: {task.vm_name} ({task.source_vmid})")

        # collect VDIs
        vdi_list = []
        for vbd_ref in vm_rec.get('VBDs', []):
            try:
                vbd = api.VBD.get_record(vbd_ref)
                if vbd.get('type') == 'CD':
                    continue
                vdi_ref = vbd.get('VDI', 'OpaqueRef:NULL')
                if vdi_ref == 'OpaqueRef:NULL':
                    continue
                vdi_rec = api.VDI.get_record(vdi_ref)
                vdi_list.append({
                    'ref': vdi_ref,
                    'uuid': vdi_rec.get('uuid', ''),
                    'size': int(vdi_rec.get('virtual_size', 0)),
                    'name': vdi_rec.get('name_label', ''),
                    'device': vbd.get('userdevice', '0'),
                    'bootable': vbd.get('bootable', False),
                })
            except Exception as exc:
                task.log(f"Skipping VBD: {exc}")

        if not vdi_list:
            task.set_phase('failed', 'No disks found on source VM')
            return

        vdi_list.sort(key=lambda v: int(v['device']))
        task.log(f"Found {len(vdi_list)} disk(s), total {sum(v['size'] for v in vdi_list) / (1024**3):.1f} GB")

        # get next VMID on target
        try:
            nxt = tgt_mgr._api_get(f"https://{tgt_mgr.host}:8006/api2/json/cluster/nextid")
            new_vmid = int(nxt.json().get('data', 100))
        except:
            new_vmid = 100
        task.log(f"Target VMID: {new_vmid}")
        task.target_vmid = new_vmid
        task.progress = 5

        if task.cancel_event.is_set():
            task.set_phase('failed', 'Cancelled by user')
            return

        # === TRANSFER ===
        task.set_phase('transfer')

        session_ref = src_mgr._session._session
        host_url = f"https://{src_mgr.host}"
        ssl_verify = getattr(src_mgr.config, 'ssl_verification', False)

        imported_volumes = []

        for idx, vdi in enumerate(vdi_list):
            if task.cancel_event.is_set():
                task.set_phase('failed', 'Cancelled')
                return

            disk_key = f"disk-{idx}"
            task.log(f"Transferring {vdi['name'] or f'disk {idx}'} ({vdi['size']/(1024**3):.1f} GB)")

            # stream from XCP-ng -> PVE node via SSH pipe
            export_url = f"{host_url}/export_raw_vdi?session_id={session_ref}&vdi={vdi['uuid']}&format=raw"

            try:
                export_resp = _req.get(export_url, stream=True, verify=ssl_verify, timeout=30)
                export_resp.raise_for_status()
            except Exception as e:
                task.set_phase('failed', f'Failed to start VDI export: {e}')
                return

            # NS Mar 2026: stream directly to storage volume via pvesm alloc + dd
            # avoids /tmp temp files that blow up on small root partitions
            total = vdi['size']
            copied = 0
            size_kb = max(1, total // 1024)

            try:
                pve_host = _resolve_pve_node_ip(tgt_mgr, task.target_node)
                if not pve_host:
                    task.set_phase('failed', f'Cannot resolve IP for PVE node {task.target_node}')
                    return

                pve_user = getattr(tgt_mgr.config, 'ssh_user', '') or 'root'
                pve_pass = getattr(tgt_mgr.config, 'pass_', '')
                pve_key = getattr(tgt_mgr.config, 'ssh_key', '')
                pve_port = int(getattr(tgt_mgr.config, 'ssh_port', 22))

                ssh = _connect_ssh(pve_host, pve_user, pve_pass,
                                   key_path=pve_key, port=pve_port)

                # allocate volume on target storage
                alloc_cmd = f"pvesm alloc {task.target_storage} {new_vmid} '' {size_kb}"
                _, a_out, a_err = ssh.exec_command(alloc_cmd, timeout=30)
                a_exit = a_out.channel.recv_exit_status()
                alloc_output = a_out.read().decode('utf-8', errors='replace').strip()
                # LVM spits warnings before the actual volume line
                # grab the "successfully created 'xxx'" or last non-empty line
                vol_id = ''
                for line in alloc_output.splitlines():
                    line = line.strip()
                    m = re.search(r"successfully created '([^']+)'", line)
                    if m:
                        vol_id = m.group(1)
                        break
                if not vol_id:
                    # fallback: last non-warning line
                    for line in reversed(alloc_output.splitlines()):
                        line = line.strip()
                        if line and not line.startswith('WARNING'):
                            vol_id = line
                            break
                if a_exit != 0 or not vol_id:
                    err_msg = a_err.read().decode('utf-8', errors='replace')[:300]
                    task.set_phase('failed', f'pvesm alloc failed: {err_msg or alloc_output[:300]}')
                    ssh.close()
                    return
                task.log(f"  Allocated {vol_id}")

                # get device/file path
                _, p_out, _ = ssh.exec_command(f"pvesm path {vol_id}", timeout=10)
                p_out.channel.recv_exit_status()
                dev_path = p_out.read().decode('utf-8', errors='replace').strip()
                if not dev_path:
                    task.set_phase('failed', f'pvesm path returned empty for {vol_id}')
                    ssh.close()
                    return

                # MK: stream XCP-ng export into the volume
                # RBD storage returns URI like rbd:pool/image:conf=... which dd can't handle (#272)
                if dev_path.startswith('rbd:'):
                    write_cmd = f"qemu-img dd -f raw -O raw bs=4M if=/dev/stdin of='{dev_path}'"
                else:
                    write_cmd = f"dd of='{dev_path}' bs=4M conv=fdatasync 2>/dev/null"
                dd_in, dd_out, dd_err = ssh.exec_command(write_cmd, timeout=7200)

                for chunk in export_resp.iter_content(chunk_size=_CHUNK_SIZE):
                    if task.cancel_event.is_set():
                        dd_in.close()
                        ssh.close()
                        task.set_phase('failed', 'Cancelled')
                        return
                    dd_in.write(chunk)
                    copied += len(chunk)
                    task.update_progress(disk_key, copied, total)

                dd_in.channel.shutdown_write()
                dd_exit = dd_out.channel.recv_exit_status()
                dd_errmsg = dd_err.read().decode('utf-8', errors='replace')[:300]

                if dd_exit != 0:
                    task.log(f"  dd failed (exit {dd_exit}): {dd_errmsg}")
                    # try to free the volume
                    ssh.exec_command(f"pvesm free {vol_id}", timeout=15)
                    ssh.close()
                    task.set_phase('failed', f'dd to storage failed: {dd_errmsg or "unknown error"}')
                    return

                task.log(f"  Written {copied/(1024**3):.1f} GB to {vol_id}")
                imported_volumes.append({
                    'vol_id': vol_id, 'bootable': vdi.get('bootable', False),
                    'index': idx,
                })
                ssh.close()

            except Exception as e:
                logger.error(f"[XHM:{task.id}] transfer error: {e}")
                task.set_phase('failed', f'Transfer error: {e}')
                return

        if not imported_volumes:
            task.set_phase('failed', 'No disks were imported')
            return

        task.progress = 80

        if task.cancel_event.is_set():
            task.set_phase('failed', 'Cancelled')
            return

        # === CREATING ===
        task.set_phase('creating')

        vm_rec = api.VM.get_record(vm_ref)
        platform = vm_rec.get('platform', {})
        is_win = platform.get('viridian', '').lower() == 'true'
        pve_ostype = _XCP_VIRIDIAN_OSTYPE if is_win else _XCP_DEFAULT_OSTYPE
        memory_mb = int(vm_rec.get('memory_static_max', 1073741824)) // (1024 * 1024)
        vcpus = int(vm_rec.get('VCPUs_max', 1))

        boot_policy = ''
        try:
            boot_policy = api.VM.get_HVM_boot_policy(vm_ref)
        except:
            pass
        bios = 'ovmf' if 'uefi' in boot_policy.lower() else 'seabios'

        # create empty VM shell
        create_data = {
            'vmid': new_vmid,
            'name': task.vm_name,
            'memory': memory_mb,
            'cores': vcpus,
            'sockets': 1,
            'ostype': pve_ostype,
            'bios': bios,
            'scsihw': 'virtio-scsi-single',
            'boot': f'order=scsi0',
        }

        # network
        net_map = task.network_map or {}
        vm_nets = vm_rec.get('VIFs', [])
        for i, vif_ref in enumerate(vm_nets[:4]):  # max 4 NICs
            try:
                vif = api.VIF.get_record(vif_ref)
                src_net = api.network.get_name_label(vif.get('network', 'OpaqueRef:NULL'))
                bridge = net_map.get(src_net, net_map.get(str(i), 'vmbr0'))
                create_data[f'net{i}'] = f'virtio,bridge={bridge}'
            except:
                if i == 0:
                    create_data['net0'] = 'virtio,bridge=vmbr0'

        try:
            resp = tgt_mgr._api_post(
                f"https://{tgt_mgr.host}:8006/api2/json/nodes/{task.target_node}/qemu",
                data=create_data
            )
            if resp.status_code not in (200, 201):
                err_body = resp.json() if resp.headers.get('content-type', '').startswith('application/json') else {}
                task.set_phase('failed', f"Failed to create VM: {err_body.get('errors', resp.text[:200])}")
                return
        except Exception as e:
            task.set_phase('failed', f'VM creation failed: {e}')
            return

        task.log(f"Created VM {new_vmid} on {task.target_node}")
        task.progress = 85

        # === ATTACHING ===
        task.set_phase('attaching')

        for vol_info in imported_volumes:
            try:
                attach_data = {f'scsi{vol_info["index"]}': vol_info['vol_id']}
                resp = tgt_mgr._api_post(
                    f"https://{tgt_mgr.host}:8006/api2/json/nodes/{task.target_node}/qemu/{new_vmid}/config",
                    data=attach_data
                )
                if resp.status_code == 200:
                    task.log(f"Attached {vol_info['vol_id']} as scsi{vol_info['index']}")
                else:
                    task.log(f"Warning: attach scsi{vol_info['index']} returned {resp.status_code}")
            except Exception as e:
                task.log(f"Warning: couldn't attach disk: {e}")

        # EFI disk for UEFI
        if bios == 'ovmf':
            try:
                efi_data = {'efidisk0': f'{task.target_storage}:1,efitype=4m,pre-enrolled-keys=1'}
                tgt_mgr._api_post(
                    f"https://{tgt_mgr.host}:8006/api2/json/nodes/{task.target_node}/qemu/{new_vmid}/config",
                    data=efi_data
                )
                task.log("Added EFI disk")
            except:
                task.log("Warning: EFI disk creation failed (non-critical)")

        task.progress = 92

        # boot order
        try:
            tgt_mgr._api_post(
                f"https://{tgt_mgr.host}:8006/api2/json/nodes/{task.target_node}/qemu/{new_vmid}/config",
                data={'boot': 'order=scsi0'}
            )
        except:
            pass

        # start if requested
        if task.start_after:
            try:
                time.sleep(2)  # give PVE a moment
                tgt_mgr._api_post(
                    f"https://{tgt_mgr.host}:8006/api2/json/nodes/{task.target_node}/qemu/{new_vmid}/status/start",
                    data={}
                )
                task.log(f"Started VM {new_vmid}")
            except Exception as e:
                task.log(f"Auto-start failed: {e}")

        # remove source if requested
        if task.remove_source:
            try:
                api.VM.destroy(vm_ref)
                task.log("Source VM destroyed on XCP-ng")
            except Exception as e:
                task.log(f"Warning: couldn't remove source VM: {e}")

        task.set_phase('completed')
        task.log(f"Migration complete! VM {task.vm_name} -> PVE VMID {new_vmid}")

    except Exception as exc:
        logger.exception(f"[XHM:{task.id}] unhandled error")
        task.set_phase('failed', str(exc))


def _run_pve_to_xcpng(task):
    """Proxmox -> XCP-ng: export raw disk via SSH, import via XAPI HTTP endpoint.

    MK: the harder direction - PVE doesn't have a clean HTTP export,
    so we SSH in and dd/qemu-img convert the disk to raw, then stream
    to XCP-ng's import_raw_vdi endpoint.
    """
    import requests as _req
    import os

    try:
        src_mgr = cluster_managers.get(task.source_cluster)
        tgt_mgr = cluster_managers.get(task.target_cluster)

        if not src_mgr or not src_mgr.is_connected:
            task.set_phase('failed', 'Source Proxmox not connected')
            return
        if not tgt_mgr or not tgt_mgr.is_connected:
            task.set_phase('failed', 'Target XCP-ng not connected')
            return

        # === PLANNING ===
        task.set_phase('planning')
        task.progress = 2

        # get VM config from PVE
        vm_cfg_result = src_mgr.get_vm_config(task.source_node, int(task.source_vmid), 'qemu')
        if not vm_cfg_result.get('success'):
            task.set_phase('failed', f"Failed to get VM config: {vm_cfg_result.get('error')}")
            return

        cfg = vm_cfg_result.get('config', {})
        raw = cfg.get('raw', cfg)

        task.vm_name = task.vm_name or raw.get('name', f'vm-{task.source_vmid}')
        task.log(f"Source VM: {task.vm_name} (VMID {task.source_vmid})")

        ostype = raw.get('ostype', 'l26')
        memory_mb = int(raw.get('memory', 1024))
        vcpus = int(raw.get('cores', 1)) * int(raw.get('sockets', 1))
        bios = raw.get('bios', 'seabios')

        # parse disks
        disks = []
        for key, val in raw.items():
            if not isinstance(val, str):
                continue
            m = re.match(r'^(scsi|virtio|sata|ide)(\d+)$', key)
            if not m:
                continue
            if 'media=cdrom' in val or 'none' in val.split(',')[0]:
                continue
            # skip EFI/TPM
            if key in ('efidisk0', 'tpmstate0'):
                continue
            parts = val.split(',')
            vol_id = parts[0].strip()
            size_str = ''
            for p in parts[1:]:
                p = p.strip()
                if p.startswith('size='):
                    size_str = p.split('=')[1]
            size_bytes = _parse_pve_size(size_str) if size_str else 0
            disks.append({
                'key': key, 'volume': vol_id, 'size': size_bytes,
                'bus': m.group(1), 'index': int(m.group(2)),
            })

        bus_order = {'scsi': 0, 'virtio': 1, 'sata': 2, 'ide': 3}
        disks.sort(key=lambda d: (bus_order.get(d['bus'], 9), d['index']))

        if not disks:
            task.set_phase('failed', 'No disks found')
            return

        task.log(f"Found {len(disks)} disk(s)")

        # resolve disk paths on PVE node
        pve_host = _resolve_pve_node_ip(src_mgr, task.source_node)
        if not pve_host:
            task.set_phase('failed', f"Can't resolve PVE node {task.source_node}")
            return

        for d in disks:
            rc, out, err = _pve_node_exec(src_mgr, task.source_node,
                                          f"pvesm path {d['volume']}", timeout=30)
            if rc == 0 and out.strip():
                d['path'] = out.strip()
                # detect format
                if '/images/' in d['path'] and d['path'].endswith('.qcow2'):
                    d['format'] = 'qcow2'
                else:
                    d['format'] = 'raw'
            else:
                # fallback: try to figure out path from volume id
                d['path'] = None
                d['format'] = 'raw'
            task.log(f"  {d['key']}: {d['volume']} -> {d.get('path', 'unknown')} ({d['format']})")

        task.progress = 5

        if task.cancel_event.is_set():
            task.set_phase('failed', 'Cancelled')
            return

        # === TRANSFER ===
        task.set_phase('transfer')

        xapi = tgt_mgr._api()
        if not xapi:
            task.set_phase('failed', 'Cannot connect to XCP-ng XAPI')
            return

        try:
            session_ref = tgt_mgr._session._session
        except AttributeError:
            task.set_phase('failed', 'Cannot get XAPI session ref')
            return

        xcp_host_url = f"https://{tgt_mgr.host}"
        ssl_verify = getattr(tgt_mgr.config, 'ssl_verification', False)

        # find target SR
        target_sr_ref = None
        try:
            sr_refs = xapi.SR.get_all()
            for sr_ref in sr_refs:
                sr_rec = xapi.SR.get_record(sr_ref)
                sr_name = sr_rec.get('name_label', '')
                sr_uuid = sr_rec.get('uuid', '')
                if sr_name == task.target_storage or sr_uuid == task.target_storage:
                    target_sr_ref = sr_ref
                    break
        except Exception as e:
            task.set_phase('failed', f'Failed to find target SR: {e}')
            return

        if not target_sr_ref:
            task.set_phase('failed', f'Storage repository "{task.target_storage}" not found on XCP-ng')
            return

        created_vdis = []  # keep track for attaching later

        for idx, disk in enumerate(disks):
            if task.cancel_event.is_set():
                task.set_phase('failed', 'Cancelled')
                return

            disk_key = f"disk-{idx}"
            total = disk['size']
            task.log(f"Transferring {disk['key']} ({total/(1024**3):.1f} GB)")

            if not disk.get('path'):
                task.log(f"  Skipping {disk['key']}: couldn't resolve path")
                continue

            # create VDI on target SR
            vdi_rec = {
                'name_label': f"{task.vm_name} disk {idx}",
                'name_description': f'Migrated from Proxmox (VMID {task.source_vmid})',
                'SR': target_sr_ref,
                'virtual_size': str(total),
                'type': 'user',
                'sharable': False,
                'read_only': False,
                'other_config': {},
            }
            try:
                new_vdi_ref = xapi.VDI.create(vdi_rec)
                new_vdi_uuid = xapi.VDI.get_uuid(new_vdi_ref)
            except Exception as e:
                task.set_phase('failed', f'VDI creation failed: {e}')
                return

            task.log(f"  Created VDI {new_vdi_uuid}")

            # SSH into PVE, stream disk -> PegaProx -> HTTP PUT to XCP-ng
            try:
                pve_user = getattr(src_mgr.config, 'ssh_user', '') or 'root'
                pve_pass = getattr(src_mgr.config, 'pass_', '')
                pve_key = getattr(src_mgr.config, 'ssh_key', '')
                pve_port = int(getattr(src_mgr.config, 'ssh_port', 22))

                ssh = _connect_ssh(pve_host, pve_user, pve_pass,
                                   key_path=pve_key, port=pve_port)

                # NS: for LVM-thin (local-lvm), the LV might not be activated
                # when the VM is stopped. Activate before reading.
                if '/dev/' in disk['path']:
                    ssh.exec_command(f"lvchange -ay '{disk['path']}' 2>/dev/null", timeout=10)
                    time.sleep(0.5)  # give udev a moment

                # build export command — #272: rbd URIs need qemu-img, dd can't read them
                if disk['format'] == 'qcow2':
                    export_cmd = f"qemu-img convert -f qcow2 -O raw '{disk['path']}' /dev/stdout"
                elif disk['path'].startswith('rbd:'):
                    export_cmd = f"qemu-img dd -f raw -O raw bs=4M if='{disk['path']}' of=/dev/stdout"
                else:
                    export_cmd = f"dd if='{disk['path']}' bs=4M status=none"

                stdin_ch, stdout_ch, stderr_ch = ssh.exec_command(export_cmd, timeout=7200)
                stdout_stream = stdout_ch

                # quick sanity: wait a moment and check if cmd already died
                time.sleep(1)
                if stdout_ch.channel.exit_status_ready():
                    exit_code = stdout_ch.channel.recv_exit_status()
                    err_out = stderr_ch.read().decode('utf-8', errors='replace')[:500]
                    ssh.close()
                    task.log(f"  Export command failed (exit {exit_code}): {err_out}")
                    try:
                        xapi.VDI.destroy(new_vdi_ref)
                    except:
                        pass
                    task.set_phase('failed', f'Disk export failed: {err_out[:200] or "no output"}')
                    return

                # upload to XCP-ng via import_raw_vdi
                import_url = (f"{xcp_host_url}/import_raw_vdi?"
                              f"session_id={session_ref}&vdi={new_vdi_uuid}&format=raw")

                # NS: must use file-like wrapper, not generator - requests adds
                # Transfer-Encoding: chunked for generators even with Content-Length
                # and XAPI chokes on the conflicting headers
                body = _StreamBody(stdout_stream, total,
                                   lambda n: task.update_progress(disk_key, n, total))

                resp = _req.put(import_url, data=body, verify=ssl_verify,
                                headers={'Content-Type': 'application/octet-stream'},
                                timeout=7200)
                copied = body._read

                # read stderr in case dd had warnings
                try:
                    dd_err = stderr_ch.read().decode('utf-8', errors='replace')[:500]
                    if dd_err.strip():
                        task.log(f"  dd stderr: {dd_err.strip()}")
                except:
                    pass

                ssh.close()

                if resp.status_code not in (200, 204):
                    task.log(f"  import_raw_vdi failed: HTTP {resp.status_code}")
                    try:
                        xapi.VDI.destroy(new_vdi_ref)
                    except:
                        pass
                    task.set_phase('failed', f'VDI import failed: HTTP {resp.status_code}')
                    return

                # catch empty transfers - dd might have failed silently
                if copied == 0:
                    task.log(f"  Transfer produced 0 bytes - disk may not exist or be inaccessible")
                    try:
                        xapi.VDI.destroy(new_vdi_ref)
                    except:
                        pass
                    task.set_phase('failed', 'Disk transfer produced 0 bytes')
                    return

                task.log(f"  Imported {copied/(1024**3):.1f} GB to VDI {new_vdi_uuid}")
                created_vdis.append({
                    'ref': new_vdi_ref,
                    'uuid': new_vdi_uuid,
                    'index': idx,
                    'bootable': idx == 0,
                })

            except Exception as e:
                logger.error(f"[XHM:{task.id}] disk transfer error: {e}")
                try:
                    xapi.VDI.destroy(new_vdi_ref)
                except:
                    pass
                task.set_phase('failed', f'Disk transfer error: {e}')
                return

        if not created_vdis:
            task.set_phase('failed', 'No disks transferred')
            return

        task.progress = 80

        # === CREATING ===
        task.set_phase('creating')

        xcp_template = _PVE_TO_XCP_OSTYPE.get(ostype, 'Other install media')
        task.log(f"Creating XCP-ng VM from template: {xcp_template}")

        # find template
        vm_template_ref = None
        try:
            all_vms = xapi.VM.get_all()
            for tpl_ref in all_vms:
                if xapi.VM.get_is_a_template(tpl_ref):
                    label = xapi.VM.get_name_label(tpl_ref)
                    if label == xcp_template:
                        vm_template_ref = tpl_ref
                        break
            if not vm_template_ref:
                # fallback to 'Other install media'
                for tpl_ref in all_vms:
                    if xapi.VM.get_is_a_template(tpl_ref):
                        label = xapi.VM.get_name_label(tpl_ref)
                        if label == 'Other install media':
                            vm_template_ref = tpl_ref
                            break
        except Exception as e:
            task.set_phase('failed', f'Template search failed: {e}')
            return

        if not vm_template_ref:
            task.set_phase('failed', 'No suitable XCP-ng template found')
            return

        # clone template
        try:
            new_vm_ref = xapi.VM.clone(vm_template_ref, task.vm_name)
            xapi.VM.set_is_a_template(new_vm_ref, False)
        except Exception as e:
            task.set_phase('failed', f'VM clone from template failed: {e}')
            return

        # configure VM
        try:
            # remove template VBDs first (they have empty disks)
            for old_vbd in xapi.VM.get_VBDs(new_vm_ref):
                try:
                    old_vbd_rec = xapi.VBD.get_record(old_vbd)
                    if old_vbd_rec.get('type') == 'Disk':
                        old_vdi = old_vbd_rec.get('VDI', 'OpaqueRef:NULL')
                        xapi.VBD.destroy(old_vbd)
                        if old_vdi != 'OpaqueRef:NULL':
                            try:
                                xapi.VDI.destroy(old_vdi)
                            except:
                                pass
                except:
                    pass

            # set properties
            xapi.VM.set_name_description(new_vm_ref,
                f'Migrated from Proxmox (VMID {task.source_vmid}) by PegaProx')
            xapi.VM.set_VCPUs_max(new_vm_ref, str(vcpus))
            xapi.VM.set_VCPUs_at_startup(new_vm_ref, str(vcpus))

            mem_bytes = str(memory_mb * 1024 * 1024)
            xapi.VM.set_memory_limits(new_vm_ref, mem_bytes, mem_bytes, mem_bytes, mem_bytes)

            # boot policy
            if bios == 'ovmf':
                xapi.VM.set_HVM_boot_policy(new_vm_ref, 'BIOS order')
                # UEFI: set firmware to uefi in platform
                platform = xapi.VM.get_platform(new_vm_ref)
                platform['device-model'] = 'qemu-upstream-uefi'
                xapi.VM.set_platform(new_vm_ref, platform)
            else:
                xapi.VM.set_HVM_boot_policy(new_vm_ref, 'BIOS order')
                xapi.VM.set_HVM_boot_params(new_vm_ref, {'order': 'cd'})

        except Exception as e:
            task.log(f"Warning: VM config failed: {e}")

        new_uuid = xapi.VM.get_uuid(new_vm_ref)
        task.log(f"Created VM {task.vm_name} (UUID: {new_uuid})")
        task.progress = 85

        # === ATTACHING ===
        task.set_phase('attaching')

        # attach VDIs
        for vdi_info in created_vdis:
            try:
                vbd_rec = {
                    'VM': new_vm_ref,
                    'VDI': vdi_info['ref'],
                    'userdevice': str(vdi_info['index']),
                    'bootable': vdi_info['bootable'],
                    'mode': 'RW',
                    'type': 'Disk',
                    'empty': False,
                    'other_config': {},
                    'qos_algorithm_type': '',
                    'qos_algorithm_params': {},
                }
                xapi.VBD.create(vbd_rec)
                task.log(f"Attached VDI {vdi_info['uuid']} as device {vdi_info['index']}")
            except Exception as e:
                task.log(f"Warning: VBD attach failed for device {vdi_info['index']}: {e}")

        # attach networks
        net_map = task.network_map or {}
        pve_nets = []
        for key, val in raw.items():
            nm = re.match(r'^net(\d+)$', key)
            if nm and isinstance(val, str):
                pve_nets.append((int(nm.group(1)), val))
        pve_nets.sort(key=lambda x: x[0])

        for net_idx, net_val in pve_nets[:4]:
            # parse bridge from PVE net config
            pve_bridge = 'vmbr0'
            for p in net_val.split(','):
                if p.strip().startswith('bridge='):
                    pve_bridge = p.strip().split('=')[1]
            target_net = net_map.get(pve_bridge, net_map.get(str(net_idx), ''))

            if target_net:
                try:
                    _xcp_attach_network(xapi, new_vm_ref, target_net, str(net_idx))
                    task.log(f"Attached network {target_net} as device {net_idx}")
                except Exception as e:
                    task.log(f"Warning: network attach failed: {e}")

        task.progress = 95

        # start if requested
        if task.start_after:
            try:
                time.sleep(2)
                xapi.Async.VM.start(new_vm_ref, False, False)
                task.log(f"Started VM on XCP-ng")
            except Exception as e:
                task.log(f"Auto-start failed: {e}")

        # cleanup source
        if task.remove_source:
            try:
                _pve_node_exec(src_mgr, task.source_node,
                               f"qm destroy {task.source_vmid} --purge", timeout=120)
                task.log("Source VM destroyed on Proxmox")
            except Exception as e:
                task.log(f"Source cleanup failed: {e}")

        # register VMID in XCP-ng DB
        try:
            from pegaprox.core.db import get_db
            db = get_db()
            new_vmid = db.xcpng_get_vmid(tgt_mgr.id, new_uuid)
            task.target_vmid = new_vmid
        except:
            task.target_vmid = new_uuid

        task.set_phase('completed')
        task.log(f"Migration complete! {task.vm_name} -> XCP-ng ({new_uuid})")

    except Exception as exc:
        logger.exception(f"[XHM:{task.id}] unhandled error in pve_to_xcpng")
        task.set_phase('failed', str(exc))


# ============================================================
# helpers
# ============================================================

def _resolve_pve_node_ip(pve_mgr, node_name):
    """Get the SSH-reachable IP of a Proxmox node. Tries API, then cluster host."""
    try:
        nr = pve_mgr._api_get(
            f"https://{pve_mgr.host}:8006/api2/json/nodes/{node_name}/network")
        if nr.status_code == 200:
            for iface in nr.json().get('data', []):
                if iface.get('type') == 'bridge' and iface.get('address'):
                    return iface['address']
    except:
        pass
    # fallback: use cluster host if single-node or node matches
    try:
        if hasattr(pve_mgr, 'nodes') and pve_mgr.nodes:
            node_info = pve_mgr.nodes.get(node_name, {})
            if node_info.get('ip'):
                return node_info['ip']
    except:
        pass
    return pve_mgr.host


def _connect_ssh(host, user, password, key_path=None, port=22):
    """Connect to SSH with multiple auth methods (matches _ssh_exec behavior).
    Returns connected paramiko.SSHClient or raises Exception."""
    import paramiko

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # try key-based first
    if key_path and os.path.exists(key_path):
        try:
            client.connect(host, port=port, username=user,
                           key_filename=key_path, timeout=30)
            return client
        except Exception as e:
            logger.debug(f"[SSH] key auth failed for {user}@{host}: {e}")

    # keyboard-interactive via Transport (some hosts require this)
    try:
        transport = paramiko.Transport((host, port))
        transport.connect()

        def _ki_handler(title, instructions, prompt_list):
            return [password] * len(prompt_list)

        transport.auth_interactive(user, _ki_handler)
        if transport.is_authenticated():
            client._transport = transport
            return client
        transport.close()
    except Exception as e:
        logger.debug(f"[SSH] keyboard-interactive failed for {user}@{host}: {e}")
        try:
            transport.close()
        except Exception:
            pass

    # standard password auth
    client2 = paramiko.SSHClient()
    client2.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client2.connect(host, port=port, username=user, password=password,
                    timeout=30, allow_agent=False, look_for_keys=False)
    return client2


def _ssh_cleanup(ssh, path):
    """Remove temp file via SSH, ignore errors."""
    try:
        ssh.exec_command(f"rm -f '{path}'", timeout=10)
    except:
        pass


def _xcp_attach_network(api, vm_ref, net_ident, device='0'):
    """Attach a VIF to an XCP-ng VM. net_ident can be UUID or name."""
    net_ref = None
    # try UUID
    try:
        net_ref = api.network.get_by_uuid(net_ident)
    except:
        pass
    # try name/bridge
    if not net_ref:
        for ref in api.network.get_all():
            rec = api.network.get_record(ref)
            if rec.get('name_label') == net_ident or rec.get('bridge') == net_ident:
                net_ref = ref
                break
    if not net_ref:
        raise ValueError(f"Network '{net_ident}' not found")

    # find free device
    existing = api.VM.get_VIFs(vm_ref)
    used = set()
    for vif_ref in existing:
        try:
            used.add(api.VIF.get_device(vif_ref))
        except:
            pass
    while device in used:
        device = str(int(device) + 1)

    vif_record = {
        'VM': vm_ref,
        'network': net_ref,
        'device': device,
        'MTU': '1500',
        'MAC': '',
        'other_config': {},
        'qos_algorithm_type': '',
        'qos_algorithm_params': {},
    }
    api.VIF.create(vif_record)


# ═══════════════════════════════════════════════════════════════
# ESXi Migration Support - NS Mar 2026
# ═══════════════════════════════════════════════════════════════

def plan_esxi_to_pve(source_cluster_id, source_vmid, target_cluster_id):
    """Build migration plan for ESXi -> Proxmox."""
    src = cluster_managers.get(source_cluster_id)
    if not src or getattr(src, 'cluster_type', '') != 'esxi':
        return {'error': 'Source ESXi cluster not found'}

    tgt = cluster_managers.get(target_cluster_id)
    if not tgt or getattr(tgt, 'cluster_type', 'proxmox') != 'proxmox':
        return {'error': 'Target must be a Proxmox cluster'}

    if not src.is_connected:
        return {'error': 'Source ESXi not connected'}
    if not tgt.is_connected:
        return {'error': 'Target Proxmox not connected'}

    export_info = src.get_vm_disks_for_export(source_vmid)
    if 'error' in export_info:
        return export_info
    data = export_info.get('data', {})

    if data.get('power_state', '').upper() == 'POWERED_ON':
        return {'error': 'VM must be powered off before migration'}

    guest_os = data.get('guest_os', '')
    pve_ostype = _ESXI_TO_PVE_OSTYPE.get(guest_os, 'l26')
    is_windows = 'win' in guest_os.lower()

    disks_info = []
    total_bytes = 0
    for d in data.get('disks', []):
        cap = d.get('capacity_bytes', 0)
        disks_info.append({
            'key': d.get('key', ''),
            'label': d.get('label', ''),
            'vmdk_file': d.get('vmdk_file', ''),
            'size': cap,
            'size_gb': round(cap / (1024**3), 1) if cap else 0,
            'thin': d.get('thin', False),
        })
        total_bytes += cap

    pve_targets = _get_pve_targets(tgt)

    return {
        'source': {
            'name': data.get('name', ''),
            'vcpus': data.get('cpu_count', 1),
            'memory_mb': data.get('memory_mb', 1024),
            'disks': disks_info,
            'networks': [],  # TODO: parse ESXi NICs
            'ostype': pve_ostype,
            'bios': 'seabios',
            'is_windows': is_windows,
            'guest_os': guest_os,
        },
        'targets': pve_targets,
        'estimated_seconds': max(60, int(total_bytes / (80 * 1024 * 1024))),
        'direction': 'esxi_to_pve',
    }


def plan_esxi_to_xcpng(source_cluster_id, source_vmid, target_cluster_id):
    """Build migration plan for ESXi -> XCP-ng."""
    src = cluster_managers.get(source_cluster_id)
    if not src or getattr(src, 'cluster_type', '') != 'esxi':
        return {'error': 'Source ESXi cluster not found'}

    tgt = cluster_managers.get(target_cluster_id)
    if not tgt or getattr(tgt, 'cluster_type', '') != 'xcpng':
        return {'error': 'Target must be an XCP-ng cluster'}

    if not src.is_connected:
        return {'error': 'Source ESXi not connected'}
    if not tgt.is_connected:
        return {'error': 'Target XCP-ng not connected'}

    export_info = src.get_vm_disks_for_export(source_vmid)
    if 'error' in export_info:
        return export_info
    data = export_info.get('data', {})

    if data.get('power_state', '').upper() == 'POWERED_ON':
        return {'error': 'VM must be powered off before migration'}

    guest_os = data.get('guest_os', '')
    xcp_template = _ESXI_TO_XCP_OSTYPE.get(guest_os, 'Other install media')

    disks_info = []
    total_bytes = 0
    for d in data.get('disks', []):
        cap = d.get('capacity_bytes', 0)
        disks_info.append({
            'key': d.get('key', ''),
            'label': d.get('label', ''),
            'vmdk_file': d.get('vmdk_file', ''),
            'size': cap,
            'size_gb': round(cap / (1024**3), 1) if cap else 0,
        })
        total_bytes += cap

    xcp_targets = _get_xcpng_targets(tgt)

    return {
        'source': {
            'name': data.get('name', ''),
            'vcpus': data.get('cpu_count', 1),
            'memory_mb': data.get('memory_mb', 1024),
            'disks': disks_info,
            'networks': [],
            'template': xcp_template,
            'guest_os': guest_os,
        },
        'targets': xcp_targets,
        'estimated_seconds': max(60, int(total_bytes / (80 * 1024 * 1024))),
        'direction': 'esxi_to_xcpng',
    }


def _run_esxi_to_pve(task):
    """ESXi -> Proxmox: SSHFS mount ESXi datastore, qemu-img convert VMDK to target storage.

    NS: same approach as V2P but integrated into XHM framework.
    Requires: qemu-img and sshfs on the target PVE node.
    """
    import requests as _req

    try:
        src_mgr = cluster_managers.get(task.source_cluster)
        tgt_mgr = cluster_managers.get(task.target_cluster)

        if not src_mgr or not src_mgr.is_connected:
            task.set_phase('failed', 'Source ESXi not connected')
            return
        if not tgt_mgr or not tgt_mgr.is_connected:
            task.set_phase('failed', 'Target Proxmox not connected')
            return

        # === PLANNING ===
        task.set_phase('planning')
        task.progress = 2

        export_info = src_mgr.get_vm_disks_for_export(task.source_vmid)
        if 'error' in export_info:
            task.set_phase('failed', f"Can't read ESXi VM: {export_info['error']}")
            return

        data = export_info.get('data', {})
        disks = data.get('disks', [])
        guest_os = data.get('guest_os', '')
        pve_ostype = _ESXI_TO_PVE_OSTYPE.get(guest_os, 'l26')
        is_windows = 'win' in guest_os.lower()
        memory_mb = data.get('memory_mb', 1024)
        cpu_count = data.get('cpu_count', 1)

        task.log(f"Source VM: {data.get('name', task.vm_name)} ({len(disks)} disk(s))")

        if not disks:
            task.set_phase('failed', 'No disks found on ESXi VM')
            return

        # resolve PVE node IP
        pve_host = _resolve_pve_node_ip(tgt_mgr, task.target_node)
        if not pve_host:
            task.set_phase('failed', f"Can't resolve PVE node {task.target_node}")
            return

        # allocate VMID
        new_vmid = task.target_vmid or _next_pve_vmid(tgt_mgr)
        if not new_vmid:
            task.set_phase('failed', 'Cannot allocate VMID')
            return
        task.target_vmid = new_vmid
        task.log(f"Target VMID: {new_vmid}")

        task.progress = 5

        # === TRANSFER ===
        task.set_phase('transfer')

        esxi_host = src_mgr.host
        esxi_user = getattr(src_mgr.config, 'ssh_user', 'root')
        esxi_pass = getattr(src_mgr.config, 'pass_', '')
        pve_user = getattr(tgt_mgr.config, 'ssh_user', '') or 'root'
        pve_pass = getattr(tgt_mgr.config, 'pass_', '')
        pve_key = getattr(tgt_mgr.config, 'ssh_key', '')
        pve_port = int(getattr(tgt_mgr.config, 'ssh_port', 22))

        imported_volumes = []
        mount_base = f"/tmp/xhm-esxi-{task.id}"

        for idx, disk in enumerate(disks):
            if task.cancel_event.is_set():
                task.set_phase('failed', 'Cancelled')
                return

            vmdk = disk.get('vmdk_file', '')
            cap = disk.get('capacity_bytes', 0)
            disk_key = f"disk-{idx}"

            if not vmdk:
                task.log(f"  Skipping disk {idx}: no VMDK path")
                continue

            task.log(f"Transferring {disk.get('label', f'disk {idx}')} ({disk.get('capacity_gb', 0)} GB)")

            # parse datastore from VMDK path: [datastore1] vm/vm.vmdk
            ds_match = re.match(r'\[(.+?)\]\s*(.+)', vmdk)
            if not ds_match:
                task.set_phase('failed', f'Cannot parse VMDK path: {vmdk}')
                return
            datastore_name = ds_match.group(1)
            vmdk_rel_path = ds_match.group(2)

            # find flat vmdk (actual data file)
            flat_path = vmdk_rel_path
            if flat_path.endswith('.vmdk') and '-flat.vmdk' not in flat_path:
                flat_path = flat_path.replace('.vmdk', '-flat.vmdk')

            try:
                ssh_pve = _connect_ssh(pve_host, pve_user, pve_pass,
                                       key_path=pve_key, port=pve_port)

                # MK Apr 2026 (#359) — VMware datastore folders / VM-name folders can
                # legitimately contain spaces (and parens). Every shell interpolation
                # below has to be `shlex.quote`'d both for the LOCAL command (run on
                # the PVE node) and ALSO single-quoted for the REMOTE SCP/SSH side
                # because scp passes the remote arg through a remote shell.
                import shlex as _shlex
                def _q_local(s): return _shlex.quote(str(s))
                def _q_remote(s):
                    # safest cross-shell quoting for the remote side: single-quote
                    # and escape any embedded apostrophes by closing+reopening.
                    return "'" + str(s).replace("'", "'\"'\"'") + "'"

                vm_folder = vmdk_rel_path.split('/')[0]

                # create SSHFS mount on PVE node to ESXi datastore
                mount_dir = f"{mount_base}-{idx}"
                mount_cmds = [
                    f"mkdir -p {_q_local(mount_dir)}",
                    f"sshfs -o StrictHostKeyChecking=no,password_stdin "
                    f"{_q_local(esxi_user + '@' + esxi_host + ':/vmfs/volumes/' + datastore_name)} "
                    f"{_q_local(mount_dir)} <<< {_q_local(esxi_pass)}",
                ]
                for cmd in mount_cmds:
                    _, out, err = ssh_pve.exec_command(cmd, timeout=30)
                    out.channel.recv_exit_status()

                # check mount worked
                _, chk_out, _ = ssh_pve.exec_command(
                    f"ls {_q_local(mount_dir + '/' + vm_folder + '/')} 2>/dev/null | head -3",
                    timeout=10,
                )
                chk_out.channel.recv_exit_status()
                if not chk_out.read().decode().strip():
                    # sshfs might not work, try NFS or direct copy fallback
                    task.log(f"  SSHFS mount failed, trying scp fallback")
                    # cleanup failed mount
                    ssh_pve.exec_command(
                        f"fusermount -u {_q_local(mount_dir)} 2>/dev/null; "
                        f"rmdir {_q_local(mount_dir)} 2>/dev/null",
                        timeout=10,
                    )

                    # fallback: scp the flat vmdk to temp, then import
                    # remote source path needs single-quoting on top of local
                    # quoting because scp invokes a remote shell.
                    tmp_path = f"/tmp/xhm-{task.id}-disk{idx}.vmdk"
                    remote_src = f"{esxi_user}@{esxi_host}:" + _q_remote('/vmfs/volumes/' + datastore_name + '/' + flat_path)
                    scp_cmd = (
                        f"sshpass -p {_q_local(esxi_pass)} "
                        f"scp -o StrictHostKeyChecking=no "
                        f"{_q_local(remote_src)} {_q_local(tmp_path)}"
                    )
                    _, scp_out, scp_err = ssh_pve.exec_command(scp_cmd, timeout=7200)
                    scp_exit = scp_out.channel.recv_exit_status()
                    if scp_exit != 0:
                        err_msg = scp_err.read().decode()[:200]
                        task.set_phase('failed', f'SCP failed: {err_msg}')
                        ssh_pve.close()
                        return

                    # allocate volume and convert
                    size_kb = max(1, cap // 1024)
                    alloc_cmd = f"pvesm alloc {task.target_storage} {new_vmid} '' {size_kb}"
                    _, a_out, a_err = ssh_pve.exec_command(alloc_cmd, timeout=30)
                    a_out.channel.recv_exit_status()
                    alloc_output = a_out.read().decode().strip()
                    vol_id = ''
                    for line in alloc_output.splitlines():
                        m = re.search(r"successfully created '([^']+)'", line)
                        if m:
                            vol_id = m.group(1)
                            break
                    if not vol_id:
                        for line in reversed(alloc_output.splitlines()):
                            line = line.strip()
                            if line and not line.startswith('WARNING'):
                                vol_id = line
                                break

                    if not vol_id:
                        task.set_phase('failed', f'pvesm alloc failed: {alloc_output[:200]}')
                        ssh_pve.close()
                        return

                    # get device path
                    _, p_out, _ = ssh_pve.exec_command(f"pvesm path {vol_id}", timeout=10)
                    p_out.channel.recv_exit_status()
                    dev_path = p_out.read().decode().strip()

                    # qemu-img convert vmdk -> raw directly to storage
                    conv_cmd = f"qemu-img convert -f vmdk -O raw '{tmp_path}' '{dev_path}'"
                    task.log(f"  Converting VMDK to raw...")
                    _, conv_out, conv_err = ssh_pve.exec_command(conv_cmd, timeout=7200)
                    conv_exit = conv_out.channel.recv_exit_status()
                    if conv_exit != 0:
                        err_msg = conv_err.read().decode()[:200]
                        ssh_pve.exec_command(f"rm -f {tmp_path}", timeout=10)
                        task.set_phase('failed', f'qemu-img convert failed: {err_msg}')
                        ssh_pve.close()
                        return

                    # cleanup temp
                    ssh_pve.exec_command(f"rm -f {tmp_path}", timeout=10)
                    task.log(f"  Imported as {vol_id}")
                    imported_volumes.append({'vol_id': vol_id, 'bootable': idx == 0, 'index': idx})
                    ssh_pve.close()
                    continue

                # SSHFS worked - convert directly from mount
                sshfs_vmdk = f"{mount_dir}/{flat_path}"
                size_kb = max(1, cap // 1024)

                alloc_cmd = f"pvesm alloc {task.target_storage} {new_vmid} '' {size_kb}"
                _, a_out, a_err = ssh_pve.exec_command(alloc_cmd, timeout=30)
                a_out.channel.recv_exit_status()
                alloc_output = a_out.read().decode().strip()
                vol_id = ''
                for line in alloc_output.splitlines():
                    m = re.search(r"successfully created '([^']+)'", line)
                    if m:
                        vol_id = m.group(1)
                        break
                if not vol_id:
                    for line in reversed(alloc_output.splitlines()):
                        line = line.strip()
                        if line and not line.startswith('WARNING'):
                            vol_id = line
                            break

                _, p_out, _ = ssh_pve.exec_command(f"pvesm path {vol_id}", timeout=10)
                p_out.channel.recv_exit_status()
                dev_path = p_out.read().decode().strip()

                # convert from SSHFS mount directly to storage volume
                conv_cmd = f"qemu-img convert -p -f vmdk -O raw '{sshfs_vmdk}' '{dev_path}'"
                task.log(f"  Converting via SSHFS → {vol_id}")
                _, conv_out, conv_err = ssh_pve.exec_command(conv_cmd, timeout=7200)
                conv_exit = conv_out.channel.recv_exit_status()

                # unmount SSHFS
                ssh_pve.exec_command(f"fusermount -u {mount_dir} 2>/dev/null; rmdir {mount_dir} 2>/dev/null", timeout=10)

                if conv_exit != 0:
                    err_msg = conv_err.read().decode()[:200]
                    task.set_phase('failed', f'qemu-img convert failed: {err_msg}')
                    ssh_pve.close()
                    return

                task.log(f"  Imported as {vol_id}")
                imported_volumes.append({'vol_id': vol_id, 'bootable': idx == 0, 'index': idx})
                ssh_pve.close()
                task.update_progress(disk_key, cap, cap)

            except Exception as e:
                logger.error(f"[XHM:{task.id}] ESXi disk transfer error: {e}")
                task.set_phase('failed', f'Transfer error: {e}')
                return

        if not imported_volumes:
            task.set_phase('failed', 'No disks imported')
            return

        task.progress = 80

        # === CREATING ===
        task.set_phase('creating')

        create_data = {
            'vmid': new_vmid,
            'name': task.vm_name,
            'memory': memory_mb,
            'cores': cpu_count,
            'sockets': 1,
            'ostype': pve_ostype,
            'bios': 'seabios',
            'scsihw': 'virtio-scsi-single',
            'boot': 'order=scsi0',
            'net0': 'virtio,bridge=vmbr0',
        }

        try:
            resp = tgt_mgr._api_post(
                f"https://{tgt_mgr.host}:8006/api2/json/nodes/{task.target_node}/qemu",
                data=create_data
            )
            if resp.status_code not in (200, 201):
                err_body = resp.json() if 'json' in resp.headers.get('content-type', '') else {}
                task.set_phase('failed', f"VM creation failed: {err_body.get('errors', resp.text[:200])}")
                return
        except Exception as e:
            task.set_phase('failed', f'VM creation failed: {e}')
            return

        task.log(f"Created VM {new_vmid}")
        task.progress = 85

        # === ATTACHING ===
        task.set_phase('attaching')
        for vol in imported_volumes:
            try:
                attach_data = {f'scsi{vol["index"]}': vol['vol_id']}
                resp = tgt_mgr._api_post(
                    f"https://{tgt_mgr.host}:8006/api2/json/nodes/{task.target_node}/qemu/{new_vmid}/config",
                    data=attach_data
                )
                if resp.status_code == 200:
                    task.log(f"Attached {vol['vol_id']} as scsi{vol['index']}")
                else:
                    task.log(f"Warning: attach scsi{vol['index']} returned {resp.status_code}")
            except Exception as e:
                task.log(f"Warning: attach failed: {e}")

        task.progress = 95
        task.set_phase('completed')
        task.log(f"Migration complete: ESXi VM -> PVE {new_vmid}")

    except Exception as e:
        logger.error(f"[XHM:{task.id}] ESXi->PVE failed: {e}")
        task.set_phase('failed', f'Migration error: {e}')


def _run_esxi_to_xcpng(task):
    """ESXi -> XCP-ng: SSHFS mount on PegaProx host, qemu-img convert VMDK to raw,
    stream to XCP-ng import_raw_vdi.

    MK: needs qemu-img on the machine running PegaProx (or on the XCP-ng host).
    Uses PegaProx server as relay since ESXi can't do qemu-img and XCP-ng
    can't mount ESXi datastores directly.
    """
    import requests as _req
    import subprocess

    try:
        src_mgr = cluster_managers.get(task.source_cluster)
        tgt_mgr = cluster_managers.get(task.target_cluster)

        if not src_mgr or not src_mgr.is_connected:
            task.set_phase('failed', 'Source ESXi not connected')
            return
        if not tgt_mgr or not tgt_mgr.is_connected:
            task.set_phase('failed', 'Target XCP-ng not connected')
            return

        task.set_phase('planning')
        task.progress = 2

        export_info = src_mgr.get_vm_disks_for_export(task.source_vmid)
        if 'error' in export_info:
            task.set_phase('failed', f"Can't read ESXi VM: {export_info['error']}")
            return

        data = export_info.get('data', {})
        disks = data.get('disks', [])
        guest_os = data.get('guest_os', '')
        xcp_template = _ESXI_TO_XCP_OSTYPE.get(guest_os, 'Other install media')
        memory_mb = data.get('memory_mb', 1024)
        cpu_count = data.get('cpu_count', 1)

        task.log(f"Source VM: {data.get('name', task.vm_name)} ({len(disks)} disk(s))")

        if not disks:
            task.set_phase('failed', 'No disks found')
            return

        # XCP-ng XAPI connection
        xapi = tgt_mgr._api()
        if not xapi:
            task.set_phase('failed', 'Cannot connect to XCP-ng XAPI')
            return

        try:
            session_ref = tgt_mgr._session._session
        except AttributeError:
            task.set_phase('failed', 'Cannot get XAPI session ref')
            return

        xcp_host_url = f"https://{tgt_mgr.host}"
        ssl_verify = getattr(tgt_mgr.config, 'ssl_verification', False)

        # find target SR
        target_sr_ref = None
        try:
            sr_refs = xapi.SR.get_all()
            for sr_ref in sr_refs:
                sr_rec = xapi.SR.get_record(sr_ref)
                if sr_rec.get('name_label') == task.target_storage or sr_rec.get('uuid') == task.target_storage:
                    target_sr_ref = sr_ref
                    break
        except Exception as e:
            task.set_phase('failed', f'Failed to find SR: {e}')
            return
        if not target_sr_ref:
            task.set_phase('failed', f'Storage "{task.target_storage}" not found')
            return

        task.progress = 5
        task.set_phase('transfer')

        esxi_host = src_mgr.host
        esxi_user = getattr(src_mgr.config, 'ssh_user', 'root')
        esxi_pass = getattr(src_mgr.config, 'pass_', '')
        created_vdis = []

        for idx, disk in enumerate(disks):
            if task.cancel_event.is_set():
                task.set_phase('failed', 'Cancelled')
                return

            vmdk = disk.get('vmdk_file', '')
            cap = disk.get('capacity_bytes', 0)
            disk_key = f"disk-{idx}"

            if not vmdk:
                continue

            task.log(f"Transferring {disk.get('label', f'disk {idx}')} ({disk.get('capacity_gb', 0)} GB)")

            ds_match = re.match(r'\[(.+?)\]\s*(.+)', vmdk)
            if not ds_match:
                task.set_phase('failed', f'Cannot parse VMDK path: {vmdk}')
                return
            datastore_name = ds_match.group(1)
            vmdk_rel_path = ds_match.group(2)
            flat_path = vmdk_rel_path
            if flat_path.endswith('.vmdk') and '-flat.vmdk' not in flat_path:
                flat_path = flat_path.replace('.vmdk', '-flat.vmdk')

            # create VDI on XCP-ng
            vdi_rec = {
                'name_label': f"{task.vm_name} disk {idx}",
                'name_description': f'Migrated from ESXi',
                'SR': target_sr_ref,
                'virtual_size': str(cap),
                'type': 'user',
                'sharable': False,
                'read_only': False,
                'other_config': {},
            }
            try:
                new_vdi_ref = xapi.VDI.create(vdi_rec)
                new_vdi_uuid = xapi.VDI.get_uuid(new_vdi_ref)
            except Exception as e:
                task.set_phase('failed', f'VDI creation failed: {e}')
                return
            task.log(f"  Created VDI {new_vdi_uuid}")

            # strategy: SCP flat vmdk to /tmp on PegaProx, then qemu-img convert | HTTP PUT
            # this uses local temp space but avoids SSHFS complexity
            tmp_vmdk = f"/tmp/xhm-esxi-{task.id}-{idx}-flat.vmdk"
            tmp_raw = f"/tmp/xhm-esxi-{task.id}-{idx}.raw"

            try:
                # SCP from ESXi
                task.log(f"  Downloading VMDK from ESXi...")
                # MK Apr 2026 (#359) — VMware datastore / VM-name folders can have
                # spaces. Even though we use argv-list invocation here (no LOCAL
                # shell to escape), scp passes the remote path through the REMOTE
                # ssh shell, so the path itself must be single-quoted inside the
                # argv string.
                _remote_path = '/vmfs/volumes/' + datastore_name + '/' + flat_path
                _q_remote_path = "'" + _remote_path.replace("'", "'\"'\"'") + "'"
                scp_cmd = [
                    'sshpass', '-p', esxi_pass,
                    'scp', '-o', 'StrictHostKeyChecking=no',
                    f'{esxi_user}@{esxi_host}:{_q_remote_path}',
                    tmp_vmdk
                ]
                proc = subprocess.run(scp_cmd, capture_output=True, timeout=7200)
                if proc.returncode != 0:
                    task.set_phase('failed', f'SCP failed: {proc.stderr.decode()[:200]}')
                    return

                # convert VMDK -> raw
                task.log(f"  Converting VMDK to raw...")
                conv = subprocess.run(
                    ['qemu-img', 'convert', '-f', 'vmdk', '-O', 'raw', tmp_vmdk, tmp_raw],
                    capture_output=True, timeout=7200
                )
                os.remove(tmp_vmdk)  # free space
                if conv.returncode != 0:
                    task.set_phase('failed', f'qemu-img failed: {conv.stderr.decode()[:200]}')
                    return

                # stream raw to XCP-ng import_raw_vdi
                import_url = (f"{xcp_host_url}/import_raw_vdi?"
                              f"session_id={session_ref}&vdi={new_vdi_uuid}&format=raw")

                task.log(f"  Uploading to XCP-ng...")
                with open(tmp_raw, 'rb') as f:
                    body = _StreamBody(f, cap,
                                       lambda n: task.update_progress(disk_key, n, cap))
                    resp = _req.put(import_url, data=body, verify=ssl_verify,
                                    headers={'Content-Type': 'application/octet-stream'},
                                    timeout=7200)
                os.remove(tmp_raw)

                if resp.status_code not in (200, 204):
                    try:
                        xapi.VDI.destroy(new_vdi_ref)
                    except:
                        pass
                    task.set_phase('failed', f'VDI import failed: HTTP {resp.status_code}')
                    return

                task.log(f"  Imported to VDI {new_vdi_uuid}")
                created_vdis.append({
                    'ref': new_vdi_ref, 'uuid': new_vdi_uuid,
                    'index': idx, 'bootable': idx == 0,
                })

            except Exception as e:
                # cleanup temp files
                for f in [tmp_vmdk, tmp_raw]:
                    try:
                        os.remove(f)
                    except:
                        pass
                try:
                    xapi.VDI.destroy(new_vdi_ref)
                except:
                    pass
                logger.error(f"[XHM:{task.id}] ESXi->XCP disk error: {e}")
                task.set_phase('failed', f'Transfer error: {e}')
                return

        if not created_vdis:
            task.set_phase('failed', 'No disks transferred')
            return

        task.progress = 80
        task.set_phase('creating')

        # create XCP-ng VM
        is_win = 'win' in guest_os.lower()
        memory_bytes = memory_mb * 1024 * 1024

        vm_template_ref = None
        try:
            for tpl_ref in xapi.VM.get_all():
                if xapi.VM.get_is_a_template(tpl_ref):
                    label = xapi.VM.get_name_label(tpl_ref)
                    if label == xcp_template:
                        vm_template_ref = tpl_ref
                        break
            if not vm_template_ref:
                for tpl_ref in xapi.VM.get_all():
                    if xapi.VM.get_is_a_template(tpl_ref):
                        if xapi.VM.get_name_label(tpl_ref) == 'Other install media':
                            vm_template_ref = tpl_ref
                            break
        except Exception as e:
            task.set_phase('failed', f'Template lookup failed: {e}')
            return

        if not vm_template_ref:
            task.set_phase('failed', 'No suitable XCP-ng template found')
            return

        try:
            new_vm_ref = xapi.VM.clone(vm_template_ref, task.vm_name)
            xapi.VM.set_is_a_template(new_vm_ref, False)
            xapi.VM.set_memory_limits(new_vm_ref, str(memory_bytes), str(memory_bytes),
                                      str(memory_bytes), str(memory_bytes))
            xapi.VM.set_VCPUs_at_startup(new_vm_ref, str(cpu_count))
            xapi.VM.set_VCPUs_max(new_vm_ref, str(cpu_count))
            if is_win:
                platform = xapi.VM.get_platform(new_vm_ref)
                platform['viridian'] = 'true'
                xapi.VM.set_platform(new_vm_ref, platform)
        except Exception as e:
            task.set_phase('failed', f'VM creation failed: {e}')
            return

        task.log(f"Created XCP-ng VM from template: {xcp_template}")
        task.progress = 90

        # attach VDIs
        task.set_phase('attaching')
        for vdi_info in created_vdis:
            try:
                _xcpng_attach_vdi(xapi, new_vm_ref, vdi_info['ref'],
                                  str(vdi_info['index']), vdi_info['bootable'])
                task.log(f"Attached VDI {vdi_info['uuid']} as device {vdi_info['index']}")
            except Exception as e:
                task.log(f"Warning: attach VDI failed: {e}")

        # add default network
        try:
            net_refs = xapi.network.get_all()
            if net_refs:
                _xcpng_attach_network(xapi, new_vm_ref, net_refs[0])
        except:
            pass

        task.progress = 100
        task.set_phase('completed')
        task.log(f"Migration complete: ESXi -> XCP-ng")

    except Exception as e:
        logger.error(f"[XHM:{task.id}] ESXi->XCP failed: {e}")
        task.set_phase('failed', f'Migration error: {e}')


