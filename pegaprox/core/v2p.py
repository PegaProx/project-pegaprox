# -*- coding: utf-8 -*-
"""
PegaProx VMware-to-Proxmox Migration - Layer 5
V2P migration infrastructure.
"""

import os
import json
import time
import logging
import threading
import uuid
import re
import hashlib
import shlex
from datetime import datetime

from pegaprox.globals import cluster_managers, vmware_managers, _v2p_migrations
from pegaprox.utils.ssh import _ssh_exec, _pve_node_exec
from pegaprox.utils.realtime import broadcast_sse

class V2PMigrationTask:
    """Tracks VMware -> Proxmox migration through all phases.
    
    Phases: planning -> pre_sync -> delta_sync -> cutover -> verify -> cleanup -> completed
    
    The key insight: during pre_sync the VM is STILL RUNNING on VMware.
    Actual downtime only occurs during delta_sync + cutover (typically seconds to minutes).
    """
    
    def __init__(self, mid, vmware_id, vm_id, target_cluster, target_node, 
                 target_storage, vm_name='', config=None):
        self.id = mid
        self.vmware_id = vmware_id
        self.vm_id = vm_id
        self.vm_name = vm_name
        self.target_cluster = target_cluster
        self.target_node = target_node
        self.target_storage = target_storage
        self.config = config or {}
        self.phase = 'planning'
        self.status = 'running'
        self.progress = 0
        self.started_at = datetime.now()
        self.completed_at = None
        self.error = None
        self.proxmox_vmid = None
        self.disk_progress = {}
        self.phase_times = {}
        self.downtime_start = None
        self.downtime_end = None
        self.total_downtime_seconds = None
        self.log_lines = []
        # Config
        self.network_bridge = self.config.get('network_bridge', 'vmbr0')
        self.start_after = self.config.get('start_after', True)
        self.remove_source = self.config.get('remove_source', False)
        # ESXi SSH credentials (required for SSHFS)
        self.esxi_host = self.config.get('esxi_host', '')
        self.esxi_user = self.config.get('esxi_user', 'root')
        self.esxi_password = self.config.get('esxi_password', '')
        self.esxi_datastore = self.config.get('esxi_datastore', '')
        self.esxi_vm_dir = self.config.get('esxi_vm_dir', '')
        # Advanced options
        self.net_driver = self.config.get('net_driver', '')  # auto-detect, or: e1000, e1000e, virtio, vmxnet3
        self.disk_bus = self.config.get('disk_bus', '')  # auto-detect, or: scsi, sata, ide
        self.transfer_mode = self.config.get('transfer_mode', 'auto')  # auto, sshfs_boot, offline
    
    def log(self, msg):
        ts = datetime.now().strftime('%H:%M:%S')
        self.log_lines.append(f"[{ts}] {msg}")
        logging.info(f"[V2P:{self.id}] {msg}")
        # Stream log line via SSE (throttled -- batch every 1s)
        try:
            now = time.time()
            if not hasattr(self, '_last_sse_log') or now - self._last_sse_log > 1:
                self._last_sse_log = now
                broadcast_sse('vmware_migration_log', {
                    'id': self.id, 'line': f"[{ts}] {msg}",
                    'progress': self.progress, 'phase': self.phase
                })
        except: pass
    
    def set_phase(self, phase, error=None):
        if self.phase in self.phase_times:
            start = datetime.fromisoformat(self.phase_times[self.phase]['start'])
            self.phase_times[self.phase]['end'] = datetime.now().isoformat()
            self.phase_times[self.phase]['duration'] = round((datetime.now() - start).total_seconds(), 1)
        self.phase = phase
        self.phase_times[phase] = {'start': datetime.now().isoformat(), 'end': None, 'duration': None}
        if phase == 'delta_sync':
            self.downtime_start = datetime.now()
        elif phase in ('cutover', 'verify') and self.downtime_start and not self.downtime_end:
            self.downtime_end = datetime.now()
            self.total_downtime_seconds = round((self.downtime_end - self.downtime_start).total_seconds(), 1)
        if error:
            self.error = error; self.status = 'failed'
            self.log(f"FAILED: {error}")
        if phase == 'completed':
            self.status = 'completed'; self.completed_at = datetime.now(); self.progress = 100
        elif phase == 'failed':
            self.status = 'failed'; self.completed_at = datetime.now()
        self.log(f"Phase: {phase}")
        # Broadcast migration status change via SSE
        try:
            broadcast_sse('vmware_migration', {
                'id': self.id, 'phase': self.phase, 'status': self.status,
                'progress': self.progress, 'vm_name': self.vm_name,
                'error': self.error, 'disk_progress': self.disk_progress
            })
        except: pass
    
    def update_progress(self, disk_key, copied, total):
        self.disk_progress[disk_key] = {
            'copied': copied, 'total': total,
            'pct': round(copied / total * 100, 1) if total else 0
        }
        tc = sum(d['copied'] for d in self.disk_progress.values())
        tt = sum(d['total'] for d in self.disk_progress.values())
        if tt > 0:
            if self.phase == 'pre_sync':
                self.progress = min(79, round((tc / tt) * 80))
            elif self.phase == 'delta_sync':
                self.progress = 80 + min(14, round((tc / tt) * 15))
            elif self.phase in ('cutover', 'verify'):
                self.progress = 95
            elif self.phase in ('cleanup', 'completed'):
                self.progress = 100
        # Broadcast progress via SSE (throttled: every 2s max)
        try:
            now = time.time()
            if not hasattr(self, '_last_sse_progress') or now - self._last_sse_progress > 2:
                self._last_sse_progress = now
                broadcast_sse('vmware_migration', {
                    'id': self.id, 'phase': self.phase, 'status': self.status,
                    'progress': self.progress, 'vm_name': self.vm_name,
                    'disk_progress': self.disk_progress
                })
        except: pass
    
    def to_dict(self):
        return {
            'id': self.id, 'vmware_id': self.vmware_id, 'vm_id': self.vm_id,
            'vm_name': self.vm_name, 'target_cluster': self.target_cluster,
            'target_node': self.target_node, 'target_storage': self.target_storage,
            'proxmox_vmid': self.proxmox_vmid, 'phase': self.phase, 'status': self.status,
            'progress': self.progress, 'error': self.error,
            'started_at': self.started_at.isoformat(),
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'disk_progress': self.disk_progress, 'phase_times': self.phase_times,
            'total_downtime_seconds': self.total_downtime_seconds,
            'log': self.log_lines[-20:],  # Last 20 log lines
            'config': {
                'network_bridge': self.network_bridge,
                'start_after': self.start_after,
                'remove_source': self.remove_source,
                'esxi_host': self.esxi_host,
                'esxi_datastore': self.esxi_datastore,
            },
        }


def _run_v2p_migration(task):
    """Execute VMware -> Proxmox migration via SSHFS + qm importdisk.
    
    Validated approach based on Proxmox forum evidence:
    - SSHFS mount ESXi datastore -> both .vmdk descriptor + -flat.vmdk visible
    - qm importdisk needs the DESCRIPTOR .vmdk (NOT the -flat.vmdk!)
    - qm importdisk auto-detects source format via qemu-img and converts to target
    - Snapshot makes base .vmdk read-only, VM writes to delta -> safe pre-copy
    - No temp files needed: qm importdisk reads from SSHFS, writes to PVE storage
    
    Phase 1 (pre_sync): VM running on VMware
      1. SSHFS mount ESXi datastore
      2. Create VMware snapshot (base vmdk read-only, delta for new writes)
      3. qm importdisk <vmid> <sshfs>/<vm>.vmdk <storage>  (reads base only!)
      -> This copies 95-99% of the data while VM stays running
    
    Phase 2 (delta_sync): Brief downtime
      1. Stop VMware VM
      2. Delete snapshot (consolidates delta back into base)
      3. qm importdisk again (now reads complete consolidated disk)
      -> The disk is now fully consistent
    
    Phase 3 (cutover): Start on Proxmox, verify, cleanup
    """
    import time
    
    mnt_path = f"/tmp/v2p-{task.id}"
    
    try:
        vmware_mgr = vmware_managers.get(task.vmware_id)
        pve_mgr = cluster_managers.get(task.target_cluster)
        if not vmware_mgr:
            task.set_phase('failed', 'VMware server not found'); return
        if not pve_mgr:
            task.set_phase('failed', 'Proxmox cluster not found'); return
        
        esxi_host = task.esxi_host or vmware_mgr.host
        esxi_user = task.esxi_user or 'root'
        esxi_pass = task.esxi_password
        
        if not esxi_pass:
            task.set_phase('failed', 'ESXi SSH password is required for SSHFS-based migration'); return
        
        # ================================================================
        # PHASE: PLANNING
        # ================================================================
        task.set_phase('planning')
        task.log(f"Planning migration of '{task.vm_name}' from {esxi_host}")
        
        # Get VM disk layout from VMware REST API
        disk_info = vmware_mgr.get_vm_disks_for_export(task.vm_id)
        if 'error' in disk_info:
            task.set_phase('failed', f"Cannot get VM info: {disk_info.get('error')}"); return
        vm_data = disk_info['data']
        disks = vm_data.get('disks', [])
        
        # Get full VM hardware info (SCSI controller, NIC type, firmware, etc.)
        full_vm = vmware_mgr.get_vm(task.vm_id)
        if 'data' in full_vm:
            fv = full_vm['data']
            vm_data['hardware'] = fv.get('hardware', {})
            vm_data['controllers'] = fv.get('controllers', {})
            vm_data['nics'] = fv.get('nics', [])
            vm_data['guest_os'] = fv.get('guest_OS', vm_data.get('guest_os', ''))
        if not disks:
            task.set_phase('failed', 'No disks found on source VM'); return
        
        task.log(f"VM has {len(disks)} disk(s), {vm_data.get('total_disk_gb', 0):.1f} GB total")
        
        # Verify SSH access to ESXi
        task.log(f"Testing SSH to {esxi_host}...")
        rc, out, err = _ssh_exec(esxi_host, esxi_user, esxi_pass, 'hostname', timeout=10)
        if rc != 0:
            task.set_phase('failed', f'Cannot SSH to ESXi {esxi_host}: {err}'); return
        task.log(f"SSH OK: {out.strip()}")
        
        # Find VM directory on ESXi datastore
        datastore = task.esxi_datastore
        vm_dir = task.esxi_vm_dir or vm_data.get('name', '')
        
        if not datastore:
            task.log("Auto-detecting datastore...")
            rc, out, err = _ssh_exec(esxi_host, esxi_user, esxi_pass,
                f"find /vmfs/volumes/ -maxdepth 3 -name {shlex.quote(vm_dir)} -type d 2>/dev/null | head -5",
                timeout=30)
            if rc == 0 and out.strip():
                found_path = out.strip().split('\n')[0]
                parts = found_path.split('/')
                if len(parts) >= 4:
                    datastore = parts[3]
                    task.log(f"Found VM on datastore: {datastore}")
        
        if not datastore:
            task.set_phase('failed', 'Could not determine ESXi datastore. Please specify it manually.'); return
        
        # Verify VM files exist and find descriptor .vmdk files
        vm_path = f"/vmfs/volumes/{datastore}/{vm_dir}"
        rc, out, err = _ssh_exec(esxi_host, esxi_user, esxi_pass,
            f"ls -la {shlex.quote(vm_path + '/')} | grep '.vmdk'", timeout=15)
        if rc != 0 or not out.strip():
            task.set_phase('failed', f'VM directory not found or empty: {vm_path}'); return
        
        task.log(f"VM files found at {vm_path}")
        
        # Find descriptor .vmdk files (NOT -flat, NOT -delta, NOT -ctk, NOT -000NNN)
        # Descriptor = small text file referencing the flat file
        rc, out, err = _ssh_exec(esxi_host, esxi_user, esxi_pass,
            f"ls -la {shlex.quote(vm_path + '/')} | grep '.vmdk' | grep -v flat | grep -v delta | grep -v ctk | grep -v '\\-0000'",
            timeout=15)
        descriptor_files = []
        for line in out.strip().split('\n'):
            parts = line.strip().split()
            if parts and parts[-1].endswith('.vmdk'):
                fname = parts[-1]
                fsize = int(parts[4]) if len(parts) > 4 and parts[4].isdigit() else 0
                if fsize < 65536:  # Descriptor files are tiny (<64KB)
                    descriptor_files.append(fname)
        
        if not descriptor_files:
            rc, out, _ = _ssh_exec(esxi_host, esxi_user, esxi_pass,
                f"ls {shlex.quote(vm_path + '/')}*.vmdk 2>/dev/null | grep -v flat | grep -v delta | grep -v ctk | grep -v '\\-0000'",
                timeout=15)
            for f in out.strip().split('\n'):
                if f.strip().endswith('.vmdk'):
                    descriptor_files.append(f.strip().split('/')[-1])
        
        task.log(f"Found {len(descriptor_files)} descriptor file(s): {descriptor_files}")
        if not descriptor_files:
            task.set_phase('failed', f'No VMDK descriptor files found in {vm_path}'); return
        
        # Verify sshfs on Proxmox node
        task.log(f"Verifying sshfs on Proxmox node {task.target_node}...")
        rc, out, err = _pve_node_exec(pve_mgr, task.target_node,
            'which sshfs || apt-get install -y sshfs 2>&1', timeout=60)
        if 'sshfs' not in (out + err) and rc != 0:
            task.set_phase('failed', f'sshfs not available on node: {err}'); return
        task.log("sshfs OK")
        
        # Also ensure sshpass is available (needed for SCP fallback)
        _pve_node_exec(pve_mgr, task.target_node,
            'which sshpass || apt-get install -y sshpass 2>&1', timeout=60)
        
        # Get next VMID
        try:
            resp = pve_mgr._api_get(f"https://{pve_mgr.host}:8006/api2/json/cluster/nextid")
            task.proxmox_vmid = int(resp.json().get('data', 100)) if resp.status_code == 200 else None
            if not task.proxmox_vmid:
                task.set_phase('failed', 'Cannot allocate Proxmox VMID'); return
        except Exception as e:
            task.set_phase('failed', f'Proxmox API error: {e}'); return
        task.log(f"Allocated Proxmox VMID: {task.proxmox_vmid}")
        
        # Create Proxmox VM shell FIRST (qm importdisk requires existing VM)
        guest_os = vm_data.get('guest_os', '').lower()
        hw = vm_data.get('hardware', {})
        
        # Firmware: match VMware (BIOS vs EFI)
        firmware = hw.get('firmware', 'bios')
        if firmware == 'efi':
            bios = 'ovmf'; machine = 'q35'
        else:
            bios = 'seabios'; machine = 'pc'
        
        # OS type for Proxmox
        ostype = 'l26'
        if 'windows' in guest_os:
            ostype = 'win11' if any(x in guest_os for x in ['11', '2022', '2025']) else 'win10'
            if bios == 'seabios':
                bios = 'ovmf'; machine = 'q35'  # Windows 10+ prefers EFI
        
        # SCSI controller: match VMware (PVSCSI, LSI Logic, etc.)
        scsihw = hw.get('scsi_controller_pve', 'virtio-scsi-single')
        if task.disk_bus == 'scsi' and scsihw not in ('pvscsi', 'lsi', 'lsi53c810', 'megasas', 'virtio-scsi-pci', 'virtio-scsi-single'):
            scsihw = 'virtio-scsi-single'
        
        # Disk bus: match VMware (SCSI, SATA, IDE)
        detected_bus = hw.get('disk_bus', 'scsi')
        disk_bus = task.disk_bus if task.disk_bus in ('scsi', 'sata', 'ide') else detected_bus
        
        # Network: match VMware (vmxnet3, E1000, E1000e)
        detected_nic = hw.get('nic_type_pve', 'e1000')
        net_driver = task.net_driver if task.net_driver in ('e1000', 'e1000e', 'virtio', 'vmxnet3') else detected_nic
        
        pve_config = {
            'vmid': task.proxmox_vmid,
            'name': vm_data.get('name', f'v2p-{task.proxmox_vmid}'),
            'memory': vm_data.get('memory_mb', 2048),
            'cores': vm_data.get('cpu_count', 1),
            'sockets': 1,
            'net0': f'{net_driver},bridge={task.network_bridge}',
            'ostype': ostype, 'bios': bios, 'machine': machine,
            'scsihw': scsihw,
            'cpu': 'host',
            'boot': f'order={disk_bus}0;net0',
        }
        if bios == 'ovmf':
            pve_config['efidisk0'] = f'{task.target_storage}:1,efitype=4m,pre-enrolled-keys=0'
        
        # Log detected VMware hardware
        task.log(f"VMware hardware: firmware={firmware}, scsi={hw.get('scsi_controller', '?')}, "
                 f"nic={hw.get('nic_type', '?')}, bus={detected_bus}")
        task.log(f"Proxmox config: bios={bios}, machine={machine}, scsihw={scsihw}, "
                 f"disk={disk_bus}, net={net_driver}")
        
        task.log(f"Creating VM {task.proxmox_vmid}: {pve_config['name']}, "
                 f"{pve_config['memory']}MB RAM, {pve_config['cores']} cores, "
                 f"{ostype}, disk={disk_bus}, net={net_driver}")
        
        try:
            cr = pve_mgr._api_post(
                f"https://{pve_mgr.host}:8006/api2/json/nodes/{task.target_node}/qemu",
                data=pve_config)
            if cr.status_code not in (200, 201):
                task.set_phase('failed', f'VM creation failed: {cr.text[:300]}'); return
            pve_task_id = cr.json().get('data', '')
        except Exception as e:
            task.set_phase('failed', f'VM creation error: {e}'); return
        
        for _ in range(60):
            time.sleep(2)
            try:
                sr = pve_mgr._api_get(
                    f"https://{pve_mgr.host}:8006/api2/json/nodes/{task.target_node}/tasks/{pve_task_id}/status")
                if sr.status_code == 200 and sr.json().get('data', {}).get('status') == 'stopped':
                    es = sr.json()['data'].get('exitstatus', '')
                    if es == 'OK': task.log("VM shell created"); break
                    else: task.set_phase('failed', f'VM creation failed: {es}'); return
            except: pass
        
        for i, df in enumerate(descriptor_files):
            ds = disks[i]['capacity_bytes'] if i < len(disks) else 1
            task.disk_progress[f'disk{i}'] = {'copied': 0, 'total': ds or 1, 'pct': 0, 'file': df}
        
        # ================================================================
        # PHASE: PRE-SYNC (VM running on VMware - minimal downtime)
        # Downloads VMDKs via ESXi HTTPS API while VM is running.
        # No snapshot needed - HTTPS /folder/ endpoint can serve files
        # through the storage stack even with active VMDK locks.
        # This is a "dirty" copy - some blocks may be inconsistent.
        # ================================================================
        task.set_phase('pre_sync')
        task.log("=== PRE-SYNC: VM continues running on VMware ===")
        
        # Mount ESXi datastore via SSHFS (for file listing/discovery only)
        task.log("Mounting ESXi datastore via SSHFS...")
        safe_pass = shlex.quote(esxi_pass)

        _pve_node_exec(pve_mgr, task.target_node,
            "grep -q '^user_allow_other' /etc/fuse.conf 2>/dev/null || "
            "sed -i 's/^#user_allow_other/user_allow_other/' /etc/fuse.conf 2>/dev/null || "
            "echo 'user_allow_other' >> /etc/fuse.conf",
            timeout=10)
        
        # SSHFS SSH options -- include legacy algorithms for ESXi compatibility
        # Performance options (each one matters for drive-mirror speed):
        #   kernel_cache: use kernel page cache (huge for sequential reads)
        #   max_read=1048576: 1MB read chunks (default 64KB, was 256KB)
        #   max_write=1048576: 1MB write chunks (for cache=writeback flushes)
        #   big_writes: required to allow writes >4KB through FUSE
        #   large_read: enable FUSE large reads
        #   entry_timeout/attr_timeout=3600: cache file metadata for 1h
        #     (avoids thousands of stat() calls -- HUGE reduction in FUSE overhead)
        #   negative_timeout=3600: cache "file not found" for 1h
        #   no_check_root: skip root dir check (faster mount)
        sshfs_ssh_opts = (
            "StrictHostKeyChecking=no,UserKnownHostsFile=/dev/null,"
            "allow_other,reconnect,ServerAliveInterval=15,ServerAliveCountMax=3,"
            "cache=yes,kernel_cache,"
            "max_read=1048576,max_write=1048576,big_writes,large_read,"
            "entry_timeout=3600,negative_timeout=3600,attr_timeout=3600,"
            "no_check_root"
        )
        sshfs_algo_opts = (
            "ssh_command=ssh -o HostKeyAlgorithms=+ssh-rsa\\,ssh-ed25519\\,ecdsa-sha2-nistp256 "
            "-o KexAlgorithms=+diffie-hellman-group14-sha1\\,diffie-hellman-group14-sha256 "
            "-o PreferredAuthentications=keyboard-interactive\\,password "
            "-o Compression=no "
            "-o Ciphers=aes128-gcm@openssh.com\\,aes128-ctr\\,aes256-ctr "
            "-o TCPKeepAlive=yes "
            "-o IPQoS=throughput"
        )
        
        mount_cmd = (
            f"mkdir -p {mnt_path} && "
            f"printf '%s' {safe_pass} | sshfs -o password_stdin,"
            f"{sshfs_ssh_opts},{sshfs_algo_opts} "
            f"{esxi_user}@{esxi_host}:/vmfs/volumes/{shlex.quote(datastore)} {mnt_path}"
        )
        rc, out, err = _pve_node_exec(pve_mgr, task.target_node, mount_cmd, timeout=30)
        if rc != 0:
            # Fallback 1: perf options but simpler SSH (no algo workaround)
            mount_cmd2 = (
                f"mkdir -p {mnt_path} && "
                f"printf '%s' {safe_pass} | sshfs -o password_stdin,"
                f"StrictHostKeyChecking=no,UserKnownHostsFile=/dev/null,"
                f"allow_other,reconnect,ServerAliveInterval=15,"
                f"cache=yes,kernel_cache,"
                f"max_read=1048576,big_writes,large_read,"
                f"entry_timeout=3600,attr_timeout=3600 "
                f"{esxi_user}@{esxi_host}:/vmfs/volumes/{shlex.quote(datastore)} {mnt_path}")
            rc, out, err = _pve_node_exec(pve_mgr, task.target_node, mount_cmd2, timeout=30)
        if rc != 0:
            # Fallback 2: minimal options (maximum compatibility)
            mount_cmd3 = (
                f"mkdir -p {mnt_path} && "
                f"printf '%s' {safe_pass} | sshfs -o password_stdin,"
                f"StrictHostKeyChecking=no,UserKnownHostsFile=/dev/null,"
                f"allow_other,reconnect,ServerAliveInterval=15,"
                f"cache=yes "
                f"{esxi_user}@{esxi_host}:/vmfs/volumes/{shlex.quote(datastore)} {mnt_path}")
            rc, out, err = _pve_node_exec(pve_mgr, task.target_node, mount_cmd3, timeout=30)
            if rc != 0:
                task.set_phase('failed', f'SSHFS mount failed: {err}'); return
        task.log(f"SSHFS mounted: {mnt_path}")
        
        # Verify files visible
        rc, out, err = _pve_node_exec(pve_mgr, task.target_node,
            f"ls {shlex.quote(mnt_path + '/' + vm_dir)}/*.vmdk 2>/dev/null | head -20", timeout=15)
        task.log(f"VMDK files via SSHFS: {len([l for l in out.strip().split(chr(10)) if l.strip()])}")
        
        # ================================================================
        # TRANSFER MODE ROUTING
        # ================================================================
        # sshfs_boot: Stop VM → Boot Proxmox from SSHFS → Live-move disks (near-zero downtime)
        # offline:    Stop VM → Full copy via SSH dd → Start Proxmox (more downtime, simpler)
        # auto:       Try pre-sync while running → fallback to sshfs_boot if locked
        
        if task.transfer_mode == 'sshfs_boot':
            task.log(f"=== TRANSFER MODE: QEMU SSH Boot + Live Copy ===")
            task.log("Near-zero downtime: boot from SSH, copy in background")
            
            # Stop VMware VM if running
            vm_state = vmware_mgr.get_vm(task.vm_id)
            is_running = 'data' in vm_state and vm_state['data'].get('power_state') == 'POWERED_ON'
            
            if is_running:
                task.log("Stopping VMware VM...")
                vmware_mgr.vm_power_action(task.vm_id, 'stop')
                for attempt in range(15):
                    time.sleep(2)
                    vm_check = vmware_mgr.get_vm(task.vm_id)
                    if 'data' in vm_check and vm_check['data'].get('power_state') == 'POWERED_OFF':
                        task.log(f"VM stopped after {(attempt+1)*2}s"); break
                else:
                    task.log("Force stopping...")
                    vmware_mgr.vm_power_action(task.vm_id, 'reset')
                    time.sleep(2)
                    vmware_mgr.vm_power_action(task.vm_id, 'stop')
                    time.sleep(5)
                # Delete any snapshot
                try: vmware_mgr.delete_migration_snapshot(task.vm_id)
                except: pass
                time.sleep(2)
            else:
                task.log("VMware VM is already off - VMDKs are unlocked")
            
            # Go directly to SSHFS-boot flow (reuse the same code block)
            # Create temp storage, symlink disks, boot, move
            _do_sshfs_boot_migration(pve_mgr, task, vmware_mgr, esxi_host, esxi_user, esxi_pass,
                                     datastore, vm_dir, descriptor_files, disk_bus, mnt_path)
            return
        
        if task.transfer_mode == 'offline':
            task.log(f"=== TRANSFER MODE: Offline Copy ===")
            task.log("Stopping VM first, then full disk copy via SSH")
            
            # Stop VMware VM if running
            vm_state = vmware_mgr.get_vm(task.vm_id)
            is_running = 'data' in vm_state and vm_state['data'].get('power_state') == 'POWERED_ON'
            
            if is_running:
                task.log("Stopping VMware VM...")
                vmware_mgr.vm_power_action(task.vm_id, 'stop')
                for attempt in range(15):
                    time.sleep(2)
                    vm_check = vmware_mgr.get_vm(task.vm_id)
                    if 'data' in vm_check and vm_check['data'].get('power_state') == 'POWERED_OFF':
                        task.log(f"VM stopped after {(attempt+1)*2}s"); break
                else:
                    task.log("Force stopping...")
                    vmware_mgr.vm_power_action(task.vm_id, 'reset')
                    time.sleep(2)
                    vmware_mgr.vm_power_action(task.vm_id, 'stop')
                    time.sleep(5)
                # Delete any snapshot
                try: vmware_mgr.delete_migration_snapshot(task.vm_id)
                except: pass
                time.sleep(2)
            else:
                task.log("VMware VM already off")
            
            # Copy each disk (VM off = no locks)
            for i, desc_file in enumerate(descriptor_files):
                dk = f'disk{i}'
                disk_size = task.disk_progress[dk]['total']
                task.log(f"Copying disk {i}: {desc_file} ({disk_size / (1024**3):.1f} GB)")
                
                vol_id, vol_path = _ssh_pipe_transfer(
                    pve_mgr, task, esxi_host, esxi_user, esxi_pass,
                    datastore, vm_dir, desc_file, i
                )
                if not vol_id:
                    task.set_phase('failed', f'Disk copy failed for {desc_file}')
                    _cleanup_sshfs(pve_mgr, task.target_node, mnt_path)
                    return
                
                # Attach disk
                attach_cmd = f"qm set {task.proxmox_vmid} --{disk_bus}{i} {vol_id} 2>&1"
                _pve_node_exec(pve_mgr, task.target_node, attach_cmd, timeout=30)
                task.log(f"  Disk {i} attached as {disk_bus}{i}")
                task.update_progress(dk, disk_size, disk_size)
            
            # Set boot order and start
            _pve_node_exec(pve_mgr, task.target_node,
                f"qm set {task.proxmox_vmid} --boot order={disk_bus}0 2>&1", timeout=10)
            
            _cleanup_sshfs(pve_mgr, task.target_node, mnt_path)
            
            if task.start_after:
                task.log("Starting Proxmox VM...")
                try:
                    pve_mgr._api_post(
                        f"https://{pve_mgr.host}:8006/api2/json/nodes/{task.target_node}"
                        f"/qemu/{task.proxmox_vmid}/status/start")
                    task.log(f"VM {task.proxmox_vmid} started")
                except Exception as e:
                    task.log(f"Start failed: {e}")
            
            task.set_phase('completed')
            task.log(f"COMPLETED: {task.vm_name} -> VMID {task.proxmox_vmid} (offline copy)")
            return
        
        # ================================================================
        # AUTO MODE: Try pre-sync while VM runs, fallback to sshfs_boot
        # ================================================================
        task.log(f"=== TRANSFER MODE: Auto (pre-sync + delta) ===")
        # IMPORTANT: Create snapshot first so base VMDK becomes read-only
        # VM continues running, writing to a delta VMDK
        task.log("Creating VMware snapshot for safe pre-sync copy...")
        snap_result = vmware_mgr.create_migration_snapshot(task.vm_id)
        if 'error' in snap_result:
            task.log(f"Snapshot creation failed: {snap_result.get('error', 'unknown')}")
            task.log("Continuing anyway - HTTPS may still work, SSHFS will be limited")
        else:
            task.log("Migration snapshot created - base VMDKs are now read-only")
        
        presync_volumes = []  # Track (vol_id, vol_path, flat_path, flat_size) for delta sync
        stopped_for_presync = False  # Flag: if we had to stop VM, skip delta-sync
        
        for i, desc_file in enumerate(descriptor_files):
            dk = f'disk{i}'
            disk_size = task.disk_progress[dk]['total']
            
            task.log(f"Pre-sync disk {i}: {desc_file} ({disk_size / (1024**3):.1f} GB)")
            
            vol_id, vol_path = _ssh_pipe_transfer(
                pve_mgr, task, esxi_host, esxi_user, esxi_pass,
                datastore, vm_dir, desc_file, i
            )
            
            # If transfer failed with VM running → use SSHFS-boot strategy
            # Stop VM briefly, boot Proxmox VM from SSHFS, live-move disk in background
            if not vol_id and not stopped_for_presync:
                task.log("Pre-sync failed (VMDK locked) - switching to QEMU SSH boot")
                
                # Stop VMware VM
                task.log("Stopping VMware VM...")
                vmware_mgr.vm_power_action(task.vm_id, 'stop')
                for attempt in range(15):
                    time.sleep(2)
                    vm_check = vmware_mgr.get_vm(task.vm_id)
                    if 'data' in vm_check and vm_check['data'].get('power_state') == 'POWERED_OFF':
                        task.log(f"VM stopped after {(attempt+1)*2}s"); break
                else:
                    task.log("Force stopping...")
                    vmware_mgr.vm_power_action(task.vm_id, 'reset')
                    time.sleep(2)
                    vmware_mgr.vm_power_action(task.vm_id, 'stop')
                    time.sleep(5)
                try: vmware_mgr.delete_migration_snapshot(task.vm_id)
                except: pass
                time.sleep(2)
                
                _do_sshfs_boot_migration(pve_mgr, task, vmware_mgr, esxi_host, esxi_user, esxi_pass,
                                         datastore, vm_dir, descriptor_files, disk_bus, mnt_path)
                return
            
            if not vol_id:
                task.set_phase('failed', f'Transfer failed for {desc_file}')
                _cleanup_sshfs(pve_mgr, task.target_node, mnt_path)
                try: vmware_mgr.delete_migration_snapshot(task.vm_id)
                except: pass
                return
            
            # Resolve flat file path for later delta sync
            flat_file = desc_file.replace('.vmdk', '-flat.vmdk')
            esxi_flat = f"/vmfs/volumes/{datastore}/{vm_dir}/{flat_file}"
            presync_volumes.append((vol_id, vol_path, esxi_flat, disk_size))
            
            # Attach the volume to the VM
            attach_cmd = f"qm set {task.proxmox_vmid} --{disk_bus}{i} {vol_id} 2>&1"
            rc_at, out_at, _ = _pve_node_exec(pve_mgr, task.target_node, attach_cmd, timeout=30)
            if rc_at == 0:
                task.log(f"  Disk {i} attached as {disk_bus}{i} ({vol_id})")
            else:
                task.log(f"  WARNING: attach failed: {str(out_at or '')[:150]}")
            
            task.log(f"Pre-sync disk {i}: complete")
            task.update_progress(dk, disk_size, disk_size)
        
        task.log("=== PRE-SYNC COMPLETE ===")
        
        if stopped_for_presync:
            # VM was stopped during pre-sync -- we have a clean copy, skip delta-sync
            task.log("=== SKIPPING DELTA SYNC (VM was stopped, copy is clean) ===")
            task.set_phase('delta_sync')
            task.log("No delta sync needed - disks are already consistent")
            # Track downtime from when we stopped
            task.set_phase('cutover')
        else:
            # Normal path: VM still running, do checksums + delta sync
            task.log("Pre-computing Proxmox checksums (VM still running)...")
            presync_checksums = {}
            DELTA_BS = 256 * 1024 * 1024  # Must match _delta_sync_blocks
            for i, (vol_id, vol_path, esxi_flat, flat_size) in enumerate(presync_volumes):
                num_blocks = (flat_size + DELTA_BS - 1) // DELTA_BS
                task.log(f"  Checksumming disk {i}: {num_blocks} blocks...")
                pve_script = (
                    f"i=0; while [ $i -lt {num_blocks} ]; do "
                    f"dd if={shlex.quote(vol_path)} bs={DELTA_BS} skip=$i count=1 2>/dev/null | md5sum | cut -d' ' -f1; "
                    f"i=$((i+1)); done"
                )
                rc_p, out_p, _ = _pve_node_exec(pve_mgr, task.target_node, pve_script, timeout=600)
                if rc_p == 0 and out_p:
                    presync_checksums[i] = [s.strip() for s in out_p.strip().split('\n') if s.strip()]
                    task.log(f"  Disk {i}: {len(presync_checksums[i])} checksums computed")
                else:
                    task.log(f"  Disk {i}: checksum failed, will do full comparison during downtime")
        
            # ================================================================
            # PHASE: DELTA SYNC (brief downtime - block-level sync)
            # VM stopped → compare checksums → transfer only changed blocks
            # ================================================================
            task.set_phase('delta_sync')
            task.log("=== DELTA SYNC: DOWNTIME STARTS ===")
        
            # Stop VMware VM (unlocks VMDKs for SSH dd access)
            task.log("Stopping VMware VM...")
            vmware_mgr.vm_power_action(task.vm_id, 'stop')
            for attempt in range(30):
                time.sleep(2)
                vm_check = vmware_mgr.get_vm(task.vm_id)
                if 'data' in vm_check and vm_check['data'].get('power_state') == 'POWERED_OFF':
                    task.log(f"VM powered off after {(attempt+1)*2}s"); break
            else:
                task.log("WARNING: VM may not be fully stopped yet")
        
            # Delete migration snapshot (consolidates delta back into base VMDK)
            task.log("Deleting migration snapshot (consolidating delta)...")
            del_snap = vmware_mgr.delete_migration_snapshot(task.vm_id)
            if 'error' in del_snap:
                task.log(f"Snapshot deletion warning: {del_snap.get('error', '')}")
            else:
                task.log("Snapshot deleted, VMDKs consolidated")
            # Small delay for ESXi to finish consolidation
            time.sleep(3)
        
            # Delta sync each disk (only changed blocks)
            for i, (vol_id, vol_path, esxi_flat, flat_size) in enumerate(presync_volumes):
                dk = f'disk{i}'
                task.log(f"Delta sync disk {i}: comparing blocks...")
            
                ok = _delta_sync_blocks(
                    pve_mgr, task, esxi_host, esxi_user, esxi_pass,
                    esxi_flat, vol_path, flat_size, i,
                    pve_checksums=presync_checksums.get(i)
                )
                if not ok:
                    task.log(f"  WARNING: Block delta failed, falling back to full re-download...")
                    # Detach old disk, free volume, re-download
                    _pve_node_exec(pve_mgr, task.target_node,
                        f"qm set {task.proxmox_vmid} --delete {disk_bus}{i} 2>/dev/null", timeout=15)
                    _pve_node_exec(pve_mgr, task.target_node,
                        f"pvesm free '{vol_id}' 2>/dev/null", timeout=30)
                
                    new_vol_id, new_vol_path = _ssh_pipe_transfer(
                        pve_mgr, task, esxi_host, esxi_user, esxi_pass,
                        datastore, vm_dir, descriptor_files[i], i
                    )
                    if not new_vol_id:
                        task.set_phase('failed', f'Delta sync failed for disk {i}')
                        _cleanup_sshfs(pve_mgr, task.target_node, mnt_path)
                        return
                
                    attach_cmd = f"qm set {task.proxmox_vmid} --{disk_bus}{i} {new_vol_id} 2>&1"
                    _pve_node_exec(pve_mgr, task.target_node, attach_cmd, timeout=30)
                    task.log(f"  Full re-download complete ({new_vol_id})")
            
                task.update_progress(dk, task.disk_progress[dk]['total'], task.disk_progress[dk]['total'])
        
            task.log("=== DELTA SYNC COMPLETE ===")
        
            # ================================================================
        # PHASE: CUTOVER
        # ================================================================
        task.set_phase('cutover')
        _pve_node_exec(pve_mgr, task.target_node,
            f"qm set {task.proxmox_vmid} --boot order={disk_bus}0 2>&1", timeout=15)
        
        if task.start_after:
            task.log("Starting VM on Proxmox...")
            try:
                pve_mgr._api_post(
                    f"https://{pve_mgr.host}:8006/api2/json/nodes/{task.target_node}"
                    f"/qemu/{task.proxmox_vmid}/status/start")
                task.log(f"VM {task.proxmox_vmid} started - DOWNTIME ENDS")
            except Exception as e:
                task.log(f"WARNING: Could not start VM: {e}")
        
        # ================================================================
        # VERIFY + CLEANUP
        # ================================================================
        task.set_phase('verify')
        time.sleep(8)
        try:
            vs = pve_mgr._api_get(
                f"https://{pve_mgr.host}:8006/api2/json/nodes/{task.target_node}"
                f"/qemu/{task.proxmox_vmid}/status/current")
            if vs.status_code == 200:
                task.log(f"VM status: {vs.json().get('data', {}).get('status', '?')}")
        except: pass
        
        task.set_phase('cleanup')
        _cleanup_sshfs(pve_mgr, task.target_node, mnt_path)
        task.log("SSHFS unmounted")
        if task.remove_source:
            task.log("Removing source VM from VMware...")
            vmware_mgr.delete_vm(task.vm_id)
        
        task.set_phase('completed')
        dt_msg = f" (downtime: {task.total_downtime_seconds:.1f}s)" if task.total_downtime_seconds else ""
        task.log(f"COMPLETED{dt_msg}: {task.vm_name} -> VMID {task.proxmox_vmid}")
        
    except Exception as e:
        task.set_phase('failed', str(e))
        try: _cleanup_sshfs(pve_mgr, task.target_node, mnt_path)
        except: pass
        # Clean up migration snapshot if it exists
        try:
            vmware_mgr = vmware_managers.get(task.vmware_id)
            if vmware_mgr:
                vmware_mgr.delete_migration_snapshot(task.vm_id)
                task.log("Cleaned up migration snapshot after failure")
        except: pass


def _qemu_device_spec(drive_id, disk_index, disk_bus):
    """Generate QEMU -device spec matching the VM's disk controller.
    VMware guests have SCSI drivers in initramfs -- use SCSI to avoid initramfs drops."""
    if disk_bus == 'scsi':
        # Attach to Proxmox's SCSI controller (scsihw0) so guest's pvscsi/lsi drivers work
        return f"scsi-hd,bus=scsihw0.0,scsi-id={disk_index},lun=0,drive={drive_id},bootindex={disk_index}"
    elif disk_bus == 'sata':
        return f"ide-hd,drive={drive_id},bus=ide.{disk_index // 2},unit={disk_index % 2},bootindex={disk_index}"
    else:  # ide or unknown
        return f"ide-hd,drive={drive_id},bus=ide.{disk_index // 2},unit={disk_index % 2},bootindex={disk_index}"


def _qm_monitor_cmd(pve_mgr, node, vmid, command, timeout=15):
    """Send HMP command to running QEMU VM via Proxmox API monitor endpoint.
    Returns (success: bool, output: str)."""
    try:
        resp = pve_mgr._api_post(
            f"https://{pve_mgr.host}:8006/api2/json/nodes/{node}/qemu/{vmid}/monitor",
            data={"command": command}, timeout=timeout)
        if resp.status_code == 200:
            data = resp.json().get('data', '')
            return True, str(data)
        return False, f"HTTP {resp.status_code}"
    except Exception as e:
        return False, str(e)


def _drive_mirror_to_local(pve_mgr, task, node, vmid, drive_id, target_path, disk_total):
    """Start a single drive-mirror job. Does NOT wait for completion.
    Use _poll_drive_mirrors() to wait for all mirrors to finish.
    Returns True if mirror started successfully."""
    
    # Verify drive exists in QEMU block graph
    ok, block_info = _qm_monitor_cmd(pve_mgr, node, vmid, "info block")
    if not ok or drive_id not in block_info:
        task.log(f"  drive-mirror: drive '{drive_id}' not found in VM")
        # Show available drives for debugging
        drives = [l.strip().split(':')[0] for l in block_info.split('\n') if ':' in l and 'Removable' not in l]
        task.log(f"  Available drives: {', '.join(drives[:10])}")
        return False
    
    # Start drive-mirror: -n = reuse existing target, -f = skip size check
    mirror_cmd = f"drive_mirror -n -f {drive_id} {target_path} raw"
    ok, out = _qm_monitor_cmd(pve_mgr, node, vmid, mirror_cmd, timeout=30)
    out_str = str(out or '').strip()
    
    if not ok:
        # Try without -f (older QEMU)
        mirror_cmd = f"drive_mirror -n {drive_id} {target_path} raw"
        ok, out = _qm_monitor_cmd(pve_mgr, node, vmid, mirror_cmd, timeout=30)
        out_str = str(out or '').strip()
    
    if not ok:
        task.log(f"  drive-mirror command failed: {out_str[:200]}")
        return False
    
    if 'error' in out_str.lower():
        task.log(f"  drive-mirror error: {out_str[:200]}")
        return False
    
    # Log the response (important for debugging!)
    if out_str:
        task.log(f"  drive-mirror response: {out_str[:150]}")
    
    # Set speed to unlimited
    _qm_monitor_cmd(pve_mgr, node, vmid, f"block_job_set_speed {drive_id} 0")
    
    # Verify job actually started (give it a moment)
    import time
    time.sleep(1)
    ok2, jobs = _qm_monitor_cmd(pve_mgr, node, vmid, "info block-jobs")
    if ok2 and drive_id in str(jobs):
        task.log(f"  drive-mirror started: {drive_id} → {target_path}")
        return True
    
    # Job not visible yet -- wait a bit more and retry
    time.sleep(3)
    ok3, jobs2 = _qm_monitor_cmd(pve_mgr, node, vmid, "info block-jobs")
    if ok3 and drive_id in str(jobs2):
        task.log(f"  drive-mirror started (delayed): {drive_id} → {target_path}")
        return True
    
    # Job didn't start -- check QEMU log for actual error
    task.log(f"  drive-mirror: job not visible in block-jobs after 4s")
    task.log(f"  block-jobs output: {str(jobs2 or jobs or '')[:200]}")
    
    rc_log, out_log, _ = _pve_node_exec(pve_mgr, node,
        f"tail -10 /var/log/pve/qemu-server/{vmid}.log 2>/dev/null | grep -i 'mirror\\|error\\|block' | tail -3", timeout=10)
    qemu_log = str(out_log or '').strip()
    if qemu_log:
        task.log(f"  QEMU log: {qemu_log[:200]}")
    
    return False


def _poll_drive_mirrors(pve_mgr, task, node, vmid, mirrors, timeout=7200):
    """poll drive-mirror jobs until ready, then pivot. for FUSE/SSHFS uses pause-pivot-resume (~1-2s downtime)"""
    import time, re
    
    drive_ids = {m[0] for m in mirrors}
    start_t = time.time()
    last_log = 0
    ready_drives = set()
    at_100_since = {}  # drive_id -> timestamp when first reached ~100%
    PAUSE_PIVOT_AFTER = 60  # seconds at 100% before trying pause-pivot
    
    for poll in range(timeout // 2):
        time.sleep(2)
        ok, jobs = _qm_monitor_cmd(pve_mgr, node, vmid, "info block-jobs")
        if not ok:
            continue
        
        # Check each mirror
        all_near_100 = True
        for drive_id, disk_total, di in mirrors:
            if drive_id in ready_drives:
                continue
            
            if drive_id not in jobs:
                elapsed = time.time() - start_t
                if elapsed < 10:
                    all_near_100 = False
                    continue
                rc_log, out_log, _ = _pve_node_exec(pve_mgr, node,
                    f"tail -5 /var/log/pve/qemu-server/{vmid}.log 2>/dev/null | "
                    f"grep -i 'mirror\\|error\\|block\\|job' | tail -2", timeout=5)
                qlog = str(out_log or '').strip()
                if qlog and 'error' in qlog.lower():
                    task.log(f"  {drive_id}: mirror job failed - {qlog[:150]}")
                    return False
                ready_drives.add(drive_id)
                continue
            
            # Check if this specific drive is ready
            for job_line in jobs.split('\n'):
                if drive_id in job_line and 'ready' in job_line.lower():
                    ready_drives.add(drive_id)
                    break
            
            # Track progress toward 100%
            m_done = re.search(rf'{re.escape(drive_id)}.*?Completed\s+(\d+)\s+of\s+(\d+)', jobs)
            if m_done:
                done = int(m_done.group(1))
                total = int(m_done.group(2))
                if total > 0 and done >= total * 0.995:
                    if drive_id not in at_100_since:
                        at_100_since[drive_id] = time.time()
                else:
                    at_100_since.pop(drive_id, None)
                    all_near_100 = False
            else:
                all_near_100 = False
        
        # === PAUSE-PIVOT-RESUME: stuck at 100% on all drives ===
        # FUSE/SSHFS can't track dirty blocks → mirror never becomes "ready"
        # Solution: pause VM → no new writes → pivot → resume
        not_ready = drive_ids - ready_drives
        if not_ready and all_near_100 and at_100_since:
            oldest_100 = min(at_100_since.values()) if at_100_since else time.time()
            if time.time() - oldest_100 > PAUSE_PIVOT_AFTER:
                task.log(f"  All disks at 100% but not 'ready' - using pause-pivot-resume...")
                task.log(f"  Pausing VM for atomic pivot (~1-2s)...")
                
                # Step 1: Pause VM (HMP "stop" = freeze CPUs, NOT qm stop!)
                _qm_monitor_cmd(pve_mgr, node, vmid, "stop", timeout=10)
                time.sleep(1)
                
                # Step 2: Wait for mirrors to catch up (should be instant, no new I/O)
                ready_after_pause = set(ready_drives)
                for _wait in range(10):
                    time.sleep(1)
                    ok2, jobs2 = _qm_monitor_cmd(pve_mgr, node, vmid, "info block-jobs")
                    if ok2:
                        for drive_id, _, _ in mirrors:
                            if drive_id in ready_after_pause:
                                continue
                            if drive_id not in jobs2:
                                ready_after_pause.add(drive_id)
                            else:
                                for jl in jobs2.split('\n'):
                                    if drive_id in jl and 'ready' in jl.lower():
                                        ready_after_pause.add(drive_id)
                                        break
                    if ready_after_pause >= drive_ids:
                        break
                
                # Step 3: Pivot all drives
                pivot_ok = True
                for drive_id, disk_total, di in mirrors:
                    ok_p, out_p = _qm_monitor_cmd(pve_mgr, node, vmid,
                        f"block_job_complete {drive_id}", timeout=30)
                    if not ok_p and 'not ready' in str(out_p).lower():
                        # Force cancel + resume if pivot fails
                        task.log(f"  {drive_id}: pivot failed (not ready) - cancelling")
                        _qm_monitor_cmd(pve_mgr, node, vmid,
                            f"block_job_cancel {drive_id}")
                        pivot_ok = False
                    elif not ok_p:
                        task.log(f"  {drive_id}: pivot issue: {str(out_p)[:100]}")
                
                # Step 4: Wait for pivots to complete
                time.sleep(2)
                ok3, jobs3 = _qm_monitor_cmd(pve_mgr, node, vmid, "info block-jobs")
                remaining = [d for d in drive_ids if d in str(jobs3 or '')]
                if remaining:
                    time.sleep(3)
                    ok3, jobs3 = _qm_monitor_cmd(pve_mgr, node, vmid, "info block-jobs")
                    remaining = [d for d in drive_ids if d in str(jobs3 or '')]
                
                # Step 5: Resume VM
                _qm_monitor_cmd(pve_mgr, node, vmid, "cont", timeout=10)
                
                if not remaining and pivot_ok:
                    elapsed = time.time() - start_t
                    total_gb = sum(m[1] for m in mirrors) / (1024**3)
                    task.log(f"  Pause-pivot-resume complete! "
                             f"({total_gb:.1f} GB in {elapsed:.0f}s) - VM resumed on local storage ✓")
                    for drive_id, disk_total, di in mirrors:
                        task.update_progress(f'disk{di}', disk_total, disk_total)
                    return True
                else:
                    task.log(f"  Pivot during pause failed - VM resumed, falling back")
                    return False
        
        # Log progress periodically
        elapsed = time.time() - start_t
        if elapsed - last_log >= 10:
            for drive_id, disk_total, di in mirrors:
                if drive_id in ready_drives:
                    continue
                m = re.search(rf'{re.escape(drive_id)}.*?Completed\s+(\d+)\s+of\s+(\d+)', jobs)
                if m:
                    done = int(m.group(1))
                    total = int(m.group(2))
                    pct = done * 100 / max(total, 1)
                    speed = done / (1024*1024) / max(elapsed, 1)
                    task.log(f"  disk{di}: {pct:.1f}% ({speed:.0f} MB/s)")
                    task.update_progress(f'disk{di}', done, total)
            last_log = elapsed
        
        # All ready?
        if ready_drives >= drive_ids:
            break
    
    if ready_drives < drive_ids:
        missing = drive_ids - ready_drives
        task.log(f"  Timed out waiting for: {missing}")
        for d in missing:
            _qm_monitor_cmd(pve_mgr, node, vmid, f"block_job_cancel {d}")
        return False
    
    elapsed = time.time() - start_t
    total_gb = sum(m[1] for m in mirrors) / (1024**3)
    task.log(f"  All {len(mirrors)} disks synced in {elapsed:.0f}s ({total_gb:.1f} GB) - pivoting...")
    
    # Pivot ALL drives atomically
    for drive_id, disk_total, di in mirrors:
        ok, out = _qm_monitor_cmd(pve_mgr, node, vmid, f"block_job_complete {drive_id}", timeout=30)
        if not ok:
            task.log(f"  WARNING: pivot {drive_id} failed: {out[:150]}")
    
    # Wait for pivots to complete
    time.sleep(3)
    ok, jobs = _qm_monitor_cmd(pve_mgr, node, vmid, "info block-jobs")
    remaining = [d for d in drive_ids if d in str(jobs)]
    if remaining:
        time.sleep(5)
        ok, jobs = _qm_monitor_cmd(pve_mgr, node, vmid, "info block-jobs")
        remaining = [d for d in drive_ids if d in str(jobs)]
    
    if not remaining:
        task.log(f"  All pivots complete - VM now on local storage ✓")
    else:
        task.log(f"  WARNING: some pivots may be pending: {remaining}")
    
    return True


def _scsi_controller_args(pve_mgr, node, vmid, disk_bus):
    """Return QEMU args prefix to create SCSI controller if needed.
    When using custom args:, Proxmox won't auto-create the SCSI controller
    because we remove scsiN: disk lines from config."""
    if disk_bus != 'scsi':
        return ""
    # Read scsihw type from VM config
    rc, out, _ = _pve_node_exec(pve_mgr, node,
        f"grep '^scsihw:' /etc/pve/qemu-server/{vmid}.conf 2>/dev/null", timeout=5)
    scsihw_type = str(out or '').strip().split(':')[-1].strip() or 'pvscsi'
    scsi_device_map = {
        'pvscsi': 'pvscsi',
        'virtio-scsi-pci': 'virtio-scsi-pci',
        'virtio-scsi-single': 'virtio-scsi-pci',
        'lsi': 'lsi53c895a',
        'lsi53c810': 'lsi53c810',
        'megasas': 'megasas',
    }
    qemu_dev = scsi_device_map.get(scsihw_type, 'pvscsi')
    return f"-device {qemu_dev},id=scsihw0 "


def _pvesm_alloc_disk(pve_mgr, node, storage, vmid, disk_index, size_bytes):
    """Robustly allocate a disk via pvesm alloc.
    
    Handles all storage types (LVM-thin, ZFS, Dir, Ceph, NFS) and 
    various Proxmox versions by trying multiple command formats.
    
    Returns (vol_id, dev_path) or (None, None) on failure.
    """
    import re, math
    
    size_gb = max(1, math.ceil(size_bytes / (1024**3)))
    size_mb = max(1, int(size_bytes / (1024*1024)))
    size_kb = max(1024, int(size_bytes / 1024))
    
    # Detect storage type first
    storage_type = 'unknown'
    try:
        rc_st, out_st, _ = _pve_node_exec(pve_mgr, node,
            f"pvesm status --storage {storage} 2>&1 | grep -v '^Name'", timeout=10)
        st_parts = str(out_st or '').split()
        if len(st_parts) >= 2:
            storage_type = st_parts[1].lower()  # lvmthin, dir, zfspool, rbd, etc.
    except:
        pass
    
    # Build filename based on storage type
    if storage_type in ('dir', 'nfs', 'cifs', 'glusterfs', 'pbs'):
        # File-based storage needs extension
        fn_raw = f"vm-{vmid}-disk-{disk_index}.raw"
        fn_qcow = f"vm-{vmid}-disk-{disk_index}.qcow2"
    else:
        # Block-based storage (lvmthin, zfspool, rbd, iscsi, etc)
        fn_raw = f"vm-{vmid}-disk-{disk_index}"
        fn_qcow = fn_raw
    
    # Clean up any leftover volume from previous attempts
    # (common when migration was retried after failure)
    for old_fn in [fn_raw, fn_qcow]:
        old_vol = f"{storage}:{old_fn}"
        rc_chk, out_chk, _ = _pve_node_exec(pve_mgr, node,
            f"pvesm path {old_vol} 2>/dev/null", timeout=5)
        old_path = str(out_chk or '').strip()
        if rc_chk == 0 and old_path:
            _pve_node_exec(pve_mgr, node,
                f"pvesm free {old_vol} 2>/dev/null", timeout=15)
            # LVM-thin: also try lvremove in case pvesm free didn't work
            if storage_type in ('lvmthin', 'lvm') and '/dev/' in old_path:
                _pve_node_exec(pve_mgr, node,
                    f"lvremove -f {old_path} 2>/dev/null", timeout=15)
    # Also remove unused disk lines from VM config
    _pve_node_exec(pve_mgr, node,
        f"sed -i '/^unused.*vm-{vmid}-disk-{disk_index}/d' "
        f"/etc/pve/qemu-server/{vmid}.conf 2>/dev/null", timeout=5)
    
    # Try allocation methods in order of reliability
    alloc_attempts = [
        # 1. Proper filename + size in G (most reliable)
        f"pvesm alloc {storage} {vmid} {fn_raw} {size_gb}G 2>&1",
        # 2. Proper filename + size in KB (integer)
        f"pvesm alloc {storage} {vmid} {fn_raw} {size_kb} 2>&1",
        # 3. With --format raw
        f"pvesm alloc {storage} {vmid} {fn_raw} {size_gb}G --format raw 2>&1",
        # 4. qcow2 filename for dir storage
        f"pvesm alloc {storage} {vmid} {fn_qcow} {size_gb}G --format qcow2 2>&1",
        # 5. Size in MB
        f"pvesm alloc {storage} {vmid} {fn_raw} {size_mb}M 2>&1",
    ]
    
    last_error = ''
    for attempt_cmd in alloc_attempts:
        rc, out, _ = _pve_node_exec(pve_mgr, node, attempt_cmd, timeout=30)
        out_str = str(out or '').strip()
        
        if rc == 0 and '400' not in out_str and 'error' not in out_str.lower() and 'failed' not in out_str.lower():
            # Success -- extract vol_id
            vol_id = None
            # Match: storage:vm-123-disk-0 or storage:vm-123-disk-0.raw
            m = re.search(r"(\S+:vm-\d+-disk-\d+(?:\.\w+)?)", out_str)
            if m:
                vol_id = m.group(1).strip("'\"")
            elif out_str and ':' in out_str:
                # Sometimes output is just the vol_id
                vol_id = out_str.split('\n')[0].strip().strip("'\"")
            
            if not vol_id:
                vol_id = f"{storage}:{fn_raw}"
            
            # Get device path
            rc_p, out_p, _ = _pve_node_exec(pve_mgr, node,
                f"pvesm path {vol_id} 2>&1", timeout=10)
            dev_path = str(out_p or '').strip()
            
            if dev_path and rc_p == 0 and 'error' not in dev_path.lower():
                logging.info(f"[V2P] Disk allocated: {vol_id} → {dev_path} (via: {attempt_cmd[:60]})")
                return vol_id, dev_path
            else:
                logging.warning(f"[V2P] Alloc OK but path failed: {vol_id} → {dev_path}")
                # Try to derive path
                return vol_id, dev_path or f"/dev/{storage}/{fn_raw}"
        else:
            last_error = out_str[:150]
    
    # Last resort: Try via Proxmox REST API
    try:
        api_data = {
            'vmid': str(vmid),
            'filename': fn_raw,
            'size': f"{size_gb}G",
            'format': 'raw'
        }
        resp = pve_mgr._api_post(
            f"https://{pve_mgr.host}:8006/api2/json/nodes/{node}/storage/{storage}/content",
            data=api_data)
        if resp.status_code in (200, 201):
            result = resp.json().get('data', '')
            if result:
                vol_id = str(result).strip("'\"")
                rc_p, out_p, _ = _pve_node_exec(pve_mgr, node,
                    f"pvesm path {vol_id} 2>&1", timeout=10)
                dev_path = str(out_p or '').strip()
                logging.info(f"[V2P] Disk allocated via API: {vol_id} → {dev_path}")
                return vol_id, dev_path
    except Exception as e:
        logging.debug(f"[V2P] API alloc failed: {e}")
    
    logging.error(f"[V2P] All allocation methods failed for disk {disk_index}. Last: {last_error}")
    return None, None


def _setup_temp_ssh_key(pve_mgr, node, esxi_host, esxi_user, esxi_pass):
    """Create temporary SSH key and deploy to ESXi for passwordless access.
    Returns key_path or None on failure.
    
    Strategy: Generate key on Proxmox node, deploy to ESXi via paramiko
    (which handles keyboard-interactive auth that ESXi requires).
    sshpass can't reliably handle keyboard-interactive, so we use paramiko
    from the management server to run the deployment commands on ESXi.
    """
    import uuid
    key_id = str(uuid.uuid4())[:8]
    key_path = f"/tmp/v2p-key-{key_id}"
    
    # SSH options for key-based verification (after deployment)
    ESXI_SSH_OPTS = (
        "-o StrictHostKeyChecking=no "
        "-o UserKnownHostsFile=/dev/null "
        "-o LogLevel=ERROR "
        "-o HostKeyAlgorithms=+ssh-rsa,ssh-ed25519,ecdsa-sha2-nistp256 "
        "-o PubkeyAcceptedAlgorithms=+ssh-rsa,ssh-ed25519 "
        "-o KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group14-sha256,ecdh-sha2-nistp256 "
    )
    
    # Step 1: Test SSH connectivity via paramiko (keyboard-interactive)
    logging.info(f"[V2P] Testing SSH to {esxi_host} via paramiko...")
    rc_test, out_test, err_test = _ssh_exec(esxi_host, esxi_user, esxi_pass, 'echo SSH_OK', timeout=15)
    if rc_test != 0 or 'SSH_OK' not in str(out_test or ''):
        logging.error(f"[V2P] Cannot SSH to ESXi: {err_test or out_test}")
        return None
    logging.info(f"[V2P] SSH to ESXi OK (paramiko)")
    
    # Generate key on Proxmox node -- RSA first (best ESXi compatibility)
    key_generated = False
    for key_type, key_opts in [("rsa -b 4096", "rsa"), ("ed25519", "ed25519")]:
        rc, out, _ = _pve_node_exec(pve_mgr, node,
            f"ssh-keygen -t {key_type} -f {key_path} -N '' -q -C 'pegaprox-v2p-{key_id}' 2>&1",
            timeout=10)
        if rc == 0:
            key_generated = True
            logging.info(f"[V2P] Generated {key_opts} key: {key_path}")
            break
        else:
            _pve_node_exec(pve_mgr, node, f"rm -f {key_path} {key_path}.pub", timeout=5)
    
    if not key_generated:
        logging.error("[V2P] Failed to generate SSH key")
        return None
    
    # Read public key from Proxmox node
    rc_pk, pub_key, _ = _pve_node_exec(pve_mgr, node, f"cat {key_path}.pub", timeout=5)
    pub = str(pub_key or '').strip()
    if not pub:
        _pve_node_exec(pve_mgr, node, f"rm -f {key_path} {key_path}.pub", timeout=5)
        return None
    
    # Step 3: Deploy public key to ESXi via paramiko (handles keyboard-interactive)
    deployed = False
    
    # Method A: ESXi standard path /etc/ssh/keys-<username>/authorized_keys
    deploy_cmd_a = (
        f"mkdir -p /etc/ssh/keys-{shlex.quote(esxi_user)} 2>/dev/null; "
        f"echo {shlex.quote(pub)} >> /etc/ssh/keys-{shlex.quote(esxi_user)}/authorized_keys; "
        f"echo DEPLOYED"
    )
    rc_a, out_a, _ = _ssh_exec(esxi_host, esxi_user, esxi_pass, deploy_cmd_a, timeout=15)
    if 'DEPLOYED' in str(out_a or ''):
        deployed = True
        logging.info(f"[V2P] Key deployed via ESXi keys-{esxi_user} path (paramiko)")
    else:
        logging.debug(f"[V2P] Method A failed: {str(out_a or '')[:150]}")
    
    # Method B: ~/.ssh/authorized_keys (custom ESXi builds)
    if not deployed:
        deploy_cmd_b = (
            f"mkdir -p ~/.ssh 2>/dev/null; chmod 700 ~/.ssh 2>/dev/null; "
            f"echo {shlex.quote(pub)} >> ~/.ssh/authorized_keys; chmod 600 ~/.ssh/authorized_keys 2>/dev/null; "
            f"echo DEPLOYED"
        )
        rc_b, out_b, _ = _ssh_exec(esxi_host, esxi_user, esxi_pass, deploy_cmd_b, timeout=15)
        if 'DEPLOYED' in str(out_b or ''):
            deployed = True
            logging.info("[V2P] Key deployed via ~/.ssh/authorized_keys (paramiko)")
        else:
            logging.debug(f"[V2P] Method B failed: {str(out_b or '')[:150]}")
    
    # Method C: Both paths at once
    if not deployed:
        deploy_cmd_c = (
            f"mkdir -p /etc/ssh/keys-{shlex.quote(esxi_user)} ~/.ssh 2>/dev/null; "
            f"echo {shlex.quote(pub)} >> /etc/ssh/keys-{shlex.quote(esxi_user)}/authorized_keys 2>/dev/null; "
            f"echo {shlex.quote(pub)} >> ~/.ssh/authorized_keys 2>/dev/null; "
            f"echo DEPLOYED"
        )
        rc_c, out_c, _ = _ssh_exec(esxi_host, esxi_user, esxi_pass, deploy_cmd_c, timeout=15)
        if 'DEPLOYED' in str(out_c or ''):
            deployed = True
            logging.info("[V2P] Key deployed via both paths (paramiko)")
        else:
            logging.debug(f"[V2P] Method C failed: {str(out_c or '')[:150]}")
    
    if not deployed:
        logging.error("[V2P] All SSH key deployment methods failed")
        _pve_node_exec(pve_mgr, node, f"rm -f {key_path} {key_path}.pub", timeout=5)
        return None
    
    # Step 4: Verify key-based login from Proxmox node
    rc_v, out_v, _ = _pve_node_exec(pve_mgr, node,
        f"ssh -i {key_path} {ESXI_SSH_OPTS} "
        f"-o BatchMode=yes -o ConnectTimeout=10 "
        f"{esxi_user}@{esxi_host} 'echo KEYOK' 2>&1", timeout=20)
    v_out = str(out_v or '')
    if 'KEYOK' not in v_out:
        # Try without BatchMode (can be too strict on some ESXi)
        rc_v2, out_v2, _ = _pve_node_exec(pve_mgr, node,
            f"ssh -i {key_path} {ESXI_SSH_OPTS} "
            f"-o PasswordAuthentication=no -o ConnectTimeout=10 "
            f"{esxi_user}@{esxi_host} 'echo KEYOK' 2>&1", timeout=20)
        if 'KEYOK' not in str(out_v2 or ''):
            logging.error(f"[V2P] Key deployed but verification failed: {v_out[:200]} / {str(out_v2 or '')[:200]}")
            _pve_node_exec(pve_mgr, node, f"rm -f {key_path} {key_path}.pub", timeout=5)
            return None
    
    # Step 6: Write an SSH config snippet for QEMU (includes algorithm workarounds)
    ssh_config_path = f"/tmp/v2p-sshcfg-{key_id}"
    ssh_config = (
        f"Host {esxi_host}\n"
        f"  HostName {esxi_host}\n"
        f"  User {esxi_user}\n"
        f"  IdentityFile {key_path}\n"
        f"  StrictHostKeyChecking no\n"
        f"  UserKnownHostsFile /dev/null\n"
        f"  HostKeyAlgorithms +ssh-rsa,ssh-ed25519,ecdsa-sha2-nistp256\n"
        f"  PubkeyAcceptedAlgorithms +ssh-rsa,ssh-ed25519\n"
        f"  KexAlgorithms +diffie-hellman-group14-sha1,diffie-hellman-group14-sha256\n"
        f"  LogLevel ERROR\n"
    )
    _pve_node_exec(pve_mgr, node,
        f"cat > {ssh_config_path} << 'SSHCFG'\n{ssh_config}SSHCFG", timeout=5)
    _pve_node_exec(pve_mgr, node, f"chmod 600 {ssh_config_path}", timeout=5)
    
    logging.info(f"[V2P] SSH key ready: {key_path} (config: {ssh_config_path})")
    return key_path


def _cleanup_temp_ssh_key(pve_mgr, node, key_path, esxi_host, esxi_user):
    """Remove temporary SSH key from Proxmox and ESXi."""
    if not key_path:
        return
    
    # Extract key_id from path for config cleanup
    key_id = key_path.replace('/tmp/v2p-key-', '')
    ssh_config_path = f"/tmp/v2p-sshcfg-{key_id}"
    
    ESXI_SSH_OPTS = (
        "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
        "-o LogLevel=ERROR "
        "-o HostKeyAlgorithms=+ssh-rsa,ssh-ed25519 "
        "-o PubkeyAcceptedAlgorithms=+ssh-rsa,ssh-ed25519 "
        "-o KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group14-sha256 "
        "-o PreferredAuthentications=keyboard-interactive,password "
    )
    
    # Read public key to build removal pattern
    rc, pub_key, _ = _pve_node_exec(pve_mgr, node, f"cat {key_path}.pub 2>/dev/null", timeout=5)
    if rc == 0 and pub_key and pub_key.strip():
        # Remove from ESXi -- both paths
        _pve_node_exec(pve_mgr, node,
            f"ssh -i {key_path} {ESXI_SSH_OPTS} "
            f"{esxi_user}@{esxi_host} "
            f"'grep -v \"pegaprox-v2p-{key_id}\" /etc/ssh/keys-{esxi_user}/authorized_keys > "
            f"/etc/ssh/keys-{esxi_user}/authorized_keys.tmp 2>/dev/null && "
            f"mv /etc/ssh/keys-{esxi_user}/authorized_keys.tmp /etc/ssh/keys-{esxi_user}/authorized_keys 2>/dev/null; "
            f"grep -v \"pegaprox-v2p-{key_id}\" ~/.ssh/authorized_keys > ~/.ssh/authorized_keys.tmp 2>/dev/null && "
            f"mv ~/.ssh/authorized_keys.tmp ~/.ssh/authorized_keys 2>/dev/null; "
            f"echo CLEANED' 2>&1", timeout=10)
    
    # Remove local key files + SSH config
    _pve_node_exec(pve_mgr, node,
        f"rm -f {key_path} {key_path}.pub {ssh_config_path}", timeout=5)


def _setup_copy_isolation(pve_mgr, node, esxi_host, vmid):
    """Setup resource isolation so copy process doesn't impact the running VM.
    
    Creates:
    - cgroup v2 with I/O weight 10 (VM default=100, so VM gets 10x priority)
    - Network QoS: limit migration traffic to 80% of link
    - I/O scheduler: mq-deadline for target device
    - OOM score: copy processes die first if memory is tight
    
    Returns dict with cleanup info.
    """
    iso = {'cgroup': None, 'tc_dev': None, 'scheduler_restore': None}
    
    # --- cgroup v2: low I/O weight for copy ---
    cg_name = f"v2p-copy-{vmid}"
    rc, _, _ = _pve_node_exec(pve_mgr, node,
        f"if [ -d /sys/fs/cgroup ]; then "
        f"  mkdir -p /sys/fs/cgroup/{cg_name} 2>/dev/null; "
        f"  echo '10' > /sys/fs/cgroup/{cg_name}/io.weight 2>/dev/null; "
        f"  echo '100' > /sys/fs/cgroup/{cg_name}/io.bfq.weight 2>/dev/null; "
        f"  echo 'OK'; "
        f"fi", timeout=5)
    if rc == 0:
        iso['cgroup'] = cg_name
    
    # --- Network QoS: limit outgoing migration traffic to ~80% link ---
    # Find network interface to ESXi
    rc_dev, out_dev, _ = _pve_node_exec(pve_mgr, node,
        f"ip route get {esxi_host} 2>/dev/null | grep -oP 'dev \\K\\S+'", timeout=5)
    net_dev = str(out_dev or '').strip()
    if net_dev:
        # Detect link speed
        rc_sp, out_sp, _ = _pve_node_exec(pve_mgr, node,
            f"cat /sys/class/net/{net_dev}/speed 2>/dev/null || echo 1000", timeout=3)
        link_mbps = int(str(out_sp or '1000').strip() or '1000')
        limit_mbit = int(link_mbps * 0.8)
        
        # tc: rate-limit the interface for migration traffic (dest port range)
        # Uses a simple tbf (token bucket filter) -- won't affect VM traffic much
        # since VM uses different ports
        _pve_node_exec(pve_mgr, node,
            f"tc qdisc del dev {net_dev} root 2>/dev/null; "
            f"tc qdisc add dev {net_dev} root handle 1: htb default 10; "
            f"tc class add dev {net_dev} parent 1: classid 1:1 htb rate {link_mbps}mbit; "
            f"tc class add dev {net_dev} parent 1:1 classid 1:10 htb rate {link_mbps}mbit; "
            f"tc class add dev {net_dev} parent 1:1 classid 1:20 htb rate {limit_mbit}mbit ceil {link_mbps}mbit; "
            f"tc filter add dev {net_dev} parent 1: protocol ip u32 "
            f"match ip dst {esxi_host}/32 flowid 1:20 2>/dev/null || true",
            timeout=10)
        iso['tc_dev'] = net_dev
    
    # --- I/O scheduler: mq-deadline is best for sequential bulk writes ---
    rc_tgt, out_tgt, _ = _pve_node_exec(pve_mgr, node,
        "lsblk -ndo NAME $(pvesm path local-lvm:nonexist 2>/dev/null | "
        "sed 's|/dev/||;s|/.*||') 2>/dev/null | head -1 || "
        "lsblk -ndo NAME /dev/sda 2>/dev/null | head -1", timeout=5)
    blk_dev = str(out_tgt or '').strip()
    if blk_dev:
        rc_sched, out_sched, _ = _pve_node_exec(pve_mgr, node,
            f"cat /sys/block/{blk_dev}/queue/scheduler 2>/dev/null", timeout=3)
        old_sched = str(out_sched or '').strip()
        # Extract current scheduler (in brackets)
        import re
        m = re.search(r'\[(\w+)\]', old_sched)
        if m:
            iso['scheduler_restore'] = (blk_dev, m.group(1))
        _pve_node_exec(pve_mgr, node,
            f"echo mq-deadline > /sys/block/{blk_dev}/queue/scheduler 2>/dev/null || true",
            timeout=3)
    
    return iso


def _cleanup_copy_isolation(pve_mgr, node, iso):
    """Remove resource isolation after copy completes."""
    
    # Remove cgroup
    if iso.get('cgroup'):
        _pve_node_exec(pve_mgr, node,
            f"rmdir /sys/fs/cgroup/{iso['cgroup']} 2>/dev/null || true", timeout=5)
    
    # Remove tc QoS
    if iso.get('tc_dev'):
        _pve_node_exec(pve_mgr, node,
            f"tc qdisc del dev {iso['tc_dev']} root 2>/dev/null || true", timeout=5)
    
    # Restore I/O scheduler
    if iso.get('scheduler_restore'):
        blk, sched = iso['scheduler_restore']
        _pve_node_exec(pve_mgr, node,
            f"echo {sched} > /sys/block/{blk}/queue/scheduler 2>/dev/null || true", timeout=3)
    
    # Drop page caches (free RAM back to VM)
    _pve_node_exec(pve_mgr, node,
        "sync; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true", timeout=5)


def _qemu_img_ssh_copy(pve_mgr, task, esxi_host, esxi_user, key_path,
                        datastore, vm_dir, descriptor_files, disk_bus):
    """Copy disks from ESXi to Proxmox -- maximum speed, minimal VM impact.
    
    Speed stack:
    - Compression (lz4/gzip): 32GB disk with 8GB data → ~3-5GB over wire
    - Netcat: no encryption overhead = full line-rate
    - conv=sparse + oflag=direct: skip zeros, bypass page cache (no VM RAM pressure)
    - nice -n19 ionice -c3: idle priority (VM I/O always has priority)
    - Parallel streams: saturate link
    - Large blocks (4MB) + iflag=fullblock: no short reads
    - Pipe buffer 1MB: fewer context switches
    - mbuffer 128MB: smooth out burst I/O
    - TCP tuning: 16MB window
    - xxhash verify: fast integrity check after copy
    
    Methods tried in order:
    1. netcat + compression (fastest: no crypto + compressed)
    2. SSH + compression + parallel streams  
    3. SSH single stream (always works)
    
    Returns True on success, False on failure.
    """
    import time, re, math, random
    
    BS_MB = 4
    esxi_pass = task.config.get('esxi_password', '')
    safe_pass = shlex.quote(esxi_pass)

    # Build SSH command prefix -- works with key or password
    # Include legacy algorithm options for ESXi compatibility (OpenSSH 9.x → ESXi)
    ESXI_ALGO_OPTS = (
        "-o HostKeyAlgorithms=+ssh-rsa,ssh-ed25519,ecdsa-sha2-nistp256 "
        "-o PubkeyAcceptedAlgorithms=+ssh-rsa,ssh-ed25519 "
        "-o KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group14-sha256,ecdh-sha2-nistp256 "
        "-o PreferredAuthentications=keyboard-interactive,password "
    )
    if key_path:
        ssh_base = (
            f"-i {key_path} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            f"-o ServerAliveInterval=30 -o ServerAliveCountMax=5 "
            f"{ESXI_ALGO_OPTS}"
        )
        SSH_PREFIX = "ssh"
    else:
        ssh_base = (
            f"-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            f"-o ServerAliveInterval=30 -o ServerAliveCountMax=5 "
            f"{ESXI_ALGO_OPTS}"
        )
        SSH_PREFIX = f"sshpass -p {safe_pass} ssh"
    ssh_fast = f"{ssh_base} -o Compression=no -c aes128-gcm@openssh.com"
    
    # nice/ionice: idle priority so VM I/O is never impacted
    NICE = "nice -n 19 ionice -c 3"
    # dd flags: iflag=fullblock prevents short reads, oflag=direct bypasses page cache
    DD_READ = f"dd iflag=fullblock bs={BS_MB}M"
    DD_WRITE_SPARSE = f"dd oflag=direct bs={BS_MB}M conv=sparse,notrunc"
    DD_WRITE_SEEK = f"dd oflag=direct bs={BS_MB}M conv=notrunc"
    
    # ================================================================
    # TOOL DETECTION (run once, reuse for all disks)
    # ================================================================
    esxi_pass = task.config.get('esxi_password', '')
    
    # Proxmox IP
    rc_ip, out_ip, _ = _pve_node_exec(pve_mgr, task.target_node,
        f"ip route get {esxi_host} 2>/dev/null | grep -oP 'src \\K[0-9.]+'", timeout=5)
    pve_ip = str(out_ip or '').strip()
    
    # ESXi capabilities
    rc_tools, tools_out, _ = _ssh_exec(esxi_host, esxi_user, esxi_pass,
        "echo NC=$(which nc 2>/dev/null || echo NO);"
        "echo LZ4=$(which lz4 2>/dev/null || echo NO);"
        "echo GZIP=$(which gzip 2>/dev/null || echo NO);"
        "echo PIGZ=$(which pigz 2>/dev/null || echo NO);"
        "echo XXHASH=$(which xxhsum 2>/dev/null || which xxh128sum 2>/dev/null || echo NO)",
        timeout=10)
    tools_str = str(tools_out or '')
    esxi_nc = 'NC=/' in tools_str
    esxi_lz4 = 'LZ4=/' in tools_str
    esxi_gzip = 'GZIP=/' in tools_str
    esxi_pigz = 'PIGZ=/' in tools_str
    esxi_xxhash = 'XXHASH=/' in tools_str
    
    task.log(f"ESXi tools: nc={esxi_nc}, lz4={esxi_lz4}, gzip={esxi_gzip}, pigz={esxi_pigz}")
    
    # Proxmox: ensure tools installed
    _pve_node_exec(pve_mgr, task.target_node,
        "which lz4 >/dev/null 2>&1 || apt-get install -y lz4 2>&1 | tail -1", timeout=20)
    _pve_node_exec(pve_mgr, task.target_node,
        "which mbuffer >/dev/null 2>&1 || apt-get install -y mbuffer 2>&1 | tail -1", timeout=20)
    
    # Compression strategy: lz4 > pigz > gzip-1 > none
    if esxi_lz4:
        esxi_compress = "lz4 -1 -"
        pve_decompress = "lz4 -d -"
        compress_name = "lz4"
    elif esxi_pigz:
        esxi_compress = "pigz -1"
        pve_decompress = "pigz -d"
        compress_name = "pigz"
    elif esxi_gzip:
        esxi_compress = "gzip -1"
        pve_decompress = "gunzip"
        compress_name = "gzip-1"
    else:
        esxi_compress = "cat"
        pve_decompress = "cat"
        compress_name = "none"
    
    task.log(f"Compression: {compress_name}")
    
    # TCP tuning + pipe buffer on Proxmox
    _pve_node_exec(pve_mgr, task.target_node,
        "sysctl -w net.core.rmem_max=16777216 net.core.wmem_max=16777216 "
        "net.ipv4.tcp_rmem='4096 87380 16777216' "
        "net.ipv4.tcp_wmem='4096 87380 16777216' "
        "net.ipv4.tcp_window_scaling=1 2>/dev/null || true;"
        # Increase default pipe buffer from 64KB to 1MB
        "sysctl -w fs.pipe-max-size=1048576 2>/dev/null || true", timeout=5)
    
    # ESXi: set readahead on datastore device for sequential reads
    _ssh_exec(esxi_host, esxi_user, esxi_pass,
        f"DISK=$(df /vmfs/volumes/{shlex.quote(datastore)} 2>/dev/null | tail -1 | awk '{{print $1}}');"
        f"[ -n \"$DISK\" ] && blockdev --setra 16384 $DISK 2>/dev/null || true",
        timeout=10)
    
    # ================================================================
    # RESOURCE ISOLATION -- keep copy from impacting VM
    # ================================================================
    iso = _setup_copy_isolation(pve_mgr, task.target_node, esxi_host, task.proxmox_vmid)
    cg = iso.get('cgroup')
    # Prefix for running commands in cgroup with low OOM score
    CG_EXEC = ""
    if cg:
        CG_EXEC = f"echo $$ > /sys/fs/cgroup/{cg}/cgroup.procs 2>/dev/null; "
        task.log(f"Resource isolation: cgroup={cg}, io.weight=10")
    if iso.get('tc_dev'):
        task.log(f"Network QoS: migration limited to 80% on {iso['tc_dev']}")
    
    for di, desc_file in enumerate(descriptor_files):
        dk = f'disk{di}'
        flat_file = desc_file.replace('.vmdk', '-flat.vmdk')
        esxi_path = f"/vmfs/volumes/{datastore}/{vm_dir}/{flat_file}"
        disk_total = task.disk_progress[dk]['total']
        disk_gb = disk_total / (1024**3)
        
        task.log(f"Disk {di}: {flat_file} ({disk_gb:.1f} GB)")
        
        # Allocate volume using robust helper
        vol_id, dev_path = _pvesm_alloc_disk(pve_mgr, task.target_node, 
            task.target_storage, task.proxmox_vmid, di, disk_total)
        
        task.log(f"  Target: {vol_id} → {dev_path}")
        if not vol_id or not dev_path:
            task.log(f"  Disk allocation failed for disk {di}")
            _cleanup_copy_isolation(pve_mgr, task.target_node, iso)
            return False
        
        copied = False
        
        # ==============================================================
        # METHOD 1: Netcat + Compression -- fastest possible
        # ==============================================================
        if pve_ip and esxi_nc:
            port = random.randint(49152, 65000)
            task.log(f"  Method 1: nc+{compress_name} ({esxi_host}→{pve_ip}:{port})")
            
            script = f"/tmp/v2p-nc-{task.id[:8]}-d{di}.sh"
            nc_script = f"""#!/bin/bash
# Resource isolation: low I/O priority + high OOM score + cgroup
{CG_EXEC}
echo 1000 > /proc/self/oom_score_adj 2>/dev/null || true
ulimit -p 1048576 2>/dev/null || true

# Receiver: listen → decompress → mbuffer → sparse direct-write
# nice/ionice: idle priority so VM I/O is never impacted
{NICE} nc -l -p {port} -w 300 \\
  | mbuffer -q -s {BS_MB}M -m 128M 2>/dev/null \\
  | {pve_decompress} \\
  | {NICE} {DD_WRITE_SPARSE} of={dev_path} 2>/dev/null &
RECV=$!
sleep 1

# Sender: read → compress → nc
{SSH_PREFIX} {ssh_base} {esxi_user}@{esxi_host} \\
  "{NICE} {DD_READ} if={esxi_path} 2>/dev/null | {esxi_compress} | nc -w 120 {pve_ip} {port}" &
SEND=$!

wait $SEND 2>/dev/null; S=$?
wait $RECV 2>/dev/null; R=$?
exit $((S + R))
"""
            _pve_node_exec(pve_mgr, task.target_node,
                f"cat > {script} << 'NCEOF'\n{nc_script}\nNCEOF\nchmod +x {script}", timeout=10)
            
            start_time = time.time()
            rc_nc_r, _, _ = _pve_node_exec(pve_mgr, task.target_node,
                f"bash {script} 2>&1", timeout=86400)
            _pve_node_exec(pve_mgr, task.target_node, f"rm -f {script}", timeout=5)
            elapsed = time.time() - start_time
            
            if rc_nc_r == 0 and elapsed > 2:
                speed = disk_gb * 1024 / max(elapsed, 1)
                task.log(f"  ✓ nc+{compress_name}: {elapsed:.0f}s, {speed:.0f} MB/s effective")
                copied = True
            else:
                task.log(f"  nc+{compress_name} failed (rc={rc_nc_r}, {elapsed:.0f}s)")
                _pve_node_exec(pve_mgr, task.target_node,
                    f"kill $(lsof -ti :{port}) 2>/dev/null; true", timeout=5)
        
        # ==============================================================
        # METHOD 2: SSH + compression + parallel streams
        # ==============================================================
        if not copied:
            total_blocks = math.ceil(disk_total / (BS_MB * 1024 * 1024))
            NUM_STREAMS = min(4, max(1, total_blocks // 4))
            bps = math.ceil(total_blocks / NUM_STREAMS)
            
            task.log(f"  Method 2: SSH+{compress_name} × {NUM_STREAMS} streams")
            
            script = f"/tmp/v2p-ssh-{task.id[:8]}-d{di}.sh"
            lines = [
                "#!/bin/bash",
                f"{CG_EXEC}",
                "echo 1000 > /proc/self/oom_score_adj 2>/dev/null || true",
                "ulimit -p 1048576 2>/dev/null || true"
            ]
            for s in range(NUM_STREAMS):
                skip = s * bps
                count = min(bps, total_blocks - skip)
                if count <= 0: break
                if compress_name != 'none':
                    lines.append(
                        f'{NICE} {SSH_PREFIX} {ssh_fast} {esxi_user}@{esxi_host} '
                        f'"{NICE} {DD_READ} if={esxi_path} skip={skip} count={count} 2>/dev/null | {esxi_compress}" '
                        f'| {pve_decompress} '
                        f'| {NICE} {DD_WRITE_SEEK} of={dev_path} seek={skip} 2>/dev/null &'
                    )
                else:
                    lines.append(
                        f'{NICE} {SSH_PREFIX} {ssh_fast} {esxi_user}@{esxi_host} '
                        f'"{NICE} {DD_READ} if={esxi_path} skip={skip} count={count} 2>/dev/null" '
                        f'| {NICE} {DD_WRITE_SEEK} of={dev_path} seek={skip} 2>/dev/null &'
                    )
            lines.append("wait")
            
            _pve_node_exec(pve_mgr, task.target_node,
                f"cat > {script} << 'SSHEOF'\n" + "\n".join(lines) + "\nSSHEOF\n"
                f"chmod +x {script}", timeout=10)
            
            start_time = time.time()
            rc_ssh, _, _ = _pve_node_exec(pve_mgr, task.target_node,
                f"bash {script} 2>&1", timeout=86400)
            _pve_node_exec(pve_mgr, task.target_node, f"rm -f {script}", timeout=5)
            elapsed = time.time() - start_time
            
            if rc_ssh == 0:
                speed = disk_gb * 1024 / max(elapsed, 1)
                task.log(f"  ✓ SSH+{compress_name}: {elapsed:.0f}s, {speed:.0f} MB/s effective")
                copied = True
            else:
                task.log(f"  SSH parallel failed (rc={rc_ssh})")
        
        # ==============================================================
        # METHOD 3: Single SSH + compression (always works)
        # ==============================================================
        if not copied:
            task.log(f"  Method 3: SSH single + {compress_name}")
            script = f"/tmp/v2p-s-{task.id[:8]}-d{di}.sh"
            if compress_name != 'none':
                pipe = (
                    f'{NICE} {SSH_PREFIX} {ssh_fast} {esxi_user}@{esxi_host} '
                    f'"{NICE} {DD_READ} if={esxi_path} 2>/dev/null | {esxi_compress}" '
                    f'| {pve_decompress} | {NICE} {DD_WRITE_SPARSE} of={dev_path} 2>/dev/null'
                )
            else:
                pipe = (
                    f'{NICE} {SSH_PREFIX} {ssh_fast} {esxi_user}@{esxi_host} '
                    f'"{NICE} {DD_READ} if={esxi_path} 2>/dev/null" '
                    f'| {NICE} {DD_WRITE_SPARSE} of={dev_path} 2>/dev/null'
                )
            _pve_node_exec(pve_mgr, task.target_node,
                f"cat > {script} << 'SEOF'\n#!/bin/bash\n{CG_EXEC}\n"
                f"echo 1000 > /proc/self/oom_score_adj 2>/dev/null || true\n"
                f"{pipe}\nSEOF\nchmod +x {script}",
                timeout=10)
            
            start_time = time.time()
            rc_s, _, _ = _pve_node_exec(pve_mgr, task.target_node,
                f"bash {script} 2>&1", timeout=86400)
            _pve_node_exec(pve_mgr, task.target_node, f"rm -f {script}", timeout=5)
            elapsed = time.time() - start_time
            
            if rc_s == 0:
                speed = disk_gb * 1024 / max(elapsed, 1)
                task.log(f"  ✓ {elapsed:.0f}s, {speed:.0f} MB/s effective")
                copied = True
            else:
                task.log(f"  All methods failed!")
                _cleanup_copy_isolation(pve_mgr, task.target_node, iso)
                return False
        
        task.update_progress(dk, disk_total, disk_total)
        
        # ==============================================================
        # VERIFY: Quick hash check (xxhash = ~10 GB/s, negligible time)
        # ==============================================================
        rc_xxh, _, _ = _pve_node_exec(pve_mgr, task.target_node,
            "which xxhsum >/dev/null 2>&1 || which xxh128sum >/dev/null 2>&1", timeout=3)
        if rc_xxh == 0 and esxi_xxhash and disk_gb < 100:  # Only for disks < 100GB
            task.log(f"  Verifying integrity (xxhash)...")
            # Hash first 64MB + last 64MB (spot check, not full hash)
            verify_script = f"/tmp/v2p-verify-{task.id[:8]}-d{di}.sh"
            verify_body = f"""#!/bin/bash
# Hash first 64MB + last 64MB on both sides
ESX_HASH=$({SSH_PREFIX} {ssh_base} {esxi_user}@{esxi_host} "{{
  dd if={esxi_path} bs=1M count=64 2>/dev/null;
  dd if={esxi_path} bs=1M skip=$((({disk_total} / 1048576) - 64)) count=64 2>/dev/null;
}}" | xxhsum 2>/dev/null | awk '{{print $1}}')

PVE_HASH=$({{
  dd if={dev_path} bs=1M count=64 2>/dev/null;
  dd if={dev_path} bs=1M skip=$((({disk_total} / 1048576) - 64)) count=64 2>/dev/null;
}} | xxhsum 2>/dev/null | awk '{{print $1}}')

if [ "$ESX_HASH" = "$PVE_HASH" ] && [ -n "$ESX_HASH" ]; then
  echo "MATCH:$ESX_HASH"
else
  echo "MISMATCH:ESX=$ESX_HASH PVE=$PVE_HASH"
fi
"""
            _pve_node_exec(pve_mgr, task.target_node,
                f"cat > {verify_script} << 'VEOF'\n{verify_body}\nVEOF\nchmod +x {verify_script}",
                timeout=10)
            rc_v, out_v, _ = _pve_node_exec(pve_mgr, task.target_node,
                f"bash {verify_script} 2>&1", timeout=120)
            _pve_node_exec(pve_mgr, task.target_node, f"rm -f {verify_script}", timeout=5)
            v_out = str(out_v or '').strip()
            if 'MATCH:' in v_out:
                task.log(f"  ✓ Verified: {v_out.split(':',1)[1][:16]}")
            elif 'MISMATCH' in v_out:
                task.log(f"  ⚠ Hash mismatch! {v_out} - disk may need re-copy")
            else:
                task.log(f"  Verify skipped (tools not available)")
        
        # Attach to VM
        _pve_node_exec(pve_mgr, task.target_node,
            f"qm set {task.proxmox_vmid} --{disk_bus}{di} {vol_id} 2>&1", timeout=15)
        task.log(f"  Attached {disk_bus}{di}: {vol_id}")
    
    # Cleanup resource isolation
    _cleanup_copy_isolation(pve_mgr, task.target_node, iso)
    task.log("Resource isolation cleaned up, page cache dropped")
    
    return True


def _do_sshfs_boot_migration(pve_mgr, task, vmware_mgr, esxi_host, esxi_user, esxi_pass,
                              datastore, vm_dir, descriptor_files, disk_bus, mnt_path):
    """Near-zero downtime migration using QEMU's native SSH block driver.
    
    QEMU has a built-in SSH block driver (libssh) that is MUCH faster than SSHFS/FUSE
    for random I/O because:
    - No FUSE kernel roundtrips
    - QEMU cache=writeback caches reads in host RAM
    - Async I/O with multiple reads in flight
    - Block-layer readahead
    
    Flow:
    1. Deploy SSH key to ESXi
    2. Allocate empty local volumes (target)
    3. Start Proxmox VM with QEMU args pointing to SSH drive (cache=writeback)
    4. VM boots from SSH - DOWNTIME ENDS (~15-30s total)
    5. Background: drive-mirror copies SSH → local (VM keeps running)
    6. When mirror done: brief stop, reconfig to local disk, restart
    
    VMware VM must already be stopped before calling this.
    """
    import time
    
    task.set_phase('cutover')
    
    # ================================================================
    # Setup SSH key for passwordless access  -- NS Feb 2026
    # ================================================================
    task.log("=== NEAR-ZERO DOWNTIME: QEMU SSH boot + live mirror ===")
    
    # Ensure sshpass available
    rc_sp, _, _ = _pve_node_exec(pve_mgr, task.target_node, "which sshpass 2>/dev/null", timeout=5)
    if rc_sp != 0:
        task.log("Installing sshpass...")
        _pve_node_exec(pve_mgr, task.target_node, "apt-get install -y sshpass 2>&1 | tail -1", timeout=30)
    
    task.log("Deploying SSH key to ESXi...")
    key_path = _setup_temp_ssh_key(pve_mgr, task.target_node, esxi_host, esxi_user, esxi_pass)
    ssh_tunnel_port = None
    
    if not key_path:
        task.log("SSH key deployment failed - trying SSH tunnel workaround...")
        
        # WORKAROUND: Create a local SSH tunnel using sshpass, 
        # then QEMU connects to localhost with a temporary key
        # This works because QEMU SSH driver connects to a LOCAL sshd/socat proxy
        import random
        tunnel_port = random.randint(10000, 60000)
        safe_pass = shlex.quote(esxi_pass)
        
        # Generate a local-only key pair (no ESXi deployment needed)
        local_key = f"/tmp/v2p-localkey-{task.id[:8]}"
        _pve_node_exec(pve_mgr, task.target_node,
            f"ssh-keygen -t rsa -b 2048 -f {local_key} -N '' -q -C 'v2p-local' 2>&1", timeout=10)
        
        # Option A: Use socat + sshpass as a TCP-to-SSH-SFTP bridge
        # Option B: Just fall back to offline copy (simpler, proven)
        
        task.log("SSH key setup failed - using sshpass for direct copy")
        task.log("(QEMU SSH boot requires key auth; falling back to offline copy)")
        _do_offline_qemuimg_copy(pve_mgr, task, esxi_host, esxi_user, esxi_pass,
                                  datastore, vm_dir, descriptor_files, disk_bus, mnt_path)
        _pve_node_exec(pve_mgr, task.target_node, f"rm -f {local_key} {local_key}.pub", timeout=5)
        return
    else:
        task.log(f"SSH key ready: {key_path}")
    
    # ================================================================
    # Allocate local target volumes  -- NS Feb 2026
    # ================================================================
    local_volumes = []  # [(vol_id, dev_path), ...]
    for di, desc_file in enumerate(descriptor_files):
        dk = f'disk{di}'
        disk_total = task.disk_progress[dk]['total']
        
        task.log(f"Disk {di}: allocating {disk_total / (1024**3):.1f} GB on {task.target_storage}")
        
        vol_id, dev_path = _pvesm_alloc_disk(pve_mgr, task.target_node,
            task.target_storage, task.proxmox_vmid, di, disk_total)
        
        if vol_id and dev_path:
            task.log(f"  Disk {di}: {vol_id} → {dev_path}")
            local_volumes.append((vol_id, dev_path))
        else:
            task.log(f"Disk {di}: Allocation failed - VM will run on SSH only")
            task.log(f"  (Background copy will retry allocation later)")
            local_volumes.append(('', ''))
    
    # ================================================================
    # Write VM config with QEMU SSH drive args  -- NS Feb 2026
    # ================================================================
    # Build QEMU args for each disk via SSH
    # QEMU's SSH block driver: file.driver=ssh, with cache=writeback for host-side caching
    ssh_key_opt = f",file.identity-file={key_path}" if key_path else ""
    
    args_parts = []
    for di, desc_file in enumerate(descriptor_files):
        flat_file = desc_file.replace('.vmdk', '-flat.vmdk')
        esxi_path = f"/vmfs/volumes/{datastore}/{vm_dir}/{flat_file}"
        drive_id = f"ssh-disk{di}"
        
        # QEMU drive spec with SSH backend + write-back cache
        drive_spec = (
            f"file.driver=ssh,"
            f"file.host={esxi_host},"
            f"file.port=22,"
            f"file.path={esxi_path},"
            f"file.user={esxi_user},"
            f"file.host-key-check.mode=none"
            f"{ssh_key_opt},"
            f"format=raw,"
            f"if=none,"
            f"id={drive_id},"
            f"cache=writeback,"
            f"aio=threads"
        )
        
        # Match the original disk controller so guest OS finds root device
        device_spec = _qemu_device_spec(drive_id, di, disk_bus)
        
        args_parts.append(f"-drive {drive_spec}")
        args_parts.append(f"-device {device_spec}")
    
    args_line = " ".join(args_parts)
    
    # When using SCSI bus with custom args, Proxmox won't auto-create the SCSI
    # controller because we removed scsiN: lines. Add it explicitly.
    scsi_prefix = _scsi_controller_args(pve_mgr, task.target_node, task.proxmox_vmid, disk_bus)
    if scsi_prefix:
        task.log(f"  SCSI controller added: {scsi_prefix.strip()}")
    args_line = scsi_prefix + " ".join(args_parts)
    
    # Write directly to VM config
    conf_path = f"/etc/pve/qemu-server/{task.proxmox_vmid}.conf"
    
    # Remove any existing disk config and add args
    for di in range(len(descriptor_files)):
        _pve_node_exec(pve_mgr, task.target_node,
            f"sed -i '/^{disk_bus}{di}:/d' {conf_path}", timeout=5)
        _pve_node_exec(pve_mgr, task.target_node,
            f"sed -i '/^scsi{di}:/d' {conf_path}", timeout=5)
        _pve_node_exec(pve_mgr, task.target_node,
            f"sed -i '/^virtio{di}:/d' {conf_path}", timeout=5)
    
    # Remove old args/boot lines  
    _pve_node_exec(pve_mgr, task.target_node,
        f"sed -i '/^args:/d' {conf_path}", timeout=5)
    _pve_node_exec(pve_mgr, task.target_node,
        f"sed -i '/^boot:/d' {conf_path}", timeout=5)
    
    # Add SSH drive args + boot from first disk
    escaped_args = args_line.replace("'", "'\\''")
    _pve_node_exec(pve_mgr, task.target_node,
        f"echo 'args: {escaped_args}' >> {conf_path}", timeout=5)
    # No boot: line needed -- args: -device bootindex=0 controls boot order
    
    # Log config
    rc_cf, out_cf, _ = _pve_node_exec(pve_mgr, task.target_node,
        f"cat {conf_path} 2>&1", timeout=5)
    task.log(f"VM config ({len(str(out_cf or '').split(chr(10)))} lines):")
    for line in str(out_cf or '').strip().split('\n'):
        if 'args:' in line:
            task.log(f"  {line[:120]}...")
        elif line.strip() and not line.startswith('#'):
            task.log(f"  {line.strip()}")
    
    # ================================================================
    # Start VM -- boots from remote VMDK  -- NS Feb 2026
    # ================================================================
    
    # Pre-flight: Test if QEMU's SSH driver can actually connect to ESXi
    # QEMU uses libssh (NOT OpenSSH), so our -o HostKeyAlgorithms options don't help
    task.log("Testing QEMU SSH connectivity to ESXi...")
    flat0 = descriptor_files[0].replace('.vmdk', '-flat.vmdk')
    esxi_test_path = f"/vmfs/volumes/{datastore}/{vm_dir}/{flat0}"
    
    qemu_ssh_works = False
    rc_qtest, out_qtest, _ = _pve_node_exec(pve_mgr, task.target_node,
        f"timeout 10 qemu-img info "
        f"'json:{{\"file.driver\":\"ssh\","
        f"\"file.host\":\"{esxi_host}\","
        f"\"file.port\":22,"
        f"\"file.path\":\"{esxi_test_path}\","
        f"\"file.user\":\"{esxi_user}\","
        f"\"file.host-key-check.mode\":\"none\","
        f"\"file.identity-file\":\"{key_path}\"}}' 2>&1",
        timeout=20)
    qtest_out = str(out_qtest or '')
    if rc_qtest == 0 and ('virtual size' in qtest_out or 'file format' in qtest_out):
        qemu_ssh_works = True
        task.log("QEMU SSH driver: connection OK")
    else:
        task.log(f"QEMU SSH driver test failed: {qtest_out[:200]}")
        # Try alternative: qemu-img with simpler SSH URL syntax
        rc_qt2, out_qt2, _ = _pve_node_exec(pve_mgr, task.target_node,
            f"timeout 10 qemu-img info "
            f"ssh://{esxi_user}@{esxi_host}{esxi_test_path} 2>&1",
            timeout=20)
        qt2_out = str(out_qt2 or '')
        if rc_qt2 == 0 and ('virtual size' in qt2_out or 'file format' in qt2_out):
            qemu_ssh_works = True
            task.log("QEMU SSH driver: connection OK (URL syntax)")
    
    # ----------------------------------------------------------------
    # Method 2: HTTPS-backed boot (ESXi datastore browser, no FUSE!)
    # ESXi serves files at /folder/ -- QEMU reads directly via HTTPS.
    # No SSHFS, no FUSE overhead → 150-300 MB/s on 1GbE/10GbE.
    # ----------------------------------------------------------------
    https_boot = False
    https_flat_paths = []
    
    if not qemu_ssh_works:
        task.log("libssh cannot connect - trying HTTPS-backed boot (ESXi datastore)...")
        
        # URL-encode password for basic auth
        import urllib.parse
        url_pass = urllib.parse.quote(esxi_pass, safe='')
        url_user = urllib.parse.quote(esxi_user, safe='')
        
        # ESXi datastore browser URL format
        # https://host/folder/VM-dir/VM-flat.vmdk?dcPath=ha-datacenter&dsName=datastore
        ds_name = urllib.parse.quote(datastore, safe='')
        
        # Test: can QEMU open the HTTPS URL?
        test_flat = descriptor_files[0].replace('.vmdk', '-flat.vmdk')
        test_url = (
            f"https://{url_user}:{url_pass}@{esxi_host}"
            f"/folder/{urllib.parse.quote(vm_dir, safe='')}"
            f"/{urllib.parse.quote(test_flat, safe='')}"
            f"?dcPath=ha-datacenter&dsName={ds_name}"
        )
        
        rc_ht, out_ht, _ = _pve_node_exec(pve_mgr, task.target_node,
            f"timeout 10 qemu-img info --force-share "
            f"'json:{{\"file.driver\":\"https\",\"file.url\":\"{test_url}\","
            f"\"file.sslverify\":\"off\"}}' 2>&1",
            timeout=15)
        ht_out = str(out_ht or '')
        
        if rc_ht == 0 and ('virtual size' in ht_out or 'file format' in ht_out):
            task.log("QEMU HTTPS driver: connection OK ✓")
            https_boot = True
            
            # Build HTTPS paths for all disks
            for di, desc_file in enumerate(descriptor_files):
                flat_file = desc_file.replace('.vmdk', '-flat.vmdk')
                flat_url = (
                    f"https://{url_user}:{url_pass}@{esxi_host}"
                    f"/folder/{urllib.parse.quote(vm_dir, safe='')}"
                    f"/{urllib.parse.quote(flat_file, safe='')}"
                    f"?dcPath=ha-datacenter&dsName={ds_name}"
                )
                https_flat_paths.append(flat_url)
                disk_sz = task.disk_progress.get(f'disk{di}', {}).get('total', 0)
                task.log(f"  HTTPS disk {di}: {flat_file} ({disk_sz / (1024**3):.1f} GB)")
            
            # Write QEMU args with HTTPS driver
            _pve_node_exec(pve_mgr, task.target_node, f"sed -i '/^args:/d' {conf_path}", timeout=5)
            _pve_node_exec(pve_mgr, task.target_node, f"sed -i '/^boot:/d' {conf_path}", timeout=5)
            
            args_parts = []
            for di, flat_url in enumerate(https_flat_paths):
                drive_id = f"sshfs-disk{di}"  # Keep same ID for drive-mirror compat
                # QEMU HTTPS driver -- kernel-level TCP, no FUSE
                drive_spec = (
                    f"file.driver=https,"
                    f"file.url={flat_url},"
                    f"file.sslverify=off,"
                    f"file.readahead=1048576,"
                    f"format=raw,"
                    f"if=none,"
                    f"id={drive_id},"
                    f"cache=writeback,"
                    f"aio=threads,"
                    f"detect-zeroes=on"
                )
                device_spec = _qemu_device_spec(drive_id, di, disk_bus)
                args_parts.append(f"-drive {drive_spec}")
                args_parts.append(f"-device {device_spec}")
            
            args_line = scsi_prefix + " ".join(args_parts)
            escaped_args = args_line.replace("'", "'\\''")
            _pve_node_exec(pve_mgr, task.target_node,
                f"echo 'args: {escaped_args}' >> {conf_path}", timeout=5)
            
            task.log("HTTPS boot config written")
        else:
            task.log(f"QEMU HTTPS test failed: {ht_out[:200]}")
    
    # ----------------------------------------------------------------
    # Method 3: SSHFS-backed boot (OpenSSH handles ESXi algorithms)
    # SSHFS is already mounted at mnt_path -- QEMU reads the FUSE file
    # ----------------------------------------------------------------
    sshfs_boot = False
    sshfs_flat_paths = []
    
    if not qemu_ssh_works and not https_boot:
        task.log("libssh cannot connect - trying SSHFS-backed boot (OpenSSH)...")
        
        # Verify SSHFS mount is still alive
        sshfs_ok = True
        for di, desc_file in enumerate(descriptor_files):
            flat_file = desc_file.replace('.vmdk', '-flat.vmdk')
            local_fuse_path = f"{mnt_path}/{vm_dir}/{flat_file}"
            
            rc_chk, out_chk, _ = _pve_node_exec(pve_mgr, task.target_node,
                f"test -f '{local_fuse_path}' && stat --format='%s' '{local_fuse_path}' 2>&1",
                timeout=10)
            chk_out = str(out_chk or '').strip()
            
            if rc_chk == 0 and chk_out.isdigit() and int(chk_out) > 0:
                sshfs_flat_paths.append(local_fuse_path)
                task.log(f"  SSHFS disk {di}: {local_fuse_path} ({int(chk_out) / (1024**3):.1f} GB)")
            else:
                task.log(f"  SSHFS disk {di}: NOT accessible at {local_fuse_path}")
                sshfs_ok = False
                break
        
        if sshfs_ok and sshfs_flat_paths:
            # Rewrite VM config with SSHFS file paths instead of SSH driver
            _pve_node_exec(pve_mgr, task.target_node, f"sed -i '/^args:/d' {conf_path}", timeout=5)
            _pve_node_exec(pve_mgr, task.target_node, f"sed -i '/^boot:/d' {conf_path}", timeout=5)
            
            args_parts = []
            for di, fuse_path in enumerate(sshfs_flat_paths):
                drive_id = f"sshfs-disk{di}"
                # QEMU reads from local FUSE path -- OpenSSH handles ESXi connection
                drive_spec = (
                    f"file={fuse_path},"
                    f"format=raw,"
                    f"if=none,"
                    f"id={drive_id},"
                    f"cache=writeback,"
                    f"aio=threads,"
                    f"detect-zeroes=on"
                )
                device_spec = _qemu_device_spec(drive_id, di, disk_bus)
                args_parts.append(f"-drive {drive_spec}")
                args_parts.append(f"-device {device_spec}")
            
            args_line = scsi_prefix + " ".join(args_parts)
            escaped_args = args_line.replace("'", "'\\''")
            _pve_node_exec(pve_mgr, task.target_node,
                f"echo 'args: {escaped_args}' >> {conf_path}", timeout=5)
            # No boot: line needed -- args: -device bootindex=0 controls boot order
            
            # Test: can QEMU open the SSHFS file?
            rc_ftest, out_ftest, _ = _pve_node_exec(pve_mgr, task.target_node,
                f"timeout 10 qemu-img info '{sshfs_flat_paths[0]}' 2>&1", timeout=15)
            ftest_out = str(out_ftest or '')
            if 'virtual size' in ftest_out or 'file format' in ftest_out:
                sshfs_boot = True
                task.log("SSHFS QEMU test: OK")
            else:
                task.log(f"SSHFS QEMU test failed: {ftest_out[:150]}")
    
    # ----------------------------------------------------------------
    # Fallback 2: NBD bridge (most robust -- bypasses AppArmor & FUSE)
    # qemu-nbd reads the SSHFS file, QEMU connects via Unix socket
    # ----------------------------------------------------------------
    nbd_boot = False
    nbd_sockets = []   # list of socket paths for cleanup
    
    if not qemu_ssh_works and not sshfs_boot and sshfs_flat_paths:
        task.log("SSHFS direct failed - trying NBD bridge...")
        
        # Check qemu-nbd is available
        rc_nbd, _, _ = _pve_node_exec(pve_mgr, task.target_node,
            "which qemu-nbd 2>/dev/null", timeout=5)
        
        if rc_nbd == 0:
            # Load nbd kernel module
            _pve_node_exec(pve_mgr, task.target_node,
                "modprobe nbd max_part=0 2>/dev/null", timeout=5)
            
            nbd_ok = True
            nbd_args_parts = []
            
            for di, fuse_path in enumerate(sshfs_flat_paths):
                sock_path = f"/tmp/v2p-nbd-{task.proxmox_vmid}-{di}.sock"
                nbd_sockets.append(sock_path)
                
                # Kill any leftover nbd on this socket
                _pve_node_exec(pve_mgr, task.target_node,
                    f"fuser -k {sock_path} 2>/dev/null; rm -f {sock_path}", timeout=5)
                
                # Start qemu-nbd serving the flat VMDK via Unix socket
                rc_ns, out_ns, _ = _pve_node_exec(pve_mgr, task.target_node,
                    f"qemu-nbd --fork --persistent "
                    f"--socket={sock_path} "
                    f"--format=raw "
                    f"--cache=writeback "
                    f"--aio=threads "
                    f"'{fuse_path}' 2>&1", timeout=15)
                ns_out = str(out_ns or '')
                
                if rc_ns != 0:
                    task.log(f"  NBD disk {di}: qemu-nbd failed: {ns_out[:150]}")
                    nbd_ok = False
                    break
                
                # Verify socket exists
                time.sleep(1)
                rc_sc, _, _ = _pve_node_exec(pve_mgr, task.target_node,
                    f"test -S {sock_path}", timeout=5)
                if rc_sc != 0:
                    task.log(f"  NBD disk {di}: socket not created at {sock_path}")
                    nbd_ok = False
                    break
                
                task.log(f"  NBD disk {di}: {sock_path} serving {fuse_path}")
                
                drive_id = f"nbd-disk{di}"
                drive_spec = (
                    f"file.driver=nbd,"
                    f"file.path={sock_path},"
                    f"format=raw,"
                    f"if=none,"
                    f"id={drive_id},"
                    f"cache=writeback,"
                    f"aio=threads"
                )
                device_spec = _qemu_device_spec(drive_id, di, disk_bus)
                nbd_args_parts.append(f"-drive {drive_spec}")
                nbd_args_parts.append(f"-device {device_spec}")
            
            if nbd_ok and nbd_args_parts:
                # Write NBD drive config
                _pve_node_exec(pve_mgr, task.target_node, f"sed -i '/^args:/d' {conf_path}", timeout=5)
                _pve_node_exec(pve_mgr, task.target_node, f"sed -i '/^boot:/d' {conf_path}", timeout=5)
                
                nbd_args_line = scsi_prefix + " ".join(nbd_args_parts)
                escaped = nbd_args_line.replace("'", "'\\''")
                _pve_node_exec(pve_mgr, task.target_node,
                    f"echo 'args: {escaped}' >> {conf_path}", timeout=5)
                # No boot: line needed -- args: -device bootindex=0 controls boot order
                
                nbd_boot = True
                task.log("NBD bridge ready - QEMU will connect via Unix sockets")
        else:
            task.log("qemu-nbd not available")
    elif not qemu_ssh_works and not sshfs_boot and not sshfs_flat_paths:
        # SSHFS mount failed entirely -- try remounting
        task.log("SSHFS not available - trying to remount...")
        safe_pass_r = shlex.quote(esxi_pass)
        sshfs_algo = (
            "ssh_command=ssh -o HostKeyAlgorithms=+ssh-rsa\\,ssh-ed25519 "
            "-o KexAlgorithms=+diffie-hellman-group14-sha1\\,diffie-hellman-group14-sha256 "
            "-o PreferredAuthentications=keyboard-interactive\\,password"
        )
        rc_remount, _, _ = _pve_node_exec(pve_mgr, task.target_node,
            f"fusermount -u {mnt_path} 2>/dev/null; "
            f"mkdir -p {mnt_path} && "
            f"printf '%s' {safe_pass_r} | sshfs -o password_stdin,"
            f"StrictHostKeyChecking=no,UserKnownHostsFile=/dev/null,"
            f"allow_other,reconnect,ServerAliveInterval=15,"
            f"cache=yes,{sshfs_algo} "
            f"{esxi_user}@{esxi_host}:/vmfs/volumes/{shlex.quote(datastore)} {mnt_path} 2>&1",
            timeout=20)
        if rc_remount == 0:
            # Retry with NBD after remount
            for di, desc_file in enumerate(descriptor_files):
                flat_file = desc_file.replace('.vmdk', '-flat.vmdk')
                fp = f"{mnt_path}/{vm_dir}/{flat_file}"
                rc_t, _, _ = _pve_node_exec(pve_mgr, task.target_node, f"test -f '{fp}'", timeout=5)
                if rc_t == 0:
                    sshfs_flat_paths.append(fp)
            task.log(f"SSHFS remounted - {len(sshfs_flat_paths)} disks found")
    
    vm_running_on_ssh = False
    boot_method = None
    
    if qemu_ssh_works or https_boot or sshfs_boot or nbd_boot:
        if qemu_ssh_works:
            boot_method = "qemu-ssh"
        elif https_boot:
            boot_method = "https"
            # HTTPS boot: QEMU reads directly from ESXi HTTPS -- no AppArmor needed
            task.log("HTTPS boot: no AppArmor changes needed (kernel-level TCP)")
        elif sshfs_boot:
            boot_method = "sshfs"
            # SSHFS boot: QEMU needs to read files from /tmp FUSE mount
            # AppArmor on Proxmox blocks this by default -- set complain mode
            task.log("Setting AppArmor complain mode for FUSE access...")
            _pve_node_exec(pve_mgr, task.target_node,
                "aa-complain /etc/apparmor.d/usr.bin.kvm 2>/dev/null; "
                "aa-complain /etc/apparmor.d/abstractions/libvirt-qemu 2>/dev/null; "
                # Also add FUSE path to AppArmor if in enforce mode
                "if [ -f /etc/apparmor.d/local/usr.bin.kvm ]; then "
                f"  echo '{mnt_path}/** rk,' >> /etc/apparmor.d/local/usr.bin.kvm 2>/dev/null; "
                f"  echo '/tmp/v2p-*/** rk,' >> /etc/apparmor.d/local/usr.bin.kvm 2>/dev/null; "
                "  apparmor_parser -r /etc/apparmor.d/usr.bin.kvm 2>/dev/null; "
                "fi",
                timeout=10)
        elif nbd_boot:
            boot_method = "nbd"
            # NBD bridge uses Unix sockets -- no AppArmor issues
        
        # Ensure key file is readable by QEMU process
        _pve_node_exec(pve_mgr, task.target_node, f"chmod 644 {key_path} 2>/dev/null", timeout=5)
        
        task.log(f"Starting Proxmox VM ({boot_method} backend + cache=writeback)...")
        try:
            pve_mgr._api_post(
                f"https://{pve_mgr.host}:8006/api2/json/nodes/{task.target_node}"
                f"/qemu/{task.proxmox_vmid}/status/start")
            
            # Wait and verify VM is actually running (not just start-queued)
            time.sleep(8)
            try:
                st = pve_mgr._api_get(
                    f"https://{pve_mgr.host}:8006/api2/json/nodes/{task.target_node}"
                    f"/qemu/{task.proxmox_vmid}/status/current")
                vm_st = st.json().get('data', {}).get('status', 'unknown')
                
                if vm_st == 'running':
                    vm_running_on_ssh = True
                    task.log(f"VM {task.proxmox_vmid} STARTED via {boot_method} - DOWNTIME ENDS")
                    task.log(f"(Running on {boot_method}-backed storage with writeback cache)")
                else:
                    task.log(f"VM failed to stay running (status: {vm_st})")
                    # Check QEMU logs for the reason -- multiple sources
                    for log_cmd in [
                        # Proxmox VM-specific task log
                        f"tail -20 /var/log/pve/qemu-server/{task.proxmox_vmid}.log 2>/dev/null | tail -5",
                        # Systemd journal for QEMU
                        f"journalctl -t qemu-system-x86_64 -n 10 --no-pager 2>/dev/null | tail -5",
                        # Syslog (catch-all)
                        f"grep -i 'kvm\\|qemu\\|{task.proxmox_vmid}' /var/log/syslog 2>/dev/null | tail -5",
                    ]:
                        rc_log, out_log, _ = _pve_node_exec(pve_mgr, task.target_node, log_cmd, timeout=10)
                        log_out = str(out_log or '').strip()
                        if log_out and len(log_out) > 5:
                            for line in log_out.split('\n')[:3]:
                                line_s = line.strip()[:150]
                                if line_s:
                                    task.log(f"  QEMU log: {line_s}")
                            break
                    
                    # SSHFS boot may fail due to other FUSE issues
                    if sshfs_boot and not vm_running_on_ssh:
                        task.log("SSHFS boot failed - trying NBD bridge fallback...")
                        
                        # Try NBD bridge if not already using it
                        if boot_method != "nbd" and sshfs_flat_paths:
                            _pve_node_exec(pve_mgr, task.target_node,
                                "modprobe nbd max_part=0 2>/dev/null", timeout=5)
                            
                            nbd_retry_ok = True
                            nbd_retry_parts = []
                            for rdi, rfpath in enumerate(sshfs_flat_paths):
                                rsock = f"/tmp/v2p-nbd-{task.proxmox_vmid}-{rdi}.sock"
                                nbd_sockets.append(rsock)
                                _pve_node_exec(pve_mgr, task.target_node,
                                    f"fuser -k {rsock} 2>/dev/null; rm -f {rsock}", timeout=5)
                                rc_rn, out_rn, _ = _pve_node_exec(pve_mgr, task.target_node,
                                    f"qemu-nbd --fork --persistent "
                                    f"--socket={rsock} --format=raw "
                                    f"--cache=writeback --aio=threads "
                                    f"'{rfpath}' 2>&1", timeout=15)
                                time.sleep(1)
                                rc_rs, _, _ = _pve_node_exec(pve_mgr, task.target_node,
                                    f"test -S {rsock}", timeout=5)
                                if rc_rn != 0 or rc_rs != 0:
                                    nbd_retry_ok = False
                                    break
                                did = f"nbd-disk{rdi}"
                                nbd_retry_parts.append(
                                    f"-drive file.driver=nbd,file.path={rsock},"
                                    f"format=raw,if=none,id={did},"
                                    f"cache=writeback,aio=threads")
                                nbd_retry_parts.append(
                                    f"-device {_qemu_device_spec(did, rdi, disk_bus)}")
                            
                            if nbd_retry_ok and nbd_retry_parts:
                                _pve_node_exec(pve_mgr, task.target_node,
                                    f"sed -i '/^args:/d' {conf_path}", timeout=5)
                                nbd_args_r = (scsi_prefix + " ".join(nbd_retry_parts)).replace("'", "'\\''")
                                _pve_node_exec(pve_mgr, task.target_node,
                                    f"echo 'args: {nbd_args_r}' >> {conf_path}", timeout=5)
                                boot_method = "nbd"
                                task.log("NBD bridge ready - retrying VM start...")
                                try:
                                    pve_mgr._api_post(
                                        f"https://{pve_mgr.host}:8006/api2/json/nodes/{task.target_node}"
                                        f"/qemu/{task.proxmox_vmid}/status/start")
                                    time.sleep(8)
                                    st3 = pve_mgr._api_get(
                                        f"https://{pve_mgr.host}:8006/api2/json/nodes/{task.target_node}"
                                        f"/qemu/{task.proxmox_vmid}/status/current")
                                    if st3.json().get('data', {}).get('status') == 'running':
                                        vm_running_on_ssh = True
                                        task.log(f"VM {task.proxmox_vmid} STARTED via NBD bridge - DOWNTIME ENDS")
                                    else:
                                        task.log("NBD boot also failed")
                                except Exception:
                                    pass
                        
                        if not vm_running_on_ssh:
                            # Last try: chmod + AppArmor fix + retry original method
                            _pve_node_exec(pve_mgr, task.target_node,
                                f"chmod -R a+r {shlex.quote(mnt_path + '/' + vm_dir)}/ 2>/dev/null; "
                                f"aa-complain /etc/apparmor.d/usr.bin.kvm 2>/dev/null",
                                timeout=5)
                            try:
                                pve_mgr._api_post(
                                    f"https://{pve_mgr.host}:8006/api2/json/nodes/{task.target_node}"
                                    f"/qemu/{task.proxmox_vmid}/status/start")
                                time.sleep(8)
                                st2 = pve_mgr._api_get(
                                    f"https://{pve_mgr.host}:8006/api2/json/nodes/{task.target_node}"
                                    f"/qemu/{task.proxmox_vmid}/status/current")
                                if st2.json().get('data', {}).get('status') == 'running':
                                    vm_running_on_ssh = True
                                    task.log(f"VM {task.proxmox_vmid} STARTED via {boot_method} (retry) - DOWNTIME ENDS")
                                else:
                                    task.log("VM still not running after all retries")
                            except Exception:
                                pass
            except Exception:
                pass
            
        except Exception as e:
            task.log(f"VM start API error: {e}")
    else:
        task.log("No remote boot method available (QEMU-SSH/SSHFS/NBD all failed)")
    
    if not vm_running_on_ssh:
        task.log("Switching to offline mode: copy first, then start VM")
        # Remove SSH/SSHFS args from config -- VM will start with local disks after copy
        _pve_node_exec(pve_mgr, task.target_node, f"sed -i '/^args:/d' {conf_path}", timeout=5)
        _pve_node_exec(pve_mgr, task.target_node, f"sed -i '/^boot:/d' {conf_path}", timeout=5)
    
    # ================================================================
    # Background copy -- compressed transfer to local volumes  -- NS Feb 2026
    #         (Runs while VM boots/runs from SSH cache, or before VM start)
    # ================================================================
    if vm_running_on_ssh and not sshfs_boot:
        task.log(f"=== BACKGROUND COPY: SSH → {task.target_storage} ===")
        task.log("(VM runs on SSH cache while disks copy to local storage)")
    elif not vm_running_on_ssh:
        task.log(f"=== DISK COPY: SSH → {task.target_storage} ===")
        task.log("(Copying disks, VM will start after copy completes)")
    
    import math, random
    BS_MB = 64  # 64MB blocks -- less syscall overhead than 4MB
    BS = BS_MB * 1024 * 1024
    
    bg_ssh_base = (
        f"-i {key_path} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
        f"-o ServerAliveInterval=30 -o ServerAliveCountMax=5 "
        f"-o HostKeyAlgorithms=+ssh-rsa,ssh-ed25519 "
        f"-o PubkeyAcceptedAlgorithms=+ssh-rsa,ssh-ed25519 "
        f"-o KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group14-sha256"
    )
    # Fast SSH: no compression (we do it ourselves), fastest cipher, large TCP buffer
    bg_ssh_fast = (
        f"{bg_ssh_base} -o Compression=no "
        f"-o IPQoS=throughput "
        f"-c aes128-gcm@openssh.com"
    )
    
    # Detect tools on ESXi
    rc_ip2, out_ip2, _ = _pve_node_exec(pve_mgr, task.target_node,
        f"ip route get {esxi_host} 2>/dev/null | grep -oP 'src \\K[0-9.]+'", timeout=5)
    bg_pve_ip = str(out_ip2 or '').strip()
    
    bg_pass = task.config.get('esxi_password', '')
    rc_t, t_out, _ = _ssh_exec(esxi_host, esxi_user, bg_pass,
        "echo NC=$(which nc 2>/dev/null || echo NO);"
        "echo GZIP=$(which gzip 2>/dev/null || echo NO);"
        "echo LZ4=$(which lz4 2>/dev/null || echo NO);"
        "echo PIGZ=$(which pigz 2>/dev/null || echo NO);"
        "echo ZSTD=$(which zstd 2>/dev/null || echo NO)", timeout=10)
    t_str = str(t_out or '')
    bg_nc = 'NC=/' in t_str
    bg_has_lz4_esxi = 'LZ4=/' in t_str
    bg_has_pigz_esxi = 'PIGZ=/' in t_str
    bg_has_zstd_esxi = 'ZSTD=/' in t_str
    bg_has_gzip = 'GZIP=/' in t_str
    
    # Detect tools on Proxmox
    rc_pt, pt_out, _ = _pve_node_exec(pve_mgr, task.target_node,
        "echo LZ4=$(which lz4 2>/dev/null || echo NO);"
        "echo PIGZ=$(which pigz 2>/dev/null || echo NO);"
        "echo ZSTD=$(which zstd 2>/dev/null || echo NO);"
        "echo GZIP=$(which gzip 2>/dev/null || echo NO)", timeout=5)
    pt_str = str(pt_out or '')
    pve_has_lz4 = 'LZ4=/' in pt_str
    pve_has_pigz = 'PIGZ=/' in pt_str
    pve_has_zstd = 'ZSTD=/' in pt_str
    
    # Choose best compression (priority: lz4 > pigz > zstd > gzip > none)
    # lz4: ~800 MB/s compress, ~4 GB/s decompress (10x faster than gzip)
    # pigz: parallel gzip, ~3-4x faster than gzip
    # zstd -1: ~500 MB/s, better ratio than lz4
    if bg_has_lz4_esxi and pve_has_lz4:
        bg_compress = "lz4 -1 -"
        bg_decompress = "lz4 -d -"
        compress_name = "lz4"
    elif bg_has_pigz_esxi and pve_has_pigz:
        bg_compress = "pigz -1"
        bg_decompress = "pigz -d"
        compress_name = "pigz"
    elif bg_has_zstd_esxi and pve_has_zstd:
        bg_compress = "zstd -1 -T0 -"
        bg_decompress = "zstd -d -T0 -"
        compress_name = "zstd"
    elif bg_has_gzip:
        bg_compress = "gzip -1"
        bg_decompress = "gunzip"
        compress_name = "gzip"
    else:
        bg_compress = "cat"
        bg_decompress = "cat"
        compress_name = "none"
    
    task.log(f"Transfer: bs={BS_MB}MB, compress={compress_name}, nc={'yes' if bg_nc else 'no'}")
    
    # Resource isolation for background copy (critical: VM is running!)
    bg_iso = _setup_copy_isolation(pve_mgr, task.target_node, esxi_host, task.proxmox_vmid)
    bg_cg = bg_iso.get('cgroup')
    BG_CG_EXEC = f"echo $$ > /sys/fs/cgroup/{bg_cg}/cgroup.procs 2>/dev/null; " if bg_cg else ""
    BG_NICE = "nice -n 19 ionice -c 3"
    BG_DD_READ = f"dd iflag=fullblock bs={BS_MB}M"
    BG_DD_WRITE = f"dd oflag=direct bs={BS_MB}M conv=sparse,notrunc"
    BG_DD_SEEK = f"dd oflag=direct bs={BS_MB}M conv=notrunc"
    if bg_cg:
        task.log(f"Background copy isolation: cgroup={bg_cg}, io.weight=10")
    
    copy_ok = True
    
    # ================================================================
    # Storage migration: drive-mirror for ALL boot methods (zero downtime)
    # drive-mirror works at QEMU's internal block layer -- doesn't matter
    # if source is FUSE/SSHFS/SSH/HTTPS, QEMU already has the file open.
    # Fallback for SSHFS: qemu-img convert -U (brief restart at end)
    # Fallback for others: qm importdisk
    # ================================================================
    mirror_success = False
    import re as _re
    
    if vm_running_on_ssh:
        task.log("Starting live storage migration (drive-mirror)...")
        
        mirrors = []
        all_started = True
        
        for di in range(len(descriptor_files)):
            dk = f'disk{di}'
            disk_total = task.disk_progress[dk]['total']
            disk_gb = disk_total / (1024**3)
            drive_id = f"sshfs-disk{di}"
            
            vol_id, dev_path = local_volumes[di]
            if not vol_id or not dev_path:
                vol_id, dev_path = _pvesm_alloc_disk(pve_mgr, task.target_node,
                    task.target_storage, task.proxmox_vmid, di, disk_total)
                if vol_id and dev_path:
                    local_volumes[di] = (vol_id, dev_path)
                else:
                    task.log(f"  Disk {di}: allocation failed")
                    all_started = False
                    break
            
            task.log(f"  Disk {di}: {drive_id} → {dev_path} ({disk_gb:.1f} GB)")
            
            ok = _drive_mirror_to_local(
                pve_mgr, task, task.target_node, task.proxmox_vmid,
                drive_id, dev_path, disk_total)
            
            if ok:
                mirrors.append((drive_id, disk_total, di))
            else:
                task.log(f"  Disk {di}: drive-mirror failed to start")
                all_started = False
                break
        
        if all_started and mirrors:
            mirror_success = _poll_drive_mirrors(
                pve_mgr, task, task.target_node, task.proxmox_vmid, mirrors)
            if mirror_success:
                for drive_id, disk_total, di in mirrors:
                    task.update_progress(f'disk{di}', disk_total, disk_total)
        
        if not mirror_success and mirrors:
            for drive_id, _, _ in mirrors:
                _qm_monitor_cmd(pve_mgr, task.target_node, task.proxmox_vmid,
                    f"block_job_cancel {drive_id}")
            task.log("  Cancelled mirror jobs")
    
    # ================================================================
    # Fallback for SSHFS: qemu-img convert -U (VM keeps running during copy)
    # Only brief restart (~5s) at end to swap disk config
    # ================================================================
    if vm_running_on_ssh and sshfs_boot and not mirror_success:
        task.log("drive-mirror failed - using qemu-img convert -U (VM stays running)")
        task.log("=== BACKGROUND COPY: SSHFS → local storage ===")
        task.log("(VM keeps running on SSHFS while disks copy to local storage)")
        
        import_ok = True
        
        for di, desc_file in enumerate(descriptor_files):
            dk = f'disk{di}'
            disk_total = task.disk_progress[dk]['total']
            disk_gb = disk_total / (1024**3)
            
            # Source: flat file on SSHFS mount (raw format)
            flat_file = desc_file.replace('.vmdk', '-flat.vmdk')
            sshfs_src = f"{mnt_path}/{vm_dir}/{flat_file}"
            
            # Verify source is accessible
            rc_chk, out_chk, _ = _pve_node_exec(pve_mgr, task.target_node,
                f"test -f '{sshfs_src}' && stat --format='%s' '{sshfs_src}' 2>&1", timeout=10)
            if rc_chk != 0:
                # Try descriptor VMDK as source (qemu-img can read VMDK descriptors)
                desc_path = f"{mnt_path}/{vm_dir}/{desc_file}"
                rc_d, out_d, _ = _pve_node_exec(pve_mgr, task.target_node,
                    f"test -f '{desc_path}' && head -5 '{desc_path}' 2>/dev/null", timeout=10)
                d_head = str(out_d or '').strip().lower()
                if rc_d == 0 and any(kw in d_head for kw in ['descriptor', 'vmdk', 'extent', 'version=']):
                    sshfs_src = desc_path
                    task.log(f"  Disk {di}: using descriptor VMDK ({desc_file})")
                else:
                    task.log(f"  Disk {di}: source not found on SSHFS!")
                    import_ok = False
                    continue
            
            # Target: allocate local volume
            vol_id, dev_path = local_volumes[di]
            if not vol_id or not dev_path:
                vol_id, dev_path = _pvesm_alloc_disk(pve_mgr, task.target_node,
                    task.target_storage, task.proxmox_vmid, di, disk_total)
                if vol_id and dev_path:
                    local_volumes[di] = (vol_id, dev_path)
                else:
                    task.log(f"  Disk {di}: allocation failed!")
                    import_ok = False
                    continue
            
            task.log(f"  Disk {di}: {sshfs_src} → {dev_path} ({disk_gb:.1f} GB)")
            
            # qemu-img convert with -U (force share) -- no lock conflict with running QEMU
            # -p = progress, -n = no create (target already allocated), -f raw -O raw
            progress_log = f"/tmp/v2p-import-{task.proxmox_vmid}-{di}.log"
            _pve_node_exec(pve_mgr, task.target_node, f"rm -f {progress_log}", timeout=5)
            
            # Detect source format (flat = raw, descriptor = vmdk)
            src_format = "raw"
            if sshfs_src.endswith('.vmdk') and not sshfs_src.endswith('-flat.vmdk'):
                src_format = "vmdk"
            
            # Write copy script (avoids quoting nightmares in nested shells)
            copy_script = f"/tmp/v2p-copy-{task.proxmox_vmid}-{di}.sh"
            # Redirect all output to log; progress monitored via /proc IO stats
            script_body = (
                f"#!/bin/bash\n"
                f"qemu-img convert -U -p -n -f {src_format} -O raw "
                f"'{sshfs_src}' '{dev_path}' "
                f"&> '{progress_log}'\n"
                f"echo \"EXIT_CODE=$?\" >> '{progress_log}'\n"
            )
            _pve_node_exec(pve_mgr, task.target_node,
                f"cat > {copy_script} << 'EOFSCRIPT'\n{script_body}EOFSCRIPT\n"
                f"chmod +x {copy_script}", timeout=10)
            
            _pve_node_exec(pve_mgr, task.target_node,
                f"nohup {copy_script} > /dev/null 2>&1 &", timeout=10)
            
            # Verify process actually started
            time.sleep(2)
            rc_ps, _, _ = _pve_node_exec(pve_mgr, task.target_node,
                f"pgrep -f 'qemu-img convert.*{dev_path}' >/dev/null 2>&1 || "
                f"pgrep -f 'v2p-copy-{task.proxmox_vmid}-{di}' >/dev/null 2>&1", timeout=5)
            if rc_ps != 0:
                # Process didn't start -- check error
                rc_err, out_err, _ = _pve_node_exec(pve_mgr, task.target_node,
                    f"cat {progress_log} 2>/dev/null", timeout=5)
                err_msg = str(out_err or '').strip()
                task.log(f"  ⚠ qemu-img did not start: {err_msg[:200]}")
                
                # Fallback: try without -U flag (older QEMU versions)
                task.log(f"  Retrying without -U flag...")
                script_body_noU = (
                    f"#!/bin/bash\n"
                    f"qemu-img convert -p -n -f {src_format} -O raw "
                    f"'{sshfs_src}' '{dev_path}' "
                    f"&> '{progress_log}'\n"
                    f"echo \"EXIT_CODE=$?\" >> '{progress_log}'\n"
                )
                _pve_node_exec(pve_mgr, task.target_node,
                    f"cat > {copy_script} << 'EOFSCRIPT'\n{script_body_noU}EOFSCRIPT", timeout=10)
                _pve_node_exec(pve_mgr, task.target_node,
                    f"nohup {copy_script} > /dev/null 2>&1 &", timeout=10)
                time.sleep(2)
            
            task.log(f"  qemu-img convert started ({src_format} → raw)")
            
            # Poll progress via /proc/PID/io (reliable, no buffering issues)
            start_t = time.time()
            last_pct = -1
            copy_done = False
            qimg_pid = ''
            
            while time.time() - start_t < 86400:
                time.sleep(5)
                
                # Find qemu-img PID if not known
                if not qimg_pid:
                    rc_pid, out_pid, _ = _pve_node_exec(pve_mgr, task.target_node,
                        "pgrep -f 'qemu-img convert' 2>/dev/null | head -1",
                        timeout=5)
                    pid_str = str(out_pid or '').strip()
                    if pid_str.isdigit():
                        qimg_pid = pid_str
                
                # Method 1: Read /proc/PID/io for write_bytes (most reliable)
                written = 0
                if qimg_pid:
                    rc_io, out_io, _ = _pve_node_exec(pve_mgr, task.target_node,
                        f"cat /proc/{qimg_pid}/io 2>/dev/null | grep write_bytes", timeout=5)
                    io_str = str(out_io or '').strip()
                    m_wb = _re.search(r'write_bytes:\s*(\d+)', io_str)
                    if m_wb:
                        written = int(m_wb.group(1))
                    else:
                        qimg_pid = ''  # PID stale, re-detect next loop
                
                # Method 2: Fallback -- parse progress file
                if written == 0:
                    rc_p, out_p, _ = _pve_node_exec(pve_mgr, task.target_node,
                        f"tail -c 500 {progress_log} 2>/dev/null", timeout=10)
                    progress_str = str(out_p or '')
                    pct_matches = _re.findall(r'\((\d+\.?\d*)/100%\)', progress_str)
                    if pct_matches:
                        written = int(disk_total * float(pct_matches[-1]) / 100)
                
                if written > 0:
                    current_pct = min(written * 100 / max(disk_total, 1), 100)
                    if current_pct - last_pct >= 10 or (current_pct >= 99 and last_pct < 99):
                        elapsed = time.time() - start_t
                        speed = written / max(elapsed, 1) / (1024*1024)
                        task.log(f"    {current_pct:.0f}% ({elapsed:.0f}s, ~{speed:.0f} MB/s)")
                    last_pct = current_pct
                    task.update_progress(dk, min(written, disk_total), disk_total)
                    
                    if current_pct >= 99.5:
                        copy_done = True
                        break
                
                # Check if process exited
                rc_chk, _, _ = _pve_node_exec(pve_mgr, task.target_node,
                    f"pgrep -f 'v2p-copy-{task.proxmox_vmid}-{di}' >/dev/null 2>&1 || "
                    f"pgrep -f 'qemu-img convert' >/dev/null 2>&1", timeout=5)
                if rc_chk != 0 and time.time() - start_t > 15:
                    # Process exited -- check EXIT_CODE
                    rc_fin, out_fin, _ = _pve_node_exec(pve_mgr, task.target_node,
                        f"tail -c 200 {progress_log} 2>/dev/null", timeout=10)
                    final_str = str(out_fin or '')
                    if 'EXIT_CODE=0' in final_str:
                        copy_done = True
                    elif 'EXIT_CODE=' in final_str:
                        task.log(f"  qemu-img exited with error: {final_str[-200:]}")
                    else:
                        # No EXIT_CODE marker -- check if all bytes written
                        if last_pct >= 95:
                            copy_done = True
                    break
            
            elapsed = time.time() - start_t
            
            if copy_done or last_pct >= 99:
                speed = (disk_total / (1024*1024)) / max(elapsed, 1)
                task.log(f"  ✓ Disk {di}: {elapsed:.0f}s, ~{speed:.0f} MB/s → {vol_id}")
                task.update_progress(dk, disk_total, disk_total)
            else:
                rc_err, out_err, _ = _pve_node_exec(pve_mgr, task.target_node,
                    f"cat {progress_log} 2>/dev/null | tail -5", timeout=10)
                task.log(f"  ✗ Disk {di} FAILED: {str(out_err or '')[-300:]}")
                import_ok = False
            
            # Cleanup temp files
            _pve_node_exec(pve_mgr, task.target_node,
                f"rm -f {progress_log} {copy_script}", timeout=5)
        
        if import_ok:
            task.log("=== ALL DISKS COPIED - switching to local storage (brief restart) ===")
            
            # Graceful shutdown: sync FS, ACPI shutdown, fallback to force stop
            # This prevents filesystem corruption (initramfs on next boot!)
            try:
                pve_mgr._api_post(
                    f"https://{pve_mgr.host}:8006/api2/json/nodes/{task.target_node}"
                    f"/qemu/{task.proxmox_vmid}/agent/fsfreeze-freeze", timeout=10)
                time.sleep(1)
                pve_mgr._api_post(
                    f"https://{pve_mgr.host}:8006/api2/json/nodes/{task.target_node}"
                    f"/qemu/{task.proxmox_vmid}/agent/fsfreeze-thaw", timeout=10)
                task.log("  Guest filesystem synced (fsfreeze)")
            except:
                pass  # Guest agent not available -- continue anyway
            
            # Try graceful ACPI shutdown first
            task.log("  Sending ACPI shutdown...")
            try:
                pve_mgr._api_post(
                    f"https://{pve_mgr.host}:8006/api2/json/nodes/{task.target_node}"
                    f"/qemu/{task.proxmox_vmid}/status/shutdown",
                    data={'timeout': 30})
            except:
                pass
            
            # Wait for clean shutdown (30s)
            stopped = False
            for _w in range(15):
                time.sleep(2)
                try:
                    st = pve_mgr._api_get(
                        f"https://{pve_mgr.host}:8006/api2/json/nodes/{task.target_node}"
                        f"/qemu/{task.proxmox_vmid}/status/current")
                    if st.json().get('data', {}).get('status') == 'stopped':
                        stopped = True
                        task.log(f"  VM stopped gracefully ({(_w+1)*2}s)")
                        break
                except:
                    pass
            
            # Force stop if graceful shutdown didn't work
            if not stopped:
                task.log("  Graceful shutdown timed out - force stopping...")
                try:
                    pve_mgr._api_post(
                        f"https://{pve_mgr.host}:8006/api2/json/nodes/{task.target_node}"
                        f"/qemu/{task.proxmox_vmid}/status/stop")
                except: pass
                for _w in range(10):
                    time.sleep(2)
                    try:
                        st = pve_mgr._api_get(
                            f"https://{pve_mgr.host}:8006/api2/json/nodes/{task.target_node}"
                            f"/qemu/{task.proxmox_vmid}/status/current")
                        if st.json().get('data', {}).get('status') == 'stopped':
                            break
                    except: pass
            
            # Reconfigure: remove SSH args, set local disks, set boot order
            _pve_node_exec(pve_mgr, task.target_node, f"sed -i '/^args:/d' {conf_path}", timeout=5)
            _pve_node_exec(pve_mgr, task.target_node, f"sed -i '/^boot:/d' {conf_path}", timeout=5)
            _pve_node_exec(pve_mgr, task.target_node, f"sed -i '/^unused/d' {conf_path}", timeout=5)
            for di in range(len(descriptor_files)):
                _pve_node_exec(pve_mgr, task.target_node,
                    f"sed -i '/^{disk_bus}{di}:/d' {conf_path}", timeout=5)
                _pve_node_exec(pve_mgr, task.target_node,
                    f"sed -i '/^scsi{di}:/d' {conf_path}", timeout=5)
                _pve_node_exec(pve_mgr, task.target_node,
                    f"sed -i '/^virtio{di}:/d' {conf_path}", timeout=5)
            
            for di in range(len(descriptor_files)):
                vol_id = local_volumes[di][0] if di < len(local_volumes) else ''
                if vol_id:
                    rc_set, out_set, _ = _pve_node_exec(pve_mgr, task.target_node,
                        f"qm set {task.proxmox_vmid} --{disk_bus}{di} {vol_id} 2>&1", timeout=15)
                    task.log(f"  {disk_bus}{di}: {vol_id}")
            
            _pve_node_exec(pve_mgr, task.target_node,
                f"qm set {task.proxmox_vmid} --boot order={disk_bus}0 2>&1", timeout=10)
            
            # Start on local storage
            try:
                pve_mgr._api_post(
                    f"https://{pve_mgr.host}:8006/api2/json/nodes/{task.target_node}"
                    f"/qemu/{task.proxmox_vmid}/status/start")
                task.log(f"VM {task.proxmox_vmid} RESTARTED on local storage (full speed)")
            except Exception as e:
                task.log(f"VM start failed: {e}")
            
            # Skip all remaining copy/config steps -- VM already reconfigured and running
            mirror_success = True
            copy_ok = True
            vm_running_on_ssh = False  # VM was stopped and restarted on local storage
        else:
            copy_ok = False
    
    # ================================================================
    # Fallback: importdisk (when drive-mirror failed, and qemu-img convert
    # either failed or wasn't applicable)
    # importdisk creates its own volume -- doesn't need pvesm alloc
    # Works for any boot method that has SSHFS paths available
    # ================================================================
    if vm_running_on_ssh and sshfs_flat_paths and not mirror_success:
        task.log("Falling back to importdisk (requires brief restart)...")
        copy_ok = True
        
        for di, sshfs_path in enumerate(sshfs_flat_paths):
                dk = f'disk{di}'
                disk_total = task.disk_progress[dk]['total']
                disk_gb = disk_total / (1024**3)
                
                desc_file = descriptor_files[di] if di < len(descriptor_files) else ''
                desc_path = f"{mnt_path}/{vm_dir}/{desc_file}" if desc_file else ''
                import_path = None
                
                if desc_path:
                    rc_d, out_d, _ = _pve_node_exec(pve_mgr, task.target_node,
                        f"test -f '{desc_path}' && head -5 '{desc_path}' 2>/dev/null", timeout=10)
                    d_head = str(out_d or '').strip().lower()
                    if rc_d == 0 and any(kw in d_head for kw in ['descriptor', 'vmdk', 'extent', 'version=']):
                        import_path = desc_path
                
                if not import_path:
                    raw_link = sshfs_path.replace('.vmdk', '.raw')
                    _pve_node_exec(pve_mgr, task.target_node,
                        f"ln -sf '{sshfs_path}' '{raw_link}'", timeout=5)
                    import_path = raw_link
                
                old_vol = local_volumes[di][0] if di < len(local_volumes) else ''
                if old_vol:
                    _pve_node_exec(pve_mgr, task.target_node,
                        f"pvesm free {old_vol} 2>&1", timeout=15)
                    local_volumes[di] = ('', '')
                
                task.log(f"  Importing disk {di} ({disk_gb:.1f} GB) → {task.target_storage}")
                start_t = time.time()
                rc_imp, out_imp, _ = _pve_node_exec(pve_mgr, task.target_node,
                    f"qm importdisk {task.proxmox_vmid} '{import_path}' {task.target_storage} --format raw 2>&1",
                    timeout=86400)
                elapsed = time.time() - start_t
                out_str = str(out_imp or '').strip()
                
                imported_vol = ''
                for imp_line in out_str.split('\n'):
                    m = _re.search(r"([\w-]+:vm-\d+-disk-\d+(?:\.\w+)?)", imp_line)
                    if m:
                        imported_vol = m.group(1).strip("'\"")
                
                if imported_vol and rc_imp == 0:
                    local_volumes[di] = (imported_vol, '')
                    speed = (disk_total / (1024*1024)) / max(elapsed, 1)
                    task.log(f"  ✓ {elapsed:.0f}s, {speed:.0f} MB/s → {imported_vol}")
                    task.update_progress(dk, disk_total, disk_total)
                else:
                    task.log(f"  FAILED (rc={rc_imp}): {out_str[-300:]}")
                    copy_ok = False
    
    # ================================================================
    # DD-based copy fallback (offline or if both mirror + importdisk failed)
    # Only for offline mode -- when VM is running on SSH, dd can't access ESXi directly
    # ================================================================
    if not copy_ok and not mirror_success and not vm_running_on_ssh:
        task.log("Falling back to SSH dd-based copy...")
        copy_ok = True

    if not mirror_success and (not vm_running_on_ssh or not copy_ok):
      for di, desc_file in enumerate(descriptor_files):
        dk = f'disk{di}'
        disk_total = task.disk_progress[dk]['total']
        disk_gb = disk_total / (1024**3)
        vol_id, dev_path = local_volumes[di]
        flat_file = desc_file.replace('.vmdk', '-flat.vmdk')
        esxi_path = f"/vmfs/volumes/{datastore}/{vm_dir}/{flat_file}"
        
        if not vol_id or not dev_path:
            vol_id, dev_path = _pvesm_alloc_disk(pve_mgr, task.target_node,
                task.target_storage, task.proxmox_vmid, di, disk_total)
            if vol_id and dev_path:
                local_volumes[di] = (vol_id, dev_path)
            else:
                copy_ok = False
                continue
        
        task.log(f"Copying disk {di} ({disk_gb:.1f} GB) → {vol_id}")
        bg_copied = False
        
        # Netcat + compression (fastest method: raw TCP, no SSH overhead)
        if bg_pve_ip and bg_nc:
            port = random.randint(49152, 65000)
            task.log(f"  nc+{compress_name} {esxi_host}→{bg_pve_ip}:{port}")
            nc_s = f"/tmp/v2p-bgnc-{task.id[:8]}-d{di}.sh"
            nc_body = f"""#!/bin/bash
{BG_CG_EXEC}
echo 1000 > /proc/self/oom_score_adj 2>/dev/null || true
# Tune TCP buffers for bulk transfer (16MB window)
sysctl -w net.core.rmem_max=16777216 net.core.wmem_max=16777216 2>/dev/null || true
sysctl -w net.ipv4.tcp_rmem='4096 1048576 16777216' net.ipv4.tcp_wmem='4096 1048576 16777216' 2>/dev/null || true
{BG_NICE} nc -l -p {port} -w 300 | {bg_decompress} | {BG_NICE} {BG_DD_WRITE} of={dev_path} 2>/dev/null &
RECV=$!
sleep 1
ssh {bg_ssh_base} {esxi_user}@{esxi_host} "{BG_NICE} {BG_DD_READ} if={esxi_path} 2>/dev/null | {bg_compress} | nc -w 120 {bg_pve_ip} {port}" &
SEND=$!
wait $SEND 2>/dev/null; S=$?
wait $RECV 2>/dev/null; R=$?
exit $((S + R))
"""
            _pve_node_exec(pve_mgr, task.target_node,
                f"cat > {nc_s} << 'NCEOF'\n{nc_body}\nNCEOF\nchmod +x {nc_s}", timeout=10)
            start_time = time.time()
            rc_bg, _, _ = _pve_node_exec(pve_mgr, task.target_node,
                f"bash {nc_s} 2>&1", timeout=86400)
            _pve_node_exec(pve_mgr, task.target_node, f"rm -f {nc_s}", timeout=5)
            elapsed = time.time() - start_time
            if rc_bg == 0 and elapsed > 2:
                speed = disk_gb * 1024 / max(elapsed, 1)
                task.log(f"  ✓ {elapsed:.0f}s, {speed:.0f} MB/s effective")
                bg_copied = True
            else:
                _pve_node_exec(pve_mgr, task.target_node,
                    f"kill $(lsof -ti :{port}) 2>/dev/null; true", timeout=5)
        
        # SSH + compression parallel
        if not bg_copied:
            total_blocks = math.ceil(disk_total / BS)
            streams = min(8, max(1, total_blocks // 4))
            bps = math.ceil(total_blocks / streams)
            task.log(f"  SSH+compress × {streams}")
            ss = f"/tmp/v2p-bgssh-{task.id[:8]}-d{di}.sh"
            lines = [
                "#!/bin/bash",
                f"{BG_CG_EXEC}",
                "echo 1000 > /proc/self/oom_score_adj 2>/dev/null || true"
            ]
            for s in range(streams):
                sk = s * bps; ct = min(bps, total_blocks - sk)
                if ct <= 0: break
                # Always pipe through compress/decompress (if none, they're "cat")
                lines.append(
                    f'{BG_NICE} ssh {bg_ssh_fast} {esxi_user}@{esxi_host} '
                    f'"{BG_NICE} {BG_DD_READ} if={esxi_path} skip={sk} count={ct} 2>/dev/null | {bg_compress}" '
                    f'| {bg_decompress} '
                    f'| {BG_NICE} {BG_DD_SEEK} of={dev_path} seek={sk} 2>/dev/null &'
                )
            lines.append("wait")
            _pve_node_exec(pve_mgr, task.target_node,
                f"cat > {ss} << 'SEOF'\n" + "\n".join(lines) + "\nSEOF\nchmod +x {ss}", timeout=10)
            start_time = time.time()
            rc_bg, _, _ = _pve_node_exec(pve_mgr, task.target_node,
                f"bash {ss} 2>&1", timeout=86400)
            _pve_node_exec(pve_mgr, task.target_node, f"rm -f {ss}", timeout=5)
            elapsed = time.time() - start_time
            if rc_bg == 0:
                speed = disk_gb * 1024 / max(elapsed, 1)
                task.log(f"  ✓ {elapsed:.0f}s, {speed:.0f} MB/s effective")
                bg_copied = True
        
        if bg_copied:
            task.update_progress(dk, disk_total, disk_total)
        else:
            task.log(f"  Copy failed!")
            copy_ok = False
            break
    
    if not copy_ok:
        if vm_running_on_ssh:
            task.log("Background copy failed - VM still running on SSH")
        else:
            task.log("Disk copy failed")
        _cleanup_copy_isolation(pve_mgr, task.target_node, bg_iso)
        if nbd_sockets:
            for sock in nbd_sockets:
                _pve_node_exec(pve_mgr, task.target_node,
                    f"fuser -k {sock} 2>/dev/null; rm -f {sock}", timeout=5)
        _cleanup_temp_ssh_key(pve_mgr, task.target_node, key_path, esxi_host, esxi_user)
        task.set_phase('failed', 'Disk copy to local storage failed')
        return
    
    _cleanup_copy_isolation(pve_mgr, task.target_node, bg_iso)
    if mirror_success:
        task.log("=== ALL DISKS MIGRATED TO LOCAL STORAGE (live pivot) ===")
    else:
        task.log("=== ALL DISKS COPIED TO LOCAL STORAGE ===")
    
    # ================================================================
    # Configure local disks and (if needed) restart VM  -- NS Feb 2026
    # ================================================================
    if mirror_success and vm_running_on_ssh:
        # drive-mirror already pivoted -- VM is live on local storage!
        # Update config FILE ONLY (no qm set -- avoid hot-plug conflicts).
        # Changes persist across reboots.
        task.log("=== LIVE PIVOT COMPLETE - updating config (no restart needed) ===")
        
        # Clean config: remove SSH args, boot, unused
        _pve_node_exec(pve_mgr, task.target_node, f"sed -i '/^args:/d' {conf_path}", timeout=5)
        _pve_node_exec(pve_mgr, task.target_node, f"sed -i '/^boot:/d' {conf_path}", timeout=5)
        _pve_node_exec(pve_mgr, task.target_node, f"sed -i '/^unused/d' {conf_path}", timeout=5)
        for di in range(len(descriptor_files)):
            _pve_node_exec(pve_mgr, task.target_node,
                f"sed -i '/^{disk_bus}{di}:/d' {conf_path}", timeout=5)
        
        # Write disk and boot lines directly to config file
        for di in range(len(descriptor_files)):
            vol_id = local_volumes[di][0] if di < len(local_volumes) else ''
            if vol_id:
                # Include size= parameter (required for Proxmox to manage disk properly)
                dk = f'disk{di}'
                disk_total = task.disk_progress.get(dk, {}).get('total', 0)
                size_gb = max(1, math.ceil(disk_total / (1024**3)))
                disk_line = f"{disk_bus}{di}: {vol_id},size={size_gb}G"
                _pve_node_exec(pve_mgr, task.target_node,
                    f"echo '{disk_line}' >> {conf_path}", timeout=5)
                task.log(f"  Disk {di}: {disk_line} ✓")
        
        _pve_node_exec(pve_mgr, task.target_node,
            f"echo 'boot: order={disk_bus}0' >> {conf_path}", timeout=5)
        task.log(f"  Boot: order={disk_bus}0")
        task.log(f"  VM {task.proxmox_vmid} continues running - ZERO downtime ✓")
        
    elif vm_running_on_ssh:
        task.log("Switching VM from SSH to local storage (brief restart)...")
        
        # Graceful shutdown to prevent filesystem corruption
        try:
            pve_mgr._api_post(
                f"https://{pve_mgr.host}:8006/api2/json/nodes/{task.target_node}"
                f"/qemu/{task.proxmox_vmid}/agent/fsfreeze-freeze", timeout=10)
            time.sleep(1)
            pve_mgr._api_post(
                f"https://{pve_mgr.host}:8006/api2/json/nodes/{task.target_node}"
                f"/qemu/{task.proxmox_vmid}/agent/fsfreeze-thaw", timeout=10)
            task.log("  Guest filesystem synced (fsfreeze)")
        except:
            pass  # Guest agent not available
        
        # Try ACPI shutdown first
        try:
            pve_mgr._api_post(
                f"https://{pve_mgr.host}:8006/api2/json/nodes/{task.target_node}"
                f"/qemu/{task.proxmox_vmid}/status/shutdown",
                data={'timeout': 30})
        except: pass
        
        stopped = False
        for attempt in range(15):
            time.sleep(2)
            try:
                st = pve_mgr._api_get(
                    f"https://{pve_mgr.host}:8006/api2/json/nodes/{task.target_node}"
                    f"/qemu/{task.proxmox_vmid}/status/current")
                if st.json().get('data', {}).get('status') != 'running':
                    task.log(f"  VM stopped gracefully ({(attempt+1)*2}s)")
                    stopped = True
                    break
            except: pass
        
        if not stopped:
            task.log("  Graceful shutdown timed out - force stopping...")
            try:
                pve_mgr._api_post(
                    f"https://{pve_mgr.host}:8006/api2/json/nodes/{task.target_node}"
                    f"/qemu/{task.proxmox_vmid}/status/stop")
            except: pass
            for _w in range(10):
                time.sleep(2)
                try:
                    st = pve_mgr._api_get(
                        f"https://{pve_mgr.host}:8006/api2/json/nodes/{task.target_node}"
                        f"/qemu/{task.proxmox_vmid}/status/current")
                    if st.json().get('data', {}).get('status') != 'running':
                        break
                except: pass
        
        time.sleep(2)
        _pve_node_exec(pve_mgr, task.target_node, "sync", timeout=10)
    else:
        task.log("Configuring VM with local disks...")
    
    if not mirror_success:
        # Clean config: remove SSH args, boot, and unused disk lines
        _pve_node_exec(pve_mgr, task.target_node, f"sed -i '/^args:/d' {conf_path}", timeout=5)
        _pve_node_exec(pve_mgr, task.target_node, f"sed -i '/^boot:/d' {conf_path}", timeout=5)
        _pve_node_exec(pve_mgr, task.target_node, f"sed -i '/^unused/d' {conf_path}", timeout=5)
        for di in range(len(descriptor_files)):
            _pve_node_exec(pve_mgr, task.target_node,
                f"sed -i '/^{disk_bus}{di}:/d' {conf_path}", timeout=5)
    
        # Attach volumes (importdisk or dd-based)
        has_imported_vols = all(
            local_volumes[di][0] for di in range(len(descriptor_files))
            if di < len(local_volumes)
        )
        
        if has_imported_vols:
            task.log("Attaching imported volumes...")
            for di in range(len(descriptor_files)):
                vol_id = local_volumes[di][0] if di < len(local_volumes) else ''
                if not vol_id:
                    task.log(f"  WARNING: No volume for disk {di}")
                    continue
                escaped_vol = vol_id.replace('/', '\\/')
                _pve_node_exec(pve_mgr, task.target_node,
                    f"sed -i '/^unused.*{escaped_vol}/d' {conf_path}", timeout=5)
                rc_at, out_at, _ = _pve_node_exec(pve_mgr, task.target_node,
                    f"qm set {task.proxmox_vmid} --{disk_bus}{di} {vol_id} 2>&1", timeout=15)
                at_out = str(out_at or '').strip()
                if rc_at == 0 and 'error' not in at_out.lower():
                    task.log(f"  Disk {di}: {disk_bus}{di} → {vol_id} ✓")
                else:
                    task.log(f"  WARNING: qm set --{disk_bus}{di} {vol_id} failed: {at_out[:150]}")
        else:
            task.log("Attaching dd-copied volumes...")
            for di in range(len(descriptor_files)):
                vol_id = local_volumes[di][0] if di < len(local_volumes) else ''
                if vol_id:
                    rc_set, out_set, _ = _pve_node_exec(pve_mgr, task.target_node,
                        f"qm set {task.proxmox_vmid} --{disk_bus}{di} {vol_id} 2>&1", timeout=15)
                    set_out = str(out_set or '').strip()
                    if rc_set == 0 and 'error' not in set_out.lower():
                        task.log(f"  {disk_bus}{di}: {vol_id}")
                    else:
                        task.log(f"  WARNING: qm set --{disk_bus}{di} {vol_id} failed: {set_out[:150]}")
        
        # Set boot order
        rc_boot, out_boot, _ = _pve_node_exec(pve_mgr, task.target_node,
            f"qm set {task.proxmox_vmid} --boot order={disk_bus}0 2>&1", timeout=10)
        boot_out = str(out_boot or '').strip()
        if rc_boot == 0 and 'error' not in boot_out.lower():
            task.log(f"  Boot: order={disk_bus}0")
        else:
            task.log(f"  WARNING: boot order failed: {boot_out[:150]}")
        
        # Start VM on local storage
        if task.start_after or vm_running_on_ssh:
            try:
                pve_mgr._api_post(
                    f"https://{pve_mgr.host}:8006/api2/json/nodes/{task.target_node}"
                    f"/qemu/{task.proxmox_vmid}/status/start")
                if vm_running_on_ssh:
                    task.log(f"VM {task.proxmox_vmid} RESTARTED on local storage (full speed)")
                else:
                    task.log(f"VM {task.proxmox_vmid} STARTED on local storage")
                    task.log("DOWNTIME ENDS")
            except Exception as e:
                task.log(f"VM start failed: {e}")
        else:
            task.log(f"VM {task.proxmox_vmid} configured - not starting (start_after=false)")
    
    # Verify final config (both paths)
    rc_cf, out_cf, _ = _pve_node_exec(pve_mgr, task.target_node,
        f"cat {conf_path} 2>&1", timeout=5)
    cfg_text = str(out_cf or '').strip()
    task.log(f"  Final VM config:")
    for cline in cfg_text.split('\n'):
        cs = cline.strip()
        if cs and not cs.startswith('#'):
            task.log(f"    {cs[:120]}")
    
    # Cleanup
    # Kill NBD bridge processes
    if nbd_sockets:
        for sock in nbd_sockets:
            _pve_node_exec(pve_mgr, task.target_node,
                f"fuser -k {sock} 2>/dev/null; rm -f {sock}", timeout=5)
        task.log(f"  Cleaned up {len(nbd_sockets)} NBD sockets")
    _cleanup_temp_ssh_key(pve_mgr, task.target_node, key_path, esxi_host, esxi_user)
    
    # After live-pivot, QEMU may still hold file handles to SSHFS source.
    # Lazy-unmount keeps mount accessible for open handles, cleans up when released.
    if mirror_success and mnt_path:
        _pve_node_exec(pve_mgr, task.target_node,
            f"umount -l '{mnt_path}' 2>/dev/null; sleep 3; "
            f"fusermount -uz '{mnt_path}' 2>/dev/null; "
            f"rm -rf '{mnt_path}' 2>/dev/null", timeout=15)
    else:
        _cleanup_sshfs(pve_mgr, task.target_node, mnt_path)
    
    task.set_phase('completed')
    task.log(f"COMPLETED: {task.vm_name} -> VMID {task.proxmox_vmid}")
    if mirror_success:
        task.log(f"Migration used live storage migration (near-zero downtime)")
    elif vm_running_on_ssh:
        task.log(f"Migration used {boot_method} boot + importdisk (near-zero downtime)")
    else:
        task.log("Migration used offline copy (QEMU SSH not available for this ESXi version)")


def _do_offline_qemuimg_copy(pve_mgr, task, esxi_host, esxi_user, esxi_pass,
                              datastore, vm_dir, descriptor_files, disk_bus, mnt_path):
    """Fallback: copy disks via SSH (key or sshpass), then start VM."""
    import time
    
    task.log("=== OFFLINE COPY: SSH transfer ===")
    
    # Try SSH key, but continue with sshpass if it fails
    key_path = _setup_temp_ssh_key(pve_mgr, task.target_node, esxi_host, esxi_user, esxi_pass)
    if key_path:
        task.log(f"SSH key deployed: {key_path}")
    else:
        task.log("SSH key not available - using sshpass for transfer")
    
    ok = _qemu_img_ssh_copy(pve_mgr, task, esxi_host, esxi_user, key_path,
                             datastore, vm_dir, descriptor_files, disk_bus)
    
    if key_path:
        _cleanup_temp_ssh_key(pve_mgr, task.target_node, key_path, esxi_host, esxi_user)
    _cleanup_sshfs(pve_mgr, task.target_node, mnt_path)
    
    if not ok:
        task.set_phase('failed', 'Disk copy failed')
        return
    
    _pve_node_exec(pve_mgr, task.target_node,
        f"qm set {task.proxmox_vmid} --boot order={disk_bus}0 2>&1", timeout=10)
    
    if task.start_after:
        task.log("Starting VM on local storage...")
        try:
            pve_mgr._api_post(
                f"https://{pve_mgr.host}:8006/api2/json/nodes/{task.target_node}"
                f"/qemu/{task.proxmox_vmid}/status/start")
            task.log(f"VM {task.proxmox_vmid} STARTED")
        except Exception as e:
            task.log(f"Start failed: {e}")
    
    task.set_phase('completed')
    task.log(f"COMPLETED: {task.vm_name} -> VMID {task.proxmox_vmid} (offline copy)")


def _ssh_pipe_transfer(pve_mgr, task, esxi_host, esxi_user, esxi_pass, datastore, vm_dir, desc_file, disk_index):
    """Transfer a flat VMDK from ESXi to Proxmox storage.
    
    Strategy (in order):
    1. HTTPS /folder endpoint with cookie-session auth (works for running VMs)
    2. SSH dd pipe (works for stopped VMs or after snapshot)
    3. SSHFS dd (FUSE, last resort)
    
    Returns (vol_id, vol_path) on success or (None, None) on failure.
    """
    import re, base64, urllib.parse
    
    flat_file = desc_file.replace('.vmdk', '-flat.vmdk')
    esxi_flat_path = f"/vmfs/volumes/{datastore}/{vm_dir}/{flat_file}"
    
    # 1. Get flat file size
    rc, out, _ = _ssh_exec(esxi_host, esxi_user, esxi_pass,
        f"stat -c'%s' {shlex.quote(esxi_flat_path)} 2>/dev/null", timeout=15)
    if rc != 0 or not str(out or '').strip().isdigit():
        esxi_flat_path = f"/vmfs/volumes/{datastore}/{vm_dir}/{desc_file}"
        flat_file = desc_file
        rc, out, _ = _ssh_exec(esxi_host, esxi_user, esxi_pass,
            f"stat -c'%s' {shlex.quote(esxi_flat_path)} 2>/dev/null", timeout=10)
    if rc != 0 or not str(out or '').strip().isdigit():
        task.log(f"  Cannot stat VMDK on ESXi")
        return None, None
    
    flat_size = int(out.strip())
    flat_size_gb = flat_size / (1024**3)
    size_kb = (flat_size + 1023) // 1024
    task.log(f"  Source: {flat_file} ({flat_size_gb:.1f} GB)")
    
    # 2. Resolve datastore friendly name
    rc_ds, out_ds, _ = _ssh_exec(esxi_host, esxi_user, esxi_pass,
        "esxcli storage filesystem list 2>/dev/null", timeout=15)
    ds_name = None
    if out_ds:
        for line in str(out_ds).split('\n'):
            if datastore in line:
                parts = line.strip().split()
                if len(parts) >= 2:
                    for p in parts[1:]:
                        if p and not p.startswith('/') and not p.isdigit():
                            ds_name = p; break
                break
    if not ds_name:
        rc_v, out_v, _ = _ssh_exec(esxi_host, esxi_user, esxi_pass,
            "vim-cmd hostsvc/datastore/listsummary 2>/dev/null", timeout=15)
        if out_v:
            current_name = None
            for line in str(out_v).split('\n'):
                line_s = line.strip()
                if 'name =' in line_s or 'name=' in line_s:
                    current_name = line_s.split('=')[-1].strip().strip('"\',' )
                if datastore in line_s and current_name:
                    ds_name = current_name; break
    if not ds_name:
        ds_name = datastore
    task.log(f"  Datastore: {ds_name}")
    
    # 3. Allocate raw volume on Proxmox using robust helper
    vol_id, vol_path = _pvesm_alloc_disk(pve_mgr, task.target_node,
        task.target_storage, task.proxmox_vmid, disk_index, flat_size)
    if not vol_id or not vol_path:
        task.log(f"  Disk allocation failed for disk {disk_index}")
        return None, None
    task.log(f"  Allocated: {vol_id}")
    task.log(f"  Target: {vol_path}")
    
    # 5. Build HTTPS URL
    url_path = urllib.parse.quote(f"{vm_dir}/{flat_file}", safe='/')
    ds_param = urllib.parse.quote(ds_name)
    url = f"https://{esxi_host}/folder/{url_path}?dcPath=ha-datacenter&dsName={ds_param}"
    task.log(f"  URL: .../{vm_dir}/{flat_file}?dsName={ds_name}")
    
    # 6. Store credentials on Proxmox node
    auth_file = f"/tmp/v2p-{task.id}-auth-{disk_index}"
    cookie_jar = f"/tmp/v2p-{task.id}-cookies-{disk_index}"
    b64auth = base64.b64encode(f"{esxi_user}:{esxi_pass}".encode()).decode()
    _pve_node_exec(pve_mgr, task.target_node,
        f"echo '{b64auth}' | base64 -d > {auth_file} && chmod 600 {auth_file}", timeout=10)
    
    # 7. Establish cookie session
    task.log(f"  Establishing ESXi session...")
    _pve_node_exec(pve_mgr, task.target_node,
        f"curl -sk --user $(cat {auth_file}) "
        f"-c {cookie_jar} -o /dev/null "
        f"'https://{esxi_host}/folder?dcPath=ha-datacenter&dsName={ds_param}' 2>/dev/null",
        timeout=15)
    
    # 8. DIAGNOSTIC: Test 1MB download to temp file
    test_file = f"/tmp/v2p-{task.id}-test-{disk_index}"
    task.log(f"  Testing 1MB download...")
    
    # Try cookie+auth (most likely to work)
    test_cmd = (
        f"curl -sk -b {cookie_jar} --user $(cat {auth_file}) -r 0-1048575 "
        f"-o {test_file} -w 'HTTP=%{{http_code}} DL=%{{size_download}}' "
        f"'{url}' 2>/dev/null && "
        f"echo ' FSIZE='$(stat -c%s {test_file} 2>/dev/null || echo 0)"
    )
    rc_t, out_t, _ = _pve_node_exec(pve_mgr, task.target_node, test_cmd, timeout=30)
    test_result = str(out_t or '').strip()
    task.log(f"  Test result: {test_result}")
    
    # If failed, try cookie only
    fsize_m = re.search(r'FSIZE=(\d+)', test_result)
    test_bytes = int(fsize_m.group(1)) if fsize_m else 0
    
    if test_bytes == 0:
        test_cmd2 = (
            f"curl -sk -b {cookie_jar} -r 0-1048575 "
            f"-o {test_file} -w 'HTTP=%{{http_code}} DL=%{{size_download}}' "
            f"'{url}' 2>/dev/null && "
            f"echo ' FSIZE='$(stat -c%s {test_file} 2>/dev/null || echo 0)"
        )
        rc_t2, out_t2, _ = _pve_node_exec(pve_mgr, task.target_node, test_cmd2, timeout=30)
        test_result2 = str(out_t2 or '').strip()
        task.log(f"  Cookie-only test: {test_result2}")
        fsize_m2 = re.search(r'FSIZE=(\d+)', test_result2)
        test_bytes = int(fsize_m2.group(1)) if fsize_m2 else 0
    
    # If still 0, verbose diagnostic
    if test_bytes == 0:
        task.log(f"  0 bytes - running verbose curl diagnostic...")
        diag_cmd = (
            f"curl -vsk -b {cookie_jar} --user $(cat {auth_file}) -r 0-1023 "
            f"'{url}' 2>&1 | head -40"
        )
        rc_d, out_d, _ = _pve_node_exec(pve_mgr, task.target_node, diag_cmd, timeout=15)
        diag = str(out_d or '').strip()
        task.log(f"  Verbose: {diag[:600]}")
    
    _pve_node_exec(pve_mgr, task.target_node, f"rm -f {test_file}", timeout=5)
    
    downloaded = 0
    dl_success = False
    
    # ================================================================
    # METHOD 1: HTTPS full download (if test download got data)
    # ================================================================
    if test_bytes > 0:
        task.log(f"  HTTPS test OK ({test_bytes}B) - full download {flat_size_gb:.1f} GB...")
        dd_log = f"/tmp/v2p-{task.id}-dl-{disk_index}.log"
        
        dl_cmd = (
            f"curl -sk -b {cookie_jar} --user $(cat {auth_file}) "
            f"--connect-timeout 30 --max-time 86400 "
            f"'{url}' 2>/dev/null "
            f"| dd of='{vol_path}' bs=4M 2>{dd_log}; "
            f"echo RC=${{PIPESTATUS[0]}}/${{PIPESTATUS[1]}}; "
            f"cat {dd_log}; rm -f {dd_log}"
        )
        rc_dl, out_dl, _ = _pve_node_exec(pve_mgr, task.target_node, dl_cmd, timeout=86400)
        dl_out = str(out_dl or '').strip()
        task.log(f"  HTTPS: {dl_out[-250:]}")
        
        bytes_m = re.search(r'(\d+) bytes', dl_out)
        if bytes_m:
            downloaded = int(bytes_m.group(1))
        if downloaded >= flat_size * 0.9:
            dl_success = True
            task.log(f"  HTTPS OK: {downloaded/(1024**3):.2f} GB")
        else:
            task.log(f"  HTTPS incomplete: {downloaded/(1024**3):.2f} GB")
    else:
        task.log(f"  HTTPS test 0 bytes - skipping HTTPS full download")
    
    # ================================================================
    # METHOD 2: SSH dd pipe (direct, no FUSE, no HTTP)
    # ================================================================
    if not dl_success:
        task.log(f"  SSH dd pipe ({flat_size_gb:.1f} GB)...")
        _pve_node_exec(pve_mgr, task.target_node,
            "which sshpass >/dev/null 2>&1 || apt-get install -y sshpass >/dev/null 2>&1", timeout=30)
        
        safe_p = shlex.quote(esxi_pass)
        dd_log2 = f"/tmp/v2p-{task.id}-sshdd-{disk_index}.log"

        ssh_cmd = (
            f"sshpass -p {safe_p} ssh -o StrictHostKeyChecking=no "
            f"-o UserKnownHostsFile=/dev/null -o ConnectTimeout=15 "
            f"-o HostKeyAlgorithms=+ssh-rsa,ssh-ed25519 "
            f"-o KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group14-sha256 "
            f"{esxi_user}@{esxi_host} "
            f"\"dd if={shlex.quote(esxi_flat_path)} bs=4M\" 2>/dev/null "
            f"| dd of='{vol_path}' bs=4M 2>{dd_log2}; "
            f"echo PIPE=${{PIPESTATUS[0]}}/${{PIPESTATUS[1]}}; "
            f"cat {dd_log2}; rm -f {dd_log2}"
        )
        rc_s, out_s, _ = _pve_node_exec(pve_mgr, task.target_node, ssh_cmd, timeout=86400)
        ssh_out = str(out_s or '').strip()
        task.log(f"  SSH: {ssh_out[-250:]}")
        
        bytes_m2 = re.search(r'(\d+) bytes', ssh_out)
        if bytes_m2:
            downloaded = int(bytes_m2.group(1))
        if downloaded >= flat_size * 0.9:
            dl_success = True
            task.log(f"  SSH OK: {downloaded/(1024**3):.2f} GB")
        else:
            task.log(f"  SSH: only {downloaded/(1024**3):.2f} GB (VMDK locked?)")
    
    # ================================================================
    # METHOD 3: SSHFS dd (FUSE mount)
    # ================================================================
    if not dl_success:
        sshfs_src = f"/tmp/v2p-{task.id}/{vm_dir}/{flat_file}"
        task.log(f"  SSHFS dd from {sshfs_src}...")
        rc_chk, out_chk, _ = _pve_node_exec(pve_mgr, task.target_node,
            f"ls -la '{sshfs_src}' 2>&1", timeout=10)
        if rc_chk == 0:
            dd_log3 = f"/tmp/v2p-{task.id}-dd3-{disk_index}.log"
            rc_dd, out_dd, _ = _pve_node_exec(pve_mgr, task.target_node,
                f"dd if='{sshfs_src}' of='{vol_path}' bs=4M 2>{dd_log3}; "
                f"cat {dd_log3}; rm -f {dd_log3}", timeout=86400)
            dd_out = str(out_dd or '').strip()
            task.log(f"  SSHFS: {dd_out[-200:]}")
            bytes_m3 = re.search(r'(\d+) bytes', dd_out)
            downloaded = int(bytes_m3.group(1)) if bytes_m3 else 0
            if downloaded >= flat_size * 0.9:
                dl_success = True
        else:
            task.log(f"  SSHFS not accessible: {str(out_chk or '')[:100]}")
    
    # Cleanup
    _pve_node_exec(pve_mgr, task.target_node, f"rm -f {auth_file} {cookie_jar}", timeout=5)
    
    if not dl_success:
        task.log(f"  ALL methods failed ({downloaded} of {flat_size} bytes)")
        task.log(f"  Hint: VMDK locked by running VM. The ESXi HTTPS /folder endpoint should")
        task.log(f"  serve files even while locked - check verbose curl output above for details.")
        _pve_node_exec(pve_mgr, task.target_node, f"pvesm free '{vol_id}' 2>/dev/null", timeout=30)
        return None, None
    
    return vol_id, vol_path



def _delta_sync_blocks(pve_mgr, task, esxi_host, esxi_user, esxi_pass,
                        esxi_flat_path, vol_path, flat_size, disk_index,
                        pve_checksums=None):
    """Block-level delta sync: only transfer changed blocks.
    
    Compares checksums of fixed-size blocks between ESXi source and Proxmox LV.
    Only re-downloads blocks that differ. VM must be stopped (no VMDK lock).
    
    If pve_checksums is provided, skips Proxmox checksum computation (pre-computed).
    Returns True on success, False on failure.
    """
    import base64
    
    BLOCK_SIZE = 256 * 1024 * 1024  # 256 MB blocks (fewer checksums = faster downtime)
    num_blocks = (flat_size + BLOCK_SIZE - 1) // BLOCK_SIZE
    bs_mb = BLOCK_SIZE // (1024 * 1024)
    
    task.log(f"  Delta sync: {num_blocks} blocks of {bs_mb}MB each")
    
    # 1. Generate checksums on ESXi (one SSH call, BusyBox-compatible)
    task.log(f"  Computing checksums on ESXi ({num_blocks} blocks)...")
    checksum_script = (
        f"i=0; while [ $i -lt {num_blocks} ]; do "
        f"dd if={shlex.quote(esxi_flat_path)} bs={BLOCK_SIZE} skip=$i count=1 2>/dev/null | md5sum | cut -d' ' -f1; "
        f"i=$((i+1)); done"
    )
    rc_e, out_e, _ = _ssh_exec(esxi_host, esxi_user, esxi_pass,
        checksum_script, timeout=600)
    
    if rc_e != 0 or not out_e:
        task.log(f"  ESXi checksum failed: rc={rc_e}")
        return False
    
    esxi_sums = [s.strip() for s in out_e.strip().split('\n') if s.strip()]
    task.log(f"  ESXi: got {len(esxi_sums)} checksums")
    
    if len(esxi_sums) < num_blocks:
        task.log(f"  WARNING: Expected {num_blocks} checksums, got {len(esxi_sums)}")
        # Pad with empty to force re-download of remaining blocks
        while len(esxi_sums) < num_blocks:
            esxi_sums.append('MISSING')
    
    # 2. Generate checksums on Proxmox LV (use pre-computed if available)
    if pve_checksums and len(pve_checksums) >= num_blocks:
        pve_sums = pve_checksums[:num_blocks]
        task.log(f"  Proxmox: using {len(pve_sums)} pre-computed checksums (no downtime cost)")
    else:
        task.log(f"  Computing checksums on Proxmox...")
        pve_script = (
            f"i=0; while [ $i -lt {num_blocks} ]; do "
            f"dd if={shlex.quote(vol_path)} bs={BLOCK_SIZE} skip=$i count=1 2>/dev/null | md5sum | cut -d' ' -f1; "
            f"i=$((i+1)); done"
        )
        rc_p, out_p, _ = _pve_node_exec(pve_mgr, task.target_node, pve_script, timeout=600)
        
        if rc_p != 0 or not out_p:
            task.log(f"  Proxmox checksum failed: rc={rc_p}")
            return False
        
        pve_sums = [s.strip() for s in out_p.strip().split('\n') if s.strip()]
        task.log(f"  Proxmox: got {len(pve_sums)} checksums")
    
    while len(pve_sums) < num_blocks:
        pve_sums.append('ZERO')
    
    # 3. Find differing blocks
    diff_blocks = []
    for i in range(num_blocks):
        if i >= len(esxi_sums) or i >= len(pve_sums) or esxi_sums[i] != pve_sums[i]:
            diff_blocks.append(i)
    
    diff_size_mb = len(diff_blocks) * bs_mb
    pct = (len(diff_blocks) / num_blocks * 100) if num_blocks > 0 else 0
    task.log(f"  Delta: {len(diff_blocks)}/{num_blocks} blocks differ ({diff_size_mb} MB, {pct:.1f}%)")
    
    if not diff_blocks:
        task.log(f"  No changes detected - disk is identical")
        return True
    
    # 4. Transfer only changed blocks via SSH dd
    # Write password file on Proxmox node
    b64pass = base64.b64encode(esxi_pass.encode()).decode()
    pass_file = f"/tmp/v2p-{task.id}-delta-pass"
    _pve_node_exec(pve_mgr, task.target_node,
        f"echo '{b64pass}' | base64 -d > {pass_file} && chmod 600 {pass_file}",
        timeout=10)
    
    # Build a script that transfers all differing blocks
    xfer_lines = ['#!/bin/bash', 'ERRORS=0']
    for i in diff_blocks:
        xfer_lines.append(
            f"sshpass -f {pass_file} ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            f"-o HostKeyAlgorithms=+ssh-rsa,ssh-ed25519 "
            f"-o KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group14-sha256 "
            f"{esxi_user}@{esxi_host} "
            f"\"dd if={shlex.quote(esxi_flat_path)} bs={BLOCK_SIZE} skip={i} count=1 2>/dev/null\" "
            f"| dd of={shlex.quote(vol_path)} bs={BLOCK_SIZE} seek={i} count=1 conv=notrunc 2>/dev/null "
            f"|| ERRORS=$((ERRORS+1))"
        )
    xfer_lines.append(f'rm -f {pass_file}')
    xfer_lines.append('echo "DELTA_DONE errors=$ERRORS"')
    xfer_lines.append('exit $ERRORS')
    
    xfer_script = '\n'.join(xfer_lines) + '\n'
    script_file = f"/tmp/v2p-{task.id}-delta-{disk_index}.sh"
    b64script = base64.b64encode(xfer_script.encode()).decode()
    _pve_node_exec(pve_mgr, task.target_node,
        f"echo '{b64script}' | base64 -d > {script_file} && chmod +x {script_file}",
        timeout=10)
    
    task.log(f"  Transferring {len(diff_blocks)} changed blocks ({diff_size_mb} MB)...")
    rc_x, out_x, _ = _pve_node_exec(pve_mgr, task.target_node,
        f"bash {script_file} 2>&1", timeout=86400)
    
    result = str(out_x or '').strip()
    task.log(f"  Delta result: rc={rc_x}, {result[-200:]}")
    
    # Cleanup
    _pve_node_exec(pve_mgr, task.target_node,
        f"rm -f {script_file} {pass_file}", timeout=5)
    
    return rc_x == 0 or 'DELTA_DONE errors=0' in result


def _cleanup_sshfs(pve_mgr, node, mnt_path):
    """Unmount SSHFS and clean up mount point."""
    _pve_node_exec(pve_mgr, node,
        f"fusermount -u {mnt_path} 2>/dev/null; rmdir {mnt_path} 2>/dev/null", timeout=15)


def _attach_imported_disk(pve_mgr, task, disk_index, disk_bus, importdisk_output):
    """Parse qm importdisk output and attach the disk to the VM.
    
    qm importdisk outputs: Successfully imported disk as 'unused0:local-lvm:vm-100-disk-0'
    We extract storage:volume and attach it with qm set.
    """
    import re
    disk_ref = None
    
    # Parse: Successfully imported disk as 'unused0:local-lvm:vm-100-disk-0'
    # We need the part after 'unusedN:' -> 'local-lvm:vm-100-disk-0'
    match = re.search(r"unused\d+:(\S+)", importdisk_output)
    if match:
        disk_ref = match.group(1).strip("'\"")
    
    # Fallback: look for storage:vm-NNN-disk-N pattern directly
    if not disk_ref:
        match2 = re.search(re.escape(task.target_storage) + r':vm-\d+-disk-\d+', importdisk_output)
        if match2:
            disk_ref = match2.group(0)
    
    if disk_ref:
        attach_cmd = f"qm set {task.proxmox_vmid} --{disk_bus}{disk_index} {disk_ref} 2>&1"
        rc, out, err = _pve_node_exec(pve_mgr, task.target_node, attach_cmd, timeout=30)
        if rc == 0:
            task.log(f"Disk {disk_index} attached as {disk_bus}{disk_index} ({disk_ref})")
        else:
            task.log(f"WARNING: attach failed: {out} {err}")
    else:
        task.log(f"WARNING: Could not parse disk ref from importdisk output: {importdisk_output[-200:]}")

