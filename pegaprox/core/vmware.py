# -*- coding: utf-8 -*-
"""
PegaProx VMware/vCenter Integration - Layer 5
Connects to vCenter Server or standalone ESXi hosts via REST API.
"""

import os
import json
import time
import logging
import threading
import ssl
import base64
import re
import requests
from datetime import datetime
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from pegaprox.core.db import get_db
from pegaprox.globals import vmware_managers

class VMwareManager:
    """Manages connection to a vCenter Server or standalone ESXi host.
    
    NS: Uses vSphere REST API (available since vSphere 6.5+).
    For older ESXi hosts, falls back to SOAP-based approach via requests.
    This is intentionally pyvmomi-free to avoid the heavy dependency.
    """
    
    def __init__(self, vmware_id: str, config: dict):
        self.id = vmware_id
        self.name = config.get('name', 'vCenter')
        self.host = config.get('host', '')
        self.port = int(config.get('port', 443))
        self.username = config.get('username', 'administrator@vsphere.local')
        self.password = config.get('password', '')
        self.server_type = config.get('server_type', 'vcenter')  # 'vcenter' or 'esxi'
        self.ssl_verify = config.get('ssl_verify', False)
        self.enabled = config.get('enabled', True)
        self.linked_clusters = config.get('linked_clusters', [])
        self.notes = config.get('notes', '')
        
        self.connected = False
        self.last_error = None
        self.session_id = None
        self.api_version = None
        self.server_info = {}
        self._api_style = 'modern'  # 'modern' (/api/) or 'legacy' (/rest/)
        self._connection_type = 'rest'  # 'rest' or 'soap' (pyvmomi)
        self._si = None  # pyvmomi ServiceInstance
        self._soap_content = None  # pyvmomi ServiceContent
        self._base_url = f"https://{self.host}:{self.port}"
        self._connect_lock = threading.Lock()  # Prevent concurrent reconnect attempts
        self._connect_fail_count = 0  # Track consecutive failures for log suppression
    
    def connect(self) -> bool:
        """Establish session with vCenter/ESXi via REST API.
        
        Compatible with:
        - vCenter Server 6.5+ / 7.x / 8.x / 9.x (VCF 9)
        - Standalone ESXi 6.5+ / 7.x / 8.x / 9.x
        
        NS: The /api/session endpoint was introduced in vSphere 6.5.
        For ESXi 9 (VCF 9) the API is the same, but some endpoints
        moved under VCF-specific paths. We handle both transparently.
        Older ESXi (pre-6.5) uses /rest/com/vmware/cis/session instead.
        """
        try:
            import requests
            import urllib3
            if not self.ssl_verify:
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            
            # Try modern /api/session first (vSphere 7.0+)
            resp = requests.post(
                f"{self._base_url}/api/session",
                auth=(self.username, self.password),
                headers={'Content-Type': 'application/json'},
                verify=self.ssl_verify,
                timeout=15
            )
            
            if resp.status_code == 201:
                self.session_id = resp.json()
                self._api_style = 'modern'  # /api/ prefix
            elif resp.status_code in (400, 404, 500, 502, 503):
                first_error = resp.status_code
                # Fallback to legacy REST endpoint (vSphere 6.5-6.7 or standalone ESXi)
                legacy_ok = False
                for legacy_path in [
                    '/rest/com/vmware/cis/session',
                    '/api/session',  # retry with different headers
                ]:
                    try:
                        headers = {'Content-Type': 'application/json'}
                        if legacy_path == '/api/session':
                            # Some ESXi need this header for /api/session
                            headers['vmware-use-header-authn'] = 'true'
                            headers['Authorization'] = 'Basic ' + __import__('base64').b64encode(f"{self.username}:{self.password}".encode()).decode()
                            resp = requests.post(
                                f"{self._base_url}{legacy_path}",
                                headers=headers,
                                verify=self.ssl_verify,
                                timeout=15
                            )
                        else:
                            resp = requests.post(
                                f"{self._base_url}{legacy_path}",
                                auth=(self.username, self.password),
                                headers=headers,
                                verify=self.ssl_verify,
                                timeout=15
                            )
                        if resp.status_code in (200, 201):
                            try:
                                data = resp.json()
                                self.session_id = data.get('value', data) if isinstance(data, dict) else data
                            except:
                                self.session_id = resp.text.strip().strip('"')
                            self._api_style = 'legacy' if '/rest/' in legacy_path else 'modern'
                            legacy_ok = True
                            break
                    except:
                        continue
                
                if not legacy_ok:
                    # Check if host is reachable at all
                    reachable = False
                    try:
                        check = requests.get(f"{self._base_url}/", verify=self.ssl_verify, timeout=10)
                        reachable = check.status_code < 500 or check.status_code == 503
                    except:
                        pass
                    
                    if first_error == 503 or (reachable and first_error in (500, 502)):
                        self.last_error = (
                            f'ESXi REST API not available (HTTP {first_error}). '
                            f'Make sure the REST API is enabled on {self.host}. '
                            f'For standalone ESXi run: /etc/init.d/restAPIService start'
                        )
                    elif not reachable:
                        self.last_error = f'Cannot reach {self.host}:{self.port}'
                    else:
                        self.last_error = f'All authentication methods failed (first error: HTTP {first_error})'
                    
                    self.connected = False
                    logging.info(f"[VMware:{self.id}] REST API failed ({self.last_error}), trying SOAP/pyvmomi...")
            elif resp.status_code == 401:
                self.last_error = 'Authentication failed - check username/password'
                self.connected = False
                logging.warning(f"[VMware:{self.id}] Connection failed: {self.last_error}")
                return False
            else:
                self.last_error = f'Connection failed: HTTP {resp.status_code}'
                self.connected = False
                logging.warning(f"[VMware:{self.id}] Connection failed: {self.last_error}")
                return False
            
            if not self.session_id:
                # REST didn't get a session (e.g. 503 block fell through) - let SOAP handle it
                pass
            else:
                self.connected = True
                self.last_error = None
            
                # Validate: can we actually fetch data? (standalone ESXi often returns
                # 400 on /api/vcenter/* endpoints despite valid session)
                validation_ok = False
                for test_path in ['/api/vcenter/vm', '/api/vcenter/host', '/rest/vcenter/vm']:
                    try:
                        test_resp = requests.get(
                            f"{self._base_url}{test_path}",
                            headers=self._headers(),
                            verify=self.ssl_verify, timeout=10)
                        if test_resp.status_code == 200:
                            validation_ok = True
                            break
                    except:
                        pass
                
                if not validation_ok:
                    logging.warning(f"[VMware:{self.id}] REST session created but data calls fail - switching to SOAP")
                    self.connected = False
                    self.session_id = None
                    # Fall through to SOAP below
                else:
                    # Detect server version
                    try:
                        info = self.api_get('/api/appliance/system/version')
                        if 'error' not in info:
                            self.server_info = info.get('data', info)
                            self.api_version = self.server_info.get('version', 'unknown')
                        else:
                            self.api_version = 'connected'
                            about = self.api_get('/api/vcenter/system/config/version' if self._api_style == 'modern' else '/rest/vcenter/system/config/version')
                            if 'error' not in about:
                                self.api_version = about.get('data', {}).get('version', self.api_version)
                    except Exception:
                        self.api_version = 'connected'
                    
                    logging.info(f"[VMware:{self.id}] Connected to {self.host} ({self.server_type}, API: {self.api_version}, style: {self._api_style})")
                    return True
                
        except requests.exceptions.SSLError as e:
            self.last_error = f'SSL error: {e}. Try disabling SSL verification.'
            self.connected = False
        except requests.exceptions.ConnectionError:
            self.last_error = f'Cannot connect to {self.host}:{self.port}'
            self.connected = False
        except Exception as e:
            self.last_error = str(e)
            self.connected = False
        
        # REST API failed - try SOAP/pyvmomi fallback (works on ALL ESXi versions)
        rest_error = self.last_error
        if self._connect_soap():
            return True
        
        # Both REST and SOAP failed
        self.last_error = f"REST: {rest_error} | SOAP: {self.last_error}"
        fail_count = getattr(self, '_connect_fail_count', 0)
        if fail_count < 2:
            logging.warning(f"[VMware:{self.id}] Connection failed: {self.last_error}")
        return False
    
    def _connect_soap(self) -> bool:
        """Fallback connection via pyvmomi SOAP API (works on all ESXi/vCenter versions)."""
        try:
            from pyVim.connect import SmartConnect
            from pyVmomi import vim
            import ssl
            
            ssl_context = None
            if not self.ssl_verify:
                ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
            
            logging.debug(f"[VMware:{self.id}] SOAP connecting to {self.host}:{self.port}")
            
            self._si = SmartConnect(
                host=self.host,
                user=self.username,
                pwd=self.password,
                port=self.port,
                sslContext=ssl_context,
                disableSslCertValidation=(not self.ssl_verify)
            )
            
            self._soap_content = self._si.RetrieveContent()
            self._connection_type = 'soap'
            self.connected = True
            self.last_error = None
            self._consecutive_400s = 0
            
            # Get version info
            about = self._soap_content.about
            self.api_version = about.version if about else 'connected'
            self.server_info = {
                'version': about.version if about else '',
                'build': about.build if about else '',
                'fullName': about.fullName if about else '',
            }
            
            logging.info(f"[VMware:{self.id}] Connected via SOAP/pyvmomi to {self.host} ({self.server_type}, v{self.api_version})")
            return True
            
        except ImportError:
            self.last_error = 'pyvmomi not installed. Run: pip install pyvmomi'
            logging.warning(f"[VMware:{self.id}] pyvmomi not available for SOAP fallback")
            return False
        except Exception as e:
            err_str = str(e)
            fail_count = getattr(self, '_connect_fail_count', 0)
            # Clean up verbose pyvmomi error messages
            if 'InvalidLogin' in err_str or 'incorrect user name or password' in err_str:
                self.last_error = f'Login failed for {self.username}@{self.host} - check password in VMware settings'
                self._last_connect_error_type = 'auth'
                if fail_count < 2:
                    logging.warning(f"[VMware:{self.id}] SOAP login failed - wrong username/password for {self.username}@{self.host}")
            elif 'No route' in err_str or 'ConnectionRefused' in err_str or 'Connection refused' in err_str or 'timed out' in err_str:
                self.last_error = f'Cannot reach {self.host}:{self.port}'
                self._last_connect_error_type = 'network'
                if fail_count < 2:
                    logging.warning(f"[VMware:{self.id}] SOAP connection failed: {err_str[:120]}")
                elif fail_count % 10 == 0:
                    logging.info(f"[VMware:{self.id}] Still unreachable ({fail_count} attempts)")
            else:
                self.last_error = err_str[:200]
                if fail_count < 3:
                    logging.warning(f"[VMware:{self.id}] SOAP connection failed: {err_str[:200]}")
            return False
    
    def _soap_get_container(self, obj_type, recursive=True):
        """Helper to get all objects of a type via SOAP."""
        if not self._soap_content:
            return []
        try:
            from pyVmomi import vim
            container = self._soap_content.rootFolder
            view_type = [obj_type]
            container_view = self._soap_content.viewManager.CreateContainerView(
                container, view_type, recursive
            )
            objects = container_view.view
            container_view.Destroy()
            return objects
        except Exception as e:
            logging.debug(f"[VMware:{self.id}] SOAP container error: {e}")
            return []
    
    def _soap_get_managed_object(self, obj_type, moid):
        """Get a specific managed object by its MoId."""
        try:
            objects = self._soap_get_container(obj_type)
            for obj in objects:
                if obj._moId == moid:
                    return obj
        except:
            pass
        return None
    
    def _headers(self) -> dict:
        return {'vmware-api-session-id': self.session_id} if self.session_id else {}
    
    def api_get(self, path: str, params: dict = None) -> dict:
        """GET request to vSphere REST API"""
        try:
            import requests
            resp = requests.get(
                f"{self._base_url}{path}",
                headers=self._headers(),
                params=params,
                verify=self.ssl_verify,
                timeout=30
            )
            if resp.status_code == 401:
                # Session expired, try reconnect
                if self.connect():
                    resp = requests.get(f"{self._base_url}{path}", headers=self._headers(), 
                                       params=params, verify=self.ssl_verify, timeout=30)
            if resp.status_code == 200:
                try:
                    self._consecutive_400s = 0  # Reset on success
                    return {'data': resp.json()}
                except Exception:
                    return {'data': resp.text}
            if resp.status_code == 400:
                self._consecutive_400s = getattr(self, '_consecutive_400s', 0) + 1
            return {'error': f'HTTP {resp.status_code}: {resp.text[:200]}', 'status_code': resp.status_code}
        except Exception as e:
            return {'error': str(e)}
    
    def api_post(self, path: str, data: dict = None) -> dict:
        """POST request to vSphere REST API"""
        try:
            import requests
            resp = requests.post(
                f"{self._base_url}{path}",
                headers={**self._headers(), 'Content-Type': 'application/json'},
                json=data,
                verify=self.ssl_verify,
                timeout=60
            )
            if resp.status_code == 401:
                if self.connect():
                    resp = requests.post(f"{self._base_url}{path}", 
                                        headers={**self._headers(), 'Content-Type': 'application/json'},
                                        json=data, verify=self.ssl_verify, timeout=60)
            if resp.status_code in (200, 201, 204):
                try:
                    return {'data': resp.json()}
                except Exception:
                    return {'data': 'ok'}
            return {'error': f'HTTP {resp.status_code}: {resp.text[:200]}', 'status_code': resp.status_code}
        except Exception as e:
            return {'error': str(e)}
    
    def api_delete(self, path: str) -> dict:
        """DELETE request to vSphere REST API"""
        try:
            import requests
            resp = requests.delete(
                f"{self._base_url}{path}",
                headers=self._headers(),
                verify=self.ssl_verify,
                timeout=30
            )
            if resp.status_code in (200, 204):
                return {'data': 'ok'}
            return {'error': f'HTTP {resp.status_code}: {resp.text[:200]}'}
        except Exception as e:
            return {'error': str(e)}
    
    # -- VMs --
    
    def get_vms(self) -> dict:
        """List all VMs from vCenter/ESXi"""
        if self._connection_type == 'soap':
            return self._soap_get_vms()
        return self.api_get('/api/vcenter/vm')
    
    def _soap_get_vms(self) -> dict:
        """List VMs via pyvmomi SOAP API."""
        try:
            from pyVmomi import vim
            vms = self._soap_get_container(vim.VirtualMachine)
            result = []
            for vm in vms:
                try:
                    cfg = vm.config
                    runtime = vm.runtime
                    guest = vm.guest
                    result.append({
                        'vm': vm._moId,
                        'name': cfg.name if cfg else vm.name,
                        'power_state': str(runtime.powerState).replace('powered', 'POWERED_').upper() if runtime else 'UNKNOWN',
                        'cpu_count': cfg.hardware.numCPU if cfg and cfg.hardware else 0,
                        'memory_size_MiB': cfg.hardware.memoryMB if cfg and cfg.hardware else 0,
                        'guest_OS': cfg.guestFullName if cfg else '',
                    })
                except:
                    result.append({'vm': getattr(vm, '_moId', '?'), 'name': getattr(vm, 'name', '?'), 'power_state': 'UNKNOWN'})
            return {'data': result}
        except Exception as e:
            return {'error': str(e)}
    
    def get_vm(self, vm_id: str) -> dict:
        """Get detailed info about a specific VM"""
        if self._connection_type == 'soap':
            return self._soap_get_vm(vm_id)
        return self.api_get(f'/api/vcenter/vm/{vm_id}')
    
    def _soap_get_vm(self, vm_id: str) -> dict:
        try:
            from pyVmomi import vim
            vm = self._soap_get_managed_object(vim.VirtualMachine, vm_id)
            if not vm:
                return {'error': 'VM not found'}
            cfg = vm.config
            runtime = vm.runtime
            guest = vm.guest
            summary = vm.summary
            
            # Extract disk info from hardware devices
            disks = {}
            scsi_controllers = {}
            nics = {}
            ide_controllers = {}
            sata_controllers = {}
            
            if cfg and cfg.hardware and cfg.hardware.device:
                for dev in cfg.hardware.device:
                    # SCSI Controllers
                    if isinstance(dev, vim.vm.device.VirtualSCSIController):
                        ctrl_type = type(dev).__name__
                        # Map VMware controller types to Proxmox equivalents
                        pve_type = 'virtio-scsi-single'  # default
                        if 'ParaVirtualSCSI' in ctrl_type or 'PVSCSI' in ctrl_type.upper():
                            pve_type = 'pvscsi'
                        elif 'LsiLogicSAS' in ctrl_type:
                            pve_type = 'lsi'
                        elif 'LsiLogic' in ctrl_type:
                            pve_type = 'lsi'
                        elif 'BusLogic' in ctrl_type:
                            pve_type = 'lsi'
                        scsi_controllers[dev.key] = {
                            'type': ctrl_type,
                            'pve_type': pve_type,
                            'bus_number': getattr(dev, 'busNumber', 0),
                            'label': dev.deviceInfo.label if dev.deviceInfo else ctrl_type,
                        }
                    
                    # IDE Controllers
                    elif isinstance(dev, vim.vm.device.VirtualIDEController):
                        ide_controllers[dev.key] = {
                            'type': 'ide',
                            'bus_number': getattr(dev, 'busNumber', 0),
                        }
                    
                    # SATA Controllers
                    elif isinstance(dev, vim.vm.device.VirtualSATAController):
                        sata_controllers[dev.key] = {
                            'type': 'sata',
                            'bus_number': getattr(dev, 'busNumber', 0),
                        }
                    
                    # Network adapters
                    elif isinstance(dev, vim.vm.device.VirtualEthernetCard):
                        nic_type = type(dev).__name__
                        pve_model = 'e1000'  # safe default
                        if 'Vmxnet3' in nic_type:
                            pve_model = 'vmxnet3'
                        elif 'Vmxnet2' in nic_type:
                            pve_model = 'vmxnet3'  # closest Proxmox equivalent
                        elif 'E1000e' in nic_type or 'E1000E' in nic_type:
                            pve_model = 'e1000e'
                        elif 'E1000' in nic_type:
                            pve_model = 'e1000'
                        elif 'Pcnet' in nic_type:
                            pve_model = 'e1000'  # PCnet not available, use e1000
                        
                        mac = getattr(dev, 'macAddress', '') or ''
                        network_name = ''
                        if hasattr(dev, 'backing') and dev.backing:
                            if hasattr(dev.backing, 'network') and dev.backing.network:
                                network_name = dev.backing.network.name
                            elif hasattr(dev.backing, 'deviceName'):
                                network_name = dev.backing.deviceName or ''
                        
                        nics[dev.key] = {
                            'type': nic_type,
                            'pve_model': pve_model,
                            'mac_address': mac,
                            'network': network_name,
                            'label': dev.deviceInfo.label if dev.deviceInfo else nic_type,
                        }
                    
                    # Disks
                    elif isinstance(dev, vim.vm.device.VirtualDisk):
                        key = str(dev.key)
                        backing = dev.backing
                        vmdk_file = ''
                        thin = False
                        datastore_name = ''
                        if backing:
                            vmdk_file = getattr(backing, 'fileName', '') or ''
                            thin = getattr(backing, 'thinProvisioned', False) or False
                            if hasattr(backing, 'datastore') and backing.datastore:
                                datastore_name = backing.datastore.name
                        cap_bytes = getattr(dev, 'capacityInBytes', 0) or (getattr(dev, 'capacityInKB', 0) * 1024)
                        
                        # Detect which bus this disk is on
                        ctrl_key = getattr(dev, 'controllerKey', None)
                        disk_bus = 'scsi'  # default
                        if ctrl_key in ide_controllers:
                            disk_bus = 'ide'
                        elif ctrl_key in sata_controllers:
                            disk_bus = 'sata'
                        
                        disks[key] = {
                            'label': dev.deviceInfo.label if dev.deviceInfo else f'Disk {key}',
                            'capacity': cap_bytes,
                            'bus': disk_bus,
                            'controller_key': ctrl_key,
                            'unit_number': getattr(dev, 'unitNumber', 0),
                            'backing': {
                                'vmdk_file': vmdk_file,
                                'thin_provisioned': thin,
                                'datastore': datastore_name,
                            }
                        }
            
            # Detect firmware (BIOS vs EFI)
            firmware = 'bios'
            if cfg:
                fw = getattr(cfg, 'firmware', '') or ''
                if 'efi' in str(fw).lower():
                    firmware = 'efi'
            
            # Determine primary SCSI controller type
            primary_scsi = 'virtio-scsi-single'
            primary_scsi_vmware = 'LSI Logic'
            if scsi_controllers:
                # Use the controller with lowest bus number
                primary = min(scsi_controllers.values(), key=lambda c: c.get('bus_number', 99))
                primary_scsi = primary.get('pve_type', 'virtio-scsi-single')
                primary_scsi_vmware = primary.get('type', 'unknown')
            
            # Determine primary NIC model
            primary_nic = 'e1000'
            primary_nic_vmware = 'E1000'
            if nics:
                primary_n = list(nics.values())[0]
                primary_nic = primary_n.get('pve_model', 'e1000')
                primary_nic_vmware = primary_n.get('type', 'unknown')
            
            # Determine disk bus
            primary_disk_bus = 'scsi'
            if disks:
                first_disk = list(disks.values())[0]
                primary_disk_bus = first_disk.get('bus', 'scsi')
            
            return {'data': {
                'vm': vm._moId,
                'name': cfg.name if cfg else vm.name,
                'power_state': str(runtime.powerState).replace('powered', 'POWERED_').upper() if runtime else 'UNKNOWN',
                'cpu': {'count': cfg.hardware.numCPU if cfg and cfg.hardware else 0},
                'memory': {'size_MiB': cfg.hardware.memoryMB if cfg and cfg.hardware else 0},
                'guest_OS': cfg.guestFullName if cfg else '',
                'hardware': {
                    'version': cfg.version if cfg else '',
                    'firmware': firmware,
                    'scsi_controller': primary_scsi_vmware,
                    'scsi_controller_pve': primary_scsi,
                    'nic_type': primary_nic_vmware,
                    'nic_type_pve': primary_nic,
                    'disk_bus': primary_disk_bus,
                },
                'controllers': {
                    'scsi': list(scsi_controllers.values()),
                    'sata': list(sata_controllers.values()),
                    'ide': list(ide_controllers.values()),
                },
                'nics': list(nics.values()),
                'disks': disks,
                'guest_info': {
                    'ip_address': guest.ipAddress if guest else None,
                    'host_name': guest.hostName if guest else None,
                    'tools_status': str(guest.toolsStatus) if guest and guest.toolsStatus else None,
                } if guest else None,
            }}
        except Exception as e:
            return {'error': str(e)}
    
    def vm_power_action(self, vm_id: str, action: str) -> dict:
        """Power action on VM: start, stop, suspend, reset"""
        if self._connection_type == 'soap':
            return self._soap_vm_power(vm_id, action)
        return self.api_post(f'/api/vcenter/vm/{vm_id}/power/{action}')
    
    def _soap_vm_power(self, vm_id: str, action: str) -> dict:
        try:
            from pyVmomi import vim
            vm = self._soap_get_managed_object(vim.VirtualMachine, vm_id)
            if not vm:
                return {'error': 'VM not found'}
            task = None
            if action == 'start':
                task = vm.PowerOn()
            elif action == 'stop':
                task = vm.PowerOff()
            elif action == 'suspend':
                task = vm.Suspend()
            elif action == 'reset':
                task = vm.Reset()
            else:
                return {'error': f'Unknown action: {action}'}
            return {'data': {'task': str(task) if task else 'ok'}}
        except Exception as e:
            return {'error': str(e)}
    
    def get_vm_guest_info(self, vm_id: str) -> dict:
        """Get guest OS info (IP, hostname, tools status)"""
        if self._connection_type == 'soap':
            try:
                from pyVmomi import vim
                vm = self._soap_get_managed_object(vim.VirtualMachine, vm_id)
                if not vm or not vm.guest:
                    return {'data': {}}
                g = vm.guest
                return {'data': {
                    'ip_address': g.ipAddress,
                    'host_name': g.hostName,
                    'family': str(g.guestFamily) if g.guestFamily else None,
                    'full_name': g.guestFullName,
                    'tools_status': str(g.toolsStatus) if g.toolsStatus else None,
                    'tools_version': g.toolsVersion,
                }}
            except Exception as e:
                return {'error': str(e)}
        return self.api_get(f'/api/vcenter/vm/{vm_id}/guest/identity')
    
    # -- Snapshots --
    
    def get_snapshots(self, vm_id: str) -> dict:
        """List snapshots for a VM"""
        if self._connection_type == 'soap':
            return self._soap_get_snapshots(vm_id)
        return self.api_get(f'/api/vcenter/vm/{vm_id}/snapshots')  # vSphere 8+
    
    def _soap_get_snapshots(self, vm_id: str) -> dict:
        try:
            from pyVmomi import vim
            vm = self._soap_get_managed_object(vim.VirtualMachine, vm_id)
            if not vm or not vm.snapshot:
                return {'data': []}
            result = []
            def _walk_snaps(snap_list):
                for snap in snap_list:
                    result.append({
                        'snapshot': str(snap.snapshot._moId) if snap.snapshot else '',
                        'name': snap.name,
                        'description': snap.description or '',
                        'create_time': snap.createTime.isoformat() if snap.createTime else '',
                        'power_state': str(snap.state).replace('powered', 'POWERED_').upper() if snap.state else '',
                    })
                    if snap.childSnapshotList:
                        _walk_snaps(snap.childSnapshotList)
            _walk_snaps(vm.snapshot.rootSnapshotList)
            return {'data': result}
        except Exception as e:
            return {'error': str(e)}
    
    def create_snapshot(self, vm_id: str, name: str, description: str = '', memory: bool = False, quiesce: bool = True) -> dict:
        """Create a snapshot"""
        return self.api_post(f'/api/vcenter/vm/{vm_id}/snapshots', data={
            'spec': {'name': name, 'description': description, 'memory': memory, 'quiesce': quiesce}
        })
    
    def delete_snapshot(self, vm_id: str, snapshot_id: str) -> dict:
        """Delete a specific snapshot"""
        return self.api_delete(f'/api/vcenter/vm/{vm_id}/snapshots/{snapshot_id}')
    
    # -- Hosts --
    
    def get_hosts(self) -> dict:
        """List all ESXi hosts (from vCenter, or self for standalone)"""
        if self._connection_type == 'soap':
            return self._soap_get_hosts()
        return self.api_get('/api/vcenter/host')
    
    def _soap_get_hosts(self) -> dict:
        try:
            from pyVmomi import vim
            hosts = self._soap_get_container(vim.HostSystem)
            result = []
            for h in hosts:
                try:
                    runtime = h.runtime
                    hw = h.hardware
                    result.append({
                        'host': h._moId,
                        'name': h.name,
                        'connection_state': str(runtime.connectionState).upper() if runtime else 'UNKNOWN',
                        'power_state': str(runtime.powerState).upper() if runtime else 'UNKNOWN',
                        'cpu_cores': hw.cpuInfo.numCpuCores if hw and hw.cpuInfo else 0,
                        'memory_bytes': hw.memorySize if hw else 0,
                    })
                except:
                    result.append({'host': getattr(h, '_moId', '?'), 'name': h.name, 'connection_state': 'CONNECTED'})
            return {'data': result}
        except Exception as e:
            return {'error': str(e)}
    
    def get_host(self, host_id: str) -> dict:
        """Get host details"""
        return self.api_get(f'/api/vcenter/host/{host_id}')
    
    # -- Datastores --
    
    def get_datastores(self) -> dict:
        """List all datastores"""
        if self._connection_type == 'soap':
            return self._soap_get_datastores()
        return self.api_get('/api/vcenter/datastore')
    
    def _soap_get_datastores(self) -> dict:
        try:
            from pyVmomi import vim
            stores = self._soap_get_container(vim.Datastore)
            result = []
            for ds in stores:
                try:
                    summ = ds.summary
                    result.append({
                        'datastore': ds._moId,
                        'name': ds.name,
                        'type': str(summ.type) if summ else 'UNKNOWN',
                        'capacity': summ.capacity if summ else 0,
                        'free_space': summ.freeSpace if summ else 0,
                    })
                except:
                    result.append({'datastore': getattr(ds, '_moId', '?'), 'name': ds.name})
            return {'data': result}
        except Exception as e:
            return {'error': str(e)}
    
    def get_datastore(self, ds_id: str) -> dict:
        """Get datastore details"""
        return self.api_get(f'/api/vcenter/datastore/{ds_id}')
    
    # -- Networks --
    
    def get_networks(self) -> dict:
        """List all networks"""
        if self._connection_type == 'soap':
            return self._soap_get_networks()
        return self.api_get('/api/vcenter/network')
    
    def _soap_get_networks(self) -> dict:
        try:
            from pyVmomi import vim
            nets = self._soap_get_container(vim.Network)
            result = []
            for net in nets:
                try:
                    result.append({
                        'network': net._moId,
                        'name': net.name,
                        'type': type(net).__name__,
                    })
                except:
                    result.append({'network': getattr(net, '_moId', '?'), 'name': net.name})
            return {'data': result}
        except Exception as e:
            return {'error': str(e)}
    
    # -- Clusters (vCenter) --
    
    def get_vcenter_clusters(self) -> dict:
        """List vCenter compute clusters"""
        return self.api_get('/api/vcenter/cluster')
    
    # -- Datacenters --
    
    def get_datacenters(self) -> dict:
        """List datacenters"""
        return self.api_get('/api/vcenter/datacenter')
    
    # -- Resource Pools --
    
    def get_resource_pools(self) -> dict:
        """List resource pools"""
        return self.api_get('/api/vcenter/resource-pool')
    
    # -- VM Console --
    
    def get_vm_console_ticket(self, vm_id: str) -> dict:
        """Get a console ticket for a VM. Tries multiple methods:
        1. REST WebMKS ticket (vCenter 7+)
        2. SOAP AcquireTicket (all versions)
        3. Direct ESXi HTML5 console URL
        """
        # Method 1: REST API WebMKS (vCenter 7+)
        if self._connection_type != 'soap':
            for ticket_type in ['WEBMKS', 'MKS']:
                result = self.api_post(f'/api/vcenter/vm/{vm_id}/console/tickets', data={
                    'spec': {'type': ticket_type}
                })
                if 'error' not in result:
                    data = result.get('data', {})
                    ticket = data.get('ticket', data.get('value', ''))
                    if isinstance(ticket, dict):
                        ticket_str = ticket.get('ticket', '')
                        host = ticket.get('host', self.host)
                        port = ticket.get('port', 443)
                    else:
                        ticket_str = str(ticket)
                        host = self.host
                        port = 443
                    if ticket_str:
                        return {'data': {
                            'ticket': ticket_str,
                            'host': host,
                            'port': port,
                            'type': ticket_type,
                            'url': f"wss://{host}:{port}/ticket/{ticket_str}",
                            'web_url': f"https://{self.host}/ui/webconsole.html?vmId={vm_id}&vmName=&serverGuid=&host={host}&sessionTicket={ticket_str}&thumbprint=",
                        }}
        
        # Method 2: SOAP AcquireTicket (works on all versions incl. ESXi)
        if self._connection_type == 'soap' or self._si:
            try:
                from pyVmomi import vim
                vm = self._soap_get_managed_object(vim.VirtualMachine, vm_id)
                if vm:
                    # Try webmks first, then mks
                    for ttype in ['webmks', 'mks']:
                        try:
                            ticket = vm.AcquireTicket(ttype)
                            if ticket and ticket.ticket:
                                host = ticket.host or self.host
                                port = ticket.port or 443
                                ssl_tp = getattr(ticket, 'sslThumbprint', '') or ''
                                # Build URLs
                                wmks_url = f"wss://{host}:{port}/ticket/{ticket.ticket}"
                                # ESXi has built-in HTML console
                                web_url = f"https://{self.host}/ui/#/console/{vm_id}"
                                # VMRC protocol link
                                vmrc_url = f"vmrc://clone:{ticket.ticket}@{host}:{port}/?moid={vm_id}"
                                return {'data': {
                                    'ticket': ticket.ticket,
                                    'host': host,
                                    'port': port,
                                    'type': ttype,
                                    'ssl_thumbprint': ssl_tp,
                                    'url': wmks_url,
                                    'web_url': web_url,
                                    'vmrc_url': vmrc_url,
                                    'cfgFile': getattr(ticket, 'cfgFile', ''),
                                }}
                        except Exception:
                            continue
                    
                    # Fallback: try AcquireMksTicket (older API)
                    try:
                        ticket = vm.AcquireMksTicket()
                        if ticket and ticket.ticket:
                            return {'data': {
                                'ticket': ticket.ticket,
                                'host': ticket.host or self.host,
                                'port': ticket.port or 902,
                                'type': 'mks_legacy',
                                'url': f"wss://{ticket.host or self.host}:{ticket.port or 902}/ticket/{ticket.ticket}",
                                'web_url': f"https://{self.host}/ui/#/console/{vm_id}",
                                'vmrc_url': f"vmrc://clone:{ticket.ticket}@{ticket.host or self.host}:{ticket.port or 902}/?moid={vm_id}",
                            }}
                    except Exception:
                        pass
            except Exception as e:
                logging.warning(f"[VMware:{self.id}] SOAP console ticket failed: {e}")
        
        # Method 3: Direct URL fallback (no ticket needed for ESXi web UI)
        web_url = f"https://{self.host}/ui/#/host/vms/{vm_id}/console" if self.server_type == 'esxi' else f"https://{self.host}/ui/app/vm;nav=v/urn:vmomi:VirtualMachine:{vm_id}/console"
        return {'data': {
            'ticket': '',
            'type': 'direct_url',
            'host': self.host,
            'web_url': web_url,
            'vmrc_url': f"vmrc://{self.username}@{self.host}/?moid={vm_id}",
        }}
    
    # -- VM Configuration --
    
    def update_vm_config(self, vm_id: str, config: dict) -> dict:
        """Update VM configuration (CPU, RAM, notes, etc).
        VM should be powered off for most changes.
        config keys: cpu_count, memory_mb, notes, num_cores_per_socket
        """
        if self._connection_type == 'soap':
            return self._soap_update_vm_config(vm_id, config)
        
        # REST API approach
        spec = {}
        if 'cpu_count' in config:
            spec['cpu'] = {'count': int(config['cpu_count'])}
        if 'memory_mb' in config:
            spec['memory'] = {'size_MiB': int(config['memory_mb'])}
        if not spec:
            return {'error': 'No configuration changes specified'}
        
        result = self.api_post(f'/api/vcenter/vm/{vm_id}', spec)
        # REST PATCH for notes
        if 'notes' in config and 'error' not in result:
            import requests
            try:
                resp = requests.patch(
                    f"{self._base_url}/api/vcenter/vm/{vm_id}",
                    headers={**self._headers(), 'Content-Type': 'application/json'},
                    json={'annotation': config['notes']},
                    verify=self.ssl_verify, timeout=30
                )
            except:
                pass
        return result if 'error' not in result else result
    
    def _soap_update_vm_config(self, vm_id: str, config: dict) -> dict:
        """Update VM config via pyvmomi."""
        try:
            from pyVmomi import vim
            vm = self._soap_get_managed_object(vim.VirtualMachine, vm_id)
            if not vm:
                return {'error': 'VM not found'}
            
            spec = vim.vm.ConfigSpec()
            changed = False
            
            if 'cpu_count' in config:
                spec.numCPUs = int(config['cpu_count'])
                changed = True
            if 'num_cores_per_socket' in config:
                spec.numCoresPerSocket = int(config['num_cores_per_socket'])
                changed = True
            if 'memory_mb' in config:
                spec.memoryMB = int(config['memory_mb'])
                changed = True
            if 'notes' in config:
                spec.annotation = str(config['notes'])
                changed = True
            if 'name' in config:
                spec.name = str(config['name'])
                changed = True
            
            # Hot-add settings
            if 'cpu_hot_add' in config:
                spec.cpuHotAddEnabled = bool(config['cpu_hot_add'])
                changed = True
            if 'memory_hot_add' in config:
                spec.memoryHotAddEnabled = bool(config['memory_hot_add'])
                changed = True
            
            if not changed:
                return {'error': 'No configuration changes specified'}
            
            task = vm.ReconfigVM_Task(spec=spec)
            # Wait for completion
            import time as _t
            for _ in range(60):
                if task.info.state in ('success', 'error'):
                    break
                _t.sleep(0.5)
            
            if task.info.state == 'success':
                return {'data': 'ok'}
            err_msg = str(task.info.error) if task.info.error else 'Unknown error'
            return {'error': f'Reconfigure failed: {err_msg}'}
        except Exception as e:
            return {'error': str(e)}
    
    def update_vm_network(self, vm_id: str, nic_key: int, network_name: str) -> dict:
        """Change a VM NIC's network."""
        if self._connection_type == 'soap':
            return self._soap_update_vm_network(vm_id, nic_key, network_name)
        return {'error': 'Network change requires SOAP/pyvmomi connection'}
    
    def _soap_update_vm_network(self, vm_id: str, nic_key: int, network_name: str) -> dict:
        """Change VM network via pyvmomi."""
        try:
            from pyVmomi import vim
            vm = self._soap_get_managed_object(vim.VirtualMachine, vm_id)
            if not vm:
                return {'error': 'VM not found'}
            
            # Find the NIC
            nic_device = None
            if vm.config and vm.config.hardware and vm.config.hardware.device:
                for dev in vm.config.hardware.device:
                    if isinstance(dev, vim.vm.device.VirtualEthernetCard):
                        if dev.key == nic_key or nic_key == 0:
                            nic_device = dev
                            break
            if not nic_device:
                return {'error': f'NIC with key {nic_key} not found'}
            
            # Find the target network
            networks = self._soap_get_container(vim.Network)
            target_net = None
            for net in networks:
                if net.name == network_name:
                    target_net = net
                    break
            if not target_net:
                return {'error': f'Network "{network_name}" not found'}
            
            # Build spec
            nic_spec = vim.vm.device.VirtualDeviceSpec()
            nic_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.edit
            nic_spec.device = nic_device
            
            if isinstance(target_net, vim.dvs.DistributedVirtualPortgroup):
                dvs_port = vim.dvs.PortConnection()
                dvs_port.portgroupKey = target_net.key
                dvs_port.switchUuid = target_net.config.distributedVirtualSwitch.uuid
                nic_device.backing = vim.vm.device.VirtualEthernetCard.DistributedVirtualPortBackingInfo()
                nic_device.backing.port = dvs_port
            else:
                nic_device.backing = vim.vm.device.VirtualEthernetCard.NetworkBackingInfo()
                nic_device.backing.network = target_net
                nic_device.backing.deviceName = network_name
            
            config_spec = vim.vm.ConfigSpec()
            config_spec.deviceChange = [nic_spec]
            
            task = vm.ReconfigVM_Task(spec=config_spec)
            import time as _t
            for _ in range(30):
                if task.info.state in ('success', 'error'):
                    break
                _t.sleep(0.5)
            
            if task.info.state == 'success':
                return {'data': 'ok'}
            return {'error': f'Network change failed: {task.info.error}'}
        except Exception as e:
            return {'error': str(e)}
    
    def update_vm_boot_order(self, vm_id: str, boot_order: list) -> dict:
        """Set VM boot order. boot_order: list of 'disk', 'cdrom', 'net', 'floppy'"""
        if self._connection_type == 'soap':
            return self._soap_update_boot_order(vm_id, boot_order)
        return {'error': 'Boot order change requires SOAP/pyvmomi connection'}
    
    def _soap_update_boot_order(self, vm_id: str, boot_order: list) -> dict:
        try:
            from pyVmomi import vim
            vm = self._soap_get_managed_object(vim.VirtualMachine, vm_id)
            if not vm:
                return {'error': 'VM not found'}
            
            spec = vim.vm.ConfigSpec()
            boot_spec = vim.vm.BootOptions()
            
            order = []
            for item in boot_order:
                if item == 'disk':
                    order.append(vim.vm.BootOptions.BootableDiskDevice(deviceKey=0))
                elif item == 'cdrom':
                    order.append(vim.vm.BootOptions.BootableCdromDevice())
                elif item == 'net':
                    order.append(vim.vm.BootOptions.BootableEthernetDevice(deviceKey=0))
                elif item == 'floppy':
                    order.append(vim.vm.BootOptions.BootableFloppyDevice())
            
            if order:
                boot_spec.bootOrder = order
            spec.bootOptions = boot_spec
            
            task = vm.ReconfigVM_Task(spec=spec)
            import time as _t
            for _ in range(30):
                if task.info.state in ('success', 'error'):
                    break
                _t.sleep(0.5)
            if task.info.state == 'success':
                return {'data': 'ok'}
            return {'error': f'Boot order change failed: {task.info.error}'}
        except Exception as e:
            return {'error': str(e)}
    
    # -- Folders --
    
    def get_folders(self, folder_type: str = None) -> dict:
        """List folders. type can be: VIRTUAL_MACHINE, HOST, DATASTORE, NETWORK, DATACENTER"""
        params = {}
        if folder_type:
            params['filter.type'] = folder_type
        return self.api_get('/api/vcenter/folder', params=params)
    
    # -- Tags & Categories --
    
    def get_tag_categories(self) -> dict:
        """List tag categories"""
        return self.api_get('/api/cis/tagging/category')
    
    def get_tags(self, category_id: str = None) -> dict:
        """List tags, optionally filtered by category"""
        if category_id:
            return self.api_post(f'/api/cis/tagging/tag/id:{{category_id}}?~action=list-tags-for-category')
        return self.api_get('/api/cis/tagging/tag')
    
    def get_vm_tags(self, vm_id: str) -> dict:
        """List tags attached to a VM"""
        return self.api_post('/api/cis/tagging/tag-association?~action=list-attached-tags', data={
            'object_id': {'type': 'VirtualMachine', 'id': vm_id}
        })
    
    # -- Performance / Monitoring --
    
    def get_vm_stats(self, vm_id: str) -> dict:
        """Get VM performance statistics (CPU, memory, disk, network)
        Uses MOB/stats endpoint available in most vSphere versions"""
        # Try vStats API first (vSphere 7+)
        result = self.api_get(f'/api/vcenter/vm/{vm_id}')
        return result
    
    # -- Storage Policies --
    
    def get_storage_policies(self) -> dict:
        """List VM storage policies"""
        return self.api_get('/api/vcenter/storage/policies')
    
    # -- Content Libraries --
    
    def get_content_libraries(self) -> dict:
        """List content libraries"""
        return self.api_get('/api/content/library')
    
    def get_library_items(self, library_id: str) -> dict:
        """List items in a content library"""
        return self.api_get(f'/api/content/library/item?library_id={library_id}')
    
    # -- Alarms --
    
    def get_alarms(self) -> dict:
        """Get triggered alarms (if available via REST)"""
        return self.api_get('/api/appliance/health/system')
    
    def get_appliance_health(self) -> dict:
        """Get vCenter appliance health status"""
        result = {}
        for component in ['system', 'load', 'mem', 'swap', 'storage', 'database-storage', 'software-packages']:
            resp = self.api_get(f'/api/appliance/health/{component}')
            if 'error' not in resp:
                result[component] = resp.get('data', resp)
        return {'data': result}
    
    # -- VM Operations --
    
    def rename_vm(self, vm_id: str, new_name: str) -> dict:
        """Rename a VM"""
        return self.api_post(f'/api/vcenter/vm/{vm_id}?~action=rename', data={'name': new_name})
    
    def clone_vm(self, vm_id: str, name: str, folder: str = None, resource_pool: str = None, datastore: str = None) -> dict:
        """Clone a VM (instant clone or full clone depending on vSphere version)"""
        spec = {
            'name': name,
            'source': vm_id,
        }
        placement = {}
        if folder:
            placement['folder'] = folder
        if resource_pool:
            placement['resource_pool'] = resource_pool
        if datastore:
            placement['datastore'] = datastore
        if placement:
            spec['placement'] = placement
        return self.api_post('/api/vcenter/vm?~action=clone', data={'spec': spec})
    
    def delete_vm(self, vm_id: str) -> dict:
        """Delete a VM (must be powered off)"""
        return self.api_delete(f'/api/vcenter/vm/{vm_id}')
    
    # -- Summary / Dashboard --
    
    # ================================================================
    # LIVE MIGRATION - VMware to Proxmox (Near-Zero-Downtime)
    # NS: Feb 2026 - Rewritten to use SSHFS + qm importdisk (real approach)
    # Works with VMFS 5, VMFS 6, vSAN, NFS datastores
    # ================================================================
    
    def get_vm_disks_for_export(self, vm_id: str) -> dict:
        """Get VM disk layout with VMDK paths for migration planning.
        Returns the datastore paths needed for SSHFS-based disk copy."""
        vm_detail = self.get_vm(vm_id)
        if 'error' in vm_detail:
            return vm_detail
        data = vm_detail.get('data', {})
        disks = []
        if isinstance(data.get('disks'), dict):
            for key, disk in data['disks'].items():
                if isinstance(disk, dict):
                    backing = disk.get('backing', {})
                    disks.append({
                        'key': key,
                        'label': disk.get('label', key),
                        'capacity_bytes': disk.get('capacity', 0),
                        'capacity_gb': round(disk.get('capacity', 0) / (1024**3), 1) if disk.get('capacity') else 0,
                        'thin': backing.get('thin_provisioned', False),
                        'vmdk_file': backing.get('vmdk_file', ''),
                    })
        cpu = data.get('cpu', {})
        mem = data.get('memory', {})
        return {'data': {
            'vm_id': vm_id,
            'name': data.get('name', ''),
            'power_state': data.get('power_state', ''),
            'cpu_count': cpu.get('count', 0) if isinstance(cpu, dict) else data.get('cpu_count', 0),
            'memory_mb': mem.get('size_MiB', 0) if isinstance(mem, dict) else data.get('memory_size_MiB', 0),
            'guest_os': data.get('guest_OS', ''),
            'disks': disks,
            'total_disk_gb': sum(d.get('capacity_gb', 0) for d in disks),
        }}
    
    def create_migration_snapshot(self, vm_id: str) -> dict:
        """Create quiesced snapshot so base VMDK becomes read-only.
        The VM continues running, writing to a delta file.
        This lets us copy the base VMDK safely via SSHFS."""
        return self.create_snapshot(vm_id, '_pegaprox_migration_snap',
            'PegaProx live migration - do not delete manually', False, True)
    
    def delete_migration_snapshot(self, vm_id: str) -> dict:
        """Delete the migration snapshot, consolidating delta back into base.
        Called after VM is stopped during cutover phase."""
        snaps = self.get_snapshots(vm_id)
        if 'data' in snaps:
            snap_list = snaps['data'] if isinstance(snaps['data'], list) else []
            for s in snap_list:
                if s.get('name') == '_pegaprox_migration_snap':
                    return self.delete_snapshot(vm_id, str(s.get('snapshot', s.get('id', ''))))
        return {'data': 'no migration snapshot found'}

    def get_summary(self) -> dict:
        """Get a summary of the entire vCenter/ESXi environment"""
        summary = {
            'vms': {'total': 0, 'powered_on': 0, 'powered_off': 0, 'suspended': 0},
            'hosts': {'total': 0, 'connected': 0},
            'datastores': {'total': 0},
            'networks': {'total': 0},
        }
        
        # VMs
        vms = self.get_vms()
        if 'data' in vms and isinstance(vms['data'], list):
            summary['vms']['total'] = len(vms['data'])
            for vm in vms['data']:
                ps = vm.get('power_state', '')
                if ps == 'POWERED_ON': summary['vms']['powered_on'] += 1
                elif ps == 'POWERED_OFF': summary['vms']['powered_off'] += 1
                elif ps == 'SUSPENDED': summary['vms']['suspended'] += 1
        
        # Hosts
        hosts = self.get_hosts()
        if 'data' in hosts and isinstance(hosts['data'], list):
            summary['hosts']['total'] = len(hosts['data'])
            summary['hosts']['connected'] = sum(1 for h in hosts['data'] if h.get('connection_state') == 'CONNECTED')
        
        # Datastores
        ds = self.get_datastores()
        if 'data' in ds and isinstance(ds['data'], list):
            summary['datastores']['total'] = len(ds['data'])
        
        # Networks
        nets = self.get_networks()
        if 'data' in nets and isinstance(nets['data'], list):
            summary['networks']['total'] = len(nets['data'])
        
        # Health (vCenter only)
        if self.server_type == 'vcenter':
            health = self.get_appliance_health()
            if 'data' in health:
                summary['health'] = health['data']
        
        return {'data': summary}
    
    def ensure_connected(self) -> bool:
        """Ensure we have a valid session, reconnect if needed.
        
        Also detects stale REST sessions (ESXi returns 400/401 for data calls
        even though session was created) and switches to SOAP if needed.
        Thread-safe with lock to prevent concurrent reconnect storms.
        """
        if self.connected and (self.session_id or self._connection_type == 'soap'):
            # Quick health check: if we've seen repeated 400s, force reconnect
            if getattr(self, '_consecutive_400s', 0) >= 3:
                logging.warning(f"[VMware:{self.id}] REST API returning 400s - forcing SOAP reconnect")
                self._consecutive_400s = 0
                self._try_soap_fallback()
                return self.connected
            return True
        
        # Cooldown check (lock-free fast path)
        now = time.time()
        last_attempt = getattr(self, '_last_connect_attempt', 0)
        last_error_type = getattr(self, '_last_connect_error_type', '')
        
        if last_error_type == 'auth' and (now - last_attempt) < 300:
            return False  # Auth failures: only retry every 5 minutes
        if last_error_type == 'network' and (now - last_attempt) < 120:
            return False  # Network unreachable: retry every 2 minutes
        if (now - last_attempt) < 60:
            return False  # Other failures: retry every 60s
        
        # Use lock to prevent multiple threads from reconnecting simultaneously
        if not self._connect_lock.acquire(blocking=False):
            return False  # Another thread is already reconnecting
        
        try:
            # Re-check after acquiring lock (another thread may have connected)
            if self.connected and (self.session_id or self._connection_type == 'soap'):
                return True
            
            self._last_connect_attempt = time.time()
            
            # Only log first failure and every 5th retry to reduce spam
            fail_count = getattr(self, '_connect_fail_count', 0)
            if fail_count == 0 or fail_count % 5 == 0:
                logging.info(f"[VMware:{self.id}] Session lost, reconnecting...{f' (attempt #{fail_count+1})' if fail_count > 0 else ''}")
            
            result = self.connect()
            
            # Track error type for cooldown
            if not result and self.last_error:
                self._connect_fail_count = fail_count + 1
                err = str(self.last_error)
                if 'Login failed' in err or 'InvalidLogin' in err or 'incorrect' in err:
                    self._last_connect_error_type = 'auth'
                elif 'No route' in err or 'Cannot connect' in err or 'Cannot reach' in err or 'Connection refused' in err:
                    self._last_connect_error_type = 'network'
                else:
                    self._last_connect_error_type = 'other'
            else:
                self._last_connect_error_type = ''
                self._connect_fail_count = 0
            
            return result
        finally:
            self._connect_lock.release()
    
    def _try_soap_fallback(self):
        """Switch to SOAP (pyvmomi) when REST API fails."""
        logging.info(f"[VMware:{self.id}] Switching to SOAP/pyvmomi...")
        self.connected = False
        self.session_id = None
        return self._connect_soap()
    
    # -- DRS/HA Cluster Management --
    
    def get_cluster_detail(self, cluster_id: str) -> dict:
        """Get detailed cluster info including DRS and HA config."""
        if self._connection_type == 'soap':
            return self._soap_get_cluster_detail(cluster_id)
        return self.api_get(f'/api/vcenter/cluster/{cluster_id}')
    
    def _soap_get_cluster_detail(self, cluster_id: str) -> dict:
        try:
            from pyVmomi import vim
            cluster = self._soap_get_managed_object(vim.ClusterComputeResource, cluster_id)
            if not cluster:
                return {'error': f'Cluster {cluster_id} not found'}
            cfg = cluster.configuration
            drs = cfg.drsConfig if cfg else None
            ha = cfg.dasConfig if cfg else None
            hosts = []
            for h in (cluster.host or []):
                try:
                    hosts.append({
                        'host': h._moId, 'name': h.name,
                        'connection_state': str(h.runtime.connectionState).upper() if h.runtime else 'UNKNOWN',
                        'maintenance': getattr(h.runtime, 'inMaintenanceMode', False) if h.runtime else False,
                    })
                except:
                    hosts.append({'host': getattr(h, '_moId', '?'), 'name': getattr(h, 'name', '?')})
            return {'data': {
                'cluster': cluster_id, 'name': cluster.name,
                'total_cpu': cluster.summary.totalCpu if cluster.summary else 0,
                'total_memory': cluster.summary.totalMemory if cluster.summary else 0,
                'num_hosts': cluster.summary.numHosts if cluster.summary else 0,
                'drs_enabled': drs.enabled if drs else False,
                'drs_automation': str(drs.defaultVmBehavior).upper() if drs and drs.defaultVmBehavior else 'MANUAL',
                'drs_vmotion_rate': drs.vmotionRate if drs else 3,
                'ha_enabled': ha.enabled if ha else False,
                'ha_admission_control': ha.admissionControlEnabled if ha else False,
                'ha_host_monitoring': str(ha.hostMonitoring).upper() if ha and ha.hostMonitoring else 'DISABLED',
                'hosts': hosts,
            }}
        except Exception as e:
            return {'error': str(e)}
    
    def set_cluster_drs(self, cluster_id: str, enabled: bool, automation: str = None) -> dict:
        """Enable/disable DRS on a cluster."""
        if self._connection_type == 'soap':
            return self._soap_set_cluster_drs(cluster_id, enabled, automation)
        spec = {'drs_enabled': enabled}
        if automation:
            spec['drs_default_vm_behavior'] = automation
        return self.api_post(f'/api/vcenter/cluster/{cluster_id}', spec)
    
    def _soap_set_cluster_drs(self, cluster_id: str, enabled: bool, automation: str = None) -> dict:
        try:
            from pyVmomi import vim
            cluster = self._soap_get_managed_object(vim.ClusterComputeResource, cluster_id)
            if not cluster:
                return {'error': f'Cluster {cluster_id} not found'}
            spec = vim.cluster.ConfigSpecEx()
            spec.drsConfig = vim.cluster.DrsConfigInfo()
            spec.drsConfig.enabled = enabled
            if automation:
                bmap = {'FULLY_AUTOMATED': vim.cluster.DrsConfigInfo.DrsBehavior.fullyAutomated,
                        'PARTIALLY_AUTOMATED': vim.cluster.DrsConfigInfo.DrsBehavior.partiallyAutomated,
                        'MANUAL': vim.cluster.DrsConfigInfo.DrsBehavior.manual}
                spec.drsConfig.defaultVmBehavior = bmap.get(automation.upper(), vim.cluster.DrsConfigInfo.DrsBehavior.manual)
            task = cluster.ReconfigureComputeResource_Task(spec=spec, modify=True)
            import time as _t
            for _ in range(30):
                if task.info.state in ('success', 'error'): break
                _t.sleep(1)
            if task.info.state == 'success':
                return {'data': 'ok'}
            return {'error': f'Task failed: {task.info.error}'}
        except Exception as e:
            return {'error': str(e)}
    
    def set_cluster_ha(self, cluster_id: str, enabled: bool) -> dict:
        """Enable/disable HA on a cluster."""
        if self._connection_type == 'soap':
            return self._soap_set_cluster_ha(cluster_id, enabled)
        spec = {'ha_enabled': enabled}
        return self.api_post(f'/api/vcenter/cluster/{cluster_id}', spec)
    
    def _soap_set_cluster_ha(self, cluster_id: str, enabled: bool) -> dict:
        try:
            from pyVmomi import vim
            cluster = self._soap_get_managed_object(vim.ClusterComputeResource, cluster_id)
            if not cluster:
                return {'error': f'Cluster {cluster_id} not found'}
            spec = vim.cluster.ConfigSpecEx()
            spec.dasConfig = vim.cluster.DasConfigInfo()
            spec.dasConfig.enabled = enabled
            if enabled:
                spec.dasConfig.hostMonitoring = 'enabled'
                spec.dasConfig.admissionControlEnabled = True
            task = cluster.ReconfigureComputeResource_Task(spec=spec, modify=True)
            import time as _t
            for _ in range(30):
                if task.info.state in ('success', 'error'): break
                _t.sleep(1)
            if task.info.state == 'success':
                return {'data': 'ok'}
            return {'error': f'Task failed: {task.info.error}'}
        except Exception as e:
            return {'error': str(e)}
    
    def get_vcenter_clusters_detailed(self) -> dict:
        """List clusters with DRS/HA status."""
        if self._connection_type == 'soap':
            return self._soap_get_clusters_detailed()
        clusters = self.api_get('/api/vcenter/cluster')
        if 'error' in clusters:
            return clusters
        enriched = []
        for c in (clusters.get('data', []) if isinstance(clusters.get('data'), list) else []):
            cid = c.get('cluster', c.get('id', ''))
            detail = self.get_cluster_detail(cid)
            enriched.append({**c, **(detail.get('data', {}) if 'data' in detail else {})})
        return {'data': enriched}
    
    def _soap_get_clusters_detailed(self) -> dict:
        try:
            from pyVmomi import vim
            clusters = self._soap_get_container(vim.ClusterComputeResource)
            result = []
            for cl in clusters:
                try:
                    cfg = cl.configuration
                    drs = cfg.drsConfig if cfg else None
                    ha = cfg.dasConfig if cfg else None
                    result.append({
                        'cluster': cl._moId, 'name': cl.name,
                        'num_hosts': cl.summary.numHosts if cl.summary else 0,
                        'total_cpu': cl.summary.totalCpu if cl.summary else 0,
                        'total_memory': cl.summary.totalMemory if cl.summary else 0,
                        'drs_enabled': drs.enabled if drs else False,
                        'drs_automation': str(drs.defaultVmBehavior).upper() if drs and drs.defaultVmBehavior else 'MANUAL',
                        'ha_enabled': ha.enabled if ha else False,
                        'ha_admission_control': ha.admissionControlEnabled if ha else False,
                    })
                except:
                    result.append({'cluster': getattr(cl, '_moId', '?'), 'name': cl.name})
            return {'data': result}
        except Exception as e:
            return {'error': str(e)}
    
    def get_vm_performance(self, vm_id: str) -> dict:
        """Get VM performance metrics."""
        if self._connection_type == 'soap':
            return self._soap_get_vm_perf(vm_id)
        return {'data': {}}
    
    def _soap_get_vm_perf(self, vm_id: str) -> dict:
        try:
            from pyVmomi import vim
            vm = self._soap_get_managed_object(vim.VirtualMachine, vm_id)
            if not vm:
                return {'error': 'VM not found'}
            qs = vm.summary.quickStats if vm.summary else None
            if not qs:
                return {'data': {}}
            return {'data': {
                'cpu_usage_mhz': getattr(qs, 'overallCpuUsage', 0) or 0,
                'memory_usage_mb': getattr(qs, 'guestMemoryUsage', 0) or 0,
                'memory_active_mb': getattr(qs, 'activeMemory', 0) or 0,
                'memory_ballooned_mb': getattr(qs, 'balloonedMemory', 0) or 0,
                'uptime_seconds': getattr(qs, 'uptimeSeconds', 0) or 0,
                'disk_committed': vm.summary.storage.committed if vm.summary and vm.summary.storage else 0,
                'disk_uncommitted': vm.summary.storage.uncommitted if vm.summary and vm.summary.storage else 0,
            }}
        except Exception as e:
            return {'error': str(e)}
    
    def get_datastore_detail(self, ds_id: str) -> dict:
        """Get detailed datastore info including VMs."""
        if self._connection_type == 'soap':
            return self._soap_get_ds_detail(ds_id)
        return self.api_get(f'/api/vcenter/datastore/{ds_id}')
    
    def _soap_get_ds_detail(self, ds_id: str) -> dict:
        try:
            from pyVmomi import vim
            ds = self._soap_get_managed_object(vim.Datastore, ds_id)
            if not ds:
                return {'error': 'Datastore not found'}
            summ = ds.summary
            vm_list = []
            for vm in (ds.vm or []):
                try:
                    vm_list.append({
                        'vm': vm._moId, 'name': vm.name,
                        'power_state': str(vm.runtime.powerState).replace('powered', 'POWERED_').upper() if vm.runtime else 'UNKNOWN',
                    })
                except:
                    vm_list.append({'vm': getattr(vm, '_moId', '?'), 'name': getattr(vm, 'name', '?')})
            host_list = []
            for hm in (ds.host or []):
                try:
                    host_list.append({'host': hm.key._moId, 'name': hm.key.name})
                except:
                    pass
            return {'data': {
                'datastore': ds_id, 'name': ds.name,
                'type': str(summ.type) if summ else 'UNKNOWN',
                'capacity': summ.capacity if summ else 0,
                'free_space': summ.freeSpace if summ else 0,
                'accessible': summ.accessible if summ else False,
                'url': str(summ.url) if summ else '',
                'vms': vm_list, 'hosts': host_list,
                'multiple_host_access': summ.multipleHostAccess if summ else False,
            }}
        except Exception as e:
            return {'error': str(e)}

    # -- Serialization --
    
    def to_dict(self) -> dict:
        """Convert to dict for API response (no secrets)"""
        return {
            'id': self.id,
            'name': self.name,
            'host': self.host,
            'port': self.port,
            'username': self.username,
            'server_type': self.server_type,
            'ssl_verify': self.ssl_verify,
            'enabled': self.enabled,
            'connected': self.connected,
            'last_error': self.last_error,
            'api_version': self.api_version,
            'server_info': self.server_info,
            'linked_clusters': self.linked_clusters,
            'notes': self.notes,
        }


def load_vmware_servers():
    """Load all VMware server configs from DB and create managers"""
    global vmware_managers
    try:
        db = get_db()
        cursor = db.conn.cursor()
        cursor.execute("SELECT * FROM vmware_servers WHERE enabled = 1")
        rows = cursor.fetchall()
        
        for row in rows:
            row_dict = dict(row)
            vmware_id = row_dict['id']
            
            password = ''
            if row_dict.get('pass_encrypted'):
                try:
                    password = db._decrypt(row_dict['pass_encrypted'])
                    # NS: Feb 2026 - SECURITY: only log safe metadata, never password chars
                    logging.debug(f"[VMware:{vmware_id}] Password loaded: len={len(password)}, encrypted=True")
                except Exception as e:
                    logging.warning(f"[VMware:{vmware_id}] Password decryption FAILED: {e}")
                    password = ''
            else:
                logging.warning(f"[VMware:{vmware_id}] No encrypted password in DB!")
            
            username = row_dict.get('username', 'administrator@vsphere.local')
            logging.warning(f"[VMware:{vmware_id}] Connecting as '{username}' to {row_dict.get('host', '?')}")
            
            config = {
                'name': row_dict.get('name', 'vCenter'),
                'host': row_dict.get('host', ''),
                'port': row_dict.get('port', 443),
                'username': username,
                'password': password,
                'server_type': row_dict.get('server_type', 'vcenter'),
                'ssl_verify': bool(row_dict.get('ssl_verify', 0)),
                'enabled': bool(row_dict.get('enabled', 1)),
                'linked_clusters': json.loads(row_dict.get('linked_clusters', '[]')),
                'notes': row_dict.get('notes', ''),
            }
            
            mgr = VMwareManager(vmware_id, config)
            if config['enabled']:
                mgr.connect()
            vmware_managers[vmware_id] = mgr
            
        logging.info(f"[VMware] Loaded {len(rows)} VMware servers ({sum(1 for m in vmware_managers.values() if m.connected)} connected)")
    except Exception as e:
        logging.warning(f"[VMware] Failed to load VMware servers: {e}")


def save_vmware_server(vmware_id: str, config: dict):
    """Save a VMware server config to DB"""
    db = get_db()
    cursor = db.conn.cursor()
    
    pass_encrypted = ''
    if config.get('password') and config['password'] != '********':
        pass_encrypted = db._encrypt(config['password'])
    
    cursor.execute('''
        INSERT OR REPLACE INTO vmware_servers 
        (id, name, host, port, username, pass_encrypted, server_type,
         ssl_verify, enabled, linked_clusters, notes, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                COALESCE((SELECT created_at FROM vmware_servers WHERE id = ?), ?), ?)
    ''', (
        vmware_id, config.get('name', 'vCenter'), config.get('host', ''), int(config.get('port', 443)),
        config.get('username', 'administrator@vsphere.local'),
        pass_encrypted or (cursor.execute("SELECT pass_encrypted FROM vmware_servers WHERE id = ?", (vmware_id,)).fetchone() or [''])[0],
        config.get('server_type', 'vcenter'),
        int(config.get('ssl_verify', False)),
        int(config.get('enabled', True)), json.dumps(config.get('linked_clusters', [])),
        config.get('notes', ''),
        vmware_id, datetime.now().isoformat(), datetime.now().isoformat(),
    ))
    db.conn.commit()



