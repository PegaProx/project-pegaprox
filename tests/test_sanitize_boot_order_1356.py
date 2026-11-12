"""sanitize_boot_order drops from the boot order the devices a VM no longer has (#1356).

It read the boot line and the device keys from what get_vm_config returns, which is the
config parsed for the UI. That dict has neither: the PVE keys are under 'raw'. So the boot
value came back empty and the function answered "No boot order to sanitize" for every VM,
before delete_vm and on its own route alike. These drive the real get_vm_config,
_parse_vm_config and sanitize_boot_order with only the HTTP answers faked.
"""
import types
from unittest.mock import MagicMock, call

from pegaprox.core.manager import PegaProxManager
from test_vm_disk_unlock import _Resp

BASE = 'https://pve.example:8006/api2/json/nodes/pve1'
STALE = {'name': 'web01', 'boot': 'order=scsi0;ide2;net0', 'memory': '2048',
         'scsi0': 'local-lvm:vm-100-disk-0,size=32G', 'net0': 'virtio=BC:24:11:00:00:01,bridge=vmbr0'}


def _mgr(config, sent=None):
    """A stand-in manager with the real config read and boot order fix bound onto it."""
    m = MagicMock()
    m.is_connected = True
    m.host, m.api_port = 'pve.example', 8006
    for name in ('get_vm_config', '_parse_vm_config', 'sanitize_boot_order', 'delete_vm'):
        setattr(m, name, types.MethodType(getattr(PegaProxManager, name), m))
    m._api_get.return_value = _Resp(200, data=dict(config))
    sent = [] if sent is None else sent

    def put(url, data=None, **kw):
        sent.append(('PUT', url, data))
        return _Resp(200, text='')
    m._api_put.side_effect = put
    m._sent = sent
    return m


def test_a_device_the_vm_no_longer_has_leaves_the_boot_order():
    """order=scsi0;ide2;net0 without an ide2 is written back as order=scsi0;net0."""
    m = _mgr(STALE)
    res = m.sanitize_boot_order('pve1', 100, 'qemu')
    assert res == {'success': True, 'message': 'Removed invalid devices: ide2', 'changed': True,
                   'removed': ['ide2'], 'new_boot_order': 'order=scsi0;net0'}, res
    assert m._sent == [('PUT', f'{BASE}/qemu/100/config', {'boot': 'order=scsi0;net0'})]


def test_a_boot_order_of_devices_the_vm_has_is_left_as_it_is():
    """Every device of the order is in the config: nothing is written."""
    m = _mgr(dict(STALE, ide2='local:iso/debian-12.iso,media=cdrom'))
    res = m.sanitize_boot_order('pve1', 100, 'qemu')
    assert res == {'success': True, 'message': 'Boot order is valid', 'changed': False}, res
    assert m._sent == []


def test_delete_vm_fixes_the_boot_order_before_it_deletes(db):
    """delete_vm writes the cleaned order first and only then sends the DELETE of the VM."""
    sent = []
    m = _mgr(STALE, sent)
    session = MagicMock()
    session.get.return_value = _Resp(200, data={'status': 'stopped'})

    def delete(url, params=None, **kw):
        sent.append(('DELETE', url, params))
        return _Resp(200, data='')
    session.delete.side_effect = delete
    m._create_session.return_value = session
    m.id = 'cluster_1'
    m._no_agent_vms = set()

    assert m.delete_vm('pve1', 100, 'qemu')['success'] is True
    assert sent == [('PUT', f'{BASE}/qemu/100/config', {'boot': 'order=scsi0;net0'}),
                    ('DELETE', f'{BASE}/qemu/100', {})]


def test_the_route_sends_the_cleaned_order_to_proxmox(api, seed):
    """POST .../sanitize-boot-order on a VM with a stale ide2 writes the order without it."""
    m = _mgr(STALE)
    m.cluster_type = 'proxmox'
    m.config.name = 'cluster_1'
    m._create_session.return_value.get.return_value = _Resp(200, data={'status': 'running'})
    api.set_manager('cluster_1', m)
    admin = api.as_user(seed.user('root', role='admin'))

    r = admin.post('/api/clusters/cluster_1/vms/pve1/qemu/100/sanitize-boot-order')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['changed'] is True and r.get_json()['removed'] == ['ide2'], r.get_json()
    assert m._sent == [('PUT', f'{BASE}/qemu/100/config', {'boot': 'order=scsi0;net0'})]


def test_a_net0_the_vm_does_not_have_leaves_the_boot_order_too():
    """PVE refuses a boot order with a missing net0 as with any missing device, so it goes as well."""
    m = _mgr({k: v for k, v in STALE.items() if k != 'net0'})
    res = m.sanitize_boot_order('pve1', 100, 'qemu')
    assert res['success'] is True and res['removed'] == ['ide2', 'net0'], res
    assert m._sent == [('PUT', f'{BASE}/qemu/100/config', {'boot': 'order=scsi0'})]


ORPHAN = {'name': 'web01', 'boot': 'order=scsi0', 'memory': '2048', 'ide2': 'none,media=cdrom'}


def test_with_no_device_left_and_no_net0_the_boot_order_is_dropped():
    """order=net0 on a VM without a NIC is refused by PVE as well: the repair then failed
    in the one case it is there for, and the bad order stayed."""
    m = _mgr(ORPHAN)
    res = m.sanitize_boot_order('pve1', 100, 'qemu')
    assert res['success'] is True and res['removed'] == ['scsi0'], res
    assert m._sent == [('PUT', f'{BASE}/qemu/100/config', {'delete': 'boot'})]


def test_with_no_device_left_a_vm_with_a_nic_boots_from_the_network():
    m = _mgr(dict(ORPHAN, net0='virtio=BC:24:11:00:00:01,bridge=vmbr0'))
    res = m.sanitize_boot_order('pve1', 100, 'qemu')
    assert res['success'] is True and res['new_boot_order'] == 'order=net0', res
    assert m._sent == [('PUT', f'{BASE}/qemu/100/config', {'boot': 'order=net0'})]


def test_the_route_repairs_a_vm_without_a_nic(api, seed):
    m = _mgr(ORPHAN)
    m.cluster_type = 'proxmox'
    m.config.name = 'cluster_1'
    m._create_session.return_value.get.return_value = _Resp(200, data={'status': 'stopped'})
    api.set_manager('cluster_1', m)
    admin = api.as_user(seed.user('root', role='admin'))

    r = admin.post('/api/clusters/cluster_1/vms/pve1/qemu/100/sanitize-boot-order')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['removed'] == ['scsi0'], r.get_json()
    assert m._sent == [('PUT', f'{BASE}/qemu/100/config', {'delete': 'boot'})]
