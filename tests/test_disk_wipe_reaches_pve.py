"""Wipe Disk on the node Disks tab got to PVE in neither of its two steps.

PVE has /nodes/{node}/disks/wipedisk as PUT only (pve-storage, PVE/API2/Disks.pm), so the
POST the manager sent came back 501. The button before it sent the disk without the
confirm_name the route asks for, so the route answered 400 first. On XCP-ng the same
button sends /dev/<name>, which the XCP-ng wipe has to take as well.
"""
import os
import re
from unittest.mock import MagicMock

from pegaprox.core.manager import PegaProxManager

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _resp(code, data=None):
    r = MagicMock()
    r.status_code = code
    r.json.return_value = {'data': data}
    r.text = ''
    return r


def test_the_manager_wipes_with_put():
    mgr = MagicMock()
    mgr.is_connected = True
    mgr.host, mgr.api_port = 'h', 8006
    mgr._api_put.return_value = _resp(200, 'UPID:pve1:00001234:0:0:wipedisk:sdb:root@pam:')
    res = PegaProxManager.wipe_disk(mgr, 'pve1', '/dev/sdb')
    assert res == {'success': True, 'task': 'UPID:pve1:00001234:0:0:wipedisk:sdb:root@pam:'}
    assert mgr._api_put.call_args.args[0] == 'https://h:8006/api2/json/nodes/pve1/disks/wipedisk'
    assert mgr._api_put.call_args.kwargs['data'] == {'disk': '/dev/sdb'}
    assert not mgr._api_post.called


def test_a_refused_wipe_is_reported():
    mgr = MagicMock()
    mgr.is_connected = True
    mgr.host, mgr.api_port = 'h', 8006
    mgr._api_put.return_value = _resp(500)
    mgr._api_put.return_value.text = 'disk /dev/sdb is used by LVM'
    assert PegaProxManager.wipe_disk(mgr, 'pve1', '/dev/sdb') == {
        'success': False, 'error': 'disk /dev/sdb is used by LVM'}


def _wipe_handler():
    with open(os.path.join(ROOT, 'web', 'src', 'node_modals.js'), encoding='utf-8') as f:
        src = f.read()
    i = src.index('/disks/wipe`')
    return src[i:src.index("addToast('Error wiping disk'", i)]


def test_the_wipe_button_sends_the_confirmation_the_route_asks_for():
    handler = _wipe_handler()
    call = handler[:handler.index('});')]
    assert re.search(r'confirm_name:\s*d\.devpath', call), call


def test_a_started_pve_task_is_not_reported_as_a_finished_wipe():
    handler = _wipe_handler()
    assert "r.task ? t('diskWipeStarted') : t('diskWiped')" in handler, handler


def test_xcpng_takes_the_devpath_the_disk_list_gives():
    from pegaprox.core.xcpng import XcpngManager
    mgr = MagicMock()
    mgr.member_node_ip.return_value = '192.0.2.21'
    mgr._ssh_exec.return_value = (0, '', '')
    assert XcpngManager.wipe_disk(mgr, 'xcp1', '/dev/sdb') == {'success': True, 'message': '/dev/sdb wiped'}
    assert mgr._ssh_exec.call_args.args[1] == 'wipefs -a /dev/sdb'
    assert mgr._ssh_exec.call_args.kwargs['host_ip'] == '192.0.2.21'
    assert XcpngManager.wipe_disk(mgr, 'xcp1', 'sdb')['success'] is True
    for bad in ('/dev/../etc/passwd', '/dev/sdb; reboot', '/etc/sdb'):
        assert XcpngManager.wipe_disk(mgr, 'xcp1', bad)['success'] is False, bad


def test_xcpng_wipes_nothing_on_a_host_it_cannot_place():
    """_get_host_ip falls back to the pool address for an unknown name; the wipe must not."""
    from pegaprox.core.xcpng import XcpngManager
    mgr = MagicMock()
    mgr.member_node_ip.return_value = None
    res = XcpngManager.wipe_disk(mgr, 'gone-host', '/dev/sdb')
    assert res['success'] is False and 'nothing was wiped' in res['error']
    assert not mgr._ssh_exec.called
