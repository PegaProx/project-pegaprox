"""Wipe Disk on the node Disks tab got to PVE in neither of its two steps.

PVE has /nodes/{node}/disks/wipedisk as PUT only (pve-storage, PVE/API2/Disks.pm), so the
POST the manager sent came back 501. The button before it sent the disk without the
confirm_name the route asks for, so the route answered 400 first.
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


def test_the_wipe_button_sends_the_confirmation_the_route_asks_for():
    with open(os.path.join(ROOT, 'web', 'src', 'node_modals.js'), encoding='utf-8') as f:
        src = f.read()
    i = src.index('/disks/wipe`')
    call = src[i:src.index('});', i)]
    assert re.search(r'confirm_name:\s*d\.devpath', call), call
