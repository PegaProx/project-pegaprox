"""Wipe Disk on the node Disks tab got to PVE in neither of its two steps.

PVE has /nodes/{node}/disks/wipedisk as PUT only (pve-storage, PVE/API2/Disks.pm), so the
POST the manager sent came back 501. The button before it sent the disk without the
confirm_name the route asks for, so the route answered 400 first. On XCP-ng the same
button sends /dev/<name>, which the XCP-ng wipe has to take as well, and so does
Initialize GPT next to it.
"""
import os
import re
import types
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
    mgr._api_token = None  # connected with root@pam's own ticket
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
    mgr._api_token = None
    mgr._api_put.return_value = _resp(500)
    mgr._api_put.return_value.text = 'disk /dev/sdb is used by LVM'
    assert PegaProxManager.wipe_disk(mgr, 'pve1', '/dev/sdb') == {
        'success': False, 'error': 'disk /dev/sdb is used by LVM'}


def test_a_token_cluster_wipes_on_a_fresh_root_ticket_and_closes_it():
    """PVE lets only root@pam run wipedisk and answers an API token 403 (user != root@pam)."""
    mgr = MagicMock()
    mgr.is_connected = True
    mgr.host, mgr.api_port, mgr.api_timeout = 'h', 8006, 10
    mgr._api_token = 'root@pam!pegaprox=secret'
    priv = MagicMock()
    priv.put.return_value = _resp(200, 'UPID:pve1:00001234:0:0:wipedisk:sdb:root@pam:')
    mgr.create_privileged_session.return_value = (priv, None)
    res = PegaProxManager.wipe_disk(mgr, 'pve1', '/dev/sdb')
    assert res == {'success': True, 'task': 'UPID:pve1:00001234:0:0:wipedisk:sdb:root@pam:'}
    mgr.create_privileged_session.assert_called_once_with('a disk wipe')
    priv.put.assert_called_once_with('https://h:8006/api2/json/nodes/pve1/disks/wipedisk',
                                     data={'disk': '/dev/sdb'}, timeout=10)
    assert not mgr._api_put.called and not mgr._api_post.called
    assert priv.close.called

    # the session is closed whatever the PUT does
    priv.reset_mock()
    priv.put.side_effect = OSError('connection reset')
    assert PegaProxManager.wipe_disk(mgr, 'pve1', '/dev/sdb') == {'success': False, 'error': 'connection reset'}
    assert priv.close.called


def test_a_token_only_cluster_is_told_why_nothing_was_wiped():
    """With no root@pam password stored the wipe sends nothing and says what it needs."""
    mgr = MagicMock()
    mgr.is_connected = True
    mgr.host, mgr.api_port = 'h', 8006
    mgr.config.user = 'root@pam!pegaprox'
    mgr._api_token = 'root@pam!pegaprox=secret'
    mgr.create_privileged_session = types.MethodType(PegaProxManager.create_privileged_session, mgr)
    res = PegaProxManager.wipe_disk(mgr, 'pve1', '/dev/sdb')
    assert res['success'] is False, res
    assert 'Proxmox forbids a disk wipe over an API token' in res['error'], res
    assert not mgr._api_put.called and not mgr._api_post.called

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


def test_xcpng_lists_the_disks_of_the_host_the_wipe_goes_to():
    """The Disks tab must not show the pool host's disks under a node it cannot place."""
    from pegaprox.core.xcpng import XcpngManager
    mgr = MagicMock()
    mgr.member_node_ip.return_value = None
    assert XcpngManager.get_node_disks(mgr, 'gone-host') == []
    assert not mgr._ssh_exec.called

    mgr.member_node_ip.return_value = '192.0.2.21'
    mgr._ssh_exec.return_value = (0, '{"blockdevices": [{"name": "sdb", "size": 1, "type": "disk"}]}', '')
    assert [d['devpath'] for d in XcpngManager.get_node_disks(mgr, 'xcp1')] == ['/dev/sdb']
    assert mgr._ssh_exec.call_args.kwargs['host_ip'] == '192.0.2.21'


def test_xcpng_initializes_gpt_on_the_devpath_on_the_host_it_places():
    """Initialize GPT sends /dev/sdb like the wipe, and sgdisk -Z runs on that host's address."""
    from pegaprox.core.xcpng import XcpngManager
    mgr = MagicMock()
    mgr.member_node_ip.return_value = '192.0.2.21'
    mgr._ssh_exec.return_value = (0, '', '')
    assert XcpngManager.init_disk_gpt(mgr, 'xcp1', '/dev/sdb') == {
        'success': True, 'message': 'GPT initialized on /dev/sdb'}
    assert mgr._ssh_exec.call_args.args[1] == 'sgdisk -Z /dev/sdb && sgdisk -o /dev/sdb'
    assert mgr._ssh_exec.call_args.kwargs['host_ip'] == '192.0.2.21'
    mgr.member_node_ip.assert_called_with('xcp1')
    for bad in ('/dev/../etc/passwd', '/dev/sdb; reboot', '/etc/sdb'):
        assert XcpngManager.init_disk_gpt(mgr, 'xcp1', bad)['success'] is False, bad


def test_xcpng_initializes_nothing_on_a_host_it_cannot_place():
    """A name XAPI cannot place never falls back to the pool address for sgdisk."""
    from pegaprox.core.xcpng import XcpngManager
    mgr = MagicMock()
    mgr.member_node_ip.return_value = None
    mgr._ssh_exec.return_value = (0, '', '')
    for disk in ('sdb', '/dev/sdb'):
        res = XcpngManager.init_disk_gpt(mgr, 'gone-host', disk)
        assert res['success'] is False and 'nothing was changed' in res['error'], (disk, res)
        assert not mgr._ssh_exec.called, disk
