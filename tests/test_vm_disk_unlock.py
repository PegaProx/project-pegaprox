# Regression guards for two live-reported bugs (NS Aug 2026):
#
#   1. Adding a disk to an LXC container sent a QEMU-shaped key (scsi0/scsi1) to the
#      /lxc/<id>/config endpoint, so PVE rejected the whole request with
#      "scsiN: property is not defined in schema". Containers use mountpoints (mpN)
#      with a container-side mount path. add_disk must coerce onto the next free mpN.
#
#   2. Unlocking a locked VM did a plain `delete=lock` with no skiplock, which PVE
#      refuses unless the caller is root@pam — and an *API token* (even root's) does
#      not count. So a cluster wired up with a root token got "Only root may use this
#      option". unlock_vm now sends skiplock when root@pam and, on refusal, clears the
#      lock over SSH with qm/pct unlock.
#
# These drive the REAL PegaProxManager methods with the HTTP/SSH helpers faked, so the
# branching logic is exercised without a live PVE.

import types
from unittest.mock import MagicMock

from pegaprox.core.manager import PegaProxManager


class _Resp:
    def __init__(self, status_code=200, data=None, text=''):
        self.status_code = status_code
        self._data = data if data is not None else {}
        self.text = text

    def json(self):
        return {'data': self._data}


def _mgr():
    """A MagicMock 'self' with the three real methods under test bound onto it and
    every I/O helper left as a mock the test configures."""
    m = MagicMock()
    m.is_connected = True
    m.host = 'pve.example'
    m.api_port = 8006
    m.add_disk = types.MethodType(PegaProxManager.add_disk, m)
    m.unlock_vm = types.MethodType(PegaProxManager.unlock_vm, m)
    m._next_lxc_mp = types.MethodType(PegaProxManager._next_lxc_mp, m)
    m._used_lxc_mp_slots = types.MethodType(PegaProxManager._used_lxc_mp_slots, m)
    return m


# ---------------------------------------------------------------------------
# add_disk — LXC mountpoint coercion
# ---------------------------------------------------------------------------

def test_lxc_add_disk_coerces_scsi_to_mp0():
    m = _mgr()
    m._api_get.return_value = _Resp(200, data={'rootfs': 'local-lvm:8'})  # no mpN used yet
    m._api_put.return_value = _Resp(200, text='')

    res = m.add_disk('pve1', 105, 'lxc',
                     {'disk_id': 'scsi1', 'storage': 'local-lvm', 'size': 8, 'mountpoint': '/data'})

    assert res['success'] is True, res
    url = m._api_put.call_args.args[0]
    data = m._api_put.call_args.kwargs['data']
    assert '/lxc/105/config' in url
    assert data == {'mp0': 'local-lvm:8,mp=/data'}


def test_lxc_add_disk_picks_next_free_mp_slot():
    m = _mgr()
    m._api_get.return_value = _Resp(200, data={'rootfs': 'x:8', 'mp0': 'x:8,mp=/a', 'mp1': 'x:8,mp=/b'})
    m._api_put.return_value = _Resp(200, text='')

    res = m.add_disk('pve1', 105, 'lxc',
                     {'disk_id': 'scsi3', 'storage': 'tank', 'size': 16, 'mountpoint': '/srv'})

    assert res['success'] is True, res
    assert m._api_put.call_args.kwargs['data'] == {'mp2': 'tank:16,mp=/srv'}


def test_lxc_add_disk_defaults_mount_path_when_missing():
    # PVE requires mp= on every mpN; if the caller omits it we synthesise one from the slot.
    m = _mgr()
    m._api_get.return_value = _Resp(200, data={'rootfs': 'x:8'})
    m._api_put.return_value = _Resp(200, text='')

    res = m.add_disk('pve1', 105, 'lxc', {'disk_id': 'mp0', 'storage': 'local-lvm', 'size': 4})

    assert res['success'] is True, res
    assert m._api_put.call_args.kwargs['data'] == {'mp0': 'local-lvm:4,mp=/mnt/mp0'}


def test_qemu_add_disk_keeps_scsi_key():
    # regression fence: the coercion must NOT touch QEMU disks.
    m = _mgr()
    m._api_put.return_value = _Resp(200, text='')

    res = m.add_disk('pve1', 100, 'qemu',
                     {'disk_id': 'scsi1', 'storage': 'local-lvm', 'size': 32})

    assert res['success'] is True, res
    data = m._api_put.call_args.kwargs['data']
    assert 'scsi1' in data
    assert data['scsi1'].startswith('local-lvm:32')


def test_lxc_add_disk_coerces_occupied_mp_slot():
    # a caller-supplied but ALREADY-USED mpN must be redirected to a free slot, never overwrite.
    m = _mgr()
    m._api_get.return_value = _Resp(200, data={'rootfs': 'x:8', 'mp0': 'x:8,mp=/a'})
    m._api_put.return_value = _Resp(200, text='')

    res = m.add_disk('pve1', 105, 'lxc',
                     {'disk_id': 'mp0', 'storage': 'local-lvm', 'size': 8, 'mountpoint': '/data'})

    assert res['success'] is True, res
    # mp0 is occupied -> the add lands on mp1, leaving mp0 untouched
    assert m._api_put.call_args.kwargs['data'] == {'mp1': 'local-lvm:8,mp=/data'}


def test_lxc_add_disk_never_targets_rootfs():
    m = _mgr()
    m._api_get.return_value = _Resp(200, data={'rootfs': 'x:8'})
    m._api_put.return_value = _Resp(200, text='')

    res = m.add_disk('pve1', 105, 'lxc',
                     {'disk_id': 'rootfs', 'storage': 'local-lvm', 'size': 8, 'mountpoint': '/data'})

    assert res['success'] is True, res
    assert m._api_put.call_args.kwargs['data'] == {'mp0': 'local-lvm:8,mp=/data'}  # not rootfs


def test_lxc_add_disk_rejects_mount_path_injection():
    # a mount path carrying ',' / '=' would inject extra mountpoint options into the config string.
    m = _mgr()
    m._api_get.return_value = _Resp(200, data={'rootfs': 'x:8'})
    m._api_put.return_value = _Resp(200, text='')

    res = m.add_disk('pve1', 105, 'lxc',
                     {'disk_id': 'mp0', 'storage': 'x', 'size': 8, 'mountpoint': '/data,ro=1'})

    assert res['success'] is False and 'mount path' in res['error'], res
    m._api_put.assert_not_called()  # rejected before any config write


# ---------------------------------------------------------------------------
# unlock_vm — skiplock + SSH fallback
# ---------------------------------------------------------------------------

def test_unlock_root_pam_uses_skiplock_and_succeeds_via_api():
    m = _mgr()
    m.config.user = 'root@pam'
    m._api_get.return_value = _Resp(200, data={'lock': 'backup'})
    m._api_put.return_value = _Resp(200)

    res = m.unlock_vm('pve1', 100, 'qemu')

    assert res['success'] is True and res['was_locked'] is True, res
    put_data = m._api_put.call_args.kwargs['data']
    assert put_data.get('delete') == 'lock'
    assert put_data.get('skiplock') == 1
    m._node_ssh_exec.assert_not_called()


def test_unlock_root_token_falls_back_to_ssh():
    # root API token -> PVE rejects skiplock ("Only root...") -> SSH pct unlock clears it.
    m = _mgr()
    m.config.user = 'root@pam!automation'
    m._api_get.return_value = _Resp(200, data={'lock': 'snapshot'})
    m._api_put.return_value = _Resp(500, text='Only root may use this option')
    m._node_ssh_exec.return_value = (0, '', '')

    res = m.unlock_vm('pve1', 105, 'lxc')

    assert res['success'] is True, res
    assert 'SSH' in res['message']
    node, cmd = m._node_ssh_exec.call_args.args[0], m._node_ssh_exec.call_args.args[1]
    assert node == 'pve1'
    assert cmd == 'pct unlock 105'


def test_unlock_not_locked_short_circuits():
    m = _mgr()
    m.config.user = 'root@pam'
    m._api_get.return_value = _Resp(200, data={'name': 'web01'})  # no lock

    res = m.unlock_vm('pve1', 100, 'qemu')

    assert res['success'] is True and res['was_locked'] is False, res
    m._api_put.assert_not_called()
    m._node_ssh_exec.assert_not_called()


def test_unlock_reports_error_when_api_and_ssh_both_fail():
    m = _mgr()
    m.config.user = 'operator@pve'          # not root@ -> no skiplock attempted
    m._api_get.return_value = _Resp(200, data={'lock': 'migrate'})
    m._api_put.return_value = _Resp(500, text='config lock timeout')
    m._node_ssh_exec.return_value = (1, '', 'ssh: connect refused')

    res = m.unlock_vm('pve1', 100, 'qemu')

    assert res['success'] is False, res
    assert 'skiplock' not in m._api_put.call_args.kwargs['data']
    assert 'config lock timeout' in res['error']
    assert 'ssh: connect refused' in res['error']
