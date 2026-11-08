# #647 (cklabautermann) — rolling-update evacuation reported false failures. A migrate POST can
# come back 500 "VM is locked (migrate)" when a migration for the guest is already in flight (PVE
# HA relocates on maintenance-enter, or a recheck/parallel pass re-issues it). PegaProx treated the
# lock error as a hard failure and paused the rolling update, even though the guest migrated fine.
# The fix waits for the in-flight move and only succeeds if the guest actually leaves the source.

from unittest.mock import MagicMock

from pegaprox.core.manager import PegaProxManager


def _mgr():
    m = PegaProxManager.__new__(PegaProxManager)   # skip heavy __init__
    # host / api_port are read-only properties resolved from these:
    m.current_host = None
    m.config = MagicMock(host='h', api_port=8006, dry_run=False)
    m.logger = MagicMock()
    m.last_migration_log = []
    return m


def _resp(status, text):
    r = MagicMock()
    r.status_code = status
    r.text = text
    return r


_LOCK = '500 - {"data":null,"message":"VM is locked (migrate)\\n"}'


def test_locked_migrate_is_success_when_guest_leaves_source():
    m = _mgr()
    m._api_post = MagicMock(return_value=_resp(500, _LOCK))
    # the in-flight migration landed the guest on pve4 (it left pve3)
    m.get_vm_resources = MagicMock(return_value=[{'vmid': 190, 'node': 'pve4', 'type': 'lxc'}])
    vm = {'vmid': 190, 'name': 'xxx64', 'node': 'pve3', 'type': 'lxc'}
    assert m.migrate_vm(vm, 'pve4', dry_run=False, wait_timeout=30) is True
    last = m.last_migration_log[-1]
    assert last['success'] is True
    assert last['to_node'] == 'pve4'


def test_locked_migrate_still_fails_when_guest_stays_and_lock_clears():
    m = _mgr()
    m._api_post = MagicMock(return_value=_resp(500, _LOCK))
    m.get_vm_resources = MagicMock(return_value=[{'vmid': 190, 'node': 'pve3', 'type': 'lxc'}])
    m._vm_has_migrate_lock = MagicMock(return_value=False)   # move ended, guest never left source
    vm = {'vmid': 190, 'name': 'xxx64', 'node': 'pve3', 'type': 'lxc'}
    assert m.migrate_vm(vm, 'pve4', dry_run=False, wait_timeout=30) is False
    assert m.last_migration_log[-1]['success'] is False


def test_non_lock_500_fails_immediately_without_polling():
    m = _mgr()
    m._api_post = MagicMock(return_value=_resp(500, 'storage pve4:local-lvm not available'))
    m.get_vm_resources = MagicMock()   # must NOT be polled for a non-lock error
    vm = {'vmid': 190, 'name': 'xxx64', 'node': 'pve3', 'type': 'lxc'}
    assert m.migrate_vm(vm, 'pve4', dry_run=False, wait_timeout=30) is False
    m.get_vm_resources.assert_not_called()
