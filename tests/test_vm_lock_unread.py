"""GET .../lock answers locked:false when it could not read the guest's config too.
The shape stays (older readers expect it), and read:false tells the two apart, so a
view can say "unknown" instead of "not locked". The UI side is test_vm_detail_reads_ui.py.
NS
"""

import pytest

LOCK = '/api/clusters/cluster_1/vms/pve1/qemu/100/lock'


@pytest.fixture
def admin(seed):
    return seed.user('root', role='admin', tenant_id='default')


def _get(api, admin, **mgr):
    api.set_manager('cluster_1', api.make_fake_manager(cluster_id='cluster_1', **mgr))
    resp = api.as_user(admin).get(LOCK)
    assert resp.status_code == 200, resp.get_data(as_text=True)
    return resp.get_json()


def test_a_failed_config_read_says_it_was_not_read(api, admin):
    body = _get(api, admin, get_vm_lock_status={'success': False, 'error': '500 Internal Server Error'})
    assert body['read'] is False
    # the old shape, unchanged
    assert body['locked'] is False and body['unlock_command'] is None
    assert body['note'] == 'Could not determine lock status'


def test_an_exception_says_it_was_not_read(api, admin):
    mgr = api.make_fake_manager(cluster_id='cluster_1')
    mgr.get_vm_lock_status.side_effect = RuntimeError('connection reset')
    api.set_manager('cluster_1', mgr)
    resp = api.as_user(admin).get(LOCK)
    assert resp.status_code == 200
    body = resp.get_json()
    assert body['read'] is False
    assert body['locked'] is False


def test_a_read_that_worked_carries_no_read_false(api, admin):
    free = _get(api, admin, get_vm_lock_status={'success': True, 'locked': False, 'lock_reason': None,
                                               'lock_description': None})
    assert free.get('read') is not False and free['locked'] is False
    assert free['unlock_command'] == 'qm unlock 100'

    held = _get(api, admin, get_vm_lock_status={'success': True, 'locked': True, 'lock_reason': 'backup',
                                               'lock_description': 'Backup in progress'})
    assert held.get('read') is not False
    assert held['locked'] is True and held['lock_reason'] == 'backup'
