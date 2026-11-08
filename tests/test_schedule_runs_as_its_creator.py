"""A schedule acts only while the account that made it still may (#1093).

A scheduled start, stop, shutdown, reboot or snapshot, and a scheduled rolling update,
runs with the cluster's own credentials. Whether its creator was allowed was asked once,
when the schedule was saved. Demote them, move them to another tenant, take the VM grant
away or delete the account, and the schedule kept acting on that VMID (by then perhaps a
different guest) and kept rolling the cluster. Every run now asks again, by the account's
own row, with the same question create asked.
"""
from datetime import datetime
from unittest.mock import MagicMock

import pytest

import pegaprox.api.schedules as sched
from pegaprox.utils import rbac

CL = 'cluster_1'


@pytest.fixture
def cluster(api, seed):
    seed.db.execute('''INSERT INTO clusters (id, name, host, user, pass_encrypted)
                       VALUES (?, ?, '10.0.0.1', 'root@pam', 'x')''', (CL, CL))
    seed.tenant('t', [CL])
    seed.tenant('other', ['cluster_9'])
    m = api.make_fake_manager(CL)
    m.is_connected = True
    m.host, m.api_port = 'pve.example', 8006
    m.get_vm_resources.return_value = [{'vmid': 100, 'node': 'pve1', 'type': 'qemu'}]
    session = MagicMock()
    m._create_session.return_value = session
    api.set_manager(CL, m)
    return session


def _sent(session):
    return [c.args[0] for c in session.post.call_args_list]


def _schedule(api, user):
    r = api.as_user(user).post('/api/schedules', json={
        'cluster_id': CL, 'vmid': 100, 'vm_type': 'qemu', 'action': 'stop',
        'schedule_type': 'daily', 'time': '02:00'})
    assert r.status_code == 200, r.get_data(as_text=True)
    return next(a for a in sched.load_schedules()['actions'] if a['id'] == r.get_json()['schedule']['id'])


STOP = 'https://pve.example:8006/api2/json/nodes/pve1/qemu/100/status/stop'


def _operator(seed, **kw):
    return seed.user('alice', **dict({'role': 'user', 'tenant_id': 't'}, **kw))


@pytest.mark.parametrize('change', ['demoted', 'moved_tenant', 'disabled', 'deleted'])
def test_a_schedule_stops_acting_once_its_creator_may_not(api, seed, db, cluster, change):
    row = _schedule(api, _operator(seed))
    if change == 'demoted':
        _operator(seed, role='viewer')
    elif change == 'moved_tenant':
        _operator(seed, tenant_id='other')
    elif change == 'disabled':
        _operator(seed, enabled=False)
    else:
        db.delete_user('alice')

    sched.execute_scheduled_action(row)

    assert _sent(cluster) == [], f'the schedule still stopped VM 100 after its creator was {change}'


def test_a_revoked_vm_grant_ends_the_schedule_on_that_vm(api, seed, db, cluster):
    seed.tenant('portal', clusters=[])
    u = seed.user('mallory', role='viewer', tenant_id='portal', permissions=['vm.view', 'vm.stop'])
    seed.vm_acl(CL, 100, ['mallory'])
    row = _schedule(api, u)
    db.delete_vm_acl(CL, 100)
    rbac._vm_acls_cache = None

    sched.execute_scheduled_action(row)

    assert _sent(cluster) == []


def _portal_user(seed, *vmids):
    seed.tenant('portal', clusters=[])
    u = seed.user('mallory', role='viewer', tenant_id='portal', permissions=['vm.view', 'vm.stop'])
    for vmid in vmids:
        seed.vm_acl(CL, vmid, ['mallory'])
    return u


def test_a_retargeted_schedule_acts_for_whoever_retargeted_it(api, seed, db, cluster):
    # NS Oct 2026 - the editor picked the new guest, so a run is theirs to answer for: an admin's
    # schedule pointed at VM 200 must end once the editor loses VM 200
    sched.cluster_managers[CL].get_vm_resources.return_value = [
        {'vmid': 100, 'node': 'pve1', 'type': 'qemu'}, {'vmid': 200, 'node': 'pve1', 'type': 'qemu'}]
    row = _schedule(api, seed.user('root', role='admin'))
    editor = _portal_user(seed, 100, 200)
    r = api.as_user(editor).put(f"/api/schedules/{row['id']}", json={'vmid': 200})
    assert r.status_code == 200, r.get_data(as_text=True)
    db.delete_vm_acl(CL, 200)
    rbac._vm_acls_cache = None

    row = next(a for a in sched.load_schedules()['actions'] if a['id'] == row['id'])
    sched.execute_scheduled_action(row)

    assert _sent(cluster) == [], 'the schedule kept stopping VM 200 under its original creator'


def test_an_edit_that_keeps_the_target_keeps_the_creator(api, seed, cluster):
    row = _schedule(api, seed.user('root', role='admin'))
    r = api.as_user(_portal_user(seed, 100)).put(f"/api/schedules/{row['id']}", json={'time': '03:00'})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert next(a for a in sched.load_schedules()['actions']
                if a['id'] == row['id'])['created_by'] == 'root'


@pytest.mark.parametrize('who', ['operator', 'admin', 'vm_grant'])
def test_a_creator_who_still_may_keeps_their_schedule(api, seed, cluster, who):
    if who == 'operator':
        u = _operator(seed)
    elif who == 'admin':
        u = seed.user('root', role='admin')
    else:
        seed.tenant('portal', clusters=[])
        u = seed.user('mallory', role='viewer', tenant_id='portal', permissions=['vm.view', 'vm.stop'])
        seed.vm_acl(CL, 100, ['mallory'])
    row = _schedule(api, u)

    sched.execute_scheduled_action(row)

    assert _sent(cluster) == [STOP]


# -- the rolling update ------------------------------------------------------------------

@pytest.fixture
def rolling(api, seed, cluster, monkeypatch):
    runs = []
    monkeypatch.setattr(sched, 'execute_scheduled_rolling_update', lambda m, cid, a: runs.append(cid))
    monkeypatch.setattr(sched.ha, 'schedule_now', lambda: datetime(2026, 10, 6, 3, 0))
    api_mgr = sched.cluster_managers[CL]
    api_mgr._rolling_update = None
    api_mgr.config.name = CL
    return runs


def _arm(api, user, include_reboot=False):
    r = api.as_user(user).post(f'/api/clusters/{CL}/updates/schedule', json={
        'enabled': True, 'day': 'daily', 'time': '03:00', 'include_reboot': include_reboot})
    assert r.status_code == 200, r.get_data(as_text=True)


def _updater(seed, **kw):
    return seed.user('upd', **dict({'role': 'viewer', 'tenant_id': 't',
                                    'permissions': ['node.update', 'node.reboot']}, **kw))


@pytest.mark.parametrize('change', ['lost_node_update', 'lost_node_reboot', 'moved_tenant', 'deleted'])
def test_a_scheduled_update_waits_for_a_creator_who_may(api, seed, db, rolling, change):
    _arm(api, _updater(seed), include_reboot=(change == 'lost_node_reboot'))
    if change == 'lost_node_update':
        _updater(seed, permissions=['node.reboot'])
    elif change == 'lost_node_reboot':
        _updater(seed, permissions=['node.update'])
    elif change == 'moved_tenant':
        _updater(seed, tenant_id='other')
    else:
        db.delete_user('upd')

    sched.check_scheduled_updates()

    assert rolling == [], f'the rolling update started after its creator {change}'


@pytest.mark.parametrize('who', ['updater', 'admin'])
def test_a_scheduled_update_of_a_creator_who_may_starts(api, seed, rolling, who):
    _arm(api, _updater(seed) if who == 'updater' else seed.user('root', role='admin'), include_reboot=True)

    sched.check_scheduled_updates()

    assert rolling == [CL]


def test_the_schedule_route_still_names_no_creator(api, seed, rolling):
    admin = seed.user('root', role='admin')
    _arm(api, admin)
    got = api.as_user(admin).get(f'/api/clusters/{CL}/updates/schedule').get_json()
    assert 'created_by' not in got
