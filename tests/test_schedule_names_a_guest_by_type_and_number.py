"""A scheduled action names one guest: qemu or lxc, and a VM ID (#1023).

vm_type went from the POST/PUT body into the row unchecked, and the scheduler spliced it
into the PVE path nodes/<node>/<vm_type>/<vmid>/status/<action>, sent with the cluster's
own credentials. The per-VM check does not look at vm_type on the VM-ACL path, so a user
with start/stop on VM 100 alone stored vm_type 'qemu/200/status/stop#' for VM 100 and
the scheduler stopped VM 200 - or anything else under the node it could spell.

Now the request is checked on create and update (action, type, number), every stored
row is checked when the table is read (one that names no guest is switched off, kept so
it can be seen and deleted), and the scheduler checks the row again and only sends when
PVE lists that number with that type. Its node goes into the path quoted.
"""
from unittest.mock import MagicMock

import pytest

import pegaprox.api.schedules as sched
import pegaprox.globals as ppglobals

INJECTED = 'qemu/200/status/stop#'


@pytest.fixture
def cluster(api, seed):
    # the scheduler asks the creator of a row again before it sends (#1093)
    seed.user('sched_owner', role='admin')
    m = api.make_fake_manager(cluster_id='cluster_1')
    m.is_connected = True
    m.host, m.api_port = 'pve.example', 8006
    m.get_vm_resources.return_value = [
        {'vmid': 100, 'node': 'pve1', 'type': 'qemu'},
        {'vmid': 101, 'node': 'pve1', 'type': 'lxc'},
        {'vmid': 200, 'node': 'pve2', 'type': 'qemu'},
    ]
    session = MagicMock()
    m._create_session.return_value = session
    api.set_manager('cluster_1', m)
    return session


def _acl_user(seed):
    """Start/stop on VM 100 and VM 101 through VM ACLs, nothing else on the cluster."""
    seed.tenant('tenant_x', clusters=[])
    u = seed.user('mallory', role='viewer', tenant_id='tenant_x',
                  permissions=['vm.view', 'vm.start', 'vm.stop'])
    seed.vm_acl('cluster_1', 100, ['mallory'])
    seed.vm_acl('cluster_1', 101, ['mallory'])
    return u


def _body(**kw):
    return dict({'cluster_id': 'cluster_1', 'vmid': 100, 'vm_type': 'qemu', 'action': 'stop',
                 'schedule_type': 'daily', 'time': '02:00'}, **kw)


def _rows(db):
    return [dict(r) for r in db.query('SELECT id, vmid, vm_type, action, enabled FROM scheduled_actions')]


def _seed_row(db, sid, vmid=100, vm_type='qemu', action='stop'):
    db.conn.execute(
        "INSERT INTO scheduled_actions (id, cluster_id, vmid, vm_type, action, schedule_type, "
        "schedule_time, enabled, name, created_by, created_at) "
        "VALUES (?, 'cluster_1', ?, ?, ?, 'daily', '02:00', 1, 'n', 'mallory', '2026-01-01')",
        (sid, vmid, vm_type, action))
    db.conn.commit()


def _sent(session):
    return [c.args[0] for c in session.post.call_args_list]


# -- what the API takes ------------------------------------------------------------------

def test_a_path_in_vm_type_is_refused_on_create(api, seed, db, cluster):
    r = api.as_user(_acl_user(seed)).post('/api/schedules', json=_body(vm_type=INJECTED))
    assert _rows(db) == [], 'a schedule with a path in vm_type was stored'
    assert r.status_code == 400, r.get_data(as_text=True)


def test_a_path_in_vm_type_is_refused_on_update(api, seed, db, cluster):
    _seed_row(db, 1)
    r = api.as_user(_acl_user(seed)).put('/api/schedules/1', json={'vm_type': INJECTED})
    assert _rows(db)[0]['vm_type'] == 'qemu', 'the update stored a path in vm_type'
    assert r.status_code == 400, r.get_data(as_text=True)


@pytest.mark.parametrize('vmid', [True, 100.9, ' 100', '1_00', '100/../200', 99, -100])
def test_a_vmid_must_be_a_vm_id(api, seed, db, cluster, vmid):
    root = seed.user('root', role='admin')
    r = api.as_user(root).post('/api/schedules', json=_body(vmid=vmid))
    assert r.status_code == 400, (vmid, r.get_data(as_text=True))
    assert _rows(db) == []


def test_an_edit_of_a_stored_bad_row_has_to_fix_it(api, seed, db, cluster):
    _seed_row(db, 1, vm_type=INJECTED)
    root = seed.user('root', role='admin')
    assert api.as_user(root).put('/api/schedules/1', json={'enabled': True}).status_code == 400
    r = api.as_user(root).put('/api/schedules/1', json={'enabled': True, 'vm_type': 'qemu'})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert _rows(db)[0]['vm_type'] == 'qemu'


def test_the_user_still_schedules_their_guests(api, seed, db, cluster):
    client = api.as_user(_acl_user(seed))
    assert client.post('/api/schedules', json=_body()).status_code == 200
    assert client.post('/api/schedules', json=_body(vmid='101', vm_type='lxc', action='start')).status_code == 200
    assert sorted((r['vmid'], r['vm_type']) for r in _rows(db)) == [(100, 'qemu'), (101, 'lxc')]


def test_a_vmid_sent_as_text_is_stored_as_a_number(api, seed, db, cluster):
    root = api.as_user(seed.user('root', role='admin'))
    assert root.post('/api/schedules', json=_body(vmid='100')).get_json()['schedule']['vmid'] == 100


# -- what is stored already --------------------------------------------------------------

def test_a_stored_row_that_names_no_guest_is_switched_off_on_load(db):
    _seed_row(db, 1, vm_type=INJECTED)
    _seed_row(db, 2, action='rolling_update')
    _seed_row(db, 3)
    rows = {a['id']: a for a in sched.load_schedules()['actions']}
    assert rows[1]['enabled'] is False, 'a stored row with a path in vm_type would still fire'
    assert rows[2]['enabled'] is False
    assert rows[3]['enabled'] is True


def test_a_switched_off_row_is_still_listed_and_deletable(api, seed, db, cluster):
    _seed_row(db, 1, vm_type=INJECTED)
    root = api.as_user(seed.user('root', role='admin'))
    assert [a['id'] for a in root.get('/api/schedules').get_json()] == [1]
    assert root.delete('/api/schedules/1').status_code == 200
    assert _rows(db) == []


# -- what the scheduler sends ------------------------------------------------------------

def _run(action, **kw):
    sched.execute_scheduled_action(dict({'id': 9, 'cluster_id': 'cluster_1', 'vmid': 100,
                                         'vm_type': 'qemu', 'action': action,
                                         'created_by': 'sched_owner'}, **kw))


def test_the_scheduler_does_not_send_a_path_from_the_row(api, cluster):
    _run('stop', vm_type=INJECTED)
    assert not any('/200/' in u for u in _sent(cluster)), _sent(cluster)
    assert _sent(cluster) == []


def test_the_scheduler_sends_only_for_the_guests_real_type(api, cluster):
    _run('stop', vm_type='lxc')
    assert _sent(cluster) == [], 'VM 100 is a qemu guest, the row said lxc'


@pytest.mark.parametrize('action,path', [('start', 'status/start'), ('stop', 'status/stop'),
                                         ('shutdown', 'status/shutdown'),
                                         ('reboot', 'status/reboot'), ('snapshot', 'snapshot')])
def test_each_action_reaches_its_guest(api, cluster, action, path):
    _run(action)
    assert _sent(cluster) == [f'https://pve.example:8006/api2/json/nodes/pve1/qemu/100/{path}']


def test_a_container_is_reached_as_one(api, cluster):
    _run('start', vmid=101, vm_type='lxc')
    assert _sent(cluster) == ['https://pve.example:8006/api2/json/nodes/pve1/lxc/101/status/start']


def test_the_node_goes_into_the_path_quoted(api, cluster):
    ppglobals.cluster_managers['cluster_1'].get_vm_resources.return_value = [
        {'vmid': 100, 'node': 'pve1/../x', 'type': 'qemu'}]
    _run('start')
    assert _sent(cluster) == ['https://pve.example:8006/api2/json/nodes/pve1%2F..%2Fx/qemu/100/status/start']
