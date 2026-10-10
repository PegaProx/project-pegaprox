"""The node task-log gate must confine without narrowing a plain operator.

The UPID names a guest in PVE field 6, and the cancel sibling has always gated on
it — so a confined caller reading another guest's task log was the gap. The risk
in closing it is the other direction: a node-level task (imgdel, srvstart) has no
guest to resolve, and denying those for everyone would take the whole task view
away from ordinary operators.

Found while diffing route reachability against v1.1.0: the confined identities
lost this route, so it needed checking that the unconfined ones did not. MK
"""
import pytest


CL, MINE, THEIRS = 'cluster_1', 100, 200


def _upid(worker_id, worker_type='qmstart'):
    return f'UPID:pve1:0000A1B2:00003C4D:68AB1F00:{worker_type}:{worker_id}:root@pam:'


@pytest.fixture
def mgr(api):
    m = api.make_fake_manager(CL)
    m.is_connected = True
    m.get_node_task_log.return_value = ['line one', 'line two']
    api.set_manager(CL, m)
    return m


@pytest.fixture
def acled(api, seed):
    seed.tenant('t', ['cluster_1'])
    u = seed.user('acl_user', role='user', tenant_id='t', permissions=['node.view', 'vm.view'])
    seed.vm_acl(CL, MINE, ['acl_user'], permissions=['vm.view'])
    return api.as_user(u)


@pytest.fixture
def operator(api, seed):
    """Tenant owns the cluster, no pool grant, no ACL — not confined."""
    seed.tenant('t', ['cluster_1'])
    return api.as_user(seed.user('op', role='user', tenant_id='t',
                                 permissions=['node.view', 'vm.view']))


def _log(client, upid):
    return client.get(f'/api/clusters/{CL}/nodes/pve1/tasks/{upid}/log')


def test_a_confined_caller_reads_their_own_guests_task_log(acled, mgr):
    r = _log(acled, _upid(MINE))

    assert r.status_code == 200, r.get_data(as_text=True)[:200]


def test_a_confined_caller_is_denied_a_foreign_guests_task_log(acled, mgr):
    assert _log(acled, _upid(THEIRS)).status_code == 403


def test_a_confined_caller_is_denied_a_node_level_task_log(acled, mgr):
    """No guest in the UPID, so nothing can answer for it — fail closed."""
    assert _log(acled, _upid('local-lvm', 'imgdel')).status_code == 403


def test_an_unconfined_operator_keeps_node_level_task_logs(operator, mgr):
    """The direction that matters: confining the gate must not take infrastructure
    task logs away from an ordinary operator."""
    r = _log(operator, _upid('local-lvm', 'imgdel'))

    assert r.status_code == 200, f'over-restricted: {r.get_data(as_text=True)[:200]}'


def test_an_unconfined_operator_keeps_any_guests_task_log(operator, mgr):
    assert _log(operator, _upid(THEIRS)).status_code == 200


# --- the status next to the log -----------------------------------------------------------------

def _status(client, upid):
    return client.get(f'/api/clusters/{CL}/nodes/pve1/tasks/{upid}/status')


def test_the_log_comes_as_lines_too(acled, mgr):
    r = _log(acled, _upid(MINE))

    assert r.get_json() == {'log': 'line one\nline two', 'lines': ['line one', 'line two']}


def test_the_status_route_answers_what_proxmox_says(operator, mgr):
    mgr.get_task_status.return_value = {'status': 'stopped', 'exitstatus': 'OK', 'type': 'vzdump',
                                        'user': 'root@pam'}
    r = _status(operator, _upid(THEIRS, 'vzdump'))

    assert r.status_code == 200
    assert r.get_json() == {'status': 'stopped', 'exitstatus': 'OK', 'type': 'vzdump'}
    assert mgr.get_task_status.call_args[0] == ('pve1', _upid(THEIRS, 'vzdump'))


def test_the_status_of_a_task_is_confined_like_its_log(acled, mgr):
    mgr.get_task_status.return_value = {'status': 'running'}

    assert _status(acled, _upid(MINE, 'vzdump')).status_code == 200
    assert _status(acled, _upid(THEIRS, 'vzdump')).status_code == 403
    assert _status(acled, _upid('', 'vzdump')).status_code == 403


def test_an_unreadable_status_is_no_server_error(operator, mgr):
    mgr.get_task_status.return_value = None

    assert _status(operator, _upid(MINE)).status_code == 502
