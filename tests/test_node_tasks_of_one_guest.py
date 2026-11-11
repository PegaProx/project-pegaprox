"""The tasks of one guest are the tasks of that guest.

GET .../nodes/<node>/tasks?vmid=N kept every task whose UPID contained the digits of N
anywhere. A UPID is UPID:<node>:<pid>:<pstart>:<starttime>:<type>:<id>:<user>: with the
first three in hex, so vmid=10 also took the tasks of guests 100, 101 and 9100, and a
node task (apt update, a backup job of the whole node) whose pid or start time happened to
hold "10". The Tasks tab of a guest showed the history of other guests.

The guest of a task is its id, field 6 of the UPID, the field the log route reads.
"""
import pytest

CID = 'c1'
URL = f'/api/clusters/{CID}/nodes/pve1/tasks'


def _task(kind, guest, pid='0012AB34', start='6731F0A1'):
    return {'upid': f'UPID:pve1:{pid}:0A1B2C3D:{start}:{kind}:{guest}:root@pam:',
            'node': 'pve1', 'type': kind, 'id': guest, 'user': 'root@pam', 'status': 'OK'}


TASKS = [
    _task('qmstart', '10'),
    _task('qmstop', '100'),                        # another guest, id starts with 10
    _task('vzdump', '101'),
    _task('qmigrate', '9100'),                     # another guest, id holds 10
    _task('aptupdate', '', pid='00101010'),        # node task, 10 in the pid
    _task('vzdump', '', start='67310100'),         # node task, 10 in the start time
    _task('qmsnapshot', '10'),
]


@pytest.fixture
def admin(api, seed):
    seed.user('root', role='admin')
    return api.as_user({'username': 'root', 'role': 'admin'})


@pytest.fixture
def pve(api):
    fake = api.make_fake_manager(CID, get_node_tasks=list(TASKS))
    api.set_manager(CID, fake)
    return fake


def test_only_the_tasks_of_that_guest_come_back(admin, pve):
    r = admin.get(URL + '?vmid=10')
    assert r.status_code == 200, r.get_json()
    assert [(t['type'], t['id']) for t in r.get_json()] == [('qmstart', '10'), ('qmsnapshot', '10')]


def test_a_guest_without_tasks_gets_none_of_another(admin, pve):
    # no guest 1 here: every UPID above holds a 1 somewhere
    r = admin.get(URL + '?vmid=1')
    assert r.status_code == 200 and r.get_json() == []


def test_a_task_without_an_id_is_matched_by_its_upid(admin, api):
    """Counterproof for the UPID field: a row that carries no `id` is still found."""
    rows = [{'upid': 'UPID:pve1:0012AB34:0A1B2C3D:6731F0A1:qmstart:10:root@pam:', 'type': 'qmstart'},
            {'upid': 'UPID:pve1:0012AB34:0A1B2C3D:6731F0A1:qmstart:100:root@pam:', 'type': 'qmstart'}]
    api.set_manager(CID, api.make_fake_manager(CID, get_node_tasks=rows))
    r = admin.get(URL + '?vmid=10')
    assert [t['upid'].split(':')[6] for t in r.get_json()] == ['10']


def test_an_xcpng_task_is_matched_by_its_vmid(admin, api):
    """XcpNgManager.get_tasks rows: a short task reference as `upid`, the guest in `vmid`."""
    rows = [{'upid': '3f9a10c2', 'type': 'start_vm', 'vmid': 10, 'status': 'running'},
            {'upid': '7b2e44d1', 'type': 'start_vm', 'vmid': 100, 'status': 'running'},
            {'upid': '10101010', 'type': 'migrate_vm', 'vmid': 7, 'status': 'running'}]
    api.set_manager(CID, api.make_fake_manager(CID, get_node_tasks=rows))
    r = admin.get(URL + '?vmid=10')
    assert r.status_code == 200, r.get_json()
    assert [t['upid'] for t in r.get_json()] == ['3f9a10c2']


def test_without_a_guest_the_whole_list_comes_back(admin, pve):
    r = admin.get(URL)
    assert r.status_code == 200 and len(r.get_json()) == len(TASKS)
