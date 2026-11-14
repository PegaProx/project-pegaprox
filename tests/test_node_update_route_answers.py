"""POST /api/clusters/<id>/nodes/<node>/update says what went wrong in English, with a code.

The route refused a node outside maintenance mode with the German
sentence "Node X ist nicht im Wartungsmodus.", and the toast showed it in every UI
language; the UIs found the case by looking for the German word. Its other answers were
German or had no code either. Each refusal now carries a code the UI translates and an
English sentence for the log. And reboot / force are read as booleans: the string "false"
was truthy, so {"reboot": "false"} rebooted the node and {"force": "false"} skipped the
maintenance check. A missing reboot stays a reboot, as API clients know it.

MK Nov 2026
"""
import pytest

CID = 'cluster_1'
URL = f'/api/clusters/{CID}/nodes/n1/update'
GERMAN = ('Wartungsmodus', 'nicht', 'konnte', 'verfuegbar', 'Bitte')


class _Task:
    def __init__(self, status):
        self.status = status


@pytest.fixture
def admin(api, seed):
    return api.as_user(seed.user('root_admin', role='admin'))


@pytest.fixture
def mgr(api):
    m = api.make_fake_manager(CID)
    m.is_connected = True
    m.config.name = CID
    m.nodes_in_maintenance = {}
    m.start_node_update.return_value = None
    return api.set_manager(CID, m)


def _english(body):
    assert not any(w in body['error'] for w in GERMAN), body['error']


def test_a_node_outside_maintenance_is_refused_with_a_code(admin, mgr):
    r = admin.post(URL, json={'reboot': False})
    body = r.get_json()
    assert (r.status_code, body['code'], body['node']) == (400, 'NOT_IN_MAINTENANCE', 'n1')
    assert body['error'] == 'Node n1 is not in maintenance mode'
    assert not mgr.start_node_update.called


def test_an_evacuation_that_runs_is_refused_with_a_code(admin, mgr):
    mgr.nodes_in_maintenance = {'n1': _Task('running')}
    r = admin.post(URL, json={'reboot': False})
    body = r.get_json()
    assert (r.status_code, body['code']) == (400, 'EVACUATION_RUNNING')
    _english(body)


def test_an_update_that_did_not_start_says_so(admin, mgr):
    mgr.nodes_in_maintenance = {'n1': _Task('completed')}
    r = admin.post(URL, json={'reboot': False})
    body = r.get_json()
    assert (r.status_code, body['code']) == (500, 'UPDATE_NOT_STARTED')
    _english(body)


def test_no_ssh_library_says_so_in_english(admin, mgr, monkeypatch):
    import pegaprox.api.vms as vms
    monkeypatch.setattr(vms, 'get_paramiko', lambda: None)
    r = admin.post(URL, json={'reboot': False})
    body = r.get_json()
    assert (r.status_code, body['code']) == (500, 'SSH_UNAVAILABLE')
    _english(body)


@pytest.mark.parametrize('value,want', [('false', False), ('0', False), (0, False), (False, False),
                                        ('true', True), (1, True), (True, True)])
def test_reboot_is_read_as_a_boolean(admin, mgr, value, want):
    mgr.nodes_in_maintenance = {'n1': _Task('completed')}
    admin.post(URL, json={'reboot': value})
    assert mgr.start_node_update.call_args.args[1] is want


def test_a_missing_reboot_is_still_a_reboot(admin, mgr):
    mgr.nodes_in_maintenance = {'n1': _Task('completed')}
    admin.post(URL, json={})
    assert mgr.start_node_update.call_args.args[1] is True


def test_force_false_as_a_string_keeps_the_maintenance_check(admin, mgr):
    r = admin.post(URL, json={'reboot': False, 'force': 'false'})
    assert (r.status_code, r.get_json()['code']) == (400, 'NOT_IN_MAINTENANCE')
    assert not mgr.start_node_update.called
    # counter-check: a real force goes past it
    admin.post(URL, json={'reboot': False, 'force': True})
    assert mgr.start_node_update.call_args.args == ('n1', False, True)


@pytest.mark.parametrize('field,value', [('reboot', 'maybe'), ('reboot', None), ('force', 'yes please'),
                                         ('force', [True])])
def test_anything_else_is_refused_before_it_starts(admin, mgr, field, value):
    mgr.nodes_in_maintenance = {'n1': _Task('completed')}
    r = admin.post(URL, json={'reboot': False, field: value})
    body = r.get_json()
    assert (r.status_code, body['code'], body['field']) == (400, 'INVALID_FIELD', field)
    assert not mgr.start_node_update.called


def test_the_reboot_permission_refusal_has_a_code(api, seed, mgr):
    seed.tenant('acme', clusters=[CID])
    u = seed.user('patcher', role='user', tenant_id='acme', permissions=['node.update', 'cluster.view'])
    r = api.as_user(u).post(URL, json={'reboot': True})
    body = r.get_json()
    assert (r.status_code, body['code'], body['required']) == (403, 'MISSING_PERMISSION', 'node.reboot')
    assert not mgr.start_node_update.called
