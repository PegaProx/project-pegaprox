"""Start, shut down or migrate every guest of a node in one call.

POST /api/clusters/<cid>/nodes/<node>/guests/<startall|stopall|migrateall> hands the
node endpoints of Proxmox an explicit list of VMIDs: each guest is asked about on its
own, and a guest the caller may not act on is never in that list. The cluster manager
is faked; what it is called with is what Proxmox would get.

MK Oct 2026
"""
import types

import pytest

from test_ha_api import ha_env, _standby_of_active, _active_with_standby  # noqa: F401 (ha_env is a fixture)

UPID = 'UPID:pve1:0000ABCD:0001:6700AAAA:startall::root@pam:'

GUESTS = [
    {'vmid': 100, 'name': 'web', 'node': 'pve1', 'type': 'qemu', 'status': 'running'},
    {'vmid': 101, 'name': 'db', 'node': 'pve1', 'type': 'qemu', 'status': 'stopped'},
    {'vmid': 102, 'name': 'tpl', 'node': 'pve1', 'type': 'qemu', 'status': 'stopped', 'template': 1},
    {'vmid': 200, 'name': 'ct', 'node': 'pve1', 'type': 'lxc', 'status': 'stopped'},
    {'vmid': 201, 'name': 'ct-run', 'node': 'pve1', 'type': 'lxc', 'status': 'running'},
    {'vmid': 300, 'name': 'elsewhere', 'node': 'pve2', 'type': 'qemu', 'status': 'stopped'},
]
NODES = {'pve1': {'status': 'online'}, 'pve2': {'status': 'online'}, 'pve3': {'status': 'offline', 'offline': True}}


def _mgr(api, cluster_id='cluster_1', guests=GUESTS, ok=True):
    result = {'success': True, 'task': UPID} if ok else {'success': False, 'error': '{"message":"no quorum\\n"}'}
    m = api.make_fake_manager(cluster_id=cluster_id, get_vm_resources=list(guests),
                              get_node_status=dict(NODES), node_guests_action=result)
    m.config.name = cluster_id
    return api.set_manager(cluster_id, m)


def _post(client, action, node='pve1', cluster_id='cluster_1', **body):
    return client.post(f'/api/clusters/{cluster_id}/nodes/{node}/guests/{action}', json=body)


def _call(m):
    assert m.node_guests_action.call_count == 1, m.node_guests_action.call_args_list
    args, kw = m.node_guests_action.call_args
    return args, kw


def _audit(seed, action):
    return [tuple(r) for r in seed.db.conn.execute(
        'SELECT user, action, details, cluster FROM audit_log WHERE action = ?', (action,)).fetchall()]


# --- what Proxmox gets ---------------------------------------------------------------------

def test_startall_takes_the_stopped_guests_and_no_template(api, seed):
    m = _mgr(api)
    c = api.as_user(seed.user('root', role='admin'))
    r = _post(c, 'startall')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json() == {'success': True, 'task': UPID, 'vms': [101, 200], 'skipped': []}
    args, kw = _call(m)
    assert args == ('pve1', 'startall', [101, 200])
    assert kw == {'target': None, 'maxworkers': 1, 'with_local_disks': False}
    rows = _audit(seed, 'node.guests_started')
    assert rows == [('root', 'node.guests_started', 'Node pve1: start 2 guest(s) (101, 200) [cluster_1]', 'cluster_1')]


def test_stopall_takes_the_running_guests(api, seed):
    m = _mgr(api)
    c = api.as_user(seed.user('root', role='admin'))
    r = _post(c, 'stopall')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['vms'] == [100, 201]
    assert _call(m)[0] == ('pve1', 'stopall', [100, 201])
    assert len(_audit(seed, 'node.guests_stopped')) == 1


def test_migrateall_takes_every_guest_with_the_options(api, seed):
    m = _mgr(api)
    c = api.as_user(seed.user('root', role='admin'))
    r = _post(c, 'migrateall', target='pve2', maxworkers=3, with_local_disks=True)
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['vms'] == [100, 101, 102, 200, 201]
    args, kw = _call(m)
    assert args == ('pve1', 'migrateall', [100, 101, 102, 200, 201])
    assert kw == {'target': 'pve2', 'maxworkers': 3, 'with_local_disks': True}
    (row,) = _audit(seed, 'node.guests_migrated')
    assert row[2] == 'Node pve1: migrate 5 guest(s) to pve2 (100, 101, 102, 200, 201) [cluster_1]'


def test_a_list_names_the_guests_and_says_which_do_not_fit(api, seed):
    m = _mgr(api)
    c = api.as_user(seed.user('root', role='admin'))
    r = _post(c, 'startall', vms=[101, '100', 102])
    assert r.status_code == 200, r.get_data(as_text=True)
    body = r.get_json()
    assert body['vms'] == [101]
    assert body['skipped'] == [{'vmid': 100, 'reason': 'already running'}, {'vmid': 102, 'reason': 'template'}]
    assert _call(m)[0] == ('pve1', 'startall', [101])


def test_a_guest_of_another_node_is_refused_by_number(api, seed):
    m = _mgr(api)
    c = api.as_user(seed.user('root', role='admin'))
    r = _post(c, 'startall', vms=[101, 300, 999])
    assert r.status_code == 400
    assert r.get_json()['error'] == 'Not on pve1 or out of reach: 300, 999'
    assert m.node_guests_action.call_count == 0


def test_nothing_to_do_is_said_and_nothing_is_sent(api, seed):
    m = _mgr(api, guests=[g for g in GUESTS if g['status'] == 'running'])
    c = api.as_user(seed.user('root', role='admin'))
    r = _post(c, 'startall')
    assert r.status_code == 400
    assert r.get_json()['error'] == 'No guest on pve1 to start'
    assert m.node_guests_action.call_count == 0
    assert _audit(seed, 'node.guests_started') == []


def test_a_refusal_of_proxmox_is_passed_on_without_an_audit_entry(api, seed):
    _mgr(api, ok=False)
    c = api.as_user(seed.user('root', role='admin'))
    r = _post(c, 'stopall')
    assert r.status_code == 500
    assert r.get_json()['error'] == 'no quorum'
    assert _audit(seed, 'node.guests_stopped') == []


@pytest.mark.parametrize('body,error', [
    ({}, 'Target node is required'),
    ({'target': 'pve1'}, 'The target is the node itself'),
    ({'target': '../pve2'}, 'Target node is required'),
    ({'target': 'pve9'}, 'pve9 is no node of this cluster'),
    ({'target': 'pve3'}, 'pve3 is not online'),
    ({'target': 'pve2', 'maxworkers': 0}, 'maxworkers is a number from 1 to 16'),
    ({'target': 'pve2', 'maxworkers': 17}, 'maxworkers is a number from 1 to 16'),
    ({'target': 'pve2', 'maxworkers': True}, 'maxworkers is a number from 1 to 16'),
    ({'target': 'pve2', 'with_local_disks': 'yes'}, 'with_local_disks is true or false'),
])
def test_migrateall_wants_a_target_that_can_take_them(api, seed, body, error):
    m = _mgr(api)
    c = api.as_user(seed.user('root', role='admin'))
    r = _post(c, 'migrateall', **body)
    assert r.status_code == 400
    assert r.get_json()['error'] == error
    assert m.node_guests_action.call_count == 0


@pytest.mark.parametrize('path,body', [
    ('/api/clusters/cluster_1/nodes/pve1/guests/rebootall', {}),
    ('/api/clusters/cluster_1/nodes/pve%201/guests/startall', {}),
    ('/api/clusters/cluster_1/nodes/pve1/guests/startall', {'vms': 'all'}),
    ('/api/clusters/cluster_1/nodes/pve1/guests/startall', {'vms': [True]}),
    ('/api/clusters/cluster_1/nodes/pve1/guests/startall', {'vms': [1.5]}),
    ('/api/clusters/cluster_1/nodes/pve1/guests/startall', {'vms': ['１０１']}),
    ('/api/clusters/cluster_1/nodes/pve1/guests/startall', {'vms': [0]}),
    ('/api/clusters/cluster_1/nodes/pve1/guests/startall', {'vms': list(range(100, 5101))}),
])
def test_a_request_out_of_shape_is_refused(api, seed, path, body):
    m = _mgr(api)
    c = api.as_user(seed.user('root', role='admin'))
    assert c.post(path, json=body).status_code == 400
    assert m.node_guests_action.call_count == 0


def test_a_body_that_is_no_object_is_refused(api, seed):
    m = _mgr(api)
    c = api.as_user(seed.user('root', role='admin'))
    r = c.post('/api/clusters/cluster_1/nodes/pve1/guests/startall', data='[1]',
               headers={'Content-Type': 'application/json'})
    assert r.status_code == 400
    assert m.node_guests_action.call_count == 0


def test_an_xcpng_pool_is_not_asked(api, seed):
    m = api.make_fake_manager(cluster_id='xcp1', cluster_type='xcpng', get_vm_resources=list(GUESTS))
    api.set_manager('xcp1', m)
    c = api.as_user(seed.user('root', role='admin'))
    r = _post(c, 'startall', cluster_id='xcp1')
    assert r.status_code == 400
    assert m.node_guests_action.call_count == 0


def test_an_enforced_affinity_rule_holds_its_guest_back(api, seed, monkeypatch):
    import pegaprox.api.history as history
    m = _mgr(api)
    monkeypatch.setattr(history, 'load_affinity_rules', lambda: {'rules': [
        {'cluster_id': 'cluster_1', 'enabled': True, 'vms': [101], 'type': 'separate'}]})
    seen = []

    def _check(cluster_id, vmid, target):
        seen.append(vmid)
        return {'violation': True, 'enforce': True, 'rule': 'keep-apart', 'message': 'x'}
    monkeypatch.setattr(history, 'check_affinity_violation', _check)
    c = api.as_user(seed.user('root', role='admin'))
    r = _post(c, 'migrateall', target='pve2')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['skipped'] == [{'vmid': 101, 'reason': "affinity rule 'keep-apart'"}]
    assert _call(m)[0] == ('pve1', 'migrateall', [100, 102, 200, 201])
    # only the guest a rule names is looked at
    assert seen == [101]


# --- who may ---------------------------------------------------------------------------------

def test_the_anonymous_caller_gets_nothing(api):
    m = _mgr(api)
    assert _post(api.anon(), 'startall').status_code == 401
    assert m.node_guests_action.call_count == 0


def test_a_viewer_acts_on_nothing(api, seed):
    m = _mgr(api)
    c = api.as_user(seed.user('watcher', role='viewer'))
    for action, body in (('startall', {}), ('stopall', {}), ('migrateall', {'target': 'pve2'})):
        r = _post(c, action, **body)
        assert r.status_code == 403, (action, r.get_data(as_text=True))
    assert m.node_guests_action.call_count == 0


def test_a_user_without_the_permission_of_the_action(api, seed):
    """A user role starts guests; one with vm.start denied does not, and still stops them."""
    m = _mgr(api)
    c = api.as_user(seed.user('ops', role='user', denied=['vm.start']))
    assert _post(c, 'startall').status_code == 403
    assert m.node_guests_action.call_count == 0
    assert _post(c, 'stopall').status_code == 200
    assert _call(m)[0] == ('pve1', 'stopall', [100, 201])


def test_a_vm_acl_user_acts_on_their_own_guests_only(api, seed):
    """The client portal case: the tenant owns the cluster, the user is given two guests.
    Start all on the node starts those two and leaves the rest of the node alone."""
    seed.tenant('acme', clusters=['cluster_1'])
    seed.vm_acl('cluster_1', 101, users=['portal'])
    seed.vm_acl('cluster_1', 100, users=['portal'])
    m = _mgr(api)
    c = api.as_user(seed.user('portal', role='user', tenant_id='acme'))
    r = _post(c, 'startall')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['vms'] == [101]
    assert _call(m)[0] == ('pve1', 'startall', [101])
    m.node_guests_action.reset_mock()
    # a guest outside the grant gets the same answer as one on another node
    r = _post(c, 'startall', vms=[101, 200])
    assert r.status_code == 400
    assert r.get_json()['error'] == 'Not on pve1 or out of reach: 200'
    assert m.node_guests_action.call_count == 0


def test_a_confined_admin_does_not_reach_a_cluster_outside_their_tenant(api, seed):
    """An admin an LDAP tenant mapping lowered where they live, in a tenant that owns
    another cluster."""
    seed.tenant('globex', clusters=['cluster_2'])
    m = _mgr(api)
    other = _mgr(api, cluster_id='cluster_2')
    c = api.as_user(seed.user('gx', role='admin', tenant_id='globex',
                              tenant_permissions={'globex': {'role': 'user'}}))
    for action, body in (('startall', {}), ('stopall', {}), ('migrateall', {'target': 'pve2'})):
        assert _post(c, action, **body).status_code == 403, action
    assert m.node_guests_action.call_count == 0
    # their own cluster they act on, as a user
    assert _post(c, 'stopall', cluster_id='cluster_2').status_code == 200
    assert other.node_guests_action.call_count == 1


def test_another_tenant_does_not_reach_the_cluster(api, seed):
    seed.tenant('acme', clusters=['cluster_1'])
    seed.tenant('initech', clusters=['cluster_2'])
    m = _mgr(api)
    _mgr(api, cluster_id='cluster_2')
    c = api.as_user(seed.user('peter', role='admin', tenant_id='initech',
                              tenant_permissions={'initech': {'role': 'user'}}))
    r = _post(c, 'stopall')
    assert r.status_code == 403
    assert m.node_guests_action.call_count == 0
    c = api.as_user(seed.user('milton', role='user', tenant_id='initech'))
    assert _post(c, 'migrateall', target='pve2').status_code == 403
    assert m.node_guests_action.call_count == 0


def test_a_standby_acts_on_none_of_them(ha_env, seed):  # noqa: F811
    api = ha_env.api
    m = _mgr(api)
    c = api.as_user(seed.user('root', role='admin'))
    _standby_of_active(ha_env)
    for action, body in (('startall', {}), ('stopall', {}), ('migrateall', {'target': 'pve2'})):
        r = _post(c, action, **body)
        assert r.status_code == 409, (action, r.get_data(as_text=True))
        assert r.get_json()['code'] == 'HA_STANDBY'
    assert m.node_guests_action.call_count == 0
    # counterproof: the active it pairs with does
    _active_with_standby(ha_env)
    assert _post(c, 'stopall').status_code == 200
    assert m.node_guests_action.call_count == 1


# --- the manager ---------------------------------------------------------------------------

class _Resp:
    def __init__(self, status=200, data=UPID, text=''):
        self.status_code = status
        self._data = data
        self.text = text

    def json(self):
        return {'data': self._data}


def _real_manager(monkeypatch, resp):
    from pegaprox.core.manager import PegaProxManager
    m = PegaProxManager.__new__(PegaProxManager)
    m.config = types.SimpleNamespace(user='root@pam', host='10.0.0.1', name='c1', api_port=8006)
    m.current_host, m.is_connected = '10.0.0.1', True
    import logging
    m.logger = logging.getLogger('test-node-guests')
    sent = []
    monkeypatch.setattr(m, '_api_post', lambda url, **kw: sent.append((url, kw)) or resp, raising=False)
    return m, sent


def test_the_manager_sends_the_list_and_the_options(monkeypatch):
    m, sent = _real_manager(monkeypatch, _Resp())
    assert m.node_guests_action('pve1', 'startall', [101, 200]) == {'success': True, 'task': UPID}
    assert sent[-1] == ('https://10.0.0.1:8006/api2/json/nodes/pve1/startall',
                        {'data': {'vms': '101,200', 'force': 1}})
    m.node_guests_action('pve1', 'stopall', [100])
    assert sent[-1][1] == {'data': {'vms': '100'}}
    m.node_guests_action('pve1', 'migrateall', [100, 101], target='pve2', maxworkers=2, with_local_disks=True)
    assert sent[-1] == ('https://10.0.0.1:8006/api2/json/nodes/pve1/migrateall',
                        {'data': {'vms': '100,101', 'target': 'pve2', 'maxworkers': 2, 'with-local-disks': 1}})
    m.node_guests_action('pve1', 'migrateall', [100], target='pve2')
    assert 'with-local-disks' not in sent[-1][1]['data']


@pytest.mark.parametrize('args,kw', [
    (('pve1', 'rebootall', [100]), {}),
    (('../x', 'startall', [100]), {}),
    (('pve1', 'startall', []), {}),
    (('pve1', 'migrateall', [100]), {'target': '../pve2'}),
])
def test_the_manager_sends_nothing_out_of_shape(monkeypatch, args, kw):
    m, sent = _real_manager(monkeypatch, _Resp())
    assert m.node_guests_action(*args, **kw)['success'] is False
    assert sent == []


def test_the_manager_hands_back_a_refusal(monkeypatch):
    m, _sent = _real_manager(monkeypatch, _Resp(status=500, text='{"message":"no quorum"}'))
    assert m.node_guests_action('pve1', 'stopall', [100]) == {'success': False, 'error': '{"message":"no quorum"}'}


def test_the_route_is_served_once(api):
    rules = [r for r in api.app.url_map.iter_rules() if r.rule.endswith('/guests/<action>')]
    assert [(r.rule, sorted(r.methods - {'HEAD', 'OPTIONS'})) for r in rules] == [
        ('/api/clusters/<cluster_id>/nodes/<node_name>/guests/<action>', ['POST'])]
