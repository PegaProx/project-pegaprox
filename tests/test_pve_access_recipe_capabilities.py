"""Least privilege: the role recipe and the capability matrix (core/pve_access.py).

GET /api/pve-role-recipe builds the pveum commands for a PegaProx role, account and token
from conncheck.PRIVILEGE_NEEDS. GET /api/clusters/<id>/capabilities says per feature whether
it works with the cluster's connection, from the privileges the last connection check read
and the same questions the refusing code asks (ssh_blocked_reason, ssh_password_for,
pve_root_access, password_login). Asking for the matrix sends nothing to the cluster.

MK Oct 2026
"""
import re

import pytest
import requests

from pegaprox.core import conncheck, pve_access
from pegaprox.core.manager import PegaProxManager
from test_connection_check import ROOT_PERMS, FakeMgr

CID = 'cluster_1'
CAPS = f'/api/clusters/{CID}/capabilities'
RECIPE = '/api/pve-role-recipe'


@pytest.fixture(autouse=True)
def _fresh():
    pve_access.reset_for_tests()
    yield
    pve_access.reset_for_tests()


class Mgr(FakeMgr):
    """The connection check's fake with the manager's own answers to the SSH and root questions."""
    cluster_type = 'proxmox'
    ssh_blocked_reason = PegaProxManager.ssh_blocked_reason
    pve_root_access = PegaProxManager.pve_root_access
    create_privileged_session = PegaProxManager.create_privileged_session
    _ssl_verify = False

    def __init__(self, **kw):
        super().__init__(**kw)
        self.id = CID
        self.config.ssh_disabled = kw.get('ssh_disabled', False)
        self.config.ssh_port = 22
        self.logger = __import__('logging').getLogger('test')


def _token(m, user='ops@pve!pegaprox'):
    m.config.user, m.config.pass_ = user, 'tok-value-1'
    m.config.api_token_user = m.config.api_token_secret = ''
    m._api_token, m._using_api_token = f'{user}=tok-value-1', True
    return m


def _matrix(m, perms=ROOT_PERMS, source='read'):
    m.perms = perms
    item = conncheck.check_privileges(m) if source == 'read' else None
    return {f['id']: f for f in pve_access.capabilities(CID, m, item, source)['features']}


# -- the recipe --------------------------------------------------------------------------------

def test_the_core_role_holds_the_api_features_and_the_optional_ones_add_to_it():
    r = pve_access.recipe([])
    assert r['privileges'] == r['core']['privileges']
    for p in ('Sys.Audit', 'VM.Audit', 'VM.Console', 'VM.Migrate', 'Datastore.Audit', 'SDN.Use', 'Pool.Audit',
              'VM.Snapshot.Rollback', 'VM.Config.HWType'):
        assert p in r['privileges'], p
    for p in ('Sys.Modify', 'Sys.PowerMgmt', 'Sys.Console', 'Mapping.Use', 'VM.Replicate'):
        assert p not in r['privileges'], p
    full = pve_access.recipe(None)
    assert set(full['privileges']) - set(r['privileges']) == {
        p for o in full['optional'] for p in o['privileges']}
    # every privilege the check asks for is in the full role, under the release's name
    wanted = {privs[0] if len(privs) == 1 else 'VM.GuestAgent.Audit' for privs, _p, _f in conncheck.PRIVILEGE_NEEDS}
    assert set(full['privileges']) == wanted
    assert len(full['privileges']) == len(set(full['privileges']))


def test_the_guest_agent_read_has_its_name_per_release():
    assert 'VM.GuestAgent.Audit' in pve_access.recipe([], pve=9)['privileges']
    assert 'VM.Monitor' not in pve_access.recipe([], pve=9)['privileges']
    assert 'VM.Monitor' in pve_access.recipe([], pve=8)['privileges']
    with pytest.raises(ValueError):
        pve_access.recipe([], pve=7)


def test_the_commands_for_the_account_and_the_token():
    r = pve_access.recipe(['sdn'], user='svc@pve', token='pp', role='PPRole')
    privs = ','.join(r['privileges'])
    assert r['commands']['account'] == [
        f'pveum role add PPRole --privs "{privs}"',
        'pveum user add svc@pve --comment "PegaProx"',
        'pveum passwd svc@pve',
        'pveum aclmod / --users svc@pve --roles PPRole']
    tok = r['commands']['token']
    # privilege separation: the user and the token each get the role
    assert 'pveum aclmod / --users svc@pve --roles PPRole' in tok
    assert 'pveum user token add svc@pve pp --privsep 1 --comment "PegaProx"' in tok
    assert tok[-1] == "pveum aclmod / --tokens 'svc@pve!pp' --roles PPRole"
    assert r['token_id'] == 'svc@pve!pp' and r['commands']['update_role'].startswith('pveum role modify PPRole')
    assert {n['need'] for n in r['not_by_role']} == {'ssh', 'root_pam', 'password_login'}


@pytest.mark.parametrize('kw', [
    {'user': 'root'}, {'user': 'a b@pve'}, {'user': 'x@pve;rm -rf /'}, {'user': "o'brien@pve"},
    {'token': '1abc'}, {'token': 'a!b'}, {'token': 'a$(id)'}, {'role': 'PVEAdmin'}, {'role': 'a"b'},
    {'role': ''}, {'user': 'x@pve\n'}, {'token': 'abc\n'}, {'role': 'R\n'}])
def test_nothing_that_could_break_out_of_the_commands_gets_in(kw):
    with pytest.raises(ValueError):
        pve_access.recipe([], **kw)


def test_the_features_parameter():
    assert pve_access.parse_features(None) == list(pve_access.OPTIONAL)
    assert pve_access.parse_features('all') == list(pve_access.OPTIONAL)
    assert pve_access.parse_features('') == []
    assert pve_access.parse_features(' sdn , uploads ') == ['uploads', 'sdn']
    with pytest.raises(ValueError):
        pve_access.parse_features('sdn,godmode')


# -- the matrix --------------------------------------------------------------------------------

def test_root_with_its_password_and_a_key_has_everything(db):
    m = Mgr()
    m.config.ssh_key = 'KEY'
    caps = _matrix(m)
    assert {f: c['status'] for f, c in caps.items() if c['status'] != 'yes'} == {}


def test_a_token_without_ssh_says_what_each_feature_needs(db):
    m = _token(Mgr())
    caps = _matrix(m)
    assert caps['consoles']['status'] == 'yes'
    for f in ('nodeShell', 'rollingUpdates', 'smbios', 'customScripts', 'hardening', 'haAgents', 'transferCheck',
              'fileRestoreCt'):
        assert caps[f]['status'] == 'no' and caps[f]['needs'] == [{'code': 'ssh_no_credentials'}], f
    assert caps['guestTerminal']['needs'] == [{'code': 'token_login'}]
    assert caps['crossCluster']['needs'] == [{'code': 'token_login'}]
    assert caps['rawDevices']['needs'] == [{'code': 'root_token'}] == caps['cephOsd']['needs']
    assert caps['esxiMigration']['needs'] == [{'code': 'ssh_password', 'key': False}]
    # a key: the SSH features come back, the password-only path does not
    m.config.ssh_key = 'KEY'
    caps = _matrix(m)
    assert caps['nodeShell']['status'] == 'yes' and caps['esxiMigration']['status'] == 'no'
    assert caps['esxiMigration']['needs'] == [{'code': 'ssh_password', 'key': True}]


def test_ssh_switched_off_closes_every_ssh_feature_and_the_node_credentials(db):
    m = Mgr(ssh_disabled=True)
    m.config.ssh_key = 'KEY'
    caps = _matrix(m)
    for f in ('nodeShell', 'hardening', 'nodeCredentials', 'esxiMigration', 'fileRestoreCt'):
        assert caps[f]['status'] == 'no' and {'code': 'ssh_disabled'} in caps[f]['needs'], f
    assert caps['fileRestoreVm']['status'] == 'yes'


def test_node_passwords_make_a_token_cluster_partly_reachable(db, monkeypatch):
    from pegaprox.core import node_creds
    m = _token(Mgr())
    monkeypatch.setattr(node_creds, 'secrets_of', lambda cid: {'pve2': 'x', 'pve1': 'y'} if cid == CID else {})
    caps = _matrix(m)
    assert caps['nodeShell']['status'] == 'partial'
    assert caps['nodeShell']['needs'] == [{'code': 'ssh_some_nodes', 'nodes': ['pve1', 'pve2']}]
    assert caps['esxiMigration']['status'] == 'partial'


def test_another_user_or_no_password_has_no_root_only_changes(db):
    m = Mgr()
    m.config.user = 'ops@pam'
    assert _matrix(m)['rawDevices']['needs'] == [{'code': 'root_only'}]
    m = Mgr()
    m.config.pass_ = ''
    caps = _matrix(m)
    assert caps['rawDevices']['needs'] == [{'code': 'root_password'}]
    assert caps['guestTerminal']['needs'] == [{'code': 'no_password'}]


def test_missing_privileges_turn_their_features_off_and_a_pool_grant_is_partial(db):
    perms = {'/': {'Sys.Audit': 1, 'Sys.Modify': 1}, '/vms': {'VM.Audit': 1, 'VM.Backup': 1},
             '/vms/100': {'VM.Console': 1}, '/storage': {'Datastore.AllocateSpace': 1}}
    caps = _matrix(Mgr(), perms)
    assert caps['consoles']['status'] == 'partial'
    assert caps['consoles']['needs'] == [{'code': 'priv', 'privs': ['VM.Console'], 'path': '/vms', 'partial': True}]
    assert caps['rollingUpdates']['status'] == 'no'
    assert {'code': 'priv', 'privs': ['VM.Migrate'], 'path': '/vms', 'partial': False} in caps['rollingUpdates']['needs']
    assert caps['backups']['status'] == 'yes'
    assert caps['mappings']['status'] == 'no' and len(caps['mappings']['needs']) == 2


def test_unknown_privileges_say_so(db):
    m = Mgr()
    m.config.ssh_key = 'KEY'
    caps = _matrix(m, source='not_checked')
    assert caps['consoles']['status'] == 'unknown' and caps['consoles']['needs'] == [{'code': 'not_checked'}]
    # what needs no privilege is answered all the same
    assert caps['nodeShell']['status'] == 'yes'
    # a hard no wins over an unknown
    caps = _matrix(_token(Mgr()), source='not_connected')
    assert caps['rollingUpdates']['status'] == 'no'
    assert caps['backups']['needs'] == [{'code': 'not_connected'}]


# -- one source of truth: the matrix and the places that refuse agree -------------------------

@pytest.mark.parametrize('setup', ['token', 'other_user', 'no_password', 'root_password', 'root_minted'])
def test_the_ceph_osd_session_refuses_exactly_where_the_matrix_says_no(db, monkeypatch, setup):
    m = Mgr()
    if setup == 'token':
        _token(m)
    elif setup == 'other_user':
        m.config.user = 'ops@pam'
    elif setup == 'no_password':
        m.config.pass_ = ''
    elif setup == 'root_password':
        m._api_token, m._using_api_token = None, False

    class _R:
        status_code = 200

        @staticmethod
        def json():
            return {'data': {'ticket': 'PVE:t', 'CSRFPreventionToken': 'c'}}
    monkeypatch.setattr(requests.Session, 'post', lambda self, *a, **k: _R())
    session, why = m.create_privileged_session()
    status = _matrix(m)['cephOsd']['status']
    assert (session is not None) == (status == 'yes'), (setup, why, status)


@pytest.mark.parametrize('user,stored', [('root@pam', 'pw1'), ('ops@pve!tok', 'tv1'), ('root@pam', '')])
def test_the_guest_terminal_route_refuses_where_the_matrix_says_no(api, seed, monkeypatch, user, stored):
    import urllib.request

    def no_network(*a, **k):
        raise OSError('no PVE here')
    monkeypatch.setattr(urllib.request, 'urlopen', no_network)
    m = Mgr()
    m.auth_host = m.host
    m.config.user, m.config.pass_ = user, stored
    api.set_manager(CID, m)
    r = api.as_user(seed.user('root', role='admin')).post(f'/api/clusters/{CID}/vms/pve1/qemu/100/termproxy')
    refused = r.status_code == 400 and 'termproxy needs user/pass' in r.get_data(as_text=True)
    assert refused == (_matrix(m)['guestTerminal']['status'] == 'no'), (user, r.status_code)


# -- the privileges kept per cluster --------------------------------------------------------------

def test_asking_sends_nothing_and_a_refresh_reads_once():
    m = Mgr()
    assert pve_access.privileges(CID, m) == (None, 'not_checked')
    assert m.api_calls == []
    item, source = pve_access.privileges(CID, m, refresh=True)
    assert source == 'read' and item['missing'] == [] and m.api_calls == ['/access/permissions']
    item, source = pve_access.privileges(CID, m)
    assert source == 'kept' and m.api_calls == ['/access/permissions']
    # another login: what was kept belongs to the old one
    m.config.user = 'ops@pve'
    assert pve_access.privileges(CID, m) == (None, 'not_checked')
    # too old
    m.config.user = 'root@pam'
    pve_access.privileges(CID, m, refresh=True)
    assert pve_access.privileges(CID, m, now=__import__('time').time() + pve_access.PRIV_FRESH + 1)[1] == 'not_checked'


def test_a_refresh_of_a_cluster_that_is_down_or_refuses():
    m = Mgr()
    m.is_connected = False
    assert pve_access.privileges(CID, m, refresh=True) == (None, 'not_connected')
    m.is_connected = True

    def refuse(url, **kw):
        return type('R', (), {'status_code': 403, 'json': lambda self: {}})()
    m._api_get = refuse
    assert pve_access.privileges(CID, m, refresh=True) == (None, 'unreadable')


# -- the routes --------------------------------------------------------------------------------

def _fake(api, cid=CID, **kw):
    m = Mgr(**kw)
    m.id = cid
    m.config.name = cid
    return api.set_manager(cid, m)


def test_the_connection_check_keeps_its_privileges_for_the_matrix(api, seed, monkeypatch):
    m = _fake(api)
    m.perms = {'/': {'Sys.Audit': 1}}
    admin = api.as_user(seed.user('root', role='admin'))
    before = admin.get(CAPS).get_json()
    assert before['privileges']['state'] == 'not_checked' and m.api_calls == []
    assert before['connected'] is True and before['login']['type'] == 'minted_token'
    monkeypatch.setattr(conncheck, 'check_ssh', lambda mgr, nodes: [])
    r = admin.post(f'/api/clusters/{CID}/connection-check', json={'ssh': False})
    assert r.status_code == 200, r.data
    calls = len(m.api_calls)
    after = admin.get(CAPS).get_json()
    assert after['privileges']['state'] == 'read' and after['privileges']['checked_at']
    assert len(m.api_calls) == calls, 'the matrix asked the cluster again'
    caps = {f['id']: f for f in after['features']}
    assert caps['consoles']['status'] == 'no'
    # ?refresh=1 reads once more
    m.perms = ROOT_PERMS
    caps = {f['id']: f for f in admin.get(CAPS + '?refresh=1').get_json()['features']}
    assert caps['consoles']['status'] == 'yes' and len(m.api_calls) == calls + 1


def test_the_matrix_never_names_a_secret(api, seed):
    m = _token(_fake(api))
    m.config.ssh_key = 'KEY-MATERIAL-XYZ'
    body = api.as_user(seed.user('root', role='admin')).get(CAPS).get_data(as_text=True)
    assert 'tok-value-1' not in body and 'KEY-MATERIAL-XYZ' not in body
    login = api.as_user(seed.user('root', role='admin')).get(CAPS).get_json()['login']
    assert login == {'type': 'api_token', 'user': 'ops@pve', 'token_id': 'ops@pve!pegaprox', 'realm': 'pve',
                     'root': False, 'has_password': False, 'ssh_key': True, 'ssh_disabled': False,
                     'node_passwords': 0}


def test_bad_input_and_xcpng(api, seed):
    _fake(api)
    admin = api.as_user(seed.user('root', role='admin'))
    assert admin.get(CAPS + '?refresh=yes').status_code == 400
    assert admin.get('/api/clusters/ghost/capabilities').status_code == 404
    api.set_manager('x1', api.make_fake_manager(cluster_id='x1', cluster_type='xcpng'))
    r = admin.get('/api/clusters/x1/capabilities')
    assert r.status_code == 400 and r.get_json()['code'] == 'PVE_ONLY'


@pytest.mark.parametrize('kind', ['user', 'viewer', 'capped_admin', 'other_tenant', 'pool_scoped'])
def test_who_may_not_read_the_matrix(api, seed, kind):
    m = _fake(api)
    if kind == 'user':
        caller = seed.user('joe', role='user')
    elif kind == 'viewer':
        caller = seed.user('watcher', role='viewer')
    elif kind == 'capped_admin':
        seed.tenant('globex', ['cluster_globex'])
        caller = seed.user('gx', role='admin', tenant_id='globex', tenant_permissions={'globex': {'role': 'user'}})
    elif kind == 'other_tenant':
        seed.tenant('acme', ['cluster_acme'])
        caller = seed.user('acmeops', role='user', tenant_id='acme', permissions=['cluster.config'])
    else:
        seed.tenant('acme', ['cluster_acme'])
        caller = seed.user('poolops', role='user', tenant_id='acme', permissions=['cluster.config'])
        seed.pool(CID, 'pool1', 'poolops', ['vm.view'])
    r = api.as_user(caller).get(CAPS)
    assert r.status_code == 403, (kind, r.data)
    if kind == 'pool_scoped':
        assert b'whole cluster' in r.data, r.data
    assert m.api_calls == []


def test_the_other_tenant_reads_its_own_cluster(api, seed):
    seed.tenant('acme', ['cluster_acme'])
    caller = seed.user('acmeops', role='user', tenant_id='acme', permissions=['cluster.config'])
    _fake(api, cid='cluster_acme')
    assert api.as_user(caller).get('/api/clusters/cluster_acme/capabilities').status_code == 200


def test_a_standby_shows_the_matrix_and_changes_nothing(api, seed, monkeypatch):
    from pegaprox.core import ha
    monkeypatch.setattr(ha, 'is_standby', lambda: True)
    monkeypatch.setattr(ha, 'forwarding', lambda: False)
    monkeypatch.setattr(ha, 'forward_writes', lambda: False)
    m = _fake(api)
    r = api.as_user(seed.user('root', role='admin')).get(CAPS)
    assert r.status_code == 200 and m.api_calls == [] and m.ssh_calls == []


def test_the_recipe_route(api, seed):
    admin = api.as_user(seed.user('root', role='admin'))
    r = admin.get(RECIPE)
    assert r.status_code == 200 and r.get_json()['privileges'] == pve_access.recipe(None)['privileges']
    r = admin.get(RECIPE + '?features=&pve=8&user=svc@pve&token=pp&role=PP')
    body = r.get_json()
    assert body['privileges'] == pve_access.recipe([], pve=8)['privileges'] and body['token_id'] == 'svc@pve!pp'
    for q in ('?features=godmode', '?pve=10', '?user=x', "?token=a'b", '?role=PVEAdmin'):
        assert admin.get(RECIPE + q).status_code == 400, q


@pytest.mark.parametrize('kind,status', [('viewer', 403), ('user', 403), ('cluster_config', 200),
                                         ('cluster_add', 200), ('capped_admin', 200)])
def test_who_may_read_the_recipe(api, seed, kind, status):
    if kind == 'viewer':
        caller = seed.user('watcher', role='viewer')
    elif kind == 'user':
        caller = seed.user('joe', role='user')
    elif kind == 'cluster_config':
        caller = seed.user('cfg', role='user', permissions=['cluster.config'])
    elif kind == 'cluster_add':
        caller = seed.user('adder', role='user', permissions=['cluster.add'])
    else:
        # the recipe names no cluster: a confined admin gets it like anyone who sets clusters up
        seed.tenant('globex', ['cluster_globex'])
        caller = seed.user('gx', role='admin', tenant_id='globex')
    r = api.as_user(caller).get(RECIPE)
    assert r.status_code == status, (kind, r.data)


def test_the_recipe_is_served_on_a_standby(api, seed, monkeypatch):
    from pegaprox.core import ha
    monkeypatch.setattr(ha, 'is_standby', lambda: True)
    monkeypatch.setattr(ha, 'forwarding', lambda: False)
    assert api.as_user(seed.user('root', role='admin')).get(RECIPE).status_code == 200


def test_the_docs_page_shows_the_role_the_recipe_builds():
    import os
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, 'docs', 'proxmox-permissions.md'), encoding='utf-8') as fh:
        doc = fh.read()
    full = pve_access.recipe(None)
    for line in full['commands']['token']:
        assert line in doc, line
    for p in full['privileges']:
        assert f'`{p}`' in doc, p
    assert '\u2014' not in doc and '\u2013' not in doc


def test_the_routes_are_in_the_openapi_description():
    import json
    import os
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, 'docs', 'openapi.json'), encoding='utf-8') as fh:
        paths = json.load(fh)['paths']
    assert '/api/pve-role-recipe' in paths
    assert any(re.fullmatch(r'/api/clusters/\{[a-z_]+\}/capabilities', p) for p in paths)
