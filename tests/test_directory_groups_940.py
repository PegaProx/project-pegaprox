"""Pool grants on a directory group matched nobody, on any version (#940).

The lookups were fixed on Testing to accept a bare group name for a DN membership, but
they were never fed: ldap_authenticate returns the memberships as `groups`, and nothing
copied them into the user row. The users table had no column for them, get_user and
get_all_users built no `groups` key, so `user.get('groups', [])` was [] at every place a
grant is evaluated. With vm.view in the base role the user saw every guest (no pool grant
matched, so nothing confined them); without it they saw none.

What is pinned here, end to end through the real login and the real routes:

  * an LDAP sign-in stores the groups the directory returned, and a pool grant on that
    group then shows exactly the pool's guests and allows exactly the actions it grants;
    a user without the group sees nothing;
  * the base role's vm.view does not widen it, and a confined tenant stays confined;
  * a group the directory dropped stops granting at the next sign-in, and the user's
    older sessions follow, because grants read the stored row on every request;
  * nobody sets their own groups through a profile or user route, and a local account
    never carries any;
  * an OIDC sign-in stores its groups too (Entra by object id, never by display name);
  * a standby refuses a sign-in whose synced row still holds a group the directory
    dropped, when a grant names it;
  * a few hundred groups cost one query per lookup, not one per group, and the users
    read on every request leaves them out;
  * a Keycloak group path matches a grant on its bare name.
"""
import copy
import time

import pytest

import pegaprox.utils.rbac as rbac
from test_ha_api import ha_env  # noqa: F401  (a fixture)

CID = 'cluster_1'
DN = 'CN=PVE-Admins,OU=Groups,DC=corp,DC=local'
OTHER_DN = 'CN=Domain Users,CN=Users,DC=corp,DC=local'
VMS = [
    {'vmid': 100, 'name': 'in-pool-a', 'node': 'pve1', 'type': 'qemu', 'status': 'running'},
    {'vmid': 101, 'name': 'in-pool-b', 'node': 'pve1', 'type': 'qemu', 'status': 'running'},
    {'vmid': 102, 'name': 'no-pool', 'node': 'pve1', 'type': 'lxc', 'status': 'stopped'},
]
RESOURCES = f'/api/clusters/{CID}/resources'


def _start(vmid, vm_type='qemu'):
    return f'/api/clusters/{CID}/vms/pve1/{vm_type}/{vmid}/start'


# --- the stand-ins: the directory, the cluster, the pool membership ----------------------

def _initialised(tmp_path, monkeypatch):
    import pegaprox.utils.auth as authmod
    marker = tmp_path / '.admin_initialized'
    marker.write_text('x')
    monkeypatch.setattr(authmod, 'ADMIN_INITIALIZED_FILE', str(marker))


def _ldap_result(username, groups, role='pool_base', tenant=''):
    return {'success': True, 'username': username, 'email': f'{username}@corp.example',
            'display_name': username.title(), 'role': role, 'tenant': tenant,
            'permissions': [], 'tenant_permissions': {}, 'groups': list(groups),
            'user_dn': f'CN={username},OU=People,DC=corp,DC=local', 'auth_source': 'ldap'}


class _Directory:
    """What the directory answers for each login. Change `people` between sign-ins."""

    def __init__(self, monkeypatch):
        import pegaprox.api.auth as auth_api
        self.people = {}
        monkeypatch.setattr(auth_api, 'get_ldap_settings',
                            lambda: {'enabled': True, 'auto_create_users': True})
        monkeypatch.setattr(auth_api, 'ldap_authenticate', self._bind)

    def _bind(self, username, password):
        if username not in self.people:
            return {'error': 'User not found in LDAP'}
        return copy.deepcopy(self.people[username])


def _sign_in(api, username):
    r = api.anon().post('/api/auth/login',
                        json={'username': username, 'password': 'from-the-directory'})
    assert r.status_code == 200, r.data
    from conftest import _ApiClient
    return _ApiClient(api.app.test_client(), r.get_json()['session_id'])


def _cluster(api):
    m = api.make_fake_manager(CID, get_vm_resources=list(VMS),
                              vm_action={'success': True, 'data': 'UPID:pve1:start:'},
                              get_pools=[{'poolid': 'pool_a'}, {'poolid': 'pool_b'}],
                              get_pool_members={'members': []})
    m.is_connected = True
    api.set_manager(CID, m)
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache[CID] = {
            'data': {'100:qemu': 'pool_a', '101:qemu': 'pool_b'},
            'timestamp': time.time(), 'refreshing': False}
    return m


def _base_role_without_vm_view():
    """The reporter's base role: the cluster and the pools, no guests of its own."""
    from pegaprox.utils.rbac import save_custom_roles
    assert save_custom_roles({'global': {'pool_base': {
        'name': 'Pool base', 'permissions': ['cluster.view', 'pool.view']}}, 'tenants': {}})
    rbac._custom_roles_cache = None


def _grant_on_the_group(api, seed, subject='PVE-Admins', perms=('pool.view', 'vm.start')):
    """The grant as the operator makes it: the admin dialog, the bare group name."""
    admin = seed.user('root', role='admin')
    r = api.as_user(admin).post(f'/api/clusters/{CID}/pools/pool_a/permissions',
                                json={'subject_type': 'group', 'subject_id': subject,
                                      'permissions': list(perms)})
    assert r.status_code == 200, r.data


def _vmids(resp):
    assert resp.status_code == 200, resp.data
    return sorted(v['vmid'] for v in resp.get_json())


@pytest.fixture
def lab(api, seed, tmp_path, monkeypatch):
    _initialised(tmp_path, monkeypatch)
    _base_role_without_vm_view()
    directory = _Directory(monkeypatch)
    mgr = _cluster(api)
    return directory, mgr


# --- the reported case ------------------------------------------------------------------

def test_an_ldap_login_with_the_group_sees_the_pool_and_may_do_what_it_grants(api, seed, lab):
    directory, mgr = lab
    _grant_on_the_group(api, seed)
    directory.people['jdoe'] = _ldap_result('jdoe', [DN, OTHER_DN])
    directory.people['jsmith'] = _ldap_result('jsmith', [OTHER_DN])

    jdoe = _sign_in(api, 'jdoe')
    jsmith = _sign_in(api, 'jsmith')

    assert _vmids(jdoe.get(RESOURCES)) == [100], 'the grant on the group still does nothing'
    assert [p['poolid'] for p in jdoe.get(f'/api/clusters/{CID}/pools').get_json()] == ['pool_a']
    assert jdoe.post(_start(100), json={}).status_code == 200
    assert jdoe.post(_start(101), json={}).status_code == 403
    assert jdoe.post(_start(102, 'lxc'), json={}).status_code == 403
    assert [c.args[1] for c in mgr.vm_action.call_args_list] == [100]

    # the user who is not in the group: nothing to see, nothing to start
    assert _vmids(jsmith.get(RESOURCES)) == []
    assert jsmith.post(_start(100), json={}).status_code == 403


def test_the_groups_are_stored_on_the_account(api, seed, lab, db):
    directory, _ = lab
    directory.people['jdoe'] = _ldap_result('jdoe', [DN, OTHER_DN, DN.lower()])
    _sign_in(api, 'jdoe')
    assert db.get_user_directory_groups('jdoe') == [DN, OTHER_DN]


def test_vm_view_in_the_base_role_does_not_widen_the_pool_user(api, seed, lab):
    """The second half of the report: with vm.view in the base role they saw every guest,
    because no grant matched and so nothing confined them."""
    directory, _ = lab
    _grant_on_the_group(api, seed)
    directory.people['jdoe'] = _ldap_result('jdoe', [DN], role='viewer')
    directory.people['viewer2'] = _ldap_result('viewer2', [OTHER_DN], role='viewer')

    assert _vmids(_sign_in(api, 'jdoe').get(RESOURCES)) == [100]
    # counterproof: a plain viewer of the default tenant without a grant keeps the cluster
    assert _vmids(_sign_in(api, 'viewer2').get(RESOURCES)) == [100, 101, 102]


def test_a_confined_tenant_stays_confined(api, seed, lab):
    """A tenant that does not own the cluster reaches it only through the grant, and only
    the pool's guests: nothing on the cluster beyond them, and nothing without the group."""
    directory, _ = lab
    seed.tenant('acme', ['cluster_home'])
    _grant_on_the_group(api, seed)
    directory.people['jdoe'] = _ldap_result('jdoe', [DN], role='viewer', tenant='acme')
    directory.people['jsmith'] = _ldap_result('jsmith', [OTHER_DN], role='viewer', tenant='acme')

    jdoe = _sign_in(api, 'jdoe')
    assert _vmids(jdoe.get(RESOURCES)) == [100]
    assert jdoe.post(_start(100), json={}).status_code == 200
    assert jdoe.post(_start(102, 'lxc'), json={}).status_code == 403

    jsmith = _sign_in(api, 'jsmith')
    assert jsmith.get(RESOURCES).status_code == 403
    assert jsmith.post(_start(100), json={}).status_code == 403


def test_a_dropped_group_stops_granting_at_the_next_sign_in(api, seed, lab, db):
    """Grants read the stored row on every request. So: until the user signs in again
    nothing has asked the directory and an open session keeps the pool; the next sign-in
    rewrites the row, and from then on every session of that user goes without it,
    the older ones included."""
    directory, _ = lab
    _grant_on_the_group(api, seed)
    directory.people['jdoe'] = _ldap_result('jdoe', [DN, OTHER_DN])
    first = _sign_in(api, 'jdoe')
    assert _vmids(first.get(RESOURCES)) == [100]

    directory.people['jdoe'] = _ldap_result('jdoe', [OTHER_DN])
    assert _vmids(first.get(RESOURCES)) == [100], 'nothing has signed in since'

    second = _sign_in(api, 'jdoe')
    assert db.get_user_directory_groups('jdoe') == [OTHER_DN]
    assert _vmids(second.get(RESOURCES)) == []
    assert _vmids(first.get(RESOURCES)) == []
    assert first.post(_start(100), json={}).status_code == 403


# --- nobody writes their own groups -----------------------------------------------------

def test_no_route_sets_or_inflates_groups(api, seed, lab, db):
    directory, _ = lab
    _grant_on_the_group(api, seed)
    directory.people['jsmith'] = _ldap_result('jsmith', [OTHER_DN])
    jsmith = _sign_in(api, 'jsmith')

    r = jsmith.put('/api/user/preferences', json={'theme': 'nord', 'groups': ['PVE-Admins', DN]})
    assert r.status_code == 200, r.data
    assert db.get_user('jsmith')['theme'] == 'nord'

    # not even an administrator: the user route has no such field
    admin = seed.user('root', role='admin')
    r = api.as_user(admin).put('/api/users/jsmith', json={'display_name': 'J', 'groups': [DN]})
    assert r.status_code == 200, r.data

    assert db.get_user_directory_groups('jsmith') == [OTHER_DN]
    assert _vmids(jsmith.get(RESOURCES)) == []


def test_a_local_account_never_carries_groups(api, seed, lab, db):
    """Not when an admin sends them along, not when the column holds some (a restored
    backup, a hand-edited row): the groups belong to the directory and the IdP."""
    admin = seed.user('root', role='admin')
    r = api.as_user(admin).post('/api/users', json={
        'username': 'localop', 'password': 'C0rrect!horse9-battery', 'role': 'viewer',
        'groups': [DN]})
    assert r.status_code == 200, r.data
    assert db.get_user_directory_groups('localop') == []

    row = db.get_user('localop')
    row['groups'] = [DN]
    db.save_user('localop', row)
    db.conn.execute('UPDATE users SET directory_groups = ? WHERE username = ?',
                    ('["%s"]' % DN, 'localop'))
    db.conn.commit()
    assert db.get_user_directory_groups('localop') == []


def test_the_groups_survive_a_reopen(db):
    """A field without a column lives exactly one process long: the bug class of the
    August revocation fix. Read it back through a new connection."""
    import pegaprox.core.db as dbmod
    db.save_user('jdoe', {'password_salt': '', 'password_hash': '', 'role': 'viewer',
                          'auth_source': 'ldap', 'groups': [DN, OTHER_DN]})
    dbmod._db = None
    dbmod.PegaProxDB._instance = None

    reopened = dbmod.get_db()

    assert reopened.get_user_directory_groups('jdoe') == [DN, OTHER_DN]


def test_a_broken_value_reads_as_no_groups(db):
    """One bad row must not break the pool lookups, nor the users read beside them."""
    db.save_user('jdoe', {'password_salt': '', 'password_hash': '', 'role': 'viewer',
                          'auth_source': 'ldap', 'groups': [DN]})
    db.conn.execute("UPDATE users SET directory_groups = '{not json' WHERE username = 'jdoe'")
    db.conn.commit()
    assert db.get_user_directory_groups('jdoe') == []
    assert 'jdoe' in db.get_all_users()


# --- OIDC ------------------------------------------------------------------------------

OIDC_ON = {
    'enabled': True, 'provider': 'keycloak', 'client_id': 'pegaprox', 'auto_create_users': True,
    'redirect_uri': 'https://pegaprox.example/oidc/callback', 'default_role': 'viewer',
    'admin_group_id': '', 'user_group_id': '', 'viewer_group_id': '', 'group_mappings': [],
}


def _idp(monkeypatch, people):
    import pegaprox.api.auth as auth_api
    monkeypatch.setattr(auth_api, 'get_oidc_settings', lambda: copy.deepcopy(OIDC_ON))
    monkeypatch.setattr(auth_api, 'oidc_exchange_code',
                        lambda cfg, code, code_verifier=None: {'access_token': code, 'id_token': code})
    monkeypatch.setattr(auth_api, 'oidc_decode_id_token',
                        lambda token, expected_nonce=None, config=None: copy.deepcopy(people[token]))
    monkeypatch.setattr(auth_api, 'oidc_get_user_info', lambda cfg, token: {})
    monkeypatch.setattr(auth_api, 'oidc_get_user_groups_ex', lambda cfg, token: ([], False))


def _oidc_sign_in(api, name):
    import pegaprox.api.auth as auth_api
    for key in [k for k in auth_api.login_attempts_by_ip if str(k).startswith('oidc_cb_')]:
        auth_api.login_attempts_by_ip.pop(key, None)
    browser = api.app.test_client()
    browser.set_cookie('oidc_state', 'the-state:the-nonce:the-verifier', domain='localhost')
    r = browser.post('/api/auth/oidc/callback', json={'code': name, 'state': 'the-state'},
                     headers={'X-Requested-With': 'XMLHttpRequest', 'Origin': 'http://localhost'},
                     base_url='http://localhost')
    assert r.status_code == 200, r.data
    from conftest import _ApiClient
    return _ApiClient(api.app.test_client(), r.get_json()['session_id'])


def test_an_oidc_login_stores_its_groups_and_the_grant_matches(api, seed, lab, db, monkeypatch):
    _grant_on_the_group(api, seed, subject='pve-admins')
    _idp(monkeypatch, {
        'kim': {'sub': 'sub-kim', 'preferred_username': 'kim', 'groups': ['pve-admins', '/ops']},
        'lee': {'sub': 'sub-lee', 'preferred_username': 'lee', 'groups': ['/ops']},
    })

    kim = _oidc_sign_in(api, 'kim')
    assert db.get_user_directory_groups('kim') == ['pve-admins', '/ops']
    assert _vmids(kim.get(RESOURCES)) == [100]
    assert _vmids(_oidc_sign_in(api, 'lee').get(RESOURCES)) == [100, 101, 102]   # plain viewer


def test_an_entra_group_is_stored_by_id_never_by_display_name():
    """A display name is what anyone allowed to create a group can claim; the object id
    is not. A pool grant matched on the stored list must not be reachable by naming a new
    group after the one it was made for."""
    from pegaprox.utils.oidc import oidc_map_groups_to_role
    out = oidc_map_groups_to_role({'provider': 'entra', 'default_role': 'viewer'},
                                  [{'id': '0b1c-guid', 'name': 'PVE-Admins'}],
                                  {'groups': ['7d2e-guid']}, groups_complete=True)
    assert out.get('groups') == ['0b1c-guid', '7d2e-guid']


def test_only_a_complete_group_set_takes_groups_away(db):
    """The IdP side follows the permissions there: a complete set replaces, an incomplete
    one (failed Graph call, groups overage) may add but never take away."""
    from pegaprox.utils.oidc import oidc_provision_user
    info = {'sub': 'sub-kim', 'preferred_username': 'kim'}
    oidc_provision_user(info, {'role': 'viewer', 'groups': ['a', 'b'], '_authoritative': True})
    assert db.get_user_directory_groups('kim') == ['a', 'b']

    oidc_provision_user(info, {'role': 'viewer', 'groups': ['c'], '_authoritative': False})
    assert db.get_user_directory_groups('kim') == ['a', 'b', 'c']

    oidc_provision_user(info, {'role': 'viewer', 'groups': ['b'], '_authoritative': True})
    assert db.get_user_directory_groups('kim') == ['b']


# --- a standby --------------------------------------------------------------------------

LUNCH_DN = 'CN=Lunch-List,OU=Distribution,DC=corp,DC=local'


def _ldap_row(db, username, groups):
    db.save_user(username, {'password_salt': '', 'password_hash': '', 'role': 'viewer',
                            'tenant_id': 'default', 'enabled': True, 'auth_source': 'ldap',
                            'groups': list(groups)})
    return db.get_all_users()[username]


def test_a_standby_refuses_a_row_that_still_holds_a_dropped_group(db, seed):
    """A standby writes no users row, so it cannot take the group away itself."""
    from pegaprox.api.auth import _directory_agrees_with_synced_row
    seed.pool(CID, 'pool_a', 'PVE-Admins', ['pool.view'], subject_type='group')
    row = _ldap_row(db, 'jdoe', [DN, OTHER_DN])
    dropped = _ldap_result('jdoe', [OTHER_DN], role='viewer')
    assert _directory_agrees_with_synced_row(dropped, row) is False

    # the same groups in another spelling of case: the same access
    same = _ldap_result('jdoe', [DN.lower(), OTHER_DN], role='viewer')
    assert _directory_agrees_with_synced_row(same, row) is True

    # a row from before the groups were stored grants none here: not a reason to refuse
    older = _ldap_row(db, 'jdoe', [])
    assert _directory_agrees_with_synced_row(same, older) is True


def test_a_standby_does_not_refuse_over_a_group_no_grant_names(db, seed):
    """Nested AD memberships churn - a mail list, an OU move that keeps the CN - without
    changing what any grant reads. Refusing on that kept users out of a standby while the
    active was down, for nothing."""
    from pegaprox.api.auth import _directory_agrees_with_synced_row
    seed.pool(CID, 'pool_a', 'PVE-Admins', ['pool.view'], subject_type='group')
    seed.pool(CID, 'pool_b', 'Lunch-List', [], subject_type='group')     # grants nothing
    row = _ldap_row(db, 'jdoe', [DN, LUNCH_DN, OTHER_DN])

    off_the_list = _ldap_result('jdoe', [DN, OTHER_DN], role='viewer')
    assert _directory_agrees_with_synced_row(off_the_list, row) is True
    moved = _ldap_result('jdoe', [DN.replace('OU=Groups', 'OU=Moved'), LUNCH_DN], role='viewer')
    assert _directory_agrees_with_synced_row(moved, row) is True

    # counterproof: the group a grant names, by its DN as well as by its bare name
    assert _directory_agrees_with_synced_row(
        _ldap_result('jdoe', [LUNCH_DN, OTHER_DN], role='viewer'), row) is False
    seed.pool(CID, 'pool_c', 'CN=Domain Users,CN=Users,DC=corp,DC=local', ['pool.view'],
              subject_type='group')
    assert _directory_agrees_with_synced_row(off_the_list, row) is True
    assert _directory_agrees_with_synced_row(
        _ldap_result('jdoe', [DN, 'CN=Domain Users,OU=Elsewhere,DC=corp,DC=local'],
                     role='viewer'), row) is False


def test_the_standby_sign_in_route_says_so(ha_env, db, seed, tmp_path, monkeypatch):
    from test_ha_api import _standby_of_active
    _initialised(tmp_path, monkeypatch)
    seed.pool(CID, 'pool_a', 'PVE-Admins', ['pool.view'], subject_type='group')
    db.save_user('jdoe', {'password_salt': '', 'password_hash': '', 'role': 'viewer',
                          'tenant_id': 'default', 'enabled': True, 'auth_source': 'ldap',
                          'groups': [DN, OTHER_DN]})
    _standby_of_active(ha_env)
    directory = _Directory(monkeypatch)

    directory.people['jdoe'] = _ldap_result('jdoe', [OTHER_DN], role='viewer')
    r = ha_env.api.anon().post('/api/auth/login', json={'username': 'jdoe', 'password': 'pw'})
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY', r.data
    assert db.get_user_directory_groups('jdoe') == [DN, OTHER_DN]          # nothing written here

    directory.people['jdoe'] = _ldap_result('jdoe', [DN, OTHER_DN], role='viewer')
    r = ha_env.api.anon().post('/api/auth/login', json={'username': 'jdoe', 'password': 'pw'})
    assert r.status_code == 200, r.data


# --- scale ------------------------------------------------------------------------------

def test_hundreds_of_groups_cost_one_query_per_lookup(db, seed):
    """Nested AD memberships easily run to a few hundred groups per user. A query per
    group per lookup was free while `groups` was always empty."""
    seed.pool(CID, 'pool_a', 'PVE-Admins', ['pool.view'], subject_type='group')
    groups = [f'CN=G{i},OU=Groups,DC=corp,DC=local' for i in range(300)] + [DN]
    seen = []
    db.conn.set_trace_callback(lambda sql: seen.append(sql) if 'pool_permissions' in sql else None)
    try:
        perms = db.get_user_pool_permissions(CID, 'jdoe', groups)
        clusters = db.get_user_pool_clusters('jdoe', groups)
    finally:
        db.conn.set_trace_callback(None)

    assert perms == {'pool_a': ['pool.view']} and clusters == [CID]
    assert len(seen) <= 4, f'{len(seen)} queries for 301 groups'


def test_the_per_request_users_read_does_not_carry_the_groups(db, seed):
    """build_authz_user reads the whole users table on every request. Nested AD
    memberships put hundreds of DNs on each directory user; carried in that read, the
    groups of every directory user were fetched and parsed on every request by anyone.
    The lookups read them by username instead, and still find the grant."""
    from pegaprox.utils.auth import load_users, save_users
    seed.pool(CID, 'pool_a', 'PVE-Admins', ['pool.view'], subject_type='group')
    many = [f'CN=Nested-{i:04d},OU=Groups,OU=Corp,DC=corp,DC=local' for i in range(300)]
    for i in range(40):
        _ldap_row(db, f'u{i}', many + [DN])
    payload = 40 * sum(len(g) for g in many)

    fetched = []
    row_factory = db.conn.row_factory

    def _counting(cursor, row):
        fetched.append(sum(len(v) for v in row if isinstance(v, str)))
        return row_factory(cursor, row)

    db.conn.row_factory = _counting
    try:
        users = load_users()
    finally:
        db.conn.row_factory = row_factory
    assert len(users) == 40
    assert sum(fetched) < payload / 20, f'{sum(fetched)} characters read for {payload} of groups'

    # failing closed would be the wrong way round here: the dict has no groups, the grant holds
    user = users['u7']
    assert db.get_user_pool_permissions(CID, 'u7', user.get('groups', [])) == {'pool_a': ['pool.view']}
    assert db.get_user_pool_clusters('u7', user.get('groups', [])) == [CID]

    # and the whole-table write back of a sign-in leaves everybody's groups where they are
    save_users(users)
    assert db.get_user_directory_groups('u3') == many + [DN]


def test_a_keycloak_group_path_matches_a_bare_name_grant(db, seed):
    """Keycloak's group mapper sends full paths by default. The dialog asks for a name."""
    seed.pool(CID, 'pool_a', 'PVE-Admins', ['pool.view'], subject_type='group')
    seed.pool(CID, 'pool_b', '/Org/Ops', ['pool.view'], subject_type='group')
    assert db.get_user_pool_permissions(CID, 'kim', ['/PVE-Admins']) == {'pool_a': ['pool.view']}
    assert db.get_user_pool_permissions(CID, 'kim', ['/Org/pve-admins']) == {'pool_a': ['pool.view']}
    assert db.get_user_pool_clusters('kim', ['/Org/PVE-Admins']) == [CID]
    # a grant written as a path stays exact
    assert db.get_user_pool_permissions(CID, 'kim', ['/Other/Ops']) == {}
    assert db.get_user_pool_permissions(CID, 'kim', ['/org/ops']) == {'pool_b': ['pool.view']}
