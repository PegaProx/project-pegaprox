"""Favorites: the star next to a global search result.

The route never stored anything. load_favorites() handed back a flat list of VM rows
per user, the route worked on three lists (vms/nodes/clusters), and save_favorites()
walked that dict's keys as if they were rows ("'str' object has no attribute 'get'",
logged, nothing written) - after a DELETE of every user's rows that stayed pending
on the connection until the next commit. Now one row per favorite with its kind,
written per user, and the three lists the dashboard reads.

Every round trip here goes through a new database connection: what only lived in
the process would pass otherwise.

MK Oct 2026
"""
import time

import pytest

import pegaprox.utils.rbac as rbac
from pegaprox.api import search
from pegaprox.core import ha

from test_ha_core import env, _be_active, _be_standby, _wire  # noqa: F401 (env is a fixture)

# the table as it was before the kinds, rows of VMs only
OLD_TABLE = '''
    CREATE TABLE user_favorites (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        cluster_id TEXT,
        vmid INTEGER,
        vm_type TEXT,
        vm_name TEXT,
        added_at TEXT
    )
'''

VMS = [
    {'vmid': 100, 'name': 'pp-web', 'node': 'pve1', 'type': 'qemu', 'status': 'running'},
    {'vmid': 101, 'name': 'pp-secret', 'node': 'pve1', 'type': 'qemu', 'status': 'running'},
    {'vmid': 200, 'name': 'pp-ct', 'node': 'pve2', 'type': 'lxc', 'status': 'stopped'},
]


def _fake_mgr(api, cluster_id='cluster_1', vms=VMS):
    m = api.make_fake_manager(cluster_id=cluster_id, get_vm_resources=list(vms))
    m.is_connected = True
    m.config.name = cluster_id
    m.nodes = {'pve1': {'status': 'online'}, 'pve2': {'status': 'online'}}
    return api.set_manager(cluster_id, m)


def _reopen():
    """A new connection to the same file, as after a restart: what only lived in the
    process is gone, and so is a transaction nobody committed."""
    import pegaprox.core.db as dbmod
    old = getattr(getattr(dbmod._db, '_local', None), 'conn', None)
    if old is not None:
        old.close()
    dbmod._db = None
    dbmod.PegaProxDB._instance = None
    return dbmod.get_db()


def _post(client, **body):
    return client.post('/api/user/favorites', json=body)


def _add_vm(client, vmid, cluster_id='cluster_1', **more):
    return _post(client, action='add', type='vm', cluster_id=cluster_id, vmid=vmid, **more)


def _get(client):
    r = client.get('/api/user/favorites')
    assert r.status_code == 200, r.get_data(as_text=True)
    return r.get_json()


def _vm_keys(favs):
    return sorted((f['cluster_id'], f['vmid']) for f in favs['vms'])


def _insert(username, kind='vm', cluster_id='cluster_1', vmid=None, node='', name=None, vm_type=None):
    db = _db_now()
    db.conn.execute('INSERT INTO user_favorites (username, kind, cluster_id, vmid, vm_type, vm_name, node, '
                    'added_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                    (username, kind, cluster_id, vmid, vm_type, name, node, '2026-10-01T00:00:00'))
    db.conn.commit()


def _db_now():
    import pegaprox.core.db as dbmod
    return dbmod.get_db()


def _rows(username=None):
    sql = 'SELECT username, kind, cluster_id, vmid, vm_type, vm_name, node FROM user_favorites'
    args = ()
    if username:
        sql += ' WHERE username = ?'
        args = (username,)
    return sorted(tuple(r) for r in _db_now().conn.execute(sql + ' ORDER BY id', args).fetchall())


# --- the bug, and the round trip of every kind ----------------------------------------------

def test_a_favorite_survives_a_new_connection(api, seed):
    """Red before the fix: the add answered 200 and stored nothing."""
    admin = seed.user('root', role='admin')
    _fake_mgr(api)
    c = api.as_user(admin)
    r = _add_vm(c, 100, vm_type='qemu')
    assert r.status_code == 200, r.get_data(as_text=True)
    _reopen()
    assert _vm_keys(_get(c)) == [('cluster_1', 100)]


def test_every_kind_round_trips_and_goes_again(api, seed):
    admin = seed.user('root', role='admin')
    _fake_mgr(api)
    c = api.as_user(admin)
    # what the dashboard sends for a VM row, a container row and a node row of the search,
    # and a cluster
    assert _post(c, action='add', type='vm', cluster_id='cluster_1', vmid=100, vm_type='qemu').status_code == 200
    assert _post(c, action='add', type='ct', cluster_id='cluster_1', vmid=200, vm_type='lxc').status_code == 200
    assert _post(c, action='add', type='node', cluster_id='cluster_1', node='pve1', vm_type='lxc').status_code == 200
    r = _post(c, action='add', type='cluster', cluster_id='cluster_1')
    assert r.status_code == 200
    expected = {
        'vms': [{'cluster_id': 'cluster_1', 'vmid': 100, 'type': 'qemu', 'name': 'pp-web'},
                {'cluster_id': 'cluster_1', 'vmid': 200, 'type': 'lxc', 'name': 'pp-ct'}],
        'nodes': [{'cluster_id': 'cluster_1', 'node': 'pve1'}],
        'clusters': ['cluster_1'],
    }
    # the answer of the write is what the dashboard sets its state to
    assert r.get_json() == {'success': True, 'favorites': expected}

    _reopen()
    assert _get(c) == expected
    assert _rows('root') == [
        ('root', 'cluster', 'cluster_1', None, None, None, ''),
        ('root', 'node', 'cluster_1', None, None, None, 'pve1'),
        ('root', 'vm', 'cluster_1', 100, 'qemu', 'pp-web', ''),
        ('root', 'vm', 'cluster_1', 200, 'lxc', 'pp-ct', ''),
    ]

    for body in ({'type': 'vm', 'vmid': 100}, {'type': 'ct', 'vmid': 200},
                 {'type': 'node', 'node': 'pve1'}, {'type': 'cluster'}):
        r = _post(c, action='remove', cluster_id='cluster_1', **body)
        assert r.status_code == 200, (body, r.get_data(as_text=True))
    _reopen()
    assert _get(c) == {'vms': [], 'nodes': [], 'clusters': []}
    assert _rows() == []


def test_the_answer_is_typed_as_the_dashboard_compares_it(api, seed):
    """isFavorite compares with ===: a vmid that came back as a string would never match
    the search row's number, and the star would never light."""
    admin = seed.user('root', role='admin')
    _fake_mgr(api)
    c = api.as_user(admin)
    _add_vm(c, '100')
    _post(c, action='add', type='cluster', cluster_id='cluster_1')
    _reopen()
    favs = _get(c)
    assert type(favs['vms'][0]['vmid']) is int and favs['vms'][0]['vmid'] == 100
    assert favs['clusters'] == ['cluster_1']


def test_adding_twice_keeps_one_row(api, seed):
    admin = seed.user('root', role='admin')
    _fake_mgr(api)
    c = api.as_user(admin)
    for _ in range(3):
        assert _add_vm(c, 100).status_code == 200
        assert _post(c, action='add', type='node', cluster_id='cluster_1', node='pve1').status_code == 200
    assert len(_rows('root')) == 2


def test_name_and_type_come_from_the_cluster_not_the_body(api, seed):
    admin = seed.user('root', role='admin')
    _fake_mgr(api)
    c = api.as_user(admin)
    # the dashboard sends qemu for anything that is not a container row; the cluster knows
    _add_vm(c, 200, vm_type='qemu', vm_name='<img src=x>', name='forged')
    assert _rows('root') == [('root', 'vm', 'cluster_1', 200, 'lxc', 'pp-ct', '')]


def test_a_vm_the_cluster_does_not_list_is_kept_with_the_type_sent(api, seed):
    """An offline cluster lists nothing; the favorite is taken all the same."""
    admin = seed.user('root', role='admin')
    _fake_mgr(api, vms=[])
    c = api.as_user(admin)
    assert _add_vm(c, 4242, vm_type='lxc').status_code == 200
    assert _rows('root') == [('root', 'vm', 'cluster_1', 4242, 'lxc', None, '')]
    assert _get(c)['vms'] == [{'cluster_id': 'cluster_1', 'vmid': 4242, 'type': 'lxc', 'name': ''}]


# --- per user, no whole-table rewrite ---------------------------------------------------------

def test_a_write_leaves_every_other_users_rows_alone(api, seed):
    """The old saver started with DELETE FROM user_favorites, and its failure left that
    DELETE pending: the next commit on the connection wiped every user's rows."""
    admin = seed.user('root', role='admin')
    seed.user('bob', role='user')
    _fake_mgr(api)
    _insert('bob', vmid=100, vm_type='qemu', name='pp-web')
    _insert('bob', kind='node', node='pve2')
    before = _rows('bob')
    c = api.as_user(admin)
    _add_vm(c, 101)
    _post(c, action='remove', type='vm', cluster_id='cluster_1', vmid=101)
    _post(c, action='add', type='cluster', cluster_id='cluster_1')
    # anybody's next commit on this connection
    _db_now().conn.commit()
    _reopen()
    assert _rows('bob') == before
    assert _rows('root') == [('root', 'cluster', 'cluster_1', None, None, None, '')]


def test_no_write_is_left_open_on_the_connection(api, seed):
    admin = seed.user('root', role='admin')
    _fake_mgr(api)
    c = api.as_user(admin)
    for body in ({'action': 'add', 'type': 'vm', 'cluster_id': 'cluster_1', 'vmid': 100},
                 {'action': 'add', 'type': 'vm', 'cluster_id': 'cluster_1', 'vmid': 100},
                 {'action': 'remove', 'type': 'vm', 'cluster_id': 'cluster_1', 'vmid': 100},
                 {'action': 'remove', 'type': 'node', 'cluster_id': 'cluster_1', 'node': 'pve9'}):
        _post(c, **body)
        assert not _db_now().conn.in_transaction, body


def test_another_users_favorites_are_never_handed_out_or_touched(api, seed):
    seed.user('alice', role='admin')
    bob = seed.user('bob', role='admin')
    _fake_mgr(api)
    _insert('alice', vmid=100, vm_type='qemu', name='pp-web')
    _insert('alice', kind='cluster')
    c = api.as_user(bob)
    assert _get(c) == {'vms': [], 'nodes': [], 'clusters': []}
    # a body naming somebody else changes nothing of theirs
    r = _post(c, action='remove', type='vm', cluster_id='cluster_1', vmid=100, username='alice')
    assert r.status_code == 200
    r = _post(c, action='add', type='vm', cluster_id='cluster_1', vmid=101, username='alice', user='alice')
    assert r.status_code == 200
    assert len(_rows('alice')) == 2
    assert _rows('bob') == [('bob', 'vm', 'cluster_1', 101, 'qemu', 'pp-secret', '')]


def test_a_deleted_account_takes_its_favorites_along(api, seed):
    seed.user('alice', role='user')
    seed.user('bob', role='user')
    db = _db_now()
    _insert('alice', vmid=100)
    _insert('bob', vmid=100)
    db.delete_user('alice')
    assert _rows('alice') == []
    assert len(_rows('bob')) == 1


# --- the cap ---------------------------------------------------------------------------------

def test_the_cap_holds_per_user_and_kind(api, seed):
    root = seed.user('root', role='admin')
    other = seed.user('other', role='admin')
    _fake_mgr(api, vms=[])
    db = _db_now()
    cap = search.FAVORITES_MAX['vm']
    assert (cap, search.FAVORITES_MAX['node'], search.FAVORITES_MAX['cluster']) == (500, 200, 100)
    db.conn.executemany(
        'INSERT INTO user_favorites (username, kind, cluster_id, vmid, node) VALUES (?, ?, ?, ?, ?)',
        [('root', 'vm', 'cluster_1', 1000 + i, '') for i in range(cap)])
    db.conn.commit()
    c = api.as_user(root)

    r = _add_vm(c, 99999)
    assert r.status_code == 409, r.get_data(as_text=True)
    assert r.get_json()['code'] == 'FAVORITES_LIMIT'
    assert r.get_json()['error'] == 'At most 500 VMs can be favorites - remove one first'
    assert not _db_now().conn.in_transaction
    # one already there is no new one
    assert _add_vm(c, 1000).status_code == 200
    # the other kinds and the other users have their own
    assert _post(c, action='add', type='node', cluster_id='cluster_1', node='pve1').status_code == 200
    assert _add_vm(api.as_user(other), 99999).status_code == 200
    # one gone, one in
    assert _post(c, action='remove', type='vm', cluster_id='cluster_1', vmid=1000).status_code == 200
    assert _add_vm(c, 99999).status_code == 200
    _reopen()
    assert _db_now().conn.execute("SELECT COUNT(*) FROM user_favorites WHERE username = 'root' "
                                  "AND kind = 'vm'").fetchone()[0] == cap


@pytest.mark.parametrize('kind,body', [
    ('node', lambda i: {'type': 'node', 'node': f'pve{i}'}),
    ('cluster', lambda i: {'type': 'cluster', 'cluster_id': f'c{i}'}),
])
def test_the_cap_of_nodes_and_clusters(api, seed, monkeypatch, kind, body):
    root = seed.user('root', role='admin')
    for i in range(4):
        _fake_mgr(api, cluster_id=f'c{i}', vms=[])
    _fake_mgr(api, vms=[])
    monkeypatch.setitem(search.FAVORITES_MAX, kind, 3)
    c = api.as_user(root)
    codes = [_post(c, **dict({'action': 'add', 'cluster_id': 'cluster_1'}, **body(i))).status_code
             for i in range(4)]
    assert codes == [200, 200, 200, 409]


# --- what is taken -------------------------------------------------------------------------

@pytest.mark.parametrize('body', [
    pytest.param({'type': 'vm', 'cluster_id': 'cluster_1'}, id='vm-without-vmid'),
    pytest.param({'type': 'vm', 'cluster_id': 'cluster_1', 'vmid': 'abc'}, id='vmid-text'),
    pytest.param({'type': 'vm', 'cluster_id': 'cluster_1', 'vmid': 0}, id='vmid-zero'),
    pytest.param({'type': 'vm', 'cluster_id': 'cluster_1', 'vmid': 10 ** 10}, id='vmid-too-big'),
    pytest.param({'type': 'vm', 'cluster_id': 'cluster_1', 'vmid': True}, id='vmid-bool'),
    pytest.param({'type': 'vm', 'cluster_id': 'cluster_1', 'vmid': 100.5}, id='vmid-float'),
    pytest.param({'type': 'vm', 'cluster_id': 'cluster_1', 'vmid': [100]}, id='vmid-list'),
    pytest.param({'type': 'vm', 'cluster_id': 'cluster_1', 'vmid': '١٠٠'}, id='vmid-other-digits'),
    pytest.param({'type': 'vm', 'cluster_id': 'cluster_1', 'vmid': 100, 'vm_type': 'kvm'}, id='vm-type'),
    pytest.param({'type': 'node', 'cluster_id': 'cluster_1'}, id='node-without-name'),
    pytest.param({'type': 'node', 'cluster_id': 'cluster_1', 'node': 'pve 1'}, id='node-space'),
    pytest.param({'type': 'node', 'cluster_id': 'cluster_1', 'node': 'n' * 64}, id='node-too-long'),
    pytest.param({'type': 'node', 'cluster_id': 'cluster_1', 'node': '../pve1'}, id='node-path'),
    pytest.param({'type': 'node', 'cluster_id': 'cluster_1', 'node': {'a': 1}}, id='node-object'),
    pytest.param({'type': 'pool', 'cluster_id': 'cluster_1'}, id='unknown-type'),
    pytest.param({'type': 'cluster'}, id='no-cluster'),
    pytest.param({'type': 'cluster', 'cluster_id': 'c/1'}, id='cluster-slash'),
    pytest.param({'type': 'cluster', 'cluster_id': 'c' * 65}, id='cluster-too-long'),
    pytest.param({'type': 'cluster', 'cluster_id': 7}, id='cluster-number'),
    pytest.param({'type': 'cluster', 'cluster_id': 'cluster_1', 'action': 'toggle'}, id='action'),
])
def test_a_body_out_of_shape_is_refused(api, seed, body):
    root = seed.user('root', role='admin')
    _fake_mgr(api)
    r = api.as_user(root).post('/api/user/favorites', json=dict({'action': 'add'}, **body))
    assert r.status_code == 400, r.get_data(as_text=True)
    assert _rows() == []


def test_a_body_that_is_no_object_is_refused(api, seed):
    root = seed.user('root', role='admin')
    c = api.as_user(root)
    for raw in ('[1, 2]', '"vm"', 'not json'):
        r = c.post('/api/user/favorites', data=raw, headers={'Content-Type': 'application/json'})
        assert r.status_code == 400, raw


def test_the_longest_names_that_are_ids_are_taken(api, seed):
    root = seed.user('root', role='admin')
    cid = 'c' * 64
    _fake_mgr(api, cluster_id=cid, vms=[])
    c = api.as_user(root)
    assert _post(c, action='add', type='node', cluster_id=cid, node='n' * 63).status_code == 200
    assert _post(c, action='add', type='node', cluster_id=cid, node='10-0-0-1.lab.example').status_code == 200
    assert _add_vm(c, 999999999, cluster_id=cid).status_code == 200


def test_a_cluster_that_is_not_there_is_not_taken(api, seed):
    root = seed.user('root', role='admin')
    _fake_mgr(api)
    r = _post(api.as_user(root), action='add', type='cluster', cluster_id='gone1234')
    assert r.status_code == 403
    assert _rows() == []


def test_the_anonymous_caller_gets_nothing(api):
    assert api.anon().get('/api/user/favorites').status_code == 401
    assert api.anon().post('/api/user/favorites', json={'type': 'cluster', 'cluster_id': 'x'}).status_code == 401


# --- what the caller may see -------------------------------------------------------------

def _pool_membership(cluster_id, mapping):
    data = {f'{vmid}:{vtype}': pool for vmid, (vtype, pool) in mapping.items()}
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache[cluster_id] = {'data': data, 'timestamp': time.time(),
                                                   'refreshing': False}


def _everything(username):
    """Favorites of every kind on two clusters, the way they were added while the user
    could still see them all."""
    for cid in ('cluster_1', 'cluster_2'):
        _insert(username, cluster_id=cid, vmid=100, vm_type='qemu', name=f'{cid}-web')
        _insert(username, cluster_id=cid, vmid=101, vm_type='qemu', name=f'{cid}-secret')
        _insert(username, kind='node', cluster_id=cid, node=f'{cid}-node')
        _insert(username, kind='cluster', cluster_id=cid)


def _seen(c):
    favs = _get(c)
    return (sorted((f['cluster_id'], f['vmid']) for f in favs['vms']),
            sorted((f['cluster_id'], f['node']) for f in favs['nodes']),
            sorted(favs['clusters']))


ALL = ([('cluster_1', 100), ('cluster_1', 101), ('cluster_2', 100), ('cluster_2', 101)],
       [('cluster_1', 'cluster_1-node'), ('cluster_2', 'cluster_2-node')],
       ['cluster_1', 'cluster_2'])
CLUSTER_1 = ([('cluster_1', 100), ('cluster_1', 101)], [('cluster_1', 'cluster_1-node')], ['cluster_1'])
VM_100_ONLY = ([('cluster_1', 100)], [('cluster_1', 'cluster_1-node')], ['cluster_1'])


def _two_clusters(api):
    _fake_mgr(api, 'cluster_1')
    _fake_mgr(api, 'cluster_2')


def _matrix_case(api, seed, who):
    if who == 'admin':
        u = seed.user('u', role='admin')
    elif who == 'viewer':
        u = seed.user('u', role='viewer')
    elif who == 'tenant':
        seed.tenant('acme', clusters=['cluster_1'])
        u = seed.user('u', role='user', tenant_id='acme')
    elif who == 'tenant-viewer':
        seed.tenant('acme', clusters=['cluster_1'])
        u = seed.user('u', role='viewer', tenant_id='acme')
    elif who == 'vm-acl':
        # the client portal setup: the tenant owns the cluster, the user is given one VM
        seed.tenant('acme', clusters=['cluster_1'])
        u = seed.user('u', role='user', tenant_id='acme')
        seed.vm_acl('cluster_1', 100, users=['u'])
    elif who == 'pool':
        seed.tenant('acme', clusters=['cluster_1'])
        u = seed.user('u', role='viewer', tenant_id='acme')
        seed.pool('cluster_1', 'pool_1', 'u', ['pool.view', 'vm.view'])
        _pool_membership('cluster_1', {100: ('qemu', 'pool_1')})
    elif who == 'no-cluster-tenant':
        seed.tenant('empty', clusters=[])
        u = seed.user('u', role='user', tenant_id='empty')
    else:
        raise AssertionError(who)
    _everything('u')
    _two_clusters(api)
    return u


@pytest.mark.parametrize('who,expected', [
    ('admin', ALL),
    ('viewer', ALL),
    ('tenant', CLUSTER_1),
    ('tenant-viewer', CLUSTER_1),
    ('vm-acl', VM_100_ONLY),
    ('pool', VM_100_ONLY),
    ('no-cluster-tenant', ([], [], [])),
])
def test_only_what_the_caller_may_see_is_listed(api, seed, who, expected):
    u = _matrix_case(api, seed, who)
    c = api.as_user(u)
    assert _seen(c) == expected
    # the answer of a write lists the same
    r = _post(c, action='remove', type='vm', cluster_id='cluster_2', vmid=999)
    favs = r.get_json()['favorites']
    assert sorted((f['cluster_id'], f['vmid']) for f in favs['vms']) == expected[0]
    # no name of a VM or node out of reach in the text of either answer
    hidden = {f'{cid}-web' if vmid == 100 else f'{cid}-secret' for cid in ('cluster_1', 'cluster_2')
              for vmid in (100, 101) if (cid, vmid) not in expected[0]}
    hidden |= {node for cid, node in ALL[1] if (cid, node) not in expected[1]}
    for text in (c.get('/api/user/favorites').get_data(as_text=True), r.get_data(as_text=True)):
        for name in hidden:
            assert name not in text, (who, name)
    # the rows stay: they show again once the access comes back
    assert len(_rows('u')) == 8


@pytest.mark.parametrize('who,allowed', [
    ('admin', {('cluster_1', 101), ('cluster_2', 101), 'node2', 'cluster2'}),
    ('viewer', {('cluster_1', 101), ('cluster_2', 101), 'node2', 'cluster2'}),
    ('tenant', {('cluster_1', 101)}),
    ('vm-acl', set()),
    ('pool', set()),
    ('no-cluster-tenant', set()),
])
def test_only_what_the_caller_may_see_is_taken(api, seed, who, allowed):
    u = _matrix_case(api, seed, who)
    _db_now().conn.execute("DELETE FROM user_favorites")
    _db_now().conn.commit()
    c = api.as_user(u)
    tries = {
        ('cluster_1', 101): {'type': 'vm', 'cluster_id': 'cluster_1', 'vmid': 101},
        ('cluster_2', 101): {'type': 'vm', 'cluster_id': 'cluster_2', 'vmid': 101},
        'node2': {'type': 'node', 'cluster_id': 'cluster_2', 'node': 'pve1'},
        'cluster2': {'type': 'cluster', 'cluster_id': 'cluster_2'},
    }
    got = set()
    for name, body in tries.items():
        r = _post(c, action='add', **body)
        assert r.status_code in (200, 403), r.get_data(as_text=True)
        if r.status_code == 200:
            got.add(name)
        else:
            assert r.get_json() == {'error': 'Access denied'}
    assert got == allowed
    assert len(_rows('u')) == len(allowed)


def test_a_favorite_hides_while_the_access_is_gone_and_shows_again(api, seed):
    seed.tenant('acme', clusters=['cluster_1', 'cluster_2'])
    u = seed.user('u', role='user', tenant_id='acme')
    _two_clusters(api)
    c = api.as_user(u)
    assert _add_vm(c, 100, cluster_id='cluster_2').status_code == 200
    assert _post(c, action='add', type='cluster', cluster_id='cluster_2').status_code == 200

    seed.tenant('acme', clusters=['cluster_1'])
    rbac.invalidate_tenants_cache()
    assert _seen(c) == ([], [], [])
    # a remove of one's own row works out of reach as well
    assert _post(c, action='remove', type='cluster', cluster_id='cluster_2').status_code == 200

    seed.tenant('acme', clusters=['cluster_1', 'cluster_2'])
    rbac.invalidate_tenants_cache()
    assert _seen(c) == ([('cluster_2', 100)], [], [])


def _token(seed, owner, role):
    from pegaprox.utils.auth import create_api_token
    res = create_api_token(owner, f'ci-{role}', role=role)
    assert 'token' in res, res
    return {'Authorization': f"Bearer {res['token']}"}


def test_an_api_token_reads_its_owners_favorites_in_its_own_scope(api, seed):
    # an admin-owned token cut to viewer: the owner's favorites, as far as a viewer sees them
    seed.user('root', role='admin')
    _everything('root')
    _insert('someone', vmid=100)
    _two_clusters(api)
    r = api.anon().get('/api/user/favorites', headers=_token(seed, 'root', 'viewer'))
    assert r.status_code == 200, r.get_data(as_text=True)
    favs = r.get_json()
    assert sorted((f['cluster_id'], f['vmid']) for f in favs['vms']) == ALL[0]


def test_an_api_token_of_a_tenant_user_stays_in_the_tenant(api, seed):
    seed.tenant('acme', clusters=['cluster_1'])
    seed.user('u', role='user', tenant_id='acme')
    _everything('u')
    _two_clusters(api)
    hdr = _token(seed, 'u', 'viewer')
    favs = api.anon().get('/api/user/favorites', headers=hdr).get_json()
    assert (sorted((f['cluster_id'], f['vmid']) for f in favs['vms']), favs['clusters']) == (
        CLUSTER_1[0], ['cluster_1'])
    # and takes nothing outside of it
    r = api.anon().post('/api/user/favorites', headers=hdr,
                        json={'action': 'add', 'type': 'cluster', 'cluster_id': 'cluster_2'})
    assert r.status_code == 403, r.get_data(as_text=True)


# --- the migration ---------------------------------------------------------------------------

def _old_shape(db, rows):
    db.conn.execute('DROP TABLE user_favorites')
    db.conn.execute(OLD_TABLE)
    db.conn.executemany('INSERT INTO user_favorites (username, cluster_id, vmid, vm_type, vm_name, added_at) '
                        'VALUES (?, ?, ?, ?, ?, ?)', rows)
    db.conn.commit()


def _columns(db):
    return {r[1]: (r[2], r[3], r[4]) for r in db.conn.execute('PRAGMA table_info(user_favorites)')}


def _indexes(db):
    return {r[0]: r[1] for r in db.conn.execute(
        "SELECT name, sql FROM sqlite_master WHERE type = 'index' AND tbl_name = 'user_favorites'")}


OLD_ROWS = [
    ('alice', 'cluster_1', 100, 'qemu', 'web01', '2026-01-20T10:00:00'),
    ('alice', 'cluster_1', 101, 'lxc', 'ct01', '2026-01-20T10:00:01'),
    ('alice', 'cluster_1', 100, 'qemu', 'web01', '2026-01-20T10:00:02'),   # the same twice
    ('bob', 'cluster_1', 100, 'qemu', 'web01', '2026-01-20T10:00:03'),
]


def test_a_table_of_the_old_shape_is_migrated_in_place(db):
    _old_shape(db, OLD_ROWS)
    db = _reopen()

    cols = _columns(db)
    assert cols['kind'] == ('TEXT', 1, "'vm'") and cols['node'] == ('TEXT', 1, "''")
    assert 'idx_favorites_unique' in _indexes(db)
    # the rows are VM favorites, the double one is gone, the oldest stays
    assert _rows() == [
        ('alice', 'vm', 'cluster_1', 100, 'qemu', 'web01', ''),
        ('alice', 'vm', 'cluster_1', 101, 'lxc', 'ct01', ''),
        ('bob', 'vm', 'cluster_1', 100, 'qemu', 'web01', ''),
    ]
    assert db.conn.execute("SELECT added_at FROM user_favorites WHERE username = 'alice' AND vmid = 100"
                           ).fetchone()[0] == '2026-01-20T10:00:00'
    assert search.load_favorites('alice') == {
        'vms': [{'cluster_id': 'cluster_1', 'vmid': 100, 'type': 'qemu', 'name': 'web01'},
                {'cluster_id': 'cluster_1', 'vmid': 101, 'type': 'lxc', 'name': 'ct01'}],
        'nodes': [], 'clusters': []}


def test_the_migration_runs_again_without_a_change(db):
    fresh = _columns(db), _indexes(db)
    _old_shape(db, OLD_ROWS)
    first = _reopen()
    rows, cols, idx = _rows(), _columns(first), _indexes(first)
    again = _reopen()
    assert (_rows(), _columns(again), _indexes(again)) == (rows, cols, idx)
    # a migrated table is the table a fresh database makes
    assert (cols, idx) == fresh


def test_the_unique_key_holds_for_every_kind(db):
    ins = ('INSERT INTO user_favorites (username, kind, cluster_id, vmid, node) VALUES (?, ?, ?, ?, ?)')
    for row in (('a', 'vm', 'c1', 100, ''), ('a', 'node', 'c1', None, 'pve1'), ('a', 'cluster', 'c1', None, '')):
        db.conn.execute(ins, row)
        with pytest.raises(Exception) as e:
            db.conn.execute(ins, row)
        assert 'UNIQUE' in str(e.value)
    # the same thing for another user, or another node, is another row
    db.conn.execute(ins, ('b', 'node', 'c1', None, 'pve1'))
    db.conn.execute(ins, ('a', 'node', 'c1', None, 'pve2'))
    db.conn.commit()


def test_the_migration_is_no_change_to_a_sync(db):
    """A member that upgrades must not count the migration as a change of its own: the
    rows hash the same before and after the two columns (their defaults are no value)."""
    _old_shape(db, OLD_ROWS[:2] + OLD_ROWS[3:])   # no double row: the dedup is a change
    before = ha._walk_snapshot(body=False)[4]
    _reopen()
    assert ha._walk_snapshot(body=False)[4] == before


# --- the instance group (#625) -----------------------------------------------------------------

def _favorites_of_every_kind():
    _insert('alice', vmid=100, vm_type='qemu', name='web01')
    _insert('alice', kind='node', node='pve1')
    _insert('alice', kind='cluster')
    _insert('bob', vmid=200, vm_type='lxc', name='ct01')


EVERY_KIND = {
    'alice': {'vms': [{'cluster_id': 'cluster_1', 'vmid': 100, 'type': 'qemu', 'name': 'web01'}],
              'nodes': [{'cluster_id': 'cluster_1', 'node': 'pve1'}], 'clusters': ['cluster_1']},
    'bob': {'vms': [{'cluster_id': 'cluster_1', 'vmid': 200, 'type': 'lxc', 'name': 'ct01'}],
            'nodes': [], 'clusters': []},
}


def _loaded():
    return {u: search.load_favorites(u) for u in ('alice', 'bob')}


def test_the_new_columns_travel_with_a_sync(env, db, seed):
    _be_active()
    _favorites_of_every_kind()
    snap = _wire(ha.build_snapshot())
    t = snap['tables']['user_favorites']
    assert {'kind', 'node'} <= set(t['columns'])
    assert t['coldefs']['kind'] == ['TEXT', "'vm'"] and t['coldefs']['node'] == ['TEXT', "''"]

    db.conn.execute('DELETE FROM user_favorites')
    _insert('carol', kind='node', node='standby-only')
    _be_standby()
    summary = ha.apply_snapshot(snap)

    assert summary['skipped_columns'] == {}
    assert _loaded() == EVERY_KIND
    assert search.load_favorites('carol') == {'vms': [], 'nodes': [], 'clusters': []}
    _reopen()
    assert _loaded() == EVERY_KIND


def test_a_member_on_the_old_schema_takes_the_new_rows(env, db, seed):
    """A release without the two columns: the sync adds them with the active's type and
    default, the rows keep their kind, and the upgrade later finds them in place."""
    _be_active()
    _favorites_of_every_kind()
    snap = _wire(ha.build_snapshot())

    _old_shape(db, [('alice', 'cluster_1', 555, 'qemu', 'old', '2026-01-01')])
    assert 'kind' not in _columns(db)
    _be_standby()
    summary = ha.apply_snapshot(snap)

    assert summary['skipped_columns'] == {}
    assert sorted(summary['added_columns']['user_favorites']) == ['kind', 'node']
    cols = _columns(db)
    assert (cols['kind'][0], cols['kind'][2], cols['node'][0], cols['node'][2]) == ('TEXT', "'vm'", 'TEXT', "''")
    assert _loaded() == EVERY_KIND

    # and the upgrade of that member: the columns are there, the index comes
    db = _reopen()
    assert 'idx_favorites_unique' in _indexes(db)
    assert _loaded() == EVERY_KIND


def test_a_member_on_the_new_schema_takes_rows_without_the_columns(env, db, seed):
    """From an active on a release without them: every row is a VM favorite, which is all
    that release could hold."""
    _be_active()
    _insert('alice', vmid=100, vm_type='qemu', name='web01')
    _insert('bob', vmid=200, vm_type='lxc', name='ct01')
    snap = _wire(ha.build_snapshot())
    t = snap['tables']['user_favorites']
    keep = [i for i, c in enumerate(t['columns']) if c not in ('kind', 'node')]
    t['columns'] = [t['columns'][i] for i in keep]
    t['rows'] = [[row[i] for i in keep] for row in t['rows']]
    for c in ('kind', 'node'):
        t['coldefs'].pop(c)
    t['sql'] = OLD_TABLE.strip()

    db.conn.execute('DELETE FROM user_favorites')
    db.conn.commit()
    _be_standby()
    summary = ha.apply_snapshot(snap)

    assert summary['skipped_columns'] == {} and not summary.get('added_columns')
    assert _loaded() == {
        'alice': {'vms': [{'cluster_id': 'cluster_1', 'vmid': 100, 'type': 'qemu', 'name': 'web01'}],
                  'nodes': [], 'clusters': []},
        'bob': {'vms': [{'cluster_id': 'cluster_1', 'vmid': 200, 'type': 'lxc', 'name': 'ct01'}],
                'nodes': [], 'clusters': []},
    }
    assert _rows() == [('alice', 'vm', 'cluster_1', 100, 'qemu', 'web01', ''),
                       ('bob', 'vm', 'cluster_1', 200, 'lxc', 'ct01', '')]


def test_the_change_count_sees_the_new_columns(db):
    """The triggers name every column of a shared table. A table that got its columns by
    the migration has triggers made before them; the next look makes them again."""
    _old_shape(db, [('alice', 'cluster_1', 100, 'qemu', 'web01', '2026-01-01')])
    assert ha.ensure_change_triggers() > 0
    old_update = db.conn.execute("SELECT sql FROM sqlite_master WHERE name = 'ha_cv_user_favorites_u'"
                                 ).fetchone()[0]
    assert '"kind"' not in old_update

    db = _reopen()
    assert ha.ensure_change_triggers() >= 1
    update = db.conn.execute("SELECT sql FROM sqlite_master WHERE name = 'ha_cv_user_favorites_u'"
                             ).fetchone()[0]
    assert 'NEW."kind" IS NOT OLD."kind"' in update and 'NEW."node" IS NOT OLD."node"' in update

    n = ha._dirty_count()
    db.conn.execute("UPDATE user_favorites SET node = 'x'")
    db.conn.commit()
    assert ha._dirty_count() == n + 1
    db.conn.execute("UPDATE user_favorites SET kind = 'node'")
    db.conn.commit()
    assert ha._dirty_count() == n + 2


def test_a_write_through_the_route_is_counted(api, seed):
    root = seed.user('root', role='admin')
    _fake_mgr(api)
    assert ha.ensure_change_triggers() > 0
    c = api.as_user(root)
    # the first read of the tenants writes the default one; not ours to count
    _get(c)
    n = ha._dirty_count()
    assert _add_vm(c, 100).status_code == 200
    assert ha._dirty_count() == n + 1
    assert _post(c, action='remove', type='vm', cluster_id='cluster_1', vmid=100).status_code == 200
    assert ha._dirty_count() == n + 2



def test_a_standalone_esxi_host_lists_its_vms_by_small_ids(api, seed):
    """An ESXi host on its own lists its VMs by moId: '5', '42'. Those were refused as
    'Invalid vmid', and '123' was stored as 123 while the dashboard compared it with
    the string it had sent, so the star never lit and could not be taken off."""
    _fake_mgr(api, 'esx1', vms=[{'vmid': '5', 'name': 'esx-small', 'node': 'esx1', 'type': 'qemu', 'status': 'running'},
                                {'vmid': '123', 'name': 'esx-mid', 'node': 'esx1', 'type': 'qemu', 'status': 'running'}])
    admin = api.as_user(seed.user('root', role='admin'))
    for vmid in ('5', '123'):
        r = _add_vm(admin, vmid, cluster_id='esx1')
        assert r.status_code == 200, r.get_data(as_text=True)
    _reopen()
    assert _vm_keys(_get(admin)) == [('esx1', 5), ('esx1', 123)]
    assert _post(admin, action='remove', type='vm', cluster_id='esx1', vmid='5').status_code == 200
    assert _vm_keys(_get(admin)) == [('esx1', 123)]


@pytest.mark.parametrize('vmid', ['0', '-5', 'abc', '1234567890', True, 1.5])
def test_a_vmid_that_is_no_number_of_a_guest_is_refused(api, seed, vmid):
    _fake_mgr(api)
    admin = api.as_user(seed.user('root', role='admin'))
    assert _add_vm(admin, vmid).status_code == 400


def test_a_deleted_vm_takes_its_stars_along(api, seed):
    """The next guest that takes the number does not inherit the star, and the row no
    longer holds a slot of the cap."""
    _fake_mgr(api)
    admin = api.as_user(seed.user('root', role='admin'))
    alice = api.as_user(seed.user('alice', role='admin'))
    for client in (admin, alice):
        assert _add_vm(client, 101).status_code == 200
    assert _add_vm(admin, 100).status_code == 200
    from pegaprox.core.db import get_db
    assert get_db().purge_vm_grants('cluster_1', 101)['favorites'] == 2
    _reopen()
    assert _vm_keys(_get(admin)) == [('cluster_1', 100)]
    assert _vm_keys(_get(alice)) == []
