"""A storage balancing group that was deleted or renamed stays that way after a reload.

save_storage_clusters only ran INSERT OR REPLACE for the groups still in memory and nothing
ever deleted a row. A deleted group therefore came back on the next load (a restart, or the
reload after an HA sync) with its auto_balance flag, and the userless worker started moving
disks again. A rename wrote a second row and kept the old one, and two groups of one name
shared a single row. The reload here is the same load_storage_clusters a restart runs. MK
"""
import json

import pytest

CLUSTER = 'cluster_1'


@pytest.fixture
def storagemod(api):
    # imported here, not at collection: importing it loads the groups of whatever DB is
    # current and starts the balancing worker
    import pegaprox.api.storage as mod
    return mod


@pytest.fixture
def admin(api, seed, storagemod):
    api.set_manager(CLUSTER, api.make_fake_manager(CLUSTER))
    api.set_manager('cluster_2', api.make_fake_manager('cluster_2'))
    storagemod.load_storage_clusters()
    assert storagemod.storage_clusters_config == {}
    return api.as_user(seed.user('sc-admin', role='admin'))


def _create(client, name, cluster=CLUSTER, auto=False):
    return client.post(f'/api/clusters/{cluster}/storage-clusters',
                       json={'name': name, 'storages': ['ceph-a', 'ceph-b'], 'auto_balance': auto})


def _reload(storagemod):
    """What a restart or an HA sync does."""
    storagemod.load_storage_clusters()
    return {cid: [(sc['name'], sc['id'], sc.get('auto_balance')) for sc in cfg['clusters']]
            for cid, cfg in storagemod.storage_clusters_config.items()}


def _rows(db):
    cur = db.conn.cursor()
    cur.execute('SELECT cluster_id, name FROM storage_clusters ORDER BY cluster_id, name')
    return [(r[0], r[1]) for r in cur.fetchall()]


def _insert(db, name, config, cluster=CLUSTER):
    db.conn.cursor().execute(
        "INSERT INTO storage_clusters (cluster_id, name, storage_type, nodes, config, enabled) "
        "VALUES (?, ?, 'ceph', '[]', ?, 1)", (cluster, name, config))
    db.conn.commit()


def test_a_deleted_group_stays_deleted_after_a_reload(admin, db, storagemod):
    armed = _create(admin, 'fast', auto=True)
    assert armed.status_code == 201, armed.data
    keep = _create(admin, 'slow', auto=True).get_json()
    r = admin.delete(f"/api/clusters/{CLUSTER}/storage-clusters/{armed.get_json()['id']}")
    assert r.status_code == 200, r.data
    assert _reload(storagemod) == {CLUSTER: [('slow', keep['id'], True)]}
    assert _rows(db) == [(CLUSTER, 'slow')]


def test_deleting_the_last_group_leaves_none_after_a_reload(admin, db, storagemod):
    sc = _create(admin, 'only', auto=True).get_json()
    assert admin.delete(f"/api/clusters/{CLUSTER}/storage-clusters/{sc['id']}").status_code == 200
    assert _reload(storagemod) == {}
    assert _rows(db) == []


def test_a_renamed_group_is_one_group_after_a_reload(admin, db, storagemod):
    sc = _create(admin, 'old-name', auto=True).get_json()
    r = admin.put(f"/api/clusters/{CLUSTER}/storage-clusters/{sc['id']}", json={'name': 'new-name'})
    assert r.status_code == 200, r.data
    assert _reload(storagemod) == {CLUSTER: [('new-name', sc['id'], True)]}
    assert _rows(db) == [(CLUSTER, 'new-name')]


def test_the_two_rows_an_earlier_rename_left_behind_become_one_group(admin, db, storagemod):
    # what a rename before the fix wrote: the old row stayed, the renamed one came later
    _insert(db, 'old-name', json.dumps({'id': 'g1', 'auto_balance': True, 'enabled': True}))
    _insert(db, 'new-name', json.dumps({'id': 'g1', 'auto_balance': True, 'enabled': True}))
    assert _reload(storagemod) == {CLUSTER: [('new-name', 'g1', True)]}
    # switching the balancing off reaches the group the user sees, and the old row goes
    r = admin.put(f'/api/clusters/{CLUSTER}/storage-clusters/g1', json={'auto_balance': False})
    assert r.status_code == 200, r.data
    assert _rows(db) == [(CLUSTER, 'new-name')]
    assert _reload(storagemod) == {CLUSTER: [('new-name', 'g1', False)]}


def test_a_second_group_of_the_same_name_is_refused(admin, db, storagemod):
    first = _create(admin, 'pool', auto=True).get_json()
    assert _create(admin, 'pool', auto=False).status_code == 409
    assert _create(admin, '  pool  ').status_code == 409
    assert _reload(storagemod) == {CLUSTER: [('pool', first['id'], True)]}


@pytest.mark.parametrize('name', [7, '', '   ', 'x' * 129, '\ud800'])
def test_a_name_the_table_cannot_keep_is_refused(admin, db, storagemod, name):
    assert _create(admin, name).status_code == 400
    sc = _create(admin, 'fine').get_json()
    r = admin.put(f"/api/clusters/{CLUSTER}/storage-clusters/{sc['id']}", json={'name': name})
    assert r.status_code == 400, r.data
    # nothing stuck in memory that would fail the saves after it
    assert admin.delete(f"/api/clusters/{CLUSTER}/storage-clusters/{sc['id']}").status_code == 200
    assert _rows(db) == []


def test_a_rename_onto_another_name_in_use_is_refused(admin, db, storagemod):
    a = _create(admin, 'a').get_json()
    _create(admin, 'b')
    url = f"/api/clusters/{CLUSTER}/storage-clusters/{a['id']}"
    assert admin.put(url, json={'name': 'b'}).status_code == 409
    # its own name sent back is no clash and no rename
    assert admin.put(url, json={'name': 'a', 'threshold': 30}).status_code == 200
    assert sorted(n for n, _, _ in _reload(storagemod)[CLUSTER]) == ['a', 'b']


def test_the_groups_of_another_cluster_are_left_alone(admin, db, storagemod):
    here = _create(admin, 'here').get_json()
    _create(admin, 'there', cluster='cluster_2', auto=True)
    assert admin.delete(f"/api/clusters/{CLUSTER}/storage-clusters/{here['id']}").status_code == 200
    got = _reload(storagemod)
    assert CLUSTER not in got
    assert [n for n, _, auto in got['cluster_2']] == ['there']


def test_a_save_after_a_load_that_broke_off_drops_nothing(admin, db, storagemod):
    # a row the load cannot read stops it half way: memory then holds less than the table,
    # and a save must not take that as the groups to keep
    _create(admin, 'first', auto=True)
    _insert(db, 'unreadable', '{not json')
    _insert(db, 'after', json.dumps({'id': 'x1', 'auto_balance': True}))
    storagemod.load_storage_clusters()
    assert [sc['name'] for sc in storagemod.storage_clusters_config[CLUSTER]['clusters']] == ['first']
    assert _create(admin, 'added').status_code == 201
    assert _rows(db) == [(CLUSTER, n) for n in ('added', 'after', 'first', 'unreadable')]


def test_a_save_after_a_failed_load_drops_nothing(admin, db, storagemod, monkeypatch):
    # memory from before the failed load may be older than the table (an HA sync replaced
    # it), so nothing is dropped until a load went through again
    sc = _create(admin, 'kept', auto=True).get_json()
    _insert(db, 'synced', json.dumps({'id': 's1', 'auto_balance': True}))

    def broken():
        raise RuntimeError('database is locked')
    with monkeypatch.context() as m:
        m.setattr(storagemod, 'get_db', broken)
        storagemod.load_storage_clusters()
    assert storagemod._storage_clusters_loaded is False
    assert _create(admin, 'added').status_code == 201
    assert _rows(db) == [(CLUSTER, n) for n in ('added', 'kept', 'synced')]
    # once a load goes through, a delete is written again
    storagemod.load_storage_clusters()
    assert admin.delete(f"/api/clusters/{CLUSTER}/storage-clusters/{sc['id']}").status_code == 200
    assert _rows(db) == [(CLUSTER, n) for n in ('added', 'synced')]
