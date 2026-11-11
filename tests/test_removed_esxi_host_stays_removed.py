"""A removed ESXi host stays removed after PegaProx restarts.

DELETE /api/clusters/<id>/esxi-hosts/<host_id> took the host out of memory and called
save_esxi_config, which only upserts rows. The row stayed in esxi_storages with enabled=1,
so the next start loaded the host again and the operator saw it back in the list. Same
route, same cluster: the removal now deletes the row before it answers.
"""
import json
import sqlite3
import types

import pytest

import pegaprox.api.storage as storagemod
from pegaprox.core.db import get_db

CLUSTER = 'cluster_1'
KEEP = 'keep.esxi.internal'
GONE = 'gone.esxi.internal'


@pytest.fixture
def admin(api, seed):
    seed.tenant('acme', clusters=[CLUSTER])
    mgr = api.set_manager(CLUSTER, api.make_fake_manager(CLUSTER))
    ok = types.SimpleNamespace(status_code=200, text='{}')
    mgr._api_post.return_value = ok
    mgr._api_delete.return_value = ok
    root = seed.user('root', role='admin')
    try:
        yield api.as_user(root)
    finally:
        storagemod.esxi_storages = {}


def _connect(client, host):
    r = client.post(f'/api/clusters/{CLUSTER}/esxi-hosts',
                    json={'host': host, 'username': 'svc', 'password': 'pw'})
    assert r.status_code == 200, r.data
    return r.get_json()['id']


def _remove(client, host_id):
    return client.delete(f'/api/clusters/{CLUSTER}/esxi-hosts/{host_id}')


def _restart():
    """What startup does: the in-memory registry is rebuilt from the table."""
    storagemod.esxi_storages = {}
    storagemod.load_esxi_config()
    return {h['host'] for h in storagemod.esxi_storages.get(CLUSTER, {}).values()}


def _row(name):
    row = get_db().conn.execute(
        'SELECT host, username, datastore, password_encrypted, enabled, config '
        'FROM esxi_storages WHERE name = ?', (name,)).fetchone()
    if row is None:
        return None
    fields = dict(row)
    fields['config'] = json.loads(fields['config'] or '{}')
    return fields


def test_a_removed_host_is_not_back_after_a_restart(admin):
    """After a restart the operator sees only the host they did not remove."""
    keep_id = _connect(admin, KEEP)
    gone_id = _connect(admin, GONE)
    assert _remove(admin, gone_id).status_code == 200
    assert _restart() == {KEEP}, 'the removed host came back after the restart'
    assert _row(gone_id) is None
    assert _row(keep_id) is not None


def test_the_remaining_host_keeps_its_row_as_it_was(admin):
    """The host that stays keeps its address, account and settings as they were."""
    keep_id = _connect(admin, KEEP)
    gone_id = _connect(admin, GONE)
    before = _row(keep_id)

    assert _remove(admin, gone_id).status_code == 200

    assert _row(keep_id) == before, 'the remaining host changed in the table'
    assert _restart() == {KEEP}


def test_a_removal_the_database_refuses_is_not_a_success(admin, monkeypatch):
    """When the row cannot be deleted the operator gets an error and the host stays listed."""
    gone_id = _connect(admin, GONE)

    def _no_db():
        raise RuntimeError('database is locked')
    with monkeypatch.context() as m:
        m.setattr(storagemod, 'get_db', _no_db)
        r = _remove(admin, gone_id)

    assert r.status_code == 500, r.data
    assert gone_id in storagemod.esxi_storages.get(CLUSTER, {})
    assert _restart() == {GONE}


class _CommitFails:
    """The real connection, with a commit that fails."""

    def __init__(self, conn):
        self._conn = conn

    def execute(self, *args):
        return self._conn.execute(*args)

    def commit(self):
        raise sqlite3.OperationalError('disk I/O error')

    def rollback(self):
        return self._conn.rollback()


def test_a_removal_whose_commit_fails_is_not_committed_by_a_later_request(admin, monkeypatch):
    """After a failed removal, the next write to the database does not remove the host after all."""
    gone_id = _connect(admin, GONE)
    real = get_db()

    with monkeypatch.context() as m:
        m.setattr(storagemod, 'get_db', lambda: types.SimpleNamespace(conn=_CommitFails(real.conn)))
        r = _remove(admin, gone_id)

    assert r.status_code == 500, r.data
    real.conn.commit()   # what any later request does on this connection
    assert _row(gone_id) is not None
    assert _restart() == {GONE}


def test_a_repeat_removal_pve_answers_with_does_not_exist_still_removes_the_host(admin):
    """The state of a second click after a removal that failed on the database: PVE has no
    such storage any more and answers 500 "does not exist". The host and its row go all the same."""
    from pegaprox.globals import cluster_managers
    gone_id = _connect(admin, GONE)
    storage = storagemod.esxi_storages[CLUSTER][gone_id]['storage_name']
    mgr = cluster_managers[CLUSTER]
    # what pve-storage dies with for an unknown id, sent as HTTP 500
    mgr._api_delete.return_value = types.SimpleNamespace(status_code=500, text=json.dumps(
        {'data': None, 'message': f"delete storage failed: storage '{storage}' does not exist"}))

    r = _remove(admin, gone_id)

    assert r.status_code == 200, r.data
    assert mgr._api_delete.call_args[0][0].endswith(f'/storage/{storage}')
    assert gone_id not in storagemod.esxi_storages.get(CLUSTER, {})
    assert _row(gone_id) is None, 'the row stayed after PVE answered that the storage is gone'
    assert _restart() == set()


def test_removing_an_unknown_host_answers_404_and_deletes_nothing(admin):
    """Removing a host the list does not show gets the same 404 as before and touches no row."""
    keep_id = _connect(admin, KEEP)
    before = _row(keep_id)

    r = _remove(admin, 'deadbeef')

    assert r.status_code == 404, r.data
    assert _row(keep_id) == before
    assert _restart() == {KEEP}


def test_a_removed_host_can_be_added_again(admin):
    """After a removal the same host can be registered again and is listed after a restart."""
    gone_id = _connect(admin, GONE)
    assert _remove(admin, gone_id).status_code == 200

    assert _connect(admin, GONE) == gone_id
    assert _restart() == {GONE}
