"""A custom-role table that did not load must not be written back over the real one.

save_custom_roles() begins with `DELETE FROM custom_roles` and rewrites the table from
the snapshot it is handed. load_custom_roles() answered `{'global': {}, 'tenants': {}}`
for a failed read, and get_custom_roles() caches the FIRST answer forever - it has no
TTL, only an explicit invalidate. So a DB blip at the wrong moment pinned an empty role
map for the life of the process, every custom-role account resolved to nothing, and the
next role create/update/delete wrote that emptiness back: every custom role in the
installation, in every tenant, gone.

Aikido ai_pentest 700489535 names the role-template route specifically; all four write
paths share the same snapshot. MK
"""
import pytest

import pegaprox.utils.rbac as rbac


@pytest.fixture
def broken_roles(db, monkeypatch):
    """Only the custom_roles SELECT fails; the writes still work."""
    rbac.invalidate_roles_cache()
    real_conn = db.conn

    class _Cursor:
        def __init__(self, inner):
            self._inner = inner
        def execute(self, sql, *a, **kw):
            if 'SELECT' in sql.upper() and 'custom_roles' in sql:
                raise RuntimeError('database is locked')
            return self._inner.execute(sql, *a, **kw)
        def __getattr__(self, name):
            return getattr(self._inner, name)

    class _Conn:
        def cursor(self):
            return _Cursor(real_conn.cursor())
        def __getattr__(self, name):
            return getattr(real_conn, name)

    class _DB:
        conn = _Conn()
        def __getattr__(self, name):
            return getattr(db, name)

    monkeypatch.setattr(rbac, 'get_db', lambda: _DB())
    yield
    rbac.invalidate_roles_cache()


def _role_names(db):
    cur = db.conn.cursor()
    cur.execute('SELECT name FROM custom_roles')
    return sorted(r[0] for r in cur.fetchall())


def _seed_role(db, name, perms="[]"):
    db.conn.execute("INSERT INTO custom_roles (name, permissions, description, tenant_id, "
                    "created_at) VALUES (?, ?, ?, '', '2026-01-01T00:00:00')",
                    (name, perms, name))
    db.conn.commit()


def test_a_failed_read_is_marked_unavailable(broken_roles):
    assert rbac.store_unavailable(rbac.load_custom_roles()) is True


def test_an_install_with_no_custom_roles_is_not_marked_unavailable(db):
    rbac.invalidate_roles_cache()
    snap = rbac.load_custom_roles()
    assert dict(snap) == {'global': {}, 'tenants': {}}
    assert rbac.store_unavailable(snap) is False


def test_a_failed_read_is_never_pinned_in_the_cache(broken_roles):
    """This cache has no TTL - a poisoned entry would last until the next restart."""
    rbac.get_custom_roles()
    assert rbac._custom_roles_cache is None


def test_the_writer_refuses_a_snapshot_that_never_loaded(db, broken_roles):
    _seed_role(db, 'tenant-operator')
    _seed_role(db, 'billing-readonly')

    snapshot = rbac.load_custom_roles()                 # fails -> empty + unavailable
    snapshot['global']['brand-new'] = {'permissions': [], 'name': 'brand-new'}

    assert rbac.save_custom_roles(snapshot) is False
    assert _role_names(db) == ['billing-readonly', 'tenant-operator']


def test_the_writer_still_rewrites_a_snapshot_that_did_load(db):
    rbac.invalidate_roles_cache()
    _seed_role(db, 'tenant-operator')

    snapshot = rbac.load_custom_roles()
    snapshot['global']['brand-new'] = {'permissions': ['vm.view'], 'name': 'brand-new'}

    assert rbac.save_custom_roles(snapshot) is True
    assert _role_names(db) == ['brand-new', 'tenant-operator']


def test_the_writer_still_honours_a_genuine_deletion(db):
    rbac.invalidate_roles_cache()
    _seed_role(db, 'doomed')

    snapshot = rbac.load_custom_roles()
    del snapshot['global']['doomed']

    assert rbac.save_custom_roles(snapshot) is True
    assert _role_names(db) == []
