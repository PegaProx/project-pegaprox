"""An unreadable tenant table must not hand anyone the whole estate.

load_tenants() answered the same thing for "no tenants configured" and "the read
failed": it invented a default tenant and returned it. The default tenant's empty
cluster list is the one value that means ALL clusters, so every default-tenant user
got the full estate for as long as the table stayed unreadable. Worse, the invented
tenant was written straight back with save_tenants(), so a transient read error
permanently erased an operator's confinement of the default tenant - the fail-open
outlived the failure that caused it.

A tenant with no clusters already answered [] (LW changed that years ago, deliberately).
The unreadable case now matches it. Same shape as the VM-ACL and custom-role snapshots.

Aikido ai_pentest, rbac.py cluster. MK
"""
import pytest

import pegaprox.utils.rbac as rbac


class _Store:
    """A tenant table that can be told how to misbehave."""

    def __init__(self, rows=None, boom=False):
        self._rows = rows
        self._boom = boom
        self.written = []

    def get_all_tenants(self):
        if self._boom:
            raise OSError('database is locked')
        return list(self._rows or [])

    def save_all_tenants(self, rows):
        self.written.append([r.get('id') for r in rows])

    def query(self, *a, **kw):
        return []

    def get_user_pool_clusters(self, *a, **kw):
        return []


@pytest.fixture
def store(monkeypatch):
    def _install(**kw):
        s = _Store(**kw)
        monkeypatch.setattr(rbac, 'get_db', lambda: s)
        monkeypatch.setattr(rbac, 'tenants_db', {})
        return s

    return _install


def _default_user():
    return {'username': 'bob', 'role': 'user', 'tenant_id': rbac.DEFAULT_TENANT_ID}


# --- the loader tells the two cases apart --------------------------------------

def test_a_failed_read_is_marked_unavailable(store):
    store(boom=True)

    assert rbac.store_unavailable(rbac.load_tenants())


def test_an_empty_table_is_not_marked_unavailable(store):
    store(rows=[])

    assert not rbac.store_unavailable(rbac.load_tenants())


def test_a_failed_read_writes_nothing_back(store):
    """The invented default used to overwrite the stored one, cluster list and all."""
    s = store(boom=True)

    rbac.load_tenants()

    assert s.written == []


def test_a_fresh_install_still_gets_its_default_tenant(store):
    s = store(rows=[])

    tenants = rbac.load_tenants()

    assert rbac.DEFAULT_TENANT_ID in tenants
    assert s.written == [[rbac.DEFAULT_TENANT_ID]]


# --- what the caller is told ---------------------------------------------------

def test_a_default_tenant_user_gets_no_clusters_while_the_store_is_down(store):
    store(boom=True)

    assert rbac.get_user_clusters(_default_user()) == []


def test_a_confined_default_tenant_is_still_honoured(store):
    store(rows=[{'id': rbac.DEFAULT_TENANT_ID, 'name': 'Default', 'clusters': ['c1']}])

    assert rbac.get_user_clusters(_default_user()) == ['c1']


def test_a_genuinely_unconfined_default_tenant_still_sees_everything(store):
    store(rows=[{'id': rbac.DEFAULT_TENANT_ID, 'name': 'Default', 'clusters': []}])

    assert rbac.get_user_clusters(_default_user()) is None


def test_a_scoped_tenant_user_was_already_fail_closed_and_stays_that_way(store):
    store(boom=True)

    user = {'username': 'carol', 'role': 'user', 'tenant_id': 'tenant-b'}
    assert rbac.get_user_clusters(user) == []


def test_a_global_admin_is_not_locked_out_by_an_unreadable_table(store):
    """Whoever has to go and fix the database must still be able to reach it."""
    store(boom=True)

    admin = {'username': 'root', 'role': rbac.ROLE_ADMIN, 'tenant_id': rbac.DEFAULT_TENANT_ID}
    assert rbac.get_user_clusters(admin) is None


def test_a_failed_read_is_never_cached(store):
    """A cached failure would outlive the outage the way the saved default used to."""
    s = store(boom=True)
    rbac.get_user_clusters(_default_user())

    assert not rbac.tenants_db

    s._boom = False
    s._rows = [{'id': rbac.DEFAULT_TENANT_ID, 'name': 'Default', 'clusters': ['c1']}]
    assert rbac.get_user_clusters(_default_user()) == ['c1']
