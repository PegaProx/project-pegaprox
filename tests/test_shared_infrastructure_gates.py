"""Reaching one linked cluster is not authority over shared infrastructure.

check_pbs_access answers "does the caller reach ONE of this PBS server's linked
clusters". That is the right question for reading a backup list and the wrong one for
garbage collection, prune, verify, datastore creation/removal, job management and host
upgrades: a PBS backing up three tenants' clusters is shared, and those actions hit all
of it. A tenant operator with one linked cluster to their name was reaching every one of
them - GC and prune destroy data other tenants own, and an upgrade with reboot takes the
backup target away from everyone.

The same shape in multi_sdn.py: check_cluster_access admits an ACL/pool-scoped caller by
design, deferring the decision downstream, and for a vnet there is no downstream. A
portal user with a single VM ACL could create, edit, apply and delete cross-cluster EVPN
spans.

Aikido ai_pentest 700487583 / 700487642 / 700489113 / 700487790. MK
"""
import json

import pytest

import pegaprox.api.pbs as pbsapi
import pegaprox.utils.rbac as rbac
import pegaprox.globals as ppglobals


class _FakePbs:
    def __init__(self, linked):
        self.linked_clusters = list(linked)
        self.name = 'pbs1'
        self.gc_calls = []

    def start_gc(self, store):
        self.gc_calls.append(store)
        return {'data': 'UPID:...'}


@pytest.fixture
def pbs(monkeypatch):
    """A PBS server linked to two clusters - one per tenant."""
    mgr = _FakePbs(['cluster_a', 'cluster_b'])
    monkeypatch.setitem(ppglobals.pbs_managers, 'pbs1', mgr)
    yield mgr
    ppglobals.pbs_managers.pop('pbs1', None)


def _tenant_operator(seed, tenant='tenant_a', clusters=('cluster_a',)):
    """An ordinary, unconfined operator - but only one of the two linked clusters."""
    seed.tenant(tenant, list(clusters))
    return seed.user('ops', role='user', tenant_id=tenant,
                     permissions=['pbs.view', 'pbs.datastore.gc', 'pbs.datastore.view',
                                  'cluster.view'])


def test_a_tenant_operator_cannot_gc_a_shared_datastore(api, db, seed, pbs):
    """GC deletes chunks no longer referenced - across the whole datastore, including
    the other tenant's backups."""
    u = _tenant_operator(seed)

    r = api.as_user(u).post('/api/pbs/pbs1/datastores/store1/gc')

    assert r.status_code == 403, r.get_data(as_text=True)
    assert pbs.gc_calls == [], "GC ran on a datastore shared with another tenant"


def test_the_same_operator_may_gc_when_they_hold_every_linked_cluster(api, db, seed, pbs):
    """The single-tenant install - which is most of them - keeps working."""
    u = _tenant_operator(seed, clusters=('cluster_a', 'cluster_b'))

    r = api.as_user(u).post('/api/pbs/pbs1/datastores/store1/gc')

    assert r.status_code == 200, r.get_data(as_text=True)
    assert pbs.gc_calls == ['store1']


def test_an_admin_is_unaffected(api, db, seed, pbs):
    admin = seed.user('root', role='admin')

    r = api.as_user(admin).post('/api/pbs/pbs1/datastores/store1/gc')

    assert r.status_code == 200, r.get_data(as_text=True)


def test_an_acl_scoped_caller_is_refused_even_on_their_own_cluster(api, db, seed, pbs):
    """Holding every linked cluster is not the same as being unconfined on them."""
    rbac.invalidate_vm_acls_cache()
    seed.tenant('tenant_a', ['cluster_a', 'cluster_b'])
    u = seed.user('portal', role='user', tenant_id='tenant_a',
                  permissions=['pbs.view', 'pbs.datastore.gc', 'cluster.view'])
    seed.vm_acl('cluster_a', 100, ['portal'])
    rbac.invalidate_vm_acls_cache()

    r = api.as_user(u).post('/api/pbs/pbs1/datastores/store1/gc')

    assert r.status_code == 403, r.get_data(as_text=True)
    assert pbs.gc_calls == []


# --- linked_clusters is authorization-bearing ---------------------------------

def test_omitting_linked_clusters_on_update_does_not_clear_them(db):
    """An empty list makes the PBS reachable by EVERYONE ("backward compatibility"),
    so silently clearing it on an update that never mentioned the field was a grant."""
    from pegaprox.core.pbs import save_pbs_server

    save_pbs_server('pbs9', {'name': 'p', 'host': 'h', 'user': 'root@pam',
                             'linked_clusters': ['cluster_a']})
    save_pbs_server('pbs9', {'name': 'renamed', 'host': 'h', 'user': 'root@pam'})

    cur = db.conn.cursor()
    cur.execute("SELECT name, linked_clusters FROM pbs_servers WHERE id='pbs9'")
    name, linked = cur.fetchone()
    assert name == 'renamed', "the update did not apply"
    assert json.loads(linked) == ['cluster_a'], "the linkage was silently cleared"


def test_an_explicit_empty_list_still_clears_them(db):
    """Unlinking has to stay possible - omission and an explicit [] are different things."""
    from pegaprox.core.pbs import save_pbs_server

    save_pbs_server('pbs9', {'name': 'p', 'host': 'h', 'user': 'root@pam',
                             'linked_clusters': ['cluster_a']})
    save_pbs_server('pbs9', {'name': 'p', 'host': 'h', 'user': 'root@pam',
                             'linked_clusters': []})

    cur = db.conn.cursor()
    cur.execute("SELECT linked_clusters FROM pbs_servers WHERE id='pbs9'")
    assert json.loads(cur.fetchone()[0]) == []

