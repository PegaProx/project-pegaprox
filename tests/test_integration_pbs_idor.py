# Regression: PBS routes must enforce the per-PBS linked-clusters tenant gate.
#
# CodeAnt exploitation finding (2026-07-13): ~20 PBS routes (download_pbs_file, browse_pbs_catalog,
# tasks/jobs/notes/reports/...) reached pbs_managers[pbs_id] with only a role perm and never called
# check_pbs_access — a cross-tenant BOLA (read another tenant's backup files/catalog/metadata),
# made trivial by list_pbs_servers returning every PBS unfiltered. Fixed: check_pbs_access guard on
# each route + a tenant filter on the listing.

from unittest.mock import MagicMock

import pegaprox.globals as ppglobals


def _inject_pbs(pbs_id, linked_clusters):
    m = MagicMock()
    m.linked_clusters = linked_clusters
    m.connected = False
    m.last_status = None
    m.to_dict = lambda: {'id': pbs_id, 'name': pbs_id, 'linked_clusters': linked_clusters,
                         'connected': False}
    ppglobals.pbs_managers[pbs_id] = m
    return m


def test_pbs_tasks_cross_tenant_denied(api, seed):
    ppglobals.pbs_managers.clear()
    seed.tenant('tenant_a', clusters=['cluster_1'])
    seed.tenant('tenant_b', clusters=['cluster_2'])
    alice = seed.user('alice', role='user', tenant_id='tenant_a', permissions=['pbs.tasks.view'])
    _inject_pbs('pbs_b', ['cluster_2'])   # PBS linked to tenant_b's cluster
    try:
        # alice (tenant_a) must NOT reach a PBS linked only to tenant_b's cluster
        r = api.as_user(alice).get('/api/pbs/pbs_b/tasks')
        assert r.status_code == 403, r.get_data(as_text=True)
    finally:
        ppglobals.pbs_managers.clear()
    # (non-over-restriction is covered by test_pbs_list_filtered_by_tenant, where alice DOES
    # see her own tenant's PBS, and test_pbs_admin_sees_everything.)


def test_pbs_download_cross_tenant_denied(api, seed):
    ppglobals.pbs_managers.clear()
    seed.tenant('tenant_a', clusters=['cluster_1'])
    seed.tenant('tenant_b', clusters=['cluster_2'])
    alice = seed.user('alice', role='user', tenant_id='tenant_a',
                      permissions=['pbs.snapshot.browse'])
    _inject_pbs('pbs_b', ['cluster_2'])
    try:
        # the headline finding: cross-tenant backup-file browse must be denied
        r = api.as_user(alice).get('/api/pbs/pbs_b/datastores/store1/catalog')
        assert r.status_code == 403, r.get_data(as_text=True)
    finally:
        ppglobals.pbs_managers.clear()


def test_pbs_list_filtered_by_tenant(api, seed):
    ppglobals.pbs_managers.clear()
    seed.tenant('tenant_a', clusters=['cluster_1'])
    seed.tenant('tenant_b', clusters=['cluster_2'])
    alice = seed.user('alice', role='user', tenant_id='tenant_a', permissions=['pbs.view'])
    _inject_pbs('pbs_a', ['cluster_1'])   # alice's tenant
    _inject_pbs('pbs_b', ['cluster_2'])   # other tenant
    try:
        r = api.as_user(alice).get('/api/pbs')
        assert r.status_code == 200, r.get_data(as_text=True)
        ids = {p['id'] for p in r.get_json()}
        assert 'pbs_a' in ids          # her tenant's PBS is visible
        assert 'pbs_b' not in ids      # the other tenant's PBS is filtered out
    finally:
        ppglobals.pbs_managers.clear()


def test_pbs_admin_sees_everything(api, seed):
    ppglobals.pbs_managers.clear()
    root = seed.user('root', role='admin', tenant_id='default')
    _inject_pbs('pbs_a', ['cluster_1'])
    _inject_pbs('pbs_b', ['cluster_2'])
    try:
        r = api.as_user(root).get('/api/pbs')
        assert r.status_code == 200
        assert {'pbs_a', 'pbs_b'} <= {p['id'] for p in r.get_json()}
    finally:
        ppglobals.pbs_managers.clear()
