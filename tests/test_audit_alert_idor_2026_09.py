# Full-stack E2E for the 2026-09 audit alert-rule finding: POST /api/alerts (global alert rules) was
# gated only by the delegatable alert.manage perm, so a tenant-scoped holder could create alert rules
# against clusters they can't reach. It now enforces check_cluster_access on the target cluster.
#
# NB (adversarial verification refinement): the audit also flagged PUT/DELETE /api/alerts/<id> as an
# IDOR. On this branch the GLOBAL alert store does not round-trip — a created global alert can't be
# reloaded by id (load_alerts_config reads the cluster_alerts/legacy tables, which save_alerts_config
# does not repopulate symmetrically), so update/delete always 404 before touching data → the IDOR is
# not practically reachable. The gates were still added to those handlers as defense-in-depth, and the
# actually-used editable path — the cluster-scoped /api/clusters/<id>/alerts — was already gated. So
# the reachable, testable fix is the create path below.


def _confined_manager(seed):
    # a delegated alert.manage holder confined to cluster_1 (tenant owns only cluster_1)
    seed.tenant('tenant_x', clusters=['cluster_1'])
    return seed.user('ann', role='viewer', tenant_id='tenant_x', permissions=['alert.manage'])


def test_create_alert_for_unreachable_cluster_denied(api, seed):
    ann = _confined_manager(seed)
    resp = api.as_user(ann).post('/api/alerts', json={'name': 'x', 'cluster_id': 'cluster_2'})
    assert resp.status_code == 403, resp.get_data(as_text=True)


def test_create_alert_for_own_cluster_allowed(api, seed):
    ann = _confined_manager(seed)
    resp = api.as_user(ann).post('/api/alerts', json={'name': 'mine', 'cluster_id': 'cluster_1'})
    assert resp.status_code == 201, resp.get_data(as_text=True)


def test_admin_can_create_any_cluster_alert(api, seed):
    admin = seed.user('root', role='admin')
    resp = api.as_user(admin).post('/api/alerts', json={'name': 'a', 'cluster_id': 'cluster_2'})
    assert resp.status_code == 201, resp.get_data(as_text=True)
