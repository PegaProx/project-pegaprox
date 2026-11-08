# Regression: DR-drill endpoints must enforce access to the plan's clusters.
#
# CodeAnt exploitation finding (IDOR): start_drill / get_drill / list_drills only had a
# site_recovery.* role perm and never checked that the caller could reach the plan's source/
# target clusters — so any site_recovery holder could trigger a DR drill on, or read the drill
# history of, ANOTHER tenant's plan. Fixed with a per-plan check_cluster_access gate.


def _seed_plan(seed, plan_id, cluster):
    seed.db.execute(
        "INSERT INTO site_recovery_plans (id, group_id, name, source_cluster, target_cluster) "
        "VALUES (?, ?, ?, ?, ?)",
        (plan_id, 'g1', plan_id, cluster, cluster),
    )


def test_dr_drill_start_cross_tenant_denied(api, seed):
    seed.tenant('tenant_a', clusters=['cluster_1'])
    seed.tenant('tenant_b', clusters=['cluster_2'])
    bob = seed.user('bob', role='user', tenant_id='tenant_b',
                    permissions=['site_recovery.failover'])
    _seed_plan(seed, 'plan_a', 'cluster_1')   # plan on tenant_a's cluster
    # bob (tenant_b) must NOT be able to trigger a drill on tenant_a's plan
    r = api.as_user(bob).post('/api/site-recovery/plans/plan_a/drill', json={})
    assert r.status_code == 403, r.get_data(as_text=True)


def test_dr_drill_list_cross_tenant_denied(api, seed):
    seed.tenant('tenant_a', clusters=['cluster_1'])
    seed.tenant('tenant_b', clusters=['cluster_2'])
    bob = seed.user('bob', role='user', tenant_id='tenant_b',
                    permissions=['site_recovery.view'])
    _seed_plan(seed, 'plan_a', 'cluster_1')
    r = api.as_user(bob).get('/api/site-recovery/plans/plan_a/drills')
    assert r.status_code == 404, r.get_data(as_text=True)   # 404: don't confirm existence


def test_dr_drill_list_owner_allowed(api, seed):
    # positive control: the plan's own tenant is not over-restricted
    seed.tenant('tenant_a', clusters=['cluster_1'])
    alice = seed.user('alice', role='user', tenant_id='tenant_a',
                      permissions=['site_recovery.view'])
    _seed_plan(seed, 'plan_a', 'cluster_1')
    r = api.as_user(alice).get('/api/site-recovery/plans/plan_a/drills')
    assert r.status_code == 200, r.get_data(as_text=True)
