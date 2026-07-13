# Regression: cluster-scoped alert push must not fan out cross-tenant.
#
# CodeAnt exploitation finding (2026-07-13): push._alert_handler wrote every alert (cluster/node/
# VM names + live metric %) into EVERY push subscriber's inbox and _wake_all()'d them, with zero
# tenant scoping -> a tenant-A user learned tenant-B cluster events. Fixed: recipients are scoped
# to subscribers who can reach alert_data['cluster_id'] via get_user_clusters (None => admin/
# default-tenant get all; cluster-less system alerts go to all; fail closed on lookup error).
#
# Driven at the handler level (it's a background hook, not an HTTP route): real DB subscriptions,
# real get_user_clusters + seeded tenants; load_users + the delivery sinks are stubbed so we can
# observe exactly who would receive each alert.

import pegaprox.api.push as push
import pegaprox.utils.auth as auth


def _subscribe(db, username):
    db.execute(
        "INSERT INTO push_subscriptions (username, endpoint, p256dh, auth, created_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (username, f'https://push.example/{username}', 'p256', 'authsecret', '2026-01-01T00:00:00'),
    )


def _setup(api, seed, monkeypatch):
    # tenant_a owns cluster_1, tenant_b owns cluster_2, root is a default-tenant admin (sees all)
    seed.tenant('tenant_a', clusters=['cluster_1'])
    seed.tenant('tenant_b', clusters=['cluster_2'])
    for u in ('alice', 'bob', 'root'):
        _subscribe(seed.db, u)
    users_map = {
        'alice': {'tenant_id': 'tenant_a', 'role': 'user'},
        'bob':   {'tenant_id': 'tenant_b', 'role': 'user'},
        'root':  {'tenant_id': 'default',  'role': 'admin'},
    }
    monkeypatch.setattr(auth, 'load_users', lambda: users_map)
    delivered = []
    monkeypatch.setattr(push, '_push_to_inbox', lambda u, *a, **k: delivered.append(u))
    monkeypatch.setattr(push, '_wake_user', lambda u: None)
    monkeypatch.setattr(push, '_wake_all', lambda: delivered.append('__ALL__'))  # trip if the old path runs
    return delivered


def test_cluster_alert_scoped_to_reachable_subscribers(api, seed, monkeypatch):
    delivered = _setup(api, seed, monkeypatch)
    push._alert_handler({'alert_name': 'CPU', 'message': '95%', 'severity': 'warning',
                         'cluster_id': 'cluster_1'})
    assert 'alice' in delivered      # tenant_a owns cluster_1
    assert 'root' in delivered       # admin sees all clusters
    assert 'bob' not in delivered    # tenant_b must NOT learn about cluster_1
    assert '__ALL__' not in delivered  # the unscoped broadcast path must be gone


def test_symmetric_other_tenant(api, seed, monkeypatch):
    delivered = _setup(api, seed, monkeypatch)
    push._alert_handler({'alert_name': 'DISK', 'message': 'full', 'severity': 'critical',
                         'cluster_id': 'cluster_2'})
    assert 'bob' in delivered        # tenant_b owns cluster_2
    assert 'root' in delivered
    assert 'alice' not in delivered  # tenant_a must NOT learn about cluster_2


def test_clusterless_system_alert_reaches_all(api, seed, monkeypatch):
    delivered = _setup(api, seed, monkeypatch)
    push._alert_handler({'alert_name': 'System', 'message': 'update available',
                         'severity': 'info', 'cluster_id': ''})
    for u in ('alice', 'bob', 'root'):
        assert u in delivered        # no cluster => not tenant-scoped


def test_ghost_subscriber_fails_closed(api, seed, monkeypatch):
    # CodeAnt re-scan: a subscription whose user record is MISSING/DELETED (still in
    # push_subscriptions) must NOT be treated as an all-cluster admin and receive every
    # tenant's alerts — it must fail CLOSED.
    delivered = _setup(api, seed, monkeypatch)
    _subscribe(seed.db, 'ghost')   # 'ghost' is NOT in the load_users map (deleted user)
    push._alert_handler({'alert_name': 'CPU', 'message': '95%', 'severity': 'warning',
                         'cluster_id': 'cluster_1'})
    assert 'ghost' not in delivered   # missing record => no cluster-scoped alert (fail closed)
    assert 'alice' in delivered       # a real tenant-a user still gets it
