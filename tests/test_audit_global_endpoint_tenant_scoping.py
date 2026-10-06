"""Global audit endpoint must scope results by tenant/cluster.

The /api/audit endpoint (unlike /api/audit/search which requires ROLE_ADMIN)
accepts the admin.audit permission, which is granted to tenant-scoped monitoring
and auditor roles. Before this fix, it returned unscoped SELECT * FROM audit_log,
leaking cross-tenant usernames, IPs, actions, and cluster names.

The fix derives the caller's reachable clusters via get_user_clusters and filters
entries to only those clusters, mirroring the cluster-specific audit route's
check_cluster_access and the audit-search endpoint's admin-only gate.

MK Sep 2026, private disclosure.
"""

import pytest
from pegaprox.utils.audit import log_audit

OWNER_TENANT = "acme"  # owns cluster_1
OTHER_TENANT = "globex"  # owns cluster_other
CLUSTER_1 = "cluster_1"
CLUSTER_OTHER = "cluster_other"


@pytest.fixture
def two_tenants_two_clusters(api, seed):
    """Two tenants, each owning one cluster."""
    seed.tenant(OWNER_TENANT, clusters=[CLUSTER_1])
    seed.tenant(OTHER_TENANT, clusters=[CLUSTER_OTHER])

    # Set up cluster managers with names
    m1 = api.make_fake_manager(cluster_id=CLUSTER_1)
    m1.config.name = "Cluster One"
    api.set_manager(CLUSTER_1, m1)

    m2 = api.make_fake_manager(cluster_id=CLUSTER_OTHER)
    m2.config.name = "Cluster Other"
    api.set_manager(CLUSTER_OTHER, m2)

    return CLUSTER_1, CLUSTER_OTHER


@pytest.fixture
def audit_entries(two_tenants_two_clusters):
    """Seed audit log with entries from both clusters and global events."""
    c1, c2 = two_tenants_two_clusters

    # Cluster 1 events
    log_audit(
        "alice",
        "vm.start",
        "Started VM 100",
        cluster="Cluster One",
        ip_address="10.0.1.5",
    )
    log_audit(
        "alice",
        "vm.stop",
        "Stopped VM 101",
        cluster="Cluster One",
        ip_address="10.0.1.5",
    )

    # Cluster Other events (should not be visible to acme tenant users)
    log_audit(
        "bob",
        "vm.start",
        "Started VM 200",
        cluster="Cluster Other",
        ip_address="10.0.2.10",
    )
    log_audit(
        "bob",
        "vm.delete",
        "Deleted VM 201",
        cluster="Cluster Other",
        ip_address="10.0.2.10",
    )

    # Global events (no cluster field)
    log_audit("alice", "user.login", "Login from 10.0.1.5", ip_address="10.0.1.5")
    log_audit("bob", "user.login", "Login from 10.0.2.10", ip_address="10.0.2.10")
    log_audit(
        "admin", "settings.update", "Updated system settings", ip_address="10.0.0.1"
    )


@pytest.fixture
def tenant_auditor(api, seed, two_tenants_two_clusters):
    """Tenant-scoped user with admin.audit permission (the vulnerable case)."""
    return api.as_user(
        seed.user(
            "auditor",
            role="user",
            tenant_id=OWNER_TENANT,
            permissions=["admin.audit", "cluster.view"],
        )
    )


@pytest.fixture
def other_tenant_auditor(api, seed, two_tenants_two_clusters):
    """Auditor from the OTHER tenant."""
    return api.as_user(
        seed.user(
            "bob_auditor",
            role="user",
            tenant_id=OTHER_TENANT,
            permissions=["admin.audit", "cluster.view"],
        )
    )


@pytest.fixture
def global_admin(api, seed, two_tenants_two_clusters):
    """Global admin should see everything."""
    return api.as_user(seed.user("root", role="admin"))


# --------------------------------------------------------------------------
# Tenant-scoped auditor must NOT see other tenants' audit entries
# --------------------------------------------------------------------------


def test_tenant_auditor_cannot_see_other_tenants_cluster_events(
    tenant_auditor, audit_entries
):
    """The vulnerability: tenant-scoped admin.audit holder could export unrelated clusters."""
    r = tenant_auditor.get("/api/audit?limit=100")
    assert r.status_code == 200, r.data

    entries = r.get_json()
    details = " | ".join(e.get("details", "") for e in entries)
    clusters = {e.get("cluster", "") for e in entries}
    users = {e.get("user", "") for e in entries}

    # Must NOT see Cluster Other events
    assert "VM 200" not in details, f"leaked other tenant VM event: {details}"
    assert "VM 201" not in details, f"leaked other tenant VM event: {details}"
    assert (
        "Cluster Other" not in clusters
    ), f"leaked other tenant cluster name: {clusters}"
    assert "bob" not in users, f"leaked other tenant username: {users}"


def test_tenant_auditor_sees_own_cluster_events(tenant_auditor, audit_entries):
    """The functional half: they must still see their own cluster's events."""
    r = tenant_auditor.get("/api/audit?limit=100")
    assert r.status_code == 200, r.data

    entries = r.get_json()
    details = " | ".join(e.get("details", "") for e in entries)

    # Must see Cluster One events
    assert "VM 100" in details, f"lost own cluster events: {details}"
    assert "VM 101" in details, f"lost own cluster events: {details}"


def test_tenant_auditor_sees_own_global_events_only(tenant_auditor, audit_entries):
    """Global events (no cluster field) should be filtered to only the caller's own actions."""
    r = tenant_auditor.get("/api/audit?limit=100")
    assert r.status_code == 200, r.data

    entries = r.get_json()
    global_entries = [e for e in entries if not e.get("cluster")]
    users = {e.get("user", "") for e in global_entries}

    # Should see their own login (alice is in OWNER_TENANT)
    assert "alice" in users, "lost own global events"

    # Must NOT see other users' global events
    assert "bob" not in users, f"leaked other user global events: {users}"
    assert "admin" not in users, f"leaked admin global events: {users}"


def test_csv_export_also_scoped(tenant_auditor, audit_entries):
    """The CSV export path must apply the same scoping."""
    r = tenant_auditor.get("/api/audit?limit=100&format=csv")
    assert r.status_code == 200, r.data

    csv_data = r.get_data(as_text=True)

    # Must NOT contain other tenant data
    assert "VM 200" not in csv_data, "CSV leaked other tenant events"
    assert "Cluster Other" not in csv_data, "CSV leaked other tenant cluster"
    assert "10.0.2.10" not in csv_data, "CSV leaked other tenant IP"

    # Must contain own cluster data
    assert "VM 100" in csv_data, "CSV lost own cluster events"
    assert "Cluster One" in csv_data, "CSV lost own cluster name"


# --------------------------------------------------------------------------
# Global admin must still see everything
# --------------------------------------------------------------------------


def test_global_admin_sees_all_clusters(global_admin, audit_entries):
    """Admins (get_user_clusters → None) must see all entries."""
    r = global_admin.get("/api/audit?limit=100")
    assert r.status_code == 200, r.data

    entries = r.get_json()
    details = " | ".join(e.get("details", "") for e in entries)
    clusters = {e.get("cluster", "") for e in entries if e.get("cluster")}

    # Must see both clusters
    assert "VM 100" in details, "admin lost Cluster One events"
    assert "VM 200" in details, "admin lost Cluster Other events"
    assert "Cluster One" in clusters, "admin lost Cluster One"
    assert "Cluster Other" in clusters, "admin lost Cluster Other"


def test_global_admin_sees_all_global_events(global_admin, audit_entries):
    """Admins must see all global events, not just their own."""
    r = global_admin.get("/api/audit?limit=100")
    assert r.status_code == 200, r.data

    entries = r.get_json()
    global_entries = [e for e in entries if not e.get("cluster")]
    users = {e.get("user", "") for e in global_entries}

    # Must see all users' global events
    assert "alice" in users, "admin lost alice global events"
    assert "bob" in users, "admin lost bob global events"
    assert "admin" in users, "admin lost admin global events"


# --------------------------------------------------------------------------
# Other tenant auditor sees their own scope
# --------------------------------------------------------------------------


def test_other_tenant_auditor_sees_only_their_cluster(
    other_tenant_auditor, audit_entries
):
    """The OTHER tenant's auditor should see Cluster Other, not Cluster One."""
    r = other_tenant_auditor.get("/api/audit?limit=100")
    assert r.status_code == 200, r.data

    entries = r.get_json()
    details = " | ".join(e.get("details", "") for e in entries)
    clusters = {e.get("cluster", "") for e in entries if e.get("cluster")}

    # Must see Cluster Other
    assert "VM 200" in details, "lost own cluster events"
    assert "VM 201" in details, "lost own cluster events"
    assert "Cluster Other" in clusters, "lost own cluster"

    # Must NOT see Cluster One
    assert "VM 100" not in details, "leaked other tenant events"
    assert "VM 101" not in details, "leaked other tenant events"
    assert "Cluster One" not in clusters, "leaked other tenant cluster"


# --------------------------------------------------------------------------
# User/action filters still work with scoping
# --------------------------------------------------------------------------


def test_user_filter_respects_tenant_scope(tenant_auditor, audit_entries):
    """The user filter should work within the tenant scope."""
    r = tenant_auditor.get("/api/audit?user=alice&limit=100")
    assert r.status_code == 200, r.data

    entries = r.get_json()
    users = {e.get("user", "") for e in entries}

    # Should only see alice (and only her events in scope)
    assert users == {"alice"}, f"user filter broken: {users}"

    # Should not see bob even with user filter (he's in other tenant)
    r2 = tenant_auditor.get("/api/audit?user=bob&limit=100")
    assert r2.status_code == 200, r2.data
    entries2 = r2.get_json()
    assert len(entries2) == 0, "user filter bypassed tenant scope"


def test_action_filter_respects_tenant_scope(tenant_auditor, audit_entries):
    """The action filter should work within the tenant scope."""
    r = tenant_auditor.get("/api/audit?action=vm.start&limit=100")
    assert r.status_code == 200, r.data

    entries = r.get_json()
    actions = {e.get("action", "") for e in entries}
    details = " | ".join(e.get("details", "") for e in entries)

    # Should see vm.start actions in own cluster
    assert "vm.start" in actions, "action filter broken"
    assert "VM 100" in details, "lost own cluster vm.start"

    # Should NOT see vm.start from other cluster
    assert "VM 200" not in details, "action filter bypassed tenant scope"
