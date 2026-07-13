# Contract test: every VM-scoped API route must enforce per-VM authorization.
#
# NS Jul 2026 — a full pentest found several per-VM routes (firewall CRUD, disk /
# network / cdrom / serial mutations, guest-file-read, backups list, ...) that
# reached the cluster with only check_cluster_access + a role permission and NEVER
# called user_can_access_vm — the cross-tenant BOLA/IDOR class. Static reviewers did
# not catch it. This test enumerates every /clusters/.../<vmid>/... route from the
# live Flask url_map and asserts each handler references a per-VM authorization gate
# (or is an explicitly-documented exemption). A NEW VM route added without a gate —
# or an old gate silently removed — turns this test red in CI.

import inspect

import pytest

from pegaprox.app import create_app


# Any one of these appearing in a handler's (unwrapped) source counts as "the
# route gates the specific VM object":
_AUTHZ_TOKENS = (
    "_require_vm_access",       # the per-VM helper used by the read + action routes
    "user_can_access_vm",       # inline (start/stop, snapshot/clone/migrate/backup, config-PUT)
    "_console_authz",           # console / VNC / termproxy handlers (separate per-VM gate)
    "_get_vm_config_response",  # the two config-GET routes delegate to this gated responder
)

# Routes that legitimately do NOT perform a per-VM ACL check. Each is here for a
# reason — adding a new VM route to this allowlist must be a conscious decision
# reviewed in the PR, which is exactly the point of the contract.
_EXEMPT = {
    # VM-ACL management itself — gated by admin / user-management permissions, not
    # by the ACL of the VM being edited (you'd need the ACL to edit the ACL):
    "users.get_vm_acl", "users.set_vm_acl", "users.delete_vm_acl",
    # Cluster-admin / pool-admin scoped operations (not per-VM):
    "clusters.add_excluded_vm", "clusters.remove_excluded_vm",
    "clusters.remove_from_proxmox_ha", "static_files.remove_pool_member",
    # Metrics / history / tags on other blueprints — cluster-scoped reads, reviewed
    # in the 2026-07-12 pentest (not confirmed as findings; additive-ACL model):
    "nodes.get_vm_guest_metrics_api", "nodes.set_vm_ha_priority_api",
    "history.check_vm_affinity", "history.get_vm_migration_history",
    "search.get_vm_tags", "search.update_vm_tags", "search.remove_vm_tag",
    # WebSocket console proxy — authorized at the single-use WS-ticket layer, not in
    # the HTTP handler body:
    "__flask_sock.vnc_websocket_proxy", "vms.vnc_websocket_route",
}


def _vm_scoped_rules(app):
    rules = []
    for r in app.url_map.iter_rules():
        p = str(r.rule)
        if "/clusters/" in p and ("<int:vmid>" in p or "<vmid>" in p):
            rules.append(r)
    return rules


@pytest.fixture(scope="module")
def flask_app():
    return create_app()


def _handler_source(app, endpoint):
    view = app.view_functions.get(endpoint)
    if view is None:
        return None
    try:
        return inspect.getsource(inspect.unwrap(view))
    except (OSError, TypeError):
        return None


def test_enumeration_is_not_empty(flask_app):
    # Guard against the url_map matcher silently matching nothing (a refactor could
    # rename the <vmid> converter and quietly disable the whole contract).
    assert len(_vm_scoped_rules(flask_app)) >= 50, (
        "expected many per-VM routes — the enumeration looks broken"
    )


def test_every_vm_route_enforces_per_vm_authz(flask_app):
    ungated = []
    for r in _vm_scoped_rules(flask_app):
        if r.endpoint in _EXEMPT:
            continue
        src = _handler_source(flask_app, r.endpoint)
        if src is None:
            continue
        if not any(tok in src for tok in _AUTHZ_TOKENS):
            ungated.append(f"{r.endpoint}  [{','.join(sorted(m for m in r.methods if m in ('GET','POST','PUT','DELETE','PATCH')))}]  {r.rule}")

    assert not ungated, (
        "VM-scoped route(s) with NO per-VM authorization gate. Add "
        "_require_vm_access(cluster_id, vmid, <perm>, vm_type) after check_cluster_access, "
        "or (if intentionally not per-VM-gated) add the endpoint to _EXEMPT with a reason:\n  "
        + "\n  ".join(sorted(ungated))
    )


def test_exemptions_are_still_real_routes(flask_app):
    # Keep the allowlist honest: an exemption that no longer maps to a route is dead
    # weight (route was renamed/removed) and should be cleaned up.
    live = {r.endpoint for r in _vm_scoped_rules(flask_app)}
    stale = sorted(e for e in _EXEMPT if e not in live)
    assert not stale, f"_EXEMPT lists endpoints that are no longer VM-scoped routes: {stale}"
