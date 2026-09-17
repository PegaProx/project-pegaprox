# -*- coding: utf-8 -*-
"""
Test for PBS linked_clusters authorization bypass vulnerability fix.

This test verifies that:
1. Non-admin users cannot clear linked_clusters during update
2. Non-admin users cannot omit linked_clusters during update (preserves existing)
3. Non-admin users cannot add PBS with empty linked_clusters
4. Non-admin users cannot add PBS with out-of-scope cluster IDs
5. Empty linked_clusters denies access to non-admin users (fail closed)
6. Admins can still manage PBS servers with empty linked_clusters
"""

from unittest.mock import MagicMock
import pegaprox.globals as ppglobals


def test_pbs_update_cannot_clear_linked_clusters(api, seed):
    """Non-admin user cannot clear linked_clusters via explicit empty list"""
    seed.tenant("tenant_a", clusters=["cluster_1"])
    user = seed.user(
        "alice",
        role="user",
        tenant_id="tenant_a",
        permissions=["pbs.config", "pbs.view"],
    )

    # Create a PBS linked to cluster_1
    pbs = MagicMock()
    pbs.host = "pbs.example.com"
    pbs.port = 8007
    pbs.linked_clusters = ["cluster_1"]
    pbs.password = "secret"
    pbs.api_token_secret = ""
    pbs.ssh_key = ""
    pbs.name = "test-pbs"
    ppglobals.pbs_managers["pbs1"] = pbs

    try:
        # Attempt to clear linked_clusters
        resp = api.as_user(user).put(
            "/api/pbs/pbs1", json={"name": "test-pbs", "linked_clusters": []}
        )
        assert (
            resp.status_code == 403
        ), f"Expected 403, got {resp.status_code}: {resp.get_data(as_text=True)}"
        assert "must link this PBS" in resp.get_data(as_text=True).lower()
    finally:
        ppglobals.pbs_managers.pop("pbs1", None)


def test_pbs_update_omitted_linked_clusters_preserved(api, seed):
    """When linked_clusters is omitted, existing value is preserved"""
    seed.tenant("tenant_a", clusters=["cluster_1"])
    user = seed.user(
        "alice",
        role="user",
        tenant_id="tenant_a",
        permissions=["pbs.config", "pbs.view"],
    )

    # Create a PBS linked to cluster_1
    pbs = MagicMock()
    pbs.host = "pbs.example.com"
    pbs.port = 8007
    pbs.linked_clusters = ["cluster_1"]
    pbs.password = "secret"
    pbs.api_token_secret = ""
    pbs.ssh_key = ""
    pbs.name = "test-pbs"
    pbs.to_dict = lambda: {
        "id": "pbs1",
        "name": "test-pbs",
        "linked_clusters": ["cluster_1"],
    }
    ppglobals.pbs_managers["pbs1"] = pbs

    try:
        # Update without linked_clusters field - should preserve existing
        resp = api.as_user(user).put(
            "/api/pbs/pbs1", json={"name": "renamed-pbs", "enabled": True}
        )
        # The update should succeed because linked_clusters is preserved
        assert (
            resp.status_code == 200
        ), f"Expected 200, got {resp.status_code}: {resp.get_data(as_text=True)}"
    finally:
        ppglobals.pbs_managers.pop("pbs1", None)


def test_pbs_add_requires_linked_clusters_for_non_admin(api, seed):
    """Non-admin user must provide linked_clusters when adding PBS"""
    seed.tenant("tenant_a", clusters=["cluster_1"])
    user = seed.user(
        "alice",
        role="user",
        tenant_id="tenant_a",
        permissions=["pbs.config", "pbs.view"],
    )

    # Attempt to add PBS without linked_clusters
    resp = api.as_user(user).post(
        "/api/pbs",
        json={
            "name": "new-pbs",
            "host": "pbs.example.com",
            "user": "root@pam",
            "password": "test",
        },
    )
    assert (
        resp.status_code == 403
    ), f"Expected 403, got {resp.status_code}: {resp.get_data(as_text=True)}"
    assert "must link this PBS" in resp.get_data(as_text=True).lower()


def test_pbs_add_rejects_out_of_scope_clusters(api, seed):
    """Non-admin user cannot link PBS to clusters outside their scope"""
    seed.tenant("tenant_a", clusters=["cluster_1"])
    seed.tenant("tenant_b", clusters=["cluster_2"])
    user = seed.user(
        "alice",
        role="user",
        tenant_id="tenant_a",
        permissions=["pbs.config", "pbs.view"],
    )

    # Attempt to add PBS linked to cluster_2 (out of scope)
    resp = api.as_user(user).post(
        "/api/pbs",
        json={
            "name": "new-pbs",
            "host": "pbs.example.com",
            "user": "root@pam",
            "password": "test",
            "linked_clusters": ["cluster_2"],
        },
    )
    assert (
        resp.status_code == 403
    ), f"Expected 403, got {resp.status_code}: {resp.get_data(as_text=True)}"
    assert "access denied" in resp.get_data(as_text=True).lower()


def test_pbs_update_rejects_out_of_scope_clusters(api, seed):
    """Non-admin user cannot change linked_clusters to out-of-scope clusters"""
    seed.tenant("tenant_a", clusters=["cluster_1"])
    seed.tenant("tenant_b", clusters=["cluster_2"])
    user = seed.user(
        "alice",
        role="user",
        tenant_id="tenant_a",
        permissions=["pbs.config", "pbs.view"],
    )

    # Create a PBS linked to cluster_1
    pbs = MagicMock()
    pbs.host = "pbs.example.com"
    pbs.port = 8007
    pbs.linked_clusters = ["cluster_1"]
    pbs.password = "secret"
    pbs.api_token_secret = ""
    pbs.ssh_key = ""
    pbs.name = "test-pbs"
    ppglobals.pbs_managers["pbs1"] = pbs

    try:
        # Attempt to change to cluster_2 (out of scope)
        resp = api.as_user(user).put(
            "/api/pbs/pbs1", json={"name": "test-pbs", "linked_clusters": ["cluster_2"]}
        )
        assert (
            resp.status_code == 403
        ), f"Expected 403, got {resp.status_code}: {resp.get_data(as_text=True)}"
        assert "access denied" in resp.get_data(as_text=True).lower()
    finally:
        ppglobals.pbs_managers.pop("pbs1", None)


def test_empty_linked_clusters_denies_non_admin_access(api, seed):
    """PBS with empty linked_clusters is inaccessible to non-admin users"""
    seed.tenant("tenant_a", clusters=["cluster_1"])
    user = seed.user(
        "alice", role="user", tenant_id="tenant_a", permissions=["pbs.view"]
    )

    # Create a PBS with empty linked_clusters
    pbs = MagicMock()
    pbs.host = "pbs.example.com"
    pbs.port = 8007
    pbs.linked_clusters = []
    pbs.connected = True
    pbs.name = "test-pbs"
    ppglobals.pbs_managers["pbs1"] = pbs

    try:
        # Attempt to access PBS status
        resp = api.as_user(user).get("/api/pbs/pbs1/status")
        assert (
            resp.status_code == 403
        ), f"Expected 403, got {resp.status_code}: {resp.get_data(as_text=True)}"
        assert "access denied" in resp.get_data(as_text=True).lower()
    finally:
        ppglobals.pbs_managers.pop("pbs1", None)


def test_empty_linked_clusters_hidden_from_non_admin_listing(api, seed):
    """PBS with empty linked_clusters is not visible in listing for non-admin users"""
    seed.tenant("tenant_a", clusters=["cluster_1"])
    user = seed.user(
        "alice", role="user", tenant_id="tenant_a", permissions=["pbs.view"]
    )

    # Create two PBS servers: one with empty linked_clusters, one with cluster_1
    pbs_empty = MagicMock()
    pbs_empty.linked_clusters = []
    pbs_empty.connected = True
    pbs_empty.name = "pbs-empty"
    pbs_empty.to_dict = lambda: {
        "id": "pbs1",
        "name": "pbs-empty",
        "linked_clusters": [],
    }
    ppglobals.pbs_managers["pbs1"] = pbs_empty

    pbs_scoped = MagicMock()
    pbs_scoped.linked_clusters = ["cluster_1"]
    pbs_scoped.connected = True
    pbs_scoped.name = "pbs-scoped"
    pbs_scoped.to_dict = lambda: {
        "id": "pbs2",
        "name": "pbs-scoped",
        "linked_clusters": ["cluster_1"],
    }
    ppglobals.pbs_managers["pbs2"] = pbs_scoped

    try:
        resp = api.as_user(user).get("/api/pbs")
        assert resp.status_code == 200
        pbs_list = resp.get_json()
        pbs_names = [p["name"] for p in pbs_list]

        # Only pbs-scoped should be visible
        assert "pbs-scoped" in pbs_names, f"Expected pbs-scoped in {pbs_names}"
        assert (
            "pbs-empty" not in pbs_names
        ), f"pbs-empty should not be visible in {pbs_names}"
    finally:
        ppglobals.pbs_managers.pop("pbs1", None)
        ppglobals.pbs_managers.pop("pbs2", None)


def test_admin_can_access_empty_linked_clusters(api, seed):
    """Admin users can still access PBS with empty linked_clusters"""
    admin = seed.user(
        "admin", role="admin", tenant_id="default", permissions=["pbs.view"]
    )

    # Create a PBS with empty linked_clusters
    pbs = MagicMock()
    pbs.host = "pbs.example.com"
    pbs.port = 8007
    pbs.linked_clusters = []
    pbs.connected = True
    pbs.name = "test-pbs"
    pbs.get_server_status = lambda: {"data": {"cpu": 0.1}}
    ppglobals.pbs_managers["pbs1"] = pbs

    try:
        # Admin should be able to access
        resp = api.as_user(admin).get("/api/pbs/pbs1/status")
        assert (
            resp.status_code == 200
        ), f"Expected 200, got {resp.status_code}: {resp.get_data(as_text=True)}"
    finally:
        ppglobals.pbs_managers.pop("pbs1", None)


def test_admin_can_see_empty_linked_clusters_in_listing(api, seed):
    """Admin users can see PBS with empty linked_clusters in listing"""
    admin = seed.user(
        "admin", role="admin", tenant_id="default", permissions=["pbs.view"]
    )

    # Create a PBS with empty linked_clusters
    pbs = MagicMock()
    pbs.linked_clusters = []
    pbs.connected = True
    pbs.name = "pbs-empty"
    pbs.last_status = None
    pbs.to_dict = lambda: {"id": "pbs1", "name": "pbs-empty", "linked_clusters": []}
    ppglobals.pbs_managers["pbs1"] = pbs

    try:
        resp = api.as_user(admin).get("/api/pbs")
        assert resp.status_code == 200
        pbs_list = resp.get_json()
        pbs_names = [p["name"] for p in pbs_list]

        # Admin should see the PBS
        assert "pbs-empty" in pbs_names, f"Expected pbs-empty in {pbs_names}"
    finally:
        ppglobals.pbs_managers.pop("pbs1", None)
