"""An API token bound to a tenant custom role must not out-scope its owner.

Two places decide what role an API token acts under. build_authz_user does it for the
object-level checks and has KEPT a custom role's name since Aug 2026 — collapsing it to
a builtin makes get_user_clusters skip the custom-role -> tenant remap, fall back to the
default tenant, and answer None, which means every cluster on the installation.

check_cluster_access carried its own inline copy of the same floor, deliberately, so the
cluster hot path would not have to load the whole users table. That copy never got the
carve-out. And it ran on every token request, because require_auth stashes the RAW stored
record in g.current_user — no effective_role on it — so the `'effective_role' not in user`
guard was always true.

The result: the cluster gate and the object gate disagreed, and the cluster gate was the
wider one. A token minted by a user confined to one tenant's clusters could read them all.

Both now go through auth.apply_token_role.

Aikido ai_pentest 700488915. MK
"""
import contextlib

import pytest

import pegaprox.utils.rbac as rbac
from pegaprox.api.helpers import check_cluster_access
from pegaprox.utils.auth import build_authz_user


CUSTOM = 'ops'


@pytest.fixture(autouse=True)
def estate(api, monkeypatch):
    # depends on `api` so it is torn up AFTER that fixture has reset the process
    # globals - otherwise the tenant table below is cleared out from under us
    """`ops` is defined by tenant_a. robin holds it while sitting in the default tenant —
    the configuration the custom-role -> tenant remap exists to serve."""
    monkeypatch.setattr(rbac, 'get_custom_roles', lambda: {
        'global': {},
        'tenants': {'tenant_a': {CUSTOM: {'permissions': ['vm.view', 'cluster.view']}}},
    })
    monkeypatch.setattr(rbac, 'tenants_db', {
        rbac.DEFAULT_TENANT_ID: {'id': rbac.DEFAULT_TENANT_ID, 'clusters': []},
        'tenant_a': {'id': 'tenant_a', 'clusters': ['cluster_a']},
        'tenant_b': {'id': 'tenant_b', 'clusters': ['cluster_b']},
    }, raising=False)


def _stored_robin():
    """What require_auth puts in g.current_user: the raw record, no effective_role."""
    return {'username': 'robin', 'role': CUSTOM, 'tenant_id': rbac.DEFAULT_TENANT_ID,
            'enabled': True}


@contextlib.contextmanager
def _token_request(api, path='/'):
    from flask import request as _rq, g as _g
    with api.app.test_request_context(path, base_url='http://localhost'):
        _rq.session = {'user': 'robin', 'role': CUSTOM, 'api_token': True}
        _g.current_user = _stored_robin()
        yield


# --- the shared decision ----------------------------------------------------------

def test_the_shared_helper_keeps_a_custom_role_name():
    from pegaprox.utils.auth import apply_token_role
    assert apply_token_role(_stored_robin(), CUSTOM)['effective_role'] == CUSTOM


def test_the_shared_helper_still_floors_a_builtin_role():
    from pegaprox.utils.auth import apply_token_role
    admin = {'role': 'admin'}
    assert apply_token_role(admin, 'viewer')['effective_role'] == 'viewer'


def test_a_builtin_token_cannot_outrank_its_owner():
    from pegaprox.utils.auth import apply_token_role
    viewer_owner = {'role': 'viewer'}
    assert apply_token_role(viewer_owner, 'admin')['effective_role'] == 'viewer'


def test_both_deciders_agree_on_the_same_identity(api):
    """The property that was actually broken: two answers for one token."""
    from pegaprox.utils.auth import apply_token_role
    with _token_request(api):
        from flask import request as _rq
        via_authz = build_authz_user('robin', _rq.session).get('effective_role')
    via_helper = apply_token_role(_stored_robin(), CUSTOM).get('effective_role')
    assert via_authz == via_helper == CUSTOM


# --- what that means at the cluster gate -------------------------------------------

def test_the_token_is_confined_to_its_roles_tenant(api):
    with _token_request(api):
        ok, _ = check_cluster_access('cluster_a')
    assert ok is True, 'the token lost access to its own tenant'


def test_the_token_cannot_reach_another_tenants_cluster(api):
    with _token_request(api):
        ok, err = check_cluster_access('cluster_b')
    assert ok is False, 'token read a cluster outside its role\'s tenant'


def test_the_token_reaches_neither_of_the_other_tenants_clusters(api):
    """Measured through the public gate, so this stays meaningful whatever the
    internals are called."""
    with _token_request(api):
        reachable = [c for c in ('cluster_a', 'cluster_b')
                     if check_cluster_access(c)[0]]
    assert reachable == ['cluster_a'], reachable
