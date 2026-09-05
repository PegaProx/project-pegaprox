"""The invariant every confinement gate rests on.

helpers.require_unconfined is now in front of roughly 130 whole-cluster routes, and
helpers.caller_is_scoped decides for all of them. That makes caller_is_scoped a single point
of failure in both directions: if it ever returns True for an admin, ~130 routes break at once;
if it returns False for an unknown identity, ~130 gates open at once. Pin both directions here
rather than re-deriving them per route.
"""
from pegaprox.api.helpers import caller_is_scoped, require_unconfined


def test_admin_is_never_confined(api, seed):
    seed.tenant('acme', clusters=['cluster_1'])
    with api.app.test_request_context('/'):
        from flask import request
        request.session = {'user': 'root', 'role': 'admin'}
        for tenant in ('acme', 'a-tenant-that-does-not-own-this-cluster'):
            u = {'username': 'root', 'role': 'admin', 'tenant_id': tenant}
            assert caller_is_scoped(u, 'cluster_1') is False, tenant


def test_admin_owned_scoped_token_is_confined(api, seed):
    # the point of the token-flooring work: effective_role beats the stored role
    seed.tenant('acme', clusters=['cluster_1'])
    with api.app.test_request_context('/'):
        from flask import request
        request.session = {'user': 'root', 'role': 'viewer', 'api_token': True}
        u = {'username': 'root', 'role': 'admin', 'effective_role': 'viewer', 'tenant_id': 'acme'}
        assert caller_is_scoped(u, 'cluster_1') is True


def test_unknown_identity_fails_closed(api, seed):
    with api.app.test_request_context('/'):
        from flask import request
        request.session = {'user': '', 'role': 'viewer'}
        assert caller_is_scoped(None, 'cluster_1') is True
        assert caller_is_scoped({}, 'cluster_1') is True


def test_plain_operator_in_the_owning_tenant_is_not_confined(api, seed):
    # a cluster-wide operator is exactly who these routes are FOR — the gate must not touch them
    seed.tenant('acme', clusters=['cluster_1'])
    u = seed.user('ops', role='user', tenant_id='acme', permissions=['cluster.view'])
    with api.app.test_request_context('/'):
        from flask import request
        request.session = {'user': 'ops', 'role': 'user'}
        assert caller_is_scoped(u, 'cluster_1') is False
        assert require_unconfined('cluster_1') is None


def test_require_unconfined_returns_a_403_tuple_not_a_bare_value(api, seed):
    # every call site does `if _cerr: return _cerr`, so the deny path must be a real response
    seed.tenant('tenant_x', clusters=['cluster_1'])
    seed.user('mallory', role='viewer', tenant_id='tenant_x', permissions=['cluster.view'])
    seed.pool('cluster_1', 'pool_1', 'mallory', ['pool.view', 'vm.view'])
    with api.app.test_request_context('/'):
        from flask import request
        request.session = {'user': 'mallory', 'role': 'viewer'}
        err = require_unconfined('cluster_1')
        assert err is not None and err[1] == 403, err
