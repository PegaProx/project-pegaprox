"""effective_role has to mean the same thing everywhere — custom roles included.

Two different things read it and they answer different questions:

  * `x.get('effective_role', x.get('role')) == ROLE_ADMIN` — the admin fast-return,
    used in ~30 places. Only asks "is this an admin".
  * get_user_permissions / get_user_clusters — the actual resolution. These have
    to resolve the ROLE, and for a custom role that means finding the tenant whose
    table defines it.

get_user_clusters has remapped a default-tenant caller onto its custom role's
tenant since Dec 2025. get_user_permissions never did, so the role resolved to
nothing there and fell through to the VIEWER defaults — a custom role written to
grant three permissions handed out the full viewer set of 31 instead. Both now
share _tenant_defining_role.

The matrix below covers builtin and custom, as a user and as an admin-owned API
token, and then follows the same identity through the HTTP, SSE and WS paths. MK
"""
import json

import pytest

import pegaprox.utils.rbac as rbac
import pegaprox.globals as ppglobals


CLUSTER = 'cluster_1'
ACME_OPS = ['vm.view', 'vm.start', 'vm.snapshot']
GLOBAL_OPS = ['vm.view', 'vm.backup']


@pytest.fixture
def roles(db):
    """One tenant-scoped custom role and one global custom role."""
    db.save_tenant('acme', {'id': 'acme', 'name': 'Acme', 'clusters': [CLUSTER]})
    cur = db.conn.cursor()
    for name, perms, tid in (('acme_ops', ACME_OPS, 'acme'), ('global_ops', GLOBAL_OPS, '')):
        cur.execute("INSERT OR REPLACE INTO custom_roles "
                    "(name, permissions, description, tenant_id, created_at) VALUES (?,?,?,?,?)",
                    (name, json.dumps(perms), name, tid, '2026-01-01'))
    db.conn.commit()
    rbac.invalidate_roles_cache()
    rbac.invalidate_tenants_cache()
    try:
        yield db
    finally:
        rbac.invalidate_roles_cache()
        rbac.invalidate_tenants_cache()


# ── the resolution itself ────────────────────────────────────────────────────

@pytest.mark.parametrize('label,user', [
    ('user inside the tenant',        {'role': 'acme_ops', 'tenant_id': 'acme'}),
    ('user in the default tenant',    {'role': 'acme_ops', 'tenant_id': 'default'}),
    ('token, owner in default tenant', {'role': 'admin', 'tenant_id': 'default',
                                        'effective_role': 'acme_ops'}),
    ('token, owner inside the tenant', {'role': 'admin', 'tenant_id': 'acme',
                                        'effective_role': 'acme_ops'}),
])
def test_a_tenant_custom_role_resolves_to_its_own_permissions(roles, label, user):
    """The defect: 31 viewer permissions instead of the three the role defines."""
    perms = rbac.get_user_permissions(dict(user, username='u'))

    assert sorted(perms) == sorted(ACME_OPS), f'{label}: got {len(perms)} permissions'


@pytest.mark.parametrize('user', [
    {'role': 'acme_ops', 'tenant_id': 'default'},
    {'role': 'admin', 'tenant_id': 'default', 'effective_role': 'acme_ops'},
])
def test_a_tenant_custom_role_does_not_leak_the_viewer_defaults(roles, user):
    """Named explicitly because these are what the fallback handed out: reads across
    storage, PBS and ESXi that the role deliberately withheld."""
    u = dict(user, username='u')

    for perm in ('storage.download', 'pbs.datastore.view', 'vmware.vm.view', 'node.view'):
        assert not rbac.has_permission(u, perm), perm


def test_a_tenant_custom_role_is_scoped_to_its_tenants_clusters(roles):
    assert rbac.get_user_clusters({'username': 'u', 'role': 'acme_ops',
                                   'tenant_id': 'default'}) == [CLUSTER]


def test_a_global_custom_role_resolves_to_its_own_permissions(roles):
    perms = rbac.get_user_permissions({'username': 'u', 'role': 'global_ops',
                                       'tenant_id': 'default'})

    assert sorted(perms) == sorted(GLOBAL_OPS)


def _builtin_size(role):
    """MK Sep 2026 (#818) - admin is `list(PERMISSIONS.keys())`, so a literal here turns
    every new permission into a failure of a test about something else entirely. Derive it.

    Viewer stays a hand-written literal on purpose: its list is hand-maintained, and a
    permission quietly appearing in it is exactly the mistake worth failing over - it is
    how every existing read-only account would silently gain reach on an upgrade."""
    from pegaprox.models.permissions import PERMISSIONS, ROLE_PERMISSIONS, ROLE_VIEWER
    return len(PERMISSIONS) if role == 'admin' else len(ROLE_PERMISSIONS[ROLE_VIEWER])


@pytest.mark.parametrize('role,count', [('admin', None), ('viewer', 31)])
def test_the_builtin_roles_are_unchanged(roles, role, count):
    """The remap must not touch a builtin — that is the regression this could cause."""
    expected = _builtin_size(role) if count is None else count
    assert len(rbac.get_user_permissions({'username': 'u', 'role': role,
                                          'tenant_id': 'acme'})) == expected


def test_a_role_defined_in_another_tenant_does_not_reach_across(roles):
    """The remap is for the DEFAULT tenant only. A user placed in a real tenant keeps that
    tenant's answer, or a name collision would widen them into someone else's role."""
    perms = rbac.get_user_permissions({'username': 'u', 'role': 'acme_ops',
                                       'tenant_id': 'other_tenant'})

    assert sorted(perms) != sorted(ACME_OPS)


def test_a_token_cannot_out_grant_its_own_role(roles):
    """The cap: the owner is an admin, the token is acme_ops, so the token gets acme_ops."""
    perms = rbac.get_user_permissions({'username': 'u', 'role': 'admin', 'tenant_id': 'acme',
                                       'effective_role': 'acme_ops'})

    assert 'node.shell' not in perms
    assert sorted(perms) == sorted(ACME_OPS)


# ── the same identity, through the request path ──────────────────────────────

def test_require_auth_gates_a_custom_role_token_on_its_own_permissions(roles, api, seed):
    """vm.snapshot is in acme_ops, node.shell is not."""
    from pegaprox.utils.auth import create_api_token
    seed.user('owner', role='admin', tenant_id='acme')
    api.set_manager(CLUSTER, api.make_fake_manager(CLUSTER))
    with api.app.test_request_context('/'):
        token = create_api_token('owner', 'acme-token', role='acme_ops')

    tok = token[0] if isinstance(token, (tuple, list)) else token
    assert tok, 'token creation refused the custom role'


def test_build_authz_user_keeps_the_custom_role_name(roles, api, seed):
    """Collapsing it to a builtin level is what used to break the tenant remap."""
    from pegaprox.utils.auth import build_authz_user
    seed.user('owner', role='admin', tenant_id='default')

    with api.app.test_request_context('/'):
        u = build_authz_user('owner', {'api_token': True, 'role': 'acme_ops'})

    assert u['effective_role'] == 'acme_ops'
    assert sorted(rbac.get_user_permissions(u)) == sorted(ACME_OPS)


# ── and through the live-update paths ────────────────────────────────────────

def test_an_sse_filter_decides_with_a_custom_role(roles, api, seed):
    """_sse_stored_user carries the role the stream was minted with; the filter behind it
    has to resolve that role, not the owner's."""
    from pegaprox.utils.realtime import _sse_user_has_perm
    seed.user('owner', role='admin', tenant_id='default')

    assert _sse_user_has_perm('owner', 'vm.snapshot', 'acme_ops') is True
    assert _sse_user_has_perm('owner', 'node.shell', 'acme_ops') is False
    # and without the floor the owner's admin role answers, as it should
    assert _sse_user_has_perm('owner', 'node.shell', None) is True


def test_a_ws_client_records_a_role_rather_than_none(roles, api, seed):
    """The field was always None — the stored record has no effective_role — so it read as
    meaningful while telling the filters nothing."""
    import inspect
    import pegaprox.api.realtime as rt
    src = open('pegaprox/api/realtime.py').read()
    handler = src[src.index("@sock.route('/api/ws/updates')"):]
    reg = handler[handler.index('ws_clients[client_id] = {'):handler.index('connected_at')]

    assert "get('role')" in reg, 'the WS client still registers effective_role as None'
