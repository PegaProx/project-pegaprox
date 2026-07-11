# API-token scoping & privilege-floor invariants.
#
# The dangerous case: an ADMIN mints a low-privilege token. If the token carried
# the owner's stored (admin) role into object-level checks, it would silently be
# an admin token. build_authz_user() floors it to effective_role and the whole
# rbac chain (user_can_access_vm:754, has_permission:285, get_user_permissions:260)
# honours effective_role. These tests lock that in.

from pegaprox.utils.rbac import user_can_access_vm, has_permission
from pegaprox.utils.auth import build_authz_user, create_api_token


def test_admin_owned_viewer_token_is_floored_no_admin_bypass(seed):
    seed.user('root', role='admin', tenant_id='default')
    session = {'user': 'root', 'role': 'viewer', 'api_token': True}
    tok_user = build_authz_user('root', session)

    assert tok_user['role'] == 'admin'             # stored account role unchanged
    assert tok_user['effective_role'] == 'viewer'  # floored for this token
    # No admin short-circuit, no role-fallback escalation on VM ops:
    assert user_can_access_vm(tok_user, 'c1', 100, 'vm.start') is False
    # ...but the token still works at its real (viewer) level:
    assert has_permission(tok_user, 'vm.view') is True
    assert has_permission(tok_user, 'vm.start') is False


def test_token_effective_role_floors_to_owner_current_role(seed):
    """min(token_role, owner_role): a 'user' token whose owner was since demoted
    to viewer must act as viewer, not user."""
    seed.user('u', role='viewer', tenant_id='default')
    session = {'user': 'u', 'role': 'user', 'api_token': True}
    tok_user = build_authz_user('u', session)
    assert tok_user['effective_role'] == 'viewer'


def test_session_auth_is_not_floored(seed):
    """Regression guard: the floor is token-only. Plain session auth leaves
    effective_role unset so the real account role applies."""
    seed.user('root', role='admin', tenant_id='default')
    session = {'user': 'root', 'role': 'admin'}  # no api_token flag
    u = build_authz_user('root', session)
    assert 'effective_role' not in u
    assert user_can_access_vm(u, 'c1', 100, 'vm.start') is True


def test_cannot_mint_token_above_owner_role(seed):
    """create_api_token must refuse a token more privileged than its issuer."""
    seed.user('viewer_bob', role='viewer', tenant_id='default')
    res = create_api_token('viewer_bob', 'escalate', role='admin')
    assert 'error' in res

    seed.user('user_carol', role='user', tenant_id='default')
    res2 = create_api_token('user_carol', 'escalate2', role='admin')
    assert 'error' in res2  # non-admins can never mint an admin token


def test_can_mint_token_at_or_below_owner_role(seed):
    seed.user('admin_alice', role='admin', tenant_id='default')
    res = create_api_token('admin_alice', 'ci-readonly', role='viewer', expires_days=1)
    assert 'error' not in res
    assert res.get('token')  # the plaintext token is returned exactly once
