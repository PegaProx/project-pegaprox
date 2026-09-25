"""An API token scoped below its owner got the difference back through a VM ACL.

effective_role exists only for API-token auth — utils/auth.build_authz_user sets it
under `if session.get('api_token')`, floored to the owner's current role so a token
can never outrank the account it belongs to. The whole point of minting a
viewer-scoped token on an admin account is that the token is weaker than the
account.

Object grants ignored it. user_can_access_vm's ACL branch returns
`permission in ACL_INHERITED_VM_PERMISSIONS` — a fixed ten-permission set including
vm.config, vm.migrate and vm.delete — as soon as the ACL names the user, and the
pool branch does the same for a pool grant. Both look at the ACL row, not at the
token. So a viewer-scoped token on an account that holds a VM ACL could delete that
VM.

The cap is applied to the RESULT of user_can_access_vm, once, rather than at each
of its five grant points. That is deliberate: the #941 follow-up on the same day
was a lesson in adding a guard to the path you happened to read instead of the
place every path goes through.

And it is a no-op for anything that is not a reduced token, because VM ACLs are
ADDITIVE by design (rbac.py says so in as many words) — capping an ordinary session
by its role would delete the feature instead of fixing a hole. Aikido ai_pentest
700487712. NS
"""
import pytest

from pegaprox.utils.rbac import user_can_access_vm

CLUSTER = 'cluster_1'
VMID = 100


def _acl_user(seed, api, username, role, tenant='default'):
    u = seed.user(username, role=role, tenant_id=tenant)
    seed.vm_acl(CLUSTER, VMID, users=[username], inherit_role=True)
    return u


def test_a_viewer_scoped_token_cannot_delete_through_an_acl(api, seed, db):
    """The finding. The account is an admin; the token is not."""
    seed.tenant('default', clusters=[CLUSTER])
    u = _acl_user(seed, api, 'tokenowner', 'admin')

    token_user = {**u, 'username': 'tokenowner', 'role': 'admin',
                  'effective_role': 'viewer'}

    assert user_can_access_vm(token_user, CLUSTER, VMID, 'vm.view') is True, \
        'the token should still be able to look'
    assert user_can_access_vm(token_user, CLUSTER, VMID, 'vm.delete') is False, \
        'a viewer-scoped token deleted a VM through the owner ACL'
    assert user_can_access_vm(token_user, CLUSTER, VMID, 'vm.config') is False


def test_an_ordinary_session_keeps_its_additive_acl(api, seed, db):
    """The mirror, and the one that matters. VM ACLs are additive on purpose — a
    viewer named in an ACL is supposed to get the inherited VM permissions. Capping
    by role here would remove the feature."""
    seed.tenant('default', clusters=[CLUSTER])
    u = _acl_user(seed, api, 'plainviewer', 'viewer')

    session_user = {**u, 'username': 'plainviewer', 'role': 'viewer'}   # no effective_role

    assert user_can_access_vm(session_user, CLUSTER, VMID, 'vm.config') is True, \
        'an additive ACL stopped being additive'


def test_a_token_at_its_owners_level_is_unaffected(api, seed, db):
    """effective_role == role means the token was not reduced; nothing to cap."""
    seed.tenant('default', clusters=[CLUSTER])
    u = _acl_user(seed, api, 'samelevel', 'user')

    token_user = {**u, 'username': 'samelevel', 'role': 'user', 'effective_role': 'user'}

    assert user_can_access_vm(token_user, CLUSTER, VMID, 'vm.config') is True


def test_an_admin_token_still_short_circuits(api, seed, db):
    seed.tenant('default', clusters=[CLUSTER])
    u = seed.user('boss', role='admin')
    token_user = {**u, 'username': 'boss', 'role': 'admin', 'effective_role': 'admin'}

    assert user_can_access_vm(token_user, CLUSTER, 999, 'vm.delete') is True


def test_the_ceiling_predicate_itself(api, seed, db):
    """The pool branch is covered by construction — the cap is applied to the RESULT
    of user_can_access_vm, so it sits after every grant point rather than beside one
    of them. A separate pool test was written first and then removed: without a
    populated pool-membership cache the pool branch never fires, so it passed against
    the unfixed tree as well, and a test that cannot fail is not evidence.

    This pins the predicate directly instead."""
    from pegaprox.utils.rbac import _within_token_role

    reduced = {'username': 'x', 'role': 'admin', 'effective_role': 'viewer'}
    assert _within_token_role(reduced, 'vm.view') is True
    assert _within_token_role(reduced, 'vm.delete') is False

    ordinary = {'username': 'x', 'role': 'viewer'}          # no token -> never capped
    assert _within_token_role(ordinary, 'vm.delete') is True

    same = {'username': 'x', 'role': 'user', 'effective_role': 'user'}
    assert _within_token_role(same, 'vm.delete') is True
