"""The per-VM token ceiling and the permission list must resolve a role the same way.

_within_token_role is the ceiling user_can_access_vm applies to an API token: whatever the
object grants say, the token may not exceed the role it was minted with. It asked
get_role_permissions_for_user for the CALLER'S OWN tenant. get_user_permissions asks
_tenant_defining_role first, because an account can hold a tenant-scoped custom role while
sitting in the default tenant — that remap is the whole reason the helper exists.

So for a token minted with a tenant custom role, held by a default-tenant owner, the two
disagreed outright. Measured before the fix: the permission list resolved 'ops' to
vm.view/vm.start/vm.config, while this ceiling resolved it to NOTHING — so the route gate
said yes and the object gate said no to every per-VM operation. A custom-role token could
not touch a single guest.

It failed closed, so it looked like "tokens are broken" rather than like a hole. But two
resolvers that disagree are the shape of the bug this campaign keeps finding, and the
ceiling has to mean what its docstring says: capped to what that role grants.

The owner ceiling still applies on top (_token_owner_capped, in get_user_permissions), so
none of this can lift a token above the account that minted it — the last test pins that.

MK
"""
import pytest

import pegaprox.utils.rbac as rbac

CUSTOM = 'ops'
GRANTS = ['vm.view', 'vm.start', 'vm.config']


@pytest.fixture(autouse=True)
def estate(monkeypatch):
    monkeypatch.setattr(rbac, 'get_custom_roles', lambda: {
        'global': {}, 'tenants': {'tenant_a': {CUSTOM: {'permissions': list(GRANTS)}}}})
    monkeypatch.setattr(rbac, 'tenants_db', {
        rbac.DEFAULT_TENANT_ID: {'id': rbac.DEFAULT_TENANT_ID, 'clusters': []},
        'tenant_a': {'id': 'tenant_a', 'clusters': ['cluster_a']},
    }, raising=False)


def _token(owner_role='admin', tenant_id=None):
    return {'username': 'robin', 'role': owner_role,
            'tenant_id': tenant_id or rbac.DEFAULT_TENANT_ID,
            'effective_role': CUSTOM, '_token_owner_capped': True}


@pytest.mark.parametrize('perm', GRANTS)
def test_the_ceiling_allows_what_the_custom_role_grants(perm):
    assert rbac._within_token_role(_token(), perm) is True, \
        f'the ceiling denied {perm}, which the token\'s own role grants'


@pytest.mark.parametrize('perm', ['vm.delete', 'cluster.config', 'admin.users'])
def test_the_ceiling_still_denies_what_it_does_not(perm):
    """The counterweight — this is a ceiling, not a bypass."""
    assert rbac._within_token_role(_token(), perm) is False


def test_the_ceiling_and_the_permission_list_agree():
    """The property that was actually broken: one identity, two answers."""
    tok = _token()
    for perm in GRANTS + ['vm.delete', 'cluster.config']:
        assert rbac._within_token_role(tok, perm) == (perm in rbac.get_user_permissions(tok)), \
            f'ceiling and permission list disagree about {perm}'


def test_an_account_placed_in_the_roles_tenant_is_unaffected():
    assert rbac._within_token_role(_token(tenant_id='tenant_a'), 'vm.start') is True


def test_an_unreduced_session_is_still_a_no_op():
    """No effective_role, or one equal to the stored role — the ceiling must not engage."""
    assert rbac._within_token_role({'role': 'viewer'}, 'vm.delete') is True
    assert rbac._within_token_role({'role': CUSTOM, 'effective_role': CUSTOM}, 'vm.delete') is True


def test_a_builtin_capped_token_is_unchanged():
    tok = {'username': 'robin', 'role': 'admin', 'tenant_id': rbac.DEFAULT_TENANT_ID,
           'effective_role': 'viewer'}
    assert rbac._within_token_role(tok, 'vm.view') is True
    assert rbac._within_token_role(tok, 'vm.delete') is False
