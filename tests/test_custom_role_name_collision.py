"""A custom-role name defined by two tenants must not resolve by dict order.

_tenant_defining_role exists because an account can sit in the DEFAULT tenant while
carrying a tenant-scoped custom role — get_user_clusters has remapped for that since
Dec 2025, and get_user_permissions joined it in 75d3a85. The lookup was "first tenant
whose table has this name", and two tenants each defining an `ops` role is an ordinary
thing for an MSP to do. So the same account resolved into tenant A or tenant B
depending on insertion order: permissions AND cluster scope both, and it could flip
across a restart with no configuration change at all.

The trap in fixing it: answering with the default tenant is not the safe direction.
A default tenant with an empty cluster list means ALL clusters (rbac.py, the
`tenant_id == DEFAULT_TENANT_ID` branch), so an ambiguous caller would come out wider
than either candidate rather than narrower. The resolution has to land on a tenant
that does not exist.

Aikido ai_pentest 700487287. MK
"""
import pytest

import pegaprox.utils.rbac as rbac


@pytest.fixture
def two_tenants_one_role_name(monkeypatch):
    """tenant_a and tenant_b both define 'ops', with visibly different grants."""
    roles = {
        'global': {},
        'tenants': {
            'tenant_a': {'ops': {'permissions': ['vm.view', 'vm.start']}},
            'tenant_b': {'ops': {'permissions': ['vm.view', 'vm.delete', 'cluster.config']}},
        },
    }
    monkeypatch.setattr(rbac, 'get_custom_roles', lambda: roles)
    monkeypatch.setattr(rbac, 'tenants_db', {
        rbac.DEFAULT_TENANT_ID: {'id': rbac.DEFAULT_TENANT_ID, 'name': 'Default', 'clusters': []},
        'tenant_a': {'id': 'tenant_a', 'name': 'A', 'clusters': ['cluster_a']},
        'tenant_b': {'id': 'tenant_b', 'name': 'B', 'clusters': ['cluster_b']},
    }, raising=False)
    return roles


@pytest.fixture
def one_tenant_owns_it(monkeypatch):
    """The counterweight: only tenant_a defines 'ops'. This must keep working."""
    roles = {'global': {}, 'tenants': {'tenant_a': {'ops': {'permissions': ['vm.view', 'vm.start']}}}}
    monkeypatch.setattr(rbac, 'get_custom_roles', lambda: roles)
    monkeypatch.setattr(rbac, 'tenants_db', {
        rbac.DEFAULT_TENANT_ID: {'id': rbac.DEFAULT_TENANT_ID, 'name': 'Default', 'clusters': []},
        'tenant_a': {'id': 'tenant_a', 'name': 'A', 'clusters': ['cluster_a']},
    }, raising=False)
    return roles


def _user(role='ops', tenant_id=None):
    return {'username': 'robin', 'role': role,
            'tenant_id': tenant_id or rbac.DEFAULT_TENANT_ID}


# --- the resolver itself ---------------------------------------------------------

def test_a_contested_name_resolves_to_no_tenant(two_tenants_one_role_name):
    got = rbac._tenant_defining_role('ops', rbac.DEFAULT_TENANT_ID)
    assert got not in ('tenant_a', 'tenant_b'), 'picked a tenant by dict order'
    assert got != rbac.DEFAULT_TENANT_ID, 'fell back to the tenant that means "all clusters"'


def test_an_uncontested_name_still_resolves(one_tenant_owns_it):
    assert rbac._tenant_defining_role('ops', rbac.DEFAULT_TENANT_ID) == 'tenant_a'


def test_a_placed_account_is_unaffected_by_the_collision(two_tenants_one_role_name):
    """Someone actually in tenant_a keeps tenant_a's answer — the early return."""
    assert rbac._tenant_defining_role('ops', 'tenant_a') == 'tenant_a'


# --- what the two consumers do with it -------------------------------------------

def test_permissions_of_a_contested_role_are_empty(two_tenants_one_role_name):
    perms = rbac.get_user_permissions(_user())
    assert perms == [], perms
    # specifically: it did not inherit either tenant's grants
    assert 'vm.start' not in perms and 'vm.delete' not in perms


def test_permissions_of_an_uncontested_role_are_the_tenants(one_tenant_owns_it):
    assert sorted(rbac.get_user_permissions(_user())) == ['vm.start', 'vm.view']


def test_cluster_scope_of_a_contested_role_is_nothing(two_tenants_one_role_name):
    """Not None — None is 'every cluster on the installation'."""
    got = rbac.get_user_clusters(_user(), include_pools=False)
    assert got == [], got


def test_cluster_scope_of_an_uncontested_role_is_the_tenants(one_tenant_owns_it):
    assert rbac.get_user_clusters(_user(), include_pools=False) == ['cluster_a']


def test_a_placed_account_keeps_its_clusters_despite_the_collision(two_tenants_one_role_name):
    assert rbac.get_user_clusters(_user(tenant_id='tenant_a'), include_pools=False) == ['cluster_a']


def test_the_collision_is_reported(two_tenants_one_role_name, caplog):
    import logging
    with caplog.at_level(logging.WARNING):
        rbac._tenant_defining_role('ops', rbac.DEFAULT_TENANT_ID)
    msg = caplog.text
    assert 'ops' in msg and 'tenant_a' in msg and 'tenant_b' in msg, msg
