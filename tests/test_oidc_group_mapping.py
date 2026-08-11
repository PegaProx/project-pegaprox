# Group → role mapping for OIDC logins — oidc_map_groups_to_role().
#
# Custom roles are a first-class choice in the OIDC config: the "Default role" dropdown
# lists every non-builtin role, and the settings validator explicitly accepts them in
# oidc_group_mappings ("NS: Accept custom roles too"). The mapping loop, however, compared
# roles through a hard-coded {viewer: 0, user: 1, admin: 2} table read with
# .get(role, 0) — so every custom role tied with viewer and the strict `>` never fired.
#
# The mapping was therefore skipped while the log line still reported "Custom group mapping
# matched: <group> → role=<role>", which made the failure invisible from the outside: users
# silently landed on oidc_default_role and the logs claimed the mapping had been applied.
#
# These cases pin the resulting order — default < viewer < user < custom < admin — plus the
# rule that a group which actually matched always outranks the bare default. Admin stays on
# top so existing installs that map an admin group cannot be demoted by a custom mapping.
#
# Harness note: oidc_map_groups_to_role() is pure (no DB, no network), so no fixtures.

from pegaprox.models.permissions import ROLE_ADMIN, ROLE_USER, ROLE_VIEWER
from pegaprox.utils.oidc import oidc_map_groups_to_role

CUSTOM_ROLE = 'tenant-operator-lab'

ADMINS = 'a1111111-1111-1111-1111-111111111111'
LAB = 'b2222222-2222-2222-2222-222222222222'
STAFF = 'c3333333-3333-3333-3333-333333333333'


def _cfg(**over):
    cfg = {
        'default_role': ROLE_VIEWER,
        'admin_group_id': '',
        'user_group_id': '',
        'viewer_group_id': '',
        'group_mappings': [],
    }
    cfg.update(over)
    return cfg


def _groups(*ids):
    """Entra-shaped membership list: Graph returns {'id': <guid>, 'name': <displayName>}."""
    return [{'id': g, 'name': f'grp-{g[:4]}'} for g in ids]


def test_custom_role_from_group_mapping_is_applied():
    cfg = _cfg(group_mappings=[{'group_id': LAB, 'role': CUSTOM_ROLE}])
    assert oidc_map_groups_to_role(cfg, _groups(LAB))['role'] == CUSTOM_ROLE


def test_admin_group_is_never_demoted_by_a_custom_mapping():
    cfg = _cfg(admin_group_id=ADMINS,
               group_mappings=[{'group_id': LAB, 'role': CUSTOM_ROLE}])
    assert oidc_map_groups_to_role(cfg, _groups(ADMINS, LAB))['role'] == ROLE_ADMIN


def test_admin_mapping_still_wins_over_a_custom_mapping():
    cfg = _cfg(group_mappings=[
        {'group_id': LAB, 'role': CUSTOM_ROLE},
        {'group_id': ADMINS, 'role': ROLE_ADMIN},
    ])
    assert oidc_map_groups_to_role(cfg, _groups(LAB, ADMINS))['role'] == ROLE_ADMIN


def test_custom_default_role_does_not_swallow_a_matching_mapping():
    cfg = _cfg(default_role=CUSTOM_ROLE,
               group_mappings=[{'group_id': STAFF, 'role': ROLE_VIEWER}])
    assert oidc_map_groups_to_role(cfg, _groups(STAFF))['role'] == ROLE_VIEWER


def test_admin_default_role_is_not_downgraded_by_a_matching_mapping():
    """An install with default_role='admin' must not lose admin on a lower-privilege match.

    The default otherwise loses to any group that matched, but demoting a configured
    admin would lock the install out of admin-only workflows, so admin is exempt.
    """
    for mapped in (ROLE_VIEWER, ROLE_USER, CUSTOM_ROLE):
        cfg = _cfg(default_role=ROLE_ADMIN,
                   group_mappings=[{'group_id': LAB, 'role': mapped}])
        assert oidc_map_groups_to_role(cfg, _groups(LAB))['role'] == ROLE_ADMIN


def test_custom_role_outranks_a_plain_user_mapping():
    cfg = _cfg(group_mappings=[
        {'group_id': STAFF, 'role': ROLE_USER},
        {'group_id': LAB, 'role': CUSTOM_ROLE},
    ])
    assert oidc_map_groups_to_role(cfg, _groups(STAFF, LAB))['role'] == CUSTOM_ROLE


def test_builtin_ladder_is_unchanged():
    cfg = _cfg(group_mappings=[
        {'group_id': STAFF, 'role': ROLE_VIEWER},
        {'group_id': LAB, 'role': ROLE_USER},
    ])
    assert oidc_map_groups_to_role(cfg, _groups(STAFF, LAB))['role'] == ROLE_USER


def test_no_matching_group_keeps_the_default_role():
    cfg = _cfg(default_role=CUSTOM_ROLE,
               group_mappings=[{'group_id': LAB, 'role': ROLE_ADMIN}])
    assert oidc_map_groups_to_role(cfg, _groups(STAFF))['role'] == CUSTOM_ROLE


def test_tenant_and_permissions_from_a_custom_mapping_still_apply():
    """The role fix must not disturb the other fields the same mapping carries."""
    cfg = _cfg(group_mappings=[{
        'group_id': LAB,
        'role': CUSTOM_ROLE,
        'tenant': 'lab-waw',
        'permissions': ['vm.create'],
    }])
    out = oidc_map_groups_to_role(cfg, _groups(LAB))
    assert out['role'] == CUSTOM_ROLE
    assert out['tenant'] == 'lab-waw'
    assert 'vm.create' in out['permissions']
