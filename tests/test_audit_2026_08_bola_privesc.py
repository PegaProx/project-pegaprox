# Regression suite for the 2026-08-17 broad codebase audit (Tier A + Tier B).
#
# The console-BOLA CVE (symplasson) turned out to be one instance of three recurring classes; the
# audit found more instances on handlers the targeted CVE remediation never touched. Each test below
# pins the fix for one finding: the DENY path (the vuln is closed) and, where it isn't cost-prohibitive
# to wire, the ALLOW path (a legitimately-scoped user is NOT over-blocked). See
# ~/Schreibtisch/codebase_security_audit_2026-08-17.md.
#
# Tier A — object-level BOLA (cluster-gate passes → per-resource re-check was missing):
#   #1 bulk_migrate, #2 restore_backup source, #4 proxmox-ha plugin, #5 pbs protect/notes,
#   #11 migration-history, #14 WS cluster subscription, #15 test_pbs_connection.
# Tier B — tenant-delegate privesc / session:
#   #3 update/create_custom_role holder-check, #6 apply_role_template scoping, #7 admin password/2FA
#   role-tier guard, #9 disable-user session revocation + enabled recheck.

import importlib.util
import os
from unittest.mock import MagicMock

import pegaprox.globals as ppglobals
from pegaprox.models.permissions import ROLE_PERMISSIONS, ROLE_USER, ROLE_ADMIN
from pegaprox.utils.rbac import save_custom_roles, invalidate_roles_cache, ROLE_TEMPLATES

DEFAULT = 'default'


# proxmox-ha ships with a hyphen in its dir name (not an importable module path); load it the same
# way the plugin loader does so we can unit-test its object-level gate helper.
_ha_path = os.path.join(os.path.dirname(__file__), '..', 'plugins', 'proxmox-ha', '__init__.py')
_ha_spec = importlib.util.spec_from_file_location('proxmox_ha_plugin_test', _ha_path)
proxmox_ha = importlib.util.module_from_spec(_ha_spec)
_ha_spec.loader.exec_module(proxmox_ha)


def _inject_pbs(pbs_id, linked_clusters):
    m = MagicMock()
    m.linked_clusters = linked_clusters
    m.connected = False
    m.to_dict = lambda: {'id': pbs_id, 'name': pbs_id, 'linked_clusters': linked_clusters}
    ppglobals.pbs_managers[pbs_id] = m
    return m


# ===========================================================================
# Tier A #1 — bulk_migrate must gate each vmid (single-VM twin already did)
# ===========================================================================

def test_bulk_migrate_denies_foreign_vmid_but_migrates_own(api, seed):
    seed.tenant('acme', clusters=['cluster_1'])
    bob = seed.user('bob', role='user', tenant_id='acme', permissions=['vm.migrate'])
    seed.vm_acl('cluster_1', 100, users=['bob'])            # scoped to VM 100 only

    fake = api.make_fake_manager('cluster_1', migrate_vm_manual={'success': True, 'task': 'UPID:mig'})
    fake.config = MagicMock(); fake.config.name = 'cluster_1'
    api.set_manager('cluster_1', fake)

    r = api.as_user(bob).post('/api/clusters/cluster_1/vms/bulk-migrate', json={
        'target': 'node2',
        'vms': [{'node': 'node1', 'vmid': 100, 'type': 'qemu'},
                {'node': 'node1', 'vmid': 200, 'type': 'qemu'}],   # 200 is foreign
    })
    assert r.status_code == 200, r.get_data(as_text=True)
    by_vmid = {row['vmid']: row for row in r.get_json()['results']}
    assert by_vmid[100]['success'] is True                        # own VM migrated
    assert by_vmid[200]['success'] is False                       # foreign VM refused
    assert 'permission denied' in (by_vmid[200]['error'] or '').lower()
    # the batch did not relocate the foreign VM
    migrated_vmids = {call.args[1] for call in fake.migrate_vm_manual.call_args_list}
    assert 200 not in migrated_vmids and 100 in migrated_vmids


# ===========================================================================
# Tier A #2 — restore_backup must authorize the SOURCE volid, not only the target
# ===========================================================================

def test_restore_backup_denies_foreign_source_volid(api, seed):
    seed.tenant('acme', clusters=['cluster_1'])
    bob = seed.user('bob', role='user', tenant_id='acme', permissions=['vm.backup'])
    seed.vm_acl('cluster_1', 100, users=['bob'])                  # owns VM 100

    fake = api.make_fake_manager('cluster_1')
    fake.is_connected = True
    api.set_manager('cluster_1', fake)

    # overwrite mode into bob's OWN VM 100, but the source archive belongs to foreign VM 999
    r = api.as_user(bob).post('/api/clusters/cluster_1/backup-restore', json={
        'mode': 'overwrite',
        'volid': 'local-pbs:backup/vm/999/2026-01-01T00:00:00Z',
        'target_node': 'node1',
        'target_vmid': 100,
    })
    assert r.status_code == 403, r.get_data(as_text=True)
    assert 'source backup' in r.get_json().get('error', '').lower()
    fake._api_post.assert_not_called()                            # never reached qmrestore


def test_restore_backup_allows_own_source(api, seed):
    seed.tenant('acme', clusters=['cluster_1'])
    bob = seed.user('bob', role='user', tenant_id='acme', permissions=['vm.backup'])
    seed.vm_acl('cluster_1', 100, users=['bob'])

    resp = MagicMock(); resp.status_code = 200; resp.json.return_value = {'data': 'UPID:restore'}
    fake = api.make_fake_manager('cluster_1')
    fake.is_connected = True; fake.host = 'h'; fake.api_port = 8006
    fake.config = MagicMock(); fake.config.name = 'cluster_1'
    fake._api_post.return_value = resp
    api.set_manager('cluster_1', fake)

    r = api.as_user(bob).post('/api/clusters/cluster_1/backup-restore', json={
        'mode': 'overwrite',
        'volid': 'local-pbs:backup/vm/100/2026-01-01T00:00:00Z',   # bob's own VM 100
        'target_node': 'node1',
        'target_vmid': 100,
    })
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['success'] is True


# ===========================================================================
# Tier A #4 — proxmox-ha plugin: HA ops confined to the caller's VMs
# ===========================================================================

def test_ha_plugin_sid_gate_confines_scoped_user(api, seed):
    seed.tenant('acme', clusters=['cluster_1'])
    seed.user('bob', role='user', tenant_id='acme', permissions=['vm.config', 'ha.config'])
    seed.vm_acl('cluster_1', 100, users=['bob'])

    with api.app.test_request_context('/'):
        from flask import request
        request.session = {'user': 'bob', 'role': 'user'}
        # own VM → allowed (helper returns None)
        assert proxmox_ha._authz_sid_or_error('cluster_1', 'vm:100', 'vm.config') is None
        # foreign VM → denied (helper returns an (error, status) tuple)
        denied = proxmox_ha._authz_sid_or_error('cluster_1', 'vm:200', 'vm.config')
        assert denied is not None and denied[1] == 403


# ===========================================================================
# Tier A #5 — PBS protect/notes writes must re-check the per-backup owner
# ===========================================================================

def test_pbs_set_protected_denies_foreign_backup(api, seed):
    ppglobals.pbs_managers.clear()
    seed.tenant('acme', clusters=['cluster_1'])
    bob = seed.user('bob', role='user', tenant_id='acme', permissions=['pbs.snapshot.protect'])
    seed.vm_acl('cluster_1', 100, users=['bob'])
    m = _inject_pbs('pbs_x', ['cluster_1'])                       # bob reaches this PBS (cluster_1)
    m.set_snapshot_protected.return_value = {'data': None}
    try:
        # backup for VM 999 (foreign) — cluster gate passes, per-backup owner check must deny
        r = api.as_user(bob).put('/api/pbs/pbs_x/datastores/store1/protected', json={
            'backup-type': 'vm', 'backup-id': '999', 'backup-time': 1700000000, 'protected': False,
        })
        assert r.status_code == 403, r.get_data(as_text=True)
        m.set_snapshot_protected.assert_not_called()

        # bob's OWN VM 100 → allowed through to the manager
        r2 = api.as_user(bob).put('/api/pbs/pbs_x/datastores/store1/protected', json={
            'backup-type': 'vm', 'backup-id': '100', 'backup-time': 1700000000, 'protected': True,
        })
        assert r2.status_code == 200, r2.get_data(as_text=True)
        m.set_snapshot_protected.assert_called_once()
    finally:
        ppglobals.pbs_managers.clear()


def test_pbs_set_notes_denies_foreign_backup(api, seed):
    ppglobals.pbs_managers.clear()
    seed.tenant('acme', clusters=['cluster_1'])
    bob = seed.user('bob', role='user', tenant_id='acme', permissions=['pbs.snapshot.notes'])
    seed.vm_acl('cluster_1', 100, users=['bob'])
    m = _inject_pbs('pbs_x', ['cluster_1'])
    try:
        r = api.as_user(bob).put('/api/pbs/pbs_x/datastores/store1/notes', json={
            'backup-type': 'vm', 'backup-id': '999', 'backup-time': 1700000000, 'notes': 'x',
        })
        assert r.status_code == 403, r.get_data(as_text=True)
        m.set_snapshot_notes.assert_not_called()
    finally:
        ppglobals.pbs_managers.clear()


# ===========================================================================
# Tier A #11 — per-VM migration history must re-check the vmid
# ===========================================================================

def test_migration_history_denies_foreign_vmid_but_allows_own(api, seed):
    seed.tenant('acme', clusters=['cluster_1'])
    bob = seed.user('bob', role='user', tenant_id='acme', permissions=['vm.view'])
    seed.vm_acl('cluster_1', 100, users=['bob'])
    api.set_manager('cluster_1', api.make_fake_manager('cluster_1'))

    denied = api.as_user(bob).get('/api/clusters/cluster_1/vms/200/migration-history')
    assert denied.status_code == 403, denied.get_data(as_text=True)

    allowed = api.as_user(bob).get('/api/clusters/cluster_1/vms/100/migration-history')
    assert allowed.status_code == 200, allowed.get_data(as_text=True)
    assert allowed.get_json() == []


# ===========================================================================
# Tier A #14 — WS cluster subscription clamp
# ===========================================================================

def test_scope_ws_clusters():
    from pegaprox.api.realtime import _scope_ws_clusters
    # admin (allowed=None) — no restriction
    assert _scope_ws_clusters(None, None) is None
    assert _scope_ws_clusters(None, ['c1', 'c2']) == ['c1', 'c2']
    # scoped user — omitting clusters must NOT grant all
    assert _scope_ws_clusters(['c1'], None) == ['c1']
    # naming a foreign cluster yields only the intersection (own set if empty)
    assert _scope_ws_clusters(['c1'], ['c2']) == ['c1']
    assert _scope_ws_clusters(['c1', 'c2'], ['c2']) == ['c2']


# ===========================================================================
# Tier A #15 — test_pbs_connection needs the object gate on the existing branch
# ===========================================================================

def test_pbs_test_connection_cross_tenant_denied(api, seed):
    ppglobals.pbs_managers.clear()
    seed.tenant('tenant_a', clusters=['cluster_1'])
    seed.tenant('tenant_b', clusters=['cluster_2'])
    alice = seed.user('alice', role='user', tenant_id='tenant_a', permissions=['pbs.config'])
    _inject_pbs('pbs_b', ['cluster_2'])                          # linked only to tenant_b
    try:
        r = api.as_user(alice).post('/api/pbs/pbs_b/test', json={})   # empty body → existing branch
        assert r.status_code == 403, r.get_data(as_text=True)
    finally:
        ppglobals.pbs_managers.clear()


# ===========================================================================
# Tier B #3 — role-definition holder-check (self-escalation)
# ===========================================================================

def test_update_custom_role_cannot_grant_perms_beyond_own(api, seed):
    save_custom_roles({'global': {}, 'tenants': {
        'acme': {'acme_ra': {'name': 'Role Admin', 'permissions': ['admin.roles']}}
    }})
    invalidate_roles_cache()
    seed.tenant('acme', clusters=[])
    bob = seed.user('bob', role='acme_ra', tenant_id='acme')     # delegate holds ONLY admin.roles

    r = api.as_user(bob).put('/api/roles/acme_ra',
                             json={'permissions': ['admin.roles', 'admin.settings']})
    assert r.status_code == 403, r.get_data(as_text=True)
    assert 'beyond your own' in r.get_json().get('error', '').lower()
    # the role's permission list was NOT rewritten
    from pegaprox.utils.rbac import load_custom_roles
    invalidate_roles_cache()
    assert load_custom_roles()['tenants']['acme']['acme_ra']['permissions'] == ['admin.roles']


def test_update_custom_role_allows_granting_held_perm(api, seed):
    save_custom_roles({'global': {}, 'tenants': {'acme': {
        'acme_ra': {'name': 'Role Admin', 'permissions': ['admin.roles', 'vm.console']},
        'acme_sub': {'name': 'Sub', 'permissions': ['vm.view']},
    }}})
    invalidate_roles_cache()
    seed.tenant('acme', clusters=[])
    bob = seed.user('bob', role='acme_ra', tenant_id='acme')     # holds admin.roles + vm.console

    # grant acme_sub a perm bob holds (vm.console) — allowed
    r = api.as_user(bob).put('/api/roles/acme_sub', json={'permissions': ['vm.console']})
    assert r.status_code == 200, r.get_data(as_text=True)


def test_create_custom_role_cannot_grant_perms_beyond_own(api, seed):
    save_custom_roles({'global': {}, 'tenants': {
        'acme': {'acme_ra': {'name': 'Role Admin', 'permissions': ['admin.roles']}}
    }})
    invalidate_roles_cache()
    seed.tenant('acme', clusters=[])
    bob = seed.user('bob', role='acme_ra', tenant_id='acme')

    r = api.as_user(bob).post('/api/roles',
                              json={'id': 'newrole', 'name': 'N', 'permissions': ['admin.settings']})
    assert r.status_code == 403, r.get_data(as_text=True)
    assert 'beyond your own' in r.get_json().get('error', '').lower()


# ===========================================================================
# Tier B #6 — apply_role_template must scope non-admins + holder-check
# ===========================================================================

def test_apply_role_template_denies_foreign_tenant_and_unheld_perms(api, seed):
    save_custom_roles({'global': {}, 'tenants': {
        'acme': {'acme_ra': {'name': 'Role Admin', 'permissions': ['admin.roles']}}
    }})
    invalidate_roles_cache()
    seed.tenant('acme', clusters=[])
    seed.tenant('victim', clusters=[])
    bob = seed.user('bob', role='acme_ra', tenant_id='acme')

    # inject a role into ANOTHER tenant — denied
    r1 = api.as_user(bob).post('/api/roles/templates/group_manager/apply',
                               json={'role_id': 'backdoor', 'tenant_id': 'victim'})
    assert r1.status_code == 403, r1.get_data(as_text=True)
    assert 'other tenants' in r1.get_json().get('error', '').lower()

    # own tenant, but the template grants admin.groups/admin.tenants bob doesn't hold — denied
    r2 = api.as_user(bob).post('/api/roles/templates/group_manager/apply',
                               json={'role_id': 'backdoor2'})
    assert r2.status_code == 403, r2.get_data(as_text=True)
    assert 'beyond your own' in r2.get_json().get('error', '').lower()


# ===========================================================================
# Tier B #7 — admin password reset / 2FA-disable must respect the target's tier
# ===========================================================================

def test_admin_change_password_denies_higher_privileged_peer(api, seed):
    save_custom_roles({'global': {}, 'tenants': {'acme': {
        'acme_ua': {'name': 'User Admin', 'permissions': ['admin.users']},
        'acme_hi': {'name': 'Privileged', 'permissions': ['admin.settings', 'admin.roles']},
    }}})
    invalidate_roles_cache()
    seed.tenant('acme', clusters=[])
    bob = seed.user('bob', role='acme_ua', tenant_id='acme')      # delegate: admin.users only
    seed.user('carol', role='acme_hi', tenant_id='acme')          # peer with admin.settings/roles

    r = api.as_user(bob).put('/api/users/carol/password', json={'password': 'NewStr0ng!pass9'})
    assert r.status_code == 403, r.get_data(as_text=True)
    assert 'beyond your own' in r.get_json().get('error', '').lower()


def test_admin_change_password_allows_peer_within_own_privileges(api, seed):
    # a full tenant-admin delegate (superset of ROLE_USER perms) may reset a plain user
    broad = list(ROLE_PERMISSIONS.get(ROLE_USER, [])) + ['admin.users']
    save_custom_roles({'global': {}, 'tenants': {'acme': {
        'acme_full': {'name': 'Tenant Admin', 'permissions': broad},
    }}})
    invalidate_roles_cache()
    seed.tenant('acme', clusters=[])
    bob = seed.user('bob', role='acme_full', tenant_id='acme')
    seed.user('dave', role='user', tenant_id='acme')             # plain user (perms ⊆ bob's)

    r = api.as_user(bob).put('/api/users/dave/password', json={'password': 'NewStr0ng!pass9'})
    assert r.status_code == 200, r.get_data(as_text=True)


def test_admin_disable_2fa_denies_higher_privileged_peer(api, seed):
    save_custom_roles({'global': {}, 'tenants': {'acme': {
        'acme_ua': {'name': 'User Admin', 'permissions': ['admin.users']},
        'acme_hi': {'name': 'Privileged', 'permissions': ['admin.settings', 'admin.roles']},
    }}})
    invalidate_roles_cache()
    seed.tenant('acme', clusters=[])
    bob = seed.user('bob', role='acme_ua', tenant_id='acme')
    seed.user('carol', role='acme_hi', tenant_id='acme')

    r = api.as_user(bob).delete('/api/users/carol/2fa')
    assert r.status_code == 403, r.get_data(as_text=True)
    assert 'beyond your own' in r.get_json().get('error', '').lower()


# ===========================================================================
# Tier B #9 — disabling an account revokes live sessions + WS-auth rechecks 'enabled'
# ===========================================================================

def test_disable_user_revokes_sessions_and_blocks_ws_auth(api, seed):
    admin = seed.user('root', role='admin', tenant_id=DEFAULT)
    victim = seed.user('victim', role='user', tenant_id=DEFAULT, permissions=['node.shell'])

    victim_client = api.as_user(victim)
    # sanity: the victim's session works while enabled
    assert victim_client.get('/api/auth/validate').status_code == 200

    # admin disables the account
    r = api.as_user(admin).put('/api/users/victim', json={'enabled': False})
    assert r.status_code == 200, r.get_data(as_text=True)

    # the live session was invalidated (root cause) AND the decorator-less WS-auth endpoint would
    # reject a disabled user anyway (defence-in-depth)
    assert victim_client.get('/api/auth/validate').status_code == 401


def test_auth_validate_rechecks_enabled_on_stale_session(api, seed):
    victim = seed.user('victim', role='user', tenant_id=DEFAULT, permissions=['node.shell'])
    client = api.as_user(victim)
    assert client.get('/api/auth/validate').status_code == 200

    # flip 'enabled' straight in the DB (simulates a disable path that didn't invalidate sessions)
    rec = seed.db.get_user('victim'); rec['enabled'] = False
    seed.db.save_user('victim', rec)

    r = client.get('/api/auth/validate')
    assert r.status_code == 401, r.get_data(as_text=True)
    assert 'disabled' in r.get_json().get('error', '').lower()


# ===========================================================================
# Re-verify round 2 — alternate paths the adversarial pass surfaced for the
# SAME classes (fixed after the first re-verification).
# ===========================================================================

# A1-alt: cross-cluster migrate also had no per-VM source check (and delete_source defaults True)
def test_cross_cluster_migrate_denies_foreign_source_vm(api, seed):
    seed.tenant('acme', clusters=['cluster_1', 'cluster_2'])
    bob = seed.user('bob', role='user', tenant_id='acme', permissions=['vm.migrate'])
    seed.vm_acl('cluster_1', 100, users=['bob'])                 # scoped to VM 100
    api.set_manager('cluster_1', api.make_fake_manager('cluster_1'))
    api.set_manager('cluster_2', api.make_fake_manager('cluster_2'))

    r = api.as_user(bob).post('/api/cross-cluster-migrate', json={
        'source_cluster': 'cluster_1', 'target_cluster': 'cluster_2',
        'vmid': 200, 'vm_type': 'qemu', 'source_node': 'n1', 'target_node': 'n2',
    })
    assert r.status_code == 403, r.get_data(as_text=True)


# A2-alt: the vms.py restore route authorized only the URL vmid, not the source volid
def test_restore_vm_backup_denies_foreign_source_volid(api, seed):
    seed.tenant('acme', clusters=['cluster_1'])
    bob = seed.user('bob', role='user', tenant_id='acme', permissions=['vm.backup'])
    seed.vm_acl('cluster_1', 100, users=['bob'])
    fake = api.make_fake_manager('cluster_1'); fake.is_connected = True
    api.set_manager('cluster_1', fake)

    r = api.as_user(bob).post('/api/clusters/cluster_1/vms/node1/qemu/100/backups/restore', json={
        'volid': 'local-pbs:backup/vm/999/2026-01-01T00:00:00Z',   # foreign source
    })
    assert r.status_code == 403, r.get_data(as_text=True)
    assert 'source backup' in r.get_json().get('error', '').lower()


# A11-alt: the migration-history LIST honored ?vmid= but scoped only per-cluster
def test_migration_history_list_vmid_filter_enforces_per_vm(api, seed):
    seed.tenant('acme', clusters=['cluster_1'])
    bob = seed.user('bob', role='user', tenant_id='acme', permissions=['cluster.view'])
    seed.vm_acl('cluster_1', 100, users=['bob'])
    admin = seed.user('root', role='admin', tenant_id=DEFAULT)

    from pegaprox.api.history import log_migration
    log_migration('cluster_1', 200, 'FOREIGN', 'qemu', 'n1', 'n2', 'migrate', 'ok', 'op', 1.0)

    # scoped bob asking for foreign VM 200 gets nothing
    r = api.as_user(bob).get('/api/migration-history', query_string={'cluster_id': 'cluster_1', 'vmid': 200})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json() == []
    # admin sees the record (not over-blocked)
    ra = api.as_user(admin).get('/api/migration-history', query_string={'cluster_id': 'cluster_1', 'vmid': 200})
    assert ra.status_code == 200
    assert any(m.get('vmid') == 200 for m in ra.get_json())


# B7-alt: update_user's password branch reset a password without the role-tier guard
def test_update_user_password_denies_higher_privileged_peer(api, seed):
    save_custom_roles({'global': {}, 'tenants': {'acme': {
        'acme_ua': {'name': 'User Admin', 'permissions': ['admin.users']},
        'acme_hi': {'name': 'Privileged', 'permissions': ['admin.settings', 'admin.roles']},
    }}})
    invalidate_roles_cache()
    seed.tenant('acme', clusters=[])
    bob = seed.user('bob', role='acme_ua', tenant_id='acme')
    seed.user('carol', role='acme_hi', tenant_id='acme')

    r = api.as_user(bob).put('/api/users/carol', json={'password': 'NewStr0ng!pass9'})
    assert r.status_code == 403, r.get_data(as_text=True)
    assert 'beyond your own' in r.get_json().get('error', '').lower()


# A5-gap: a TARGETED prune (specific backup group) is a per-backup write
def test_pbs_prune_targeted_denies_foreign_backup(api, seed):
    ppglobals.pbs_managers.clear()
    seed.tenant('acme', clusters=['cluster_1'])
    bob = seed.user('bob', role='user', tenant_id='acme', permissions=['pbs.datastore.prune'])
    seed.vm_acl('cluster_1', 100, users=['bob'])
    _inject_pbs('pbs_x', ['cluster_1'])
    try:
        r = api.as_user(bob).post('/api/pbs/pbs_x/datastores/store1/prune', json={
            'backup_type': 'vm', 'backup_id': '999', 'dry_run': False,
        })
        assert r.status_code == 403, r.get_data(as_text=True)
    finally:
        ppglobals.pbs_managers.clear()


# B9-alt: the ws_token path is the DEFAULT console/shell auth; disable must cut it
def test_console_authz_denies_disabled_user():
    from pegaprox.api.vms import _console_authz
    ok, reason = _console_authz({'username': 'v', 'role': 'user', 'enabled': False}, 'cluster_1', 100)
    assert ok is False
    # an enabled admin still passes
    ok2, _ = _console_authz({'username': 'a', 'role': ROLE_ADMIN, 'enabled': True}, 'cluster_1', 100)
    assert ok2 is True


def test_ws_token_validate_rejects_disabled_user(api, seed):
    seed.tenant('acme', clusters=['cluster_1'])
    seed.user('victim', role='user', tenant_id='acme', enabled=False, permissions=['vm.console'])
    from pegaprox.utils.realtime import create_ws_token
    tok = create_ws_token('victim', 'user')

    r = api.anon().get('/api/ws/token/validate', query_string={'token': tok, 'cluster_id': 'cluster_1'})
    assert r.status_code == 401, r.get_data(as_text=True)
    assert 'disabled' in r.get_json().get('error', '').lower()


def test_ws_token_validate_rejects_disabled_user_without_cluster(api, seed):
    # CodeAnt #2: the DEFAULT VM-console path passes NO cluster_id, so the enabled recheck must run
    # before the `if requested_cluster:` branch — otherwise a disabled user's ws_token still validates.
    seed.user('victim', role='user', tenant_id=DEFAULT, enabled=False, permissions=['vm.console'])
    from pegaprox.utils.realtime import create_ws_token
    tok = create_ws_token('victim', 'user')

    r = api.anon().get('/api/ws/token/validate', query_string={'token': tok})   # no cluster_id
    assert r.status_code == 401, r.get_data(as_text=True)
    assert 'disabled' in r.get_json().get('error', '').lower()


def test_disable_purges_ws_tokens(api, seed):
    admin = seed.user('root', role='admin', tenant_id=DEFAULT)
    seed.user('victim', role='user', tenant_id=DEFAULT, permissions=['vm.console'])
    from pegaprox.utils.realtime import create_ws_token, ws_tokens
    create_ws_token('victim', 'user')
    assert any(d.get('user') == 'victim' for d in ws_tokens.values())

    r = api.as_user(admin).put('/api/users/victim', json={'enabled': False})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert not any(d.get('user') == 'victim' for d in ws_tokens.values())


# ===========================================================================
# Re-verify round 3 — the last two gaps (unconditional history filter +
# effective-perms takeover guard).
# ===========================================================================

# A11-round3: omitting ?vmid= must NOT bypass the per-VM filter on the LIST route
def test_migration_history_list_without_vmid_still_per_vm_filtered(api, seed):
    seed.tenant('acme', clusters=['cluster_1'])
    bob = seed.user('bob', role='user', tenant_id='acme', permissions=['cluster.view'])
    seed.vm_acl('cluster_1', 100, users=['bob'])
    admin = seed.user('root', role='admin', tenant_id=DEFAULT)

    from pegaprox.api.history import log_migration
    log_migration('cluster_1', 100, 'MINE', 'qemu', 'n1', 'n2', 'migrate', 'ok', 'op', 1.0)
    log_migration('cluster_1', 200, 'FOREIGN', 'qemu', 'n1', 'n2', 'migrate', 'ok', 'op', 1.0)

    # NO vmid param — the previous fix only filtered when ?vmid= was present
    r = api.as_user(bob).get('/api/migration-history', query_string={'cluster_id': 'cluster_1'})
    assert r.status_code == 200, r.get_data(as_text=True)
    vmids = {m.get('vmid') for m in r.get_json()}
    assert 100 in vmids and 200 not in vmids        # own row kept, foreign row filtered

    ra = api.as_user(admin).get('/api/migration-history', query_string={'cluster_id': 'cluster_1'})
    assert {100, 200} <= {m.get('vmid') for m in ra.get_json()}   # admin not over-blocked


# B7-round3: the takeover guard must weigh the target's EFFECTIVE perms, not just the role label —
# a peer elevated by a DIRECT grant (role 'user' + permissions=['admin.settings']) must be protected
# from a delegate that holds all of ROLE_USER's perms but not that direct grant.
def test_admin_password_denies_peer_with_direct_admin_grant(api, seed):
    broad = list(ROLE_PERMISSIONS.get(ROLE_USER, [])) + ['admin.users']   # all ROLE_USER perms, NOT admin.settings
    save_custom_roles({'global': {}, 'tenants': {'acme': {
        'acme_full': {'name': 'Tenant Admin', 'permissions': broad},
    }}})
    invalidate_roles_cache()
    seed.tenant('acme', clusters=[])
    bob = seed.user('bob', role='acme_full', tenant_id='acme')
    seed.user('carol', role='user', tenant_id='acme', permissions=['admin.settings'])   # direct grant

    # with the old role-only guard bob (superset of ROLE_USER) would have been allowed through
    r = api.as_user(bob).put('/api/users/carol/password', json={'password': 'NewStr0ng!pass9'})
    assert r.status_code == 403, r.get_data(as_text=True)
    assert 'beyond your own' in r.get_json().get('error', '').lower()

    # sanity: the same delegate CAN still reset a genuinely plain peer (no over-block)
    seed.user('dave', role='user', tenant_id='acme')
    r2 = api.as_user(bob).put('/api/users/dave/password', json={'password': 'NewStr0ng!pass9'})
    assert r2.status_code == 200, r2.get_data(as_text=True)
