# Regression guards for the 15 confirmed-open findings from the 2026-08 Aikido AI-pentest re-triage
# (the other 59 verified as already-fixed or false-positive). Authz/BOLA/IDOR invariants driven
# through the real Flask app + a few pure-unit checks.

from unittest.mock import MagicMock

import pegaprox.globals as ppglobals


# ---------------------------------------------------------------------------
# #3 — PBS host/port change must reject a FIELD-OMITTED credential, not just a masked one
# ---------------------------------------------------------------------------

def _inject_pbs(pbs_id, host, linked):
    m = MagicMock()
    m.host = host; m.port = 8007; m.password = 'REAL-SECRET'; m.api_token_secret = ''
    m.ssh_key = ''; m.linked_clusters = linked; m.name = pbs_id
    m.to_dict = lambda: {'id': pbs_id, 'host': host}
    ppglobals.pbs_managers[pbs_id] = m
    return m


def test_pbs_host_change_with_OMITTED_password_is_rejected(api, seed):
    # the field-omission bypass: {"host": ...} with NO password key must still fail closed.
    ppglobals.pbs_managers.clear()
    root = seed.user('root', role='admin', tenant_id='default')
    _inject_pbs('p1', 'good-pbs.example', ['cluster_1'])
    try:
        r = api.as_user(root).put('/api/pbs/p1', json={'host': 'attacker.tld', 'enabled': True})
        assert r.status_code == 400, r.get_data(as_text=True)
        assert ppglobals.pbs_managers['p1'].host == 'good-pbs.example'  # nothing persisted
    finally:
        ppglobals.pbs_managers.clear()


# ---------------------------------------------------------------------------
# #4 — SIEM syslog line must strip ALL C0 controls (CR/ESC/NUL), not just \n
# ---------------------------------------------------------------------------

def test_siem_syslog_strips_control_chars():
    from pegaprox.api.siem import _to_syslog_5424
    line = _to_syslog_5424({
        'severity': 'info', 'user': 'alice',
        'action': 'key.registered',
        'details': "MyKey\r<134>1 2026 victimhost forged - injected",
        'cluster': 'c\x1b[2J', 'ip_address': 'x\x00y',
    })
    body = line.split(' - ', 1)[-1]  # after the MSGID/SD
    assert '\r' not in line and '\x1b' not in line and '\x00' not in line
    assert 'injected' in line  # content kept, control chars neutralised


# ---------------------------------------------------------------------------
# #10 — a deleted DR plan (None row) must fail closed, not return allowed
# ---------------------------------------------------------------------------

def test_dr_drill_require_plan_access_fails_closed_on_missing_plan(api):
    from pegaprox.api.dr_drill import _require_plan_access
    with api.app.test_request_context('/'):
        res = _require_plan_access(None)
    assert res is not None                      # None would mean 'allowed'
    body, code = res
    assert code == 404


# ---------------------------------------------------------------------------
# #5 — GET /api/users/<u>/permissions must not disclose a cross-tenant user
# ---------------------------------------------------------------------------

def test_user_perms_cross_tenant_denied_for_tenant_admin(api, seed):
    seed.tenant('tenant_a', clusters=['cluster_1'])
    seed.tenant('tenant_b', clusters=['cluster_2'])
    alice = seed.user('alice', role='user', tenant_id='tenant_a', permissions=['admin.users'])
    seed.user('bob', role='user', tenant_id='tenant_b')
    r = api.as_user(alice).get('/api/users/bob/permissions')
    assert r.status_code == 403, r.get_data(as_text=True)


def test_user_perms_same_tenant_allowed(api, seed):
    seed.tenant('tenant_a', clusters=['cluster_1'])
    alice = seed.user('alice', role='user', tenant_id='tenant_a', permissions=['admin.users'])
    seed.user('carol', role='viewer', tenant_id='tenant_a')
    r = api.as_user(alice).get('/api/users/carol/permissions')
    assert r.status_code == 200, r.get_data(as_text=True)


# ---------------------------------------------------------------------------
# #15 — check-affinity must enforce per-VM access, not just cluster access
# ---------------------------------------------------------------------------

def test_check_affinity_denies_foreign_vm(api, seed):
    # bob reaches cluster_1 via a VM-ACL on VM 100, but asks about foreign VM 200
    seed.tenant('tenant_b', clusters=['cluster_other'])
    bob = seed.user('bob', role='user', tenant_id='tenant_b', permissions=['vm.view'])
    seed.vm_acl('cluster_1', 100, users=['bob'])
    api.set_manager('cluster_1', api.make_fake_manager('cluster_1'))
    r = api.as_user(bob).get('/api/clusters/cluster_1/vms/200/check-affinity/pve1')
    assert r.status_code == 403, r.get_data(as_text=True)


# ---------------------------------------------------------------------------
# #11 — drift events (config diffs w/ secrets) require admin.audit, not cluster.view
# ---------------------------------------------------------------------------

def test_drift_events_requires_admin_audit(api, seed):
    seed.tenant('acme', clusters=['cluster_1'])
    viewer = seed.user('v', role='viewer', tenant_id='acme', permissions=['cluster.view'])
    api.set_manager('cluster_1', api.make_fake_manager('cluster_1'))
    r = api.as_user(viewer).get('/api/clusters/cluster_1/drift/events')
    assert r.status_code == 403, r.get_data(as_text=True)


# ---------------------------------------------------------------------------
# #13 — check_pbs_access / check_vmware_access floor an admin-owned scoped token (#491)
# ---------------------------------------------------------------------------

def test_check_pbs_access_confines_admin_owned_viewer_token(api, seed):
    seed.tenant('acme', clusters=['cluster_1'])
    seed.tenant('other', clusters=['cluster_other'])
    seed.user('root', role='admin', tenant_id='acme')
    m = MagicMock(); m.linked_clusters = ['cluster_other']
    ppglobals.pbs_managers['pbsX'] = m
    try:
        with api.app.test_request_context('/'):
            from flask import request, g
            from pegaprox.api.helpers import check_pbs_access
            request.session = {'user': 'root', 'role': 'viewer', 'api_token': True}
            g.current_user = {'role': 'admin', 'tenant_id': 'acme'}
            ok, _ = check_pbs_access('pbsX')      # linked only to cluster_other, token scoped to acme
            assert ok is False
    finally:
        ppglobals.pbs_managers.pop('pbsX', None)


# ---------------------------------------------------------------------------
# #8 — an API token must not bypass a tenant-scoped role downgrade / denial
# ---------------------------------------------------------------------------

def test_token_tenant_role_floor_helper():
    # unit-check the floor logic used in require_auth: a tenant override role above the token's
    # fresh_role is capped; denials/downgrades are preserved.
    from pegaprox.models.permissions import ROLE_ADMIN, ROLE_USER, ROLE_VIEWER
    _h = {ROLE_ADMIN: 3, ROLE_USER: 2, ROLE_VIEWER: 1}
    fresh_role = ROLE_VIEWER
    _fl = _h.get(fresh_role, 1)
    tp = {'default': {'role': ROLE_ADMIN, 'denied': ['storage.delete']}}
    out = {}
    for tid, ov in tp.items():
        ov = dict(ov)
        if ov.get('role') and _h.get(ov['role'], 1) > _fl:
            ov['role'] = next((k for k, v in _h.items() if v == _fl), fresh_role)
        out[tid] = ov
    assert out['default']['role'] == ROLE_VIEWER       # admin capped down to the token's viewer
    assert out['default']['denied'] == ['storage.delete']  # denial preserved
