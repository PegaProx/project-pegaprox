# Full-stack E2E for #766 (cybrwerk): assigning a VM to a pool must be gated by the granular
# pool.assign permission, not admin.users. Drives REAL requests through the REAL Flask app + the
# REAL require_auth decorator (managers faked) — the perm gate fires before any cluster/manager
# work, so these deny/allow decisions are exactly what a browser would get.
import json

import pytest


def _code(resp):
    try:
        return (resp.get_json() or {}).get('code')
    except Exception:
        return None


def _required(resp):
    try:
        return (resp.get_json() or {}).get('required')
    except Exception:
        return None


POOL_MEMBERS = '/api/clusters/c-e2e/pools/mypool/members'
_BODY = {'vmid': 100, 'type': 'qemu'}


def test_admin_users_only_is_now_rejected(api, seed):
    # The heart of #766: a user who has the OLD perm (admin.users) but NOT pool.assign used to be
    # allowed; after the fix they are blocked, and the gate names pool.assign as what's missing.
    u = seed.user('useradmin_no_pool', role='viewer', permissions=['admin.users'])
    resp = api.as_user(u).post(POOL_MEMBERS, json=_BODY)
    assert resp.status_code == 403
    assert _code(resp) == 'MISSING_PERMISSION'
    assert _required(resp) == 'pool.assign', "gate must now demand pool.assign, not admin.users (#766)"


def test_plain_viewer_is_rejected(api, seed):
    u = seed.user('plainviewer', role='viewer', permissions=[])
    resp = api.as_user(u).post(POOL_MEMBERS, json=_BODY)
    assert resp.status_code == 403
    assert _code(resp) == 'MISSING_PERMISSION'
    assert _required(resp) == 'pool.assign'


def test_pool_assign_holder_passes_the_gate(api, seed):
    # A pool manager with pool.assign but NO admin.users now gets PAST the permission gate. What
    # happens downstream (cluster-access / the faked manager) is irrelevant here — the point is the
    # request is no longer stopped at the perm check with MISSING_PERMISSION.
    u = seed.user('poolmgr', role='viewer', permissions=['pool.assign', 'cluster.view'])
    resp = api.as_user(u).post(POOL_MEMBERS, json=_BODY)
    assert not (resp.status_code == 403 and _code(resp) == 'MISSING_PERMISSION'), (
        f"pool.assign holder was wrongly blocked at the perm gate: "
        f"{resp.status_code} {resp.get_data(as_text=True)[:200]}")


def test_admin_still_passes_the_gate(api, seed):
    # Regression guard: platform admins keep unconditional access (has_permission safety net).
    u = seed.user('adminuser', role='admin')
    resp = api.as_user(u).post(POOL_MEMBERS, json=_BODY)
    assert not (resp.status_code == 403 and _code(resp) == 'MISSING_PERMISSION')


def test_remove_member_same_gate(api, seed):
    # DELETE /members/<vmid> must enforce the same pool.assign gate as POST.
    viewer = seed.user('rm_viewer', role='viewer', permissions=['admin.users'])
    resp = api.as_user(viewer).delete('/api/clusters/c-e2e/pools/mypool/members/100')
    assert resp.status_code == 403
    assert _required(resp) == 'pool.assign', "remove_pool_member must also demand pool.assign (#766)"
