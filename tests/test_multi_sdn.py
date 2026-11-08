# #612 cross-cluster EVPN (api/multi_sdn.py) — auth/validation surface + the
# per-vid merge-write the 2026-08 review added. Drives real requests through the
# Flask app (api fixture); the create/edit happy path still needs live SDN members
# and is E2E-owed, so here we cover everything reachable without a real cluster.
import json
from datetime import datetime

import pytest

from pegaprox.api import multi_sdn as msdn


def _admin(api, seed):
    return api.as_user(seed.user('evadmin', role='admin'))


def _viewer(api, seed):
    # ROLE_USER: has node.view, lacks sdn.manage / admin.settings
    return api.as_user(seed.user('evviewer', role='user'))


def test_list_empty_ok(api, seed):
    r = _admin(api, seed).get('/api/multi-sdn/vnets')
    assert r.status_code == 200 and isinstance(r.get_json(), list)


def test_validate_unreachable_members_is_ok_false_not_500(api, seed):
    r = _admin(api, seed).post('/api/multi-sdn/vnets/validate', json={
        'name': 'evpnA', 'zone': 'zoneA', 'controller': 'evpnctl1',
        'vni': 100100, 'asn': 65001, 'cluster_ids': ['ghostA', 'ghostB']})
    assert r.status_code == 200
    assert r.get_json().get('ok') is False


def test_validate_bad_name_400(api, seed):
    r = _admin(api, seed).post('/api/multi-sdn/vnets/validate', json={
        'name': 'name_too_long_and_underscored', 'zone': 'z', 'controller': 'c',
        'vni': 1, 'asn': 1, 'cluster_ids': ['x']})
    assert r.status_code == 400


def test_create_ghost_members_409_not_500(api, seed):
    r = _admin(api, seed).post('/api/multi-sdn/vnets', json={
        'name': 'evpnB', 'zone': 'zoneB', 'controller': 'evpnctl2',
        'vni': 100200, 'asn': 65001, 'cluster_ids': ['ghostA']})
    assert r.status_code == 409
    assert 'not_found' in (r.get_json().get('error') or '')


def test_create_no_members_400(api, seed):
    r = _admin(api, seed).post('/api/multi-sdn/vnets', json={
        'name': 'evpnC', 'zone': 'z', 'controller': 'c', 'vni': 1, 'asn': 1})
    assert r.status_code == 400


def test_get_bogus_404(api, seed):
    assert _admin(api, seed).get('/api/multi-sdn/vnets/deadbeef').status_code == 404


def test_anon_401(api, seed):
    a = api.anon()
    assert a.get('/api/multi-sdn/vnets').status_code == 401
    assert a.post('/api/multi-sdn/vnets', json={}).status_code == 401


@pytest.mark.parametrize('method,path,body', [
    ('post', '/api/multi-sdn/vnets', {'name': 'x'}),
    ('put', '/api/multi-sdn/vnets/abc', {'alias': 'y'}),
    ('delete', '/api/multi-sdn/vnets/abc', None),
    ('post', '/api/multi-sdn/vnets/abc/apply', None),
    ('post', '/api/multi-sdn/vnets/abc/reconcile', None),
    ('post', '/api/multi-sdn/vnets/abc/scan', None),   # sdn.manage-gated now (review B2)
    ('post', '/api/multi-sdn/vnets/abc/members', {'cluster_id': 'z'}),
    ('delete', '/api/multi-sdn/vnets/abc/members/z', None),
])
def test_viewer_403_on_every_write(api, seed, method, path, body):
    c = _viewer(api, seed)
    kw = {'json': body} if body is not None else {}
    r = getattr(c, method)(path, **kw)
    assert r.status_code == 403, f"{method} {path} -> {r.status_code}"


# --- _merge_status_write: the per-vid lock + merge that stops a concurrent
#     add/remove-member from being clobbered by a stale-snapshot full replace. ---
def _insert_vnet(db, vid, name, members, per_cluster):
    now = datetime.now().isoformat()
    db.execute(
        'INSERT INTO multi_cluster_vnets (id,name,alias,zone,vni,asn,vrf_vxlan,controller,'
        'peers,member_clusters,subnets,desired_state,per_cluster_status,status,enabled,'
        'created_by,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,?,?,?)',
        (vid, name, '', 'z', 100, 65001, None, 'ctl', '', json.dumps(members), '[]',
         json.dumps({'name': name, 'member_clusters': members}),
         json.dumps(per_cluster), 'applied', 'tester', now, now))


def test_merge_status_write_preserves_untouched_members(api, seed):
    with api.app.app_context():
        db = msdn.get_db()
        _insert_vnet(db, 'v1', 'evM', ['A', 'B', 'C'],
                     {'A': {'status': 'applied'}, 'B': {'status': 'applied'}, 'C': {'status': 'applied'}})
        out = msdn._merge_status_write('v1', {'A': {'status': 'drift', 'detail': 'x'}})
    pcs = out['per_cluster_status']
    assert pcs['A']['status'] == 'drift'      # fresh result wins
    assert pcs['B']['status'] == 'applied'    # NOT wiped by the partial write
    assert pcs['C']['status'] == 'applied'


def test_merge_status_write_drops_removed_member(api, seed):
    with api.app.app_context():
        db = msdn.get_db()
        _insert_vnet(db, 'v2', 'evN', ['A'],   # B is no longer a member
                     {'A': {'status': 'applied'}, 'B': {'status': 'applied'}})
        out = msdn._merge_status_write('v2', {'A': {'status': 'in_sync'}})
    assert set(out['per_cluster_status'].keys()) == {'A'}


def test_merge_status_write_missing_record_none(api, seed):
    with api.app.app_context():
        assert msdn._merge_status_write('nope', {'A': {'status': 'x'}}) is None
