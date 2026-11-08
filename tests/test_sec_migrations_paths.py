# -*- coding: utf-8 -*-
"""Every path into the migration operations behind #1088, #1048, #981 and #1106.
NS Oct 2026.

test_sec_migrations_routes.py proves each fix on the route the finding named. This file
walks the other ways in - the twin route, the parameter spellings a gate can read
differently from the code behind it, a token with a smaller role than its owner, a
caller of another tenant - and pairs each refusal with the operator who must still get
through, so a gate that says no to everybody cannot pass for a fix.
"""
import json
import time
from unittest.mock import MagicMock

import pytest

import pegaprox.globals as ppglobals
import pegaprox.utils.rbac as rbac


SRC, TGT = 'cluster_1', 'cluster_2'


def _pool_member(cluster_id, vmid, pool, vtype='qemu'):
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache[cluster_id] = {
            'data': {f'{vmid}:{vtype}': pool}, 'timestamp': time.time(), 'refreshing': False}


def _token_client(api, owner, role):
    """A bearer token minted for `owner` with `role` - the narrower-token identity."""
    from pegaprox.utils.auth import create_api_token
    with api.app.test_request_context('/'):
        res = create_api_token(owner, f'tok-{role}', role=role)
    assert res.get('token'), res
    c = api.anon()
    hdr = {'Authorization': f"Bearer {res['token']}"}
    return type('TokenClient', (), {
        'post': lambda self, p, **kw: c.post(p, headers=hdr, **kw),
        'put': lambda self, p, **kw: c.put(p, headers=hdr, **kw),
    })()


# =========================================================================== #1048
# POST /api/clusters/<c>/vms/<node>/<type>/<vmid>/remote-migrate, Proxmox source

RMIG = f'/api/clusters/{SRC}/vms/pve1/qemu/100/remote-migrate'
_PVE_BODY = {'target_endpoint': 'apitoken=PVEAPIToken=x!y=z,host=h,fingerprint=f',
             'target_storage': 'local-lvm', 'target_bridge': 'vmbr0'}


@pytest.fixture
def pve_src(api, seed):
    seed.tenant('acme', clusters=[SRC, TGT])
    seed.tenant('globex', clusters=['cluster_9'])
    return api.set_manager(SRC, api.make_fake_manager(
        SRC, remote_migrate_vm={'success': True, 'task': 'UPID:pve1:rmig:'}))


@pytest.fixture
def portal(api, seed, pve_src):
    """The Client Portal shape: tenant owns the cluster, an ACL row confines them to VM
    100. inherit_role grants vm.migrate and deliberately never vm.delete; the extra
    vm.delete on the account is what a role fall-through would hand back."""
    seed.vm_acl(SRC, 100, ['portal'], inherit_role=True)
    return api.as_user(seed.user('portal', role='user', tenant_id='acme',
                                 permissions=['vm.delete']))


# Python truthiness decides both the gate and PegaProxManager.remote_migrate_vm
# (`if delete_source: data['delete'] = 1`), so every truthy spelling deletes.
_DELETES = [True, 1, 'false', '0', 'no', [1], {'x': 1}]
_KEEPS = [False, 0, None, '', []]


@pytest.mark.parametrize('flag', _DELETES, ids=repr)
def test_remote_migrate_every_deleting_spelling_needs_vm_delete(portal, pve_src, flag):
    r = portal.post(RMIG, json={**_PVE_BODY, 'delete_source': flag})
    assert r.status_code == 403, r.get_data(as_text=True)
    pve_src.remote_migrate_vm.assert_not_called()


def test_remote_migrate_an_omitted_flag_is_the_deleting_default(portal, pve_src):
    r = portal.post(RMIG, json=dict(_PVE_BODY))
    assert r.status_code == 403
    pve_src.remote_migrate_vm.assert_not_called()


@pytest.mark.parametrize('flag', _KEEPS, ids=repr)
def test_remote_migrate_a_keeping_spelling_goes_through_and_keeps(portal, pve_src, flag):
    r = portal.post(RMIG, json={**_PVE_BODY, 'delete_source': flag})
    assert r.status_code == 200, r.get_data(as_text=True)
    args = pve_src.remote_migrate_vm.call_args.args
    assert not args[8], f'delete_source={flag!r} passed the gate yet reached the manager as {args[8]!r}'


def test_remote_migrate_pool_confined_user_cannot_delete(api, seed, pve_src):
    seed.tenant('poolco', clusters=[])          # reaches cluster_1 through the pool only
    seed.pool(SRC, 'pool_a', 'pooler', ['vm.migrate'])
    _pool_member(SRC, 100, 'pool_a')
    u = api.as_user(seed.user('pooler', role='user', tenant_id='poolco',
                              permissions=['vm.delete']))
    assert u.post(RMIG, json={**_PVE_BODY, 'delete_source': True}).status_code == 403
    pve_src.remote_migrate_vm.assert_not_called()
    r = u.post(RMIG, json={**_PVE_BODY, 'delete_source': False})
    assert r.status_code == 200, r.get_data(as_text=True)


def test_remote_migrate_a_user_token_of_an_admin_cannot_delete(api, seed, pve_src):
    seed.user('root', role='admin')
    tok = _token_client(api, 'root', 'user')
    r = tok.post(RMIG, json={**_PVE_BODY, 'delete_source': True})
    assert r.status_code == 403, r.get_data(as_text=True)
    assert 'vm.delete' in r.get_data(as_text=True)
    pve_src.remote_migrate_vm.assert_not_called()


def test_remote_migrate_an_admin_token_still_deletes(api, seed, pve_src):
    seed.user('root', role='admin')
    tok = _token_client(api, 'root', 'admin')
    r = tok.post(RMIG, json={**_PVE_BODY, 'delete_source': True})
    assert r.status_code == 200, r.get_data(as_text=True)


def test_remote_migrate_an_unconfined_operator_with_vm_delete_deletes(api, seed, pve_src):
    u = api.as_user(seed.user('ops', role='user', tenant_id='acme', permissions=['vm.delete']))
    r = u.post(RMIG, json={**_PVE_BODY, 'delete_source': True})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert pve_src.remote_migrate_vm.call_args.args[8] is True


def test_remote_migrate_another_tenant_is_refused(api, seed, pve_src):
    u = api.as_user(seed.user('outsider', role='user', tenant_id='globex',
                              permissions=['vm.delete']))
    assert u.post(RMIG, json={**_PVE_BODY, 'delete_source': False}).status_code == 403
    pve_src.remote_migrate_vm.assert_not_called()


@pytest.mark.parametrize('verb', ['get', 'put', 'patch', 'delete'])
def test_remote_migrate_has_no_other_verb(api, seed, pve_src, verb):
    admin = api.as_user(seed.user('root', role='admin'))
    assert getattr(admin, verb)(RMIG).status_code == 405


# =========================================================================== #1088 / #1048
# The same route on an XCP-ng source: the target is a registered pool, never a URL.

XRMIG = f'/api/clusters/xcp_a/vms/xcp1/qemu/100/remote-migrate'
_XBODY = {'target_storage': 'sr1', 'target_bridge': 'xenbr0'}


@pytest.fixture
def xcp_pools(api, seed):
    seed.tenant('acme', clusters=['xcp_a', 'xcp_b'])
    seed.tenant('globex', clusters=['xcp_g'])
    src = api.set_manager('xcp_a', api.make_fake_manager(
        'xcp_a', cluster_type='xcpng', remote_migrate_vm={'success': True, 'task': 't1'}))
    tgt = api.set_manager('xcp_b', api.make_fake_manager('xcp_b', cluster_type='xcpng'))
    api.set_manager('xcp_g', api.make_fake_manager('xcp_g', cluster_type='xcpng'))
    api.set_manager(SRC, api.make_fake_manager(SRC))
    return src, tgt


@pytest.mark.parametrize('target', [['xcp_b'], {'id': 'xcp_b'}, 7, True, '', None],
                         ids=repr)
def test_xcp_remote_migrate_a_non_name_target_is_a_400(api, seed, xcp_pools, target):
    src, _ = xcp_pools
    admin = api.as_user(seed.user('root', role='admin'))
    r = admin.post(XRMIG, json={**_XBODY, 'target_cluster': target})
    assert r.status_code == 400, r.get_data(as_text=True)
    src.remote_migrate_vm.assert_not_called()


@pytest.mark.parametrize('target', ['xcp_a', SRC, 'nope', 'XCP_B'])
def test_xcp_remote_migrate_target_must_be_another_registered_pool(api, seed, xcp_pools, target):
    src, _ = xcp_pools
    admin = api.as_user(seed.user('root', role='admin'))
    r = admin.post(XRMIG, json={**_XBODY, 'target_cluster': target,
                                'target_endpoint': 'https://elsewhere.invalid'})
    assert r.status_code == 400, r.get_data(as_text=True)
    src.remote_migrate_vm.assert_not_called()


def test_xcp_remote_migrate_the_operator_reaches_the_pool_not_the_url(api, seed, xcp_pools):
    src, tgt = xcp_pools
    u = api.as_user(seed.user('ops', role='user', tenant_id='acme'))
    r = u.post(XRMIG, json={**_XBODY, 'target_cluster': 'xcp_b',
                            'target_endpoint': 'https://elsewhere.invalid'})
    assert r.status_code == 200, r.get_data(as_text=True)
    call = src.remote_migrate_vm.call_args
    assert call.kwargs['target_pool'] is tgt
    assert call.args[3] is None, 'the request URL still reached the manager'


def test_xcp_remote_migrate_a_pool_of_another_tenant_is_refused(api, seed, xcp_pools):
    src, _ = xcp_pools
    u = api.as_user(seed.user('ops', role='user', tenant_id='acme'))
    r = u.post(XRMIG, json={**_XBODY, 'target_cluster': 'xcp_g'})
    assert r.status_code == 403, r.get_data(as_text=True)
    src.remote_migrate_vm.assert_not_called()


def test_xcp_remote_migrate_a_caller_confined_on_the_target_is_refused(api, seed, xcp_pools):
    """Reaches xcp_b only through an ACL row there: not an owner of the target pool."""
    src, _ = xcp_pools
    seed.tenant('portalco', clusters=['xcp_a'])
    seed.vm_acl('xcp_b', 300, ['portal'])
    u = api.as_user(seed.user('portal', role='user', tenant_id='portalco'))
    r = u.post(XRMIG, json={**_XBODY, 'target_cluster': 'xcp_b'})
    assert r.status_code == 403, r.get_data(as_text=True)
    assert 'target cluster' in r.get_data(as_text=True)
    src.remote_migrate_vm.assert_not_called()


def test_xcp_remote_migrate_needs_xapi_vm_migrate(api, seed, xcp_pools):
    src, _ = xcp_pools
    u = api.as_user(seed.user('ops', role='user', tenant_id='acme',
                              denied=['xapi.vm.migrate']))
    r = u.post(XRMIG, json={**_XBODY, 'target_cluster': 'xcp_b'})
    assert r.status_code == 403
    assert 'xapi.vm.migrate' in r.get_data(as_text=True)
    src.remote_migrate_vm.assert_not_called()


def test_xcp_remote_migrate_an_acl_user_needs_the_row_for_this_vm(api, seed, xcp_pools):
    src, _ = xcp_pools
    seed.vm_acl('xcp_a', 200, ['portal'])
    u = api.as_user(seed.user('portal', role='user', tenant_id='acme'))
    r = u.post(XRMIG, json={**_XBODY, 'target_cluster': 'xcp_b'})
    assert r.status_code == 403
    src.remote_migrate_vm.assert_not_called()


# =========================================================================== #1048
# POST /api/cross-cluster-migrate - the high-level twin

XC = '/api/cross-cluster-migrate'


@pytest.fixture
def xc_pair(api, seed):
    seed.tenant('acme', clusters=[SRC, TGT])
    # failure from the source manager stops the route before its token-cleanup thread
    src = api.set_manager(SRC, api.make_fake_manager(
        SRC, remote_migrate_vm={'success': False, 'error': 'stub'},
        get_vm_config={'success': True, 'config': {}}))
    api.set_manager(TGT, api.make_fake_manager(
        TGT, create_api_token={'success': True, 'token_id': 'a!b', 'token_value': 'v'},
        get_cluster_fingerprint={'success': True, 'host': 'h', 'fingerprint': 'f'}))
    return src


def _xc_body(**kw):
    b = {'source_cluster': SRC, 'target_cluster': TGT, 'vmid': 100,
         'source_node': 'n1', 'target_node': 'n2'}
    b.update(kw)
    return b


@pytest.mark.parametrize('vmid', [100, '100', '0100', ' 100', '100 ', 100.0, '+100'],
                         ids=repr)
def test_cross_cluster_every_spelling_of_vm_100_meets_its_acl_row(api, seed, xc_pair, vmid):
    """Gap: '0100' or ' 100' missed the ACL row of VM 100 (no vm.delete there) and fell to
    the role, which carries vm.delete - the migration went out with delete set."""
    seed.vm_acl(SRC, 100, ['portal'], inherit_role=True)
    u = api.as_user(seed.user('portal', role='user', tenant_id='acme', permissions=['vm.delete']))
    r = u.post(XC, json=_xc_body(vmid=vmid, delete_source=True))
    assert r.status_code == 403, r.get_data(as_text=True)
    assert 'vm.delete' in r.get_data(as_text=True)
    xc_pair.remote_migrate_vm.assert_not_called()


@pytest.mark.parametrize('vmid', ['abc', '', None, [100], {'v': 100}], ids=repr)
def test_cross_cluster_a_non_number_vmid_is_a_400(api, seed, xc_pair, vmid):
    admin = api.as_user(seed.user('root', role='admin'))
    r = admin.post(XC, json=_xc_body(vmid=vmid, delete_source=False))
    assert r.status_code == 400, r.get_data(as_text=True)
    xc_pair.remote_migrate_vm.assert_not_called()


@pytest.mark.parametrize('flag', _DELETES, ids=repr)
def test_cross_cluster_every_deleting_spelling_needs_vm_delete(api, seed, xc_pair, flag):
    seed.vm_acl(SRC, 100, ['portal'], inherit_role=True)
    u = api.as_user(seed.user('portal', role='user', tenant_id='acme'))
    assert u.post(XC, json=_xc_body(delete_source=flag)).status_code == 403
    xc_pair.remote_migrate_vm.assert_not_called()


def test_cross_cluster_the_acl_user_may_move_without_deleting(api, seed, xc_pair):
    seed.vm_acl(SRC, 100, ['portal'], inherit_role=True)
    u = api.as_user(seed.user('portal', role='user', tenant_id='acme'))
    u.post(XC, json=_xc_body(vmid='100', delete_source=False))
    xc_pair.remote_migrate_vm.assert_called_once()
    assert xc_pair.remote_migrate_vm.call_args.args[1] == 100


def test_cross_cluster_the_operator_gets_the_canonical_id(api, seed, xc_pair):
    u = api.as_user(seed.user('ops', role='user', tenant_id='acme', permissions=['vm.delete']))
    u.post(XC, json=_xc_body(vmid=' 100', delete_source=True))
    xc_pair.remote_migrate_vm.assert_called_once()
    args = xc_pair.remote_migrate_vm.call_args.args
    assert args[1] == 100 and isinstance(args[1], int)
    assert args[8] is True


def test_cross_cluster_a_user_token_of_an_admin_cannot_delete(api, seed, xc_pair):
    seed.user('root', role='admin')
    tok = _token_client(api, 'root', 'user')
    r = tok.post(XC, json=_xc_body(delete_source=True))
    assert r.status_code == 403 and 'vm.delete' in r.get_data(as_text=True)
    xc_pair.remote_migrate_vm.assert_not_called()


def test_cross_cluster_mixed_case_type_does_not_widen(api, seed, xc_pair):
    """vm_type only feeds the pool lookup; a spelling that misses it must not grant more.
    poolco owns the target, so the refusals below are the source-side decision."""
    seed.tenant('poolco', clusters=[TGT])
    seed.pool(SRC, 'pool_a', 'pooler', ['vm.migrate'])
    _pool_member(SRC, 100, 'pool_a')
    u = api.as_user(seed.user('pooler', role='user', tenant_id='poolco',
                              permissions=['vm.delete']))
    for vt in ('qemu', 'QEMU', 'Qemu', 'lxc'):
        r = u.post(XC, json=_xc_body(vm_type=vt, delete_source=True))
        assert r.status_code == 403, (vt, r.get_data(as_text=True))
    xc_pair.remote_migrate_vm.assert_not_called()
    # and the pool grant itself still moves the guest
    u.post(XC, json=_xc_body(vm_type='qemu', delete_source=False))
    xc_pair.remote_migrate_vm.assert_called_once()


# =========================================================================== #981
# PUT /api/vmware/<id> linked_clusters

VMW = '/api/vmware/vmw_shared'
_VBODY = {'host': 'esxi.example.com', 'port': 443, 'username': 'root',
          'password': '********', 'enabled': False}


@pytest.fixture
def shared_esxi(api, seed):
    from pegaprox.core.vmware import save_vmware_server
    seed.tenant('tenant_a', clusters=[SRC])
    seed.tenant('tenant_b', clusters=[TGT])
    seed.tenant('tenant_c', clusters=['cluster_3'])
    save_vmware_server('vmw_shared', {
        'name': 'Shared ESXi', 'host': 'esxi.example.com', 'port': 443,
        'username': 'root', 'password': 'realpw', 'server_type': 'esxi',
        'linked_clusters': [SRC, TGT]})
    m = MagicMock()
    m.linked_clusters = [SRC, TGT]
    m.host, m.port, m.password = 'esxi.example.com', 443, ''
    ppglobals.vmware_managers['vmw_shared'] = m
    return m


def _links(seed):
    row = seed.db.conn.execute(
        "SELECT linked_clusters FROM vmware_servers WHERE id = ?", ('vmw_shared',)).fetchone()
    return json.loads(row[0] or '[]')


@pytest.fixture
def a_admin(api, seed, shared_esxi):
    return api.as_user(seed.user('a_admin', role='user', tenant_id='tenant_a',
                                 permissions=['vmware.config', 'vmware.view']))


@pytest.mark.parametrize('links', [SRC, {SRC: 1}, [[SRC]], [SRC, 5], 0, False, ''],
                         ids=repr)
def test_esxi_links_of_the_wrong_shape_are_refused(a_admin, seed, links):
    r = a_admin.put(VMW, json={**_VBODY, 'linked_clusters': links})
    assert r.status_code in (400, 403), r.get_data(as_text=True)
    assert _links(seed) == [SRC, TGT]


@pytest.mark.parametrize('links', [None, []], ids=repr)
def test_esxi_links_an_explicit_empty_value_is_admin_only(a_admin, seed, links):
    assert a_admin.put(VMW, json={**_VBODY, 'linked_clusters': links}).status_code == 403
    assert _links(seed) == [SRC, TGT]


def test_esxi_links_mixed_case_is_another_cluster(a_admin, seed):
    r = a_admin.put(VMW, json={**_VBODY, 'linked_clusters': ['CLUSTER_1']})
    assert r.status_code == 403
    assert _links(seed) == [SRC, TGT]


def test_esxi_links_a_tenant_not_linked_cannot_touch_them(api, seed, shared_esxi):
    u = api.as_user(seed.user('c_admin', role='user', tenant_id='tenant_c',
                              permissions=['vmware.config', 'vmware.view']))
    r = u.put(VMW, json={**_VBODY, 'linked_clusters': ['cluster_3']})
    assert r.status_code == 403
    assert _links(seed) == [SRC, TGT]


def test_esxi_links_patch_is_not_a_way_round(a_admin, seed):
    assert a_admin.patch(VMW, json={'linked_clusters': []}).status_code == 405
    assert _links(seed) == [SRC, TGT]


def test_esxi_links_a_user_token_of_an_admin_cannot_unlink(api, seed, shared_esxi):
    seed.user('root', role='admin')
    tok = _token_client(api, 'root', 'user')
    r = tok.put(VMW, json={**_VBODY, 'linked_clusters': []})
    assert r.status_code == 403
    assert _links(seed) == [SRC, TGT]


def test_esxi_links_the_tenant_admin_still_narrows(a_admin, seed):
    r = a_admin.put(VMW, json={**_VBODY, 'linked_clusters': [SRC]})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert _links(seed) == [SRC]


def test_esxi_links_an_admin_still_sets_any_list(api, seed, shared_esxi):
    boss = api.as_user(seed.user('boss', role='admin'))
    r = boss.put(VMW, json={**_VBODY, 'linked_clusters': ['cluster_3']})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert _links(seed) == ['cluster_3']


# =========================================================================== #1106
# POST /api/vmware/<id>/vms/<vm>/migrate: the node only ever talks to the registered host

V2P = '/api/vmware/vmw1/vms/42/migrate'


@pytest.fixture
def v2p_route(api, seed, monkeypatch):
    import pegaprox.api.vmware as vmware_api
    started = []
    monkeypatch.setattr(vmware_api, '_run_v2p_migration', lambda task: started.append(task))
    m = MagicMock()
    m.host, m.linked_clusters = 'esxi1.example.com', []
    m.get_vm.return_value = {'data': {'name': 'guest', 'nics': []}}
    ppglobals.vmware_managers['vmw1'] = m
    seed.tenant('acme', clusters=[TGT])
    # with the node list a real manager has: the start asks target_node against it (#1224)
    api.set_manager(TGT, api.make_fake_manager(TGT)).nodes = {'pve1': {'node': 'pve1'}}
    monkeypatch.setattr(vmware_api, '_vmware_migrations', {})
    return started


def _v2p_body(**kw):
    b = {'target_cluster': TGT, 'target_node': 'pve1', 'target_storage': 'local-lvm',
         'esxi_password': 'pw'}
    b.update(kw)
    return b


@pytest.mark.parametrize('host', ['10.6.6.6', 'esxi1.example.com.evil.invalid',
                                  ['esxi1.example.com'], {'h': 1}, 7], ids=repr)
def test_v2p_a_host_other_than_the_registered_one_is_refused(api, seed, v2p_route, host):
    admin = api.as_user(seed.user('root', role='admin'))
    r = admin.post(V2P, json=_v2p_body(esxi_host=host))
    assert r.status_code == 400, r.get_data(as_text=True)
    assert v2p_route == []


@pytest.mark.parametrize('host', [None, '', 'esxi1.example.com', 'ESXi1.Example.COM',
                                  ' esxi1.example.com '], ids=repr)
def test_v2p_the_task_always_carries_the_registered_host(api, seed, v2p_route, host):
    """The compare accepts spellings of the same host; the task must not inherit them."""
    u = api.as_user(seed.user('ops', role='user', tenant_id='acme'))
    body = _v2p_body() if host is None else _v2p_body(esxi_host=host)
    r = u.post(V2P, json=body)
    assert r.status_code == 202, r.get_data(as_text=True)
    assert v2p_route and v2p_route[0].esxi_host == 'esxi1.example.com'


def test_v2p_a_tenant_without_the_target_cannot_start(api, seed, v2p_route):
    seed.tenant('globex', clusters=['cluster_9'])
    u = api.as_user(seed.user('outsider', role='user', tenant_id='globex'))
    assert u.post(V2P, json=_v2p_body()).status_code == 403
    assert v2p_route == []


def test_xcp_remote_migrate_asks_the_tenant_quota(api, seed, xcp_pools, monkeypatch):
    """A move between two pools of the tenant adds nothing; one onto a counted pool from a
    pool that is not counted adds the guest. A refusal starts nothing."""
    import pegaprox.api.vms as vms_api
    from flask import jsonify
    src, _ = xcp_pools
    asked = []

    def gate(user, what, adds, **kw):
        asked.append(adds())
        return (jsonify({'error': 'quota'}), 403) if len(asked) > 1 else None, None
    monkeypatch.setattr(vms_api, 'tenant_quota_gate', gate)
    monkeypatch.setattr(vms_api, 'guest_size', lambda *a: {'cores': 2, 'memory_gb': 4.0, 'disk_gb': 20.0})
    u = api.as_user(seed.user('ops', role='user', tenant_id='acme'))
    assert u.post(XRMIG, json={**_XBODY, 'target_cluster': 'xcp_b'}).status_code == 200
    assert asked == [None]                      # both pools are acme's: a move adds nothing
    r = u.post(XRMIG, json={**_XBODY, 'target_cluster': 'xcp_b'})
    assert r.status_code == 403 and src.remote_migrate_vm.call_count == 1


def _xcp_manager(power, monkeypatch):
    import types
    from unittest.mock import MagicMock
    from pegaprox.core import xcpng
    login = MagicMock(side_effect=AssertionError('no login to the target'))
    monkeypatch.setattr(xcpng, 'XenAPI', types.SimpleNamespace(
        Session=lambda *a, **k: types.SimpleNamespace(xenapi=types.SimpleNamespace(login_with_password=login))))
    mgr = object.__new__(xcpng.XcpngManager)
    mgr.config = types.SimpleNamespace(ssl_verification=True, user='src', pass_='x')
    api_ = MagicMock()
    api_.VM.get_power_state.return_value = power
    mgr._api = lambda: api_
    mgr._resolve_vm = lambda vmid: 'OpaqueRef:vm'
    mgr.logger = MagicMock()
    target = object.__new__(xcpng.XcpngManager)
    target.config = types.SimpleNamespace(ssl_verification=True, user='root', pass_='y', name='b')
    target._get_xapi_url = lambda: 'https://target.example'
    return mgr, target, api_


@pytest.mark.parametrize('power,online', [('Halted', True), ('Suspended', True), ('Running', False)])
def test_xcp_remote_migrate_moves_a_running_guest_only(monkeypatch, power, online):
    """The other branch shut the guest down hard and copied it within its own pool."""
    mgr, target, api_ = _xcp_manager(power, monkeypatch)
    res = mgr.remote_migrate_vm('xcp1', 100, online=online, target_pool=target)
    assert res['success'] is False and res['code'] == 'NOT_RUNNING'
    assert not api_.VM.hard_shutdown.called and not api_.Async.VM.copy.called
    assert not api_.Async.VM.migrate_send.called


def test_xcp_remote_migrate_a_refused_move_is_a_409(api, seed, xcp_pools):
    src, _ = xcp_pools
    src.remote_migrate_vm.return_value = {'success': False, 'code': 'NOT_RUNNING', 'error': 'not running'}
    admin = api.as_user(seed.user('root', role='admin'))
    assert admin.post(XRMIG, json={**_XBODY, 'target_cluster': 'xcp_b'}).status_code == 409
