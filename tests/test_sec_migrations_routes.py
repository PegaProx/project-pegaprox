# -*- coding: utf-8 -*-
"""Migration authorization + credential-flow fixes, end to end. NS Oct 2026.

Covers:
  #1088 / #1048 - an XCP-ng remote migrate logs into the TARGET pool with THAT pool's stored
                  credentials, never a URL from the request; and a PVE remote migrate that
                  deletes the source needs vm.delete, not vm.migrate alone.
  #981          - an ESXi server's linked_clusters can only be narrowed by a non-admin, like
                  the PBS twin; an empty list opens the whole server.
  #1039         - XHM authorizes a standalone ESXi source through the ESXi VM-level check, not
                  the Proxmox vm.* check that falls through to the role permission.
"""
import json
import types
from unittest.mock import MagicMock

import pytest

import pegaprox.globals as ppglobals


# =========================================================================== #1088/#1048
# XcpngManager.remote_migrate_vm: target credentials come from the target pool.

def test_xcpng_remote_migrate_never_sends_stored_creds_to_a_request_url(monkeypatch):
    """Counterproof on 8b36c2a: the method logged into target_endpoint with self.config's
    user+password, so a caller URL received the pool root credential."""
    from pegaprox.core import xcpng

    recorded = {}

    class _Sess:
        def __init__(self, url, ignore_ssl=None):
            recorded['url'] = url
            self._session = 'ref'
            self.xenapi = self
        def login_with_password(self, user, pw, *a):
            recorded['user'] = user
            recorded['pw'] = pw

    src = object.__new__(xcpng.XcpngManager)
    src.config = types.SimpleNamespace(ssl_verification=False, user='SRC', pass_='SRCPW', name='src')
    # running: a guest that is not is refused before any session is built
    src._api = lambda: types.SimpleNamespace(
        VM=types.SimpleNamespace(get_power_state=lambda r: 'Running'))
    src._resolve_vm = lambda v: 'vmref'
    import logging
    src.logger = logging.getLogger('t.xcpng')

    tgt = object.__new__(xcpng.XcpngManager)
    tgt.config = types.SimpleNamespace(ssl_verification=True, user='TGT', pass_='TGTPW', name='tgt')
    tgt._get_xapi_url = lambda: 'https://target-pool.internal'

    # monkeypatch, not assignment: both are module state the next test file in this
    # worker would otherwise inherit (the HA guard above all)
    monkeypatch.setattr(xcpng.ha_transport, 'guard_xapi', lambda s: s)
    monkeypatch.setattr(xcpng, 'XenAPI', types.SimpleNamespace(Session=_Sess), raising=False)

    # a caller-chosen endpoint must be ignored entirely
    src.remote_migrate_vm('node1', 101, target_endpoint='https://attacker.evil',
                          target_pool=tgt)

    assert recorded['url'] == 'https://target-pool.internal'
    assert recorded['user'] == 'TGT' and recorded['pw'] == 'TGTPW'
    assert 'SRCPW' not in recorded.values()


def test_xcpng_remote_migrate_refuses_without_a_registered_target_pool():
    from pegaprox.core import xcpng
    src = object.__new__(xcpng.XcpngManager)
    src.config = types.SimpleNamespace(ssl_verification=False, user='SRC', pass_='SRCPW', name='src')
    r = src.remote_migrate_vm('node1', 101, target_endpoint='https://attacker.evil')
    assert r['success'] is False
    assert 'XCP-ng pool' in r['error']


# =========================================================================== #1048
# The PVE per-node remote-migrate route: delete_source is a delete, so it needs vm.delete.

CID = 'cluster_1'
RMIG = f'/api/clusters/{CID}/vms/pve1/qemu/100/remote-migrate'
_RBODY = {'target_endpoint': 'apitoken=PVEAPIToken=x!y=z,host=h,fingerprint=f',
          'target_storage': 'local-lvm', 'target_bridge': 'vmbr0'}


def _pve_fake(api):
    return api.set_manager(CID, api.make_fake_manager(
        cluster_id=CID, cluster_type='proxmox',
        remote_migrate_vm={'success': True, 'task': 'UPID:pve1:rmig:'}))


def test_migrate_acl_user_without_vm_delete_cannot_delete_the_source(api, seed):
    """An ACL grants vm.migrate but never vm.delete (inherit_role set). delete_source=True
    on 8b36c2a went through on vm.migrate alone."""
    fake = _pve_fake(api)
    seed.tenant('t_a', clusters=[])        # reaches the cluster only via the ACL
    seed.vm_acl(CID, 100, ['acluser'], inherit_role=True)
    u = api.as_user(seed.user('acluser', role='user', tenant_id='t_a'))
    r = u.post(RMIG, json={**_RBODY, 'delete_source': True})
    assert r.status_code == 403, r.get_data(as_text=True)
    assert 'vm.delete' in r.get_data(as_text=True)
    fake.remote_migrate_vm.assert_not_called()


def test_the_same_user_may_migrate_without_deleting_the_source(api, seed):
    fake = _pve_fake(api)
    seed.tenant('t_a', clusters=[])
    seed.vm_acl(CID, 100, ['acluser'], inherit_role=True)
    u = api.as_user(seed.user('acluser', role='user', tenant_id='t_a'))
    r = u.post(RMIG, json={**_RBODY, 'delete_source': False})
    assert r.status_code == 200, r.get_data(as_text=True)
    fake.remote_migrate_vm.assert_called_once()


def test_an_admin_can_still_delete_the_source(api, seed):
    fake = _pve_fake(api)
    admin = api.as_user(seed.user('root', role='admin'))
    r = admin.post(RMIG, json={**_RBODY, 'delete_source': True})
    assert r.status_code == 200, r.get_data(as_text=True)
    fake.remote_migrate_vm.assert_called_once()


def test_xcpng_remote_migrate_route_demands_a_registered_target_pool(api, seed):
    api.set_manager(CID, api.make_fake_manager(cluster_id=CID, cluster_type='xcpng',
                                               remote_migrate_vm={'success': True, 'task': 't'}))
    admin = api.as_user(seed.user('root', role='admin'))
    # a raw endpoint is no longer accepted for an XCP-ng source
    r = admin.post(RMIG, json={'target_endpoint': 'https://attacker.evil',
                               'target_storage': 'sr', 'target_bridge': 'xenbr0'})
    assert r.status_code == 400
    assert 'XCP-ng pool' in r.get_data(as_text=True)


# =========================================================================== #981
# ESXi server linked_clusters: a non-admin may only narrow it.

VMW = '/api/vmware/vmw_shared'
_VVALID = {'host': 'esxi.example.com', 'port': 443, 'username': 'root',
           'password': '********', 'enabled': False}


@pytest.fixture
def linked_vmware(api, seed):
    from pegaprox.core.vmware import save_vmware_server
    ppglobals.vmware_managers.clear()
    seed.tenant('tenant_a', clusters=['cluster_1'])
    seed.tenant('tenant_b', clusters=['cluster_2'])
    save_vmware_server('vmw_shared', {
        'name': 'Shared ESXi', 'host': 'esxi.example.com', 'port': 443,
        'username': 'root', 'password': 'realpw', 'server_type': 'esxi',
        'linked_clusters': ['cluster_1', 'cluster_2'],
    })
    m = MagicMock()
    m.linked_clusters = ['cluster_1', 'cluster_2']
    m.host, m.port = 'esxi.example.com', 443
    m.password = ''        # the preserved-credential branch reads this back into `data`
    ppglobals.vmware_managers['vmw_shared'] = m
    try:
        yield m
    finally:
        ppglobals.vmware_managers.clear()


def _stored_vmw_links(seed):
    row = seed.db.conn.execute(
        "SELECT linked_clusters FROM vmware_servers WHERE id = ?", ('vmw_shared',)).fetchone()
    if row is None:
        return None
    return json.loads(row[0] or '[]')


@pytest.fixture
def tenant_a_vmware_admin(api, seed, linked_vmware):
    return api.as_user(seed.user('a_admin', role='user', tenant_id='tenant_a',
                                 permissions=['vmware.config', 'vmware.view']))


def test_a_tenant_caller_cannot_unlink_the_esxi_server_from_everything(tenant_a_vmware_admin, seed):
    r = tenant_a_vmware_admin.put(VMW, json={**_VVALID, 'linked_clusters': []})
    assert _stored_vmw_links(seed) != [], 'the ESXi server was opened to every tenant on disk'
    assert r.status_code == 403, r.get_data(as_text=True)


def test_a_tenant_caller_cannot_link_it_to_an_unreachable_cluster(tenant_a_vmware_admin, seed):
    r = tenant_a_vmware_admin.put(VMW, json={**_VVALID,
                                             'linked_clusters': ['cluster_1', 'cluster_9']})
    assert 'cluster_9' not in (_stored_vmw_links(seed) or []), 'the foreign link was persisted'
    assert r.status_code == 403
    assert 'cluster_9' in r.get_data(as_text=True)


def test_a_tenant_caller_may_narrow_to_its_own_cluster(tenant_a_vmware_admin):
    r = tenant_a_vmware_admin.put(VMW, json={**_VVALID, 'linked_clusters': ['cluster_1']})
    assert r.status_code == 200, r.get_data(as_text=True)


def test_an_update_not_mentioning_links_keeps_them(tenant_a_vmware_admin, seed):
    r = tenant_a_vmware_admin.put(VMW, json={**_VVALID, 'name': 'Renamed'})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert set(_stored_vmw_links(seed) or []) == {'cluster_1', 'cluster_2'}


def test_a_global_admin_can_still_unlink_the_esxi_server(api, seed, linked_vmware):
    boss = api.as_user(seed.user('boss', role='admin'))
    r = boss.put(VMW, json={**_VVALID, 'linked_clusters': []})
    assert r.status_code == 200, r.get_data(as_text=True)
