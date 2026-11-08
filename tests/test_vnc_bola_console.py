# Security regression for the VNC BOLA a pentest report claimed: a portal/scoped user obtains a
# console ws_token, then substitutes a FOREIGN vmid on the vncwebsocket URL to open a console to a
# VM outside their scope. The claim is that the token/pve_ticket aren't bound to the vmid.
#
# They don't need to be: the vncwebsocket handler re-authorizes the token's user against the URL
# vmid via _console_authz -> user_can_access_vm(..., 'vm.console'), independent of the token. A
# substituted vmid is rejected with 403 before any PVE connection. This pins that (H-1/H-2, #490).

from pegaprox.utils.realtime import create_ws_token

ROUTE = '/api/clusters/cluster_1/vms/pve1/qemu/{vmid}/vncwebsocket?token={tok}'


def _reacher(seed):
    # alice's tenant does NOT include cluster_1; she reaches it ONLY through a VM-ACL grant on
    # VM 100, so every other VM on cluster_1 must be denied downstream.
    seed.tenant('tenant_iso', clusters=['cluster_other'])
    seed.user('alice', role='user', tenant_id='tenant_iso', permissions=['vm.console'])
    seed.vm_acl('cluster_1', 100, users=['alice'], inherit_role=True)
    return 'alice'


def _tok(api, user):
    with api.app.app_context():
        return create_ws_token(user, 'user')


def test_vnc_token_cannot_be_replayed_against_a_foreign_vmid(api, seed):
    alice = _reacher(seed)
    api.set_manager('cluster_1', api.make_fake_manager())
    # a valid token for alice, replayed against VM 101 she does NOT own
    r = api.anon().get(ROUTE.format(vmid=101, tok=_tok(api, alice)))
    assert r.status_code == 403, r.get_data(as_text=True)
    assert 'INSUFFICIENT' in r.get_data(as_text=True) or 'denied' in r.get_data(as_text=True).lower()


def test_vnc_token_allowed_for_own_vm(api, seed):
    # positive control: her own VM 100 clears the per-VM console gate (not 403).
    alice = _reacher(seed)
    api.set_manager('cluster_1', api.make_fake_manager())
    r = api.anon().get(ROUTE.format(vmid=100, tok=_tok(api, alice)))
    assert r.status_code != 403, r.get_data(as_text=True)


def test_vnc_requires_a_token(api, seed):
    _reacher(seed)
    api.set_manager('cluster_1', api.make_fake_manager())
    r = api.anon().get('/api/clusters/cluster_1/vms/pve1/qemu/101/vncwebsocket')
    assert r.status_code in (401, 403), r.get_data(as_text=True)
