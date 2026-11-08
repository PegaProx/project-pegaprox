"""A cross-cluster vnet is a whole-cluster act, not a per-VM one.

check_cluster_access answers reachability, and its #248/#555 fallbacks admit a caller
whose only claim on the cluster is a VM-ACL row or a pool grant - by design, deferring
the real decision downstream. For SDN there is no downstream: a vnet, a zone or an EVPN
controller is cluster-wide plumbing with no per-object notion. A portal user with a
single VM ACL was reaching create, edit, apply, reconcile and delete.

Aikido ai_pentest 700487790. MK
"""
import pytest

import pegaprox.utils.rbac as rbac


def test_an_acl_scoped_caller_cannot_create_a_cross_cluster_vnet(api, db, seed):
    """A vnet is cluster-wide networking with no per-object notion, so there is no
    downstream gate to defer to - check_cluster_access alone let a portal user with one
    VM ACL build and tear down EVPN spans."""
    rbac.invalidate_vm_acls_cache()
    seed.tenant('tenant_a', ['cluster_a'])
    u = seed.user('portal', role='user', tenant_id='tenant_a',
                  permissions=['sdn.manage', 'admin.settings', 'cluster.view'])
    seed.vm_acl('cluster_a', 100, ['portal'])
    rbac.invalidate_vm_acls_cache()

    r = api.as_user(u).post('/api/multi-sdn/vnets',
                            json={'name': 'evil', 'zone': 'z1', 'controller': 'c1',
                                  'vni': 10001, 'asn': 65000,
                                  'cluster_ids': ['cluster_a']})

    assert r.status_code == 403, r.get_data(as_text=True)


def test_an_unconfined_operator_still_reaches_the_sdn_routes(api, db, seed):
    """The invariant: an ordinary cluster operator is not newly locked out. Whatever
    happens after the gate (the cluster is not registered here), it must not be OUR 403."""
    rbac.invalidate_vm_acls_cache()
    seed.tenant('tenant_a', ['cluster_a'])
    u = seed.user('ops', role='user', tenant_id='tenant_a',
                  permissions=['sdn.manage', 'admin.settings', 'cluster.view'])

    r = api.as_user(u).post('/api/multi-sdn/vnets',
                            json={'name': 'span', 'zone': 'z1', 'controller': 'c1',
                                  'vni': 10001, 'asn': 65000,
                                  'cluster_ids': ['cluster_a']})

    body = r.get_data(as_text=True)
    assert not (r.status_code == 403 and 'whole cluster' in body), body
