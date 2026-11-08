"""Reading a node's hardening state is a whole-node act, like applying it.

GET /api/clusters/<c>/nodes/<n>/hardening runs root checks on the node over SSH and, with
verbose=1, returns the node's own security evidence (sshd settings, PAM, kernel
parameters, audit rules). It sat behind check_cluster_access alone, which admits a caller
confined to a pool or to some VMs on the cluster, including another tenant's user whose
only reach is a pool grant. The POST and rollback twins already refused them; there is no
per-object notion of a node to narrow it to.
"""
import pytest

CL = 'cluster_1'
NODE = 'pve1'
CONTROLS = [{'id': 'sshd_hardening', 'status': 'fail', 'evidence': 'PermitRootLogin yes'}]


@pytest.fixture
def mgr(api, seed):
    seed.db.execute('''INSERT INTO clusters (id, name, host, user, pass_encrypted)
                       VALUES (?, ?, '10.0.0.1', 'root@pam', 'x')''', (CL, CL))
    seed.tenant('t', [CL])
    seed.tenant('other', ['cluster_9'])
    m = api.make_fake_manager(CL, check_node_hardening=CONTROLS)
    m.is_connected = True
    m._effective_profile = lambda p: p or 'cis-l1'
    return api.set_manager(CL, m)


def _check(client):
    return client.get(f'/api/clusters/{CL}/nodes/{NODE}/hardening?verbose=1')


@pytest.mark.parametrize('who', ['pool_in_own_tenant', 'pool_from_other_tenant', 'vm_acl'])
def test_a_confined_caller_runs_no_check_and_reads_no_evidence(api, seed, mgr, who):
    perms = ['node.maintenance', 'cluster.view', 'vm.view']
    if who == 'pool_in_own_tenant':
        u = seed.user('poolie', role='viewer', tenant_id='t', permissions=perms)
        seed.pool(CL, 'shop', 'poolie', ['vm.start'])
    elif who == 'pool_from_other_tenant':
        u = seed.user('foreign', role='viewer', tenant_id='other', permissions=perms)
        seed.pool(CL, 'shop', 'foreign', ['vm.start'])
    else:
        u = seed.user('portal', role='viewer', tenant_id='t', permissions=perms)
        seed.vm_acl(CL, 100, ['portal'], permissions=['vm.view'])
    r = _check(api.as_user(u))
    assert r.status_code == 403, r.get_data(as_text=True)
    assert 'PermitRootLogin' not in r.get_data(as_text=True)
    mgr.check_node_hardening.assert_not_called()


@pytest.mark.parametrize('who', ['operator', 'admin'])
def test_an_unconfined_operator_and_an_admin_still_check(api, seed, mgr, who):
    u = (seed.user('root', role='admin') if who == 'admin'
         else seed.user('op', role='viewer', tenant_id='t', permissions=['node.maintenance']))
    r = _check(api.as_user(u))
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['controls'] == CONTROLS and r.get_json()['verbose'] is True
