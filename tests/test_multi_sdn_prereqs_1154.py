"""E2E coverage for POST /api/multi-sdn/prerequisites (#1154).

The endpoint batches every per-node probe into ONE SSH round-trip and fans
the nodes out through run_per_node, 8 per cluster, so the tests pin four things a
refactor could silently break: the authz shape (whole-cluster, unconfined -
the same gate as the vnet writes), the label parsing incl. the PVE >= 8
floor, the one-SSH-call-per-node property, and the parallel fan-out with
offline nodes and timeouts answered without another SSH round-trip.
"""
import types

import pytest

import pegaprox.utils.rbac as rbac
import pegaprox.utils.ssh as sshmod

from pegaprox.api import multi_sdn as msdn


GOOD_OUTPUT = '\n'.join([
    'pve=pve-manager/8.4-1',
    'frr_pkg=1',
    'frr_py=1',
    'frr_srv=active',
    'ifup2=1',
    'src_d=1',
    'fwd=1',
    'ntp=yes',
])

PVE7_OUTPUT = GOOD_OUTPUT.replace('pve-manager/8.4-1', 'pve-manager/7.4-3') \
                         .replace('frr_pkg=1', 'frr_pkg=0') \
                         .replace('frr_py=1', 'frr_py=0') \
                         .replace('frr_srv=active', 'frr_srv=inactive') \
                         .replace('fwd=1', 'fwd=0') \
                         .replace('ntp=yes', 'ntp=no')

PVE10_OUTPUT = GOOD_OUTPUT.replace('pve-manager/8.4-1', 'pve-manager/10.0-1')

GARBAGE_PVE_OUTPUT = GOOD_OUTPUT.replace('pve=pve-manager/8.4-1', 'pve=garbage')

# only a commented source line: the anchored grep counts zero matches
COMMENTED_ONLY_OUTPUT = GOOD_OUTPUT.replace('src_d=1', 'src_d=0')


def _admin(api, seed):
    return api.as_user(seed.user('pradmin', role='admin'))


def _fake_manager(api, cluster_id, nodes, node_ip='10.0.0.5', connected=True):
    m = api.make_fake_manager(cluster_id, _get_node_ip=node_ip)
    m.nodes = dict(nodes)
    m.config = types.SimpleNamespace(name=cluster_id)
    m.is_connected = connected
    return api.set_manager(cluster_id, m)


def _online(*names):
    return {n: {'status': 'online'} for n in names}


def test_anon_401(api, seed):
    assert api.anon().post('/api/multi-sdn/prerequisites',
                           json={'cluster_ids': ['c1']}).status_code == 401


def test_user_without_sdn_perms_403(api, db, seed):
    u = seed.user('plain', role='user')
    r = api.as_user(u).post('/api/multi-sdn/prerequisites', json={'cluster_ids': ['c1']})
    assert r.status_code == 403, r.get_data(as_text=True)


@pytest.mark.parametrize('payload', [
    {},
    {'cluster_ids': []},
    {'cluster_ids': 'cluster_a'},
    {'cluster_ids': 7},
    {'cluster_ids': [{}]},
    {'cluster_ids': ['']},
    {'cluster_ids': ['a', 5]},
    {'cluster_ids': ['c%d' % i for i in range(51)]},
])
def test_rejects_missing_or_malformed_cluster_ids(api, db, seed, payload):
    r = _admin(api, seed).post('/api/multi-sdn/prerequisites', json=payload)
    assert r.status_code == 400
    assert 'cluster_ids' in (r.get_json().get('error') or '')


def test_acl_scoped_operator_gets_whole_cluster_403(api, db, seed, monkeypatch):
    """Same invariant as the vnet writes: a VM-ACL is not a claim on cluster-wide
    SDN state, and host-level SSH output + node IPs are not for a scoped caller."""
    rbac.invalidate_vm_acls_cache()
    seed.tenant('tenant_p', ['cluster_p'])
    u = seed.user('portalops', role='user', tenant_id='tenant_p',
                  permissions=['sdn.manage', 'admin.settings', 'cluster.view'])
    seed.vm_acl('cluster_p', 100, ['portalops'])
    rbac.invalidate_vm_acls_cache()
    _fake_manager(api, 'cluster_p', _online('pve1'))

    def _boom(*a, **k):
        raise AssertionError('SSH probe ran for a confined caller')
    monkeypatch.setattr(msdn, '_check_node_prereqs', _boom)

    r = api.as_user(u).post('/api/multi-sdn/prerequisites',
                            json={'cluster_ids': ['cluster_p']})
    body = r.get_data(as_text=True)
    assert r.status_code == 403 and 'whole cluster' in body, body


def test_unconfined_operator_proceeds_past_the_gate(api, db, seed):
    """The allow-direction: an ordinary operator whose tenant owns the cluster is
    not newly locked out (here the cluster resolves but has no nodes)."""
    seed.tenant('tenant_o', ['cluster_o'])
    u = seed.user('ops2', role='user', tenant_id='tenant_o',
                  permissions=['sdn.manage', 'admin.settings', 'cluster.view'])
    _fake_manager(api, 'cluster_o', {})

    r = api.as_user(u).post('/api/multi-sdn/prerequisites',
                            json={'cluster_ids': ['cluster_o']})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['summary']['nodes_checked'] == 0


def test_unknown_and_offline_members_land_in_errors(api, db, seed):
    c = _admin(api, seed)
    r = c.post('/api/multi-sdn/prerequisites', json={'cluster_ids': ['ghost']})
    assert r.status_code == 200
    body = r.get_json()
    assert body['errors'] == [{'cluster_id': 'ghost', 'reason': 'not_found'}]
    assert body['summary']['nodes_checked'] == 0

    _fake_manager(api, 'cl_off', _online('pve1'), connected=False)
    r = c.post('/api/multi-sdn/prerequisites', json={'cluster_ids': ['cl_off']})
    assert r.status_code == 200
    assert r.get_json()['errors'][0]['reason'] == 'offline'


def test_happy_path_parses_labels_and_maps_mgmt_ip(api, db, seed, monkeypatch):
    _fake_manager(api, 'cl_a', _online('pve1'), node_ip='10.0.0.5')
    monkeypatch.setattr(sshmod, '_pve_node_exec',
                        lambda *a, **k: (0, GOOD_OUTPUT, ''))

    r = _admin(api, seed).post('/api/multi-sdn/prerequisites',
                               json={'cluster_ids': ['cl_a']})
    assert r.status_code == 200, r.get_data(as_text=True)
    body = r.get_json()
    assert body['summary'] == {'nodes_checked': 1, 'nodes_ok': 1, 'nodes_with_issues': 0}
    check = body['checks'][0]
    assert check['node'] == 'pve1' and check['cluster_id'] == 'cl_a'
    assert {i['id']: i['status'] for i in check['items']} == {
        'pve': 'ok', 'frr_pkg': 'ok', 'frr_py': 'ok', 'frr_srv': 'ok',
        'ifup2': 'ok', 'src_d': 'ok', 'fwd': 'ok', 'ntp': 'ok'}
    assert 'mtu' not in check
    # the address is what PegaProx reaches the node on, named as such
    assert check['mgmt_ip'] == '10.0.0.5'
    assert 'underlay_ip' not in check
    assert body['node_ips'] == {'cl_a:pve1': '10.0.0.5'}


def test_unreadable_pve_version_is_unknown_not_fail(api, db, seed, monkeypatch):
    _fake_manager(api, 'cl_v', _online('pve1'), node_ip='10.0.0.9')
    monkeypatch.setattr(sshmod, '_pve_node_exec',
                        lambda *a, **k: (0, GARBAGE_PVE_OUTPUT, ''))
    r = _admin(api, seed).post('/api/multi-sdn/prerequisites',
                               json={'cluster_ids': ['cl_v']})
    assert r.status_code == 200
    items = {i['id']: i for i in r.get_json()['checks'][0]['items']}
    assert items['pve']['status'] == 'unknown'   # version not readable


def test_pve10_passes_the_floor(api, db, seed, monkeypatch):
    _fake_manager(api, 'cl_w', _online('pve1'), node_ip='10.0.0.9')
    monkeypatch.setattr(sshmod, '_pve_node_exec',
                        lambda *a, **k: (0, PVE10_OUTPUT, ''))
    r = _admin(api, seed).post('/api/multi-sdn/prerequisites',
                               json={'cluster_ids': ['cl_w']})
    items = {i['id']: i for i in r.get_json()['checks'][0]['items']}
    assert items['pve']['status'] == 'ok'


def test_pve7_and_missing_frr_are_fail_with_fix_hint(api, db, seed, monkeypatch):
    _fake_manager(api, 'cl_b', _online('pve1'), node_ip='10.0.0.6')
    monkeypatch.setattr(sshmod, '_pve_node_exec',
                        lambda *a, **k: (0, PVE7_OUTPUT, ''))

    r = _admin(api, seed).post('/api/multi-sdn/prerequisites',
                               json={'cluster_ids': ['cl_b']})
    assert r.status_code == 200
    body = r.get_json()
    items = {i['id']: i for i in body['checks'][0]['items']}
    # SDN needs PVE >= 8: a healthy 7.x node must not pass
    assert items['pve']['status'] == 'fail'
    assert items['frr_pkg']['status'] == 'fail'
    assert items['frr_pkg']['fix_hint'] == 'apt install frr'
    assert items['frr_py']['status'] == 'fail'
    assert items['frr_py']['fix_hint'] == 'apt install frr-pythontools'
    # service/time-sync gaps are warnings, not hard failures
    assert items['frr_srv']['status'] == 'warn'
    assert items['ntp']['status'] == 'warn'
    assert body['summary'] == {'nodes_checked': 1, 'nodes_ok': 0, 'nodes_with_issues': 1}


def test_commented_source_line_counts_as_missing(api, db, seed, monkeypatch):
    _fake_manager(api, 'cl_s', _online('pve1'), node_ip='10.0.0.7')
    monkeypatch.setattr(sshmod, '_pve_node_exec',
                        lambda *a, **k: (0, COMMENTED_ONLY_OUTPUT, ''))

    r = _admin(api, seed).post('/api/multi-sdn/prerequisites',
                               json={'cluster_ids': ['cl_s']})
    items = {i['id']: i for i in r.get_json()['checks'][0]['items']}
    assert items['src_d']['status'] == 'fail'


def test_script_checks_frr_pythontools_and_drops_vxlan_and_mtu():
    """The batched script is the contract with the node: constants, asserted
    directly because no route call can observe the shell line."""
    script = msdn._PREREQ_SCRIPT
    assert "frr_py=$(dpkg -l frr-pythontools 2>/dev/null | grep -c '^ii')" in script
    assert 'vxlan' not in script
    assert 'mtu' not in script
    # anchored source check: a '#source ...' comment line must not count
    assert "grep -cE '^[[:space:]]*source[[:space:]]+/etc/network/interfaces\\.d/'" in script


def test_unreachable_node_marks_every_item_unknown(api, db, seed, monkeypatch):
    _fake_manager(api, 'cl_c', _online('pve1'), node_ip='10.0.0.7')
    monkeypatch.setattr(sshmod, '_pve_node_exec',
                        lambda *a, **k: (1, '', 'SSH connect timeout'))

    r = _admin(api, seed).post('/api/multi-sdn/prerequisites',
                               json={'cluster_ids': ['cl_c']})
    assert r.status_code == 200
    check = r.get_json()['checks'][0]
    assert all(i['status'] == 'unknown' for i in check['items'])
    assert 'SSH connect timeout' in check['items'][0]['detail']
    assert check['ip_error']
    assert r.get_json()['node_ips'] == {}


def test_one_ssh_roundtrip_per_node(api, db, seed, monkeypatch):
    """The batching property: N nodes cost N SSH calls, not 8*N."""
    _fake_manager(api, 'cl_d', _online('pve1', 'pve2', 'pve3'), node_ip='10.0.0.8')
    calls = []

    def _exec(mgr, node, cmd, timeout=20):
        calls.append(node)
        return 0, GOOD_OUTPUT, ''
    monkeypatch.setattr(sshmod, '_pve_node_exec', _exec)

    r = _admin(api, seed).post('/api/multi-sdn/prerequisites',
                               json={'cluster_ids': ['cl_d']})
    assert r.status_code == 200
    assert sorted(calls) == ['pve1', 'pve2', 'pve3']


def test_offline_node_is_listed_without_an_ssh_call(api, db, seed, monkeypatch):
    _fake_manager(api, 'cl_e', {'pve1': {'status': 'online'},
                                'pve2': {'status': 'offline'}})
    calls = []

    def _exec(mgr, node, cmd, timeout=20):
        calls.append(node)
        return 0, GOOD_OUTPUT, ''
    monkeypatch.setattr(sshmod, '_pve_node_exec', _exec)

    r = _admin(api, seed).post('/api/multi-sdn/prerequisites',
                               json={'cluster_ids': ['cl_e']})
    assert r.status_code == 200
    body = r.get_json()
    assert calls == ['pve1']
    checks = {c['node']: c for c in body['checks']}
    assert set(checks) == {'pve1', 'pve2'}
    assert all(i['status'] == 'unknown' and i['detail'] == 'node offline'
               for i in checks['pve2']['items'])


def test_the_route_fans_out_through_run_per_node(api, db, seed, monkeypatch):
    _fake_manager(api, 'cl_f', _online('pve1'))
    seen = []
    real = msdn.run_per_node

    def _spy(tasks, max_concurrent=8, timeout=120, whole=False):
        seen.append((sorted(tasks), max_concurrent, whole))
        return real(tasks, max_concurrent=max_concurrent, timeout=timeout, whole=whole)
    monkeypatch.setattr(msdn, 'run_per_node', _spy)

    monkeypatch.setattr(sshmod, '_pve_node_exec',
                        lambda *a, **k: (0, GOOD_OUTPUT, ''))
    r = _admin(api, seed).post('/api/multi-sdn/prerequisites',
                               json={'cluster_ids': ['cl_f']})
    assert r.status_code == 200
    # the nodes of a cluster 8 at a time, with the request's deadline
    assert (['pve1'], 8, True) in seen


def test_a_timed_out_node_is_unknown_not_a_crash(api, db, seed, monkeypatch):
    _fake_manager(api, 'cl_g', _online('pve1', 'pve2'), node_ip='10.0.0.9')
    real = msdn.run_per_node

    def _one_times_out(tasks, **kw):
        out = real(tasks, **kw)
        if 'pve1' in out:
            out['pve1'] = None   # run_per_node answers None past its deadline
        return out
    monkeypatch.setattr(msdn, 'run_per_node', _one_times_out)
    monkeypatch.setattr(sshmod, '_pve_node_exec',
                        lambda *a, **k: (0, GOOD_OUTPUT, ''))

    r = _admin(api, seed).post('/api/multi-sdn/prerequisites',
                               json={'cluster_ids': ['cl_g']})
    assert r.status_code == 200
    checks = {c['node']: c for c in r.get_json()['checks']}
    assert all(i['status'] == 'unknown' and i['detail'] == 'timeout'
               for i in checks['pve1']['items'])
    assert checks['pve2']['items'][0]['status'] == 'ok'


def test_duplicate_cluster_ids_probe_once(api, db, seed, monkeypatch):
    _fake_manager(api, 'cl_h', _online('pve1'))
    rounds = []

    def _exec(mgr, node, cmd, timeout=20):
        rounds.append(node)
        return 0, GOOD_OUTPUT, ''
    monkeypatch.setattr(sshmod, '_pve_node_exec', _exec)

    r = _admin(api, seed).post('/api/multi-sdn/prerequisites',
                               json={'cluster_ids': ['cl_h', 'cl_h']})
    assert r.status_code == 200
    assert rounds == ['pve1']
    assert r.get_json()['summary']['nodes_checked'] == 1


def test_node_ips_are_keyed_by_cluster_id_not_name(api, db, seed, monkeypatch):
    # two clusters with the same display name must not overwrite each other
    a = _fake_manager(api, 'id_a', _online('pve1'), node_ip='10.1.0.1')
    b = _fake_manager(api, 'id_b', _online('pve1'), node_ip='10.2.0.1')
    a.config = types.SimpleNamespace(name='twin')
    b.config = types.SimpleNamespace(name='twin')
    monkeypatch.setattr(sshmod, '_pve_node_exec',
                        lambda *a, **k: (0, GOOD_OUTPUT, ''))

    r = _admin(api, seed).post('/api/multi-sdn/prerequisites',
                               json={'cluster_ids': ['id_a', 'id_b']})
    assert r.status_code == 200
    assert r.get_json()['node_ips'] == {'id_a:pve1': '10.1.0.1', 'id_b:pve1': '10.2.0.1'}
