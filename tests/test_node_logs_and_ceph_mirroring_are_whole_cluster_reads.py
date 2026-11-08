"""A node's journal, the Ceph log and the Ceph mirroring belong to the whole cluster.

GET .../nodes/<node>/syslog hands back the host journal: sshd logins with their source
addresses, the API logins of other accounts, the start, stop and backup lines of every
guest on the node. .../nodes/<node>/ceph/log is the cluster log of the whole Ceph. Both
only asked check_cluster_access, whose VM-ACL and pool fallbacks let a confined caller
in on purpose and leave the real decision to the route. The node task log next to them
already refuses a node-level log to such a caller, and these two now do the same.

The mirroring reads (overview, pool status, schedule list) told the same caller every
pool with its mirror mode, the site names and the peers, and opened SSH sessions to a
node for it. Ceph is the cluster's storage and a pool or a guest grant does not cover
it, which the Ceph overview already says for a confined cluster. So a confined caller
gets an empty answer there, before any SSH, and the mirroring pane shows no pools
instead of an error.

Every test has its counterproof: an operator whose tenant owns the cluster and a global
admin still read all of it.
MK Oct 2026
"""
import types

import pytest

import pegaprox.api.ceph as ceph

CLUSTER = 'cluster_1'

SYSLOG = [{'n': 1, 't': 'sshd[811]: Accepted publickey for root from 10.0.0.9 port 51234'},
          {'n': 2, 't': 'qemu-server[902]: VM 200 started with PID 4711'}]
CEPH_LOG = [{'n': 1, 't': 'mon.pve1 (mon.0) 812 : cluster [WRN] Health check failed: 1 osds down'}]

INFO = {'mode': 'image', 'site_name': 'dc-a',
        'peers': [{'uuid': 'p-1', 'site_name': 'dc-b', 'client_name': 'client.rbd-mirror-peer'}]}
STATUS = {'health': 'OK', 'summary': {'health': 'OK', 'states': {'total': 7, 'replaying': 7}}}
SCHEDULES = [{'interval': '1h', 'start_time': ''}]


@pytest.fixture
def mgr(api, seed):
    seed.tenant('acme', clusters=[CLUSTER])
    seed.tenant('globex', clusters=['cluster_other'])
    m = api.make_fake_manager(CLUSTER)
    m.is_connected = True
    m.host, m.api_port = 'pve1.example', 8006
    return api.set_manager(CLUSTER, m)


def _vm_acl_other_tenant(api, seed):
    """Reaches the cluster only through a VM-ACL on VM 100."""
    seed.vm_acl(CLUSTER, 100, users=['portal'])
    return api.as_user(seed.user('portal', role='viewer', tenant_id='globex'))


def _pool_other_tenant(api, seed):
    """Reaches the cluster only through a grant on pool_a."""
    seed.pool(CLUSTER, 'pool_a', 'poolguy', ['pool.view', 'vm.view'])
    return api.as_user(seed.user('poolguy', role='viewer', tenant_id='globex'))


def _pool_own_tenant(api, seed):
    """Their tenant owns the cluster, a pool grant still confines them to pool_a."""
    seed.pool(CLUSTER, 'pool_a', 'tina', ['pool.view', 'vm.view'])
    return api.as_user(seed.user('tina', role='viewer', tenant_id='acme'))


def _operator(api, seed):
    return api.as_user(seed.user('ops', role='viewer', tenant_id='acme'))


def _admin(api, seed):
    return api.as_user(seed.user('root', role='admin'))


CONFINED = {'vm_acl_other_tenant': _vm_acl_other_tenant,
            'pool_other_tenant': _pool_other_tenant,
            'pool_own_tenant': _pool_own_tenant}
WHOLE_CLUSTER = {'operator': _operator, 'admin': _admin}


def _pve_session(mgr, data):
    """The PVE API session of the fake manager, answering `data`; returns the urls asked."""
    asked = []
    resp = types.SimpleNamespace(status_code=200, json=lambda: {'data': data})

    def get(url, **kw):
        asked.append(url)
        return resp
    mgr._create_session.return_value = types.SimpleNamespace(get=get)
    return asked


# --------------------------------------------------------------------------
# GET .../nodes/<node>/syslog
# --------------------------------------------------------------------------

def _syslog():
    return f'/api/clusters/{CLUSTER}/nodes/pve1/syslog?limit=5000'


@pytest.mark.parametrize('who', sorted(CONFINED))
def test_a_confined_caller_gets_no_node_journal(api, seed, mgr, who):
    mgr.get_node_syslog.return_value = SYSLOG
    r = CONFINED[who](api, seed).get(_syslog())
    assert r.status_code == 403, f'got the host journal: {r.data}'
    assert 'whole cluster' in r.get_json()['error'], 'refused for another reason than confinement'
    mgr.get_node_syslog.assert_not_called()


@pytest.mark.parametrize('who', sorted(WHOLE_CLUSTER))
def test_the_whole_cluster_still_reads_the_node_journal(api, seed, mgr, who):
    mgr.get_node_syslog.return_value = SYSLOG
    r = WHOLE_CLUSTER[who](api, seed).get(_syslog())
    assert r.status_code == 200, r.data
    assert r.get_json() == SYSLOG


# --------------------------------------------------------------------------
# GET .../nodes/<node>/ceph/log
# --------------------------------------------------------------------------

def _ceph_log():
    return f'/api/clusters/{CLUSTER}/nodes/pve1/ceph/log?limit=500'


@pytest.mark.parametrize('who', sorted(CONFINED))
def test_a_confined_caller_gets_no_ceph_log(api, seed, mgr, who):
    asked = _pve_session(mgr, CEPH_LOG)
    r = CONFINED[who](api, seed).get(_ceph_log())
    assert r.status_code == 403, f'got the Ceph cluster log: {r.data}'
    assert 'whole cluster' in r.get_json()['error']
    assert asked == [], 'the node was asked for it anyway'


@pytest.mark.parametrize('who', sorted(WHOLE_CLUSTER))
def test_the_whole_cluster_still_reads_the_ceph_log(api, seed, mgr, who):
    asked = _pve_session(mgr, CEPH_LOG)
    r = WHOLE_CLUSTER[who](api, seed).get(_ceph_log())
    assert r.status_code == 200, r.data
    assert r.get_json() == CEPH_LOG
    assert asked and asked[0].endswith('/nodes/pve1/ceph/log')


# --------------------------------------------------------------------------
# GET .../ceph/mirror/overview, .../mirror/pool/<p>/status, .../mirror/pool/<p>/schedule
# --------------------------------------------------------------------------

@pytest.fixture
def mirror(monkeypatch, mgr):
    """Stands in for the node: the PVE pool list and the rbd commands over SSH.
    Returns what was asked of it, PVE urls and rbd command lines."""
    asked = types.SimpleNamespace(pve=_pve_session(mgr, [{'pool_name': 'rbd'}]), ssh=[])

    def batch(m, ip, args, **kw):
        asked.ssh.extend(args)
        return [((INFO if a.startswith('mirror pool info') else STATUS), None) for a in args]

    def cmd(m, ip, args, **kw):
        asked.ssh.append(args)
        return (SCHEDULES if 'schedule list' in args else STATUS), None

    monkeypatch.setattr(ceph, '_get_any_online_node', lambda m: ('pve1', None))
    monkeypatch.setattr(ceph, '_resolve_node_ip', lambda m, n: '10.0.0.1')
    monkeypatch.setattr(ceph, '_rbd_batch', batch)
    monkeypatch.setattr(ceph, '_rbd_cmd', cmd)
    return asked


MIRROR = f'/api/clusters/{CLUSTER}/ceph/mirror'


# 200 and an empty answer: the mirroring pane shows "no pools", a non-ok answer an error.
# The schedule list stays a list, the shape every caller of it iterates.
EMPTY = [('overview', {'pools': [], 'node': None, 'confined': True}),
         ('pool/rbd/status', {'summary': {}, 'confined': True}),
         ('pool/rbd/schedule', [])]


@pytest.mark.parametrize('who', sorted(CONFINED))
@pytest.mark.parametrize('path,empty', EMPTY, ids=[p for p, _ in EMPTY])
def test_a_confined_caller_sees_no_mirroring_and_costs_no_ssh(api, seed, mirror, who, path, empty):
    r = CONFINED[who](api, seed).get(f'{MIRROR}/{path}')
    assert r.status_code == 200, r.data
    assert r.get_json() == empty
    assert mirror.ssh == [], f'rbd ran on the node for a confined caller: {mirror.ssh}'
    assert mirror.pve == []


@pytest.mark.parametrize('who', sorted(WHOLE_CLUSTER))
def test_the_whole_cluster_still_sees_the_mirroring(api, seed, mirror, who):
    c = WHOLE_CLUSTER[who](api, seed)

    d = c.get(f'{MIRROR}/overview').get_json()
    assert d['node'] == 'pve1' and 'confined' not in d
    pool = d['pools'][0]
    assert pool['name'] == 'rbd' and pool['mode'] == 'image' and pool['image_count'] == 7
    assert pool['peers'][0]['site_name'] == 'dc-b'

    assert c.get(f'{MIRROR}/pool/rbd/status').get_json() == STATUS
    assert c.get(f'{MIRROR}/pool/rbd/schedule').get_json() == SCHEDULES
    assert 'mirror pool info rbd' in mirror.ssh
    assert any(a.startswith('mirror snapshot schedule list') for a in mirror.ssh)
