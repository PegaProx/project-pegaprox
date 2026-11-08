"""Attack round on the least-privilege code: the role recipe, the capability matrix and the
quorum gate of a rolling update.

Each test here asserts a property the code claims and does not hold on ac231cd.
"""
import types

import pytest

from pegaprox.core import pve_access, qdevice, rolling_runs

CID = 'cluster_1'


# -- the quorum gate --------------------------------------------------------------------------

def _status(online=None, quorate=1, names=('pve1', 'pve2', 'pve3'), cluster=True):
    online = set(names if online is None else online)
    rows = [{'type': 'node', 'name': n, 'online': int(n in online), 'ip': f'10.0.0.{i + 1}'}
            for i, n in enumerate(names)]
    if cluster:
        rows.insert(0, {'type': 'cluster', 'name': 'lab', 'quorate': quorate, 'nodes': len(names)})
    return rows


class _Mgr:
    cluster_type = 'proxmox'

    def __init__(self, entries):
        self.id = CID
        self.entries = entries
        self.ha_config = {'fence_strategy': {'two_node_flag': False}}

    def _ha_cluster_status(self):
        return [dict(e) for e in self.entries] if self.entries is not None else None


@pytest.fixture
def no_votes(monkeypatch):
    monkeypatch.setattr(rolling_runs, '_config_votes', lambda mgr: {})


def _qd_row(node, connected):
    return {'node': node, 'online': True, 'api_host': node == 'pve1', 'asked': True, 'answered': True,
            'present': True, 'connected': connected, 'state': 'Connected' if connected else 'Disconnected',
            'last_poll': None, 'echo_reply': None, 'error': None}


def test_the_qdevice_vote_is_not_counted_for_a_node_whose_own_daemon_is_disconnected(monkeypatch, no_votes):
    """Two nodes and a QDevice. qdevice.view says 'Connected' from the API host pve1, while
    the daemon on pve2 has lost its qnetd (its own row says so). With pve1 down only pve2
    is left: its daemon cannot bring the QDevice vote, so it holds 1 of 3 votes and needs 2.
    The gate takes the API host's state for the whole cluster and lets pve1 go."""
    view = {'present': True, 'answered_by': 'pve1', 'api_node': 'pve1', 'state': 'Connected',
            'algorithm': 'Fast Semi-Split', 'nodes': [_qd_row('pve1', True), _qd_row('pve2', False)]}
    monkeypatch.setattr(qdevice, 'view', lambda cid, mgr, *a, **k: view)
    m = _Mgr(_status(names=('pve1', 'pve2')))
    verdict = rolling_runs.quorum_without(rolling_runs.quorum_facts(m), 'pve1')
    assert not verdict['ok'], verdict
    # the other way round it is right: pve1, whose daemon is connected, stays
    assert rolling_runs.quorum_without(rolling_runs.quorum_facts(m), 'pve2')['ok']


class _Session:
    def __init__(self, body):
        self.body = body

    def get(self, url, **kw):
        body = self.body
        return types.SimpleNamespace(status_code=200, json=lambda: body)


def _real_status_reader(body):
    """PegaProxManager._ha_cluster_status over a session that answers 200 with `body`."""
    from pegaprox.core.manager import PegaProxManager
    m = _Mgr(None)
    m.host, m.api_port = '10.0.0.1', 8006
    m.logger = __import__('logging').getLogger('test')
    m._bracket_ipv6 = lambda h: h
    m._create_session = lambda: _Session(body)
    m._ha_cluster_status = types.MethodType(PegaProxManager._ha_cluster_status, m)
    return m


@pytest.mark.parametrize('case', ['data_null', 'empty_list', 'nodes_without_cluster_entry'])
def test_an_answer_that_is_no_single_node_does_not_pass_as_one(no_votes, case):
    """quorum_facts reads 'no cluster entry' as a standalone node with nothing to lose. An
    answer with no node at all (a 200 whose data is null or empty) or three nodes, two of them
    offline, and no cluster entry is no standalone node, and the gate must not wave the node
    through. manager._ha_quorum_in already answers None for the first ('not a yes')."""
    if case == 'data_null':
        m = _real_status_reader({'data': None})
    elif case == 'empty_list':
        m = _real_status_reader({'data': []})
    else:
        m = _Mgr(_status(online=('pve1',), cluster=False))
    verdict = rolling_runs.quorum_without(rolling_runs.quorum_facts(m), 'pve1')
    assert not verdict['ok'], (case, verdict)


# -- the role recipe ----------------------------------------------------------------------------

# PegaProx routes that write to Proxmox VE under a feature the recipe offers, the PVE call
# they make, and the privilege the PVE API schema checks for it:
#   POST /cluster/mapping/dir  check => ['perm', '/mapping/dir', ['Mapping.Modify']]
#   POST /pools                check => ['perm', '/pool/{poolid}', ['Pool.Allocate']]
WRITES = [
    ('mappings', 'POST', '/api/clusters/<cluster_id>/datacenter/mapping/dir', 'pegaprox/api/vms.py',
     '/api2/json/cluster/mapping/dir', 'Mapping.Modify'),
    ('pools', 'POST', '/api/clusters/<cluster_id>/pools', 'pegaprox/core/manager.py',
     '/api2/json/pools"', 'Pool.Allocate'),
]


@pytest.mark.parametrize('feature,method,rule,source,pve_call,priv', WRITES, ids=[w[0] for w in WRITES])
def test_the_role_of_a_feature_holds_what_pve_asks_for_the_writes_pegaprox_makes_under_it(
        _integration_app, feature, method, rule, source, pve_call, priv):
    import os
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    app = _integration_app
    assert any(r.rule == rule and method in r.methods for r in app.url_map.iter_rules()), rule
    with open(os.path.join(root, source), encoding='utf-8') as fh:
        assert pve_call in fh.read(), pve_call
    picked = [] if feature in pve_access.CORE else [feature]
    recipe = pve_access.recipe(picked)
    assert priv in recipe['privileges'], (
        f"{rule} sends {method} {pve_call.strip(chr(34))}, PVE asks for {priv}; the role of "
        f"'{feature}' is {recipe['privileges']}")


@pytest.mark.parametrize('feature', ['crossCluster', 'siteRecovery'])
def test_a_remote_migration_is_called_available_only_where_the_role_lets_the_target_take_it_in(db, feature):
    """Cross-cluster migration, replication and Site Recovery all end in PVE's remote_migrate
    (manager.remote_migrate_vm, background/site_recovery.py), with a token PegaProx creates
    for the target's own user (create_api_token, privsep 0: the user's privileges). The target
    side of remote_migrate is POST .../mtunnel, which PVE checks with
    ['and', ['perm', '/vms/{vmid}', ['VM.Allocate']], ['perm', '/', ['Sys.Incoming']]].
    An account set up with the full recipe role and a password is told the feature works, yet
    the role has no Sys.Incoming, so every remote migration into that cluster is refused."""
    from test_pve_access_recipe_capabilities import Mgr
    from pegaprox.core import conncheck
    full = pve_access.recipe(None)['privileges']
    m = Mgr()
    m.config.user, m.config.pass_ = 'pegaprox@pve', 'pw-of-the-account'
    m.perms = {'/': {p: 1 for p in full}}
    item = conncheck.check_privileges(m)
    caps = {f['id']: f for f in pve_access.capabilities(CID, m, item, 'read')['features']}
    if caps[feature]['status'] == 'yes':
        assert 'Sys.Incoming' in full, (
            f"{feature} is 'yes' for a connection holding exactly the recipe role {full}")


@pytest.mark.parametrize('kw', [{'role': 'Administrator'}, {'user': 'root@pam'}])
def test_the_recipe_does_not_build_commands_around_a_built_in_name(kw):
    """role=Administrator: 'pveum role add Administrator' fails (a built-in role, it exists)
    and the lines after it grant the built-in Administrator role on / to the account and its
    token - a least-privilege recipe that ends in a full admin token. user=root@pam: the
    account commands run 'pveum passwd root@pam', a new root password on that node."""
    try:
        out = pve_access.recipe([], **kw)
    except ValueError:
        return
    lines = out['commands']['account'] + out['commands']['token']
    granted = [ln for ln in lines if ln.startswith('pveum aclmod')]
    pytest.fail(f"{kw}: the commands are built; {granted} / passwd: "
                f"{[ln for ln in lines if ln.startswith('pveum passwd')]}")


def test_the_recipe_route_refuses_the_built_in_administrator_role(api, seed):
    admin = api.as_user(seed.user('root', role='admin'))
    r = admin.get('/api/pve-role-recipe?role=Administrator')
    assert r.status_code == 400, r.get_json()['commands']['token']
