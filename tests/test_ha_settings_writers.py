"""Who writes a cluster's stored HA settings (#625, stage two S6).

The stored HA settings carry two switches that have their own proof (the cluster
claim: unconfined admin, own password, typed phrase; unsafe two-node recovery: typed
phrase), the token the node agents sign with, what the agent installs recorded and
the fence of each node. The HA routes write them. Four other routes built or stored
the whole dict from a request body: PUT /api/clusters/<id> and
PATCH /api/clusters/<id>/config (cluster.config, an API token too), POST /api/clusters,
and POST /api/clusters/<id>/reconfigure, whose dialog never sends them.

A backup restore writes whole cluster rows as well, and a backup "without secrets"
carried the agent token out.

The last test walks the source: every place that assigns ha_settings, copies listed
fields onto a cluster config or writes a whole cluster row is listed here, so a new
writer shows up as a failure and gets looked at.

MK Oct 2026
"""
import ast
import hashlib
import hmac
import os

import pytest

import pegaprox
import pegaprox.api.clusters as clusters_api
from pegaprox.core.manager import PegaProxManager
from test_ha_api import ha_env, _admin, _audit, ADMIN_PW  # noqa: F401
from test_ha_claim import claimed, pve, me, _mgr, _claim, A  # noqa: F401

TOKEN = 'ab' * 32
IPMI = {'type': 'ipmi', 'host': '10.8.0.2', 'user': 'ADMIN', 'password': 'bmc-pw'}
# what an existing two-node cluster with the claim on and the agents installed holds
HELD = {'two_node_mode': True, 'unsafe_two_node_recovery': True, 'claim_enabled': True,
        'agent_token': TOKEN, 'self_fence_installed': True, 'self_fence_nodes': ['pve1', 'pve2'],
        'node_agent_installed': {'pve1': True}, 'fence_agent_versions': {'pve1': 2, 'pve2': 2},
        'fencing': {'pve2': IPMI}}


def _restarted(env):
    """The manager as the next PegaProx start builds it from the stored row, with the
    SSH stand-in of the claim tests."""
    stored = env.db.get_cluster('c1')['ha_settings']
    m = _mgr(env.pve)
    m._apply_ha_settings(stored)
    return m, stored


def _client(env, kind):
    api, seed = env.api, env.seed
    if kind == 'cluster-config-user':
        # not an admin, never typed a password in this session
        return _admin(api, seed, 'ops', role='user', permissions=['cluster.config', 'cluster.view']), None
    from pegaprox.utils.auth import create_api_token
    _admin(api, seed)
    res = create_api_token('root', 'ci', role='admin')
    assert res.get('success'), res
    return api.anon(), {'Authorization': f"Bearer {res['token']}"}


CONFIG_ROUTES = [('put', '/api/clusters/c1'), ('patch', '/api/clusters/c1/config')]


@pytest.mark.parametrize('kind', ['cluster-config-user', 'api-token'])
@pytest.mark.parametrize('method,url', CONFIG_ROUTES)
def test_the_cluster_config_routes_do_not_switch_the_claim_on(claimed, kind, method, url):
    """The claim route refuses this caller (no admin, or an API token), and the config
    route took the same switch from them: stored, no audit line, and on at the next
    start, where start_ha_monitor writes /etc/pve/pegaprox/claim."""
    c, headers = _client(claimed, kind)
    r = c.post('/api/clusters/c1/ha/claim', headers=headers,
               json={'action': 'enable', 'confirm': 'WRITE CLAIM', 'user_password': ADMIN_PW})
    assert r.status_code in (401, 403)

    r = getattr(c, method)(url, headers=headers, json={'name': 'lab2', 'ha_settings': {'claim_enabled': True}})

    # the route itself works for this caller: the name went through, the settings did not
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['updated_fields'] == ['name']
    assert claimed.db.get_cluster('c1')['name'] == 'lab2'
    m, stored = _restarted(claimed)
    assert not stored.get('claim_enabled') and m._ha_claim_enabled() is False
    assert m._ha_claim_ensure() == {'state': 'off'} and _claim(claimed.pve) is None


@pytest.mark.parametrize('method,url', CONFIG_ROUTES)
@pytest.mark.parametrize('sent', [{'two_node_mode': True, 'unsafe_two_node_recovery': True},
                                  {'force_quorum_on_failure': True}],
                         ids=['named', 'key-left-out'])
def test_the_cluster_config_routes_do_not_switch_unsafe_recovery_on(claimed, method, url, sent):
    """Without the phrase the HA config route asks for. Leaving the key out did the
    same: two_node_mode without it is what a setup from before the update looks like,
    so the next start read a new setup as an old one."""
    c, _ = _client(claimed, 'cluster-config-user')

    assert getattr(c, method)(url, json={'ha_settings': sent}).status_code == 200

    m, stored = _restarted(claimed)
    assert m._ha_forces_quorum() is False and m._ha_unsafe_two_node() is False
    assert not stored.get('two_node_mode') and not stored.get('force_quorum_on_failure')


@pytest.mark.parametrize('method,url', CONFIG_ROUTES)
def test_the_cluster_config_routes_leave_what_the_cluster_holds(claimed, method, url):
    """ha_settings was replaced as a whole: the agent token went with it, and after the
    next start every installed tiebreak agent was answered 403."""
    claimed.mgr.config.ha_settings = dict(HELD)
    claimed.mgr.ha_config.update(HELD)
    c, _ = _client(claimed, 'cluster-config-user')

    assert getattr(c, method)(url, json={'ha_settings': {'recovery_delay': 30}}).status_code == 200

    m, stored = _restarted(claimed)
    assert stored == HELD
    assert m.ha_config['agent_token'] == TOKEN and m.ha_config['self_fence_installed'] is True


def test_ha_settings_is_no_field_of_the_cluster_config_routes():
    assert 'ha_settings' not in clusters_api.ALLOWED_CONFIG_FIELDS
    # the two that carry HA state and stay: on/off, which has routes of its own too
    assert 'ha_enabled' in clusters_api.ALLOWED_CONFIG_FIELDS


def _ask(api, token=TOKEN):
    nonce = '0f' * 16
    sig = hmac.new(token.encode(), f'pegaprox-agent ask c1 {nonce}'.encode(), hashlib.sha256).hexdigest()
    return api.anon().get(f'/api/ha/agent?cluster=c1&nonce={nonce}&sig={sig}')


@pytest.fixture
def no_cluster(monkeypatch):
    """A manager the routes build connects to nothing and starts nothing."""
    monkeypatch.setattr(PegaProxManager, 'connect_to_proxmox', lambda self: True)
    monkeypatch.setattr(PegaProxManager, 'start', lambda self: None)


DIALOG = {'current_password': ADMIN_PW, 'name': 'lab', 'host': '10.9.0.1', 'user': 'root@pam',
          'pass': 'new-pw', 'ha_enabled': True, 'ssl_verification': False}


@pytest.mark.parametrize('extra', [{}, {'ha_settings': {'claim_enabled': False, 'agent_token': 'cd' * 32}}],
                         ids=['as-the-dialog-sends-it', 'with-ha-settings-in-the-body'])
def test_re_configure_keeps_the_ha_settings_of_the_cluster(claimed, no_cluster, extra):
    """The Re-configure dialog changes the credentials. It sends the connection fields
    and ha_enabled, never the HA settings, and the route built the new manager from
    that body alone: the agent token was gone (every installed tiebreak agent got 403
    from then on, and nothing redeployed them), an existing two-node setup came back
    as a new one, and the claim switch went off with the file still in /etc/pve."""
    from pegaprox.globals import cluster_managers
    claimed.mgr.config.ha_settings = dict(HELD)
    claimed.mgr.ha_config.update(HELD)
    claimed.mgr.stop = lambda: None
    c = _admin(claimed.api, claimed.seed)
    assert _ask(claimed.api).get_data(as_text=True).startswith('leader ')

    r = c.post('/api/clusters/c1/reconfigure', json=dict(DIALOG, **extra))

    assert r.status_code == 200, r.get_data(as_text=True)
    m = cluster_managers['c1']
    assert m is not claimed.mgr and m.config.pass_ == 'new-pw'
    stored = claimed.db.get_cluster('c1')['ha_settings']
    for key, value in HELD.items():
        assert stored[key] == value, key
    assert _ask(claimed.api).get_data(as_text=True).startswith('leader ')      # the agents are still heard
    assert m.ha_config['agent_token'] == TOKEN and m.ha_config['self_fence_installed'] is True
    assert m._ha_claim_enabled() is True
    assert m._ha_unsafe_two_node() is True and m.ha_config['fencing'] == {'pve2': IPMI}


def test_a_cluster_is_added_with_no_ha_settings_from_the_body(claimed, no_cluster):
    """POST /api/clusters builds the manager from its body too, and starts it: with
    ha_enabled and claim_enabled in there the claim would be written at once, by
    whoever may add a cluster. And storage_heartbeat_path, which the HA config route
    checks because it goes into a script that runs as root on the nodes, went in
    unchecked. A new cluster starts with the safety rules and nothing else."""
    from pegaprox.globals import cluster_managers
    c = _admin(claimed.api, claimed.seed)
    sent = dict(HELD, recovery_delay=45, force_quorum_on_failure=True,
                storage_heartbeat_path='/mnt/x"; reboot; "', storage_heartbeat_enabled=True)

    r = c.post('/api/clusters', json={'name': 'new', 'host': '10.9.5.1', 'user': 'root@pam', 'pass': 'pw',
                                      'ha_enabled': True, 'ha_settings': sent})

    assert r.status_code == 201, r.get_data(as_text=True)
    cid = r.get_json()['id']
    assert claimed.db.get_cluster(cid)['ha_settings'] == {'unsafe_two_node_recovery': False}
    m = cluster_managers[cid]
    assert m._ha_claim_enabled() is False and m.ha_config['agent_token'] == ''
    assert m._ha_forces_quorum() is False and m._ha_unsafe_two_node() is False
    assert m.ha_config['fencing'] == {} and m.ha_config['self_fence_installed'] is False
    assert m.ha_config['storage_heartbeat_path'] == '' and m.ha_config['recovery_delay'] == 30

    # two-node mode set on it afterwards is a new setup: the rules, not the old way
    m.get_ha_status = lambda: {}
    assert c.put(f'/api/clusters/{cid}/ha/config', json={'two_node_mode': True}).status_code == 200
    stored = claimed.db.get_cluster(cid)['ha_settings']
    assert stored['two_node_mode'] is True and stored['unsafe_two_node_recovery'] is False


def test_every_guarded_key_is_one_the_settings_carry():
    """HA_SETTINGS_GUARDED names keys of the stored settings: a typo there would guard
    nothing."""
    m = _mgr()
    m._apply_ha_settings({})
    assert clusters_api.HA_SETTINGS_GUARDED <= set(clusters_api._ha_settings_of(m))
    assert clusters_api.HA_SETTINGS_GUARDED <= set(m.ha_config)


# --- the backup: what it carries out and what a restore brings back --------------------------

BACKUP_PW = 'backup-pw-123'
ROW = dict(name='lab', host='10.9.0.1', user='root@pam', ssl_verification=False, fallback_hosts=[],
           ha_enabled=True, ssh_user='root', ssh_key='', ssh_port=22, cluster_type='proxmox',
           api_port=8006, **{'pass': 'pw'})


def test_a_backup_without_secrets_carries_no_agent_token_and_no_bmc_password(claimed):
    """The sweep for "secrets excluded" looked at the keys of the cluster row. The HA
    settings are a dict inside it: the agent token, and the BMC password of each
    fence, went into the archive."""
    import pegaprox.api.settings as settings_api
    claimed.db.save_cluster('c1', dict(ROW, ha_settings=dict(HELD)))
    c = _admin(claimed.api, claimed.seed)

    def export(**kw):
        r = c.post('/api/config/backup', json=dict(user_password=ADMIN_PW, backup_password=BACKUP_PW, **kw))
        assert r.status_code == 200, r.get_data(as_text=True)
        return settings_api._decrypt_backup(r.get_data(), BACKUP_PW)

    plain = export()
    assert TOKEN not in plain and 'bmc-pw' not in plain
    import json
    ha_settings = json.loads(plain)['clusters']['c1']['ha_settings']
    assert 'agent_token' not in ha_settings
    assert ha_settings['fencing'] == {'pve2': {'type': 'ipmi', 'host': '10.8.0.2', 'user': 'ADMIN'}}
    assert ha_settings['claim_enabled'] is True and ha_settings['self_fence_nodes'] == ['pve1', 'pve2']

    # counterproof: asked for, they are in
    full = export(include_secrets=True)
    assert TOKEN in full and 'bmc-pw' in full


def _restore(env, clusters, mode='merge'):
    import io
    import json
    import pegaprox.api.settings as settings_api
    data = {'version': 'test', 'export_date': '2026-10-02T10:00:00', 'clusters': clusters}
    blob = settings_api._encrypt_backup(json.dumps(data), BACKUP_PW)
    c = _admin(env.api, env.seed)
    r = c.post('/api/config/restore', content_type='multipart/form-data',
               data={'user_password': ADMIN_PW, 'backup_password': BACKUP_PW, 'mode': mode,
                     'backup_file': (io.BytesIO(blob), 'x.pegabackup')})
    assert r.status_code == 200, r.get_data(as_text=True)
    return r.get_json()


@pytest.mark.parametrize('sent', [
    {'recovery_delay': 45, 'two_node_mode': True},                            # a backup without secrets, or an old one
    {'recovery_delay': 45, 'two_node_mode': True, 'claim_enabled': False, 'unsafe_two_node_recovery': False, 'agent_token': 'cd' * 32,
     'self_fence_installed': False, 'fencing': {}},
], ids=['keys-left-out', 'other-values'])
def test_a_merge_restore_leaves_what_the_cluster_holds(claimed, sent):
    """The restore writes the cluster row as the backup has it. Over a cluster that is
    there, the agent token went (every installed tiebreak agent was then answered
    403) and the two switches took the backup's value."""
    claimed.db.save_cluster('c1', dict(ROW, ha_settings=dict(HELD)))

    _restore(claimed, {'c1': dict(ROW, ha_settings=sent)})

    stored = claimed.db.get_cluster('c1')['ha_settings']
    assert stored == dict(HELD, recovery_delay=45)


@pytest.mark.parametrize('held,expected', [
    ({}, False),                                     # the cluster forces nothing: a new setup, the rules
    ({'two_node_mode': True}, True),                 # a setup from before the rules stays one
    ({'two_node_mode': True, 'unsafe_two_node_recovery': False}, False),
    # a flag kept from an earlier setup on a cluster that forces nothing now: the backup's
    # 2-node mode makes a new setup, not an unsafe one
    ({'unsafe_two_node_recovery': True}, False),
])
def test_a_merge_restore_switches_neither_the_claim_nor_unsafe_recovery_on(claimed, held, expected):
    claimed.db.save_cluster('c1', dict(ROW, ha_settings=dict(held)))

    _restore(claimed, {'c1': dict(ROW, ha_settings={'two_node_mode': True, 'claim_enabled': True,
                                                    'unsafe_two_node_recovery': True})})

    m, stored = _restarted(claimed)
    assert not stored.get('claim_enabled') and m._ha_claim_enabled() is False
    assert stored['two_node_mode'] is True and m._ha_unsafe_two_node() is expected


def test_a_backup_that_has_no_ha_settings_changes_none(claimed):
    claimed.db.save_cluster('c1', dict(ROW, ha_settings=dict(HELD, recovery_delay=45)))

    _restore(claimed, {'c1': {k: v for k, v in ROW.items()}})

    assert claimed.db.get_cluster('c1')['ha_settings'] == dict(HELD, recovery_delay=45)


def test_a_cluster_that_is_not_there_comes_back_as_the_backup_has_it(claimed):
    """The counterproof, and what a restore is for: on a fresh instance the cluster
    comes back with its token (the agents on the nodes still carry it) and its
    switches. The route takes an admin's own password and the backup's."""
    _restore(claimed, {'c9': dict(ROW, name='other', ha_settings=dict(HELD))})

    assert claimed.db.get_cluster('c9')['ha_settings'] == HELD


# --- the walk: every place that assigns ha_settings ---------------------------------------------

# file -> the functions in it that assign `<x>.ha_settings` or `<x>['ha_settings']`
WRITERS = {
    'models/tasks.py': {'__init__'},                        # the config object, from a stored row or a body
    'api/clusters.py': {
        'add_cluster',                                      # the body, guarded keys out
        'reconfigure_cluster',                              # the old manager's, never the body's
        'disable_ha', 'update_ha_config', '_save_ha_config_to_db',   # _ha_settings_of(manager)
    },
    'core/manager.py': {'_ha_agent_token', '_ha_store_settings'},    # one key into the row
    'api/settings.py': {'_keep_guarded_ha_settings'},      # a merge restore: guarded keys from the row
}
# file -> the functions that copy fields named in a list onto a cluster config
COPIERS = {
    'api/clusters.py': {'update_cluster_config', 'update_cluster_config_live',
                        '_rebind'},   # ALLOWED_CONFIG_FIELDS; _rebind writes only the re-entered credential
    'core/ha.py': {'_refresh_managers'},                    # a standby takes the leader's row
}
# file -> the functions that write a whole cluster row
ROW_WRITERS = {
    'core/config.py': {'save_config'},                      # what the managers hold
    'core/manager.py': {'_ha_agent_token', '_ha_store_settings'},
    'api/clusters.py': {'_save_ha_config_to_db'},
    'api/settings.py': {'restore_config'},                  # the backup's row, guarded keys kept on a merge
}


def _walk_source():
    root = os.path.dirname(pegaprox.__file__)
    writers, copiers, rows = {}, {}, {}
    for folder, _dirs, files in os.walk(root):
        for name in files:
            if not name.endswith('.py'):
                continue
            path = os.path.join(folder, name)
            rel = os.path.relpath(path, root).replace(os.sep, '/')
            tree = ast.parse(open(path, encoding='utf-8').read())
            for func in ast.walk(tree):
                if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                for node in ast.walk(func):
                    targets = []
                    if isinstance(node, ast.Assign):
                        targets = node.targets
                    elif isinstance(node, (ast.AugAssign, ast.AnnAssign)):
                        targets = [node.target]
                    for t in targets:
                        if (isinstance(t, ast.Attribute) and t.attr == 'ha_settings') or (
                                isinstance(t, ast.Subscript) and isinstance(t.slice, ast.Constant)
                                and t.slice.value == 'ha_settings'):
                            writers.setdefault(rel, set()).add(func.name)
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                            and node.func.attr == 'save_cluster':
                        rows.setdefault(rel, set()).add(func.name)
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                            and node.func.id == 'setattr' and len(node.args) == 3:
                        obj, key = ast.unparse(node.args[0]), node.args[1]
                        if isinstance(key, ast.Constant):
                            if key.value == 'ha_settings':
                                writers.setdefault(rel, set()).add(func.name)
                        elif obj.endswith('config') or obj in ('cfg', 'config'):
                            copiers.setdefault(rel, set()).add(func.name)
    return writers, copiers, rows


def test_nothing_else_writes_the_stored_ha_settings():
    """A function that assigns ha_settings, or copies listed fields onto a cluster
    config, is a writer of the two switches and the agent token. Each one here was
    read for what it lets through; one that is not listed has to be, before it ships."""
    writers, copiers, rows = _walk_source()

    assert writers == WRITERS
    assert copiers == COPIERS
    assert rows == ROW_WRITERS
    from pegaprox.core import ha
    assert 'ha_settings' in ha._REFRESH_CLUSTER_FIELDS       # the standby's copy of the row, as before
