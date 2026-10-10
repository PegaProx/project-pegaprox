"""Four points left open when serving members were built (#625).

1. Views only the leader's process fills: the maintenance and update of a node, which the
   node list reads from /metrics, and the task list of an XCP-ng pool. A member reads
   /node-progress on the leader and lays it over its own /metrics (the UI half is in
   tests/test_ha_leftovers_ui.py); an XCP-ng pool's task lists come from the leader.
2. Force Password Reset on a member is a write the member forwards. Only the UI kept it
   locked (tests/test_ha_leftovers_ui.py); here the route.
3. A read that changes shared configuration on the leader (a plugin's GET, or any read a
   member hands over) tells the members like a write, by the change count.
4. Server, syslog, LDAP, SMTP, OIDC, security and compliance settings saved on a member:
   pinned as they are today, nothing changed.

Runs on the in-process group of tests/test_ha_members.py with the forwarding of
tests/test_ha_forward.py: a is the leader, b its member. The instances share one process,
so a cluster manager is one object for both of them here; the stand-ins below hand out
their jobs only while the state file is the leader's, as two processes would.

MK Oct 2026
"""
import base64
import json
import os
import time
import types

import pytest

from test_ha_api import _admin, ADMIN_PW  # noqa: F401
from test_ha_members import group, _built, _watch, IDS, URLS  # noqa: F401
from test_ha_forward import fwd, _forward_calls, _forward_as, _envelope, FORWARD  # noqa: F401
from test_ha_serving import _serve, _api_token

CID, XID = 'c1', 'x1'
PROGRESS = f'/api/clusters/{CID}/node-progress'


# --- 1. what only the leader's process holds -----------------------------------------------

class _Job:
    def __init__(self, **fields):
        self.fields = fields
        self.acknowledged = fields.get('acknowledged', False)

    def to_dict(self):
        return dict(self.fields)


EVACUATING = {'node': 'n1', 'status': 'evacuating', 'total_vms': 5, 'migrated_vms': 2,
              'failed_vms': [{'vmid': 104, 'name': 'db04'}],
              'pending_vms': [{'vmid': 105, 'name': 'web05'}],
              'current_vm': {'vmid': 103, 'name': 'app03'}, 'progress_percent': 40.0,
              'acknowledged': False}
UPDATING = {'node': 'n2', 'status': 'running', 'phase': 'apt_upgrade',
            'output_lines': [{'timestamp': '2026-10-03T01:00:00', 'text': 'Unpacking pve-manager'}]}


class _PerProcess:
    """A cluster manager whose jobs live in the leader's process: wherever the state file
    is not the leader's, the dicts are those of another process, empty. get_node_status
    puts them on each node the way the real one does."""

    def __init__(self, g, cluster_type='proxmox', tasks=()):
        self.g, self.cluster_type = g, cluster_type
        self.is_connected = True
        self._maint = {'n1': _Job(**EVACUATING)}
        self._updating = {'n2': _Job(**UPDATING)}
        self._tasks = list(tasks)
        self.asked = []

    def _leader(self):
        return self.g.ha.role() == 'active'

    @property
    def nodes_in_maintenance(self):
        return self._maint if self._leader() else {}

    @property
    def nodes_updating(self):
        return self._updating if self._leader() else {}

    def get_node_status(self):
        out = {}
        for name in ('n1', 'n2', 'n3'):
            m, u = self.nodes_in_maintenance.get(name), self.nodes_updating.get(name)
            out[name] = {'status': 'online', 'cpu_percent': 5.0, 'mem_percent': 20.0,
                         'maintenance_mode': m is not None,
                         'maintenance_task': m.to_dict() if m else None,
                         'maintenance_acknowledged': bool(m and m.acknowledged),
                         'is_updating': u is not None,
                         'update_task': u.to_dict() if u else None, 'offline': False}
        return out

    def get_tasks(self, limit=50):
        self.asked.append(self.g.ha.role())
        return list(self._tasks)[:limit] if self._leader() else []

    def get_node_tasks(self, node, start=0, limit=50, errors=False):
        return self.get_tasks(limit)

    def get_node_task_log(self, node, upid, start=0, limit=50):
        self.asked.append(self.g.ha.role())
        return ['Action: start', 'Status: running'] if self._leader() else ['not found']


def _job_fields(node):
    return {k: node[k] for k in ('maintenance_mode', 'maintenance_task', 'maintenance_acknowledged',
                                 'is_updating', 'update_task')}


@pytest.fixture
def cluster(fwd):
    mgr = _PerProcess(fwd)
    fwd.api.set_manager(CID, mgr)
    return mgr


def test_the_node_list_shows_the_jobs_of_its_own_process(fwd, seed, cluster):
    """The gap: /metrics puts the maintenance and update of every node on it from the
    managers of the process that answers. On a member, which runs neither (the leader does
    what its users start), the node list shows nothing of them."""
    g = fwd
    admin = _built(g, seed, 'b')
    _serve(g, 'b')
    with g.at('a'):
        leader = admin.get(f'/api/clusters/{CID}/metrics').get_json()
    with g.at('b'):
        member = admin.get(f'/api/clusters/{CID}/metrics').get_json()
    assert leader['n1']['maintenance_task']['status'] == 'evacuating'
    assert leader['n2']['is_updating'] is True
    assert member['n1']['maintenance_mode'] is False and member['n1']['maintenance_task'] is None
    assert member['n2']['is_updating'] is False and member['n2']['update_task'] is None
    # /metrics stays this instance's own: the live figures are read here, by every member
    assert '/api/clusters/<cluster_id>/metrics' not in g.ha.FORWARDED_READS


def test_a_member_reads_the_node_progress_on_the_leader(fwd, seed, cluster):
    g = fwd
    admin = _built(g, seed, 'b')
    _serve(g, 'b')
    with g.at('a'):
        on_leader = admin.get(PROGRESS)
        metrics = admin.get(f'/api/clusters/{CID}/metrics').get_json()
    assert on_leader.status_code == 200
    nodes = on_leader.get_json()['nodes']
    assert sorted(nodes) == ['n1', 'n2']
    # the five fields the node list reads, as /metrics puts them on each node
    for name in nodes:
        assert nodes[name] == _job_fields(metrics[name]), name
    g.calls.clear()
    with g.at('b'):
        r = admin.get(PROGRESS)
    assert r.status_code == 200 and r.get_json() == {'nodes': nodes}
    assert _forward_calls(g) == [('b', 'a', 'POST', FORWARD)]
    # a read changes nothing: no sync after it
    assert g.pulls == []


def test_without_the_leader_the_member_answers_for_itself(fwd, seed, cluster):
    """A progress read, not a view only the leader keeps: forwarding off, an API token or
    the leader gone, and the member answers from its own process (nothing to lay over)."""
    g = fwd
    admin = _built(g, seed, 'b')
    _serve(g, 'b')
    assert PROGRESS.replace(CID, '<cluster_id>') in g.ha.FORWARDED_READS
    assert PROGRESS.replace(CID, '<cluster_id>') not in g.ha.LEADER_ONLY_READS
    token = _api_token()
    g.calls.clear()
    with g.at('b') as ha:
        assert g.api.anon().get(PROGRESS, headers=token).get_json() == {'nodes': {}}
        ha.set_forward_writes(False)
        assert admin.get(PROGRESS).get_json() == {'nodes': {}}
        ha.set_forward_writes(True)
    assert _forward_calls(g) == []
    g.down.add('a')
    with g.at('b') as ha:
        ha._note_source_heard(IDS['a'], True)
        r = admin.get(PROGRESS)
    assert r.status_code == 200 and r.get_json() == {'nodes': {}}
    # counterproof: back, and it comes from the leader again
    g.down.discard('a')
    _watch(g, 'b')
    with g.at('b'):
        assert sorted(admin.get(PROGRESS).get_json()['nodes']) == ['n1', 'n2']


def test_a_node_both_updates_and_maintains_in_one_entry(api, seed):
    """An update after the evacuation: one entry with both, and an ESXi cluster, which
    keeps a set and runs neither, answers none."""
    mgr = types.SimpleNamespace(cluster_type='proxmox',
                                nodes_in_maintenance={'n1': _Job(**dict(EVACUATING, status='completed'))},
                                nodes_updating={'n1': _Job(**UPDATING)})
    api.set_manager(CID, mgr)
    api.set_manager('esx', types.SimpleNamespace(cluster_type='esxi', nodes_in_maintenance=set()))
    admin = api.as_user(seed.user('root', role='admin'))
    n1 = admin.get(PROGRESS).get_json()['nodes']['n1']
    assert n1['maintenance_mode'] is True and n1['maintenance_task']['status'] == 'completed'
    assert n1['is_updating'] is True and n1['update_task']['phase'] == 'apt_upgrade'
    assert admin.get('/api/clusters/esx/node-progress').get_json() == {'nodes': {}}
    assert admin.get('/api/clusters/nope/node-progress').status_code == 404


def test_a_confined_caller_gets_the_progress_without_the_guests(api, seed):
    """The permission of /metrics, and from a maintenance only what updates/status hands a
    confined caller: the progress, not which guests are in it."""
    mgr = types.SimpleNamespace(cluster_type='proxmox', nodes_in_maintenance={'n1': _Job(**EVACUATING)},
                                nodes_updating={'n2': _Job(**UPDATING)})
    api.set_manager(CID, mgr)
    seed.tenant('acme', clusters=[CID])
    seed.tenant('globex', clusters=['other'])
    operator = api.as_user(seed.user('operator', role='user', tenant_id='acme', permissions=['cluster.view']))
    portal = api.as_user(seed.user('portal', role='user', tenant_id='globex',
                                   permissions=['cluster.view', 'vm.view']))
    seed.vm_acl(CID, 100, users=['portal'])
    nobody = api.as_user(seed.user('nobody', role='user', tenant_id='acme', denied=['cluster.view']))

    full = operator.get(PROGRESS).get_json()['nodes']['n1']['maintenance_task']
    assert full['failed_vms'] and full['pending_vms'] and full['current_vm']
    confined = portal.get(PROGRESS).get_json()['nodes']
    task = confined['n1']['maintenance_task']
    assert task['status'] == 'evacuating' and task['migrated_vms'] == 2 and task['total_vms'] == 5
    assert not {'failed_vms', 'pending_vms', 'current_vm'} & set(task)
    assert confined['n2']['update_task']['phase'] == 'apt_upgrade'
    assert nobody.get(PROGRESS).status_code == 403


def test_the_node_progress_fields_are_the_ones_metrics_carries():
    """The overlay replaces exactly these on a node; get_node_status has to keep setting
    each of them."""
    import inspect
    from pegaprox.core.manager import PegaProxManager
    src = inspect.getsource(PegaProxManager.get_node_status)
    for key in ('maintenance_mode', 'maintenance_task', 'maintenance_acknowledged',
                'is_updating', 'update_task'):
        assert f"'{key}': " in src, key


# The task list of an XCP-ng pool

XTASK = {'upid': 'a1b2c3d4', 'type': 'start', 'status': 'running', 'vmid': 100,
         'starttime': 1790000000, 'node': 'h1', 'user': 'xapi@xcpng'}


@pytest.fixture
def pools(fwd):
    """An XCP-ng pool and a Proxmox cluster, each following its tasks the way it does."""
    xcp = _PerProcess(fwd, cluster_type='xcpng', tasks=[XTASK])
    pve = _PerProcess(fwd, tasks=[dict(XTASK, upid='UPID:n1:0001:task')])
    fwd.api.set_manager(XID, xcp)
    fwd.api.set_manager(CID, pve)
    return types.SimpleNamespace(xcp=xcp, pve=pve)


XCP_READS = [f'/api/clusters/{XID}/tasks', f'/api/clusters/{XID}/nodes/h1/tasks?limit=50',
             f'/api/clusters/{XID}/nodes/h1/tasks/a1b2c3d4/log']


def test_an_xcpng_pool_lists_its_tasks_where_they_were_started(fwd, seed, pools):
    """The gap: an XCP-ng pool lists the XAPI tasks of the process that started them, and
    a member starts none (its users' actions run on the leader)."""
    g = fwd
    admin = _built(g, seed, 'b')
    _serve(g, 'b')
    with g.at('b') as ha:
        ha.set_forward_writes(False)
        assert admin.get(f'/api/clusters/{XID}/tasks').get_json() == []
    with g.at('a'):
        assert admin.get(f'/api/clusters/{XID}/tasks').get_json() == [XTASK]


def test_a_member_reads_an_xcpng_pools_tasks_on_the_leader(fwd, seed, pools):
    g = fwd
    admin = _built(g, seed, 'b')
    _serve(g, 'b')
    for rule in g.ha.XCPNG_TASK_READS:
        assert rule in g.ha.FORWARDED_READS and rule not in g.ha.LEADER_ONLY_READS
    g.calls.clear()
    with g.at('b'):
        lists = [admin.get(path).get_json() for path in XCP_READS]
    assert lists == [[XTASK], [XTASK], {'log': 'Action: start\nStatus: running',
                                         'lines': ['Action: start', 'Status: running']}]
    assert _forward_calls(g) == [('b', 'a', 'POST', FORWARD)] * 3
    assert set(pools.xcp.asked) == {'active'}
    assert g.pulls == []


def test_a_proxmox_clusters_tasks_stay_with_the_member(fwd, seed, pools):
    """PVE keeps the task log itself, and every instance reads it there: nothing goes to
    the leader for those, so a member at another site does not send it every poll."""
    g = fwd
    admin = _built(g, seed, 'b')
    _serve(g, 'b')
    g.calls.clear()
    with g.at('b') as ha:
        assert admin.get(f'/api/clusters/{CID}/tasks').status_code == 200
        assert admin.get(f'/api/clusters/{CID}/nodes/n1/tasks').status_code == 200
        assert admin.get(f'/api/clusters/{CID}/nodes/n1/tasks/UPID:n1:0001:task/log').status_code == 200
        assert ha.forwards_read('/api/clusters/<cluster_id>/tasks', {'cluster_id': CID}) is False
        assert ha.forwards_read('/api/clusters/<cluster_id>/tasks', {'cluster_id': 'gone'}) is False
        assert ha.forwards_read('/api/clusters/<cluster_id>/tasks', {'cluster_id': XID}) is True
        assert ha.forwards_read('/api/xhm/migrations', {}) is True
        assert ha.forwards_read('/api/clusters/<cluster_id>/metrics', {'cluster_id': XID}) is False
    assert _forward_calls(g) == []
    assert set(pools.pve.asked) == {'standby'}


def test_an_xcpng_task_read_falls_back_to_the_member(fwd, seed, pools):
    g = fwd
    admin = _built(g, seed, 'b')
    _serve(g, 'b')
    g.down.add('a')
    with g.at('b') as ha:
        ha._note_source_heard(IDS['a'], True)
        r = admin.get(f'/api/clusters/{XID}/tasks')
    assert r.status_code == 200 and r.get_json() == []


def test_the_leader_takes_a_task_read_for_any_cluster(fwd, seed, pools):
    """What the leader accepts goes by the rule: a member on another release may ask for
    a Proxmox cluster's tasks as well, and gets them read with the user's rights."""
    g = fwd
    _built(g, seed, 'b')
    for path in (f'/api/clusters/{XID}/tasks', f'/api/clusters/{CID}/tasks'):
        r = _forward_as(g, 'b', _envelope(method='GET', path=path, body_b64=''))
        assert r.status_code == 200 and r.get_json()['status'] == 200, (path, r.data)


# --- 2. Force Password Reset on a member -----------------------------------------------------

def test_force_password_reset_is_forwarded_like_any_change(fwd, seed):
    """The route the button sends to: on a member that forwards it runs on the leader, as
    the user; on one that does not it is refused. The settings around it in the same tab
    are refused either way (point 4)."""
    from test_ha_forward import _audit_rows
    g = fwd
    admin = _built(g, seed, 'b')
    _serve(g, 'b')
    seed.user('alice', role='user')
    g.calls.clear()
    with g.at('b'):
        r = admin.post('/api/security/password-expiry/reset-all', json={'include_admins': False})
    assert r.status_code == 200 and r.get_json()['reset_count'] >= 1, r.data
    assert _forward_calls(g) == [('b', 'a', 'POST', FORWARD)]
    assert [row['user'] for row in _audit_rows('security.password_reset_all')] == ['root']
    assert g.pulls == ['b']

    g.calls.clear()
    with g.at('b') as ha:
        ha.set_forward_writes(False)
        r = admin.post('/api/security/password-expiry/reset-all', json={'include_admins': False})
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY'
    assert _forward_calls(g) == []


# --- 3. a read that changes shared configuration on the leader -------------------------------

@pytest.fixture
def told(fwd, monkeypatch):
    """The notes the leader sets up for its members (instance, timer name) and the journal
    lines that wait; reset() starts both over."""
    g = fwd
    timers = []
    monkeypatch.setattr(g.ha, '_later', lambda delay, fn, name: timers.append((g.name(), name)))

    def reset():
        timers.clear()
        g.ha._nudge.update(due=False, last=None)
        g.ha._journal['pending'].clear()
    return types.SimpleNamespace(timers=timers, reset=reset,
                                 journal=lambda: [line[2:] for line in g.ha._journal['pending']])


@pytest.fixture
def writer(fwd, monkeypatch):
    """A loaded plugin whose routes write a shared table, a plugin's config.json, a table of
    this instance only, or nothing, whichever method they are called with."""
    import pegaprox.api.plugins as plugins
    from pegaprox.core.db import get_db

    def kv():
        conn = get_db().conn
        conn.execute("INSERT OR REPLACE INTO pegaprox_kv (k, v) VALUES ('probe', ?)", (repr(time.time()),))
        conn.commit()
        return {'wrote': 'pegaprox_kv'}

    def config():
        folder = os.path.join(fwd.ha.PLUGINS_DIR, 'probe')
        os.makedirs(folder, exist_ok=True)
        with open(os.path.join(folder, 'config.json'), 'w', encoding='utf-8') as fh:
            json.dump({'at': time.time()}, fh)
        return {'wrote': 'config.json'}

    def own():
        from pegaprox.utils.audit import log_audit
        log_audit('root', 'probe.read', 'a row of this instance only')
        return {'wrote': 'audit_log'}

    def peek():
        row = get_db().conn.execute("SELECT v FROM pegaprox_kv WHERE k = 'probe'").fetchone()
        return {'v': row[0] if row else None}

    conn = get_db().conn
    conn.execute('CREATE TABLE IF NOT EXISTS pegaprox_kv (k TEXT PRIMARY KEY, v TEXT)')
    conn.commit()
    monkeypatch.setitem(plugins._loaded_plugins, 'probe', types.SimpleNamespace())
    monkeypatch.setitem(plugins._plugin_routes, 'probe',
                        {'kv': kv, 'config': config, 'own': own, 'peek': peek})
    return '/api/plugins/probe/api/'


def _no_triggers():
    """The leader of a manual group, which has never been a member: no counter yet."""
    from pegaprox.core.db import get_db
    conn = get_db().conn
    for (name,) in conn.execute("SELECT name FROM sqlite_master WHERE type = 'trigger' "
                                "AND name LIKE 'ha_cv_%'").fetchall():
        conn.execute(f'DROP TRIGGER "{name}"')
    conn.execute('DROP TABLE IF EXISTS ha_cv_dirty')
    conn.commit()


def test_a_forwarded_plugin_read_that_wrote_tells_the_members(fwd, seed, told, writer):
    g = fwd
    admin = _built(g, seed, 'b')
    _serve(g, 'b')
    _no_triggers()
    told.reset()
    g.calls.clear()
    with g.at('b'):
        r = admin.get(writer + 'kv')
    assert r.status_code == 200 and r.get_json() == {'wrote': 'pegaprox_kv'}
    assert _forward_calls(g) == [('b', 'a', 'POST', FORWARD)]
    # the leader sets up its note to the members, as after a write, and journals the read
    assert told.timers == [('a', 'ha-nudge')]
    assert told.journal() == [('GET', writer + 'kv', URLS['b'])]

    # the counter is the leader's own now
    told.reset()
    with g.at('b'):
        assert admin.get(writer + 'peek').status_code == 200
    assert told.timers == [] and told.journal() == []


@pytest.mark.parametrize('route,nudged', [('kv', True), ('config', True), ('own', False), ('peek', False)])
def test_a_plugin_read_on_the_leader_is_counted(fwd, seed, told, writer, route, nudged):
    """Signed in on the leader itself as well. The count says what changed: a shared table
    or a plugin's config.json (both travel with a sync), not a row of this instance's own
    tables, nor nothing at all."""
    g = fwd
    admin = _built(g, seed, 'b')
    told.reset()
    with g.at('a'):
        assert admin.get(writer + route).status_code == 200
    assert (told.timers == [('a', 'ha-nudge')]) is nudged, told.timers
    assert (told.journal() == [('GET', writer + route, '')]) is nudged, told.journal()


def test_a_read_that_did_not_go_through_tells_the_members_but_names_nobody(fwd, seed, told, monkeypatch):
    """Something changed while a read was answered with a refusal: the members pull, but
    the journal does not put the change down to the caller - another connection made it."""
    from pegaprox.core.db import get_db
    g = fwd
    admin = _built(g, seed, 'b')
    app = g.api.app
    endpoint = next(r.endpoint for r in app.url_map.iter_rules()
                    if r.rule == '/api/xhm/migrations' and 'GET' in r.methods)

    def view(*a, **kw):
        conn = get_db().conn
        conn.execute("UPDATE server_settings SET value = ? WHERE key = 'default_theme'", (repr(time.time()),))
        conn.execute("INSERT OR IGNORE INTO server_settings (key, value) VALUES ('default_theme', 'x')")
        conn.commit()
        return {'error': 'no'}, 403
    monkeypatch.setitem(app.view_functions, endpoint, view)
    told.reset()
    with g.at('b'):
        assert admin.get('/api/xhm/migrations').status_code == 403
    assert told.timers == [('a', 'ha-nudge')]
    assert told.journal() == []


def test_any_read_a_member_hands_over_is_counted(fwd, seed, told, monkeypatch):
    """Not only a plugin's: a progress read the leader serves for a member that happens to
    change a shared table tells the members too."""
    from pegaprox.core.db import get_db
    g = fwd
    admin = _built(g, seed, 'b')
    app = g.api.app
    endpoint = next(r.endpoint for r in app.url_map.iter_rules()
                    if r.rule == '/api/xhm/migrations' and 'GET' in r.methods)

    def view(*a, **kw):
        conn = get_db().conn
        conn.execute("UPDATE server_settings SET value = ? WHERE key = 'default_theme'", (repr(time.time()),))
        conn.execute("INSERT OR IGNORE INTO server_settings (key, value) VALUES ('default_theme', 'x')")
        conn.commit()
        return {'migrations': []}
    monkeypatch.setitem(app.view_functions, endpoint, view)
    told.reset()
    with g.at('b'):
        assert admin.get('/api/xhm/migrations').status_code == 200
    assert told.timers == [('a', 'ha-nudge')]
    assert told.journal() == [('GET', '/api/xhm/migrations', URLS['b'])]


def test_an_instance_without_members_counts_nothing(api, seed, writer, monkeypatch):
    """A standalone instance (and a member) takes no count and makes no counter."""
    from pegaprox.core import ha
    from pegaprox.core.db import get_db
    asked = []
    monkeypatch.setattr(ha, 'ensure_change_triggers', lambda: asked.append(1) or 0)
    admin = api.as_user(seed.user('root', role='admin'))
    assert admin.get(writer + 'kv').status_code == 200
    assert asked == [] and ha.read_mark() is None
    assert get_db().conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE name = 'ha_cv_dirty'").fetchone()[0] == 0


def test_a_write_still_tells_the_members_once(fwd, seed, told):
    """The read count does not touch the writes: one note, one journal line."""
    g = fwd
    admin = _built(g, seed, 'b')
    told.reset()
    with g.at('a'):
        assert admin.put('/api/user/preferences', json={'theme': 'nord'}).status_code == 200
    assert told.timers == [('a', 'ha-nudge')]
    assert told.journal() == [('PUT', '/api/user/preferences', '')]


# --- 4. the settings a member saves, as they are today ------------------------------------------
#
# Every form below posts to POST /api/settings/server. app.py keeps that route from being
# forwarded (_STANDBY_NOT_FORWARDED): one body mixes keys of this instance (ha.LOCAL_SETTING_KEYS:
# port, domain, trusted proxies, ...) with shared ones, and the server form sends its local keys
# with every save. So on a member, serving or not, forwarding or not, each is refused with 409
# HA_STANDBY: nothing goes to the leader, nothing is written here, so no sync has anything to
# overwrite. The local keys can be set on a member only before it pairs or after a promotion; the
# shared ones on the leader, from where they arrive with the next sync. No change here, by design
# of this pass (auth settings are the owner's call).

SERVER_FORM = {'domain': 'member.example', 'port': '5999', 'ssl_enabled': 'false',
               'reverse_proxy_enabled': 'true', 'trusted_proxies': '10.9.0.0/16',
               'proxy_bind_address': '10.9.9.9', 'syslog_enabled': 'false',
               'default_theme': 'nord', 'audit_retention_days': '120', 'air_gap_mode': 'true'}
FORMS = {
    # name: (body, multipart, the keys of this instance in it, the shared ones)
    'server': (SERVER_FORM, True,
               {'domain', 'port', 'ssl_enabled', 'reverse_proxy_enabled', 'trusted_proxies',
                'proxy_bind_address', 'syslog_enabled'},
               {'default_theme', 'audit_retention_days', 'air_gap_mode'}),
    'syslog': ({'syslog_enabled': True, 'syslog_filter_by_selected_cluster': True}, False,
               {'syslog_enabled'}, {'syslog_filter_by_selected_cluster'}),
    'ldap': ({'ldap_enabled': True, 'ldap_server': 'ldap.member.example', 'ldap_port': 636,
              'ldap_base_dn': 'dc=member,dc=example', 'ldap_bind_dn': 'cn=pp,dc=member,dc=example'},
             False, set(), {'ldap_enabled', 'ldap_server', 'ldap_port', 'ldap_base_dn', 'ldap_bind_dn'}),
    'smtp': ({'smtp_enabled': True, 'smtp_host': 'mail.member.example', 'smtp_port': 2525,
              'smtp_from_email': 'pp@member.example', 'alert_email_recipients': ['ops@member.example']},
             False, set(), {'smtp_enabled', 'smtp_host', 'smtp_port', 'smtp_from_email',
                            'alert_email_recipients'}),
    # the form fills in the redirect URI from the address the browser is on: this member's
    'oidc': ({'oidc_enabled': True, 'oidc_provider': 'generic', 'oidc_client_id': 'pegaprox-member',
              'oidc_client_secret': '********', 'oidc_authority': 'https://idp.member.example',
              'oidc_redirect_uri': 'https://member.example/oidc/callback'},
             False, {'oidc_redirect_uri'}, {'oidc_enabled', 'oidc_client_id', 'oidc_authority'}),
    'security': ({'login_max_attempts': 9, 'password_min_length': 14, 'session_timeout': 7200,
                  'force_2fa': True, 'strict_session_ip': True}, False, set(),
                 {'login_max_attempts', 'password_min_length', 'session_timeout', 'force_2fa',
                  'strict_session_ip'}),
    'compliance': ({'audit_retention_days': 400, 'air_gap_mode': True}, False, set(),
                   {'audit_retention_days', 'air_gap_mode'}),
}


def _save(admin, body, multipart):
    if multipart:
        return admin.post('/api/settings/server', content_type='multipart/form-data', data=dict(body))
    return admin.post('/api/settings/server', json=body)


def _settings(keys):
    from pegaprox.api.helpers import load_server_settings
    current = load_server_settings()
    return {k: current.get(k) for k in keys}


def test_the_forms_name_their_keys_right():
    """What the table above calls a key of this instance is one."""
    from pegaprox.core import ha
    for name, (body, _multipart, local, shared) in FORMS.items():
        assert local | shared <= set(body), name
        assert all(ha._is_local_setting(k) for k in local), name
        assert not any(ha._is_local_setting(k) for k in shared), name


@pytest.mark.parametrize('forwarding', [True, False], ids=['forwarding', 'not-forwarding'])
@pytest.mark.parametrize('form', sorted(FORMS))
def test_a_member_refuses_every_settings_form_and_keeps_nothing(fwd, seed, form, forwarding):
    g = fwd
    admin = _built(g, seed, 'b')
    _serve(g, 'b')
    body, multipart, local, shared = FORMS[form]
    before = _settings(local | shared)
    g.calls.clear()
    with g.at('b') as ha:
        if not forwarding:
            ha.set_forward_writes(False)
        assert ha.serving() is forwarding
        r = _save(admin, body, multipart)
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY', r.data
    assert _forward_calls(g) == []
    assert _settings(local | shared) == before
    assert g.pulls == []


@pytest.mark.parametrize('form', sorted(set(FORMS) - {'server'}))
def test_the_same_save_on_the_leader_goes_through(fwd, seed, form):
    """Counterproof, and what a sync then carries: the shared keys, never the leader's own
    (tests/test_ha_core.py test_instance_local_settings_never_travel_and_survive_an_apply)."""
    g = fwd
    admin = _built(g, seed, 'b')
    body, multipart, local, shared = FORMS[form]
    with g.at('a') as ha:
        r = _save(admin, body, multipart)
        assert r.status_code == 200, r.data
        changed = _settings(shared)
        snap = ha.build_snapshot()
    assert changed != {k: None for k in shared}
    sent = {row[0] for row in snap['tables']['server_settings']['rows']}
    assert not sent & local
    assert {k for k in shared if changed[k] is not None} <= sent


@pytest.mark.parametrize('path', ['/api/settings/ldap/test', '/api/settings/oidc/test',
                                  '/api/settings/smtp/test'])
def test_a_members_connection_tests_run_on_the_leader(fwd, seed, monkeypatch, path):
    """The test buttons next to those forms are writes the member forwards: the check runs
    from the leader, with the values typed into the member's form."""
    from flask import request
    g = fwd
    admin = _built(g, seed, 'b')
    _serve(g, 'b')
    app = g.api.app
    endpoint = next(r.endpoint for r in app.url_map.iter_rules() if r.rule == path)
    ran = []

    def view(*a, **kw):
        ran.append((g.ha.role(), request.get_json(silent=True)))
        return {'success': True}
    monkeypatch.setitem(app.view_functions, endpoint, view)
    g.calls.clear()
    with g.at('b'):
        r = admin.post(path, json={'ldap_server': 'ldap.member.example'})
    assert r.status_code == 200
    assert _forward_calls(g) == [('b', 'a', 'POST', FORWARD)]
    assert ran == [('active', {'ldap_server': 'ldap.member.example'})]
