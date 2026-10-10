"""The two evacuation options of the rolling update (#763, #954), where else they apply.

Scheduled rolling updates: the options are stored with the schedule (the update_schedules
row), listed and edited with it, and the scheduled run handles them like the run started by
hand - rules off just before the first evacuation, on again when the run ends however it
ends, the same log lines and the same audit. A schedule saved before the options existed runs
as before, and XCP-ng keeps both off.

A node's maintenance: its templates move with the evacuation, and the negative affinity rules
over its guests are off from before the evacuation until the node leaves maintenance. Who
holds a rule off is in the row (owner 'rolling' or 'maintenance:<node>'); a rule held by two
owners comes back on when the last of them lets go, also after a restart or a takeover, and
the daemon loop switches on what an owner left behind.

MK Oct 2026
"""
import threading
import time
from unittest.mock import MagicMock

import pytest

import pegaprox.core.manager as mgrmod
from pegaprox.core import ha
from pegaprox.core.manager import PegaProxManager
from pegaprox.models.tasks import MaintenanceTask, UpdateTask
from test_rolling_templates_affinity_763_954 import (GUESTS, SAN_TEMPLATE, _FastTime, _cluster_manager, _manager,
                                                     _Pve, _reads, _running, _template)


# -- the HA rules as Proxmox keeps them: a PUT switches one off or on ---------------------------

def _rules():
    return [
        # over vm:100 (pve5) and vm:101 (pve4)
        {'rule': 'web-apart', 'type': 'resource-affinity', 'affinity': 'negative', 'resources': 'vm:100,vm:101'},
        # over the container 201 (pve5)
        {'rule': 'ct-apart', 'type': 'resource-affinity', 'affinity': 'negative', 'resources': 'ct:201,vm:200'},
        # nothing on pve5 or pve4
        {'rule': 'elsewhere', 'type': 'resource-affinity', 'affinity': 'negative', 'resources': 'vm:200,vm:300'},
        # vm:201 is not the container 201
        {'rule': 'other-kind', 'type': 'resource-affinity', 'affinity': 'negative', 'resources': 'vm:201,vm:200'},
        # switched off by the admin, not by PegaProx
        {'rule': 'admin-off', 'type': 'resource-affinity', 'affinity': 'negative', 'resources': 'vm:100,vm:200',
         'disable': 1},
    ]


MGUESTS = [_running(100, node='pve5'), _running(101, node='pve4'), _running(200, node='pve1'),
           {'vmid': 201, 'name': 'ct201', 'node': 'pve5', 'type': 'lxc', 'status': 'running', 'mem': 1},
           _template(9000, node='pve5'), _template(9100, node='pve4')]


def _stateful(pve):
    rules = _rules()
    pve.reads['/cluster/ha/rules'] = rules

    def on_put(path, data):
        name = path.rsplit('/', 1)[1]
        for r in rules:
            if r['rule'] == name and pve.put_status.get(path, 200) == 200:
                if data.get('disable') == 1:
                    r['disable'] = 1
                elif data.get('delete') == 'disable':
                    r.pop('disable', None)
    pve.on_put = on_put
    return rules


def _node_manager(db, monkeypatch, order=None):
    pve = _Pve(_reads(v9000=SAN_TEMPLATE))
    rules = _stateful(pve)
    m = _manager(pve, MGUESTS)
    m.maintenance_lock = threading.Lock()
    m.nodes_in_maintenance = {}
    order = [] if order is None else order
    m._set_ceph_maintenance_flags = lambda node: order.append(('ceph', node))
    m._unset_ceph_maintenance_flags = lambda node: None
    m._try_native_ha_maintenance = lambda node, task: order.append(('pve flag', node)) or False
    started = []
    monkeypatch.setattr(m, '_evacuate_node', lambda node, task: started.append(node) or order.append(('evacuate', node)),
                        raising=False)
    pve.on_put = (lambda f: (lambda path, data: (order.append(('put', path.rsplit('/', 1)[1], dict(data))),
                                                 f(path, data))))(pve.on_put)
    m._started = started
    return m, pve, rules, order


def _enter(m, node, wait=True, **kw):
    task = PegaProxManager.enter_maintenance_mode(m, node, **kw)
    deadline = time.time() + 5
    while wait and node not in m._started and time.time() < deadline:
        time.sleep(0.01)
    return task


def _off(rules):
    return sorted(r['rule'] for r in rules if r.get('disable'))


def _rows(db):
    return [(r[0], r[3]) for r in db.get_suspended_ha_rules('cluster_1')]


# -- a node's maintenance ------------------------------------------------------------------------

def test_maintenance_switches_off_the_rules_over_its_guests_before_the_evacuation_and_on_when_it_ends(db, monkeypatch):
    m, pve, rules, order = _node_manager(db, monkeypatch)
    task = _enter(m, 'pve5', migrate_templates=True, relax_anti_affinity=True, who='admin')
    # only the rules over a guest of pve5, the container by its own kind
    assert _off(rules) == ['admin-off', 'ct-apart', 'web-apart']
    assert task.ha_rules_off == ['web-apart', 'ct-apart'] and task.ha_rules_kept_on == []
    assert task.migrate_templates is True and task.relax_anti_affinity is True
    assert _rows(db) == [('ct-apart', 'maintenance:pve5'), ('web-apart', 'maintenance:pve5')]
    # off before PVE's own maintenance flag (ha-manager moves its guests at once) and before ours
    steps = [o[0] for o in order]
    assert steps.index('put') < steps.index('pve flag') < steps.index('evacuate'), order
    audit = db.conn.execute("SELECT user, details FROM audit_log WHERE action='ha.rules_suspended'").fetchall()
    assert [a[0] for a in audit] == ['admin'] and 'for the maintenance of pve5: web-apart, ct-apart' in audit[0][1]
    assert task.to_dict()['ha_rules_off'] == ['web-apart', 'ct-apart']

    order.clear()
    assert PegaProxManager.exit_maintenance_mode(m, 'pve5', who='admin') is True
    assert _off(rules) == ['admin-off'], 'the rule the admin switched off stays off'
    assert [(o[1], o[2]) for o in order if o[0] == 'put'] == [('ct-apart', {'type': 'resource-affinity', 'delete': 'disable'}),
                                                              ('web-apart', {'type': 'resource-affinity', 'delete': 'disable'})]
    assert _rows(db) == []
    restored = db.conn.execute("SELECT user FROM audit_log WHERE action='ha.rules_restored'").fetchall()
    assert [r[0] for r in restored] == ['admin']


def test_maintenance_without_the_option_touches_no_rule(db, monkeypatch):
    m, pve, rules, order = _node_manager(db, monkeypatch)
    task = _enter(m, 'pve5')
    assert pve.puts == [] and _rows(db) == [] and task.relax_anti_affinity is False
    assert '/cluster/ha/rules' not in pve.gets, 'nothing extra is read'
    assert PegaProxManager.exit_maintenance_mode(m, 'pve5') is True
    assert pve.puts == []
    # skipping the evacuation takes the option with it
    task = _enter(m, 'pve4', wait=False, skip_evacuation=True, relax_anti_affinity=True)
    assert task.relax_anti_affinity is False and pve.puts == []


def test_a_rule_two_maintenances_hold_comes_back_on_with_the_last(db, monkeypatch):
    m, pve, rules, order = _node_manager(db, monkeypatch)
    _enter(m, 'pve5', relax_anti_affinity=True)
    pve.puts.clear()
    # web-apart covers vm:101 on pve4 too: already off, now held by both, nothing sent
    task = _enter(m, 'pve4', relax_anti_affinity=True)
    assert pve.puts == [] and task.ha_rules_off == ['web-apart']
    assert _rows(db) == [('ct-apart', 'maintenance:pve5'), ('web-apart', 'maintenance:pve4'),
                         ('web-apart', 'maintenance:pve5')]

    PegaProxManager.exit_maintenance_mode(m, 'pve5')
    assert [p[0] for p in pve.puts] == ['/cluster/ha/rules/ct-apart'], 'web-apart is still held by pve4'
    assert _off(rules) == ['admin-off', 'web-apart']
    assert _rows(db) == [('web-apart', 'maintenance:pve4')]
    PegaProxManager.exit_maintenance_mode(m, 'pve4')
    assert _off(rules) == ['admin-off'] and _rows(db) == []


def test_a_rule_a_rolling_update_and_a_maintenance_hold_stays_off_until_both_let_go(db, monkeypatch):
    m, pve, rules, order = _node_manager(db, monkeypatch)
    # the maintenance first, then a relaxed rolling update joins it
    _enter(m, 'pve5', relax_anti_affinity=True)
    m._rolling_update = {'status': 'running', 'ha_rules_held': True}
    off, failed = m.suspend_negative_ha_rules(who='root')
    # the two the maintenance holds are held by the run too, the others switched off for it
    assert off == ['web-apart', 'ct-apart', 'elsewhere', 'other-kind'] and failed == []
    assert [p[0].rsplit('/', 1)[1] for p in pve.puts[-2:]] == ['elsewhere', 'other-kind']
    assert ('web-apart', 'rolling') in _rows(db) and ('web-apart', 'maintenance:pve5') in _rows(db)
    pve.puts.clear()
    # the node leaves maintenance during the run: its rules stay off, the run still holds them
    PegaProxManager.exit_maintenance_mode(m, 'pve5')
    assert pve.puts == [] and _off(rules) == ['admin-off', 'ct-apart', 'elsewhere', 'other-kind', 'web-apart']
    # the run ends
    m._rolling_update = {'status': 'completed', 'ha_rules_held': False}
    on, left = m.restore_suspended_ha_rules(who='root')
    assert sorted(on) == ['ct-apart', 'elsewhere', 'other-kind', 'web-apart'] and left == []
    assert _rows(db) == [] and _off(rules) == ['admin-off']

    # the other way round: the run ends first, the maintenance keeps what it holds
    _enter(m, 'pve5', relax_anti_affinity=True)
    m._rolling_update = {'status': 'running', 'ha_rules_held': True}
    m.suspend_negative_ha_rules()
    pve.puts.clear()
    m._rolling_update['ha_rules_held'] = False
    m.restore_suspended_ha_rules()
    assert sorted(p[0].rsplit('/', 1)[1] for p in pve.puts) == ['elsewhere', 'other-kind']
    assert _off(rules) == ['admin-off', 'ct-apart', 'web-apart']
    PegaProxManager.exit_maintenance_mode(m, 'pve5')
    assert _off(rules) == ['admin-off'] and _rows(db) == []


def test_a_rule_proxmox_kept_on_is_not_held_and_one_that_does_not_come_back_is_retried(db, monkeypatch):
    m, pve, rules, order = _node_manager(db, monkeypatch)
    pve.put_status['/cluster/ha/rules/ct-apart'] = 403
    task = _enter(m, 'pve5', relax_anti_affinity=True)
    assert task.ha_rules_off == ['web-apart'] and task.ha_rules_kept_on == ['ct-apart']
    assert _rows(db) == [('web-apart', 'maintenance:pve5')]
    pve.put_status['/cluster/ha/rules/web-apart'] = 500
    assert PegaProxManager.exit_maintenance_mode(m, 'pve5') is True, 'the node left maintenance anyway'
    assert _rows(db) == [('web-apart', 'maintenance:pve5')], 'listed for the next try'
    # the daemon loop: the owner is gone, so the row was left behind
    del pve.put_status['/cluster/ha/rules/web-apart']
    monkeypatch.setattr(ha, 'is_active', lambda: True)
    m._restore_suspended_ha_rules_if_due()
    assert _rows(db) == [] and 'web-apart' not in _off(rules)


def test_the_daemon_leaves_what_a_node_in_maintenance_holds(db, monkeypatch):
    m, pve, rules, order = _node_manager(db, monkeypatch)
    _enter(m, 'pve5', relax_anti_affinity=True)
    pve.puts.clear()
    monkeypatch.setattr(ha, 'is_active', lambda: True)
    m._restore_suspended_ha_rules_if_due()
    assert pve.puts == []
    # left behind by a rolling update that died: switched on, the maintenance's rules stay off
    db.save_suspended_ha_rules('cluster_1', ['elsewhere'])
    rules[2]['disable'] = 1
    m._restore_suspended_ha_rules_if_due()
    assert [p[0] for p in pve.puts] == ['/cluster/ha/rules/elsewhere']
    assert _rows(db) == [('ct-apart', 'maintenance:pve5'), ('web-apart', 'maintenance:pve5')]


def test_after_a_restart_and_a_takeover_the_maintenance_still_holds_its_rules(db, monkeypatch):
    """The rows and node_maintenance travel to the standby (both synced); the node is in
    maintenance there too, so its rules stay off until it leaves."""
    assert 'suspended_ha_rules' in ha.SYNC_TABLES and 'node_maintenance' in ha.SYNC_TABLES
    monkeypatch.setattr(mgrmod, 'get_db', lambda: db)
    m, pve, rules, order = _node_manager(db, monkeypatch)
    _enter(m, 'pve5', relax_anti_affinity=True)
    assert db.get_node_maintenance('cluster_1')

    # a restart: a new manager over the same database
    fresh = _manager(pve, MGUESTS)
    fresh.maintenance_lock = threading.Lock()
    fresh.nodes_in_maintenance = {}
    fresh._unset_ceph_maintenance_flags = lambda node: None
    PegaProxManager._restore_persisted_maintenance(fresh)
    pve.puts.clear()
    monkeypatch.setattr(ha, 'is_active', lambda: True)
    fresh._restore_suspended_ha_rules_if_due()
    assert pve.puts == []

    # a standby follows the rows and acts on none of them, stale or not
    standby = _manager(pve, MGUESTS)
    standby.maintenance_lock = threading.Lock()
    standby.nodes_in_maintenance = {}
    standby._unset_ceph_maintenance_flags = lambda node: None
    monkeypatch.setattr(ha, 'is_active', lambda: False)
    PegaProxManager._follow_persisted_maintenance(standby)
    assert 'pve5' in standby.nodes_in_maintenance
    db.save_suspended_ha_rules('cluster_1', ['elsewhere'])
    standby._restore_suspended_ha_rules_if_due()
    assert pve.puts == []
    # it takes over: what the old rolling update left goes on, the maintenance's stays off
    monkeypatch.setattr(ha, 'is_active', lambda: True)
    standby._restore_suspended_ha_rules_if_due()
    assert [p[0] for p in pve.puts] == ['/cluster/ha/rules/elsewhere']
    # and the node leaves maintenance there
    PegaProxManager.exit_maintenance_mode(standby, 'pve5', who='ops')
    assert _rows(db) == [] and _off(rules) == ['admin-off']


def test_the_old_tables_are_brought_forward_and_their_rows_kept(db):
    """suspended_ha_rules keyed on (cluster_id, rule) is built again with the owner in the key,
    its rows were all a rolling update's; update_schedules gets the two columns, off."""
    c = db.conn
    c.execute('DROP TABLE suspended_ha_rules')
    c.execute('CREATE TABLE suspended_ha_rules (cluster_id TEXT NOT NULL, rule TEXT NOT NULL, '
              'rule_type TEXT NOT NULL, suspended_at TEXT NOT NULL, PRIMARY KEY (cluster_id, rule))')
    c.execute("INSERT INTO suspended_ha_rules VALUES ('c1', 'keep-apart', 'resource-affinity', '2026-10-05T10:00:00')")
    c.execute('DROP TABLE update_schedules')
    c.execute('CREATE TABLE update_schedules (cluster_id TEXT PRIMARY KEY, enabled INTEGER DEFAULT 0, '
              "schedule_type TEXT DEFAULT 'recurring', day TEXT DEFAULT 'sunday', time TEXT DEFAULT '03:00', "
              'include_reboot INTEGER DEFAULT 1, skip_evacuation INTEGER DEFAULT 0, skip_up_to_date INTEGER '
              'DEFAULT 1, evacuation_timeout INTEGER DEFAULT 1800, last_run TEXT, next_run TEXT, '
              'created_by TEXT, created_at TEXT, updated_at TEXT)')
    c.execute("INSERT INTO update_schedules (cluster_id, enabled, day, time) VALUES ('c1', 1, 'daily', '03:00')")
    # on an active with members the shared tables carry the change triggers (#625)
    ha._make_change_triggers(c.cursor())
    c.commit()
    triggers = lambda: {r[0]: r[1] for r in c.execute(  # noqa: E731
        "SELECT name, tbl_name FROM sqlite_master WHERE type = 'trigger' AND name LIKE '%suspended_ha_rules%'")}
    assert set(triggers().values()) == {'suspended_ha_rules'}
    import pegaprox.api.schedules as sch
    # read before any migration ran: both off
    old = sch.load_all_update_schedules()['c1']
    assert old['migrate_templates'] is False and old['relax_anti_affinity'] is False

    db._init_db()
    assert db.get_suspended_ha_rules('c1') == [('keep-apart', 'resource-affinity', '2026-10-05T10:00:00', 'rolling')]
    tables = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert 'suspended_ha_rules_keyed' not in tables
    # the old table took its triggers along; the next look makes them for the new one
    assert set(triggers().values()) <= {'suspended_ha_rules'}
    ha._make_change_triggers(c.cursor())
    c.commit()
    assert len(triggers()) == 3 and set(triggers().values()) == {'suspended_ha_rules'}
    db.save_suspended_ha_rules('c1', ['keep-apart'], owner='maintenance:pve2')
    assert [r[3] for r in db.get_suspended_ha_rules('c1')] == ['maintenance:pve2', 'rolling']
    db.remove_suspended_ha_rule('c1', 'keep-apart', owners='rolling')
    assert [r[3] for r in db.get_suspended_ha_rules('c1')] == ['maintenance:pve2']
    cols = {r[1] for r in c.execute('PRAGMA table_info(update_schedules)').fetchall()}
    assert {'migrate_templates', 'relax_anti_affinity', 'reboot_timeout'} <= cols
    old = sch.load_all_update_schedules()['c1']
    assert old['migrate_templates'] is False and old['relax_anti_affinity'] is False
    assert old['day'] == 'daily'
    # a second start changes nothing
    db._init_db()
    assert [r[3] for r in db.get_suspended_ha_rules('c1')] == ['maintenance:pve2']


# -- the plan of one node ------------------------------------------------------------------------

def test_the_plan_of_a_node_has_its_templates_and_the_rules_over_its_guests(api, seed, db, monkeypatch):
    m, pve, rules, order = _node_manager(db, monkeypatch)
    # pve4 holds web-apart off for its maintenance already
    _enter(m, 'pve4', relax_anti_affinity=True)
    pve.puts.clear()
    db.save_suspended_ha_rules('cluster_1', ['gone-rule'])
    api.set_manager('cluster_1', m)
    r = api.as_user(seed.user('root', role='admin')).get('/api/clusters/cluster_1/nodes/pve5/maintenance-plan')
    assert r.status_code == 200, r.data
    plan = r.get_json()
    assert [t['vmid'] for t in plan['templates']] == [9000], 'the templates of pve5 only'
    assert [(x['rule'], x['resources']) for x in plan['negative_rules']] == [('ct-apart', ['ct:201', 'vm:200'])]
    assert plan['held'] == [{'rule': 'web-apart', 'rolling': False, 'nodes': ['pve4']}]
    # a stale row over no guest of pve5 is not this node's business
    assert plan['still_off'] == []
    assert pve.puts == [] and pve.migrations == []
    # the cluster's plan has all of them
    cl = api.as_user(seed.user('root2', role='admin')).get('/api/clusters/cluster_1/updates/rolling/plan').get_json()
    assert cl['still_off'] == ['gone-rule'] and cl['held'] == [{'rule': 'web-apart', 'rolling': False, 'nodes': ['pve4']}]
    assert sorted(t['vmid'] for t in cl['templates']) == [9000, 9100]


def _pool_user(seed, name, perms):
    import pegaprox.utils.rbac as rbac
    seed.tenant('tenant_x', clusters=['cluster_1'])
    u = seed.user(name, role='viewer', tenant_id='tenant_x', permissions=perms)
    seed.pool('cluster_1', 'pool_1', name, ['pool.view', 'vm.view'])
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache['cluster_1'] = {'data': {'100:qemu': 'pool_1'}, 'timestamp': time.time(),
                                                    'refreshing': False}
    return u


def test_nobody_confined_or_without_node_maintenance_reads_the_plan_of_a_node(api, seed, db, monkeypatch):
    m, pve, rules, order = _node_manager(db, monkeypatch)
    api.set_manager('cluster_1', m)
    seed.tenant('globex', clusters=['cluster_2'])
    api.set_manager('cluster_2', api.make_fake_manager('cluster_2'))
    callers = {
        'confined admin': seed.user('gx', role='admin', tenant_id='globex',
                                    tenant_permissions={'globex': {'role': 'user'}}),
        'other tenant': seed.user('milton', role='user', tenant_id='globex', permissions=['node.maintenance']),
        'pool-confined': _pool_user(seed, 'mallory', ['node.maintenance', 'node.view', 'cluster.view']),
        'no node.maintenance': seed.user('vic', role='viewer'),
        'node.update only': seed.user('upd', role='user', permissions=['node.update', 'node.view', 'cluster.view']),
    }
    for who, user in callers.items():
        r = api.as_user(user).get('/api/clusters/cluster_1/nodes/pve5/maintenance-plan')
        assert r.status_code == 403, (who, r.status_code, r.get_data(as_text=True))
    assert pve.gets == [], 'a refused caller made the manager read'
    ops = seed.user('ops', role='user', permissions=['node.maintenance', 'node.view', 'cluster.view'])
    assert api.as_user(ops).get('/api/clusters/cluster_1/nodes/pve5/maintenance-plan').status_code == 200
    assert api.anon().get('/api/clusters/cluster_1/nodes/pve5/maintenance-plan').status_code == 401


def test_the_plan_of_an_xcpng_host_says_unsupported(api, seed):
    api.set_manager('cluster_1', api.make_fake_manager('cluster_1', cluster_type='xcpng'))
    r = api.as_user(seed.user('root', role='admin')).get('/api/clusters/cluster_1/nodes/h1/maintenance-plan')
    assert r.get_json() == {'supported': False}


# -- the maintenance routes ----------------------------------------------------------------------

def _maint_fake(api, cluster_type='proxmox'):
    fake = api.make_fake_manager('cluster_1', cluster_type=cluster_type)
    fake.config.name = 'Testi'
    fake.config.balance_local_disks = False
    fake.enter_maintenance_mode.return_value = MaintenanceTask('pve5')
    fake.exit_maintenance_mode.return_value = True
    api.set_manager('cluster_1', fake)
    return fake


def test_the_maintenance_route_carries_both_options_and_audits_them(api, seed):
    fake = _maint_fake(api)
    c = api.as_user(seed.user('root', role='admin'))
    r = c.put('/api/clusters/cluster_1/nodes/pve5/maintenance',
              json={'enable': True, 'migrate_templates': True, 'relax_anti_affinity': True})
    assert r.status_code == 200, r.data
    kw = fake.enter_maintenance_mode.call_args.kwargs
    assert (kw['migrate_templates'], kw['relax_anti_affinity'], kw['who']) == (True, True, 'root')
    details = seed.db.conn.execute(
        "SELECT details FROM audit_log WHERE action='node.maintenance_entered'").fetchone()[0]
    assert details.startswith('Node pve5 entered maintenance mode: templates move with the evacuation; '
                              'negative affinity rules give way until it ends')
    # only a real true, and never without an evacuation
    for body in ({'enable': True}, {'enable': True, 'migrate_templates': 'yes', 'relax_anti_affinity': 1},
                 {'enable': True, 'skip_evacuation': True, 'migrate_templates': True, 'relax_anti_affinity': True}):
        c.put('/api/clusters/cluster_1/nodes/pve5/maintenance', json=body)
        kw = fake.enter_maintenance_mode.call_args.kwargs
        assert (kw['migrate_templates'], kw['relax_anti_affinity']) == (False, False), body
    # leaving says who, for the audit of the rules switched back on
    assert c.delete('/api/clusters/cluster_1/nodes/pve5/maintenance').status_code == 200
    assert fake.exit_maintenance_mode.call_args.kwargs == {'who': 'root'}
    c.put('/api/clusters/cluster_1/nodes/pve5/maintenance', json={'enable': False})
    assert fake.exit_maintenance_mode.call_args.kwargs == {'who': 'root'}


def test_xcpng_maintenance_gets_neither_option(api, seed):
    fake = _maint_fake(api, cluster_type='xcpng')
    c = api.as_user(seed.user('root', role='admin'))
    c.put('/api/clusters/cluster_1/nodes/h1/maintenance',
          json={'enable': True, 'migrate_templates': True, 'relax_anti_affinity': True})
    assert set(fake.enter_maintenance_mode.call_args.kwargs) == {'skip_evacuation', 'allow_local_disks'}
    c.delete('/api/clusters/cluster_1/nodes/h1/maintenance')
    assert fake.exit_maintenance_mode.call_args.kwargs == {}
    from pegaprox.core.xcpng import XcpngManager
    import inspect
    inspect.signature(XcpngManager.exit_maintenance_mode).bind(None, 'h1')


def test_the_maintenance_route_keeps_its_gates(api, seed):
    fake = _maint_fake(api)
    seed.tenant('globex', clusters=['cluster_2'])
    body = {'enable': True, 'migrate_templates': True, 'relax_anti_affinity': True}
    for user in (seed.user('vic', role='viewer'),
                 seed.user('milton', role='user', tenant_id='globex', permissions=['node.maintenance']),
                 _pool_user(seed, 'mallory', ['node.maintenance', 'node.view', 'cluster.view'])):
        c = api.as_user(user)
        assert c.put('/api/clusters/cluster_1/nodes/pve5/maintenance', json=body).status_code == 403
        assert c.delete('/api/clusters/cluster_1/nodes/pve5/maintenance').status_code == 403
    assert not fake.enter_maintenance_mode.called and not fake.exit_maintenance_mode.called


def test_a_standby_takes_no_maintenance_and_switches_no_rule(api, seed, monkeypatch):
    import pegaprox.api.ha as ha_api
    fake = _maint_fake(api)
    monkeypatch.setattr(ha, 'is_standby', lambda: True)
    monkeypatch.setattr(ha_api, 'forward_to_active', lambda read=False: None)
    c = api.as_user(seed.user('root', role='admin'))
    r = c.put('/api/clusters/cluster_1/nodes/pve5/maintenance',
              json={'enable': True, 'relax_anti_affinity': True})
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY', r.data
    r = c.delete('/api/clusters/cluster_1/nodes/pve5/maintenance')
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY', r.data
    r = c.post('/api/clusters/cluster_1/updates/schedule', json={'enabled': True, 'relax_anti_affinity': True})
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY', r.data
    assert not fake.enter_maintenance_mode.called and not fake.exit_maintenance_mode.called
    # reading the plan is no change
    fake.evacuation_plan.return_value = {'supported': True, 'templates': []}
    assert c.get('/api/clusters/cluster_1/nodes/pve5/maintenance-plan').status_code == 200


# -- scheduled rolling updates -------------------------------------------------------------------

SCHEDULE = '/api/clusters/cluster_1/updates/schedule'


def test_a_schedule_stores_lists_and_edits_both_options(api, seed):
    _maint_fake(api)
    c = api.as_user(seed.user('root', role='admin'))
    body = {'enabled': True, 'day': 'sunday', 'time': '03:00', 'include_reboot': False,
            'migrate_templates': True, 'relax_anti_affinity': True}
    r = c.post(SCHEDULE, json=body)
    assert r.status_code == 200, r.data
    got = c.get(SCHEDULE).get_json()
    assert got['migrate_templates'] is True and got['relax_anti_affinity'] is True
    import pegaprox.api.schedules as sch
    stored = sch.load_all_update_schedules()['cluster_1']
    assert stored['migrate_templates'] is True and stored['relax_anti_affinity'] is True
    audit = seed.db.conn.execute("SELECT details FROM audit_log WHERE action='update.schedule'").fetchall()
    assert audit[-1][0].startswith('Update schedule enabled for Testi: templates move with the evacuation; '
                                   'negative affinity rules give way until it ends')
    # edited: one off, the other on
    assert c.post(SCHEDULE, json=dict(body, migrate_templates=False)).status_code == 200
    got = c.get(SCHEDULE).get_json()
    assert got['migrate_templates'] is False and got['relax_anti_affinity'] is True
    # a schedule saved without them has both off
    assert c.post(SCHEDULE, json={'enabled': True, 'include_reboot': False}).status_code == 200
    got = c.get(SCHEDULE).get_json()
    assert got['migrate_templates'] is False and got['relax_anti_affinity'] is False


def test_an_xcpng_schedule_keeps_both_off(api, seed):
    _maint_fake(api, cluster_type='xcpng')
    c = api.as_user(seed.user('root', role='admin'))
    c.post(SCHEDULE, json={'enabled': True, 'include_reboot': False, 'migrate_templates': True,
                           'relax_anti_affinity': True})
    got = c.get(SCHEDULE).get_json()
    assert got['migrate_templates'] is False and got['relax_anti_affinity'] is False


def test_the_schedule_route_keeps_its_gates(api, seed):
    _maint_fake(api)
    body = {'enabled': True, 'include_reboot': False, 'relax_anti_affinity': True}
    for user in (seed.user('vic', role='viewer'),
                 seed.user('bk', role='user', permissions=['backup.schedule', 'cluster.view']),
                 _pool_user(seed, 'mallory', ['node.update', 'node.view', 'cluster.view'])):
        assert api.as_user(user).post(SCHEDULE, json=body).status_code == 403
    import pegaprox.api.schedules as sch
    assert sch.load_all_update_schedules() == {}


def test_the_scheduler_hands_the_stored_options_to_the_run(monkeypatch):
    import pegaprox.api.schedules as sch
    from datetime import datetime
    monkeypatch.setattr(ha, 'schedule_now', lambda: datetime(2026, 10, 4, 3, 0))
    mgr = MagicMock()
    mgr.is_connected, mgr._rolling_update = True, None
    monkeypatch.setitem(sch.cluster_managers, 'c1', mgr)
    monkeypatch.setitem(sch.cluster_managers, 'c2', mgr)
    runs = []
    monkeypatch.setattr(sch, 'execute_scheduled_rolling_update', lambda m, cid, a: runs.append((cid, a['config'])))
    monkeypatch.setattr(sch, 'update_schedule_last_run', lambda *a: None)
    monkeypatch.setattr(sch, '_creator_may_update', lambda cid, s: True)   # its own file (#1093)
    base = {'enabled': True, 'schedule_type': 'recurring', 'day': 'daily', 'time': '03:00'}
    monkeypatch.setattr(sch, 'load_all_update_schedules', lambda: {
        'c1': dict(base, migrate_templates=True, relax_anti_affinity=True),
        'c2': dict(base)})     # from before the options
    sch.check_scheduled_updates()
    got = dict(runs)
    assert (got['c1']['migrate_templates'], got['c1']['relax_anti_affinity']) == (True, True)
    assert (got['c2']['migrate_templates'], got['c2']['relax_anti_affinity']) == (False, False)


@pytest.fixture
def fast_schedule(monkeypatch):
    import pegaprox.api.schedules as sch
    monkeypatch.setattr(sch, 'time', _FastTime())
    return sch


def _scheduled_fake(api, guests=GUESTS, cluster_type='proxmox'):
    fake, order = _cluster_manager(api, guests, cluster_type=cluster_type)

    def update(node, reboot=False, force=False):
        order.append(('update', node))
        t = UpdateTask(node, reboot=False)
        t.status, t.phase = 'completed', 'done'
        return t
    fake.start_node_update.side_effect = update
    return fake, order


def _run_scheduled(sch, fake, **config):
    action = {'cluster_id': 'cluster_1', 'action': 'rolling_update',
              'config': dict({'include_reboot': False, 'skip_up_to_date': False}, **config)}
    sch.execute_scheduled_rolling_update(fake, 'cluster_1', action)
    deadline = time.time() + 20
    while time.time() < deadline and (fake._rolling_update or {}).get('status') == 'running':
        time.sleep(0.02)
    return fake._rolling_update


def test_a_scheduled_run_switches_the_rules_off_before_its_first_evacuation_and_on_at_its_end(api, seed, fast_schedule):
    fake, order = _scheduled_fake(api)
    state = _run_scheduled(fast_schedule, fake, migrate_templates=True, relax_anti_affinity=True)
    assert state['status'] == 'completed', state['logs']
    steps = [o[0] if o[0].startswith('rules') else f'{o[0]} {o[1]}' for o in order]
    assert steps == ['rules off', 'enter pve1', 'update pve1', 'exit pve1',
                     'enter pve2', 'update pve2', 'exit pve2', 'rules on'], steps
    assert ('rules off', 'scheduler') in order and ('rules on', 'scheduler') in order
    assert [o[2].get('migrate_templates') for o in order if o[0] == 'enter'] == [True, True]
    logs = '\n'.join(state['logs'])
    assert 'migrate_templates=True, relax_anti_affinity=True' in logs
    assert "Templates: moved offline with each node's evacuation" in logs
    assert 'Negative affinity: guests that must run apart may share a node until the run ends.' in logs
    assert 'Negative affinity: 1 Proxmox HA rule(s) switched off until the run ends: keep-apart' in logs
    assert 'template(s) to move: tpl9000 (9000)' in logs
    assert '✓ Template tpl9000 (9000) moved to pve2' in logs
    assert '⚠ Template tpl9001 (9001) stays on the node: no other node has storage local-zfs' in logs
    assert 'Negative affinity rules switched back on: keep-apart' in logs
    assert state['ha_rules_held'] is False and state['relax_anti_affinity'] is True
    rows = [tuple(r) for r in seed.db.conn.execute(
        "SELECT user, details FROM audit_log WHERE action='node.rolling_update_started'").fetchall()]
    assert len(rows) == 1 and rows[0][0] == 'scheduler'
    assert rows[0][1].startswith('Scheduled rolling update of 2 node(s) started: templates move with the '
                                 'evacuation; negative affinity rules give way until it ends')


def test_a_failed_scheduled_run_switches_the_rules_back_on(api, seed, fast_schedule):
    fake, order = _scheduled_fake(api)
    enter = fake.enter_maintenance_mode.side_effect

    def enter_or_fail(node, **kw):
        if node == 'pve2':
            raise RuntimeError('ssh went away')
        return enter(node, **kw)
    fake.enter_maintenance_mode.side_effect = enter_or_fail
    state = _run_scheduled(fast_schedule, fake, relax_anti_affinity=True)
    assert state['status'] == 'failed'
    assert order[0] == ('rules off', 'scheduler') and order[-1] == ('rules on', 'scheduler'), order
    assert state['ha_rules_held'] is False


def test_an_old_or_default_schedule_runs_as_before(api, seed, fast_schedule):
    fake, order = _scheduled_fake(api)
    state = _run_scheduled(fast_schedule, fake)      # a config from before the options
    assert state['status'] == 'completed', state['logs']
    assert fake.suspend_negative_ha_rules.call_count == 0 and fake.restore_suspended_ha_rules.call_count == 0
    assert [o[2] for o in order if o[0] == 'enter'] == [{'skip_evacuation': False, 'allow_local_disks': True}] * 2
    logs = '\n'.join(state['logs'])
    assert 'migrate_templates=False, relax_anti_affinity=False' in logs
    assert 'template(s) staying here: tpl9000 (9000)' in logs
    assert 'Negative affinity' not in logs and 'Templates:' not in logs
    rows = [r[0] for r in seed.db.conn.execute(
        "SELECT details FROM audit_log WHERE action='node.rolling_update_started'").fetchall()]
    assert len(rows) == 1 and rows[0].startswith('Scheduled rolling update of 2 node(s) started')
    assert 'templates' not in rows[0] and 'negative affinity' not in rows[0]


def test_a_scheduled_run_on_xcpng_takes_neither_option(api, seed, fast_schedule):
    fake, order = _scheduled_fake(api, cluster_type='xcpng')
    state = _run_scheduled(fast_schedule, fake, migrate_templates=True, relax_anti_affinity=True)
    assert state['status'] == 'completed', state['logs']
    assert fake.suspend_negative_ha_rules.call_count == 0
    assert all('migrate_templates' not in o[2] for o in order if o[0] == 'enter')
    assert state['migrate_templates'] is False and state['relax_anti_affinity'] is False


def test_a_scheduled_run_without_an_evacuation_switches_nothing(api, seed, fast_schedule):
    fake, order = _scheduled_fake(api)
    state = _run_scheduled(fast_schedule, fake, skip_evacuation=True, relax_anti_affinity=True)
    assert state['status'] == 'completed', state['logs']
    assert fake.suspend_negative_ha_rules.call_count == 0 and fake.restore_suspended_ha_rules.call_count == 0


def test_both_runs_use_the_one_helper():
    """The two copies of the loop share what the options do (api/helpers.py)."""
    import inspect
    import pegaprox.api.schedules as sch
    import pegaprox.api.settings as st
    run = inspect.getsource(sch.execute_scheduled_rolling_update)
    # the route starts the run, its worker (also the one of a Continue after a restart) runs it
    start = inspect.getsource(st.start_rolling_update) + inspect.getsource(st.run_rolling_update)
    for name in ('evacuation_options(', 'rolling_rules_give_way(', 'rolling_rules_back_on(',
                 'rolling_moved_templates(', 'rolling_options_intro(', 'rolling_node_templates(',
                 'evacuation_options_said(', 'rolling_wind_down('):
        assert name in run and name in start, name
    assert 'suspend_negative_ha_rules' not in run + start
