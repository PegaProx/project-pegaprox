"""The balancer's moves in the migration history, with why, and its cooldown per cluster.

The balancer kept the moves it made in a list in memory: no reason, gone with a restart,
and the pause before it moved a guest again was 900 seconds on every cluster. Every move
it makes now (the load check, a trend, an anti-affinity rule, a node pin, an XCP-ng pool)
goes into migration_history with the numbers that started it, GET
/api/clusters/<id>/balance-history lists them for the settings tab, and migration_cooldown
sets the pause per cluster, read back from the history after a restart.

MK Oct 2026
"""
import logging
import time
import types
from datetime import datetime, timedelta
from unittest.mock import MagicMock

import pytest

import pegaprox.api.clusters as clusters_api
import pegaprox.core.manager as mgrmod
from pegaprox.core.manager import BALANCE_WHY, PegaProxManager, balance_reason
from pegaprox.models.tasks import PegaProxConfig, balancer_cooldown
from test_ha_api import ha_env, _admin, _audit, _standby_of_active  # noqa: F401

CID = 'cluster_1'
NODES = ('pve1', 'pve2', 'pve3')
ROUTE = f'/api/clusters/{CID}/balance-history'


def _resp(status=200, data=None, text=''):
    return types.SimpleNamespace(status_code=status, json=lambda: {'data': data}, text=text)


def _guest(vmid=101, node='pve1', name=None, tags=''):
    return {'vmid': vmid, 'name': name or f'g{vmid}', 'node': node, 'status': 'running',
            'type': 'qemu', 'mem': 1024 ** 3, 'tags': tags}


def _manager(guests, scores=None, **cfg):
    """A real manager, the PVE calls stubbed: the balance code and migrate_vm run as they are."""
    m = object.__new__(PegaProxManager)
    m.id = CID
    m.current_host = None
    m.logger = logging.getLogger('test.balancer_history')
    m.last_migration_log = []
    m._vm_migration_cooldown = {}
    conf = {'name': 'lab', 'host': 'h', 'user': 'u', 'auto_migrate': True, 'dry_run': False,
            'migration_threshold': 20, 'migration_tolerance': 10}
    conf.update(cfg)
    m.config = PegaProxConfig(conf)
    scores = dict({'pve1': 80.0, 'pve2': 20.0, 'pve3': 50.0}, **(scores or {}))
    m.get_node_status = lambda: {
        n: {'status': 'online', 'maintenance_mode': False, 'score': scores[n],
            'cpu_percent': scores[n] / 2, 'mem_percent': scores[n] / 2 + 10,
            'mem_used': 10 * 1024 ** 3, 'mem_total': 100 * 1024 ** 3} for n in NODES}
    m.get_vm_resources = lambda *a, **k: guests
    m.get_balancing_excluded_vms = lambda: []
    m.get_balancing_excluded_pools = lambda: []
    m.get_proxmox_ha_resources = lambda: []
    m._api_get = lambda *a, **k: _resp(404)
    m.check_vm_storage_type = lambda *a, **k: 'shared'
    m._check_cpu_compatibility = lambda *a, **k: {'compatible': True}
    session = MagicMock()
    session.get.return_value = _resp(200, {'cpu': 'kvm64'})
    m._create_session = lambda: session
    m.posts = []
    m.task_ok = True

    def post(url, data=None, **kw):
        m.posts.append((url, data))
        return _resp(200, 'UPID:pve1:0001:qmigrate')
    m._api_post = post
    m._wait_for_task = lambda node, upid, timeout=0: m.task_ok
    return m


def _moves(db, **kw):
    return db.list_balancer_moves(CID, **kw)


def _ago(seconds):
    return (datetime.now().astimezone() - timedelta(seconds=seconds)).isoformat(timespec='seconds')


# --- what a move records ------------------------------------------------------------------------

def test_a_balance_move_is_recorded_with_the_loads_that_started_it(db):
    guests = [_guest()]
    m = _manager(guests)
    m.run_balance_check()
    assert len(m.posts) == 1 and m.posts[0][1]['target'] == 'pve2'
    rows = _moves(db)
    assert len(rows) == 1
    row = rows[0]
    assert (row['trigger'], row['status'], row['vmid'], row['vm_name']) == ('balance', 'success', 101, 'g101')
    assert (row['source_node'], row['target_node']) == ('pve1', 'pve2')
    assert 'pve1 score 80.0 (CPU 40.0%, RAM 50.0%)' in row['reason']
    assert 'pve2 score 20.0' in row['reason'] and 'above threshold 20 + tolerance 10' in row['reason']
    d = row['details']
    assert d['diff'] == 60.0 and d['threshold'] == 20.0 and d['tolerance'] == 10.0
    assert d['source_load']['score'] == 80.0 and d['target_load']['mem'] == 20.0
    assert 'manual' not in d
    # the reason rode in on the guest dict and does not stay on it
    assert BALANCE_WHY not in guests[0]
    # the in-memory list says which rule moved it, the guest goes into the cooldown
    assert m.last_migration_log[-1]['trigger'] == 'balance'
    assert 101 in m._vm_migration_cooldown
    assert row['timestamp'][-6] in '+-'     # carries its UTC offset


def test_balance_now_is_marked_as_started_by_hand(db):
    m = _manager([_guest()], auto_migrate=False)
    m.run_balance_check(force=True)
    row = _moves(db)[0]
    assert row['details']['manual'] is True and row['reason'].endswith('(started by hand)')


def test_a_dry_run_is_recorded_as_one_and_moves_nothing(db):
    m = _manager([_guest()], dry_run=True)
    m.run_balance_check()
    assert m.posts == []
    assert [(r['status'], r['trigger']) for r in _moves(db)] == [('dry_run', 'balance')]


def test_a_failed_move_says_what_failed(db, monkeypatch):
    monkeypatch.setattr(mgrmod, 'HA_MIGRATE_SETTLE_SECONDS', 0)
    m = _manager([_guest()])
    m.task_ok = False
    m.run_balance_check()
    row = _moves(db)[0]
    assert row['status'] == 'failed' and row['details']['error'] == 'Task failed'
    assert row['reason'].endswith('failed: Task failed')
    assert 101 not in m._vm_migration_cooldown


def test_a_move_ha_placed_elsewhere_names_both_nodes(db, monkeypatch):
    monkeypatch.setattr(mgrmod, 'HA_MIGRATE_SETTLE_SECONDS', 0)
    guests = [_guest()]
    m = _manager(guests)
    m.task_ok = False
    picked = []

    def resources(*a, **k):
        # the candidate pick reads it first; once the task failed, HA has it on pve3
        picked.append(1)
        return guests if len(picked) == 1 else [dict(guests[0], node='pve3')]
    m.get_vm_resources = resources
    m.run_balance_check()
    row = _moves(db)[0]
    assert row['status'] == 'success' and row['target_node'] == 'pve3'
    assert row['details']['requested_target'] == 'pve2'
    assert 'HA placed it on pve3 instead of pve2' in row['reason']


def test_a_move_that_is_no_balancer_move_writes_no_history(db):
    # a maintenance evacuation, a manual migration: they keep their own records
    m = _manager([_guest()])
    assert m.migrate_vm(_guest(), 'pve2') is True
    assert _moves(db) == [] and db.query('SELECT COUNT(*) AS n FROM migration_history')[0]['n'] == 0
    assert 'trigger' not in m.last_migration_log[-1]


def test_a_trend_move_is_recorded_with_its_forecast(db):
    # no imbalance now (50 vs 40), pve1 is heading for overload
    m = _manager([_guest()], scores={'pve1': 50.0, 'pve2': 40.0, 'pve3': 45.0},
                 predictive_balancing=True, predictive_threshold=75)
    m._compute_predictive_score = lambda n: ({'score': 88.4, 'trend': 'critical', 'confidence': 0.75}
                                             if n == 'pve1' else {'score': 10, 'trend': 'stable', 'confidence': 1})
    m.run_balance_check()
    row = _moves(db)[0]
    assert row['trigger'] == 'predictive' and row['target_node'] == 'pve2'
    assert row['details']['forecast'] == 88.4 and row['details']['confidence'] == 75
    assert 'forecast score 88.4 above 75, confidence 75%' in row['reason']


def test_an_anti_affinity_move_names_the_rule(db):
    db.save_all_affinity_rules({CID: [{'id': 'r1', 'name': 'web apart', 'type': 'separate',
                                       'vms': [101, 102], 'enabled': True, 'enforce': True}]})
    guests = [_guest(101), _guest(102)]
    m = _manager(guests, scores={'pve1': 40.0, 'pve2': 35.0, 'pve3': 30.0})
    m.run_balance_check()
    row = _moves(db)[0]
    assert row['trigger'] == 'affinity' and row['vmid'] == 102 and row['target_node'] == 'pve3'
    assert row['details']['rule'] == 'web apart'
    assert "anti-affinity rule 'web apart'" in row['reason']
    assert 102 in m._vm_migration_cooldown


def test_a_return_to_the_pin_is_recorded(db):
    guests = [_guest(tags='plb_pin_pve2')]
    m = _manager(guests, scores={'pve1': 40.0, 'pve2': 35.0, 'pve3': 30.0},
                 proxlb_tags_enabled=True, proxlb_pins_auto_migrate=True)
    m.reconcile_proxlb_pins()
    row = _moves(db)[0]
    assert (row['trigger'], row['source_node'], row['target_node']) == ('pin', 'pve1', 'pve2')
    assert row['details']['pinned'] == ['pve2']
    assert row['reason'] == 'pinned to pve2 but running on pve1, returned to pve2'


def test_the_reasons_read_without_a_long_dash():
    for why in (balance_reason('balance', 'a', 'b', {}, threshold=1, tolerance=2, manual=True),
                balance_reason('predictive', 'a', 'b', {}, forecast=1, confidence=0.5, threshold=1),
                balance_reason('affinity', 'a', 'b', {}, rule='r'),
                balance_reason('pin', 'a', 'b', {}, pinned=['b'])):
        assert '\u2014' not in why['reason'] and '\u2013' not in why['reason']


def test_an_xcpng_pool_records_its_moves_and_keeps_the_cooldown(db, monkeypatch):
    import pegaprox.core.xcpng as xcpng_mod
    from pegaprox.core.xcpng import XcpngManager
    monkeypatch.setattr(xcpng_mod, 'time', types.SimpleNamespace(sleep=lambda s: None, time=time.time,
                                                                 monotonic=time.monotonic))
    x = object.__new__(XcpngManager)
    x.id, x.cluster_type = 'xcp1', 'xcpng'
    x.logger = logging.getLogger('test.balancer_history.xcp')
    x.config = PegaProxConfig({'name': 'pool', 'host': 'h', 'user': 'u', 'migration_threshold': 30,
                               'migration_cooldown': 600})
    x.last_migration_log, x._vm_migration_cooldown = [], {}
    x.get_node_status = lambda: {'h1': {'score': 150.0, 'cpu_percent': 70.0, 'mem_percent': 80.0},
                                 'h2': {'score': 40.0, 'cpu_percent': 20.0, 'mem_percent': 20.0}}
    x._cached_vms = [{'vmid': 7, 'name': 'app', 'node': 'h1', 'status': 'running', 'mem': 1}]
    x.get_balancing_excluded_vms = lambda: []
    x.check_vm_storage_type = lambda node, vmid: 'shared'
    sent = []
    x.migrate_vm_manual = lambda *a, **k: sent.append(k['target_node']) or {'success': True}
    XcpngManager.run_balance_check(x)
    assert sent == ['h2']
    row = db.list_balancer_moves('xcp1')[0]
    assert (row['trigger'], row['status'], row['source_node'], row['target_node']) == \
        ('balance', 'success', 'h1', 'h2')
    assert 'h1 score 150.0' in row['reason'] and 'above threshold 30 + tolerance 0' in row['reason']
    # the pool had no cooldown at all: the guest is left alone now
    assert 7 in x._vm_migration_cooldown
    assert x.find_migration_candidate('h1', 'h2') is None


# --- the cooldown ---------------------------------------------------------------------------------

def test_the_cooldown_is_the_cluster_setting(db):
    m = _manager([_guest()])
    m._vm_migration_cooldown = {101: time.time() - 600}
    assert m.find_migration_candidate('pve1', 'pve2') is None           # 900 s, the default
    m.config.migration_cooldown = 300
    assert m.find_migration_candidate('pve1', 'pve2')['vmid'] == 101


def test_the_cooldown_survives_a_restart(db):
    db.add_migration_event(CID, 101, 'g101', 'pve3', 'pve1', 'success', trigger='balance',
                           timestamp=_ago(300))
    db.add_migration_event(CID, 102, 'g102', 'pve3', 'pve1', 'failed', trigger='balance',
                           timestamp=_ago(300))
    db.add_migration_event(CID, 103, 'g103', 'pve3', 'pve1', 'success', trigger='balance',
                           timestamp=_ago(2000))
    # a manager built after the restart, its list in memory empty
    m = _manager([_guest(101), _guest(102), _guest(103)])
    picked = [m.find_migration_candidate('pve1', 'pve2', exclude_vmids=done)
              for done in ([], [102], [102, 103])]
    assert [p['vmid'] if p else None for p in picked] == [102, 103, None]
    assert set(m._vm_migration_cooldown) == {101}


def test_the_return_to_a_pin_waits_out_the_cluster_cooldown(db):
    guests = [_guest(tags='plb_pin_pve2')]
    m = _manager(guests, proxlb_tags_enabled=True, proxlb_pins_auto_migrate=True)
    m._vm_migration_cooldown = {101: time.time() - 600}
    m._cooldown_seeded = True
    r = m.reconcile_proxlb_pins()
    assert m.posts == [] and [v['vmid'] for v in r['deferred']] == [101]
    m.config.migration_cooldown = 300
    m._proxlb_derived_cache = None
    assert [v['vmid'] for v in m.reconcile_proxlb_pins()['migrated']] == [101]


@pytest.mark.parametrize('value,expected', [(1800, 1800), ('1800', 1800), (5, 60), (10 ** 9, 86400),
                                            (None, 900), ('x', 900), (True, 900)])
def test_a_stored_cooldown_is_whole_seconds_in_range(value, expected):
    assert balancer_cooldown(value) == expected


def test_the_cooldown_survives_a_save_a_reload_and_an_old_backup(db):
    base = {'name': 'c', 'host': 'h', 'user': 'u', 'pass': 'p', 'migration_cooldown': 1800}
    db.save_cluster(CID, base)
    assert PegaProxConfig(db.get_cluster(CID)).migration_cooldown == 1800
    assert db.get_all_clusters()[CID]['migration_cooldown'] == 1800
    # a restore from a backup that predates the field keeps what is stored
    db.save_cluster(CID, {k: v for k, v in base.items() if k != 'migration_cooldown'})
    assert db.get_cluster(CID)['migration_cooldown'] == 1800
    db.save_cluster(CID, dict(base, migration_cooldown=600))
    assert db.get_cluster(CID)['migration_cooldown'] == 600


def test_a_synced_cooldown_reaches_the_running_manager(db, monkeypatch):
    # #625: a standby hands the synced row to its managers field by field
    from pegaprox.core import ha
    import pegaprox.globals as g
    db.save_cluster(CID, {'name': 'c', 'host': 'h', 'user': 'u', 'pass': 'p', 'migration_cooldown': 2400})
    cfg = PegaProxConfig({'name': 'c', 'host': 'h', 'user': 'u'})
    monkeypatch.setitem(g.cluster_managers, CID, types.SimpleNamespace(config=cfg))
    ha._refresh_managers()
    assert cfg.migration_cooldown == 2400


def test_each_cluster_keeps_its_own_newest_rows(db, monkeypatch):
    monkeypatch.setattr(type(db), 'MIGRATION_HISTORY_KEEP', 5)
    for i in range(8):
        db.add_migration_event('busy', 100 + i, '', 'a', 'b', 'success', trigger='balance')
    for i in range(3):
        db.add_migration_event('quiet', 200 + i, '', 'a', 'b', 'success', trigger='balance')
    assert [r['vmid'] for r in db.list_balancer_moves('busy')] == [107, 106, 105, 104, 103]
    assert len(db.list_balancer_moves('quiet')) == 3


# --- the route -------------------------------------------------------------------------------------

@pytest.fixture
def hist(api, seed):
    seed.db.save_cluster(CID, {'name': 'lab', 'host': '10.0.0.1', 'user': 'root@pam', 'pass': 'pw',
                               'migration_cooldown': 1200})
    m = PegaProxManager(CID, PegaProxConfig(seed.db.get_cluster(CID)))
    api.set_manager(CID, m)
    db = seed.db
    why = balance_reason('balance', 'pve1', 'pve2', {'pve1': {'score': 80}}, threshold=20, tolerance=10)
    db.add_migration_event(CID, 100, 'mine', 'pve1', 'pve2', 'success', reason=why['reason'],
                           trigger='balance', details=why['details'], timestamp=_ago(500))
    rule = balance_reason('affinity', 'pve2', 'pve3', {}, rule='secret pair')
    db.add_migration_event(CID, 200, 'theirs', 'pve2', 'pve3', 'failed', reason=rule['reason'],
                           trigger='affinity', details=rule['details'], timestamp=_ago(400))
    pin = balance_reason('pin', 'pve3', 'pve1', {}, pinned=['pve1'])
    db.add_migration_event(CID, 100, 'mine', 'pve3', 'pve1', 'dry_run', reason=pin['reason'],
                           trigger='pin', details=pin['details'], timestamp=_ago(300))
    # a migration that is no balancer move, and a move of another cluster
    from pegaprox.api.history import log_migration
    log_migration(CID, 100, 'mine', 'qemu', 'pve1', 'pve3', 'manual', 'success', user='root')
    db.add_migration_event('other', 300, 'x', 'a', 'b', 'success', trigger='balance')
    return types.SimpleNamespace(api=api, seed=seed, mgr=m, db=db)


def test_the_history_lists_the_balancer_moves_newest_first(hist):
    c = hist.api.as_user(hist.seed.user('root', role='admin'))
    r = c.get(ROUTE)
    assert r.status_code == 200, r.get_data(as_text=True)
    body = r.get_json()
    assert [(e['trigger'], e['status'], e['vmid']) for e in body['entries']] == \
        [('pin', 'dry_run', 100), ('affinity', 'failed', 200), ('balance', 'success', 100)]
    assert body['cooldown'] == 1200 and body['next_before'] is None
    assert body['entries'][2]['details']['diff'] == 80.0
    assert body['entries'][1]['reason'].startswith("anti-affinity rule 'secret pair'")


@pytest.mark.parametrize('query,expected', [
    ('trigger=affinity', [200]),
    ('trigger=balance,pin', [100, 100]),
    ('status=failed', [200]),
    ('trigger=pin&status=success', []),
])
def test_the_history_filters(hist, query, expected):
    c = hist.api.as_user(hist.seed.user('root', role='admin'))
    r = c.get(f'{ROUTE}?{query}')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert [e['vmid'] for e in r.get_json()['entries']] == expected


def test_the_history_pages_from_a_row_on(hist):
    c = hist.api.as_user(hist.seed.user('root', role='admin'))
    first = c.get(f'{ROUTE}?limit=2').get_json()
    assert [e['trigger'] for e in first['entries']] == ['pin', 'affinity']
    assert first['next_before'] == first['entries'][-1]['id']
    rest = c.get(f"{ROUTE}?limit=2&before={first['next_before']}").get_json()
    assert [e['trigger'] for e in rest['entries']] == ['balance'] and rest['next_before'] is None


@pytest.mark.parametrize('query', ['trigger=manual', 'trigger=balance,bogus', 'status=moved',
                                   'before=abc', 'before=-5', 'before=1e5', 'before=' + '9' * 30])
def test_a_malformed_query_is_a_400(hist, query):
    c = hist.api.as_user(hist.seed.user('root', role='admin'))
    r = c.get(f'{ROUTE}?{query}')
    assert r.status_code == 400, r.get_data(as_text=True)


def test_an_oversized_limit_is_capped(hist):
    for i in range(205):
        hist.db.add_migration_event(CID, 1000 + i, '', 'a', 'b', 'success', trigger='balance')
    c = hist.api.as_user(hist.seed.user('root', role='admin'))
    body = c.get(f'{ROUTE}?limit=100000').get_json()
    assert len(body['entries']) == 200 and body['next_before'] is not None


def test_the_history_wants_a_session(hist):
    assert hist.api.anon().get(ROUTE).status_code == 401


def test_a_viewer_reads_it(hist):
    c = hist.api.as_user(hist.seed.user('vicky', role='viewer'))
    assert len(c.get(ROUTE).get_json()['entries']) == 3


def test_a_user_without_cluster_view_does_not(hist):
    c = hist.api.as_user(hist.seed.user('nora', role='viewer', denied=['cluster.view']))
    assert c.get(ROUTE).status_code == 403


def test_another_tenant_is_refused(hist):
    hist.seed.tenant('acme', clusters=['other'])
    c = hist.api.as_user(hist.seed.user('milton', role='user', tenant_id='acme'))
    assert c.get(ROUTE).status_code == 403


def test_a_confined_admin_is_refused(hist):
    hist.seed.tenant('globex', clusters=['other'])
    c = hist.api.as_user(hist.seed.user('gx', role='admin', tenant_id='globex',
                                        tenant_permissions={'globex': {'role': 'user'}}))
    assert c.get(ROUTE).status_code == 403


def test_a_pool_scoped_caller_sees_their_guests_and_not_why(hist):
    from test_proxlb_pins import _seed_pool_membership
    hist.seed.tenant('acme', clusters=[CID])
    hist.seed.pool(CID, 'pool_1', 'mallory', ['pool.view', 'vm.view'])
    _seed_pool_membership(CID, {100: ('qemu', 'pool_1'), 200: ('qemu', 'pool_2')})
    c = hist.api.as_user(hist.seed.user('mallory', role='viewer', tenant_id='acme'))
    entries = c.get(ROUTE).get_json()['entries']
    assert [e['vmid'] for e in entries] == [100, 100]
    assert all(e['reason'] == '' and e['details'] == {} for e in entries)
    assert 'secret pair' not in str(entries)


@pytest.mark.parametrize('route', ['/api/migration-history?cluster_id=' + CID,
                                   f'/api/clusters/{CID}/vms/100/migration-history'])
def test_the_other_migration_lists_leave_why_to_whoever_sees_the_cluster(hist, route):
    from test_proxlb_pins import _seed_pool_membership
    hist.seed.tenant('acme', clusters=[CID])
    hist.seed.pool(CID, 'pool_1', 'mallory', ['pool.view', 'vm.view'])
    _seed_pool_membership(CID, {100: ('qemu', 'pool_1'), 200: ('qemu', 'pool_2')})
    confined = hist.api.as_user(hist.seed.user('mallory', role='viewer', tenant_id='acme'))
    rows = confined.get(route).get_json()
    assert sorted((r['vmid'], r['trigger'] or '', r['reason']) for r in rows) == \
        [(100, '', 'manual by root'), (100, 'balance', ''), (100, 'pin', '')]
    admin = hist.api.as_user(hist.seed.user('root', role='admin'))
    reasons = {r['trigger']: r['reason'] for r in admin.get(route).get_json()}
    assert reasons['pin'] == 'pinned to pve1 but running on pve3, returned to pve1'
    assert reasons['balance'].startswith('pve1 score 80.0')


def test_an_unknown_cluster_is_a_404(hist):
    c = hist.api.as_user(hist.seed.user('root', role='admin'))
    assert c.get('/api/clusters/nope/balance-history').status_code == 404


def test_a_standby_reads_the_history_from_its_active():
    from pegaprox.core import ha
    assert '/api/clusters/<cluster_id>/balance-history' in ha.LEADER_ONLY_READS


# --- setting the cooldown --------------------------------------------------------------------------

@pytest.fixture
def conf(api, seed):
    seed.db.save_cluster(CID, {'name': 'lab', 'host': '10.0.0.1', 'user': 'root@pam', 'pass': 'pw'})
    m = PegaProxManager(CID, PegaProxConfig(seed.db.get_cluster(CID)))
    api.set_manager(CID, m)
    return types.SimpleNamespace(api=api, seed=seed, mgr=m, db=seed.db)


def test_an_admin_sets_the_cooldown_and_it_is_kept(conf):
    c = conf.api.as_user(conf.seed.user('root', role='admin'))
    r = c.patch(f'/api/clusters/{CID}/config', json={'migration_cooldown': 1800})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['updated_fields'] == ['migration_cooldown']
    assert conf.mgr.config.migration_cooldown == 1800
    assert conf.db.get_cluster(CID)['migration_cooldown'] == 1800
    listed = next(x for x in c.get('/api/clusters').get_json() if x['id'] == CID)
    assert listed['migration_cooldown'] == 1800
    assert c.get(f'/api/clusters/{CID}/config/export').get_json()['migration_cooldown'] == 1800
    assert any('migration_cooldown' in a['details'] for a in _audit('cluster.config_changed'))


@pytest.mark.parametrize('method,url', [('patch', f'/api/clusters/{CID}/config'), ('put', f'/api/clusters/{CID}')])
@pytest.mark.parametrize('value', ['1800', 59, 86401, True, 900.5, None, [900]])
def test_a_cooldown_out_of_range_is_a_400(conf, method, url, value):
    c = conf.api.as_user(conf.seed.user('root', role='admin'))
    r = getattr(c, method)(url, json={'migration_cooldown': value, 'name': 'renamed'})
    assert r.status_code == 400, r.get_data(as_text=True)
    assert conf.mgr.config.migration_cooldown == 900 and conf.mgr.config.name == 'lab'


@pytest.mark.parametrize('who', ['viewer', 'confined-admin', 'other-tenant'])
def test_who_may_not_set_it(conf, who):
    seed = conf.seed
    if who == 'viewer':
        user = seed.user('vicky', role='viewer')
    elif who == 'confined-admin':
        seed.tenant('globex', clusters=['other'])
        user = seed.user('gx', role='admin', tenant_id='globex', tenant_permissions={'globex': {'role': 'user'}})
    else:
        seed.tenant('acme', clusters=['other'])
        user = seed.user('milton', role='user', tenant_id='acme', permissions=['cluster.config'])
    r = conf.api.as_user(user).patch(f'/api/clusters/{CID}/config', json={'migration_cooldown': 1800})
    assert r.status_code == 403, r.get_data(as_text=True)
    assert conf.mgr.config.migration_cooldown == 900


def test_a_pool_scoped_operator_may_not_set_it(conf):
    conf.seed.tenant('acme', clusters=[CID])
    conf.seed.pool(CID, 'pool_1', 'mallory', ['pool.view', 'vm.view', 'cluster.config'])
    user = conf.seed.user('mallory', role='user', tenant_id='acme', permissions=['cluster.config'])
    r = conf.api.as_user(user).patch(f'/api/clusters/{CID}/config', json={'migration_cooldown': 1800})
    assert r.status_code == 403
    assert conf.mgr.config.migration_cooldown == 900


def test_a_standby_sets_no_cooldown(ha_env, seed):  # noqa: F811
    api = ha_env.api
    seed.db.save_cluster(CID, {'name': 'lab', 'host': '10.0.0.1', 'user': 'root@pam', 'pass': 'pw'})
    m = PegaProxManager(CID, PegaProxConfig(seed.db.get_cluster(CID)))
    api.set_manager(CID, m)
    c = api.as_user(seed.user('root', role='admin'))
    _standby_of_active(ha_env)
    r = c.patch(f'/api/clusters/{CID}/config', json={'migration_cooldown': 1800})
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY'
    assert m.config.migration_cooldown == 900
    # reading is no write: the history answers from here while nothing is forwarded
    assert c.get(ROUTE).status_code == 200


@pytest.fixture
def no_connect(monkeypatch):
    monkeypatch.setattr(PegaProxManager, 'connect_to_proxmox', lambda self: True)
    monkeypatch.setattr(PegaProxManager, 'start', lambda self: None)
    monkeypatch.setattr(PegaProxManager, 'stop', lambda self: None)


def test_re_configure_keeps_the_cooldown(conf, no_connect):
    from pegaprox.globals import cluster_managers
    from test_ha_api import ADMIN_PW
    conf.mgr.config.migration_cooldown = 3600
    c = _admin(conf.api, conf.seed)
    dialog = {'current_password': ADMIN_PW, 'name': 'lab', 'host': '10.0.0.1', 'user': 'root@pam',
              'pass': 'new-pw'}
    r = c.post(f'/api/clusters/{CID}/reconfigure', json=dialog)
    assert r.status_code == 200, r.get_data(as_text=True)
    assert cluster_managers[CID].config.migration_cooldown == 3600
    r = c.post(f'/api/clusters/{CID}/reconfigure', json=dict(dialog, migration_cooldown=10))
    assert r.status_code == 400


def test_a_new_cluster_takes_a_cooldown_and_refuses_a_bad_one(conf, no_connect):
    from pegaprox.globals import cluster_managers
    c = conf.api.as_user(conf.seed.user('root', role='admin'))
    body = {'name': 'new', 'host': '10.9.5.1', 'user': 'root@pam', 'pass': 'pw'}
    assert c.post('/api/clusters', json=dict(body, migration_cooldown='soon')).status_code == 400
    r = c.post('/api/clusters', json=dict(body, migration_cooldown=600))
    assert r.status_code == 201, r.get_data(as_text=True)
    assert cluster_managers[r.get_json()['id']].config.migration_cooldown == 600
