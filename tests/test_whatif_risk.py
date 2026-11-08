"""The risk view of the what-if simulator (pegaprox/core/whatif.py, pegaprox/api/whatif.py):
critical guests, a PBS storage failing, tenants and restore status per affected guest, and the
ranking of the single points of failure.

Same harness as tests/test_whatif.py: a real manager with its PVE reads answered from a dict,
the routes driven through the real app.
MK Oct 2026
"""
import time
import types

import pytest

from pegaprox.core import recovery, whatif
from test_ha_api import ha_env, _standby_of_active  # noqa: F401
from test_whatif import (CID, NETS, NODES, STORAGES, THR, _cfg, _cluster, _limit, _manager, _rows, _vm)

NOW = time.time()
T_PBS = int(NOW - 3600)          # the restore point the restore test of 100 used
URL = f'/api/clusters/{CID}/whatif'
RANK = URL + '/ranking'


def _bk(vmid, volid, ctime, storage):
    return {'vmid': vmid, 'volid': volid, 'ctime': ctime, 'subtype': 'qemu', 'size': 1000,
            'storage': storage}


def _pve(guests=None, configs=None, tags=None, jobs=None, pbs_points=None, nfs_points=None, ha=None):
    """A cluster with a PBS storage 'pbs1' and an NFS backup storage 'nfs1'."""
    guests = guests or [_vm(100, 'pve1'), _vm(101, 'pve1'), _vm(102, 'pve2'), _vm(103, 'pve2'),
                        _vm(104, 'pve3', status='stopped')]
    for vm in guests:
        if tags and vm['vmid'] in tags:
            vm['tags'] = tags[vm['vmid']]
    configs = configs or {v['vmid']: _cfg() for v in guests}
    api = _cluster(guests, configs, ha=ha if ha is not None else [('vm:100', 'started')], extra=NETS)
    api['/storage'] = STORAGES + [{'storage': 'pbs1', 'type': 'pbs', 'content': 'backup'},
                                  {'storage': 'nfs1', 'type': 'nfs', 'content': 'backup'}]
    api['/nodes'] = [{'node': n, 'status': 'online'} for n in NODES]
    api[('/cluster/resources', 'storage')] = api[('/cluster/resources', 'storage')] + [
        {'node': n, 'storage': s, 'status': 'available', 'shared': 1} for n in NODES for s in ('pbs1', 'nfs1')]
    if jobs is not None:
        api['/cluster/backup'] = jobs
    api[('/nodes/pve1/storage/pbs1/content', 'backup')] = pbs_points if pbs_points is not None else [
        _bk(100, 'pbs1:backup/vm/100/%s' % time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(T_PBS)), T_PBS, 'pbs1'),
        _bk(101, 'pbs1:backup/vm/101/2026-10-10T01:00:00Z', T_PBS - 100, 'pbs1'),
    ]
    api[('/nodes/pve1/storage/backups/content', 'backup')] = []
    api[('/nodes/pve1/storage/nfs1/content', 'backup')] = nfs_points if nfs_points is not None else [
        _bk(101, 'nfs1:backup/vzdump-qemu-101-2026_10_10-01_00_00.vma.zst', T_PBS - 50, 'nfs1'),
    ]
    return guests, api


@pytest.fixture(autouse=True)
def _forget():
    recovery.forget_backups()
    yield
    recovery.forget_backups()


@pytest.fixture
def env(api, seed):
    guests, pve = _pve(tags={100: 'critical;web', 101: 'db'},
                       jobs=[{'id': 'job-a', 'storage': 'pbs1', 'all': 1, 'exclude': '103', 'schedule': '01:00'},
                             {'id': 'job-b', 'storage': 'nfs1', 'vmid': '103', 'schedule': '02:00'},
                             {'id': 'job-off', 'storage': 'pbs1', 'vmid': '103', 'enabled': 0}])
    m = api.set_manager(CID, _manager(pve, guests))
    return types.SimpleNamespace(api=api, seed=seed, mgr=m, guests=guests, pve=pve)


def _mark_passed(vmid=100, backup_ts=T_PBS):
    recovery.note_result({'cluster_id': CID, 'vmid': vmid, 'status': 'passed', 'id': f'ok{vmid}',
                          'backup_ts': backup_ts, 'measured_seconds': 60.0, 'checks': []}, at=NOW - 3600)


def _pbs(env, **body):
    return whatif.run(env.mgr, whatif.parse_scenario(dict({'type': 'pbs_failure', 'storage': 'pbs1'}, **body)),
                      dict(THR))


# --- the PBS scenario ------------------------------------------------------------------------------

def test_a_pbs_failure_names_the_guests_that_lose_restore_points(env):
    _mark_passed(100)
    r = _pbs(env)
    rows = _rows(r)
    assert rows[100]['reason']['code'] == 'pbs_only_copy' and rows[100]['basis'] == 'known'
    assert rows[101]['reason']['code'] == 'pbs_some_copy'
    assert rows[101]['reason']['args'] == {'storage': 'pbs1', 'count': 1, 'total': 2}
    # selected by the job, no restore point listed there
    assert rows[102]['reason']['code'] == 'pbs_job_only' and rows[104]['reason']['code'] == 'pbs_job_only'
    # excluded by the job, and the disabled job does not count
    assert 103 not in rows
    pbs = r['pbs']
    assert [j['id'] for j in pbs['jobs']] == ['job-a'] and pbs['jobs'][0]['guests'] == 4
    assert (pbs['guests_all_lost'], pbs['guests_some_lost'], pbs['guests_job_only']) == (1, 1, 2)
    assert pbs['tests_lost'] == 1 and rows[100]['restore_test_lost'] is True
    # read in full and active: nothing to say about the storage itself
    assert pbs['points_read'] is True and pbs['active'] is True and pbs['active_on'] == list(NODES)
    assert _limit(r, 'pbs_inactive') is None and _limit(r, 'pbs_points_unread') is None
    assert _limit(r, 'pbs_tests_lost')['guests'] == [100]
    assert _limit(r, 'pbs_only_copy')['guests'] == [100]
    assert {a['code'] for a in r['assumptions']} >= {'pbs_listing', 'pbs_jobs', 'critical_tags'}


def test_a_restore_test_on_a_copy_that_is_also_elsewhere_does_not_depend_on_it(env):
    _mark_passed(101, backup_ts=T_PBS - 50)      # the NFS copy
    r = _pbs(env)
    assert r['pbs']['tests_lost'] == 0 and 'restore_test_lost' not in _rows(r)[101]


def test_a_test_older_than_the_listing_is_counted_apart(env):
    _mark_passed(100, backup_ts=T_PBS - 99999)
    r = _pbs(env)
    assert r['pbs']['tests_lost'] == 0 and r['pbs']['tests_unmatched'] == 1


def test_stopped_guests_of_a_pbs_failure_are_counted_apart_with_their_own_statement(env):
    r = _pbs(env)
    assert r['summary']['stopped'] == 1 and r['summary']['guests'] == 5
    a = next(x for x in r['assumptions'] if x['code'] == 'stopped_backups')
    assert a['args'] == {'count': 1} and a['text'].startswith('Stopped guests (1) count as affected only where')
    # 104 is stopped and tied to the storage by the job: listed, not counted as unaffected
    assert _rows(r)[104]['reason']['code'] == 'pbs_job_only'
    assert not any(x['code'] == 'stopped_guests' for x in r['assumptions'])


def test_only_a_pbs_storage_can_fail_this_way(env):
    for name, code in (('nfs1', 'not_pbs'), ('nope', 'unknown_storage'), ('ceph', 'not_pbs')):
        with pytest.raises(whatif.Invalid) as e:
            _pbs(env, storage=name)
        assert e.value.code == code


def test_unread_restore_points_fall_back_on_the_jobs_and_say_so(env, monkeypatch):
    monkeypatch.setattr(recovery, 'guest_backups', lambda *a, **k: None)
    r = _pbs(env)
    assert _limit(r, 'pbs_points_unread') is not None
    rows = _rows(r)
    assert {v: rows[v]['reason']['code'] for v in rows} == {100: 'pbs_job_only', 101: 'pbs_job_only',
                                                            102: 'pbs_job_only', 104: 'pbs_job_only'}
    assert all(row['basis'] == 'assumed' for row in rows.values())
    assert r['pbs']['points_read'] is False


def test_nothing_read_is_unreadable_not_empty(env, monkeypatch):
    monkeypatch.setattr(recovery, 'guest_backups', lambda *a, **k: None)
    env.pve['/cluster/backup'] = types.SimpleNamespace(status_code=500, json=lambda: {}, text='')
    whatif._cache(env.mgr).clear()
    with pytest.raises(whatif.Unreadable):
        _pbs(env)


def test_jobs_unread_leave_the_listed_restore_points(env):
    env.pve['/cluster/backup'] = types.SimpleNamespace(status_code=500, json=lambda: {}, text='')
    r = _pbs(env)
    assert _limit(r, 'pbs_jobs_unread') is not None
    assert sorted(_rows(r)) == [100, 101] and r['pbs']['jobs_read'] is False


def _unreadable():
    return types.SimpleNamespace(status_code=500, json=lambda: {}, text='')


def test_an_offline_pbs_storage_is_not_reported_as_read_and_is_said_to_be_inactive(env):
    # PVE lists it as not available and its content cannot be read
    env.pve[('/cluster/resources', 'storage')] = [x for x in env.pve[('/cluster/resources', 'storage')]
                                                  if x['storage'] != 'pbs1']
    env.pve[('/nodes/pve1/storage/pbs1/content', 'backup')] = _unreadable()
    whatif._cache(env.mgr).clear()
    recovery.forget_backups()
    r = _pbs(env)
    assert r['pbs']['points_read'] is False
    assert r['pbs']['active'] is False and r['pbs']['active_on'] == []
    assert r['limits'][0]['code'] == 'pbs_points_unread'
    inactive = _limit(r, 'pbs_inactive')
    assert inactive['basis'] == 'known' and inactive['args'] == {'storage': 'pbs1'}
    assert inactive['text'].startswith('pbs1 is not active on any node') and 'listed' in inactive['text']
    # the other backup storage was listed, the jobs stand in for this one and say they are assumed
    assert recovery.guest_backups(CID, env.mgr)['listed'] == ['backups', 'nfs1']
    assert {row['reason']['code'] for row in _rows(r).values()} == {'pbs_job_only'}
    assert {row['basis'] for row in _rows(r).values()} == {'assumed'}


def test_another_storage_failing_to_list_does_not_unread_this_one(env):
    env.pve[('/nodes/pve1/storage/nfs1/content', 'backup')] = _unreadable()
    whatif._cache(env.mgr).clear()
    recovery.forget_backups()
    r = _pbs(env)
    assert r['pbs']['points_read'] is True and r['pbs']['active'] is True
    assert _limit(r, 'pbs_points_unread') is not None and _limit(r, 'pbs_inactive') is None
    assert _rows(r)[100]['reason']['code'] == 'pbs_only_copy' and _rows(r)[100]['basis'] == 'known'


def test_nothing_is_claimed_about_a_storage_whose_state_cannot_be_read(env):
    env.pve[('/cluster/resources', 'storage')] = _unreadable()
    whatif._cache(env.mgr).clear()
    r = _pbs(env)
    assert r['pbs']['active'] is None and _limit(r, 'pbs_inactive') is None


def test_a_job_selecting_a_pool_covers_its_guests(env):
    env.pve['/cluster/backup'] = [{'id': 'p', 'storage': 'pbs1', 'pool': 'gold'}]
    whatif._cache(env.mgr).clear()
    vms = env.mgr.get_vm_resources()
    vms[2]['pool'] = 'gold'
    r = _pbs(env)
    assert _rows(r)[102]['reason']['code'] == 'pbs_job_only' and 103 not in _rows(r)


# --- critical guests, tenants, restore status ----------------------------------------------------

def test_a_report_marks_the_critical_guests_and_counts_them(env):
    r = whatif.run(env.mgr, whatif.parse_scenario({'type': 'node_failure', 'nodes': ['pve1']}), dict(THR))
    rows = _rows(r)
    assert rows[100]['critical'] is True and rows[101]['critical'] is False
    assert rows[100]['tags'] == ['critical', 'web']
    risk = r['risk']
    assert risk['critical'] == {'tags': ['critical'], 'source': 'default', 'tags_basis': 'known',
                                'in_cluster': 1, 'affected': 1, 'down': 0, 'basis': 'calculated'}
    assert risk['weight']['critical_factor'] == whatif.CRITICAL_FACTOR
    assert risk['weight']['value'] == 0.25 * 3 + 1.0


def test_the_critical_tags_come_from_the_request_the_recovery_settings_or_the_default(env, monkeypatch):
    body = {'type': 'node_failure', 'nodes': ['pve1']}
    r = whatif.run(env.mgr, whatif.parse_scenario(dict(body, critical_tags=['DB'])), dict(THR))
    assert r['risk']['critical']['source'] == 'request' and _rows(r)[101]['critical'] is True
    assert _rows(r)[100]['critical'] is False
    r = whatif.run(env.mgr, whatif.parse_scenario(dict(body, critical_tags=[])), dict(THR))
    assert r['risk']['critical']['affected'] == 0

    # the recovery settings fill in the default tag; that is no choice of an admin
    r = whatif.run(env.mgr, whatif.parse_scenario(body), dict(THR))
    assert r['risk']['critical']['source'] == 'default'
    recovery.save_rule(CID, 'cluster', None, {'critical_tags': ['web']}, 'admin')
    r = whatif.run(env.mgr, whatif.parse_scenario(body), dict(THR))
    assert r['risk']['critical']['source'] == 'recovery' and _rows(r)[100]['critical'] is True


def test_the_restore_status_is_proven_only_by_a_passed_test(env):
    _mark_passed(100)
    recovery.note_result({'cluster_id': CID, 'vmid': 101, 'status': 'failed', 'id': 'f', 'restore_ok': False},
                         at=NOW - 60)
    r = whatif.run(env.mgr, whatif.parse_scenario({'type': 'node_failure', 'nodes': ['pve1']}), dict(THR))
    rows = _rows(r)
    assert rows[100]['restore']['state'] == 'proven' and rows[100]['restore']['basis'] == 'known'
    assert rows[101]['restore']['state'] == 'failing'
    assert r['risk']['restore'] == {'proven': 1, 'not_proven': 0, 'failing': 1, 'unknown': 0, 'basis': 'known'}
    # nothing recorded is not a pass
    r = _pbs(env)
    assert _rows(r)[102]['restore']['state'] == 'not_proven'


def test_unreadable_marks_are_unknown_never_proven(env, monkeypatch):
    monkeypatch.setattr(whatif, '_marks', lambda cid: None)
    r = whatif.run(env.mgr, whatif.parse_scenario({'type': 'node_failure', 'nodes': ['pve1']}), dict(THR))
    assert {g['restore']['state'] for g in r['guests']} == {'unknown'}
    assert all(g['restore']['basis'] == 'assumed' for g in r['guests'])
    assert r['risk']['restore']['proven'] == 0


def test_tenants_are_summarised_and_labelled_assumed(env, monkeypatch):
    monkeypatch.setattr(whatif, '_tenants', lambda cid: [{'id': 'acme', 'name': 'Acme'}])
    r = whatif.run(env.mgr, whatif.parse_scenario({'type': 'node_failure', 'nodes': ['pve1']}), dict(THR))
    assert all(g['tenants'] == ['acme'] for g in r['guests'])
    assert r['risk']['tenants'] == {'items': [{'id': 'acme', 'name': 'Acme', 'affected': 2, 'down': 1, 'critical': 1}],
                                    'readable': True, 'basis': 'assumed'}
    assert 'tenant_by_cluster' in {a['code'] for a in r['assumptions']}
    monkeypatch.setattr(whatif, '_tenants', lambda cid: None)
    r = whatif.run(env.mgr, whatif.parse_scenario({'type': 'node_failure', 'nodes': ['pve1']}), dict(THR))
    assert r['risk']['tenants']['readable'] is False and r['risk']['tenants']['items'] == []


def test_a_broken_risk_view_leaves_the_report(env, monkeypatch):
    monkeypatch.setattr(whatif, 'risk_view', lambda *a: 1 / 0)
    r = whatif.run(env.mgr, whatif.parse_scenario({'type': 'node_failure', 'nodes': ['pve1']}), dict(THR))
    assert r['risk'] is None and len(r['guests']) == 2


@pytest.mark.parametrize('body,code', [
    ({'type': 'node_failure', 'nodes': ['pve1'], 'critical_tags': 'critical'}, 'bad_tags'),
    ({'type': 'node_failure', 'nodes': ['pve1'], 'critical_tags': [1]}, 'bad_tags'),
    ({'type': 'node_failure', 'nodes': ['pve1'], 'critical_tags': ['a b']}, 'bad_tags'),
    ({'type': 'node_failure', 'nodes': ['pve1'], 'critical_tags': ['t%d' % i for i in range(21)]}, 'bad_tags'),
    ({'type': 'pbs_failure'}, 'bad_name'),
])
def test_malformed_risk_input_is_refused(body, code):
    with pytest.raises(whatif.Invalid) as e:
        whatif.parse_scenario(body)
    assert e.value.code == code


# --- the ranking ------------------------------------------------------------------------------------

def _rank_env(api, seed):
    guests = [_vm(100, 'pve1'), _vm(101, 'pve1'), _vm(102, 'pve2')]
    guests[1]['tags'] = 'critical'
    configs = {100: _cfg(), 101: _cfg(), 102: _cfg(bridge='vmbr1')}
    pve = _cluster(guests, configs, ha=[('vm:100', 'started')], extra=NETS)
    pve['/storage'] = STORAGES + [{'storage': 'pbs1', 'type': 'pbs', 'content': 'backup'}]
    pve['/nodes'] = [{'node': n, 'status': 'online'} for n in NODES]
    pve['/cluster/backup'] = [{'id': 'j', 'storage': 'pbs1', 'vmid': '102'}]
    pve[('/nodes/pve1/storage/pbs1/content', 'backup')] = []
    pve[('/nodes/pve1/storage/ceph/content', 'images')] = [{'vmid': 100}, {'vmid': 101}, {'vmid': 102}]
    pve[('/nodes/pve1/storage/ceph/content', 'rootdir')] = []
    m = api.set_manager(CID, _manager(pve, guests))
    return types.SimpleNamespace(api=api, seed=seed, mgr=m, pve=pve, guests=guests)


@pytest.fixture
def rank_env(api, seed):
    return _rank_env(api, seed)


def test_the_ranking_orders_by_weight_with_critical_guests_counted_up(rank_env):
    out = whatif.ranking(rank_env.mgr, dict(THR))
    by = {(r['kind'], r['name']): r for r in out['ranking']}
    assert [(r['kind'], r['name']) for r in out['ranking']][:3] == [
        ('storage', 'ceph'), ('bridge', 'vmbr0'), ('node', 'pve1')]
    assert by[('storage', 'ceph')]['weight'] == 5.0 and by[('storage', 'ceph')]['critical_affected'] == 1
    assert by[('bridge', 'vmbr0')]['weight'] == 4.0
    # pve1: 100 is restarted by HA (0.25), 101 is critical and stays down (3)
    assert by[('node', 'pve1')]['weight'] == 3.25 and by[('node', 'pve1')]['critical_down'] == 1
    assert by[('node', 'pve1')]['restarted'] == 1 and by[('node', 'pve1')]['down'] == 1
    assert by[('node', 'pve3')]['weight'] == 0.0 and by[('node', 'pve3')]['affected'] == 0
    # the PBS storage holds only a job for 102, no restore point
    assert by[('pbs', 'pbs1')]['affected'] == 1 and by[('pbs', 'pbs1')]['weight'] == 0.5
    assert all(r['basis'] == 'calculated' for r in out['ranking'])
    assert out['weighting']['critical_factor'] == 3 and out['weighting']['outcomes']['down'] == 1.0
    assert out['guests'] == {'total': 3, 'running': 3, 'stopped': 0, 'critical': 1, 'basis': 'known'}
    assert {a['code'] for a in out['assumptions']} >= {'rank_weighting', 'rank_cheap', 'critical_tags'}
    # no time limit hit: no key for it either
    assert out['capped'] == [] and out['skipped'] == [] and 'stopped' not in out


def test_the_ranking_ranks_shared_storages_only_and_says_so(rank_env):
    out = whatif.ranking(rank_env.mgr, dict(THR))
    # local-lvm is a storage of its guests' nodes: it fails with them, the node rows cover it
    assert [r['name'] for r in out['ranking'] if r['kind'] == 'storage'] == ['ceph']
    note = next(a for a in out['assumptions'] if a['code'] == 'rank_shared_only')
    assert note['text'] == ('Only shared storages are ranked: a local storage fails with its node, '
                            'which the node rows cover')


def test_the_ranking_says_where_stopped_guests_stand(rank_env):
    out = whatif.ranking(rank_env.mgr, dict(THR))
    assert not any(a['code'] == 'rank_stopped' for a in out['assumptions'])
    for g in rank_env.guests:
        g['status'] = 'stopped'
    whatif._cache(rank_env.mgr).clear()
    out = whatif.ranking(rank_env.mgr, dict(THR))
    assert out['guests'] == {'total': 3, 'running': 0, 'stopped': 3, 'critical': 1, 'basis': 'known'}
    note = next(a for a in out['assumptions'] if a['code'] == 'rank_stopped')
    assert note['args'] == {'count': 3} and 'not counted as affected' in note['text']
    # the weights are what they are: nothing running is affected
    assert {r['weight'] for r in out['ranking'] if r['kind'] != 'pbs'} == {0.0}


def test_the_critical_tags_of_the_ranking_are_a_list_like_those_of_a_report(rank_env):
    out = whatif.ranking(rank_env.mgr, dict(THR))
    r = whatif.run(rank_env.mgr, whatif.parse_scenario({'type': 'node_failure', 'nodes': ['pve1']}), dict(THR))
    assert out['critical_tags'] == ['critical'] and out['critical_tags'] == r['risk']['critical']['tags']
    assert isinstance(out['critical_tags'], list)


def test_the_ranking_takes_its_critical_tags_from_the_request(rank_env):
    out = whatif.ranking(rank_env.mgr, dict(THR), critical_tags=[])
    assert out['critical_tags'] == [] and out['critical_tags_source'] == 'request'
    assert {(r['kind'], r['name']): r['weight'] for r in out['ranking']}[('node', 'pve1')] == 1.25


def test_the_ranking_caps_its_candidates_and_says_so(rank_env, monkeypatch):
    monkeypatch.setattr(whatif, 'RANK_CAPS', {'node': 2, 'storage': 30, 'pbs': 10, 'bridge': 1})
    out = whatif.ranking(rank_env.mgr, dict(THR))
    assert out['capped'] == [{'kind': 'node', 'cap': 2, 'total': 3}, {'kind': 'bridge', 'cap': 1, 'total': 2}]
    assert out['considered'] == 3 + 1 + 2 + 2 and len(out['ranking']) == 2 + 1 + 2 + 1
    # the nodes with most running guests come first into the cap
    assert {r['name'] for r in out['ranking'] if r['kind'] == 'node'} == {'pve1', 'pve2'}


def test_the_ranking_stops_at_its_time_limit_and_counts_what_is_left(rank_env, monkeypatch):
    monkeypatch.setattr(whatif, 'RANK_SECONDS', -1)
    out = whatif.ranking(rank_env.mgr, dict(THR))
    assert out['ranking'] == [] and out['stopped'] == {'ranked': 0, 'left': out['considered']}
    assert out['guests']['stopped'] == 0     # the guests that are stopped, not the run


def test_the_ranking_reads_guest_configs_up_to_its_budget_only(rank_env, monkeypatch):
    whatif._cache(rank_env.mgr).clear()
    monkeypatch.setattr(whatif, 'RANK_CONFIG_READS', 1)
    out = whatif.ranking(rank_env.mgr, dict(THR))
    reads = [c for c in rank_env.mgr.calls if c.endswith('/config')]
    assert len(reads) <= 1 and out['config_reads'] <= 1
    assert out['configs_unread'] > 0
    # a guest whose config was not read is unknown, not unaffected
    assert any(r['unknown'] for r in out['ranking'])


def test_a_candidate_that_cannot_run_is_listed_not_ranked(rank_env, monkeypatch):
    real = whatif._SCENARIO_FN['network_failure']

    def boom(run):
        raise whatif.Invalid('gone', 'unknown_bridge')
    monkeypatch.setitem(whatif._SCENARIO_FN, 'network_failure', boom)
    out = whatif.ranking(rank_env.mgr, dict(THR))
    assert [(s['kind'], s['code']) for s in out['skipped']] == [('bridge', 'unknown_bridge')] * 2
    assert not any(r['kind'] == 'bridge' for r in out['ranking'])
    assert real is not boom


def test_ranking_input_is_checked():
    assert whatif.parse_ranking(None) == {}
    assert whatif.parse_ranking({'critical_tags': ['Prod'], 'thresholds': {'cpu': 70}}) == {
        'critical_tags': ['prod'], 'thresholds': {'cpu': 70.0}}
    for bad in ([], 'x', {'critical_tags': 'a'}, {'thresholds': {'disk': 1}}, {'thresholds': {'cpu': 500}}):
        with pytest.raises(whatif.Invalid):
            whatif.parse_ranking(bad)


# --- routes ------------------------------------------------------------------------------------------

def test_options_offer_the_pbs_storages_and_the_critical_tags(env):
    c = env.api.as_user(env.seed.user('root', role='admin'))
    d = c.get(URL + '/options').get_json()
    assert [p['storage'] for p in d['pbs']] == ['backups', 'pbs1']
    assert d['critical_tags'] == {'tags': ['critical'], 'source': 'default'}


def test_an_admin_runs_the_pbs_scenario_and_the_ranking(env):
    c = env.api.as_user(env.seed.user('root', role='admin'))
    r = c.post(URL, json={'type': 'pbs_failure', 'storage': 'pbs1'})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['pbs']['guests_all_lost'] == 1
    r = c.post(RANK, json={'critical_tags': ['db']})
    assert r.status_code == 200, r.get_data(as_text=True)
    d = r.get_json()
    assert d['critical_tags'] == ['db'] and d['ranking'][0]['weight'] >= d['ranking'][-1]['weight']
    assert c.post(RANK).status_code == 200      # no body is the defaults


@pytest.mark.parametrize('body', ['not json', {'critical_tags': 'x'}, {'thresholds': {'cpu': 0}}, [1]])
def test_a_malformed_ranking_body_is_a_400(env, body):
    c = env.api.as_user(env.seed.user('root', role='admin'))
    r = c.post(RANK, data=body, content_type='application/json') if isinstance(body, str) else c.post(RANK, json=body)
    assert r.status_code == 400, r.get_data(as_text=True)


def test_a_malformed_pbs_body_is_a_400(env):
    c = env.api.as_user(env.seed.user('root', role='admin'))
    assert c.post(URL, json={'type': 'pbs_failure', 'storage': 'nfs1'}).get_json()['code'] == 'not_pbs'
    assert c.post(URL, json={'type': 'pbs_failure'}).status_code == 400


@pytest.mark.parametrize('who', ['no-cluster-view', 'confined-admin', 'other-tenant', 'pool-scoped'])
def test_who_may_not_rank(env, who):
    seed = env.seed
    if who == 'no-cluster-view':
        user = seed.user('nora', role='viewer', denied=['cluster.view'])
    elif who == 'confined-admin':
        seed.tenant('globex', clusters=['other'])
        user = seed.user('gx', role='admin', tenant_id='globex', tenant_permissions={'globex': {'role': 'user'}})
    elif who == 'other-tenant':
        seed.tenant('acme', clusters=['other'])
        user = seed.user('milton', role='user', tenant_id='acme')
    else:
        # reaches the cluster through a pool: a whole-cluster view is not for it
        from test_audit_bola_high_2026_09 import _seed_pool_membership
        seed.tenant('acme', clusters=[CID])
        seed.pool(CID, 'pool_1', 'mallory', ['pool.view', 'vm.view'])
        _seed_pool_membership(CID, {101: ('qemu', 'pool_1')})
        user = seed.user('mallory', role='viewer', tenant_id='acme')
    assert env.api.as_user(user).post(RANK, json={}).status_code == 403


def test_a_viewer_ranks(env):
    assert env.api.as_user(env.seed.user('vicky', role='viewer')).post(RANK, json={}).status_code == 200


def test_the_ranking_of_an_xcpng_pool_and_a_disconnected_cluster(env):
    c = env.api.as_user(env.seed.user('root', role='admin'))
    env.mgr.cluster_type = 'xcpng'
    assert c.post(RANK, json={}).get_json() == {'supported': False}
    env.mgr.cluster_type = 'proxmox'
    env.mgr.is_connected = False
    assert c.post(RANK, json={}).status_code == 503


def test_tenants_are_shown_by_name_to_an_admin_and_only_the_own_to_a_tenant_user(env):
    seed = env.seed
    seed.tenant('acme', clusters=[CID])
    seed.tenant('globex', clusters=[CID])
    body = {'type': 'node_failure', 'nodes': ['pve1']}
    admin = env.api.as_user(seed.user('root', role='admin')).post(URL, json=body).get_json()
    ids = {t['id'] for t in admin['risk']['tenants']['items']}
    assert {'acme', 'globex'} <= ids
    assert all({'acme', 'globex'} <= set(g['tenants']) for g in admin['guests'])
    own = env.api.as_user(seed.user('milton', role='user', tenant_id='acme')).post(URL, json=body).get_json()
    assert [t['id'] for t in own['risk']['tenants']['items']] == ['acme']
    assert all(g['tenants'] == ['acme'] for g in own['guests'])
    assert 'globex' not in str(own)


def test_a_pool_scoped_caller_gets_no_tenants_and_only_its_guests(env):
    from test_audit_bola_high_2026_09 import _seed_pool_membership
    seed = env.seed
    seed.tenant('acme', clusters=[CID])
    seed.pool(CID, 'pool_1', 'mallory', ['pool.view', 'vm.view'])
    _seed_pool_membership(CID, {101: ('qemu', 'pool_1')})
    c = env.api.as_user(seed.user('mallory', role='viewer', tenant_id='acme'))
    d = c.post(URL, json={'type': 'node_failure', 'nodes': ['pve1']}).get_json()
    assert [g['vmid'] for g in d['guests']] == [101]
    assert d['guests'][0]['tenants'] == [] and d['risk']['tenants']['items'] == []
    assert d['risk']['critical']['affected'] == 1      # counts stay whole, the name of 100 does not
    assert 'guest100' not in str(d)


def test_a_standby_ranks_from_its_own_view(ha_env, seed):  # noqa: F811
    guests, pve = _pve()
    ha_env.api.set_manager(CID, _manager(pve, guests))
    c = ha_env.api.as_user(seed.user('root', role='admin'))
    _standby_of_active(ha_env)
    r = c.post(RANK, json={})
    assert r.status_code == 200, r.get_data(as_text=True)


def test_the_ranking_route_is_in_the_api_reference():
    import json
    import os
    spec = json.load(open(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'docs', 'openapi.json')))
    assert '/api/clusters/{cluster_id}/whatif/ranking' in spec['paths']
