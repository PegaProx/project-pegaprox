"""Two more event alerts: Ceph OSDs that stay slow, and PegaProx's own replication jobs
past their RPO.

ceph_osd_latency reads /nodes/<n>/ceph/osd - the CRUSH tree with the apply and commit
latency of every OSD - through one node with Ceph, at most once a minute per cluster,
whoever asks (the Prometheus exporter shares the read). An OSD is reported once it was
above the limit in three reads in a row, so one slow minute does not page, and cleared
once a read has it at or below the limit.

replication_rpo watches the jobs of cross_cluster_replications, the ones the recovery
plans link included, from the database only: the last successful run (last_ok_at) older
than the rule's minutes, or twice the job's interval when it says 0. A job that never
went through counts from its creation; a disabled one, or one held while its guest is
failed over, closes.

Driven tick by tick against the fake cluster of test_alert_events.py; the rule fields,
the mutes and who may see and set them through the real app.
MK Oct 2026
"""
import types
from datetime import datetime

import pytest

from pegaprox.background import alert_events as E
from pegaprox.globals import cluster_managers

from test_alert_events import (NOW, _Cluster, _closed, _mute, _open, _rule, _rules, _store, _who,  # noqa: F401
                               cluster, sent)
from test_ha_api import ha_env, _standby_of_active  # noqa: F401
from test_ha_loop_gates import _drive, role  # noqa: F401

OSD_PATH = '/nodes/{}/ceph/osd'


@pytest.fixture(autouse=True)
def _state(monkeypatch):
    for name in ('_osd', '_osd_locks', '_own_repl', '_ceph'):
        monkeypatch.setattr(E, name, {})


def _osd(oid, host, apply=2, commit=None, missing=False):
    o = {'id': oid, 'name': f'osd.{oid}', 'type': 'osd', 'host': host, 'status': 'up', 'in': 1,
         'device_class': 'ssd', 'crush_weight': 0.87}
    if not missing:
        o['apply_latency_ms'] = apply
        o['commit_latency_ms'] = apply if commit is None else commit
    return o


def _tree(*osds):
    """What Proxmox VE answers: the CRUSH tree, OSDs as the leaves of their host bucket."""
    hosts = {}
    for o in osds:
        hosts.setdefault(o['host'], []).append(o)
    buckets = [{'id': -2 - i, 'name': h, 'type': 'host', 'children': kids}
               for i, (h, kids) in enumerate(hosts.items())]
    return {'root': {'leaf': 0, 'children': [{'id': -1, 'name': 'default', 'type': 'root',
                                              'children': buckets}]},
            'flags': 'sortbitwise,recovery_deletes'}


def _osds(cluster, *osds, node='pve1', code=200):
    cluster.answer(OSD_PATH.format(node), _tree(*osds) if code == 200 else None, code=code)


def _ticks(start, n):
    return [start + 60 * i for i in range(n)]


# --- slow OSDs ---------------------------------------------------------------------------

def test_an_osd_slow_for_three_reads_alerts_once_on_every_path_and_resolves(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('ceph_osd_latency'))
    _osds(cluster, _osd(0, 'pve1'), _osd(3, 'pve2', apply=250, commit=310))

    E.check_event_alerts(NOW)
    E.check_event_alerts(NOW + 60)
    assert sent.push == [] and _open(db) == []          # two reads are not three
    E.check_event_alerts(NOW + 120)

    assert sent.names() == ['osd.3 on pve2 is slow']
    (hook, ids), = sent.hooks
    assert ids == ['hook1'] and hook['event'] == 'firing' and hook['metric'] == 'ceph_osd_latency'
    assert hook['current_value'] == '310 ms'
    assert 'osd.3 on node pve2: apply latency 250 ms, commit latency 310 ms, above 100 ms' in hook['message']
    assert len(sent.mail) == 1 and 'Commit latency: 310 ms' in sent.mail[0][2]
    row, = _open(db)
    assert (row['target_type'], row['target_id'], row['object_key']) == ('node', 'pve2', 'osd:pve2:3')
    assert row['severity'] == 'warning'
    # one read per minute through one node, never per OSD
    assert cluster.count(OSD_PATH.format('pve1')) == 3
    assert not [c for c in cluster.calls if '/ceph/osd/' in c or c == OSD_PATH.format('pve2')]

    # still slow: nothing more is sent
    E.check_event_alerts(NOW + 180)
    assert len(sent.push) == 1

    _osds(cluster, _osd(0, 'pve1'), _osd(3, 'pve2', apply=40))
    E.check_event_alerts(NOW + 240)
    assert sent.names()[-1] == 'Resolved: latency of osd.3 on pve2'
    assert sent.hooks[-1][0]['event'] == 'resolved' and 'at or below 100 ms again' in sent.push[-1]['message']
    assert _open(db) == [] and _closed(db)[0]['resolved_by'] == 'clear'


def test_a_spike_does_not_page(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('ceph_osd_latency', threshold=50))
    for at, ms in zip(_ticks(NOW, 5), (200, 200, 10, 200, 200)):
        _osds(cluster, _osd(1, 'pve1', apply=ms))
        E.check_event_alerts(at)
    assert sent.push == []
    _osds(cluster, _osd(1, 'pve1', apply=200))
    E.check_event_alerts(NOW + 300)
    assert sent.names() == ['osd.1 on pve1 is slow']


def test_either_latency_counts(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('ceph_osd_latency'))
    _osds(cluster, _osd(1, 'pve1', apply=5, commit=180))
    for at in _ticks(NOW, 3):
        E.check_event_alerts(at)
    assert sent.names() == ['osd.1 on pve1 is slow']


def test_ten_times_the_limit_is_critical(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('ceph_osd_latency', threshold=20))
    _osds(cluster, _osd(1, 'pve1', apply=250))
    for at in _ticks(NOW, 3):
        E.check_event_alerts(at)
    assert sent.push[0]['severity'] == 'critical' and _open(db)[0]['severity'] == 'critical'


def test_one_read_a_minute_shared_with_the_exporter(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('ceph_osd_latency'))
    _osds(cluster, _osd(1, 'pve1', apply=500))
    # the exporter read it a moment ago: the tick takes that read
    assert E.ceph_osds('c1', cluster, now=NOW - 10)['osds'][1]['apply'] == 500
    E.check_event_alerts(NOW)
    E.check_event_alerts(NOW + 30)
    assert cluster.count(OSD_PATH.format('pve1')) == 1
    # and both see the same reads in a row
    E.check_event_alerts(NOW + 60)
    E.check_event_alerts(NOW + 120)
    assert cluster.count(OSD_PATH.format('pve1')) == 3
    assert sent.names() == ['osd.1 on pve1 is slow']
    assert E.osd_reading('c1')['hist'][1] == [500.0, 500.0, 500.0]


def test_without_latency_figures_an_osd_is_unknown(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('ceph_osd_latency'))
    _osds(cluster, _osd(1, 'pve1', apply=400), _osd(2, 'pve1'))
    for at in _ticks(NOW, 3):
        E.check_event_alerts(at)
    assert len(_open(db)) == 1
    # the OSD went down: no latency in the list, neither raised nor cleared
    _osds(cluster, dict(_osd(1, 'pve1', missing=True), status='down'), _osd(2, 'pve1'))
    for at in _ticks(NOW + 180, 3):
        E.check_event_alerts(at)
    assert len(_open(db)) == 1 and len(sent.push) == 1
    # back with low figures: a clear at once
    _osds(cluster, _osd(1, 'pve1', apply=3), _osd(2, 'pve1'))
    E.check_event_alerts(NOW + 360)
    assert _open(db) == [] and sent.names()[-1] == 'Resolved: latency of osd.1 on pve1'
    # and the streak starts over after the gap the missing figures left
    _osds(cluster, _osd(1, 'pve1', apply=400), _osd(2, 'pve1'))
    E.check_event_alerts(NOW + 420)
    E.check_event_alerts(NOW + 480)
    assert _open(db) == []


@pytest.mark.parametrize('raw', ['n/a', None, True, float('nan'), -3, [1]])
def test_latency_that_is_no_number_is_left_out(cluster, sent, monkeypatch, db, raw):
    _rules(monkeypatch, _rule('ceph_osd_latency'))
    _osds(cluster, dict(_osd(1, 'pve1'), apply_latency_ms=raw, commit_latency_ms=raw))
    for at in _ticks(NOW, 3):
        E.check_event_alerts(at)
    entry = E.osd_reading('c1')
    assert entry['osds'][1]['apply'] is None and entry['hist'][1] == [None, None, None]
    assert sent.push == []


def test_a_node_rule_and_an_osd_that_left(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('ceph_osd_latency', rid='r1'),
           _rule('ceph_osd_latency', rid='r2', target_type='node', target_id='pve2'))
    _osds(cluster, _osd(1, 'pve1', apply=300), _osd(2, 'pve2', apply=300))
    for at in _ticks(NOW, 3):
        E.check_event_alerts(at)
    assert sorted((r['alert_id'], r['object_key']) for r in _open(db)) == [
        ('r1', 'osd:pve1:1'), ('r1', 'osd:pve2:2'), ('r2', 'osd:pve2:2')]
    assert cluster.count(OSD_PATH.format('pve1')) == 3   # one read for both rules
    # osd.2 is destroyed: closed without a word
    sent.push.clear()
    _osds(cluster, _osd(1, 'pve1', apply=300))
    E.check_event_alerts(NOW + 180)
    assert [r['object_key'] for r in _open(db)] == ['osd:pve1:1'] and sent.push == []
    assert {r['resolved_by'] for r in _closed(db)} == {'gone'}


def test_the_node_that_lists_the_osds_is_found_and_kept(cluster, sent, monkeypatch, db):
    """The first online node has no Ceph of its own: the next one answers, and from then on
    only that one is asked."""
    _rules(monkeypatch, _rule('ceph_osd_latency'))
    cluster.answer(OSD_PATH.format('pve1'), None, code=500)
    _osds(cluster, _osd(1, 'pve2', apply=300), node='pve2')
    for at in _ticks(NOW, 3):
        E.check_event_alerts(at)
    assert cluster.count(OSD_PATH.format('pve1')) == 1 and cluster.count(OSD_PATH.format('pve2')) == 3
    assert sent.names() == ['osd.1 on pve2 is slow']
    note = E.source_status()['c1']['ceph_osd']
    assert note['ok'] is True and '1 OSD(s) listed by pve2' in note['note'] and 'osd.1 at 300 ms' in note['note']


def test_the_node_the_ceph_status_probe_found_is_asked_first(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('ceph_osd_latency'))
    E._ceph['c1'] = {'absent_until': 0, 'node': 'pve2', 'seen': True}
    _osds(cluster, _osd(1, 'pve2'), node='pve2')
    E.check_event_alerts(NOW)
    assert cluster.calls == [OSD_PATH.format('pve2')]


def test_a_cluster_without_ceph_is_asked_again_only_later(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('ceph_osd_latency'))
    E.check_event_alerts(NOW)
    asked = len(cluster.calls)
    assert asked == 2                                   # each online node once
    E.check_event_alerts(NOW + 600)
    assert len(cluster.calls) == asked
    assert 'asking again in 30 minutes' in E.source_status()['c1']['ceph_osd']['note']
    _osds(cluster, _osd(1, 'pve1'))
    E.check_event_alerts(NOW + E.CEPH_RETRY + 1)
    assert E.osd_reading('c1') is not None


def test_no_ceph_found_by_the_status_probe_is_not_probed_again(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('ceph_osd_latency'))
    E._ceph['c1'] = {'absent_until': NOW + 900, 'node': None, 'seen': False}
    E.check_event_alerts(NOW)
    assert cluster.calls == []


def test_a_list_that_stops_answering_keeps_the_incident_and_a_gap_starts_over(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('ceph_osd_latency'))
    _osds(cluster, _osd(1, 'pve1', apply=300))
    for at in _ticks(NOW, 3):
        E.check_event_alerts(at)
    assert len(_open(db)) == 1
    _osds(cluster, code=500)
    for at in _ticks(NOW + 180, 8):
        E.check_event_alerts(at)
    assert len(_open(db)) == 1 and len(sent.push) == 1
    assert E.source_status()['c1']['ceph_osd']['ok'] is False
    # answering again after more than OSD_SERVE_MAX: one read is no run of three
    _osds(cluster, _osd(1, 'pve1', apply=300))
    E.check_event_alerts(NOW + 180 + 8 * 60)
    assert E.osd_reading('c1')['hist'][1] == [300.0]


def test_mutes_of_an_osd_and_of_its_node(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('ceph_osd_latency'))
    _mute(db, object_key='osd:pve1:1')
    _mute(db, object_key='node:pve2')
    _osds(cluster, _osd(1, 'pve1', apply=300), _osd(2, 'pve2', apply=300), _osd(3, 'pve1', apply=300))
    for at in _ticks(NOW, 3):
        E.check_event_alerts(at)
    assert sent.names() == ['osd.3 on pve1 is slow']
    assert E._target_key_of('osd:pve2:2') == 'node:pve2'


def test_without_an_osd_rule_no_osd_list_is_read(cluster, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('ceph_health'))
    cluster.answer('/cluster/ceph/status', {'health': {'status': 'HEALTH_OK'}})
    E.check_event_alerts(NOW)
    assert not [c for c in cluster.calls if 'ceph/osd' in c]


# --- PegaProx's own replication jobs -----------------------------------------------------

def _iso(ago):
    return None if ago is None else datetime.fromtimestamp(NOW - ago).isoformat()


def _job(db, jid='j1', vmid=101, source='c1', target='c2', schedule='0 */6 * * *', enabled=1,
         ok_ago=None, run_ago='same', status='ok', error='', created_ago=7 * 86400, target_node=''):
    run_ago = ok_ago if run_ago == 'same' else run_ago
    db.conn.execute(
        "INSERT OR REPLACE INTO cross_cluster_replications (id, source_cluster, target_cluster, vmid, schedule, "
        "enabled, last_run, last_status, last_error, last_ok_at, created_at, target_node) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (jid, source, target, vmid, schedule, enabled, _iso(run_ago), status if run_ago is not None else '',
         error, _iso(ok_ago), _iso(created_ago), target_node))
    db.conn.commit()


def _set(db, jid, **cols):
    for k, v in cols.items():
        db.conn.execute(f"UPDATE cross_cluster_replications SET {k} = ? WHERE id = ?", (v, jid))
    db.conn.commit()


@pytest.fixture
def dr(cluster):
    """The target cluster of the jobs; it has no rules of its own."""
    cluster_managers['c2'] = _Cluster(name='DR')
    yield cluster_managers['c2']
    cluster_managers.pop('c2', None)


H = 3600


def test_a_job_past_its_rpo_alerts_once_on_every_path_and_resolves(cluster, dr, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('replication_rpo'))
    _job(db, ok_ago=13 * H)                 # every 6 h: the RPO is 12 h
    _job(db, jid='j2', vmid=102, ok_ago=5 * H)

    E.check_event_alerts(NOW)

    assert sent.names() == ['Replication of web01 (101) is past its RPO']
    (hook, ids), = sent.hooks
    assert ids == ['hook1'] and hook['event'] == 'firing' and hook['metric'] == 'replication_rpo'
    assert hook['current_value'] == '13 h'
    assert hook['message'] == ('Replication job j1 (web01 (101) from Testi to DR) last ran successfully '
                               '13 h ago; the RPO is 12 h.')
    assert len(sent.mail) == 1 and 'RPO: 12 h (twice the interval)' in sent.mail[0][2]
    row, = _open(db)
    assert (row['target_type'], row['target_id'], row['object_key']) == ('vm', '101', 'xcrepl:101:j1')
    assert row['severity'] == 'warning' and row['current_value'] == 780
    # DB only: nothing is asked of a cluster
    assert cluster.calls == [] and dr.calls == []

    E.check_event_alerts(NOW + 60)
    assert len(sent.push) == 1

    _set(db, 'j1', last_ok_at=_iso(-120), last_run=_iso(-120))
    E.check_event_alerts(NOW + 120)
    assert sent.names()[-1] == 'Resolved: replication of web01 (101)'
    assert 'is within its RPO of 12 h again' in sent.push[-1]['message']
    assert _open(db) == [] and _closed(db)[0]['resolved_by'] == 'clear'


@pytest.mark.parametrize('minutes,ok_ago,fires', [(60, 90 * 60, True), (60, 30 * 60, False),
                                                 (1440, 13 * H, False), (1440, 25 * H, True)])
def test_the_rule_sets_the_rpo_in_minutes(cluster, dr, sent, monkeypatch, db, minutes, ok_ago, fires):
    _rules(monkeypatch, _rule('replication_rpo', threshold=minutes))
    _job(db, ok_ago=ok_ago)
    E.check_event_alerts(NOW)
    assert bool(sent.push) == fires


@pytest.mark.parametrize('schedule,ok_ago,fires', [('*/30 * * * *', 61 * 60, True), ('*/30 * * * *', 59 * 60, False),
                                                   ('0 2 * * *', 47 * H, False), ('0 2 * * *', 49 * H, True),
                                                   ('0 */2 * * *', 5 * H, True)])
def test_automatic_is_twice_the_interval_of_the_schedule(cluster, dr, sent, monkeypatch, db, schedule, ok_ago, fires):
    _rules(monkeypatch, _rule('replication_rpo'))
    _job(db, schedule=schedule, ok_ago=ok_ago)
    E.check_event_alerts(NOW)
    assert bool(sent.push) == fires


def test_far_past_the_rpo_is_critical(cluster, dr, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('replication_rpo'))
    _job(db, ok_ago=30 * H)
    E.check_event_alerts(NOW)
    assert sent.push[0]['severity'] == 'critical'


def test_a_failed_run_does_not_reset_the_clock_and_says_why(cluster, dr, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('replication_rpo'))
    _job(db, ok_ago=14 * H, run_ago=600, status='error', error='Clone failed: no space left on device.')
    E.check_event_alerts(NOW)
    msg = sent.push[0]['message']
    assert 'last ran successfully 14 h ago' in msg
    assert msg.endswith('The last run failed: Clone failed: no space left on device.')
    assert 'Last error: Clone failed' in sent.mail[0][2]


def test_a_job_that_never_went_through_counts_from_its_creation(cluster, dr, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('replication_rpo'))
    _job(db, ok_ago=None, run_ago=300, status='error', error='VM 101 not found', created_ago=13 * H)
    _job(db, jid='j2', vmid=102, ok_ago=None, run_ago=None, created_ago=2 * H)
    E.check_event_alerts(NOW)
    assert sent.names() == ['Replication of web01 (101) is past its RPO']
    assert 'has no successful run on record since it was created 13 h ago' in sent.push[0]['message']
    assert 'Last success: none on record' in sent.mail[0][2]


def test_a_job_from_before_last_ok_at_counts_its_last_good_run(cluster, dr, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('replication_rpo'))
    _job(db, ok_ago=None, run_ago=13 * H, status='ok')   # last_ok_at not written yet
    E.check_event_alerts(NOW)
    assert 'last ran successfully 13 h ago' in sent.push[0]['message']


def test_a_disabled_job_resolves(cluster, dr, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('replication_rpo'))
    _job(db, ok_ago=13 * H)
    E.check_event_alerts(NOW)
    _set(db, 'j1', enabled=0)
    E.check_event_alerts(NOW + 60)
    assert sent.names()[-1] == 'Resolved: replication of web01 (101)'
    assert sent.push[-1]['message'] == 'Replication job j1 (web01 (101) from Testi to DR) was disabled.'
    assert _open(db) == []


def _fail_over(db, jid='j1', vmid=101, on=True):
    db.conn.execute("INSERT OR IGNORE INTO site_recovery_plans (id, group_id, name, source_cluster, target_cluster) "
                    "VALUES ('p1', 'g1', 'Plan A', 'c1', 'c2')")
    db.conn.execute("INSERT OR REPLACE INTO site_recovery_vms (id, plan_id, vmid, replication_job_id, failed_over) "
                    "VALUES ('v1', 'p1', ?, ?, ?)", (vmid, jid, 'emergency' if on else ''))
    db.conn.commit()


def test_a_job_held_for_a_failover_resolves_and_gets_its_chance_after_the_failback(cluster, dr, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('replication_rpo'))
    _job(db, ok_ago=13 * H)
    E.check_event_alerts(NOW)
    assert len(_open(db)) == 1

    # the plan failed the guest over: its replication waits, its age says nothing
    _fail_over(db)
    E.check_event_alerts(NOW + 60)
    assert _open(db) == [] and 'waits for the failback of its guest' in sent.push[-1]['message']
    E.check_event_alerts(NOW + 3 * 86400)
    assert _open(db) == []

    # failed back three days later: the old run is far past the RPO, but the job just came back
    _fail_over(db, on=False)
    back = NOW + 3 * 86400 + 60
    E.check_event_alerts(back)
    E.check_event_alerts(back + 11 * H)
    assert _open(db) == []
    E.check_event_alerts(back + 12 * H + 120)
    assert sent.names()[-1] == 'Replication of web01 (101) is past its RPO'
    assert 'came back 12 h 2 min ago and has not completed a run since' in sent.push[-1]['message']


def test_a_job_switched_on_again_gets_its_chance(cluster, dr, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('replication_rpo'))
    _job(db, ok_ago=10 * 86400, enabled=0)
    E.check_event_alerts(NOW)
    _set(db, 'j1', enabled=1)
    E.check_event_alerts(NOW + 60)
    assert sent.push == [] and _open(db) == []


def test_a_deleted_job_closes_quietly(cluster, dr, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('replication_rpo'))
    _job(db, ok_ago=13 * H)
    E.check_event_alerts(NOW)
    db.conn.execute("DELETE FROM cross_cluster_replications WHERE id = 'j1'")
    db.conn.commit()
    E.check_event_alerts(NOW + 60)
    assert _open(db) == [] and _closed(db)[0]['resolved_by'] == 'gone' and len(sent.push) == 1


def test_a_source_cluster_out_of_reach_is_still_watched(cluster, dr, sent, monkeypatch, db):
    from pegaprox.background import alerts as A
    _rules(monkeypatch, _rule('replication_rpo'), _rule('clock_drift', rid='r2'))
    _job(db, ok_ago=13 * H)
    cluster.is_connected = False
    E.check_event_alerts(NOW)
    # no guest names without the cluster, the job is reported all the same
    assert sent.names() == ['Replication of VM 101 is past its RPO']
    assert 'not connected' in A._last_eval['r2']['reason']
    assert cluster.calls == []


def test_a_cluster_that_is_not_answering_in_time_still_gets_its_rpo_rule(cluster, dr, sent, monkeypatch, db):
    import pegaprox.background.alert_events as mod
    _rules(monkeypatch, _rule('replication_rpo'))
    _job(db, ok_ago=13 * H)
    monkeypatch.setattr(mod, 'run_concurrent', lambda jobs, timeout=0: [None for _ in jobs])
    E.check_event_alerts(NOW)
    assert sent.names() == ['Replication of VM 101 is past its RPO']


def test_the_target_and_the_source_cluster(cluster, dr, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('replication_rpo', target_type='vm', target_id='102'))
    _job(db, ok_ago=13 * H)
    _job(db, jid='j2', vmid=102, ok_ago=13 * H)
    _job(db, jid='j3', vmid=102, source='c2', target='c1', ok_ago=13 * H)   # c2's own job
    E.check_event_alerts(NOW)
    assert [r['object_key'] for r in _open(db)] == ['xcrepl:102:j2']


def test_a_job_within_one_cluster(cluster, dr, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('replication_rpo'))
    _job(db, target='c1', target_node='pve2', ok_ago=13 * H)
    E.check_event_alerts(NOW)
    assert '(web01 (101) to node pve2 of Testi)' in sent.push[0]['message']


def test_a_run_under_way_is_said(cluster, dr, sent, monkeypatch, db):
    from pegaprox.background import cross_cluster_replication as X
    monkeypatch.setattr(X, 'is_job_inflight', lambda jid: jid == 'j1')
    _rules(monkeypatch, _rule('replication_rpo'))
    _job(db, ok_ago=13 * H)
    E.check_event_alerts(NOW)
    assert sent.push[0]['message'].endswith('the RPO is 12 h. A run is under way.')


def test_an_unreadable_job_table_closes_nothing(cluster, dr, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('replication_rpo'))
    _job(db, ok_ago=13 * H)
    E.check_event_alerts(NOW)
    monkeypatch.setattr(E, 'own_replications', lambda now=None: None)
    E.check_event_alerts(NOW + 60)
    assert len(_open(db)) == 1 and len(sent.push) == 1
    assert E.source_status()['c1']['own_replication']['ok'] is False


def test_a_job_mute_and_a_guest_mute(cluster, dr, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('replication_rpo'))
    _mute(db, object_key='xcrepl:101:j1')
    _mute(db, object_key='vm:102')
    _job(db, ok_ago=13 * H)
    _job(db, jid='j2', vmid=102, ok_ago=13 * H)
    _job(db, jid='j3', vmid=101, target='c1', target_node='pve2', ok_ago=13 * H)
    E.check_event_alerts(NOW)
    assert [r['object_key'] for r in _open(db)] == ['xcrepl:101:j3']
    assert E.object_vmid('xcrepl:101:j1') == 101 and E._target_key_of('xcrepl:101:j1') == 'vm:101'
    assert E.object_vmid('xcrepl:') is None and E.object_vmid('xcrepl:abc:j1') is None


def test_the_diagnostics_line(cluster, dr, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('replication_rpo'))
    _job(db, ok_ago=60)
    _job(db, jid='j2', vmid=102, enabled=0, ok_ago=60)
    E.check_event_alerts(NOW)
    note = E.source_status()['c1']['own_replication']
    assert note['ok'] is True and note['note'] == '2 PegaProx replication job(s) from this cluster, 1 running on schedule'


def test_a_run_writes_last_ok_at_only_when_it_went_through(db):
    from pegaprox.api import vms
    _job(db, ok_ago=None, run_ago=None, status='')
    vms._update_repl_status(db, 'j1', 'ok')
    ok_at, = db.conn.execute("SELECT last_ok_at FROM cross_cluster_replications WHERE id = 'j1'").fetchone()
    assert ok_at
    vms._update_repl_status(db, 'j1', 'error', 'snapshot failed')
    row = db.conn.execute("SELECT last_ok_at, last_run, last_status FROM cross_cluster_replications "
                          "WHERE id = 'j1'").fetchone()
    assert row['last_ok_at'] == ok_at and row['last_status'] == 'error' and row['last_run'] >= ok_at


def test_an_older_database_learns_the_last_good_run(db):
    """The column comes with this change: a job whose last run was fine takes that run, one
    whose last run failed the newest 'succeeded' the audit log has of it."""
    _job(db, jid='j1', ok_ago=None, run_ago=600, status='ok')
    _job(db, jid='j2', vmid=102, ok_ago=None, run_ago=600, status='error')
    _job(db, jid='j3', vmid=103, ok_ago=None, run_ago=600, status='error')
    for at, jid in (('2026-09-01T10:00:00', 'j2'), ('2026-09-02T10:00:00', 'j2'), ('2026-09-03T10:00:00', 'jx')):
        db.conn.execute("INSERT INTO audit_log (timestamp, user, action, details) VALUES (?, 'system', "
                        "'replication.completed', ?)", (at, f'xcrepl job {jid} succeeded'))
    db.conn.execute("ALTER TABLE cross_cluster_replications DROP COLUMN last_ok_at")
    db.conn.commit()
    db._init_db()
    got = dict(db.conn.execute("SELECT id, last_ok_at FROM cross_cluster_replications").fetchall())
    assert got == {'j1': _iso(600), 'j2': '2026-09-02T10:00:00', 'j3': None}


# --- the rule fields and who may see what ------------------------------------------------

@pytest.fixture
def routes(api, seed):
    api.set_manager('c1', api.make_fake_manager('c1'))
    return types.SimpleNamespace(api=api, seed=seed, admin=api.as_user(seed.user('root', role='admin')))


def test_both_rules_take_their_defaults(routes, monkeypatch):
    store = _store(monkeypatch)
    r = routes.admin.post('/api/clusters/c1/alerts', json={'name': 'OSDs', 'metric': 'ceph_osd_latency'})
    assert r.status_code == 200, r.data
    rule = r.get_json()['alert']
    assert (rule['operator'], rule['threshold'], rule['target_type'], rule['notify_resolved']) == (
        'event', 100, 'cluster', True)
    r = routes.admin.post('/api/clusters/c1/alerts', json={'name': 'RPO', 'metric': 'replication_rpo'})
    assert r.get_json()['alert']['threshold'] == 0
    r = routes.admin.post('/api/clusters/c1/alerts', json={
        'name': 'RPO 101', 'metric': 'replication_rpo', 'threshold': 240, 'target_type': 'vm', 'target_id': '101'})
    assert (r.get_json()['alert']['threshold'], r.get_json()['alert']['target_id']) == (240, '101')
    r = routes.admin.post('/api/clusters/c1/alerts', json={
        'name': 'OSD pve2', 'metric': 'ceph_osd_latency', 'threshold': 40, 'target_type': 'node', 'target_id': 'pve2'})
    assert r.get_json()['alert']['threshold'] == 40
    assert len(store['c1']) == 4


@pytest.mark.parametrize('body,needle', [
    ({'metric': 'ceph_osd_latency', 'threshold': 4}, 'threshold'),
    ({'metric': 'ceph_osd_latency', 'threshold': 10001}, 'threshold'),
    ({'metric': 'ceph_osd_latency', 'threshold': 'fast'}, 'threshold'),
    ({'metric': 'ceph_osd_latency', 'threshold': 12.5}, 'threshold'),
    ({'metric': 'ceph_osd_latency', 'threshold': None}, 'threshold'),
    ({'metric': 'ceph_osd_latency', 'target_type': 'vm', 'target_id': '101'}, 'OSD latency rule'),
    ({'metric': 'replication_rpo', 'threshold': -1}, 'threshold'),
    ({'metric': 'replication_rpo', 'threshold': 10081}, 'threshold'),
    ({'metric': 'replication_rpo', 'threshold': [60]}, 'threshold'),
    ({'metric': 'replication_rpo', 'threshold': True}, 'threshold'),
    ({'metric': 'replication_rpo', 'target_type': 'node', 'target_id': 'pve1'}, 'replication RPO rule'),
    ({'metric': 'replication_rpo', 'target_type': 'vm', 'target_id': 'web01'}, 'numeric'),
])
def test_a_bad_rule_is_refused(routes, monkeypatch, body, needle):
    store = _store(monkeypatch)
    r = routes.admin.post('/api/clusters/c1/alerts', json=dict(body, name='x'))
    assert r.status_code == 400 and needle in r.get_json()['error'], r.data
    assert store['c1'] == []


def test_a_new_limit_starts_the_rule_over(routes, monkeypatch, db):
    store = _store(monkeypatch, [_rule('ceph_osd_latency')])
    db.conn.execute("INSERT INTO active_alerts (id, alert_key, alert_id, cluster_id, metric, object_key, "
                    "triggered_at) VALUES ('x1', 'r1:c1:osd:pve1:1', 'r1', 'c1', 'ceph_osd_latency', "
                    "'osd:pve1:1', '2026-10-09')")
    db.conn.commit()
    assert routes.admin.put('/api/clusters/c1/alerts/r1', json={'name': 'OSDs'}).status_code == 200
    assert len(_open(db)) == 1
    r = routes.admin.put('/api/clusters/c1/alerts/r1', json={'threshold': 250})
    assert r.status_code == 200 and store['c1'][0]['threshold'] == 250
    assert _open(db) == []


@pytest.mark.parametrize('kind,code', [
    ('operator', 200),
    ('no_permission', 403),
    ('pool_confined', 403),
    ('capped_admin', 403),
    ('other_tenant', 403),
])
@pytest.mark.parametrize('metric', ['ceph_osd_latency', 'replication_rpo'])
def test_who_may_set_a_rule(routes, monkeypatch, kind, code, metric):
    store = _store(monkeypatch)
    c = _who(routes, kind)
    r = c.post('/api/clusters/c1/alerts', json={'name': 'n', 'metric': metric})
    assert r.status_code == code, (kind, r.data)
    assert len(store['c1']) == (1 if code == 200 else 0)


def test_a_standby_takes_neither_rule(ha_env, seed, monkeypatch):  # noqa: F811
    api = ha_env.api
    store = _store(monkeypatch)
    api.set_manager('c1', api.make_fake_manager('c1'))
    c = api.as_user(seed.user('root', role='admin'))
    _standby_of_active(ha_env)
    for metric in ('ceph_osd_latency', 'replication_rpo'):
        r = c.post('/api/clusters/c1/alerts', json={'name': 'n', 'metric': metric})
        assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY'
    assert store['c1'] == []


@pytest.mark.parametrize('which', ['standby', 'active'])
def test_only_the_active_instance_reads_and_sends(which, role, cluster, dr, sent, monkeypatch, db):  # noqa: F811
    from pegaprox.background import alerts as A
    role(which)
    _rules(monkeypatch, _rule('replication_rpo'), _rule('ceph_osd_latency', rid='r2'))
    _job(db, ok_ago=13 * H)
    _osds(cluster, _osd(1, 'pve1', apply=300))
    for name in ('check_and_send_alerts', 'process_alert_lifecycle', 'check_node_status_transitions',
                 'check_update_available_alert', '_periodic_session_cleanup', '_periodic_audit_cleanup'):
        monkeypatch.setattr(A, name, lambda *a, **k: None)
    monkeypatch.setattr(A, '_alert_running', False)
    _drive(monkeypatch, A, A.alert_check_loop)
    if which == 'standby':
        assert cluster.calls == [] and sent.push == sent.hooks == sent.mail == []
        assert _open(db) == []
    else:
        assert cluster.count(OSD_PATH.format('pve1')) == 1
        assert sent.names() == ['Replication of web01 (101) is past its RPO']


def _incident(db, metric, obj, ttype, tid, rid='r1', name=None):
    db.conn.execute(
        "INSERT INTO active_alerts (id, alert_key, alert_id, cluster_id, metric, target_type, target_id, "
        "target_name, message, object_key, triggered_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (f'i-{obj}', f'{rid}:c1:{obj}', rid, 'c1', metric, ttype, tid, name or tid, 'x', obj,
         '2026-10-09T00:00:00'))
    db.conn.commit()


def test_a_confined_caller_sees_its_guests_replication_and_no_osd(routes, monkeypatch, db):
    _incident(db, 'ceph_osd_latency', 'osd:pve1:3', 'node', 'pve1')
    _incident(db, 'replication_rpo', 'xcrepl:101:j1', 'vm', '101')
    _incident(db, 'replication_rpo', 'xcrepl:300:j9', 'vm', '300')
    for key in ('osd:pve1:3', 'xcrepl:101:j1', 'xcrepl:300:j9'):
        _mute(db, object_key=key)
    from pegaprox.utils import rbac
    monkeypatch.setattr(rbac, 'user_can_access_vm', lambda u, cid, vmid, perm='vm.view', vt=None: int(vmid) == 101)
    _store(monkeypatch)
    c = _who(routes, 'pool_confined')
    rows = c.get('/api/clusters/c1/active-alerts').get_json()['active_alerts']
    assert [i['object_key'] for i in rows] == ['xcrepl:101:j1']
    assert [m['object_key'] for m in c.get('/api/clusters/c1/alert-mutes').get_json()['mutes']] == ['xcrepl:101:j1']
    # another tenant gets nothing at all
    other = _who(routes, 'other_tenant')
    assert other.get('/api/clusters/c1/active-alerts').status_code == 403
    assert other.get('/api/clusters/c1/alert-mutes').status_code == 403
    # counterproof: the admin sees all of them
    rows = routes.admin.get('/api/clusters/c1/active-alerts').get_json()['active_alerts']
    assert sorted(i['object_key'] for i in rows) == ['osd:pve1:3', 'xcrepl:101:j1', 'xcrepl:300:j9']
    assert len(routes.admin.get('/api/clusters/c1/alert-mutes').get_json()['mutes']) == 3


def test_an_incident_mutes_its_osd_or_its_node_and_its_job_or_its_guest(routes, monkeypatch, db):
    _store(monkeypatch, [_rule('ceph_osd_latency'), _rule('replication_rpo', rid='r2')])
    _incident(db, 'ceph_osd_latency', 'osd:pve1:3', 'node', 'pve1')
    _incident(db, 'replication_rpo', 'xcrepl:101:j1', 'vm', '101', rid='r2', name='web01 (101)')
    a = routes.admin
    r = a.post('/api/clusters/c1/alert-mutes', json={'active_alert_id': 'i-osd:pve1:3', 'minutes': 60})
    assert (r.get_json()['mute']['rule_id'], r.get_json()['mute']['object_key']) == ('r1', 'osd:pve1:3')
    r = a.post('/api/clusters/c1/alert-mutes', json={'active_alert_id': 'i-osd:pve1:3', 'minutes': 60,
                                                     'whole_object': True})
    assert r.get_json()['mute']['object_key'] == 'node:pve1'
    r = a.post('/api/clusters/c1/alert-mutes', json={'active_alert_id': 'i-xcrepl:101:j1', 'minutes': 60})
    assert r.get_json()['mute']['object_key'] == 'xcrepl:101:j1'
    r = a.post('/api/clusters/c1/alert-mutes', json={'active_alert_id': 'i-xcrepl:101:j1', 'minutes': 60,
                                                     'whole_object': True})
    assert r.get_json()['mute']['object_key'] == 'vm:101'
    audited = db.conn.execute("SELECT COUNT(*) FROM audit_log WHERE action = 'alert.muted'").fetchone()[0]
    assert audited == 4


def test_an_acknowledged_rpo_incident_stays_quiet_and_still_closes(routes, cluster, dr, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('replication_rpo'))
    _job(db, ok_ago=13 * H)
    E.check_event_alerts(NOW)
    row, = _open(db)
    r = routes.admin.post(f"/api/clusters/c1/active-alerts/{row['id']}/ack")
    assert r.status_code == 200 and _open(db)[0]['acked_by'] == 'root'
    E.check_event_alerts(NOW + 60)
    assert len(sent.push) == 1
    _set(db, 'j1', last_ok_at=_iso(-100))
    E.check_event_alerts(NOW + 120)
    assert _open(db) == [] and sent.names()[-1] == 'Resolved: replication of web01 (101)'


def test_the_diagnostics_carry_both_sources_for_the_callers_clusters(routes, cluster, dr, sent, monkeypatch, db):
    _rules(monkeypatch, _rule('replication_rpo'), _rule('ceph_osd_latency', rid='r2'))
    _osds(cluster, _osd(1, 'pve1'))
    _job(db, ok_ago=60)
    E.check_event_alerts(NOW)
    diag = routes.admin.get('/api/alerts/diagnostics').get_json()
    assert set(diag['event_sources']['c1']) >= {'ceph_osd', 'own_replication'}
    c_diag = _who(routes, 'other_tenant').get('/api/alerts/diagnostics')
    if c_diag.status_code == 200:
        assert 'c1' not in c_diag.get_json()['event_sources']
