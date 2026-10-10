"""The Prometheus exporter: Ceph OSD latency and PegaProx's own replication jobs.

/api/metrics gains:
  - pegaprox_ceph_osd_{apply,commit}_latency_seconds per OSD, labels cluster_id, cluster,
    osd and host only, from the OSD list the ceph_osd_latency alert reads
    (alert_events.ceph_osds): one /nodes/<n>/ceph/osd per cluster at most once a minute, in
    the background, and only for a cluster that has shown Ceph
  - pegaprox_cross_cluster_replication_{active,interval_seconds,last_success_age_seconds,
    failed} per replication job of PegaProx, from the database in one query: the clusters
    are not asked, and a source cluster that is not connected still has its jobs
The clusters are faked at the API paths they are asked (test_metrics_exporter_breadth.py).
MK Oct 2026
"""
import os
import re
import time
from datetime import datetime

import pytest

import pegaprox.api.metrics_exporter as mx
from pegaprox.background import alert_events as E

from test_metrics_exporter_breadth import GUESTS, _Pve, _find, _fresh, _fresh_now, _one, _samples, _scrape  # noqa: F401
from test_alert_osd_rpo import _osd, _tree

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OSD_PATH = '/nodes/{}/ceph/osd'


@pytest.fixture(autouse=True)
def _osd_state(monkeypatch):
    for name in ('_osd', '_osd_locks', '_own_repl', '_ceph'):
        monkeypatch.setattr(E, name, {})


class _Ceph(_Pve):
    """A cluster whose Ceph the health probe found."""

    def __init__(self, *a, nodes=('pve1', 'pve2'), ceph=True, **kw):
        super().__init__(*a, **kw)
        self.node_names, self.ceph = nodes, ceph

    def get_node_status(self):
        return {n: {'status': 'online', 'cpu': 0.1, 'mem_percent': 5, 'uptime': 10} for n in self.node_names}

    def get_ceph_health_summary(self):
        return {'status': 'HEALTH_OK', 'osd_up': 3, 'osd_in': 3} if self.ceph else None


# --- OSD latency -------------------------------------------------------------------------

def test_osd_latency_per_osd_from_one_read(api):
    c1 = api.set_manager('c1', _Ceph('Testi', GUESTS))
    c1.answer(OSD_PATH.format('pve1'), _tree(_osd(0, 'pve1', apply=2, commit=3), _osd(3, 'pve2', apply=250, commit=310),
                                             _osd(4, 'pve2', missing=True)))
    body = _scrape(api)
    slow = dict(cluster_id='c1', cluster='Testi', osd='osd.3', host='pve2')
    assert _one(body, 'pegaprox_ceph_osd_apply_latency_seconds', **slow) == 0.25
    assert _one(body, 'pegaprox_ceph_osd_commit_latency_seconds', **slow) == 0.31
    assert _one(body, 'pegaprox_ceph_osd_commit_latency_seconds', osd='osd.0') == 0.003
    # an OSD without figures (down) has no series rather than a zero
    assert _find(body, 'pegaprox_ceph_osd_apply_latency_seconds', osd='osd.4') == []
    # the labels a dashboard needs and no more
    lbl, _ = _find(body, 'pegaprox_ceph_osd_apply_latency_seconds', osd='osd.3')[0]
    assert set(lbl) == {'cluster_id', 'cluster', 'osd', 'host'}
    assert _one(body, 'pegaprox_cluster_source_up', cluster_id='c1', source='ceph_osd') == 1
    assert body.count('# TYPE pegaprox_ceph_osd_apply_latency_seconds gauge') == 1
    # once a minute, one call per cluster, never per OSD
    _scrape(api)
    assert c1.count(OSD_PATH.format('pve1')) == 1
    assert not [p for p in c1.calls if re.search(r'/ceph/osd/\d', p) or p == OSD_PATH.format('pve2')]


def test_the_exporter_and_the_alert_share_the_read(api):
    c1 = api.set_manager('c1', _Ceph('Testi', GUESTS))
    c1.answer(OSD_PATH.format('pve1'), _tree(_osd(1, 'pve1', apply=120)))
    E.ceph_osds('c1', c1)
    body = _scrape(api)
    assert c1.count(OSD_PATH.format('pve1')) == 1
    assert _one(body, 'pegaprox_ceph_osd_apply_latency_seconds', osd='osd.1') == 0.12
    # what the scrape reads counts towards the alert's reads in a row
    E._osd['c1']['at'] = 0
    E._osd['c1']['last']['at'] = time.time() - 61
    _scrape(api)
    assert c1.count(OSD_PATH.format('pve1')) == 2 and E.osd_reading('c1')['hist'][1] == [120.0, 120.0]


def test_a_cluster_without_ceph_is_not_probed(api):
    c1 = api.set_manager('c1', _Ceph('Testi', GUESTS, ceph=False))
    body = _scrape(api)
    assert not [p for p in c1.calls if 'ceph' in p]
    assert _find(body, 'pegaprox_cluster_source_up', cluster_id='c1', source='ceph_osd') == []
    assert _find(body, 'pegaprox_ceph_osd_apply_latency_seconds') == []


def test_ceph_a_status_read_found_is_enough_without_the_probe(api):
    """A standby takes no SSH health probe; a Ceph status read of the overview or the alert,
    or an OSD read of before, is reason enough to list the OSDs."""
    c1 = api.set_manager('c1', _Ceph('Testi', GUESTS, ceph=False))
    c1.answer(OSD_PATH.format('pve1'), _tree(_osd(1, 'pve1', apply=7)))
    E._ceph['c1'] = {'absent_until': 0, 'node': None, 'seen': True}
    body = _scrape(api)
    assert _one(body, 'pegaprox_ceph_osd_apply_latency_seconds', osd='osd.1') == 0.007


def test_an_unreadable_osd_list_says_so(api):
    c1 = api.set_manager('c1', _Ceph('Testi', GUESTS))
    c1.answer(OSD_PATH.format('pve1'), None, code=500)
    c1.answer(OSD_PATH.format('pve2'), None, code=500)
    body = _scrape(api)
    assert _one(body, 'pegaprox_cluster_source_up', cluster_id='c1', source='ceph_osd') == 0
    assert _find(body, 'pegaprox_ceph_osd_apply_latency_seconds') == []


# --- PegaProx's own replication jobs -----------------------------------------------------

def _iso(ago):
    return None if ago is None else datetime.fromtimestamp(time.time() - ago).isoformat()


def _job(db, jid, vmid=101, source='c1', target='c2', schedule='0 */6 * * *', enabled=1, ok_ago=None,
         status='ok', created_ago=86400):
    db.conn.execute(
        "INSERT INTO cross_cluster_replications (id, source_cluster, target_cluster, vmid, schedule, enabled, "
        "last_run, last_status, last_ok_at, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (jid, source, target, vmid, schedule, enabled, _iso(ok_ago if status == 'ok' else 60), status,
         _iso(ok_ago), _iso(created_ago)))
    db.conn.commit()


def test_one_series_set_per_job_from_the_database(api, db):
    c1 = api.set_manager('c1', _Pve('Testi', GUESTS))
    c2 = api.set_manager('c2', _Pve('DR', []))
    _job(db, 'j1', ok_ago=7200)
    _job(db, 'j2', vmid=102, enabled=0, ok_ago=600, schedule='*/30 * * * *')
    _job(db, 'j3', vmid=103, ok_ago=None, status='error')
    _job(db, 'j4', vmid=104, ok_ago=50 * 3600, status='error')
    _job(db, 'j5', vmid=105, source='gone', ok_ago=60)          # its source cluster is not registered
    body = _scrape(api)

    j1 = dict(cluster_id='c1', cluster='Testi', job='j1', vmid='101', target_cluster_id='c2', target_cluster='DR')
    assert 7195 <= _one(body, 'pegaprox_cross_cluster_replication_last_success_age_seconds', **j1) <= 7260
    assert _one(body, 'pegaprox_cross_cluster_replication_interval_seconds', **j1) == 21600
    assert _one(body, 'pegaprox_cross_cluster_replication_active', **j1) == 1
    assert _one(body, 'pegaprox_cross_cluster_replication_failed', **j1) == 0
    lbl, _ = _find(body, 'pegaprox_cross_cluster_replication_active', job='j1')[0]
    assert set(lbl) == set(j1)

    assert _one(body, 'pegaprox_cross_cluster_replication_active', job='j2') == 0
    assert _one(body, 'pegaprox_cross_cluster_replication_interval_seconds', job='j2') == 1800
    # never went through: no age, and the failure says so
    assert _find(body, 'pegaprox_cross_cluster_replication_last_success_age_seconds', job='j3') == []
    assert _one(body, 'pegaprox_cross_cluster_replication_failed', job='j3') == 1
    assert _one(body, 'pegaprox_cross_cluster_replication_failed', job='j4') == 1
    assert _one(body, 'pegaprox_cross_cluster_replication_last_success_age_seconds', job='j4') >= 50 * 3600
    assert _find(body, 'pegaprox_cross_cluster_replication_active', job='j5') == []
    # nothing is asked of the clusters for it
    assert not [p for p in c1.calls + c2.calls if 'replication' in p and p != '/cluster/replication']


def test_a_source_cluster_that_is_not_connected_keeps_its_jobs(api, db):
    c1 = api.set_manager('c1', _Pve('Testi', GUESTS))
    c1.is_connected = False
    _job(db, 'j1', ok_ago=7200)
    body = _scrape(api)
    assert _one(body, 'pegaprox_cross_cluster_replication_active', cluster_id='c1', job='j1') == 1
    # the target cluster's name falls back to its id when it is not registered
    assert _find(body, 'pegaprox_cross_cluster_replication_active', job='j1')[0][0]['target_cluster'] == 'c2'


def test_a_job_held_for_a_failover_is_not_active(api, db):
    api.set_manager('c1', _Pve('Testi', GUESTS))
    _job(db, 'j1', ok_ago=7200)
    db.conn.execute("INSERT INTO site_recovery_plans (id, group_id, name, source_cluster, target_cluster) "
                    "VALUES ('p1', 'g1', 'Plan A', 'c1', 'c2')")
    db.conn.execute("INSERT INTO site_recovery_vms (id, plan_id, vmid, replication_job_id, failed_over) "
                    "VALUES ('v1', 'p1', 101, 'j1', 'emergency')")
    db.conn.commit()
    body = _scrape(api)
    assert _one(body, 'pegaprox_cross_cluster_replication_active', job='j1') == 0


def test_ten_thousand_jobs_cost_no_cluster_call(api, db):
    """What a scrape asks a cluster does not grow with its replication jobs: the same paths
    for a cluster with none and one with 10 000."""
    small, big = api.set_manager('small', _Pve('Small', GUESTS)), api.set_manager('big', _Pve('Big', GUESTS))
    stamp = _iso(3600)
    db.conn.executemany(
        "INSERT INTO cross_cluster_replications (id, source_cluster, target_cluster, vmid, schedule, enabled, "
        "last_run, last_status, last_ok_at, created_at) VALUES (?, 'big', 'small', ?, '0 */6 * * *', 1, ?, 'ok', ?, ?)",
        [(f'j{i}', 1000 + i, stamp, stamp, stamp) for i in range(10_000)])
    db.conn.commit()
    body = _scrape(api)
    assert len(_find(body, 'pegaprox_cross_cluster_replication_active', cluster_id='big')) == 10_000
    assert len(_find(body, 'pegaprox_cross_cluster_replication_last_success_age_seconds', cluster_id='big')) == 10_000
    assert sorted(big.calls) == sorted(small.calls)


# --- docs --------------------------------------------------------------------------------

def test_the_new_series_and_rules_are_documented_with_the_others():
    with open(os.path.join(ROOT, 'misc', 'grafana', 'README.md'), encoding='utf-8') as fh:
        doc = fh.read()
    for name, _t, _h in mx._DR_FAMILIES:
        assert f'`{name}`' in doc, name
    assert '`ceph_osd`' in doc and 'Ceph OSD latency' in doc and 'replication RPO' in doc
    assert '\u2014' not in doc and '\u2013' not in doc
    for _n, _t, help_text in mx._DR_FAMILIES:
        assert '\u2014' not in help_text and '\u2013' not in help_text
