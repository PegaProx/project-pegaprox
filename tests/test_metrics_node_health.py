"""The Prometheus exporter: node health and guest tags.

/api/metrics gains:
  - pegaprox_node_clock_offset_seconds from the clock read the clock_drift alert makes
    (alert_events.read_node_clocks), shared both ways, in the background every 5 minutes
  - pegaprox_node_temperature_celsius and pegaprox_node_power_watts from the caches the
    5-minute hardware poll fills; nothing is asked for them in a scrape
  - pegaprox_node_pressure_{some,full}_percent from the newest point of each online node's
    RRD, read in the background once a minute; a node whose RRD has none (before Proxmox
    VE 9) is asked again an hour later
  - pegaprox_guest_pressure_{some,full}_percent where /cluster/resources lists pressure with
    a running guest, and pegaprox_guest_tag_info, one series per tag (Proxmox and PegaProx
    tags, at most _GUEST_TAGS_MAX per guest). Nothing is asked per guest.
The clusters are faked at the API paths they are asked (test_metrics_exporter_breadth.py).
MK Oct 2026
"""
import json
import os
import re
import time

import pytest

import pegaprox.api.metrics_exporter as mx
from pegaprox.background import alert_events as E

from test_metrics_exporter_breadth import (GUESTS, _Pve, _Xen, _find, _fresh, _fresh_now, _one,  # noqa: F401
                                           _samples, _scrape)

RRD = '/nodes/{}/rrddata?timeframe=hour&cf=AVERAGE'


class _Hw(_Pve):
    """A cluster whose hardware poll ran: temperatures and BMC readings in the caches."""

    def __init__(self, *a, temps=None, hw=None, nodes=('pve1',), **kw):
        super().__init__(*a, **kw)
        self.temps, self.hw = temps or {}, hw or {}
        self.node_names = nodes

    def get_node_status(self):
        return {n: {'status': 'online' if n != 'pve3' else 'offline', 'cpu': 0.1, 'mem_percent': 5, 'uptime': 10}
                for n in self.node_names}

    def get_cached_node_temp(self, node, max_age=900):
        return self.temps.get(node)

    def get_cached_node_hardware(self, node, max_age=900):
        return self.hw.get(node)


def _rrd(*points):
    rows = [{'time': 1000 + 60 * i, 'cpu': 0.1, 'netin': 5} for i in range(3)]
    return rows + list(points)


# --- guest tags --------------------------------------------------------------------------

def test_one_tag_series_per_guest_and_tag(api, db):
    guests = [dict(GUESTS[0], tags='prod;Web;prod'), dict(GUESTS[1], tags='db'), GUESTS[2], GUESTS[3]]
    db.conn.execute("INSERT INTO vm_tags (cluster_id, vmid, tag_name, tag_color) VALUES ('c1', 101, 'Billing', '')")
    db.conn.execute("INSERT INTO vm_tags (cluster_id, vmid, tag_name, tag_color) VALUES ('c1', 999, 'gone', '')")
    db.conn.execute("INSERT INTO vm_tags (cluster_id, vmid, tag_name, tag_color) VALUES ('c2', 101, 'other', '')")
    db.conn.commit()
    api.set_manager('c1', _Pve('Testi', guests))
    body = _scrape(api)
    got = sorted((lbl['vmid'], lbl['tag']) for lbl, v in _samples(body, 'pegaprox_guest_tag_info') if v == 1)
    assert got == [('101', 'billing'), ('101', 'prod'), ('101', 'web'), ('102', 'db')]
    # the labels a join needs and no more: a migration does not start a new series
    lbl, _ = _find(body, 'pegaprox_guest_tag_info', vmid='102')[0]
    assert set(lbl) == {'cluster_id', 'cluster', 'vmid', 'tag'}
    assert body.count('# TYPE pegaprox_guest_tag_info gauge') == 1


def test_tags_per_guest_are_capped(api):
    many = ';'.join(f't{i:02d}' for i in range(25))
    api.set_manager('c1', _Pve('Testi', [dict(GUESTS[0], tags=many)]))
    body = _scrape(api)
    tags = [lbl['tag'] for lbl, _ in _find(body, 'pegaprox_guest_tag_info', vmid='101')]
    assert tags == [f't{i:02d}' for i in range(mx._GUEST_TAGS_MAX)]


# --- guest pressure ----------------------------------------------------------------------

def test_guest_pressure_where_the_resources_list_it(api):
    psi = {'pressurecpusome': 12.5, 'pressurecpufull': 3.25, 'pressurememorysome': 0,
           'pressurememoryfull': 0, 'pressureiosome': 1.5, 'pressureiofull': 0.75}
    guests = [dict(GUESTS[0], **psi),                    # running
              dict(GUESTS[1]),                           # running, no pressure in its row
              dict(GUESTS[2], **psi)]                    # stopped
    api.set_manager('c1', _Pve('Testi', guests))
    body = _scrape(api)
    web = dict(cluster_id='c1', vmid='101', name='web01', node='pve1', type='vm')
    assert _one(body, 'pegaprox_guest_pressure_some_percent', resource='cpu', **web) == 12.5
    assert _one(body, 'pegaprox_guest_pressure_full_percent', resource='cpu', **web) == 3.25
    assert _one(body, 'pegaprox_guest_pressure_some_percent', resource='memory', **web) == 0
    assert _one(body, 'pegaprox_guest_pressure_full_percent', resource='io', **web) == 0.75
    assert _find(body, 'pegaprox_guest_pressure_some_percent', vmid='102') == []
    assert _find(body, 'pegaprox_guest_pressure_some_percent', vmid='103') == []


# --- node health -------------------------------------------------------------------------

def test_temperature_and_power_from_the_hardware_caches(api):
    c1 = api.set_manager('c1', _Hw('Testi', GUESTS, nodes=('pve1', 'pve2', 'pve3'),
                                   temps={'pve1': 61.25, 'pve3': 40.0},
                                   hw={'pve1': {'available': True, 'health': 'ok', 'power_w': 231.5},
                                       'pve2': {'available': False, 'power_w': 99.0},
                                       'pve3': {'available': True, 'health': 'ok'}}))
    body = _scrape(api)
    assert _one(body, 'pegaprox_node_temperature_celsius', cluster_id='c1', node='pve1') == 61.2
    assert _one(body, 'pegaprox_node_temperature_celsius', node='pve3') == 40
    assert _find(body, 'pegaprox_node_temperature_celsius', node='pve2') == []
    assert _one(body, 'pegaprox_node_power_watts', cluster_id='c1', node='pve1') == 231.5
    # a BMC that is not available says nothing, one without a reading neither
    assert _find(body, 'pegaprox_node_power_watts', node='pve2') == []
    assert _find(body, 'pegaprox_node_power_watts', node='pve3') == []
    # caches only: no SSH, no BMC, no per-node sensor read in a scrape
    assert not [p for p in c1.calls if 'sensors' in p or 'ipmi' in p or 'hardware' in p]


def test_node_pressure_from_the_newest_rrd_point(api, monkeypatch):
    c1 = api.set_manager('c1', _Hw('Testi', GUESTS, nodes=('pve1', 'pve2', 'pve3', 'pve4')))
    c1.answer(RRD.format('pve1'), _rrd(
        {'time': 2000, 'pressurecpusome': 4.5, 'pressurecpufull': 0.5, 'pressureiosome': 7.25,
         'pressureiofull': 2.0, 'pressurememorysome': 0.0, 'pressurememoryfull': 0.0},
        {'time': 2060, 'pressurecpusome': None},          # still being averaged
        None))
    c1.answer(RRD.format('pve2'), _rrd())                  # an RRD without pressure: before PVE 9
    c1.answer(RRD.format('pve4'), None, code=500)
    body = _scrape(api)
    pve1 = dict(cluster_id='c1', cluster='Testi', node='pve1')
    assert _one(body, 'pegaprox_node_pressure_some_percent', resource='cpu', **pve1) == 4.5
    assert _one(body, 'pegaprox_node_pressure_full_percent', resource='cpu', **pve1) == 0.5
    assert _one(body, 'pegaprox_node_pressure_some_percent', resource='io', **pve1) == 7.25
    assert _one(body, 'pegaprox_node_pressure_full_percent', resource='memory', **pve1) == 0
    assert _find(body, 'pegaprox_node_pressure_some_percent', node='pve2') == []
    assert _one(body, 'pegaprox_cluster_source_up', cluster_id='c1', source='node_pressure') == 0
    # pve3 is offline: not asked
    assert c1.count(RRD.format('pve3')) == 0

    # a minute on: pve2 had no pressure and is not asked again before the hour is up
    mx._pressure_reads.clear()
    c1.answer(RRD.format('pve4'), _rrd())
    body = _scrape(api)
    assert c1.count(RRD.format('pve1')) == 2 and c1.count(RRD.format('pve2')) == 1
    assert _one(body, 'pegaprox_cluster_source_up', source='node_pressure') == 1
    monkeypatch.setitem(mx._pressure_absent, ('c1', 'pve2'), time.time() - 1)
    mx._pressure_reads.clear()
    _scrape(api)
    assert c1.count(RRD.format('pve2')) == 2


def test_node_pressure_is_read_once_a_minute(api):
    c1 = api.set_manager('c1', _Hw('Testi', GUESTS))
    c1.answer(RRD.format('pve1'), _rrd({'time': 2000, 'pressurecpusome': 1.0}))
    for _ in range(3):
        body = _scrape(api)
    assert c1.count(RRD.format('pve1')) == 1
    assert _one(body, 'pegaprox_node_pressure_some_percent', node='pve1', resource='cpu') == 1


# --- node clocks -------------------------------------------------------------------------

def _clock_answers(c, **offsets):
    for node, off in offsets.items():
        c.answer(f'/nodes/{node}/time', {'time': int(time.time()) + off, 'timezone': 'UTC'})


def test_the_clock_offset_per_node(api):
    c1 = api.set_manager('c1', _Hw('Testi', GUESTS, nodes=('pve1', 'pve2')))
    _clock_answers(c1, pve1=30, pve2=0)
    body = _scrape(api)
    assert 29 <= _one(body, 'pegaprox_node_clock_offset_seconds', cluster_id='c1', node='pve1') <= 31
    assert -1 <= _one(body, 'pegaprox_node_clock_offset_seconds', node='pve2') <= 1
    assert _one(body, 'pegaprox_cluster_source_up', cluster_id='c1', source='clock') == 1
    # five minutes between reads, the scrapes in between take the last one
    _scrape(api)
    assert c1.count('/nodes/pve1/time') == 1


def test_a_node_that_does_not_answer_its_clock_is_left_out(api):
    c1 = api.set_manager('c1', _Hw('Testi', GUESTS, nodes=('pve1', 'pve2')))
    _clock_answers(c1, pve1=0)
    body = _scrape(api)
    assert len(_find(body, 'pegaprox_node_clock_offset_seconds', cluster_id='c1')) == 1
    assert _one(body, 'pegaprox_cluster_source_up', source='clock') == 0


def test_the_alert_and_the_exporter_share_one_clock_read(api):
    c1 = api.set_manager('c1', _Hw('Testi', GUESTS, nodes=('pve1',)))
    _clock_answers(c1, pve1=12)
    E.read_node_clocks('c1', c1)
    body = _scrape(api)
    assert c1.count('/nodes/pve1/time') == 1
    assert 11 <= _one(body, 'pegaprox_node_clock_offset_seconds', node='pve1') <= 13
    # and the other way round: what the scrape read is the alert's newest reading
    E._clock.clear()
    _clock_answers(c1, pve1=-7)
    _scrape(api)
    assert c1.count('/nodes/pve1/time') == 2 and -8 <= E.clock_reading('c1')['nodes']['pve1'][0] <= -6


def test_an_xcpng_pool_gets_no_clock_or_pressure_reads(api):
    api.set_manager('x1', _Xen('Xen', [], [
        {'vmid': 301, 'type': 'qemu', 'node': 'xcp1', 'name': 'xen-vm', 'status': 'running', 'tags': ['lab']}]))
    body = _scrape(api)
    assert _find(body, 'pegaprox_cluster_source_up', cluster_id='x1', source='clock') == []
    assert _find(body, 'pegaprox_node_clock_offset_seconds', cluster_id='x1') == []
    assert _one(body, 'pegaprox_guest_tag_info', cluster_id='x1', vmid='301', tag='lab') == 1


# --- dashboards and docs -----------------------------------------------------------------

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DASHBOARDS = ('pegaprox_grafana_dashboard_node_health_v1.0.json', 'pegaprox_grafana_dashboard_guests_by_tag_v1.0.json')


def _families():
    """Every family the exporter can write, from its HELP lines and the families written inline."""
    with open(os.path.join(ROOT, 'pegaprox', 'api', 'metrics_exporter.py'), encoding='utf-8') as fh:
        src = fh.read()
    return set(re.findall(r'# HELP (pegaprox_\w+)', src)) | {n for n, _t, _h in mx._ESTATE_FAMILIES + mx._HEALTH_FAMILIES}


@pytest.mark.parametrize('name', DASHBOARDS)
def test_the_dashboards_ask_only_for_series_the_exporter_writes(name):
    with open(os.path.join(ROOT, 'misc', 'grafana', name), encoding='utf-8') as fh:
        text = fh.read()
    dash = json.loads(text)
    assert '\u2014' not in text and '\u2013' not in text
    exprs = [t['expr'] for p in dash['panels'] for t in p.get('targets', [])]
    exprs += [v['query'] for v in dash['templating']['list']]
    used = {m for e in exprs for m in re.findall(r'\bpegaprox_\w+', e)}
    assert used and not used - _families(), sorted(used - _families())
    # what this change added is what they are for
    assert used & {n for n, _t, _h in mx._HEALTH_FAMILIES}
    for e in exprs:
        assert e.count('(') == e.count(')') and e.count('{') == e.count('}'), e
    ids = [p['gridPos'] for p in dash['panels']]
    assert all(g['x'] + g['w'] <= 24 for g in ids)


def test_the_dashboards_are_their_own_and_ship_with_updates():
    uids = set()
    for name in DASHBOARDS + ('pegaprox_grafana_dashboard_v1.1.json',):
        with open(os.path.join(ROOT, 'misc', 'grafana', name), encoding='utf-8') as fh:
            uids.add(json.load(fh)['uid'])
    assert len(uids) == 3
    with open(os.path.join(ROOT, 'version.json'), encoding='utf-8') as fh:
        shipped = json.load(fh)['update_files']
    assert all(f'misc/grafana/{n}' in shipped for n in DASHBOARDS)


def test_the_new_series_are_documented_with_the_others():
    with open(os.path.join(ROOT, 'misc', 'grafana', 'README.md'), encoding='utf-8') as fh:
        doc = fh.read()
    for name, _t, _h in mx._HEALTH_FAMILIES:
        assert f'`{name}`' in doc, name
    for name in DASHBOARDS:
        assert name in doc
    assert '\u2014' not in doc


# --- scale -------------------------------------------------------------------------------

def test_ten_thousand_guests_cost_no_extra_call(api):
    """What a scrape asks the cluster does not grow with the guests: the same paths for 2 and
    for 10 000 of them, and no path names a guest."""
    def estate(cid, n):
        guests = [{'vmid': 1000 + i, 'type': 'qemu' if i % 3 else 'lxc', 'node': f'pve{i % 4 + 1}',
                   'name': f'g{i}', 'status': 'running', 'tags': 'prod;web' if i % 2 else 'db',
                   'pressurecpusome': 1.0, 'pressureiosome': 0.5}
                  for i in range(n)]
        return api.set_manager(cid, _Hw('Testi', guests, nodes=('pve1', 'pve2', 'pve3', 'pve4')))
    small, big = estate('small', 2), estate('big', 10_000)
    body = _scrape(api)
    assert sorted(big.calls) == sorted(small.calls)
    assert not any(re.search(r'/(qemu|lxc)/\d+', p) for p in big.calls)
    assert len(_find(body, 'pegaprox_guest_tag_info', cluster_id='big')) == 15_000
    assert len(_find(body, 'pegaprox_guest_pressure_some_percent', cluster_id='big')) == 20_000
