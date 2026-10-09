"""A slot of PVE's rrddata without a sample is a gap in the chart, not a measured 0.

PVE leaves a value out of an rrddata slot it has no sample for: the guest was stopped
(pvestatd writes U for cpu, mem, net and disk then), the node or pvestatd was down. The
guest and node series used to turn that into 0 on the server and again in LineChart, so an
outage looked like an idle machine. Now the server sends null for it and LineChart keeps the
null, with spanGaps off. The drawing itself is checked at runtime in test_lists_ui.py.
MK Oct 2026
"""
import logging
import math
import types

import pytest

from pegaprox.core.manager import PegaProxManager, _rrd_share, _rrd_value


class _Resp:
    status_code = 200

    def __init__(self, rows):
        self.rows = rows
        self.text = ''

    def json(self):
        return {'data': self.rows}


class _Session:
    def __init__(self, owner):
        self.owner = owner

    def get(self, url, params=None, timeout=None):
        self.owner.urls.append((url, params))
        return _Resp(self.owner.rows)


def _pve(rows):
    m = types.SimpleNamespace(is_connected=True, host='pve.test', api_port=8006, rows=rows, urls=[],
                              logger=logging.getLogger('test_chart_gaps'))
    m._create_session = lambda: _Session(m)
    return m


GUEST = [
    {'time': 1000, 'cpu': 0.25, 'mem': 1073741824, 'maxmem': 4294967296, 'diskread': 1536.5,
     'diskwrite': 2048, 'netin': 100, 'netout': 50, 'maxcpu': 2},
    # stopped: PVE writes U for everything that is measured, the limits stay
    {'time': 1060, 'maxmem': 4294967296, 'maxcpu': 2},
    # running and idle: real zeros
    {'time': 1120, 'cpu': 0, 'mem': 0, 'maxmem': 4294967296, 'diskread': 0, 'diskwrite': 0,
     'netin': 0, 'netout': 0, 'maxcpu': 2},
]


def test_a_guest_slot_without_a_sample_is_none_and_a_zero_stays_zero():
    m = _pve(GUEST)
    res = PegaProxManager.get_vm_rrd(m, 'pve1', 100, 'qemu', 'hour')
    assert res['success'], res
    d = res['data']
    assert d['timestamps'] == [1000, 1060, 1120]
    assert d['metrics'] == {
        'cpu': [25.0, None, 0.0],
        'memory': [25.0, None, 0.0],
        'disk_read': [1536.5, None, 0.0],
        'disk_write': [2048.0, None, 0.0],
        'net_in': [100.0, None, 0.0],
        'net_out': [50.0, None, 0.0],
    }
    assert m.urls == [('https://pve.test:8006/api2/json/nodes/pve1/qemu/100/rrddata', {'timeframe': 'hour'})]


def test_psi_is_found_when_the_first_slot_is_a_gap():
    # a year of a guest that was off at first: the series must not vanish for that
    rows = [{'time': 1000}, {'time': 1060, 'cpu': 0.1, 'mem': 1, 'maxmem': 2, 'pressurecpusome': 1.5,
                             'pressurecpufull': 0, 'pressureiosome': 12.25}]
    d = PegaProxManager.get_vm_rrd(_pve(rows), 'pve1', 101, 'lxc', 'year')['data']['metrics']
    assert d['pressurecpusome'] == [None, 1.5]
    assert d['pressurecpufull'] == [None, 0.0]
    assert d['pressureiosome'] == [None, 12.25]
    # a series no slot has stays away, as before
    assert 'pressurememorysome' not in d and 'pressureiofull' not in d
    assert d['memory'] == [None, 50.0]


def test_a_node_slot_without_a_sample_is_none():
    rows = [
        {'time': 1000, 'cpu': 0.5, 'iowait': 0.02, 'memused': 8, 'memtotal': 32, 'swapused': 1,
         'swaptotal': 4, 'loadavg': 1.25, 'netin': 2048, 'netout': 1024, 'rootused': 10, 'roottotal': 100},
        {'time': 1060},
        # a node without swap has 0% of it, which is a real value
        {'time': 1120, 'cpu': 0, 'iowait': 0, 'memused': 0, 'memtotal': 32, 'swapused': 0,
         'swaptotal': 0, 'loadavg': 0, 'netin': 0, 'netout': 0, 'rootused': 10, 'roottotal': 0},
    ]
    d = PegaProxManager.get_node_rrddata(_pve(rows), 'pve1', 'day')
    assert d['timestamps'] == [1000, 1060, 1120]
    assert d['metrics'] == {
        'cpu': [50.0, None, 0.0], 'iowait': [2.0, None, 0.0], 'memory': [25.0, None, 0.0],
        'swap': [25.0, None, 0], 'loadavg': [1.25, None, 0.0], 'net_in': [2.0, None, 0.0],
        'net_out': [1.0, None, 0.0], 'rootfs': [10.0, None, 0],
    }


@pytest.mark.parametrize('value,expected', [
    (None, None), (True, None), ('x', None), (float('nan'), None), (float('inf'), None),
    (0, 0.0), ('0.5', 0.5), (1.23456, 1.23),
])
def test_one_value(value, expected):
    got = _rrd_value({'k': value}, 'k')
    assert got == expected or (expected is None and got is None)
    assert _rrd_value({}, 'k') is None


def test_one_share():
    assert _rrd_share({'u': 1, 't': 4}, 'u', 't') == 25.0
    assert _rrd_share({'t': 4}, 'u', 't') is None
    assert _rrd_share({'u': 1}, 'u', 't') is None
    assert _rrd_share({'u': 1, 't': 0}, 'u', 't', no_total=0) == 0


def test_the_route_sends_null(api, seed):
    admin = api.as_user(seed.user('root', role='admin'))
    m = api.make_fake_manager('cluster_1')
    m.get_vm_rrd = lambda node, vmid, vm_type, tf: PegaProxManager.get_vm_rrd(_pve(GUEST), node, vmid, vm_type, tf)
    api.set_manager('cluster_1', m)
    r = admin.get('/api/clusters/cluster_1/vms/pve1/qemu/100/rrd/day')
    assert r.status_code == 200, r.data
    assert b'"cpu":[25.0,null,0.0]' in r.data.replace(b' ', b'')
    assert not any(isinstance(v, float) and math.isnan(v) for v in r.get_json()['metrics']['cpu'] if v is not None)
