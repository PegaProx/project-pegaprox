# -*- coding: utf-8 -*-
"""Unit tests for the #609 phase-2 manager hardware cache + cluster rollup.

These bind the real PegaProxManager methods onto a tiny fake carrying just the
cache + lock, so we exercise get_cached_node_hardware() + get_cluster_hw_rollup()
without constructing a whole manager (heavy, needs a live cluster).
"""
import threading
import time

from pegaprox.core.manager import PegaProxManager


class _FakeMgr:
    get_cached_node_hardware = PegaProxManager.get_cached_node_hardware
    get_cluster_hw_rollup = PegaProxManager.get_cluster_hw_rollup

    def __init__(self, cache):
        self._node_hw_cache = cache
        self._node_hw_lock = threading.Lock()


def _mk(now=None):
    now = now or time.time()
    return _FakeMgr({
        'pve1': {'summary': {'available': True, 'health': 'ok', 'bad': []}, 'ts': now},
        'pve2': {'summary': {'available': True, 'health': 'critical',
                             'bad': ['PSU2 fail', 'chassis intrusion']}, 'ts': now},
        'pve3': {'summary': {'available': False, 'reason': 'no ipmitool'}, 'ts': now},
        'pveOLD': {'summary': {'available': True, 'health': 'warning', 'bad': ['Fan2']},
                   'ts': now - 99999},  # stale
    })


def test_rollup_worst_health_and_counts():
    roll = _mk().get_cluster_hw_rollup()
    assert roll['health'] == 'critical'
    assert roll['available'] is True
    assert roll['checked'] == 2                       # pve1 + pve2 (pve3 unavail, pveOLD stale)
    assert roll['counts'] == {'ok': 1, 'warning': 0, 'critical': 1}
    assert len(roll['degraded']) == 1
    d = roll['degraded'][0]
    assert d['node'] == 'pve2' and d['health'] == 'critical' and 'PSU2 fail' in d['reasons']


def test_cached_getter_stale_and_missing():
    m = _mk()
    assert m.get_cached_node_hardware('pve2')['health'] == 'critical'
    assert m.get_cached_node_hardware('pveOLD') is None    # stale -> None
    assert m.get_cached_node_hardware('nope') is None       # missing -> None


def test_rollup_all_ok():
    now = time.time()
    m = _FakeMgr({'a': {'summary': {'available': True, 'health': 'ok', 'bad': []}, 'ts': now},
                  'b': {'summary': {'available': True, 'health': 'ok', 'bad': []}, 'ts': now}})
    roll = m.get_cluster_hw_rollup()
    assert roll['health'] == 'ok' and roll['checked'] == 2 and roll['degraded'] == []


def test_rollup_warning_only():
    now = time.time()
    m = _FakeMgr({'a': {'summary': {'available': True, 'health': 'warning', 'bad': ['Fan1']}, 'ts': now}})
    roll = m.get_cluster_hw_rollup()
    assert roll['health'] == 'warning' and roll['counts']['warning'] == 1
    assert roll['degraded'][0]['node'] == 'a'


def test_rollup_empty_or_unavailable_is_unknown():
    assert _FakeMgr({}).get_cluster_hw_rollup()['health'] == 'unknown'
    now = time.time()
    only_unavail = _FakeMgr({'x': {'summary': {'available': False, 'reason': 'no bmc'}, 'ts': now}})
    roll = only_unavail.get_cluster_hw_rollup()
    assert roll['health'] == 'unknown' and roll['available'] is False and roll['checked'] == 0
