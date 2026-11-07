"""An XCP-ng pool's balancer takes the settings the cluster balancer takes: dry run, the
enabled switch, excluded nodes, and Balance Now reaches it at all."""
import logging
import types
import time

import pytest

from pegaprox.core.xcpng import XcpngManager
from pegaprox.models.tasks import PegaProxConfig


@pytest.fixture
def pool(db, monkeypatch):
    import pegaprox.core.xcpng as xcpng_mod
    monkeypatch.setattr(xcpng_mod, 'time', types.SimpleNamespace(sleep=lambda s: None, time=time.time,
                                                                 monotonic=time.monotonic))
    x = object.__new__(XcpngManager)
    x.id, x.cluster_type = 'xcp1', 'xcpng'
    x.logger = logging.getLogger('test.xcpng_balancer')
    x.last_migration_log, x._vm_migration_cooldown = [], {}
    x._cached_vms = [{'vmid': 7, 'name': 'app', 'node': 'h1', 'status': 'running', 'mem': 1},
                     {'vmid': 8, 'name': 'db', 'node': 'h1', 'status': 'running', 'mem': 2}]
    x.get_balancing_excluded_vms = lambda: []
    x.check_vm_storage_type = lambda node, vmid: 'shared'
    x.get_node_status = lambda: {'h1': {'score': 150.0, 'cpu_percent': 70.0, 'mem_percent': 80.0},
                                 'h2': {'score': 40.0, 'cpu_percent': 20.0, 'mem_percent': 20.0},
                                 'h3': {'score': 90.0, 'cpu_percent': 40.0, 'mem_percent': 50.0}}
    x.sent = []
    x.migrate_vm_manual = lambda *a, **k: x.sent.append((a[1], k['target_node'])) or {'success': True}
    def configure(**over):
        x.config = PegaProxConfig({'name': 'pool', 'host': 'h', 'user': 'u', 'migration_threshold': 30,
                                   'auto_migrate': True, **over})
        return x
    x.configure = configure
    return x


def test_dry_run_moves_nothing_and_says_what_it_would_do(pool, db):
    pool.configure(dry_run=True)
    XcpngManager.run_balance_check(pool)
    assert pool.sent == []
    assert pool._vm_migration_cooldown == {}
    row = db.list_balancer_moves('xcp1')[0]
    assert (row['status'], row['source_node'], row['target_node']) == ('dry_run', 'h1', 'h2')


def test_without_dry_run_it_still_moves(pool):
    pool.configure()
    XcpngManager.run_balance_check(pool)
    assert pool.sent and pool.sent[0][1] == 'h2'


def test_an_excluded_node_is_neither_source_nor_target(pool):
    pool.configure(excluded_nodes=['h2'])
    XcpngManager.run_balance_check(pool)
    assert pool.sent and all(target == 'h3' for _, target in pool.sent)

    pool.sent.clear()
    pool._vm_migration_cooldown.clear()
    pool.configure(excluded_nodes=['h1'])
    XcpngManager.run_balance_check(pool)
    assert pool.sent == []


def test_balance_now_runs_and_is_recorded_as_manual(pool, db):
    pool.configure(auto_migrate=False)
    XcpngManager.run_balance_check(pool, force=True)
    assert pool.sent
    row = db.list_balancer_moves('xcp1')[0]
    assert row['status'] == 'success'
    assert row['details']['manual'] is True


@pytest.mark.parametrize('enabled, auto, runs', [(True, True, 1), (False, True, 0), (True, False, 0)])
def test_the_loop_leaves_a_disabled_pool_alone(pool, monkeypatch, enabled, auto, runs):
    import pegaprox.core.xcpng as xcpng_mod
    monkeypatch.setattr(xcpng_mod.ha, 'is_active', lambda: True)
    pool.configure(enabled=enabled, auto_migrate=auto, check_interval=1)
    stopped = []
    pool.stop_event = types.SimpleNamespace(is_set=lambda: bool(stopped), wait=lambda t=None: stopped.append(1))
    pool._session, pool._last_balance_check, pool._last_reconnect_attempt = object(), 0, 0
    monkeypatch.setattr(XcpngManager, 'is_connected', True, raising=False)
    pool._refresh_cache = pool._poll_tasks = lambda: None
    calls = []
    pool.run_balance_check = lambda: calls.append(1)
    XcpngManager._run_loop(pool)
    assert len(calls) == runs
