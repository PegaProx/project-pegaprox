"""The cross-hypervisor migration registry has to forget finished migrations.

globals._xhm_migrations is written on every start and nothing ever removed from
it, so every migration a server had run stayed resident for the process lifetime
— each holding its own unbounded log — and GET /api/xhm/migrations re-authorized
all of them, one by one, on every call. Running migrations are never touched. MK
"""
from datetime import datetime, timedelta

import pytest

import pegaprox.api.xhm as xhm
import pegaprox.core.xhm as core_xhm
import pegaprox.globals as ppglobals


def _task(mid, status='completed', age_hours=0.0):
    t = core_xhm.XHMigrationTask(
        mid=mid, direction='pve_to_xcpng', source_cluster='c1', source_node='n1',
        source_vmid=100, target_cluster='c2', target_node='n2', target_storage='local')
    t.status = status
    if status in ('completed', 'failed'):
        t.completed_at = datetime.now() - timedelta(hours=age_hours)
    return t


@pytest.fixture
def registry():
    ppglobals._xhm_migrations.clear()
    try:
        yield ppglobals._xhm_migrations
    finally:
        ppglobals._xhm_migrations.clear()


def test_a_running_migration_is_never_pruned(registry):
    registry['running'] = _task('running', status='running')
    registry['old'] = _task('old', age_hours=48)

    xhm._prune_finished_migrations()

    assert sorted(registry) == ['running']


def test_a_recent_result_is_kept_for_the_ui(registry):
    registry['fresh'] = _task('fresh', age_hours=1)
    registry['stale'] = _task('stale', age_hours=48)
    registry['failed_fresh'] = _task('failed_fresh', status='failed', age_hours=0.5)

    xhm._prune_finished_migrations()

    assert sorted(registry) == ['failed_fresh', 'fresh']


def test_a_burst_cannot_outrun_the_time_window(registry, monkeypatch):
    """All within the retention window, so only the count cap can bound them."""
    monkeypatch.setattr(xhm, '_XHM_MAX_FINISHED', 5)
    for i in range(20):
        registry[f'm{i:02d}'] = _task(f'm{i:02d}', age_hours=i * 0.01)

    xhm._prune_finished_migrations()

    assert len(registry) == 5
    assert 'm00' in registry, 'the newest results must be the ones kept'
    assert 'm19' not in registry


def test_an_empty_registry_is_fine(registry):
    xhm._prune_finished_migrations()

    assert registry == {}


def test_the_per_migration_log_is_a_rolling_window():
    t = _task('logtest', status='running')

    for i in range(core_xhm._MAX_LOG_LINES + 250):
        t.log(f'line {i}')

    assert len(t.log_lines) == core_xhm._MAX_LOG_LINES
    assert t.log_lines[-1].endswith(f'line {core_xhm._MAX_LOG_LINES + 249}')
    assert t.to_dict()['log'][-1] == t.log_lines[-1]
