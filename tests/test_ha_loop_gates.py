"""A standby keeps its background loops but lets none of them act (#625).

The standby's database is a copy of the active's: same schedules, same alert rules,
same replication jobs, same SIEM targets. Any loop that acted on it would do the
active's work a second time - a second snapshot, a second mail, a second failover.
So every loop that acts asks ha.is_active() first, and keeps sleeping when the
answer is no.

Two halves. The source half reads each gated function's AST and proves the work
calls sit behind the gate: inside `if ha.is_active()`, or after an
`if not ha.is_active(): return/continue/break` in an enclosing block. A gate in the
wrong function, or below the work it should hold back, fails there. The behaviour
half drives the functions for real against a state file in tmp_path, once as a
standby and once as an active instance, and records what they called.

MK Sep 2026
"""
import ast
import json
import os
import time
import types
from unittest.mock import MagicMock

import pytest

from pegaprox.core import ha

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# --- source half ---------------------------------------------------------------

# (file, function, calls that must sit behind the gate, calls of which at least one
# must not - the sleep or wait that keeps the loop at its pace on a standby)
GATES = [
    ('pegaprox/api/schedules.py', 'check_schedules',
     ['load_schedules', 'execute_scheduled_action', 'check_scheduled_updates',
      'cleanup_deleted_scripts', 'cleanup_orphaned_excluded_vms'], ['_wait_a_minute']),
    ('pegaprox/background/scheduler.py', 'scheduler_loop', ['run_scheduled_tasks'], ['sleep']),
    ('pegaprox/background/alerts.py', 'alert_check_loop',
     ['check_and_send_alerts', 'process_alert_lifecycle', 'check_node_status_transitions',
      'check_update_available_alert'], ['sleep']),
    ('pegaprox/background/password_expiry.py', 'password_expiry_check_loop',
     ['check_password_expiry'], ['sleep']),
    ('pegaprox/background/cross_cluster_lb.py', 'run_cross_cluster_balance_check',
     ['get_db', 'compute_cluster_score', 'find_migration_candidate', 'create_api_token',
      'remote_migrate_vm', 'log_audit'], []),
    # the jobs query is the gate here; a standby gets no jobs, so nothing below it starts
    ('pegaprox/background/cross_cluster_replication.py', '_xcrepl_loop', ['query'], ['sleep']),
    ('pegaprox/background/site_recovery.py', 'heartbeat_loop', ['_heartbeat_check'], ['sleep']),
    ('pegaprox/background/site_recovery.py', 'recover_orphan_runs',
     ['get_db', 'query', 'execute', 'log_audit'], []),
    ('pegaprox/api/storage.py', 'run_auto_storage_balance',
     ['_create_session', 'acquire', 'post', 'save_storage_clusters'], ['sleep']),
    ('pegaprox/api/drift.py', '_scanner_loop', ['_scan_cluster'], ['sleep']),
    ('pegaprox/api/multi_sdn.py', '_msdn_scanner_loop', ['_msdn_scan_once'], ['sleep']),
    ('pegaprox/api/snapshots.py', '_scheduler_loop', ['_execute_policy'], ['sleep']),
    ('pegaprox/core/manager.py', 'PegaProxManager.run_balance_check',
     ['get_node_status', 'find_migration_candidate', 'migrate_vm'], []),
    ('pegaprox/core/manager.py', 'PegaProxManager.connect_to_proxmox',
     ['_try_create_api_token'], []),
    ('pegaprox/core/manager.py', 'PegaProxManager.start_ha_monitor',
     ['_ha_discover_fallback_hosts', 'connect_to_proxmox', 'Thread'], []),
    ('pegaprox/core/xcpng.py', 'XcpngManager._run_loop', ['run_balance_check'], ['wait']),
    # the live view (#625 v2): managers run on a standby, so what they reach that acts
    # or writes a synced table is gated where it happens, not only at the call site.
    # Behaviour in tests/test_ha_v2_managers.py.
    ('pegaprox/core/config.py', 'save_config', ['get_db', 'save_cluster'], []),
    ('pegaprox/core/manager.py', 'PegaProxManager._try_create_api_token',
     ['post', 'update_cluster', 'save_config'], []),
    ('pegaprox/core/manager.py', 'PegaProxManager.stop_ha_monitor', ['Thread'], ['join']),
    ('pegaprox/core/manager.py', 'PegaProxManager._ha_monitor_loop',
     ['_ha_check_nodes', '_ha_update_fallback_hosts'], []),
    ('pegaprox/core/manager.py', 'PegaProxManager._ha_recovery_worker',
     ['_ha_acquire_recovery_lock', '_ha_ssh_stop_vms_on_node', '_ha_write_poison_pill',
      '_ha_fence_node', '_ha_start_vm_on_node',
      # the claim write and the fence that is read back (S6)
      '_ha_recovery_allowed', '_ha_fence_outside'], []),
    ('pegaprox/core/manager.py', 'PegaProxManager.get_efficient_snapshots',
     ['_node_ssh_exec', 'update_efficient_snapshot_disks', 'update_efficient_snapshot_status'],
     ['get_efficient_snapshots']),
    ('pegaprox/core/xcpng.py', 'XcpngManager.run_balance_check',
     ['get_node_status', 'find_migration_candidate', '_do_balance_migrate'], []),
    ('pegaprox/background/metrics.py', 'collect_metrics_snapshot', ['run_per_node'],
     ['get_vm_resources']),
    # the scrape reads over the API in every role; only the SSH-backed Ceph probe is gated
    ('pegaprox/api/metrics_exporter.py', 'prometheus_metrics', ['get_ceph_health_summary'],
     ['get_node_status', 'get_vm_resources']),
]

# gated right at the top: the first statement after the docstring is the early return
TOP_GATED = {'run_cross_cluster_balance_check', 'recover_orphan_runs',
             'PegaProxManager.run_balance_check', 'PegaProxManager.start_ha_monitor',
             'save_config', 'PegaProxManager._try_create_api_token',
             'PegaProxManager._ha_recovery_worker', 'XcpngManager.run_balance_check'}

# per host, never behind the gate
UNGATED = {
    'alert_check_loop': ['_periodic_session_cleanup', '_periodic_audit_cleanup'],
    # drift_events is a local table, a standby collapses its own repeats and prunes its own
    '_scanner_loop': ['_collapse_repeats', '_prune_events'],
    '_worker_loop': ['get', 'task_done'],
}

_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)


def _parse(rel):
    with open(os.path.join(ROOT, rel), encoding='utf-8') as fh:
        return ast.parse(fh.read())


def _find(tree, qualname):
    scope, node = tree.body, None
    for part in qualname.split('.'):
        node = next((n for n in scope if isinstance(n, (ast.FunctionDef, ast.ClassDef))
                     and n.name == part), None)
        assert node is not None, f'{qualname} is gone - update GATES'
        scope = node.body
    return node


def _is_active_call(node):
    return (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == 'is_active' and isinstance(node.func.value, ast.Name)
            and node.func.value.id == 'ha')


def _holds_on_active(test):
    """`ha.is_active()` or `x and ha.is_active()` - true only when this instance acts."""
    if _is_active_call(test):
        return True
    return (isinstance(test, ast.BoolOp) and isinstance(test.op, ast.And)
            and any(_holds_on_active(v) for v in test.values))


def _exits_on_standby(stmt):
    """`if not ha.is_active(): ...` ending in return, continue or break."""
    return (isinstance(stmt, ast.If) and not stmt.orelse
            and isinstance(stmt.test, ast.UnaryOp) and isinstance(stmt.test.op, ast.Not)
            and _is_active_call(stmt.test.operand)
            and isinstance(stmt.body[-1], (ast.Return, ast.Continue, ast.Break)))


def _own_nodes(func):
    """Every node of `func` with its parent, not descending into nested scopes."""
    parents, todo = {}, [func]
    while todo:
        node = todo.pop()
        for child in ast.iter_child_nodes(node):
            parents[child] = node
            if not isinstance(child, _SCOPES):
                todo.append(child)
    return parents


def _callee(call):
    f = call.func
    return f.id if isinstance(f, ast.Name) else getattr(f, 'attr', None)


def _gated(node, parents, func):
    while node is not func:
        parent = parents[node]
        if isinstance(parent, (ast.If, ast.IfExp)) and _holds_on_active(parent.test):
            inside = parent.body if isinstance(parent, ast.If) else [parent.body]
            if node in inside:
                return True
        for field in ('body', 'orelse', 'finalbody'):
            block = getattr(parent, field, None)
            if isinstance(block, list) and node in block:
                if any(_exits_on_standby(s) for s in block[:block.index(node)]):
                    return True
        node = parent
    return False


def _calls(parents, name):
    return [n for n in parents if isinstance(n, ast.Call) and _callee(n) == name]


@pytest.mark.parametrize('rel,qualname,work,keep', GATES, ids=[g[1] for g in GATES])
def test_the_work_sits_behind_the_gate(rel, qualname, work, keep):
    tree = _parse(rel)
    func = _find(tree, qualname)
    parents = _own_nodes(func)

    assert any(_is_active_call(n) for n in parents), f'{qualname} never asks ha.is_active()'
    for name in work:
        calls = _calls(parents, name)
        assert calls, f'{qualname} no longer calls {name} - update GATES'
        for call in calls:
            assert _gated(call, parents, func), \
                f'{qualname}: {name}() on line {call.lineno} runs on a standby too'
    for name in keep:
        calls = _calls(parents, name)
        assert any(not _gated(c, parents, func) for c in calls), \
            f'{qualname}: every {name}() is behind the gate, so a standby spins instead of waiting'
    for name in UNGATED.get(qualname, []):
        calls = _calls(parents, name)
        assert calls and not any(_gated(c, parents, func) for c in calls), \
            f'{qualname}: {name}() is per host and must run on a standby as well'


@pytest.mark.parametrize('qualname', sorted(TOP_GATED))
def test_top_gated_functions_return_before_anything_else(qualname):
    rel = next(g[0] for g in GATES if g[1] == qualname)
    func = _find(_parse(rel), qualname)
    body = func.body
    if isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], 'value', None), ast.Constant):
        body = body[1:]
    first = body[0]
    assert _exits_on_standby(first) and isinstance(first.body[-1], ast.Return), \
        f'{qualname} does something before it asks whether this instance may act'


@pytest.mark.parametrize('rel', sorted({g[0] for g in GATES}))
def test_ha_is_the_pegaprox_module(rel):
    """`ha` has to be pegaprox.core.ha, bound at module level, or the gate asks the
    wrong thing (manager.py is full of PVE HA code)."""
    tree = _parse(rel)
    bound = [n for n in tree.body if isinstance(n, ast.ImportFrom)
             and n.module == 'pegaprox.core' and any(a.name == 'ha' and a.asname is None
                                                     for a in n.names)]
    assert bound, f'{rel} does not import ha from pegaprox.core at module level'
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id == 'ha':
            assert isinstance(node.ctx, ast.Load), f'{rel}:{node.lineno} rebinds ha'
        if isinstance(node, ast.arg):
            assert node.arg != 'ha', f'{rel}:{node.lineno} takes a parameter named ha'


def test_the_gate_check_itself_tells_gated_from_ungated():
    """Counterproof for the walker: the same shapes without the gate must fail it."""
    src = '''
def loop():
    while True:
        try:
            if ha.is_active():
                work_a()
            work_b()
            if not ha.is_active():
                continue
            work_c()
        except Exception:
            pass
        sleep(1)

def other():
    if not ha.is_active():
        pass
    work_d()
    x = work_e() if ha.is_active() else None
    if something or ha.is_active():
        work_f()
'''
    tree = ast.parse(src)
    loop, other = tree.body
    p1, p2 = _own_nodes(loop), _own_nodes(other)
    gated = {_callee(c): _gated(c, p1, loop) for c in p1 if isinstance(c, ast.Call)}
    gated.update({_callee(c): _gated(c, p2, other) for c in p2 if isinstance(c, ast.Call)})
    assert gated['work_a'] and gated['work_c'] and gated['work_e']
    assert not gated['work_b'] and not gated['sleep']
    # no exit in the body, and an `or` lets a standby through
    assert not gated['work_d'] and not gated['work_f']


# --- behaviour half ------------------------------------------------------------

A = 'a' * 32
B = 'b' * 32


class _Stop(BaseException):
    """Ends a loop after one pass. The loops catch Exception, not this."""


class _Spin(BaseException):
    """A loop that asks the gate again and again without sleeping in between."""


@pytest.fixture
def role(tmp_path, monkeypatch, db):
    """Put this process into a role through a real state file in tmp_path.

    Takes the throwaway db as well: storage.py and friends read the database when
    they are first imported, and without it that read creates config/pegaprox.db."""
    monkeypatch.setattr(ha, 'STATE_FILE', str(tmp_path / 'ha_state.json'))
    monkeypatch.setattr(ha, 'AES_KEY_FILE', str(tmp_path / 'aes.key'))
    monkeypatch.setattr(ha, 'KNOWN_HOSTS_FILE', str(tmp_path / 'known_hosts'))
    monkeypatch.setattr(ha, 'BRANDING_DIR', str(tmp_path / 'branding'))
    restarts = []
    monkeypatch.setattr(ha, 'restart_process', restarts.append)

    # a gate that `continue`s past the sleep turns a loop into a spin; fail instead of hanging
    real_is_active, asked = ha.is_active, []

    def counted():
        asked.append(1)
        if len(asked) > 50:
            raise _Spin('ha.is_active() asked 50 times in one pass - the loop is spinning')
        return real_is_active()
    monkeypatch.setattr(ha, 'is_active', counted)
    ha.reset_for_tests()

    def set_role(name):
        peer = {'instance_id': B if name == 'active' else A, 'url': 'https://peer.example:5000',
                'fingerprint': '', 'secret_out': 'x' * 43, 'secret_in_hash': 'y' * 64}
        with open(ha.STATE_FILE, 'w', encoding='utf-8') as fh:
            json.dump({'role': name, 'epoch': 2, 'instance_id': A if name == 'active' else B,
                       'peer': None if name == 'standalone' else peer}, fh)
        ha.reset_for_tests()
        assert ha.role() == name
        return name

    yield set_role
    ha.reset_for_tests()
    assert restarts == []


def _drive(monkeypatch, module, loop, sleeps=0):
    """Run `loop` for one pass. The sleep after `sleeps` sleeps raises _Stop."""
    naps = []

    def nap(seconds):
        naps.append(seconds)
        if len(naps) > sleeps:
            raise _Stop()
    monkeypatch.setattr(module, 'time', types.SimpleNamespace(
        sleep=nap, time=time.time, monotonic=time.monotonic))
    with pytest.raises(_Stop):
        loop()
    return naps


def _recorder(monkeypatch, module, *names, ret=None):
    calls = []
    for name in names:
        monkeypatch.setattr(module, name,
                            lambda *a, _n=name, **k: calls.append(_n) or ret)
    return calls


ROLES = ['standby', 'active', 'standalone']


@pytest.mark.parametrize('which', ROLES)
def test_alert_loop_keeps_only_the_local_cleanup_on_a_standby(which, role, monkeypatch):
    import pegaprox.background.alerts as alerts
    role(which)
    calls = _recorder(monkeypatch, alerts, 'check_and_send_alerts', 'process_alert_lifecycle',
                      'check_node_status_transitions', 'check_update_available_alert',
                      '_periodic_session_cleanup', '_periodic_audit_cleanup')
    monkeypatch.setattr(alerts, '_alert_running', False)

    _drive(monkeypatch, alerts, alerts.alert_check_loop)

    if which == 'standby':
        assert calls == ['_periodic_session_cleanup', '_periodic_audit_cleanup']
    else:
        assert calls == ['check_and_send_alerts', 'process_alert_lifecycle',
                         'check_node_status_transitions', 'check_update_available_alert',
                         '_periodic_session_cleanup', '_periodic_audit_cleanup']


@pytest.mark.parametrize('which', ROLES)
def test_scheduled_actions_tick_waits_on_a_standby(which, role, monkeypatch):
    import pegaprox.api.schedules as sched
    role(which)
    calls = _recorder(monkeypatch, sched, 'check_scheduled_updates', 'execute_scheduled_action',
                      'cleanup_deleted_scripts', 'cleanup_orphaned_excluded_vms')
    monkeypatch.setattr(sched, 'load_schedules',
                        lambda: calls.append('load_schedules') or {'actions': []})
    monkeypatch.setattr(sched, '_scheduler_running', True)

    naps = _drive(monkeypatch, sched, sched.check_schedules)

    assert naps == [1]  # it sleeps either way, it does not spin
    if which == 'standby':
        assert calls == []
    else:
        assert calls[:2] == ['load_schedules', 'check_scheduled_updates']


@pytest.mark.parametrize('module_name,loop_name,flag,work', [
    pytest.param('pegaprox.background.scheduler', 'scheduler_loop', '_scheduler_running',
                 'run_scheduled_tasks', id='scheduled-tasks'),
    pytest.param('pegaprox.background.password_expiry', 'password_expiry_check_loop',
                 '_password_expiry_running', 'check_password_expiry', id='password-expiry'),
    pytest.param('pegaprox.background.site_recovery', 'heartbeat_loop', '_heartbeat_running',
                 '_heartbeat_check', id='sr-heartbeat'),
    pytest.param('pegaprox.api.multi_sdn', '_msdn_scanner_loop', '_msdn_scanner_running',
                 '_msdn_scan_once', id='multi-sdn'),
])
@pytest.mark.parametrize('which', ROLES)
def test_single_call_loops(which, module_name, loop_name, flag, work, role, monkeypatch):
    import importlib
    module = importlib.import_module(module_name)
    role(which)
    calls = _recorder(monkeypatch, module, work)
    monkeypatch.setattr(module, flag, True)

    naps = _drive(monkeypatch, module, getattr(module, loop_name))

    assert len(naps) == 1
    assert calls == ([] if which == 'standby' else [work])


@pytest.mark.parametrize('which', ROLES)
def test_drift_scanner_scans_nothing_on_a_standby(which, role, monkeypatch):
    import pegaprox.api.drift as drift
    role(which)
    scanned = []
    monkeypatch.setattr(drift, '_scan_cluster', lambda cid, **kw: scanned.append(cid))
    monkeypatch.setattr(drift, 'cluster_managers', {'c1': object(), 'c2': object()})
    monkeypatch.setattr(drift, '_scanner_running', True)

    _drive(monkeypatch, drift, drift._scanner_loop)

    assert scanned == ([] if which == 'standby' else ['c1', 'c2'])


@pytest.mark.parametrize('which', ROLES)
def test_snapshot_policies_do_not_fire_on_a_standby(which, role, monkeypatch):
    import pegaprox.api.snapshots as snaps
    role(which)
    fake_db = MagicMock()
    fake_db.conn.cursor.return_value.fetchall.return_value = [{'id': 'p1'}, {'id': 'p2'}]
    monkeypatch.setattr(snaps, 'get_db', lambda: fake_db)
    monkeypatch.setattr(snaps, '_row_to_policy', dict)
    monkeypatch.setattr(snaps, '_is_due', lambda p: True)
    ran = []
    monkeypatch.setattr(snaps, '_execute_policy', ran.append)
    monkeypatch.setattr(snaps, '_scheduler_running', True)

    _drive(monkeypatch, snaps, snaps._scheduler_loop)

    assert ran == ([] if which == 'standby' else ['p1', 'p2'])


@pytest.mark.parametrize('which', ROLES)
def test_replication_jobs_are_not_even_looked_at_on_a_standby(which, role, monkeypatch):
    import pegaprox.background.cross_cluster_replication as xcrepl
    role(which)
    queried, claimed = [], []
    fake_db = MagicMock()
    fake_db.query.side_effect = lambda *a: queried.append(a) or [
        {'id': 'j1', 'vmid': 100, 'schedule': '0 */6 * * *', 'last_run': '',
         'source_cluster': 'c1', 'target_cluster': 'c2'}]
    monkeypatch.setattr(xcrepl, 'get_db', lambda: fake_db)
    # the claim is where a job would start; refusing it keeps the real handler out of the test
    monkeypatch.setattr(xcrepl, '_claim_job', lambda jid: claimed.append(jid) and False)
    monkeypatch.setattr(xcrepl, '_xcrepl_running', False)

    _drive(monkeypatch, xcrepl, xcrepl._xcrepl_loop)

    if which == 'standby':
        assert queried == [] and claimed == []
    else:
        assert len(queried) == 1 and claimed == ['j1']


@pytest.mark.parametrize('which', ROLES)
def test_storage_balancer_sleeps_and_skips_on_a_standby(which, role, monkeypatch):
    import pegaprox.api.storage as storage
    role(which)
    lock = MagicMock()
    monkeypatch.setattr(storage, '_storage_config_lock', lock)

    # the first sleep opens the pass, the second one ends it
    naps = _drive(monkeypatch, storage, storage.run_auto_storage_balance, sleeps=1)

    assert naps == [60, 60]
    assert lock.__enter__.called == (which != 'standby')


@pytest.mark.parametrize('which', ROLES)
def test_siem_worker_forwards_this_instances_audit_trail_in_every_role(which, role, monkeypatch):
    """The standby's audit rows (logins, failed logins, promotion) exist nowhere else,
    so they are forwarded on a standby too. Nothing is sent twice: audit_log is not
    part of the sync."""
    import pegaprox.api.siem as siem
    role(which)

    class _Queue:
        def __init__(self, items):
            self.items, self.done = list(items), 0

        def get(self, timeout=None):
            if not self.items:
                raise _Stop()
            return self.items.pop(0)

        def task_done(self):
            self.done += 1

    q = _Queue([{'action': f'e{i}'} for i in range(5)])
    monkeypatch.setattr(siem, '_queue', q)
    monkeypatch.setattr(siem, '_worker_running', True)
    monkeypatch.setattr(siem, '_list_enabled', lambda: [{'id': 't1', 'type': 'generic'}])
    sent = []
    monkeypatch.setattr(siem, '_deliver_one', lambda t, e: sent.append(e['action']))

    with pytest.raises(_Stop):
        siem._worker_loop()

    assert q.items == [] and q.done == 5
    assert sent == ['e0', 'e1', 'e2', 'e3', 'e4']


@pytest.mark.parametrize('which', ROLES)
def test_xcpng_pool_loop_refreshes_but_does_not_balance_on_a_standby(which, role):
    from pegaprox.core.xcpng import XcpngManager
    role(which)
    calls = []

    class _Event:
        def is_set(self):
            return False

        def wait(self, timeout):
            raise _Stop()

    # not logged in yet, as at boot: the loop logs in first
    fake = types.SimpleNamespace(
        stop_event=_Event(), is_connected=True, _session=None, logger=MagicMock(), last_run=None,
        config=types.SimpleNamespace(check_interval=300, auto_migrate=True),
        _last_balance_check=0, _last_reconnect_attempt=0,
        connect=lambda: calls.append('connect'),
        _refresh_cache=lambda: calls.append('refresh'),
        _poll_tasks=lambda: calls.append('poll'),
        run_balance_check=lambda: calls.append('balance'))

    with pytest.raises(_Stop):
        XcpngManager._run_loop(fake)

    expected = ['connect', 'refresh', 'poll']
    assert calls == (expected if which == 'standby' else expected + ['balance'])


# functions gated at their top

@pytest.mark.parametrize('which', ROLES)
def test_cross_cluster_balance_does_nothing_on_a_standby(which, role, monkeypatch):
    import pegaprox.background.cross_cluster_lb as xclb
    role(which)
    fake_db = MagicMock()
    fake_db.query.return_value = [{'id': 'c1'}, {'id': 'c2'}]
    got_db = []
    monkeypatch.setattr(xclb, 'get_db', lambda: got_db.append(1) or fake_db)
    monkeypatch.setattr(xclb, 'cluster_managers', {'c1': 'mgr1', 'c2': 'mgr2'})
    monkeypatch.setattr(xclb, 'compute_cluster_score', {'mgr1': 85.0, 'mgr2': 20.0}.get)
    audits = []
    monkeypatch.setattr(xclb, 'log_audit', lambda *a, **k: audits.append(a[1]))
    group = {'id': 'g1', 'name': 'grp', 'cross_cluster_threshold': 10, 'cross_cluster_dry_run': 1}

    assert xclb.run_cross_cluster_balance_check(group) is None

    if which == 'standby':
        assert got_db == [] and audits == []
    else:
        assert audits == ['xclb.dry_run']


@pytest.mark.parametrize('which', ROLES)
def test_manager_balance_check_does_nothing_on_a_standby(which, role):
    from pegaprox.core.manager import PegaProxManager
    role(which)
    fake = MagicMock()
    fake.get_node_status.return_value = {}

    PegaProxManager.run_balance_check(fake)

    if which == 'standby':
        assert fake.mock_calls == []
    else:
        fake.get_node_status.assert_called_once_with()


@pytest.mark.parametrize('which', ROLES)
def test_pve_ha_monitor_never_starts_on_a_standby(which, role):
    from pegaprox.core.manager import PegaProxManager
    role(which)
    fake = MagicMock()
    fake.ha_thread = None
    fake._ha_discover_fallback_hosts.side_effect = _Stop()

    if which == 'standby':
        PegaProxManager.start_ha_monitor(fake)
        fake._ha_discover_fallback_hosts.assert_not_called()
        fake.connect_to_proxmox.assert_not_called()
    else:
        # past the gate the first thing it does is discover fallback hosts
        with pytest.raises(_Stop):
            PegaProxManager.start_ha_monitor(fake)


def _seed_orphans(db):
    db.conn.execute(
        "INSERT INTO site_recovery_plans (id, group_id, name, source_cluster, target_cluster, status) "
        "VALUES ('plan1', 'g1', 'dc failover', 'c1', 'c2', 'running')")
    db.conn.execute(
        "INSERT INTO site_recovery_events (id, plan_id, event_type, status, started_at) "
        "VALUES ('ev1', 'plan1', 'failover', 'running', '2026-09-29T10:00:00')")
    db.conn.commit()


@pytest.mark.parametrize('which', ROLES)
def test_orphan_run_cleanup_resets_nothing_on_a_standby(which, role, db):
    from pegaprox.background.site_recovery import recover_orphan_runs
    role(which)
    _seed_orphans(db)

    recover_orphan_runs()

    plan = db.conn.execute("SELECT status FROM site_recovery_plans WHERE id='plan1'").fetchone()
    event = db.conn.execute("SELECT status FROM site_recovery_events WHERE id='ev1'").fetchone()
    if which == 'standby':
        assert (plan['status'], event['status']) == ('running', 'running')
    else:
        assert (plan['status'], event['status']) == ('failed', 'aborted')


def test_an_unreadable_state_file_holds_the_loops_back(role, monkeypatch):
    """Not a role anyone chose: the state file is damaged. _load makes that a standby,
    and the loops treat it like one."""
    import pegaprox.background.scheduler as scheduler
    with open(ha.STATE_FILE, 'w', encoding='utf-8') as fh:
        fh.write('{"role": "act')
    ha.reset_for_tests()
    calls = _recorder(monkeypatch, scheduler, 'run_scheduled_tasks')
    monkeypatch.setattr(scheduler, '_scheduler_running', False)

    _drive(monkeypatch, scheduler, scheduler.scheduler_loop)

    assert calls == []
