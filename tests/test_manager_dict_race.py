"""Concurrent cluster add/remove vs. the loops that walk cluster_managers.

Every one of these routes iterates the process-global manager dict and does
network I/O inside the loop body (a PVE API call, an SSH fan-out, a threadpool
read). Under gevent that I/O is a yield point, so an /api/clusters POST or
DELETE running in another greenlet can add or drop a key mid-iteration —
"dictionary changed size during iteration".

The fake manager below models exactly that: its stubbed method mutates the dict
on first call, which is what the other greenlet does while we are parked on the
socket. MK
"""
import pytest

import pegaprox.globals as ppglobals


def _mutating_manager(new_id, method, rows, cluster_id='cluster_1'):
    """A manager whose `method` adds `new_id` to cluster_managers before
    returning — i.e. a cluster registered while we were blocked on I/O."""
    from tests.conftest import make_fake_manager

    mgr = make_fake_manager(cluster_id)
    mgr.is_connected = True
    mgr.connected = True
    mgr.config.name = cluster_id

    def _side_effect(*a, **kw):
        if new_id not in ppglobals.cluster_managers:
            other = make_fake_manager(new_id)
            other.is_connected = True
            other.connected = True
            other.config.name = new_id
            getattr(other, method).return_value = []
            ppglobals.cluster_managers[new_id] = other
        return rows

    getattr(mgr, method).side_effect = _side_effect
    return mgr


VM_ROWS = [
    {'vmid': 100, 'name': 'web-01', 'type': 'qemu', 'node': 'pve1', 'status': 'running',
     'cpu': 0.1, 'maxcpu': 4, 'mem': 1073741824, 'maxmem': 4294967296, 'pool': ''},
]


@pytest.fixture
def admin(api, seed):
    return api.as_user(seed.user('root_admin', role='admin'))


@pytest.mark.parametrize('path,query', [
    ('/api/global/search', '?q=web'),
    ('/api/global/summary', ''),
    ('/api/reports/top-vms', ''),
    ('/api/snapshots/overview', ''),
])
def test_route_survives_cluster_added_mid_walk(api, admin, path, query):
    api.set_manager('cluster_1', _mutating_manager('cluster_2', 'get_vm_resources', VM_ROWS))

    r = admin.get(path + query)

    assert r.status_code == 200, f'{path} -> {r.status_code}: {r.get_data(as_text=True)[:400]}'


def test_prometheus_exporter_survives_cluster_added_mid_scrape(api, seed, monkeypatch):
    import pegaprox.api.metrics_exporter as mx
    monkeypatch.setattr(mx, '_auth_ok', lambda: True)

    mgr = _mutating_manager('cluster_2', 'get_vm_resources', VM_ROWS)
    mgr.get_resources.return_value = []
    mgr.get_node_status.return_value = {}
    mgr.get_ceph_health_summary.return_value = None
    api.set_manager('cluster_1', mgr)

    r = api.anon().get('/api/metrics')

    assert r.status_code == 200, r.get_data(as_text=True)[:400]


def test_metrics_collector_survives_cluster_added_mid_cycle(api):
    from pegaprox.background.metrics import collect_metrics_snapshot

    mgr = _mutating_manager('cluster_2', 'get_vm_resources', VM_ROWS)
    mgr.nodes = {}
    api.set_manager('cluster_1', mgr)

    # the collector's caller swallows exceptions and drops the whole 5-minute
    # cycle, so assert on the call itself rather than on the loop above it
    snapshot = collect_metrics_snapshot()

    assert 'cluster_1' in (snapshot.get('clusters') or {})


def test_tenant_quota_check_survives_cluster_added_mid_count(api, seed):
    from pegaprox.utils.rbac import check_tenant_quota

    seed.tenant('t1', clusters=['cluster_1'])
    api.set_manager('cluster_1', _mutating_manager('cluster_2', 'get_vm_resources', VM_ROWS))

    # check_tenant_quota is deliberately fail-open, so a RuntimeError here does
    # not surface as an error — it silently returns ok=True and the quota goes
    # unenforced. Force the usage computation and assert the VM was counted.
    res = check_tenant_quota('t1', force=True)

    assert res['usage'].get('vms') == 1, res


# The manager methods that are safe to call while iterating the dict itself:
# plain field reads that never touch a socket. Everything else on a manager can
# park the greenlet, which is what makes the un-snapshotted walk racy.
PURE_MANAGER_METHODS = {'to_dict'}


def _manager_loops():
    """Every `for k, v in <manager global>.items():` in the package, with the
    methods the body calls on `v` and whether the dict was copied first."""
    import ast
    import pathlib

    globals_ = {'cluster_managers', 'pbs_managers', 'vmware_managers'}
    root = pathlib.Path(__file__).resolve().parent.parent / 'pegaprox'

    for path in sorted(root.rglob('*.py')):
        src = path.read_text(encoding='utf-8', errors='replace')
        if not any(g in src for g in globals_):
            continue
        for node in ast.walk(ast.parse(src)):
            if not isinstance(node, ast.For):
                continue
            it, copied = node.iter, False
            if isinstance(it, ast.Call) and isinstance(it.func, ast.Name) and it.func.id == 'list':
                it, copied = it.args[0] if it.args else it, True
            if not (isinstance(it, ast.Call) and isinstance(it.func, ast.Attribute)
                    and it.func.attr in ('items', 'values', 'keys')
                    and isinstance(it.func.value, ast.Name)
                    and it.func.value.id in globals_):
                continue

            targets = node.target.elts if isinstance(node.target, ast.Tuple) else [node.target]
            names = {t.id for t in targets if isinstance(t, ast.Name)}
            calls = {n.func.attr for n in ast.walk(node)
                     if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                     and isinstance(n.func.value, ast.Name) and n.func.value.id in names}
            yield str(path.relative_to(root.parent)), node.lineno, it.func.value.id, calls, copied


def test_manager_loops_that_do_io_snapshot_the_dict_first():
    """Guard the whole pattern, not just the sites fixed above: calling a manager
    method inside the loop means the greenlet can park there, so the dict has to
    be copied before iterating or a concurrent cluster add/remove kills the walk."""
    offenders = [
        f'{path}:{line} iterates {glob} live and calls {sorted(calls - PURE_MANAGER_METHODS)}'
        for path, line, glob, calls, copied in _manager_loops()
        if not copied and (calls - PURE_MANAGER_METHODS)
    ]

    assert not offenders, 'wrap the .items() in list():\n  ' + '\n  '.join(offenders)


def test_the_invariant_check_actually_sees_the_loops():
    """A typo in the AST walk above would make the guard vacuously green."""
    loops = list(_manager_loops())

    assert len(loops) >= 15, loops
    assert sum(1 for _, _, _, _, copied in loops if copied) >= 12, loops
