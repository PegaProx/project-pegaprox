"""The cluster report says what it could not read (api/reports.py, api/alerts.py).

reports/summary answered 200 with CPU, memory and both guest counts at 0 for a cluster
that is not connected, and the same zeros where the node status or the guest list did not
answer, with nothing in the answer to tell that from an idle, empty cluster. The page drew
"0.0 %" and "0 VMs running". `live.unread` names what was not read now ('nodes' for CPU and
memory, 'guests' for the running counts); a complete read has no such key, as before.

reports/top-vms answered [] for a cluster that is not connected and for a guest list that
did not answer, which the page showed as "No running VMs". It answers 503 now, and 500 for a
row it cannot rank (a bare except turned that into 200 with the rows before it). It reads the
guest list the broadcast loop read a moment ago (max_age), so the page can ask it for the
CPU and the memory ranking without a second walk of every node. The summary reads it so too.

A count that broke off half way leaves 'guests' unread, and without stored samples the
figures above them (cpu, memory, vms_running) are null where the live read did not answer.
NS Nov 2026
"""
import types

import pytest

from pegaprox.core.manager import UnreadList

CID = 'cluster_1'
NODES = {'pve1': {'status': 'online', 'cpu_percent': 40.0, 'mem_percent': 50.0, 'mem_total': 100, 'mem_used': 50}}
GUESTS = [{'vmid': 100, 'type': 'qemu', 'status': 'running', 'node': 'pve1', 'name': 'busy',
           'cpu': 0.9, 'mem': 1, 'maxmem': 10},
          {'vmid': 101, 'type': 'qemu', 'status': 'running', 'node': 'pve1', 'name': 'big',
           'cpu': 0.01, 'mem': 9, 'maxmem': 10},
          {'vmid': 200, 'type': 'lxc', 'status': 'running', 'node': 'pve1', 'name': 'ct', 'cpu': 0.2, 'mem': 2, 'maxmem': 10}]


@pytest.fixture
def env(api, seed, monkeypatch):
    import pegaprox.api.reports as rep
    monkeypatch.setattr(rep, 'load_metrics_history', lambda days=1, totals_only=True: {'snapshots': []})
    m = api.make_fake_manager(CID)
    m.is_connected = True
    m.config = types.SimpleNamespace(name='c1')
    m.get_node_status.return_value = dict(NODES)
    m.get_vm_resources.return_value = [dict(g) for g in GUESTS]
    api.set_manager(CID, m)
    return types.SimpleNamespace(mgr=m, c=api.as_user(seed.user('root', role='admin')))


def _summary(env):
    r = env.c.get(f'/api/clusters/{CID}/reports/summary?period=day')
    assert r.status_code == 200, r.get_data(as_text=True)
    return r.get_json()


def test_a_complete_read_carries_no_unread_key(env):
    d = _summary(env)
    assert 'unread' not in d['live']
    assert (d['live']['cpu_percent'], d['live']['vms_running'], d['live']['cts_running']) == (40.0, 2, 1)


def test_a_cluster_that_is_not_connected_says_nothing_was_read(env):
    env.mgr.is_connected = False
    d = _summary(env)
    assert d['live'].get('unread') == ['nodes', 'guests'], d['live']


def test_a_guest_list_that_did_not_answer_is_named(env):
    env.mgr.get_vm_resources.return_value = UnreadList()
    d = _summary(env)
    assert d['live'].get('unread') == ['guests'], d['live']
    assert d['live']['cpu_percent'] == 40.0


@pytest.mark.parametrize('status', [RuntimeError('timed out'), {}])
def test_a_node_status_that_did_not_answer_is_named(env, status):
    if isinstance(status, Exception):
        env.mgr.get_node_status.side_effect = status
    else:
        env.mgr.get_node_status.return_value = status
    d = _summary(env)
    assert d['live'].get('unread') == ['nodes'], d['live']
    assert d['live']['vms_running'] == 2


# --- the top lists -------------------------------------------------------------------------------

def test_the_memory_ranking_is_its_own_list(env):
    cpu = env.c.get(f'/api/clusters/{CID}/reports/top-vms?metric=cpu&limit=1').get_json()
    mem = env.c.get(f'/api/clusters/{CID}/reports/top-vms?metric=memory&limit=1').get_json()
    assert [v['name'] for v in cpu] == ['busy'] and [v['name'] for v in mem] == ['big']


def test_both_rankings_read_the_guest_list_the_broadcast_loop_has(env):
    env.c.get(f'/api/clusters/{CID}/reports/top-vms?metric=cpu')
    env.c.get(f'/api/clusters/{CID}/reports/top-vms?metric=memory')
    ages = [c.kwargs.get('max_age', c.args[0] if c.args else 0) for c in env.mgr.get_vm_resources.call_args_list]
    assert len(ages) == 2 and all(a > 0 for a in ages), ages


@pytest.mark.parametrize('how', ['offline', 'unread'])
def test_a_guest_list_that_was_not_read_is_no_empty_ranking(env, how):
    if how == 'offline':
        env.mgr.is_connected = False
    else:
        env.mgr.get_vm_resources.return_value = UnreadList()
    r = env.c.get(f'/api/clusters/{CID}/reports/top-vms?metric=memory')
    assert r.status_code == 503, (r.status_code, r.get_data(as_text=True))
    assert r.get_json().get('error')


# --- a read that broke off half way, and the figures above the samples ------------------------

def test_the_summary_reads_the_guest_list_the_broadcast_loop_has(env):
    _summary(env)
    ages = [c.kwargs.get('max_age', c.args[0] if c.args else 0) for c in env.mgr.get_vm_resources.call_args_list]
    assert len(ages) == 1 and ages[0] > 0, ages


def test_a_count_that_broke_off_leaves_the_guests_unread(env):
    # the counting loop meets a row that is no dict after it counted the three before it
    env.mgr.get_vm_resources.return_value = [dict(g) for g in GUESTS] + ['garbage']
    d = _summary(env)
    assert d['live'].get('unread') == ['guests'], d['live']
    # no half count either
    assert (d['live']['vms_running'], d['live']['cts_running']) == (0, 0)
    assert d['vms_running']['current'] is None


def test_a_scope_that_failed_leaves_the_guests_unread(env, monkeypatch):
    import pegaprox.api.helpers as helpers
    import pegaprox.api.reports as rep

    def _broken(cluster_id, rows):
        raise RuntimeError('pool permissions could not be read')
    monkeypatch.setattr(helpers, 'caller_is_scoped', lambda user, cluster_id: True)
    monkeypatch.setattr(rep, 'scope_vm_rows', _broken)
    d = _summary(env)
    assert d['live'].get('unread') == ['guests'], d['live']
    assert d['vms_running']['current'] is None


FIGURES = ('avg', 'min', 'max', 'current')


@pytest.mark.parametrize('how,blank', [
    ('offline', ('cpu', 'memory', 'vms_running')),
    ('guests', ('vms_running',)),
    ('nodes', ('cpu', 'memory')),
])
def test_without_samples_a_figure_that_was_not_read_is_null(env, how, blank):
    if how == 'offline':
        env.mgr.is_connected = False
    elif how == 'guests':
        env.mgr.get_vm_resources.return_value = UnreadList()
    else:
        env.mgr.get_node_status.return_value = {}
    d = _summary(env)
    assert d['data_points'] == 0
    for metric in ('cpu', 'memory', 'vms_running'):
        got = [d[metric][k] for k in FIGURES]
        if metric in blank:
            assert got == [None] * 4, (metric, got)
        else:
            assert None not in got, (metric, got)
    # the live part keeps its shape, live.unread says which of it was not read
    assert d['live']['cpu_percent'] is not None and d['live']['vms_running'] is not None


def test_a_complete_read_without_samples_keeps_the_live_figures(env):
    d = _summary(env)
    assert [d['cpu'][k] for k in FIGURES] == [40.0] * 4
    assert [d['memory'][k] for k in FIGURES] == [50.0] * 4
    assert [d['vms_running'][k] for k in FIGURES] == [3] * 4


def test_stored_samples_still_give_the_figures_when_the_live_read_failed(env, monkeypatch):
    import pegaprox.api.reports as rep
    from datetime import datetime, timedelta
    stamp = (datetime.now() - timedelta(minutes=5)).isoformat()
    totals = {'cpu_total': 8, 'cpu_used': 2, 'mem_total': 16, 'mem_used': 4, 'vms_running': 4, 'cts_running': 1}
    monkeypatch.setattr(rep, 'load_metrics_history', lambda days=1, totals_only=True: {
        'snapshots': [{'timestamp': stamp, 'clusters': {CID: {'name': 'c1', 'totals': totals}}}]})
    env.mgr.is_connected = False
    d = _summary(env)
    assert d['live']['unread'] == ['nodes', 'guests']
    assert (d['cpu']['current'], d['memory']['current'], d['vms_running']['current']) == (25.0, 25.0, 5)


@pytest.mark.parametrize('row', ['garbage', {'vmid': 102, 'type': 'qemu', 'status': 'running', 'node': 'pve1',
                                             'name': 'odd', 'cpu': 0.5, 'mem': None, 'maxmem': 10}])
def test_a_row_the_ranking_cannot_read_is_an_error_not_a_list(env, row):
    # was 200 with what came before the row (an empty or a partial list) for the whole one
    env.mgr.get_vm_resources.return_value = [dict(GUESTS[0]), row, dict(GUESTS[1])]
    r = env.c.get(f'/api/clusters/{CID}/reports/top-vms?metric=cpu')
    assert r.status_code == 500, (r.status_code, r.get_data(as_text=True))
    assert r.get_json().get('error')
