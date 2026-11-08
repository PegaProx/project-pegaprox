"""Long loops of plain Python in a request let the hub in between their steps.

At 100 nodes and 10k guests (the estates go to 200) the what-if ranking held the gevent hub two seconds, the
migration preflight without a target more than four, a search of 20 terms half a second:
every other request, event stream and console of the process waited, and the HA lease
renewal with them. They let the hub in between their steps now (utils.concurrent
yield_to_hub, a sleep of a millisecond: sleep(0) came straight back before the loop looked
at its timers, idle() never came back while another greenlet kept the loop busy). A chart
range read takes one of the heavy-read slots at most.
MK Oct 2026
"""
import gc
import time

import gevent
import pytest

import test_migration_preflight as tm
import test_whatif as tw
from pegaprox.core import preflight, whatif
from pegaprox.utils import concurrent as cc

NODES, GUESTS = 200, 10000
GAP = 0.3


def _hub_gap(work):
    """(result, longest time the hub was held, time work() took) of work() on the hub.

    The garbage collector is off while it runs: in one process over the whole suite (as
    in CI) the heap is large, and a full collection can pause the interpreter for a second
    at any point - a hold of the interpreter, not of the code measured here."""
    gaps, stop = [], []

    def tick():
        last = time.perf_counter()
        while not stop:
            gevent.sleep(0.005)
            now = time.perf_counter()
            gaps.append(now - last)
            last = now
    gc.collect()
    gc.disable()
    g = gevent.spawn(tick)
    gevent.sleep(0.05)
    start = time.perf_counter()
    try:
        out = work()
    finally:
        wall = time.perf_counter() - start
        gevent.sleep(0.02)
        stop.append(1)
        g.join()
        gc.enable()
    return out, max(gaps), wall


def _best_of_two(work):
    """_hub_gap of the run that held the hub less: a pause from outside (another process,
    the host of a CI runner) rarely meets both, a loop that holds the hub holds it in each."""
    first = _hub_gap(work)
    second = _hub_gap(work)
    return min(first, second, key=lambda r: r[1])


def _held_briefly(gap, wall):
    """Under the fixed bound, or, where a loaded machine runs it all slower, under half of
    the whole run: the loops this is about held the hub for nine tenths of it and more (the
    set-up before a loop, 19900 pairs sorted at 200 nodes, is a hold of its own)."""
    return gap < GAP or gap < wall / 2


def _whatif_cluster():
    nodes = tuple(f'pve{i}' for i in range(NODES))
    guests = [tw._vm(1000 + i, nodes[i % NODES], mem=2, maxmem=4, status='running') for i in range(GUESTS)]
    api = {'/cluster/ha/resources': [], '/cluster/ha/rules': [], '/storage': tw.STORAGES,
           ('/cluster/resources', 'storage'): [{'node': n, 'storage': 'ceph', 'status': 'available', 'shared': 1}
                                               for n in nodes]}
    for g in guests:
        api[f"/nodes/{g['node']}/qemu/{g['vmid']}/config"] = tw._cfg()
    return tw._manager(api, guests, nodes=nodes, mem_used=20, mem_total=256)


def test_the_ranking_lets_the_hub_in_between_its_candidates():
    mgr = _whatif_cluster()
    rep, gap, wall = _best_of_two(lambda: whatif.ranking(mgr, {'cpu': 80.0, 'memory': 90.0}))
    assert len(rep['ranking']) >= NODES // 2
    assert _held_briefly(gap, wall), f'the hub was held {gap:.2f}s of {wall:.2f}s'


@pytest.mark.parametrize('scenario', [{'type': 'headroom', 'depth': 2},
                                      {'type': 'maintenance', 'nodes': [f'pve{i}' for i in range(16)]}],
                         ids=['headroom-pairs', 'maintenance-16'])
def test_a_scenario_over_every_pair_or_many_guests_lets_the_hub_in(scenario):
    # 200 nodes are 19900 pairs; the pairs alone held the hub 0.7 s
    mgr = _whatif_cluster()
    _, gap, wall = _best_of_two(lambda: whatif.run(mgr, whatif.parse_scenario(scenario), {'cpu': 80.0, 'memory': 90.0}))
    assert _held_briefly(gap, wall), f'the hub was held {gap:.2f}s of {wall:.2f}s'


def test_the_preflight_without_a_target_lets_the_hub_in_between_its_guests():
    class _Api:
        def set_manager(self, cid, m):
            pass
    nodes = {f'pve{i}': tm._node(mem_used_gb=20, mem_total_gb=256) for i in range(NODES)}
    guests = [tm._guest(1000 + i, f'pve{i % NODES}') for i in range(GUESTS)]
    cfgs = {g['vmid']: {'scsi0': 'ceph:vm-1-disk-0,size=32G', 'net0': 'virtio=AA:BB:CC:00:00:01,bridge=vmbr0'}
            for g in guests}
    m = tm._Pve(_Api(), guests=guests, nodes=nodes, configs=cfgs)
    res, gap, wall = _best_of_two(lambda: preflight.intra('cluster_1', m, [1000 + i for i in range(400)], None,
                                                          True, False, None, 2))
    assert res['totals']['guests'] == 400
    assert _held_briefly(gap, wall), f'the hub was held {gap:.2f}s of {wall:.2f}s'


def test_a_long_search_lets_the_hub_in_between_its_guests():
    from pegaprox.api import search
    from pegaprox.utils import search_query
    rows = []
    for i in range(GUESTS):
        r = {'vmid': 100 + i, 'name': f'vm-{i}-web', 'node': f'pve{i % NODES}', 'ip': '10.0.0.5',
             'status': 'running', 'type': 'qemu', 'tags': 'a;b', 'pool': 'p', 'ip_addresses': ['10.0.0.1']}
        rows.append(search._search_facts(r, 'c1', 'Lab', {}))
    reading = search_query.parse(' OR '.join(f'zz{i}q' for i in range(20)))
    hits, gap, wall = _best_of_two(lambda: search._search_results(reading, rows, [], 'all'))
    assert hits == []
    assert _held_briefly(gap, wall), f'the hub was held {gap:.2f}s of {wall:.2f}s'


def test_the_yield_lets_timers_run_where_sleep_zero_did_not():
    """The counterproof of the primitive: steps of 20 ms, as a ranking candidate is, with
    sleep(0) between them still hold a timer through all of them."""
    def busy(yielding):
        def work():
            for _ in range(25):
                step = time.perf_counter() + 0.02
                while time.perf_counter() < step:
                    pass
                yielding()
        return _hub_gap(work)[1]
    assert busy(lambda: gevent.sleep(0)) > GAP
    assert busy(cc.yield_to_hub) < 0.1


def test_the_yield_comes_back_while_another_greenlet_keeps_the_loop_busy():
    """gevent.idle() waited for a loop with nothing pending: next to a greenlet that keeps
    yielding it never came back, and the suite hung on it."""
    stop, done = [], []

    def spin():
        while not stop:
            gevent.sleep(0)
    n = gevent.spawn(spin)
    w = gevent.spawn(lambda: [cc.yield_to_hub() for _ in range(20)] and done.append(1))
    w.join(timeout=5)
    stop.append(1)
    n.join()
    assert done == [1]


def test_the_yield_is_nothing_in_a_thread_without_a_hub():
    import threading
    done = []
    t = threading.Thread(target=lambda: (cc.yield_to_hub(), done.append(1)))
    t.start()
    t.join(5)
    assert done == [1]


def test_a_chart_range_takes_one_heavy_read_slot_at_most(monkeypatch):
    from pegaprox.background import metrics
    from pegaprox.core import dbcrypto
    sem = dbcrypto._heavy_sem()
    seen, gate = [], gevent.event.Event()

    def slow_read(sql, params, transform=None, **kw):
        seen.append(sem.counter)
        gate.wait(5)
        return []
    monkeypatch.setattr(dbcrypto, 'run_heavy_read', slow_read)
    free = sem.counter
    readers = [gevent.spawn(metrics.load_metrics_range, 0, 3600, lambda c: c) for _ in range(4)]
    gevent.sleep(0.1)
    # one range parses, the others wait for the range slot, not for the shared ones
    assert seen == [free - 1] and sem.counter == free - 1
    gate.set()
    gevent.joinall(readers, timeout=5)
    assert len(seen) == 4 and sem.counter == free


def test_quick_steps_do_not_pay_a_turn_each(monkeypatch):
    """A preflight with a named target walks a thousand guests in about a tenth of a
    second; a turn per guest made that more than a second."""
    turns = []
    monkeypatch.setattr(cc, 'yield_to_hub', lambda: turns.append(1))
    t = cc.HubTurns(every=0.02)
    start = time.perf_counter()
    for _ in range(2000):
        t.take()
    assert time.perf_counter() - start < 0.1 and len(turns) <= 2
