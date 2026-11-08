# The history reports (power, costs, right-sizing) work through guests x snapshots in plain
# Python: about 11 s at 10k guests over a month. Run on the gevent hub, that held every
# other request, event stream and console of the process for as long. The arithmetic runs
# in gevent's thread pool now, one report at a time, and a result is kept: the same history
# within a minute is served as is, a newer history within 15 minutes gets the kept figures
# at once while new ones are worked out in the background, and only a report nobody has
# asked for (or an older one) is waited for. Every answer says when its figures were
# worked out (computed_at) and whether newer ones are on the way (refreshing).
import os
import sys
import time
from datetime import datetime

import gevent
import pytest
import pegaprox.api.costs as costs
import pegaprox.api.helpers as helpers
import pegaprox.api.insights as insights
import pegaprox.api.power as power
import pegaprox.utils.rbac as rbac

from test_power_host_profiles_965 import _admin, _cluster, _snap, _vm

SUMMARY = '/api/clusters/cluster_1/power/summary?days=1'
PER_VM = '/api/clusters/cluster_1/power/per-vm?days=1'


def _settle():
    """Let the background run of a kept report finish."""
    for done in list(helpers._report_running.values()):
        done.get(timeout=30)
    gevent.sleep(0)


def _count(monkeypatch, module, name, slow=0.0):
    runs = []
    real = getattr(module, name)

    def counted(*a, **k):
        runs.append(1)
        end = time.perf_counter() + slow
        while time.perf_counter() < end:   # busy: holds the GIL as the real arithmetic does
            pass
        return real(*a, **k)
    monkeypatch.setattr(module, name, counted)
    return runs


def _history(n, cpu=50.0):
    return [_snap(i * 300, {'100': _vm('n1', cpu), '101': _vm('n1', 0.0)}, n1_cpu=cpu) for i in range(n)]


# -- the hub ------------------------------------------------------------------------------------

def test_the_hub_keeps_running_while_a_report_is_worked_out(api, seed, monkeypatch):
    _cluster(api, monkeypatch)
    _count(monkeypatch, power, '_compute_power', slow=1.5)
    gaps, stop = [], [False]

    def ticker():
        last = time.perf_counter()
        while not stop[0]:
            gevent.sleep(0.01)
            now = time.perf_counter()
            gaps.append(now - last)
            last = now
    tick = gevent.spawn(ticker)
    gevent.sleep(0.05)
    started = time.perf_counter()
    r = api.as_user(_admin(seed)).get(SUMMARY)
    took = time.perf_counter() - started
    stop[0] = True
    tick.join()
    assert r.status_code == 200, r.get_data(as_text=True)
    assert took >= 1.5
    # the hub went on with the other greenlets all along, not once 1.5 s later. A busy CI runner stalled it
    # for half a second with the work off the hub as it should be, and on the hub this would be the full 1.5
    assert max(gaps) < 1.0, max(gaps)
    assert len(gaps) > 20


def test_requests_at_the_same_time_share_one_run(api, seed, monkeypatch):
    _cluster(api, monkeypatch)
    runs = _count(monkeypatch, power, '_compute_power', slow=0.5)
    c = api.as_user(_admin(seed))
    calls = [gevent.spawn(c.get, SUMMARY), gevent.spawn(c.get, PER_VM), gevent.spawn(c.get, SUMMARY)]
    gevent.joinall(calls, timeout=30)
    assert [g.value.status_code for g in calls] == [200, 200, 200]
    assert len(runs) == 1


# -- kept, and served while a newer one is worked out ---------------------------------------------

def test_a_newer_history_gets_the_kept_figures_at_once_and_new_ones_after(api, seed, monkeypatch):
    _cluster(api, monkeypatch, snaps=_history(2))
    runs = _count(monkeypatch, power, '_compute_power')
    c = api.as_user(_admin(seed))
    first = c.get(SUMMARY).get_json()
    assert first['refreshing'] is False
    assert datetime.fromisoformat(first['computed_at']).tzinfo is not None
    # the collector wrote another snapshot, at a higher load
    monkeypatch.setattr(power, '_load_history', lambda *a, **k: _history(2) + [_snap(600, {'100': _vm('n1', 100.0)}, n1_cpu=100.0)])
    second = c.get(SUMMARY).get_json()
    assert second['monthly'] == first['monthly'] and second['computed_at'] == first['computed_at']
    assert second['refreshing'] is True
    _settle()
    third = c.get(SUMMARY).get_json()
    assert len(runs) == 2
    assert third['refreshing'] is False and third['monthly']['kwh'] != first['monthly']['kwh']


def test_the_same_history_within_a_minute_is_not_worked_out_again(api, seed, monkeypatch):
    _cluster(api, monkeypatch)
    runs = _count(monkeypatch, power, '_compute_power')
    c = api.as_user(_admin(seed))
    for _ in range(3):
        assert c.get(SUMMARY).get_json()['refreshing'] is False
    assert len(runs) == 1
    # a minute on, the live names and hosts are read again, in the background
    key = next(iter(helpers._reports))
    value, version, mono, wall, rows = helpers._reports[key]
    helpers._reports[key] = (value, version, mono - helpers._REPORT_FRESH - 1, wall, rows)
    assert c.get(SUMMARY).get_json()['refreshing'] is True
    _settle()
    assert len(runs) == 2


def test_a_report_past_the_keep_window_is_waited_for(api, seed, monkeypatch):
    _cluster(api, monkeypatch, snaps=_history(2))
    _count(monkeypatch, power, '_compute_power')
    c = api.as_user(_admin(seed))
    first = c.get(SUMMARY).get_json()
    key = next(iter(helpers._reports))
    value, version, mono, wall, rows = helpers._reports[key]
    helpers._reports[key] = (value, version, mono - helpers._REPORT_KEEP - 1, wall, rows)
    monkeypatch.setattr(power, '_load_history', lambda *a, **k: _history(2, cpu=100.0))
    second = c.get(SUMMARY).get_json()
    assert second['refreshing'] is False and second['monthly'] != first['monthly']


def test_changed_rates_are_worked_out_before_the_answer(api, seed, monkeypatch):
    _cluster(api, monkeypatch)
    monkeypatch.setattr(costs, '_load_history', lambda *a, **k: _history(2))
    c = api.as_user(_admin(seed))
    before = c.get('/api/clusters/cluster_1/costs/summary?days=1')
    assert before.status_code == 200 and before.get_json()['enough_data'], before.get_data(as_text=True)
    r = c.put('/api/cost/rates/cluster_1', json={'cpu_per_core_h': 1.0, 'mem_per_gb_h': 0.0,
                                                  'storage_per_gb_month': 0.0, 'currency': 'EUR'})
    assert r.status_code == 200, r.get_data(as_text=True)
    after = c.get('/api/clusters/cluster_1/costs/summary?days=1').get_json()
    assert after['refreshing'] is False
    assert after['monthly_total'] != before.get_json()['monthly_total']


def test_a_failed_background_run_keeps_the_last_report(api, seed, monkeypatch, caplog):
    _cluster(api, monkeypatch, snaps=_history(2))
    c = api.as_user(_admin(seed))
    first = c.get(SUMMARY).get_json()

    def broken(*a, **k):
        raise RuntimeError('boom')
    monkeypatch.setattr(power, '_compute_power', broken)
    monkeypatch.setattr(power, '_load_history', lambda *a, **k: _history(3))
    assert c.get(SUMMARY).get_json()['monthly'] == first['monthly']
    _settle_quiet()
    again = c.get(SUMMARY)
    assert again.status_code == 200 and again.get_json()['monthly'] == first['monthly']
    assert 'the power report was not worked out' in caplog.text


def _settle_quiet():
    for done in list(helpers._report_running.values()):
        try:
            done.get(timeout=30)
        except Exception:
            pass
    gevent.sleep(0)


def test_a_run_from_before_forget_stores_nothing(api, seed, monkeypatch):
    _cluster(api, monkeypatch, snaps=_history(2))
    c = api.as_user(_admin(seed))
    c.get(SUMMARY)
    monkeypatch.setattr(power, '_load_history', lambda *a, **k: _history(3))
    assert c.get(SUMMARY).get_json()['refreshing'] is True
    running = list(helpers._report_running.values())
    helpers.forget_reports()
    for done in running:
        done.get(timeout=30)
    assert helpers._reports == {}


def test_the_kept_reports_are_capped_in_number(monkeypatch):
    monkeypatch.setattr(helpers, '_REPORT_MAX', 3)
    for i in range(5):
        helpers.history_report(('t', i), 1, lambda: i)
    assert sorted(k[1] for k in helpers._reports) == [2, 3, 4]


def test_the_kept_reports_are_capped_in_guest_rows(monkeypatch):
    # a row per guest is what makes a report big: 10k guests are about 1.5 MB pickled
    monkeypatch.setattr(helpers, '_REPORT_ROWS', 250)
    for i in range(4):
        helpers.history_report(('t', i), 1, lambda: list(range(100)), rows=len)
    assert sorted(k[1] for k in helpers._reports) == [2, 3]
    # the newest stays even when it alone is over the cap
    helpers.history_report(('big', 0), 1, lambda: list(range(1000)), rows=len)
    assert list(helpers._reports) == [('big', 0)]


def test_an_expired_report_goes_on_the_next_request_not_only_on_the_next_store(api, seed, monkeypatch):
    helpers.history_report(('t', 'old'), 1, lambda: 'x')
    value, version, mono, wall, rows = helpers._reports[('t', 'old')]
    helpers._reports[('t', 'old')] = (value, version, mono - helpers._REPORT_KEEP - 1, wall, rows)
    _cluster(api, monkeypatch)
    api.as_user(_admin(seed)).get('/api/clusters/cluster_1/power/hosts')   # no report involved
    helpers.history_report(('t', 'other'), 1, lambda: 'y')
    assert ('t', 'old') not in helpers._reports


def test_a_reconnected_cluster_is_worked_out_again(api, seed, monkeypatch):
    _cluster(api, monkeypatch)
    runs = _count(monkeypatch, power, '_compute_power')
    c = api.as_user(_admin(seed))
    c.get(SUMMARY)
    # a new manager for the same cluster id, as after a reconnect
    _cluster(api, monkeypatch)
    assert c.get(SUMMARY).get_json()['refreshing'] is False
    assert len(runs) == 2


def test_a_new_manager_never_takes_over_the_key_of_a_collected_one():
    class Manager:
        pass
    first = Manager()
    key, gone = helpers.report_owner(first), id(first)
    del first
    for _ in range(100000):
        again = Manager()
        if id(again) == gone:
            break
    else:
        pytest.skip('the allocator did not hand the same address out again')
    # same address, still another key: the old token lives on in the old key
    assert helpers.report_owner(again) is not key


def test_a_cut_off_waiter_keeps_the_next_report_waiting_until_its_thread_is_done():
    import threading
    running, peak, lock = [0], [0], threading.Lock()

    def work():
        with lock:
            running[0] += 1
            peak[0] = max(peak[0], running[0])
        end = time.perf_counter() + 0.6
        while time.perf_counter() < end:
            pass
        with lock:
            running[0] -= 1
        return 1
    first = gevent.spawn(helpers.run_off_hub, work)
    gevent.sleep(0.1)
    first.kill()                       # the request waiting for it went away
    second = gevent.spawn(helpers.run_off_hub, work)
    assert second.get(timeout=10) == 1
    assert peak[0] == 1


def test_without_a_background_run_the_caller_waits_for_the_new_figures(api, seed, monkeypatch):
    _cluster(api, monkeypatch, snaps=_history(2))
    c = api.as_user(_admin(seed))
    first = c.get(SUMMARY).get_json()
    monkeypatch.setattr(helpers, '_report_start', lambda *a: None)   # no gevent
    monkeypatch.setattr(power, '_load_history', lambda *a, **k: _history(3, cpu=100.0))
    second = c.get(SUMMARY).get_json()
    assert second['refreshing'] is False and second['monthly'] != first['monthly']


# -- shared, and still per caller --------------------------------------------------------------

def _pool_user(seed):
    seed.tenant('tenant_x', clusters=['cluster_1'])
    u = seed.user('mallory', role='viewer', tenant_id='tenant_x')
    seed.pool('cluster_1', 'pool_1', 'mallory', ['pool.view', 'vm.view'])
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache['cluster_1'] = {'data': {'100:qemu': 'pool_1'}, 'timestamp': time.time(),
                                                    'refreshing': False}
    return u


def _sizing_history():
    # 30 samples: enough for a recommendation; 100 idle (oversized), 101 busy (undersized)
    return [_snap(i * 300, {'100': _vm('n1', 1.0, vcpus=4, mem=10.0, mem_gib=8),
                            '101': _vm('n1', 95.0, vcpus=2, mem=95.0, mem_gib=2)}) for i in range(30)]


def test_one_kept_report_answers_each_caller_with_their_own_guests(api, seed, monkeypatch):
    _cluster(api, monkeypatch, snaps=_sizing_history())
    monkeypatch.setattr(costs, '_load_history', lambda *a, **k: _sizing_history())
    monkeypatch.setattr(insights, '_load_history', lambda *a, **k: _sizing_history())
    power_runs = _count(monkeypatch, power, '_compute_power')
    cost_runs = _count(monkeypatch, costs, '_cost_stats')
    sizing_runs = _count(monkeypatch, insights, '_sizing_stats')
    admin, mallory = api.as_user(_admin(seed)), api.as_user(_pool_user(seed))
    paths = {'power': '/api/clusters/cluster_1/power/per-vm?days=1',
             'costs': '/api/clusters/cluster_1/costs/per-vm?days=1',
             'sizing': '/api/clusters/cluster_1/insights/right-sizing?days=1'}
    seen = {}
    for who, c in (('admin', admin), ('mallory', mallory)):
        for name, path in paths.items():
            r = c.get(path)
            assert r.status_code == 200, (who, name, r.get_data(as_text=True))
            body = r.get_json()
            rows = body.get('rows', body.get('recommendations'))
            seen[who, name] = sorted(str(x['vmid']) for x in rows)
    for name in paths:
        assert seen['admin', name] == ['100', '101'], name
        assert seen['mallory', name] == ['100'], name
    assert (len(power_runs), len(cost_runs), len(sizing_runs)) == (1, 1, 1)


def test_cost_summary_per_vm_and_chargeback_share_one_run_and_leave_it_unchanged(api, seed, monkeypatch):
    m = _cluster(api, monkeypatch)
    m.config.name = 'lab'
    monkeypatch.setattr(costs, '_load_history', lambda *a, **k: _sizing_history())
    runs = _count(monkeypatch, costs, '_cost_stats')
    seed.tenant('tenant_x', clusters=['cluster_1'])
    c = api.as_user(_admin(seed))
    s = c.get('/api/clusters/cluster_1/costs/summary?days=7')
    p = c.get('/api/clusters/cluster_1/costs/per-vm?days=7')
    b = c.get('/api/tenants/tenant_x/chargeback?days=7')
    assert [x.status_code for x in (s, p, b)] == [200, 200, 200], b.get_data(as_text=True)
    assert len(runs) == 1
    assert b.get_json()['computed_at'] == s.get_json()['computed_at'] == p.get_json()['computed_at']
    # what is kept is the history part only, the routes build their rows from it
    kept = next(v[0] for k, v in helpers._reports.items() if k[0] == 'costs')
    assert all('monthly_total' not in r and 'cluster_id' not in r and 'name' not in r for r in kept.values())


def test_right_sizing_reads_as_before(api, seed, monkeypatch):
    _cluster(api, monkeypatch)
    monkeypatch.setattr(insights, '_load_history', lambda *a, **k: _sizing_history())
    body = api.as_user(_admin(seed)).get('/api/clusters/cluster_1/insights/right-sizing?days=1').get_json()
    recs = {r['vmid']: r for r in body['recommendations']}
    assert {f['kind'] for f in recs['100']['flags']} == {'oversized_cpu', 'oversized_mem'}
    assert {f['kind'] for f in recs['101']['flags']} == {'undersized_cpu', 'undersized_mem'}
    assert recs['100']['cpu_avg'] == 1.0 and recs['101']['cpu_p95'] == 95.0 and recs['101']['samples'] == 30
    assert recs['100']['maxmem_gb'] == 8.0 and recs['101']['mem_max'] == 95.0
    assert body['total_vms'] == 2 and body['snapshots_in_window'] == 30
    assert body['refreshing'] is False and body['computed_at']


def test_no_history_no_report(api, seed, monkeypatch):
    _cluster(api, monkeypatch, snaps=[])
    monkeypatch.setattr(insights, '_load_history', lambda *a, **k: [])
    c = api.as_user(_admin(seed))
    assert c.get(SUMMARY).get_json()['enough_data'] is False
    body = c.get('/api/clusters/cluster_1/insights/right-sizing?days=1').get_json()
    assert body['recommendations'] == [] and 'computed_at' not in body
    assert helpers._reports == {}


# -- the parts run off the hub only read what they are handed ---------------------------------

def test_the_off_hub_parts_get_a_copy_of_the_live_guest_list(api, seed, monkeypatch):
    m = _cluster(api, monkeypatch)
    handed = []
    real = power._compute_power
    monkeypatch.setattr(power, '_compute_power', lambda snaps, live, *a, **k: handed.append(live) or real(snaps, live, *a, **k))
    api.as_user(_admin(seed)).get(SUMMARY)
    live = m.get_vm_resources()
    assert handed and handed[0] == [{'vmid': r['vmid'], 'name': r['name'], 'node': r['node']} for r in live]
    assert all(a is not b for a, b in zip(handed[0], live))


def test_run_off_hub_runs_in_another_thread():
    import threading
    here = threading.get_ident()
    assert helpers.run_off_hub(threading.get_ident) != here


# -- what the attack round found ----------------------------------------------------------------

def test_a_renamed_moved_or_grown_guest_shows_at_once(api, seed, monkeypatch):
    m = _cluster(api, monkeypatch)
    monkeypatch.setattr(costs, '_load_history', lambda *a, **k: _history(2))
    c = api.as_user(_admin(seed))
    rows = lambda path: {str(r['vmid']): r for r in c.get(path).get_json()['rows']}
    assert rows(PER_VM)['100']['name'] == 'db01'
    assert rows('/api/clusters/cluster_1/costs/per-vm?days=1')['100']['disk_gb'] == 0
    m.get_vm_resources.return_value = [{'vmid': 100, 'name': 'db02', 'node': 'n2', 'type': 'qemu',
                                        'maxdisk': 50 * 1024 ** 3},
                                       {'vmid': 101, 'name': 'web01', 'node': 'n1', 'type': 'qemu'}]
    p, k = rows(PER_VM)['100'], rows('/api/clusters/cluster_1/costs/per-vm?days=1')['100']
    assert (p['name'], p['node']) == ('db02', 'n2')
    assert (k['name'], k['node'], k['disk_gb']) == ('db02', 'n2', 50.0) and k['cost_storage'] > 0
    # the kept power rows themselves are untouched
    kept = next(v[0] for key, v in helpers._reports.items() if key[0] == 'power')
    assert next(r for r in kept['rows'] if r['vmid'] == '100')['name'] == 'db01'


def test_one_unreadable_guest_does_not_take_right_sizing_down(api, seed, monkeypatch):
    _cluster(api, monkeypatch)
    hist = _sizing_history()
    for i, (_ts, cd) in enumerate(hist):
        if i >= 25:   # a guest with a short history and a value no number reads from
            cd['vms']['102'] = dict(_vm('n1', 'n/a'), maxcpu='n/a')
    monkeypatch.setattr(insights, '_load_history', lambda *a, **k: hist)
    r = api.as_user(_admin(seed)).get('/api/clusters/cluster_1/insights/right-sizing?days=1')
    assert r.status_code == 200, r.get_data(as_text=True)
    body = r.get_json()
    assert {x['vmid'] for x in body['recommendations']} == {'100', '101'}
    assert body['summary']['no_data'] == 1


def test_a_caller_that_goes_away_leaves_the_others_their_figures(api, seed, monkeypatch):
    _cluster(api, monkeypatch)
    runs = _count(monkeypatch, power, '_compute_power', slow=0.6)
    c = api.as_user(_admin(seed))
    first = gevent.spawn(c.get, SUMMARY)
    gevent.sleep(0.1)
    second = gevent.spawn(c.get, SUMMARY)
    gevent.sleep(0.1)
    first.kill()                     # the browser of the first one closed
    r = second.get(timeout=30)
    assert r.status_code == 200, r.get_data(as_text=True)
    assert len(runs) == 1


def test_right_sizing_counts_the_snapshots_its_figures_were_worked_out_of(api, seed, monkeypatch):
    """MK Oct 2026 - a stored window is two reads: its index, then the parts. The rows the
    retention prunes in between leave the window, so the count has to be taken after the
    figures, not before (it said 30 over figures of 25)."""
    import metrics_history_fixture as mhf
    from datetime import timedelta
    from pegaprox import constants
    from pegaprox.core import dbcrypto
    _cluster(api, monkeypatch)
    now = datetime.now()
    rows = [((now - timedelta(seconds=300 * (30 - i))).isoformat(), {'clusters': {'cluster_1': cd}})
            for i, (_ts, cd) in enumerate(_sizing_history())]
    ids = mhf.History().write(rows)
    real = insights._sizing_stats

    def pruned_meanwhile(history):
        conn = dbcrypto.connect(constants.DATABASE_FILE)
        try:
            for sid in ids[:5]:
                conn.execute('DELETE FROM metrics_part WHERE snap_id = ?', (sid,))
                conn.execute('DELETE FROM metrics_history WHERE id = ?', (sid,))
            conn.commit()
        finally:
            conn.close()
        return real(history)
    monkeypatch.setattr(insights, '_sizing_stats', pruned_meanwhile)
    body = api.as_user(_admin(seed)).get('/api/clusters/cluster_1/insights/right-sizing?days=1').get_json()
    assert {r['samples'] for r in body['recommendations']} == {25}
    assert body['snapshots_in_window'] == 25


def test_the_long_term_history_is_worked_out_off_the_hub(api, seed, monkeypatch):
    """MK Oct 2026 - the samples and buckets of insights/history were built on the hub: a
    year at 200 nodes is 0.5-0.7 s of plain Python, and the hub stood still for it on every
    request. It runs in the thread pool now, and answers as before."""
    from gevent.monkey import get_original
    real_ident = get_original('_thread', 'get_ident')
    _cluster(api, monkeypatch)
    monkeypatch.setattr(insights, '_load_history', lambda *a, **k: _history(30))
    hub, seen, real = real_ident(), [], insights._avg_samples
    monkeypatch.setattr(insights, '_avg_samples', lambda *a: seen.append(real_ident()) or real(*a))
    c = api.as_user(_admin(seed))
    body = c.get('/api/clusters/cluster_1/insights/history?days=7&step=3600').get_json()
    assert body['sample_count'] == len(seen) == 3
    assert hub not in seen
    assert body['samples'][0]['nodes']['n1'] == {'cpu': 50.0, 'mem_percent': 50.0}
    raw = c.get('/api/clusters/cluster_1/insights/history?days=7').get_json()
    assert raw['sample_count'] == 30 and raw['samples'][1]['ts'] == 300


def _rss_mb():
    with open('/proc/self/statm') as fh:
        return int(fh.read().split()[1]) * os.sysconf('SC_PAGE_SIZE') / 2 ** 20


def _fragments():
    """What a report does to the heap: a lot made and dropped, the result kept, and the
    kept bits lie all over what was freed (2 KB blocks go to malloc, not to Python's own)."""
    end = time.perf_counter() + 0.3          # as long as a report takes at the least
    blocks = [bytearray(2048) for _ in range(60000)]
    kept = blocks[::16]
    del blocks
    while time.perf_counter() < end:
        pass
    return kept


@pytest.mark.skipif(not sys.platform.startswith('linux'), reason='glibc heap')
@pytest.mark.parametrize('job', ['report', 'heavy read'])
def test_a_long_job_off_the_hub_hands_back_the_memory_it_freed(db, job):
    """MK Oct 2026 - glibc keeps memory freed in the middle of its heaps: after a few
    history pages the process stayed some hundred MB larger at 3000 guests, more than half a
    GB at 10k, with nothing live in it. A long job off the hub (a history report, a heavy
    read and what it makes of its rows) hands it back when it is done."""
    import ctypes
    from pegaprox.core import dbcrypto
    from gevent import get_hub
    try:
        libc_trim = ctypes.CDLL(None).malloc_trim
    except (OSError, AttributeError):
        pytest.skip('no glibc')
    libc_trim(0)
    base = _rss_mb()
    kept = get_hub().threadpool.apply(_fragments)       # the same work, nothing handed back
    held = _rss_mb() - base
    del kept
    libc_trim(0)
    if held < 80:
        pytest.skip(f'this allocator gives memory back on its own ({held:.0f} MB held)')
    base = _rss_mb()
    if job == 'report':
        kept = helpers.run_off_hub(_fragments)
    else:
        kept = dbcrypto.run_heavy_read('SELECT 1', transform=lambda rows: _fragments())
    after = _rss_mb() - base
    del kept
    assert after < held / 2, f'{after:.0f} MB still held after the job, {held:.0f} MB without handing back'
