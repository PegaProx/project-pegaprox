"""Attacks on GET /api/timeline and the node state history.

Each test asserts a property the timeline promises (a source is read under the rules of the
route that serves it, a page goes on until nothing is left, a malformed query is a 400) and
fails on the code it was written against.

MK Oct 2026
"""
import json
import types
from datetime import datetime, timedelta, timezone

import pytest

from pegaprox.core import node_history
from test_timeline import (CID, ROUTE, _admin_client, _alert, _audit, _fresh, _get, _local, _ns, _q,  # noqa: F401
                           _rows, _utc, env)


def _follow(client, query, pages=40):
    """Every id the pages of `query` hand out, one page after the other."""
    seen, before = [], ''
    for _ in range(pages):
        body = _get(client, query + before)
        seen += [e['id'] for e in body['events']]
        if not body['next_before']:
            return seen
        before = '&before=' + body['next_before'].replace('+', '%2B')
    raise AssertionError(f'{query}: still paging after {pages} pages')


def _whole(client, query):
    return [e['id'] for e in _get(client, query + '&limit=500')['events']]


# --- visibility -----------------------------------------------------------------------------------

def _syslog_line(when, ip, host, message, severity=2, text='crit'):
    from pegaprox.background import syslog_server
    conn = syslog_server._open_db()
    conn.execute('INSERT INTO logs (timestamp, source_ip, hostname, facility, severity, severity_text, '
                 'message, protocol) VALUES (?, ?, ?, 0, ?, ?, ?, ?)',
                 (when, ip, host, severity, text, message, 'UDP'))
    conn.commit()
    conn.close()


def test_a_node_filter_reads_no_syslog_of_a_host_outside_the_cluster(env):
    """The syslog source turns ?node= into host names without asking whether the node is one
    of the cluster's. An auditor of one tenant then reads another tenant's node logs by
    naming that node on their own cluster's timeline, which /api/syslog/events refuses."""
    from pegaprox.api import reports
    env.seed.tenant('acme', clusters=[CID])
    env.seed.tenant('globex', clusters=['other'])
    other = env.api.make_fake_manager('other', get_tasks=[],
                                      get_node_status={'gx-pve9': {'status': 'online'}})
    other.config = types.SimpleNamespace(name='globex-prod', host='10.9.9.9')
    env.api.set_manager('other', other)
    reports._AMBIGUOUS_HOSTS['at'] = 0.0
    _syslog_line(_local(3), '10.9.9.9', 'gx-pve9', 'zfs: pool tank of globex faulted')
    # the Auditor template of acme: admin.audit, their own cluster only
    c = env.api.as_user(env.seed.user('aud', role='user', tenant_id='acme', permissions=['admin.audit']))

    r = c.get('/api/syslog/events?per_page=50')
    assert r.status_code == 200 and 'globex' not in r.get_data(as_text=True)

    leaked = [e['title'] for node in ('gx-pve9', 'stranger')     # stranger: a sender of no cluster (env)
              for e in _get(c, f'&node={node}')['events'] if e['kind'] == 'syslog']
    assert leaked == [], leaked


def test_a_caller_without_vm_view_gets_no_guest_migrations(env):
    """The migration routes ask vm.view per guest (/vms/<vmid>/migration-history and
    /api/migration-history); the timeline asks only a confined caller, so an account that
    may not view guests gets the guests' moves on the cluster page while the guest page
    of the same guest is refused."""
    c = env.api.as_user(env.seed.user('nemo', role='viewer', denied=['vm.view']))
    assert c.get(f'/api/clusters/{CID}/vms/100/migration-history').status_code == 403
    assert c.get(ROUTE + '&vmid=100').status_code == 403
    body = _get(c, '&kinds=migration')
    assert [e['guest_name'] for e in body['events']] == []


# --- paging ---------------------------------------------------------------------------------------
# Each test isolates one defect: distinct seconds where the same second is not the point, and
# every page past the first keeps an event, so a fix of that one defect turns it green.

def test_pages_go_past_more_events_of_one_second_than_a_page_holds(env):
    """A source reads its newest `limit` rows up to the second of the cursor. When that many
    of them fell into the cursor's second, the next page reads the same rows again, all of
    them at or after the cursor, and the list ends: the rest of that second and everything
    older is never handed out."""
    for i in range(12):
        env.db.add_migration_event(CID, 5000 + i, '', 'pve1', 'pve2', 'success', timestamp=_local(1))
    c = _admin_client(env)
    whole = _whole(c, '&kinds=migration')
    assert len(whole) == 13
    seen = _follow(c, '&kinds=migration&limit=5')
    assert sorted(seen) == sorted(whole), f'{len(seen)} of {len(whole)}: {sorted(set(whole) - set(seen))} never came'


def test_a_page_of_one_goes_past_the_first_event(env):
    """The same with limit=1 and one row per second: the next page reads the row of the
    cursor again, it fills the cap, and nothing older is read."""
    c = _admin_client(env)
    whole = _whole(c, '&kinds=audit')
    assert len(whole) == 3
    assert _follow(c, '&kinds=audit&limit=1') == whole


def test_a_page_the_floor_empties_still_says_more_follow(env):
    """The floor holds back what is older than the oldest row of a capped source. When the
    filter drops every row above the floor, the page is empty, and an empty page hands out
    no next_before: the critical events below it are never reached. On a busy cluster the
    newest audit rows are mostly info, so severity=critical shows nothing at all."""
    for i in range(3):
        _audit(env.db, 1 + i / 10, 'vm.config', 'Updated config of VM 100 [lab]')
    c = _admin_client(env)
    q = '&kinds=audit,node&severity=critical'
    whole = _whole(c, q)
    assert whole and all(i.startswith('node:') for i in whole)
    first = _get(c, q + '&limit=3')
    assert first['events'] or first['next_before'], 'an empty page ends the list while more wait below'
    assert _follow(c, q + '&limit=3') == whole


def test_a_guest_page_loses_no_rows_a_filtered_read_cut_at_the_page_size(env):
    """A source filtered in Python (a guest or node page, a confined caller) reads up to
    SCAN rows and cuts what it kept at the page size, but counts as capped only when the
    read reached SCAN. No floor, so the page goes on below the rows it cut."""
    for i in range(7):
        warn = i % 2 == 0
        _audit(env.db, 1 + i / 10, 'vm.stop' if warn else 'vm.start',
               ('Force stopped' if warn else 'Started') + ' VM 100 [lab]', severity='warning' if warn else 'info')
    env.db.add_migration_event(CID, 100, 'web01', 'pve1', 'pve2', 'failed', reason='lock', timestamp=_local(20))
    c = _admin_client(env)
    q = '&vmid=100&kinds=audit,migration&severity=warning'
    whole = _whole(c, q)
    assert sum(i.startswith('audit:') for i in whole) == 4 and any(i.startswith('migration:') for i in whole)
    assert _follow(c, q + '&limit=3') == whole


def test_the_floor_of_the_alerts_is_their_capped_read(env):
    """The alerts are two reads, fired and cleared, and the floor is the oldest event of
    both. A capped read of the fired ones with a clear far below it puts the floor down
    there, and the fired alerts the capped read left out are skipped."""
    _q(env.db, 'DELETE FROM active_alerts')
    for i in range(5):
        crit = i % 2 == 0
        _alert(env.db, f'f{i}', 1 + i / 10, 'vm', 100, 'web01', severity='critical' if crit else 'warning')
    _alert(env.db, 'old', 55, 'vm', 200, 'db01', severity='warning', resolved_ago=50)
    c = _admin_client(env)
    q = '&kinds=alert,node&severity=critical'
    whole = _whole(c, q)
    assert whole[:3] == ['alert:f0', 'alert:f2', 'alert:f4'] and whole[3].startswith('node:')
    assert _follow(c, q + '&limit=3') == whole


def test_the_rolling_updates_are_cut_newest_first(env):
    """The rolling updates are cut at the page size in the order runs are stored, each run
    with its start before its end, and count as never capped: the end of the older run
    (how it failed) falls between the start of the newer one and its own start."""
    state = {'nodes': ['pve1', 'pve2'], 'failed_nodes': [], 'started_by': 'root'}
    _q(env.db, "INSERT INTO rolling_update_runs (id, cluster_id, status, state, logs, started_by, started_at, "
               "completed_at) VALUES ('r2', ?, 'completed', ?, '[]', 'root', ?, ?)",
       CID, json.dumps(state), _local(30).replace('T', ' ')[:19], _local(20).replace('T', ' ')[:19])
    c = _admin_client(env)
    whole = _whole(c, '&kinds=rolling_update')
    assert whole == ['rolling_update:r2:ended', 'rolling_update:r2:started',
                     'rolling_update:r1:ended', 'rolling_update:r1:started']
    assert _follow(c, '&kinds=rolling_update&limit=3') == whole


# --- what the route reads -------------------------------------------------------------------------

def test_the_route_reads_no_node_list_when_the_syslog_memo_is_cold(env):
    """The syslog source drops host names two clusters claim (reports._syslog_ambiguous_hostnames),
    and working those out calls get_node_status() of every cluster once a minute. The test
    that says the route reads no node list (test_timeline.py) passes only when an earlier
    test in the same process filled that memo; on its own it fails."""
    from pegaprox.api import reports
    reports._AMBIGUOUS_HOSTS['at'] = 0.0
    _get(_admin_client(env))
    assert not env.mgr.get_node_status.called


# --- the query ------------------------------------------------------------------------------------

@pytest.mark.parametrize('query', [
    '&vmid=%C2%B2',                                        # str.isdigit() says yes, int() says no
    '&correlate=%C2%B2',
    '&to=0001-01-01T00:00:00',                             # the default window reaches before year 1
    '&to=0001-01-01T00:00:00%2B14:00',                     # no UTC time
    '&before=0001-01-01T00:00:00%2B14:00|audit:1',
])
def test_an_odd_value_is_a_400_not_a_crash(env, query):
    c = _admin_client(env)
    try:
        r = c.get(ROUTE + query)
    except Exception as e:      # the test app propagates what would be a 500
        pytest.fail(f'{query}: {type(e).__name__}: {e}')
    assert r.status_code == 400, (query, r.status_code, r.get_data(as_text=True)[:200])


# --- the node state history -----------------------------------------------------------------------

def test_a_takeover_dates_a_change_when_it_was_seen(db, monkeypatch):
    """A standby records nothing, and the instance that takes over compares its first read
    with the rows it wrote when it last acted. pve2 came back while it was a standby, and
    its history says pve2 came back at the takeover."""
    active = {'now': True}
    clock = {'now': '2026-10-01T08:00:00+00:00'}
    monkeypatch.setattr(node_history.ha, 'is_active', lambda: active['now'])
    monkeypatch.setattr(node_history, 'now_utc', lambda: clock['now'])
    node_history.observe(CID, _ns(pve1='online', pve2='online'))
    node_history.observe(CID, _ns(pve1='online', pve2='offline'))
    active['now'] = False
    clock['now'] = '2026-10-01T09:00:00+00:00'
    node_history.observe(CID, _ns(pve1='online', pve2='online'))      # pve2 is back
    assert _rows(db) == [('pve2', 'offline', 'online', '')]            # a standby writes nothing
    active['now'] = True
    clock['now'] = '2026-10-03T12:00:00+00:00'                          # two days later
    node_history.observe(CID, _ns(pve1='online', pve2='online'))
    back = [r['at'] for r in db.query("SELECT at FROM node_state_history WHERE state = 'online'")]
    assert back in ([], ['2026-10-01T09:00:00+00:00']), back
