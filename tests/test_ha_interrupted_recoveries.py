"""Interrupted recoveries across a change of leader (#625 stage 2, design 5.6; what the
round-two attack on slice S4 found, and where the journal meets the recovery fix).

  * a guest a recovery moved while its node was online, and did not start on purpose,
    stays listed with the reason, and the start of the moved guests leaves it out
  * a guest whose config move began and was never marked done (the mv ran, the leader
    was gone before it wrote so) and that sits stopped on another node is moved: listed
    so and started by an admin. A run is forgotten once nothing is left in it, never on
    a guest list that came back empty
  * a run kept for a config move that did not go through is not listed or said again
    once the guest runs or sits on the failed node again
  * the routes that start and dismiss what a run left: ha.config, the cluster's own runs
    only, audited, refused on a standby like the other HA writes

MK Oct 2026 (#625)
"""
import types
from unittest.mock import MagicMock

import pytest

from pegaprox.core import ha as _ha
from test_ha_members import IDS, group  # noqa: F401
from _ha_lease_harness import T, auto  # noqa: F401
from test_ha_guard_rounds import _worker_fake, pve

START_101 = 'https://10.0.0.1:8006/api2/json/nodes/pve1/qemu/101/status/start'


def _posts(m, status=200):
    posts = []

    class _Sess:
        def post(self, url, **k):
            posts.append(url)
            return types.SimpleNamespace(status_code=status)
    m._create_session = lambda: _Sess()
    return posts


def _guests(m, *rows):
    m.get_vm_resources = lambda *a, **k: [dict(zip(('vmid', 'node', 'status'), r), type='qemu')
                                          for r in rows]


def _said(f):
    return [c.args[1] for c in f._ha_refuse.call_args_list if c.args[0] == 'ha.recovery_interrupted']


# --- the recovery fix and the journal -------------------------------------------------------

def test_a_guest_moved_while_its_node_was_online_is_held_listed_and_never_started(
        auto, seed, db, monkeypatch):
    """pve2 is listed online again once the config of 101 moved: the worker leaves 101
    stopped where its config is now, as pve2 may still run it without a config. The
    journal says so: 101 is listed under held with the reason, not under moved, and the
    start of the moved guests does not start it."""
    from pegaprox.core.manager import PegaProxManager
    auto.form(seed)
    moved, started = [], []
    f = _worker_fake(monkeypatch, moved, started)
    f._ha_node_listed_online.return_value = True       # the look right before the start
    with auto.at('a') as ha:
        PegaProxManager._ha_recovery_worker(f, 'pve2')
        assert ha.is_active()
        mine = ha.recovery_leftovers('c1')
        ha._recovery_live.clear()
        m = pve()
        posts = _posts(m)
        _guests(m, (101, 'pve1', 'stopped'))
        m._ha_refuse = MagicMock()
        listed = m.ha_interrupted_recoveries()
        assert m.ha_start_moved_vms() == {} and posts == []
        m._ha_say_interrupted()
        still = ha.recovery_leftovers('c1')
    assert moved == [101] and started == []
    assert [(r['moved'], r['held'], r['guests_open']) for r in mine] == [([], [101], [])]
    # reported by the worker as moved and not started, not as an interrupted recovery
    assert not _said(f)
    assert len(listed) == 1 and listed[0]['held'] == [101] and listed[0]['moved'] == []
    assert 'pve2 may still run it without a config' in listed[0]['held_note']
    assert [r['held'] for r in still] == [[101]]
    text, = _said(m)
    assert 'not started on purpose' in text and '101' in text


def test_a_held_guest_drops_out_once_an_admin_started_it(auto, seed, db):
    auto.form(seed)
    with auto.at('a') as ha:
        ha.recovery_step('r', 'c1', 'pve2', 'move_config', vmid=101, done=True)
        ha.recovery_step('r', 'c1', 'pve2', 'hold', vmid=101, done=True)
        m = pve()
        _guests(m, (101, 'pve1', 'stopped'))
        assert [r['held'] for r in m.ha_interrupted_recoveries()] == [[101]]
        _guests(m, (101, 'pve1', 'running'))
        assert m.ha_interrupted_recoveries() == []
        assert ha.recovery_leftovers() == []


def test_the_guests_left_with_a_node_that_is_back_need_nothing_from_the_journal(auto, seed, db, monkeypatch):
    """pve2 is back right before the config of 101 would move: nothing moved, 101 stays
    with pve2. The run is forgotten, nothing is listed."""
    from pegaprox.core.manager import PegaProxManager
    auto.form(seed)
    moved, started = [], []
    f = _worker_fake(monkeypatch, moved, started)
    f._ha_node_back.return_value = True
    f._ha_leave_to_node.return_value = [(101, 'running')]
    with auto.at('a') as ha:
        PegaProxManager._ha_recovery_worker(f, 'pve2')
        ha._recovery_live.clear()
        assert ha.recovery_leftovers() == []
    assert moved == [] and started == [] and not _said(f)


# --- a move that went through and was never marked done ------------------------------------

def _dead_leader_mid_move(ha, step='move_config'):
    run = ha.recovery_begin('c1', 'pve2')
    ha.recovery_step(run, 'c1', 'pve2', 'fence')
    ha.recovery_step(run, 'c1', 'pve2', 'fence', done=True)
    ha.recovery_step(run, 'c1', 'pve2', 'clear_lock', vmid=101)
    ha.recovery_step(run, 'c1', 'pve2', 'clear_lock', vmid=101, done=True)
    if step == 'start':
        ha.recovery_step(run, 'c1', 'pve2', 'move_config', vmid=101)
        ha.recovery_step(run, 'c1', 'pve2', 'move_config', vmid=101, done=True)
    ha.recovery_step(run, 'c1', 'pve2', step, vmid=101)
    # the mv went out and ran; the leader is gone before `done` (what a restart sees)
    ha._recovery_live.clear()
    return run


@pytest.mark.parametrize('step', ['move_config', 'start'])
def test_a_guest_whose_move_was_not_marked_done_is_started_by_the_admin_and_the_run_forgotten(
        auto, seed, db, step):
    auto.form(seed)
    m = pve()
    posts = _posts(m)
    _guests(m, (101, 'pve1', 'stopped'))           # the config is on pve1 now
    m._ha_refuse = MagicMock()
    with auto.at('a') as ha:
        _dead_leader_mid_move(ha, step)
        listed = m.ha_interrupted_recoveries()
        m._ha_say_interrupted()
        started = m.ha_start_moved_vms()
        after = ha.recovery_leftovers('c1')
    assert [(r['moved'], r['guests_open']) for r in listed] == [([101], [])]
    text, = _said(m)
    assert 'guests moved and not started: 101' in text
    assert started == {101: True} and posts == [START_101]
    assert after == []


def test_nothing_is_forgotten_on_a_guest_list_that_came_back_empty(auto, seed, db):
    auto.form(seed)
    m = pve()
    posts = _posts(m)
    _guests(m)                                      # the cluster did not answer
    with auto.at('a') as ha:
        run = _dead_leader_mid_move(ha)
        listed = m.ha_interrupted_recoveries()
        assert m.ha_start_moved_vms() == {} and posts == []
        assert [r['run'] for r in ha.recovery_leftovers('c1')] == [run]
    assert [(r['moved'], r['guests_open']) for r in listed] == [([], [101])]


def test_a_run_that_left_nothing_for_the_guests_is_forgotten_only_once_the_list_answers(auto, seed, db):
    """The leader was gone in the middle of the fence of pve2: the next pass does it
    again, nothing is left for an admin. Forgotten once the guests could be read, not
    while the list comes back empty."""
    auto.form(seed)
    m = pve()
    _posts(m)
    _guests(m)
    with auto.at('a') as ha:
        run = ha.recovery_begin('c1', 'pve2')
        ha.recovery_step(run, 'c1', 'pve2', 'fence')
        ha._recovery_live.clear()
        assert [r['open'] for r in m.ha_interrupted_recoveries()] == [['fence']]
        assert m.ha_start_moved_vms() == {}
        assert [r['run'] for r in ha.recovery_leftovers()] == [run]
        _guests(m, (101, 'pve1', 'running'))
        assert m.ha_interrupted_recoveries() == []
        assert ha.recovery_leftovers() == []


def test_a_guest_whose_config_never_left_is_the_monitors_again(auto, seed, db):
    """The leader was gone after the lock of 101 was cleared, before its config moved:
    101 still sits on pve2, the next leader's monitor recovers it. Nothing is listed."""
    auto.form(seed)
    m = pve()
    _guests(m, (101, 'pve2', 'stopped'))
    with auto.at('a') as ha:
        _dead_leader_mid_move(ha, 'clear_lock')
        assert m.ha_interrupted_recoveries() == []
        assert ha.recovery_leftovers() == []


def test_a_member_reads_the_journal_and_leaves_it_to_the_leader(auto, seed, db):
    auto.form(seed)
    m = pve()
    _guests(m, (101, 'pve2', 'stopped'))
    with auto.at('a') as ha:
        _dead_leader_mid_move(ha, 'clear_lock')
    with auto.at('b') as ha:
        assert not ha.is_active()
        assert m.ha_interrupted_recoveries() == []
        assert len(ha.recovery_leftovers()) == 1


# --- a config move that did not go through --------------------------------------------------

def test_a_failed_config_move_leaves_nothing_listed_once_the_guest_is_recovered(
        auto, seed, db, monkeypatch):
    """The first pass: the mv of 101's config fails, it still sits on pve2, nothing was
    started. The run is not kept for it, and nothing is said: the next pass moves and
    starts 101, and no run stays listed after that."""
    from pegaprox.core.manager import PegaProxManager
    auto.form(seed)
    moved, started = [], []
    f = _worker_fake(monkeypatch, moved, started)
    f._ha_move_vm_config.side_effect = lambda *a: False
    f._ha_vm_is_on.return_value = False
    f._ha_guests_now.return_value = {101: {'vmid': 101, 'node': 'pve2', 'status': 'stopped'}}
    with auto.at('a') as ha:
        PegaProxManager._ha_recovery_worker(f, 'pve2')
        first = ha.recovery_leftovers('c1')
        f._ha_move_vm_config.side_effect = lambda *a: moved.append(a[0]) or True
        f._ha_vm_is_on.return_value = True
        PegaProxManager._ha_recovery_worker(f, 'pve2')
        ha._recovery_live.clear()
        later = ha.recovery_leftovers('c1')
    assert first == [] and later == [] and not _said(f)
    assert len(started) == 1


def test_a_failed_move_whose_guest_could_not_be_placed_is_kept_until_it_is(auto, seed, db, monkeypatch):
    """The guests could not be read as the worker ended: the config may have left with
    a mv whose answer was lost, so the run is kept and said. Once the guest runs (the
    next pass recovered it), the listing drops it and forgets the run."""
    from pegaprox.core.manager import PegaProxManager
    auto.form(seed)
    moved, started = [], []
    f = _worker_fake(monkeypatch, moved, started)
    f._ha_move_vm_config.side_effect = lambda *a: False
    f._ha_vm_is_on.return_value = False
    with auto.at('a') as ha:
        PegaProxManager._ha_recovery_worker(f, 'pve2')
        kept = ha.recovery_leftovers('c1')
        m = pve()
        _guests(m, (101, 'pve1', 'running'))
        listed = m.ha_interrupted_recoveries()
        after = ha.recovery_leftovers('c1')
    assert [(r['guests_open'], r['open']) for r in kept] == [([101], ['move_config 101'])]
    assert len(_said(f)) == 1
    assert listed == [] and after == []


def test_the_end_of_a_run_keeps_only_what_may_have_left_the_node(auto, seed, db):
    auto.form(seed)
    with auto.at('a') as ha:
        run = ha.recovery_begin('c1', 'pve2')
        ha.recovery_step(run, 'c1', 'pve2', 'clear_lock', vmid=101)      # its config never left
        ha.recovery_step(run, 'c1', 'pve2', 'move_config', vmid=102)     # sits on pve2: did not
        ha.recovery_step(run, 'c1', 'pve2', 'move_config', vmid=103)     # sits on pve1: did
        ha.recovery_step(run, 'c1', 'pve2', 'move_config', vmid=104, done=True)
        ha.recovery_step(run, 'c1', 'pve2', 'start', vmid=104)           # its start began
        where = {102: {'node': 'pve2'}, 103: {'node': 'pve1'}, 104: {'node': 'pve1'}}
        left = ha.recovery_end(run, lambda: where)
        assert (left['guests_open'], left['moved']) == ([103, 104], [104])
        assert left['open'] == ['move_config 103', 'start 104']
        ha._recovery_live.clear()
        stored, = ha.recovery_leftovers('c1')
    assert stored['guests_open'] == [103, 104] and stored['open'] == ['move_config 103', 'start 104']


# --- the routes -------------------------------------------------------------------------------

START = '/api/clusters/c1/ha/interrupted-recoveries/start'
DISMISS = '/api/clusters/c1/ha/interrupted-recoveries/dismiss'


@pytest.fixture
def journal(api, seed, monkeypatch):
    """Two runs on c1 (101 moved and stopped on pve1, 102 held) and one on c2; c1 a
    manager without a network. The journal is written as an automatic leader writes it,
    the instance itself is standalone."""
    for run, cid, steps in (('7.aaaa.0001', 'c1', (('move_config', 101), ('move_config', 102),
                                                   ('hold', 102))),
                            ('7.aaaa.0002', 'c2', (('move_config', 201),))):
        for step, vmid in steps:
            _ha.recovery_step(run, cid, 'pve2', step, vmid=vmid, done=True)
    m = pve()
    posts = _posts(m)
    _guests(m, (101, 'pve1', 'stopped'), (102, 'pve1', 'stopped'))
    api.set_manager('c1', m)
    api.set_manager('c2', pve())
    audits = []
    import pegaprox.api.clusters as clusters_api
    monkeypatch.setattr(clusters_api, 'log_audit',
                        lambda user, action, details=None, **kw: audits.append((user, action, details)))
    return types.SimpleNamespace(m=m, posts=posts, audits=audits,
                                 admin=api.as_user(seed.user('root1', role='admin')))


def test_the_admin_starts_the_moved_guests_and_the_held_one_is_named(journal):
    r = journal.admin.post(START, json={'runs': ['7.aaaa.0001', '7.aaaa.0002', 'nope']})
    assert r.status_code == 200, r.data
    body = r.get_json()
    assert body['started'] == [101] and body['failed'] == []
    assert [(h['vmid'], h['run']) for h in body['held']] == [(102, '7.aaaa.0001')]
    assert 'may still run it without a config' in body['held'][0]['note']
    # another cluster's run is not this cluster's to start
    assert body['unknown'] == ['7.aaaa.0002', 'nope']
    assert journal.posts == [START_101]
    # the held guest keeps its run listed
    assert [r['run'] for r in _ha.recovery_leftovers('c1')] == ['7.aaaa.0001']
    (user, action, details), = journal.audits
    assert (user, action) == ('root1', 'ha.interrupted_recoveries_started')
    assert 'started: 101' in details and 'held: 102' in details


def test_the_admin_dismisses_a_run_of_this_cluster_only(journal):
    r = journal.admin.post(DISMISS, json={'runs': ['7.aaaa.0001', '7.aaaa.0002']})
    assert r.status_code == 200, r.data
    assert r.get_json() == {'dismissed': ['7.aaaa.0001'], 'unknown': ['7.aaaa.0002']}
    assert _ha.recovery_leftovers('c1') == []
    assert [r['run'] for r in _ha.recovery_leftovers('c2')] == ['7.aaaa.0002']
    (user, action, details), = journal.audits
    assert action == 'ha.interrupted_recoveries_dismissed' and '7.aaaa.0001' in details
    assert journal.posts == []


@pytest.mark.parametrize('body', [None, {}, {'runs': []}, {'runs': 'r'}, {'runs': [1]}, {'runs': ['x' * 65]}])
def test_a_body_without_run_ids_is_refused(journal, body):
    for path in (START, DISMISS):
        r = journal.admin.post(path, json=body)
        assert r.status_code == 400, (path, r.data)
    assert journal.posts == [] and journal.audits == []
    assert len(_ha.recovery_leftovers()) == 2


def test_without_ha_config_or_from_another_tenant_nothing_is_started_or_dismissed(api, seed, journal):
    viewer = api.as_user(seed.user('ops', role='user', permissions=['ha.view', 'cluster.view']))
    seed.tenant('t1', ['c2'])
    other = api.as_user(seed.user('tops', role='user', tenant_id='t1', permissions=['ha.config']))
    for client in (viewer, other):
        for path in (START, DISMISS):
            r = client.post(path, json={'runs': ['7.aaaa.0001']})
            assert r.status_code == 403, (path, r.status_code, r.data)
    assert journal.posts == [] and journal.audits == []
    assert len(_ha.recovery_leftovers()) == 2
    # the counterproof: ha.config without being an admin is what it takes
    ops = api.as_user(seed.user('ops2', role='user', permissions=['ha.config']))
    assert ops.post(START, json={'runs': ['7.aaaa.0001']}).get_json()['started'] == [101]


def test_on_a_standby_both_are_refused_like_the_other_ha_writes(journal, monkeypatch):
    import pegaprox.api.ha as ha_api
    monkeypatch.setattr(_ha, 'is_standby', lambda: True)
    monkeypatch.setattr(ha_api, 'forward_to_active', lambda read=False: None)
    for path in (START, DISMISS, '/api/clusters/c1/ha/enable'):
        r = journal.admin.post(path, json={'runs': ['7.aaaa.0001']})
        assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY', (path, r.data)
    assert journal.posts == [] and journal.audits == []
    assert len(_ha.recovery_leftovers()) == 2


# --- the next leader holds a moved guest as the worker would ---------------------------------

class _Died(BaseException):
    """The leader's process ends here (a restart after a lost lease, a crash)."""


def _nodes(m, posts, pve2_online):
    """The cluster API of c1: /nodes lists pve2 as said, a start is recorded."""
    class _Sess:
        def get(self, url, **k):
            if url.endswith('/nodes'):
                return types.SimpleNamespace(status_code=200, json=lambda: {'data': [
                    {'node': 'pve1', 'status': 'online'},
                    {'node': 'pve2', 'status': 'online' if pve2_online else 'offline'}]})
            return types.SimpleNamespace(status_code=200, json=lambda: {'data': []})

        def post(self, url, **k):
            posts.append(url)
            return types.SimpleNamespace(status_code=200, text='')
    m._create_session = lambda: _Sess()


def _die_in_the_sleep_after_the_move(monkeypatch, moved, seen):
    import pegaprox.core.manager as mgr_mod
    from pegaprox.core.db import get_db

    def sleep(s):
        if moved and s == 2:
            seen.extend(tuple(r) for r in get_db().conn.execute(
                'SELECT step, vmid, done FROM ha_recovery_journal ORDER BY at, id').fetchall())
            raise _Died()
    monkeypatch.setattr(mgr_mod.time, 'sleep', sleep)


def test_a_leader_gone_in_the_sleep_after_the_move_leaves_the_guest_held(auto, seed, db, monkeypatch):
    """101's config moved, then the leader died in the 2 s sleep before the look that
    would have held it, with pve2 back online. The hold was begun before the sleep: the
    next leader lists 101 under held and the start of the moved guests leaves it alone."""
    from pegaprox.core.manager import PegaProxManager
    auto.form(seed)
    moved, started, seen = [], [], []
    f = _worker_fake(monkeypatch, moved, started)
    f._ha_node_listed_online.return_value = True
    _die_in_the_sleep_after_the_move(monkeypatch, moved, seen)
    with auto.at('a') as ha:
        with pytest.raises(_Died):
            PegaProxManager._ha_recovery_worker(f, 'pve2')
        ha._recovery_live.clear()
        m = pve()
        posts = []
        _nodes(m, posts, pve2_online=True)
        _guests(m, (101, 'pve1', 'stopped'))
        listed = m.ha_interrupted_recoveries()
        out = m.ha_start_moved_vms()
    assert moved == [101] and started == []
    assert ('hold', 101, 0) in seen and ('move_config', 101, 1) in seen
    assert [(r['moved'], r['held']) for r in listed] == [([], [101])]
    assert 'may still run it without a config' in listed[0]['held_note']
    assert out == {} and posts == []


@pytest.mark.parametrize('online', [True, False])
def test_a_moved_guest_whose_hold_row_never_arrived_is_held_while_its_node_is_online(
        auto, seed, db, monkeypatch, online):
    """The hold row did not reach the next leader (the leader was gone before the tick):
    101 reads as moved. The next leader asks the node itself: listed online, 101 is held;
    gone and not seen since the move, 101 is started."""
    from pegaprox.core.manager import PegaProxManager
    from pegaprox.core.db import get_db
    auto.form(seed)
    moved, started, seen = [], [], []
    f = _worker_fake(monkeypatch, moved, started)
    _die_in_the_sleep_after_the_move(monkeypatch, moved, seen)
    with auto.at('a') as ha:
        with pytest.raises(_Died):
            PegaProxManager._ha_recovery_worker(f, 'pve2')
        conn = get_db().conn
        conn.execute("DELETE FROM ha_recovery_journal WHERE step = 'hold'")
        conn.commit()
        ha._recovery_live.clear()
        m = pve()
        posts = []
        _nodes(m, posts, pve2_online=online)
        _guests(m, (101, 'pve1', 'stopped'))
        listed = m.ha_interrupted_recoveries()
        out = m.ha_start_moved_vms()
    if online:
        assert [(r['moved'], r['held']) for r in listed] == [([], [101])]
        assert out == {} and posts == []
    else:
        assert [(r['moved'], r['held']) for r in listed] == [([101], [])]
        assert out == {101: True} and posts == [START_101]


def test_the_start_route_holds_a_moved_guest_while_its_failed_node_is_online(api, seed):
    """POST .../start: 101 moved (marked done, no hold, no start), pve2 listed online
    again. Held with the reason, not started."""
    _ha.recovery_step('7.aaaa.0009', 'c1', 'pve2', 'move_config', vmid=101, done=True)
    m = pve()
    posts = []
    _nodes(m, posts, pve2_online=True)
    _guests(m, (101, 'pve1', 'stopped'))
    api.set_manager('c1', m)
    admin = api.as_user(seed.user('root1', role='admin'))
    r = admin.post(START, json={'runs': ['7.aaaa.0009']})
    assert r.status_code == 200, r.data
    body = r.get_json()
    assert body['started'] == [] and [h['vmid'] for h in body['held']] == [101]
    assert 'may still run it without a config' in body['held'][0]['note']
    assert posts == []
    # still listed, for an admin who looked at pve2
    assert [r['run'] for r in _ha.recovery_leftovers('c1')] == ['7.aaaa.0009']


def test_a_node_back_since_the_listing_is_looked_at_again_before_the_start(api, seed):
    """The listing said moved; pve2 is listed online by the time the admin starts it."""
    _ha.recovery_step('7.aaaa.0010', 'c1', 'pve2', 'move_config', vmid=101, done=True)
    m = pve()
    posts = []
    _nodes(m, posts, pve2_online=False)
    _guests(m, (101, 'pve1', 'stopped'))
    listed = m.ha_interrupted_recoveries()
    assert listed[0]['moved'] == [101]
    _nodes(m, posts, pve2_online=True)
    assert m.ha_start_moved_vms(listed=listed) == {} and posts == []
    assert listed[0]['held'] == [101] and listed[0]['moved'] == []


def _ago(minutes):
    from datetime import datetime, timedelta, timezone
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes)).replace(microsecond=0).isoformat()


@pytest.mark.parametrize('seen, held', [(-30, True), (-60, True), (-120, False), (None, False)])
def test_a_pass_that_saw_the_node_online_since_the_move_holds_the_guest(api, seed, db, seen, held):
    """pve2 is not listed online now; 101's config moved an hour ago. A monitor pass here
    that saw pve2 online after the move (or within the skew allowed around it) holds
    101; one from well before the move does not, and neither does a node first tracked
    while it was offline (last_seen set, never seen online)."""
    from datetime import datetime, timedelta
    from pegaprox.core.db import get_db
    _ha.recovery_step('7.aaaa.0011', 'c1', 'pve2', 'move_config', vmid=101, done=True)
    conn = get_db().conn
    conn.execute('UPDATE ha_recovery_journal SET at = ?', (_ago(60),))
    conn.commit()
    m = pve()
    _nodes(m, [], pve2_online=False)
    _guests(m, (101, 'pve1', 'stopped'))
    status = {'status': 'offline', 'last_seen': datetime.now()}
    if seen is not None:
        status['online_at'] = datetime.now() + timedelta(minutes=seen)
    m.ha_node_status = {'pve2': status}
    rec, = m.ha_interrupted_recoveries()
    assert (rec['held'], rec['moved']) == (([101], []) if held else ([], [101]))


def test_the_monitor_notes_a_node_as_seen_online_only_when_a_pass_lists_it_online():
    from pegaprox.core.manager import PegaProxManager
    m = pve()
    m.ha_failure_threshold = 3
    m.nodes_in_maintenance, m.ha_recovery_in_progress = set(), {}
    m._ha_cluster_quorum = lambda: (True, None)
    _nodes(m, [], pve2_online=False)
    PegaProxManager._ha_check_nodes(m)
    assert 'online_at' in m.ha_node_status['pve1']
    # tracked from this pass on, with a last_seen, and never seen online
    assert 'online_at' not in m.ha_node_status['pve2'] and m.ha_node_status['pve2']['last_seen']


def test_a_hold_begun_counts_as_held(auto, seed, db):
    auto.form(seed)
    with auto.at('a') as ha:
        ha.recovery_step('r1', 'c1', 'pve2', 'move_config', vmid=101, done=True)
        ha.recovery_step('r1', 'c1', 'pve2', 'hold', vmid=101)
        rec, = ha.recovery_leftovers('c1')
        assert (rec['held'], rec['moved'], rec['guests_open'], rec['open']) == ([101], [], [], [])
        # cleared by the look that found the node away: moved again
        ha.recovery_clear('r1', 'hold', 101)
        rec, = ha.recovery_leftovers('c1')
        assert (rec['held'], rec['moved']) == ([], [101])


# --- the journal goes to the members at once ----------------------------------------------

def test_the_begun_rows_of_a_move_go_on_before_its_round_with_the_hold(auto, seed, db, monkeypatch):
    """Right after the 'begun' row of the config move, with the hold written just before
    it: the cv steps and the members hear of both (cv_tick), and only then the step's
    confirm round and the mv. One send-on per guest - the start and the other rows wait
    for the tick, since each send-on is a walk of the shared tables in the recovery's time."""
    from pegaprox.core.manager import PegaProxManager
    auto.form(seed)
    events = []
    moved, started = [], []
    f = _worker_fake(monkeypatch, moved, started)
    real_write = _ha._recovery_write

    def write(sql, args):
        if sql.startswith('INSERT'):
            events.append(f"{args[6]}{' ' + str(args[7]) if args[7] is not None else ''}"
                          f"{' done' if args[8] else ' begun'}")
        return real_write(sql, args)
    monkeypatch.setattr(_ha, '_recovery_write', write)
    monkeypatch.setattr(_ha, 'cv_tick', lambda force=False: events.append('cv_tick') or 'stepped')
    real_confirm = _ha.confirm_step
    monkeypatch.setattr(_ha, 'confirm_step', lambda what, need=_ha.NEED_STEP:
                        events.append(f'confirm {what}') or real_confirm(what, need))
    real_move = f._ha_move_vm_config.side_effect
    f._ha_move_vm_config.side_effect = lambda *a: events.append('mv') or real_move(*a)
    real_post = f._create_session.return_value.post.side_effect
    f._create_session.return_value.post.side_effect = \
        lambda url, **k: events.append('start') or real_post(url, **k)
    with auto.at('a'):
        PegaProxManager._ha_recovery_worker(f, 'pve2')
    i = events.index('move_config 101 begun')
    assert events[i - 1:i + 4] == ['hold 101 begun', 'move_config 101 begun', 'cv_tick',
                                   'confirm moving the config of 101', 'mv']
    j = events.index('start 101 begun')
    assert events[j:j + 3] == ['start 101 begun', 'confirm starting 101 on pve1', 'start']
    assert events.count('cv_tick') == 1
    assert started and moved == [101]


def test_the_round_after_a_begun_row_brings_the_voters_to_pull(auto, seed, db):
    """What closes the window: the row steps the cv, the confirm round that follows carries
    the leader's cv in every renewal, and a voter that holds less pulls at once - before
    the leader's step goes out, not with the nudge or the next poll."""
    auto.form(seed)
    with auto.at('a') as ha:
        before = ha.cv_entry()
        run = ha.recovery_begin('c1', 'pve2')
        auto.pulls.clear()
        ha.recovery_step(run, 'c1', 'pve2', 'move_config', vmid=101)
        assert ha.cv_entry() != before
        assert ha.confirm_step('moving the config of 101')
    assert set(auto.pulls) >= {'b', 'c'}


def test_in_manual_mode_the_journal_writes_nothing_and_sends_nothing(api, seed, db, monkeypatch):
    ticks = []
    monkeypatch.setattr(_ha, 'cv_tick', lambda force=False: ticks.append(1))
    assert _ha.recovery_begin('c1', 'pve2') is None
    _ha.recovery_step(None, 'c1', 'pve2', 'move_config', vmid=101)
    _ha.recovery_step(None, 'c1', 'pve2', 'start', vmid=101)
    assert ticks == [] and _ha.recovery_leftovers() == []


# --- what is read, and what is kept --------------------------------------------------------

def _row(conn, run, cid, node, step, vmid, done, at):
    key = f"{run}/{step}" + (f"/{vmid}" if vmid is not None else '')
    conn.execute('INSERT OR REPLACE INTO ha_recovery_journal (id, run, cluster_id, node, epoch, instance_id, '
                 'step, vmid, done, at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                 (key, run, cid, node, 3, 'aaaaaaaaaaaa', step, vmid, done, at))


def test_kept_runs_of_a_large_recovery_on_another_cluster_hide_no_later_run(db):
    """60 kept runs of 100 guests each on c2 (more rows than the old read window of
    RECOVERY_KEEP * 64): the run on c1 after them is read, listed and startable."""
    from pegaprox.core.db import get_db
    _ha.recovery_step('x', 'c0', 'n', 'begin', done=True)
    conn = get_db().conn
    conn.execute('DELETE FROM ha_recovery_journal')
    for k in range(60):
        run, at = f'3.aaaa.{k:04d}', f'2026-10-0{1 + k // 30}T10:{k % 30:02d}:00+00:00'
        _row(conn, run, 'c2', f'r{k}', 'begin', None, 1, at)
        for i in range(100):
            v = 10000 + k * 100 + i
            for step in ('clear_lock', 'move_config', 'start'):
                _row(conn, run, 'c2', f'r{k}', step, v, 0, at)
                _row(conn, run, 'c2', f'r{k}', step, v, 1, at)
        _row(conn, run, 'c2', f'r{k}', 'hold', 10000 + k * 100, 1, at)
    _row(conn, '4.bbbb.0001', 'c1', 'pve2', 'begin', None, 1, '2026-10-05T08:00:00+00:00')
    _row(conn, '4.bbbb.0001', 'c1', 'pve2', 'move_config', 101, 1, '2026-10-05T08:00:01+00:00')
    conn.commit()
    assert conn.execute('SELECT COUNT(*) FROM ha_recovery_journal').fetchone()[0] > _ha.RECOVERY_KEEP * 64
    c1 = _ha.recovery_leftovers('c1')
    assert [(r['run'], r['moved']) for r in c1] == [('4.bbbb.0001', [101])]
    m = pve()
    _guests(m, (101, 'pve1', 'stopped'))
    assert [r['moved'] for r in m.ha_interrupted_recoveries()] == [[101]]


def test_past_recovery_keep_the_newest_runs_are_read_and_the_rest_said_once(db, monkeypatch):
    from pegaprox.core.db import get_db
    monkeypatch.setattr(_ha, 'RECOVERY_KEEP', 3)
    monkeypatch.setattr(_ha, '_recovery_said', {})
    audits = []
    monkeypatch.setattr(_ha, '_audit', lambda action, details: audits.append((action, details)))
    _ha.recovery_step('x', 'c0', 'n', 'begin', done=True)
    conn = get_db().conn
    conn.execute('DELETE FROM ha_recovery_journal')
    for k in range(5):
        _row(conn, f'5.aaaa.{k}', 'c1', 'pve2', 'move_config', 100 + k, 1, f'2026-10-03T10:0{k}:00+00:00')
    _row(conn, '5.bbbb.0', 'c2', 'pve9', 'move_config', 900, 1, '2026-10-03T11:00:00+00:00')
    conn.commit()
    for _ in range(3):
        runs = _ha.recovery_leftovers('c1')
        # the newest three, oldest first
        assert [r['run'] for r in runs] == ['5.aaaa.2', '5.aaaa.3', '5.aaaa.4']
    assert len(audits) == 1 and '5 interrupted node recoveries are kept for cluster c1' in audits[0][1]
    # the other cluster's run is its own
    assert [r['run'] for r in _ha.recovery_leftovers('c2')] == ['5.bbbb.0']


def test_the_rows_of_guests_that_started_in_a_kept_run_go(auto, seed, db):
    """A run kept for one held guest held every row of its started guests for good: they
    go at its end, and so do the rows of a guest an admin started from the listing, or
    one the listing finds running."""
    from pegaprox.core.db import get_db

    def vmids(run):
        return {r[0] for r in get_db().conn.execute('SELECT vmid FROM ha_recovery_journal WHERE run = ?',
                                                    (run,))}
    auto.form(seed)
    with auto.at('a') as ha:
        run = ha.recovery_begin('c1', 'pve2')
        for v in (101, 102, 103):
            ha.recovery_step(run, 'c1', 'pve2', 'clear_lock', vmid=v, done=True)
            ha.recovery_step(run, 'c1', 'pve2', 'move_config', vmid=v, done=True)
        for v in (101, 102):
            ha.recovery_step(run, 'c1', 'pve2', 'start', vmid=v, done=True)
        ha.recovery_step(run, 'c1', 'pve2', 'hold', vmid=103, done=True)
        assert ha.recovery_end(run) is None
        assert vmids(run) == {None, 103}
        # a second run: 201 moved, 202 held; the admin starts 201
        run2 = '7.aaaa.0099'
        for v in (201, 202):
            ha.recovery_step(run2, 'c1', 'pve2', 'move_config', vmid=v, done=True)
        ha.recovery_step(run2, 'c1', 'pve2', 'hold', vmid=202, done=True)
        m = pve()
        posts = _posts(m)
        _guests(m, (201, 'pve1', 'stopped'), (202, 'pve1', 'stopped'), (103, 'pve1', 'stopped'))
        assert m.ha_start_moved_vms(runs=[run2]) == {201: True}
        assert vmids(run2) == {202} and len(posts) == 1
        # the held one an admin started by hand: the listing finds it running
        _guests(m, (202, 'pve1', 'running'), (103, 'pve1', 'stopped'))
        m.ha_interrupted_recoveries()
        assert vmids(run2) == set()


class _Died(BaseException):
    pass


def test_a_leader_gone_between_the_move_and_its_look_leaves_the_guest_held(auto, seed, db, monkeypatch):
    """pve2 was online while 101's config moved, and the leader is gone in the pmxcfs sleep,
    before its look. The next leader has the journal only as far as the last send-on
    carried it, its monitor has seen no pass yet, and pve2 is listed offline by now: the
    hold, written before the move and sent on with it, keeps 101 from being started."""
    from pegaprox.core.manager import PegaProxManager
    import pegaprox.core.manager as mgr_mod
    auto.form(seed)
    rows, sent_upto = [], []
    moved, started = [], []
    f = _worker_fake(monkeypatch, moved, started)
    f._ha_node_listed_online.return_value = True
    real_write = _ha._recovery_write

    def write(sql, args):
        if sql.startswith('INSERT'):
            rows.append(args[0])
        return real_write(sql, args)
    monkeypatch.setattr(_ha, '_recovery_write', write)
    # what a member pulls when the cv steps: every row written so far
    monkeypatch.setattr(_ha, 'cv_tick', lambda force=False: sent_upto.append(len(rows)) or 'stepped')

    def sleep(s):
        if moved and s == 2:
            raise _Died()
    monkeypatch.setattr(mgr_mod.time, 'sleep', sleep)
    with auto.at('a') as ha:
        with pytest.raises(_Died):
            PegaProxManager._ha_recovery_worker(f, 'pve2')
        carried = set(rows[:sent_upto[-1]])
        assert any(r.endswith('/hold/101') for r in carried)
        # the next leader's copy: what the last send-on carried, nothing after it
        from pegaprox.core.db import get_db
        conn = get_db().conn
        for rid in rows[sent_upto[-1]:]:
            if rid in carried:
                conn.execute('UPDATE ha_recovery_journal SET done = 0 WHERE id = ?', (rid,))
            else:
                conn.execute('DELETE FROM ha_recovery_journal WHERE id = ?', (rid,))
        conn.commit()
        ha._recovery_live.clear()
        m = pve()
        posts = []

        class _Sess:
            def get(self, url, **k):
                if url.endswith('/nodes'):
                    return types.SimpleNamespace(status_code=200, json=lambda: {'data': [
                        {'node': 'pve1', 'status': 'online'}, {'node': 'pve2', 'status': 'offline'}]})
                return types.SimpleNamespace(status_code=200, json=lambda: {'data': []})

            def post(self, url, **k):
                posts.append(url)
                return types.SimpleNamespace(status_code=200, text='')
        m._create_session = lambda: _Sess()
        m.get_vm_resources = lambda *a, **k: [{'vmid': 101, 'node': 'pve1', 'status': 'stopped', 'type': 'qemu'}]
        listed = m.ha_interrupted_recoveries()
        out = m.ha_start_moved_vms()
    assert listed and listed[0]['held'] == [101] and listed[0]['moved'] == []
    assert out == {} and posts == []
