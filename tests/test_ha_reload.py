"""Changes reach the members of a group fast, and nobody is signed out for them (#625).

A standby with the live view used to restart once a sync had changed how one of its
managers connects, and every start ends every session. Now it reloads, in this
process, only the managers the change is about: a cluster, PBS or ESXi server added on
the leader is started here read-only, one removed is stopped and dropped, one whose
connection changed is stopped and built again. The process still restarts for a
switched live view and for a new role, and for nothing else.

The leader tells its members after a write (POST /api/ha/peer/changed), so a member
pulls within seconds instead of at its next poll.

Runs on the in-process group of tests/test_ha_members.py. The managers are stand-ins
that note what is done to them. A timer the code starts (ha._later) is noted and run
by the test, on the instance that started it, once the clock has moved past it.
The last part runs on the single standby of tests/test_ha_v2_managers.py instead,
with real threads: two of them on the one state file of the group would not work.

MK Oct 2026
"""
import json
import threading
import time
import types

import pytest

import pegaprox.globals as gl
from pegaprox.core import ha
from test_ha_members import group, _built, _post, _send, _sync, IDS  # noqa: F401
from test_ha_signed_peers import _sign_as
from test_ha_api import _admin, _local_user, _audit, ADMIN_PW
from test_ha_v2_managers import (  # noqa: F401  (env and registries are fixtures)
    env, registries, _be, _seed_all, _seed_cluster, _seed_pbs, _seed_esxi, _started, _update,
)
from test_ha_v2_managers import _sync as _v2_sync

CHANGED = '/api/ha/peer/changed'
SNAPSHOT = '/api/ha/peer/snapshot'
# taken before the v2 fixture puts a recorder in its place
_REAL_REBUILD = ha._rebuild


# --- stand-ins for the managers ----------------------------------------------------------

def _stand_ins(monkeypatch, events):
    """Every kind of manager the start path builds, as a class that notes what happens
    to it in `events`: ('built' | 'started' | 'stopped', id, host)."""
    import pegaprox.core.manager as mgrmod
    import pegaprox.core.pbs as pbsmod
    import pegaprox.core.vmware as vmwmod
    import pegaprox.core.xcpng as xcpmod

    class Cluster:
        cluster_type = 'proxmox'

        def __init__(self, cid, config):
            self.id, self.config, self.running = cid, config, False
            events.append(('built', cid, config.host))

        def start(self):
            self.running = True
            events.append(('started', self.id, self.config.host))

        def stop(self):
            self.running = False
            events.append(('stopped', self.id, self.config.host))

    class Pool(Cluster):
        cluster_type = 'xcpng'

    class Server:
        """A PBS or ESXi server: built from the row, connects, has no loop to stop."""

        def __init__(self, sid, config):
            self.id, self.connected = sid, False
            for key, value in config.items():
                setattr(self, key, value)
            events.append(('built', sid, config['host']))

        def connect(self):
            self.connected = True
            return True

    monkeypatch.setattr(mgrmod, 'PegaProxManager', Cluster)
    monkeypatch.setattr(xcpmod, 'XcpngManager', Pool)
    monkeypatch.setattr(pbsmod, 'PBSManager', Server)
    monkeypatch.setattr(vmwmod, 'VMwareManager', Server)


# --- the group ----------------------------------------------------------------------------

@pytest.fixture
def grp(group, monkeypatch):
    g = group
    g.events = []
    _stand_ins(monkeypatch, g.events)
    # the monotonic clock, moved on by the test; the wall clock stays real, the
    # signatures go by it
    g.ahead = [0.0]
    mono = time.monotonic
    monkeypatch.setattr(ha, 'time', types.SimpleNamespace(
        time=time.time, sleep=time.sleep, monotonic=lambda: mono() + g.ahead[0]))
    # (instance, due at, fn, name) of every timer started
    g.timers = []
    monkeypatch.setattr(ha, '_later', lambda delay, fn, name: g.timers.append(
        (g.name(), ha.time.monotonic() + delay, fn, name)))
    # a pull the leader's note asks for runs in place, as in tests/test_ha_forward.py
    g.pulls = []

    def in_place(fn, name):
        g.pulls.append(g.name())
        fn()
    monkeypatch.setattr(ha, '_in_background', in_place)
    monkeypatch.setattr(ha, '_soon', {'wanted': False, 'running': False})
    return g


def _fire(g, seconds=0):
    """Move the clock on and run the timers that are due by then, each on the instance
    that started it. Returns how many ran."""
    g.ahead[0] += seconds
    now = ha.time.monotonic()
    due = [t for t in g.timers if t[1] <= now]
    g.timers[:] = [t for t in g.timers if t[1] > now]
    for n, _at, fn, _name in due:
        with g.at(n):
            fn()
    return len(due)


def _started_on(g, n):
    """main() on `n`: its managers through the start path, then what they started from."""
    import pegaprox.app as app_mod
    from pegaprox.core.config import load_config
    with g.at(n):
        app_mod._start_managers(load_config())
        ha.note_managers_started(ha.manager_signature())


def _live_standby(g, seed, db):
    """a leads, b follows it with the live view on and its managers running: a Proxmox
    cluster, an XCP-ng pool, a PBS server and an ESXi host, which XHM lists as a
    cluster too."""
    admin = _built(g, seed, 'b')
    _seed_all(db)
    assert _sync(g, admin, 'b') == 'applied'
    _started_on(g, 'b')
    g.events.clear()
    return admin


def _signed_in(g, n, db, tmp_path, monkeypatch):
    """A user who signed in on `n` with a password: the session id."""
    creds = _local_user(db, tmp_path, monkeypatch)
    with g.at(n):
        r = g.api.anon().post('/api/auth/login', json=creds)
    assert r.status_code == 200, r.data
    return r.get_json()['session_id']


def _still_signed_in(g, n, sid):
    with g.at(n):
        r = g.api.anon().get('/api/auth/check', headers={'X-Session-ID': sid})
    return r.status_code == 200 and r.get_json().get('authenticated') is not False


def _status(g, n):
    with g.at(n):
        return ha.public_status()


def _config_restarts(g):
    return [(n, why) for n, why in g.restarts if why != 'joined as standby']


# --- a change on the leader, reloaded on the standby ----------------------------------------

def test_a_changed_connection_rebuilds_that_one_manager_and_signs_nobody_out(
        grp, seed, db, tmp_path, monkeypatch):
    g = grp
    admin = _live_standby(g, seed, db)
    sid = _signed_in(g, 'b', db, tmp_path, monkeypatch)
    pve, pool = gl.cluster_managers['pve1'], gl.cluster_managers['xcp1']
    pbs, esx = gl.pbs_managers['pbs1'], gl.vmware_managers['esx1']
    wrapper = gl.cluster_managers['esx1']

    _update(db, 'clusters', 'pve1', host='10.0.0.9')
    assert _sync(g, admin, 'b') == 'applied'
    st = _status(g, 'b')['sync']
    assert st['reload_pending']['reason'] == '1 cluster changed' and st['restart_pending'] is None
    # held for the settle time and no longer: nothing yet
    assert _fire(g, ha.RELOAD_SETTLE) == 0 and g.events == []

    assert _fire(g, 1) == 1
    assert g.events == [('stopped', 'pve1', '10.0.0.1'), ('built', 'pve1', '10.0.0.9'),
                        ('started', 'pve1', '10.0.0.9')]
    new = gl.cluster_managers['pve1']
    assert new is not pve and new.running and not pve.running
    # everything else is the object it was, still running
    assert gl.cluster_managers['xcp1'] is pool and pool.running
    assert gl.pbs_managers['pbs1'] is pbs and gl.vmware_managers['esx1'] is esx
    assert gl.cluster_managers['esx1'] is wrapper
    # no restart, and the user who signed in on the standby still is
    assert _config_restarts(g) == []
    assert _still_signed_in(g, 'b', sid)
    st = _status(g, 'b')['sync']
    assert st['reload_pending'] is None and st['restart_pending'] is None
    assert st['last_reload']['reason'] == '1 cluster changed' and st['last_reload']['failed'] == []
    assert _audit('ha.managers_reloaded')[-1]['details'] == '1 cluster changed'
    # the new one is what the next sync is measured against: nothing more to do
    assert _sync(g, admin, 'b') in ('applied', 'unchanged')
    assert _fire(g, 3600) == 0 and len(g.events) == 3


def test_added_and_removed_servers_come_and_go_in_place(grp, seed, db, tmp_path, monkeypatch):
    g = grp
    admin = _live_standby(g, seed, db)
    sid = _signed_in(g, 'b', db, tmp_path, monkeypatch)
    pve, pool = gl.cluster_managers['pve1'], gl.cluster_managers['xcp1']

    _seed_cluster(db, 'pve2', host='10.0.5.1')
    _seed_pbs(db, 'pbs2', host='10.0.2.5')
    _seed_esxi(db, 'esx2', host='10.0.3.5')
    db.conn.execute("DELETE FROM clusters WHERE id = 'xcp1'")
    db.conn.execute("DELETE FROM pbs_servers WHERE id = 'pbs1'")
    db.conn.execute("DELETE FROM vmware_servers WHERE id = 'esx1'")
    db.conn.commit()
    assert _sync(g, admin, 'b') == 'applied'
    assert _fire(g, ha.RELOAD_SETTLE + 1) == 1

    assert _status(g, 'b')['sync']['last_reload']['reason'] == (
        '1 cluster added, 1 cluster removed, 1 PBS server added, 1 PBS server removed, '
        '1 ESXi server added, 1 ESXi server removed')
    # the new ones built and started, the pool stopped, the unchanged cluster left alone
    assert ('stopped', 'xcp1', '10.0.1.1') in g.events
    assert {e for e in g.events if e[0] == 'built'} == {
        ('built', 'pve2', '10.0.5.1'), ('built', 'pbs2', '10.0.2.5'), ('built', 'esx2', '10.0.3.5')}
    assert ('started', 'pve2', '10.0.5.1') in g.events
    assert not any(e[1] == 'pve1' for e in g.events)
    assert gl.cluster_managers['pve1'] is pve and pve.running and not pool.running
    # the ESXi host that left takes its XHM entry among the clusters with it
    assert set(gl.cluster_managers) == {'pve1', 'pve2', 'esx2'}
    assert gl.cluster_managers['esx2'].cluster_type == 'esxi'
    assert gl.cluster_managers['esx2']._vmware is gl.vmware_managers['esx2']
    assert set(gl.pbs_managers) == {'pbs2'} and gl.pbs_managers['pbs2'].connected
    assert set(gl.vmware_managers) == {'esx2'}
    assert _config_restarts(g) == [] and _still_signed_in(g, 'b', sid)


def test_an_esxi_host_that_turns_into_a_vcenter_leaves_the_cluster_list(grp, seed, db):
    """Its XHM entry among the clusters goes with the old manager: the new one is built
    from the row, and a vCenter is no ESXi host."""
    g = grp
    admin = _live_standby(g, seed, db)
    old = gl.vmware_managers['esx1']
    _update(db, 'vmware_servers', 'esx1', server_type='vcenter')
    assert _sync(g, admin, 'b') == 'applied'
    assert _fire(g, ha.RELOAD_SETTLE + 1) == 1
    assert gl.vmware_managers['esx1'] is not old
    assert gl.vmware_managers['esx1'].server_type == 'vcenter'
    assert 'esx1' not in gl.cluster_managers


def test_a_burst_of_changes_is_one_reload(grp, seed, db):
    g = grp
    admin = _live_standby(g, seed, db)
    settle = ha.RELOAD_SETTLE

    _update(db, 'clusters', 'pve1', host='10.0.0.9')
    assert _sync(g, admin, 'b') == 'applied'
    assert _fire(g, settle - 3) == 0
    _update(db, 'clusters', 'pve1', user='admin@pve')
    assert _sync(g, admin, 'b') == 'applied'
    # the first change's timer: the clock started over with the second
    assert _fire(g, settle - 3) == 1 and g.events == []
    _seed_pbs(db, 'pbs2', host='10.0.2.5')
    assert _sync(g, admin, 'b') == 'applied'
    assert _fire(g, settle - 1) == 1 and g.events == []

    assert _fire(g, 2) == 1
    assert [e for e in g.events if e[1] == 'pve1'] == [
        ('stopped', 'pve1', '10.0.0.1'), ('built', 'pve1', '10.0.0.9'), ('started', 'pve1', '10.0.0.9')]
    assert gl.cluster_managers['pve1'].config.user == 'admin@pve'
    assert [e for e in g.events if e[1] == 'pbs2'] == [('built', 'pbs2', '10.0.2.5')]
    assert len(_audit('ha.managers_reloaded')) == 1
    assert _fire(g, 3600) == 0 and _config_restarts(g) == []


def test_a_change_undone_before_it_settled_reloads_nothing(grp, seed, db):
    g = grp
    admin = _live_standby(g, seed, db)
    _update(db, 'clusters', 'pve1', host='10.0.0.9')
    assert _sync(g, admin, 'b') == 'applied'
    _update(db, 'clusters', 'pve1', host='10.0.0.1')
    assert _sync(g, admin, 'b') == 'applied'
    assert _status(g, 'b')['sync']['reload_pending'] is None
    _fire(g, 3600)
    assert g.events == [] and _audit('ha.managers_reloaded') == []


def test_names_and_thresholds_are_still_handed_over_in_place(grp, seed, db):
    """Counterproof: what a manager reads at the moment of use needs no new manager."""
    g = grp
    admin = _live_standby(g, seed, db)
    pve = gl.cluster_managers['pve1']
    _update(db, 'clusters', 'pve1', name='Lab A', migration_threshold=55)
    assert _sync(g, admin, 'b') == 'applied'
    assert (pve.config.name, pve.config.migration_threshold) == ('Lab A', 55)
    assert _status(g, 'b')['sync']['reload_pending'] is None
    assert _fire(g, 3600) == 0 and g.events == []


def test_apply_now_reloads_at_once(grp, seed, db):
    g = grp
    admin = _live_standby(g, seed, db)
    _update(db, 'pbs_servers', 'pbs1', host='10.0.2.2')
    assert _sync(g, admin, 'b') == 'applied'
    with g.at('b'):
        r = admin.post('/api/ha/apply-config', json={})
    assert r.status_code == 200, r.data
    assert r.get_json() == {'success': True, 'restarting': False, 'reloaded': True}
    assert g.events == [('built', 'pbs1', '10.0.2.2')]
    assert gl.pbs_managers['pbs1'].host == '10.0.2.2'
    assert _audit('ha.config_applied')[-1]['details'] == (
        'reloaded the managers now for the waiting change: 1 PBS server changed')
    # its timer finds nothing left to do
    assert _fire(g, 3600) == 1 and len(g.events) == 1
    # nothing waiting: nothing to apply
    with g.at('b'):
        r = admin.post('/api/ha/apply-config', json={})
    assert r.get_json() == {'success': True, 'restarting': False, 'reloaded': False}
    assert len(_audit('ha.config_applied')) == 1 and _config_restarts(g) == []


def test_a_switched_live_view_still_restarts(grp, seed, db):
    g = grp
    admin = _live_standby(g, seed, db)
    with g.at('b'):
        r = admin.put('/api/ha/settings', json={'live_view': False})
    assert r.status_code == 200, r.data
    assert r.get_json()['restarting'] is True
    assert _config_restarts(g) == [
        ('b', 'configuration changed on the active instance: the live view was switched off')]
    # the managers are left to the restart, and so is a change that comes in meanwhile
    assert g.events == []
    _update(db, 'clusters', 'pve1', host='10.0.0.9')
    assert _sync(g, admin, 'b') == 'applied'
    assert _fire(g, 3600) == 1 and g.events == []


def test_a_role_change_still_restarts(grp, seed, db):
    """Counterproof for the restarts that stay: a promotion restarts into the new role."""
    g = grp
    admin = _live_standby(g, seed, db)
    with g.at('b'):
        r = _post(admin, '/api/ha/promote', {'confirm': 'PROMOTE', 'user_password': ADMIN_PW})
    assert r.status_code == 200, r.data
    assert ('b', 'promoted to active') in g.restarts
    assert g.events == []


def test_a_standby_without_the_live_view_has_nothing_to_reload(grp, seed, db):
    g = grp
    admin = _built(g, seed, 'b')
    with g.at('b'):
        ha.set_live_view(False)
    _seed_all(db)
    assert _sync(g, admin, 'b') == 'applied'
    _update(db, 'clusters', 'pve1', host='10.0.0.9')
    assert _sync(g, admin, 'b') == 'applied'
    assert _status(g, 'b')['sync']['reload_pending'] is None
    assert _fire(g, 3600) == 0 and g.events == [] and gl.cluster_managers == {}


# --- the leader tells its members ------------------------------------------------------------

def _group_write(admin, name='Rack 4'):
    return admin.post('/api/cluster-groups', json={'name': name})


def _notes(g, since=0):
    return [(frm, to) for frm, to, _method, path in g.calls[since:] if path == CHANGED]


def _snapshots(g, since=0):
    return [(frm, to) for frm, to, _method, path in g.calls[since:] if path == SNAPSHOT]


def test_a_write_on_the_leader_makes_every_member_pull_once(grp, seed):
    g = grp
    admin = _built(g, seed, 'bc')
    with g.at('a'):
        for i in range(3):
            r = _group_write(admin, f'Rack {i}')
            assert r.status_code in (200, 201), r.data
    # one note for the three writes, NUDGE_DELAY seconds out, from the leader
    assert [(n, name) for n, _at, _fn, name in g.timers] == [('a', 'ha-nudge')]
    assert _fire(g, ha.NUDGE_DELAY - 1) == 0 and g.pulls == []

    before = len(g.calls)
    assert _fire(g, 1) == 1
    assert _notes(g, before) == [('a', 'b'), ('a', 'c')]
    assert g.pulls == ['b', 'c']
    assert _snapshots(g, before) == [('b', 'a'), ('c', 'a')]
    assert all(g.state(n)['sync']['last_ok_at'] for n in 'bc')

    # a write after it gets a note of its own, NUDGE_SPACING after the one before
    with g.at('a'):
        assert _group_write(admin, 'Rack 9').status_code in (200, 201)
    assert len(g.timers) == 1 and _fire(g, ha.NUDGE_DELAY) == 0
    assert _fire(g, ha.NUDGE_SPACING - ha.NUDGE_DELAY) == 1
    assert g.pulls == ['b', 'c', 'b', 'c']


def test_reads_failed_writes_and_the_ha_routes_tell_nobody(grp, seed):
    g = grp
    admin = _built(g, seed, 'bc')
    with g.at('a'):
        assert admin.get('/api/cluster-groups').status_code == 200
        assert admin.post('/api/cluster-groups', json={}).status_code == 400
        assert admin.put('/api/ha/settings', json={'interval': 60}).status_code == 200
        # the live stream's token changes nothing a member holds
        assert admin.post('/api/sse/token', json={}).status_code == 200
    assert g.timers == []
    # counterproof: the same client, a write that goes through
    with g.at('a'):
        assert _group_write(admin).status_code in (200, 201)
    assert len(g.timers) == 1


def test_a_standby_tells_nobody(grp, seed):
    """A write on a standby: refused there, or carried out on the leader, which is then
    the one that tells the members."""
    g = grp
    admin = _built(g, seed, 'bc')
    with g.at('b'):
        ha.set_forward_writes(False)
        assert _group_write(admin).status_code == 409
    assert g.timers == []
    with g.at('b'):
        ha.set_forward_writes(True)
        r = _group_write(admin)
    assert r.status_code in (200, 201), r.data
    assert [n for n, _at, _fn, _name in g.timers] == ['a']


def test_a_standalone_instance_tells_nobody(grp, seed):
    g = grp
    admin = _admin(g.api, seed)
    with g.at('e'):
        assert _group_write(admin).status_code in (200, 201)
    assert g.timers == []


def test_a_member_that_misses_the_note_holds_up_nobody(grp, seed):
    """And is no error of that member: it pulls at its next poll."""
    g = grp
    admin = _built(g, seed, 'bc')
    noted = g.state('a')['members'][IDS['b']].get('last_error')
    g.down.add('b')
    with g.at('a'):
        assert _group_write(admin).status_code in (200, 201)
    assert _fire(g, ha.NUDGE_DELAY) == 1
    assert g.pulls == ['c']
    assert g.state('a')['members'][IDS['b']].get('last_error') == noted


def test_the_note_is_taken_from_the_leader_only(grp, seed):
    g = grp
    _built(g, seed, 'bc')
    # from the member b pulls from: a pull
    r = _send(g, 'b', _sign_as(g, 'a', 'b', method='POST', path=CHANGED), method='POST', path=CHANGED)
    assert r.status_code == 200 and r.get_json() == {'success': True, 'pull': True}
    assert g.pulls == ['b']
    # from another member of the group: heard, and nothing done
    r = _send(g, 'b', _sign_as(g, 'c', 'b', method='POST', path=CHANGED), method='POST', path=CHANGED)
    assert r.status_code == 200 and r.get_json() == {'success': True, 'pull': False}
    # the leader itself pulls from nobody
    r = _send(g, 'a', _sign_as(g, 'b', 'a', method='POST', path=CHANGED), method='POST', path=CHANGED)
    assert r.status_code == 200 and r.get_json() == {'success': True, 'pull': False}
    assert g.pulls == ['b']


def _etag_walks(monkeypatch):
    """Every walk over the shared tables for an etag, the leader's or a poll's."""
    walks = []
    walk = ha.snapshot_etag
    monkeypatch.setattr(ha, 'snapshot_etag', lambda *a, **kw: walks.append(1) or walk(*a, **kw))
    return walks


def _note_bodies(g, since=0):
    return [(frm, to, json.loads(body) if body else None)
            for frm, to, _method, path, body, _h in g.sent[since:] if path == CHANGED]


def test_a_note_carries_the_etag_and_a_member_that_holds_it_pulls_nothing(grp, seed, monkeypatch):
    """A write that changes nothing the members hold (the push inbox is per instance)
    costs the leader one walk for the etag of the round, and no member a pull."""
    from pegaprox.api.push import _ensure_inbox_table
    g = grp
    admin = _built(g, seed, 'bc')
    _ensure_inbox_table()
    held = g.state('b')['sync']['etag']
    assert held and g.state('c')['sync']['etag'] == held
    walks = _etag_walks(monkeypatch)
    sent, before = len(g.sent), len(g.calls)
    with g.at('a'):
        assert admin.post('/api/push/inbox/clear', json={}).status_code == 200
    assert _fire(g, ha.NUDGE_DELAY) == 1
    # next to the etag, where the leader's configuration is at (tests/test_ha_orphans.py)
    assert [(frm, to, body['etag']) for frm, to, body in _note_bodies(g, sent)] == [
        ('a', 'b', held), ('a', 'c', held)]
    assert len(walks) == 1 and g.pulls == [] and _snapshots(g, before) == []

    # counterproof: a write that changes what they hold
    with g.at('a'):
        assert _group_write(admin).status_code in (200, 201)
    assert _fire(g, ha.NUDGE_SPACING) == 1
    assert g.pulls == ['b', 'c'] and _snapshots(g, before) == [('b', 'a'), ('c', 'a')]
    assert g.state('b')['sync']['etag'] not in ('', None, held)


def test_a_member_pulls_for_a_note_about_a_configuration_it_does_not_hold(grp, seed, monkeypatch):
    g = grp
    _built(g, seed, 'bc')
    held = g.state('b')['sync']['etag']

    def note(body):
        raw = json.dumps(body).encode() if body is not None else b''
        r = _send(g, 'b', _sign_as(g, 'a', 'b', method='POST', path=CHANGED, body=raw),
                  method='POST', path=CHANGED, body=raw)
        assert r.status_code == 200, r.data
        return r.get_json()['pull']
    assert note({'etag': held}) is False and g.pulls == []
    assert note({'etag': 'f' * 32}) is True and g.pulls == ['b']
    # a leader of an earlier release sends no etag: a pull, as before
    for body in (None, {}, {'etag': ''}, {'etag': 7}):
        g.pulls.clear()
        assert note(body) is True and g.pulls == ['b'], body
    # the first pull of a process is a full one, whatever the etag says
    g.pulls.clear()
    monkeypatch.setattr(ha, '_etag_checked', False)
    assert note({'etag': g.state('b')['sync']['etag']}) is True and g.pulls == ['b']


def test_under_a_run_of_writes_the_notes_are_spaced(grp, seed, monkeypatch):
    """One note NUDGE_DELAY after the first write, then one per NUDGE_SPACING however
    many writes come in between. Quiet for a while, the next one is quick again."""
    g = grp
    admin = _built(g, seed, 'bc')
    # the test's clock alone: a round with its pulls takes real time as well
    monkeypatch.setattr(ha, 'time', types.SimpleNamespace(
        time=time.time, sleep=time.sleep, monotonic=lambda: g.ahead[0]))
    before = len(g.calls)

    def write(name):
        with g.at('a'):
            assert _group_write(admin, name).status_code in (200, 201)
    write('Rack 0')
    assert _fire(g, ha.NUDGE_DELAY) == 1
    # a write every second for 30 seconds
    rounds = []
    for second in range(1, 31):
        write(f'Rack {second}')
        if _fire(g, 1):
            rounds.append(second)
    assert ha.NUDGE_SPACING == 10 and rounds == [10, 20, 30]
    assert len(_notes(g, before)) == 2 * 4
    assert g.timers == []

    # quiet for a while: the next note goes NUDGE_DELAY after its write again
    assert _fire(g, 60) == 0
    write('Rack 99')
    assert _fire(g, ha.NUDGE_DELAY - 1) == 0 and _fire(g, 1) == 1


def test_consoles_on_the_leader_tell_nobody(grp, seed, monkeypatch):
    """Nothing a member holds changes, and a console over vnc-poll is a POST for every
    screen update."""
    import pegaprox.api.plugins as plugins
    from test_ha_forward import _hook_lists, _concrete
    g = grp
    admin = _built(g, seed, 'bc')
    app = g.api.app
    consoles = sorted(_hook_lists(app)['_STANDBY_CONSOLES'])
    for method, rule in consoles:
        for r in app.url_map.iter_rules():
            if r.rule == rule and method in r.methods:
                monkeypatch.setitem(app.view_functions, r.endpoint, lambda *a, **kw: {'ok': True})
    monkeypatch.setitem(plugins._loaded_plugins, 'probe', types.SimpleNamespace())
    monkeypatch.setitem(plugins._plugin_routes, 'probe', {'vm/console': lambda: {'ticket': 'x'},
                                                          'record': lambda: {'written': True}})
    with g.at('a'):
        for method, rule in consoles:
            r = getattr(admin, method.lower())(_concrete(rule), json={})
            assert r.status_code == 200, (rule, r.data)
        assert admin.post('/api/plugins/probe/api/vm/console', json={}).status_code == 200
    assert g.timers == []
    # counterproof: another write of the same plugin tells them
    with g.at('a'):
        assert admin.post('/api/plugins/probe/api/record', json={}).status_code == 200
    assert [(n, name) for n, _at, _fn, name in g.timers] == [('a', 'ha-nudge')]


def test_an_unsigned_or_foreign_note_is_refused(grp, seed):
    g = grp
    _built(g, seed, 'bc')
    with g.at('e'):
        ha._update(signing_key=ha._new_signing_key())
    for headers in (
            {},                                                              # no peer header
            {ha.PEER_HEADER: IDS['a']},                                      # a name, no signature
            _sign_as(g, 'e', 'b', method='POST', path=CHANGED),              # not in the group
            _sign_as(g, 'a', 'b', method='POST', path=CHANGED, key_of='e'),  # a's name, e's key
            _sign_as(g, 'a', 'c', method='POST', path=CHANGED),              # signed for c
            _sign_as(g, 'a', 'b', method='POST', path='/api/ha/peer/tombstones'),  # another call
    ):
        r = _send(g, 'b', headers, method='POST', path=CHANGED)
        assert r.status_code == 401, (headers, r.status_code, r.data)
    assert g.pulls == [] and g.state('b')['role'] == 'standby'


# --- one reload at a time ------------------------------------------------------------------------

@pytest.fixture
def live(env, registries, monkeypatch):
    """The standby of tests/test_ha_v2_managers.py, its managers started through the
    start path as stand-ins; the syncs and the reloads are run by the test."""
    import pegaprox.app as app_mod
    from pegaprox.core.config import load_config
    events = []
    _stand_ins(monkeypatch, events)
    monkeypatch.setattr(ha, '_rebuild', _REAL_REBUILD)
    _be('standby')
    _seed_all(env.db)
    assert _v2_sync(env) == 'applied'
    app_mod._start_managers(load_config())
    _started(env)
    events.clear()
    env.events = events
    env.sync = lambda change=None: _v2_sync(env, change)
    return env


def test_one_reload_at_a_time_and_a_sync_in_between_is_reloaded_next(live):
    env = live
    pve = gl.cluster_managers['pve1']
    inside, go = threading.Event(), threading.Event()
    stop = pve.stop

    def held():
        inside.set()
        assert go.wait(10)
        stop()
    pve.stop = held

    assert env.sync(lambda: _update(env.db, 'clusters', 'pve1', host='10.0.0.9')) == 'applied'
    env.clock.advance(ha.RELOAD_SETTLE)
    results = []
    first = threading.Thread(target=lambda: results.append(ha._reload_if_due()))
    first.start()
    try:
        assert inside.wait(10)
        # while that one runs, a second one does not start
        assert ha._reload_if_due() is False
        # a sync lands meanwhile, with a change of its own
        assert env.sync(lambda: _update(env.db, 'pbs_servers', 'pbs1', host='10.0.2.2')) == 'applied'
    finally:
        go.set()
        first.join(10)
    assert results == [True]
    assert [e for e in env.events if e[1] == 'pve1'] == [
        ('stopped', 'pve1', '10.0.0.1'), ('built', 'pve1', '10.0.0.9'), ('started', 'pve1', '10.0.0.9')]
    # it rebuilt what it read before that sync; the PBS change waits for its own turn
    assert not any(e[1] == 'pbs1' for e in env.events) and ha._run['reload']
    env.clock.advance(ha.RELOAD_SETTLE)
    assert ha._reload_if_due() is True
    assert [e for e in env.events if e[1] == 'pbs1'] == [('built', 'pbs1', '10.0.2.2')]
    assert ha.public_status()['sync']['last_reload']['reason'] == '1 PBS server changed'
    assert len([e for e in env.events if e[0] == 'built']) == 2
    assert ha._run['reload'] is None and env.restarts == []


def test_a_reload_reads_the_configuration_between_two_syncs(live):
    """It takes the pull lock to read: never rows a sync is halfway through."""
    env = live
    assert env.sync(lambda: _update(env.db, 'clusters', 'pve1', host='10.0.0.9')) == 'applied'
    env.clock.advance(ha.RELOAD_SETTLE)
    assert ha._pull_lock.acquire(timeout=5)
    done = []
    worker = threading.Thread(target=lambda: done.append(ha._reload_if_due()))
    try:
        worker.start()
        worker.join(0.3)
        assert worker.is_alive() and env.events == []
    finally:
        ha._pull_lock.release()
    worker.join(10)
    assert done == [True] and ('built', 'pve1', '10.0.0.9') in env.events


def test_a_stop_that_fails_does_not_hold_up_the_rest(live):
    env = live

    def broken():
        raise RuntimeError('join timed out')
    gl.cluster_managers['pve1'].stop = broken

    def change():
        _update(env.db, 'clusters', 'pve1', host='10.0.0.9')
        _update(env.db, 'pbs_servers', 'pbs1', host='10.0.2.2')
    assert env.sync(change) == 'applied'
    env.clock.advance(ha.RELOAD_SETTLE)
    assert ha._reload_if_due() is True
    assert gl.cluster_managers['pve1'].config.host == '10.0.0.9'
    assert gl.pbs_managers['pbs1'].host == '10.0.2.2'
    assert ha.public_status()['sync']['last_reload']['failed'] == []


def test_a_manager_that_cannot_be_built_is_named_and_not_tried_in_a_loop(live, monkeypatch):
    import pegaprox.core.pbs as pbsmod
    env = live

    def refuse(pid, config):
        raise ValueError('host not allowed')
    monkeypatch.setattr(pbsmod, 'PBSManager', refuse)
    assert env.sync(lambda: _update(env.db, 'pbs_servers', 'pbs1', host='10.0.2.2')) == 'applied'
    env.clock.advance(ha.RELOAD_SETTLE)
    assert ha._reload_if_due() is True
    # the old one is built from settings that are gone: it goes too, as at a start
    assert 'pbs1' not in gl.pbs_managers
    assert ha.public_status()['sync']['last_reload']['failed'] == ['pbs:pbs1']
    assert env.audits[-1] == ('ha.managers_reloaded', '1 PBS server changed - could not build pbs:pbs1')
    # tried again once its row changes, not on every poll
    env.clock.advance(3600)
    assert ha._reload_if_due() is False and ha._run['reload'] is None


# --- a sync that lands while the managers are rebuilt ------------------------------------------

def _held_stop(mgr):
    """mgr.stop() waits for `go`: the rebuild is held between the stop of the old manager
    and the start of the new one."""
    inside, go = threading.Event(), threading.Event()
    stop = mgr.stop

    def held():
        inside.set()
        assert go.wait(10)
        stop()
    mgr.stop = held
    return inside, go


def _reload_while(env, inside, go, change):
    """The reload that is due, in a thread of its own; `change` synced while it is held."""
    env.clock.advance(ha.RELOAD_SETTLE)
    results = []
    worker = threading.Thread(target=lambda: results.append(ha._reload_if_due()))
    worker.start()
    try:
        assert inside.wait(10)
        assert env.sync(change) == 'applied'
    finally:
        go.set()
        worker.join(10)
    return results


def _host_of(env, table, rid):
    return env.db.conn.execute(f'SELECT host FROM {table} WHERE id = ?', (rid,)).fetchone()[0]


def test_a_change_undone_while_the_managers_are_rebuilt_is_reloaded_back(live):
    """The sync with the undo was compared with what ran before the rebuild, the same
    settings, and cleared the reload: nothing would have reloaded it until the leader
    changed something else."""
    env = live
    inside, go = _held_stop(gl.cluster_managers['pve1'])
    assert env.sync(lambda: _update(env.db, 'clusters', 'pve1', host='10.0.0.9')) == 'applied'
    undo = lambda: _update(env.db, 'clusters', 'pve1', host='10.0.0.1')  # noqa: E731
    assert _reload_while(env, inside, go, undo) == [True]
    assert gl.cluster_managers['pve1'].config.host == '10.0.0.9'
    assert ha.public_status()['sync']['reload_pending']['reason'] == '1 cluster changed'

    env.clock.advance(ha.RELOAD_SETTLE)
    assert ha._reload_if_due() is True
    assert gl.cluster_managers['pve1'].config.host == _host_of(env, 'clusters', 'pve1') == '10.0.0.1'
    assert [e for e in env.events if e[1] == 'pve1'] == [
        ('stopped', 'pve1', '10.0.0.1'), ('built', 'pve1', '10.0.0.9'), ('started', 'pve1', '10.0.0.9'),
        ('stopped', 'pve1', '10.0.0.9'), ('built', 'pve1', '10.0.0.1'), ('started', 'pve1', '10.0.0.1')]
    # and nothing after that
    env.clock.advance(3600)
    assert env.sync() == 'unchanged' and ha._reload_if_due() is False and ha._run['reload'] is None


def test_a_server_change_undone_during_its_slow_connect_is_reloaded_back(live, monkeypatch):
    """A PBS server is connected while it is built, up to 10 s for a host that does not
    answer: the leader's own connect fails the same way, and the admin undoes it."""
    import pegaprox.core.pbs as pbsmod
    env = live
    inside, go = threading.Event(), threading.Event()
    connect = pbsmod.PBSManager.connect

    def slow(self):
        if self.host == '10.0.2.9':
            inside.set()
            assert go.wait(10)
        return connect(self)
    monkeypatch.setattr(pbsmod.PBSManager, 'connect', slow)
    before = gl.pbs_managers['pbs1'].host
    assert env.sync(lambda: _update(env.db, 'pbs_servers', 'pbs1', host='10.0.2.9')) == 'applied'
    undo = lambda: _update(env.db, 'pbs_servers', 'pbs1', host=before)  # noqa: E731
    assert _reload_while(env, inside, go, undo) == [True]
    assert gl.pbs_managers['pbs1'].host == '10.0.2.9' and ha._run['reload']

    env.clock.advance(ha.RELOAD_SETTLE)
    assert ha._reload_if_due() is True
    assert gl.pbs_managers['pbs1'].host == _host_of(env, 'pbs_servers', 'pbs1') == before
    env.clock.advance(3600)
    assert env.sync() == 'unchanged' and ha._reload_if_due() is False


def test_what_a_sync_hands_over_during_a_rebuild_reaches_the_new_manager(live):
    """The sync handed name and threshold to the old manager, stopped by then; the new one
    was built from the rows read before it. Nothing hands them over again until the
    leader changes something."""
    env = live
    old = gl.cluster_managers['pve1']
    inside, go = _held_stop(old)
    assert env.sync(lambda: _update(env.db, 'clusters', 'pve1', host='10.0.0.9')) == 'applied'
    rename = lambda: _update(env.db, 'clusters', 'pve1', name='Renamed', migration_threshold=77)  # noqa: E731
    assert _reload_while(env, inside, go, rename) == [True]
    new = gl.cluster_managers['pve1']
    assert new is not old and new.config.host == '10.0.0.9'
    assert (new.config.name, new.config.migration_threshold) == ('Renamed', 77)
    # a rename needs no reload of its own
    assert ha._run['reload'] is None


# --- a pool the reload stops ---------------------------------------------------------------------

def _xenapi(monkeypatch):
    """XenAPI as far as XcpngManager uses it in its loop: sessions that count their logins
    and logouts, a call on a session logged out fails, and the host list waits for
    `release` once `hold` is set."""
    import pegaprox.constants as consts
    import pegaprox.core.xcpng as xcpmod
    monkeypatch.setattr(consts, 'FILE_LOG_DISABLED', True)
    pool = types.SimpleNamespace(logins=[], logouts=[], live=set(), hold=False,
                                 fetching=threading.Event(), release=threading.Event())

    class Session:
        def __init__(self, url, ignore_ssl=False):
            self._session = None

            def login(user, password, version, origin):
                self._session = f'S{len(pool.logins) + 1}'
                pool.logins.append(self._session)
                pool.live.add(self._session)

            def logout():
                pool.logouts.append(self._session)
                pool.live.discard(self._session)

            def hosts():
                if pool.hold:
                    pool.fetching.set()
                    assert pool.release.wait(10)
                if self._session not in pool.live:
                    raise RuntimeError('SESSION_INVALID')
                return []

            self.xenapi = types.SimpleNamespace(
                login_with_password=login, host=types.SimpleNamespace(get_all=hosts),
                session=types.SimpleNamespace(logout=logout, get_uuid=lambda s: 'u'))

    monkeypatch.setattr(xcpmod, 'XenAPI', types.SimpleNamespace(Session=Session))
    monkeypatch.setattr(xcpmod, 'XENAPI_AVAILABLE', True)
    return pool


def _pool_manager():
    from pegaprox.core.xcpng import XcpngManager
    from pegaprox.models.tasks import PegaProxConfig
    return XcpngManager('xcp1', PegaProxConfig({'name': 'pool', 'host': '10.0.1.1', 'user': 'root',
                                                 'pass': 'pw', 'cluster_type': 'xcpng'}))


def test_a_stopped_pool_logs_in_no_more(monkeypatch):
    pool = _xenapi(monkeypatch)
    mgr = _pool_manager()
    assert mgr.connect() is True and pool.logins == ['S1']
    # counterproof: one that runs logs in again when its session is gone
    mgr.disconnect()
    assert mgr._api() is not None and pool.logins == ['S1', 'S2']
    # stop() sets its event before it logs out: from then on nothing is handed out
    mgr.stop_event.set()
    assert mgr._api() is None
    mgr.stop()
    assert pool.live == set()
    assert mgr.connect() is False and mgr.connect_to_proxmox() is False and mgr._api() is None
    assert pool.logins == ['S1', 'S2'] and mgr.is_connected is False


def test_a_pool_stopped_in_the_middle_of_a_fetch_leaves_no_session_open(monkeypatch):
    """The reload stops a changed pool while its loop fetches; the fetch fails on the
    session stop() logged out, and the loop goes on to its task poll before it ends."""
    pool = _xenapi(monkeypatch)
    pool.hold = True
    mgr = _pool_manager()
    mgr.start()
    try:
        assert pool.fetching.wait(10)
        mgr.stop()
    finally:
        pool.release.set()
    mgr.thread.join(10)
    assert not mgr.thread.is_alive()
    assert pool.logins == ['S1'] and pool.logouts == ['S1'] and pool.live == set()


def _stop_and_join(mgr, pool):
    try:
        mgr.stop()
    finally:
        pool.release.set()
    mgr.thread.join(10)
    assert not mgr.thread.is_alive()


def test_a_pool_started_after_its_login_goes_on_with_that_session(monkeypatch):
    """Adding and reconfiguring a pool log in to test it, then start it. The loop used to
    log in once more over the top, and the first session stayed open on the pool master
    until it timed out: one per reconfigure."""
    pool = _xenapi(monkeypatch)
    pool.hold = True
    mgr = _pool_manager()
    assert mgr.connect() is True
    mgr.start()
    try:
        assert pool.fetching.wait(10)
        assert pool.logins == ['S1'] and pool.live == {'S1'}
    finally:
        _stop_and_join(mgr, pool)
    assert pool.logouts == ['S1'] and pool.live == set()

    # counterproof: started without a login (the boot path), the loop logs in itself
    pool = _xenapi(monkeypatch)
    pool.hold = True
    mgr = _pool_manager()
    mgr.start()
    try:
        assert pool.fetching.wait(10)
        assert pool.logins == ['S1']
    finally:
        _stop_and_join(mgr, pool)
    assert pool.live == set()


def test_a_new_login_logs_out_the_session_it_takes_over_from(monkeypatch):
    """The loop gives up on a session after a run of failed fetches and logs in again; the
    session it gave up on may still be open there."""
    import pegaprox.core.xcpng as xcpmod
    pool = _xenapi(monkeypatch)
    mgr = _pool_manager()
    try:
        assert mgr.connect() is True
        mgr.is_connected = False
        assert mgr._api() is not None
        assert pool.logins == ['S1', 'S2'] and pool.logouts == ['S1'] and pool.live == {'S2'}
        # counterproof: a login that fails leaves the session it has alone
        mgr.is_connected = False

        def refused(url, ignore_ssl=False):
            raise RuntimeError('HOST_IS_SLAVE')
        monkeypatch.setattr(xcpmod.XenAPI, 'Session', refused)
        assert mgr.connect() is False
        assert pool.logouts == ['S1'] and pool.live == {'S2'}
    finally:
        mgr.stop()
    assert pool.live == set()


def test_reconfiguring_a_pool_leaves_one_session_open(api, seed, monkeypatch):
    pool = _xenapi(monkeypatch)
    pool.hold = True
    admin = _admin(api, seed)
    old = api.set_manager('xcp1', api.make_fake_manager('xcp1', cluster_type='xcpng'))
    r = admin.post('/api/clusters/xcp1/reconfigure', json={
        'name': 'pool', 'host': '10.0.1.1', 'user': 'root', 'pass': 'pw',
        'cluster_type': 'xcpng', 'current_password': ADMIN_PW})
    new = gl.cluster_managers.get('xcp1')
    assert r.status_code == 200, r.data
    assert new is not old and old.stop.called and new.cluster_type == 'xcpng'
    try:
        assert pool.fetching.wait(10)
        # the login that tested the new credentials is the one the loop runs on
        assert pool.logins == ['S1'] and pool.live == {'S1'}
    finally:
        _stop_and_join(new, pool)
    assert pool.live == set()
