"""Serving members (#625): a standby the leader made active is an active instance to the
users. They sign in there, see the clusters live and open consoles, shells and SPICE
there; every change goes to the leader (tests/test_ha_forward.py). Its role stays
standby, so nothing that acts on its own starts there, and tests/test_ha_loop_gates.py
holds as it is.

Who is active is set on the leader, for every member (PUT /api/ha/members/<id>/serve):
up to three instances, the leader included. The flag travels with the member list, and
a member takes it with its next sync.

Runs on the in-process group of tests/test_ha_members.py with the forwarding of
tests/test_ha_forward.py: a is the leader, b its standby. Every console path is taken
both ways on b: opened here while b serves users, refused (409, nothing forwarded)
while it does not. A standby pins no SSH host key of its own, whether it serves or not.

MK Oct 2026
"""
import asyncio
import json
import subprocess
import threading
import time
import types
from urllib.parse import parse_qsl, urlsplit

import pytest

from test_ha_api import _admin, _audit, _local_user, ADMIN_PW  # noqa: F401
from test_ha_members import (group, _built, _pair, _post, _promote, _pub, _send, _sync,  # noqa: F401
                             _watch, IDS, URLS)
from test_ha_forward import fwd, probe, _forward_calls, _hook_lists, _concrete, FORWARD  # noqa: F401
from test_ha_v2_surface import (CID, VM, SHELL, STANDBY_ANSWER, _registry, _fake_manager,
                                _console_calls, _SyncWS, _AsyncWS, _sock_handler,
                                _standalone_vnc_handler, _auth_query, _ssh_server, _Resp)

VNC_SOCKET = '/api/clusters/<cluster_id>/vms/<node>/<vm_type>/<int:vmid>/vncwebsocket'
NOT_KNOWN = 'is not known here yet - open a shell to it on the leader once'
ON_LEADER = {'code': 'HA_SERVE_ON_LEADER', 'error': 'Which instances are active is set on the leader'}


def _serve(g, n='b', on=True):
    """The leader a makes `n` active (or a standby again), and `n` takes it with a sync,
    as it does within seconds of the leader's note."""
    with g.at('a') as ha:
        ha.set_member_serve(IDS[n], on)
    with g.at(n) as ha:
        assert ha.pull_once() in ('applied', 'unchanged')


def _put_serve(admin, n, body):
    return admin.put(f'/api/ha/members/{IDS[n]}/serve', json=body)


def _api_token():
    from pegaprox.utils.auth import create_api_token
    return {'Authorization': f"Bearer {create_api_token('root', 'automation', role='admin')['token']}"}


def _members(g, admin, n):
    with g.at(n):
        return {m['instance_id']: m for m in admin.get('/api/ha/status').get_json()['members']}


# --- the leader decides ------------------------------------------------------------------------

def test_the_leader_makes_a_member_active_and_it_takes_that_with_its_sync(fwd, seed):
    g = fwd
    admin = _built(g, seed, 'bc')
    restarts = list(g.restarts)
    with g.at('b') as ha:
        assert (ha.serve_assigned(), ha.serving(), ha.consoles_here()) == (False, False, False)
    with g.at('a') as ha:
        assert ha.set_member_serve(IDS['b'], True) == (True, 2)
        assert ha.set_member_serve(IDS['b'], True) == (False, 2)
        for who, value in ((IDS['b'], 'yes'), (IDS['e'], True), (IDS['a'], True)):
            with pytest.raises(ha.HaError):
                ha.set_member_serve(who, value)
        # the leader is active anyway and has no flag of its own
        assert (ha.serve_assigned(), ha.serving(), ha.actives()) == (False, False, 2)
    assert g.file('a')['members'][IDS['b']]['serve'] is True
    assert 'serve_assigned' not in g.file('a')
    # nothing on b until it syncs, and b decides nothing itself
    with g.at('b') as ha:
        assert (ha.serve_assigned(), ha.serving()) == (False, False)
        with pytest.raises(ha.HaError, match='Only the leader'):
            ha.set_member_serve(IDS['c'], True)
    assert _sync(g, admin, 'b') == 'applied'
    with g.at('b') as ha:
        assert (ha.serve_assigned(), ha.serving(), ha.consoles_here(), ha.actives()) == (True, True, True, 2)
        # still a standby: nothing that acts on its own starts here
        assert ha.is_standby() and ha.is_active() is False and ha.managers_wanted() is True
        st = admin.get('/api/ha/status').get_json()
    assert (st['serve_assigned'], st['serving'], st['actives'], st['active_limit']) == (True, True, 2, 3)
    assert 'serve_users' not in st
    assert g.file('b')['serve_assigned'] is True and IDS['b'] not in g.file('b')['members']

    # c learns who serves with its own sync, and serves nobody itself
    assert _sync(g, admin, 'c') == 'applied'
    c = g.state('c')
    assert c['members'][IDS['b']]['serve'] is True and c['members'][IDS['a']]['serve'] is False
    with g.at('c') as ha:
        assert (ha.serve_assigned(), ha.serving(), ha.actives()) == (False, False, 2)
        st = admin.get('/api/ha/status').get_json()
    assert {m['instance_id']: m['serve'] for m in st['members']} == {IDS['a']: False, IDS['b']: True}

    # a standby again: b stops with its next sync
    with g.at('a') as ha:
        assert ha.set_member_serve(IDS['b'], False) == (True, 1)
    assert _sync(g, admin, 'b') == 'applied'
    with g.at('b') as ha:
        assert (ha.serve_assigned(), ha.serving(), ha.consoles_here(), ha.actives()) == (False, False, False, 1)
    # no restart either way: it counts from the next request
    assert g.restarts == restarts


def test_the_etag_carries_the_flag(fwd, seed):
    """A poll after the leader changed who is active is no 304, though no table changed."""
    g = fwd
    admin = _built(g, seed, 'b')
    assert _sync(g, admin, 'b') == 'unchanged'
    with g.at('a') as ha:
        etag = ha.snapshot_etag()
        ha.set_member_serve(IDS['b'], True)
        assert ha.snapshot_etag() != etag
        snap = ha.build_snapshot()
        assert [(e['instance_id'], e.get('serve')) for e in snap['members']] == [(IDS['a'], None),
                                                                                 (IDS['b'], True)]
    assert _sync(g, admin, 'b') == 'applied'
    assert _sync(g, admin, 'b') == 'unchanged'
    # counterproof: back to a standby, back to the etag of before
    with g.at('a') as ha:
        ha.set_member_serve(IDS['b'], False)
        assert ha.snapshot_etag() == etag


def test_only_a_true_serve_counts(fwd, seed):
    g = fwd
    _built(g, seed, 'b')
    entry = {'instance_id': IDS['c'], 'url': URLS['c'], 'fingerprint': '', 'public_key': _pub(g, 'b')}
    with g.at('b') as ha:
        got = [ha._clean_entries([dict(entry, serve=v)])[IDS['c']]['serve'] for v in (True, 'yes', 1, None)]
        assert got == [True, False, False, False]
        assert ha._clean_entries([entry])[IDS['c']]['serve'] is False


def test_a_switch_of_its_own_is_gone(fwd, seed):
    """The per-instance switch of the build before: a value left in the state file serves
    nobody and goes with the next write, and the settings route refuses it before it
    saves anything else of the body."""
    g = fwd
    admin = _built(g, seed, 'b')
    g.write('b', dict(g.file('b'), serve_users=True))
    with g.at('b') as ha:
        assert (ha.serve_assigned(), ha.serving(), ha.consoles_here()) == (False, False, False)
    before = g.file('b')
    for n in 'ab':
        with g.at(n):
            for body in ({'serve_users': True}, {'serve_users': False, 'interval': 60},
                         {'serve_users': 'yes', 'forward_writes': False}):
                r = admin.put('/api/ha/settings', json=body)
                assert r.status_code == 400 and r.get_json() == ON_LEADER, (n, body, r.data)
    assert g.file('b') == before and g.file('b')['interval'] == 30
    # counterproof: the rest of the settings still go through, and the old value goes
    with g.at('b'):
        r = admin.put('/api/ha/settings', json={'interval': 60})
        assert r.status_code == 200 and r.get_json() == {'success': True, 'interval': 60}, r.data
    assert 'serve_users' not in g.file('b') and g.file('b')['interval'] == 60


def test_serving_needs_the_live_view_and_forwarding(fwd, seed):
    g = fwd
    _built(g, seed, 'b')
    _serve(g, 'b')
    with g.at('b') as ha:
        ha.set_live_view(False)
        assert (ha.serving(), ha.consoles_here()) == (False, False)
        ha.set_live_view(True)
        ha.set_forward_writes(False)
        assert (ha.serving(), ha.consoles_here()) == (False, False)
        ha.set_forward_writes(True)
        assert (ha.serving(), ha.consoles_here()) == (True, True)
    # an instance that acts opens consoles anyway; it is not a serving standby, whatever
    # its state file says
    for n in 'ae':
        with g.at(n) as ha:
            ha._update(serve_assigned=True)
            assert ha.role() == ('active' if n == 'a' else 'standalone')
            assert (ha.serve_assigned(), ha.serving(), ha.consoles_here()) == (False, False, True)


# --- the route on the leader ----------------------------------------------------------------------

def test_the_serve_route_answers_on_the_leader_only_and_audits(fwd, seed):
    g = fwd
    admin = _built(g, seed, 'bc')
    restarts = list(g.restarts)
    with g.at('a'):
        st = admin.get('/api/ha/status').get_json()
        assert (st['serve_assigned'], st['serving'], st['actives'], st['active_limit']) == (False, False, 1, 3)
        assert [m['serve'] for m in st['members']] == [False, False]
        before = g.file('a')
        for body in (None, {}, {'serve': 'yes'}, {'serve': 1}, {'serve': None}):
            r = _put_serve(admin, 'b', body)
            assert r.status_code == 400 and r.get_json()['error'] == 'serve is true or false', body
        assert _put_serve(admin, 'e', {'serve': True}).status_code == 404
        assert g.file('a') == before

        r = _put_serve(admin, 'b', {'serve': True})
        assert r.status_code == 200, r.data
        assert r.get_json() == {'success': True, 'serve': True, 'actives': 2}
        # the same again changes nothing and says so the same way
        r = _put_serve(admin, 'b', {'serve': True})
        assert r.get_json() == {'success': True, 'serve': True, 'actives': 2}
        st = admin.get('/api/ha/status').get_json()
    assert st['actives'] == 2
    assert {m['instance_id']: m['serve'] for m in st['members']} == {IDS['b']: True, IDS['c']: False}

    # a standby, and an instance outside any group, decide nothing
    files = {n: g.file(n) for n in 'bc'}
    for n, other in (('b', 'c'), ('c', 'a'), ('e', 'b')):
        with g.at(n):
            r = _put_serve(admin, other, {'serve': True})
        assert r.status_code == 409, (n, r.data)
        assert r.get_json() == {'code': 'HA_STANDBY', 'error': 'Which instances are active is set on the leader'}
    assert {n: g.file(n) for n in 'bc'} == files

    with g.at('a'):
        assert _put_serve(admin, 'b', {'serve': False}).get_json() == {'success': True, 'serve': False,
                                                                       'actives': 1}
    rows = [row['details'] for row in _audit('ha.member_serve_changed')]
    assert rows == [f"{URLS['b']} is active from its next sync (2 of 3 instances active)",
                    f"{URLS['b']} is a standby from its next sync (1 of 3 instances active)"]
    assert g.restarts == restarts


def test_the_members_hear_about_it_at_once(fwd, seed, monkeypatch):
    """The HA routes tell nobody by themselves (app.py): the route sends the note."""
    g = fwd
    admin = _built(g, seed, 'bc')
    timers = []
    monkeypatch.setattr(g.ha, '_later', lambda delay, fn, name: timers.append((g.name(), fn, name)))
    with g.at('a'):
        assert _put_serve(admin, 'b', {'serve': True}).status_code == 200
    assert [(n, name) for n, _fn, name in timers] == [('a', 'ha-nudge')]
    g.pulls.clear()
    n, fn, _name = timers.pop()
    with g.at(n):
        fn()
    assert g.pulls == ['b', 'c']
    with g.at('b') as ha:
        assert ha.serving() is True
    assert g.state('c')['members'][IDS['b']]['serve'] is True
    # counterproof: nothing changed, no note
    with g.at('a'):
        assert _put_serve(admin, 'b', {'serve': True}).status_code == 200
    assert timers == []


def test_three_instances_at_most_are_active(fwd, seed):
    g = fwd
    admin = _built(g, seed, 'bcd')
    with g.at('a') as ha:
        assert _put_serve(admin, 'b', {'serve': True}).get_json()['actives'] == 2
        assert _put_serve(admin, 'c', {'serve': True}).get_json()['actives'] == 3
        before = g.file('a')
        r = _put_serve(admin, 'd', {'serve': True})
        assert r.status_code == 409
        assert r.get_json() == {'code': 'HA_ACTIVE_LIMIT', 'error': ha.ACTIVE_LIMIT_ERROR}
        assert 'at most 3 active instances' in r.get_json()['error']
        with pytest.raises(ha.ActiveLimit):
            ha.set_member_serve(IDS['d'], True)
        assert g.file('a') == before
        # a standby stays one, which always goes through, and a member back to a
        # standby frees its place
        assert _put_serve(admin, 'd', {'serve': False}).get_json() == {'success': True, 'serve': False,
                                                                       'actives': 3}
        assert _put_serve(admin, 'c', {'serve': False}).get_json()['actives'] == 2
        assert _put_serve(admin, 'd', {'serve': True}).get_json()['actives'] == 3
        st = admin.get('/api/ha/status').get_json()
    assert st['actives'] == 3
    assert {m['instance_id']: m['serve'] for m in st['members']} == {IDS['b']: True, IDS['c']: False,
                                                                    IDS['d']: True}
    for n in 'bcd':
        assert _sync(g, admin, n) == 'applied'
    for n in 'bcd':
        with g.at(n) as ha:
            assert (ha.serving(), ha.actives()) == (n != 'c', 3), n


def test_two_admins_at_once_cannot_both_take_the_last_place(fwd, seed, monkeypatch):
    """Counted and written under the state lock: the second call waits for the first and
    then finds the group full."""
    g = fwd
    _built(g, seed, 'bcd', sync=False)
    ha = g.ha
    real = ha._commit_locked
    inside = threading.Event()
    out = {}

    def slow(new):
        inside.set()
        time.sleep(0.3)            # the second call is under way by now
        real(new)

    def take(n):
        try:
            out[n] = ha.set_member_serve(IDS[n], True)
        except ha.ActiveLimit as e:
            out[n] = e
    with g.at('a'):
        ha.set_member_serve(IDS['b'], True)
        monkeypatch.setattr(ha, '_commit_locked', slow)
        first = threading.Thread(target=take, args=('c',))
        first.start()
        assert inside.wait(5)
        take('d')
        first.join(5)
        monkeypatch.setattr(ha, '_commit_locked', real)
        assert out['c'] == (True, 3) and isinstance(out['d'], ha.ActiveLimit), out
        assert ha.actives() == 3
    assert {mid: rec.get('serve') for mid, rec in g.file('a')['members'].items()} == \
        {IDS['b']: True, IDS['c']: True, IDS['d']: None}


# --- a promotion, a removal ----------------------------------------------------------------------

def test_a_promotion_keeps_the_flags_and_the_new_leader_has_none(fwd, seed):
    """c, an active member, is promoted: it leads now, and its own flag counts no more.
    The others keep theirs, and the old leader follows it as a standby."""
    g = fwd
    admin = _built(g, seed, 'bcd')
    with g.at('a') as ha:
        ha.set_member_serve(IDS['b'], True)
        ha.set_member_serve(IDS['c'], True)
    for n in 'bcd':
        assert _sync(g, admin, n) == 'applied'
    assert [g.state(n)['serve_assigned'] for n in 'bcd'] == [True, True, False]

    r = _promote(g, admin, 'c')
    assert r.status_code == 200, r.data
    c = g.state('c')
    assert c['role'] == 'active' and c['serve_assigned'] is False
    assert {mid: rec['serve'] for mid, rec in c['members'].items()} == \
        {IDS['a']: False, IDS['b']: True, IDS['d']: False}
    with g.at('c') as ha:
        assert (ha.serve_assigned(), ha.serving(), ha.actives()) == (False, False, 2)
        assert admin.get('/api/ha/status').get_json()['actives'] == 2

    for n in 'bd':
        assert _watch(g, n) == 'source switched'
    # b follows c and still holds the flag the old list gave c: the leader counts once
    assert g.state('b')['members'][IDS['c']]['serve'] is True
    with g.at('b') as ha:
        assert (ha.serving(), ha.actives()) == (True, 2)
    for n in 'abd':
        assert _sync(g, admin, n) == 'applied'
    assert [g.state(n)['serve_assigned'] for n in 'abd'] == [False, True, False]
    with g.at('a') as ha:
        assert (ha.role(), ha.serving(), ha.actives()) == ('standby', False, 2)
    with g.at('b') as ha:
        assert (ha.serving(), ha.actives()) == (True, 2)
    # the new leader decides from now on, with the same limit
    with g.at('c'):
        assert _put_serve(admin, 'd', {'serve': True}).get_json()['actives'] == 3
        r = _put_serve(admin, 'a', {'serve': True})
        assert r.status_code == 409 and r.get_json()['code'] == 'HA_ACTIVE_LIMIT'
    with g.at('a'):
        r = _put_serve(admin, 'b', {'serve': False})
        assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY'


def test_a_serving_member_removed_while_away_stops_at_its_next_sync(fwd, seed):
    g = fwd
    admin = _built(g, seed, 'b')
    _serve(g, 'b')
    g.down.add('b')
    with g.at('a'):
        r = _post(admin, f"/api/ha/members/{IDS['b']}/remove",
                  {'confirm': 'REMOVE', 'user_password': ADMIN_PW})
    assert r.status_code == 200 and r.get_json()['told'] is False, r.data
    assert g.state('a')['members'] == {}
    g.down.discard('b')
    # it has not heard yet
    with g.at('b') as ha:
        assert ha.serving() is True
    assert _sync(g, admin, 'b') == 'removed'
    with g.at('b') as ha:
        assert (ha.serve_assigned(), ha.serving(), ha.consoles_here()) == (False, False, False)
    assert g.state('b')['serve_assigned'] is False

    # it unpairs and joins again: a record of its own, a standby like any newcomer
    with g.at('b'):
        r = _post(admin, '/api/ha/unpair', {'confirm': 'UNPAIR', 'user_password': ADMIN_PW})
        assert r.status_code == 200, r.data
    _pair(g, admin, 'b')
    assert _sync(g, admin, 'b') == 'applied'
    assert g.state('a')['members'][IDS['b']].get('serve') is None
    with g.at('b') as ha:
        assert (ha.serve_assigned(), ha.serving()) == (False, False)


def test_a_member_that_leaves_takes_no_flag_along(fwd, seed):
    """Neither out of the group nor into the next one: a newcomer serves once the leader
    of its group says so, not from its first request on."""
    g = fwd
    admin = _built(g, seed, 'b')
    _serve(g, 'b')
    with g.at('b'):
        r = _post(admin, '/api/ha/unpair', {'confirm': 'UNPAIR', 'user_password': ADMIN_PW})
    assert r.status_code == 200, r.data
    b = g.state('b')
    assert (b['role'], b['serve_assigned']) == ('standalone', False)
    # the leader dropped it with its record
    assert g.state('a')['members'] == {}

    # a flag left in the file of a standalone instance does not survive its join
    g.write('b', dict(g.file('b'), serve_assigned=True))
    _pair(g, admin, 'b')
    with g.at('b') as ha:
        assert ha.source_id() == IDS['a'] and ha.live_view() and ha.forward_writes()
        assert (ha.serve_assigned(), ha.serving(), ha.consoles_here()) == (False, False, False)
    assert g.state('b')['serve_assigned'] is False


# --- what the others see ---------------------------------------------------------------------

def test_the_members_see_who_serves(fwd, seed, monkeypatch):
    g = fwd
    admin = _built(g, seed, 'bc')
    _watch(g, 'a')
    ms = _members(g, admin, 'a')
    assert ms[IDS['b']]['serving_seen'] is False and ms[IDS['c']]['serving_seen'] is False

    _serve(g, 'b')
    r = _send(g, 'b', g.signed('a', 'b'))
    assert r.status_code == 200 and r.get_json()['serving'] is True
    r = _send(g, 'a', g.signed('b', 'a'))
    assert r.get_json()['serving'] is False
    # the check before a removal notes it too
    with g.at('a') as ha:
        ha.refresh_member(IDS['b'])
        assert ha.member(IDS['b'])['serving_seen'] is True
    _watch(g, 'a')
    _watch(g, 'c')
    ms = _members(g, admin, 'a')
    assert ms[IDS['b']]['serving_seen'] is True and ms[IDS['c']]['serving_seen'] is False
    # what the leader set, next to what the member says
    assert ms[IDS['b']]['serve'] is True and ms[IDS['c']]['serve'] is False
    ms = _members(g, admin, 'c')
    assert ms[IDS['b']]['serving_seen'] is True and ms[IDS['a']]['serving_seen'] is False

    # anything but true is not serving
    from pegaprox.core import ha as ha_mod
    # a context of its own: undoing the test's monkeypatch would undo the harness too,
    # and every call after it would go out to the network
    with monkeypatch.context() as m:
        m.setattr(ha_mod, 'serving', lambda: 'yes')
        _watch(g, 'a')
        assert _members(g, admin, 'a')[IDS['b']]['serving_seen'] is False
    _watch(g, 'a')
    assert _members(g, admin, 'a')[IDS['b']]['serving_seen'] is True
    # a standby again: b says so with the next look at it
    _serve(g, 'b', False)
    _watch(g, 'a')
    ms = _members(g, admin, 'a')
    assert (ms[IDS['b']]['serve'], ms[IDS['b']]['serving_seen']) == (False, False)
    assert not g.state('a')['members'][IDS['b']]['last_error']


def test_the_banner_of_a_serving_standby(fwd, seed, db, tmp_path, monkeypatch):
    g = fwd
    admin = _built(g, seed, 'b')
    creds = _local_user(db, tmp_path, monkeypatch)
    with g.at('b'):
        banner = admin.get('/api/auth/check').get_json()['ha']
    assert (banner['serving'], banner['leader_reachable'], banner['forwarding']) == (False, True, True)

    _serve(g, 'b')
    with g.at('b'):
        r = g.api.anon().post('/api/auth/login', json=creds)
        assert r.status_code == 200, r.data
        assert r.get_json()['ha']['serving'] is True
        assert r.get_json()['ha']['leader_reachable'] is True
        assert admin.get('/api/auth/check').get_json()['ha']['serving'] is True

    # the leader goes silent: b still serves (consoles here), and says the leader is gone
    g.down.add('a')
    _watch(g, 'b')
    with g.at('b'):
        banner = admin.get('/api/auth/check').get_json()['ha']
    assert (banner['serving'], banner['leader_reachable'], banner['forwarding']) == (True, False, False)
    g.down.discard('a')
    _watch(g, 'b')
    with g.at('b'):
        assert admin.get('/api/auth/check').get_json()['ha']['leader_reachable'] is True
    # an instance that acts says its role and nothing more
    with g.at('a'):
        assert admin.get('/api/auth/check').get_json()['ha'] == {'role': 'active'}


def test_a_member_removed_from_the_group_serves_nobody(fwd, seed, monkeypatch):
    """Its accounts and rights stay those of its last sync, and nothing the leader
    changes reaches it any more: no consoles there, and it does not call itself active.
    Its flag goes with its record on the leader."""
    g = fwd
    admin = _built(g, seed, 'b')
    mgr = _fake_manager(g.api)
    _registry(monkeypatch, **{CID: mgr})
    mgr.get_vnc_ticket.return_value = {'success': True, 'ticket': 'PVEVNC:x', 'port': '5900'}
    _serve(g, 'b')
    # counterproof: until the removal it serves
    with g.at('b'):
        assert admin.get(f'{VM}/console').status_code == 200
        assert admin.post('/api/ws/token', json={}).status_code == 200

    with g.at('a'):
        r = _post(admin, f"/api/ha/members/{IDS['b']}/remove",
                  {'confirm': 'REMOVE', 'user_password': ADMIN_PW})
    assert r.status_code == 200 and r.get_json()['told'] is True, r.data
    assert g.state('b')['removed'] and g.state('b')['role'] == 'standby'
    assert IDS['b'] not in g.state('a')['members']
    g.calls.clear()
    with g.at('b') as ha:
        assert (ha.serve_assigned(), ha.actives()) == (False, 1)
        assert (ha.serving(), ha.consoles_here(), ha.leader_reachable()) == (False, False, False)
        r = admin.get(f'{VM}/console')
        assert r.status_code == 409 and r.get_json() == STANDBY_ANSWER
        r = admin.post('/api/ws/token', json={})
        assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY'
        banner = admin.get('/api/auth/check').get_json()['ha']
        st = admin.get('/api/ha/status').get_json()
    assert (banner['serving'], banner['removed'], banner['peer_url']) == (False, True, '')
    assert st['serving'] is False and st['removed']['by'] == IDS['a']
    assert mgr.get_vnc_ticket.call_count == 1 and _forward_calls(g) == []


def test_a_standby_that_lost_its_source_serves_nobody(fwd, seed):
    """The leader unpaired while this one could not be told: nobody to follow."""
    g = fwd
    _built(g, seed, 'b')
    _serve(g, 'b')
    with g.at('b') as ha:
        assert ha.serving() is True
        ha._update(source='f' * 32)
        assert ha.source_id() is None
        assert (ha.serving(), ha.consoles_here()) == (False, False)
        assert ha.banner()['removed'] is False


# --- consoles: the GET routes ------------------------------------------------------------------

def test_the_console_routes_open_on_a_serving_standby(fwd, seed, monkeypatch):
    g = fwd
    admin = _built(g, seed, 'b')
    mgr = _fake_manager(g.api)
    reg = _registry(monkeypatch, **{CID: mgr})
    calls = _console_calls(monkeypatch)
    for method, ret in calls.values():
        if method:
            getattr(mgr, method).return_value = ret
    g.calls.clear()
    with g.at('b'):
        for path in calls:
            r = admin.get(path)
            assert r.status_code == 409 and r.get_json() == STANDBY_ANSWER, path
    assert reg.asked == []

    _serve(g, 'b')
    with g.at('b'):
        for path in calls:
            reg.asked.clear()
            r = admin.get(path)
            assert r.status_code == 200, (path, r.status_code, r.data)
            assert CID in reg.asked, path
    assert mgr.get_vnc_ticket.call_count == 2 and mgr.get_spice_ticket.call_count == 1
    assert _forward_calls(g) == []


def test_an_api_token_gets_no_console_on_a_serving_standby(fwd, seed, monkeypatch):
    """Scripts use the leader: a token keeps the standby answer, a browser session opens."""
    g = fwd
    _built(g, seed, 'b')
    mgr = _fake_manager(g.api)
    _registry(monkeypatch, **{CID: mgr})
    mgr.get_vnc_ticket.return_value = {'success': True, 'ticket': 'PVEVNC:x', 'port': '5900'}
    token = _api_token()
    _serve(g, 'b')
    g.calls.clear()
    with g.at('b'):
        r = g.api.anon().get(f'{VM}/console', headers=token)
        assert r.status_code == 409 and r.get_json() == STANDBY_ANSWER
        r = g.api.anon().post('/api/ws/token', json={}, headers=token)
        assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY'
    assert _forward_calls(g) == [] and mgr.get_vnc_ticket.call_count == 0
    # counterproof: the same token on the leader
    with g.at('a'):
        assert g.api.anon().get(f'{VM}/console', headers=token).status_code == 200
        assert g.api.anon().post('/api/ws/token', json={}, headers=token).status_code == 200


# --- consoles: the POST routes the block in app.py decides ------------------------------------

# what each route answers here once it runs: no such cluster or ESXi server, or a token
LOCAL_ANSWER = {
    '/api/ws/token': 200,
    '/api/clusters/<cluster_id>/nodes/<node>/shell': 404,
    '/api/clusters/<cluster_id>/vms/<node>/<vm_type>/<int:vmid>/termproxy': 404,
    '/api/clusters/<cluster_id>/vms/<node>/<vm_type>/<int:vmid>/vnc-poll': 404,
    '/api/vmware/<vmware_id>/vms/<vm_id>/console': 404,
}


def test_the_console_posts_run_here_on_a_serving_standby(fwd, seed, monkeypatch):
    from pegaprox.globals import ws_tokens
    g = fwd
    admin = _built(g, seed, 'b')
    reg = _registry(monkeypatch)
    entries = sorted(_hook_lists(g.api.app)['_STANDBY_CONSOLES'])
    assert sorted(rule for _m, rule in entries) == sorted(LOCAL_ANSWER)
    before = set(ws_tokens)
    g.calls.clear()
    with g.at('b'):
        for method, rule in entries:
            r = getattr(admin, method.lower())(_concrete(rule), json={})
            assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY', (rule, r.data)
    assert reg.asked == [] and set(ws_tokens) == before and _forward_calls(g) == []

    _serve(g, 'b')
    with g.at('b'):
        for method, rule in entries:
            reg.asked.clear()
            r = getattr(admin, method.lower())(_concrete(rule), json={})
            assert r.status_code == LOCAL_ANSWER[rule], (rule, r.status_code, r.data)
            if rule.startswith('/api/clusters/'):
                assert r.get_json()['error'] == 'Cluster not found' and reg.asked, rule
            elif rule.startswith('/api/vmware/'):
                assert r.get_json()['error'] == 'VMware server not found'
            else:
                assert r.get_json()['token'] in ws_tokens
    assert _forward_calls(g) == []


PLUGIN_CONSOLE = '/api/plugins/probe/api/vm/console'


def _plugin_state(plugin_id, enabled):
    """The plugin_state row as a sync leaves it, None for none."""
    from pegaprox.core.db import get_db
    db = get_db()
    db.execute('DELETE FROM plugin_state WHERE plugin_id = ?', (plugin_id,))
    if enabled is not None:
        db.execute('INSERT INTO plugin_state (plugin_id, enabled) VALUES (?, ?)', (plugin_id, int(enabled)))


@pytest.fixture
def plugin_console(fwd, probe, monkeypatch):
    """The probe plugin with a console route that notes where it opened."""
    import pegaprox.api.plugins as plugins
    opened = []

    def console():
        from pegaprox.core import ha
        opened.append(ha.role())
        return {'ticket': 'x'}
    monkeypatch.setitem(plugins._plugin_routes, 'probe', dict(plugins._plugin_routes['probe'],
                                                               **{'vm/console': console}))
    return opened


def test_a_serving_standby_opens_a_plugin_console_the_leader_runs(fwd, seed, plugin_console):
    """Consoles are local where users are served, a plugin's too: the browser connects to
    the instance that opened it. Only for a plugin loaded here that the synced
    plugin_state says is switched on, any method, and never forwarded."""
    g = fwd
    admin = _built(g, seed, 'b')
    _plugin_state('probe', True)
    _serve(g, 'b')
    g.calls.clear()
    with g.at('b'):
        assert admin.get(f'{PLUGIN_CONSOLE}?cluster_id=c1&vmid=100').get_json() == {'ticket': 'x'}
        assert admin.post(PLUGIN_CONSOLE, json={}).status_code == 200
    assert plugin_console == ['standby', 'standby'] and _forward_calls(g) == []


@pytest.mark.parametrize('state', [False, None, 'unloaded'])
def test_a_plugin_the_leader_does_not_run_opens_no_console_here(fwd, seed, plugin_console, monkeypatch, state):
    """Switched off on the leader (the module stays loaded here until a restart), never
    switched on, or switched on there and not loaded here: 409, the console is the
    leader's."""
    import pegaprox.api.plugins as plugins
    g = fwd
    admin = _built(g, seed, 'b')
    _plugin_state('probe', True if state == 'unloaded' else state)
    if state == 'unloaded':
        monkeypatch.delitem(plugins._loaded_plugins, 'probe')
    _serve(g, 'b')
    g.calls.clear()
    with g.at('b'):
        for call in (admin.get, admin.post):
            r = call(PLUGIN_CONSOLE)
            assert r.status_code == 409, (call, r.data)
            assert r.get_json() == {'code': 'HA_STANDBY', 'error': 'This plugin is not running on this '
                                    'instance - open its console on the leader.'}
    assert plugin_console == [] and _forward_calls(g) == []
    # counterproof: switched on and loaded, the same call opens here
    _plugin_state('probe', True)
    monkeypatch.setitem(plugins._loaded_plugins, 'probe', types.SimpleNamespace())
    with g.at('b'):
        assert admin.get(PLUGIN_CONSOLE).status_code == 200
    assert plugin_console == ['standby']


def test_a_plugin_console_stays_refused_where_no_console_opens(fwd, seed, plugin_console):
    """A standby that does not serve users, and an API token on one that does: refused
    as before, and nothing reaches the leader."""
    g = fwd
    admin = _built(g, seed, 'b')
    _plugin_state('probe', True)
    token = _api_token()
    g.calls.clear()
    with g.at('b'):
        for call in (admin.post, admin.get):
            r = call(PLUGIN_CONSOLE)
            assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY', r.data
            assert 'open its console on the leader' not in r.get_json()['error']
    _serve(g, 'b')
    with g.at('b'):
        r = g.api.anon().get(PLUGIN_CONSOLE, headers=token)
        assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY', r.data
    assert plugin_console == [] and _forward_calls(g) == []
    # counterproof: the browser session on the serving standby opens it here, the
    # plugin's other calls go to the leader, and the leader opens it for its own
    with g.at('b'):
        assert admin.get(PLUGIN_CONSOLE).status_code == 200
        assert admin.post('/api/plugins/probe/api/record', json={}).status_code == 200
        assert admin.get('/api/plugins/probe/api/record').status_code == 200
    assert len(_forward_calls(g)) == 2 and plugin_console == ['standby']
    with g.at('a'):
        assert admin.get(PLUGIN_CONSOLE).status_code == 200
    assert plugin_console == ['standby', 'active']


def test_the_client_portal_console_hands_out_a_token_of_the_serving_standby(fwd, seed, monkeypatch):
    """The portal opens its noVNC socket on the instance it was loaded from, with the ws
    token and the VNC ticket vm/console handed it: both from this process."""
    import pegaprox.api.plugins as plugins
    import plugins.client_portal as portal
    from pegaprox.globals import ws_tokens
    g = fwd
    admin = _built(g, seed, 'b')
    monkeypatch.setitem(plugins._loaded_plugins, 'client_portal', portal)
    monkeypatch.setitem(plugins._plugin_routes, 'client_portal', {})
    portal.register(None)
    mgr = _fake_manager(g.api)
    mgr.get_vm_resources.return_value = [{'vmid': 100, 'node': 'n1', 'type': 'qemu'}]
    mgr.get_vnc_ticket.return_value = {'success': True, 'ticket': 'PVEVNC:x', 'port': '5900'}
    monkeypatch.setattr(portal, 'cluster_managers', {CID: mgr})
    _plugin_state('client_portal', True)
    _serve(g, 'b')
    before = set(ws_tokens)
    path = f'/api/plugins/client_portal/api/vm/console?cluster_id={CID}&vmid=100'
    g.calls.clear()
    with g.at('b'):
        r = admin.get(path)
    assert r.status_code == 200 and r.get_json()['success'] is True, r.data
    token = r.get_json()['ws_token']
    assert token in ws_tokens and token not in before
    assert mgr.get_vnc_ticket.call_count == 1 and _forward_calls(g) == []
    # counterproof: switched off on the leader, the portal console is not handed out here
    _plugin_state('client_portal', False)
    with g.at('b'):
        r = admin.get(path)
    assert r.status_code == 409 and 'on the leader' in r.get_json()['error']
    assert set(ws_tokens) - before == {token} and mgr.get_vnc_ticket.call_count == 1


_CONSOLE_MARKERS = ('create_ws_token', 'get_vnc_ticket', 'get_spice_ticket', 'vncproxy',
                    'termproxy', 'spiceproxy', 'vnc-poll', '/api/ws/token')


def _plugin_routes_that_open_a_console():
    """{(plugin dir, route path)} of the bundled plugins whose handler, or a function of
    the plugin it calls, hands out a console ticket or a ws token."""
    import ast
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent / 'plugins'
    found = set()
    for init in sorted(root.glob('*/__init__.py')):
        src = init.read_text(encoding='utf-8')
        tree = ast.parse(src)
        funcs = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}

        def reaches_a_console(name, seen):
            if name in seen or name not in funcs:
                return False
            seen.add(name)
            body = ast.get_source_segment(src, funcs[name])
            if any(m in body for m in _CONSOLE_MARKERS):
                return True
            called = {c.func.id for c in ast.walk(funcs[name])
                      if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)}
            return any(reaches_a_console(c, seen) for c in called)

        for call in ast.walk(tree):
            if not (isinstance(call, ast.Call) and getattr(call.func, 'id', '') == 'register_plugin_route'):
                continue
            path, handler = call.args[1], call.args[2]
            assert isinstance(path, ast.Constant) and isinstance(handler, ast.Name), ast.dump(call)
            if reaches_a_console(handler.id, set()):
                found.add((init.parent.name, path.value))
    return found


def test_every_plugin_route_that_hands_out_a_console_is_a_console_path():
    """Read on the leader like the rest of a plugin, its ticket and token would be the
    leader's and the browser here could not use them; refused like a write on a standby
    that does not serve users. ha.PLUGIN_CONSOLE_PATHS is what keeps them local."""
    from pegaprox.core import ha
    found = _plugin_routes_that_open_a_console()
    # counterproof: the scan sees the one the portal has
    assert ('client_portal', 'vm/console') in found
    assert {path for _plugin, path in found} <= ha.PLUGIN_CONSOLE_PATHS, found


# --- consoles: the WebSockets ------------------------------------------------------------------

@pytest.mark.parametrize('auth', ['token', 'session'])
def test_the_vnc_sockets_open_on_a_serving_standby(fwd, seed, monkeypatch, auth):
    g = fwd
    admin = _built(g, seed, 'b')
    reg = _registry(monkeypatch)
    app = g.api.app
    main_port = _sock_handler(app, VNC_SOCKET)
    own_port = _standalone_vnc_handler(reg)
    path = f'{VM}/vncwebsocket'

    def on_main_port():
        ws = _SyncWS()
        with app.test_request_context(f'{path}?{_auth_query(auth, admin)}'):
            main_port(ws, CID, 'n1', 'qemu', 100)
        return ws

    def on_own_port():
        ws = _AsyncWS(f'{path}?{_auth_query(auth, admin)}')
        asyncio.run(own_port(ws))
        return ws

    with g.at('b'):
        assert on_main_port().sent == [STANDBY_ANSWER['error']]
        assert on_own_port().closed == (1008, STANDBY_ANSWER['error'])
    assert reg.asked == []

    _serve(g, 'b')
    with g.at('b'):
        ws = on_main_port()
        assert STANDBY_ANSWER['error'] not in ws.sent and reg.asked[-1] == CID
        reg.asked.clear()
        ws = on_own_port()
        assert ws.closed == (1002, 'Cluster not found') and reg.asked[-1] == CID


def test_the_gevent_vnc_socket_and_the_legacy_shell_open_on_a_serving_standby(fwd, seed, monkeypatch):
    g = fwd
    admin = _built(g, seed, 'b')
    reg = _registry(monkeypatch)
    app = g.api.app
    client = app.test_client()
    url = f'{VM}/vncwebsocket?session={admin.session_id}'
    shell = _sock_handler(app, '/api/clusters/<cluster_id>/nodes/<node>/shellws')
    shell_url = f'/api/clusters/{CID}/nodes/n1/shellws?session={admin.session_id}'

    def gevent_vnc():
        ws = _SyncWS()
        client.get(url, base_url='http://localhost', environ_base={'wsgi.websocket': ws})
        return ws

    def legacy_shell():
        ws = _SyncWS()
        with app.test_request_context(shell_url):
            shell(ws, CID, 'n1')
        return [json.loads(m)['message'] for m in ws.sent]

    with g.at('b'):
        assert gevent_vnc().closed == ((1008, STANDBY_ANSWER['error']), {})
        assert legacy_shell() == [STANDBY_ANSWER['error']]
    assert reg.asked == []

    pytest.importorskip('paramiko')
    _serve(g, 'b')
    with g.at('b'):
        assert gevent_vnc().closed is None and reg.asked[-1] == CID
        reg.asked.clear()
        assert legacy_shell() == ['Cluster not found'] and reg.asked[-1] == CID


def test_the_ssh_servers_calls_answer_on_a_serving_standby(fwd, seed, monkeypatch):
    """The ws token check and the cluster-creds of the SSH server process, and what it
    learns there: a standby holds the leader's known_hosts."""
    from pegaprox.utils.realtime import create_ws_token
    g = fwd
    admin = _built(g, seed, 'b')
    reg = _registry(monkeypatch)
    client = g.api.app.test_client()
    client.set_cookie('session', admin.session_id, domain='localhost')

    def validate():
        token = create_ws_token('root', 'admin')
        return client.get(f'/api/ws/token/validate?token={token}&cluster_id={CID}&node=n1&shell=node',
                          base_url='http://localhost')

    def creds():
        return client.get(f'/api/internal/cluster-creds/{CID}', base_url='http://localhost')

    def session_check():
        return client.get('/api/auth/validate', base_url='http://localhost')

    with g.at('b'):
        assert validate().get_json() == STANDBY_ANSWER
        assert creds().get_json() == STANDBY_ANSWER
    assert reg.asked == []

    _serve(g, 'b')
    with g.at('b'):
        r = validate()
        assert r.status_code == 200 and r.get_json()['valid'] is True, r.data
        assert r.get_json()['known_hosts_only'] is True
        r = creds()
        assert r.status_code == 404 and r.get_json()['error'] == 'Cluster not found'
        assert session_check().get_json()['known_hosts_only'] is True
    assert CID in reg.asked
    with g.at('a'):
        assert validate().get_json()['known_hosts_only'] is False
        assert session_check().get_json()['known_hosts_only'] is False


# --- no host key pinned on a standby -----------------------------------------------------------

class _HostKeys(dict):
    def add(self, host, keytype, key):
        self.setdefault(host, {})[keytype] = key


def _fake_paramiko(known):
    """What the SSH server script uses of paramiko: a client whose connect meets the
    host key as `known` or not, and notes whether the keys were saved."""
    fake = types.SimpleNamespace(saved=[])

    class SSHException(Exception):
        pass

    class SSHClient:
        def __init__(self):
            self._host_keys, self._policy = _HostKeys(), None

        def load_host_keys(self, path):
            pass

        def set_missing_host_key_policy(self, policy):
            self._policy = policy

        def connect(self, host, **kw):
            if not known:
                self._policy.missing_host_key(self, host, types.SimpleNamespace(get_name=lambda: 'ssh-ed25519'))

        def get_host_keys(self):
            return self._host_keys

        def invoke_shell(self, **kw):
            raise SSHException('no shell in this test')

        def close(self):
            pass

    class _OnDisk(_HostKeys):
        # the script merges into the file instead of saving the client's set (NS Oct 2026)
        def load(self, path):
            pass

        def lookup(self, host):
            return self.get(host)

        def save(self, path):
            fake.saved.append(path)

    fake.hostkeys = types.SimpleNamespace(HostKeys=_OnDisk)
    fake.SSHException = SSHException
    fake.AuthenticationException = type('AuthenticationException', (SSHException,), {})
    fake.MissingHostKeyPolicy = object
    fake.SSHClient = SSHClient
    return fake


class _TalkingWS(_AsyncWS):
    """A browser that sends the node's credentials when asked for them."""

    def __init__(self, path, *incoming):
        super().__init__(path)
        self.incoming = list(incoming)

    async def recv(self):
        if self.incoming:
            return self.incoming.pop(0)
        raise ConnectionError('nothing more to say')


@pytest.mark.parametrize('known_only, known', [(True, False), (True, True), (False, False)])
def test_the_ssh_server_pins_nothing_on_a_standby(tmp_path, monkeypatch, known_only, known):
    pytest.importorskip('paramiko')
    pytest.importorskip('websockets')
    monkeypatch.setenv('PEGAPROX_SSH_KNOWN_HOSTS', str(tmp_path / 'known_hosts'))
    # the node's own address, as the main app names it (#1143)
    answer = _Resp(200, {'valid': True, 'known_hosts_only': known_only,
                         'cluster_context': {'host': '192.0.2.10', 'node_ips': {'n1': '192.0.2.10'}}})
    ns, _asked = _ssh_server({'/api/ws/token/validate': answer})
    fake = _fake_paramiko(known)
    ns['paramiko'] = fake
    ws = _TalkingWS(f'{SHELL}?token=t', json.dumps({'username': 'root', 'password': 'pw'}))
    asyncio.run(ns['ssh_handler'](ws))
    said = ''.join(m for m in ws.sent if isinstance(m, str))
    if known_only and not known:
        # the address tried, as the main app says it (the leader may know the node under
        # another one), and not the node's name
        from pegaprox.utils.ssh_security import _not_known_here
        assert _not_known_here('192.0.2.10') in said, ws.sent
        assert 'another address than 192.0.2.10,' in said and 'host key of n1' not in said
        assert fake.saved == []
    elif known_only:
        # a key it holds: the shell opens (and fails in this test), and nothing is saved
        assert NOT_KNOWN not in said and 'no shell in this test' in said, ws.sent
        assert fake.saved == []
    else:
        # counterproof: the TOFU pin as before, then the (fake) shell fails
        assert NOT_KNOWN not in said and 'no shell in this test' in said, ws.sent
        assert fake.saved == [str(tmp_path / 'known_hosts')]


@pytest.fixture
def known_hosts(tmp_path, monkeypatch):
    import pegaprox.utils.ssh_security as sec
    path = str(tmp_path / 'known_hosts')
    monkeypatch.setattr(sec, '_KNOWN_HOSTS', path)
    return path


class _Transport:
    """A paramiko Transport after the key exchange, as far as the check reads it."""

    def __init__(self, key):
        self.key = key

    def get_remote_server_key(self):
        return self.key


def _roles(g):
    g.write('a', {'role': 'active', 'epoch': 1, 'instance_id': IDS['a'], 'interval': 30,
                  'pairing': None, 'sync': {}})
    g.write('b', {'role': 'standby', 'epoch': 1, 'instance_id': IDS['b'], 'interval': 30,
                  'pairing': None, 'sync': {}, 'serve_assigned': True})


def test_a_standby_pins_no_host_key_and_takes_the_ones_it_holds(group, known_hosts):
    paramiko = pytest.importorskip('paramiko')
    from pegaprox.utils import ssh_security as sec
    g = group
    _roles(g)
    known, stranger = paramiko.ECDSAKey.generate(), paramiko.ECDSAKey.generate()
    pinned = paramiko.hostkeys.HostKeys()
    pinned.add('192.0.2.10', known.get_name(), known)
    pinned.save(known_hosts)
    before = open(known_hosts).read()

    with g.at('b'):
        assert sec.pins_host_keys_here() is False
        assert sec.cli_hostkey_opts() == ('yes', known_hosts)
        client = sec.secure_ssh_client(paramiko)
        with pytest.raises(paramiko.SSHException, match=f'host key of 192.0.2.11 {NOT_KNOWN}'):
            client._policy.missing_host_key(client, '192.0.2.11', stranger)
        with pytest.raises(paramiko.SSHException, match=f'host key of 192.0.2.11 {NOT_KNOWN}'):
            sec.verify_transport_host_key(_Transport(stranger), '192.0.2.11', paramiko)
        # the key it holds goes through, a changed one is refused as everywhere
        sec.verify_transport_host_key(_Transport(known), '192.0.2.10', paramiko)
        with pytest.raises(paramiko.BadHostKeyException):
            sec.verify_transport_host_key(_Transport(stranger), '192.0.2.10', paramiko)
        # a client carrying a key nobody checked writes nothing either
        client.get_host_keys().add('192.0.2.12', stranger.get_name(), stranger)
        sec.persist_host_keys(client)
    assert open(known_hosts).read() == before

    # counterproof: an instance that acts pins on first sight, as before
    for n in 'ae':
        with open(known_hosts, 'w') as fh:
            fh.write(before)
        with g.at(n):
            assert sec.pins_host_keys_here() is True
            assert sec.cli_hostkey_opts()[0] == 'accept-new'
            client = sec.secure_ssh_client(paramiko)
            client._policy.missing_host_key(client, '192.0.2.11', stranger)
            sec.persist_host_keys(client)
            sec.verify_transport_host_key(_Transport(stranger), '192.0.2.13', paramiko)
        now = paramiko.hostkeys.HostKeys(known_hosts)
        assert now.lookup('192.0.2.11') and now.lookup('192.0.2.13'), n


def test_the_refusal_names_the_address_that_was_tried(group, known_hosts):
    """A standby looks a key up under the address it reached the node at. The leader may
    know the node under another one (another site, another VLAN), which the refusal says:
    a shell on the leader then pins nothing this standby could use."""
    paramiko = pytest.importorskip('paramiko')
    from pegaprox.utils import ssh_security as sec
    g = group
    _roles(g)
    key = paramiko.ECDSAKey.generate()
    # the leader's pin, under the address the leader uses
    pinned = paramiko.hostkeys.HostKeys()
    pinned.add('10.1.0.5', key.get_name(), key)
    pinned.save(known_hosts)
    with g.at('b'):
        sec.verify_transport_host_key(_Transport(key), '10.1.0.5', paramiko)
        for tried, port, shown in (('10.2.0.5', 22, '10.2.0.5'), ('10.2.0.5', 2222, '[10.2.0.5]:2222')):
            with pytest.raises(paramiko.SSHException) as e:
                sec.verify_transport_host_key(_Transport(key), tried, paramiko, port=port)
            said = str(e.value)
            assert said.startswith(f'host key of {shown} is not known here yet'), said
            assert f'if the leader reaches this node at another address than {shown}' in said
        client = sec.secure_ssh_client(paramiko)
        with pytest.raises(paramiko.SSHException, match='another address than 10.2.0.5,'):
            client._policy.missing_host_key(client, '10.2.0.5', key)


def test_the_system_ssh_fallback_is_strict_on_a_standby(group, known_hosts, monkeypatch):
    """utils/ssh.py falls back to sshpass + ssh when paramiko gets nowhere."""
    paramiko = pytest.importorskip('paramiko')
    import socket
    from pegaprox.utils import ssh as sshmod
    g = group
    _roles(g)

    def no_network(*a, **kw):
        raise OSError('no network in this test')
    monkeypatch.setattr(socket, 'create_connection', no_network)
    monkeypatch.setattr(paramiko.SSHClient, 'connect', no_network)
    ran = []

    def run(args, **kw):
        ran.append(args)
        return subprocess.CompletedProcess(args, 0, 'ok', '')
    monkeypatch.setattr(subprocess, 'run', run)
    for n, want in (('b', 'yes'), ('a', 'accept-new'), ('e', 'accept-new')):
        with g.at(n):
            rc, out, _err = sshmod._ssh_exec('192.0.2.10', 'root', 'pw', 'true')
        assert (rc, out) == (0, 'ok'), n
        assert f'StrictHostKeyChecking={want}' in ran[-1], (n, ran[-1])
        assert f'UserKnownHostsFile={known_hosts}' in ran[-1]


# --- what only the leader's tables hold ----------------------------------------------------------

LEADER_VIEWS = {
    '/api/clusters/<cluster_id>/active-alerts': f'/api/clusters/{CID}/active-alerts',
    '/api/clusters/<cluster_id>/drift/status': f'/api/clusters/{CID}/drift/status',
    '/api/clusters/<cluster_id>/drift/events': f'/api/clusters/{CID}/drift/events?status=all',
    '/api/push/inbox': '/api/push/inbox?unread=1',
    '/api/migration-history': f'/api/migration-history?cluster_id={CID}',
    '/api/clusters/<cluster_id>/vms/<int:vmid>/migration-history':
        f'/api/clusters/{CID}/vms/100/migration-history',
    '/api/clusters/<cluster_id>/balance-history': f'/api/clusters/{CID}/balance-history',
}
ACKS = {
    ('POST', '/api/drift/events/<int:eid>/acknowledge'): '/api/drift/events/7/acknowledge',
    ('POST', '/api/clusters/<cluster_id>/active-alerts/<fired_id>/ack'):
        f'/api/clusters/{CID}/active-alerts/7/ack',
    ('POST', '/api/push/inbox/clear'): '/api/push/inbox/clear',
}


@pytest.fixture
def recorded(fwd, monkeypatch):
    """swap(rule, method): that route answers where it ran, noting how it was reached."""
    from flask import request
    app = fwd.api.app
    seen = []

    def swap(rule, method):
        endpoints = [r.endpoint for r in app.url_map.iter_rules() if r.rule == rule and method in r.methods]
        assert len(endpoints) == 1, (rule, endpoints)

        def view(*a, **kw):
            from pegaprox.core import ha
            seen.append({'role': ha.role(), 'mark': request.environ.get(ha.FORWARD_ENVIRON),
                         'args': request.args.to_dict()})
            return {'on': ha.role()}
        monkeypatch.setitem(app.view_functions, endpoints[0], view)
    return types.SimpleNamespace(swap=swap, seen=seen)


def test_the_leader_views_are_forwarded_reads(api):
    from pegaprox.core import ha
    assert set(LEADER_VIEWS) == ha.LEADER_ONLY_READS
    assert ha.LEADER_ONLY_READS < ha.FORWARDED_READS


def _failing_forward(g, monkeypatch, how):
    """The forwarded read of b fails the way `how` says; every other call goes through."""
    import pegaprox.api.ha as ha_api
    if how == 'down':
        g.down.add('a')
        return
    if how == 'unreadable':
        monkeypatch.setattr(ha_api, '_forwarded_answer', lambda resp: None)
        return
    plain = g.call

    def call(method, base_url, fingerprint, path, *a, **kw):
        if path == FORWARD:
            if how == 'no_answer':
                raise g.ha.PeerNoAnswer('The peer took the call but sent no answer: ReadTimeout')
            # a proxy in front of the leader while it restarts
            return types.SimpleNamespace(status_code=502, headers={}, content=b'',
                                         json=lambda: {'error': 'Bad Gateway'})
        return plain(method, base_url, fingerprint, path, *a, **kw)
    monkeypatch.setattr(g.ha, '_peer_call', call)


@pytest.mark.parametrize('how', ['no_answer', 'down', 'refused', 'unreadable'])
def test_a_leader_view_is_never_the_standbys_own_rows(fwd, seed, recorded, monkeypatch, how):
    """When the leader does not answer, the list says so (503) instead of showing the
    standby's own rows: those carry ids of its own, and an ack picked from them would be
    forwarded and name another row on the leader."""
    g = fwd
    admin = _built(g, seed, 'b')
    for rule in LEADER_VIEWS:
        recorded.swap(rule, 'GET')
    recorded.swap('/api/vmware/migrations', 'GET')
    _failing_forward(g, monkeypatch, how)
    for rule, path in sorted(LEADER_VIEWS.items()):
        with g.at('b') as ha:
            ha._note_source_heard(IDS['a'], True)
            r = admin.get(path)
        assert r.status_code == 503, (rule, r.status_code, r.data)
        assert r.get_json()['code'] == 'HA_ACTIVE_UNREACHABLE', rule
    # the leader may have run it (its answer got lost on the way), this instance did not
    assert [s for s in recorded.seen if s['role'] != 'active'] == []
    # counterproof: the progress of a job falls back to this instance's own copy
    with g.at('b') as ha:
        ha._note_source_heard(IDS['a'], True)
        r = admin.get('/api/vmware/migrations')
    assert r.status_code == 200 and r.get_json() == {'on': 'standby'}, r.data
    assert [s['role'] for s in recorded.seen if s['role'] != 'active'] == ['standby']


def test_a_leader_view_answers_here_while_nothing_is_forwarded(fwd, seed, recorded):
    """No attempt, no refusal: forwarding switched off, or an API token. The route
    answers as it did before."""
    from pegaprox.utils.auth import create_api_token
    g = fwd
    admin = _built(g, seed, 'b')
    rule = '/api/clusters/<cluster_id>/drift/events'
    recorded.swap(rule, 'GET')
    token = {'Authorization': f"Bearer {create_api_token('root', 'automation', role='admin')['token']}"}
    g.calls.clear()
    with g.at('b') as ha:
        assert g.api.anon().get(LEADER_VIEWS[rule], headers=token).get_json() == {'on': 'standby'}
        ha.set_forward_writes(False)
        assert admin.get(LEADER_VIEWS[rule]).get_json() == {'on': 'standby'}
    assert _forward_calls(g) == []


def test_a_leader_view_says_so_while_the_leader_is_known_to_be_away(fwd, seed, recorded):
    """Forwarding is on and the leader is known to be away: no attempt, and the view
    says the leader keeps it rather than showing this instance's own rows. The
    progress of a job still answers from here."""
    g = fwd
    admin = _built(g, seed, 'b')
    rule = '/api/clusters/<cluster_id>/drift/events'
    recorded.swap(rule, 'GET')
    recorded.swap('/api/vmware/migrations', 'GET')
    g.calls.clear()
    with g.at('b') as ha:
        ha._note_source_heard(IDS['a'], False)
        assert ha.forwarding() is False and ha.forward_writes() is True
        r = admin.get(LEADER_VIEWS[rule])
        assert r.status_code == 503 and r.get_json()['code'] == 'HA_ACTIVE_UNREACHABLE', r.data
        assert admin.get('/api/vmware/migrations').get_json() == {'on': 'standby'}
    assert _forward_calls(g) == []


@pytest.mark.parametrize('rule', sorted(LEADER_VIEWS))
def test_a_view_only_the_leader_fills_comes_from_the_leader(fwd, seed, recorded, rule):
    g = fwd
    admin = _built(g, seed, 'b')
    recorded.swap(rule, 'GET')
    path = LEADER_VIEWS[rule]
    g.calls.clear()
    with g.at('b'):
        r = admin.get(path)
    assert r.status_code == 200 and r.get_json() == {'on': 'active'}, r.data
    assert _forward_calls(g) == [('b', 'a', 'POST', FORWARD)]
    assert recorded.seen[-1]['mark']['via'] == URLS['b']
    assert recorded.seen[-1]['args'] == dict(parse_qsl(urlsplit(path).query))
    # a read changes nothing: no sync after it
    assert g.pulls == []

    # forwarding off: this instance's own answer, and nothing sent
    g.calls.clear()
    with g.at('b') as ha:
        ha.set_forward_writes(False)
        r = admin.get(path)
    assert r.status_code == 200 and r.get_json() == {'on': 'standby'}
    assert _forward_calls(g) == []


@pytest.mark.parametrize('method, rule', sorted(ACKS))
def test_an_acknowledgement_goes_to_the_leader(fwd, seed, recorded, method, rule):
    g = fwd
    admin = _built(g, seed, 'b')
    lists = _hook_lists(g.api.app)
    assert (method, rule) not in lists['_STANDBY_NOT_FORWARDED']
    # the two that name rows of this instance's own tables stay kept back
    assert {('DELETE', '/api/auto-install/runs/<run_id>'),
            ('POST', '/api/insights/force-snapshot')} <= lists['_STANDBY_NOT_FORWARDED']
    recorded.swap(rule, method)
    g.calls.clear()
    with g.at('b'):
        r = admin.post(ACKS[(method, rule)], json={})
    assert r.status_code == 200 and r.get_json() == {'on': 'active'}, r.data
    assert _forward_calls(g) == [('b', 'a', 'POST', FORWARD)]
    assert recorded.seen[-1]['mark']['via'] == URLS['b']
    assert g.pulls == ['b']

    # forwarding off: refused, as every change is
    g.calls.clear()
    with g.at('b') as ha:
        ha.set_forward_writes(False)
        r = admin.post(ACKS[(method, rule)], json={})
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY'
    assert _forward_calls(g) == [] and len(recorded.seen) == 1


def test_the_inbox_clear_runs_on_the_leader_as_the_user(fwd, seed):
    """The real route, not a stand-in: the leader marks the user's rows read."""
    from datetime import datetime
    from pegaprox.api.push import _ensure_inbox_table
    from pegaprox.core.db import get_db
    g = fwd
    admin = _built(g, seed, 'b')
    _ensure_inbox_table()
    db = get_db()
    db.conn.cursor().execute(
        "INSERT INTO push_inbox (username, title, body, severity, url, tag, created_at) "
        "VALUES ('root', 't', 'b', 'info', '/', 'x', ?)", (datetime.now().isoformat(),))
    db.conn.commit()
    g.calls.clear()
    with g.at('b'):
        r = admin.post('/api/push/inbox/clear', json={})
        assert r.status_code == 200 and r.get_json() == {'ok': True}, r.data
        items = admin.get('/api/push/inbox').get_json()['items']
    assert _forward_calls(g) == [('b', 'a', 'POST', FORWARD)] * 2
    assert items and all(i['read_at'] for i in items)


# --- a plugin's own page on a standby -----------------------------------------------------

@pytest.mark.parametrize('page,plugin', [('/portal', 'client_portal'), ('/status', 'status_page'),
                                         ('/api/public/status-page', 'status_page')])
def test_a_plugin_page_on_a_standby_goes_by_the_synced_state(fwd, seed, monkeypatch, page, plugin):
    """The module stays loaded on a standby until a restart after the leader switched the
    plugin off: its page goes by the plugin state the sync brought, not by being loaded."""
    import types as _types
    import pegaprox.api.plugins as plugins
    g = fwd
    _built(g, seed, 'b')
    monkeypatch.setitem(plugins._loaded_plugins, plugin, _types.SimpleNamespace())
    _plugin_state(plugin, False)
    with g.at('b'):
        r = g.api.anon().get(page)
    assert r.status_code == 404, (page, r.status_code)
    # counterproof: switched on in the synced state, the page is there
    _plugin_state(plugin, True)
    with g.at('b'):
        r = g.api.anon().get(page)
    assert r.status_code != 404 or b'not installed' in r.data, (page, r.status_code, r.data[:120])
    # and the leader still goes by what it has loaded, as before
    _plugin_state(plugin, False)
    with g.at('a'):
        r = g.api.anon().get(page)
    assert r.status_code != 404 or b'not installed' in r.data, (page, r.status_code, r.data[:120])


def test_the_portal_says_why_a_console_does_not_open():
    """portal.html shows the server's reason for a refused console (a standby's 409)
    instead of doing nothing."""
    import os
    html = open(os.path.join(os.path.dirname(__file__), '..', 'plugins', 'client_portal', 'portal.html')).read()
    start = html.index('async function openConsole(vm)')
    body = html[start:html.index('\n}\n', start)]
    assert "else if(r){" in body and "toast(msg,'error')" in body and 'd.error' in body


def test_a_standby_runs_a_plugin_exactly_when_the_leader_does(fwd, seed, monkeypatch):
    """A standby starts before its first sync, so the plugin state that sync brings was
    never acted on: after each applied sync it loads what the leader switched on and
    unloads what it switched off, and writes nothing back."""
    import pegaprox.api.plugins as plugins
    g = fwd
    _built(g, seed, 'b')
    calls = []

    def load(app, pid):
        calls.append(('load', pid))
        plugins._loaded_plugins[pid] = object()
        return True, ''

    def unload(pid):
        calls.append(('unload', pid))
        plugins._loaded_plugins.pop(pid, None)
    monkeypatch.setattr(plugins, '_app', object())
    monkeypatch.setattr(plugins, '_loaded_plugins', {'gone_one': object()})
    monkeypatch.setattr(plugins, 'load_plugin', load)
    monkeypatch.setattr(plugins, 'unload_plugin', unload)
    monkeypatch.setattr(g.ha, '_follow_plugin_state', g.follow_plugin_state)
    _plugin_state('hello_world', True)
    _plugin_state('gone_one', False)
    with g.at('b') as ha:
        assert ha.pull_once() == 'applied'
    assert calls == [('unload', 'gone_one'), ('load', 'hello_world')]
    # the state rows are the leader's: nothing written back
    from pegaprox.core.db import get_db
    rows = {r['plugin_id']: r['enabled'] for r in get_db().query('SELECT plugin_id, enabled FROM plugin_state')}
    assert rows.get('hello_world') == 1 and rows.get('gone_one') == 0
    # counterproof: the leader follows nobody
    calls.clear()
    plugins._loaded_plugins['gone_one'] = object()
    with g.at('a') as ha:
        ha._follow_plugin_state()
    assert calls == []
