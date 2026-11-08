"""Taking a member out of a group, and the leader rules around it (#625 review).

Removing the old active after a failover used to leave it acting as active once it
came back: every member refused it with 401, which it read as "unreachable", and
an unreachable group changes nothing. Now the removal wants the member confirmed
as a standby (or the admin's word that it is shut down for good), keeps a tombstone
that every member holds, and a removed instance that hears 410 lets go and stays
passive. An active that every member refuses, or that sees the group under a newer
epoch without it, steps aside. A standby that missed the new active follows the
name its old source gives, once that instance confirms it. A promotion syncs
first. The state file is written only when something changed.

Runs on the in-process group of tests/test_ha_members.py.

MK Sep 2026
"""
import json
import logging
import time
import types

import pytest

from test_ha_members import (group, _built, _pair, _sync, _watch, _promote, _post, _send,  # noqa: F401
                             _asks, _pub, IDS, URLS, V2_ACTIVE, V2_STANDBY)
from test_ha_api import _admin, _audit, ADMIN_PW


def _refused(g, target, headers, method='GET', path='/api/ha/peer/status', body=b''):
    """The status a peer call gets, with the failure budget fresh: this file sends
    more refused calls from one address than the budget lets through."""
    import pegaprox.api.ha as ha_api
    ha_api._peer_failures.reset()
    return _send(g, target, headers, method, path, body).status_code


def _remove(g, admin, at, n, **extra):
    with g.at(at):
        return _post(admin, f"/api/ha/members/{IDS[n]}/remove",
                     dict({'confirm': 'REMOVE', 'user_password': ADMIN_PW}, **extra))


def _failover(g, seed):
    """a is down, b is promoted, c follows b and has synced."""
    admin = _built(g, seed, 'bc')
    g.down = {'a'}
    r = _promote(g, admin, 'b')
    assert r.status_code == 200, r.data
    assert 'not reached' in _audit('ha.promoted')[-1]['details']
    assert _watch(g, 'c') == 'source switched'
    assert _sync(g, admin, 'c') == 'applied'
    return admin


def _status(g, admin, n):
    with g.at(n):
        return admin.get('/api/ha/status').get_json()


def _row(status, n):
    return next(m for m in status['members'] if m['instance_id'] == IDS[n])


# --- the removal guard and the tombstones ------------------------------------------------

def test_the_dead_old_active_is_removed_only_on_the_admins_word_and_comes_back_passive(group, seed):
    g = group
    admin = _failover(g, seed)
    row = _row(_status(g, admin, 'b'), 'a')
    assert row['confirmed_standby'] is False and row['role_seen'] is None

    r = _remove(g, admin, 'b', 'a')
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_REMOVE_UNCONFIRMED'
    assert 'shut down' in r.get_json()['error']
    # said before the password is asked for, as for a full group
    with g.at('b'):
        r = _post(admin, f"/api/ha/members/{IDS['a']}/remove", {'confirm': 'REMOVE'})
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_REMOVE_UNCONFIRMED'
    assert IDS['a'] in g.members('b') and _audit('ha.member_removed') == []

    r = _remove(g, admin, 'b', 'a', shut_down=True)
    assert r.status_code == 200, r.data
    body = r.get_json()
    assert body['success'] is True and body['told'] is False
    assert [m['instance_id'] for m in body['members']] == [IDS['c']]
    details = _audit('ha.member_removed')[-1]['details']
    assert 'not told' in details and 'shut down for good' in details
    assert '1 of 1 other member(s) told' in details
    # c heard at once, not only with its next pull
    for n in 'bc':
        assert IDS['a'] not in g.members(n) and IDS['a'] in g.state(n)['tombstones'], n
    assert g.state('b')['tombstones'][IDS['a']]['public_key'] == _pub(g, 'a')

    # a comes back: it hears that it was removed and comes up passive, without a restart
    g.down = set()
    before = list(g.restarts)
    with g.at('a') as ha:
        assert ha.check_peer_at_boot() == 'removed'
        assert ha.role() == 'standby' and not ha.is_active() and ha.members() == []
    assert g.restarts == before
    status = _status(g, admin, 'a')
    assert status['removed']['epoch'] == 2 and status['removed']['by'] in (IDS['b'], IDS['c'])
    assert status['role'] == 'standby' and status['members'] == []
    assert _audit('ha.removed')
    # and stays so: nothing to watch, and no promotion of its own
    assert _watch(g, 'a') == 'idle'
    r = _promote(g, admin, 'a')
    assert r.status_code == 409 and 'removed' in r.get_json()['error']
    assert g.state('a')['role'] == 'standby'
    # the group goes on
    assert _watch(g, 'b') == 'ok' and _watch(g, 'c') == 'ok'
    assert [g.state(n)['role'] for n in 'bc'] == ['active', 'standby']


def test_the_core_refuses_an_unconfirmed_removal_too(group, seed):
    g = group
    _failover(g, seed)
    assert _watch(g, 'b') == 'ok'                  # c answers as a standby under 2
    with g.at('b') as ha:
        assert ha.member_confirmed(IDS['c']) is True and ha.member_confirmed(IDS['a']) is False
        with pytest.raises(ha.RemoveUnconfirmed):
            ha.remove_member(IDS['a'])
        assert IDS['a'] in {m['instance_id'] for m in ha.members()}
        rec = ha.remove_member(IDS['a'], shut_down=True)
        assert rec['instance_id'] == IDS['a']
        assert ha.tombstone(IDS['a'])['public_key'] == _pub(g, 'a')
        assert ha.tombstone(IDS['a'])['epoch'] == 2 and ha.tombstone(IDS['a'])['by'] == IDS['b']


def test_an_old_active_removed_while_it_runs_lets_go_at_its_next_look(group, seed):
    g = group
    admin = _failover(g, seed)
    assert _remove(g, admin, 'b', 'a', shut_down=True).status_code == 200
    g.down = set()
    assert _watch(g, 'a') == 'removed'
    assert ('a', 'removed from the group') in g.restarts
    assert g.state('a')['role'] == 'standby' and g.state('a')['removed']


def test_a_live_old_active_that_is_removed_is_told_and_goes_passive(group, seed):
    """c was promoted while a could not be reached; a is back and still active when c
    removes it. The removal notice comes from the instance the group follows, so a
    lets go even though it is active."""
    g = group
    admin = _built(g, seed, 'bc')
    g.down = {'a'}
    assert _promote(g, admin, 'c').status_code == 200
    g.down = set()
    assert g.state('a')['role'] == 'active'

    r = _remove(g, admin, 'c', 'a', shut_down=True)
    assert r.status_code == 200 and r.get_json()['told'] is True
    a = g.state('a')
    assert a['role'] == 'standby' and a['members'] == {} and a['removed']['by'] == IDS['c']
    assert ('a', 'removed from the group') in g.restarts
    # b followed a until now; it heard from c right away and follows c from its next look
    assert IDS['a'] not in g.members('b')
    assert _watch(g, 'b') == 'source switched' and _sync(g, admin, 'b') == 'applied'
    assert g.state('b')['source'] == IDS['c']


def test_a_removal_right_after_a_promotion_is_reported_as_it_happened(group, seed, monkeypatch):
    """Right after b's promotion c still follows a and has not seen b active. When c
    cannot confirm that b speaks for the group, it keeps the group, and the removal
    says 'not told' instead of 'told'."""
    g = group
    admin = _built(g, seed, 'bc')
    assert _promote(g, admin, 'b').status_code == 200
    assert g.state('c')['source'] == IDS['a']
    # c answered as a standby under epoch 1 at best, not under b's 2
    r = _remove(g, admin, 'b', 'c')
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_REMOVE_UNCONFIRMED'

    ha = g.ha
    real = ha._speaks_for_group
    monkeypatch.setattr(ha, '_speaks_for_group',
                        lambda pid, timeout=3: None if ha.STATE_FILE == g.files['c'] else real(pid, timeout))
    r = _remove(g, admin, 'b', 'c', shut_down=True)
    assert r.status_code == 200 and r.get_json()['told'] is False
    assert '(not told' in _audit('ha.member_removed')[-1]['details']
    assert g.state('c')['removed'] is None


def test_a_standby_removed_right_after_a_promotion_lets_go_once_the_new_active_confirms(group, seed):
    g = group
    admin = _built(g, seed, 'bc')
    assert _promote(g, admin, 'b').status_code == 200
    assert g.state('c')['source'] == IDS['a']
    r = _remove(g, admin, 'b', 'c', shut_down=True)
    assert r.status_code == 200 and r.get_json()['told'] is True
    assert '(told' in _audit('ha.member_removed')[-1]['details']
    c = g.state('c')
    assert c['members'] == {} and c['source'] is None and c['removed']['by'] == IDS['b']
    # it asked b first: an active under a newer epoch than its own
    assert ('c', 'b', 'GET', '/api/ha/peer/status') in g.calls
    # and the old active, b's standby now, dropped it at once
    assert IDS['c'] not in g.members('a') and IDS['c'] in g.state('a')['tombstones']


# --- replays after a removal ----------------------------------------------------------

def test_a_removed_member_replaying_what_it_saw_gets_nowhere(group, seed, monkeypatch):
    """d was a member long enough to see every other member's calls. After it is
    removed, none of them does anything anywhere: they were made for d, once, and
    d's own calls get 410."""
    g = group
    admin = _built(g, seed, 'bcd')
    for n in 'abcd':
        assert _watch(g, n) == 'ok'
    to_d = [s for s in g.sent if s[1] == 'd']
    # its signed calls; the pair call carried the code, which is spent
    from_d = [s for s in g.sent if s[0] == 'd' and s[3] != '/api/ha/peer/pair']
    assert to_d and from_d
    # nothing d saw carries a secret
    assert all(':' not in s[5][g.ha.PEER_HEADER] for s in to_d)

    assert _remove(g, admin, 'a', 'd').get_json()['told'] is True
    for frm, _to, method, path, body, headers in to_d:
        for target in 'abc':
            assert _refused(g, target, headers, method, path, body) == 401, (frm, target)
    for _frm, to, method, path, body, headers in from_d:
        for target in 'abc':
            assert _refused(g, target, headers, method, path, body) == 401, (to, target)

    # the three moves the review made with captured headers
    b_to_d = next(s[5] for s in to_d if s[0] == 'b')
    a_to_d = next(s[5] for s in to_d if s[0] == 'a')
    assert _refused(g, 'a', b_to_d, 'GET', '/api/ha/peer/snapshot') == 401
    removed = g.ha._wire_body({'removed': True})
    assert _refused(g, 'c', a_to_d, 'POST', '/api/ha/peer/unpaired', removed) == 401
    down = g.ha._wire_body({'epoch': 5})
    assert _refused(g, 'a', b_to_d, 'POST', '/api/ha/peer/step-down', down) == 401
    assert [g.state(n)['role'] for n in 'abc'] == ['active', 'standby', 'standby']
    assert g.members('c') == {IDS['a'], IDS['b']}

    # what d signs now is answered 410, everywhere
    with g.at('d') as ha:
        signer = ha._signer()
    for target in 'abc':
        headers = g.ha._auth_for(signer, IDS[target])('GET', '/api/ha/peer/status', b'')
        r = _send(g, target, headers)
        assert r.status_code == 410 and r.get_json()['code'] == 'HA_REMOVED'
        assert r.get_json()['epoch'] == 1


def test_a_removal_keeps_a_stale_member_list_from_taking_it_back(group, seed):
    """b was down while d was removed, so its list still names d. Promoting b syncs
    first, and the tombstone keeps d out; the old active, now b's standby, keeps its
    own tombstone whatever list it pulls."""
    g = group
    admin = _built(g, seed, 'bcd')
    g.down = {'b'}
    r = _remove(g, admin, 'a', 'd')
    assert r.status_code == 200 and '1 of 2 other member(s) told' in _audit('ha.member_removed')[-1]['details']
    g.down = set()
    assert IDS['d'] in g.members('b')

    assert _promote(g, admin, 'b').status_code == 200
    b = g.state('b')
    assert b['role'] == 'active' and IDS['d'] not in b['members'] and IDS['d'] in b['tombstones']
    assert _sync(g, admin, 'a') == 'applied'
    assert IDS['d'] not in g.members('a') and IDS['d'] in g.state('a')['tombstones']
    with g.at('d') as ha:
        signer = ha._signer()
    for target in 'abc':
        headers = g.ha._auth_for(signer, IDS[target])('GET', '/api/ha/peer/status', b'')
        assert _send(g, target, headers).status_code == 410, target


def test_a_removal_the_new_active_missed_reaches_it_from_a_standby(group, seed):
    """b could not hear from a while a removed d, and was promoted once a had failed. d
    stayed a member at b with every right (the snapshots, a step-down), and nothing
    ever carried the tombstone back to an active. c heard; it hands the tombstone to b
    with its first pull from it."""
    g = group
    admin = _built(g, seed, 'bcd')
    for n in 'abcd':
        assert _watch(g, n) == 'ok'
    g.cut = {frozenset('ab')}
    r = _remove(g, admin, 'a', 'd')
    assert r.status_code == 200 and r.get_json()['told'] is True
    assert IDS['d'] in g.members('b') and g.state('b')['tombstones'] == {}
    g.down = {'a'}
    assert _promote(g, admin, 'b').status_code == 200
    with g.at('d') as ha:
        signer = ha._signer()

    def d_asks_b():
        return _send(g, 'b', g.ha._auth_for(signer, IDS['b'])('GET', '/api/ha/peer/status', b''))
    assert d_asks_b().status_code == 200

    assert _watch(g, 'c') == 'source switched'
    assert _sync(g, admin, 'c') == 'applied'
    b = g.state('b')
    assert IDS['d'] not in b['members'] and b['tombstones'][IDS['d']]['by'] == IDS['a']
    r = d_asks_b()
    assert r.status_code == 410 and r.get_json()['code'] == 'HA_REMOVED'
    assert 'holds a tombstone' in _audit('ha.member_removed')[-1]['details']
    # and b hands it out from now on
    with g.at('b') as ha:
        assert [t['instance_id'] for t in ha.snapshot_meta()['tombstones']] == [IDS['d']]
    assert _sync(g, admin, 'c') == 'applied'


def test_a_tombstone_from_a_member_takes_no_live_standby_out(group, seed):
    """A member can hand the active a tombstone, but not for a standby that answers
    under the active's epoch, nor one that names credentials other than the member's."""
    g = group
    _built(g, seed, 'bcd')
    assert _watch(g, 'a') == 'ok'
    ha = g.ha

    def tomb(n, key):
        return {'instance_id': IDS[n], 'epoch': 1, 'at': '2026-09-30T12:00:00+00:00',
                'by': IDS['a'], 'public_key': key, 'secret_hash': ''}
    path = '/api/ha/peer/tombstones'
    body = ha._wire_body({'tombstones': [tomb('c', _pub(g, 'c')), tomb('d', _pub(g, 'b'))]})
    r = _send(g, 'a', g.signed('b', 'a', 'POST', path, body), 'POST', path, body)
    assert r.status_code == 200 and r.get_json()['taken'] == []
    assert g.members('a') == {IDS[n] for n in 'bcd'} and g.state('a')['tombstones'] == {}
    # d does not answer now: it is not confirmed, but the key still has to be its own
    st = g.state('a')
    st['members'][IDS['d']]['epoch_seen'] = 0
    g.write('a', st)
    g.down = {'d'}
    r = _send(g, 'a', g.signed('b', 'a', 'POST', path, body), 'POST', path, body)
    assert r.get_json()['taken'] == [] and IDS['d'] in g.members('a')
    # a standby takes nothing that way
    body = ha._wire_body({'tombstones': [tomb('d', _pub(g, 'd'))]})
    r = _send(g, 'b', g.signed('c', 'b', 'POST', path, body), 'POST', path, body)
    assert r.get_json()['taken'] == [] and IDS['d'] in g.members('b')


def test_a_member_list_never_brings_a_removed_member_back(group, seed):
    g = group
    _built(g, seed, 'bc', sync=False)
    ha = g.ha
    with g.at('a') as h:
        stale = h.snapshot_meta()['members']
    with g.at('b') as h:
        st = h._load()
        tombs = {IDS['c']: {'epoch': 1, 'at': '2026-09-30T12:00:00+00:00', 'by': IDS['a'],
                            'public_key': _pub(g, 'c'), 'secret_hash': ''}}
        assert IDS['c'] not in ha._merged_members(st, IDS['a'], stale, tombs)
        # the same id paired again comes with a new key and is a member again
        fresh = h._public_of(h._private_key(h._new_signing_key()))
        again = [dict(e, public_key=fresh) if e['instance_id'] == IDS['c'] else e for e in stale]
        assert IDS['c'] in ha._merged_members(st, IDS['a'], again, tombs)


# --- stepping aside --------------------------------------------------------------------

def _forget(g, n, who):
    """n drops `who` from its list by hand, as a release without tombstones did."""
    st = g.state(n)
    st['members'].pop(IDS[who], None)
    if st.get('source') == IDS[who]:
        st['source'] = None
    g.write(n, st)


def test_an_active_that_every_member_refuses_steps_aside(group, seed):
    import pegaprox.api.ha as ha_api
    g = group
    _built(g, seed, 'bc')
    _forget(g, 'b', 'a')
    _forget(g, 'c', 'a')
    # one refuses, one does not answer: that proves nothing, a stays active
    g.down = {'c'}
    assert _watch(g, 'a') == 'unreachable'
    assert g.state('a')['role'] == 'active'
    g.down = set()
    ha_api._peer_failures.reset()
    assert _watch(g, 'a') == 'stepped aside'
    a = g.state('a')
    assert a['role'] == 'standby' and a['source'] is None and a['epoch'] == 1
    assert 'every member (2) refused' in a['sync']['last_error']
    assert ('a', 'stepped aside to standby') in g.restarts
    assert 'refused' in _audit('ha.stepped_aside')[-1]['details']


def test_another_instance_at_a_members_address_is_no_refusal(group, seed):
    """b's host was set up anew and answers at b's address as a fresh standalone. Its
    401 is not b refusing a: the one standby of a pair must not make its active step
    aside by being reinstalled."""
    g = group
    _built(g, seed, 'b')
    g.write('b', {'role': 'standalone', 'epoch': 0, 'instance_id': IDS['e'], 'interval': 30,
                  'pairing': None, 'sync': {}})
    assert _watch(g, 'a') == 'unreachable'
    a = g.state('a')
    assert a['role'] == 'active' and 'Another instance' in a['members'][IDS['b']]['last_error']
    assert not [r for r in g.restarts if r[0] == 'a']
    # the member itself refusing is a refusal
    g.write('b', {'role': 'standalone', 'epoch': 0, 'instance_id': IDS['b'], 'interval': 30,
                  'pairing': None, 'sync': {}})
    assert _watch(g, 'a') == 'stepped aside'


def test_a_standby_under_our_epoch_never_demotes_the_active(group, seed):
    g = group
    _built(g, seed, 'bc')
    for _ in range(3):
        assert _watch(g, 'a') == 'ok'
    assert g.state('a')['role'] == 'active' and not [r for r in g.restarts if r[0] == 'a']


def test_an_old_active_that_the_group_moved_on_from_steps_aside(group, seed):
    """a is back after c's promotion but cannot reach c; b follows c under epoch 2 and
    says so. a steps aside instead of acting on the old configuration, and follows c
    once it can reach it."""
    g = group
    admin = _built(g, seed, 'bc')
    g.down = {'a'}
    assert _promote(g, admin, 'c').status_code == 200
    assert _watch(g, 'b') == 'source switched' and _sync(g, admin, 'b') == 'applied'
    g.down, g.cut = set(), {frozenset('ac')}

    with g.at('a') as ha:
        assert ha.check_peer_at_boot() == 'stepped aside'
        assert ha.role() == 'standby' and ha.epoch() == 2 and ha.source_id() is None
    assert 'reports epoch 2' in g.state('a')['sync']['last_error']
    assert _watch(g, 'a') == 'no active member'

    g.cut = set()
    assert _watch(g, 'a') == 'source switched'
    assert _sync(g, admin, 'a') == 'applied' and g.state('a')['source'] == IDS['c']
    assert [g.state(n)['role'] for n in 'abc'] == ['standby', 'standby', 'active']


def test_an_old_active_running_when_it_sees_the_newer_epoch_steps_aside(group, seed):
    g = group
    admin = _built(g, seed, 'bc')
    g.down = {'a'}
    assert _promote(g, admin, 'c').status_code == 200
    assert _watch(g, 'b') == 'source switched' and _sync(g, admin, 'b') == 'applied'
    # c is gone for good; a comes back on its old configuration
    g.down = {'c'}
    assert _watch(g, 'a') == 'stepped aside'
    assert ('a', 'stepped aside to standby') in g.restarts
    assert g.state('a')['role'] == 'standby' and g.state('a')['epoch'] == 2
    # nobody acts on the configuration from before c's promotion
    assert _watch(g, 'b') == 'no active member' and _watch(g, 'a') == 'no active member'


# --- the epoch ceiling ----------------------------------------------------------------------

def test_no_promotion_goes_past_the_epoch_every_member_reads(group, seed):
    """c, a mere standby, tells the active to step down to the top epoch. a follows its
    word (members are trusted with that), but the next promotion no longer makes an
    epoch nobody reads: that left two actives that never settle. It is refused, and
    unpairing, which the admin is sent to, starts the count anew."""
    g = group
    admin = _built(g, seed, 'bc')
    ha = g.ha
    path = '/api/ha/peer/step-down'
    for epoch, status in ((ha.EPOCH_MAX + 1, 400), (ha.EPOCH_MAX, 200)):
        body = ha._wire_body({'epoch': epoch})
        assert _send(g, 'a', g.signed('c', 'a', 'POST', path, body), 'POST', path, body).status_code == status
    a = g.state('a')
    assert a['role'] == 'standby' and a['epoch'] == ha.EPOCH_MAX and a['source'] == IDS['c']

    with g.at('a'):
        r = _post(admin, '/api/ha/promote', {'confirm': 'PROMOTE', 'user_password': ADMIN_PW,
                                             'force': True})
    assert r.status_code == 409 and 'highest epoch' in r.get_json()['error']
    assert g.state('a')['role'] == 'standby' and g.state('a')['epoch'] == ha.EPOCH_MAX
    assert all(g.state(n)['epoch'] <= ha.EPOCH_MAX for n in 'abc')

    with g.at('a'):
        r = _post(admin, '/api/ha/unpair', {'confirm': 'UNPAIR', 'user_password': ADMIN_PW})
    assert r.status_code == 200
    assert g.state('a')['role'] == 'standalone' and g.state('a')['epoch'] == 0


def test_an_active_at_an_epoch_nobody_reads_takes_no_standby(group, seed):
    """A state file an earlier build wrote past the ceiling: the standby refuses the
    answer, and the active must not keep it in its member list either."""
    g = group
    admin = _built(g, seed, 'b', sync=False)
    st = g.state('a')
    st['epoch'] = 2 ** 31
    g.write('a', st)
    with g.at('a'):
        r = _post(admin, '/api/ha/pairing-code', {'url': URLS['a'], 'user_password': ADMIN_PW})
        code = r.get_json()['code']
    with g.at('c'):
        r = _post(admin, '/api/ha/join', {'code': code, 'own_url': URLS['c'], 'confirm': True,
                                          'user_password': ADMIN_PW})
    assert r.status_code == 502 and 'epoch' in r.get_json()['error']
    assert g.members('a') == {IDS['b']} and g.state('c')['role'] == 'standalone'


def test_a_snapshot_under_an_epoch_nobody_reads_is_not_taken(group, seed, monkeypatch):
    g = group
    admin = _built(g, seed, 'b', sync=False)
    ha = g.ha
    real = ha.snapshot_meta
    monkeypatch.setattr(ha, 'snapshot_meta', lambda: dict(real(), epoch=2 ** 31))
    assert _sync(g, admin, 'b') == 'failed'
    assert 'epoch' in g.state('b')['sync']['last_error'] and g.state('b')['epoch'] == 1


# --- a standby that missed the new active ---------------------------------------------------

def _stranded(g, seed):
    """b missed c joining; a died, c was promoted, a came back and follows c. b's
    list names only a."""
    admin = _built(g, seed, 'b')
    g.down = {'b'}
    _pair(g, admin, 'c')
    assert _sync(g, admin, 'c') == 'applied'
    g.down = {'a', 'b'}
    assert _promote(g, admin, 'c').status_code == 200
    g.down = {'b'}
    with g.at('a') as ha:
        assert ha.check_peer_at_boot() == 'stepped down'
    assert _sync(g, admin, 'a') == 'applied'
    g.down = set()
    assert g.members('b') == {IDS['a']}
    return admin


def test_a_stranded_standby_follows_the_active_its_source_names(group, seed):
    g = group
    admin = _stranded(g, seed)
    assert _watch(g, 'b') == 'no active member'
    assert _sync(g, admin, 'b') == 'source switched'
    b = g.state('b')
    assert b['source'] == IDS['c'] and b['members'][IDS['c']]['public_key'] == _pub(g, 'c')
    assert b['members'][IDS['c']]['role_seen'] == 'active'
    assert 'following' in _audit('ha.follow_hint')[-1]['details']
    assert _sync(g, admin, 'b') == 'applied'
    b = g.state('b')
    assert b['epoch'] == 2 and set(b['members']) == {IDS['a'], IDS['c']}
    assert _watch(g, 'b') == 'ok' and _watch(g, 'c') == 'ok'


def test_a_hint_is_taken_only_once_the_named_active_confirms_it(group, seed, monkeypatch):
    g = group
    admin = _stranded(g, seed)
    ha = g.ha
    # the named instance does not answer
    g.down = {'c'}
    assert _sync(g, admin, 'b') == 'failed'
    assert g.state('b')['source'] == IDS['a'] and IDS['c'] not in g.members('b')
    g.down = set()
    # it answers, but not under the epoch the hint names
    real = ha.follow_hint
    monkeypatch.setattr(ha, 'follow_hint', lambda: dict(real(), epoch=3) if real() else None)
    assert _sync(g, admin, 'b') == 'failed'
    assert g.state('b')['source'] == IDS['a']
    monkeypatch.setattr(ha, 'follow_hint', real)
    # b holds a tombstone for it
    st = g.state('b')
    st['tombstones'] = {IDS['c']: {'epoch': 2, 'at': '2026-09-30T12:00:00+00:00', 'by': IDS['a'],
                                   'public_key': _pub(g, 'c'), 'secret_hash': ''}}
    g.write('b', st)
    assert _sync(g, admin, 'b') == 'failed'
    assert g.state('b')['source'] == IDS['a'] and IDS['c'] not in g.members('b')
    assert _audit('ha.follow_hint') == []


def test_a_standby_names_only_an_active_it_has_seen(group, seed):
    g = group
    _built(g, seed, 'bc')
    with g.at('b') as ha:
        hint = ha.follow_hint()
    assert hint == {'instance_id': IDS['a'], 'url': URLS['a'], 'fingerprint': '',
                    'public_key': _pub(g, 'a'), 'epoch': 1}
    with g.at('a') as ha:
        assert ha.follow_hint() is None               # an active names nobody
    st = g.state('b')
    st['members'][IDS['a']]['role_seen'] = 'standby'
    g.write('b', st)
    with g.at('b') as ha:
        assert ha.follow_hint() is None


# --- a promotion syncs first ----------------------------------------------------------------

def test_a_promotion_is_refused_when_its_source_answers_and_the_sync_fails(group, seed, monkeypatch):
    g = group
    admin = _built(g, seed, 'bc')
    ha = g.ha
    real = ha.apply_snapshot

    def refused(snap):
        if ha.STATE_FILE == g.files['b']:
            raise ha.HaError('The field key changed on the active instance (key rotation?) - pair again')
        return real(snap)
    monkeypatch.setattr(ha, 'apply_snapshot', refused)
    # no etag: the pull is a full one, not a 304
    st = g.state('b')
    st['sync'] = {}
    g.write('b', st)
    monkeypatch.setattr(ha, '_etag_checked', False)

    r = _promote(g, admin, 'b')
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_PROMOTE_SYNC'
    assert 'field key changed' in r.get_json()['error'] and 'force' in r.get_json()['error']
    assert g.state('b')['role'] == 'standby' and g.state('a')['role'] == 'active'
    assert _audit('ha.promoted') == []

    with g.at('b'):
        r = _post(admin, '/api/ha/promote', {'confirm': 'PROMOTE', 'user_password': ADMIN_PW,
                                             'force': True})
    assert r.status_code == 200 and r.get_json()['epoch'] == 2
    assert 'without the sync first (force)' in _audit('ha.promoted')[-1]['details']
    assert g.state('a')['role'] == 'standby'


def test_a_promotion_syncs_before_it_promotes(group, seed):
    g = group
    admin = _built(g, seed, 'b')
    _pair(g, admin, 'c')
    assert g.members('b') == {IDS['a']}              # b has not pulled since c joined
    mark = len(g.calls)
    assert _promote(g, admin, 'b').status_code == 200
    calls = [c for c in g.calls[mark:] if c[0] == 'b']
    assert calls[0] == ('b', 'a', 'GET', '/api/ha/peer/snapshot')
    assert ('b', 'a', 'POST', '/api/ha/peer/step-down') in calls
    # so b promotes with the member list of now, and c follows it
    assert g.members('b') == {IDS['a'], IDS['c']}
    assert _watch(g, 'c') == 'source switched' and _sync(g, admin, 'c') == 'applied'


# --- the group mark --------------------------------------------------------------------

def test_no_further_standby_until_every_member_answered_as_a_group_member(group, seed, monkeypatch):
    """A pair from before the groups: until b answers with the group mark, a hands out
    no code - on the pair release b refuses every member but a, and a third one would
    be stranded the day b is promoted."""
    g = group
    admin = _admin(g.api, seed)
    g.write('a', V2_ACTIVE)
    g.write('b', V2_STANDBY)
    ha = g.ha

    def code():
        with g.at('a'):
            return _post(admin, '/api/ha/pairing-code', {'url': URLS['a'], 'user_password': ADMIN_PW})
    r = code()
    assert r.status_code == 409 and URLS['b'] in r.get_json()['error']

    # b on the pair release: a status without the mark
    real = ha._peer_call

    def pair_release(method, base_url, fingerprint, path, **kw):
        if path == '/api/ha/peer/status':
            body = {'instance_id': IDS['b'], 'role': 'standby', 'epoch': 1}
            return types.SimpleNamespace(status_code=200, json=lambda: body, headers={})
        return real(method, base_url, fingerprint, path, **kw)
    monkeypatch.setattr(ha, '_peer_call', pair_release)
    assert _watch(g, 'a') == 'ok'
    assert code().status_code == 409

    monkeypatch.setattr(ha, '_peer_call', real)
    assert _watch(g, 'a') == 'ok'
    assert g.state('a')['members'][IDS['b']]['group_seen'] is True
    r = code()
    assert r.status_code == 200, r.data


# --- writes and timeouts ----------------------------------------------------------------

def test_a_winner_whose_state_cannot_be_written_still_tells_the_loser(group, seed, monkeypatch):
    """c holds the newer epoch but its disk is full, and a cannot reach c. The notes
    about the answers fail; the step-down notice to a needs no write of c's."""
    g = group
    admin = _built(g, seed, 'bc')
    g.down = {'a'}
    assert _promote(g, admin, 'c').status_code == 200
    g.down = set()
    ha = g.ha
    real_write = ha._write_locked

    def write(st):
        if ha.STATE_FILE == g.files['c']:
            raise OSError(28, 'No space left on device')
        return real_write(st)
    monkeypatch.setattr(ha, '_write_locked', write)
    real_call = g.call

    def call(method, base_url, *a, **kw):
        if g.name() == 'a' and g.by_url[base_url.rstrip('/')] == 'c':
            raise ha.PeerUnreachable('Cannot reach the peer: ConnectTimeout')
        return real_call(method, base_url, *a, **kw)
    monkeypatch.setattr(ha, '_peer_call', call)

    assert _watch(g, 'c') == 'told peer to step down'
    a = g.state('a')
    assert a['role'] == 'standby' and a['source'] == IDS['c'] and a['epoch'] == 2


class _Writes:
    def __init__(self, g, monkeypatch):
        self.paths = []
        real = g.ha._write_locked

        def spy(st):
            self.paths.append(g.ha.STATE_FILE)
            return real(st)
        monkeypatch.setattr(g.ha, '_write_locked', spy)

    def of(self, path):
        return self.paths.count(path)


def _pass(ha):
    """The body of ha._loop for one pass, without the sleep."""
    r = ha.role()
    if r != ha.ROLE_STANDALONE and ha._load().get('members'):
        ha.watch_once()
    if r == ha.ROLE_STANDBY and ha.is_standby() and ha.peer():
        ha.pull_once()


def test_a_pass_writes_the_state_file_only_for_what_changed(group, seed, monkeypatch):
    g = group
    admin = _built(g, seed, 'bc')
    assert _sync(g, admin, 'b') == 'unchanged'
    with g.at('a') as ha:
        _pass(ha)
    with g.at('b') as ha:
        _pass(ha)
    writes = _Writes(g, monkeypatch)
    time.sleep(1.1)                      # a new second, so last_contact does change
    with g.at('a') as ha:
        _pass(ha)
    with g.at('b') as ha:
        _pass(ha)
    assert writes.of(g.files['a']) <= 1
    # the look at the group, and the 304 with the source's contact in the same write
    assert writes.of(g.files['b']) <= 2

    # everybody else down: the second pass notes the same errors and writes no more
    g.down = {'a', 'c'}
    with g.at('b') as ha:
        ha.watch_once()
    before = open(g.files['b'], 'rb').read()
    writes.paths.clear()
    with g.at('b') as ha:
        ha.watch_once()
    assert writes.of(g.files['b']) == 0 and open(g.files['b'], 'rb').read() == before


def test_a_pass_whose_watch_missed_the_source_pulls_with_a_short_timeout(group, seed, monkeypatch):
    g = group
    _built(g, seed, 'bc')
    ha = g.ha

    class _Stop(BaseException):
        pass

    def run_one_pass():
        naps, seen = [], []

        def sleep(seconds):
            naps.append(seconds)
            if len(naps) == 2:
                raise _Stop()
        monkeypatch.setattr(ha, 'time', types.SimpleNamespace(time=time.time, monotonic=time.monotonic,
                                                                sleep=sleep))
        monkeypatch.setattr(ha, 'pull_once', lambda timeout=None: seen.append(timeout))
        with g.at('b'):
            with pytest.raises(_Stop):
                ha._loop()
        return seen

    g.down = {'a'}
    assert run_one_pass() == [ha.PULL_TIMEOUT_UNREACHABLE]
    g.down = set()
    seen = run_one_pass()
    # what is left of the 30 s interval, within the floor and the ceiling
    assert len(seen) == 1 and ha.PULL_TIMEOUT_FLOOR <= seen[0] <= 30


def test_a_removal_asks_the_member_itself_before_calling_it_unconfirmed(group, seed):
    """(#625 group live test) Right after a failover the active's last look at a member
    predates the new epoch, so a standby that follows it already still counted as
    unconfirmed and the admin was sent to "shut down for good" for nothing. The route
    asks that member itself first."""
    g = group
    admin = _failover(g, seed)
    with g.at('b') as ha:
        assert ha.member_confirmed(IDS['c']) is False       # no look since the promotion
    r = _remove(g, admin, 'b', 'c')
    assert r.status_code == 200, r.data
    with g.at('b') as ha:
        assert IDS['c'] not in {m['instance_id'] for m in ha.members()}


def test_a_member_that_does_not_answer_the_check_stays_unconfirmed(group, seed):
    g = group
    admin = _failover(g, seed)
    g.down = {'a', 'c'}
    r = _remove(g, admin, 'b', 'c')
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_REMOVE_UNCONFIRMED', r.data
