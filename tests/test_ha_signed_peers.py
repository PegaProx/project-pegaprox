"""Signed peer calls (#625 review): every member signs each call with its own Ed25519
key, for one receiver, one moment and once.

Before, every member sent '<id>:<secret>' to every other member on every tick, and
a removed member could replay what it had been sent: pull the active's snapshot,
make the standbys drop the group, make the active step down. A signed call is
worth nothing at another member, a second time, or two minutes later.

A group paired before the keys still talks: a member that has only the hash of a
secret on record is taken with that secret until it has published a key, and an
instance on this release sends its key along until the other side says it holds it.
Then the secret is refused and dropped.

Runs on the in-process group of tests/test_ha_members.py.

MK Sep 2026
"""
import base64
import json
import secrets
import time
import types

import pytest

from test_ha_members import (group, _built, _pair, _sync, _watch, _send, _asks, _pub,  # noqa: F401
                             _promote, _post, IDS, URLS, V2_ACTIVE, V2_STANDBY,
                             V2_ACTIVE_PRESENTS, V2_STANDBY_PRESENTS)
from test_ha_api import _admin, _audit, ADMIN_PW

STATUS = '/api/ha/peer/status'


def _sign_as(g, n, to, method='GET', path=STATUS, body=b'', ts=None, nonce=None, key_of=None):
    """Headers of a call `n` signs for `to` by hand, with the time and nonce given.
    key_of signs with another instance's key under n's id."""
    ha = g.ha
    with g.at(key_of or n):
        private = ha._private_key(ha._load()['signing_key'])
    ts = str(int(time.time()) if ts is None else ts)
    nonce = nonce or secrets.token_urlsafe(18)
    sig = private.sign(ha._to_sign(method, path, body, ts, nonce, IDS[to], IDS[n]))
    return {ha.PEER_HEADER: IDS[n], ha.PEER_TS_HEADER: ts, ha.PEER_NONCE_HEADER: nonce,
            ha.PEER_SIG_HEADER: base64.b64encode(sig).decode()}


# --- the signature --------------------------------------------------------------------

def test_a_signed_call_is_taken_and_says_the_key_is_known(group, seed):
    g = group
    _built(g, seed, 'bc')
    r = _send(g, 'a', _sign_as(g, 'b', 'a'))
    assert r.status_code == 200 and r.get_json()['role'] == 'active'
    assert r.headers.get(g.ha.PEER_KEYED_HEADER) == '1'
    # no secret travels in a group paired on this release
    for (_frm, _to, _m, _p, _b, headers) in g.sent:
        assert ':' not in headers.get(g.ha.PEER_HEADER, ''), headers
        assert g.ha.PEER_KEY_HEADER not in headers


def test_a_call_signed_for_another_member_is_refused(group, seed):
    """A standby holds calls made for it; it cannot pass them on to anybody else."""
    g = group
    _built(g, seed, 'bc')
    for_c = _sign_as(g, 'b', 'c')
    assert _send(g, 'a', for_c).status_code == 401
    # c itself takes it, once
    assert _send(g, 'c', for_c).status_code == 200


def test_a_replayed_call_is_refused(group, seed):
    g = group
    _built(g, seed, 'bc')
    headers = _sign_as(g, 'b', 'a')
    assert _send(g, 'a', headers).status_code == 200
    assert _send(g, 'a', headers).status_code == 401
    # the same nonce under a fresh signature is still the same call
    again = _sign_as(g, 'b', 'a', nonce=headers[g.ha.PEER_NONCE_HEADER])
    assert _send(g, 'a', again).status_code == 401
    # a real call from b goes through: the nonces are fresh every time
    assert _asks(g, 'b', 'a') == 200 and _asks(g, 'b', 'a') == 200


@pytest.mark.parametrize('skew,status', [(-121, 401), (121, 401), (-100, 200), (100, 200)])
def test_a_call_from_outside_the_window_is_refused(group, seed, monkeypatch, skew, status):
    g = group
    _built(g, seed, 'bc')
    # the clock stands still on a whole second: signed late in a second, 121 s ahead
    # was 119.9 s ahead by the time it was checked, and the call went through
    now = float(int(time.time()))
    monkeypatch.setattr(g.ha, 'time', types.SimpleNamespace(time=lambda: now, monotonic=time.monotonic))
    headers = _sign_as(g, 'b', 'a', ts=int(now) + skew)
    assert _send(g, 'a', headers).status_code == status


def test_a_captured_call_is_worthless_two_minutes_later(group, seed, monkeypatch):
    g = group
    _built(g, seed, 'bc')
    headers = _sign_as(g, 'b', 'a')
    later = time.time() + g.ha.SIGNATURE_WINDOW + 1
    monkeypatch.setattr(g.ha, 'time', types.SimpleNamespace(time=lambda: later,
                                                            monotonic=time.monotonic))
    assert _send(g, 'a', headers).status_code == 401


def test_a_changed_body_path_or_method_is_refused(group, seed):
    g = group
    _built(g, seed, 'bc')
    ha = g.ha
    body = ha._wire_body({'epoch': 1})
    headers = _sign_as(g, 'a', 'b', 'POST', '/api/ha/peer/step-down', body)
    for method, path, sent in (
            ('POST', '/api/ha/peer/step-down', ha._wire_body({'epoch': 9})),     # the body
            ('POST', '/api/ha/peer/unpaired', body),                             # the path
            ('POST', '/api/ha/peer/step-down?x=1', body),                        # the query
            ('POST', '/api/ha/peer/step-down', body + b' '),                     # one byte
            ('GET', '/api/ha/peer/status', b'')):                                # the method
        r = _send(g, 'b', headers, method, path, sent)
        assert r.status_code == 401, (method, path, sent)
    assert g.state('b')['role'] == 'standby' and g.members('b') == {IDS['a'], IDS['c']}
    # untouched, it is taken (and changes nothing on a standby)
    r = _send(g, 'b', headers, 'POST', '/api/ha/peer/step-down', body)
    assert r.status_code == 200 and r.get_json()['stepped_down'] is False


def test_an_unknown_sender_or_a_wrong_key_is_refused(group, seed):
    g = group
    admin = _built(g, seed, 'bc')
    # e is paired elsewhere (with d), so it has a key of its own
    _pair(g, admin, 'e', active='d')
    assert _send(g, 'a', _sign_as(g, 'e', 'a')).status_code == 401
    # b's id under e's key
    assert _send(g, 'a', _sign_as(g, 'b', 'a', key_of='e')).status_code == 401
    # a signature with the headers cut short
    headers = _sign_as(g, 'b', 'a')
    for name in (g.ha.PEER_TS_HEADER, g.ha.PEER_NONCE_HEADER, g.ha.PEER_SIG_HEADER):
        cut = {k: v for k, v in headers.items() if k != name}
        assert _send(g, 'a', cut).status_code == 401, name


def test_the_old_secret_of_a_member_with_a_key_is_refused(group, seed):
    """Once a member has a key on record, only its signed calls count: its old secret,
    which every other member has seen, is worth nothing."""
    g = group
    admin = _admin(g.api, seed)
    g.write('a', V2_ACTIVE)
    g.write('b', V2_STANDBY)
    assert _asks(g, {g.ha.PEER_HEADER: f"{IDS['b']}:{V2_STANDBY_PRESENTS}"}, 'a') == 200
    assert _sync(g, admin, 'b') == 'applied'
    assert _watch(g, 'a') == 'ok'
    assert _asks(g, {g.ha.PEER_HEADER: f"{IDS['b']}:{V2_STANDBY_PRESENTS}"}, 'a') == 401
    assert _asks(g, {g.ha.PEER_HEADER: f"{IDS['a']}:{V2_ACTIVE_PRESENTS}"}, 'b') == 401
    # even with a signature by the right key alongside: the secret alone is refused,
    # the signature is what counts
    assert _send(g, 'a', dict(_sign_as(g, 'b', 'a'),
                              **{g.ha.PEER_HEADER: f"{IDS['b']}:{V2_STANDBY_PRESENTS}"})).status_code == 200


def test_a_body_over_the_cap_is_refused_before_it_is_read(group, seed):
    g = group
    _built(g, seed, 'bc')
    body = b'{"epoch":1,"pad":"' + b'x' * (70 * 1024) + b'"}'
    headers = _sign_as(g, 'b', 'a', 'POST', '/api/ha/peer/step-down', body)
    assert _send(g, 'a', headers, 'POST', '/api/ha/peer/step-down', body).status_code == 401


def test_the_allow_list_lets_a_signed_member_through_once(group, seed, monkeypatch):
    """The IP allow list asks who the caller is before the route does: the nonce must
    count once for both, and a bad signature is counted like a bad header."""
    import pegaprox.api.settings as st
    import pegaprox.api.ha as ha_api
    g = group
    _built(g, seed, 'bc')
    monkeypatch.setattr(st, '_ip_whitelist_enabled', True)
    monkeypatch.setattr(st, '_ip_whitelist', {'10.20.0.0/24'})
    monkeypatch.setattr(st, '_ip_blacklist', set())

    def from_outside(headers):
        with g.at('a'):
            return g.client.get(STATUS, base_url='http://localhost',
                                headers=dict(headers, **{'X-Requested-With': 'XMLHttpRequest'}),
                                environ_base={'REMOTE_ADDR': '203.0.113.50'})
    def failures():
        return len(ha_api._peer_failures._hits.get('203.0.113.50', ()))
    ha_api._peer_failures.reset()
    r = from_outside(_sign_as(g, 'b', 'a'))
    assert r.status_code == 200, r.data
    assert failures() == 0
    bad = dict(_sign_as(g, 'b', 'a'), **{g.ha.PEER_SIG_HEADER: base64.b64encode(b'x' * 64).decode()})
    r = from_outside(bad)
    assert r.status_code == 403 and r.get_json()['error'] == 'Access denied'
    assert failures() == 1
    # a replay is refused at the list, as a stranger would be
    headers = _sign_as(g, 'b', 'a')
    assert from_outside(headers).status_code == 200
    assert from_outside(headers).status_code == 403
    assert failures() == 2


def test_the_verdict_belongs_to_the_request_not_to_the_app_context(group, seed):
    """Two requests served in one app context, as the test client serves a request made
    from inside a route: the second is checked on its own. The verdict sat on flask.g,
    and the second got the first one's."""
    g = group
    _built(g, seed, 'bc')
    with g.at('a'), g.api.app.app_context():
        assert _send(g, 'a', _sign_as(g, 'b', 'a')).status_code == 200
        assert _send(g, 'a', {}).status_code == 401


def _unsigned(g, monkeypatch, path, to=None):
    """Calls to `path` (to the member `to`, or to all) go out without any peer
    credential."""
    real = g.ha._peer_call

    def call(method, base_url, fingerprint, p, json_body=None, auth=None, **kw):
        if p == path and to in (None, g.by_url[base_url.rstrip('/')]):
            auth = None
        return real(method, base_url, fingerprint, p, json_body=json_body, auth=auth, **kw)
    monkeypatch.setattr(g.ha, '_peer_call', call)


def test_the_notices_of_a_promotion_are_checked_at_every_receiver(group, seed, monkeypatch):
    """The promotion pulls from a with a signed call first; the step-down notices after
    it carry nothing. Every receiver refuses them, a stays active."""
    g = group
    admin = _built(g, seed, 'bcd')
    _unsigned(g, monkeypatch, '/api/ha/peer/step-down')
    assert _promote(g, admin, 'b').status_code == 200
    assert g.state('a')['role'] == 'active' and g.state('a')['epoch'] == 1
    details = _audit('ha.promoted')[-1]['details']
    assert 'not reached' in details and '0 of 2 other member(s) told' in details


@pytest.mark.parametrize('path,to', [('/api/ha/peer/member-removed', 'c'),
                                     ('/api/ha/peer/unpaired', 'd')])
def test_the_notices_of_a_removal_are_checked_at_every_receiver(group, seed, monkeypatch, path, to):
    """The first notice of the removal goes to b, signed. The one to `to` carries
    nothing and changes nothing there."""
    g = group
    admin = _built(g, seed, 'bcd')
    _unsigned(g, monkeypatch, path, to)
    with g.at('a'):
        r = _post(admin, f"/api/ha/members/{IDS['d']}/remove",
                  {'confirm': 'REMOVE', 'user_password': ADMIN_PW})
    assert r.status_code == 200, r.data
    assert IDS['d'] not in g.members('b') and IDS['d'] in g.state('b')['tombstones']
    if to == 'c':
        assert IDS['d'] in g.members('c') and g.state('c')['tombstones'] == {}
        assert '1 of 2 other member(s) told' in _audit('ha.member_removed')[-1]['details']
    else:
        assert r.get_json()['told'] is False
        d = g.state('d')
        assert d['removed'] is None and IDS['a'] in d['members'] and d['source'] == IDS['a']


def test_a_call_from_before_a_restart_is_not_taken_after_it(group, seed, monkeypatch):
    """The nonces a member has seen go with its process. A call signed before the
    receiver started is refused like one from outside the window, so a call captured
    before a restart is not taken a second time after it."""
    g = group
    _built(g, seed, 'bc')
    ha = g.ha
    headers = _sign_as(g, 'b', 'a', ts=int(time.time()) - 5)
    assert _send(g, 'a', headers).status_code == 200
    assert _send(g, 'a', headers).status_code == 401
    # a restarts
    ha.forget_seen_nonces()
    monkeypatch.setattr(ha, '_PROCESS_STARTED', ha.ha_vote.ha_clock())
    r = _send(g, 'a', headers)
    assert r.status_code == 401 and r.get_json()['code'] == 'HA_CLOCK'
    # what b signs from now on is taken
    assert _asks(g, 'b', 'a') == 200 and _watch(g, 'b') == 'ok'


def test_the_start_of_the_process_follows_the_wall_clock(group, seed, monkeypatch):
    """The start is kept in lease time and read in the wall clock of the moment: an
    instance whose clock was ahead when it started, and that NTP set back since, takes
    its members' calls again instead of answering HA_CLOCK for as long as it was off. A
    call signed before the start is still not taken."""
    g = group
    _built(g, seed, 'bc')
    ha = g.ha
    # started 30 seconds ago, whatever the wall clock said then
    monkeypatch.setattr(ha, '_PROCESS_STARTED', ha.ha_vote.ha_clock() - 30)
    assert _send(g, 'a', _sign_as(g, 'b', 'a')).status_code == 200
    assert _send(g, 'a', _sign_as(g, 'b', 'a', ts=int(time.time()) - 10)).status_code == 200
    r = _send(g, 'a', _sign_as(g, 'b', 'a', ts=int(time.time()) - 60))
    assert r.status_code == 401 and r.get_json()['code'] == 'HA_CLOCK'


def test_the_body_is_read_whatever_the_content_type_says(group, seed):
    """The signature covers the body, not the Content-Type. A removal notice sent as a
    form is still the removal, not a plain leave."""
    g = group
    _built(g, seed, 'bc')
    body = g.ha._wire_body({'removed': True, 'epoch': 1})
    headers = dict(_sign_as(g, 'a', 'b', 'POST', '/api/ha/peer/unpaired', body),
                   **{'X-Requested-With': 'XMLHttpRequest',
                      'Content-Type': 'application/x-www-form-urlencoded'})
    with g.at('b'):
        r = g.client.post('/api/ha/peer/unpaired', data=body, headers=headers,
                          base_url='http://localhost')
    assert r.status_code == 200 and r.get_json()['left_group'] is True
    b = g.state('b')
    assert b['members'] == {} and b['removed']['by'] == IDS['a']


def test_a_peer_call_with_a_query_is_nobodys(group, seed):
    """No peer call carries a query string, and the signature covers the path alone. A
    call with a query is refused, and so is one whose '?' only appears once the path
    is decoded: the two would read alike."""
    import pegaprox.api.ha as ha_api
    g = group
    _built(g, seed, 'bc')
    with_query = '/api/ha/peer/status?x=1'
    assert _send(g, 'a', _sign_as(g, 'b', 'a', path=with_query), path=with_query).status_code == 401
    headers = dict(_sign_as(g, 'b', 'a', path=with_query), **{'X-Requested-With': 'XMLHttpRequest'})
    with g.at('a'), g.api.app.test_request_context('/api/ha/peer/status%3Fx=1', headers=headers):
        from flask import request
        assert request.path == with_query and not request.query_string
        assert ha_api.request_peer() == (None, None)
    assert _send(g, 'a', _sign_as(g, 'b', 'a')).status_code == 200


def test_a_public_key_of_small_order_is_no_key(group, seed):
    """Under the identity point one fixed signature holds for every message. OpenSSL
    takes it, and the other small-order points, as public keys; a member list, a
    tombstone or a pairing that carried one would give that member an identity
    anybody can sign as."""
    g = group
    ha = g.ha
    identity = base64.b64encode(b'\x01' + b'\x00' * 31).decode()
    assert ha._public_key(identity) is None
    p = 2 ** 255 - 19
    y8 = 2707385501144840649318225287225658788936804267575313519463743609750303402022
    # all eight points, with the sign bit or without, and the two encodings above p
    for y in (0, 1, p - 1, y8, p - y8, p, p + 1):
        for sign in (0, 1 << 255):
            raw = base64.b64encode((y | sign).to_bytes(32, 'little')).decode()
            assert ha._public_key(raw) is None, (y, sign)
    _built(g, seed, 'b', sync=False)
    assert ha._public_key(_pub(g, 'b')) is not None

    entry = {'instance_id': IDS['c'], 'url': URLS['c'], 'fingerprint': '', 'public_key': identity}
    assert ha._clean_entries([entry]) == {}
    assert ha._clean_tombstones([dict(entry, epoch=1, at='', by=IDS['a'])]) == {}
    with g.at('a') as h:
        code, _exp = h.create_pairing_code(URLS['a'], '')
        with pytest.raises(h.HaError, match='public key'):
            h.accept_pairing(h.decode_code(code)['secret'], IDS['c'], URLS['c'], '', identity)
    assert g.members('a') == {IDS['b']}


# --- from before the keys -----------------------------------------------------------

def test_a_pair_from_before_the_groups_moves_to_keys_without_pairing_again(group, seed):
    """Both sides talk at every step: first with the old secrets, then each takes the
    other's key from a call that carries it, and the secrets go."""
    g = group
    admin = _admin(g.api, seed)
    g.write('a', V2_ACTIVE)
    g.write('b', V2_STANDBY)
    for n in 'ab':
        st = g.state(n)
        assert st['signing_key'] is None and st['member_secret']
        assert all(not r.get('public_key') for r in st['members'].values())

    # b first: it presents its secret and its new key, a takes both
    assert _sync(g, admin, 'b') == 'applied'
    first = [s for s in g.sent if s[:2] == ('b', 'a')][-1][5]
    assert first[g.ha.PEER_HEADER] == f"{IDS['b']}:{V2_STANDBY_PRESENTS}"
    assert first[g.ha.PEER_KEY_HEADER] == _pub(g, 'b') and first[g.ha.PEER_SIG_HEADER]
    assert g.state('a')['members'][IDS['b']]['public_key'] == _pub(g, 'b')
    # a said it holds the key, so b needs its secret no more
    assert g.state('b')['member_secret'] is None
    assert g.state('b')['members'][IDS['a']]['key_acked'] is True

    # a still goes by its secret towards b, and b takes a's key from that call
    assert _watch(g, 'a') == 'ok'
    assert g.state('b')['members'][IDS['a']]['public_key'] == _pub(g, 'a')
    assert g.state('a')['member_secret'] is None

    # from now on only signatures, both ways
    mark = len(g.sent)
    assert _sync(g, admin, 'b') == 'applied'          # the list carries the keys now
    assert _sync(g, admin, 'b') == 'unchanged'
    assert _watch(g, 'a') == 'ok' and _watch(g, 'b') == 'ok'
    for (_frm, _to, _m, _p, _b, headers) in g.sent[mark:]:
        assert headers[g.ha.PEER_HEADER] in (IDS['a'], IDS['b'])
        assert g.ha.PEER_KEY_HEADER not in headers
    for n, secret, other in (('a', V2_ACTIVE_PRESENTS, 'b'), ('b', V2_STANDBY_PRESENTS, 'a')):
        assert _asks(g, {g.ha.PEER_HEADER: f'{IDS[n]}:{secret}'}, other) == 401
        assert _asks(g, n, other) == 200


def test_the_old_release_on_the_other_side_keeps_taking_the_secret(group, seed, monkeypatch):
    """a is on this release, b not yet: b makes no key, records none and takes none
    from the member list, so it never says it holds a's key. a keeps sending its secret
    along, and both keep talking. Once b is updated, the keys go over and the secrets go."""
    g = group
    admin = _admin(g.api, seed)
    g.write('a', V2_ACTIVE)
    g.write('b', V2_STANDBY)
    ha = g.ha

    def on_b():
        return ha.STATE_FILE == g.files['b']
    real_signer, real_record, real_clean = ha._signer, ha._record_key, ha._clean_entries

    def old_signer():
        if on_b():
            st = ha._load()
            return ha._Signer(st['instance_id'], None, st['member_secret'])
        return real_signer()

    def old_clean(entries):
        out = real_clean(entries)
        if on_b():
            out = {mid: dict(e, public_key='') for mid, e in out.items() if e['secret_hash']}
        return out
    monkeypatch.setattr(ha, '_signer', old_signer)
    monkeypatch.setattr(ha, '_record_key', lambda mid, key: False if on_b() else real_record(mid, key))
    monkeypatch.setattr(ha, '_clean_entries', old_clean)

    for _ in range(2):
        assert _watch(g, 'a') == 'ok'
        assert _sync(g, admin, 'b') in ('applied', 'unchanged')
    a, b = g.state('a'), g.state('b')
    assert a['member_secret'] == V2_ACTIVE_PRESENTS and not a['members'][IDS['b']].get('key_acked')
    assert not a['members'][IDS['b']].get('public_key')
    assert not b['members'][IDS['a']].get('public_key') and not b.get('signing_key')
    last = [s for s in g.sent if s[:2] == ('a', 'b')][-1][5]
    assert last[ha.PEER_HEADER] == f"{IDS['a']}:{V2_ACTIVE_PRESENTS}"
    assert last[ha.PEER_KEY_HEADER] == _pub(g, 'a')

    # b is updated
    for name, real in (('_signer', real_signer), ('_record_key', real_record),
                       ('_clean_entries', real_clean)):
        monkeypatch.setattr(ha, name, real)
    assert _watch(g, 'a') == 'ok'
    assert g.state('b')['members'][IDS['a']]['public_key'] == _pub(g, 'a')
    assert g.state('a')['member_secret'] is None
    assert _sync(g, admin, 'b') in ('applied', 'unchanged')
    assert g.state('a')['members'][IDS['b']]['public_key'] == _pub(g, 'b')
    assert g.state('b')['member_secret'] is None
    assert _watch(g, 'a') == 'ok' and _sync(g, admin, 'b') in ('applied', 'unchanged')


def test_a_group_with_hashes_takes_no_key_along_with_a_secret(group, seed):
    """Three instances as the unreleased group format before the keys wrote them: every
    member holds the hash of every other member's secret, and was sent each of those
    secrets on every tick. There a secret proves nothing about a key sent along with
    it: d, removed on that format with c's secret in hand, got its own key recorded as
    c's before c came by, signed as c from then on, and c was refused. Only the partner
    of a pair gets its key taken that way. Such a group keeps going by its secrets
    (the active's own key reaches the standbys with its member list) until it is
    paired again."""
    g = group
    admin = _admin(g.api, seed)
    ha = g.ha
    secret = {n: f'group-secret-{n}-' + 'q' * 30 for n in 'abc'}

    def rec(n, role_seen):
        return {'url': URLS[n], 'fingerprint': '', 'secret_hash': ha._hash_secret(secret[n]),
                'role_seen': role_seen, 'epoch_seen': 1, 'last_contact': None,
                'last_error': '', 'joined_at': '2026-09-30T10:00:00+00:00'}
    g.write('a', {'role': 'active', 'epoch': 1, 'instance_id': IDS['a'], 'interval': 30,
                  'member_secret': secret['a'], 'own_url': URLS['a'], 'own_fingerprint': '',
                  'members': {IDS['b']: rec('b', 'standby'), IDS['c']: rec('c', 'standby')},
                  'source': None, 'pairing': None, 'sync': {}})
    for n, other in (('b', 'c'), ('c', 'b')):
        g.write(n, {'role': 'standby', 'epoch': 1, 'instance_id': IDS[n], 'interval': 30,
                    'member_secret': secret[n],
                    'members': {IDS['a']: rec('a', 'active'), IDS[other]: rec(other, None)},
                    'source': IDS['a'], 'pairing': None, 'sync': {}})

    # d comes first, with c's secret and a key of its own
    private = ha._private_key(ha._new_signing_key())
    forged = dict(ha._signed_headers(private, IDS['c'], IDS['a'], 'GET', STATUS, b''),
                  **{ha.PEER_HEADER: f"{IDS['c']}:{secret['c']}",
                     ha.PEER_KEY_HEADER: ha._public_of(private)})
    r = _send(g, 'a', forged)
    assert r.status_code == 200                      # the secret is c's, as on that format
    assert r.headers.get(ha.PEER_KEYED_HEADER) is None
    assert not g.state('a')['members'][IDS['c']].get('public_key')
    # the key is nobody's
    signed_only = ha._signed_headers(private, IDS['c'], IDS['a'], 'GET', STATUS, b'')
    assert _send(g, 'a', signed_only).status_code == 401

    # every look at the group and every pull works throughout, c's included
    for _ in range(2):
        for n in 'bc':
            assert _sync(g, admin, n) in ('applied', 'unchanged')
        assert _watch(g, 'a') == 'ok'
        assert _watch(g, 'b') == 'ok' and _watch(g, 'c') == 'ok'

    for n in 'abc':
        st = g.state(n)
        for m in 'bc':
            if m != n:
                # the standbys sent their keys along every time, and nobody took one
                assert not st['members'][IDS[m]].get('public_key'), (n, m)
                assert _asks(g, m, n) == 200, (m, n)
    # the active's key travelled with its member list, which is the active's word
    for n in 'bc':
        assert g.state(n)['members'][IDS['a']]['public_key'] == _pub(g, 'a')
        assert _asks(g, 'a', n) == 200
    assert g.state('a')['member_secret'] is None
    assert all(g.state(n)['member_secret'] for n in 'bc')


def test_a_key_from_before_its_own_write_is_never_offered(group, seed, monkeypatch):
    """A member takes an offered key for good. One that a restart would forget must
    not go out: when the key cannot be written, the call goes with the secret alone."""
    g = group
    admin = _admin(g.api, seed)
    g.write('a', V2_ACTIVE)
    g.write('b', V2_STANDBY)
    ha = g.ha
    real = ha._write_locked

    def full_disk(st):
        if ha.STATE_FILE == g.files['b'] and st.get('signing_key'):
            raise OSError(28, 'No space left on device')
        return real(st)
    monkeypatch.setattr(ha, '_write_locked', full_disk)
    assert _sync(g, admin, 'b') == 'applied'
    sent = [s for s in g.sent if s[:2] == ('b', 'a')][-1][5]
    assert sent == {k: v for k, v in sent.items() if not k.startswith('X-PegaProx-Peer-')}
    assert sent[ha.PEER_HEADER] == f"{IDS['b']}:{V2_STANDBY_PRESENTS}"
    assert not g.state('a')['members'][IDS['b']].get('public_key')
    assert not g.state('b').get('signing_key')


def test_a_member_whose_clock_is_off_is_told_so_and_proves_nothing(group, seed, monkeypatch):
    """A good signature from outside the window is refused with HA_CLOCK, so the admin
    sees what to fix. Every member refusing an active steps it aside; a clock that is
    off is no sign that the group moved on, and must not do that."""
    g = group
    _built(g, seed, 'bc')
    ha = g.ha
    r = _send(g, 'a', _sign_as(g, 'b', 'a', ts=int(time.time()) - 200))
    assert r.status_code == 401 and r.get_json()['code'] == 'HA_CLOCK'
    assert 'NTP' in r.get_json()['error']
    # a bad signature from the same moment says nothing about clocks
    bad = dict(_sign_as(g, 'b', 'a', ts=int(time.time()) - 200),
               **{ha.PEER_SIG_HEADER: base64.b64encode(b'x' * 64).decode()})
    r = _send(g, 'a', bad)
    assert r.status_code == 401 and 'code' not in r.get_json()

    # a's clock is 200 s behind: b and c refuse it, and a stays what it is
    real_time = time.time
    monkeypatch.setattr(ha, 'time', types.SimpleNamespace(
        time=lambda: real_time() - 200 if ha.STATE_FILE == g.files['a'] else real_time(),
        monotonic=time.monotonic, sleep=time.sleep))
    assert _watch(g, 'a') == 'unreachable'
    a = g.state('a')
    assert a['role'] == 'active' and not [r for r in g.restarts if r[0] == 'a']
    assert 'clocks' in a['members'][IDS['b']]['last_error']
