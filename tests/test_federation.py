"""The federation of instances (Phase 1): pairing by a one-time code, signed peer
calls over the federation's own signature domain, the registry and its tombstones.

Two (and in the mesh test three) instances live in one process, as the HA group tests
do it: each side holds its own federation state file, and federation._runtime names
whichever side is acting. The transport the core calls out on is a stand-in that
routes the call into the Flask test client of the side the address names, with that
side's runtime active while it answers - the same swap the HA tests do with the state
file. No network is dialed.

The security cases are the point of this suite: a replayed call, a call signed for
another member, one signed on the HA group's domain, one from outside the signature
window, a spent pairing code, a member the federation took out, and a member list
answer that must only open under the pairing code's secret.

Nov 2026, three-leader federation Phase 1.
"""
import base64
import contextlib
import json
import os
import secrets
import time

import pytest

from pegaprox.core import federation, ha_wire

STATUS = '/api/federation/peer/status'
JOIN = '/api/federation/peer/join'
URL = {'a': 'https://a.example:5000', 'b': 'https://b.example:5000',
       'c': 'https://c.example:5000'}


class Side:
    """One instance: its state file, its runtime slot and a Flask app with nothing
    but the federation blueprint, so nothing else of the app can carry a test."""

    def __init__(self, tmp, name):
        self.name = name
        self.file = str(tmp / f'fed-{name}.json')
        # a process that just started refuses everything signed before its start (the
        # nonces are gone): a side here is five seconds old, as a real one is by the
        # time a peer has paired and calls
        self.runtime = {'file': self.file, 'started': time.time() - 5, 'nonces': {},
                        'transport': None}
        from flask import Flask
        from pegaprox.api import federation as api_fed
        self.app = Flask(__name__)
        self.app.config['TESTING'] = True
        self.app.register_blueprint(api_fed.bp)
        self.client = self.app.test_client()


@contextlib.contextmanager
def at(side):
    """Make `side` the one the core acts for; its runtime slot (with the nonces it
    spent) comes back when the context ends."""
    saved = dict(federation._runtime)
    federation._runtime.clear()
    federation._runtime.update(side.runtime)
    try:
        yield side
    finally:
        side.runtime.clear()
        side.runtime.update(federation._runtime)
        federation._runtime.clear()
        federation._runtime.update(saved)


def transport_for(sides):
    """The stand-in for the network: a call to a side's address lands in that side's
    test client, with its runtime active while it answers. The join call carries no
    signature - the code in its body is its authorization - everything else is signed
    by whoever makes it."""
    by_url = {URL[s.name]: s for s in sides}

    def transport(url, method, path, body, fingerprint, timeout):
        target = by_url[url]
        # the answering side answers with its runtime AND its database, as an
        # instance does - a call about identities reads the writer's tables
        with at_db(target):
            receiver = federation.instance_id()
        headers = {'X-Requested-With': 'XMLHttpRequest'}
        data = ha_wire.wire_body(body) if body is not None else None
        if data is not None:
            headers['Content-Type'] = 'application/json'
        if path != JOIN:
            # the caller's runtime is active out here: its key, its name
            headers.update(federation.signed_headers(receiver, method, path, body))
        with at_db(target):
            resp = target.client.open(path, method=method, data=data,
                                      headers=headers)
        return resp.status_code, resp.get_json(silent=True)
    return transport


@pytest.fixture(autouse=True)
def _fresh_budgets():
    """The pairing and peer budgets are per process and every test here joins from
    the one address of the test client: a fresh pair per test, or the fifth join of
    the suite would be the door closing - which is its own test below."""
    from pegaprox.utils.ratelimit import SlidingWindow
    from pegaprox.api import federation as api_fed
    api_fed._pair_attempts = SlidingWindow(limit=5, window=300, max_keys=2048,
                                           name='fed-pair-test')
    api_fed._peer_failures = SlidingWindow(limit=10, window=300, max_keys=2048,
                                           name='fed-peer-test')
    yield


@pytest.fixture
def sides(tmp_path):
    out = [Side(tmp_path, 'a'), Side(tmp_path, 'b')]
    transport = transport_for(out)
    for s in out:
        s.runtime['transport'] = transport
    return out


@pytest.fixture
def paired(sides):
    """Side a has handed out a code, side b has joined: both hold each other."""
    a, b = sides
    with at(a):
        federation.set_own_site('site-a')
        code, _ = federation.create_pairing_code(URL['a'])
    with at(b):
        out = federation.join(code, URL['b'], 'site-b')
    return a, b, out


def _post(side, path, body=None, headers=None, query=''):
    """A call at `side`'s client while its runtime is active."""
    headers = dict(headers or {'X-Requested-With': 'XMLHttpRequest'})
    data = ha_wire.wire_body(body) if body is not None else None
    if data is not None:
        headers.setdefault('Content-Type', 'application/json')
    with at(side):
        return side.client.open(path + query, method='POST', data=data,
                                headers=headers)


def test_the_wire_says_the_word_the_csrf_gate_takes(sides):
    """The CSRF gate of the real app (app.py) takes state-changing /api calls with no
    Origin only when X-Requested-With says exactly XMLHttpRequest - the HA peer calls
    send that word, and a federation call sends the same. A bare test client has no
    gate, so this holds the word in place where the smoke test found it once."""
    a = sides[0]
    with at(a):
        headers = federation.signed_headers('0' * 32, 'GET', '/x')
    assert federation.PEER_XHR == 'XMLHttpRequest'
    assert headers['X-Requested-With'] == federation.PEER_XHR


def _get(side, path, headers=None, query=''):
    with at(side):
        return side.client.open(path + query, method='GET', headers=headers or {})


def _signed_headers_of(side, receiver_id, method='GET', path=STATUS, body=None,
                       now=None, ts=None, nonce=None, domain='fed'):
    """Headers `side` signs for `receiver_id`, by hand, with the time and nonce the
    caller wants - the tool for the security cases."""
    body = ha_wire.wire_body(body) if body is not None else b''
    with at(side):
        sender = federation.instance_id()
        private = federation._private()
    ts = str(int(time.time()) if ts is None else ts)
    nonce = nonce or secrets.token_urlsafe(18)
    digest = ha_wire.body_digest(body)
    if domain == 'fed':
        to_sign = federation._to_sign(method, path, body, ts, nonce, receiver_id,
                                      sender, digest)
    else:
        to_sign = ha_wire.to_sign(method, path, body, ts, nonce, receiver_id, sender,
                                  digest)
    sig = private.sign(to_sign)
    return {ha_wire.PEER_HEADER: sender, ha_wire.PEER_TS_HEADER: ts,
            ha_wire.PEER_NONCE_HEADER: nonce,
            ha_wire.PEER_SIG_HEADER: base64.b64encode(sig).decode(),
            ha_wire.PEER_BODY_HEADER: digest, 'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest'}


# --- the state and the identity ---------------------------------------------------------

def test_state_file_is_private_and_stable(sides, tmp_path):
    a, _ = sides
    with at(a):
        first = federation.instance_id()
        key = federation.public_key()
        assert os.stat(federation._runtime['file']).st_mode & 0o777 == 0o600
        assert federation.instance_id() == first
        assert federation.public_key() == key
    assert tmp_path.joinpath('fed-a.json').exists()


def test_a_pairing_code_carries_a_url_and_an_id(sides):
    a, _ = sides
    with at(a):
        code, expires = federation.create_pairing_code(URL['a'])
    parts = ha_wire.decode_code(federation.CODE_PREFIX, code)
    assert parts['url'] == URL['a']
    assert parts['instance_id'] == federation_ref_id(a)
    assert expires > time.time()


def federation_ref_id(side):
    with at(side):
        return federation.instance_id()


def test_a_code_expires(sides):
    a, _ = sides
    with at(a):
        code, _ = federation.create_pairing_code(URL['a'])
        # push the open code into the past, as a slow admin would
        def age(state):
            if state.get('pairing'):
                state['pairing']['expires'] = int(time.time()) - 1
                return True
            return False
        federation._mutate(age)
        with pytest.raises(federation.FederationError):
            federation.accept_join(code, URL['b'], 'b' * 32, some_key(), 'site-b')


def some_key():
    return ha_wire.public_of(ha_wire.private_key(ha_wire.new_signing_key()))


# --- the join ---------------------------------------------------------------------------

def test_a_join_pairs_both_sides(paired):
    a, b, out = paired
    a_id, b_id = federation_ref_id(a), federation_ref_id(b)
    assert out['joined'] == a_id
    with at(a):
        assert sorted(federation.members()) == [b_id]
        assert federation.members()[b_id]['site'] == 'site-b'
        assert federation.members()[b_id]['url'] == URL['b']
    with at(b):
        assert sorted(federation.members()) == [a_id]
        assert federation.members()[a_id]['site'] == 'site-a'


def test_a_code_is_spent_by_the_join(paired):
    a, b, out = paired
    code, _ = None, None
    # the code b used is gone: a second join with it is refused, however soon
    with at(a):
        code, _ = federation.create_pairing_code(URL['a'])
    # join once, through the api, spending it
    body = {'code': code, 'url': URL['b'], 'instance_id': 'c' * 32,
            'public_key': some_key(), 'site': ''}
    r = _post(a, JOIN, body)
    assert r.status_code == 200
    body['instance_id'] = 'd' * 32
    r = _post(a, JOIN, body)
    assert r.status_code == 403
    assert 'expired' in r.get_json()['error'] or 'not one' in r.get_json()['error']


def test_the_member_list_answer_opens_under_the_code_secret_only(sides):
    a, b = sides
    with at(a):
        code, _ = federation.create_pairing_code(URL['a'])
    parts = ha_wire.decode_code(federation.CODE_PREFIX, code)
    body = {'code': code, 'url': URL['b'], 'instance_id': federation_ref_id(b),
            'public_key': some_key(), 'site': 'site-b'}
    r = _post(a, JOIN, body)
    assert r.status_code == 200
    sealed = r.get_json()['sealed']
    opened = ha_wire.unseal(parts['secret'], sealed,
                            f'federation-join:{parts["instance_id"]}:'
                            f'{federation_ref_id(b)}')
    assert parts['instance_id'] in opened['members']
    with pytest.raises(Exception):
        ha_wire.unseal('f' * 64, sealed, 'federation-join:x:y')


def test_a_member_cannot_pair_with_itself(sides):
    a, _ = sides
    with at(a):
        code, _ = federation.create_pairing_code(URL['a'])
        with pytest.raises(federation.FederationError):
            federation.accept_join(code, URL['a'], federation.instance_id(),
                                   some_key(), '')


def test_a_join_refuses_a_junk_key(paired):
    a = paired[0]
    with at(a):
        code, _ = federation.create_pairing_code(URL['a'])
    # 32 zero bytes: an Ed25519 point of small order, an identity anybody can sign as
    junk = base64.b64encode(b'\x00' * 32).decode()
    body = {'code': code, 'url': URL['b'], 'instance_id': 'e' * 32,
            'public_key': junk, 'site': ''}
    r = _post(a, JOIN, body)
    assert r.status_code == 403
    assert 'public key' in r.get_json()['error']


# --- the signed calls --------------------------------------------------------------------

def test_a_signed_status_call_is_taken(paired):
    a, b, _ = paired
    a_id, b_id = federation_ref_id(a), federation_ref_id(b)
    with at(b):
        status, body = federation.call_peer(a_id, 'GET', STATUS)
    assert status == 200
    assert body['instance_id'] == a_id
    assert body['fed'] == federation.FED_MARK
    assert body['site'] == 'site-a'
    # a counts the visit
    with at(a):
        assert federation.members()[b_id]['last_seen'] > 0


def test_a_call_without_headers_is_nobody(paired):
    a = paired[0]
    r = _get(a, STATUS)
    assert r.status_code == 401


def test_a_replayed_call_is_refused(paired):
    a, b, _ = paired
    headers = _signed_headers_of(b, federation_ref_id(a))
    assert _get(a, STATUS, headers).status_code == 200
    assert _get(a, STATUS, headers).status_code == 401
    # the same nonce under a fresh signature is still the same call
    again = _signed_headers_of(b, federation_ref_id(a),
                               nonce=headers[ha_wire.PEER_NONCE_HEADER])
    assert _get(a, STATUS, again).status_code == 401


def test_a_call_signed_for_another_member_is_refused(paired):
    a, b, _ = paired
    # b signs for c (unknown); a takes nothing of it
    for_c = _signed_headers_of(b, 'f' * 32)
    assert _get(a, STATUS, for_c).status_code == 401


def test_a_call_signed_on_the_ha_domain_is_refused(paired):
    """The federation's domain is its own: a signature for the HA group of the same
    instance, the same key, the same moment, is worthless here."""
    a, b, _ = paired
    wrong = _signed_headers_of(b, federation_ref_id(a), domain='ha')
    assert _get(a, STATUS, wrong).status_code == 401


def test_a_call_outside_the_window_is_told_about_its_clock(paired):
    a, b, _ = paired
    old = _signed_headers_of(b, federation_ref_id(a), ts=int(time.time()) - 3600)
    r = _get(a, STATUS, old)
    assert r.status_code == 401
    assert r.get_json()['code'] == 'FED_CLOCK'
    assert r.get_json()['clock'] == 'window'


def test_an_early_call_is_told_what_it_is(paired):
    a, b, _ = paired
    # inside the signature window, but signed before this receiver started: early,
    # not a clock two minutes apart
    early = _signed_headers_of(b, federation_ref_id(a), ts=int(time.time()) - 30)
    with at(a):
        federation._runtime['started'] = time.time() + 1800
    r = _get(a, STATUS, early)
    assert r.status_code == 401
    assert r.get_json()['clock'] == 'early'


def test_a_tampered_body_is_refused(paired):
    a, b, _ = paired
    headers = _signed_headers_of(b, federation_ref_id(a), method='POST',
                                 path='/api/federation/peer/member-added',
                                 body={'member': {}})
    # the signature covers the body digest of {'member': {}}; this sends another
    with at(a):
        r = a.client.post('/api/federation/peer/member-added',
                          data=ha_wire.wire_body({'member': {'instance_id': '0' * 32}}),
                          headers=headers)
    assert r.status_code == 401


def test_a_peer_call_with_a_query_string_is_nobody(paired):
    a, b, _ = paired
    headers = _signed_headers_of(b, federation_ref_id(a), path=STATUS,
                                 body=None)
    r = _get(a, STATUS, headers, query='?x=1')
    assert r.status_code == 401


# --- the registry and its tombstones -------------------------------------------------------

def test_a_removed_member_hears_it_and_lets_go(paired):
    a, b, _ = paired
    a_id, b_id = federation_ref_id(a), federation_ref_id(b)
    with at(a):
        assert federation.remove_member(b_id, by='admin:test')
        assert federation.members() == {}
        assert b_id in federation.tombstones()
    headers = _signed_headers_of(b, a_id)
    r = _get(a, STATUS, headers)
    assert r.status_code == 410
    assert r.get_json()['code'] == 'FED_REMOVED'


def test_a_member_that_leaves_tells_the_others(paired):
    a, b, _ = paired
    a_id, b_id = federation_ref_id(a), federation_ref_id(b)
    with at(b):
        assert federation.leave()
        assert federation.members() == {}
    with at(a):
        # the push landed: a holds a tombstone for b, not a member
        assert federation.members() == {}
        assert b_id in federation.tombstones()


def test_a_member_added_notice_keeps_a_good_record(paired, tmp_path):
    a, b, _ = paired
    c = Side(tmp_path, 'c')
    c.runtime['transport'] = a.runtime['transport']
    # rebind the transport to know c's address
    sides = [a, b, c]
    shared = transport_for(sides)
    for s in sides:
        s.runtime['transport'] = shared
    c_id = federation_ref_id(c)
    notice = {'member': {'instance_id': c_id, 'url': URL['c'],
                         'public_key': some_key(), 'site': 'site-c',
                         'fingerprint': '', 'paired_at': int(time.time()),
                         'last_seen': 0}}
    headers = _signed_headers_of(a, federation_ref_id(b), method='POST',
                                 path='/api/federation/peer/member-added',
                                 body=notice)
    r = _post(b, '/api/federation/peer/member-added', notice, headers)
    assert r.status_code == 200
    with at(b):
        assert federation.members()[c_id]['site'] == 'site-c'


def test_three_instances_reach_a_full_mesh(tmp_path):
    """a pairs b, a pairs c: the pushes tell b of c, and every side can ask the
    others - the read federation as three leaders will run it."""
    a = Side(tmp_path, 'a')
    b = Side(tmp_path, 'b')
    c = Side(tmp_path, 'c')
    all_sides = [a, b, c]
    shared = transport_for(all_sides)
    for s in all_sides:
        s.runtime['transport'] = shared
    with at(a):
        set_sites = federation.set_own_site('site-a')
        code1, _ = federation.create_pairing_code(URL['a'])
    with at(b):
        federation.join(code1, URL['b'], 'site-b')
    with at(a):
        code2, _ = federation.create_pairing_code(URL['a'])
    with at(c):
        federation.join(code2, URL['c'], 'site-c')
    a_id, b_id, c_id = (federation_ref_id(s) for s in (a, b, c))
    with at(a):
        assert sorted(federation.members()) == sorted([b_id, c_id])
    # the push of the second join told b of c
    with at(b):
        assert sorted(federation.members()) == sorted([a_id, c_id])
    # the sealed answer c got carried a and b already: the issuer lists every member
    with at(c):
        assert sorted(federation.members()) == sorted([a_id, b_id])
        learned = federation.reconcile()
        assert learned == []
        assert sorted(federation.members()) == sorted([a_id, b_id])


def test_reconcile_learns_a_member_a_push_missed(paired, tmp_path):
    a, b, out = paired
    c = Side(tmp_path, 'c')
    all_sides = [a, b, c]
    shared = transport_for(all_sides)
    for s in all_sides:
        s.runtime['transport'] = shared
    a_id, c_id = federation_ref_id(a), federation_ref_id(c)
    # c joins a directly through the api at a; the member-added push to b arrives,
    # then c is taken away from b again - as a push that never arrived
    with at(a):
        code, _ = federation.create_pairing_code(URL['a'])
    body = {'code': code, 'url': URL['c'], 'instance_id': c_id,
            'public_key': some_key(), 'site': 'site-c'}
    r = _post(a, JOIN, body)
    assert r.status_code == 200
    with at(b):
        def drop(state):
            return state['members'].pop(c_id, None) is not None
        federation._mutate(drop)
        assert c_id not in federation.members()
        learned = federation.reconcile()
        assert c_id in learned
        assert c_id in federation.members()


# --- the admin half ------------------------------------------------------------------------

def test_admin_routes_want_a_session(paired):
    a = paired[0]
    for method, path in (('get', '/api/federation/status'),
                         ('get', '/api/federation/members'),
                         ('post', '/api/federation/pairing-code'),
                         ('post', '/api/federation/join'),
                         ('post', f'/api/federation/members/{"0" * 32}/remove'),
                         ('post', '/api/federation/leave'),
                         ('post', '/api/federation/reconcile')):
        with at(a):
            r = getattr(a.client, method)(path, json={})
            assert r.status_code == 401, (method, path, r.status_code)


def test_the_join_endpoint_has_a_budget(paired, monkeypatch):
    """Five wrong codes from one address, then the door holds for a while. The
    fixture's join spent one already, so this test hands the route a fresh budget."""
    from pegaprox.utils.ratelimit import SlidingWindow
    from pegaprox.api import federation as api_fed
    monkeypatch.setattr(api_fed, '_pair_attempts',
                        SlidingWindow(limit=5, window=300, max_keys=2048,
                                      name='fed-pair-budget'))
    a = paired[0]
    body = {'code': 'pgxfd1_junk', 'url': URL['b'], 'instance_id': '0' * 32,
            'public_key': some_key(), 'site': ''}
    for _ in range(5):
        r = _post(a, JOIN, body)
        assert r.status_code == 403
    r = _post(a, JOIN, body)
    assert r.status_code == 429
    assert r.headers.get('Retry-After') == '300'


def test_a_broken_state_file_is_a_clear_error(sides):
    a, _ = sides
    with open(a.file, 'w') as fh:
        fh.write('not json')
    with at(a):
        with pytest.raises(federation.FederationError):
            federation.instance_id()


# --- the hardening the audit asked for ---------------------------------------------------

def test_a_notice_cannot_bring_a_removed_member_back(tmp_path):
    """A tombstone only a fresh pairing clears: member c announcing b - which a took
    out - changes nothing. The removal must survive the members it was meant for."""
    a, b = Side(tmp_path, 'a'), Side(tmp_path, 'b')
    c = Side(tmp_path, 'c')
    all_sides = [a, b, c]
    shared = transport_for(all_sides)
    for s in all_sides:
        s.runtime['transport'] = shared
    with at(a):
        code1, _ = federation.create_pairing_code(URL['a'])
    with at(b):
        federation.join(code1, URL['b'], 'site-b')
    with at(a):
        code2, _ = federation.create_pairing_code(URL['a'])
    with at(c):
        federation.join(code2, URL['c'], 'site-c')
    a_id, b_id = federation_ref_id(a), federation_ref_id(b)
    with at(a):
        assert federation.remove_member(b_id, by='admin:test')
        assert b_id in federation.tombstones()
    notice = {'member': {'instance_id': b_id, 'url': URL['b'],
                         'public_key': some_key(), 'site': 'site-b',
                         'paired_at': int(time.time()), 'last_seen': 0}}
    headers = _signed_headers_of(c, a_id, method='POST',
                                 path='/api/federation/peer/member-added',
                                 body=notice)
    r = _post(a, '/api/federation/peer/member-added', notice, headers)
    assert r.status_code == 409
    with at(a):
        assert federation.members().get(b_id) is None
        assert b_id in federation.tombstones()


def test_a_member_list_nobody_read_cannot_fill_the_state(tmp_path):
    """The sealed join answer carries whatever the issuer wrote: the merge stops at
    MAX_MEMBERS whatever the list says, as a pairing does."""
    a, b = Side(tmp_path, 'a'), Side(tmp_path, 'b')
    a_id = federation_ref_id(a)
    with at(a):
        code, _ = federation.create_pairing_code(URL['a'])
    parts = ha_wire.decode_code(federation.CODE_PREFIX, code)
    listed = {a_id: {'instance_id': a_id, 'url': URL['a'],
                     'public_key': some_key(), 'site': '', 'fingerprint': '',
                     'paired_at': 0, 'last_seen': 0}}
    for i in range(20):
        iid = f'{i:032x}'[:32]
        listed[iid] = {'instance_id': iid, 'url': f'https://m{i}.example:5000',
                       'public_key': some_key(), 'site': '', 'fingerprint': '',
                       'paired_at': 0, 'last_seen': 0}
    sealed = ha_wire.seal(parts['secret'], {'members': listed},
                          f'federation-join:{a_id}:{federation_ref_id(b)}')

    def forged(url, method, path, body, fingerprint, timeout):
        if path == federation.JOIN_PATH:
            return 200, {'sealed': sealed}
        return 0, None
    b.runtime['transport'] = forged
    with at(b):
        out = federation.join(code, URL['b'], 'site-b')
        assert len(federation.members()) == federation.MAX_MEMBERS
        assert a_id in federation.members()


def test_tombstones_have_a_bound(sides):
    a, b = paired_side(sides)
    a_id = federation_ref_id(a)
    with at(a):
        def seed(state):
            for i in range(federation.MAX_TOMBSTONES + 10):
                state.setdefault('tombstones', {})[f'{i:032x}'[:32]] = {
                    'url': 'https://x.example:5000', 'public_key': some_key(),
                    'removed_at': i, 'removed_by': 'test'}
            return True
        federation._mutate(seed)
        b_id = federation_ref_id(b)
        federation.remove_member(b_id, by='admin:test')
        assert len(federation.tombstones()) <= federation.MAX_TOMBSTONES


def paired_side(sides):
    """The paired fixture builds its own sides; this one pairs the fixture's two."""
    a, b = sides
    with at(a):
        code, _ = federation.create_pairing_code(URL['a'])
    with at(b):
        federation.join(code, URL['b'], 'site-b')
    return a, b


# --- identity federation (Phase 2) -------------------------------------------------------
#
# Each side needs its own database here, as three instances have: the harness swaps
# the db singleton with the runtime, and a side's database is built once, next to
# its state file.

def _db_of(side):
    """A side's own database, built once: PegaProxDB is a hard singleton (its
    __new__ hands out one object however often it is called), so both the module
    global and the class instance step aside while this one is made."""
    if getattr(side, 'db', None) is None:
        from pegaprox.core import db as db_mod
        old_path = db_mod.DATABASE_FILE
        db_mod.DATABASE_FILE = side.file.replace('fed-', 'db-').replace('.json', '.db')
        saved_db, saved_inst = db_mod._db, db_mod.PegaProxDB._instance
        db_mod._db = None
        db_mod.PegaProxDB._instance = None
        try:
            side.db = db_mod.get_db()
        finally:
            db_mod.DATABASE_FILE = old_path
            db_mod._db = saved_db
            db_mod.PegaProxDB._instance = saved_inst
    return side.db


@contextlib.contextmanager
def at_db(side):
    """The side's runtime and the side's database, together: every core call that
    reads identities lands in the database of the instance it acts for."""
    from pegaprox.core import db as db_mod
    _db_of(side)
    saved_db = db_mod._db
    db_mod._db = side.db
    try:
        with at(side):
            yield side
    finally:
        db_mod._db = saved_db


def _add_local_user(side, username, hash_='h1', role='admin'):
    conn = _db_of(side).conn
    conn.execute("INSERT OR REPLACE INTO users (username, password_salt, "
                 "password_hash, role, fed_home) VALUES (?, 'salt', ?, ?, '')",
                 (username, hash_, role))
    conn.commit()


def _users(side, where_extra=''):
    conn = _db_of(side).conn
    rows = conn.execute("SELECT username, password_hash, fed_home FROM users "
                        f"WHERE username != '' {where_extra}").fetchall()
    return {r['username']: (r['password_hash'], r['fed_home']) for r in rows}


@pytest.fixture
def identity_sides(tmp_path):
    a, b = Side(tmp_path, 'a'), Side(tmp_path, 'b')
    transport = transport_for([a, b])
    for s in (a, b):
        s.runtime['transport'] = transport
    return a, b


def _pair_with_identities(a, b):
    with at_db(a):
        code, _ = federation.create_pairing_code(URL['a'])
    with at_db(b):
        out = federation.join(code, URL['b'], 'site-b')
    return out


def test_a_user_homed_at_a_is_a_mirror_at_b(identity_sides):
    a, b = identity_sides
    a_id = federation_ref_id(a)
    _add_local_user(a, 'alice', hash_='hash-alice')
    _pair_with_identities(a, b)
    # the join pulled the issuer's identities along
    with at_db(b):
        assert _users(b)['alice'] == ('hash-alice', a_id)
    with at_db(a):
        assert _users(a)['alice'] == ('hash-alice', '')


def test_a_changed_password_travels_on_the_next_sync(identity_sides):
    a, b = identity_sides
    _pair_with_identities(a, b)
    _add_local_user(a, 'bob', hash_='first')
    with at_db(b):
        report = federation.sync_identities()
        assert _users(b)['bob'][0] == 'first'
    _add_local_user(a, 'bob', hash_='second')
    with at_db(b):
        report = federation.sync_identities()
        row = _users(b)['bob']
    assert row[0] == 'second', report


def test_nothing_to_do_is_an_unchanged_not_a_refetch(identity_sides):
    a, b = identity_sides
    _pair_with_identities(a, b)
    _add_local_user(a, 'carol')
    with at_db(b):
        assert federation.sync_identities()[federation_ref_id(a)]['applied'] >= 1
        again = federation.sync_identities()[federation_ref_id(a)]
    assert again == {'unchanged': True}


def test_a_delete_travels_and_stays_deleted(identity_sides):
    a, b = identity_sides
    a_id = federation_ref_id(a)
    _add_local_user(a, 'dave')
    _pair_with_identities(a, b)
    with at_db(b):
        assert 'dave' in _users(b)
    with at_db(a):
        conn = _db_of(a).conn
        conn.execute("DELETE FROM users WHERE username = 'dave'")
        conn.commit()
        federation.note_identity_delete('user', 'dave')
    with at_db(b):
        report = federation.sync_identities()
        assert 'dave' not in _users(b)
    # a row the home re-creates is a fresh identity and travels again
    _add_local_user(a, 'dave', hash_='new-dave')
    with at_db(b):
        federation.sync_identities()
        assert _users(b)['dave'] == ('new-dave', a_id)


def test_a_delete_without_a_note_travels_by_the_diff(identity_sides):
    a, b = identity_sides
    _add_local_user(a, 'erin')
    _pair_with_identities(a, b)
    with at_db(b):
        assert 'erin' in _users(b)
    with at_db(a):
        conn = _db_of(a).conn
        conn.execute("DELETE FROM users WHERE username = 'erin'")
        conn.commit()
    with at_db(b):
        federation.sync_identities()
        assert 'erin' not in _users(b)


def test_a_local_row_is_never_overwritten(identity_sides):
    a, b = identity_sides
    # pair first, then the collision: the join's own pull would take the conflict
    # into a report nobody reads, and the second pull would find nothing to do
    _pair_with_identities(a, b)
    _add_local_user(a, 'root', hash_='theirs')
    _add_local_user(b, 'root', hash_='ours')
    with at_db(b):
        report = federation.sync_identities()
        assert _users(b)['root'] == ('ours', '')
        assert any('root' in c for c in report[federation_ref_id(a)]['conflicts'])


def test_tokens_and_roles_travel_too(identity_sides):
    a, b = identity_sides
    a_id = federation_ref_id(a)
    _pair_with_identities(a, b)
    with at_db(a):
        conn = _db_of(a).conn
        conn.execute("INSERT INTO api_tokens (token_hash, token_prefix, username, "
                     "name, role, created_at, fed_home) "
                     "VALUES ('th1', 'pgx_1', 'alice', 'ci', 'viewer', '2026', '')")
        conn.execute("INSERT INTO custom_roles (name, permissions, fed_home) "
                     "VALUES ('auditor', '[\"logs\"]', '')")
        conn.commit()
    with at_db(b):
        report = federation.sync_identities()
        tok = _db_of(b).conn.execute("SELECT fed_home FROM api_tokens "
                                     "WHERE token_hash = 'th1'").fetchone()
        role = _db_of(b).conn.execute("SELECT fed_home FROM custom_roles "
                                      "WHERE name = 'auditor'").fetchone()
    assert tok['fed_home'] == a_id and role['fed_home'] == a_id


def test_an_identity_snapshot_is_only_from_a_member(identity_sides):
    a, b = identity_sides
    _pair_with_identities(a, b)
    with at_db(b):
        for bad in ({}, {'fed': federation.FED_MARK, 'home': 'nobody', 'rows': {}},
                    {'fed': 99, 'home': federation_ref_id(a), 'rows': {}}):
            with pytest.raises(federation.FederationError):
                federation.apply_identity_snapshot(bad)


def test_foreign_home_names_the_owner(identity_sides):
    a, b = identity_sides
    a_id = federation_ref_id(a)
    _pair_with_identities(a, b)
    _add_local_user(a, 'frank')
    with at_db(b):
        federation.sync_identities()
        # the mirror names its home; a local row and a missing row are ours
        assert federation.foreign_home('users', ('frank',)) == a_id
        assert federation.foreign_home('users', ('nobody',)) == ''
    with at_db(a):
        assert federation.foreign_home('users', ('frank',)) == ''
    # and the mirrored hash lets the user sign in here
    from pegaprox.utils.auth import hash_password, verify_password
    salt, ph = hash_password('the-password')
    with at_db(a):
        conn = _db_of(a).conn
        conn.execute("UPDATE users SET password_salt = ?, password_hash = ? "
                     "WHERE username = 'frank'", (salt, ph))
        conn.commit()
    with at_db(b):
        federation.sync_identities()
        row = _db_of(b).conn.execute("SELECT password_salt, password_hash FROM users "
                                     "WHERE username = 'frank'").fetchone()
        assert verify_password('the-password', row['password_salt'],
                               row['password_hash'])


def test_a_role_delete_noted_here_is_served_there(identity_sides):
    a, b = identity_sides
    _pair_with_identities(a, b)
    with at_db(a):
        conn = _db_of(a).conn
        conn.execute("INSERT INTO custom_roles (name, permissions, fed_home) "
                     "VALUES ('temps', '[]', '')")
        conn.commit()
        conn.execute("DELETE FROM custom_roles WHERE name = 'temps'")
        conn.commit()
        federation.note_identity_delete('role', 'temps\x1f')
        snap = federation.identity_snapshot_body()
        assert {'kind': 'role', 'key': 'temps\x1f'} in [
            {k: t[k] for k in ('kind', 'key')} for t in snap['tombstones']]


def test_a_second_factor_never_travels_as_ciphertext(identity_sides):
    """The E1 regression: a TOTP secret is ciphertext under the home's field key -
    left on a mirror it breaks every reader of the users table (load_users answers
    {} and no login works at all). The mirror carries the row without it, the flag
    still travels, and the readers keep working."""
    a, b = identity_sides
    a_id = federation_ref_id(a)
    _pair_with_identities(a, b)
    with at_db(a):
        conn = _db_of(a).conn
        conn.execute("INSERT INTO users (username, password_salt, password_hash, "
                     "role, totp_enabled, totp_secret_encrypted, fed_home) "
                     "VALUES ('gina', 'salt', 'hash', 'viewer', 1, 'Zm9yZWlnbg==', '')")
        conn.commit()
    with at_db(b):
        report = federation.sync_identities()
        row = _db_of(b).conn.execute("SELECT totp_enabled, totp_secret_encrypted, "
                                     "fed_home FROM users WHERE username = 'gina'").fetchone()
        assert row['totp_enabled'] == 1
        assert row['totp_secret_encrypted'] == ''
        assert row['fed_home'] == a_id
        # and the readers of the table still work - load_users answers, not {}
        from pegaprox.utils.auth import load_users
        assert 'gina' in load_users()
    # a mirror written earlier, before this rule, is healed by the next real pull
    # (an unchanged etag answers 304 and applies nothing)
    with at_db(a):
        conn = _db_of(a).conn
        conn.execute("UPDATE users SET display_name = 'G.' WHERE username = 'gina'")
        conn.commit()
    with at_db(b):
        conn = _db_of(b).conn
        conn.execute("UPDATE users SET totp_secret_encrypted = 'c3RhbGU=' "
                     "WHERE username = 'gina'")
        conn.commit()
        federation.sync_identities()
        row = conn.execute("SELECT totp_secret_encrypted FROM users "
                           "WHERE username = 'gina'").fetchone()
        assert row['totp_secret_encrypted'] == ''


# --- partition leases (Phase 3) -------------------------------------------------------

def _add_cluster(side, cid, name=None):
    conn = _db_of(side).conn
    conn.execute("INSERT OR REPLACE INTO clusters (id, name, host, user, "
                 "pass_encrypted, fed_owner) VALUES (?, ?, 'h', 'u', 'x', '')",
                 (cid, name or cid))
    conn.commit()


def _three(tmp_path):
    a, b, c = Side(tmp_path, 'a'), Side(tmp_path, 'b'), Side(tmp_path, 'c')
    shared = transport_for([a, b, c])
    for s in (a, b, c):
        s.runtime['transport'] = shared
    with at_db(a):
        code1, _ = federation.create_pairing_code(URL['a'])
    with at_db(b):
        federation.join(code1, URL['b'], 'site-b')
    with at_db(a):
        code2, _ = federation.create_pairing_code(URL['a'])
    with at_db(c):
        federation.join(code2, URL['c'], 'site-c')
    return a, b, c


def test_a_cluster_without_a_lease_is_this_instances_own(sides):
    a, b = sides
    _add_cluster(a, 'c-local')
    with at_db(a):
        assert federation.cluster_owner('c-local') == ''
        assert federation.takes_writes_for('c-local') is True
        # a row that is not there is nobody's to gate
        assert federation.takes_writes_for('c-missing') is True


def test_enroll_gives_the_lease_and_the_gate(tmp_path):
    a, b, c = _three(tmp_path)
    _add_cluster(a, 'c1')
    with at_db(a):
        lease = federation.enroll_cluster('c1')
        assert lease.get('term') == 1
        assert lease['votes'] >= 2  # majority of three
        assert federation.cluster_owner('c1') == federation.instance_id()
        assert federation.takes_writes_for('c1') is True
    # another member sees the cluster as foreign - but only where the row exists
    with at_db(a):
        conn = _db_of(a).conn
        conn.execute("UPDATE clusters SET fed_owner = ? WHERE id = 'c1'",
                     (federation_ref_id(b),))
        conn.commit()
        assert federation.takes_writes_for('c1') is False


def test_a_lease_runs_out_and_the_gate_closes(tmp_path):
    a, b, c = _three(tmp_path)
    _add_cluster(a, 'c2')
    with at_db(a):
        federation.enroll_cluster('c2')
        assert federation.takes_writes_for('c2') is True
        # time travel: the lease as it was a minute ago
        def age(state):
            rec = state.get('my_leases', {}).get('c2')
            if rec:
                rec['expires'] = federation._lease_now() - 60
                return True
            return False
        federation._mutate(age)
        assert federation.takes_writes_for('c2') is False


def test_a_renewal_extends_the_lease(tmp_path):
    a, b, c = _three(tmp_path)
    _add_cluster(a, 'c3')
    with at_db(a):
        federation.enroll_cluster('c3')
        before = federation.my_leases()['c3']['expires']
        report = federation.renew_leases()
        assert report['c3']['renewed'] is True
        assert federation.my_leases()['c3']['expires'] > before


def test_a_new_candidate_waits_for_the_old_lease(tmp_path):
    """The split-brain rule: a voter grants a higher term only once the promise
    has run out (plus the skew) - the old writer stops at its margin, the new one
    starts past the end, and the two never meet."""
    a, b, c = _three(tmp_path)
    a_id, b_id = federation_ref_id(a), federation_ref_id(b)
    _add_cluster(a, 'c4')
    with at_db(a):
        federation.enroll_cluster('c4')
    # b asks for the same cluster while a's lease stands: refused
    with at_db(b):
        out = federation.acquire_lease('c4')
        assert out.get('failed')
    # time travel at every voter: the promise is long over
    for s in (a, b, c):
        with at_db(s):
            def expire(state):
                for rec in (state.get('lease_promises') or {}).values():
                    rec['until'] = federation._lease_now() - 60
                return True
            federation._mutate(expire)
    with at_db(b):
        out = federation.acquire_lease('c4')
        assert not out.get('failed'), out
        assert out['term'] >= 2
        assert federation.takes_writes_for('c4') is True
    # and a's renewal at the old term fails now: its gate closes at its own clock
    with at_db(a):
        report = federation.renew_leases()
        assert report['c4']['renewed'] is False


def test_a_release_keeps_the_gate_shut_until_unenrolled(tmp_path):
    """A release hands the LEASE over, not the cluster: the row stays enrolled and
    this instance writes nothing more on it (an owner without a lease is out),
    until an unenroll says the row is this instance's alone again."""
    a, b, c = _three(tmp_path)
    _add_cluster(a, 'c5')
    with at_db(a):
        federation.enroll_cluster('c5')
        federation.release_lease('c5')
        assert federation.cluster_owner('c5') == federation.instance_id()
        assert federation.takes_writes_for('c5') is False
        federation.unenroll_cluster('c5')
        assert federation.cluster_owner('c5') == ''
        assert federation.takes_writes_for('c5') is True
    with at_db(b):
        out = federation.acquire_lease('c5')
        assert not out.get('failed'), out


def test_a_member_asks_for_its_own_lease_alone(tmp_path):
    a, b, c = _three(tmp_path)
    a_id = federation_ref_id(a)
    with at_db(a):
        # b cannot ask a to promise a's lease to b: the sender is the candidate
        verdict = federation.lease_vote(federation_ref_id(b),
                                        {'cluster_id': 'c6',
                                         'candidate': a_id, 'term': 1,
                                         'lease_s': 30})
        assert verdict.get('granted') is False
        # junk is junk
        for bad in ({'cluster_id': 'x y!', 'candidate': a_id, 'term': 1},
                    {'cluster_id': 'c6', 'candidate': 'nothex', 'term': 1},
                    {'cluster_id': 'c6', 'candidate': a_id, 'term': 0}):
            v = federation.lease_vote(a_id, {**bad, 'lease_s': 30})
            assert v.get('granted') is False


def test_the_vote_lands_on_disk_before_the_grant(tmp_path):
    a, b, c = _three(tmp_path)
    a_id = federation_ref_id(a)
    with at_db(a):
        # the first word on a cluster is term 1 - a term may only step by one
        verdict = federation.lease_vote(a_id, {'cluster_id': 'c7',
                                               'candidate': a_id, 'term': 4,
                                               'lease_s': 30})
        assert verdict.get('granted') is False
        verdict = federation.lease_vote(a_id, {'cluster_id': 'c7',
                                               'candidate': a_id, 'term': 1,
                                               'lease_s': 30})
        assert verdict.get('granted')
        # the promise is in the state file, not just in the answer
        state = federation._load()
        promised = state['lease_promises']['c7']
        assert promised['term'] == 1 and promised['candidate'] == a_id
        # and a second grant at the same term for another candidate is refused
        v2 = federation.lease_vote(federation_ref_id(b),
                                   {'cluster_id': 'c7',
                                    'candidate': federation_ref_id(b),
                                    'term': 1, 'lease_s': 30})
        assert v2.get('granted') is False
