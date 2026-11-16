"""The federation of PegaProx instances: pairing, the agreed member view, signed calls and
signed answers, field keys, leases, ownership and adoption, the HA group as one member,
the outbound transport and the linked view.

Several instances live in one process, as the HA group tests do it: each side holds its
own database (the identity row lives there), its own lease file and its own runtime
slot, and at(side) makes one of them the instance the core acts for. The transport the
core calls out on is a stand-in that routes a call into the Flask test client of the side
the address names, with that side active while it answers. The core signs the request
and checks the signature on the answer as it does on the wire, so the tests exercise both.

A member's rounds ask the others side by side (federation._parallel). The stand-in is not
thread-safe - it swaps the process-wide runtime and database - so each call holds a lock
for its whole length, and a call made while answering another (a pairing that takes the
members lock) holds a lock of its own level: the caller waits in the pool while the
workers take turns, and nothing waits on itself.

The lease clock is a stand-in where a test needs time to pass (clock fixture); the
signatures go by the wall clock as on the wire.

MK Nov 2026
"""
import base64
import contextlib
import contextvars
import io
import json
import os
import secrets
import threading
import time
from unittest.mock import MagicMock

import pytest

from pegaprox.core import federation, ha_wire
from pegaprox.core import federation_lease as fl

STATUS = '/api/federation/peer/status'
JOIN = '/api/federation/peer/join'
URL = {n: f'https://{n}.example:5000' for n in 'abcdefgh'}
FP1 = ':'.join(['AB'] * 32)
FP2 = ':'.join(['CD'] * 32)


class Side:
    """One instance: its database, its lease file, its runtime slot and a Flask app with
    nothing but the federation blueprint."""

    def __init__(self, tmp, name):
        self.name = name
        self.dir = tmp / f'side-{name}'
        self.dir.mkdir(exist_ok=True)
        self.lease_file = str(self.dir / 'federation_leases.json')
        self.runtime = federation._fresh_runtime(self.lease_file)
        self.db = None
        self.wire = None
        from flask import Flask
        from pegaprox.api import federation as api_fed
        self.app = Flask(f'side-{name}')
        self.app.config['TESTING'] = True
        self.app.register_blueprint(api_fed.bp)
        self.client = self.app.test_client()


def _db_of(side, key_from=None):
    """A side's own database with its own database key (or `key_from`'s: an HA standby
    holds its active's)."""
    if side.db is None:
        from pegaprox.core import db as db_mod
        keys = side.dir / 'keys'
        keys.mkdir(exist_ok=True)
        key_file = keys / '.pegaprox_aes256.key'
        if key_from is not None:
            key_file.write_bytes((key_from.dir / 'keys' / '.pegaprox_aes256.key').read_bytes())
        elif not key_file.exists():
            key_file.write_bytes(os.urandom(32))
        old = (db_mod.DATABASE_FILE, db_mod.CONFIG_DIR, db_mod._db, db_mod.PegaProxDB._instance)
        db_mod.DATABASE_FILE = str(side.dir / 'pegaprox.db')
        db_mod.CONFIG_DIR = str(keys)
        db_mod._db = None
        db_mod.PegaProxDB._instance = None
        try:
            side.db = db_mod.get_db()
        finally:
            (db_mod.DATABASE_FILE, db_mod.CONFIG_DIR, db_mod._db,
             db_mod.PegaProxDB._instance) = old
    return side.db


@contextlib.contextmanager
def at(side):
    """Make `side` the instance the core acts for: its runtime and its database. What the
    side's runtime gathered comes back with it when the context ends."""
    from pegaprox.core import db as db_mod
    _db_of(side)
    saved_rt, saved_db = dict(federation._runtime), db_mod._db
    federation._runtime.clear()
    federation._runtime.update(side.runtime)
    db_mod._db = side.db
    try:
        yield side
    finally:
        side.runtime.clear()
        side.runtime.update(federation._runtime)
        federation._runtime.clear()
        federation._runtime.update(saved_rt)
        db_mod._db = saved_db


at_db = at

_ROOT = threading.RLock()
_LEVEL = contextvars.ContextVar('fed_test_level', default=None)


def transport_for(sides, calls=None):
    """The stand-in for the network. `calls`, when given, collects (url, method, path)."""
    by_url = {URL[s.name]: s for s in sides}

    def transport(url, method, path, body, headers):
        target = by_url.get(url)
        if target is None:
            return 0, b'', {}
        lock = _LEVEL.get() or _ROOT
        with lock:
            token = _LEVEL.set(threading.RLock())
            try:
                if calls is not None:
                    calls.append((url, method, path))
                with at(target):
                    resp = target.client.open(path, method=method, data=body, headers=headers)
                return resp.status_code, resp.get_data(), dict(resp.headers)
            finally:
                _LEVEL.reset(token)
    return transport


def _wire(sides, calls=None):
    t = transport_for(sides, calls)
    for s in sides:
        s.wire = t
        s.runtime['transport'] = t
    return t


def _without(inner, *urls):
    def transport(url, method, path, body, headers):
        if url in urls:
            return 0, b'', {}
        return inner(url, method, path, body, headers)
    return transport


def _cut(sides, victim):
    """`victim` is cut off from the others, both ways."""
    for s in sides:
        if s is victim:
            s.runtime['transport'] = lambda *a: (0, b'', {})
        else:
            s.runtime['transport'] = _without(s.wire, URL[victim.name])


def _heal(sides):
    for s in sides:
        s.runtime['transport'] = s.wire


def _restart(side):
    """The process of `side` restarts: everything in memory is gone, the files and the
    database stay."""
    keep = side.runtime.get('transport')
    side.runtime.clear()
    side.runtime.update(federation._fresh_runtime(side.lease_file))
    side.runtime['transport'] = keep


def _reboot(side, monkeypatch, boot='rebooted-boot-id'):
    """The host of `side` rebooted: a restart with another kernel boot id."""
    from pegaprox.core import ha_vote
    monkeypatch.setattr(ha_vote, 'read_boot_id', lambda: boot)
    _restart(side)


class Clock:
    def __init__(self, t):
        self.t = float(t)

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t += seconds


@pytest.fixture
def clock(monkeypatch):
    c = Clock(fl._lease_now())
    monkeypatch.setattr(fl, '_lease_now', c)
    return c


@pytest.fixture(autouse=True)
def _fresh_budgets(monkeypatch):
    """The pairing, peer and vote budgets are per process and every test here calls from
    the one address of the test client. The windows of the process come back afterwards."""
    from pegaprox.utils.ratelimit import SlidingWindow
    from pegaprox.api import federation as api_fed
    for name, limit, window in (('_pair_attempts', 5, 300), ('_peer_failures', 10, 300),
                                ('_lease_votes', 10000, 30), ('_lease_ticks', 10000, 30),
                                ('_lease_returns', 10000, 30)):
        monkeypatch.setattr(api_fed, name, SlidingWindow(
            limit=limit, window=window, max_keys=2048 if window == 300 else 256,
            name=f'fed{name}-test'))
    yield


@pytest.fixture(autouse=True)
def _defaults_out_of_the_config_dir(tmp_path, monkeypatch):
    """Nothing a test here does may reach the config directory the process started with:
    the default database moves into this test's tmp dir (a side swaps its own in on top),
    and the federation is switched on by the environment."""
    monkeypatch.setenv(federation.ENV_SWITCH, '1')
    import pegaprox.constants as constants
    import pegaprox.core.db as db_mod
    import pegaprox.core.dbcrypto as dbcrypto
    from pegaprox.background import metrics_store
    cfg = tmp_path / 'config'
    cfg.mkdir()
    saved = (db_mod.CONFIG_DIR, db_mod.DATABASE_FILE, db_mod.KEY_FILE,
             constants.DATABASE_FILE)
    db_mod.CONFIG_DIR = str(cfg)
    db_mod.DATABASE_FILE = str(cfg / 'pegaprox.db')
    db_mod.KEY_FILE = str(cfg / '.pegaprox.key')
    constants.DATABASE_FILE = db_mod.DATABASE_FILE
    db_mod._db = None
    db_mod.PegaProxDB._instance = None
    dbcrypto._HEAVY_CACHE.clear()
    metrics_store.forget()
    yield
    db_mod._db = None
    db_mod.PegaProxDB._instance = None
    db_mod.CONFIG_DIR, db_mod.DATABASE_FILE, db_mod.KEY_FILE, \
        constants.DATABASE_FILE = saved
    dbcrypto._HEAVY_CACHE.clear()
    metrics_store.forget()


def iid(side):
    with at(side):
        return federation.ensure_identity()


def _code(issuer):
    with at(issuer):
        federation.set_own_site(f'site-{issuer.name}')
        code, _ = federation.create_pairing_code(URL[issuer.name])
    return code


def _join(joiner, code):
    with at(joiner):
        return federation.join(code, URL[joiner.name], f'site-{joiner.name}')


def _sides(tmp, names='ab', calls=None):
    """Sides that paired one after another through the first, a while ago: the settle
    span of those joins is over everywhere (_settled)."""
    out = [Side(tmp, n) for n in names]
    _wire(out, calls)
    for s in out[1:]:
        _join(s, _code(out[0]))
    for s in out:
        _settled(s)
    return out


def _settled(side):
    """The settle span of the last view change `side` took is over, as it is a while
    after a pairing: a voter grants no cluster ask for SETTLE_SECONDS after a change of
    the view. A test that changes the view itself waits that out with the clock."""
    def go(st):
        st['view_changed'] = 0.0
        return True
    with at(side):
        federation._mutate_leases(go)


@pytest.fixture
def sides(tmp_path):
    out = [Side(tmp_path, 'a'), Side(tmp_path, 'b')]
    _wire(out)
    return out


@pytest.fixture
def paired(tmp_path):
    a, b = _sides(tmp_path, 'ab')
    return a, b


def _three(tmp):
    return _sides(tmp, 'abc')


def some_key():
    return ha_wire.public_of(ha_wire.private_key(ha_wire.new_signing_key()))


def _post(side, path, body=None, headers=None, query=''):
    headers = dict(headers or {'X-Requested-With': 'XMLHttpRequest'})
    data = ha_wire.wire_body(body) if body is not None else None
    if data is not None:
        headers.setdefault('Content-Type', 'application/json')
    with at(side):
        return side.client.open(path + query, method='POST', data=data, headers=headers)


def _get(side, path, headers=None, query=''):
    with at(side):
        return side.client.open(path + query, method='GET', headers=headers or {})


def _signed_headers_of(side, receiver_id, method='GET', path=STATUS, body=None,
                       ts=None, nonce=None, domain='fed'):
    body = ha_wire.wire_body(body) if body is not None else b''
    with at(side):
        sender = federation.instance_id()
        private = federation.signing_key()
    ts = str(int(time.time()) if ts is None else ts)
    nonce = nonce or secrets.token_urlsafe(18)
    digest = ha_wire.body_digest(body)
    if domain == 'fed':
        to_sign = federation._to_sign(method, path, body, ts, nonce, receiver_id, sender, digest)
    else:
        to_sign = ha_wire.to_sign(method, path, body, ts, nonce, receiver_id, sender, digest)
    return {ha_wire.PEER_HEADER: sender, ha_wire.PEER_TS_HEADER: ts,
            ha_wire.PEER_NONCE_HEADER: nonce,
            ha_wire.PEER_SIG_HEADER: base64.b64encode(private.sign(to_sign)).decode(),
            ha_wire.PEER_BODY_HEADER: digest, 'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest'}


def _add_cluster(side, cid, name=None, owner='', password=None, ctype='proxmox'):
    db = _db_of(side)
    db.conn.execute("INSERT OR REPLACE INTO clusters (id, name, host, user, pass_encrypted, "
                    "fed_owner, cluster_type) VALUES (?, ?, 'h', 'u', ?, ?, ?)",
                    (cid, name or cid, db._encrypt(password) if password else '', owner, ctype))
    db.conn.commit()
    with at(side):
        fl.drop_owner_cache()


def _owner_at(side, cid):
    row = _db_of(side).conn.execute('SELECT fed_owner FROM clusters WHERE id = ?',
                                    (cid,)).fetchone()
    return None if row is None else row['fed_owner']


def _enroll(side, cid, password=None):
    _add_cluster(side, cid, password=password)
    with at(side):
        return fl.enroll_cluster(cid)


def _sync(*sides_):
    """A sync round of each side. The members' snapshot etags are cached for a few
    seconds; a test does in a moment what takes the loop a minute, so the cache goes."""
    from pegaprox.api import federation as api_fed
    for s in sides_:
        api_fed._etag_cache['etag'] = ''
        with at(s):
            federation.sync_identities()


def _writes(side, cid):
    with at(side):
        return federation.takes_writes_for(cid)


def _view(side):
    with at(side):
        return federation.view_epoch(), federation.view_digest(), sorted(federation.members())


# --- the identity and the switch -----------------------------------------------------------

def test_the_identity_lives_in_the_database(sides):
    a, _ = sides
    with at(a):
        assert federation.instance_id() == ''        # a read never makes one
        first = federation.ensure_identity()
        assert federation.ensure_identity() == first
        key = federation.public_key()
        row = _db_of(a).conn.execute(
            "SELECT v FROM pegaprox_kv WHERE k = 'federation_identity'").fetchone()
        ident = json.loads(row[0])
        assert ident['instance_id'] == first
        # the secrets are sealed under the database key, never in the clear
        assert ident['signing_key'].startswith('aes256:')
        assert ident['field_key'].startswith('aes256:')
    # a restart reads it back from the database, the same identity
    _restart(a)
    with at(a):
        assert federation.instance_id() == first and federation.public_key() == key


def test_an_ha_standby_never_makes_an_identity(sides, monkeypatch):
    from pegaprox.core import ha
    a, _ = sides
    monkeypatch.setattr(ha, 'is_standby', lambda: True)
    with at(a):
        assert federation.ensure_identity() == ''
        assert federation.identity() is None


def test_a_key_rotation_keeps_the_federation_identity(tmp_path, monkeypatch):
    import pegaprox.core.db as db_mod
    a, b, c = _three(tmp_path)
    _enroll(a, 'pve-r', password='rot-secret')
    _sync(b)
    monkeypatch.setattr(db_mod, 'CONFIG_DIR', str(b.dir / 'keys'))
    with at(b):
        before = federation.instance_id()
        db = _db_of(b)
        old_ct = federation.identity()['signing_key']
        stats = db.rotate_encryption_key()
        assert not [e for e in stats['errors'] if 'ederation' in e], stats['errors']
        federation._runtime['identity'] = None
        federation._runtime['signer'] = None
        federation._runtime['fkeys'] = {}
        assert federation.instance_id() == before
        # resealed under the new key, not left behind
        assert federation.identity()['signing_key'] != old_ct
        # the key still signs: a member call goes through
        status, body, _h = federation.call_peer(iid(a), 'GET', STATUS)
        assert status == 200 and body['instance_id'] == iid(a)
        # and the field key of the owner still opens a mirror value
        value = db.conn.execute("SELECT pass_encrypted FROM clusters WHERE id = 'pve-r'").fetchone()[0]
        assert federation.unwrap_credential(value, iid(a), 'pve-r', 'pass_encrypted') == 'rot-secret'


# --- pairing --------------------------------------------------------------------------

def test_a_pairing_code_carries_a_url_and_an_id(sides):
    a, _ = sides
    code = _code(a)
    parts = ha_wire.decode_code(federation.CODE_PREFIX, code)
    assert parts['url'] == URL['a'] and parts['instance_id'] == iid(a)


def test_a_pairing_code_carries_the_issuers_fingerprint(sides, monkeypatch):
    a, _ = sides
    monkeypatch.setattr(federation, '_fp_provider', {'fn': lambda: [FP1, FP2]})
    parts = ha_wire.decode_code(federation.CODE_PREFIX, _code(a))
    assert parts['fingerprint'] == FP1
    with at(a):
        assert federation.identity()['self']['fingerprints'] == [FP1, FP2]


def test_the_joiner_fingerprint_is_kept_by_the_issuer(sides, monkeypatch):
    a, b = sides
    code = _code(a)
    monkeypatch.setattr(federation, '_fp_provider', {'fn': lambda: [FP2]})
    _join(b, code)
    with at(a):
        assert federation.members()[iid(b)]['fingerprints'] == [FP2]


def test_a_code_expires(sides):
    a, b = sides
    code = _code(a)
    with at(a):
        def age(st):
            st['pairing']['expires'] = int(time.time()) - 1
            return True
        federation._mutate_leases(age)
    with pytest.raises(federation.FederationError):
        _join(b, code)


def test_a_join_pairs_both_sides(paired):
    a, b = paired
    assert _view(a) == (1, _view(b)[1], [iid(b)])
    assert _view(b)[0] == 1 and _view(b)[2] == [iid(a)]
    with at(a):
        assert federation.members()[iid(b)]['site'] == 'site-b'
        assert federation.members()[iid(b)]['url'] == URL['b']
    with at(b):
        assert federation.members()[iid(a)]['site'] == 'site-a'


def test_three_instances_hold_one_view(tmp_path):
    a, b, c = _three(tmp_path)
    epochs = {_view(s)[0] for s in (a, b, c)}
    digests = {_view(s)[1] for s in (a, b, c)}
    assert epochs == {2} and len(digests) == 1
    with at(b):
        assert sorted(federation.members()) == sorted([iid(a), iid(c)])


def test_a_code_is_spent_by_the_join(paired):
    a, b = paired
    code = _code(a)
    body = {'code': code, 'url': URL['c'], 'instance_id': 'c' * 32,
            'public_key': some_key(), 'site': ''}
    # a view of two takes a third only with both: b answers, so it goes in
    r = _post(a, JOIN, body)
    assert r.status_code == 200, r.data
    body['instance_id'] = 'd' * 32
    r = _post(a, JOIN, body)
    assert r.status_code == 403


def test_the_view_answer_opens_under_the_code_secret_only(sides):
    a, b = sides
    code = _code(a)
    parts = ha_wire.decode_code(federation.CODE_PREFIX, code)
    body = {'code': code, 'url': URL['b'], 'instance_id': iid(b),
            'public_key': some_key(), 'site': 'site-b'}
    r = _post(a, JOIN, body)
    assert r.status_code == 200, r.data
    sealed = r.get_json()['sealed']
    opened = ha_wire.unseal(parts['secret'], sealed,
                            f'federation-join:{parts["instance_id"]}:{iid(b)}')
    assert parts['instance_id'] in opened['view']['members']
    # no field key travels with the view any more, and certainly no database key
    assert 'field_keys' not in opened and 'field_key' not in json.dumps(opened)
    with pytest.raises(Exception):
        ha_wire.unseal('f' * 64, sealed, 'federation-join:x:y')


def test_a_member_cannot_pair_with_itself_or_with_a_junk_key(sides):
    a, _ = sides
    code = _code(a)
    with at(a):
        with pytest.raises(federation.FederationError):
            federation.accept_join(code, URL['a'], federation.instance_id(), some_key(), '')
    junk = base64.b64encode(b'\x00' * 32).decode()
    r = _post(a, JOIN, {'code': code, 'url': URL['b'], 'instance_id': 'e' * 32,
                        'public_key': junk, 'site': ''})
    assert r.status_code == 403 and 'public key' in r.get_json()['error']


def test_a_member_cannot_join_another_federation(tmp_path):
    a, b = _sides(tmp_path, 'ab')
    c = Side(tmp_path, 'c')
    _wire([a, b, c])
    with pytest.raises(federation.FederationError) as err:
        _join(b, _code(c))
    assert err.value.code == 'FED_ALREADY_MEMBER'


def test_a_full_federation_offers_no_code(paired):
    a, _ = paired

    def fill(ident):
        for i in range(federation.MAX_SITES - 2):
            ident['view']['members'][f'{i:032x}'] = {'url': f'https://m{i}.example:5000',
                                                     'public_key': some_key(), 'site': '',
                                                     'fingerprints': []}
        return True
    with at(a):
        federation._mutate_identity(fill)
        assert len(federation.members()) == federation.MAX_SITES - 1
        with pytest.raises(federation.FederationError) as err:
            federation.create_pairing_code(URL['a'])
    assert err.value.code == 'FED_FULL'


def test_a_join_needs_a_majority_and_keeps_the_code_open(tmp_path):
    a, b = _sides(tmp_path, 'ab')
    c = Side(tmp_path, 'c')
    _wire([a, b, c])
    code = _code(a)
    a.runtime['transport'] = _without(a.wire, URL['b'])
    with pytest.raises(federation.FederationError) as err:
        _join(c, code)
    assert err.value.code == 'FED_NO_QUORUM'
    assert _view(a)[2] == [iid(b)]
    with at(a):
        assert federation.pairing_open() is not None
    # b answers again: the same code pairs c
    a.runtime['transport'] = a.wire
    with at(c):
        federation._runtime['identity'] = None
    _join(c, code)
    assert sorted(_view(a)[2]) == sorted([iid(b), iid(c)])


def test_the_join_endpoint_has_a_budget(paired, monkeypatch):
    from pegaprox.utils.ratelimit import SlidingWindow
    from pegaprox.api import federation as api_fed
    monkeypatch.setattr(api_fed, '_pair_attempts',
                        SlidingWindow(limit=5, window=300, max_keys=2048, name='fed-pair-b'))
    a = paired[0]
    body = {'code': 'pgxfd1_junk', 'url': URL['b'], 'instance_id': '0' * 32,
            'public_key': some_key(), 'site': ''}
    for _ in range(5):
        assert _post(a, JOIN, body).status_code == 403
    r = _post(a, JOIN, body)
    assert r.status_code == 429 and r.headers.get('Retry-After') == '300'


# --- signed calls and signed answers --------------------------------------------------------

def test_a_signed_status_call_is_taken(paired):
    a, b = paired
    with at(b):
        status, body, headers = federation.call_peer(iid(a), 'GET', STATUS)
    assert status == 200 and body['instance_id'] == iid(a)
    assert body['fed'] == federation.FED_MARK and body['site'] == 'site-a'
    assert body['view']['epoch'] == 1 and federation.ANSWER_HEADER in headers
    # the visit is noted in memory, not written anywhere
    with at(a):
        assert federation._runtime['seen'][iid(b)] > 0


def test_an_answer_without_its_signature_is_no_answer(paired):
    a, b = paired

    def strip(url, method, path, body, headers):
        status, raw, h = b.wire(url, method, path, body, headers)
        return status, raw, {k: v for k, v in h.items() if k != federation.ANSWER_HEADER}
    b.runtime['transport'] = strip
    with at(b):
        assert federation.call_peer(iid(a), 'GET', STATUS) == (0, None, {})


def test_an_old_answer_does_not_replay(paired):
    """An answer is bound to the nonce of the request it answers: the answer to one call
    is worthless for the next, however good its signature."""
    a, b = paired
    held = {}

    def replay(url, method, path, body, headers):
        if 'answer' not in held:
            held['answer'] = b.wire(url, method, path, body, headers)
        return held['answer']
    b.runtime['transport'] = replay
    with at(b):
        assert federation.call_peer(iid(a), 'GET', STATUS)[0] == 200
        assert federation.call_peer(iid(a), 'GET', STATUS)[0] == 0


def test_a_call_without_headers_is_nobody(paired):
    r = _get(paired[0], STATUS)
    assert r.status_code == 403 and r.get_json()['code'] == 'FED_NOT_MEMBER'


def test_a_replayed_call_is_refused(paired):
    a, b = paired
    headers = _signed_headers_of(b, iid(a))
    assert _get(a, STATUS, headers).status_code == 200
    assert _get(a, STATUS, headers).status_code == 403
    again = _signed_headers_of(b, iid(a), nonce=headers[ha_wire.PEER_NONCE_HEADER])
    assert _get(a, STATUS, again).status_code == 403


def test_a_call_signed_for_another_member_or_domain_is_refused(paired):
    a, b = paired
    assert _get(a, STATUS, _signed_headers_of(b, 'f' * 32)).status_code == 403
    assert _get(a, STATUS, _signed_headers_of(b, iid(a), domain='ha')).status_code == 403


def test_a_call_outside_the_window_is_told_about_its_clock(paired):
    a, b = paired
    r = _get(a, STATUS, _signed_headers_of(b, iid(a), ts=int(time.time()) - 3600))
    assert r.status_code == 403 and r.get_json()['clock'] == 'window'


def test_an_early_call_is_told_what_it_is(paired):
    a, b = paired
    early = _signed_headers_of(b, iid(a), ts=int(time.time()) - 30)
    a.runtime['started'] = time.time() + 1800
    r = _get(a, STATUS, early)
    assert r.status_code == 403 and r.get_json()['clock'] == 'early'


def test_a_tampered_body_or_a_query_string_is_refused(paired):
    a, b = paired
    path = federation.MEMBER_UPDATE_PATH
    headers = _signed_headers_of(b, iid(a), method='POST', path=path, body={'url': URL['b']})
    r = _post(a, path, {'url': 'https://evil.example:5000'}, headers)
    assert r.status_code == 403
    r = _get(a, STATUS, _signed_headers_of(b, iid(a)), query='?x=1')
    assert r.status_code == 403


def test_the_old_member_routes_are_gone(paired):
    a, b = paired
    for path in ('/api/federation/peer/member-added', '/api/federation/peer/member-removed',
                 '/api/federation/peer/left'):
        headers = _signed_headers_of(b, iid(a), method='POST', path=path, body={})
        assert _post(a, path, {}, headers).status_code == 404, path


# --- the agreed view ----------------------------------------------------------------------------

def test_a_member_cannot_add_members_on_its_own(tmp_path):
    """A membership commit is taken only from the member this instance granted the members
    lock, and only with the signed grants of a majority of the view: a member that pushes
    one without them gets 409 FED_NO_LOCK."""
    a, b, c = _three(tmp_path)
    with at(b):
        base, epoch = federation.view_digest(), federation.view_epoch()
    rec = {'url': URL['d'], 'public_key': some_key(), 'site': 'd', 'fingerprints': []}
    with at(b):
        entries = federation._view_entries(federation.identity())
    entries['d' * 32] = rec['public_key']
    commit = {'epoch': epoch + 1, 'base': base, 'digest': federation._digest(entries),
              'change': {'op': 'add', 'instance_id': 'd' * 32, **rec}, 'by': iid(c)}
    with at(c):
        commit['sig'] = federation._sign_commit(commit['epoch'], base, commit['digest'],
                                                federation._wire_change(commit['change']))
        status, body, _h = federation.call_peer(iid(b), 'POST', federation.MEMBERSHIP_PATH,
                                                commit)
    assert status == 409 and body['code'] == 'FED_NO_LOCK'
    assert 'd' * 32 not in _view(b)[2]
    # counterproof: with b's promise for the lock naming c, the same commit goes in
    with at(b):
        def promise(st):
            st['promises'][federation.MEMBERS_LOCK] = {'candidate': iid(c),
                                                       'until': fl._lease_now() + 30,
                                                       'released': False}
            return True
        federation._mutate_leases(promise)
    # b's own promise alone is not enough: one ask would get it, so the commit must carry
    # the grants of a majority, each signed by its voter
    with at(c):
        status, body, _h = federation.call_peer(iid(b), 'POST', federation.MEMBERSHIP_PATH,
                                                commit)
    assert status == 409 and body['code'] == 'FED_NO_LOCK', body
    assert 'd' * 32 not in _view(b)[2]
    certs = {}
    for voter in (b, c):
        with at(voter):
            certs[iid(voter)] = federation.lock_cert(iid(c), base, epoch)
    with at(c):
        status, body, _h = federation.call_peer(iid(b), 'POST', federation.MEMBERSHIP_PATH,
                                                dict(commit, certs=certs))
    assert status == 200, body
    assert 'd' * 32 in _view(b)[2]


def test_a_commit_may_change_one_member_only(tmp_path):
    a, b, c = _three(tmp_path)
    with at(b):
        def promise(st):
            st['promises'][federation.MEMBERS_LOCK] = {'candidate': iid(c),
                                                       'until': fl._lease_now() + 30,
                                                       'released': False}
            return True
        federation._mutate_leases(promise)
        base, epoch = federation.view_digest(), federation.view_epoch()
        entries = federation._view_entries(federation.identity())
    rec = {'url': URL['d'], 'public_key': some_key(), 'site': 'd', 'fingerprints': []}
    good = dict(entries, **{'d' * 32: rec['public_key']})
    two = dict(good, **{'e' * 32: some_key()})
    for commit in ({'epoch': epoch + 2, 'base': base, 'digest': federation._digest(good)},
                   {'epoch': epoch + 1, 'base': 'f' * 32, 'digest': federation._digest(good)},
                   {'epoch': epoch + 1, 'base': base, 'digest': federation._digest(two)}):
        commit['change'] = {'op': 'add', 'instance_id': 'd' * 32, **rec}
        commit['by'] = iid(c)
        with at(c):
            status, body, _h = federation.call_peer(iid(b), 'POST',
                                                    federation.MEMBERSHIP_PATH, commit)
        assert status == 409 and body['code'] == 'FED_VIEW', commit
    assert 'd' * 32 not in _view(b)[2]


def test_a_removal_reaches_every_member_and_the_remover_keeps_its_leases(tmp_path, clock):
    a, b, c, d = _sides(tmp_path, 'abcd')
    _enroll(a, 'pve-1')
    with at(a):
        out = federation.remove_member(iid(d), by='admin:test')
    assert out['not_told'] == [] and out['removed'] == iid(d)
    assert out['remedy']['enrolled_here'] == ['pve-1']
    for s in (a, b, c):
        assert iid(d) not in _view(s)[2]
        with at(s):
            assert iid(d) in federation.tombstones()
    assert {_view(s)[1] for s in (a, b, c)} == {_view(a)[1]}
    # d was told and wiped itself
    with at(d):
        assert federation.members() == {}
        assert federation.identity()['removed']['by'] == iid(a)
    # the lease a held before the removal still runs; the voters back no cluster ask for
    # the settle span of the change, then a renews with two of the three that are left
    assert _writes(a, 'pve-1') is True
    with at(a):
        r = fl.lease_round()
    assert r['pve-1']['held'] is False and r['pve-1']['refusals'] == {'settling': 3}
    clock.advance(fl.SETTLE_SECONDS + 1)
    with at(a):
        r = fl.lease_round()
    assert r['pve-1']['held'] is True and r['pve-1']['needed'] == 2


def test_a_removal_lowers_the_majority(tmp_path, clock):
    a, b, c, d, e = _sides(tmp_path, 'abcde')
    _enroll(a, 'pve-5')
    with at(a):
        federation.remove_member(iid(d), by='admin:test')
        federation.remove_member(iid(e), by='admin:test')
    _cut([a, b, c, d, e], c)
    # inside the settle span of the two removals even a renewal waits: a lease counted
    # two changes back may still run, and a majority of {a, b, c} need not share a voter
    # with it
    clock.advance(20)
    with at(a):
        r = fl.lease_round()
    assert r['pve-5']['held'] is False and r['pve-5']['refusals'] == {'settling': 2, 'down': 1}
    clock.advance(fl.SETTLE_SECONDS - 20 + 1)
    with at(a):
        r = fl.lease_round()
    assert r['pve-5']['held'] is True and r['pve-5']['votes'] == 2
    assert r['pve-5']['needed'] == 2


def test_a_cut_off_member_can_neither_shrink_nor_adopt(tmp_path, clock):
    a, b, c = _three(tmp_path)
    _enroll(b, 'pve-b')
    _sync(a, c)
    _cut([a, b, c], a)
    with at(a):
        for victim in (b, c):
            with pytest.raises(federation.FederationError) as err:
                federation.remove_member(iid(victim), by='admin:test')
            assert err.value.code == 'FED_NO_QUORUM'
    clock.advance(60)
    with at(b):
        fl.lease_round()
    with at(a):
        with pytest.raises(federation.FederationError):
            fl.adopt_cluster('pve-b')
    assert _view(a)[2] == sorted([iid(b), iid(c)])
    assert _writes(b, 'pve-b') is True
    assert _writes(a, 'pve-b') is False and _writes(c, 'pve-b') is False


def test_a_member_behind_catches_up(tmp_path):
    a, b, c = _three(tmp_path)
    d = Side(tmp_path, 'd')
    _wire([a, b, c, d])
    # c misses the commit of d's join
    a.runtime['transport'] = _without(a.wire, URL['c'])
    b.runtime['transport'] = _without(b.wire, URL['c'])
    _join(d, _code(a))
    assert iid(d) not in _view(c)[2]
    a.runtime['transport'], b.runtime['transport'] = a.wire, b.wire
    with at(c):
        out = federation.catch_up()
    assert out['adopted'] is True
    assert _view(c) == _view(c)[:1] + _view(c)[1:] and iid(d) in _view(c)[2]
    assert _view(c)[1] == _view(a)[1]


def test_a_removed_member_that_missed_it_lets_go(tmp_path):
    a, b, c = _three(tmp_path)
    _cut([a, b, c], c)
    with at(a):
        federation.remove_member(iid(c), by='admin:test')
    _heal([a, b, c])
    # every member answers c with 410 now; a majority of them makes c let go
    with at(c):
        federation.catch_up()
        assert sorted(federation.removed_by_some()) == sorted([iid(a), iid(b)])
        assert federation._check_removed_by() is True
        assert federation.members() == {}
        assert federation.identity()['removed'] is not None


def test_leaving_drops_every_mirror_and_key(tmp_path):
    a, b, c = _three(tmp_path)
    _enroll(a, 'pve-l', password='l-secret')
    _add_local_user(a, 'ann')
    _sync(c)
    with at(c):
        assert federation._peer_key(iid(a)) is not None
        out = federation.leave()
    assert out == {'left': True, 'not_told': []}
    with at(c):
        assert federation.members() == {}
        assert federation.identity()['peer_keys'] == {}
    assert _owner_at(c, 'pve-l') is None
    assert 'ann' not in _users(c)
    for s in (a, b):
        assert iid(c) not in _view(s)[2]


def test_a_view_of_one_holds_no_lease(tmp_path, clock):
    a, b, c = _three(tmp_path)
    _enroll(a, 'pve-1')
    _cut([a, b, c], a)
    with at(a):
        with pytest.raises(federation.FederationError) as err:
            federation.leave()
        assert err.value.code in ('FED_LEAVE_BLOCKED', 'FED_NO_QUORUM')
        clock.advance(60)
        assert federation.leave(force=True)['left'] is True
        # the row stays enrolled and closed, and no round of a lone instance opens it
        assert federation.cluster_owner('pve-1') == federation.instance_id()
        assert fl.lease_round() == {}
        assert federation.takes_writes_for('pve-1') is False


def test_adopt_needs_the_owner_in_the_view(tmp_path):
    a, b, c = _three(tmp_path)
    _add_cluster(b, 'pve-x', owner='9' * 32)
    with at(b):
        with pytest.raises(federation.FederationError) as err:
            fl.adopt_cluster('pve-x')
    assert err.value.code == 'FED_NOT_MEMBER'


# --- field keys -------------------------------------------------------------------------

def test_pairing_hands_no_database_key(tmp_path):
    a, b, c = _three(tmp_path)
    _enroll(a, 'pve-k', password='k-secret')
    _sync(b, c)
    for owner in (a, b, c):
        secret = base64.b64encode(_db_of(owner).aes_key).decode()
        for other in (a, b, c):
            if other is owner:
                continue
            row = _db_of(other).conn.execute(
                "SELECT v FROM pegaprox_kv WHERE k = 'federation_identity'").fetchone()[0]
            assert secret not in row
            with open(other.lease_file) as fh:
                assert secret not in fh.read()
            conn = _db_of(other).conn
            for table in ('pegaprox_kv', 'server_settings', 'clusters', 'users'):
                for row in conn.execute(f'SELECT * FROM {table}').fetchall():
                    assert secret not in ' '.join(str(v) for v in tuple(row)), table
    for other in (b, c):
        cols = _db_of(other).conn.execute(
            "SELECT pass_encrypted, ssh_key_encrypted, api_token_secret_encrypted, "
            "ha_settings FROM clusters WHERE id = 'pve-k'").fetchone()
        assert cols['pass_encrypted'].startswith('fedk1:')
        assert all(v == '' or v.startswith('fedk1:') for v in cols)


def test_removing_a_member_drops_its_key_and_mirrors(tmp_path):
    a, b, c = _three(tmp_path)
    _enroll(a, 'pve-r', password='r')
    _add_local_user(a, 'rita')
    _sync(b)
    with at(b):
        assert federation._peer_key(iid(a)) is not None
    assert _owner_at(b, 'pve-r') == iid(a) and 'rita' in _users(b)
    with at(b):
        federation.remove_member(iid(a), by='admin:test')
        assert federation._peer_key(iid(a)) is None
        assert iid(a) not in federation.identity()['peer_keys']
    assert _owner_at(b, 'pve-r') is None and 'rita' not in _users(b)
    assert _owner_at(c, 'pve-r') is None


def test_a_mirror_never_breaks_the_cluster_reads(tmp_path, monkeypatch):
    """A mirror's credentials are wrapped, never the owner's database ciphertext: the
    reads of the database leave mirrors out with the federation on, and with it off they
    leave out every row a federation owns - nothing raises either way."""
    a, b, c = _three(tmp_path)
    _enroll(a, 'pve-m', password='m')
    _enroll(b, 'pve-own', password='own-enrolled')
    _add_cluster(b, 'own-b', password='own')
    _sync(b)
    with at(b):
        assert set(_db_of(b).get_all_clusters()) == {'own-b', 'pve-own'}
        assert _db_of(b).get_cluster('pve-m') is None
        monkeypatch.setenv(federation.ENV_SWITCH, '0')
        every = _db_of(b).get_all_clusters()
        assert set(every) == {'own-b'} and every['own-b']['pass'] == 'own'
        assert _db_of(b).get_cluster('pve-own') is None


def test_a_snapshot_with_foreign_ciphertext_lands_nothing(tmp_path):
    a, b, c = _three(tmp_path)
    with at(a):
        body = federation.identity_snapshot_body()
    body['clusters'] = [{'id': 'pve-z', 'name': 'z', 'host': 'h', 'user': 'u',
                         'pass_encrypted': 'aes256:AAAA'}]
    body['etag'] = 'forged'
    with at(b):
        report = federation.apply_identity_snapshot(body, sender=iid(a))
    assert any('pve-z' in x for x in report['conflicts'])
    assert _owner_at(b, 'pve-z') is None


# --- the vote ------------------------------------------------------------------------------------

def _ask(side, sender_side, cids, adopt=False, view=None):
    with at(sender_side):
        me, digest, epoch = federation.instance_id(), federation.view_digest(), federation.view_epoch()
    body = {'candidate': me, 'view': view or digest, 'epoch': epoch,
            'asks': [{'cluster_id': c, 'adopt': adopt} for c in cids], 'releases': []}
    with at(side):
        return federation.cast_votes(me, body)


def test_a_vote_is_on_disk_before_the_answer(tmp_path):
    a, b, c = _three(tmp_path)
    status, answer = _ask(b, a, ['c7'])
    # the grant names the owner b's row gives, none for an id b holds no row of
    assert status == 200 and answer['votes']['c7'] == {'granted': True, 'owner': ''}
    with open(b.lease_file) as fh:
        on_disk = json.load(fh)
    assert on_disk['promises']['c7']['candidate'] == iid(a)


def test_a_vote_for_another_candidate_waits_for_the_promise(tmp_path, clock):
    a, b, c = _three(tmp_path)
    assert _ask(b, a, ['c8'])[1]['votes']['c8']['granted'] is True
    v = _ask(b, c, ['c8'])[1]['votes']['c8']
    assert v['granted'] is False and v['reason'] == 'held' and v['holder'] == iid(a)
    clock.advance(fl.LEASE_SECONDS)
    assert _ask(b, c, ['c8'])[1]['votes']['c8']['reason'] == 'held'   # skew not over
    clock.advance(fl.LEASE_SKEW + 1)
    assert _ask(b, c, ['c8'])[1]['votes']['c8']['granted'] is True


def test_the_vote_refuses_junk_and_strangers(tmp_path):
    a, b, c = _three(tmp_path)
    with at(b):
        digest = federation.view_digest()
        assert federation.cast_votes(iid(a), {'candidate': iid(c), 'view': digest,
                                              'asks': [], 'releases': []}) == \
            (409, {'reason': 'candidate'})
        assert federation.cast_votes('9' * 32, {'candidate': '9' * 32, 'view': digest,
                                                'asks': [{'cluster_id': 'x'}],
                                                'releases': []})[1]['reason'] == 'member'
        for bad in ({'candidate': iid(a), 'asks': [{'cluster_id': 'x y!'}]},
                    {'candidate': iid(a), 'asks': 'x'},
                    {'candidate': iid(a), 'asks': [{'cluster_id': 'x', 'adopt': 'yes'}]},
                    {'candidate': iid(a), 'asks': [{'cluster_id': f'c{i}'} for i in range(300)]}):
            assert federation.cast_votes(iid(a), dict(bad, view=digest)) == \
                (400, {'reason': 'body'}), bad
    status, answer = _ask(b, a, ['c1'], view='0' * 32)
    assert status == 409 and answer['reason'] == 'view' and answer['epoch'] == 2


def test_the_promises_of_a_member_are_bounded(tmp_path):
    a, b, c = _three(tmp_path)
    granted = 0
    for start in (0, 256):
        status, answer = _ask(b, a, [f'cl{i}' for i in range(start, start + 150)])
        granted += sum(1 for v in answer['votes'].values() if v.get('granted'))
        full = [v for v in answer['votes'].values() if v.get('reason') == 'full']
    assert granted == fl.MAX_PROMISES_PER_CANDIDATE
    assert len(full) == 300 - fl.MAX_PROMISES_PER_CANDIDATE
    # no live promise was dropped for the new ones: every granted one is still there
    with at(b):
        promises = federation._lease_state()['promises']
    assert sum(1 for p in promises.values()
               if p['candidate'] == iid(a) and p['until'] > 0) == granted
    # c still gets its own
    assert _ask(b, c, ['other'])[1]['votes']['other']['granted'] is True


def test_one_vote_implementation():
    """The old vote paths are gone and stay gone."""
    for name in ('lease_vote', '_lease_check_vote', '_vote_round', 'acquire_lease',
                 'lease_vote_atomic', 'acquire_lease_arch', '_vote_round_arch',
                 '_needed_votes', 'renew_leases', 'release_lease', '_owner_released_lease',
                 '_lease_release', '_deadline_past_reboot', '_reset_rebooted_lease_clocks',
                 '_apply_boot_reset', 'adopt_ha_federation_identity',
                 '_is_foreign_federation_mirror', 'federation_state_has_member',
                 'field_key_b64', '_field_key_file', 'peer_field_keys', '_remember_field_keys',
                 'add_member', 'reconcile', 'push', 'push_all', '_post', '_deliver',
                 '_pinned_session', '_load', '_save', '_mutate', 'touch', '_STATE_FILE'):
        assert not hasattr(federation, name), name
        assert not hasattr(fl, name), name
    from pegaprox.api import federation as api_fed
    for name in ('peer_member_added', 'peer_member_removed', 'peer_left', 'start_sync_worker',
                 '_sync_loop', '_lease_loop'):
        assert not hasattr(api_fed, name), name


# --- rounds -----------------------------------------------------------------------------------

def test_enroll_gives_the_lease_and_the_gate(tmp_path):
    a, b, c = _three(tmp_path)
    lease = _enroll(a, 'c1')
    assert lease['held'] is True and lease['votes'] == 3 and lease['needed'] == 2
    assert _writes(a, 'c1') is True
    assert _owner_at(a, 'c1') == iid(a)


def test_enroll_needs_three_sites_and_a_proxmox_cluster(tmp_path, clock):
    a, b = _sides(tmp_path, 'ab')
    _add_cluster(a, 'c2')
    with at(a):
        with pytest.raises(federation.FederationError) as err:
            fl.enroll_cluster('c2')
    assert err.value.code == 'FED_TOO_FEW_SITES' and _owner_at(a, 'c2') == ''
    c = Side(tmp_path, 'c')
    _wire([a, b, c])
    _join(c, _code(a))
    _add_cluster(a, 'xp', ctype='xcpng')
    with at(a):
        with pytest.raises(federation.FederationError) as err:
            fl.enroll_cluster('xp')
        assert err.value.code == 'FED_TYPE'
        # right after the join the voters are in its settle span
        with pytest.raises(federation.FederationError) as err:
            fl.enroll_cluster('c2')
        assert err.value.code == 'FED_NO_QUORUM' and 'changed members' in str(err.value)
    assert _owner_at(a, 'c2') == ''
    clock.advance(fl.SETTLE_SECONDS + 1)
    with at(a):
        assert fl.enroll_cluster('c2')['held'] is True


def test_a_failed_enroll_leaves_the_row_as_it_was(tmp_path):
    a, b, c = _three(tmp_path)
    _add_cluster(a, 'c3')
    _cut([a, b, c], a)
    with at(a):
        with pytest.raises(federation.FederationError) as err:
            fl.enroll_cluster('c3')
    assert err.value.code == 'FED_NO_QUORUM' and err.value.extra['votes'] == 1
    assert _owner_at(a, 'c3') == ''


def test_a_lease_runs_out_and_the_gate_closes(tmp_path, clock):
    a, b, c = _three(tmp_path)
    _enroll(a, 'c4')
    clock.advance(fl.LEASE_SECONDS - fl.LEASE_WRITE_MARGIN - 1)
    assert _writes(a, 'c4') is True
    clock.advance(2)
    assert _writes(a, 'c4') is False


def test_a_round_is_one_call_per_member(tmp_path):
    calls = []
    a, b, c = _sides(tmp_path, 'abc', calls=calls)
    for i in range(20):
        _add_cluster(a, f'cl{i}', owner=iid(a))
    del calls[:]
    with at(a):
        r = fl.lease_round()
    assert len(r) == 20 and all(x['held'] for x in r.values())
    votes = [x for x in calls if x[2] == federation.LEASE_PATH]
    assert len(votes) == 2 and sorted(u for u, _m, _p in votes) == [URL['b'], URL['c']]


def test_one_silent_member_costs_no_lease(tmp_path, clock):
    a, b, c = _three(tmp_path)
    for i in range(5):
        _add_cluster(a, f'cs{i}', owner=iid(a))

    def slow(url, method, path, body, headers):
        if url == URL['c']:
            clock.advance(10)
            return 0, b'', {}
        return a.wire(url, method, path, body, headers)
    a.runtime['transport'] = slow
    with at(a):
        r = fl.lease_round()
        left = fl.lease_status()['leases']
    assert all(x['held'] for x in r.values())
    assert all(x['remaining_s'] >= 18 for x in left.values()), left


def test_a_round_renews_only_rows_led_here(tmp_path):
    a, b, c = _three(tmp_path)
    _enroll(a, 'mine')
    _add_cluster(a, 'local')
    with at(a):
        def stale(st):
            st['my_leases']['gone'] = {'expires': 0, 'released': False}
            return True
        federation._mutate_leases(stale)
        r = fl.lease_round()
    assert sorted(r) == ['mine']


def test_an_owner_regains_its_lease_after_a_long_outage(tmp_path, clock):
    a, b, c = _three(tmp_path)
    _enroll(a, 'pve-o')
    _cut([a, b, c], a)
    for _ in range(18):
        clock.advance(10)
        with at(a):
            fl.lease_round()
    assert _writes(a, 'pve-o') is False
    _heal([a, b, c])
    with at(a):
        r = fl.lease_round()
    assert r['pve-o']['held'] is True and _writes(a, 'pve-o') is True


def test_a_broken_cluster_row_never_aborts_the_round(tmp_path, monkeypatch):
    a, b, c = _three(tmp_path)
    _enroll(a, 'ok-1')
    real = fl._owner_map
    broken_at = iid(a)

    def owner_map():
        if federation.instance_id() == broken_at:
            raise federation.FederationError('the clusters table is gone')
        return real()
    monkeypatch.setattr(fl, '_owner_map', owner_map)
    with at(a):
        r = fl.lease_round()
    assert r['ok-1']['held'] is True


def test_unenroll_needs_the_lease(tmp_path, clock):
    a, b, c = _three(tmp_path)
    _enroll(a, 'pve-u')
    with at(a):
        fl.release('pve-u')
        with pytest.raises(federation.FederationError) as err:
            fl.unenroll_cluster('pve-u')
        assert err.value.code == 'FED_NO_LEASE'
        assert fl.enroll_cluster('pve-u')['held'] is True
        assert fl.unenroll_cluster('pve-u') is True
    assert _owner_at(a, 'pve-u') == ''
    assert _writes(a, 'pve-u') is True


def test_an_unenroll_needs_a_majority_to_drop_their_copies(tmp_path):
    """An owner that takes a cluster back while it is cut off would treat it as its own
    while the others may still adopt their copy of it: the unenroll needs a majority that
    dropped its copy first, and stays enrolled without one."""
    a, b, c = _three(tmp_path)
    _enroll(a, 'pve-un')
    _sync(b, c)
    _cut([a, b, c], a)
    with at(a):
        with pytest.raises(federation.FederationError) as err:
            fl.unenroll_cluster('pve-un')
    assert err.value.code == 'FED_NO_QUORUM'
    assert _owner_at(a, 'pve-un') == iid(a) and _owner_at(b, 'pve-un') == iid(a)
    # c misses the notice, b gets it: two of three, the cluster is a's own again
    _heal([a, b, c])
    a.runtime['transport'] = _without(a.wire, URL['c'])
    with at(a):
        assert fl.unenroll_cluster('pve-un') is True
    assert _owner_at(a, 'pve-un') == '' and _owner_at(b, 'pve-un') is None
    assert _owner_at(c, 'pve-un') == iid(a)


def test_an_unenrolled_cluster_cannot_be_adopted(tmp_path, clock):
    """The site that missed the notice still holds its copy, but the voters that dropped
    theirs back nobody's adoption of it."""
    a, b, c = _three(tmp_path)
    _enroll(a, 'pve-ua')
    _sync(b, c)
    a.runtime['transport'] = _without(a.wire, URL['c'])
    with at(a):
        fl.unenroll_cluster('pve-ua')
    _cut([a, b, c], a)
    clock.advance(fl.LEASE_SECONDS + fl.LEASE_SKEW + 1)
    with at(c):
        with pytest.raises(federation.FederationError) as err:
            fl.adopt_cluster('pve-ua')
    assert err.value.code == 'FED_NO_QUORUM'
    v = _ask(b, c, ['pve-ua'], adopt=True)[1]['votes']['pve-ua']
    assert v['granted'] is False and v['reason'] == 'cluster'
    assert _writes(c, 'pve-ua') is False and _writes(a, 'pve-ua') is True


# --- the lease fence under a partition ---------------------------------------------------------

def test_a_partition_never_gives_two_writers(tmp_path, clock):
    """A leads a cluster and is cut off. At every moment at most one site may write: A
    until its lease ends on its own clock, B only once every promise behind A's lease has
    run out, plus the skew. Asked every few seconds across the whole hand-over."""
    a, b, c = _three(tmp_path)
    _enroll(a, 'pve-p')
    _sync(b, c)
    _cut([a, b, c], a)
    b_writes_at = None
    for step in range(40):
        clock.advance(2)
        with at(a):
            fl.lease_round()
        with at(b):
            try:
                fl.adopt_cluster('pve-p')
            except federation.FederationError:
                pass
        writers = [s.name for s in (a, b, c) if _writes(s, 'pve-p')]
        assert len(writers) <= 1, (step, writers)
        if writers == ['b'] and b_writes_at is None:
            b_writes_at = step
    assert b_writes_at is not None
    # B took over only after A's lease and every promise behind it were gone
    assert (b_writes_at + 1) * 2 >= fl.LEASE_SECONDS + fl.LEASE_SKEW


# --- restarts, reboots, failovers ---------------------------------------------------------------

def test_a_restarted_voter_keeps_its_promise(tmp_path):
    a, b, c = _three(tmp_path)
    assert _ask(b, a, ['pr'])[1]['votes']['pr']['granted'] is True
    _restart(b)
    v = _ask(b, c, ['pr'])[1]['votes']['pr']
    assert v['reason'] == 'held' and v['holder'] == iid(a)
    # and the holder's lease survives its own restart too
    _enroll(a, 'pve-s')
    _restart(a)
    assert _writes(a, 'pve-s') is True


def test_a_rebooted_voter_holds_for_a_lease(tmp_path, clock, monkeypatch):
    a, b, c = _three(tmp_path)
    _enroll(b, 'pve-rb')
    assert _ask(b, a, ['pr2'])[1]['votes']['pr2']['granted'] is True
    _reboot(b, monkeypatch)
    for cid in ('pr2', 'fresh'):
        v = _ask(b, c, [cid])[1]['votes'][cid]
        assert v['reason'] == 'hold' and v['retry_after'] >= fl.LEASE_SECONDS, cid
    # its own leases closed with the reboot
    assert _writes(b, 'pve-rb') is False
    clock.advance(fl.LEASE_SECONDS + fl.LEASE_SKEW + 1)
    assert _ask(b, c, ['fresh'])[1]['votes']['fresh']['granted'] is True


def test_a_host_that_became_active_holds(tmp_path, clock, monkeypatch):
    from pegaprox.core import ha
    a, b, c = _three(tmp_path)
    assert _ask(b, a, ['ha1'])[1]['votes']['ha1']['granted'] is True
    monkeypatch.setattr(ha, 'epoch', lambda: 7)
    v = _ask(b, c, ['ha1'])[1]['votes']['ha1']
    assert v['reason'] == 'hold'
    clock.advance(fl.LEASE_SECONDS + fl.LEASE_SKEW + 1)
    assert _ask(b, c, ['ha1'])[1]['votes']['ha1']['granted'] is True


def test_a_release_survives_a_restart(tmp_path, clock):
    a, b, c = _three(tmp_path)
    _enroll(a, 'pve-rel', password='rel')
    _sync(b, c)
    with at(a):
        fl.release('pve-rel')
    _restart(a)
    _restart(b)
    # the pairings just changed the view: an adoption waits out the settle span
    clock.advance(fl.SETTLE_SECONDS + 1)
    with at(b):
        p = federation._lease_state()['promises']['pve-rel']
        assert p['candidate'] == iid(a) and p['released'] is True
        assert fl.adopt_cluster('pve-rel')['held'] is True
    with at(a):
        assert federation._lease_state()['my_leases']['pve-rel']['released'] is True


# --- ownership: mirrors, squatting, adoption -----------------------------------------------------

def test_a_cluster_mirror_reaches_the_others(tmp_path):
    a, b, c = _three(tmp_path)
    _enroll(a, 'pve-1', password='the-password')
    _sync(b)
    row = _db_of(b).conn.execute(
        "SELECT fed_owner, pass_encrypted FROM clusters WHERE id = 'pve-1'").fetchone()
    assert row['fed_owner'] == iid(a) and row['pass_encrypted'].startswith('fedk1:')
    with at(b):
        assert federation.unwrap_credential(row['pass_encrypted'], iid(a), 'pve-1',
                                            'pass_encrypted') == 'the-password'
        assert 'pve-1' not in _db_of(b).get_all_clusters()


def test_an_unchanged_cluster_row_writes_nothing(tmp_path):
    a, b, c = _three(tmp_path)
    _enroll(a, 'pve-u1')
    _enroll(a, 'pve-u2')
    _sync(b)
    _db_of(a).conn.execute("UPDATE clusters SET name = 'renamed' WHERE id = 'pve-u1'")
    _db_of(a).conn.commit()
    from pegaprox.api import federation as api_fed
    api_fed._etag_cache['etag'] = ''
    with at(b):
        report = federation.sync_identities()[iid(a)]
    assert report['updated'] == 1 and report['unchanged'] == 1, report


def test_a_snapshot_cannot_take_a_cluster_led_here(tmp_path):
    a, b, c = _three(tmp_path)
    _enroll(b, 'pve-h')
    with at(a):
        body = federation.identity_snapshot_body()
    body['clusters'] = [{'id': 'pve-h', 'name': 'stolen', 'host': 'evil', 'user': 'u',
                         'pass_encrypted': ''}]
    body['etag'] = 'forged'
    with at(b):
        report = federation.apply_identity_snapshot(body, sender=iid(a))
    assert any('led here' in x for x in report['conflicts'])
    row = _db_of(b).conn.execute("SELECT name, fed_owner FROM clusters WHERE id = 'pve-h'").fetchone()
    assert row['name'] == 'pve-h' and row['fed_owner'] == iid(b)


def test_a_member_listing_anothers_cluster_changes_nothing(tmp_path):
    a, b, c = _three(tmp_path)
    _enroll(b, 'pve-b2')
    _sync(c)
    with at(a):
        body = federation.identity_snapshot_body()
    body['clusters'] = [{'id': 'pve-b2', 'name': 'mine now', 'host': 'h', 'user': 'u',
                         'pass_encrypted': ''}]
    body['etag'] = 'forged'
    with at(c):
        federation.apply_identity_snapshot(body, sender=iid(a))
    row = _db_of(c).conn.execute("SELECT name, fed_owner FROM clusters WHERE id = 'pve-b2'").fetchone()
    assert row['fed_owner'] == iid(b) and row['name'] == 'pve-b2'


def test_a_member_cannot_squat_another_owners_cluster(tmp_path, clock):
    a, b, c = _three(tmp_path)
    _enroll(a, 'pve-sq')
    _sync(b)
    v = _ask(b, c, ['pve-sq'])[1]['votes']['pve-sq']
    assert v['granted'] is False and v['reason'] in ('held', 'owner') and v['owner'] == iid(a)
    clock.advance(fl.LEASE_SECONDS + fl.LEASE_SKEW + 1)
    v = _ask(b, c, ['pve-sq'])[1]['votes']['pve-sq']
    assert v['granted'] is False and v['reason'] == 'owner' and v['owner'] == iid(a)


def test_a_squat_on_an_unknown_id_ends_once_the_owner_row_arrives(tmp_path, clock):
    a, b, c = _three(tmp_path)
    # c holds b's promise for an id nobody has enrolled yet
    assert _ask(b, c, ['pve-new'])[1]['votes']['pve-new']['granted'] is True
    clock.advance(fl.LEASE_SECONDS + fl.LEASE_SKEW + 1)
    _add_cluster(a, 'pve-new', owner=iid(a))
    with at(a):
        fl.lease_round()
    _sync(b)
    v = _ask(b, c, ['pve-new'])[1]['votes']['pve-new']
    assert v['granted'] is False and v['reason'] in ('held', 'owner')
    assert v['owner'] == iid(a)
    clock.advance(fl.LEASE_SECONDS + fl.LEASE_SKEW + 1)
    v = _ask(b, c, ['pve-new'])[1]['votes']['pve-new']
    assert v['granted'] is False and v['reason'] == 'owner' and v['owner'] == iid(a)


def test_an_adoption_needs_the_owner_gone(tmp_path):
    a, b, c = _three(tmp_path)
    _enroll(a, 'pve-2')
    _sync(b)
    with at(b):
        with pytest.raises(federation.FederationError) as err:
            fl.adopt_cluster('pve-2')
    assert err.value.code == 'FED_OWNER_ALIVE'


def test_an_adoption_opens_the_wrapped_credentials(tmp_path, clock):
    a, b, c = _three(tmp_path)
    _enroll(a, 'pve-3', password='berlin-secret')
    _sync(b, c)
    _cut([a, b, c], a)
    clock.advance(fl.LEASE_SECONDS + fl.LEASE_SKEW + 1)
    with at(b):
        lease = fl.adopt_cluster('pve-3')
        assert lease['held'] is True and lease['adopted'] is True
        assert federation.cluster_owner('pve-3') == federation.instance_id()
        assert federation.takes_writes_for('pve-3') is True
        row = _db_of(b).conn.execute("SELECT pass_encrypted FROM clusters WHERE id = 'pve-3'").fetchone()
        assert row['pass_encrypted'].startswith('aes256:')
        assert _db_of(b)._decrypt(row['pass_encrypted']) == 'berlin-secret'
        assert _db_of(b).get_cluster('pve-3')['pass'] == 'berlin-secret'


def test_an_adoption_without_the_key_needs_force(tmp_path, clock):
    a, b, c = _three(tmp_path)
    _enroll(a, 'pve-4', password='x')
    _sync(b, c)
    with at(b):
        federation._mutate_identity(lambda ident: ident['peer_keys'].clear() or True)
    _cut([a, b, c], a)
    clock.advance(fl.LEASE_SECONDS + fl.LEASE_SKEW + 1)
    with at(b):
        with pytest.raises(federation.FederationError) as err:
            fl.adopt_cluster('pve-4')
        assert err.value.code == 'FED_NO_KEY'
        assert fl.adopt_cluster('pve-4', force=True)['held'] is True
    assert _db_of(b).conn.execute("SELECT pass_encrypted FROM clusters WHERE id = 'pve-4'").fetchone()[0] == ''


def test_a_failed_reseat_changes_nothing_and_keeps_no_lease(tmp_path, clock, monkeypatch):
    a, b, c = _three(tmp_path)
    _enroll(a, 'pve-f', password='f-secret')
    _sync(b, c)
    _cut([a, b, c], a)
    clock.advance(fl.LEASE_SECONDS + fl.LEASE_SKEW + 1)
    before = _db_of(b).conn.execute("SELECT * FROM clusters WHERE id = 'pve-f'").fetchone()
    real = fl._reseat_credentials

    def broken(conn, cid, owner, force):
        real(conn, cid, owner, force)
        raise RuntimeError('the disk is full')
    monkeypatch.setattr(fl, '_reseat_credentials', broken)
    with at(b):
        with pytest.raises(federation.FederationError):
            fl.adopt_cluster('pve-f')
        assert 'pve-f' not in federation._lease_state()['my_leases']
        assert federation.takes_writes_for('pve-f') is False
    after = _db_of(b).conn.execute("SELECT * FROM clusters WHERE id = 'pve-f'").fetchone()
    assert dict(after) == dict(before)
    for voter in (b, c):
        with at(voter):
            p = federation._lease_state()['promises']['pve-f']
            assert p['candidate'] == iid(b) and p['released'] is True
    # the retry goes through
    monkeypatch.setattr(fl, '_reseat_credentials', real)
    with at(b):
        assert fl.adopt_cluster('pve-f')['held'] is True


def test_an_adoption_reads_a_value_an_off_reader_reencrypted(tmp_path, clock):
    a, b, c = _three(tmp_path)
    _enroll(a, 'pve-e', password='e-secret')
    _sync(b, c)
    db = _db_of(b)
    wrapped = db.conn.execute("SELECT pass_encrypted FROM clusters WHERE id = 'pve-e'").fetchone()[0]
    db.conn.execute("UPDATE clusters SET pass_encrypted = ? WHERE id = 'pve-e'",
                    (db._encrypt(wrapped),))
    db.conn.commit()
    _cut([a, b, c], a)
    clock.advance(fl.LEASE_SECONDS + fl.LEASE_SKEW + 1)
    with at(b):
        fl.adopt_cluster('pve-e')
        assert db.get_cluster('pve-e')['pass'] == 'e-secret'


def test_a_released_cluster_moves_to_its_adopter_everywhere(tmp_path, clock):
    a, b, c = _three(tmp_path)
    _enroll(a, 'pve-mv', password='mv')
    _sync(b, c)
    stopped = []
    from pegaprox import globals as g
    fake = MagicMock()
    fake.stop.side_effect = lambda: stopped.append('pve-mv')
    with at(a):
        fl.release('pve-mv')
    clock.advance(fl.SETTLE_SECONDS + 1)
    with at(b):
        assert fl.adopt_cluster('pve-mv')['held'] is True
    g.cluster_managers['pve-mv'] = fake
    try:
        _sync(a, c)
    finally:
        g.cluster_managers.pop('pve-mv', None)
    row = _db_of(a).conn.execute("SELECT fed_owner, pass_encrypted FROM clusters "
                                 "WHERE id = 'pve-mv'").fetchone()
    assert row['fed_owner'] == iid(b) and row['pass_encrypted'].startswith('fedk1:')
    assert stopped == ['pve-mv']
    assert _owner_at(c, 'pve-mv') == iid(b)
    assert [s.name for s in (a, b, c) if _writes(s, 'pve-mv')] == ['b']
    with at(a):
        with pytest.raises(federation.FederationError) as err:
            fl.unenroll_cluster('pve-mv')
    assert err.value.code == 'FED_FOREIGN'


def test_a_stale_owner_cannot_flip_a_mirror_back(tmp_path, clock):
    a, b, c = _three(tmp_path)
    _enroll(a, 'pve-st')
    _sync(b, c)
    _cut([a, b, c], a)
    clock.advance(fl.LEASE_SECONDS + fl.LEASE_SKEW + 1)
    with at(b):
        fl.adopt_cluster('pve-st')
    _sync(c)
    assert _owner_at(c, 'pve-st') == iid(b)
    # a comes back still believing it leads: its snapshots change nothing at c
    a.runtime['transport'] = a.wire
    c.runtime['transport'] = c.wire
    for _ in range(3):
        with at(a):
            body = federation.identity_snapshot_body()
        assert any(r['id'] == 'pve-st' for r in body['clusters'])
        with at(c):
            federation.apply_identity_snapshot(body, sender=iid(a))
        assert _owner_at(c, 'pve-st') == iid(b)
    # and a's own round sees the majority's rows and hands the row over
    _heal([a, b, c])
    with at(a):
        r = fl.lease_round()
    assert r['pve-st']['lost_to'] == iid(b)
    assert _owner_at(a, 'pve-st') == iid(b)
    assert [s.name for s in (a, b, c) if _writes(s, 'pve-st')] == ['b']


def test_a_local_cluster_is_never_overwritten_by_a_mirror(tmp_path):
    a, b, c = _three(tmp_path)
    _add_cluster(b, 'pve-5', name='ours')
    _enroll(a, 'pve-5')
    report = _pull(b, a)
    assert _db_of(b).conn.execute("SELECT name FROM clusters WHERE id = 'pve-5'").fetchone()[0] == 'ours'
    assert any('pve-5' in x for x in report['conflicts'])


def test_a_home_that_cannot_read_refuses_the_pull(tmp_path, monkeypatch):
    a, b, c = _three(tmp_path)
    _add_local_user(a, 'ada')
    _enroll(a, 'pve-rd')
    _sync(b)
    assert 'ada' in _users(b) and _owner_at(b, 'pve-rd') == iid(a)

    def broken():
        raise RuntimeError('the disk is gone')
    monkeypatch.setattr(federation, '_identities_conn', broken)
    with at(a):
        with pytest.raises(federation.FederationError):
            federation.identity_snapshot_body()
    monkeypatch.undo()
    monkeypatch.setenv(federation.ENV_SWITCH, '1')
    real_conn = federation._identities_conn

    def broken_at_a():
        if federation.instance_id() == iid(a):
            raise RuntimeError('the disk is gone')
        return real_conn()
    monkeypatch.setattr(federation, '_identities_conn', broken_at_a)
    _db_of(a).conn.execute("UPDATE users SET display_name = 'x' WHERE username = 'ada'")
    _db_of(a).conn.commit()
    with at(b):
        report = federation.pull_identities(iid(a))
    assert report.get('failed') is True
    assert 'ada' in _users(b) and _owner_at(b, 'pve-rd') == iid(a)


# --- the HA group is one member ------------------------------------------------------------------

def _standby_of(tmp, active, name='a2'):
    """A host that took over `active`'s HA group: the synced tables (the identity row,
    the clusters) and the database key, nothing of the host-local lease file."""
    s = Side(tmp, name)
    _db_of(s, key_from=active)
    src, dst = _db_of(active).conn, s.db.conn
    dst.execute('CREATE TABLE IF NOT EXISTS pegaprox_kv (k TEXT PRIMARY KEY, v TEXT)')
    for k, v in src.execute('SELECT k, v FROM pegaprox_kv').fetchall():
        dst.execute('INSERT OR REPLACE INTO pegaprox_kv (k, v) VALUES (?, ?)', (k, v))
    cols = [r[1] for r in src.execute('PRAGMA table_info(clusters)').fetchall()]
    for row in src.execute('SELECT * FROM clusters').fetchall():
        dst.execute(f'INSERT OR REPLACE INTO clusters ({", ".join(cols)}) VALUES '
                    f'({", ".join("?" * len(cols))})', tuple(row))
    for table in ('users', 'federation_identity_map'):
        for row in src.execute(f'SELECT * FROM {table}').fetchall():
            ucols = row.keys()
            dst.execute(f'INSERT OR REPLACE INTO {table} ({", ".join(ucols)}) VALUES '
                        f'({", ".join("?" * len(ucols))})', tuple(row))
    dst.commit()
    return s


def test_a_promoted_standby_is_the_same_member(tmp_path, clock, monkeypatch):
    a, b, c = _three(tmp_path)
    _enroll(a, 'pve-a')
    _enroll(b, 'pve-b')
    _sync(a)
    a2 = _standby_of(tmp_path, a)
    # the standby answers at the group's address from now on
    URL['a2'] = URL['a']
    try:
        _wire([a2, b, c])
        # the HA epoch moves on the promoted host alone, as it does between hosts
        monkeypatch.setattr(fl, '_ha_epoch',
                            lambda: 5 if federation._runtime['lease_file'] == a2.lease_file
                            else 0)
        with at(a2):
            assert federation.instance_id() == iid(a)
            assert set(_db_of(a2).get_all_clusters()) == {'pve-a'}
        assert _owner_at(a2, 'pve-b') == iid(b)
        # the new acting host's own votes wait for one lease span, its own ask included;
        # b and c go on renewing the member's lease meanwhile
        with at(a2):
            r = fl.lease_round()['pve-a']
        assert r['held'] is True and r['votes'] == 2 and r['refusals'] == {'hold': 1}
        v = _ask(a2, b, ['pve-b'])[1]['votes']['pve-b']
        assert v['granted'] is False and v['reason'] == 'hold'
        clock.advance(fl.LEASE_SECONDS + fl.LEASE_SKEW + 1)
        with at(a2):
            r = fl.lease_round()
        assert r['pve-a']['held'] is True and r['pve-a']['votes'] == 3
        assert _writes(a2, 'pve-a') is True
        assert _ask(a2, b, ['pve-b'])[1]['votes']['pve-b']['granted'] is True
        assert _owner_at(a2, 'pve-b') == iid(b)
    finally:
        URL.pop('a2', None)


@pytest.fixture
def ha_state(tmp_path, monkeypatch):
    """The HA module on a state file of this test (a standalone until a test writes
    another), no restart."""
    from pegaprox.core import ha
    monkeypatch.setattr(ha, 'STATE_FILE', str(tmp_path / 'ha_state.json'))
    monkeypatch.setattr(ha, 'AES_KEY_FILE', str(tmp_path / 'aes256.key'))
    monkeypatch.setattr(ha, 'restart_process', lambda *a, **k: None)
    ha.reset_for_tests()
    yield ha
    ha.reset_for_tests()


def test_a_standby_that_leaves_its_group_is_no_member_any_more(tmp_path, ha_state):
    """A standby holds its active's federation identity through the sync. ha.unpair()
    makes it a standalone that acts; were the identity still there, it would lease the
    member's clusters next to the active, push its own certificate as the member's and
    could leave in its name. So what it inherited goes; the active keeps all of it."""
    ha = ha_state
    a, b, c = _three(tmp_path)
    _enroll(a, 'pve-a')
    _add_local_user(b, 'bea')
    _sync(a)
    a2 = _standby_of(tmp_path, a)
    with open(ha.STATE_FILE, 'w', encoding='utf-8') as fh:
        json.dump({'role': 'standby', 'instance_id': 'b' * 32, 'epoch': 3,
                   'members': {'a' * 32: {'url': URL['a']}}}, fh)
    ha.reset_for_tests()
    with at(a2):
        federation._lease_state()
        # counterproof: as a standby it holds the member's identity, passive
        assert federation.instance_id() == iid(a) and not federation._ha_active()
        assert os.path.exists(a2.lease_file)
        assert ha.unpair() == 'standby'
        assert federation._ha_active() is True
        assert federation.identity() is None and federation.instance_id() == ''
    assert _db_of(a2).get_server_setting(federation.SETTING_KEY, None) is False
    assert not os.path.exists(a2.lease_file)
    conn = _db_of(a2).conn
    assert conn.execute("SELECT COUNT(*) FROM clusters WHERE fed_owner != ''").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM users WHERE fed_home != ''").fetchone()[0] == 0
    assert conn.execute('SELECT COUNT(*) FROM federation_identity_map').fetchone()[0] == 0
    # the member itself is untouched
    with at(a):
        assert federation.instance_id() == iid(a)
    for s in (b, c):
        assert iid(a) in _view(s)[2]
    assert _writes(a, 'pve-a') is True and 'bea' in _users(a)


@pytest.mark.parametrize('off', ['env', 'setting'])
def test_a_standby_that_leaves_with_the_switch_off_drops_the_identity_too(
        tmp_path, ha_state, monkeypatch, off):
    """The switch is off on the standby (PEGAPROX_FEDERATION=0 on that host, or the
    setting), but the sync carried the identity row all the same: switched on later, the
    standalone host would be that member next to the active. So the row goes with the
    unpairing whatever the switch says - the one thing of the federation that runs while
    it is off. Counterproof: the row is there up to the unpairing."""
    ha = ha_state
    a, b, c = _three(tmp_path)
    _enroll(a, 'pve-a')
    a2 = _standby_of(tmp_path, a)
    with open(ha.STATE_FILE, 'w', encoding='utf-8') as fh:
        json.dump({'role': 'standby', 'instance_id': 'b' * 32, 'epoch': 3,
                   'members': {'a' * 32: {'url': URL['a']}}}, fh)
    ha.reset_for_tests()
    if off == 'env':
        monkeypatch.setenv(federation.ENV_SWITCH, '0')
    else:
        monkeypatch.delenv(federation.ENV_SWITCH)
        _db_of(a2).save_server_setting(federation.SETTING_KEY, False)
    conn = _db_of(a2).conn

    def held():
        return (conn.execute('SELECT COUNT(*) FROM pegaprox_kv WHERE k = ?',
                             (federation.IDENTITY_KEY,)).fetchone()[0],
                conn.execute("SELECT COUNT(*) FROM clusters WHERE fed_owner != ''").fetchone()[0])
    assert held() == (1, 1)
    with at(a2):
        assert federation.enabled() is False
        assert ha.unpair() == 'standby'
        assert federation.enabled() is False
    assert held() == (0, 0)
    assert not os.path.exists(a2.lease_file)
    with at(a):
        assert federation.instance_id() == iid(a)


@pytest.mark.parametrize('told', [True, False])
def test_an_active_that_takes_a_standby_or_leaves_its_group_keeps_its_votes(
        tmp_path, clock, monkeypatch, ha_state, told):
    """The HA epoch of a member moves from 0 to 1 when it takes its first standby, and back
    to 0 when it leaves its group as the active. The same host acts throughout, with its
    whole lease file: ha.py says so to the federation, and nobody holds. With c down that
    is the difference between keeping every lease and losing them for 35 seconds, which
    is what happens without the notice (the counterproof)."""
    ha = ha_state
    a, b, c = _three(tmp_path)
    _enroll(a, 'pve-a')
    _enroll(b, 'pve-b')
    # the lease clock of a reads its own HA epoch; b and c have none
    monkeypatch.setattr(fl, '_ha_epoch',
                        lambda: ha.epoch() if federation._runtime['lease_file'] == a.lease_file
                        else 0)
    if not told:
        monkeypatch.setattr(ha, '_federation_epoch_kept', lambda old, new: None)
    _cut([a, b, c], c)
    standby_key = ha._public_of(ha._private_key(base64.b64encode(bytes(range(1, 33))).decode()))
    with at(a):
        code, _exp = ha.create_pairing_code(URL['a'], '')
        ha.accept_pairing(ha.decode_code(code)['secret'], 'b' * 32,
                          'https://a2.example:5000', '', standby_key)
        assert ha.epoch() == 1 and ha.role() == 'active'

    def rounds():
        clock.advance(fl.LEASE_RENEW_AFTER)
        with at(a):
            ra = fl.lease_round()['pve-a']
        with at(b):
            rb = fl.lease_round()['pve-b']
        return ra['held'], rb['held']
    assert rounds() == (told, told)
    if told:
        with at(a):
            # its standby keeps the member's identity: no unpairing while it is there
            with pytest.raises(ha.AutoMode, match='federation'):
                ha.unpair()
            assert ha.role() == 'active' and ha.epoch() == 1
            # the standby gone (an active whose members left before it was promoted is
            # the same), the active leaves its group and stays the member
            with ha._lock:
                ha._commit_locked(dict(ha._load(), members={}))
            assert ha.unpair() == 'active' and ha.epoch() == 0
        assert rounds() == (True, True)


def test_mirrors_keep_syncing_after_a_promotion(tmp_path):
    a, b, c = _three(tmp_path)
    _add_local_user(b, 'bea')
    _sync(a)
    _map(a, b, 'tenant', 'default', 'default')
    assert _row(a, 'bea')['enabled'] == 1
    a2 = _standby_of(tmp_path, a)
    URL['a2'] = URL['a']
    try:
        _wire([a2, b, c])
        # the mapping came over with the group's tables: the new host's first pull (its
        # pull state is its own) resolves bea as before, no admin maps anything again
        _sync(a2)
        assert _row(a2, 'bea')['enabled'] == 1
        _db_of(b).conn.execute("UPDATE users SET enabled = 0 WHERE username = 'bea'")
        _db_of(b).conn.commit()
        _sync(a2)
        row = _db_of(a2).conn.execute("SELECT enabled, fed_home FROM users "
                                      "WHERE username = 'bea'").fetchone()
        assert row['enabled'] == 0 and row['fed_home'] == iid(b)
    finally:
        URL.pop('a2', None)


def test_the_workers_stand_still_on_a_standby(monkeypatch):
    import gevent
    from pegaprox.core import ha
    ran = []

    def go(active):
        monkeypatch.setattr(ha, 'is_active', lambda: active)
        monkeypatch.setattr(federation, 'instance_id', lambda create=False: 'f' * 32)
        stop = threading.Event()
        g = gevent.spawn(federation._loop, stop, 0.01, lambda: ran.append(active))
        gevent.sleep(0.1)
        stop.set()
        g.join(timeout=1)
    go(False)
    assert ran == []
    go(True)
    assert ran and set(ran) == {True}


def test_peer_routes_answer_fed_standby_on_a_standby(paired, monkeypatch):
    from pegaprox.core import ha
    a, b = paired
    monkeypatch.setattr(ha, 'is_standby', lambda: True)
    r = _get(a, STATUS, _signed_headers_of(b, iid(a)))
    assert r.status_code == 503 and r.get_json()['code'] == 'FED_STANDBY'
    monkeypatch.setattr(ha, 'is_standby', lambda: False)
    monkeypatch.setattr(ha, 'is_active', lambda: False)
    # a host that is not acting right now still answers a status, but votes for nobody
    assert _get(a, STATUS, _signed_headers_of(b, iid(a))).status_code == 200
    body = {'candidate': iid(b), 'view': 'x', 'asks': [], 'releases': []}
    r = _post(a, federation.LEASE_PATH, body,
              _signed_headers_of(b, iid(a), method='POST', path=federation.LEASE_PATH, body=body))
    assert r.status_code == 503 and r.get_json()['code'] == 'FED_STANDBY'


# --- the outbound transport ---------------------------------------------------------------------

class _Answer:
    def __init__(self, status=200, body=b'{}', headers=None):
        import requests
        self.resp = requests.Response()
        self.resp.status_code = status
        self.resp.raw = io.BytesIO(body)
        self.resp.headers = requests.structures.CaseInsensitiveDict(headers or {})


@pytest.fixture
def wire_calls(monkeypatch):
    """Every send of the real transport, with the adapter's pin and the verify it got,
    answered by `answers` (a callable of the adapter's pin)."""
    import requests
    seen = []
    state = {'answer': lambda pin: _Answer()}

    def send(self, request, **kwargs):
        pin = getattr(self, '_pinned_fingerprint', '')
        seen.append({'pin': pin, 'verify': kwargs.get('verify'), 'url': request.url})
        got = state['answer'](pin)
        if isinstance(got, Exception):
            raise got
        got.resp.request = request
        return got.resp
    monkeypatch.setattr(requests.adapters.HTTPAdapter, 'send', send)
    federation._runtime['sessions'] = {}
    return seen, state


def test_a_pinned_call_passes_verify_false(wire_calls):
    seen, _state = wire_calls
    status, data, _h = federation._send('https://10.0.0.5:5000', [FP1], 'GET', STATUS)
    assert status == 200 and data == {}
    assert seen[-1]['verify'] is False and seen[-1]['pin'] == FP1
    federation._send('https://10.0.0.6:5000', [], 'GET', STATUS)
    assert seen[-1]['verify'] is True and seen[-1]['pin'] == ''


def test_a_ca_bundle_in_the_environment_keeps_the_pin(wire_calls, monkeypatch, tmp_path):
    seen, _state = wire_calls
    bundle = tmp_path / 'ca.pem'
    bundle.write_text('')
    monkeypatch.setenv('REQUESTS_CA_BUNDLE', str(bundle))
    federation._send('https://10.0.0.5:5000', [FP1], 'GET', STATUS)
    assert seen[-1]['verify'] is False
    # counterproof: the bundle is live for a call without a pin
    federation._send('https://10.0.0.7:5000', [], 'GET', STATUS)
    assert seen[-1]['verify'] == str(bundle)


def test_the_second_fingerprint_of_a_group_is_tried(wire_calls):
    import requests
    seen, state = wire_calls
    state['answer'] = lambda pin: requests.exceptions.SSLError('no match') if pin == FP1 \
        else _Answer(200, b'{"ok": true}')
    status, data, _h = federation._send('https://10.0.0.5:5000', [FP1, FP2], 'GET', STATUS)
    assert status == 200 and data == {'ok': True}
    assert [s['pin'] for s in seen] == [FP1, FP2]


def test_an_answer_over_the_cap_is_refused(wire_calls, sides):
    seen, state = wire_calls
    state['answer'] = lambda pin: _Answer(200, b'x' * (federation.MAX_ANSWER + 10))
    assert federation._send('https://10.0.0.5:5000', [FP1], 'GET', STATUS) == (0, None, {})
    # and through the join, which carries a sealed view
    a, b = sides
    code = _code(a)
    b.runtime['transport'] = None
    with at(b):
        federation._runtime['url_ok'] = {}
    import pegaprox.utils.url_security as us
    us_real = us.is_safe_outbound_url
    try:
        us.is_safe_outbound_url = lambda *a_, **k: (True, '')
        with pytest.raises(federation.FederationError):
            _join(b, code)
    finally:
        us.is_safe_outbound_url = us_real
    assert seen[-1]['url'].endswith(JOIN)


def test_a_redirect_is_never_followed(wire_calls):
    seen, state = wire_calls
    state['answer'] = lambda pin: _Answer(307, b'', {'Location': 'https://10.0.0.9:5000/x'})
    assert federation._send('https://10.0.0.5:5000', [], 'POST', JOIN, {}) == (0, None, {})
    assert len(seen) == 1


def test_a_metadata_address_is_never_dialed(wire_calls):
    seen, _state = wire_calls
    for url in ('https://169.254.169.254', 'http://10.0.0.5:5000'):
        assert federation._send(url, [], 'POST', JOIN, {}) == (0, None, {})
    assert seen == []


# --- the linked view ----------------------------------------------------------------------------

def _stub_members(n):
    keys = {}
    for i in range(n):
        priv = ha_wire.private_key(ha_wire.new_signing_key())
        keys[f'{i + 1:032x}'] = priv
    return keys


def _stub_transport(keys, answers, asked, lock):
    """A pure function of the member and the path (plus a counter under a lock): signs its
    canned answer with that member's key, as the member would."""
    by_url = {f'https://m{n}.example:5000': n for n in keys}

    def transport(url, method, path, body, headers):
        member = by_url[url]
        with lock:
            asked.append(member)
        status, payload = answers(member)
        raw = json.dumps(payload).encode()
        sig = keys[member].sign(federation._answer_message(
            method, path, headers[ha_wire.PEER_NONCE_HEADER], status, raw, member,
            headers[ha_wire.PEER_HEADER]))
        return status, raw, {federation.ANSWER_HEADER: base64.b64encode(sig).decode()}
    return transport


def test_the_view_carries_counts_of_every_site(sides):
    a, _ = sides
    keys = _stub_members(3)
    ids = sorted(keys)

    def answers(member):
        if member == ids[0]:
            rows = [{'id': 'c1', 'name': 'one', 'type': 'proxmox', 'enabled': True,
                     'enrolled': True, 'connected': True, 'nodes': 3, 'vms': 40},
                    {'id': 'c2', 'name': 'two', 'type': 'weird', 'nodes': True, 'vms': -1},
                    {'id': 'c3', 'nodes': 'many', 'vms': 7}]
            return 200, {'clusters': rows, 'total': 3}
        if member == ids[1]:
            return 200, {'clusters': [{'id': f'x{i}', 'name': 'n'} for i in range(150)],
                         'total': 150}
        return 0, {}
    asked, lock = [], threading.Lock()
    with at(a):
        federation.ensure_identity()

        def add(ident):
            for n, priv in keys.items():
                ident['view']['members'][n] = {'url': f'https://m{n}.example:5000',
                                               'public_key': ha_wire.public_of(priv),
                                               'site': f's{n[-1]}', 'fingerprints': []}
            return True
        federation._mutate_identity(add)
        federation._runtime['transport'] = _stub_transport(keys, answers, asked, lock)
        out = federation.federation_clusters()
    first = out['peers'][ids[0]]['clusters']
    assert first[0]['nodes'] == 3 and first[0]['vms'] == 40 and first[0]['connected'] is True
    assert first[1]['type'] == 'other' and 'nodes' not in first[1] and 'vms' not in first[1]
    assert 'nodes' not in first[2] and first[2]['vms'] == 7
    second = out['peers'][ids[1]]
    assert len(second['clusters']) == federation.MAX_VIEW_ROWS and second['total'] == 150
    assert out['peers'][ids[2]]['clusters'] is None
    # every member asked once
    assert sorted(asked) == ids


def test_the_own_clusters_body_is_built_once_per_window(sides, monkeypatch):
    a, _ = sides
    _add_cluster(a, 'own-1')
    built = []
    with at(a):
        federation.ensure_identity()
        real = federation._db
        monkeypatch.setattr(federation, '_db', lambda: built.append(1) or real())
        for _ in range(5):
            assert [r['id'] for r in federation.own_clusters_body()] == ['own-1']
    assert len(built) <= 2
    with at(a):
        body = federation.peer_clusters_body()
    assert body['total'] == 1


def test_the_peer_route_answers_only_for_members(tmp_path):
    a, b, c = _three(tmp_path)
    _enroll(a, 'clx3')
    r = _get(a, federation.CLUSTERS_PATH, {'X-Requested-With': 'XMLHttpRequest'})
    assert r.status_code == 403
    r = _get(a, federation.CLUSTERS_PATH,
             _signed_headers_of(b, iid(a), path=federation.CLUSTERS_PATH))
    assert r.status_code == 200
    data = r.get_json()
    assert data['instance_id'] == iid(a) and any(x['id'] == 'clx3' for x in data['clusters'])
    for rec in data['clusters']:
        assert not {'pass', 'ssh', 'token'} & set(str(rec).lower().split("'"))


def _identity_in(db_file):
    """Whether the database file holds a federation identity, opened the way the app opens
    it (SQLCipher where that backend runs, with the process's master key). A file that
    does not open raises: a check that cannot read the database proves nothing."""
    from pegaprox.core import dbcrypto
    conn = dbcrypto.connect(db_file)
    try:
        try:
            row = conn.execute(
                "SELECT 1 FROM pegaprox_kv WHERE k = 'federation_identity'").fetchone()
        except Exception as e:
            if 'no such table' not in str(e):
                raise
            row = None
    finally:
        conn.close()
    return row is not None


def test_no_federation_test_writes_the_config_dir():
    """The checkout's config/ holds no federation file, and the database the session
    started with holds no federation identity."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for name in ('federation_leases.json', 'federation_state.json'):
        assert not os.path.exists(os.path.join(root, 'config', name)), name
    import tests.conftest as conftest
    boot_db = os.path.join(conftest._BOOT_CONFIG_DIR, 'pegaprox.db')
    if os.path.exists(boot_db):
        assert _identity_in(boot_db) is False


def test_the_config_dir_check_reads_what_it_checks(tmp_path):
    """Counterproof for the check above: it sees an identity row where there is one, finds
    none in a database without it, and a file it cannot open fails it instead of passing."""
    a = Side(tmp_path, 'a')
    db = _db_of(a)
    assert _identity_in(db.db_path) is False
    with at(a):
        federation.ensure_identity()
    assert _identity_in(db.db_path) is True
    junk = tmp_path / 'junk.db'
    junk.write_bytes(os.urandom(4096))
    with pytest.raises(Exception):
        _identity_in(str(junk))


# --- identity federation ---------------------------------------------------------------------
#
# Users, API tokens and passkeys travel; tenants and roles are mapped by an admin of the
# receiving side, and a mirror that names an unmapped one waits quarantined. Every test
# drives a real pull through the wire stand-in.

def _add_local_user(side, username, hash_='h1', role='admin', tenant=None, **cols):
    conn = _db_of(side).conn
    conn.execute("INSERT OR REPLACE INTO users (username, password_salt, "
                 "password_hash, role, tenant, fed_home) VALUES (?, 'salt', ?, ?, ?, '')",
                 (username, hash_, role, tenant))
    for col, value in cols.items():
        conn.execute(f'UPDATE users SET "{col}" = ? WHERE username = ?', (value, username))
    conn.commit()


def _set(side, username, **cols):
    conn = _db_of(side).conn
    for col, value in cols.items():
        conn.execute(f'UPDATE users SET "{col}" = ? WHERE username = ?', (value, username))
    conn.commit()


def _users(side, where_extra=''):
    conn = _db_of(side).conn
    rows = conn.execute("SELECT username, password_hash, fed_home FROM users "
                        f"WHERE username != '' {where_extra}").fetchall()
    return {r['username']: (r['password_hash'], r['fed_home']) for r in rows}


def _row(side, username):
    row = _db_of(side).conn.execute('SELECT * FROM users WHERE username = ?',
                                    (username,)).fetchone()
    return dict(row) if row is not None else None


def _token_hash(token):
    import hashlib
    return hashlib.sha256(token.encode()).hexdigest()


def _add_token(side, token, username, role='viewer', revoked=0, name='ci'):
    conn = _db_of(side).conn
    conn.execute("INSERT OR REPLACE INTO api_tokens (token_hash, token_prefix, username, name, "
                 "role, created_at, revoked, fed_home) VALUES (?, ?, ?, ?, ?, '2026', ?, '')",
                 (_token_hash(token), token[:8], username, name, role, revoked))
    conn.commit()


def _token_row(side, token):
    row = _db_of(side).conn.execute('SELECT * FROM api_tokens WHERE token_hash = ?',
                                    (_token_hash(token),)).fetchone()
    return dict(row) if row is not None else None


def _token_works(side, token):
    from pegaprox.utils.auth import validate_api_token
    with at(side):
        with side.app.test_request_context('/', base_url=URL[side.name]):
            return validate_api_token(token) is not None


def _add_passkey(side, username, cred=b'cred-1', name='key'):
    conn = _db_of(side).conn
    conn.execute("INSERT OR REPLACE INTO webauthn_credentials (username, credential_id, "
                 "public_key, name, user_handle, created_at, fed_home) "
                 "VALUES (?, ?, ?, ?, ?, '2026', '')",
                 (username, cred, b'public-' + cred, name, b'handle-' + username.encode()))
    conn.commit()


def _map(side, home, kind, value, local):
    """An admin of `side` maps a tenant or role of member `home` onto `local`."""
    from pegaprox.api import federation as api_fed
    home_id = iid(home)
    api_fed._etag_cache['etag'] = ''
    with at(side):
        return federation.map_identity(home_id, kind, value, local, by='root')


def _map_rows(side, home):
    home_id = iid(home)
    return {(r['kind'], r['home_value']): (r['local_value'], r['users'])
            for r in _db_of(side).conn.execute(
                'SELECT kind, home_value, local_value, users FROM federation_identity_map '
                'WHERE home = ?', (home_id,)).fetchall()}


def _pull(side, home):
    """One pull of `home` by `side`, the home's etag cache forgotten."""
    from pegaprox.api import federation as api_fed
    home_id = iid(home)
    api_fed._etag_cache['etag'] = ''
    with at(side):
        return federation.pull_identities(home_id)


@pytest.fixture
def identity_sides(tmp_path):
    a, b = Side(tmp_path, 'a'), Side(tmp_path, 'b')
    _wire([a, b])
    return a, b


@pytest.fixture
def audits(monkeypatch):
    """What the applies write to the audit log, (action, details) per entry."""
    from pegaprox.utils import audit
    got = []

    def record(user, action, details=None, **kw):
        if action.startswith('federation.identity_'):
            got.append((action, details))
    monkeypatch.setattr(audit, 'log_audit', record)
    return got


@pytest.fixture
def sessions():
    from pegaprox.utils import auth as auth_mod
    with auth_mod.sessions_lock:
        auth_mod.active_sessions.clear()
    yield auth_mod
    with auth_mod.sessions_lock:
        auth_mod.active_sessions.clear()


def _session_of(side, username, sessions):
    with at(side):
        with side.app.test_request_context('/', base_url=URL[side.name]):
            return sessions.create_session(username, 'viewer')


def _live_sessions(sessions, username):
    with sessions.sessions_lock:
        return [s for s in sessions.active_sessions.values() if s.get('user') == username]


def _pair_with_identities(a, b):
    return _join(b, _code(a))


def _paired_and_mapped(a, b, *users, role='user'):
    """a and b paired, the given users of a at b with tenant 'default' mapped onto b's."""
    for name in users:
        _add_local_user(a, name, role=role)
    _pair_with_identities(a, b)
    out = _map(b, a, 'tenant', 'default', 'default')
    assert out['pulled'], out
    return out


def test_a_user_homed_at_a_is_a_mirror_at_b(identity_sides):
    a, b = identity_sides
    _add_local_user(a, 'alice', hash_='hash-alice')
    _pair_with_identities(a, b)
    assert _users(b)['alice'] == ('hash-alice', iid(a))
    assert _users(a)['alice'] == ('hash-alice', '')


def test_a_changed_password_travels_on_the_next_sync(identity_sides):
    a, b = identity_sides
    _pair_with_identities(a, b)
    _add_local_user(a, 'bob', hash_='first')
    _sync(b)
    assert _users(b)['bob'][0] == 'first'
    _add_local_user(a, 'bob', hash_='second')
    _sync(b)
    assert _users(b)['bob'][0] == 'second'


def test_nothing_to_do_is_an_unchanged_not_a_refetch(identity_sides):
    from pegaprox.api import federation as api_fed
    a, b = identity_sides
    _pair_with_identities(a, b)
    _add_local_user(a, 'carol')
    api_fed._etag_cache['etag'] = ''
    with at(b):
        assert federation.sync_identities()[iid(a)]['applied'] >= 1
        again = federation.sync_identities()[iid(a)]
    # carol waits for a mapping, and the answer says so without a refetch
    assert again == {'unchanged': True, 'quarantined': 1}


def test_a_delete_travels_by_the_diff_and_a_new_row_comes_back(identity_sides):
    a, b = identity_sides
    _add_local_user(a, 'dave')
    _pair_with_identities(a, b)
    assert 'dave' in _users(b)
    _db_of(a).conn.execute("DELETE FROM users WHERE username = 'dave'")
    _db_of(a).conn.commit()
    _sync(b)
    assert 'dave' not in _users(b)
    _add_local_user(a, 'dave', hash_='new-dave')
    _sync(b)
    assert _users(b)['dave'] == ('new-dave', iid(a))


def test_a_local_row_is_never_overwritten(identity_sides):
    a, b = identity_sides
    _pair_with_identities(a, b)
    _add_local_user(a, 'root', hash_='theirs')
    _add_local_user(b, 'root', hash_='ours')
    from pegaprox.api import federation as api_fed
    api_fed._etag_cache['etag'] = ''
    with at(b):
        report = federation.sync_identities()
    assert _users(b)['root'] == ('ours', '')
    assert any('root' in x for x in report[iid(a)]['conflicts'])


def test_tokens_and_passkeys_travel_and_roles_do_not(identity_sides):
    a, b = identity_sides
    _add_local_user(a, 'alice', role='viewer')
    _pair_with_identities(a, b)
    _add_token(a, 'pgx_alice_1', 'alice')
    _add_passkey(a, 'alice')
    conn = _db_of(a).conn
    conn.execute("INSERT INTO custom_roles (name, permissions, fed_home) "
                 "VALUES ('auditor', '[\"logs\"]', '')")
    conn.commit()
    _sync(b)
    assert _token_row(b, 'pgx_alice_1')['fed_home'] == iid(a)
    key = _db_of(b).conn.execute("SELECT fed_home, sign_count FROM webauthn_credentials "
                                 "WHERE credential_id = ?", (b'cred-1',)).fetchone()
    assert key['fed_home'] == iid(a) and key['sign_count'] == 0
    assert _db_of(b).conn.execute("SELECT 1 FROM custom_roles WHERE name = 'auditor'"
                                  ).fetchone() is None
    with at(a):
        snap = federation.identity_snapshot_body()
    assert set(snap['rows']) == {'users', 'api_tokens', 'webauthn_credentials'}
    assert 'tombstones' not in snap


def test_an_identity_snapshot_is_only_from_a_member(identity_sides):
    a, b = identity_sides
    _pair_with_identities(a, b)
    with at(b):
        for bad in ({}, {'fed': federation.FED_MARK, 'home': 'nobody', 'rows': {}},
                    {'fed': 99, 'home': iid(a), 'rows': {}}):
            with pytest.raises(federation.FederationError):
                federation.apply_identity_snapshot(bad, iid(a))
        with pytest.raises(federation.FederationError):
            federation.apply_identity_snapshot({'fed': federation.FED_MARK, 'home': iid(a),
                                                'rows': {}}, sender='9' * 32)
        # a home that is no member is refused even when it sends for itself
        with pytest.raises(federation.FederationError):
            federation.apply_identity_snapshot({'fed': federation.FED_MARK, 'home': '9' * 32,
                                                'rows': {}}, sender='9' * 32)
        with pytest.raises(TypeError):
            federation.apply_identity_snapshot({'fed': federation.FED_MARK, 'home': iid(a),
                                                'rows': {}})


def test_foreign_home_names_the_owner(identity_sides):
    a, b = identity_sides
    _pair_with_identities(a, b)
    _add_local_user(a, 'frank')
    _sync(b)
    with at(b):
        assert federation.foreign_home('users', ('frank',)) == iid(a)
        assert federation.foreign_home('users', ('nobody',)) == ''
    with at(a):
        assert federation.foreign_home('users', ('frank',)) == ''
    from pegaprox.utils.auth import hash_password, verify_password
    salt, ph = hash_password('the-password')
    _db_of(a).conn.execute("UPDATE users SET password_salt = ?, password_hash = ? "
                           "WHERE username = 'frank'", (salt, ph))
    _db_of(a).conn.commit()
    _sync(b)
    row = _row(b, 'frank')
    assert verify_password('the-password', row['password_salt'], row['password_hash'])


def test_a_second_factor_never_travels_as_ciphertext(identity_sides):
    a, b = identity_sides
    _pair_with_identities(a, b)
    conn = _db_of(a).conn
    conn.execute("INSERT INTO users (username, password_salt, password_hash, role, "
                 "totp_enabled, totp_secret_encrypted, fed_home) "
                 "VALUES ('gina', 'salt', 'hash', 'viewer', 1, 'Zm9yZWlnbg==', '')")
    conn.commit()
    _sync(b)
    with at(b):
        row = _row(b, 'gina')
        assert row['totp_enabled'] == 1 and row['totp_secret_encrypted'] == ''
        assert row['fed_home'] == iid(a)
        from pegaprox.utils.auth import load_users
        assert load_users()['gina']['fed_home'] == iid(a)


# --- tenants and roles: mapped, never matched by name ------------------------------------------

def test_an_unmapped_tenant_lands_quarantined(identity_sides):
    a, b = identity_sides
    _add_local_user(a, 'ann', role='user', tenant='acme')
    _pair_with_identities(a, b)
    row = _row(b, 'ann')
    assert (row['tenant'], row['role'], row['enabled']) == (federation.QUARANTINE,
                                                             federation.QUARANTINE, 0)
    assert row['permissions'] == '[]' and row['tenant_permissions'] == '{}'
    assert _map_rows(b, a) == {('tenant', 'acme'): ('', 1)}
    # counterproof: mapped onto a tenant of b, the re-pull lands it there, enabled
    _db_of(b).save_tenant('acme-b', {'name': 'Acme here', 'clusters': ['c1']})
    out = _map(b, a, 'tenant', 'acme', 'acme-b')
    assert out['saved'] and out['pulled'], out
    row = _row(b, 'ann')
    assert (row['tenant'], row['role'], row['enabled']) == ('acme-b', 'user', 1)
    assert _map_rows(b, a)[('tenant', 'acme')] == ('acme-b', 1)


def test_a_same_named_tenant_does_not_resolve_by_itself(identity_sides):
    a, b = identity_sides
    _db_of(b).save_tenant('customer', {'name': 'customer', 'clusters': []})
    _add_local_user(a, 'cora', role='user', tenant='customer')
    _pair_with_identities(a, b)
    row = _row(b, 'cora')
    assert row['tenant'] == federation.QUARANTINE and row['enabled'] == 0


def test_the_default_tenant_needs_a_mapping_too(identity_sides):
    a, b = identity_sides
    _add_local_user(a, 'dina', role='user')
    _pair_with_identities(a, b)
    row = _row(b, 'dina')
    assert row['tenant'] == federation.QUARANTINE and row['enabled'] == 0
    assert _map_rows(b, a) == {('tenant', 'default'): ('', 1)}
    _map(b, a, 'tenant', 'default', 'default')
    row = _row(b, 'dina')
    assert (row['tenant'], row['role'], row['enabled']) == ('default', 'user', 1)


def test_a_custom_role_resolves_only_through_a_mapping(identity_sides):
    a, b = identity_sides
    # b has a role of that name, broader than a's
    _db_of(b).conn.execute("INSERT INTO custom_roles (name, permissions, tenant_id, fed_home) "
                           "VALUES ('support', '[\"vm.delete\", \"node.reboot\"]', '', '')")
    _db_of(b).conn.commit()
    _add_local_user(a, 'sam', role='support')
    _add_local_user(a, 'uma', role='user')
    _paired_and_mapped(a, b)
    assert _row(b, 'sam')['role'] == federation.QUARANTINE
    assert _map_rows(b, a)[('role', 'support')] == ('', 1)
    # counterproof: a builtin role passes by name once the tenant is mapped
    assert (_row(b, 'uma')['role'], _row(b, 'uma')['enabled']) == ('user', 1)
    _map(b, a, 'role', 'support', 'viewer')
    row = _row(b, 'sam')
    assert (row['tenant'], row['role'], row['enabled']) == ('default', 'viewer', 1)


def test_a_role_mapped_onto_another_tenants_role_does_not_resolve(identity_sides):
    """A tenant role resolves only for its own tenant: mapped onto a role of tenant X, an
    account of the default tenant does not quietly move into X."""
    a, b = identity_sides
    _db_of(b).save_tenant('x', {'name': 'x', 'clusters': ['cx']})
    _db_of(b).conn.execute("INSERT INTO custom_roles (name, permissions, tenant_id, fed_home) "
                           "VALUES ('x-ops', '[\"vm.view\"]', 'x', '')")
    _db_of(b).conn.commit()
    _add_local_user(a, 'sam', role='support')
    _paired_and_mapped(a, b)
    _map(b, a, 'role', 'support', 'x-ops')
    assert _row(b, 'sam')['tenant'] == federation.QUARANTINE


def test_an_unmapped_tenant_override_quarantines(identity_sides):
    a, b = identity_sides
    _add_local_user(a, 'olga', role='admin',
                    tenant_permissions=json.dumps({'globex': {'role': 'viewer'}}))
    _paired_and_mapped(a, b)
    row = _row(b, 'olga')
    # the override caps an admin in globex: dropping it would widen her, so she waits
    assert row['tenant'] == federation.QUARANTINE and row['enabled'] == 0
    assert _map_rows(b, a)[('tenant', 'globex')] == ('', 1)
    _db_of(b).save_tenant('globex-b', {'name': 'g', 'clusters': ['cg']})
    _map(b, a, 'tenant', 'globex', 'globex-b')
    row = _row(b, 'olga')
    assert row['role'] == 'admin' and row['enabled'] == 1
    assert json.loads(row['tenant_permissions']) == {'globex-b': {'role': 'viewer'}}


def test_unmapping_blocks_at_once_without_the_home(identity_sides, sessions):
    a, b = identity_sides
    _paired_and_mapped(a, b, 'una')
    assert _row(b, 'una')['enabled'] == 1
    _session_of(b, 'una', sessions)
    assert _live_sessions(sessions, 'una')
    # a goes silent: the mapping is taken away anyway
    b.runtime['transport'] = lambda *args: (0, b'', {})
    out = _map(b, a, 'tenant', 'default', '')
    assert out == {'saved': True, 'pulled': False, 'report': {'failed': True}}
    row = _row(b, 'una')
    assert (row['tenant'], row['enabled']) == (federation.QUARANTINE, 0)
    assert _live_sessions(sessions, 'una') == []
    assert _map_rows(b, a)[('tenant', 'default')] == ('', 1)


def test_a_mapping_needs_a_value_the_home_uses_and_a_local_target(identity_sides):
    a, b = identity_sides
    _add_local_user(a, 'vera', role='user')
    _pair_with_identities(a, b)
    with pytest.raises(federation.FederationError) as e:
        _map(b, a, 'tenant', 'nobody-uses-this', 'default')
    assert e.value.code == 'FED_MAP_UNKNOWN'
    with pytest.raises(federation.FederationError) as e:
        _map(b, a, 'tenant', 'default', 'no-such-tenant-here')
    assert e.value.code == 'FED_MAP_INVALID'
    with pytest.raises(federation.FederationError) as e:
        with at(b):
            federation.map_identity('9' * 32, 'tenant', 'default', 'default', by='root')
    assert e.value.code == 'FED_NOT_MEMBER'
    assert _row(b, 'vera')['enabled'] == 0


def test_a_token_with_an_unmapped_role_is_not_mirrored(identity_sides):
    a, b = identity_sides
    _add_local_user(a, 'tom', role='user')
    _add_token(a, 'pgx_tom_custom', 'tom', role='deployer')
    _add_token(a, 'pgx_tom_plain', 'tom', role='viewer')
    report = _paired_and_mapped(a, b)['report']
    assert _token_row(b, 'pgx_tom_custom') is None
    assert _token_row(b, 'pgx_tom_plain') is not None
    assert any('not mapped' in c for c in report['conflicts'])
    assert _map_rows(b, a)[('role', 'deployer')] == ('', 0)
    # counterproof: mapped, it is mirrored with the local role
    _map(b, a, 'role', 'deployer', 'viewer')
    assert _token_row(b, 'pgx_tom_custom')['role'] == 'viewer'


def test_directory_groups_never_travel(identity_sides):
    a, b = identity_sides
    _add_local_user(a, 'lena', role='user', auth_source='ldap',
                    directory_groups=json.dumps(['admins']))
    _paired_and_mapped(a, b)
    row = _row(b, 'lena')
    assert row['auth_source'] == 'ldap' and json.loads(row['directory_groups'] or '[]') == []
    b.db.save_pool_permission('c1', 'pool1', 'group', 'admins', ['vm.view'])
    with at(b):
        assert b.db.get_user_pool_clusters('lena', []) == []
    # counterproof: a local directory account of b in 'admins' reaches that pool
    _add_local_user(b, 'local-lena', role='user', auth_source='ldap',
                    directory_groups=json.dumps(['admins']))
    with at(b):
        assert b.db.get_user_pool_clusters('local-lena', []) == ['c1']


# --- compare before write, and the audit of what changed ---------------------------------------

def test_an_unchanged_row_writes_nothing(identity_sides, audits, monkeypatch):
    a, b = identity_sides
    _paired_and_mapped(a, b, 'ina', 'ivo')
    audits.clear()
    _set(a, 'ina', display_name='Ina at home')
    report = _pull(b, a)
    assert (report['updated'], report['unchanged']) == (1, 1), report
    assert audits == [('federation.identity_applied',
                       f'user "ina" from {iid(a)[:8]}: updated')]
    # counterproof: with the compare broken every row is written and audited again
    audits.clear()
    _set(a, 'ina', display_name='Ina again')
    monkeypatch.setattr(federation, '_comparable', lambda values: {'never': object()})
    report = _pull(b, a)
    assert report['updated'] == 2 and len(audits) == 2


def test_a_raise_to_admin_is_flagged_once(identity_sides, audits):
    a, b = identity_sides
    _paired_and_mapped(a, b, 'rita')
    audits.clear()
    _set(a, 'rita', role='admin')
    _pull(b, a)
    assert [x[0] for x in audits] == ['federation.identity_escalated']
    assert 'role raised to admin' in audits[0][1]
    audits.clear()
    _set(a, 'rita', email='rita@example.org')
    _pull(b, a)
    assert [x[0] for x in audits] == ['federation.identity_applied']


def test_a_snapshot_that_fails_late_lands_nothing(identity_sides, audits, sessions,
                                                  monkeypatch):
    """One snapshot, one commit. A snapshot that drops one mirror (whose grants go with
    it), changes another's password and raises a third to admin, and then fails in its
    cluster half, leaves every mirror as it was. The retry lands all of it, ends the
    session of the re-passworded account and flags the raise once."""
    a, b = identity_sides
    _paired_and_mapped(a, b, 'gone', 'kept', 'rita')
    _session_of(b, 'kept', sessions)
    _set(a, 'kept', password_hash='new-hash')
    _set(a, 'rita', role='admin')
    _db_of(a).conn.execute("DELETE FROM users WHERE username = 'gone'")
    _db_of(a).conn.commit()
    audits.clear()
    real = federation._apply_cluster_mirrors

    def broken(*args, **kwargs):
        raise RuntimeError('the cluster half failed')
    monkeypatch.setattr(federation, '_apply_cluster_mirrors', broken)
    assert _pull(b, a) == {'failed': True}
    held = _users(b)
    assert 'gone' in held and held['kept'][0] == 'h1'
    assert _row(b, 'rita')['role'] == 'user'
    assert _live_sessions(sessions, 'kept') and audits == []
    monkeypatch.setattr(federation, '_apply_cluster_mirrors', real)
    report = _pull(b, a)
    assert report['deleted'] == 1 and report['updated'] == 2, report
    held = _users(b)
    assert 'gone' not in held and held['kept'][0] == 'new-hash'
    assert _row(b, 'rita')['role'] == 'admin'
    assert not _live_sessions(sessions, 'kept')
    assert [x for x in audits if x[0] == 'federation.identity_escalated'
            and 'rita' in x[1]] and len([x for x in audits
                                          if x[0] == 'federation.identity_escalated']) == 1


def test_granted_permissions_and_lifted_denials_are_flagged(identity_sides, audits):
    a, b = identity_sides
    _add_local_user(a, 'pia', role='user', denied_permissions=json.dumps(['vm.delete']))
    _paired_and_mapped(a, b)
    audits.clear()
    _set(a, 'pia', permissions=json.dumps(['node.reboot']), denied_permissions='[]')
    _pull(b, a)
    assert [x[0] for x in audits] == ['federation.identity_escalated']
    assert 'permissions added: node.reboot' in audits[0][1]
    assert 'denials lifted: vm.delete' in audits[0][1]


def test_a_revoked_token_coming_back_is_flagged(identity_sides, audits):
    a, b = identity_sides
    _add_local_user(a, 'tia', role='user')
    _add_token(a, 'pgx_tia_1', 'tia', revoked=1)
    _paired_and_mapped(a, b)
    audits.clear()
    _db_of(a).conn.execute('UPDATE api_tokens SET revoked = 0 WHERE token_hash = ?',
                           (_token_hash('pgx_tia_1'),))
    _db_of(a).conn.commit()
    _pull(b, a)
    assert [x[0] for x in audits] == ['federation.identity_escalated']
    assert 'a revoked token came back' in audits[0][1]
    assert _token_row(b, 'pgx_tia_1')['revoked'] == 0


def test_routine_changes_are_summed_up_past_the_cap(identity_sides, audits):
    a, b = identity_sides
    names = [f'u{i:02d}' for i in range(60)]
    _paired_and_mapped(a, b, *names)
    audits.clear()
    conn = _db_of(a).conn
    conn.execute("UPDATE users SET display_name = 'changed'")
    conn.commit()
    report = _pull(b, a)
    assert report['updated'] == 60
    assert len(audits) == federation.AUDIT_ROUTINE_CAP + 1
    assert audits[-1][1].startswith('and 10 more from') and 'users +0 ~10 -0' in audits[-1][1]


def test_a_mapping_that_lets_accounts_in_is_no_escalation(identity_sides, audits):
    a, b = identity_sides
    _add_local_user(a, 'adam', role='admin')
    _pair_with_identities(a, b)
    audits.clear()
    _map(b, a, 'tenant', 'default', 'default')
    assert [x[0] for x in audits] == ['federation.identity_applied']
    assert audits[0][1].endswith('mapped here')


def test_a_passkey_sign_in_at_the_home_leaves_the_mirror_alone(identity_sides):
    a, b = identity_sides
    _add_local_user(a, 'kim', role='user')
    _add_passkey(a, 'kim')
    _paired_and_mapped(a, b)
    conn = _db_of(a).conn
    conn.execute("UPDATE webauthn_credentials SET sign_count = 41, last_used_at = 'now'")
    conn.commit()
    assert _pull(b, a) == {'unchanged': True, 'quarantined': 0}
    # counterproof: a renamed key does move the snapshot
    conn.execute("UPDATE webauthn_credentials SET name = 'renamed'")
    conn.commit()
    assert _pull(b, a)['updated'] == 1


# --- tokens and passkeys belong to a mirror of the same home ------------------------------------

def test_a_token_for_a_user_nobody_holds_is_not_mirrored(identity_sides):
    a, b = identity_sides
    _add_local_user(a, 'nina', role='user')
    _paired_and_mapped(a, b)
    # a row for an account the home does not hold - nothing names it at b either
    _add_token(a, 'pgx_ghost_1', 'futureadmin', role='admin')
    _add_passkey(a, 'futureadmin', cred=b'ghost-key')
    report = _pull(b, a)
    assert _token_row(b, 'pgx_ghost_1') is None
    assert sum('futureadmin' in c for c in report['conflicts']) == 2
    # later an admin at b creates a local account of that name: the token is no key to it
    _add_local_user(b, 'futureadmin', role='admin')
    _pull(b, a)
    assert _token_row(b, 'pgx_ghost_1') is None
    assert not _token_works(b, 'pgx_ghost_1')


def test_an_update_cannot_retarget_a_token_or_a_passkey(identity_sides):
    a, b = identity_sides
    _add_local_user(a, 'alice', role='user')
    _add_token(a, 'pgx_alice_2', 'alice')
    _add_passkey(a, 'alice', cred=b'alice-key')
    _paired_and_mapped(a, b)
    assert _token_works(b, 'pgx_alice_2')
    _add_local_user(b, 'localadmin', role='admin')
    conn = _db_of(a).conn
    conn.execute("UPDATE api_tokens SET username = 'localadmin', role = 'admin'")
    conn.execute("UPDATE webauthn_credentials SET username = 'localadmin'")
    conn.commit()
    _pull(b, a)
    # the held copies are gone, nothing names b's local admin
    assert _token_row(b, 'pgx_alice_2') is None
    assert not _token_works(b, 'pgx_alice_2')
    assert _db_of(b).conn.execute("SELECT COUNT(*) FROM webauthn_credentials WHERE "
                                  "username = 'localadmin'").fetchone()[0] == 0


def test_a_token_revoked_at_the_home_stops_working_at_the_mirror(identity_sides):
    a, b = identity_sides
    _add_local_user(a, 'ron', role='user')
    _add_token(a, 'pgx_ron_1', 'ron')
    _paired_and_mapped(a, b)
    assert _token_works(b, 'pgx_ron_1')
    _db_of(a).conn.execute('UPDATE api_tokens SET revoked = 1')
    _db_of(a).conn.commit()
    _pull(b, a)
    assert not _token_works(b, 'pgx_ron_1')


# --- local twins, deletes, sessions and the orphan sweep ---------------------------------------

def test_a_snapshot_never_touches_a_local_twin(identity_sides, sessions):
    a, b = identity_sides
    _pair_with_identities(a, b)
    _add_local_user(b, 'bob', hash_='ours', role='user')
    b.db.save_vm_acl('c1', '100', {'users': ['bob'], 'inherit_role': True, 'permissions': []})
    b.db.save_pool_permission('c1', 'pool1', 'user', 'bob', ['vm.view'])
    _session_of(b, 'bob', sessions)

    def intact():
        assert _users(b)['bob'] == ('ours', '')
        assert any('bob' in acl['users'] for acl in b.db.get_all_vm_acls()['c1'].values())
        assert b.db.get_user_pool_clusters('bob', []) == ['c1']
        assert len(_live_sessions(sessions, 'bob')) == 1
    # a lists a 'bob' of its own: a conflict
    _add_local_user(a, 'bob', hash_='theirs')
    report = _pull(b, a)
    assert any('bob' in c for c in report['conflicts'])
    intact()
    # a drops it: the diff does not reach the local row
    _db_of(a).conn.execute("DELETE FROM users WHERE username = 'bob'")
    _db_of(a).conn.commit()
    _pull(b, a)
    intact()
    # a forged body that still carries the old tombstones changes nothing either
    with at(a):
        body = federation.identity_snapshot_body()
    body['tombstones'] = [{'kind': 'user', 'key': 'bob', 'at': 1}]
    body['custom_roles'] = [{'name': 'evil', 'permissions': '["*"]'}]
    with at(b):
        federation.apply_identity_snapshot(body, iid(a))
    intact()
    assert _db_of(b).conn.execute("SELECT 1 FROM custom_roles WHERE name = 'evil'"
                                  ).fetchone() is None


def test_a_user_deleted_at_the_home_is_signed_out_at_the_mirror(identity_sides, sessions):
    a, b = identity_sides
    _paired_and_mapped(a, b, 'dora')
    _session_of(b, 'dora', sessions)
    assert _live_sessions(sessions, 'dora')
    _db_of(a).conn.execute("DELETE FROM users WHERE username = 'dora'")
    _db_of(a).conn.commit()
    assert _pull(b, a)['deleted'] == 1
    assert _row(b, 'dora') is None and _live_sessions(sessions, 'dora') == []


def test_a_user_disabled_at_the_home_is_signed_out_at_the_mirror(identity_sides, sessions):
    a, b = identity_sides
    _paired_and_mapped(a, b, 'oskar')
    _session_of(b, 'oskar', sessions)
    assert _live_sessions(sessions, 'oskar')
    _set(a, 'oskar', enabled=0)
    _pull(b, a)
    row = _row(b, 'oskar')
    assert row['enabled'] == 0 and row['fed_home'] == iid(a)
    assert _live_sessions(sessions, 'oskar') == []


def test_an_unrelated_change_keeps_the_session(identity_sides, sessions):
    """Counterproof for the two above: a change that takes nothing away ends no session."""
    a, b = identity_sides
    _paired_and_mapped(a, b, 'otto')
    _session_of(b, 'otto', sessions)
    _set(a, 'otto', display_name='Otto')
    assert _pull(b, a)['updated'] == 1
    assert len(_live_sessions(sessions, 'otto')) == 1


def test_mirrors_of_a_home_outside_the_registry_go_at_the_next_sync(identity_sides):
    a, b = identity_sides
    _paired_and_mapped(a, b, 'kept')
    gone = 'e' * 32
    conn = _db_of(b).conn
    conn.execute("INSERT INTO users (username, password_salt, password_hash, role, fed_home) "
                 "VALUES ('stray', 's', 'h', 'admin', ?)", (gone,))
    conn.execute("INSERT INTO api_tokens (token_hash, token_prefix, username, name, role, "
                 "created_at, fed_home) VALUES ('th-stray', 'pgx_s', 'stray', 'ci', 'admin', "
                 "'2026', ?)", (gone,))
    conn.execute("INSERT INTO federation_identity_map (home, kind, home_value) "
                 "VALUES (?, 'tenant', 'default')", (gone,))
    conn.commit()
    _sync(b)
    assert _row(b, 'stray') is None
    for table in ('api_tokens', 'federation_identity_map'):
        col = 'home' if table == 'federation_identity_map' else 'fed_home'
        assert conn.execute(f'SELECT COUNT(*) FROM {table} WHERE {col} = ?',
                            (gone,)).fetchone()[0] == 0
    # counterproof: the member's own mirrors stay
    assert _row(b, 'kept')['fed_home'] == iid(a)


def test_the_orphan_sweep_stands_still_when_the_view_cannot_be_read(identity_sides, monkeypatch):
    a, b = identity_sides
    _paired_and_mapped(a, b, 'kept2')

    def broken():
        raise federation.FederationError('unreadable')
    with at(b):
        monkeypatch.setattr(federation, 'members', broken)
        assert federation.drop_orphan_mirrors() == []
    assert _row(b, 'kept2') is not None


# --- whole-table saves never undo the sync -------------------------------------------------------

def test_a_whole_table_save_never_undoes_a_mirror_change(identity_sides, monkeypatch):
    from pegaprox.utils.auth import load_users, save_users
    a, b = identity_sides
    _paired_and_mapped(a, b, 'bea')
    with at(b):
        stale = load_users()
    assert stale['bea']['enabled'] is True
    _set(a, 'bea', enabled=0)
    _pull(b, a)
    assert _row(b, 'bea')['enabled'] == 0
    stale['bea']['theme'] = 'dark'
    with at(b):
        save_users(stale)
    row = _row(b, 'bea')
    # the workbench is written, what the home decides is not
    assert row['enabled'] == 0 and row['theme'] == 'dark' and row['fed_home'] == iid(a)
    # counterproof: with the federation off the same save writes the snapshot back
    monkeypatch.setenv(federation.ENV_SWITCH, '0')
    with at(b):
        save_users(stale)
    assert _row(b, 'bea')['enabled'] == 1


def test_a_whole_table_save_never_brings_a_dropped_mirror_back(tmp_path):
    from pegaprox.utils.auth import load_users, save_users
    a, b, c = _three(tmp_path)
    _add_local_user(a, 'max', role='admin')
    _sync(b)
    assert _row(b, 'max') is not None
    with at(b):
        stale = load_users()
        federation.remove_member(iid(a), by='admin:root')
    assert _row(b, 'max') is None
    with at(b):
        save_users(stale)
    assert _row(b, 'max') is None


def test_the_identity_map_view_lists_every_member(identity_sides):
    a, b = identity_sides
    _add_local_user(a, 'wim', role='support', tenant='acme')
    _pair_with_identities(a, b)
    _db_of(b).conn.execute("INSERT INTO custom_roles (name, permissions, tenant_id, fed_home) "
                           "VALUES ('helpdesk', '[]', '', '')")
    _db_of(b).conn.commit()
    with at(b):
        view = federation.identity_map_view()
        counts = federation.unmapped_counts()
    entries = view['members'][iid(a)]['entries']
    assert view['members'][iid(a)]['site'] == 'site-a'
    assert {(e['kind'], e['home_value'], e['local_value'], e['users']) for e in entries} == {
        ('tenant', 'acme', '', 1), ('role', 'support', '', 1)}
    assert view['local']['roles'][:3] == ['admin', 'user', 'viewer']
    assert 'helpdesk' in view['local']['roles']
    assert any(t['id'] == 'default' for t in view['local']['tenants'])
    assert counts == {iid(a): 2}
