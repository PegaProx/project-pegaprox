"""Linked mode, the relay under load and from a member that does not play fair.

- One account's calls to a site no longer fill the store of nonces the site keeps for this
  one: each account has a rate of its own (ACCOUNT_RATE), the site counts a member's calls
  before it spends a nonce, and a full store says busy, not "not a member".
- A member's relayed request no longer counts against the address it names (the user's at
  its site): it could spend the rate window of any address here, loopback included, which
  stopped the console servers' token check.
- A relay session opens once the request is built: a path that would not encode left one
  behind until the session timeout.
- An upload announced and never sent holds neither the disk nor a slot of the site.
- The migration route dials under the breaker, the account's rate and the slots.
- The leading site lifts the 30 s body clock for an upload it took.
MK Nov 2026
"""
import json
import secrets
import shutil
import time
from collections import namedtuple

import pytest

import pegaprox.utils.auth as authmod
from pegaprox.app import _BodyDeadline
from pegaprox.core import federation, ha_wire
from pegaprox.core import federation_relay as relay
from pegaprox.utils.auth import BODY_DEADLINE_ENVIRON
from tests.conftest import make_fake_manager
from tests.test_federation import (  # noqa: F401 - fixtures by name
    _add_local_user, _defaults_out_of_the_config_dir, _fresh_budgets, _pull, at, iid)
from tests.test_federation_auth_guards import PEER, _add_member, fed  # noqa: F401
from tests.test_federation_relay import (  # noqa: F401 - fixtures by name
    CID, UPLOADED, _fresh_relay, _get, _post, _relayed_calls, _session, _upload, linked)


# --- one account and the site's nonces --------------------------------------------------------

def test_one_account_does_not_cut_its_site_off(linked):
    a, b = linked
    alice, vic = _session(a, 'alice'), _session(a, 'vic')
    bogus = f'/api/clusters/nosuch~{iid(b)}/status'
    codes = [_get(a, bogus, vic).status_code for _ in range(relay.ACCOUNT_RATE + 20)]
    # the viewer's own rate ran out, at this site, before b spent a nonce for it
    assert codes[-1] == 429 and codes.count(404) == relay.ACCOUNT_RATE
    assert len(relay._nonces.get(iid(a), {})) <= relay.ACCOUNT_RATE
    # alice reaches b as before
    r = _get(a, f'/api/clusters/{CID}~{iid(b)}/status', alice)
    assert r.status_code == 200 and r.get_json()['user'] == 'alice', r.data


def test_a_call_over_the_sites_rate_spends_no_nonce(linked, monkeypatch):
    from pegaprox.utils.ratelimit import SlidingWindow
    a, b = linked
    monkeypatch.setattr(relay, '_sender_rate', SlidingWindow(limit=2, window=60, max_keys=8))
    sid = _session(a, 'alice')
    path = f'/api/clusters/{CID}~{iid(b)}/status'
    assert [_get(a, path, sid).status_code for _ in range(2)] == [200, 200]
    r = _get(a, path, sid)
    assert r.status_code == 429 and r.get_json()['code'] == 'FED_RELAY_BUSY'
    assert len(relay._nonces[iid(a)]) == 2


def test_a_full_store_of_nonces_says_busy(linked, monkeypatch):
    a, b = linked
    monkeypatch.setattr(relay, 'RELAY_NONCES', 2)
    sid = _session(a, 'alice')
    path = f'/api/clusters/{CID}~{iid(b)}/status'
    assert [_get(a, path, sid).status_code for _ in range(2)] == [200, 200]
    r = _get(a, path, sid)
    # not "not a member": the browser hears that the site is busy
    assert r.status_code == 429 and r.get_json()['code'] == 'FED_RELAY_BUSY', r.data


# --- the address a member names ---------------------------------------------------------------

VICTIM = '198.51.100.7'
ELSEWHERE = '203.0.113.9'


def _relayed(priv, me, path, ip):
    envelope = {'v': relay.RELAY_VERSION, 'rid': secrets.token_hex(16), 'method': 'GET',
                'path': path, 'query': '', 'ctype': '',
                'principal': {'user': 'mallory', 'home': PEER, 'sh': '', 'ip': ip}}
    env_text = relay._b64(json.dumps(envelope, separators=(',', ':'), sort_keys=True).encode())
    body_sha = relay._sha(b'')
    ts, nonce = str(int(time.time())), secrets.token_urlsafe(18)
    sig = priv.sign(relay._request_message(body_sha, relay._sha(env_text.encode()), ts, nonce,
                                           me, PEER, relay.RELAY_PATH))
    import base64
    return {ha_wire.PEER_HEADER: PEER, ha_wire.PEER_TS_HEADER: ts,
            ha_wire.PEER_NONCE_HEADER: nonce,
            ha_wire.PEER_SIG_HEADER: base64.b64encode(sig).decode(),
            relay.ENVELOPE_HEADER: env_text, relay.BODY_HEADER: body_sha,
            'X-Requested-With': federation.PEER_XHR, 'Content-Type': 'application/json'}



@pytest.fixture
def leading(fed, seed):
    from pegaprox.constants import API_RATE_LIMIT
    relay.reset_for_tests()
    federation.ensure_identity()
    federation._lease_state()
    priv = _add_member(federation)
    # the member's account, mirrored here and mapped to a tenant that holds no cluster:
    # every request it makes is refused, and that is all it needs
    seed.tenant('nothing', clusters=['other'])
    seed.user('mallory', role='viewer', tenant_id='nothing')
    seed.db.conn.execute("UPDATE users SET fed_home = ? WHERE username = 'mallory'", (PEER,))
    seed.db.conn.commit()
    fed.set_manager('pve1', make_fake_manager('pve1'))
    root = fed.as_user(seed.user('root', role='admin'))
    yield fed, priv, root, API_RATE_LIMIT
    relay.reset_for_tests()
    import pegaprox.globals as ppglobals
    ppglobals.api_rate_window.reset()



def test_a_member_does_not_spend_the_rate_window_of_an_address_it_names(leading):
    api, priv, root, limit = leading
    me = federation.instance_id()
    client = api.app.test_client()
    for ip in (VICTIM, '127.0.0.1'):
        for _ in range(limit + 5):
            r = client.post(relay.RELAY_PATH, data=b'',
                            headers=_relayed(priv, me, '/api/clusters/pve1/nodes', ip))
            assert r.status_code == 200 and relay.SIG_HEADER in r.headers, r.data
        inner = json.loads(relay._unb64(r.headers[relay.ANSWER_HEADER]))['status']
        assert inner != 429, inner
    # the admin of this site still works from that address
    r = root.get('/api/user/preferences', environ_base={'REMOTE_ADDR': VICTIM})
    assert r.status_code == 200, r.data
    # and the console servers' token check from loopback goes through
    from pegaprox.utils.realtime import create_ws_token
    r = client.get(f"/api/ws/token/validate?token={create_ws_token('root', 'admin')}",
                   environ_base={'REMOTE_ADDR': '127.0.0.1'})
    assert r.status_code == 200 and r.get_json().get('user') == 'root', r.data


# --- a path that does not encode ----------------------------------------------------------------

def _relay_sessions():
    with authmod.sessions_lock:
        return {sid: dict(s) for sid, s in authmod.active_sessions.items() if s.get('fed_relay')}


def test_a_path_that_does_not_encode_leaves_no_relay_session(linked):
    a, b = linked
    principal = {'user': 'alice', 'home': iid(a), 'sh': '', 'ip': ''}
    for _ in range(3):
        with at(a):
            relay.relay_call(iid(b), 'POST', f'/api/clusters/{CID}/vms/n1\ud800/qemu/101/start',
                             body=b'{}', ctype='application/json', principal=principal)
    assert _relay_sessions() == {}
    assert relay.valid_envelope({'v': relay.RELAY_VERSION, 'method': 'GET',
                                 'path': '/api/clusters/x\ud800', 'query': '', 'ctype': '',
                                 'rid': secrets.token_hex(16),
                                 'principal': {'user': 'u', 'home': 'a' * 32}}) is None


# --- an upload that never comes ---------------------------------------------------------------

_Usage = namedtuple('_Usage', 'total used free')
FREE = 2 * 1024 ** 3


class _HeldBody:
    """A body of `size` bytes that never comes: on the first read it lets `during` run
    (what the site does meanwhile), then the client goes away."""

    def __init__(self, size, during):
        self.size, self.during, self.reads, self.pos = size, during, 0, 0

    def tell(self):
        return self.pos

    def seek(self, pos, whence=0):
        self.pos = self.size if whence == 2 else pos
        return self.pos

    def read(self, n=-1):
        self.reads += 1
        if self.reads == 1:
            self.during()
        return b''

    def readinto(self, b):
        self.read()
        return 0



@pytest.fixture
def uploader(linked, monkeypatch):
    a, b = linked
    _add_local_user(a, 'uma', role='user')
    _pull(b, a)
    real = shutil.disk_usage
    monkeypatch.setattr(shutil, 'disk_usage',
                        lambda p: _Usage(real(p).total, real(p).total - FREE, FREE))
    return a, b



def test_an_upload_that_never_comes_holds_neither_the_disk_nor_the_site(uploader):
    a, b = uploader
    uma, alice = _session(a, 'uma'), _session(a, 'alice')
    seen = {}

    def meanwhile():
        seen['slots'] = relay._uploads_out._per.get(iid(b))
        seen['other'] = _upload(a, b, alice)

    announced = FREE - relay.UPLOAD_RESERVE - 1
    with at(a):
        r = a.client.post(f'/api/clusters/{CID}~{iid(b)}/datastores/local/upload',
                          input_stream=_HeldBody(announced, meanwhile),
                          content_type='multipart/form-data; boundary=x',
                          headers={'X-Session-ID': uma, 'X-Requested-With': 'XMLHttpRequest'})
    assert r.status_code == 400, r.data
    # while uma's body did not come, no slot of the site was hers, and alice's went through
    assert not seen['slots']
    assert seen['other'].status_code == 200, seen['other'].data
    assert [u[0] for u in UPLOADED] == ['alice']


# --- the migration's own calls ------------------------------------------------------------------

def _migrate(a, b, sid):
    return _post(a, '/api/federation/migrate', sid, {
        'source_cluster': f'{CID}~{iid(b)}', 'target_cluster': CID, 'vmid': 101,
        'vm_type': 'qemu', 'source_node': 'n1', 'target_node': 'n1',
        'target_storage': 'local-lvm'})


def test_a_migration_dials_under_the_slots_and_the_breaker(linked, monkeypatch):
    a, b = linked
    vic = _session(a, 'vic')
    monkeypatch.setattr(relay, 'SLOT_WAIT', 0)
    for n in range(relay._out.each):
        assert relay._out.take(iid(b)), n
    before = len(_relayed_calls(a))
    r = _migrate(a, b, vic)
    assert r.status_code == 429 and r.get_json()['code'] == 'FED_RELAY_BUSY', r.data
    assert len(_relayed_calls(a)) == before
    for _ in range(relay._out.each):
        relay._out.give(iid(b))
    for _ in range(relay._BREAK_AFTER):
        relay._note_dial(iid(b), False)
    assert relay._broken(iid(b))
    r = _migrate(a, b, vic)
    assert r.status_code == 503 and r.get_json()['code'] == 'FED_SITE_UNREACHABLE', r.data
    assert len(_relayed_calls(a)) == before


# --- the body clock at the leading site ---------------------------------------------------------

class _Clocked:
    """What _IdleTimeoutMixin.get_environ does to every request, for the test client."""

    def __init__(self, app, seen):
        self.app, self.seen = app, seen

    def __call__(self, environ, start_response):
        clock = _BodyDeadline(environ['wsgi.input'], 30)
        environ['wsgi.input'] = clock
        environ[BODY_DEADLINE_ENVIRON] = clock
        self.seen.append((environ.get('PATH_INFO'), clock))
        return self.app(environ, start_response)



def test_the_leading_site_lifts_the_clock_for_an_upload_it_took(linked):
    a, b = linked
    seen_a, seen_b = [], []
    a.app.wsgi_app = _Clocked(a.app.wsgi_app, seen_a)
    b.app.wsgi_app = _Clocked(b.app.wsgi_app, seen_b)
    r = _upload(a, b, _session(a, 'alice'))
    assert r.status_code == 200 and UPLOADED, r.data
    leading = [c for p, c in seen_b if p == '/api/federation/peer/relay/upload']
    assert len(leading) == 1 and leading[0].lifted


class _SlowLink:
    """A body that comes in at a finite speed: each read waits a little first."""

    def __init__(self, body, pause):
        self.body, self.pause = body, pause

    def read(self, *args):
        import gevent
        gevent.sleep(self.pause)
        return self.body.read(*args)

    def readline(self, *args):
        return self.body.read(*args)


class _ClockedSlow(_Clocked):
    def __init__(self, app, seen, seconds, pause):
        super().__init__(app, seen)
        self.seconds, self.pause = seconds, pause

    def __call__(self, environ, start_response):
        clock = _BodyDeadline(_SlowLink(environ['wsgi.input'], self.pause), self.seconds)
        environ['wsgi.input'] = clock
        environ[BODY_DEADLINE_ENVIRON] = clock
        self.seen.append((environ.get('PATH_INFO'), clock))
        return self.app(environ, start_response)



def test_an_upload_slower_than_the_clock_reaches_the_leading_site(linked):
    """The clock scaled down to 0.3 s and the link to 0.1 s per MiB: both sites take it."""
    a, b = linked
    seen_a, seen_b = [], []
    a.app.wsgi_app = _ClockedSlow(a.app.wsgi_app, seen_a, 0.3, 0.1)
    b.app.wsgi_app = _ClockedSlow(b.app.wsgi_app, seen_b, 0.3, 0.1)
    r = _upload(a, b, _session(a, 'alice'))
    assert r.status_code == 200 and UPLOADED, r.data
