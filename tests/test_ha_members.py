"""Warm standby groups (#625): up to four instances, one active and up to three
standbys, in one process.

Every instance is a state file of its own, and ha.STATE_FILE points at whichever one
is answering, as in tests/test_ha_api.py. Calls between the instances go through the
real routes of the one Flask app: ha._peer_call is answered by the test client with
the state file of the instance the address belongs to, each call in a context of its
own, as a request to another process is. All of them share the one test database,
which is what a group looks like right after a sync anyway.

The fan-out that asks the members side by side runs one call after the other here,
because the instances take turns on one ha.STATE_FILE.
test_the_fan_out_runs_the_calls_side_by_side covers the real one.

MK Sep 2026
"""
import contextlib
import contextvars
import json
import threading
import time
import types

import pytest

from pegaprox.core import ha as _ha
from test_ha_api import _admin, _audit, _Wire, ADMIN_PW

# taken before any test replaces it
_REAL_FAN_OUT = _ha._fan_out

NAMES = 'abcde'
IDS = {n: n * 32 for n in NAMES}
URLS = {
    'a': 'https://active.example:5000',
    'b': 'https://standby.example:5000',
    'c': 'https://standby-c.example:5000',
    'd': 'https://standby-d.example:5000',
    'e': 'https://standby-e.example:5000',
}

# The two state files of a real pair, written by the v2 pairing code (ea2296c) through
# its own routes: pairing code on the active, join on the standby. token_urlsafe was
# fixed to readable values for it, so the secrets below are what the two hashes are of.
V2_ACTIVE_PRESENTS = 'v2-pair-secret-2-' + 'q' * 30
V2_STANDBY_PRESENTS = 'v2-pair-secret-3-' + 'q' * 30
V2_ACTIVE = {
    'epoch': 1, 'instance_id': IDS['a'], 'interval': 30, 'pairing': None, 'role': 'active', 'sync': {},
    'peer': {
        'epoch_seen': 1, 'fingerprint': '', 'instance_id': IDS['b'],
        'paired_at': '2026-09-30T10:50:51+00:00', 'role_seen': 'standby',
        'secret_in_hash': 'd0977f1f1c44552cb5c9071f071349b7d9de3b757d78912171ded7ea70c8e2c9',
        'secret_out': V2_ACTIVE_PRESENTS, 'url': 'https://standby.example:5000',
    },
}
V2_STANDBY = {
    'epoch': 1, 'instance_id': IDS['b'], 'interval': 30, 'pairing': None, 'role': 'standby', 'sync': {},
    'peer': {
        'epoch_seen': 1, 'fingerprint': '', 'instance_id': IDS['a'],
        'paired_at': '2026-09-30T10:50:51+00:00', 'role_seen': 'active',
        'secret_in_hash': 'e5b66454c9432c717851f4a54e9188ca60c1421708a398e86bd41c0e2e844356',
        'secret_out': V2_STANDBY_PRESENTS, 'url': 'https://active.example:5000',
    },
}

MEMBER_KEYS = {'instance_id', 'url', 'fingerprint', 'role_seen', 'epoch_seen', 'last_contact',
               'last_error', 'joined_at', 'is_source', 'confirmed_standby', 'key_fingerprint',
               'serve', 'serving_seen', 'site'}


def _one_after_the_other(jobs, timeout):
    out = []
    for job in jobs:
        try:
            out.append((job(), None))
        except Exception as e:
            out.append((None, e))
    return out


class _Group:
    """Five instances a to e, standalone to begin with. `down` holds the names that do
    not answer, `cut` the pairs that cannot reach each other; `calls` records (from,
    to, method, path) of every call between them."""

    def __init__(self, ha, api, tmp):
        self.ha, self.api = ha, api
        self.files = {n: str(tmp / f'{n}.json') for n in NAMES}
        self.by_url = {URLS[n]: n for n in NAMES}
        self.down, self.calls, self.restarts, self.installed = set(), [], [], []
        # (from, to, method, path, body, headers) of every call, as it went out
        self.sent = []
        # pairs of names that cannot reach each other, either way
        self.cut = set()
        self.client = api.app.test_client()
        for n in NAMES:
            self.write(n, {'role': 'standalone', 'epoch': 0, 'instance_id': IDS[n],
                           'interval': 30, 'pairing': None, 'sync': {}})

    def write(self, n, st):
        with open(self.files[n], 'w', encoding='utf-8') as fh:
            json.dump(st, fh)
        self.ha.reset_for_tests()

    def file(self, n):
        with open(self.files[n], encoding='utf-8') as fh:
            return json.load(fh)

    def name(self):
        return next(n for n, path in self.files.items() if path == self.ha.STATE_FILE)

    def _switch(self, path):
        self.ha.STATE_FILE = path                 # monkeypatch restores it at teardown
        self.ha.reset_for_tests()

    @contextlib.contextmanager
    def at(self, n):
        home = self.ha.STATE_FILE
        self._switch(self.files[n])
        try:
            yield self.ha
        finally:
            self._switch(home)

    def state(self, n):
        with self.at(n) as ha:
            return json.loads(json.dumps(ha._load()))

    def members(self, n):
        return set(self.state(n)['members'])

    def signed(self, n, to, method='GET', path='/api/ha/peer/status', body=b''):
        """The peer headers `n` would send `to` for this call, the way call_member makes
        them: signed for `to`, plus the old secret while `n` has one and does not know
        that `to` holds its key."""
        with self.at(n) as ha:
            rec = ha.member(IDS[to]) or {}
            signer = ha._signer()
            legacy = bool(signer.secret) and not rec.get('key_acked')
            return ha._auth_for(signer, IDS[to], legacy)(method, path, body)

    def call(self, method, base_url, fingerprint, path, json_body=None, auth=None,
             headers=None, timeout=15):
        ha = self.ha
        me, to = self.name(), self.by_url[base_url.rstrip('/')]
        self.calls.append((me, to, method, path))
        body = ha._wire_body(json_body)
        h = {'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json'}
        if body:
            h['Content-Type'] = 'application/json'
        if auth is not None:
            h.update(auth(method, path, body))
        h.update(headers or {})
        self.sent.append((me, to, method, path, body, dict(h)))
        if to in self.down or frozenset((me, to)) in self.cut:
            raise ha.PeerUnreachable('Cannot reach the peer: ConnectTimeout')
        # A call made from inside a route (a promotion telling the members, a removed
        # instance asking the remover) would be served in the app context of that
        # route, flask.g included. Between two processes it is a request of its own,
        # so it is served from an empty context here.
        return contextvars.Context().run(self._serve, to, method, path, body, h)

    def _serve(self, to, method, path, body, h):
        with self.at(to):
            resp = self.client.open(path, method=method, data=body or None, headers=h,
                                    base_url='http://localhost')
        return _Wire(resp)

    def restarted(self, reason):
        self.restarts.append((self.name(), reason))


@pytest.fixture
def group(api, tmp_path, monkeypatch):
    from pegaprox.core import ha
    import pegaprox.api.ha as ha_api
    monkeypatch.setattr(ha, 'STATE_FILE', str(tmp_path / 'a.json'))
    monkeypatch.setattr(ha, 'AES_KEY_FILE', str(tmp_path / '.pegaprox_aes256.key'))
    monkeypatch.setattr(ha, 'KNOWN_HOSTS_FILE', str(tmp_path / '.ssh_known_hosts'))
    monkeypatch.setattr(ha, 'BRANDING_DIR', str(tmp_path / 'branding'))
    monkeypatch.setattr(ha, '_etag_checked', False)
    monkeypatch.setattr(ha, '_run', ha._fresh_run())
    g = _Group(ha, api, tmp_path)
    monkeypatch.setattr(ha, 'restart_process', g.restarted)
    monkeypatch.setattr(ha, '_install_field_key', g.installed.append)
    monkeypatch.setattr(ha, '_peer_call', g.call)
    monkeypatch.setattr(ha, '_fan_out', _one_after_the_other)
    # The instances here share one process, so a standby that loads or unloads plugins
    # after a sync would do it for all of them; the test of that turns it back on.
    g.follow_plugin_state = ha._follow_plugin_state
    monkeypatch.setattr(ha, '_follow_plugin_state', lambda: None)
    _fresh_windows(ha_api)
    # the replay cache lives as long as the process; each test starts it over
    ha.forget_seen_nonces()
    yield g
    ha.reset_for_tests()
    _fresh_windows(ha_api)
    ha.forget_seen_nonces()


def _fresh_windows(ha_api):
    for window in (ha_api._pair_attempts, ha_api._peer_failures, ha_api._reauth_attempts,
                   ha_api._forward_per_user):
        window.reset()


def _post(admin, path, body=None):
    """An admin call that wants the password again. The re-check budget counts every
    attempt, and a test here makes more of them than a person would in five minutes."""
    import pegaprox.api.ha as ha_api
    _fresh_windows(ha_api)
    return admin.post(path, json=body)


def _pair(g, admin, name, active='a'):
    """A real pairing: the code from the active's route, the join through the standby's
    route, the handshake through the active's pair route."""
    with g.at(active):
        r = _post(admin, '/api/ha/pairing-code', {'url': URLS[active], 'user_password': ADMIN_PW})
        assert r.status_code == 200, r.data
        code = r.get_json()['code']
    with g.at(name):
        r = _post(admin, '/api/ha/join', {'code': code, 'own_url': URLS[name], 'confirm': True,
                                          'user_password': ADMIN_PW})
        assert r.status_code == 200, r.data
    return r


def _sync(g, admin, name):
    with g.at(name):
        r = admin.post('/api/ha/sync-now')
        assert r.status_code == 200, r.data
        return r.get_json()['result']


def _pub(g, n):
    with g.at(n) as ha:
        return ha.own_public_key()


def _built(g, seed, standbys='bc', sync=True):
    """a active, `standbys` paired with it, and every standby synced once."""
    admin = _admin(g.api, seed)
    for n in standbys:
        _pair(g, admin, n)
    if sync:
        for n in standbys:
            assert _sync(g, admin, n) == 'applied'
    return admin


def _watch(g, n):
    with g.at(n) as ha:
        return ha.watch_once()


def _promote(g, admin, n):
    with g.at(n):
        return _post(admin, '/api/ha/promote', {'confirm': 'PROMOTE', 'user_password': ADMIN_PW})


def _send(g, target, headers, method='GET', path='/api/ha/peer/status', body=b''):
    """A peer call with exactly `headers` to `target`, as it arrives there."""
    h = dict(headers, **{'X-Requested-With': 'XMLHttpRequest'})
    if body:
        h['Content-Type'] = 'application/json'
    with g.at(target):
        return g.client.open(path, method=method, data=body or None, headers=h,
                             base_url='http://localhost')


def _asks(g, caller, target):
    """The status `target` answers a fresh status call from `caller` with. `caller` is
    a name (the call as it would sign it now) or a dict of headers made earlier."""
    headers = caller if isinstance(caller, dict) else g.signed(caller, target)
    return _send(g, target, headers).status_code


# --- pairing three standbys ------------------------------------------------------------

def test_three_standbys_pair_with_the_active(group, seed):
    g = group
    admin = _built(g, seed, 'bcd', sync=False)

    a = g.state('a')
    assert a['role'] == 'active' and a['epoch'] == 1 and set(a['members']) == {IDS[n] for n in 'bcd'}
    for n in 'bcd':
        st = g.state(n)
        assert st['role'] == 'standby' and st['source'] == IDS['a'] and st['epoch'] == 1
        assert a['members'][IDS[n]]['url'] == URLS[n]
        # the active holds the public key of each standby, never its private key
        assert a['members'][IDS[n]]['public_key'] == _pub(g, n)
        assert st['signing_key'] not in json.dumps(a)
        assert st['members'][IDS['a']]['public_key'] == _pub(g, 'a')
        # and no secret travels any more
        assert st['member_secret'] is None and 'secret_hash' not in a['members'][IDS[n]]
    # every instance has its own key pair
    assert len({g.state(n)['signing_key'] for n in 'abcd'}) == 4
    # the sealed answer carried the members that were there already
    assert g.members('b') == {IDS['a']}
    assert g.members('c') == {IDS['a'], IDS['b']}
    assert g.members('d') == {IDS['a'], IDS['b'], IDS['c']}
    assert g.state('d')['members'][IDS['b']]['url'] == URLS['b']
    # so d can check b's calls from the start
    assert _asks(g, 'b', 'd') == 200
    assert len(_audit('ha.paired')) == 3 and len(_audit('ha.joined')) == 3
    assert g.installed and all(r == 'joined as standby' for _n, r in g.restarts)

    with g.at('a'):
        body = admin.get('/api/ha/status').get_json()
    assert body['standby_count'] == 3 and body['max_members'] == 4 and body['role'] == 'active'


def test_the_address_is_kept_at_the_join_already(group, seed):
    g = group
    _built(g, seed, 'b', sync=False)
    assert g.state('b')['own_url'] == URLS['b']


def test_a_member_keeps_the_address_it_joined_with(group, seed):
    """A member stored no address of its own: own_url was only set by a pairing code.
    Once promoted, it gave the node agents an address made from the IP the cluster
    sees and the bind port instead of the one the group knows it by."""
    g = group
    _built(g, seed, 'bc')
    for n in 'bc':
        assert g.state(n)['own_url'] == URLS[n]
    # the leader's member list keeps it current
    st = g.state('a')
    st['members'][IDS['c']]['url'] = 'https://standby-c.example:5443'
    g.write('a', st)
    admin = _admin(g.api, seed)
    _sync(g, admin, 'c')
    assert g.state('c')['own_url'] == 'https://standby-c.example:5443'
    assert _promote(g, admin, 'b').status_code == 200
    from pegaprox.core.manager import PegaProxManager
    m = PegaProxManager.__new__(PegaProxManager)
    m._get_pegaprox_server_ip = lambda: pytest.fail('the cluster was asked for our address')
    with g.at('b'):
        assert URLS['b'] in m._ha_agent_members()


def test_a_fourth_standby_is_refused(group, seed):
    g = group
    admin = _built(g, seed, 'bcd', sync=False)
    with g.at('a') as ha:
        r = _post(admin, '/api/ha/pairing-code', {'url': URLS['a'], 'user_password': ADMIN_PW})
        assert r.status_code == 409
        assert r.get_json() == {'error': 'This group already has 3 standbys - remove one first'}
        assert ha.group_full()
        # said before the password is asked for, as for a standby
        r = _post(admin, '/api/ha/pairing-code', {'url': URLS['a']})
        assert r.status_code == 409 and 'already has 3 standbys' in r.get_json()['error']
        # a code handed out before the group filled up is refused at the pair route too
        ha._update(pairing={'code_hash': ha._hash_secret('s' * 43), 'expires': int(time.time()) + 600})
        stale = ha.encode_code(URLS['a'], '', 's' * 43, IDS['a'])
    with g.at('e'):
        r = _post(admin, '/api/ha/join', {'code': stale, 'own_url': URLS['e'], 'confirm': True,
                                          'user_password': ADMIN_PW})
    assert r.status_code == 502 and 'already has 3 standbys' in r.get_json()['error']
    assert g.state('e')['role'] == 'standalone' and g.members('e') == set()
    assert g.members('a') == {IDS[n] for n in 'bcd'}

    # one out, and the next one may join
    with g.at('a'):
        r = _post(admin, f"/api/ha/members/{IDS['d']}/remove",
                  {'confirm': 'REMOVE', 'user_password': ADMIN_PW})
        assert r.status_code == 200, r.data
    _pair(g, admin, 'e')
    assert g.members('a') == {IDS[n] for n in 'bce'}


# --- the member list travels with the snapshot ---------------------------------------------------

def test_the_member_lists_converge_with_the_next_pull(group, seed):
    g = group
    admin = _built(g, seed, 'bcd', sync=False)
    assert g.members('b') == {IDS['a']}

    for n in 'bcd':
        assert _sync(g, admin, n) == 'applied'

    for n in 'bcd':
        assert g.members(n) == {IDS[m] for m in 'abcd' if m != n}, n
        st = g.state(n)
        for m in 'bcd':
            if m != n:
                assert st['members'][IDS[m]]['url'] == URLS[m]
                # every standby takes the calls of every other one
                assert _asks(g, m, n) == 200, (m, n)
        # and pulls from the active still, at the address it paired with
        assert st['source'] == IDS['a'] and st['members'][IDS['a']]['url'] == URLS['a']
    # nothing new: the next poll is a 304
    assert _sync(g, admin, 'b') == 'unchanged'


def test_a_removed_member_is_refused_everywhere_at_once(group, seed):
    g = group
    admin = _built(g, seed, 'bcd')
    assert _asks(g, 'd', 'b') == 200

    with g.at('a'):
        r = _post(admin, f"/api/ha/members/{IDS['d']}/remove",
                  {'confirm': 'REMOVE', 'user_password': ADMIN_PW})
    assert r.status_code == 200, r.data
    body = r.get_json()
    assert body['success'] is True and body['told'] is True
    assert [m['instance_id'] for m in body['members']] == [IDS['b'], IDS['c']]
    assert all(set(m) == MEMBER_KEYS for m in body['members'])
    # d was told, and let go of the whole group; it waits as a passive standby
    assert ('a', 'd', 'POST', '/api/ha/peer/unpaired') in g.calls
    d = g.state('d')
    assert d['role'] == 'standby' and d['members'] == {} and d['source'] is None
    assert d['removed']['by'] == IDS['a'] and d['removed']['epoch'] == 1
    details = _audit('ha.member_removed')[-1]['details']
    assert '(told' in details and '2 of 2 other member(s) told' in details

    # every member heard at once, not only with its next sync: d is out everywhere,
    # and hears so (410) rather than a plain refusal
    for n in 'abc':
        assert IDS['d'] not in g.members(n)
        assert IDS['d'] in g.state(n)['tombstones']
        assert _asks(g, 'd', n) == 410, n
    assert _sync(g, admin, 'b') == 'applied'        # the list changed, the tables did not
    assert _asks(g, 'd', 'b') == 410
    # nobody else lost anything
    assert _asks(g, 'c', 'b') == 200 and _asks(g, 'b', 'a') == 200


def test_removing_a_member_wants_the_active_the_word_and_the_password(group, seed):
    g = group
    admin = _built(g, seed, 'b', sync=False)
    before = {n: g.file(n) for n in 'ab'}
    path = f"/api/ha/members/{IDS['b']}/remove"
    with g.at('a'):
        for body in (None, {}, {'confirm': 'remove'}, {'confirm': True}):
            assert _post(admin, path, body).status_code == 400, body
        r = _post(admin, path, {'confirm': 'REMOVE'})
        assert r.status_code == 403 and r.get_json()['code'] == 'HA_REAUTH'
        r = _post(admin, f"/api/ha/members/{IDS['e']}/remove",
                  {'confirm': 'REMOVE', 'user_password': ADMIN_PW})
        assert r.status_code == 404
    with g.at('b'):
        r = _post(admin, f"/api/ha/members/{IDS['a']}/remove",
                  {'confirm': 'REMOVE', 'user_password': ADMIN_PW})
        assert r.status_code == 409 and 'active' in r.get_json()['error']
    assert {n: g.file(n) for n in 'ab'} == before
    assert _audit('ha.member_removed') == []

    # the last one out: the active is standalone again, as when b unpairs itself
    with g.at('a'):
        r = _post(admin, path, {'confirm': 'REMOVE', 'user_password': ADMIN_PW})
    assert r.status_code == 200 and r.get_json()['members'] == []
    assert g.state('a')['role'] == 'standalone'


def test_a_removal_notice_counts_only_from_the_active(group, seed):
    """removed: true makes a standby drop the whole group. From another standby it
    drops that one standby and nothing else."""
    g = group
    _built(g, seed, 'bc')
    body = g.ha._wire_body({'removed': True})
    r = _send(g, 'b', g.signed('c', 'b', 'POST', '/api/ha/peer/unpaired', body),
              'POST', '/api/ha/peer/unpaired', body)
    assert r.status_code == 200 and r.get_json()['forgotten'] is True
    assert r.get_json()['left_group'] is False
    b = g.state('b')
    assert set(b['members']) == {IDS['a']} and b['source'] == IDS['a'] and b['role'] == 'standby'
    assert b['removed'] is None
    # b asked c whether it speaks for the group, and c said it is a standby
    assert ('b', 'c', 'GET', '/api/ha/peer/status') in g.calls


def test_the_etag_carries_the_member_list_and_nothing_that_moves(group, seed):
    g = group
    _built(g, seed, 'bc', sync=False)
    with g.at('a') as ha:
        etag = ha.snapshot_etag()
        snap = ha.build_snapshot()
        assert snap['etag'] == etag
        # addresses, pins and public keys, nothing private; for a member whether the
        # active made it active too (tests/test_ha_serving.py)
        assert {tuple(sorted(e)) for e in snap['members']} == \
            {('fingerprint', 'instance_id', 'public_key', 'secret_hash', 'url'),
             ('fingerprint', 'instance_id', 'public_key', 'secret_hash', 'serve', 'url')}
        assert [e['instance_id'] for e in snap['members']] == [IDS[n] for n in 'abc']
        assert [e.get('serve') for e in snap['members']] == [None, False, False]
        assert all(e['public_key'] and e['secret_hash'] == '' for e in snap['members'])
        assert ha._load()['signing_key'] not in json.dumps(snap)
        assert snap['group'] == 1 and snap['tombstones'] == []
        # what every tick writes leaves it alone
        ha._note_members({IDS['b']: {'last_contact': '2026-09-30T12:00:00+00:00', 'role_seen': 'standby',
                                     'epoch_seen': 1, 'last_error': 'slow'}})
        assert ha.snapshot_etag() == etag
        ha._note_members({IDS['b']: {'url': 'https://moved.example:5000'}})
        moved = ha.snapshot_etag()
        assert moved != etag
        ha.remove_member(IDS['c'])
        assert ha.snapshot_etag() not in (etag, moved)


# --- promotion and following -----------------------------------------------------------------

def test_a_promoted_standby_is_followed_by_every_other_member(group, seed):
    g = group
    admin = _built(g, seed, 'bc')

    r = _promote(g, admin, 'b')
    assert r.status_code == 200, r.data
    assert r.get_json() == {'success': True, 'epoch': 2, 'restarting': True}
    # the old active stepped down before b restarted, and follows b
    assert g.restarts[-2:] == [('a', 'stepped down to standby'), ('b', 'promoted to active')]
    a = g.state('a')
    assert a['role'] == 'standby' and a['epoch'] == 2 and a['source'] == IDS['b']
    details = _audit('ha.promoted')[-1]['details']
    assert 'told to step down' in details and '1 of 1 other member(s) told' in details
    # c heard about it and is still a standby of a until it looks at the group
    c = g.state('c')
    assert c['role'] == 'standby' and c['source'] == IDS['a']

    assert _watch(g, 'c') == 'source switched'
    c = g.state('c')
    assert c['source'] == IDS['b'] and c['sync'].get('etag') is None
    assert _sync(g, admin, 'c') == 'applied'
    c = g.state('c')
    assert c['epoch'] == 2 and set(c['members']) == {IDS['a'], IDS['b']}
    with g.at('c') as ha:
        assert ha.banner()['peer_url'] == URLS['b']
        status = admin.get('/api/ha/status').get_json()
    assert [m['instance_id'] for m in status['members'] if m['is_source']] == [IDS['b']]
    assert status['peer']['instance_id'] == IDS['b']

    # the old active pulls from the new one with the secret it always had
    assert _sync(g, admin, 'a') == 'applied'
    # and everybody is where they belong
    assert _watch(g, 'b') == 'ok'
    assert _watch(g, 'a') == 'ok' and _watch(g, 'c') == 'ok'
    assert [g.state(n)['role'] for n in 'abc'] == ['standby', 'active', 'standby']


@pytest.mark.parametrize('first', ['b', 'c'])
def test_two_promotions_at_once_are_settled_by_the_instance_id(group, seed, first):
    """Two admins promote two standbys while neither reaches anybody: both are active
    under epoch 2. Whichever looks at the group first, c (the higher id) stays active
    and both others follow it."""
    g = group
    admin = _built(g, seed, 'bc')
    g.down = set('abc')
    for n in 'bc':
        r = _promote(g, admin, n)
        assert r.status_code == 200 and r.get_json()['epoch'] == 2
        assert 'not reached' in _audit('ha.promoted')[-1]['details']
    g.down = set()
    assert [g.state(n)['role'] for n in 'abc'] == ['active', 'active', 'active']

    if first == 'b':
        assert _watch(g, 'b') == 'stepped down'
        assert _watch(g, 'c') == 'told peer to step down'   # a, still under epoch 1
    else:
        assert _watch(g, 'c') == 'told peer to step down'   # a and b
        assert _watch(g, 'b') == 'ok'

    assert [g.state(n)['role'] for n in 'abc'] == ['standby', 'standby', 'active']
    for n in 'ab':
        assert g.state(n)['source'] == IDS['c'] and g.state(n)['epoch'] == 2
    assert ('b', 'stepped down to standby') in g.restarts and ('a', 'stepped down to standby') in g.restarts
    assert ('c', 'stepped down to standby') not in g.restarts
    assert _watch(g, 'a') == 'ok' and _watch(g, 'c') == 'ok'


def test_a_tie_steps_down_only_to_the_higher_id_and_only_to_a_member(group, seed):
    g = group
    _built(g, seed, 'bc')                           # synced: b knows c
    with g.at('b') as ha:
        ha.promote()                                # b active under epoch 2
        assert ha.step_down(2, IDS['a']) is False   # a is the lower id
        assert ha.step_down(2, IDS['e']) is False   # e is nobody here
        assert ha.step_down(1, IDS['c']) is False   # older
        assert ha.role() == 'active'
        assert ha.step_down(2, IDS['c']) is True    # the same epoch, the higher id
        assert ha.role() == 'standby' and ha.source_id() == IDS['c'] and ha.epoch() == 2


def test_promote_goes_one_above_every_epoch_it_has_seen(group, seed):
    g = group
    _built(g, seed, 'bc', sync=False)
    with g.at('c') as ha:
        ha._note_members({IDS['a']: {'epoch_seen': 3}, IDS['b']: {'epoch_seen': 7}})
        assert ha.promote() == 8
        assert ha.source_id() is None and ha.role() == 'active'
        # whoever it saw active is unknown again until it answers
        assert ha.member(IDS['a'])['role_seen'] is None


def test_a_standby_never_promotes_itself_and_keeps_its_source(group, seed):
    g = group
    admin = _built(g, seed, 'bc')
    g.down = {'a'}

    assert _watch(g, 'c') == 'no active member'      # b answers, as a standby
    c = g.state('c')
    assert c['role'] == 'standby' and c['source'] == IDS['a'] and c['epoch'] == 1
    assert 'Cannot reach' in c['members'][IDS['a']]['last_error']
    assert _sync(g, admin, 'c') == 'failed'
    assert 'Cannot reach' in g.state('c')['sync']['last_error']

    g.down = {'a', 'b'}
    assert _watch(g, 'c') == 'unreachable'
    assert g.state('c')['source'] == IDS['a'] and g.state('c')['role'] == 'standby'

    g.down = set()
    assert _watch(g, 'c') == 'ok'
    assert _sync(g, admin, 'c') in ('applied', 'unchanged')
    assert ('c', 'promoted to active') not in g.restarts and g.state('c')['epoch'] == 1


def test_an_old_active_steps_down_at_start_to_whoever_replaced_it(group, seed):
    """a was down while c got promoted; at start it asks every member and comes up as
    c's standby, without a restart."""
    g = group
    admin = _built(g, seed, 'bc')
    g.down = {'a'}
    assert _promote(g, admin, 'c').status_code == 200
    g.down = set()
    before = list(g.restarts)

    with g.at('a') as ha:
        assert ha.check_peer_at_boot() == 'stepped down'
        assert ha.role() == 'standby' and ha.source_id() == IDS['c'] and ha.epoch() == 2
    assert g.restarts == before
    assert [c[:2] + c[3:] for c in g.calls[-2:]] == [('a', 'b', '/api/ha/peer/status'),
                                                     ('a', 'c', '/api/ha/peer/status')]


# --- leaving the group -----------------------------------------------------------------------

def test_an_active_that_unpairs_leaves_the_standbys_to_each_other(group, seed):
    g = group
    admin = _built(g, seed, 'bc')
    with g.at('a'):
        r = _post(admin, '/api/ha/unpair', {'confirm': 'UNPAIR', 'user_password': ADMIN_PW})
    assert r.status_code == 200 and r.get_json() == {'success': True, 'restarting': False}
    a = g.state('a')
    assert a['role'] == 'standalone' and a['members'] == {} and a['member_secret'] is None
    for n, other in (('b', 'c'), ('c', 'b')):
        st = g.state(n)
        assert st['role'] == 'standby' and set(st['members']) == {IDS[other]} and st['source'] is None
    assert '2 of 2 members told' in _audit('ha.unpaired')[-1]['details']
    assert 'and 1 more' in _audit('ha.unpaired')[-1]['details']

    # one of them is promoted, the other follows it
    assert _promote(g, admin, 'b').status_code == 200
    assert _watch(g, 'c') == 'source switched'
    assert _sync(g, admin, 'c') == 'applied'
    assert g.state('c')['source'] == IDS['b']


def test_a_standby_that_unpairs_is_dropped_by_everybody(group, seed):
    g = group
    admin = _built(g, seed, 'bc')
    with g.at('c'):
        r = _post(admin, '/api/ha/unpair', {'confirm': 'UNPAIR', 'user_password': ADMIN_PW})
    assert r.status_code == 200 and r.get_json() == {'success': True, 'restarting': True}
    assert g.state('c')['role'] == 'standalone' and g.members('c') == set()
    assert g.members('a') == {IDS['b']} and g.members('b') == {IDS['a']}
    assert ('c', 'unpaired, standalone from now on') in g.restarts
    assert g.state('a')['role'] == 'active'


# --- the status page ----------------------------------------------------------------------------

def test_the_status_lists_every_member_and_no_secret(group, seed):
    g = group
    admin = _built(g, seed, 'bcd')
    with g.at('a'):
        text = admin.get('/api/ha/status').get_data(as_text=True)
    body = json.loads(text)
    assert [m['instance_id'] for m in body['members']] == [IDS[n] for n in 'bcd']
    assert all(set(m) == MEMBER_KEYS and m['is_source'] is False for m in body['members'])
    assert (body['max_members'], body['standby_count']) == (4, 3)
    assert body['peer']['instance_id'] == IDS['b']
    assert 'secret' not in text
    for n in 'abcd':
        assert g.state(n)['signing_key'] not in text
    # the public keys only as their short fingerprints
    for m in body['members']:
        n = next(k for k in 'bcd' if IDS[k] == m['instance_id'])
        assert m['key_fingerprint'] == g.ha.peer_key_fingerprint(_pub(g, n))
        assert len(m['key_fingerprint']) == 16 and _pub(g, n) not in text
        assert m['confirmed_standby'] is True
    assert body['removed'] is None

    with g.at('c'):
        body = admin.get('/api/ha/status').get_json()
        check = admin.get('/api/auth/check').get_json()
    assert [(m['instance_id'], m['is_source']) for m in body['members']] == \
        [(IDS['a'], True), (IDS['b'], False), (IDS['d'], False)]
    assert body['peer']['instance_id'] == IDS['a'] and body['standby_count'] == 3
    assert check['ha']['peer_url'] == URLS['a']

    with g.at('e'):
        body = admin.get('/api/ha/status').get_json()
    assert (body['members'], body['peer'], body['standby_count'], body['max_members']) == ([], None, 0, 4)


# --- a pair from before the groups ------------------------------------------------------------

def test_a_pair_from_before_the_groups_keeps_talking(group, seed):
    g = group
    admin = _admin(g.api, seed)
    g.write('a', V2_ACTIVE)
    g.write('b', V2_STANDBY)
    raw = {n: open(g.files[n], 'rb').read() for n in 'ab'}

    with g.at('a') as ha:
        assert ha.role() == 'active' and [m['instance_id'] for m in ha.members()] == [IDS['b']]
        assert ha._load()['member_secret'] == V2_ACTIVE_PRESENTS
        assert ha.verify_peer({ha.PEER_HEADER: f"{IDS['b']}:{V2_STANDBY_PRESENTS}"})['url'] == URLS['b']
        ha.public_status()
    with g.at('b') as ha:
        assert ha.source_id() == IDS['a'] and ha.peer()['url'] == URLS['a']
        assert ha.verify_peer({ha.PEER_HEADER: f"{IDS['a']}:{V2_ACTIVE_PRESENTS}"})
    # reading alone writes nothing: the file stays in the old form until something changes
    assert {n: open(g.files[n], 'rb').read() for n in 'ab'} == raw

    # both directions, through the routes
    assert _sync(g, admin, 'b') == 'applied'
    assert _watch(g, 'a') == 'ok'
    for n in 'ab':
        on_disk = g.file(n)
        assert 'peer' not in on_disk and len(on_disk['members']) == 1
        # and on the way both sides took each other's key and let the secret go
        assert on_disk['member_secret'] is None and on_disk['signing_key']
    assert g.state('a')['members'][IDS['b']]['public_key'] == _pub(g, 'b')
    assert g.state('b')['members'][IDS['a']]['public_key'] == _pub(g, 'a')

    # the old pair takes a second standby, and b learns it with its next pull
    _pair(g, admin, 'c')
    assert g.members('c') == {IDS['a'], IDS['b']}
    assert _sync(g, admin, 'b') == 'applied'
    assert g.members('b') == {IDS['a'], IDS['c']}
    assert _asks(g, 'c', 'b') == 200 and _asks(g, 'b', 'c') == 200

    # and a promotion in it works as it did in the pair
    assert _promote(g, admin, 'b').status_code == 200
    assert g.state('a')['role'] == 'standby' and g.state('a')['source'] == IDS['b']


def test_a_pair_file_reads_the_same_on_both_sides(group):
    """The migration alone, both roles: a standby follows its old peer, an active has
    it as its one member, and neither holds anything it did not hold before."""
    g = group
    g.write('a', V2_ACTIVE)
    g.write('b', V2_STANDBY)
    a, b = g.state('a'), g.state('b')
    assert a['member_secret'] == V2_ACTIVE_PRESENTS and b['member_secret'] == V2_STANDBY_PRESENTS
    assert a['source'] is None and b['source'] == IDS['a']
    rec = a['members'][IDS['b']]
    assert rec == {'url': URLS['b'], 'fingerprint': '', 'role_seen': 'standby', 'epoch_seen': 1,
                   'secret_hash': V2_ACTIVE['peer']['secret_in_hash'], 'pair_secret': True,
                   'last_contact': None, 'last_error': '', 'joined_at': '2026-09-30T10:50:51+00:00'}
    assert 'peer' not in a and 'peer' not in b
    assert V2_STANDBY_PRESENTS not in json.dumps(a) and V2_ACTIVE_PRESENTS not in json.dumps(b)


# --- the pieces ------------------------------------------------------------------------------

def test_a_member_list_is_taken_only_as_far_as_it_is_well_formed(group, seed):
    g = group
    _built(g, seed, 'b', sync=False)
    good = g.ha._hash_secret('x')
    with g.at('b') as ha:
        st = ha._load()
        entries = [
            {'instance_id': IDS['a'], 'url': 'https://elsewhere.example', 'fingerprint': '',
             'secret_hash': good},                                           # the sender
            {'instance_id': IDS['b'], 'url': URLS['b'], 'fingerprint': '', 'secret_hash': good},  # us
            {'instance_id': IDS['c'], 'url': 'http://c.example', 'fingerprint': 'AB', 'secret_hash': good},
            {'instance_id': 'C' * 32, 'url': URLS['c'], 'fingerprint': '', 'secret_hash': good},
            {'instance_id': IDS['d'], 'url': URLS['d'], 'fingerprint': '', 'secret_hash': 'x' * 64},
            {'instance_id': IDS['e'], 'url': URLS['e'], 'fingerprint': ':'.join(['ab'] * 32),
             'secret_hash': good},
            'not a dict', None,
        ]
        out = ha._merged_members(st, IDS['a'], entries)
    assert set(out) == {IDS['a'], IDS['c'], IDS['e']}
    # the sender keeps the address we reach it on
    assert out[IDS['a']]['url'] == URLS['a']
    # an address that is not plain https is none, and a pin without one too
    assert (out[IDS['c']]['url'], out[IDS['c']]['fingerprint']) == ('', '')
    assert out[IDS['e']]['fingerprint'] == ':'.join(['AB'] * 32)

    # never more than three others, the sender first
    many = [{'instance_id': ch * 32, 'url': f'https://{ch}.example', 'fingerprint': '',
             'secret_hash': good} for ch in '0123456789']
    with g.at('b') as ha:
        out = ha._merged_members(ha._load(), IDS['a'], many)
    assert len(out) == 3 and IDS['a'] in out


def test_a_call_between_members_is_a_request_of_its_own(group, seed, monkeypatch):
    """The harness itself. A call made from inside a route is served in an app context
    of its own, as a call to another process is: nothing the route keeps on flask.g
    reaches the member that answers. It did, and every receiver after the first in a
    route took the first one's verdict without looking at the signature."""
    import flask
    g = group
    _built(g, seed, 'b', sync=False)
    ha = g.ha
    seen = []
    real = ha.peer_verdict

    def spy(*args):
        seen.append(flask.g.get('outer'))
        return real(*args)
    monkeypatch.setattr(ha, 'peer_verdict', spy)
    with g.at('b'), g.api.app.test_request_context('/api/ha/promote'):
        flask.g.outer = 'the route'
        resp = ha.call_member(ha.member(IDS['a']), 'GET', '/api/ha/peer/status')
    assert resp.status_code == 200
    assert seen == [None]


def test_the_checkouts_certificate_is_no_pin_in_a_test(group, seed, tmp_path, monkeypatch):
    """A self-signed certificate in the checkout's config/ssl (a dev instance runs from
    it) went into every pairing code the tests made, and from there into the member
    records: green in CI, red next to a running instance. tests/conftest.py keeps it
    out; a test that wants a pin sets one."""
    import datetime
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    import pegaprox.api.auto_install as ai
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'checkout')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1).not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=1)).sign(key, hashes.SHA256()))
    (tmp_path / 'ssl').mkdir()
    (tmp_path / 'ssl' / 'cert.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    monkeypatch.setattr(ai, 'SSL_DIR', str(tmp_path / 'ssl'))
    monkeypatch.setattr(ai, 'SSL_CERT_FILE', str(tmp_path / 'ssl' / 'cert.pem'))
    monkeypatch.delenv('PEGAPROX_BEHIND_PROXY', raising=False)

    g = group
    _built(g, seed, 'b', sync=False)
    assert g.state('b')['members'][IDS['a']]['fingerprint'] == ''
    assert g.state('a')['members'][IDS['b']]['fingerprint'] == ''


def test_the_fan_out_runs_the_calls_side_by_side():
    fan_out = _REAL_FAN_OUT

    def slow(value):
        def job():
            time.sleep(0.4)
            return value
        return job

    def refused():
        raise _ha.HaError('refused')
    started = time.monotonic()
    out = fan_out([slow(1), refused, slow(3)], timeout=5)
    assert time.monotonic() - started < 0.75         # not 0.8 s one after the other
    assert out[0] == (1, None) and out[2] == (3, None)
    assert out[1][0] is None and str(out[1][1]) == 'refused'

    # a member that hangs holds up none of the others, and counts as failed
    gate = threading.Event()
    started = time.monotonic()
    out = fan_out([lambda: gate.wait(5), slow('fast')], timeout=0.8)
    gate.set()
    assert time.monotonic() - started < 2
    assert out[1] == ('fast', None)
    assert out[0][0] is None and 'in time' in str(out[0][1])
    # a single job is held to the same deadline: the one member of a pair that hangs
    # costs the timeout, not whatever the job takes
    gate = threading.Event()
    started = time.monotonic()
    out = fan_out([lambda: gate.wait(5)], timeout=0.5)
    gate.set()
    assert time.monotonic() - started < 1.5
    assert out[0][0] is None and 'in time' in str(out[0][1])
    assert fan_out([lambda: 'one'], timeout=1) == [('one', None)]


def test_a_member_that_does_not_answer_holds_up_nobody(group, seed, monkeypatch):
    """The real fan-out in watch_once: the member that fails is noted on its record,
    the ones that answer are counted."""
    g = group
    _built(g, seed, 'bcd', sync=False)
    ha = g.ha
    monkeypatch.setattr(ha, '_fan_out', _REAL_FAN_OUT)
    answers = {URLS['b']: 'standby', URLS['c']: None, URLS['d']: 'standby'}

    def call(method, base_url, fingerprint, path, json_body=None, auth='peer', headers=None,
             timeout=15):
        if answers[base_url] is None:
            raise ha.HaError('Cannot reach the peer: ConnectTimeout')
        body = {'instance_id': IDS[g.by_url[base_url]], 'role': answers[base_url], 'epoch': 1}
        return types.SimpleNamespace(status_code=200, json=lambda: body)
    monkeypatch.setattr(ha, '_peer_call', call)

    with g.at('a'):
        assert ha.watch_once() == 'ok'
        recs = {m['instance_id']: m for m in ha.members()}
    assert recs[IDS['b']]['last_contact'] and recs[IDS['d']]['last_contact']
    assert recs[IDS['b']]['last_error'] == '' and 'Cannot reach' in recs[IDS['c']]['last_error']
    assert g.state('a')['role'] == 'active'


