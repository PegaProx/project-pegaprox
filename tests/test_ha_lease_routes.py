"""The routes of automatic failover and the gates it changes (#625 stage 2).

Who reaches the new routes (every caller below an unconfined admin gets nothing, a peer
route wants the signature of a member), what a vote writes down before it answers, and
every gate of the design's section 5.1 in both modes: in a manual group it is what it
was, in an automatic one it goes by the lease.

MK Oct 2026 (#625)
"""
import time

import pytest

from pegaprox.core import ha_vote as hv
from test_ha_api import (ADMIN_PW, GOOD, B_ID, _active_with_standby, _admin, _audit, _peer,  # noqa: F401
                         ha_env)
from test_ha_members import IDS, URLS, _built, _post, _promote, _send, _sync, group  # noqa: F401
from _ha_lease_harness import T, auto  # noqa: F401 - the fixture

VOTE, RENEW, FINGERPRINT = '/api/ha/peer/vote', '/api/ha/peer/renew', '/api/ha/peer/fingerprint'
ADMIN_ROUTES = [
    ('put', '/api/ha/mode', {'mode': 'manual', 'user_password': ADMIN_PW}),
    ('post', f"/api/ha/members/{IDS['b']}/readmit", {'user_password': ADMIN_PW}),
    ('put', '/api/ha/timezone', {'timezone': 'Europe/Vienna'}),
]
PEER_ROUTES = [VOTE, RENEW, FINGERPRINT]


def _call(client, method, path, body, headers=None):
    return getattr(client, method)(path, json=body, headers=headers)


def _fresh():
    import pegaprox.api.ha as ha_api
    for window in (ha_api._pair_attempts, ha_api._peer_failures, ha_api._reauth_attempts):
        window.reset()


def _signed_send(auto, frm, to, path, body):
    raw = auto.ha._wire_body(body)
    _fresh()
    return _send(auto.g, to, auto.g.signed(frm, to, 'POST', path, raw), 'POST', path, raw)


def _vote(auto, cand, voter, epoch, pre=False):
    node = auto.node(cand)
    return {'epoch': epoch, 'candidate': IDS[cand], 'pre': pre, 'why': 'timer',
            'cv': list(node.cv), 'cfg_id': list(node.view.id), 'lease_s': 20}


# --- the admin routes: nobody below an unconfined admin ------------------------------------

@pytest.mark.parametrize('kind', ['anonymous', 'user', 'viewer', 'capped_admin',
                                  'capped_default_admin', 'admins_viewer_token'])
def test_below_an_unconfined_admin_the_new_routes_change_nothing(auto, seed, kind):
    """In a group that runs automatically, on its leader, where each of them would act."""
    auto.form(seed)
    api = auto.g.api
    headers = None
    if kind == 'anonymous':
        c = api.anon()
    elif kind == 'user':
        c = api.as_user(seed.user('ops', role='user', permissions=[
            'admin.users', 'admin.settings', 'security.settings.manage']))
    elif kind == 'viewer':
        c = api.as_user(seed.user('watcher', role='viewer'))
    elif kind == 'capped_admin':
        seed.tenant('globex', ['cluster_globex'])
        c = api.as_user(seed.user('gx', role='admin', tenant_id='globex',
                                  tenant_permissions={'globex': {'role': 'user'}}))
    elif kind == 'capped_default_admin':
        c = _admin(api, seed, 'lowered', tenant_id='default',
                   tenant_permissions={'default': {'role': 'viewer'}})
    else:
        from pegaprox.utils.auth import create_api_token
        res = create_api_token('root', 'ci', role='viewer')
        assert res.get('success'), res
        c, headers = api.anon(), {'Authorization': f"Bearer {res['token']}"}
    before = auto.file('a')

    with auto.at('a'):
        for method, path, body in ADMIN_ROUTES:
            _fresh()
            r = _call(c, method, path, body, headers)
            assert r.status_code == (401 if kind == 'anonymous' else 403), (kind, path, r.data)
            if kind.startswith('capped'):
                assert b'tenant' in r.data, r.data

    assert auto.file('a') == before and auto.mode('a') == 'auto' and auto.leader() == 'a'


def test_an_admin_api_token_cannot_switch_or_readmit_but_sets_the_time_zone(auto, seed):
    """The switch decides which instance acts and a re-admitted voter counts again: both
    want the password, which a token cannot give. The zone is a setting."""
    from pegaprox.utils.auth import create_api_token
    auto.form(seed)
    res = create_api_token('root', 'automation', role='admin')
    headers = {'Authorization': f"Bearer {res['token']}"}
    c = auto.g.api.anon()

    with auto.at('a'):
        for method, path, body in ADMIN_ROUTES[:2]:
            r = _call(c, method, path, body, headers)
            assert r.status_code == 403 and r.get_json()['code'] == 'HA_REAUTH', (path, r.data)
        r = _call(c, *ADMIN_ROUTES[2], headers)
        assert r.status_code == 200, r.data
    assert auto.mode('a') == 'auto' and auto.file('a')['timezone'] == 'Europe/Vienna'


def test_a_wrong_password_switches_nothing(auto, seed):
    auto.pair(seed)
    r = auto.put('a', '/api/ha/mode', {'mode': 'auto', 'user_password': 'not-it'})
    assert r.status_code == 403 and r.get_json()['code'] == 'HA_REAUTH'
    assert 'lease' not in auto.file('a') and _audit('ha.reauth_failed')


# --- the peer routes: the signature of a member ---------------------------------------------

@pytest.mark.parametrize('path', PEER_ROUTES)
def test_a_peer_route_wants_the_signature_of_a_member(auto, seed, path, monkeypatch):
    auto.form(seed)
    ha, g = auto.ha, auto.g
    body = {'fingerprint': ''} if path == FINGERPRINT else _vote(auto, 'b', 'a', 2, pre=True)
    raw = ha._wire_body(body)
    before = auto.file('a')
    good = g.signed('b', 'a', 'POST', path, raw)

    def status(headers, data=raw):
        _fresh()
        return _send(g, 'a', headers, 'POST', path, data).status_code

    # no header at all, and one that names a member without signing
    assert status({}) == 401 and status({'X-PegaProx-Peer': IDS['b']}) == 401
    # signed for another member, for another route, over another body
    assert status(g.signed('b', 'c', 'POST', path, raw)) == 401
    assert status(g.signed('b', 'a', 'POST', '/api/ha/peer/changed', raw)) == 401
    assert status(good, raw + b' ') == 401
    # signed by a key that is not b's
    assert status(dict(g.signed('c', 'a', 'POST', path, raw), **{'X-PegaProx-Peer': IDS['b']})) == 401
    # d never joined this group
    with g.at('d') as dha:
        dha._update(signing_key=dha._new_signing_key(), members={IDS['a']: {'url': URLS['a']}})
    assert status(g.signed('d', 'a', 'POST', path, raw)) == 401
    assert auto.file('a') == before

    # a member whose clock is far off hears so, and nothing is taken from it
    real = time.time
    with monkeypatch.context() as m:
        m.setattr(ha.time, 'time', lambda: real() - 500)
        old = g.signed('b', 'a', 'POST', path, raw)
    _fresh()
    r = _send(g, 'a', old, 'POST', path, raw)
    assert r.status_code == 401 and r.get_json()['code'] == 'HA_CLOCK'
    assert auto.file('a') == before

    # the real thing, once: a second time it is a replay
    r = _send(g, 'a', good, 'POST', path, raw)
    assert r.status_code == 200, r.data
    assert status(good) == 401


@pytest.mark.parametrize('path', PEER_ROUTES)
def test_a_removed_member_hears_that_it_is_out(group, seed, path, monkeypatch):
    monkeypatch.setattr(hv, 'AUTO_MODE_SHIPPED', True)
    g = group
    admin = _built(g, seed, 'bc')
    with g.at('a'):
        r = _post(admin, f"/api/ha/members/{IDS['c']}/remove",
                  {'confirm': 'REMOVE', 'shut_down': True, 'user_password': ADMIN_PW})
        assert r.status_code == 200, r.data
    raw = g.ha._wire_body({'fingerprint': ''})

    with g.at('c') as ha:
        # as it would sign it had it not heard yet
        signer = ha._signer()
        headers = ha._auth_for(signer, IDS['a'])('POST', path, raw)
    _fresh()
    r = _send(g, 'a', headers, 'POST', path, raw)

    assert r.status_code == 410 and r.get_json()['code'] == 'HA_REMOVED'


@pytest.mark.parametrize('path', PEER_ROUTES)
def test_a_member_that_still_goes_by_its_old_secret_neither_votes_nor_renews(ha_env, path, monkeypatch):
    """Paired before the keys: its secret opens the status, and a vote rests on who asks."""
    monkeypatch.setattr(hv, 'AUTO_MODE_SHIPPED', True)
    _active_with_standby(ha_env)
    assert _peer(ha_env.api, 'GET', '/api/ha/peer/status', GOOD).status_code == 200

    r = _peer(ha_env.api, 'POST', path, GOOD, json={'fingerprint': '', 'epoch': 3, 'leader': B_ID})

    assert r.status_code == 401 and r.get_json()['code'] == 'HA_LEASE_UNSIGNED'
    assert ha_env.ha.epoch() == 1 and 'lease' not in ha_env.ha._load()


def test_a_peer_call_without_the_marker_of_our_own_calls_is_no_peer_call(auto, seed):
    """The CSRF gate stands in front of the peer routes as of every write."""
    auto.form(seed)
    raw = auto.ha._wire_body(_vote(auto, 'b', 'a', 2, pre=True))
    headers = auto.g.signed('b', 'a', 'POST', VOTE, raw)
    with auto.at('a'):
        r = auto.g.client.post(VOTE, data=raw, base_url='http://localhost',
                               headers=dict(headers, **{'Content-Type': 'application/json'}))
    assert r.status_code == 403 and 'CSRF' in r.get_json()['error']


# --- what a vote and a renewal do -----------------------------------------------------------

def test_a_vote_is_on_disk_before_it_is_granted(auto, seed, monkeypatch):
    auto.form(seed)
    auto.past_the_hold()
    ha = auto.ha
    log = []
    real_write, real_request = ha._write_locked, ha.lease_request

    def write(st):
        real_write(st)
        log.append(('write', auto.g.name(), st['epoch'], (st.get('lease') or {}).get('voted_for')))

    def request(sender, kind, body):
        ans = real_request(sender, kind, body)
        log.append(('answer', auto.g.name(), kind, body.get('pre'), ans.get('granted'), ans.get('epoch')))
        return ans
    monkeypatch.setattr(ha, '_write_locked', write)
    monkeypatch.setattr(ha, 'lease_request', request)

    auto.crash('a')
    auto.members = 'bc'
    auto.run(T.P + T.L / 4 + T.R, until=lambda: auto.holders() != [])
    winner = auto.holders()[0]
    voter = 'c' if winner == 'b' else 'b'

    granted = log.index(('answer', voter, 'vote', False, True, 2))
    written = log.index(('write', voter, 2, IDS[winner]))
    assert written < granted
    # the pre-vote before it changed nothing: no write of the voter between the two
    pre = log.index(('answer', voter, 'vote', True, True, 1))
    assert pre < written and not [e for e in log[:pre] if e[:2] == ('write', voter) and e[2] == 2]
    # the candidate wrote its own vote down before it asked for any
    assert log.index(('write', winner, 2, IDS[winner])) < granted


def test_a_vote_that_cannot_be_written_is_no_vote(auto, seed, monkeypatch):
    auto.form(seed)
    auto.past_the_hold()
    ha = auto.ha
    real = ha._write_locked

    def write(st):
        if auto.g.name() == 'c' and st.get('epoch', 0) > 1:
            raise OSError(28, 'No space left on device')
        real(st)
    monkeypatch.setattr(ha, '_write_locked', write)
    auto.crash('a')
    auto.members = 'bc'
    auto.g.calls.clear()

    auto.run(3 * (T.P + T.L), dt=1.0)

    # b asked, c could not write its vote down and said no, c could not vote for itself
    assert [c for c in auto.g.calls if c[:2] == ('b', 'c') and c[3] == VOTE]
    assert auto.holders() == [] and auto.file('c')['epoch'] == 1
    assert auto.file('c')['lease']['voted_for'] == IDS['a']


def test_a_voter_with_a_live_promise_refuses_every_other_candidate(auto, seed):
    auto.form(seed)
    auto.past_the_hold()
    before = auto.file('b')

    for pre in (True, False):
        r = _signed_send(auto, 'c', 'b', VOTE, _vote(auto, 'c', 'b', 2, pre=pre))
        ans = r.get_json()
        assert r.status_code == 200 and ans['granted'] is False and ans['reason'] == 'PROMISED'
    assert auto.file('b') == before

    # the promise ends P after the last renewal: then it would, and says so without a write
    auto.pause('a')
    auto.advance(T.P + 1)
    ans = _signed_send(auto, 'c', 'b', VOTE, _vote(auto, 'c', 'b', 2, pre=True)).get_json()
    assert ans['granted'] is True and auto.file('b') == before
    # the real vote is written down: the epoch and who got it
    ans = _signed_send(auto, 'c', 'b', VOTE, _vote(auto, 'c', 'b', 2)).get_json()
    assert ans['granted'] is True
    st = auto.file('b')
    assert st['epoch'] == 2 and st['lease']['voted_for'] == IDS['c']
    assert st['lease']['gen'] == before['lease']['gen'] + 1
    # and nobody else gets one in that epoch
    with auto.at('b') as ha:
        ha._update(members=dict(ha._load()['members']))   # no change: the node stays
    other = dict(_vote(auto, 'c', 'b', 2), candidate=IDS['a'])
    ans = _signed_send(auto, 'a', 'b', VOTE, other).get_json()
    assert ans['granted'] is False


def test_a_member_in_manual_mode_refuses_votes_and_renewals(auto, seed):
    auto.pair(seed)

    ans = _signed_send(auto, 'c', 'b', VOTE, {'epoch': 2, 'candidate': IDS['c'], 'pre': False,
                                              'cv': [1, 1], 'cfg_id': [1, 1]}).get_json()
    # no voter config here, and no write counted: the leader of an automatic group
    # would send its chain again
    assert ans == {'ok': False, 'granted': False, 'reason': 'MODE_MANUAL', 'epoch': 1,
                   'cfg_id': [0, 0], 'gen': 0}
    # a renewal from a member it does not follow founds nothing here either
    ans = _signed_send(auto, 'c', 'b', RENEW, {'epoch': 5, 'leader': IDS['c'], 'lease_s': 20,
                                               'chain': []}).get_json()
    assert ans['ok'] is False and ans['reason'] == 'MODE_MANUAL'
    st = auto.file('b')
    assert 'lease' not in st and st['epoch'] == 1 and st['source'] == IDS['a']


def test_a_voter_config_from_anybody_but_the_followed_instance_is_not_taken(auto, seed):
    """The first voter config reaches a member with the switch of the instance it
    follows. The same chain from another member founds nothing."""
    auto.pair(seed)
    with auto.at('c') as ha:
        key = ha._signer().private
        import base64
        body = ha._voter_body(ha._load(), 20)
        body['voters'] = [dict(v, voter=v['id'] != IDS['a']) for v in body['voters']]
        cfg = hv.make_cfg(None, 1, IDS['c'], body, lambda m: base64.b64encode(key.sign(m)).decode())

    ans = _signed_send(auto, 'c', 'b', RENEW, {'epoch': 1, 'leader': IDS['c'], 'switch': True,
                                               'lease_s': 20, 'chain': [cfg]}).get_json()

    assert ans['ok'] is False and ans['reason'] == 'MODE_MANUAL' and 'lease' not in auto.file('b')


def test_votes_and_renewals_have_a_replay_cache_of_their_own(auto, seed, monkeypatch):
    """A member that forwards many writes must not use up what its renewals need, and a
    burst of confirm rounds must not shut out its sync. The lease calls a member sends
    are numbered (stream nonces): however many come, none fills a share, and each is
    taken once. A lease call with a random nonce goes to a share of its own."""
    from pegaprox.core import ha_wire
    auto.form(seed)
    ha, g = auto.ha, auto.g
    monkeypatch.setattr(ha, '_NONCES_PER_SENDER', 6)
    ha.forget_seen_nonces()
    status = '/api/ha/peer/status'
    raw = ha._wire_body(_vote(auto, 'b', 'a', 2, pre=True))

    def ask(path, method='GET', headers=None):
        body = b'' if method == 'GET' else raw
        _fresh()
        h = headers or g.signed('b', 'a', method, path, body)
        return _send(g, 'a', h, method, path, body).status_code

    def random_nonce(path, method='POST'):
        with g.at('b'):
            key = ha._signer().private
        return ha_wire.signed_headers(key, IDS['b'], IDS['a'], method, path, raw if method == 'POST' else b'',
                                      time.time())

    # the share of the other calls is used up by random nonces (a member on the release
    # before) ...
    assert [ask(status, headers=random_nonce(status, 'GET')) for _ in range(6)] == [200] * 6
    assert ask(status, headers=random_nonce(status, 'GET')) == 401
    # ... while the other calls of this release are numbered and still get through
    assert [ask(status) for _ in range(20)] == [200] * 20
    # ... and votes and renewals still get through, many more than a share holds
    signed = [g.signed('b', 'a', 'POST', VOTE, raw) for _ in range(40)]
    assert all(ha_wire.is_stream_nonce(h[ha.PEER_NONCE_HEADER]) for h in signed)
    assert [ask(VOTE, 'POST', h) for h in signed] == [200] * 40
    assert ask(RENEW, 'POST') == 200
    # each one once, and in any order
    assert ask(VOTE, 'POST', signed[7]) == 401 and ask(VOTE, 'POST', signed[39]) == 401
    assert not [k for k in ha._seen_nonces if k == (IDS['a'], IDS['b'], 'lease')]
    # a random nonce on a lease route: the share of its own, which fills
    assert [ask(VOTE, 'POST', random_nonce(VOTE)) for _ in range(6)] == [200] * 6
    assert ask(VOTE, 'POST', random_nonce(VOTE)) == 401
    assert ask(RENEW, 'POST') == 200
    keys = [k for k in ha._seen_nonces if k[:2] == (IDS['a'], IDS['b'])]
    assert sorted(len(k) for k in keys) == [2, 3] and all(len(ha._seen_nonces[k]) == 6 for k in keys)

    ha.forget_seen_nonces()
    # the other way round
    assert [ask(VOTE, 'POST', random_nonce(VOTE)) for _ in range(6)] == [200] * 6
    assert ask(status) == 200


def test_a_signed_lease_call_is_outside_the_rate_limit_per_address(auto, seed, monkeypatch):
    import pegaprox.app as app_mod
    auto.form(seed)
    monkeypatch.setattr(app_mod, '_check_api_rate_limit', lambda ip: False)
    r = _signed_send(auto, 'b', 'a', VOTE, _vote(auto, 'b', 'a', 2, pre=True))
    assert r.status_code == 200
    # an unsigned one is a client like any other
    with auto.at('a'):
        r = auto.g.client.post(VOTE, json={}, base_url='http://localhost',
                               headers={'X-Requested-With': 'XMLHttpRequest'})
    assert r.status_code == 429


# --- the fingerprint announce ---------------------------------------------------------------

FP1 = ':'.join(['AB'] * 32)
FP2 = ':'.join(['CD'] * 32)


def test_a_member_announces_a_new_pin_and_only_its_own(auto, seed):
    auto.pair(seed)
    assert auto.state('a')['members'][IDS['b']]['fingerprint'] == ''

    r = _signed_send(auto, 'b', 'a', FINGERPRINT, {'fingerprint': FP1.lower()})
    assert r.status_code == 200 and r.get_json() == {'success': True, 'changed': True}
    assert auto.state('a')['members'][IDS['b']]['fingerprint'] == FP1
    # c's pin is c's to announce
    assert auto.state('a')['members'][IDS['c']]['fingerprint'] == ''
    assert _signed_send(auto, 'b', 'a', FINGERPRINT, {'fingerprint': FP1}).get_json()['changed'] is False
    assert _audit('ha.fingerprint_changed')

    for bad in ('nope', FP1[:-1], 5, None, {'x': 1}):
        r = _signed_send(auto, 'b', 'a', FINGERPRINT, {'fingerprint': bad})
        assert r.status_code == 400, bad
    assert auto.state('a')['members'][IDS['b']]['fingerprint'] == FP1
    # '' is a certificate a CA signed: no pin
    assert _signed_send(auto, 'b', 'a', FINGERPRINT, {'fingerprint': ''}).status_code == 200
    assert auto.state('a')['members'][IDS['b']]['fingerprint'] == ''


def test_a_changed_certificate_is_announced_to_every_member_until_each_heard(auto, seed, monkeypatch):
    import pegaprox.api.ha as ha_api
    auto.pair(seed)
    monkeypatch.setattr(ha_api, '_own_fingerprint', lambda: FP1 if auto.g.name() == 'b' else '')

    auto.crash('c')
    with auto.at('b') as ha:
        assert ha.announce_fingerprint() == [IDS['a']]
        # c did not hear: nothing is noted as announced yet
        assert 'announced_fp' not in ha._load()
    assert auto.state('a')['members'][IDS['b']]['fingerprint'] == FP1

    auto.g.down.discard('c')
    auto.g.calls.clear()
    with auto.at('b') as ha:
        # only c is asked again
        assert ha.announce_fingerprint() == [IDS['c']]
        assert ha._load()['announced_fp'] == FP1
        auto.g.calls.clear()
        assert ha.announce_fingerprint() == [] and auto.g.calls == []
    assert auto.state('c')['members'][IDS['b']]['fingerprint'] == FP1
    # the leader hands the new pin on with the member list as well
    with auto.at('a') as ha:
        assert [e['fingerprint'] for e in ha.snapshot_meta()['members']
                if e['instance_id'] == IDS['b']] == [FP1]


def test_the_housekeeping_runs_nothing_until_automatic_mode_ships(auto, seed, monkeypatch):
    import pegaprox.api.ha as ha_api
    auto.pair(seed)
    monkeypatch.setattr(ha_api, '_own_fingerprint', lambda: FP2)
    monkeypatch.setattr(hv, 'AUTO_MODE_SHIPPED', False)
    auto.g.calls.clear()
    with auto.at('b') as ha:
        ha._lease_housekeeping()
    assert auto.g.calls == [] and auto.state('a')['members'][IDS['b']]['fingerprint'] == ''


def test_the_pin_announce_takes_nothing_until_automatic_mode_ships(group, seed):
    """Its sender is part of automatic failover and switched off with it: a call to the
    receiving half changes no pin that the pairing took, on the active or a standby."""
    g = group
    _built(g, seed, 'bc')
    assert hv.AUTO_MODE_SHIPPED is False
    before = {n: g.file(n) for n in 'ac'}
    for frm, to in (('b', 'a'), ('b', 'c'), ('a', 'c')):
        raw = g.ha._wire_body({'fingerprint': FP1})
        _fresh()
        r = _send(g, to, g.signed(frm, to, 'POST', FINGERPRINT, raw), 'POST', FINGERPRINT, raw)
        assert r.status_code == 409 and r.get_json()['code'] == 'HA_AUTO_NOT_SHIPPED', r.data
    for n in 'ac':
        now = g.file(n)
        for st in (now, before[n]):
            for rec in st['members'].values():
                rec.pop('last_contact', None)
        assert now == before[n]
    assert _audit('ha.fingerprint_changed') == []
    with g.at('a') as ha:
        with pytest.raises(ha.HaError, match='not available'):
            ha.take_fingerprint(IDS['b'], FP1)


# --- gates: the write gate (5.1) --------------------------------------------------------------

WRITES = [('put', '/api/user/preferences', {'theme': 'corporateDark'}),
          ('post', '/api/users', {'username': 'newbie', 'password': 'Longer-Pa55word!', 'role': 'user'})]


def _write(auto, n, probe=WRITES[0]):
    method, path, body = probe
    with auto.at(n):
        return getattr(auto.admin, method)(path, json=body)


def test_the_write_gate_in_a_manual_group_is_what_it_was(auto, seed):
    auto.pair(seed)
    for probe in WRITES:
        assert _write(auto, 'a', probe).status_code == 200
    r = _write(auto, 'b', ('put', '/api/user/preferences', {'theme': 'corporateLight'}))
    # a standby hands it on or refuses it, as before; never the answer of a lease
    assert r.status_code in (200, 409) and b'HA_NO_LEASE' not in r.data


def test_a_leader_without_its_lease_takes_no_write(auto, seed):
    from pegaprox.core.db import get_db
    auto.form(seed)
    assert _write(auto, 'a').status_code == 200

    auto.isolate('a')
    auto.auto_restart = False
    auto.advance(T.per_round + 0.5)

    # nothing ticked: the gate itself reads the clock
    for probe in WRITES:
        r = _write(auto, 'a', probe)
        assert r.status_code == 503 and r.get_json()['code'] == 'HA_NO_LEASE', r.data
        assert 'No leader at the moment' in r.get_json()['error']
        assert r.headers['Retry-After'] == '10'
    assert get_db().get_user('newbie') is None
    # reads go on, and so does the HA page: an admin has to see what is wrong
    with auto.at('a'):
        assert auto.admin.get('/api/ha/status').status_code == 200
        assert auto.admin.get('/api/users').status_code == 200


def test_a_leader_that_is_taking_over_says_for_how_long(auto, seed):
    auto.form(seed)
    auto.past_the_hold()
    auto.crash('a')
    auto.members = 'bc'
    auto.run(T.P + T.L / 4 + T.R + 2, until=lambda: auto.holders() != [])
    winner = auto.holders()[0]

    r = _write(auto, winner)

    assert r.status_code == 503 and r.get_json()['code'] == 'HA_NO_LEASE'
    assert 'taking over' in r.get_json()['error']
    assert 1 <= int(r.headers['Retry-After']) <= int(T.W_take) + 1
    auto.run(int(r.headers['Retry-After']) + 1, dt=0.5)
    assert _write(auto, winner).status_code == 200


def test_a_console_still_opens_on_a_leader_without_its_lease(auto, seed, monkeypatch):
    """The console is the user's, on the instance the browser is on."""
    auto.form(seed)
    auto.isolate('a')
    auto.auto_restart = False
    auto.advance(T.per_round + 0.5)

    with auto.at('a'):
        r = auto.admin.post('/api/ws/token', json={})
    assert not (r.status_code == 503 and b'HA_NO_LEASE' in r.data)


def test_a_standby_of_an_automatic_group_refuses_writes_as_a_standby(auto, seed):
    auto.form(seed)
    with auto.at('b') as ha:
        ha.set_forward_writes(False)
    r = _write(auto, 'b')
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY'


def test_the_gate_takes_no_write_whatever_a_second_look_at_the_state_finds(auto, seed, monkeypatch):
    """The gate asks whether this instance may act, hears no, and then asks what to
    answer. The lease loop may step the instance down between the two (each reads the
    state under its lock). Nothing to refuse for a standby must not mean the write
    goes through."""
    from pegaprox.core.db import get_db
    ha = auto.ha
    auto.form(seed)
    auto.isolate('a')
    auto.auto_restart = False
    auto.advance(T.per_round + 0.5)            # the lease ran out, the loop has not passed yet
    with auto.at('a') as h:
        assert h.role() == 'active' and not h.is_active()
    real, passes = ha.no_lease, []

    def no_lease():
        if not passes:
            passes.append(ha.lease_step())
        return real()
    monkeypatch.setattr(ha, 'no_lease', no_lease)

    _fresh()
    with auto.at('a'):
        r = auto.admin.post('/api/users', json={'username': 'slipped', 'password': 'Longer-Pa55word!',
                                                'role': 'user'})

    assert passes and auto.file('a')['role'] == 'standby'
    assert r.status_code == 503 and r.get_json()['code'] == 'HA_NO_LEASE', r.data
    assert get_db().get_user('slipped') is None


def test_a_caller_nobody_checked_hears_only_that_changes_are_paused(auto, seed):
    """The gate runs before any route has looked at the caller. Without a session it
    says neither whether the group has a leader nor how long a takeover still runs."""
    auto.form(seed)
    auto.past_the_hold()
    auto.crash('a')
    auto.members = 'bc'
    auto.run(T.P + T.L / 4 + T.R + 2, until=lambda: auto.holders() != [])
    winner = auto.holders()[0]
    said = set()
    for headers in ({}, {'X-Session-ID': 'f' * 64}, {'Authorization': 'Bearer pgx_' + 'a' * 40}):
        _fresh()
        with auto.at(winner):
            r = auto.g.api.anon().post('/api/users', json={}, headers=headers)
        assert r.status_code == 503 and r.get_json()['code'] == 'HA_NO_LEASE', r.data
        assert r.headers['Retry-After'] == '10'
        said.add(r.get_json()['error'])
    assert said == {auto.ha.NO_LEASE_ANON_ERROR} and 'taking over' not in said.pop()
    # the signed-in user hears it, as before
    r = _write(auto, winner)
    assert r.status_code == 503 and 'taking over - changes resume in' in r.get_json()['error']
    assert 1 <= int(r.headers['Retry-After']) <= int(T.W_take) + 1


def _lease_left(auto, n, left):
    """Turn every clock until `left` seconds of n's lease are left. Nothing ticks, so no
    renewal comes in between."""
    auto.advance(auto.node(n).lease_until - auto.clock[n] - left)


def test_a_leader_takes_a_write_only_while_two_seconds_of_its_lease_are_left(auto, seed):
    """Q16: a write let in with less left may commit after the lease ran out, a change the
    next leader never sees (lab E6b, 25 ms past it). The lease still runs: the leader
    acts, reads go on, and the next renewal lets writes in again."""
    from pegaprox.core.db import get_db
    auto.form(seed)
    _lease_left(auto, 'a', 3.0)
    assert _write(auto, 'a').status_code == 200

    auto.advance(1.5)
    with auto.at('a') as ha:
        assert ha.is_active() and not ha.takes_writes()
    for probe in WRITES:
        r = _write(auto, 'a', probe)
        assert r.status_code == 503 and r.get_json()['code'] == 'HA_NO_LEASE', r.data
        assert r.get_json()['error'] == auto.ha.LEASE_ENDING_ERROR
        assert r.headers['Retry-After'] == '2'
    assert get_db().get_user('newbie') is None
    with auto.at('a'):
        assert auto.admin.get('/api/users').status_code == 200

    auto.step('a')
    with auto.at('a') as ha:
        assert ha.takes_writes()
    assert _write(auto, 'a', WRITES[1]).status_code == 200


def test_a_forwarded_write_meets_the_same_margin(auto, seed):
    """Handed over by a member, the write takes the same gate: 503 HA_NO_LEASE with less
    than two seconds left, and the browser on the member hears it with its Retry-After."""
    auto.form(seed)
    envelope = {'method': 'PUT', 'path': '/api/user/preferences', 'query': '',
                'content_type': 'application/json', 'body_b64': 'eyJ0aGVtZSI6ICJjb3Jwb3JhdGVEYXJrIn0=',
                'user': 'root', 'client_ip': '203.0.113.9'}
    with auto.at('b') as ha:
        envelope['sign_in'] = ha.sign_in_digest('root')
    _lease_left(auto, 'a', 3.0)
    r = _signed_send(auto, 'b', 'a', '/api/ha/peer/forward', envelope)
    assert r.status_code == 200 and r.get_json()['status'] == 200, r.data

    auto.advance(1.5)
    r = _signed_send(auto, 'b', 'a', '/api/ha/peer/forward', envelope)
    assert r.status_code == 503 and r.get_json()['code'] == 'HA_NO_LEASE', r.data
    assert r.headers['Retry-After'] == '2'
    r = _write(auto, 'b')
    assert r.status_code == 503 and r.get_json()['code'] == 'HA_NO_LEASE', r.data
    assert r.get_json()['error'] == auto.ha.LEASE_ENDING_ERROR and r.headers['Retry-After'] == '2'


def test_in_a_manual_group_a_write_needs_no_lease_left(auto, seed):
    """Switched back to manual mode the lease means nothing, and neither does the margin."""
    auto.form(seed)
    r = auto.put('a', '/api/ha/mode', {'mode': 'manual', 'user_password': ADMIN_PW})
    assert r.status_code == 200
    auto.run(2 * T.R, dt=1.0)
    assert auto.mode('a') == 'manual' and auto.node('a') is not None
    auto.advance(3 * T.L)
    with auto.at('a') as ha:
        assert ha.takes_writes() and ha.no_lease() is None
    assert _write(auto, 'a').status_code == 200


# --- gates: the snapshot and the forwarded write ------------------------------------------------

def _snapshot(auto, frm, to):
    _fresh()
    return _send(auto.g, to, auto.g.signed(frm, to, 'GET', '/api/ha/peer/snapshot'), 'GET',
                 '/api/ha/peer/snapshot')


def test_the_snapshot_comes_from_the_lease_holder_only(auto, seed):
    auto.pair(seed)
    assert _snapshot(auto, 'b', 'a').status_code == 200       # manual: the active, as before
    auto.switch_on()
    assert _snapshot(auto, 'b', 'a').status_code == 200       # automatic: it holds the lease

    auto.isolate('a')
    auto.auto_restart = False
    auto.advance(T.per_round + 0.5)
    auto.heal()

    r = _snapshot(auto, 'b', 'a')
    assert r.status_code == 409 and 'not active' in r.get_json()['error']
    # a standby never did, in either mode, and names the member it follows
    r = _snapshot(auto, 'c', 'b')
    assert r.status_code == 409 and r.get_json()['follow']['instance_id'] == IDS['a']


def test_a_forwarded_write_meets_the_lease_on_the_leader(auto, seed):
    auto.form(seed)
    envelope = {'method': 'PUT', 'path': '/api/user/preferences', 'query': '',
                'content_type': 'application/json', 'body_b64': 'eyJ0aGVtZSI6ICJjb3Jwb3JhdGVEYXJrIn0=',
                'user': 'root', 'client_ip': '203.0.113.9'}
    with auto.at('b') as ha:
        envelope['sign_in'] = ha.sign_in_digest('root')

    r = _signed_send(auto, 'b', 'a', '/api/ha/peer/forward', envelope)
    assert r.status_code == 200 and r.get_json()['status'] == 200, r.data

    auto.isolate('a')
    auto.auto_restart = False
    auto.advance(T.per_round + 0.5)
    auto.heal()
    r = _signed_send(auto, 'b', 'a', '/api/ha/peer/forward', envelope)
    assert r.status_code == 503 and r.get_json()['code'] == 'HA_NO_LEASE'


def test_a_standby_passes_the_leaders_no_lease_on_to_the_browser(auto, seed):
    auto.form(seed)
    auto.isolate('a')
    auto.auto_restart = False
    auto.advance(T.per_round + 0.5)
    auto.heal()

    r = _write(auto, 'b')

    assert r.status_code == 503 and r.get_json()['code'] == 'HA_NO_LEASE'
    assert r.headers['Retry-After'] == '10'


def test_a_large_forwarded_write_meets_the_lease_before_its_body_is_read(auto, seed, monkeypatch):
    """The read limit of a forwarded write is raised for the leader. One that is taking
    over, or whose lease ran out, used to read a signed envelope above 64 KB as nobody's
    call: 401, a failure counted against the member's address, and 502 in the browser."""
    import pegaprox.api.ha as ha_api
    auto.form(seed)
    auto.past_the_hold()
    auto.crash('a')
    auto.members = 'bc'
    auto.run(T.P + T.L / 4 + T.R + 2, until=lambda: auto.holders() != [])
    winner = auto.holders()[0]
    other = 'c' if winner == 'b' else 'b'
    auto.run(T.R + 1)
    assert auto.file(other)['source'] == IDS[winner]
    large = {'theme': 'corporateDark', 'pad': 'x' * (100 * 1024)}
    real, checked = auto.ha.peer_verdict, []
    monkeypatch.setattr(auto.ha, 'peer_verdict',
                        lambda *a, **kw: checked.append(auto.g.name()) or real(*a, **kw))

    _fresh()
    ha_api._forward_per_user.reset()
    with auto.at(other):
        r = auto.admin.put('/api/user/preferences', json=large)
    assert r.status_code == 503 and r.get_json()['code'] == 'HA_NO_LEASE', r.data
    assert 'taking over' in r.get_json()['error'] and int(r.headers['Retry-After']) >= 1
    assert sum(len(v) for v in ha_api._peer_failures._hits.values()) == 0
    # the leader answered on the signature over the headers: no body read, no nonce spent
    assert winner not in checked

    # the body is read where the allow list asks who calls, and the answer is the same
    envelope = {'method': 'PUT', 'path': '/api/user/preferences', 'query': '',
                'content_type': 'application/json', 'body_b64': 'eA==' * (30 * 1024),
                'user': 'root', 'client_ip': '203.0.113.9', 'sign_in': 'x'}
    raw = auto.ha._wire_body(envelope)
    assert len(raw) > 64 * 1024
    with auto.at(winner):
        with auto.g.api.app.test_request_context('/api/ha/peer/forward', method='POST', data=raw,
                                                 headers=auto.g.signed(other, winner, 'POST',
                                                                       '/api/ha/peer/forward', raw)):
            assert ha_api._peer_body_limit() == ha_api._MAX_FORWARD_ENVELOPE
            assert ha_api.request_peer()[0] == 'member'
    # a call nobody signed stays a few bytes, on a leader as anywhere
    with auto.at(winner):
        with auto.g.api.app.test_request_context('/api/ha/peer/forward', method='POST', data=raw):
            assert ha_api._peer_body_limit() == ha_api._MAX_PEER_BODY

    auto.run(T.W_take + 2, until=lambda: auto.active() != [])
    _fresh()
    ha_api._forward_per_user.reset()
    with auto.at(other):
        r = auto.admin.put('/api/user/preferences', json=large)
    assert r.status_code not in (502, 503), r.data


# --- gates: the predicates, and the path the sign-in takes -----------------------------------

def test_the_three_predicates_in_every_state(auto, seed):
    def said(n):
        with auto.at(n) as ha:
            return ha.is_active(), ha.holds_lease(), ha.acting_process(), ha.is_standby()

    # an instance of its own, and a manual group: the role, nothing else
    assert said('e') == (True, True, True, False)
    auto.pair(seed)
    assert said('a') == (True, True, True, False) and said('b') == (False, False, False, True)
    auto.switch_on()
    assert said('a') == (True, True, True, False) and said('b') == (False, False, False, True)

    # the lease ran out: every gate closes, and the role the sign-in path asks stays
    auto.isolate('a')
    auto.auto_restart = False
    auto.advance(T.per_round + 0.5)
    assert said('a') == (False, False, True, False)
    # the node noticed: a standby from here on
    auto.step('a')
    assert said('a') == (False, False, False, True)


def test_an_instance_without_a_node_for_its_lease_state_stays_shut(auto, seed):
    """A leader on disk whose process has not run the boot check yet, or one whose lease
    state the node was not built from: fail closed."""
    auto.form(seed)
    with auto.at('a') as ha:
        ha._rts.pop(IDS['a'], None)
        assert ha._load()['role'] == 'active'
        assert (ha.is_active(), ha.holds_lease(), ha.acting_process()) == (False, False, False)
        assert ha.no_lease()['retry_after'] is None and not ha.confirm_lease()


def test_a_role_changed_past_the_node_builds_it_again(auto, seed):
    auto.form(seed)
    rt = auto.rt('b')
    node = rt.node
    with auto.at('b') as ha:
        ha._update(interval=45)
        assert not rt.stale and ha._lease_node() is node
        ha._update(epoch=3)
        assert rt.stale and ha._lease_live(ha._load()) is None
        again = ha._lease_node()
    assert again is not node and again.epoch == 3
    # the epoch moved by hand: nobody was voted for in it
    assert again.st['voted_for'] is None


# --- gates: promotion, removal, pairing, who serves -------------------------------------------

def test_nobody_is_promoted_or_removed_by_hand_in_an_automatic_group(auto, seed):
    auto.form(seed)

    r = _promote(auto.g, auto.admin, 'b')
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_AUTO_MODE'
    assert 'elect the leader' in r.get_json()['error']
    with auto.at('b') as ha:
        with pytest.raises(ha.AutoMode):
            ha.promote()
    r = auto.post('a', f"/api/ha/members/{IDS['c']}/remove",
                  {'confirm': 'REMOVE', 'shut_down': True, 'user_password': ADMIN_PW})
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_AUTO_MODE'
    with auto.at('a') as ha:
        with pytest.raises(ha.AutoMode):
            ha.remove_member(IDS['c'], shut_down=True)
    assert auto.file('b')['role'] == 'standby' and IDS['c'] in auto.file('a')['members']
    assert auto.leader() == 'a'


def test_an_automatic_leader_does_not_step_down_on_a_members_word(auto, seed):
    auto.form(seed)
    r = _signed_send(auto, 'b', 'a', '/api/ha/peer/step-down', {'epoch': 9})
    assert r.status_code == 200 and r.get_json()['stepped_down'] is False
    with auto.at('a') as ha:
        assert ha.step_aside(9, 'test') is False
    assert auto.file('a')['role'] == 'leader' and auto.leader() == 'a' and auto.g.restarts == [
        r for r in auto.g.restarts if 'step' not in str(r[1])]


def test_a_pairing_code_comes_from_the_lease_holder_after_a_majority_said_so(auto, seed):
    auto.form(seed)
    code = {'url': URLS['a'], 'user_password': ADMIN_PW}
    auto.g.calls.clear()

    assert auto.post('a', '/api/ha/pairing-code', code).status_code == 200
    # a round of its own went out for it
    assert len([c for c in auto.g.calls if c[0] == 'a' and c[3] == RENEW]) == 2
    r = auto.post('b', '/api/ha/pairing-code', dict(code, url=URLS['b']))
    assert r.status_code == 409 and 'standby' in r.get_json()['error']

    # cut off: its lease may still look valid, the round that asks does not come back
    auto.isolate('a')
    auto.auto_restart = False
    r = auto.post('a', '/api/ha/pairing-code', code)
    assert r.status_code == 503 and r.get_json()['code'] == 'HA_NO_LEASE'


def test_the_pair_call_is_refused_without_a_confirmed_lease(auto, seed):
    auto.form(seed)
    r = auto.post('a', '/api/ha/pairing-code', {'url': URLS['a'], 'user_password': ADMIN_PW})
    code = r.get_json()['code']
    auto.isolate('a')
    auto.auto_restart = False

    with auto.at('d'):
        r = _post(auto.admin, '/api/ha/join', {'code': code, 'own_url': URLS['d'], 'confirm': True,
                                              'user_password': ADMIN_PW})

    assert r.status_code == 502 and IDS['d'] not in auto.file('a')['members']
    assert auto.file('d')['role'] == 'standalone'


def _anon_pair(auto, n, code='x' * 43):
    """What anybody on the network can send: a pair call, here with a code that is none."""
    _fresh()
    with auto.at(n):
        return auto.g.client.post('/api/ha/peer/pair', base_url='http://localhost',
                                  json={'code': code, 'instance_id': 'f' * 32,
                                        'url': 'https://nobody.example', 'public_key': ''},
                                  headers={'X-Requested-With': 'XMLHttpRequest'})


def test_a_pair_call_without_the_code_learns_nothing_about_the_group(auto, seed):
    """The route has no session and no peer header. A wrong code gets the same answer
    on every instance in every mode, and costs the leader no renewal round."""
    auto.pair(seed)
    manual = _anon_pair(auto, 'a')
    assert manual.status_code == 403 and b'pairing code is wrong' in manual.data
    assert auto.switch_on().status_code == 200
    auto.g.calls.clear()

    for n in 'abc':
        r = _anon_pair(auto, n)
        assert (r.status_code, r.get_json()) == (403, manual.get_json()), n
    assert not [c for c in auto.g.calls if c[3] == RENEW]

    # a takeover: the new leader says as little
    auto.past_the_hold()
    auto.crash('a')
    auto.members = 'bc'
    auto.run(T.P + T.L / 4 + T.R + 2, until=lambda: auto.holders() != [])
    winner = auto.holders()[0]
    r = _anon_pair(auto, winner)
    assert (r.status_code, r.get_json()) == (403, manual.get_json())
    # whoever holds the code hears where the lease is at
    with auto.at(winner) as ha:
        ha._update(pairing={'code_hash': ha._hash_secret('s' * 43), 'expires': int(time.time()) + 600})
        assert ha.pairing_code_ok('s' * 43) and not ha.pairing_code_ok('t' * 43)
    r = _anon_pair(auto, winner, 's' * 43)
    assert r.status_code == 503 and 'taking over' in r.get_json()['error']
    # and the code is not spent by having been looked at
    with auto.at(winner) as ha:
        assert ha.pairing_code_ok('s' * 43)
        ha._update(pairing={'code_hash': ha._hash_secret('s' * 43), 'expires': int(time.time()) - 1})
        assert not ha.pairing_code_ok('s' * 43)


def test_who_serves_is_set_on_a_leader_that_holds_its_lease(auto, seed):
    auto.form(seed)
    assert auto.put('a', f"/api/ha/members/{IDS['b']}/serve", {'serve': True}).status_code == 200
    auto.isolate('a')
    auto.auto_restart = False
    auto.advance(T.per_round + 0.5)
    r = auto.put('a', f"/api/ha/members/{IDS['c']}/serve", {'serve': True})
    assert r.status_code == 503 and r.get_json()['code'] == 'HA_NO_LEASE'
    assert auto.file('a')['members'][IDS['c']].get('serve') is not True


# --- the status ---------------------------------------------------------------------------------

def test_the_status_says_who_holds_the_lease_and_what_each_member_was_last_heard_with(auto, seed):
    auto.skew['c'] = 3.0
    auto.form(seed)
    auto.watch('a', 'b')

    with auto.at('a'):
        body = auto.admin.get('/api/ha/status').get_json()
    lease = body['auto']
    assert lease['mode'] == 'auto' and lease['lease_s'] == 20 and lease['epoch'] == 1
    assert (lease['voters'], lease['majority']) == (3, 2)
    assert lease['holds_lease'] and lease['acting'] and lease['holder'] == IDS['a']
    assert 0 < lease['lease_left'] <= T.per_round and lease['acting_in'] is None
    rows = {m['instance_id']: m for m in lease['members']}
    assert set(rows) == {IDS['b'], IDS['c']}
    assert rows[IDS['c']]['skew'] == pytest.approx(3.0, abs=0.5) and rows[IDS['c']]['voter'] is True
    assert rows[IDS['b']]['mode'] == 'auto' and rows[IDS['b']]['quarantined'] is False
    assert lease['findings'] == [] and lease['hub_lag_max'] == 0.0

    with auto.at('b'):
        theirs = auto.admin.get('/api/ha/status').get_json()['auto']
    assert theirs['holder'] == IDS['a'] and not theirs['holds_lease'] and not theirs['acting']
    assert theirs['voted_for'] == IDS['a'] and theirs['lease_left'] > 0
    # what a member tells another one about it
    said = _send(auto.g, 'a', auto.g.signed('b', 'a')).get_json()
    assert said['lease_mark'] == 2 and said['group'] == 1 and said['mode'] == 'auto'
    assert said['lease'] == {'holds': True, 'holder': IDS['a'], 'epoch': 1}
    assert said['kind'] == 'data' and abs(said['wall'] - time.time()) < 5
    said = _send(auto.g, 'b', auto.g.signed('a', 'b')).get_json()
    assert said['lease'] == {'holds': False, 'holder': IDS['a'], 'epoch': 1}


def test_a_running_group_shows_what_to_look_at_and_blocks_nothing(auto, seed, monkeypatch):
    auto.form(seed)
    real = auto.ha.peer_lease_status
    monkeypatch.setattr(auto.ha, 'peer_lease_status',
                        lambda: {} if auto.g.name() == 'b' else real())
    auto.skew['c'] = 30.0
    auto.watch('a')

    with auto.at('a') as ha:
        found = {f['code']: f for f in ha.auto_findings()}
        ha._lease_housekeeping()
    assert found['DOWNGRADED']['member'] == IDS['b'] and found['CLOCK_SKEW']['member'] == IDS['c']
    assert {f['level'] for f in found.values()} == {'warn'}
    # the leader says so once: a downgraded member can be promoted by hand there
    assert len(_audit('ha.member_downgraded')) == 1
    with auto.at('a') as ha:
        ha._lease_housekeeping()
    assert len(_audit('ha.member_downgraded')) == 1


def test_a_lease_state_with_a_witness_counts_it_and_reaches_it(auto, seed, monkeypatch):
    """The voting set takes a witness: its own key in the state file, never a member, a
    vote in the voter config. Nothing pairs one yet."""
    g = auto.g
    auto.pair(seed, 'b')
    with g.at('e') as eha:
        eha._update(signing_key=eha._new_signing_key())
        witness = {'instance_id': IDS['e'], 'url': URLS['e'], 'fingerprint': '',
                   'public_key': eha.own_public_key(), 'site': 'dc3'}
    with g.at('a') as ha:
        ha._update(witness=witness)
        assert ha.standby_count() == 1 and len(ha.members()) == 1 and not ha.group_full()
        body = ha._voter_body(ha._load(), 20)
        meta = ha.snapshot_meta()
    assert body['witness'] == {'id': IDS['e'], 'public_key': witness['public_key'], 'site': 'dc3'}
    assert hv.voter_ids(body) == [IDS['a'], IDS['b'], IDS['e']] and not hv.body_error(body)
    assert meta['witness'] == witness
    # the member takes it with the member list, and can reach it should it lead one day
    assert _sync(g, auto.admin, 'b') == 'applied'
    assert auto.file('b')['witness'] == witness and len(auto.file('b')['members']) == 1
    with g.at('b') as ha:
        assert ha._lease_target(IDS['e'])['url'] == URLS['e']
    # three votes now: the count is enough, the witness has to answer like a member
    r = auto.put('a', '/api/ha/mode', {'mode': 'auto', 'user_password': ADMIN_PW})
    found = {f['code']: f for f in r.get_json()['findings']}
    assert r.status_code == 409 and 'TOO_FEW_VOTERS' not in found
    assert found['VOTER_DOWN']['member'] == IDS['e']
