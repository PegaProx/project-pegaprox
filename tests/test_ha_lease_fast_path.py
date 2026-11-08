"""The lease calls of automatic failover answered before Flask (#625 stage 2, app.py
_LeaseFastPath).

A leader renews before every write, and through Flask and its hooks a renewal cost a
member three times what the answer itself does. The fast path answers POST
/api/ha/peer/renew and /api/ha/peer/vote in the WSGI layer, and only where the Flask path
would answer 200 as well. Each test here sends the same request down both paths (the
fast path switched off for one of them) and wants the same status, body, headers and
failure count: the IP lists, the rate limit and the failure budget, a missing or bad
signature, a replay, a body over the cap, a wrong method, an instance that is not
paired, a removed member, a clock that is off, a member without a key, the CSRF and
content-type checks. Nothing but those two routes takes it, and a hook nobody looked at
turns it off.

MK Oct 2026 (#625)
"""
import inspect
import json
import time

import pytest

from pegaprox.core import ha_wire
from test_ha_members import IDS, _built, group  # noqa: F401
from _ha_lease_harness import auto  # noqa: F401

RENEW, VOTE = '/api/ha/peer/renew', '/api/ha/peer/vote'
FAR = '192.0.2.7'


@pytest.fixture
def pair(group, seed):
    """a active, b its standby; the calls go from a to b."""
    _built(group, seed, 'b')
    return group


def _fresh(g):
    import pegaprox.api.ha as ha_api
    from pegaprox import globals as ppg
    for w in (ha_api._pair_attempts, ha_api._peer_failures, ha_api._reauth_attempts):
        w.reset()
    ppg.api_rate_window.reset()


def _body(epoch=1):
    return ha_wire.wire_body({'epoch': epoch, 'leader': IDS['a'], 'lease_s': 20, 'cv': [1, 1],
                              'wall': time.time(), 'floor_cv': [0, 0]})


def _headers(g, path=RENEW, body=None, frm='a', to='b', **extra):
    body = _body() if body is None else body
    h = {'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json',
         'Content-Type': 'application/json'}
    h.update(g.signed(frm, to, 'POST', path, body))
    h.update(extra)
    return h


def _send(g, fast, path, headers, body, to='b', method='POST', remote='127.0.0.1', query=''):
    app = g.api.app
    front = app.wsgi_app
    was, front.on = front.on, fast
    before = front.answered
    try:
        with g.at(to):
            r = g.client.open(path + query, method=method, data=body, headers=headers,
                              base_url='https://localhost', environ_overrides={'REMOTE_ADDR': remote})
    finally:
        front.on = was
    return r, front.answered - before


def _forged(g, path=RENEW, body=None):
    """A call in a's name, signed by a key that is not a's."""
    body = _body() if body is None else body
    h = {'X-Requested-With': 'XMLHttpRequest', 'Content-Type': 'application/json'}
    h.update(ha_wire.signed_headers(ha_wire.private_key(ha_wire.new_signing_key()), IDS['a'], IDS['b'],
                                    'POST', path, body, time.time()))
    return h, body


def _failures(ip):
    import pegaprox.api.ha as ha_api
    return len(ha_api._peer_failures._hits.get(ip, []))


def both(g, path=RENEW, headers=None, body=None, *, to='b', method='POST', remote='127.0.0.1',
         query='', setup=None, again=False):
    """The same request down the Flask path, then (the nonce taken back) down the fast
    path. Returns (flask answer, fast answer, whether the fast path answered it)."""
    body = _body() if body is None else body
    headers = _headers(g, path, body) if headers is None else headers
    out = []
    for fast in (False, True):
        _fresh(g)
        g.ha.forget_seen_nonces()
        if setup:
            setup()
        if again:
            # the call went through once already: what comes now is a replay
            _send(g, False, path, headers, body, to=to, method=method, remote=remote, query=query)
        r, answered = _send(g, fast, path, headers, body, to=to, method=method, remote=remote, query=query)
        out.append((r.status_code, r.get_data(), list(r.headers.items()), _failures(remote), answered))
    slow, quick = out
    assert slow[4] == 0
    assert quick[:4] == slow[:4], (slow[:4], quick[:4])
    return slow, quick, bool(quick[4])


def _ip_lists(monkeypatch, allow=(), block=()):
    import pegaprox.api.settings as settings_api
    monkeypatch.setattr(settings_api, '_ip_whitelist_enabled', True)
    monkeypatch.setattr(settings_api, '_ip_whitelist', set(allow))
    monkeypatch.setattr(settings_api, '_ip_blacklist', set(block))


# --- answered here ------------------------------------------------------------------------

def test_a_renewal_of_a_member_is_answered_the_same_and_before_flask(pair, monkeypatch):
    hooks = []
    import pegaprox.api.ha as ha_api
    real = ha_api.signed_member_call
    monkeypatch.setattr(ha_api, 'signed_member_call', lambda: hooks.append(1) or real())
    slow, quick, fast = both(pair)
    assert fast and slow[0] == 200
    ans = json.loads(quick[1])
    assert 'ok' in ans and 'reason' in ans
    # the hooks ran for the Flask path only
    assert len(hooks) == 1
    names = [k for k, _v in quick[2]]
    assert ('X-PegaProx-Peer-Keyed', '1') in quick[2] and 'Strict-Transport-Security' in names
    assert names == [k for k, _v in slow[2]]


def test_a_vote_is_answered_the_same(pair):
    body = ha_wire.wire_body({'epoch': 3, 'candidate': IDS['a'], 'pre': True, 'why': 'timer',
                              'cv': [1, 1], 'cfg_id': [1, 1], 'lease_s': 20})
    slow, quick, fast = both(pair, VOTE, _headers(pair, VOTE, body), body)
    assert fast and slow[0] == 200


def test_a_renewal_in_an_automatic_group_is_taken_the_same(auto, seed):
    auto.form(seed)
    node = auto.node('a')
    body = ha_wire.wire_body({'epoch': node.led_epoch, 'leader': IDS['a'], 'lease_s': 20,
                              'cv': list(node.cv), 'wall': time.time(), 'floor_cv': [0, 0]})
    slow, quick, fast = both(auto.g, RENEW, _headers(auto.g, RENEW, body), body)
    assert fast and json.loads(slow[1])['ok'] is True


def test_an_address_the_allow_list_does_not_name_passes_as_a_signed_member(pair, monkeypatch):
    _ip_lists(monkeypatch, allow={'10.9.9.9'})
    slow, quick, fast = both(pair, remote=FAR)
    assert slow[0] == 200 and fast


def test_an_address_the_allow_list_names_passes(pair, monkeypatch):
    _ip_lists(monkeypatch, allow={FAR})
    slow, quick, fast = both(pair, remote=FAR)
    assert slow[0] == 200 and fast


def test_the_rate_limit_of_an_address_spares_a_member_on_both_paths(pair, monkeypatch):
    from pegaprox import globals as ppg
    monkeypatch.setattr(ppg.api_rate_window, 'limit', 1)

    def used_up():
        ppg.api_rate_window.allow(FAR)
    slow, quick, fast = both(pair, remote=FAR, setup=used_up)
    assert slow[0] == 200 and fast


# --- refused, the same way ----------------------------------------------------------------

def test_a_blocked_address_is_refused_the_same(pair, monkeypatch):
    _ip_lists(monkeypatch, block={FAR})
    slow, quick, fast = both(pair, remote=FAR)
    assert slow[0] == 403 and not fast


def test_a_bad_signature_from_an_address_off_the_list_is_refused_and_counted_the_same(pair, monkeypatch):
    _ip_lists(monkeypatch, allow={'10.9.9.9'})
    h, body = _forged(pair)
    slow, quick, fast = both(pair, RENEW, h, body, remote=FAR)
    assert slow[0] == 403 and slow[3] == 1 and not fast


def test_over_the_rate_limit_a_bad_call_is_refused_the_same(pair, monkeypatch):
    from pegaprox import globals as ppg
    monkeypatch.setattr(ppg.api_rate_window, 'limit', 1)
    h, body = _forged(pair)
    slow, quick, fast = both(pair, RENEW, h, body, remote=FAR, setup=lambda: ppg.api_rate_window.allow(FAR))
    assert slow[0] == 429 and not fast


def test_over_the_failure_budget_a_bad_call_is_refused_the_same(pair):
    import pegaprox.api.ha as ha_api
    h, body = _forged(pair)

    def spent():
        for _ in range(ha_api._peer_failures.limit):
            ha_api._peer_failures.allow(FAR)
    slow, quick, fast = both(pair, RENEW, h, body, remote=FAR, setup=spent)
    assert slow[0] == 429 and not fast


def test_without_a_signature_it_is_refused_the_same(pair):
    body = _body()
    h = {'X-Requested-With': 'XMLHttpRequest', 'Content-Type': 'application/json',
         'X-PegaProx-Peer': IDS['a']}
    slow, quick, fast = both(pair, RENEW, h, body)
    assert slow[0] == 401 and slow[3] == 1 and not fast


def test_a_call_signed_for_another_member_is_refused_the_same(pair):
    body = _body()
    h = _headers(pair, RENEW, body, to='c')
    slow, quick, fast = both(pair, RENEW, h, body)
    assert slow[0] == 401 and not fast


def test_a_body_that_is_not_the_signed_one_is_refused_the_same(pair):
    body = _body()
    h = _headers(pair, RENEW, body)
    other = _body(epoch=2)
    slow, quick, fast = both(pair, RENEW, h, other)
    assert slow[0] == 401 and not fast


def test_a_replay_is_refused_the_same(pair):
    slow, quick, fast = both(pair, again=True)
    assert slow[0] == 401 and not fast


def test_a_body_over_the_cap_is_refused_the_same(pair):
    import pegaprox.api.ha as ha_api
    body = ha_wire.wire_body({'epoch': 1, 'pad': 'x' * (ha_api._MAX_PEER_BODY + 10)})
    slow, quick, fast = both(pair, RENEW, _headers(pair, RENEW, body), body)
    assert slow[0] == 401 and not fast


def test_a_body_over_the_size_the_app_takes_is_left_to_flask(pair, monkeypatch):
    """PEGAPROX_MAX_REQUEST_SIZE below the peer cap: the fast path takes no body Flask
    would refuse for its size."""
    monkeypatch.setattr(pair.api.app.wsgi_app, 'max_size', 64)
    slow, quick, fast = both(pair)
    assert not fast


@pytest.mark.parametrize('method', ['GET', 'PUT', 'DELETE', 'PATCH'])
def test_a_wrong_method_is_refused_the_same(pair, method):
    slow, quick, fast = both(pair, method=method)
    assert slow[0] == 405 and not fast


def test_an_instance_that_is_not_paired_refuses_the_same(pair):
    slow, quick, fast = both(pair, RENEW, _headers(pair, RENEW, None, to='d'), None, to='d')
    assert slow[0] == 401 and not fast


def test_a_removed_member_hears_the_same(pair):
    st = pair.state('b')
    rec = st['members'].pop(IDS['a'])
    st.setdefault('tombstones', {})[IDS['a']] = {'public_key': rec['public_key'], 'epoch': 2}
    body = _body()
    h = _headers(pair, RENEW, body)
    pair.write('b', st)
    slow, quick, fast = both(pair, RENEW, h, body)
    assert slow[0] == 410 and not fast


def test_a_clock_that_is_off_is_told_the_same(pair):
    body = _body()
    with pair.at('a') as ha:
        key = ha._signer().private
    h = {'X-Requested-With': 'XMLHttpRequest', 'Content-Type': 'application/json'}
    h.update(ha_wire.signed_headers(key, IDS['a'], IDS['b'], 'POST', RENEW, body, time.time() - 600))
    slow, quick, fast = both(pair, RENEW, h, body)
    assert slow[0] == 401 and json.loads(slow[1])['code'] == 'HA_CLOCK' and not fast


def test_a_member_without_a_key_is_refused_the_same(pair):
    st = pair.state('b')
    rec = st['members'][IDS['a']]
    rec.pop('public_key', None)
    rec['secret_hash'] = pair.ha._hash_secret('old-pair-secret-' + 'k' * 20)
    pair.write('b', st)
    body = _body()
    h = {'X-Requested-With': 'XMLHttpRequest', 'Content-Type': 'application/json',
         'X-PegaProx-Peer': f"{IDS['a']}:old-pair-secret-{'k' * 20}"}
    slow, quick, fast = both(pair, RENEW, h, body)
    assert slow[0] == 401 and json.loads(slow[1])['code'] == 'HA_LEASE_UNSIGNED' and not fast


def test_a_query_string_is_refused_the_same(pair):
    slow, quick, fast = both(pair, query='?x=1')
    assert slow[0] == 401 and not fast


@pytest.mark.parametrize('extra', [{'Origin': 'https://evil.example'},
                                   {'X-Requested-With': ''},
                                   {'Referer': 'https://evil.example/x'}])
def test_the_csrf_check_refuses_the_same(pair, extra):
    body = _body()
    h = _headers(pair, RENEW, body, **extra)
    slow, quick, fast = both(pair, RENEW, h, body)
    assert slow[0] == 403 and not fast


def test_a_body_that_is_not_json_by_its_type_is_refused_the_same(pair):
    body = _body()
    h = _headers(pair, RENEW, body, **{'Content-Type': 'text/plain'})
    slow, quick, fast = both(pair, RENEW, h, body)
    assert slow[0] == 415 and not fast


def test_a_caller_that_takes_gzip_is_answered_by_flask(pair):
    body = _body()
    h = _headers(pair, RENEW, body, **{'Accept-Encoding': 'gzip'})
    slow, quick, fast = both(pair, RENEW, h, body)
    assert slow[0] == 200 and not fast


# --- nothing else -------------------------------------------------------------------------

@pytest.mark.parametrize('path', ['/api/ha/peer/renewal', '/api/ha/peer/status', '/api/ha/peer/renew/',
                                  '//api/ha/peer/renew', '/api/ha/peer/vote/x', '/api/ha/peer/forward',
                                  '/api/health'])
def test_no_other_route_takes_the_fast_path(pair, path):
    body = _body()
    _fresh(pair)
    r, answered = _send(pair, True, path, _headers(pair, path, body), body)
    assert answered == 0, (path, r.status_code)


@pytest.mark.parametrize('method', ['HEAD', 'OPTIONS'])
def test_no_other_method_takes_the_fast_path(pair, method):
    _fresh(pair)
    body = _body()
    r, answered = _send(pair, True, RENEW, _headers(pair, RENEW, body), body, method=method)
    assert answered == 0


def test_a_hook_added_later_turns_it_off(pair, monkeypatch):
    """A plugin that hooks into every request (a ban list of its own) sees the lease
    calls again: the fast path stands in only for the hooks it was made for."""
    app = pair.api.app
    seen = []

    def plugin_hook():
        seen.append(1)
    monkeypatch.setitem(app.before_request_funcs, None, list(app.before_request_funcs[None]) + [plugin_hook])
    _fresh(pair)
    body = _body()
    r, answered = _send(pair, True, RENEW, _headers(pair, RENEW, body), body)
    assert r.status_code == 200 and answered == 0 and seen == [1]


def test_it_stands_in_only_for_the_hooks_it_knows():
    import pegaprox.app as app_mod
    src = inspect.getsource(app_mod.create_app)
    # made before the plugins load, and the hooks it was made for are the app's own
    assert src.index('_LeaseFastPath(app, app.wsgi_app') < src.index('load_enabled_plugins(app)')
    for name in app_mod._STOOD_IN_FOR['before']:
        assert f'def {name}(' in src or name == 'check_ip_whitelist'


def test_an_error_in_the_answer_goes_the_way_flask_takes_it(pair, monkeypatch):
    def broken(*a, **k):
        raise RuntimeError('lease state unreadable')
    monkeypatch.setattr(pair.ha, 'lease_request', broken)
    for fast in (False, True):
        _fresh(pair)
        pair.ha.forget_seen_nonces()
        body = _body()
        with pytest.raises(RuntimeError, match='lease state unreadable'):
            _send(pair, fast, RENEW, _headers(pair, RENEW, body), body)
    # outside the tests Flask answers 500 with its headers, and so does the fast path
    app = pair.api.app
    monkeypatch.setitem(app.config, 'PROPAGATE_EXCEPTIONS', False)
    slow, quick, fast = both(pair)
    assert slow[0] == 500 and fast
