"""What a confirm round costs once there is one before every write (#625 stage 2).

Each piece here was paid on every lease call before: the member's key parsed, the lease
block and the cv history checked, a voter's public key read, a thread started, the lease
loop woken for a tick it did not need, and on the member's side an answer held back 40 ms
by Nagle. They are paid once now, or not at all; what they guard is unchanged.

MK Oct 2026 (#625)
"""
import inspect
import socket

import pytest

from pegaprox.core import ha, ha_vote, ha_wire


def test_the_key_of_this_instance_is_parsed_once(monkeypatch):
    key = ha_wire.new_signing_key()
    st = {'instance_id': 'a' * 32, 'signing_key': key, 'member_secret': None, 'members': {}}
    monkeypatch.setattr(ha, '_load', lambda: st)
    monkeypatch.setattr(ha, '_signer_made', {})
    parsed = []
    real = ha._private_key
    monkeypatch.setattr(ha, '_private_key', lambda v: parsed.append(v) or real(v))
    one, two = ha._signer(), ha._signer()
    assert one is two and len(parsed) == 1
    # a new key pair is a new signer at once
    st['signing_key'] = ha_wire.new_signing_key()
    three = ha._signer()
    assert three is not one and three.public_key != one.public_key and len(parsed) == 2
    # a key that cannot be read is not kept: it raises every time
    st['signing_key'] = 'broken'
    for _ in range(2):
        with pytest.raises(ha.HaError):
            ha._signer()


def test_a_lease_block_is_checked_once(monkeypatch):
    checked = []
    real = ha_vote.body_error
    monkeypatch.setattr(ha_vote, 'body_error', lambda b: checked.append(1) or real(b))
    monkeypatch.setattr(ha, '_lease_checked', [None])
    import test_ha_vote as tv
    cfg = tv.genesis()
    st = {'lease': {'cfg': cfg, 'cfg_chain': [], 'mode': 'auto'}}
    assert ha._lease(st) is st['lease'] and ha._lease(st) is st['lease']
    assert len(checked) == 1
    # a write puts a new block in: checked again, and a broken one is no lease
    st = {'lease': {'cfg': dict(cfg, body=dict(cfg['body'], mode='nonsense')), 'cfg_chain': []}}
    assert ha._lease(st) is None and ha._lease(st) is None
    assert len(checked) == 2
    st['lease'] = dict(st['lease'], cfg=cfg)
    assert ha._lease(st) is st['lease'] and len(checked) == 3


def test_the_cv_history_is_checked_once_per_history(monkeypatch):
    calls = []
    real = ha._clean_hist
    monkeypatch.setattr(ha, '_clean_hist', lambda v: calls.append(1) or real(v))
    monkeypatch.setattr(ha, '_hist_checked', [None])
    hist = [[1, n, f'{n:016x}', 'a' * 32] for n in range(1, 40)]
    st = {'cv': {'hist': hist}}
    assert ha.config_version(st) == (1, 39) and ha.cv_entry(st) == [1, 39, f'{39:016x}', 'a' * 32]
    assert ha.config_version(st) == (1, 39) and len(calls) == 1
    st = {'cv': {'hist': hist + [[1, 40, 'zz', 'a' * 32]]}}
    assert ha.config_version(st) == ha.CV_ZERO and ha.cv_entry(st) is None and len(calls) == 2
    assert ha.config_version({}) == ha.CV_ZERO


def test_a_public_key_is_read_once_and_a_small_order_one_never():
    k = ha_wire.public_of(ha_wire.private_key(ha_wire.new_signing_key()))
    assert ha_wire.public_key(k) is ha_wire.public_key(k)
    bad = 'AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
    assert ha_wire.public_key(bad) is None and bad not in ha_wire._keys_read
    assert ha_wire.public_key('nope') is None


def test_the_lease_loop_is_woken_only_for_an_earlier_tick():
    rt = ha._LeaseRuntime('a' * 32)
    rt.wake_at = 100.0
    for due, woken in ((150.0, False), (99.0, True), (None, True)):
        rt.wake.clear()
        rt.due = due
        ha._lease_after(rt)
        assert rt.wake.is_set() is woken, due
        assert rt.due is None
    # a pass is running: whatever comes in wakes it
    rt.wake_at, rt.due = None, 150.0
    rt.wake.clear()
    ha._lease_after(rt)
    assert rt.wake.is_set()


def test_a_lease_call_is_a_greenlet_of_its_own_under_gevent(monkeypatch):
    started = []
    monkeypatch.setattr(ha, '_in_background', lambda fn, name: started.append(('thread', name)))
    monkeypatch.setattr(ha, '_gevent_threads', [False])
    ha._lease_call_spawn(lambda: None)
    import gevent
    monkeypatch.setattr(gevent, 'spawn', lambda fn: started.append(('greenlet', fn)))
    monkeypatch.setattr(ha, '_gevent_threads', [True])
    ha._lease_call_spawn(lambda: None)
    assert [s[0] for s in started] == ['thread', 'greenlet']


def test_a_voter_writes_nothing_for_renewals_at_the_round_bound():
    """10 s of renewals at CONFIRM_RATE_MAX, on a data member: after the first one (it
    names the holder) nothing is written. The promise each one makes is covered by the
    hold after a restart (P + D from the start) whatever the rate: none is written down."""
    import test_ha_vote as tv
    box = tv.settled(tv.Box('b', tv.genesis(), voted_for=None))
    T = ha_vote.Timings()
    first = box.renew('a', 1)
    assert first['ok'] and len(box.store.saves) == 1
    for _ in range(10 * ha_vote.CONFIRM_RATE_MAX):
        box.now += 1.0 / ha_vote.CONFIRM_RATE_MAX
        assert box.renew('a', 1)['ok']
    assert len(box.store.saves) == 1 and box.store.state['promised'] is None
    assert box.node.promise_until <= box.now + T.P + 1e-9
    # what a restart holds covers the last promise
    again = tv.Box('b', tv.genesis(), state=box.store.state, start=box.now)
    assert again.node.hold_until >= box.node.promise_until


def test_the_witness_writes_only_its_check_for_renewals_at_the_round_bound(tmp_path, monkeypatch):
    from pegaprox import witness as wm
    import test_ha_witness as tw
    box = tw.Box(tmp_path / 'w', tw.genesis())
    box.settle()
    assert box.renew(tw.A, 1)[1]['ok']
    writes = []
    real = wm._write_json
    monkeypatch.setattr(wm, '_write_json',
                        lambda path, data, strict=True: writes.append(box.now) or real(path, data, strict))
    secs = 10
    for _ in range(secs * ha_vote.CONFIRM_RATE_MAX // 10):
        box.now += 10.0 / ha_vote.CONFIRM_RATE_MAX
        status, ans = box.renew(tw.A, 1)
        assert status == 200 and ans['ok']
    # the write check of the state directory, every WRITE_CHECK seconds, and nothing else
    assert len(writes) <= secs / wm.WRITE_CHECK + 1, writes


def test_the_server_answers_without_waiting_for_an_ack():
    """pywsgi writes the head of an answer and its body apart: with Nagle on the body waits
    for the client's delayed ack, 40 ms on every kept-alive call."""
    import pegaprox.app as app_mod
    ls = socket.socket()
    ls.bind(('127.0.0.1', 0))
    ls.listen(1)
    client = socket.create_connection(ls.getsockname())
    accepted, _ = ls.accept()
    try:
        assert not accepted.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY)
        app_mod._no_delay(accepted)
        assert accepted.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY)
    finally:
        for s in (accepted, client, ls):
            s.close()
    src = inspect.getsource(app_mod._start_gevent_server)
    body = src[src.index('def wrap_socket_and_handle(self, client_socket, address):'):]
    body = body[:body.index('def handle(self, sock, address):')]
    assert '_no_delay(client_socket)' in body
    assert body.index('_no_delay(client_socket)') < body.index('super().wrap_socket_and_handle')
