"""Stream nonces for the votes and renewals of automatic failover (#625 stage 2).

A leader that confirms before every write sends up to CONFIRM_RATE_MAX rounds a second.
A replay cache of random nonces sized for that would hold 121 entries per round a second
and sender; the old share of 4096 refused ('full') above about 34 rounds a second and
cost the leader its renewals. Lease calls are numbered per sending process instead
(ha_wire.take_stream): each number is taken once, in any order within STREAM_WINDOW, and
what is kept per stream is a bitmap. Every other signed call of a member (the writes a
serving member forwards above all) is numbered as well, in a stream and a share of its
own, so forwarded writes are not capped at 34 a second and never use up what the
renewals need; a random nonce still goes to the old share, for a member on the release
before. Pinned here: the replay rule as strong as before
(a call taken once is refused for as long as its signature is good), a sender's restart,
a receiver's restart, calls that overtake each other, the cap on streams, the cost at
the rate bound, and both receivers (data members in ha.py, the witness).

MK Oct 2026 (#625)
"""
import time

import pytest

from pegaprox import witness as wm
from pegaprox.core import ha_vote as hv
from pegaprox.core import ha_wire
from test_ha_witness import A, B, KEYS, W, Box, genesis

S1, S2 = 'a' * 32, 'b' * 32
WIN = ha_wire.SIGNATURE_WINDOW


def _n(stream, seq):
    return ha_wire.stream_nonce(stream, seq)


def test_each_number_is_taken_once_in_any_order_within_the_window():
    st, now = {}, 1000.0
    assert ha_wire.take_stream(st, _n(S1, 5), 1000, now) == 'ok'
    assert ha_wire.take_stream(st, _n(S1, 5), 1000, now) == 'seen'
    # overtaken on the way: 3 and 4 come after 5, once each
    assert [ha_wire.take_stream(st, _n(S1, k), 1000, now) for k in (3, 4, 3, 4)] == ['ok', 'ok', 'seen', 'seen']
    # a jump ahead moves the window; what fell below it is refused
    far = 5 + ha_wire.STREAM_WINDOW
    assert ha_wire.take_stream(st, _n(S1, far), 1000, now) == 'ok'
    assert ha_wire.take_stream(st, _n(S1, 4), 1000, now) == 'seen'
    assert ha_wire.take_stream(st, _n(S1, far - ha_wire.STREAM_WINDOW + 1), 1000, now) == 'ok'
    assert ha_wire.take_stream(st, _n(S1, far - ha_wire.STREAM_WINDOW + 1), 1000, now) == 'seen'
    # far beyond: the old window is gone, nothing below the new top gets in twice
    top = far + 10 * ha_wire.STREAM_WINDOW
    assert ha_wire.take_stream(st, _n(S1, top), 1000, now) == 'ok'
    assert ha_wire.take_stream(st, _n(S1, top), 1000, now) == 'seen'
    assert ha_wire.take_stream(st, _n(S1, far), 1000, now) == 'seen'
    # looking does not take
    assert ha_wire.take_stream(st, _n(S1, top + 1), 1000, now, spend=False) == 'ok'
    assert ha_wire.take_stream(st, _n(S1, top + 1), 1000, now) == 'ok'


def test_the_format_is_its_own():
    assert ha_wire.is_stream_nonce(_n(S1, 1))
    for other in ('x' * 24, 'ls1-' + 'g' * 32 + '-1', 'ls1-' + 'a' * 32 + '-0', 'ls1-' + 'a' * 32 + '-1x',
                  'ls1-' + 'a' * 31 + '-1', None, 7):
        assert not ha_wire.is_stream_nonce(other)
    # a random nonce of signed_headers never looks like one
    assert not any(ha_wire.is_stream_nonce(ha_wire.signed_headers(
        ha_wire.private_key(KEYS[A]), A, W, 'POST', '/x', b'', time.time())[ha_wire.PEER_NONCE_HEADER])
        for _ in range(50))


def test_a_stream_is_kept_while_its_newest_call_is_signed_well_and_a_replay_finds_it():
    """As strong as the random nonces: a number taken is refused while its signature is
    inside the window. Past that the window refuses it, and the stream may go."""
    st = {}
    assert ha_wire.take_stream(st, _n(S1, 1), 1000, 1000.0) == 'ok'
    assert ha_wire.take_stream(st, _n(S1, 2), 1050, 1050.0) == 'ok'
    # a new stream (the sender restarted) late in the window of the old one: the old one stays
    assert ha_wire.take_stream(st, _n(S2, 1), 1170, 1170.0) == 'ok'
    assert S1 in st
    assert ha_wire.take_stream(st, _n(S1, 1), 1000, 1170.0) == 'seen'
    # once the newest call of S1 is out of every window, a new stream lets it go
    assert ha_wire.take_stream(st, _n('c' * 32, 1), 1050 + WIN + 2, 1050 + WIN + 2.0) == 'ok'
    assert S1 not in st and S2 in st


def test_the_streams_of_one_sender_are_capped_until_they_age_out():
    st = {}
    for k in range(ha_wire.STREAMS_PER_SENDER):
        assert ha_wire.take_stream(st, _n(f'{k:032x}', 1), 1000, 1000.0) == 'ok'
    assert ha_wire.take_stream(st, _n('f' * 32, 1), 1000, 1000.0) == 'full'
    # a stream already held is not refused for the cap
    assert ha_wire.take_stream(st, _n(f'{3:032x}', 2), 1000, 1000.0) == 'ok'
    assert ha_wire.take_stream(st, _n('f' * 32, 1), 1000 + WIN + 2, 1000 + WIN + 2.0) == 'ok'


def test_at_the_rate_bound_for_a_whole_window_one_stream_stays_a_bitmap():
    """CONFIRM_RATE_MAX rounds a second for the signature window: the state of the stream
    is one int of STREAM_WINDOW bits at most, never 'full', and a check stays cheap."""
    st, n = {}, int(hv.CONFIRM_RATE_MAX * (WIN + 1))
    t0 = time.perf_counter()
    for k in range(1, n + 1):
        ts = 1000 + k // hv.CONFIRM_RATE_MAX
        # every 50th pair comes swapped, as two calls on two connections may
        seq = k + 1 if k % 50 == 1 else k - 1 if k % 50 == 2 else k
        assert ha_wire.take_stream(st, _n(S1, seq), ts, float(ts)) == 'ok'
    per = (time.perf_counter() - t0) / n
    rec = st[S1]
    assert len(st) == 1 and rec[0] == n and rec[1].bit_length() <= ha_wire.STREAM_WINDOW
    print(f'\n{n} lease calls in one stream: {per * 1e6:.2f} us per check, state {rec[1].bit_length() // 8} bytes')


def test_a_data_member_takes_numbered_lease_calls_without_a_share_and_each_once(monkeypatch):
    from pegaprox.core import ha
    ha.forget_seen_nonces()
    monkeypatch.setattr(ha, '_NONCES_PER_SENDER', 8)
    now = int(time.time())
    for k in range(1, 200):
        assert ha._fresh_nonce(W, A, _n(S1, k), now, lease=True)
    assert not ha._fresh_nonce(W, A, _n(S1, 7), now, lease=True)
    assert not [k for k in ha._seen_nonces if k[:2] == (W, A)]
    # a random nonce on a lease route: its share, which fills
    assert all(ha._fresh_nonce(W, A, f'random-nonce-{k:08d}', now, lease=True) for k in range(8))
    assert not ha._fresh_nonce(W, A, 'random-nonce-x0000000', now, lease=True)
    # a stream nonce on any other route is taken once, in a share of its own
    assert ha._fresh_nonce(W, A, _n(S1, 500), now, lease=False)
    assert not ha._fresh_nonce(W, A, _n(S1, 500), now, lease=False)
    ha.forget_seen_nonces()
    assert ha._fresh_nonce(W, A, _n(S1, 7), now, lease=True)
    ha.forget_seen_nonces()


def test_forwarded_writes_take_numbered_nonces_and_never_fill_a_share(monkeypatch):
    """A serving member forwards writes as fast as its users make them: with random nonces
    the active refused ('full') past NONCES_PER_SENDER in a signature window, about 34
    writes a second. Numbered, nothing fills; the renewals keep their own share, and a
    random nonce (a member on the release before) still goes to the old share and its cap."""
    from pegaprox.core import ha
    ha.forget_seen_nonces()
    monkeypatch.setattr(ha, '_NONCES_PER_SENDER', 8)
    now = int(time.time())
    calls = [_n(S1, k) for k in range(1, 2001)]
    assert all(ha._fresh_nonce(W, A, n, now) for n in calls)
    assert not any(ha._fresh_nonce(W, A, n, now) for n in calls[-50:])
    assert not ha._seen_nonces
    # the same numbers in the lease share are that share's: taken once there as well
    assert all(ha._fresh_nonce(W, A, n, now, lease=True) for n in calls[:100])
    assert all(ha._fresh_nonce(W, A, f'random-nonce-{k:08d}', now) for k in range(8))
    assert not ha._fresh_nonce(W, A, 'random-nonce-x0000000', now)
    ha.forget_seen_nonces()


def test_a_member_forwards_more_writes_than_a_share_holds_through_the_verdict(monkeypatch):
    """End to end on the receiving side: signed forward calls of a member, more than the
    random share would take, all judged as the member's."""
    from pegaprox.core import ha
    ha.forget_seen_nonces()
    monkeypatch.setattr(ha, '_NONCES_PER_SENDER', 16)
    key = ha_wire.private_key(KEYS[A])
    pub = ha_wire.public_of(key)
    raw = ha_wire.wire_body({'method': 'POST', 'path': '/api/vms/start'})
    said = []
    for _ in range(200):
        h = ha._signed_headers(key, A, W, 'POST', ha.FORWARD_PATH, raw)
        said.append(ha._signature_check(h, 'POST', ha.FORWARD_PATH, raw, A, pub, W))
        # a replay of the very same call is refused
        assert ha._signature_check(h, 'POST', ha.FORWARD_PATH, raw, A, pub, W) == ''
    assert said == ['ok'] * 200
    ha.forget_seen_nonces()


def test_the_witness_takes_numbered_calls_off_its_lease_routes_apart(box):
    """Members number their other calls too; the witness keeps those apart from the
    lease calls, as it keeps the random ones apart."""
    box.settle()
    h = ha_wire.signed_headers(ha_wire.private_key(KEYS[A]), A, W, 'POST', wm.UNPAIRED_PATH, b'{}',
                               time.time(), nonce=_n(S1, 1))
    with box.w.lock:
        assert box.w._spend(A, 'unpaired', h) == 'ok'
        assert box.w._spend(A, 'unpaired', h) == 'seen'
        # number 1 of the same stream is still free in the lease share
        assert box.w._spend(A, 'renew', h) == 'ok'
    assert set(box.w.streams) == {A, (A, 'calls')}


def test_a_member_numbers_its_lease_calls_per_receiver_and_its_other_calls_apart():
    from pegaprox.core import ha
    key = ha_wire.private_key(KEYS[A])
    first = [ha._signed_headers(key, A, B, 'POST', ha.RENEW_PATH, b'{}')[ha.PEER_NONCE_HEADER] for _ in range(3)]
    other = ha._signed_headers(key, A, W, 'POST', ha.VOTE_PATH, b'{}')[ha.PEER_NONCE_HEADER]
    plain = [ha._signed_headers(key, A, B, method, path, b'')[ha.PEER_NONCE_HEADER]
             for method, path in (('GET', '/api/ha/peer/status'), ('POST', ha.FORWARD_PATH))]
    seqs = [int(n.rsplit('-', 1)[1]) for n in first]
    assert all(ha_wire.is_stream_nonce(n) for n in first + [other] + plain)
    assert seqs == [seqs[0], seqs[0] + 1, seqs[0] + 2]
    assert {n.split('-')[1] for n in first + [other]} == {ha._lease_stream['id']}
    # every other signed call in a stream of its own: forwarded writes never move the
    # numbers the renewals go by
    assert {n.split('-')[1] for n in plain} == {ha._call_stream['id']} != {ha._lease_stream['id']}
    a, b = (int(n.rsplit('-', 1)[1]) for n in plain)
    assert b == a + 1


def test_a_member_that_restarted_refuses_what_was_signed_before_its_start(monkeypatch):
    """The receiver forgot its streams with its process: a call signed before the start
    never reaches them (signature_verdict 'early'), the same as for random nonces."""
    from pegaprox.core import ha
    ha.forget_seen_nonces()
    key = ha_wire.private_key(KEYS[A])
    pub = ha_wire.public_of(key)
    raw = b'{"epoch": 1}'
    h = ha_wire.signed_headers(key, A, W, 'POST', ha.RENEW_PATH, raw, time.time() - 30, nonce=_n(S1, 1))
    assert ha._signature_check(h, 'POST', ha.RENEW_PATH, raw, A, pub, W) == 'ok'
    assert ha._signature_check(h, 'POST', ha.RENEW_PATH, raw, A, pub, W) == ''
    # the process starts again: its streams are gone, and so is the call from before
    monkeypatch.setattr(ha, '_PROCESS_STARTED', hv.ha_clock())
    ha.forget_seen_nonces()
    assert ha._signature_check(h, 'POST', ha.RENEW_PATH, raw, A, pub, W) == 'skewed'
    fresh = ha_wire.signed_headers(key, A, W, 'POST', ha.RENEW_PATH, raw, time.time() + 2, nonce=_n(S1, 2))
    assert ha._signature_check(fresh, 'POST', ha.RENEW_PATH, raw, A, pub, W) == 'ok'
    ha.forget_seen_nonces()


@pytest.fixture
def box(tmp_path):
    return Box(tmp_path / 'w', genesis())


def _renewal(box, seq, stream=S1, ts_off=0):
    payload = {'epoch': 1, 'leader': A, 'lease_s': 20, 'cv': [1, 9], 'floor_cv': [1, 0],
               'wall': time.time() + box.wall_off}
    raw = ha_wire.wire_body(payload)
    h = ha_wire.signed_headers(ha_wire.private_key(KEYS[A]), A, W, 'POST', wm.RENEW_PATH, raw,
                               time.time() + ts_off, nonce=_n(stream, seq) if seq else None)
    return h, raw


def test_the_witness_takes_more_numbered_renewals_than_a_share_holds_and_each_once(box):
    box.settle()
    n = ha_wire.NONCES_PER_SENDER + 200
    for seq in range(1, n + 1):
        h, raw = _renewal(box, seq)
        status, ans = box.w.handle('POST', wm.RENEW_PATH, h, raw, remote='192.0.2.10')
        assert status == 200 and ans['ok'] is True, (seq, status, ans)
    h, raw = _renewal(box, 17)
    assert box.w.precheck('POST', wm.RENEW_PATH, h) == ''
    assert box.w.handle('POST', wm.RENEW_PATH, h, raw, remote='192.0.2.10')[0] == 401
    # a leader that restarted numbers in a stream of its own
    h, raw = _renewal(box, 1, stream=S2)
    assert box.w.precheck('POST', wm.RENEW_PATH, h) == 'member'
    assert box.w.handle('POST', wm.RENEW_PATH, h, raw, remote='192.0.2.10')[0] == 200
    assert set(box.w.streams[A]) == {S1, S2} and not box.w.nonces.get((A, True))


def test_the_witness_still_caps_random_nonces_on_its_lease_routes(box, monkeypatch):
    box.settle()
    monkeypatch.setattr(ha_wire.take_nonce, '__defaults__', (6,))
    for _ in range(6):
        h, raw = _renewal(box, None)
        assert box.w.handle('POST', wm.RENEW_PATH, h, raw, remote='192.0.2.10')[0] == 200
    h, raw = _renewal(box, None)
    assert box.w.handle('POST', wm.RENEW_PATH, h, raw, remote='192.0.2.10')[0] == 401
    # the numbered ones are not in that share
    h, raw = _renewal(box, 1)
    assert box.w.handle('POST', wm.RENEW_PATH, h, raw, remote='192.0.2.10')[0] == 200


def test_a_witness_that_restarted_refuses_what_was_signed_before_its_start(tmp_path):
    box = Box(tmp_path / 'w', genesis(), started=int(time.time()) + 60)
    box.settle()
    h, raw = _renewal(box, 1)
    status, ans = box.w.handle('POST', wm.RENEW_PATH, h, raw, remote='192.0.2.10')
    assert status == 401 and ans.get('code') == 'HA_CLOCK'
    assert not box.w.streams
