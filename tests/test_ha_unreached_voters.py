"""A voter that refuses connections or drops them, while the leader confirms before every
write (#625 stage 2; found by the round-three measurement of slice S4).

A member that is down answers a confirm round with a refused connection at once, or
with a TLS handshake it closes. It owed nothing (the call came back), so every confirm
round asked it again, and every failed call dropped the kept session with its link: a
new session and TLS context per round, and writes slowed by both. Now:
  * a voter whose renewal failed counts as owing (ha_vote Node._unreached): confirm
    rounds pass it while the others make a majority, the renewal every R still goes to
    it, and the first answer it gives brings it back into the rounds
  * the kept session and its link stay across a PeerUnreachable; only the socket that
    failed is closed

MK Oct 2026 (#625)
"""
import socket
import ssl
import threading

import pytest

from pegaprox.core import ha
from test_ha_members import IDS, group  # noqa: F401
from _ha_lease_harness import T, auto  # noqa: F401
from test_ha_lease_link import _Member, kept, member  # noqa: F401


def _renewals_to(auto, n):
    return sum(1 for c in auto.g.calls if c[0] == 'a' and c[1] == n and c[3] == ha.RENEW_PATH)


def test_a_voter_that_cannot_be_reached_is_passed_by_confirm_rounds_until_a_renewal_reaches_it(auto, seed):
    auto.form(seed)
    auto.cut('a', 'c', both=False)
    with auto.at('a') as ha_:
        assert ha_.confirm_lease()
    first = _renewals_to(auto, 'c')
    assert first >= 1
    assert IDS['c'] in auto.node('a')._unreached
    for _ in range(20):
        with auto.at('a') as ha_:
            assert ha_.confirm_lease()
    # twenty writes, b alone made the majority with a: c was not asked once
    assert _renewals_to(auto, 'c') == first
    assert _renewals_to(auto, 'b') >= 21
    # the renewal every R goes to everyone, c too; once c answers it is asked again
    auto.heal()
    auto.run(T.R + 1, dt=0.5, members='a')
    assert IDS['c'] not in auto.node('a')._unreached
    before = _renewals_to(auto, 'c')
    with auto.at('a') as ha_:
        assert ha_.confirm_lease()
    assert _renewals_to(auto, 'c') == before + 1


def test_voters_that_failed_are_asked_again_where_the_rest_make_no_majority(auto, seed):
    """b and c both failed: a alone is no majority, so a round asks them anyway rather
    than none at all."""
    auto.form(seed)
    node = auto.node('a')
    node._unreached |= {IDS['b'], IDS['c']}
    asked = _renewals_to(auto, 'b'), _renewals_to(auto, 'c')
    with auto.at('a') as ha_:
        assert ha_.confirm_lease()
    assert _renewals_to(auto, 'b') > asked[0] and _renewals_to(auto, 'c') > asked[1]
    assert not node._unreached


def test_a_round_that_made_no_majority_without_them_asks_them_again(auto, seed):
    """c failed and is passed; then b goes as well and the round of a and b alone finds
    no majority: the next round asks c again instead of waiting for the renewal every R."""
    auto.form(seed)
    auto.cut('a', 'c', both=False)
    with auto.at('a') as ha_:
        assert ha_.confirm_lease()
    node = auto.node('a')
    assert IDS['c'] in node._unreached
    auto.heal()
    auto.pause('b')
    before = _renewals_to(auto, 'c')
    with auto.at('a') as ha_:
        # the round passes c and b does not answer: no majority, and c is asked again
        assert ha_.confirm_lease()
    assert _renewals_to(auto, 'c') > before and IDS['c'] not in node._unreached


def test_a_refusal_answer_is_an_answer(auto, seed):
    """A voter that answers, whatever it says (HA_CLOCK, a refusal), was reached."""
    auto.form(seed)
    node = auto.node('a')
    node._unreached.add(IDS['c'])
    with auto.at('a'):
        r = node._new_round('renew', node.clock(), node.clock() + 2, node.st['led']['epoch'], {IDS['c']})
        node.on_answer(IDS['c'], r.tag, {'ok': False, 'granted': False, 'reason': 'HA_CLOCK'})
    assert IDS['c'] not in node._unreached


# --- the kept session across a peer that cannot be reached ---------------------------------

def _closed_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _call(url, fp):
    return ha._peer_call('POST', url, fp, ha.RENEW_PATH, json_body={'epoch': 1}, timeout=2, keep_alive=True)


def test_a_refused_connection_keeps_the_session_and_its_link(member, kept):
    assert _call(member.url, member.fp).status_code == 200
    url = f'https://127.0.0.1:{_closed_port()}'
    for _ in range(3):
        with pytest.raises(ha.PeerUnreachable):
            _call(url, member.fp)
    held = ha._kept_sessions[url][1]
    with pytest.raises(ha.PeerUnreachable):
        _call(url, member.fp)
    assert ha._kept_sessions[url][1] is held and isinstance(held.pegaprox_lean, ha._LeaseLink)
    # the member's own session is untouched, its connection still in use
    assert _call(member.url, member.fp).status_code == 200 and member.connections == 1


class _Closer:
    """Accepts and closes: a stopped service behind a port that is still open."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(('127.0.0.1', 0))
        self.sock.listen(64)
        self.url = f'https://127.0.0.1:{self.sock.getsockname()[1]}'
        self.accepted = 0
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            self.accepted += 1
            c.close()


def test_a_member_that_accepts_and_closes_keeps_the_session_and_its_link(member, kept):
    closer = _Closer()
    try:
        made = []
        real = ha._new_session
        import pegaprox.core.ha as ha_mod
        ha_mod._new_session = lambda fp: made.append(fp) or real(fp)
        try:
            for _ in range(4):
                with pytest.raises(ha.PeerUnreachable):
                    _call(closer.url, member.fp)
        finally:
            ha_mod._new_session = real
        assert len(made) == 1, 'one session for all four calls'
        link = ha._kept_sessions[closer.url][1].pegaprox_lean
        assert link.idle == []
    finally:
        closer.sock.close()


def test_a_call_that_got_out_and_broke_still_drops_the_session(member, kept):
    """Taken and not answered (PeerNoAnswer): what broke may sit in the pool."""
    member.reply = lambda req: b'HTTP/1.1 2x0 OK\r\nContent-Length: 2\r\n\r\n{}'
    with pytest.raises(ha.PeerNoAnswer):
        _call(member.url, member.fp)
    assert member.url not in ha._kept_sessions
