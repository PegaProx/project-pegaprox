"""Linked mode: the live updates of another site's clusters.

The site that leads a cluster streams its own SSE frames for the mirror of an account,
filtered by its own broadcast as for a browser there; every frame is signed over the
request's nonce and a running number. The site the browser works at passes on only the
frame types of a cluster view for the clusters it asked for, with the remote id, and stops
at the first frame that is not as signed or not in order.

MK Nov 2026
"""
import json
import queue

import pytest

from pegaprox.core import federation_relay as relay
from pegaprox.core import federation_stream as fstream
from tests.test_federation import (  # noqa: F401 - fixtures by name
    _db_of, _defaults_out_of_the_config_dir, _fresh_budgets, at, iid)
from tests.test_federation_relay import CID, _fresh_relay, linked  # noqa: F401


@pytest.fixture(autouse=True)
def _fresh_streams():
    fstream.reset_for_tests()
    yield
    fstream.reset_for_tests()
    from pegaprox.utils.realtime import sse_clients, sse_clients_lock
    with sse_clients_lock:
        for k in [k for k in sse_clients if k.startswith(('fed-', 'test-'))]:
            sse_clients.pop(k, None)


def _principal(a, user='alice'):
    return {'user': user, 'home': iid(a), 'sh': 'ab' * 16, 'ip': '192.0.2.7'}


def _open(a, b, principal=None, clusters=CID):
    """a's signed stream request to b, and b's answer as it starts."""
    with at(a):
        headers, nonce, rid = relay.signed_request(
            iid(b), 'GET', fstream.STREAM_RULE, f'clusters={clusters}', relay._sha(b''), '',
            principal or _principal(a), relay.RELAY_STREAM_PATH)
    with at(b):
        resp = b.client.post(relay.RELAY_STREAM_PATH, data=b'', headers=headers, buffered=False)
    return resp, nonce, rid


def _lines(b, resp, n, before=()):
    """The first n lines of b's stream, with the frames in `before` broadcast at b once the
    stream is open."""
    from pegaprox.utils.realtime import broadcast_sse
    out, it = [], iter(resp.response)
    with at(b):
        out.append(next(it))
        for args in before:
            broadcast_sse(*args)
        while len(out) < n:
            out.append(next(it))
    resp.close()
    return [x.decode() if isinstance(x, bytes) else x for x in out]


_METRICS = ('metrics', {'nodes': {'n1': {'cpu': 0.5}}}, CID)
# a global event of the site, and one of a kind no cluster view reads, sent for the cluster
_ELSEWHERE = [('vmware_servers', {'servers': ['esx1']}, None),
              ('site_recovery', {'plan': 'p1', 'step': 2}, CID)]


def test_the_leading_site_streams_its_own_frames_signed(linked):
    a, b = linked
    resp, nonce, rid = _open(a, b)
    assert resp.status_code == 200
    first, frame = _lines(b, resp, 2, before=_ELSEWHERE + [_METRICS])
    assert json.loads(first.split(' ', 2)[2]) == {'type': 'fed_stream', 'clusters': [CID]}
    seq, _sig, body = frame.split(' ', 2)
    # another site's global event never leaves it, the cluster's metrics do
    assert seq == '1' and json.loads(body)['type'] == 'metrics'
    assert json.loads(body)['cluster_id'] == CID
    # closed with its response: no stream of the mirror stays registered, no slot held
    from pegaprox.utils.realtime import sse_clients
    assert not [k for k in sse_clients if k.startswith('fed-')]
    assert fstream._streams_in._used == 0


def _feed_into_browser(a, b, lines, nonce, rid, raws=(CID,)):
    from pegaprox.utils.realtime import sse_clients, sse_clients_lock
    q = queue.Queue()
    with sse_clients_lock:
        sse_clients['test-browser'] = {'queue': q, 'user': 'alice', 'clusters': []}
    feed = fstream.Feed('test-browser', iid(b), set(raws), _principal(a))
    with at(a):
        rec = __import__('pegaprox.core.federation', fromlist=['x']).member_record(iid(b))
        key = relay.ha_wire.public_key(rec['public_key'])
        good = feed.read(lines, nonce, rid, key)
    got = []
    while not q.empty():
        got.append(json.loads(q.get_nowait()))
    return good, got


def test_a_stream_closed_before_its_first_frame_lets_its_slot_go(linked):
    """A generator that never started runs no finally: the answer ends the feed itself."""
    a, b = linked
    from pegaprox.core.db import get_db
    from pegaprox.utils.realtime import sse_clients
    call = {'user': 'alice', 'home': iid(a), 'sh': '', 'tok': None, 'query': f'clusters={CID}'}
    with at(b):
        row = dict(get_db().get_user('alice'), username='alice')
        body = fstream.leading_stream(iid(a), call, row, 'n' * 24, 'f' * 32)
    assert [k for k in sse_clients if k.startswith('fed-')] and fstream._streams_in._used == 1
    # the server closes the answer without asking it for a single frame
    body.close()
    assert not [k for k in sse_clients if k.startswith('fed-')]
    assert fstream._streams_in._used == 0


def test_the_browser_gets_the_frames_under_the_remote_id(linked):
    a, b = linked
    resp, nonce, rid = _open(a, b)
    lines = _lines(b, resp, 2, before=[_METRICS])
    good, got = _feed_into_browser(a, b, lines, nonce, rid)
    assert good is True
    assert [(f['type'], f['cluster_id']) for f in got] == [('metrics', f'{CID}~{iid(b)}')]
    assert got[0]['data'] == {'nodes': {'n1': {'cpu': 0.5}}}


def test_a_frame_not_as_signed_or_out_of_order_ends_the_feed(linked):
    a, b = linked
    resp, nonce, rid = _open(a, b)
    lines = _lines(b, resp, 3, before=[_METRICS, _METRICS])
    bent = lines[:1] + [lines[1].replace('0.5', '0.9')] + lines[2:]
    good, got = _feed_into_browser(a, b, bent, nonce, rid)
    assert good is True and got == []
    # the right frames, in another order: nothing after the gap
    good, got = _feed_into_browser(a, b, [lines[0], lines[2], lines[1]], nonce, rid)
    assert got == []
    # counterproof: as sent, both come through
    good, got = _feed_into_browser(a, b, lines, nonce, rid)
    assert len(got) == 2


def test_a_site_passes_on_only_what_a_cluster_view_reads(linked):
    """Even signed: another type, or a cluster this feed did not ask for, stays out."""
    a, b = linked
    with at(b):
        nonce, rid = 'n' * 24, 'f' * 32
        lines = [fstream.signed_line(nonce, rid, 0, json.dumps({'type': 'fed_stream'})),
                 fstream.signed_line(nonce, rid, 1, json.dumps(
                     {'type': 'site_recovery', 'cluster_id': CID, 'data': {}})),
                 fstream.signed_line(nonce, rid, 2, json.dumps(
                     {'type': 'metrics', 'cluster_id': 'pve9', 'data': {}})),
                 fstream.signed_line(nonce, rid, 3, json.dumps(
                     {'type': 'tasks', 'cluster_id': CID, 'data': []}))]
    good, got = _feed_into_browser(a, b, lines, nonce, rid)
    assert [(f['type'], f['cluster_id']) for f in got] == [('tasks', f'{CID}~{iid(b)}')]


def test_the_leading_site_streams_only_what_the_account_may_see(linked, monkeypatch):
    a, b = linked
    from pegaprox.utils import rbac
    with monkeypatch.context() as m:
        m.setattr(rbac, 'get_user_clusters', lambda user, **kw: ['other'])
        resp, _n, _r = _open(a, b)
        assert resp.status_code == 403 and resp.get_json()['code'] == 'FED_STREAM_SCOPE'
    _db_of(b).conn.execute("UPDATE users SET enabled = 0 WHERE username = 'alice'")
    _db_of(b).conn.commit()
    resp, _n, _r = _open(a, b)
    assert resp.status_code == 403 and resp.get_json()['code'] == 'FED_RELAY_DISABLED'


def test_an_open_stream_ends_when_the_account_goes_there(linked):
    a, b = linked
    call = {'user': 'alice', 'home': iid(a), 'tok': None}
    with at(b):
        assert fstream._recheck(iid(a), call, [CID], [CID]) == [CID]
    _db_of(b).conn.execute("UPDATE users SET enabled = 0 WHERE username = 'alice'")
    _db_of(b).conn.commit()
    with at(b):
        assert fstream._recheck(iid(a), call, [CID], [CID]) == []


def test_a_stream_names_the_clusters_of_this_site_only(linked):
    a, b = linked
    with at(a):
        local, remote = fstream.split_wanted([CID, f'{CID}~{iid(b)}', f'x~{iid(a)}'])
    assert remote == [f'{CID}~{iid(b)}'] and local == [CID, f'x~{iid(a)}']
    from pegaprox.core import federation
    import unittest.mock as um
    with um.patch.object(federation, 'enabled', lambda: False):
        assert fstream.split_wanted([f'{CID}~{iid(b)}']) == ([f'{CID}~{iid(b)}'], [])


def test_a_line_without_an_end_is_not_held_whole():
    chunks = [b'1 sig {"type":', b'x' * 600]
    got = fstream.bounded_lines(iter([b'0 a b\n2 c d\n'] + chunks + [b'y' * 600]), limit=1000)
    assert next(got) == b'0 a b' and next(got) == b'2 c d'
    with pytest.raises(ValueError):
        next(got)


def test_one_account_takes_a_share_of_a_sites_feeds(linked, monkeypatch):
    a, b = linked
    started = []
    monkeypatch.setattr(fstream.Feed, 'start', lambda self: started.append(self.client_id))
    with at(a):
        for n in range(4):
            fstream.watch(f'test-{n}', [f'{CID}~{iid(b)}'], _principal(a))
        fstream.watch('test-other', [f'{CID}~{iid(b)}'], _principal(a, user='vic'))
    assert started == ['test-0', 'test-1', 'test-other']


def test_no_feed_for_an_account_of_another_site_or_a_custom_token_role(linked):
    from tests.test_federation import _add_local_user
    a, b = linked
    _add_local_user(a, 'mira', role='admin', fed_home='f' * 32)
    with at(a):
        assert fstream.principal_for('mira', 'sid', None, None, '') is None
        assert fstream.principal_for('alice', None, 7, 'ci-ops', '') is None
        p = fstream.principal_for('alice', None, 7, 'viewer', '')
        assert p['tok'] == 'viewer' and p['user'] == 'alice'
        assert 'tok' not in fstream.principal_for('alice', 'sid', None, None, '')
