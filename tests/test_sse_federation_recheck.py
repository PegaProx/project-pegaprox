"""Linked mode: the 30 s re-check of an SSE stream stops the other sites' feeds under the
lock the subscription update takes, and decides with the selection as it stands then.

When the re-check got no principal any more it closed the feeds and only afterwards
cleared the stream's remote ids, both outside that lock. A subscription update whose own
principal_for still answered could open its feeds in between; the cleared selection then
hid them, the stream carried frames of clusters it showed none of, and the next re-check
(no remote id left) never asked again. It also decided whether the stream had anything
of this site left from what it read before asking, so a cluster selected meanwhile went
with the stream. MK Nov 2026
"""
import threading

import pytest

import pegaprox.api.realtime as rt
import pegaprox.globals as ppglobals

REMOTE = 'pve-far~' + 'f' * 32


class _TellingLock:
    """Stands in for _fed_watch_lock and says when a thread found it held, so the test
    knows the update waits on it without guessing a sleep."""

    def __init__(self, told):
        self._lock = threading.Lock()
        self.told = told

    def locked(self):
        return self._lock.locked()

    def __enter__(self):
        if not self._lock.acquire(blocking=False):
            self.told.set()
            self._lock.acquire()
        return self

    def __exit__(self, *exc):
        self._lock.release()


@pytest.fixture
def linked(api, seed, monkeypatch):
    from pegaprox.core import federation as fed, federation_stream
    ppglobals.sse_clients.clear()
    monkeypatch.setattr(rt, 'SSE_REAUTHZ_INTERVAL', 0)
    monkeypatch.setattr(fed, 'enabled', lambda: True)
    monkeypatch.setattr(federation_stream, 'split_wanted', lambda ids: (
        [c for c in ids or [] if '~' not in c], [c for c in ids or [] if '~' in c]))
    feeds = {}

    def watch(client_id, ids, principal):
        assert rt._fed_watch_lock.locked(), 'feeds opened outside the subscription lock'
        feeds[client_id] = list(ids)
    monkeypatch.setattr(federation_stream, 'watch', watch)
    admin = seed.user('root2', role='admin')
    yield api, admin, federation_stream, feeds
    ppglobals.sse_clients.clear()


def _principal(user, ip):
    return {'user': user, 'home': 'h' * 32, 'sh': 'ab' * 16, 'ip': ip or ''}


def _open(api, clusters):
    token = rt.create_sse_token('root2', None)
    with api.app.test_request_context(f'/api/sse/updates?token={token}&clusters={clusters}'):
        resp = rt.sse_updates()
    assert resp.status_code == 200, resp.get_data(as_text=True)[:200]
    with ppglobals.sse_clients_lock:
        cid = next(k for k, v in ppglobals.sse_clients.items() if v.get('user') == 'root2')
    return resp.response, cid


# the update may come in before the re-check takes the feeds away or right after it
@pytest.mark.parametrize('feeds_go_first', [True, False], ids=['after-unwatch', 'before-unwatch'])
def test_an_update_during_the_recheck_keeps_feeds_and_selection_together(linked, monkeypatch,
                                                                         feeds_go_first):
    api, admin, federation_stream, feeds = linked
    told = threading.Event()
    monkeypatch.setattr(rt, '_fed_watch_lock', _TellingLock(told))
    main, recheck = threading.current_thread(), [False]

    def principal_for(user, sid, token_id, token_role, ip):
        # the re-check finds the principal gone, the update next to it still gets one
        if threading.current_thread() is main and recheck[0]:
            return None
        return _principal(user, ip)
    monkeypatch.setattr(federation_stream, 'principal_for', principal_for)

    session, workers, answers = api.as_user(admin), [], []

    def update(cid):
        try:
            answers.append(session.post('/api/sse/subscribe',
                                        json={'client_id': cid, 'clusters': ['pve1', REMOTE]}))
        finally:
            told.set()

    def unwatch(client_id):
        if feeds_go_first:
            feeds.pop(client_id, None)
        if threading.current_thread() is main and recheck[0] and not workers:
            # the browser picks the other site's cluster again right now
            workers.append(threading.Thread(target=update, args=(client_id,), daemon=True))
            workers[0].start()
            # until that update has opened its feeds, or waits for the lock held here
            assert told.wait(15), 'the subscription update neither ran nor waited'
        if not feeds_go_first:
            feeds.pop(client_id, None)
    monkeypatch.setattr(federation_stream, 'unwatch', unwatch)

    gen, cid = _open(api, f'pve1,{REMOTE}')
    try:
        assert feeds.get(cid) == [REMOTE]
        q = ppglobals.sse_clients[cid]['queue']
        next(gen)
        recheck[0] = True
        for _ in range(3):
            q.put_nowait('{"type":"heartbeat"}')
        next(gen)
        next(gen)                       # the re-check ran before this frame
        assert workers, 'the re-check did not stop the feeds'
        workers[0].join(15)
        assert not workers[0].is_alive()
        assert answers and answers[0].status_code == 200, answers
        with ppglobals.sse_clients_lock:
            remote = list(ppglobals.sse_clients[cid]['remote'])
        assert feeds.get(cid, []) == remote, \
            "the other sites' feeds and the stream's selection of them went apart"
    finally:
        gen.close()


def test_a_cluster_selected_while_the_recheck_asks_keeps_the_stream(linked, monkeypatch):
    api, admin, federation_stream, feeds = linked
    recheck, asked = [False], []
    monkeypatch.setattr(federation_stream, 'unwatch',
                        lambda client_id: feeds.pop(client_id, None))

    def principal_for(user, sid, token_id, token_role, ip):
        if not recheck[0]:
            return _principal(user, ip)
        if not asked:
            asked.append(user)
            # the browser swaps the other site's cluster for one of this site meanwhile
            with ppglobals.sse_clients_lock:
                cid = next(iter(ppglobals.sse_clients))
            r = api.as_user(admin).post('/api/sse/subscribe',
                                        json={'client_id': cid, 'clusters': ['pve1']})
            assert r.status_code == 200 and r.get_json().get('ok') is not False, r.data
        return None
    monkeypatch.setattr(federation_stream, 'principal_for', principal_for)

    gen, cid = _open(api, REMOTE)
    try:
        assert ppglobals.sse_clients[cid]['clusters'] == []
        q = ppglobals.sse_clients[cid]['queue']
        next(gen)
        recheck[0] = True
        for _ in range(3):
            q.put_nowait('{"type":"heartbeat"}')
        next(gen)
        # the re-check runs, then this frame: the stream has pve1 to show now
        frame = next(gen, None)
        assert asked == ['root2']
        assert frame is not None and cid in ppglobals.sse_clients, \
            'the stream closed with a cluster of this site selected'
        assert 'heartbeat' in frame
        assert ppglobals.sse_clients[cid]['clusters'] == ['pve1']
        assert ppglobals.sse_clients[cid]['remote'] == [] and cid not in feeds
    finally:
        gen.close()
