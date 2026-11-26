"""Linked mode: the feeds a new SSE stream opens for other sites' clusters follow the
selection as it stands, not the one in the URL the stream was opened with.

The stream registered its client, looked up the principal of the feeds (a query), and then
opened the feeds for the remote ids of its URL, outside the lock the subscription update
takes. A browser that deselected those clusters in between (the update ran, found no
remote id and closed the feeds) got them back from the older selection, and the stream
then carried frames of clusters it no longer asked for. MK Nov 2026
"""
import pytest

import pegaprox.api.realtime as rt
import pegaprox.globals as ppglobals

REMOTE = 'pve-far~' + 'f' * 32


@pytest.fixture
def linked_stream(api, seed, monkeypatch):
    """A federation that is on, with one remote id; the feeds recorded, not opened."""
    from pegaprox.core import federation as fed, federation_stream
    ppglobals.sse_clients.clear()
    monkeypatch.setattr(fed, 'enabled', lambda: True)

    def split(ids):
        if not ids:
            return ids, []
        return [c for c in ids if '~' not in c], [c for c in ids if '~' in c]
    monkeypatch.setattr(federation_stream, 'split_wanted', split)
    feeds = {}

    def watch(client_id, ids, principal):
        # the feeds and the selection change under the lock the subscription update takes
        assert rt._fed_watch_lock.locked(), 'feeds opened outside the subscription lock'
        feeds[client_id] = list(ids)
    monkeypatch.setattr(federation_stream, 'watch', watch)
    monkeypatch.setattr(federation_stream, 'unwatch',
                        lambda client_id: feeds.pop(client_id, None))
    admin = seed.user('root2', role='admin')
    yield api, admin, federation_stream, feeds
    ppglobals.sse_clients.clear()


def _open(api, token, clusters):
    with api.app.test_request_context(f'/api/sse/updates?token={token}&clusters={clusters}'):
        resp = rt.sse_updates()
    assert resp.status_code == 200, resp.get_data(as_text=True)[:200]
    return resp


def _client_of(user):
    with ppglobals.sse_clients_lock:
        return next(k for k, v in ppglobals.sse_clients.items() if v.get('user') == user)


def test_a_deselect_while_the_stream_opens_keeps_the_feed_closed(linked_stream, monkeypatch):
    api, admin, federation_stream, feeds = linked_stream

    def principal_for(user, sid, token_id, token_role, ip):
        # the browser deselects the other site's cluster before the stream got this far
        r = api.as_user(admin).post('/api/sse/subscribe',
                                    json={'client_id': _client_of(user), 'clusters': ['pve1']})
        assert r.status_code == 200 and r.get_json().get('ok') is not False, r.data
        return {'user': user, 'home': 'h' * 32, 'sh': 'ab' * 16, 'ip': ip or ''}
    monkeypatch.setattr(federation_stream, 'principal_for', principal_for)

    resp = _open(api, rt.create_sse_token('root2', None), f'pve1,{REMOTE}')
    try:
        cid = _client_of('root2')
        assert ppglobals.sse_clients[cid]['remote'] == []
        assert cid not in feeds, 'the older selection opened its feed again'
    finally:
        resp.response.close()


def test_a_stream_opened_with_a_remote_cluster_gets_its_feed(linked_stream, monkeypatch):
    api, admin, federation_stream, feeds = linked_stream
    monkeypatch.setattr(federation_stream, 'principal_for',
                        lambda user, sid, token_id, token_role, ip:
                        {'user': user, 'home': 'h' * 32, 'sh': 'ab' * 16, 'ip': ip or ''})

    resp = _open(api, rt.create_sse_token('root2', None), f'pve1,{REMOTE}')
    cid = _client_of('root2')
    assert feeds.get(cid) == [REMOTE]
    # the stream ends after its first frame: its feeds go with it
    gen = resp.response
    next(gen)
    gen.close()
    assert cid not in feeds


def test_a_selection_changed_to_another_remote_cluster_opens_that_one(linked_stream,
                                                                      monkeypatch):
    api, admin, federation_stream, feeds = linked_stream
    other = 'pve-near~' + 'e' * 32

    def principal_for(user, sid, token_id, token_role, ip):
        cid = _client_of(user)
        with ppglobals.sse_clients_lock:
            ppglobals.sse_clients[cid]['remote'] = [other]
        return {'user': user, 'home': 'h' * 32, 'sh': 'ab' * 16, 'ip': ip or ''}
    monkeypatch.setattr(federation_stream, 'principal_for', principal_for)

    resp = _open(api, rt.create_sse_token('root2', None), f'pve1,{REMOTE}')
    try:
        assert feeds.get(_client_of('root2')) == [other]
    finally:
        resp.response.close()
