"""The Ceph page says "Not installed, install it" only when a node says so. A timeout or a
500 about something else is a read that failed. The lists already tell the two apart."""
from unittest.mock import MagicMock

import pytest

from test_ha_ui import CLUSTER, NODE_METRICS, SSE_TOKEN, VM, browser, _App, _FakeServer  # noqa: F401

CID = 'cluster_1'
URL = f'/api/clusters/{CID}/datacenter/ceph'
NODES = {'data': [{'node': 'n1', 'status': 'online'}, {'node': 'n2', 'status': 'online'}]}


def _answer(status=200, text='{}', data=None):
    return MagicMock(status_code=status, text=text, json=lambda: data if data is not None else {})


def _manager(api, nodes, status):
    """status(node) answers the /ceph/status of a node, or raises."""
    m = api.make_fake_manager(CID)
    m.is_connected = True
    m.host, m.api_port = 'pve', 8006

    def get(url, **kw):
        if url.endswith('/nodes'):
            return nodes
        if url.endswith('/ceph/status'):
            return status(url.split('/nodes/')[1].split('/')[0])
        return _answer(200, data={'data': []})
    m._create_session.return_value.get = get
    api.set_manager(CID, m)


def _read(api, seed):
    r = api.as_user(seed.user('adm', role='admin')).get(URL)
    assert r.status_code == 200
    return r.get_json()


NOT_INSTALLED = _answer(500, 'binaries not installed')


def _raise(_node):
    raise TimeoutError('no answer')


def _no_json():
    def broken():
        raise ValueError('Expecting value: line 1 column 1 (char 0)')
    return MagicMock(status_code=200, text='<html>proxy error</html>', json=broken)


@pytest.mark.parametrize('name, nodes, status, available, failed', [
    ('every node says no ceph', _answer(data=NODES), lambda n: NOT_INSTALLED, False, False),
    ('every node times out', _answer(data=NODES), _raise, False, True),
    ('a 500 about something else', _answer(data=NODES), lambda n: _answer(500, 'got timeout'), False, True),
    ('the node list is refused', _answer(500, 'nope'), lambda n: NOT_INSTALLED, False, True),
    ('no node online', _answer(data={'data': [{'node': 'n1', 'status': 'offline'}]}), lambda n: NOT_INSTALLED,
     False, True),
    ('one times out, the next has ceph', _answer(data=NODES),
     lambda n: _raise(n) if n == 'n1' else _answer(data={'data': {'health': {'status': 'HEALTH_OK'}}}), True, False),
    ('one has no ceph, the next times out', _answer(data=NODES),
     lambda n: NOT_INSTALLED if n == 'n1' else _raise(n), False, True),
    ('one answers 200 with no JSON, the next has no ceph', _answer(data=NODES),
     lambda n: _no_json() if n == 'n1' else NOT_INSTALLED, False, True),
])
def test_the_answer_tells_the_two_apart(api, seed, name, nodes, status, available, failed):
    _manager(api, nodes, status)
    got = _read(api, seed)
    assert got['available'] is available, name
    assert got.get('read_failed', False) is failed, name


def _page(browser, answer, layout='modern'):  # noqa: F811
    app = _App(browser, _FakeServer(role='standalone', layout=layout, clusters=[CLUSTER], resources=[VM],
                                    metrics=NODE_METRICS, extra={
        **SSE_TOKEN, ('GET', '/api/clusters/c1/datacenter/ceph'): answer}))
    page = app.page
    page.get_by_text('Testi').first.click()
    page.locator('button', has_text='Datacenter').first.click()
    page.locator('button', has_text='Ceph').first.click()
    return app, page


EMPTY = {'available': False, 'status': None, 'osd': [], 'mon': [], 'mds': [], 'mgr': [], 'pools': [], 'fs': [],
         'rules': []}


@pytest.mark.parametrize('answer', [(200, dict(EMPTY, read_failed=True)), (500, {'error': 'boom'})],
                         ids=['the_route_says_so', 'the_route_itself_fails'])
def test_runtime_a_failed_read_does_not_say_not_installed(browser, answer):  # noqa: F811
    app, page = _page(browser, answer)
    try:
        page.get_by_text('Could not read Ceph').first.wait_for(timeout=6000)
        assert page.get_by_text('Ceph Not Installed').count() == 0
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


def test_runtime_no_ceph_still_says_not_installed(browser):  # noqa: F811
    app, page = _page(browser, (200, dict(EMPTY, read_failed=False)))
    try:
        page.get_by_text('Ceph Not Installed').first.wait_for(timeout=6000)
        assert page.get_by_text('Could not read Ceph').count() == 0
    finally:
        app.ctx.close()


def test_runtime_the_cloud_view_says_it_too(browser):  # noqa: F811
    app = _App(browser, _FakeServer(role='standalone', layout='cloud', clusters=[CLUSTER], resources=[VM],
                                    metrics=NODE_METRICS, extra={
        **SSE_TOKEN, ('GET', '/api/clusters/c1/datacenter/ceph'): (200, dict(EMPTY, read_failed=True))}))
    page = app.page
    try:
        page.locator('.cloud-shell').get_by_text('Ceph', exact=True).first.click()
        page.get_by_text('None of the reachable nodes').first.wait_for(timeout=6000)
        assert page.get_by_text('Ceph is not configured').count() == 0
        assert not app.errors, app.errors
    finally:
        app.ctx.close()
