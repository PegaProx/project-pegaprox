"""The fake server of tests/test_ha_ui.py keeps the bodies of writes, not of reads.

The app reads a list again after it wrote to it, under the same path. The {} kept for that read
became bodies[path][-1] whenever it came before the test looked, so a test of what a dialog
sent failed now and then with a KeyError, depending on how busy the machine was.
"""
import json
import types

from test_ha_ui import BASE, _FakeServer

PATH = '/api/clusters/c1/storage-clusters'


def _call(server, method, body=None):
    req = types.SimpleNamespace(method=method, url=f'{BASE}{PATH}', post_data=json.dumps(body) if body else None,
                                headers={})
    server.handle(types.SimpleNamespace(request=req, fulfill=lambda **kw: None, fallback=lambda: None,
                                        abort=lambda *a: None, continue_=lambda: None))


def test_a_read_after_a_write_leaves_the_body_of_the_write_last():
    server = _FakeServer(extra={('GET', PATH): (200, []), ('POST', PATH): (201, {})})
    _call(server, 'GET')
    _call(server, 'POST', {'tolerance': 12})
    _call(server, 'GET')
    assert server.bodies[PATH] == [{'tolerance': 12}]
    assert server.calls == [('GET', PATH), ('POST', PATH), ('GET', PATH)]


def test_a_write_with_no_body_is_still_there():
    server = _FakeServer(extra={('POST', PATH): (200, {})})
    _call(server, 'POST')
    assert server.bodies[PATH] == [{}]
