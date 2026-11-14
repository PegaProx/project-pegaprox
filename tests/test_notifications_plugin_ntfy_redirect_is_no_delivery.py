"""The push notification plugin posts to ntfy without following a redirect.

_send_ntfy checked the ntfy url against the outbound guard and then let requests follow
whatever Location the server answered with, so the alert went on to an address nobody
had checked (a 307 or 308 posted it there again), and the 200 from there counted as
delivered. It posts with allow_redirects=False now, like the alert webhooks: a 3xx is a
failed delivery whose error says the redirect was not followed. MK Nov 2026

Real requests: an HTTP endpoint on loopback stands for the ntfy server, a second one for
the place its redirect points at. That one must never see a request.
"""
import importlib.util
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALERT = {'alert_name': 'CPU high', 'severity': 'warning', 'metric': 'cpu',
         'message': 'vm-db01 on pve3 at 97%'}
TOKEN = 'tk_ntfy_5b2e91'


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get('Content-Length') or 0)
        self.server.seen.append((self.command, self.path, self.headers.get('Authorization'),
                                 self.rfile.read(n) if n else b''))
        self.send_response(self.server.status)
        if self.server.location:
            self.send_header('Location', self.server.location)
        self.send_header('Content-Length', '0')
        self.end_headers()

    # a followed 301, 302 or 303 arrives as a GET
    do_GET = do_POST


@pytest.fixture
def net():
    started = []

    def start(status=200, location=None):
        srv = ThreadingHTTPServer(('127.0.0.1', 0), _Handler)
        srv.daemon_threads = True
        srv.seen, srv.status, srv.location = [], status, location
        threading.Thread(target=srv.serve_forever, kwargs={'poll_interval': 0.01}, daemon=True).start()
        started.append(srv)
        return srv

    yield start
    for srv in started:
        srv.shutdown()
        srv.server_close()


def _base(srv):
    return f'http://127.0.0.1:{srv.server_address[1]}'


@pytest.fixture
def plugin(db, tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location(
        'notifications_redirect_under_test', os.path.join(ROOT, 'plugins', 'notifications', '__init__.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    monkeypatch.setattr(mod, 'PLUGIN_DIR', str(tmp_path))
    monkeypatch.setattr(mod, '_require_admin', lambda: None)
    # loopback stands for the ntfy server here, the guard has tests of its own
    monkeypatch.setattr('pegaprox.utils.url_security.resolve_and_pin_url', lambda url, **kw: url)
    return mod


def _cfg(srv):
    return {'ntfy_enabled': True, 'ntfy_url': _base(srv), 'ntfy_topic': 'ops', 'ntfy_token': TOKEN}


@pytest.mark.parametrize('status', [301, 302, 303, 307, 308])
def test_a_redirect_is_a_failed_delivery_and_nothing_goes_to_its_target(plugin, net, status):
    elsewhere = net(200)
    ntfy = net(status, location=_base(elsewhere) + '/moved')

    ok, err = plugin._send_ntfy(ALERT, _cfg(ntfy))

    assert ok is False, err
    assert str(status) in err and 'redirect' in err, err
    assert len(ntfy.seen) == 1
    assert elsewhere.seen == []


def test_the_test_button_says_a_redirect_was_not_delivered(plugin, net):
    elsewhere = net(200)
    ntfy = net(307, location=_base(elsewhere) + '/moved')
    with open(os.path.join(plugin.PLUGIN_DIR, 'config.json'), 'w') as f:
        json.dump(_cfg(ntfy), f)

    res = plugin._send_test()['ntfy']

    assert res['success'] is False and 'redirect' in res['error'], res
    assert elsewhere.seen == []


@pytest.mark.parametrize('status', [200, 201])
def test_a_post_ntfy_takes_is_still_a_delivery(plugin, net, status):
    ntfy = net(status)

    assert plugin._send_ntfy(ALERT, _cfg(ntfy)) == (True, None)
    assert ntfy.seen == [('POST', '/ops', f'Bearer {TOKEN}', ALERT['message'].encode())]


@pytest.mark.parametrize('status', [400, 403, 500])
def test_an_error_status_keeps_its_plain_message(plugin, net, status):
    ntfy = net(status)

    assert plugin._send_ntfy(ALERT, _cfg(ntfy)) == (False, f'ntfy returned {status}')
