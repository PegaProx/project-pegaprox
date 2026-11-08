# Regression for the webhook DNS-rebind pin (Aikido #469089218). _guard_url now returns a
# 3-tuple (ok, reason, url_to_use) — the callers unpack `url` from it, so a shape regression
# would break every alert send. These are network-free: literal IPs + a stubbed settings load.

import pegaprox.utils.webhooks as wh


def _settings(allow_private):
    return lambda: {'alert_webhook_allow_private': allow_private}


def test_guard_url_returns_triple_and_blocks_metadata(monkeypatch):
    monkeypatch.setattr('pegaprox.api.helpers.load_server_settings', _settings(False), raising=False)
    res = wh._guard_url('http://169.254.169.254/latest/meta-data/')
    assert isinstance(res, tuple) and len(res) == 3
    ok, _reason, _url = res
    assert ok is False


def test_guard_url_blocks_ipv6_loopback(monkeypatch):
    monkeypatch.setattr('pegaprox.api.helpers.load_server_settings', _settings(False), raising=False)
    ok, _r, _u = wh._guard_url('http://[::1]:8080/hook')
    assert ok is False


def test_guard_url_allow_private_permits_and_does_not_pin(monkeypatch):
    # operator opt-in: an internal ntfy/Gotify is allowed AND left un-pinned (url unchanged).
    monkeypatch.setattr('pegaprox.api.helpers.load_server_settings', _settings(True), raising=False)
    ok, _r, url = wh._guard_url('http://10.0.0.5:9000/hook')
    assert ok is True
    assert url == 'http://10.0.0.5:9000/hook'
