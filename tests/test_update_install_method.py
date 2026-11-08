# The in-app updater is a git-tree + pip file update and only fits the source/deploy.sh layout.
# On an apt/dpkg or Docker install it would diverge from the package manager and (for apt) can't
# lift the dpkg-owned crypto libs -> fail-closed TLS brick on restart (the bbailey 1.0.1 case).
# These guard tests pin that perform_pegaprox_update refuses on apt/docker and still runs on source.

import pegaprox.api.settings as settings
import requests


def _admin(seed):
    return seed.user('root', role='admin', tenant_id='default')


def _kill_network(monkeypatch):
    # make both version fetches fail fast so a guard-passing request returns the 503 network
    # error quickly instead of hanging on real GitHub/mirror I/O.
    def _boom(*a, **k):
        raise requests.exceptions.ConnectionError('blocked in test')
    monkeypatch.setattr(settings.requests, 'get', _boom)


def test_update_blocked_on_apt(api, seed, monkeypatch):
    admin = _admin(seed)
    monkeypatch.setattr(settings, '_detect_install_method', lambda d: 'apt')
    r = api.as_user(admin).post('/api/pegaprox/update', json={})
    assert r.status_code == 409, r.get_data(as_text=True)
    body = r.get_json()
    assert body['error'] == 'in_app_update_not_supported'
    assert body['install_method'] == 'apt'
    assert 'apt' in body['message'].lower()


def test_update_blocked_on_docker(api, seed, monkeypatch):
    admin = _admin(seed)
    monkeypatch.setattr(settings, '_detect_install_method', lambda d: 'docker')
    r = api.as_user(admin).post('/api/pegaprox/update', json={})
    assert r.status_code == 409, r.get_data(as_text=True)
    body = r.get_json()
    assert body['error'] == 'in_app_update_not_supported'
    assert body['install_method'] == 'docker'
    assert 'image' in body['message'].lower() or 'container' in body['message'].lower()


def test_update_source_passes_guard(api, seed, monkeypatch):
    # source install: guard must NOT fire; request reaches the (killed) network step -> 503.
    admin = _admin(seed)
    monkeypatch.setattr(settings, '_detect_install_method', lambda d: 'source')
    _kill_network(monkeypatch)
    r = api.as_user(admin).post('/api/pegaprox/update', json={})
    assert r.status_code == 503, r.get_data(as_text=True)


def test_update_apt_override_with_allow_managed(api, seed, monkeypatch):
    # explicit power-user override bypasses the guard even on apt -> reaches the network step.
    admin = _admin(seed)
    monkeypatch.setattr(settings, '_detect_install_method', lambda d: 'apt')
    _kill_network(monkeypatch)
    r = api.as_user(admin).post('/api/pegaprox/update', json={'allow_managed': True})
    assert r.status_code == 503, r.get_data(as_text=True)


def test_check_update_reports_install_method(api, seed, monkeypatch):
    admin = _admin(seed)
    monkeypatch.setattr(settings, '_detect_install_method', lambda d: 'apt')

    class _Resp:
        status_code = 200
        def json(self):
            return {'version': '99.0', 'build': '2099.01.01', 'release_date': '2099-01-01', 'changelog': []}
    monkeypatch.setattr(settings.requests, 'get', lambda *a, **k: _Resp())

    r = api.as_user(admin).get('/api/pegaprox/check-update')
    assert r.status_code == 200, r.get_data(as_text=True)
    body = r.get_json()
    assert body['install_method'] == 'apt'
    assert body['in_app_update_supported'] is False
    assert 'apt' in body['managed_update_hint'].lower()
