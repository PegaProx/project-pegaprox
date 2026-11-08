"""The in-app updater belongs to accounts that see every cluster.

Checking for, installing and rolling back an update replaces and restarts the whole
installation, every tenant's included. The three routes asked for update.manage and
nothing else, and update.manage is grantable like any other permission, so a role
confined to one tenant could hold it. Same rule as the automated installations, which
are installation-wide in the same way, and the permission grid now says so next to the
checkbox.
"""
import pytest
import requests

import pegaprox.api.settings as settings
from pegaprox.models.permissions import PERMISSION_WARNINGS

ROUTES = [('get', '/api/pegaprox/check-update', None),
          ('post', '/api/pegaprox/update', {}),
          ('post', '/api/pegaprox/update/rollback', {})]


@pytest.fixture
def offline(monkeypatch):
    def _boom(*a, **k):
        raise requests.exceptions.ConnectionError('blocked in test')
    monkeypatch.setattr(settings.requests, 'get', _boom)
    # an apt install refuses the file updater right after the gate, before it touches anything
    monkeypatch.setattr(settings, '_detect_install_method', lambda d: 'apt')


def _call(client, method, path, body):
    return getattr(client, method)(path, **({'json': body} if body is not None else {}))


@pytest.mark.parametrize('method,path,body', ROUTES, ids=[r[1] for r in ROUTES])
def test_a_tenant_confined_holder_is_turned_away(api, seed, offline, method, path, body):
    seed.tenant('acme', clusters=['cluster_1'])
    u = seed.user('acme_ops', role='user', tenant_id='acme', permissions=['update.manage'])
    r = _call(api.as_user(u), method, path, body)
    assert r.status_code == 403, r.get_data(as_text=True)
    assert 'not limited to a tenant' in r.get_json()['error']


@pytest.mark.parametrize('who', ['admin', 'unconfined_operator'])
def test_who_sees_every_cluster_still_reaches_the_updater(api, seed, offline, who):
    u = (seed.user('root', role='admin') if who == 'admin'
         else seed.user('ops', role='user', permissions=['update.manage']))
    c = api.as_user(u)
    check = c.get('/api/pegaprox/check-update')
    assert check.status_code == 200 and 'current_version' in check.get_json()
    # past the gate: the apt install answers its own refusal, nothing was replaced
    upd = c.post('/api/pegaprox/update', json={})
    assert upd.status_code == 409 and upd.get_json()['error'] == 'in_app_update_not_supported'
    rb = c.post('/api/pegaprox/update/rollback', json={})
    assert rb.status_code == 200 and 'backups' in rb.get_json(), rb.get_data(as_text=True)


def test_the_permission_grid_warns_about_it(api, seed):
    assert 'Not tenant-scoped' in PERMISSION_WARNINGS['update.manage']
    rows = api.as_user(seed.user('root', role='admin')).get('/api/permissions').get_json()
    assert next(p for p in rows if p['permission'] == 'update.manage')['warning']
