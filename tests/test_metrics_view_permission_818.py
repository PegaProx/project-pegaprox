"""#818 (falschgeldkind) - a granular permission for the Prometheus endpoint.

Today /api/metrics takes an admin-role API token or `metrics_public: true`, and
nothing in between, so a Prometheus job needs an admin token. The permission is
opt-in and it comes with a warning, because the endpoint is the one place in
PegaProx that is deliberately NOT tenant-scoped: it emits cluster-wide gauges for
every cluster the installation knows. That is why the admin gate was put there in
the first place (Aikido, Aug 2026), and why `metrics.view` must not be quietly
folded into the builtin viewer or user roles - it has to be granted on purpose.
"""
import pytest


# --- the permission exists and is grantable ---------------------------------

def test_the_permission_is_in_the_catalogue():
    from pegaprox.models.permissions import PERMISSIONS
    assert 'metrics.view' in PERMISSIONS


def test_it_carries_a_warning_where_it_is_granted():
    """The admin ticking this box is the person who needs to know it is not
    tenant-scoped. A description alone reads like every other one."""
    from pegaprox.models.permissions import PERMISSION_WARNINGS
    warning = PERMISSION_WARNINGS.get('metrics.view', '')
    assert warning, 'metrics.view has no warning'
    low = warning.lower()
    assert 'tenant' in low, f'the warning does not say what it crosses: {warning}'


def test_the_warning_reaches_the_permissions_api(api, seed):
    root = seed.user('root', role='admin')
    r = api.as_user(root).get('/api/permissions')
    assert r.status_code == 200
    entry = next((p for p in r.get_json() if p['permission'] == 'metrics.view'), None)
    assert entry is not None, 'metrics.view is not offered by the API'
    assert entry.get('warning'), 'the API drops the warning, so the UI cannot show it'


def test_it_is_not_quietly_added_to_the_builtin_roles():
    """Handing it to every existing viewer would turn a least-privilege feature
    into a cross-tenant data leak on upgrade."""
    from pegaprox.models.permissions import ROLE_PERMISSIONS, ROLE_USER, ROLE_VIEWER
    assert 'metrics.view' not in ROLE_PERMISSIONS[ROLE_VIEWER]
    assert 'metrics.view' not in ROLE_PERMISSIONS[ROLE_USER]


def test_admin_still_holds_it():
    from pegaprox.models.permissions import ROLE_PERMISSIONS, ROLE_ADMIN
    assert 'metrics.view' in ROLE_PERMISSIONS[ROLE_ADMIN]


# --- the gate ----------------------------------------------------------------

def _token(monkeypatch, *, user, role, enabled=True, owner_role=None, perms=None):
    """Point the exporter at a fake token + owner without touching the DB."""
    from pegaprox.api import metrics_exporter as mx
    monkeypatch.setattr(mx, 'load_server_settings', lambda: {})
    monkeypatch.setattr(mx, 'validate_api_token',
                        lambda t: {'user': user, 'role': role, 'api_token': True})

    class _DB:
        def get_user(self, u):
            return {'username': u, 'role': owner_role or role, 'enabled': enabled}
    monkeypatch.setattr(mx, 'get_db', lambda: _DB())
    monkeypatch.setattr(mx, 'build_authz_user', lambda u, s: {'username': u, 'role': s.get('role')})
    monkeypatch.setattr(mx, 'has_permission', lambda u, p: p in (perms or []))


def _call(client):
    return client.get('/api/metrics', headers={'Authorization': 'Bearer pgx_test'})


def test_a_viewer_token_with_the_permission_may_scrape(api, seed, monkeypatch):
    _token(monkeypatch, user='prom', role='viewer', owner_role='viewer', perms=['metrics.view'])
    r = _call(api.anon())
    assert r.status_code == 200, r.data[:200]


def test_a_viewer_token_without_it_still_cannot(api, seed, monkeypatch):
    """The counter-test. Without this, 'it works' would only prove the gate is gone."""
    _token(monkeypatch, user='prom', role='viewer', owner_role='viewer', perms=[])
    r = _call(api.anon())
    assert r.status_code == 401, r.data[:200]


def test_an_admin_token_is_unaffected(api, seed, monkeypatch):
    _token(monkeypatch, user='root', role='admin', owner_role='admin', perms=[])
    assert _call(api.anon()).status_code == 200


def test_a_disabled_owner_loses_the_scrape(api, seed, monkeypatch):
    """Disabling an account does not revoke its tokens - the endpoint re-checks the
    owner for exactly that reason, and the new path has to do it too."""
    _token(monkeypatch, user='prom', role='viewer', owner_role='viewer',
           enabled=False, perms=['metrics.view'])
    assert _call(api.anon()).status_code == 401


def test_the_permission_is_read_through_the_token_not_the_owner(api, seed, monkeypatch):
    """A token is capped by its own role AND by what its owner holds today.

    Checked by behaviour, not by looking for the function name in the source - the
    docstring of _auth_ok mentions build_authz_user, so a text search stays green
    even when the call is gone.

    Here the token is viewer-capped while its owner is an admin. has_permission only
    grants when it is handed the TOKEN identity; if the code looks the permission up
    on the stored account instead, it sees an admin and the scrape is allowed - which
    is precisely the escalation this guards against.
    """
    from pegaprox.api import metrics_exporter as mx
    monkeypatch.setattr(mx, 'load_server_settings', lambda: {})
    monkeypatch.setattr(mx, 'validate_api_token',
                        lambda t: {'user': 'prom', 'role': 'viewer', 'api_token': True})

    class _DB:
        def get_user(self, u):
            return {'username': u, 'role': 'admin', 'enabled': True}
    monkeypatch.setattr(mx, 'get_db', lambda: _DB())
    monkeypatch.setattr(mx, 'build_authz_user',
                        lambda u, sess: {'username': u, 'role': sess.get('role'), '_via': 'token'})
    seen = []

    def _perm(identity, perm):
        seen.append(identity)
        return identity.get('_via') == 'token'
    monkeypatch.setattr(mx, 'has_permission', _perm)

    r = _call(api.anon())
    assert seen, 'the permission was never checked'
    assert seen[0].get('_via') == 'token', \
        f"the permission was resolved on {seen[0]} instead of the token identity"
    assert r.status_code == 200

def test_a_non_admin_scrape_is_visible_in_the_log(api, seed, monkeypatch, caplog):
    """The warning is worth nothing if nobody ever sees it fire. Logged once per
    token, not per scrape - Prometheus comes back every 15 seconds."""
    import logging
    _token(monkeypatch, user='prom', role='viewer', owner_role='viewer', perms=['metrics.view'])
    from pegaprox.api import metrics_exporter as mx
    mx._metrics_perm_announced.clear()
    with caplog.at_level(logging.WARNING):
        _call(api.anon())
        first = [r for r in caplog.records if 'metrics.view' in r.getMessage()]
        _call(api.anon())
        _call(api.anon())
        again = [r for r in caplog.records if 'metrics.view' in r.getMessage()]
    assert len(first) == 1, f'expected one warning, got {len(first)}'
    assert len(again) == 1, 'the warning repeats on every scrape'


# --- the warning is actually put in front of somebody ------------------------

def test_the_grid_renders_the_warning_when_there_is_one():
    """The whole point of `mit einer Warnung`: the admin ticking the box sees it.
    A field the API sends and the UI drops would be worse than no field."""
    import os
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    body = open(os.path.join(root, 'web', 'src', 'settings_modal.js'), encoding='utf-8').read()
    grid = body[body.index('function PermissionsGrid('):]
    grid = grid[:grid.index('\n        }\n')]
    assert 'p.warning' in grid, 'the permissions grid ignores the warning'
    assert 'AlertTriangle' in grid or 'Alert' in grid, 'the warning has no visual marker'


def test_nothing_else_grows_a_warning_line():
    """`{p.warning && ...}` - guarded, so the 200-odd permissions without one are
    unchanged."""
    import os
    import re
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    body = open(os.path.join(root, 'web', 'src', 'settings_modal.js'), encoding='utf-8').read()
    assert re.search(r'\{p\.warning\s*&&', body), 'the warning line is rendered unconditionally'


def test_the_shipped_bundle_carries_it():
    import os
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    built = open(os.path.join(root, 'web', 'index.html'), encoding='utf-8').read()
    assert 'metrics.view' in built or 'p.warning' in built or 'warning' in built
