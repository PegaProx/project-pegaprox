"""Routes that scope their own output must use the token's identity, not its owner's.

require_auth stashes the RAW stored user record in g.current_user. It has no
effective_role on it, so four list routes that filter their own rows handed that record
straight to get_user_clusters — and for an admin OWNER get_user_clusters answers None,
which means "all clusters". None then makes the filter a no-op:

    _allowed = get_user_clusters(...)
    if _allowed is not None:        # <-- skipped entirely
        rows = [r for r in rows if r['cluster_id'] in _allowed]

So an admin-owned bearer token deliberately capped to viewer read every tenant's
scheduled tasks, migration history, affinity rules and alert rules. The cap was applied
at the door by require_auth and then dropped by the routes behind it.

history.py already knew the right answer: the migration route builds a proper authz
identity twelve lines further down for its per-VM filter. The cluster filter above it
used the wrong one.

These tests drive the real handlers and look at the ROWS that come back, so they measure
the disclosure itself rather than the name of whatever helper is doing the flooring.

Aikido ai_pentest 700487434. MK
"""
import contextlib

import pytest

import pegaprox.api.alerts as alertsapi
import pegaprox.api.history as historyapi
import pegaprox.utils.rbac as rbac


def _handler(mod, name):
    fn = getattr(mod, name)
    while hasattr(fn, '__wrapped__'):
        fn = fn.__wrapped__
    return fn


@contextlib.contextmanager
def _bearer(api, owner_role='admin', token_role='viewer', tenant_id='tenant_a'):
    """A token whose OWNER is `owner_role`, capped to `token_role` — and the raw
    stored record in g.current_user, exactly as require_auth leaves it."""
    from flask import request as _rq, g as _g
    with api.app.test_request_context('/', base_url='http://localhost'):
        _rq.session = {'user': 'casey', 'role': token_role, 'api_token': True}
        _g.current_user = {'username': 'casey', 'role': owner_role,
                           'enabled': True, 'tenant_id': tenant_id}
        yield


@contextlib.contextmanager
def _session_login(api, role='admin', tenant_id='tenant_a'):
    from flask import request as _rq, g as _g
    with api.app.test_request_context('/', base_url='http://localhost'):
        _rq.session = {'user': 'dana', 'role': role}
        _g.current_user = {'username': 'dana', 'role': role,
                           'enabled': True, 'tenant_id': tenant_id}
        yield


@pytest.fixture(autouse=True)
def estate(api, monkeypatch):
    """tenant_a holds cluster_a; tenant_b holds cluster_b. One row in each."""
    monkeypatch.setattr(rbac, 'get_custom_roles', lambda: {'global': {}, 'tenants': {}})
    monkeypatch.setattr(rbac, 'tenants_db', {
        rbac.DEFAULT_TENANT_ID: {'id': rbac.DEFAULT_TENANT_ID, 'clusters': []},
        'tenant_a': {'id': 'tenant_a', 'clusters': ['cluster_a']},
        'tenant_b': {'id': 'tenant_b', 'clusters': ['cluster_b']},
    }, raising=False)
    monkeypatch.setattr(historyapi, 'load_scheduled_tasks', lambda: {'tasks': [
        {'id': 'a1', 'cluster_id': 'cluster_a', 'name': 'ours'},
        {'id': 'b1', 'cluster_id': 'cluster_b', 'name': 'theirs'},
    ]})
    monkeypatch.setattr(alertsapi, 'load_alerts_config', lambda: {'alerts': [
        {'id': 'a1', 'cluster_id': 'cluster_a', 'name': 'ours'},
        {'id': 'b1', 'cluster_id': 'cluster_b', 'name': 'theirs'},
    ]})


def _names(payload, key):
    return sorted(r['name'] for r in payload.get(key, []))


# --- scheduled tasks -------------------------------------------------------------

def test_a_capped_token_sees_only_its_own_tenants_scheduled_tasks(api):
    with _bearer(api):
        body = _handler(historyapi, 'get_scheduled_tasks')().get_json()
    assert _names(body, 'tasks') == ['ours'], _names(body, 'tasks')


def test_the_owners_own_login_still_sees_every_scheduled_task(api):
    """The counterweight — an actual admin is not being confined by this."""
    with _session_login(api):
        body = _handler(historyapi, 'get_scheduled_tasks')().get_json()
    assert _names(body, 'tasks') == ['ours', 'theirs']


# --- alert rules -----------------------------------------------------------------

def test_a_capped_token_sees_only_its_own_tenants_alert_rules(api):
    with _bearer(api):
        body = _handler(alertsapi, 'get_alerts')().get_json()
    assert _names(body, 'alerts') == ['ours'], _names(body, 'alerts')


def test_the_owners_own_login_still_sees_every_alert_rule(api):
    with _session_login(api):
        body = _handler(alertsapi, 'get_alerts')().get_json()
    assert _names(body, 'alerts') == ['ours', 'theirs']


# --- an admin-scoped token is still an admin token --------------------------------

def test_an_admin_owned_admin_token_is_not_confined(api):
    with _bearer(api, token_role='admin'):
        body = _handler(historyapi, 'get_scheduled_tasks')().get_json()
    assert _names(body, 'tasks') == ['ours', 'theirs']


# --- and the shape stays fixed ----------------------------------------------------

@pytest.mark.parametrize('module', ['history', 'alerts'])
def test_no_self_filtering_route_scopes_from_the_raw_record(module):
    """A fifth one added later should show up here rather than in a pentest."""
    import io
    src = io.open(f'pegaprox/api/{module}.py', encoding='utf-8').read()
    assert "get_user_clusters(getattr(_g, 'current_user'" not in src, \
        f'{module}.py scopes a list from the raw stored record again'
