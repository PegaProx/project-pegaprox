"""A console reached through a ws token is judged by the API token that minted it.

POST /api/ws/token takes an API token like any other route and stores only the token's
declared role. The consumers never knew a token stood behind it: the VNC routes read the
owner's stored record, so a token bound to a custom role without vm.console opened the
console of every guest as its admin owner, and the node shell check of the console
server floored a builtin role but kept the owner's extra grants, and left a custom-role
token with nothing but its role after its owner was demoted. (#1014) MK
"""
import json

import pytest

import pegaprox.utils.rbac as rbac
from pegaprox.utils.auth import create_api_token

CLUSTER = 'c1'
VNC = f'/api/clusters/{CLUSTER}/vms/pve1/qemu/100/vncwebsocket'


def _role(db, name, perms, tenant=''):
    db.conn.execute("INSERT OR REPLACE INTO custom_roles "
                    "(name, permissions, description, tenant_id, created_at) VALUES (?,?,?,?,?)",
                    (name, json.dumps(perms), name, tenant, '2026-01-01'))
    db.conn.commit()
    rbac.invalidate_roles_cache()


def _ws_token_from(api, api_token):
    r = api.anon().post('/api/ws/token', headers={'Authorization': f'Bearer {api_token}'})
    assert r.status_code == 200, r.data
    return r.get_json()['token']


def _ws_token_by_api_token(api, owner, role=None):
    tok = create_api_token(owner, 'ci', role=role)
    assert tok.get('token'), tok
    return _ws_token_from(api, tok['token'])


def _ws_token_by_session(api, user):
    r = api.as_user(user).post('/api/ws/token')
    assert r.status_code == 200, r.data
    return r.get_json()['token']


def _node_shell(api, wst):
    return api.anon().get(f'/api/ws/token/validate?token={wst}&cluster_id={CLUSTER}'
                          f'&node=pve1&shell=node')


# --- the bypass --------------------------------------------------------------------------

def test_a_scrape_only_token_opens_no_console_as_its_admin_owner(api, seed, db):
    """The #818 setup: a token bound to a role holding nothing but metrics.view."""
    _role(db, 'scrape', ['metrics.view'])
    seed.user('root', role='admin')
    wst = _ws_token_by_api_token(api, 'root', role='scrape')

    r = api.anon().get(f'{VNC}?token={wst}')

    assert r.status_code == 403, f'a metrics-only token reached a guest console ({r.status_code})'


def test_a_viewer_token_gets_no_node_shell_from_its_owners_extra_grant(api, seed):
    """node.shell as an extra grant on the account: the route gate refuses the viewer
    token, and the console server had to refuse it as well."""
    seed.user('ops', role='user', permissions=['node.shell'])
    tok = create_api_token('ops', 'ci', role='viewer')
    gate = api.anon().post(f'/api/clusters/{CLUSTER}/nodes/pve1/shell',
                           headers={'Authorization': f"Bearer {tok['token']}"})
    assert gate.status_code == 403, 'the route gate let the token through, this proves nothing'
    wst = _ws_token_by_api_token(api, 'ops', role='viewer')

    r = _node_shell(api, wst)

    assert r.status_code == 403, 'a viewer token opened a root shell on a node'


def test_a_custom_role_token_loses_the_node_shell_with_its_owner(api, seed, db):
    _role(db, 'shell_ops', ['node.view', 'node.shell'])
    seed.user('ops', role='shell_ops')
    tok = create_api_token('ops', 'ci')
    assert tok.get('role') == 'shell_ops', tok
    assert _node_shell(api, _ws_token_from(api, tok['token'])).status_code == 200, \
        'the token never had the shell, this proves nothing'

    rec = db.get_user('ops')
    rec['role'] = 'viewer'
    db.save_user('ops', rec)

    assert _node_shell(api, _ws_token_from(api, tok['token'])).status_code == 403, \
        'the token kept the shell its demoted owner lost'


def test_an_account_that_cannot_be_read_opens_no_console(api, seed, monkeypatch):
    """load_users() answers {} when the store cannot be read. The console then judged a
    bare {'username': ...}: no tenant, so the default one, whose empty cluster list means
    every cluster, and the viewer defaults, which hold vm.console."""
    seed.tenant('acme', clusters=['elsewhere'])
    ops = seed.user('ops', role='user', tenant_id='acme')
    wst = _ws_token_by_session(api, ops)
    assert api.anon().get(f'{VNC}?token={_ws_token_by_session(api, ops)}').status_code == 403, \
        'the account reaches this cluster anyway, this proves nothing'

    import pegaprox.api.vms as vms
    monkeypatch.setattr(vms, 'load_users', lambda *a, **k: {})

    assert api.anon().get(f'{VNC}?token={wst}').status_code == 403, \
        'an unreadable account store opened the console of a cluster outside the tenant'


# --- what keeps working ------------------------------------------------------------------

def test_an_admin_session_still_opens_the_console(api, seed):
    root = seed.user('root', role='admin')
    wst = _ws_token_by_session(api, root)

    r = api.anon().get(f'{VNC}?token={wst}')

    assert r.status_code != 403, r.data
    assert r.status_code == 426      # authorised, just not a WebSocket


def test_a_session_keeps_its_extra_grant_for_the_node_shell(api, seed):
    ops = seed.user('ops', role='user', permissions=['node.shell'])
    wst = _ws_token_by_session(api, ops)

    assert _node_shell(api, wst).status_code == 200


@pytest.mark.parametrize('token_role', ['admin', None])
def test_an_admin_token_still_opens_console_and_shell(api, seed, token_role):
    seed.user('root', role='admin')

    assert api.anon().get(f'{VNC}?token={_ws_token_by_api_token(api, "root", token_role)}'
                          ).status_code == 426
    assert _node_shell(api, _ws_token_by_api_token(api, 'root', token_role)).status_code == 200


def test_a_viewer_token_keeps_the_console_its_role_grants(api, seed):
    """vm.console is a viewer permission: the token is judged, not shut out."""
    seed.user('root', role='admin')
    wst = _ws_token_by_api_token(api, 'root', role='viewer')

    assert api.anon().get(f'{VNC}?token={wst}').status_code == 426
