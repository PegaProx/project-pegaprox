"""Cluster-group routes must authorize the API token, not the account that minted it.

Ten handlers in groups.py resolved the caller with load_users()[name] - the STORED
account. An API token presents its owner's username, so a token deliberately capped at
viewer or user read back as its administrator owner: _user_tenant() saw role='admin',
returned None ("unscoped"), and every tenant gate in the file was skipped for exactly the
identity that is meant to be the most confined one. Three routes here (collapse, status,
lb-history) had already been moved to build_authz_user one at a time; this is the rest,
plus the shared helper they all go through.

What a capped token could actually do before this: list every tenant's groups, edit and
delete any of them including the global ones, and trigger cross-cluster balancing on a
global group. The two cluster-facing routes (rename, re-group) turned out to be covered
already - require_unconfined() sits in front of both and has resolved the token identity
since it was written - so their tests here are guards, not proofs. They are worth keeping:
those two are the ones that escalate, because a group grants tenant membership over the
clusters in it.

Aikido ai_pentest 700488845. MK
"""
import contextlib

import pytest

import pegaprox.api.groups as groups
from tests.conftest import make_fake_manager


@contextlib.contextmanager
def _as(api, session, body=None):
    from flask import request as _rq
    with api.app.test_request_context('/', base_url='http://localhost',
                                      json=body if body is not None else {}):
        _rq.session = session
        yield


def _token(username, role='user'):
    """The session an API token produces: owner's name, the token's capped role."""
    return {'user': username, 'role': role, 'api_token': True}


def _login(username, role='admin'):
    """The session a normal interactive login produces."""
    return {'user': username, 'role': role}


def _handler(name):
    """The route body without @require_auth - these tests are about what the handler
    decides once the caller is past the door, and the door is not what changed."""
    fn = getattr(groups, name)
    while hasattr(fn, '__wrapped__'):
        fn = fn.__wrapped__
    return fn


@pytest.fixture
def estate(api, seed):
    """An administrator who lives in tenant_a, and a group belonging to tenant_b."""
    seed.tenant('tenant_a', clusters=['cluster_1'])
    seed.tenant('tenant_b', clusters=['cluster_2'])
    seed.user('taylor', role='admin', tenant_id='tenant_a')
    api.set_manager('cluster_1', make_fake_manager('cluster_1'))
    api.set_manager('cluster_2', make_fake_manager('cluster_2'))

    db = seed.db
    for cid in ('cluster_1', 'cluster_2'):
        db.execute('''INSERT INTO clusters (id, name, host, user, pass_encrypted)
                      VALUES (?, ?, '10.0.0.1', 'root@pam', 'x')''', (cid, cid))
    for gid, name, tid in (('g_a', 'Tenant A', 'tenant_a'),
                           ('g_b', 'Tenant B', 'tenant_b'),
                           ('g_glob', 'Global', None)):
        db.execute('''INSERT INTO cluster_groups (id, name, description, color, tenant_id,
                      sort_order, created_at, updated_at)
                      VALUES (?, ?, '', '#fff', ?, 0, '2026-01-01', '2026-01-01')''',
                   (gid, name, tid))
    db.execute("UPDATE clusters SET group_id = 'g_b' WHERE id = 'cluster_2'")
    return db


# --- the shared helper ----------------------------------------------------------

def test_the_scoping_helper_reads_the_effective_role(api, estate):
    """Everything in this file hangs off _user_tenant."""
    with _as(api, _token('taylor')):
        assert groups._user_tenant(groups._authz_caller()) == 'tenant_a'


def test_an_interactive_admin_login_is_still_unscoped(api, estate):
    with _as(api, _login('taylor')):
        assert groups._user_tenant(groups._authz_caller()) is None


# --- reads ----------------------------------------------------------------------

def test_a_capped_token_does_not_list_another_tenants_groups(api, estate):
    with _as(api, _token('taylor')):
        body = _handler('get_cluster_groups')().get_json()

    names = sorted(g['name'] for g in body)
    assert 'Tenant B' not in names, names
    assert 'Tenant A' in names


def test_the_owners_own_login_still_lists_everything(api, estate):
    with _as(api, _login('taylor')):
        body = _handler('get_cluster_groups')().get_json()

    assert sorted(g['name'] for g in body) == ['Global', 'Tenant A', 'Tenant B']


# --- writes ---------------------------------------------------------------------

def test_a_capped_token_cannot_edit_another_tenants_group(api, estate):
    with _as(api, _token('taylor'), body={'name': 'stolen'}):
        resp = _handler('update_cluster_group')('g_b')

    # denial is now reported as 404, same as a group that is not there;
    # what matters is that the call did not go through
    assert resp[1] == 404


def test_a_capped_token_cannot_delete_a_global_group(api, estate):
    with _as(api, _token('taylor')):
        resp = _handler('delete_cluster_group')('g_glob')

    # 404 rather than 403 since the group routes stopped confirming existence; the
    # property is that the group is still there afterwards
    assert resp[1] == 404
    assert estate.query_one("SELECT id FROM cluster_groups WHERE id = 'g_glob'"), \
        'the group was deleted anyway'


def test_a_capped_token_cannot_regroup_a_cluster_it_does_not_own(api, estate):
    """Already held by require_unconfined - kept because this is the route that would
    escalate if the front gate ever moved."""
    with _as(api, _token('taylor'), body={'group_id': 'g_a'}):
        resp = _handler('assign_cluster_to_group')('cluster_2')

    assert resp[1] == 403
    row = estate.query_one("SELECT group_id FROM clusters WHERE id = 'cluster_2'")
    assert row['group_id'] == 'g_b', 'the cluster was moved anyway'


def test_a_capped_token_cannot_rename_a_cluster_it_does_not_own(api, estate):
    with _as(api, _token('taylor'), body={'display_name': 'mine now'}):
        resp = _handler('rename_cluster')('cluster_2')

    assert resp[1] == 403


def test_a_capped_token_cannot_trigger_balancing_on_a_global_group(api, estate):
    """This spawns real cross-cluster VM migrations."""
    with _as(api, _token('taylor')):
        resp = _handler('trigger_xclb_balance_now')('g_glob')

    # denial is now reported as 404, same as a group that is not there;
    # what matters is that the call did not go through
    assert resp[1] == 404


def test_the_owner_can_still_do_all_of_it_from_their_own_session(api, estate):
    """The counterweight: none of this may lock the actual administrator out."""
    with _as(api, _login('taylor'), body={'display_name': 'renamed by the owner'}):
        assert _handler('rename_cluster')('cluster_2').get_json()['success'] is True
