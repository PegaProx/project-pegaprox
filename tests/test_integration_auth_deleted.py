# Regression: off-boarding must actually revoke access.
#
# CodeAnt exploitation finding (2026-07-13): require_auth did `get_user() or {}`, so a DELETED
# user resolved to {} -> {}.get('enabled', True)==True passed the disabled-check and the role
# fell back to the stale session role. A deleted user (or their pgx_ token) kept access until
# the session expired. Fixed: require_auth fails CLOSED when the record is gone (ACCOUNT_DELETED),
# and delete_user now invalidates the live sessions + revokes API tokens. These drive it E2E.

AUTHED_ROUTE = '/api/clusters'   # bare @require_auth() — any live user gets non-401


def test_deleted_user_live_session_is_rejected(api, seed):
    bob = seed.user('bob', role='user', tenant_id='default')
    c = api.as_user(bob)

    # sanity: the session works while the account exists
    assert c.get(AUTHED_ROUTE).status_code != 401

    # admin deletes the account (out from under bob's still-valid session)
    seed.db.delete_user('bob')

    # the SAME session must now be rejected — fail-closed on the missing record
    r = c.get(AUTHED_ROUTE)
    assert r.status_code == 401, r.get_data(as_text=True)
    assert (r.get_json() or {}).get('code') == 'ACCOUNT_DELETED'


def test_disabled_user_session_is_rejected(api, seed):
    # (pins the pre-existing disabled-check next to the new deleted-check)
    bob = seed.user('bob', role='user', tenant_id='default', enabled=False)
    r = api.as_user(bob).get(AUTHED_ROUTE)
    assert r.status_code == 401
    assert (r.get_json() or {}).get('code') == 'ACCOUNT_DISABLED'


def test_live_user_is_unaffected(api, seed):
    # the fail-closed change must NOT break a normal, present user
    alice = seed.user('alice', role='admin', tenant_id='default')
    r = api.as_user(alice).get(AUTHED_ROUTE)
    assert r.status_code != 401
