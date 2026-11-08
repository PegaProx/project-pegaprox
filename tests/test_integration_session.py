# Regression: an admin password reset must kill the target user's live sessions.
#
# CodeAnt exploitation finding (incomplete session handling): update_user set a new password
# hash but never invalidated the user's existing sessions, so a stolen/old session survived the
# reset. Fixed: the password branch now calls invalidate_all_user_sessions().

AUTHED_ROUTE = '/api/clusters'   # bare @require_auth()


def test_password_change_invalidates_target_sessions(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    bob = seed.user('bob', role='user', tenant_id='default')

    bob_client = api.as_user(bob)
    assert bob_client.get(AUTHED_ROUTE).status_code != 401   # bob's session works

    # admin resets bob's password
    r = api.as_user(admin).put('/api/users/bob', json={'password': 'Str0ng-New-Pass!42'})
    assert r.status_code == 200, r.get_data(as_text=True)

    # bob's OLD session is now dead
    assert bob_client.get(AUTHED_ROUTE).status_code == 401


def test_non_password_edit_does_not_invalidate_sessions(api, seed):
    # a role/email edit must NOT log the user out (scoped to the password branch)
    admin = seed.user('root', role='admin', tenant_id='default')
    bob = seed.user('bob', role='user', tenant_id='default')

    bob_client = api.as_user(bob)
    assert bob_client.get(AUTHED_ROUTE).status_code != 401

    r = api.as_user(admin).put('/api/users/bob', json={'email': 'bob@example.com'})
    assert r.status_code == 200, r.get_data(as_text=True)

    # bob's session still works — no needless logout
    assert bob_client.get(AUTHED_ROUTE).status_code != 401
