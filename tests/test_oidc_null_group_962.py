# #962 - an Entra sign-in whose group list holds an entry with "displayName": null.
#
# oidc_get_user_groups_ex builds {'id': ..., 'name': member.get('displayName', '')}, and Graph
# sends the key with a null value for some groups, so 'name' arrives as None. The mapping
# lowercased it and the whole callback answered 500; the browser bounced back to the login
# page and the user never got in. test_oidc_group_mapping pins the function, this drives the
# real callback route so the 500 itself is covered.

import copy

OIDC_ENTRA = {
    'enabled': True, 'provider': 'entra', 'client_id': 'pegaprox', 'auto_create_users': True,
    'redirect_uri': 'https://pegaprox.example/oidc/callback', 'default_role': 'viewer',
    'admin_group_id': 'a1111111-1111-1111-1111-111111111111', 'user_group_id': '',
    'viewer_group_id': '', 'group_mappings': [],
}


def _sign_in(api, monkeypatch, groups):
    import pegaprox.api.auth as auth_api
    monkeypatch.setattr(auth_api, 'get_oidc_settings', lambda: copy.deepcopy(OIDC_ENTRA))
    monkeypatch.setattr(auth_api, 'oidc_exchange_code',
                        lambda cfg, code, code_verifier=None: {'access_token': code, 'id_token': code})
    monkeypatch.setattr(auth_api, 'oidc_decode_id_token',
                        lambda token, expected_nonce=None, config=None:
                            {'sub': 'sub-dana', 'preferred_username': 'dana'})
    monkeypatch.setattr(auth_api, 'oidc_get_user_info', lambda cfg, token: {})
    monkeypatch.setattr(auth_api, 'oidc_get_user_groups_ex', lambda cfg, token: (groups, True))
    for key in [k for k in auth_api.login_attempts_by_ip if str(k).startswith('oidc_cb_')]:
        auth_api.login_attempts_by_ip.pop(key, None)
    browser = api.app.test_client()
    browser.set_cookie('oidc_state', 'the-state:the-nonce:the-verifier', domain='localhost')
    return browser.post('/api/auth/oidc/callback', json={'code': 'dana', 'state': 'the-state'},
                        headers={'X-Requested-With': 'XMLHttpRequest', 'Origin': 'http://localhost'},
                        base_url='http://localhost')


def test_a_null_display_name_signs_in_and_the_admin_group_still_counts(api, db, monkeypatch):
    r = _sign_in(api, monkeypatch, [
        {'id': 'a1111111-1111-1111-1111-111111111111', 'name': None},
        {'id': 'b2222222-2222-2222-2222-222222222222', 'name': None},
    ])
    assert r.status_code == 200, r.data
    assert r.get_json()['role'] == 'admin'


def test_a_group_with_nothing_in_it_signs_in_as_the_default_role(api, db, monkeypatch):
    r = _sign_in(api, monkeypatch, [{'id': None, 'name': None}])
    assert r.status_code == 200, r.data
    assert r.get_json()['role'] == 'viewer'
