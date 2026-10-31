"""A provider-specific group claim must drive roles and stored memberships together."""
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from pegaprox.utils import oidc
from tests.conftest import _seed_user
from tests.test_oidc_fallback_name_1141 import (  # noqa: F401 - loopback signing fixtures
    SUB, _id_token, idp, signer,
)


@pytest.fixture(autouse=True)
def isolated_callback_rate_limit(monkeypatch):
    import pegaprox.api.auth as auth
    monkeypatch.setattr(auth, 'login_attempts_by_ip', {})


@pytest.fixture
def admin(api, db):
    return api.as_user(_seed_user(db, 'root', role='admin'))


def _config(**overrides):
    return dict({'provider': 'okta', 'groups_claim': 'groups_proxmox',
                 'default_role': 'viewer', 'admin_group_id': 'admins',
                 'user_group_id': 'operators', 'group_mappings': []}, **overrides)


def test_custom_claim_drives_roles_and_directory_memberships():
    mapping = oidc.oidc_map_groups_to_role(
        _config(), [], oidc._VerifiedClaims({'groups': ['admins'], 'groups_proxmox': ['operators']}))
    assert mapping['role'] == 'user'
    assert mapping['groups'] == ['operators']
    assert mapping['_authoritative'] is True


def test_default_claim_keeps_existing_behavior():
    config = _config()
    config.pop('groups_claim')
    mapping = oidc.oidc_map_groups_to_role(config, [], oidc._VerifiedClaims({'groups': ['admins']}))
    assert mapping['role'] == 'admin'
    assert mapping['groups'] == ['admins']
    assert mapping['_authoritative'] is True


NON_ARRAY_GROUPS = [None, True, False, 17, 17.5, '', 'a', 'admins', {}, {'a': True}]
MALFORMED_GROUP_ARRAYS = [
    [None], [True], [False], [17.5], [''], ['   '], [{}],
    [{'name': 'operators'}], [{'id': 'admins'}], [['admins']],
    ['admins', {}], ['operators', False],
]


@pytest.mark.parametrize('claim_name', ['groups', 'groups_proxmox'])
@pytest.mark.parametrize('value', NON_ARRAY_GROUPS)
def test_non_array_claim_is_incomplete_and_cannot_grant(claim_name, value):
    config = _config(groups_claim=claim_name, admin_group_id='a')
    if claim_name == 'groups':
        config.pop('groups_claim')  # exercise the legacy default too
    mapping = oidc.oidc_map_groups_to_role(config, [], oidc._VerifiedClaims({claim_name: value}))
    assert mapping['_authoritative'] is False
    assert mapping['role'] == 'viewer'
    assert mapping['groups'] == []


@pytest.mark.parametrize('value', NON_ARRAY_GROUPS)
def test_non_array_token_claim_does_not_change_complete_graph_groups(value):
    mapping = oidc.oidc_map_groups_to_role(
        _config(provider='entra'), [{'id': 'admins', 'name': 'Administrators'}],
        oidc._VerifiedClaims({'groups_proxmox': value}), groups_complete=True)
    assert mapping['_authoritative'] is True
    assert mapping['role'] == 'admin'
    assert mapping['groups'] == ['admins']


@pytest.mark.parametrize('name', ['Groups_Proxmox', 'https://example.org/claims/groups', 'realm.groups'])
def test_claim_names_are_literal_and_case_sensitive(name):
    mapping = oidc.oidc_map_groups_to_role(
        _config(groups_claim=name), [], oidc._VerifiedClaims({name: ['operators'], 'groups_proxmox': ['admins']}))
    assert mapping['role'] == 'user'
    assert mapping['groups'] == ['operators']


@pytest.mark.parametrize('claims,authoritative', [
    ({'groups_proxmox': []}, True),
    ({'groups': ['admins']}, False),
    ({'Groups_Proxmox': ['admins']}, False),
    ({'groups_proxmox': [], '_claim_names': {'groups_proxmox': 'src1'}}, False),
    ({'groups_proxmox': [], '_claim_names': {'groups': 'src1'}}, True),
])
def test_selected_claim_controls_completeness(claims, authoritative):
    mapping = oidc.oidc_map_groups_to_role(_config(), [], oidc._VerifiedClaims(claims), groups_complete=False)
    assert mapping['_authoritative'] is authoritative
    assert mapping['role'] == 'viewer'
    assert mapping['groups'] == []


def test_complete_graph_groups_are_unchanged():
    mapping = oidc.oidc_map_groups_to_role(
        _config(provider='entra'), [{'id': 'admins', 'name': 'Administrators'}],
        oidc._VerifiedClaims({'groups': ['ignored']}), groups_complete=True)
    assert mapping['_authoritative'] is True
    assert mapping['role'] == 'admin'
    assert mapping['groups'] == ['admins']


def test_complete_graph_fetch_wins_over_token_overage():
    mapping = oidc.oidc_map_groups_to_role(
        _config(provider='entra'), [{'id': 'admins', 'name': 'Administrators'}],
        oidc._VerifiedClaims({'groups_proxmox': [], '_claim_names': {'groups_proxmox': 'src1'}}),
        groups_complete=True)
    assert mapping['_authoritative'] is True
    assert mapping['role'] == 'admin'


@pytest.mark.parametrize('value,expected', [
    ('groups_proxmox', 'groups_proxmox'), (' Groups_Proxmox ', 'Groups_Proxmox'),
    ('https://example.org/groups', 'https://example.org/groups'),
    ('', 'groups'), ('   ', 'groups'), (None, 'groups'),
])
def test_setting_round_trip(admin, value, expected):
    response = admin.post('/api/settings/server', json={'oidc_groups_claim': value})
    assert response.status_code == 200, response.get_data(as_text=True)
    assert admin.get('/api/settings/server').get_json()['oidc_groups_claim'] == expected
    assert oidc.get_oidc_settings()['groups_claim'] == expected


@pytest.mark.parametrize('value', [True, 123, [], {}, 'g' * 257, 'groups\n', 'groups\x00', '\tgroups'])
def test_invalid_claim_rejects_the_whole_save(admin, value):
    assert admin.post('/api/settings/server', json={'oidc_groups_claim': 'groups_proxmox'}).status_code == 200
    response = admin.post('/api/settings/server', json={
        'oidc_groups_claim': value, 'oidc_enabled': True})
    assert response.status_code == 400
    assert 'oidc_groups_claim' in response.get_json()['error']
    settings = admin.get('/api/settings/server').get_json()
    assert settings['oidc_groups_claim'] == 'groups_proxmox'
    assert settings['oidc_enabled'] is False


def test_non_admin_cannot_change_the_claim(api, db):
    viewer = api.as_user(_seed_user(db, 'read-only', role='viewer'))
    assert viewer.post('/api/settings/server', json={'oidc_groups_claim': 'groups_proxmox'}).status_code == 403


def test_default_and_audit(admin, db):
    assert admin.get('/api/settings/server').get_json()['oidc_groups_claim'] == 'groups'
    assert oidc.get_oidc_settings()['groups_claim'] == 'groups'
    assert admin.post('/api/settings/server', json={'oidc_groups_claim': 'groups_proxmox'}).status_code == 200
    details = [row[0] for row in db.conn.execute(
        "SELECT details FROM audit_log WHERE action = 'settings.oidc'")]
    assert any('groups_claim=groups->groups_proxmox' in detail for detail in details)


def test_invalid_stored_claim_uses_the_default(db, monkeypatch):
    import pegaprox.api.helpers as helpers
    monkeypatch.setattr(helpers, 'load_server_settings', lambda: {'oidc_groups_claim': ['invalid']})
    assert oidc.get_oidc_settings()['groups_claim'] == 'groups'


def _okta_sign_in(api, monkeypatch, token, **overrides):
    import pegaprox.api.auth as auth
    config = _config(enabled=True, auto_create_users=True, client_id='pegaprox',
                     redirect_uri='https://pegaprox.example/oidc/callback', **overrides)
    monkeypatch.setattr(auth, 'get_oidc_settings', lambda: config)
    monkeypatch.setattr(auth, 'oidc_exchange_code', lambda *a, **kw: {
        'access_token': 'access-token', 'id_token': token})
    monkeypatch.setattr(auth, 'oidc_get_user_info', lambda *a, **kw: {
        'sub': SUB, 'preferred_username': 'wanda@corp.example'})
    # Keep the real generic-provider group fetch: it returns ([], False).
    browser = api.app.test_client()
    browser.set_cookie('oidc_state', 'the-state:the-nonce:the-verifier', domain='localhost')
    response = browser.post('/api/auth/oidc/callback', json={'code': 'c', 'state': 'the-state'},
                            headers={'X-Requested-With': 'XMLHttpRequest', 'Origin': 'http://localhost'},
                            base_url='http://localhost')
    assert response.status_code == 200, response.get_data(as_text=True)
    return response.get_json()['user']


def test_signed_custom_claim_provisions_the_correct_role_and_groups(api, db, idp, signer, monkeypatch):
    token = _id_token(signer, groups=['admins'], groups_proxmox=['operators'])
    username = _okta_sign_in(api, monkeypatch, token)
    assert db.get_user(username)['role'] == 'user'
    assert db.get_user_directory_groups(username) == ['operators']


@pytest.mark.parametrize('claims,role,groups', [
    ({'groups_proxmox': []}, 'viewer', []),
    ({'groups': ['admins']}, 'user', ['operators']),
    ({'groups_proxmox': [], '_claim_names': {'groups_proxmox': 'src1'}}, 'user', ['operators']),
])
def test_custom_claim_removal_obeys_completeness_on_relogin(api, db, idp, signer, monkeypatch,
                                                           claims, role, groups):
    username = _okta_sign_in(api, monkeypatch, _id_token(signer, groups_proxmox=['operators']))
    assert db.get_user(username)['role'] == 'user'
    assert _okta_sign_in(api, monkeypatch, _id_token(signer, **claims)) == username
    assert db.get_user(username)['role'] == role
    assert db.get_user_directory_groups(username) == groups


@pytest.mark.parametrize('value', NON_ARRAY_GROUPS + MALFORMED_GROUP_ARRAYS + [[]])
def test_relogin_with_malformed_claim_preserves_access_but_empty_array_revokes(
        api, db, idp, signer, monkeypatch, value):
    username = _okta_sign_in(api, monkeypatch, _id_token(signer, groups_proxmox=['operators']))
    held = db.get_user(username)
    held.update(permissions=['vm.delete'], groups=['operators'],
                tenant_permissions={'default': {'role': 'viewer', 'extra': ['vm.view']}})
    db.save_user(username, held)

    assert _okta_sign_in(api, monkeypatch, _id_token(signer, groups_proxmox=value)) == username
    user = db.get_user(username)
    if value == []:
        assert user['role'] == 'viewer'
        assert user['permissions'] == []
        assert user['tenant_permissions'] == {}
        assert db.get_user_directory_groups(username) == []
    else:
        assert user['role'] == 'user'
        assert user['permissions'] == ['vm.delete']
        assert user['tenant_permissions'] == held['tenant_permissions']
        assert db.get_user_directory_groups(username) == ['operators']


@pytest.mark.parametrize('claim_name', ['groups', 'groups_proxmox'])
@pytest.mark.parametrize('value', MALFORMED_GROUP_ARRAYS)
def test_malformed_array_cannot_grant_or_revoke(claim_name, value):
    mapping = oidc.oidc_map_groups_to_role(
        _config(groups_claim=claim_name), [],
        oidc._VerifiedClaims({claim_name: value}))
    assert mapping['_authoritative'] is False
    assert mapping['role'] == 'viewer'
    assert mapping['groups'] == []


@pytest.mark.parametrize('claim_name', ['groups', 'groups_proxmox'])
@pytest.mark.parametrize('value', [[], ['admins']])
def test_unverified_token_cannot_grant_or_revoke(claim_name, value):
    mapping = oidc.oidc_map_groups_to_role(
        _config(groups_claim=claim_name), [],
        {claim_name: value, 'verified': True})
    assert mapping['_authoritative'] is False
    assert mapping['role'] == 'viewer'
    assert mapping['groups'] == []


@pytest.mark.parametrize('complete', [False, True])
@pytest.mark.parametrize('claims', [
    {'groups_proxmox': ['admins'], 'verified': True},
    oidc._VerifiedClaims({'groups_proxmox': ['admins', {}]}),
])
def test_unusable_token_preserves_graph_mapping(claims, complete):
    mapping = oidc.oidc_map_groups_to_role(
        _config(provider='entra'), [{'id': 'operators', 'name': 'Operators'}],
        claims, groups_complete=complete)
    assert mapping['_authoritative'] is complete
    assert mapping['role'] == 'user'
    assert mapping['groups'] == ['operators']


@pytest.mark.parametrize('claim_name', ['groups', 'groups_proxmox'])
@pytest.mark.parametrize('identifier', ['  Operators  ', 42, 0])
def test_valid_group_identifiers_drive_roles_and_memberships_together(claim_name, identifier):
    expected = str(identifier).strip()
    mapping = oidc.oidc_map_groups_to_role(
        _config(groups_claim=claim_name, user_group_id=expected), [],
        oidc._VerifiedClaims({claim_name: [identifier, expected.upper()]}))
    assert mapping['_authoritative'] is True
    assert mapping['role'] == 'user'
    assert mapping['groups'] == [expected]


@pytest.mark.parametrize('claim_name', ['groups', 'groups_proxmox'])
@pytest.mark.parametrize('value', [[], ['admins']])
@pytest.mark.parametrize('failure', ['signature', 'jwks', 'skip'])
def test_unverified_token_relogin_preserves_existing_access(
        api, db, idp, signer, monkeypatch, caplog, claim_name, value, failure):
    config = {'groups_claim': claim_name}
    username = _okta_sign_in(
        api, monkeypatch, _id_token(signer, **{claim_name: ['operators']}), **config)
    held = db.get_user(username)
    held.update(permissions=['vm.delete'], groups=['operators'],
                tenant_permissions={'default': {'role': 'viewer', 'extra': ['vm.view']}})
    db.save_user(username, held)

    key = signer
    if failure == 'signature':
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    elif failure == 'jwks':
        def unavailable(environ, start_response):
            start_response('503 Service Unavailable', [('Content-Length', '0')])
            return [b'']
        monkeypatch.setattr(idp.server, 'application', unavailable)
        monkeypatch.setattr(oidc, '_jwks_clients', {})
    else:
        config['oidc_skip_jwt_verification'] = True
    caplog.clear()

    assert _okta_sign_in(
        api, monkeypatch, _id_token(key, **{claim_name: value}), **config) == username
    if failure == 'skip':
        assert 'JWT signature verification DISABLED' in caplog.text
    else:
        assert 'falling back to unverified decode' in caplog.text
    user = db.get_user(username)
    assert user['role'] == 'user'
    assert user['permissions'] == ['vm.delete']
    assert user['tenant_permissions'] == held['tenant_permissions']
    assert db.get_user_directory_groups(username) == ['operators']
