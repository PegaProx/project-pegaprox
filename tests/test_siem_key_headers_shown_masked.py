"""A custom header that carries a key or a credential is masked like the token and password.

The names that count as a secret were token, password, api_key, apikey, secret and
auth, so the read of a target showed X-API-Key, DD-API-KEY, X-Insert-Key,
Ocp-Apim-Subscription-Key, Cookie, X-Honeycomb-Team, X-Pass, X-Credential and Signature
in full. A header with "key", "cookie", "pass", "credential", "signature" or "honeycomb"
in its name is masked now, an edit with the mask keeps the stored value, and the plain
settings fields of the types stay readable. MK Nov 2026
"""
import pytest

import pegaprox.api.siem as siem

HEADERS = {
    'X-API-Key': 'xk-5d20a7',
    'DD-API-KEY': 'dd-91c3e0',
    'X-Insert-Key': 'nr-4f6b18',
    'Ocp-Apim-Subscription-Key': 'az-0e7d52',
    'Cookie': 'session=ck-8a41f2',
    'X-Honeycomb-Team': 'hc-73be09',
    'X-Pass': 'xp-2c5d81',
    'X-Credential': 'xc-6f0a3e',
    'Signature': 'sg-91d7b4',
    'X-Scope-OrgID': 'tenant-a',
}


@pytest.fixture
def admin(api, db, seed):
    a = api.as_user(seed.user('root', role='admin'))
    r = a.post('/api/siem/targets', json={'name': 'loki', 'type': 'http_json',
                                          'endpoint': 'https://loki.example/loki/api/v1/push',
                                          'settings': {'headers': dict(HEADERS), 'verify_tls': True}})
    assert r.status_code == 200, r.get_data(as_text=True)
    a.tid = r.get_json()['target']['id']
    return a


def _shown(admin):
    return next(t for t in admin.get('/api/siem/targets').get_json()['targets'] if t['id'] == admin.tid)


def test_the_key_headers_are_shown_masked(admin):
    r = admin.get('/api/siem/targets')
    body = r.get_data(as_text=True)
    assert [v for k, v in HEADERS.items() if k != 'X-Scope-OrgID' and v in body] == []
    headers = _shown(admin)['settings']['headers']
    assert headers == dict({k: '********' for k in HEADERS}, **{'X-Scope-OrgID': 'tenant-a'})


def test_an_edit_with_the_masked_headers_keeps_them(admin):
    t = _shown(admin)
    r = admin.put(f'/api/siem/targets/{admin.tid}', json={'name': 'loki prod', 'settings': t['settings']})
    assert r.status_code == 200, r.get_data(as_text=True)
    stored = next(x for x in siem._list_enabled() if x['id'] == admin.tid)
    assert stored['settings']['headers'] == HEADERS


def test_a_new_endpoint_asks_for_the_key_again(admin):
    r = admin.put(f'/api/siem/targets/{admin.tid}', json={
        'endpoint': 'https://loki.elsewhere.example/loki/api/v1/push', 'settings': _shown(admin)['settings']})
    assert r.status_code == 400 and r.get_json()['code'] == 'CREDENTIAL_REQUIRED', r.get_data(as_text=True)


@pytest.mark.parametrize('field', ['facility', 'host_override', 'label_field', 'sourcetype', 'index',
                                   'username', 'verify_tls', 'headers', 'format'])
def test_the_plain_settings_fields_stay_readable(field):
    assert not siem._is_secret(field)


def test_no_settings_field_the_types_offer_is_masked_beside_token_and_password(admin):
    # the editor builds its inputs from these
    offered = {f for t in admin.get('/api/siem/types').get_json()['types'] for f in t['settings_fields']}
    assert {f for f in offered if siem._is_secret(f)} == {'token', 'password'}
