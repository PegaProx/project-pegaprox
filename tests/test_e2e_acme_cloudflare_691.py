# E2E-through-app for #691 (Cloudflare DNS-01). The PR's own suite mocks _cloudflare_update; these
# drive the *full app path*: the real /api/settings/server endpoint must store the token ENCRYPTED,
# mask it on read, decrypt it only when the ACME flow builds its provider config, resist a
# masked-value re-save clobbering it, and the decrypted token must actually reach the Cloudflare API.

import pegaprox.core.acme as acme
from pegaprox.api.helpers import load_server_settings, acme_dns_config_from_settings

SETTINGS = '/api/settings/server'
SECRET = 'cf-tok-abc123-SECRET'


def test_e2e_cloudflare_token_encrypts_masks_and_decrypts_for_the_provider(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')

    r = api.as_user(admin).post(SETTINGS, json={
        'acme_dns_provider': 'cloudflare',
        'acme_dns_cloudflare_token': SECRET,
        'acme_dns_cloudflare_zone': 'example.com',
    })
    assert r.status_code == 200, r.get_data(as_text=True)

    with api.app.app_context():
        raw = load_server_settings()
        assert raw.get('acme_dns_provider') == 'cloudflare'
        stored = raw.get('acme_dns_cloudflare_token')
        assert stored and stored != SECRET          # stored ENCRYPTED, not plaintext
        cfg = acme_dns_config_from_settings(raw)
        assert cfg['token'] == SECRET               # decrypted only when the ACME flow needs it
        assert cfg['cloudflare_zone'] == 'example.com'

    got = api.as_user(admin).get(SETTINGS).get_json()
    assert got.get('acme_dns_cloudflare_token') == '********'   # masked on read

    # a re-save carrying the masked sentinel must NOT clobber the stored token
    r2 = api.as_user(admin).post(SETTINGS, json={
        'acme_dns_provider': 'cloudflare', 'acme_dns_cloudflare_token': '********'})
    assert r2.status_code == 200, r2.get_data(as_text=True)
    with api.app.app_context():
        assert acme_dns_config_from_settings(load_server_settings())['token'] == SECRET


def test_e2e_decrypted_token_reaches_the_cloudflare_api(api, seed, monkeypatch):
    admin = seed.user('root', role='admin', tenant_id='default')
    api.as_user(admin).post(SETTINGS, json={
        'acme_dns_provider': 'cloudflare',
        'acme_dns_cloudflare_token': SECRET,
        'acme_dns_cloudflare_zone_id': 'zone123',   # override → no /zones lookup needed
    })

    calls = []
    def _fake_cf_api(token, method, path, params=None, json_body=None):
        calls.append((token, method, path))
        return {'success': True, 'result': ({'id': 'rec1'} if method == 'POST' else None)}
    monkeypatch.setattr(acme, '_cloudflare_api', _fake_cf_api)

    with api.app.app_context():
        cfg = acme_dns_config_from_settings(load_server_settings())
        assert acme._cloudflare_update(cfg, '_acme-challenge.example.com', 'txtval', action='present')['success']
        assert acme._cloudflare_update(cfg, '_acme-challenge.example.com', 'txtval', action='delete')['success']

    assert calls and all(tok == SECRET for tok, _, _ in calls)   # decrypted real token reached CF
    methods = [m for _, m, _ in calls]
    assert 'POST' in methods and 'DELETE' in methods              # record created then cleaned up
