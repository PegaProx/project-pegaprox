# Cloudflare DNS-01 provider — pegaprox/core/acme.py (#687).
#
# Pure unit tests: Cloudflare HTTP is mocked, so CI never talks to
# api.cloudflare.com. The invariants here are zone walking, zone-id
# override (no Zone.Zone.Read required), TXT create/delete, and
# rejecting unsafe ids so they cannot become API path segments.

from unittest.mock import patch

from pegaprox.core import acme


class _FakeResp:
    def __init__(self, status, payload):
        self.status_code = status
        self._payload = payload

    def json(self):
        return self._payload


def _cf_ok(result, status=200):
    return _FakeResp(status, {'success': True, 'result': result})


def _cf_err(message, status=400):
    return _FakeResp(status, {'success': False, 'errors': [{'message': message}]})


# ---------------------------------------------------------------------------
# Zone candidates / TXT matching / record names
# ---------------------------------------------------------------------------

def test_dns01_record_name_strips_wildcard():
    assert acme._dns01_record_name('*.example.com') == '_acme-challenge.example.com'
    assert acme._dns01_record_name('www.example.com.') == '_acme-challenge.www.example.com'


def test_cloudflare_zone_candidates_walk_labels():
    assert acme._cloudflare_zone_candidates('_acme-challenge.www.example.com') == [
        'www.example.com',
        'example.com',
    ]


def test_cloudflare_zone_candidates_prefer_hint():
    assert acme._cloudflare_zone_candidates(
        '_acme-challenge.www.example.com', zone_hint='example.com'
    ) == ['example.com', 'www.example.com']


def test_txt_contents_match_strips_quotes():
    assert acme._txt_contents_match('"abc"', 'abc')
    assert not acme._txt_contents_match('abc', 'other')


# ---------------------------------------------------------------------------
# Create / delete via mocked Cloudflare API
# ---------------------------------------------------------------------------

def test_cloudflare_update_requires_token():
    result = acme._cloudflare_update({}, '_acme-challenge.example.com', 'abc', 'present')
    assert result['success'] is False
    assert 'token' in result['message'].lower()


def test_cloudflare_rejects_unsafe_zone_id():
    result = acme._cloudflare_update(
        {'token': 'tok', 'zone_id': '../evil'},
        '_acme-challenge.example.com', 'abc', 'present',
    )
    assert result['success'] is False
    assert 'invalid' in result['message'].lower()


def test_cloudflare_create_with_zone_id_skips_zone_list():
    zone_id = 'a' * 32
    calls = []

    def fake_request(method, url, **kwargs):
        calls.append((method, url, kwargs.get('json')))
        assert url.startswith(acme.CLOUDFLARE_API_BASE)
        if method == 'POST' and url.endswith(f'/zones/{zone_id}/dns_records'):
            return _cf_ok({'id': 'rec123'})
        raise AssertionError(f'unexpected call {method} {url}')

    config = {'token': 'tok', 'zone_id': zone_id, 'ttl': 1}
    with patch('pegaprox.core.acme.requests.request', side_effect=fake_request):
        result = acme._cloudflare_update(
            config, '_acme-challenge.example.com', 'challenge-value', 'present'
        )

    assert result == {'success': True}
    assert config['_cloudflare_record_id'] == 'rec123'
    assert config['_cloudflare_zone_id'] == zone_id
    assert len(calls) == 1
    method, url, body = calls[0]
    assert method == 'POST'
    assert body['type'] == 'TXT'
    assert body['name'] == '_acme-challenge.example.com'
    assert body['content'] == 'challenge-value'
    assert body['ttl'] == 60  # Cloudflare minimum


def test_cloudflare_create_autodetects_zone():
    zone_id = 'b' * 32
    calls = []

    def fake_request(method, url, **kwargs):
        calls.append((method, url, kwargs.get('params')))
        if method == 'GET' and url.endswith('/zones'):
            name = (kwargs.get('params') or {}).get('name')
            if name == 'example.com':
                return _cf_ok([{'id': zone_id, 'name': 'example.com'}])
            return _cf_ok([])
        if method == 'POST' and url.endswith(f'/zones/{zone_id}/dns_records'):
            return _cf_ok({'id': 'rec456'})
        raise AssertionError(f'unexpected call {method} {url}')

    config = {'token': 'tok'}
    with patch('pegaprox.core.acme.requests.request', side_effect=fake_request):
        result = acme._cloudflare_update(
            config, '_acme-challenge.www.example.com', 'val', 'present'
        )

    assert result['success'] is True
    assert config['_cloudflare_record_id'] == 'rec456'
    zone_lookups = [params.get('name') for method, url, params in calls if method == 'GET']
    assert zone_lookups[0] == 'www.example.com'
    assert 'example.com' in zone_lookups


def test_cloudflare_delete_uses_stored_record_id():
    zone_id = 'c' * 32
    calls = []

    def fake_request(method, url, **kwargs):
        calls.append((method, url))
        if method == 'DELETE' and url.endswith(f'/zones/{zone_id}/dns_records/rec123'):
            return _cf_ok({'id': 'rec123'})
        raise AssertionError(f'unexpected call {method} {url}')

    config = {
        'token': 'tok',
        'zone_id': zone_id,
        '_cloudflare_record_id': 'rec123',
        '_cloudflare_zone_id': zone_id,
    }
    with patch('pegaprox.core.acme.requests.request', side_effect=fake_request):
        result = acme._cloudflare_update(
            config, '_acme-challenge.example.com', 'val', 'delete'
        )

    assert result['success'] is True
    assert '_cloudflare_record_id' not in config
    assert calls == [('DELETE', f'{acme.CLOUDFLARE_API_BASE}/zones/{zone_id}/dns_records/rec123')]


def test_cloudflare_delete_matches_quoted_txt_when_id_missing():
    zone_id = 'd' * 32

    def fake_request(method, url, **kwargs):
        if method == 'GET' and url.endswith(f'/zones/{zone_id}/dns_records'):
            return _cf_ok([
                {'id': 'other', 'content': 'nope'},
                {'id': 'rec789', 'content': '"wanted"'},
            ])
        if method == 'DELETE' and url.endswith(f'/zones/{zone_id}/dns_records/rec789'):
            return _cf_ok({'id': 'rec789'})
        raise AssertionError(f'unexpected call {method} {url}')

    config = {'token': 'tok', 'zone_id': zone_id}
    with patch('pegaprox.core.acme.requests.request', side_effect=fake_request):
        result = acme._cloudflare_update(
            config, '_acme-challenge.example.com', 'wanted', 'delete'
        )
    assert result['success'] is True


def test_cloudflare_zone_lookup_auth_error_mentions_zone_id():
    def fake_request(method, url, **kwargs):
        return _cf_err('Authentication error', status=403)

    with patch('pegaprox.core.acme.requests.request', side_effect=fake_request):
        result = acme._cloudflare_update(
            {'token': 'tok'}, '_acme-challenge.example.com', 'val', 'present'
        )
    assert result['success'] is False
    assert 'Zone ID' in result['message']


def test_cloudflare_ambiguous_zones_require_override():
    def fake_request(method, url, **kwargs):
        return _cf_ok([
            {'id': 'a' * 32, 'name': 'example.com'},
            {'id': 'b' * 32, 'name': 'example.com'},
        ])

    with patch('pegaprox.core.acme.requests.request', side_effect=fake_request):
        result = acme._cloudflare_update(
            {'token': 'tok', 'cloudflare_zone': 'example.com'},
            '_acme-challenge.example.com', 'val', 'present',
        )
    assert result['success'] is False
    assert 'Multiple' in result['message']


def test_automated_updater_table_includes_cloudflare():
    assert 'cloudflare' in acme._AUTOMATED_DNS_UPDATERS
    assert 'rfc2136' in acme._AUTOMATED_DNS_UPDATERS
    assert acme._AUTOMATED_DNS_UPDATERS['cloudflare'][1] is acme._cloudflare_update
