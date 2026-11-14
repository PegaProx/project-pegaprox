"""A server settings save as form data without http_redirect_port keeps the stored value.

The form branch of POST /api/settings/server read the field with a fallback of '0'. 0 is
"auto" now and opens port 80 wherever the service may bind it, so a form that left the field
out (a script, an older client) switched the extra port on and asked for a restart. Without
the field the stored value stays and nothing about it asks for a restart; a value that is
sent is stored as before.
"""
import pytest

from pegaprox.api.helpers import load_server_settings

FORM = {'domain': '', 'port': '5000', 'ssl_enabled': 'false', 'reverse_proxy_enabled': 'false',
        'trusted_proxies': '', 'proxy_bind_address': ''}


@pytest.fixture
def admin(api, db, seed):
    return api.as_user(seed.user('root', role='admin'))


def _save(client, **fields):
    r = client.post('/api/settings/server', data={**FORM, **fields})
    assert r.status_code == 200, r.get_data(as_text=True)[:300]
    return r.get_json()


@pytest.mark.parametrize('stored', ['-1', '8080'])
def test_a_form_without_the_field_keeps_the_stored_port(admin, stored):
    _save(admin, http_redirect_port=stored)
    assert load_server_settings()['http_redirect_port'] == int(stored)
    answer = _save(admin)
    assert load_server_settings()['http_redirect_port'] == int(stored)
    assert answer['restart_required'] is False


def test_a_port_that_is_sent_is_stored(admin):
    _save(admin, http_redirect_port='-1')
    answer = _save(admin, http_redirect_port='0')
    assert load_server_settings()['http_redirect_port'] == 0
    assert answer['restart_required'] is True
