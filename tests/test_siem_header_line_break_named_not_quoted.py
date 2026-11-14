"""A header value with a line break is named in the last error of a SIEM target, not quoted.

http.client refuses such a value before it connects, and its error quotes the value, so
the last error of the target, which the read of the targets returns, showed the token.
Only a direct API call stores such a value: the token input of the tab drops line breaks,
and the headers textarea needs an escaped one. Now the sender names the header and sends
nothing. MK Nov 2026
"""
import socket

import pytest

import pegaprox.utils.url_security as url_security

CASES = {
    'splunk': ('splunk_hec', 'https://hec.example:8088/services/collector',
               {'token': 'hec-nl-secret\n'}, 'Authorization'),
    'generic': ('generic', 'https://siem.example/ingest',
                {'headers': {'X-API-Key': 'gk-nl-secret\r\nX: y'}}, 'X-API-Key'),
    'http_json': ('http_json', 'https://loki.example/loki/api/v1/push',
                  {'headers': {'X-Scope-OrgID': 'tenant-a\nnl-secret'}}, 'X-Scope-OrgID'),
}


@pytest.fixture
def admin(api, db, seed, monkeypatch):
    # the endpoint as typed, with no lookup, and no connection at all
    monkeypatch.setattr(url_security, 'resolve_and_pin_url', lambda url, **kw: url)

    def _no_connection(*a, **kw):
        raise OSError('no connection in this test')
    monkeypatch.setattr(socket, 'create_connection', _no_connection)
    return api.as_user(seed.user('root', role='admin'))


@pytest.mark.parametrize('name', sorted(CASES))
def test_the_last_error_names_the_header_and_quotes_no_value(admin, name):
    typ, endpoint, settings, header = CASES[name]
    r = admin.post('/api/siem/targets', json={'name': name, 'type': typ, 'endpoint': endpoint,
                                              'settings': settings})
    assert r.status_code == 200, r.get_data(as_text=True)
    tid = r.get_json()['target']['id']
    r = admin.post(f'/api/siem/targets/{tid}/test')
    assert r.status_code == 200 and r.get_json()['ok'] is False, r.get_data(as_text=True)
    assert r.get_json()['target']['last_error'] == \
        f'the {header} header of this target holds a line break, enter it again'
    shown = next(t for t in admin.get('/api/siem/targets').get_json()['targets'] if t['id'] == tid)
    assert 'nl-secret' not in shown['last_error']


def test_a_header_without_a_line_break_goes_on_to_the_send(admin):
    r = admin.post('/api/siem/targets', json={'name': 'hec', 'type': 'splunk_hec',
                                              'endpoint': 'https://hec.example:8088/services/collector',
                                              'settings': {'token': 'hec-ok-1'}})
    tid = r.get_json()['target']['id']
    r = admin.post(f'/api/siem/targets/{tid}/test')
    assert r.get_json()['ok'] is False
    assert 'no connection in this test' in r.get_json()['target']['last_error']
