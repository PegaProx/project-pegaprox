"""A SIEM target sends with the token and password it stores, not with their mask.

The read of a target masks its secrets for the settings tab. The sender and the test
button read the targets through the same function, so a Splunk HEC target sent
"Splunk ********", an Elastic one logged in with the password "********" and a custom
Authorization header went out as the mask too. They read the stored values again; what
the routes hand out stays masked. MK Nov 2026
"""
import pytest

import pegaprox.api.siem as siem

HEC = 'hec-6c1f0a9e-77d2'
ELASTIC_PW = 'el-pw-41b8'
BEARER = 'Bearer gen-0e93c5'


@pytest.fixture
def targets(api, db, seed):
    admin = api.as_user(seed.user('root', role='admin'))
    made = {}
    for name, typ, endpoint, settings in (
            ('splunk', 'splunk_hec', 'https://hec.example:8088', {'token': HEC, 'index': 'audit'}),
            ('elastic', 'elastic', 'https://es.example:9200', {'username': 'pp', 'password': ELASTIC_PW}),
            ('generic', 'generic', 'https://siem.example/ingest', {'headers': {'Authorization': BEARER}})):
        r = admin.post('/api/siem/targets', json={'name': name, 'type': typ, 'endpoint': endpoint,
                                                  'settings': settings})
        assert r.status_code == 200, r.get_data(as_text=True)
        made[name] = r.get_json()['target']['id']
    admin.ids = made
    return admin


def test_the_routes_still_hand_the_secrets_out_masked(targets):
    body = targets.get('/api/siem/targets').get_data(as_text=True)
    assert HEC not in body and ELASTIC_PW not in body and BEARER not in body


def test_the_sender_gets_the_stored_values(targets):
    by_name = {t['name']: t['settings'] for t in siem._list_enabled()}
    assert by_name['splunk'] == {'token': HEC, 'index': 'audit'}
    assert by_name['elastic']['password'] == ELASTIC_PW
    assert by_name['generic']['headers'] == {'Authorization': BEARER}


def test_the_test_button_sends_with_the_stored_token(targets, monkeypatch):
    seen = []
    monkeypatch.setitem(siem._DISPATCH, 'splunk_hec', lambda t, e: seen.append(t['settings']['token']))
    r = targets.post(f"/api/siem/targets/{targets.ids['splunk']}/test")
    assert r.status_code == 200 and r.get_json()['ok'] is True, r.get_data(as_text=True)
    assert seen == [HEC]
    assert HEC not in r.get_data(as_text=True)
