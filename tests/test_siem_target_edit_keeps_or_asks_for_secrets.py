"""An edit of a SIEM target keeps its stored secrets, and a new endpoint asks for them.

The settings tab gets the token, the password and an Authorization header masked and
sends them back with every edit, which wrote the mask over the stored values: a target
renamed in the tab sent "********" from then on. A masked value is the stored one again.
And a secret goes to the address it was typed for: an edit that moves the endpoint
without typing the token or password again is refused (CREDENTIAL_REQUIRED), as PBS and
the cluster connection do. MK Nov 2026
"""
import pytest

import pegaprox.api.siem as siem

HEC = 'hec-91d0c2e5'


@pytest.fixture
def admin(api, db, seed):
    a = api.as_user(seed.user('root', role='admin'))
    r = a.post('/api/siem/targets', json={'name': 'splunk', 'type': 'splunk_hec',
                                          'endpoint': 'https://hec.example:8088',
                                          'settings': {'token': HEC, 'index': 'audit',
                                                       'headers': {'Authorization': 'Bearer hdr-5a'}}})
    assert r.status_code == 200, r.get_data(as_text=True)
    a.tid = r.get_json()['target']['id']
    return a


def _stored():
    return {t['id']: t for t in siem._list_enabled()}


def _shown(admin):
    return next(t for t in admin.get('/api/siem/targets').get_json()['targets'] if t['id'] == admin.tid)


def test_an_edit_from_the_tab_keeps_the_stored_secrets(admin):
    t = _shown(admin)
    assert t['settings']['token'] == '********'
    r = admin.put(f'/api/siem/targets/{admin.tid}', json={
        'name': 'splunk prod', 'type': t['type'], 'endpoint': t['endpoint'], 'enabled': True,
        'settings': dict(t['settings'], index='audit-2')})
    assert r.status_code == 200, r.get_data(as_text=True)
    s = _stored()[admin.tid]
    assert s['name'] == 'splunk prod'
    assert s['settings'] == {'token': HEC, 'index': 'audit-2', 'headers': {'Authorization': 'Bearer hdr-5a'}}


def test_a_typed_value_replaces_the_stored_one(admin):
    t = _shown(admin)
    admin.put(f'/api/siem/targets/{admin.tid}', json={'settings': dict(t['settings'], token='hec-new')})
    assert _stored()[admin.tid]['settings']['token'] == 'hec-new'


@pytest.mark.parametrize('with_settings', [True, False])
def test_a_new_endpoint_with_the_stored_secrets_is_refused(admin, with_settings):
    t = _shown(admin)
    body = {'endpoint': 'https://collector.elsewhere.example:8088'}
    if with_settings:
        body['settings'] = t['settings']
    r = admin.put(f'/api/siem/targets/{admin.tid}', json=body)
    assert r.status_code == 400 and r.get_json()['code'] == 'CREDENTIAL_REQUIRED', r.get_data(as_text=True)
    s = _stored()[admin.tid]
    assert s['endpoint'] == 'https://hec.example:8088' and s['settings']['token'] == HEC


def test_a_new_endpoint_with_the_secrets_typed_again_is_taken(admin):
    r = admin.put(f'/api/siem/targets/{admin.tid}', json={
        'endpoint': 'https://collector.elsewhere.example:8088',
        'settings': {'token': 'hec-other', 'index': 'audit', 'headers': {'Authorization': 'Bearer hdr-6b'}}})
    assert r.status_code == 200, r.get_data(as_text=True)
    s = _stored()[admin.tid]
    assert s['endpoint'] == 'https://collector.elsewhere.example:8088' and s['settings']['token'] == 'hec-other'


def test_a_target_without_secrets_moves_freely(admin):
    r = admin.post('/api/siem/targets', json={'name': 'syslog', 'type': 'syslog_udp',
                                              'endpoint': '10.0.0.5:514', 'settings': {'facility': 'local3'}})
    tid = r.get_json()['target']['id']
    assert admin.put(f'/api/siem/targets/{tid}', json={'endpoint': '10.0.0.6:514'}).status_code == 200


def test_an_edit_of_a_target_that_is_gone_is_a_404(admin):
    assert admin.put('/api/siem/targets/nope', json={'name': 'x'}).status_code == 404
