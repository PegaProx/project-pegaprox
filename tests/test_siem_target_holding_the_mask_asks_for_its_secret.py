"""A SIEM target that stores the mask as its secret asks for the secret again.

Until today the edit route wrote the masked settings of the tab back, so a target edited
since July can hold "********" as its token, password or Authorization header. That is
no secret: the sender used to send "Splunk ********", an edit kept the mask as if it were
the stored token, and moving the endpoint was refused for a secret that was never there.
Now a stored mask counts as not set: the form shows the field empty, the sender sends
nothing and says which value to type again, an edit drops it and the endpoint moves
freely. MK Nov 2026
"""
import json

import pytest

import pegaprox.api.siem as siem

MASK = '********'
HEC = 'hec-3b7e9d12'

TARGETS = {
    'splunk': ('splunk_hec', 'https://hec.example:8088', {'token': MASK, 'index': 'audit'},
               'the token of this target is not set, enter it again'),
    'elastic': ('elastic', 'https://es.example:9200', {'username': 'pp', 'password': MASK},
                'the password of this target is not set, enter it again'),
    'generic': ('generic', 'https://siem.example/ingest', {'headers': {'Authorization': MASK}},
                'the Authorization header of this target is not set, enter it again'),
}


@pytest.fixture
def admin(api, db, seed, monkeypatch):
    a = api.as_user(seed.user('root', role='admin'))
    a.ids, a.posts = {}, []
    monkeypatch.setattr(siem, '_http_post', lambda url, body, headers, **kw: a.posts.append(headers))
    for name, (typ, endpoint, settings, _) in TARGETS.items():
        r = a.post('/api/siem/targets', json={'name': name, 'type': typ, 'endpoint': endpoint,
                                              'settings': {}})
        assert r.status_code == 200, r.get_data(as_text=True)
        tid = r.get_json()['target']['id']
        # what the old edit route left in the row
        db.conn.execute('UPDATE siem_targets SET settings = ? WHERE id = ?', (json.dumps(settings), tid))
        db.conn.commit()
        a.ids[name] = tid
    return a


def _row(tid):
    return next(t for t in siem._list_enabled() if t['id'] == tid)


def _shown(admin, tid):
    return next(t for t in admin.get('/api/siem/targets').get_json()['targets'] if t['id'] == tid)


@pytest.mark.parametrize('name', sorted(TARGETS))
def test_the_sender_sends_no_mask_and_says_what_to_type_again(admin, name):
    r = admin.post(f'/api/siem/targets/{admin.ids[name]}/test')
    assert r.status_code == 200 and r.get_json()['ok'] is False, r.get_data(as_text=True)
    assert admin.posts == []
    assert r.get_json()['target']['last_error'] == TARGETS[name][3]


def test_a_real_token_is_still_sent(admin):
    t = _shown(admin, admin.ids['splunk'])
    assert admin.put(f"/api/siem/targets/{admin.ids['splunk']}",
                     json={'settings': dict(t['settings'], token=HEC)}).status_code == 200
    r = admin.post(f"/api/siem/targets/{admin.ids['splunk']}/test")
    assert r.get_json()['ok'] is True, r.get_data(as_text=True)
    assert [h['Authorization'] for h in admin.posts] == [f'Splunk {HEC}']


SHOWN_EMPTY = {
    'splunk': {'token': '', 'index': 'audit'},
    'elastic': {'username': 'pp', 'password': ''},
    'generic': {'headers': {'Authorization': ''}},
}


@pytest.mark.parametrize('name', sorted(TARGETS))
def test_a_stored_mask_reads_as_not_set_in_the_form(admin, name):
    # shown as the mask it read as set, and the edit dropped it without a word
    assert _shown(admin, admin.ids[name])['settings'] == SHOWN_EMPTY[name]


@pytest.mark.parametrize('name', sorted(TARGETS))
def test_an_edit_from_the_tab_drops_the_stored_mask(admin, name):
    tid = admin.ids[name]
    t = _shown(admin, tid)
    r = admin.put(f'/api/siem/targets/{tid}', json={
        'name': f'{name} renamed', 'type': t['type'], 'endpoint': t['endpoint'], 'enabled': True,
        'settings': t['settings']})
    assert r.status_code == 200, r.get_data(as_text=True)
    stored = _row(tid)
    assert stored['name'] == f'{name} renamed'
    assert MASK not in json.dumps(stored['settings'])


@pytest.mark.parametrize('with_settings', [True, False])
@pytest.mark.parametrize('name', sorted(TARGETS))
def test_the_endpoint_of_a_target_holding_the_mask_moves(admin, name, with_settings):
    tid = admin.ids[name]
    body = {'endpoint': 'https://collector.elsewhere.example:8088'}
    if with_settings:
        body['settings'] = _shown(admin, tid)['settings']
    r = admin.put(f'/api/siem/targets/{tid}', json=body)
    assert r.status_code == 200, r.get_data(as_text=True)
    assert _row(tid)['endpoint'] == 'https://collector.elsewhere.example:8088'
