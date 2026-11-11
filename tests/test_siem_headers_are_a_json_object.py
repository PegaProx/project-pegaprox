"""The custom headers of a SIEM target are a JSON object, nothing else.

The textarea of the tab takes any JSON, and a list of name/value pairs made headers as
well. The mask goes by name and only into objects, so the read of such a target showed
the values and the test button sent them. Now the routes take an object only, a row
stored as a list before sends nothing and says why, and its read shows none of it.
MK Nov 2026
"""
import json

import pytest

import pegaprox.api.siem as siem

PAIRS = [['X-API-Key', 'pairsecret-1'], ['Authorization', 'Bearer pairsecret-2']]
NOT_AN_OBJECT = 'the headers of this target are not a JSON object, enter them again'


@pytest.fixture
def admin(api, db, seed, monkeypatch):
    a = api.as_user(seed.user('root', role='admin'))
    a.posts = []
    monkeypatch.setattr(siem, '_http_post', lambda url, body, headers, **kw: a.posts.append(headers))
    return a


def _new(admin, headers):
    return admin.post('/api/siem/targets', json={'name': 'loki', 'type': 'http_json',
                                                 'endpoint': 'https://loki.example/loki/api/v1/push',
                                                 'settings': {'headers': headers, 'verify_tls': True}})


def _row(tid):
    return next(t for t in siem._list_enabled() if t['id'] == tid)


def _shown(admin, tid):
    return next(t for t in admin.get('/api/siem/targets').get_json()['targets'] if t['id'] == tid)


@pytest.mark.parametrize('headers', [PAIRS, 'X-API-Key: pairsecret-1', 7, []],
                         ids=['pairs', 'string', 'number', 'empty-list'])
def test_a_new_target_with_headers_that_are_no_object_is_refused(admin, headers):
    r = _new(admin, headers)
    assert r.status_code == 400, r.get_data(as_text=True)
    assert r.get_json()['error'] == 'headers must be a JSON object'
    assert admin.get('/api/siem/targets').get_json()['targets'] == []


@pytest.mark.parametrize('headers', [{'X-Scope-OrgID': 'tenant-a'}, {}, None], ids=['object', 'empty', 'none'])
def test_headers_as_an_object_or_none_at_all_are_taken(admin, headers):
    r = _new(admin, headers)
    assert r.status_code == 200, r.get_data(as_text=True)
    r = admin.post(f"/api/siem/targets/{r.get_json()['target']['id']}/test")
    assert r.get_json()['ok'] is True, r.get_data(as_text=True)
    assert admin.posts == [dict({'Content-Type': 'application/json'}, **(headers or {}))]


def test_an_edit_with_headers_that_are_no_object_is_refused(admin):
    tid = _new(admin, {'X-API-Key': 'objsecret-1'}).get_json()['target']['id']
    r = admin.put(f'/api/siem/targets/{tid}', json={'name': 'loki prod', 'settings': {'headers': PAIRS}})
    assert r.status_code == 400 and r.get_json()['error'] == 'headers must be a JSON object'
    assert (_row(tid)['name'], _row(tid)['settings']['headers']) == ('loki', {'X-API-Key': 'objsecret-1'})


@pytest.fixture
def stored_pairs(admin, db):
    tid = _new(admin, {}).get_json()['target']['id']
    # what the routes took before
    db.conn.execute('UPDATE siem_targets SET settings = ? WHERE id = ?', (json.dumps({'headers': PAIRS}), tid))
    db.conn.commit()
    return tid


def test_a_stored_list_of_pairs_is_not_shown(admin, stored_pairs):
    assert 'pairsecret' not in admin.get('/api/siem/targets').get_data(as_text=True)
    assert _shown(admin, stored_pairs)['settings']['headers'] == '********'


def test_a_stored_list_of_pairs_sends_nothing_and_says_why(admin, stored_pairs):
    r = admin.post(f'/api/siem/targets/{stored_pairs}/test')
    assert r.status_code == 200 and r.get_json()['ok'] is False, r.get_data(as_text=True)
    assert admin.posts == []
    assert r.get_json()['target']['last_error'] == NOT_AN_OBJECT


def test_an_edit_from_the_tab_asks_for_the_headers_again(admin, stored_pairs):
    t = _shown(admin, stored_pairs)
    r = admin.put(f'/api/siem/targets/{stored_pairs}', json={'name': 'loki', 'settings': t['settings']})
    assert r.status_code == 400 and r.get_json()['error'] == 'headers must be a JSON object'
    assert _row(stored_pairs)['settings']['headers'] == PAIRS
    # typed again as an object, they are taken and sent
    r = admin.put(f'/api/siem/targets/{stored_pairs}',
                  json={'settings': dict(t['settings'], headers={'X-API-Key': 'pairsecret-1'})})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert admin.post(f'/api/siem/targets/{stored_pairs}/test').get_json()['ok'] is True
    assert admin.posts[-1]['X-API-Key'] == 'pairsecret-1'
