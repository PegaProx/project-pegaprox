"""Cloud layout: the per-user dashboard layout lives in the preferences.

The Cloud widget engine (web/src/cloud.js) persists {v, widgets:[{id,size,cfg}]}
server-side so a user's customized dashboard follows them across browsers,
with localStorage as the offline fallback. The server treats it as opaque
layout data: shape-checked and size-capped, never interpreted. NS Nov 2026.
"""
import pytest

from tests.conftest import _seed_user


def _cloud_user(db, name='cloudy'):
    _seed_user(db, name, role='user')
    row = db.get_user(name)
    row.update({'ui_layout': 'cloud', 'layout_chosen': True})
    db.save_user(name, row)
    out = db.get_user(name)
    out['username'] = name
    return out


LAYOUT = {
    'v': 1,
    'widgets': [
        {'id': 'kpi', 'size': 'full', 'cfg': {}},
        {'id': 'utilization', 'size': 'lg', 'cfg': {}},
        {'id': 'consumers', 'size': 'md', 'cfg': {'metric': 'cpu'}},
        {'id': 'activity', 'size': 'md', 'cfg': {'max': 8}},
    ],
}


def test_get_names_the_field_so_the_client_can_tell_unset_from_absent(api, db):
    _cloud_user(db)
    me = api.as_user(_cloud_user(db))
    body = me.get('/api/user/preferences').get_json()
    assert 'cloud_dashboard' in body and body['cloud_dashboard'] is None


def test_put_stores_the_layout_and_hands_it_back(api, db):
    _cloud_user(db)
    me = api.as_user(_cloud_user(db))
    r = me.put('/api/user/preferences', json={'cloud_dashboard': LAYOUT})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert db.get_user('cloudy')['cloud_dashboard'] == LAYOUT
    assert me.get('/api/user/preferences').get_json()['cloud_dashboard'] == LAYOUT


def test_null_clears_the_saved_layout(api, db):
    _cloud_user(db)
    me = api.as_user(_cloud_user(db))
    assert me.put('/api/user/preferences', json={'cloud_dashboard': LAYOUT}).status_code == 200
    r = me.put('/api/user/preferences', json={'cloud_dashboard': None})
    assert r.status_code == 200
    assert db.get_user('cloudy')['cloud_dashboard'] is None


def test_anything_that_is_not_an_object_is_refused(api, db):
    _cloud_user(db)
    me = api.as_user(_cloud_user(db))
    for bad in ([LAYOUT], 'kpi/full', 42, True):
        r = me.put('/api/user/preferences', json={'cloud_dashboard': bad})
        assert (r.status_code, r.get_json().get('error')) == (400, 'cloud_dashboard must be an object'), bad
    assert db.get_user('cloudy')['cloud_dashboard'] is None


def test_a_bloated_layout_is_capped_at_32k(api, db):
    _cloud_user(db)
    me = api.as_user(_cloud_user(db))
    bloated = {'v': 1, 'widgets': [{'id': 'activity', 'size': 'md',
                                    'cfg': {'max': 8, 'blob': 'x' * 40000}}]}
    r = me.put('/api/user/preferences', json={'cloud_dashboard': bloated})
    assert (r.status_code, r.get_json().get('error')) == (400, 'cloud_dashboard too large')
    assert db.get_user('cloudy')['cloud_dashboard'] is None


def test_the_layout_choice_keeps_working_next_to_the_widget_data(api, db):
    _cloud_user(db)
    me = api.as_user(_cloud_user(db))
    r = me.put('/api/user/preferences', json={'ui_layout': 'cloud', 'cloud_dashboard': LAYOUT})
    assert r.status_code == 200
    row = db.get_user('cloudy')
    assert row['ui_layout'] == 'cloud' and row['cloud_dashboard'] == LAYOUT
