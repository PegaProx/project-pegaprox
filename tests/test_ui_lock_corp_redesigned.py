"""An admin can pin Corporate Redesigned for everyone.

Classic Corporate is frozen and gets bug fixes only, and a corporate lock pins its users to
it. Without a lock value for the redesign an admin could give nobody the redesign: the
only way was each user picking it, and a corporate lock took that away again.

  a) POST /api/settings/server takes ui_layout_lock = corporate-redesigned, from the JSON
     body and from the form the UI sends, and GET /api/settings/server and the public
     GET /api/interface/lock hand it back as it was stored (a value outside the list reads
     as no lock, so a dropped value would lift the lock without anyone seeing it).
  b) a held user may send corporate-redesigned and nothing else for ui_layout, the plain
     corporate included; an admin is exempt unless the lock says so.
  c) a corporate lock still means the classic one: corporate-redesigned is refused there.

MK Nov 2026
"""
import pytest

from tests.conftest import _seed_user

REDESIGN = 'corporate-redesigned'


@pytest.fixture
def admin(api, db):
    return api.as_user(_seed_user(db, 'root', role='admin'))


def _person(db, name, role='user', layout='modern'):
    _seed_user(db, name, role=role)
    row = db.get_user(name)
    row.update({'ui_layout': layout, 'language': 'en', 'theme': 'proxmoxDark', 'layout_chosen': True})
    db.save_user(name, row)
    out = db.get_user(name)
    out['username'] = name
    return out


def _pin(db, layout, admins=False):
    db.save_server_setting('ui_layout_lock', layout)
    db.save_server_setting('ui_language_lock', '')
    db.save_server_setting('ui_lock_admins', admins)


def _stored():
    from pegaprox.api.helpers import load_server_settings
    return load_server_settings().get('ui_layout_lock')


# --- a) saving and reading it ------------------------------------------------------------------

def test_a_json_save_pins_the_redesign_and_it_reads_back(api, admin):
    r = admin.post('/api/settings/server', json={'ui_layout_lock': REDESIGN, 'ui_language_lock': '',
                                                 'ui_lock_admins': False})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert _stored() == REDESIGN
    assert admin.get('/api/settings/server').get_json()['ui_layout_lock'] == REDESIGN
    assert api.anon().get('/api/interface/lock').get_json() == {'layout': REDESIGN, 'language': '',
                                                                'admins': False}


def test_the_form_the_ui_sends_pins_it_too(admin):
    r = admin.post('/api/settings/server', content_type='multipart/form-data',
                   data={'domain': '', 'port': '5000', 'ui_layout_lock': REDESIGN,
                         'ui_language_lock': '', 'ui_lock_admins': 'false'})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert _stored() == REDESIGN


def test_the_change_is_audited_with_the_value(admin, db):
    assert admin.post('/api/settings/server', json={'ui_layout_lock': REDESIGN}).status_code == 200
    rows = db.conn.execute("SELECT details FROM audit_log WHERE action = 'settings.interface_lock'").fetchall()
    assert any(REDESIGN in (r[0] or '') for r in rows), rows


def test_a_stored_redesign_lock_is_in_effect_not_dropped(api, db):
    # a restored config carries it as a plain string; it must not read as "users choose"
    _pin(db, REDESIGN)
    assert api.anon().get('/api/interface/lock').get_json()['layout'] == REDESIGN


@pytest.mark.parametrize('value', ['Corporate-Redesigned', 'corporate-redesigned2', 'redesigned'])
def test_anything_near_it_is_still_refused(admin, db, value):
    _pin(db, 'modern')
    r = admin.post('/api/settings/server', json={'ui_layout_lock': value})
    assert r.status_code == 400
    assert _stored() == 'modern'


# --- b) who it holds ---------------------------------------------------------------------------

@pytest.mark.parametrize('other', ['corporate', 'modern', 'cloud', 'classic'])
def test_a_held_user_cannot_leave_the_redesign(api, db, other):
    _pin(db, REDESIGN)
    alice = api.as_user(_person(db, 'alice', layout=REDESIGN))
    r = alice.put('/api/user/preferences', json={'ui_layout': other})
    body = r.get_json()
    assert (r.status_code, body.get('code'), body.get('field')) == (403, 'UI_LOCKED', 'ui_layout')
    assert body['lock']['layout'] == REDESIGN
    assert db.get_user('alice')['ui_layout'] == REDESIGN


def test_a_held_user_can_send_the_pinned_redesign(api, db):
    _pin(db, REDESIGN)
    bob = api.as_user(_person(db, 'bob', layout='modern'))
    r = bob.put('/api/user/preferences', json={'ui_layout': REDESIGN, 'layout_chosen': True})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert db.get_user('bob')['ui_layout'] == REDESIGN


def test_an_admin_is_exempt_unless_the_lock_says_so(api, db):
    _pin(db, REDESIGN, admins=False)
    root = api.as_user(_person(db, 'boss', role='admin', layout=REDESIGN))
    assert root.put('/api/user/preferences', json={'ui_layout': 'corporate'}).status_code == 200
    _pin(db, REDESIGN, admins=True)
    r = root.put('/api/user/preferences', json={'ui_layout': 'modern'})
    assert (r.status_code, r.get_json().get('code')) == (403, 'UI_LOCKED')


# --- c) a corporate lock is the classic one ----------------------------------------------------

def test_a_corporate_lock_still_refuses_the_redesign(api, db):
    _pin(db, 'corporate')
    alice = api.as_user(_person(db, 'alice', layout='corporate'))
    r = alice.put('/api/user/preferences', json={'ui_layout': REDESIGN})
    assert (r.status_code, r.get_json().get('code')) == (403, 'UI_LOCKED')
    assert db.get_user('alice')['ui_layout'] == 'corporate'
