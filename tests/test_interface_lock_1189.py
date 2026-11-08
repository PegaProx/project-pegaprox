"""An admin pins the UI layout and/or the UI language for everyone (#1189, #1167).

Settings > Server carries three keys, saved through POST /api/settings/server (JSON and
the form-data branch the UI uses) and read back by GET:

  ui_layout_lock    '' (users choose) | modern | corporate | cloud
  ui_language_lock  '' (users choose) | de en it fr es pt ko zh pl
  ui_lock_admins    false by default: administrators are exempt unless this is on

  a) a value outside the lists, a type that is not a string, a checkbox that is not a
     clear yes or no is refused with 400 and nothing of that save lands. The string
     "false" never turns ui_lock_admins on. Cloud holds the admins like any other layout:
     it opens Users and Settings in place, so a held admin can still lift the lock. The
     lock is one for the whole installation, so a change of it takes the bar of the
     banners: a caller limited to a tenant or to clusters is refused with 403. It is
     audited where it lands, also when the syslog toggle saves it halfway through a save
     that fails later. GET hands out the lock in effect, which the form sends back.
  b) GET /api/interface/lock is public and answers the three values and nothing else.
     A portal_only account reads it too: / asks for it before it sends such an account on
     to /portal, so the portal_only hook leaves the route alone (PORTAL_ONLY_UNREAD).
  c) PUT /api/user/preferences refuses a layout or language that differs from a lock that
     binds the caller with 403 UI_LOCKED, the whole request and before anything is saved.
     The pinned value itself, layout_chosen and the other fields keep working. Who is an
     admin goes by the stored role, the user.role auth_check reports. The refusal carries
     the lock, so a page that could not read it follows it straight away.
  d) setting or lifting the lock never rewrites a user row, so lifting it gives everyone
     their own choice back.
  e) the counter-checks: every refusal above turns into a success when only the lock (or
     only the bad value) is taken away, and with the guard taken out the refused requests
     go through - so the refusals are the lock's and nothing else's.

MK Oct 2026
"""
import pytest

from tests.conftest import _seed_user

LOCK_KEYS = ('ui_layout_lock', 'ui_language_lock', 'ui_lock_admins')
LOCKED = (403, 'UI_LOCKED')


@pytest.fixture
def admin(api, db):
    return api.as_user(_seed_user(db, 'root', role='admin'))


def _person(db, name, role='user', layout='modern', language='de', **extra):
    """An account with a layout and a language of its own."""
    _seed_user(db, name, role=role)
    row = db.get_user(name)
    row.update({'ui_layout': layout, 'language': language, 'theme': 'proxmoxDark',
                'layout_chosen': True, 'taskbar_auto_expand': True, 'sidebar_show_vmid': False})
    row.update(extra)
    db.save_user(name, row)
    out = db.get_user(name)
    out['username'] = name
    return out


def _pin(db, layout='', language='', admins=False):
    """The lock straight into the store, for the tests that are not about saving it."""
    db.save_server_setting('ui_layout_lock', layout)
    db.save_server_setting('ui_language_lock', language)
    db.save_server_setting('ui_lock_admins', admins)


def _stored(keys=LOCK_KEYS):
    from pegaprox.api.helpers import load_server_settings
    current = load_server_settings()
    return {k: current.get(k) for k in keys}


def _code(resp):
    return (resp.get_json(silent=True) or {}).get('code')


def _rows(db):
    cur = db.conn.execute('SELECT * FROM users ORDER BY username')
    return [tuple(r) for r in cur.fetchall()]


def _form(admin, body):
    return admin.post('/api/settings/server', content_type='multipart/form-data', data=dict(body))


# --- a) the settings -----------------------------------------------------------------------

def test_off_by_default_and_read_back_by_the_settings_route(api, admin):
    got = admin.get('/api/settings/server').get_json()
    assert {k: got[k] for k in LOCK_KEYS} == {'ui_layout_lock': '', 'ui_language_lock': '',
                                              'ui_lock_admins': False}
    assert api.anon().get('/api/interface/lock').get_json() == {'layout': '', 'language': '',
                                                                'admins': False}


def test_a_json_save_lands_and_reads_back(api, admin):
    r = admin.post('/api/settings/server', json={'ui_layout_lock': 'corporate',
                                                 'ui_language_lock': 'en', 'ui_lock_admins': True})
    assert r.status_code == 200, r.get_data(as_text=True)
    got = admin.get('/api/settings/server').get_json()
    assert (got['ui_layout_lock'], got['ui_language_lock'], got['ui_lock_admins']) == ('corporate', 'en', True)
    assert api.anon().get('/api/interface/lock').get_json() == {'layout': 'corporate', 'language': 'en',
                                                                'admins': True}


def test_the_form_the_ui_sends_lands_too(admin):
    r = _form(admin, {'domain': '', 'port': '5000', 'ui_layout_lock': 'modern',
                      'ui_language_lock': 'pl', 'ui_lock_admins': 'true'})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert _stored() == {'ui_layout_lock': 'modern', 'ui_language_lock': 'pl', 'ui_lock_admins': True}
    r = _form(admin, {'domain': '', 'port': '5000', 'ui_layout_lock': '', 'ui_language_lock': '',
                      'ui_lock_admins': 'false'})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert _stored() == {'ui_layout_lock': '', 'ui_language_lock': '', 'ui_lock_admins': False}


def test_a_save_without_the_keys_leaves_the_lock_alone(admin, db):
    _pin(db, 'corporate', 'en', True)
    assert admin.post('/api/settings/server', json={'session_timeout': 7200}).status_code == 200
    assert _form(admin, {'domain': '', 'port': '5000'}).status_code == 200
    assert _stored() == {'ui_layout_lock': 'corporate', 'ui_language_lock': 'en', 'ui_lock_admins': True}


@pytest.mark.parametrize('multipart', [False, True], ids=['json', 'form'])
@pytest.mark.parametrize('value', ['false', 'False', ' FALSE ', '0', 'off', 'no', ''])
def test_a_stringy_false_never_turns_the_admins_on(admin, db, value, multipart):
    body = {'ui_lock_admins': value}
    r = _form(admin, body) if multipart else admin.post('/api/settings/server', json=body)
    assert r.status_code == 200, r.get_data(as_text=True)
    assert _stored()['ui_lock_admins'] is False
    # and it turns them off again
    _pin(db, 'corporate', '', True)
    r = _form(admin, body) if multipart else admin.post('/api/settings/server', json=body)
    assert r.status_code == 200 and _stored()['ui_lock_admins'] is False


@pytest.mark.parametrize('value', [True, 1, 'true', 'True', '1', 'on', 'yes'])
def test_a_clear_yes_turns_the_admins_on(admin, value):
    r = admin.post('/api/settings/server', json={'ui_lock_admins': value})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert _stored()['ui_lock_admins'] is True


BAD = [
    ('ui_layout_lock', 'classic'), ('ui_layout_lock', 'Modern'), ('ui_layout_lock', 'cloud2'),
    ('ui_layout_lock', 5), ('ui_layout_lock', None), ('ui_layout_lock', ['modern']),
    ('ui_layout_lock', {'v': 'modern'}), ('ui_layout_lock', True),
    ('ui_language_lock', 'nl'), ('ui_language_lock', 'EN'), ('ui_language_lock', 'en-US'),
    ('ui_language_lock', 'ru'), ('ui_language_lock', 7), ('ui_language_lock', None),
    ('ui_language_lock', ['en']),
    ('ui_lock_admins', 'maybe'), ('ui_lock_admins', 'truthy'), ('ui_lock_admins', 2),
    ('ui_lock_admins', -1), ('ui_lock_admins', 1.0), ('ui_lock_admins', None),
    ('ui_lock_admins', ['true']), ('ui_lock_admins', {}),
]
GOOD = {'ui_layout_lock': 'corporate', 'ui_language_lock': 'en', 'ui_lock_admins': False}


@pytest.mark.parametrize('key,value', BAD, ids=[f'{k}={v!r}' for k, v in BAD])
def test_a_value_outside_the_lists_is_refused_and_nothing_lands(admin, db, key, value):
    _pin(db, 'modern', 'de', False)
    r = admin.post('/api/settings/server', json={key: value, 'session_timeout': 7200,
                                                 'default_theme': 'nord'})
    assert r.status_code == 400, r.get_data(as_text=True)
    assert key in r.get_json()['error']
    assert _stored() == {'ui_layout_lock': 'modern', 'ui_language_lock': 'de', 'ui_lock_admins': False}
    rest = _stored(('session_timeout', 'default_theme'))
    assert rest['session_timeout'] != 7200 and rest['default_theme'] != 'nord'
    # counter-check: the same save with a good value goes through, so the 400 was the value's
    r = admin.post('/api/settings/server', json={key: GOOD[key], 'session_timeout': 7200,
                                                 'default_theme': 'nord'})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert _stored()[key] == GOOD[key]


@pytest.mark.parametrize('key,value', [('ui_layout_lock', 'classic'), ('ui_language_lock', 'nl'),
                                       ('ui_lock_admins', 'maybe')])
def test_the_form_branch_refuses_before_it_writes_anything(admin, db, key, value):
    _pin(db, 'modern', 'de', False)
    r = _form(admin, {'domain': 'pp.example', 'port': '5000', key: value})
    assert r.status_code == 400, r.get_data(as_text=True)
    assert key in r.get_json()['error']
    assert _stored(('domain',))['domain'] != 'pp.example'
    assert _stored() == {'ui_layout_lock': 'modern', 'ui_language_lock': 'de', 'ui_lock_admins': False}


def test_blanks_around_a_value_are_forgiven(admin):
    r = admin.post('/api/settings/server', json={'ui_layout_lock': ' cloud ', 'ui_language_lock': 'ko '})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert _stored()['ui_layout_lock'] == 'cloud' and _stored()['ui_language_lock'] == 'ko'


@pytest.mark.parametrize('multipart', [False, True], ids=['json', 'form'])
def test_cloud_holds_the_admins_like_any_other_layout(api, admin, db, multipart):
    """Cloud opens Users and Settings in place (cloud.js selectSection), so an admin held
    there still reaches the lock and can lift it again."""
    body = {'ui_layout_lock': 'cloud', 'ui_lock_admins': 'true' if multipart else True}
    r = _form(admin, body) if multipart else admin.post('/api/settings/server', json=body)
    assert r.status_code == 200, r.get_data(as_text=True)
    assert _stored() == {'ui_layout_lock': 'cloud', 'ui_language_lock': '', 'ui_lock_admins': True}
    assert api.anon().get('/api/interface/lock').get_json() == {'layout': 'cloud', 'language': '',
                                                                'admins': True}
    dana = api.as_user(_person(db, 'dana', role='admin'))
    assert _code(_put(dana, {'ui_layout': 'modern'})) == 'UI_LOCKED'
    # the admins are held, and still lift it through the same route
    r = admin.post('/api/settings/server', json={'ui_layout_lock': '', 'ui_lock_admins': False})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert _put(dana, {'ui_layout': 'modern'}).status_code == 200


def test_a_restored_value_outside_the_lists_blocks_no_save_of_the_tab(admin, db):
    """GET answers the lock in effect, and the form sends back what GET gave it. A restored
    or hand-edited value outside the lists reads as no lock there too, so the next save of
    the tab goes through instead of a 400 on a field the admin never touched."""
    _pin(db, 'classic', 'xx', 'true')
    got = admin.get('/api/settings/server').get_json()
    assert {k: got[k] for k in LOCK_KEYS} == {'ui_layout_lock': '', 'ui_language_lock': '',
                                              'ui_lock_admins': False}
    r = _form(admin, {'domain': 'pp.example', 'port': '5000', 'ui_layout_lock': got['ui_layout_lock'],
                      'ui_language_lock': got['ui_language_lock'],
                      'ui_lock_admins': 'true' if got['ui_lock_admins'] else 'false'})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert _stored(('domain',))['domain'] == 'pp.example'
    assert _stored() == {'ui_layout_lock': '', 'ui_language_lock': '', 'ui_lock_admins': False}
    # nothing that was in effect changed, so there is no lock line to audit
    assert not db.conn.execute("SELECT 1 FROM audit_log WHERE action = 'settings.interface_lock'").fetchall()
    # counter-check: the raw value is what the form would have sent before, and refused
    _pin(db, 'classic', '', False)
    r = _form(admin, {'domain': 'pp.example', 'port': '5000', 'ui_layout_lock': 'classic'})
    assert r.status_code == 400


def test_a_good_stored_lock_reads_back_as_it_is(admin, db):
    _pin(db, 'corporate', 'pl', True)
    got = admin.get('/api/settings/server').get_json()
    assert {k: got[k] for k in LOCK_KEYS} == {'ui_layout_lock': 'corporate', 'ui_language_lock': 'pl',
                                              'ui_lock_admins': True}


@pytest.mark.parametrize('role', ['user', 'viewer'])
def test_only_admin_settings_may_save_or_read_it(api, db, role):
    other = api.as_user(_seed_user(db, 'mallory', role=role))
    r = other.post('/api/settings/server', json={'ui_layout_lock': 'corporate'})
    assert r.status_code == 403
    assert _form(other, {'ui_language_lock': 'en'}).status_code == 403
    assert other.get('/api/settings/server').status_code == 403
    assert _stored() == {'ui_layout_lock': '', 'ui_language_lock': '', 'ui_lock_admins': False}


def test_an_anonymous_save_is_refused(api):
    r = api.anon().post('/api/settings/server', json={'ui_layout_lock': 'corporate'})
    assert r.status_code == 401
    assert _stored()['ui_layout_lock'] == ''


def test_a_change_is_audited_and_a_save_that_keeps_it_is_not(admin, db):
    def lines():
        return [r[0] for r in db.conn.execute(
            "SELECT details FROM audit_log WHERE action = 'settings.interface_lock' ORDER BY id")]
    admin.post('/api/settings/server', json={'ui_layout_lock': 'corporate', 'ui_language_lock': 'en'})
    assert lines() == ['Interface lock: layout users choose -> corporate, language users choose -> en']
    admin.post('/api/settings/server', json={'ui_layout_lock': 'corporate', 'ui_lock_admins': 'false'})
    assert len(lines()) == 1
    _form(admin, {'domain': '', 'port': '5000', 'ui_layout_lock': '', 'ui_language_lock': 'en',
                  'ui_lock_admins': 'true'})
    assert lines()[-1] == 'Interface lock: layout corporate -> users choose, administrators included'
    # a refused save is not audited either
    admin.post('/api/settings/server', json={'ui_layout_lock': 'nope'})
    assert len(lines()) == 2


def _lock_lines(db):
    return [r[0] for r in db.conn.execute(
        "SELECT details FROM audit_log WHERE action = 'settings.interface_lock' ORDER BY id")]


@pytest.fixture
def syslog_toggle(monkeypatch):
    """The receiver is started and stopped by the toggle: not in a test, it binds a port"""
    import pegaprox.background.syslog_server as syslog_server
    calls = []
    monkeypatch.setattr(syslog_server, 'start_syslog_server', lambda: calls.append('start'))
    monkeypatch.setattr(syslog_server, 'stop_syslog_server', lambda: calls.append('stop'))
    return calls


def test_the_lock_is_audited_where_the_syslog_toggle_saves_it(admin, db, syslog_toggle):
    """Flipping the syslog receiver saves the settings halfway through the route, the lock
    with them. A later error (a file that is not a certificate, a port that is no number)
    no longer leaves the lock stored without its audit line."""
    import io
    from pegaprox.api.helpers import load_server_settings
    syslog = load_server_settings().get('syslog_enabled', True)
    r = admin.post('/api/settings/server', content_type='multipart/form-data', data={
        'ui_layout_lock': 'corporate', 'ui_language_lock': 'en', 'ui_lock_admins': 'true',
        'syslog_enabled': 'false' if syslog else 'true', 'ssl_cert': (io.BytesIO(b'not a cert'), 'c.pem')})
    assert r.status_code == 400 and 'certificate' in r.get_json()['error']
    assert _stored() == {'ui_layout_lock': 'corporate', 'ui_language_lock': 'en', 'ui_lock_admins': True}
    assert _lock_lines(db) == ['Interface lock: layout users choose -> corporate, '
                               'language users choose -> en, administrators included']

    syslog = load_server_settings().get('syslog_enabled', True)
    r = admin.post('/api/settings/server', json={'ui_layout_lock': 'modern', 'ui_language_lock': 'fr',
                                                 'syslog_enabled': not syslog, 'ldap_port': 'abc'})
    assert r.status_code == 500
    assert _stored()['ui_layout_lock'] == 'modern'
    assert _lock_lines(db)[-1] == 'Interface lock: layout corporate -> modern, language en -> fr'
    assert len(syslog_toggle) == 2   # both saves went through the toggle


@pytest.mark.parametrize('multipart', [False, True], ids=['json', 'form'])
def test_a_save_through_the_syslog_toggle_audits_the_lock_once(admin, db, multipart, syslog_toggle):
    from pegaprox.api.helpers import load_server_settings
    syslog = load_server_settings().get('syslog_enabled', True)
    if multipart:
        r = _form(admin, {'domain': '', 'port': '5000', 'ui_layout_lock': 'cloud',
                          'syslog_enabled': 'false' if syslog else 'true'})
    else:
        r = admin.post('/api/settings/server', json={'ui_layout_lock': 'cloud', 'syslog_enabled': not syslog})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert _lock_lines(db) == ['Interface lock: layout users choose -> cloud']
    assert len(syslog_toggle) == 1


@pytest.fixture
def delegate(api, db):
    """admin.settings and admin.users for one tenant, the caller the banners refuse"""
    from tests.conftest import _seed_tenant
    _seed_tenant(db, 'globex', ['cluster_globex'])
    return api.as_user(_seed_user(db, 'gxadmin', role='user', tenant_id='globex',
                                  permissions=['admin.settings', 'admin.users']))


@pytest.mark.parametrize('multipart', [False, True], ids=['json', 'form'])
def test_a_caller_limited_to_a_tenant_cannot_pin_it_for_everyone(api, db, delegate, multipart):
    body = {'ui_layout_lock': 'cloud', 'ui_language_lock': 'ko', 'domain': 'gx.example', 'port': '5000'}
    r = _form(delegate, body) if multipart else delegate.post('/api/settings/server', json=body)
    assert r.status_code == 403, r.get_data(as_text=True)
    assert 'not limited to a tenant' in r.get_json()['error']
    assert _stored() == {'ui_layout_lock': '', 'ui_language_lock': '', 'ui_lock_admins': False}
    assert _stored(('domain',))['domain'] != 'gx.example'
    assert not _lock_lines(db)
    # nor lift or widen one an unconfined admin set
    _pin(db, 'corporate', 'en')
    for change in ({'ui_layout_lock': ''}, {'ui_lock_admins': 'true'}, {'ui_language_lock': 'de'}):
        r = _form(delegate, change) if multipart else delegate.post('/api/settings/server', json=change)
        assert r.status_code == 403, (change, r.get_data(as_text=True))
    assert _stored() == {'ui_layout_lock': 'corporate', 'ui_language_lock': 'en', 'ui_lock_admins': False}


@pytest.mark.parametrize('multipart', [False, True], ids=['json', 'form'])
def test_the_delegate_still_saves_the_tab_without_changing_the_lock(db, delegate, multipart):
    """The counter-check: the form sends the lock with every save of the tab. As it stands it
    is no change, and the rest of the save goes through as before for this caller."""
    _pin(db, 'corporate', 'en')
    body = {'ui_layout_lock': 'corporate', 'ui_language_lock': 'en', 'ui_lock_admins': 'false',
            'domain': 'gx.example', 'port': '5000'}
    if not multipart:
        body['ui_lock_admins'] = False
    r = _form(delegate, body) if multipart else delegate.post('/api/settings/server', json=body)
    assert r.status_code == 200, r.get_data(as_text=True)
    assert _stored(('domain',))['domain'] == 'gx.example'


def test_the_tenant_gate_is_what_refuses_the_delegate(api, db, delegate, monkeypatch):
    """Take only the scope out of the picture: the same change by the same caller lands."""
    import pegaprox.api.ha as ha_api
    monkeypatch.setattr(ha_api, '_unconfined', lambda user: True)
    r = delegate.post('/api/settings/server', json={'ui_layout_lock': 'cloud'})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert _stored()['ui_layout_lock'] == 'cloud'


# --- b) the public route ---------------------------------------------------------------------

def test_the_public_route_answers_three_values_and_nothing_else(api, admin, db):
    mark = 'leakcheck'
    r = admin.post('/api/settings/server', json={
        'ui_layout_lock': 'corporate', 'ui_language_lock': 'fr', 'domain': mark + '-host.example',
        'smtp_host': mark + '-mail.example', 'smtp_password': mark + '-smtp',
        'oidc_client_secret': mark + '-oidc', 'ldap_bind_password': mark + '-ldap'})
    assert r.status_code == 200, r.get_data(as_text=True)
    r = api.anon().get('/api/interface/lock')
    assert r.status_code == 200
    assert r.get_json() == {'layout': 'corporate', 'language': 'fr', 'admins': False}
    assert 'no-store' in r.headers.get('Cache-Control', '')
    body = r.get_data(as_text=True)
    for leaked in (mark, 'smtp', 'oidc', 'ldap', 'domain'):
        assert leaked not in body


def test_a_stored_value_outside_the_lists_reads_as_no_lock(api, db):
    _pin(db, 'classic', 'xx', 'true')
    assert api.anon().get('/api/interface/lock').get_json() == {'layout': '', 'language': '',
                                                                'admins': False}


def test_a_signed_in_account_reads_the_same(api, db):
    _pin(db, 'modern', 'it')
    alice = api.as_user(_person(db, 'alice'))
    assert alice.get('/api/interface/lock').get_json() == {'layout': 'modern', 'language': 'it',
                                                           'admins': False}


def test_a_portal_account_reads_the_lock_and_is_still_held_elsewhere(api, db, monkeypatch):
    """The decision for the portal_only hook: the route reads no credential and answers
    everyone the same, like /api/health, so it is in PORTAL_ONLY_UNREAD. The main page
    reads it before it knows the account belongs to the portal, a refusal there was a
    PORTAL_ONLY on every portal sign-in through /. The same credential is still refused on
    a route next to it, and the hook does not look the credential up here."""
    import pegaprox.utils.auth as auth_mod
    from pegaprox.utils.auth import PORTAL_ONLY_ENDPOINTS, PORTAL_ONLY_UNREAD, create_api_token
    endpoint = api.app.url_map.bind('localhost').match('/api/interface/lock', method='GET')[0]
    assert endpoint == 'settings.get_interface_lock'
    assert endpoint in PORTAL_ONLY_UNREAD and endpoint not in PORTAL_ONLY_ENDPOINTS
    _pin(db, 'modern', 'en')
    want = {'layout': 'modern', 'language': 'en', 'admins': False}
    cust = _seed_user(db, 'cust', portal_only=True)
    session = api.as_user(cust)
    token = create_api_token('cust', 'ci')['token']
    by_token = {'Authorization': f'Bearer {token}'}

    reads = []
    real = auth_mod._request_accounts
    monkeypatch.setattr(auth_mod, '_request_accounts', lambda *a, **k: reads.append(1) or real(*a, **k))
    r = session.get('/api/interface/lock')
    assert r.status_code == 200 and r.get_json() == want
    r = api.anon().get('/api/interface/lock', headers=by_token)
    assert r.status_code == 200 and r.get_json() == want
    assert reads == []

    # counter-check: the account is held, only not here
    r = session.get('/api/password-policy')
    assert (r.status_code, _code(r)) == (403, 'PORTAL_ONLY')
    r = api.anon().get('/api/password-policy', headers=by_token)
    assert (r.status_code, _code(r)) == (403, 'PORTAL_ONLY')
    assert reads


# --- c) the preferences ----------------------------------------------------------------------

def _put(client, body):
    return client.put('/api/user/preferences', json=body)


@pytest.mark.parametrize('body,field', [
    ({'ui_layout': 'modern'}, 'ui_layout'),
    ({'ui_layout': 'cloud'}, 'ui_layout'),
    ({'ui_layout': 'classic'}, 'ui_layout'),
    ({'language': 'de'}, 'language'),
    ({'language': ''}, 'language'),
    ({'theme': 'nord', 'ui_layout': 'modern'}, 'ui_layout'),
    ({'language': 'en', 'ui_layout': 'modern', 'layout_chosen': True}, 'ui_layout'),
])
def test_a_held_user_cannot_move_away_from_the_lock_and_nothing_is_saved(api, db, body, field):
    _pin(db, 'corporate', 'en')
    alice = api.as_user(_person(db, 'alice', layout='modern', language='de'))
    before = _rows(db)
    r = _put(alice, body)
    assert (r.status_code, _code(r)) == LOCKED, r.get_data(as_text=True)
    assert r.get_json()['field'] == field and r.get_json()['error']
    assert _rows(db) == before


def test_the_refusal_carries_the_lock(api, db):
    """The page follows it from here when its own read of the public route failed (#1189):
    a first-login picker would otherwise refuse every pick without a word."""
    _pin(db, 'corporate', 'pl')
    alice = api.as_user(_person(db, 'alice'))
    for body in ({'ui_layout': 'modern', 'layout_chosen': True}, {'language': 'de'}):
        r = _put(alice, body)
        assert (r.status_code, _code(r)) == LOCKED
        assert r.get_json()['lock'] == {'layout': 'corporate', 'language': 'pl', 'admins': False}
        assert r.get_json()['lock'] == api.anon().get('/api/interface/lock').get_json()


def test_the_pinned_value_itself_and_the_other_fields_go_through(api, db):
    _pin(db, 'corporate', 'en')
    alice = api.as_user(_person(db, 'alice', layout='modern', language='de'))
    r = _put(alice, {'ui_layout': 'corporate', 'language': 'en', 'layout_chosen': True})
    assert r.status_code == 200, r.get_data(as_text=True)
    r = _put(alice, {'theme': 'nord', 'taskbar_auto_expand': False, 'sidebar_show_vmid': 'true',
                     'layout_chosen': False})
    assert r.status_code == 200, r.get_data(as_text=True)
    row = db.get_user('alice')
    assert (row['theme'], row['taskbar_auto_expand'], row['sidebar_show_vmid'], row['layout_chosen']) \
        == ('nord', False, True, False)


@pytest.mark.parametrize('lock,body', [
    (('corporate', ''), {'language': 'pl'}),
    (('', 'en'), {'ui_layout': 'cloud'}),
    (('', ''), {'ui_layout': 'cloud', 'language': 'pl'}),
], ids=['layout-only', 'language-only', 'no-lock'])
def test_what_is_not_pinned_stays_the_users_choice(api, db, lock, body):
    _pin(db, *lock)
    alice = api.as_user(_person(db, 'alice'))
    r = _put(alice, body)
    assert r.status_code == 200, r.get_data(as_text=True)
    row = db.get_user('alice')
    assert all(row[k] == v for k, v in body.items())


@pytest.mark.parametrize('role', ['viewer', 'ops'])
def test_every_role_but_admin_is_held(api, db, role):
    _pin(db, 'corporate', 'en')
    other = api.as_user(_person(db, 'olga', role=role))
    assert _code(_put(other, {'ui_layout': 'modern'})) == 'UI_LOCKED'
    assert _code(_put(other, {'language': 'de'})) == 'UI_LOCKED'


def test_an_admin_is_exempt_by_default(api, db):
    _pin(db, 'corporate', 'en', admins=False)
    root = api.as_user(_person(db, 'root', role='admin'))
    r = _put(root, {'ui_layout': 'cloud', 'language': 'de'})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert (db.get_user('root')['ui_layout'], db.get_user('root')['language']) == ('cloud', 'de')


def test_an_admin_is_held_when_the_lock_says_so(api, db):
    _pin(db, 'corporate', 'en', admins=True)
    root = api.as_user(_person(db, 'root', role='admin'))
    before = _rows(db)
    for body in ({'ui_layout': 'modern'}, {'language': 'de'}):
        r = _put(root, body)
        assert (r.status_code, _code(r)) == LOCKED
    assert _rows(db) == before
    assert _put(root, {'ui_layout': 'corporate', 'language': 'en'}).status_code == 200


@pytest.mark.parametrize('admins', [False, True], ids=['admins-exempt', 'admins-held'])
def test_an_admins_token_bound_to_a_lower_role_goes_by_the_owner(api, db, admins):
    """The only caller whose session role differs from the stored one: require_auth reads an
    interactive session's role back from the DB, a token keeps the role it was made with.
    The preferences are the account's, so the owner's stored role decides."""
    from pegaprox.utils.auth import create_api_token
    _pin(db, 'corporate', 'en', admins=admins)
    _person(db, 'root', role='admin')
    token = create_api_token('root', 'ci', role='viewer')['token']
    r = api.anon().put('/api/user/preferences', json={'ui_layout': 'modern'},
                       headers={'Authorization': f'Bearer {token}'})
    if admins:
        assert (r.status_code, _code(r)) == LOCKED, r.get_data(as_text=True)
    else:
        assert r.status_code == 200, r.get_data(as_text=True)
        assert db.get_user('root')['ui_layout'] == 'modern'


def test_an_admin_a_tenant_mapping_lowers_is_exempt_as_the_browser_sees_it(api, db):
    """auth_check reports the stored role, and the browser shows the switchers by it. The
    server goes by the same role, so the page and the guard agree on who is held."""
    from pegaprox.utils.rbac import acts_as_admin
    _pin(db, 'corporate', 'en')
    capped = _person(db, 'lowered', role='admin', tenant_permissions={'default': {'role': 'viewer'}})
    assert acts_as_admin(capped) is False
    client = api.as_user(capped)
    assert client.get('/api/auth/check').get_json()['user']['role'] == 'admin'
    assert _put(client, {'ui_layout': 'cloud'}).status_code == 200
    # held once the lock says so, like every admin
    _pin(db, 'corporate', 'en', admins=True)
    assert _code(_put(client, {'ui_layout': 'modern'})) == 'UI_LOCKED'


def test_an_api_token_is_held_like_the_session(api, db):
    """The browser hides the switch; the guard is here, for every way into the route."""
    from pegaprox.utils.auth import create_api_token
    _pin(db, 'corporate', 'en')
    _person(db, 'alice')
    token = create_api_token('alice', 'ci')['token']
    r = api.anon().put('/api/user/preferences', json={'ui_layout': 'modern'},
                       headers={'Authorization': f'Bearer {token}'})
    assert (r.status_code, _code(r)) == LOCKED, r.get_data(as_text=True)


def test_the_preferences_read_still_answers_the_users_own_choice(api, db):
    _pin(db, 'corporate', 'en')
    alice = api.as_user(_person(db, 'alice', layout='cloud', language='ko'))
    got = alice.get('/api/user/preferences').get_json()
    assert (got['ui_layout'], got['language']) == ('cloud', 'ko')


def test_a_body_that_is_not_an_object_is_a_400(api, db):
    _pin(db, 'corporate', 'en')
    alice = api.as_user(_person(db, 'alice'))
    assert _put(alice, ['ui_layout']).status_code == 400


# --- d) user rows are never rewritten --------------------------------------------------------

def test_setting_and_lifting_the_lock_leaves_every_user_row_as_it_was(api, admin, db):
    _person(db, 'alice', layout='cloud', language='ko')
    _person(db, 'bob', layout='modern', language='')
    _person(db, 'carol', role='viewer', layout='corporate', language='pl')
    _person(db, 'dave', role='admin', layout='classic', language='fr')
    before = _rows(db)
    assert admin.post('/api/settings/server', json={'ui_layout_lock': 'corporate',
                                                    'ui_language_lock': 'en',
                                                    'ui_lock_admins': True}).status_code == 200
    assert _rows(db) == before
    assert _form(admin, {'domain': '', 'port': '5000', 'ui_layout_lock': '', 'ui_language_lock': '',
                         'ui_lock_admins': 'false'}).status_code == 200
    assert _rows(db) == before
    # and everyone has their own choice back, through the same route the browser reads
    alice = api.as_user(db.get_user('alice') | {'username': 'alice'})
    got = alice.get('/api/auth/check').get_json()['user']
    assert (got['ui_layout'], got['language']) == ('cloud', 'ko')
    assert _put(alice, {'ui_layout': 'modern'}).status_code == 200


# --- e) the counter-checks -------------------------------------------------------------------

REFUSALS = [
    ('user', ('corporate', 'en', False), {'ui_layout': 'modern'}),
    ('user', ('corporate', 'en', False), {'language': 'de'}),
    ('user', ('corporate', 'en', False), {'theme': 'nord', 'ui_layout': 'cloud'}),
    ('viewer', ('', 'en', False), {'language': 'zh'}),
    ('admin', ('modern', 'en', True), {'ui_layout': 'corporate'}),
    ('admin', ('modern', 'en', True), {'language': 'it'}),
]


@pytest.mark.parametrize('role,lock,body', REFUSALS)
def test_each_refusal_is_the_locks(api, db, role, lock, body):
    """The same account and the same request: refused with the lock, saved without it."""
    _pin(db, *lock)
    who = api.as_user(_person(db, 'pat', role=role, layout='classic', language='fr'))
    r = _put(who, body)
    assert (r.status_code, _code(r)) == LOCKED
    _pin(db)
    r = _put(who, body)
    assert r.status_code == 200, r.get_data(as_text=True)
    row = db.get_user('pat')
    assert all(row[k] == v for k, v in body.items())


@pytest.mark.parametrize('role,lock,body', REFUSALS)
def test_each_refusal_is_gone_with_the_guard_taken_out(api, db, monkeypatch, role, lock, body):
    """Remove only the check in users.py: the refused requests go through. So it is that
    check, not the CSRF gate, the auth or a bad value, that answers UI_LOCKED."""
    import pegaprox.api.users as users_api
    _pin(db, *lock)
    who = api.as_user(_person(db, 'pat', role=role, layout='classic', language='fr'))
    monkeypatch.setattr(users_api, 'ui_lock_holds', lambda role, lock: False)
    r = _put(who, body)
    assert r.status_code == 200, r.get_data(as_text=True)


def test_the_admin_exemption_is_the_flags(api, db):
    """The admin that goes through with admins off is refused with it on, nothing else changed."""
    root = api.as_user(_person(db, 'root', role='admin'))
    _pin(db, 'corporate', 'en', admins=False)
    assert _put(root, {'ui_layout': 'modern'}).status_code == 200
    _pin(db, 'corporate', 'en', admins=True)
    assert _code(_put(root, {'ui_layout': 'cloud'})) == 'UI_LOCKED'


# --- the helpers on their own ----------------------------------------------------------------

def test_the_languages_are_the_ones_the_ui_ships():
    """A language added to contexts.js is one the lock can pin, and the lock pins none the UI
    does not ship."""
    import os
    import re
    from pegaprox.api.helpers import UI_LANGUAGE_LOCKS
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, 'web', 'src', 'contexts.js'), encoding='utf-8') as fh:
        found = re.search(r"SUPPORTED_LANGS = \[([^\]]*)\]", fh.read())
    assert found
    assert set(re.findall(r"'(\w+)'", found.group(1))) == set(UI_LANGUAGE_LOCKS)


def test_ui_lock_holds():
    from pegaprox.api.helpers import ui_lock_holds
    off = {'layout': '', 'language': '', 'admins': True}
    on = {'layout': 'modern', 'language': '', 'admins': False}
    assert not ui_lock_holds('user', off)
    assert ui_lock_holds('user', on) and ui_lock_holds('viewer', on) and ui_lock_holds(None, on)
    assert not ui_lock_holds('admin', on)
    assert ui_lock_holds('admin', dict(on, admins=True))
