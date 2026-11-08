"""Broadcast banners (api/banners.py).

An admin writes a message in the settings, every signed-in user it is meant for reads it
from /api/banners: to everyone, to some tenants or to some roles, until it runs out. The
text is plain, one line, at most 500 characters. The list is a server setting, so it
reaches a standby with the sync; there it is shown and not written. Only an admin.settings
holder who is not limited to a tenant or to specific clusters writes or lists them.

Driven through the real Flask app (conftest `api`, `seed`).
MK
"""
from datetime import datetime, timedelta, timezone

import pytest

from pegaprox.api import banners as bmod

ADMIN_LIST = '/api/settings/banners'
MINE = '/api/banners'


def _root(api, seed, name='root'):
    return api.as_user(seed.user(name, role='admin'))


def _iso(delta):
    return (datetime.now(timezone.utc) + delta).strftime('%Y-%m-%dT%H:%M:%SZ')


def _make(client, **kw):
    body = {'text': 'Maintenance tonight at 22:00', 'severity': 'warning'}
    body.update(kw)
    r = client.post(ADMIN_LIST, json=body)
    assert r.status_code == 201, r.data
    return r.get_json()['banner']


def _mine(client, headers=None):
    r = client.get(MINE, headers=headers)
    assert r.status_code == 200, r.data
    return r.get_json()['banners']


def _stored(db):
    return db.get_server_setting(bmod.BANNERS_KEY, None)


def _audit(db, prefix='settings.banner_'):
    return [r['action'] for r in (db.query('SELECT action FROM audit_log ORDER BY id') or [])
            if r['action'].startswith(prefix)]


# -- the main scenario -------------------------------------------------------------------------

def test_an_admin_writes_it_and_every_signed_in_user_reads_it(api, seed):
    admin = _root(api, seed)
    banner = _make(admin)
    assert banner['rev'] == 1 and banner['scope'] == 'everyone' and banner['expired'] is False
    assert len(banner['id']) == 16

    for name, role in (('watcher', 'viewer'), ('ops', 'user'), ('root2', 'admin')):
        mine = _mine(api.as_user(seed.user(name, role=role)))
        assert mine == [{'id': banner['id'], 'text': 'Maintenance tonight at 22:00', 'severity': 'warning',
                         'rev': 1, 'expires_at': None, 'expires_in': None}], name
    # signed in only
    assert api.anon().get(MINE).status_code == 401
    assert _audit(seed.db) == ['settings.banner_created']


def test_nothing_stored_reads_as_no_banners(api, seed):
    assert _mine(api.as_user(seed.user('watcher', role='viewer'))) == []


def test_a_changed_text_is_a_new_revision_the_rest_is_not(api, seed):
    admin = _root(api, seed)
    b = _make(admin)
    r = admin.put(f'{ADMIN_LIST}/{b["id"]}', json={'severity': 'critical'})
    assert r.status_code == 200, r.data
    assert r.get_json()['changed'] == ['severity'] and r.get_json()['banner']['rev'] == 1
    r = admin.put(f'{ADMIN_LIST}/{b["id"]}', json={'text': 'Maintenance moved to 23:00'})
    assert r.get_json()['changed'] == ['text'] and r.get_json()['banner']['rev'] == 2
    # the same again changes nothing and writes no audit line
    r = admin.put(f'{ADMIN_LIST}/{b["id"]}', json={'text': 'Maintenance moved to 23:00'})
    assert r.get_json()['changed'] == [] and r.get_json()['banner']['rev'] == 2
    mine = _mine(api.as_user(seed.user('watcher', role='viewer')))
    assert [(m['text'], m['severity'], m['rev']) for m in mine] == [('Maintenance moved to 23:00', 'critical', 2)]
    assert _audit(seed.db) == ['settings.banner_created', 'settings.banner_updated', 'settings.banner_updated']

    assert admin.delete(f'{ADMIN_LIST}/{b["id"]}').status_code == 200
    assert _mine(api.as_user(seed.user('ops', role='user'))) == []
    assert _audit(seed.db)[-1] == 'settings.banner_deleted'
    assert admin.delete(f'{ADMIN_LIST}/{b["id"]}').status_code == 404
    assert admin.put(f'{ADMIN_LIST}/{b["id"]}', json={'text': 'x'}).status_code == 404
    assert admin.put(f'{ADMIN_LIST}/not-an-id', json={'text': 'x'}).status_code == 404


def test_critical_first_and_the_newest_first_within_a_severity(api, seed):
    admin = _root(api, seed)
    a = _make(admin, text='info one', severity='info')
    b = _make(admin, text='critical one', severity='critical')
    c = _make(admin, text='info two', severity='info')
    d = _make(admin, text='warning one', severity='warning')
    order = [m['id'] for m in _mine(api.as_user(seed.user('watcher', role='viewer')))]
    assert order == [b['id'], d['id'], c['id'], a['id']]


# -- scope -------------------------------------------------------------------------------------

def test_a_tenant_banner_reaches_that_tenant_only(api, seed):
    from pegaprox.utils import rbac
    seed.tenant('acme', ['cluster_acme'])
    seed.tenant('globex', ['cluster_globex'])
    rbac.save_custom_roles({'global': {}, 'tenants': {'acme': {'acme_ops': {'name': 'Acme ops',
                                                                             'permissions': ['vm.view']}}}})
    rbac.invalidate_roles_cache()
    admin = _root(api, seed)
    b = _make(admin, text='Acme maintenance', scope='tenants', tenants=['acme'])
    assert b['tenants'] == ['acme'] and b['roles'] == []

    sees = {
        'acme user': seed.user('a1', role='user', tenant_id='acme'),
        'acme viewer': seed.user('a2', role='viewer', tenant_id='acme'),
        # a tenant role held from the default tenant puts the account in that tenant
        'acme role from default': seed.user('a3', role='acme_ops'),
    }
    blind = {
        'globex user': api.as_user(seed.user('g1', role='user', tenant_id='globex')),
        'default user': api.as_user(seed.user('d1', role='user')),
        # the admin who wrote it is no acme user either
        'admin': admin,
    }
    for name, user in sees.items():
        assert [m['id'] for m in _mine(api.as_user(user))] == [b['id']], name
    for name, client in blind.items():
        assert _mine(client) == [], name
    # the admin list still has it
    assert [x['id'] for x in admin.get(ADMIN_LIST).get_json()['banners']] == [b['id']]


def test_a_role_banner_goes_by_the_role_the_caller_acts_with(api, seed):
    from pegaprox.utils.auth import create_api_token
    admin = _root(api, seed)
    b = _make(admin, text='Viewers: read-only window', scope='roles', roles=['viewer'])
    assert _mine(api.as_user(seed.user('watcher', role='viewer'))) != []
    assert _mine(api.as_user(seed.user('ops', role='user'))) == []
    assert _mine(admin) == []
    # an admin lowered to viewer where they live acts as a viewer
    lowered = seed.user('lowered', role='admin', tenant_permissions={'default': {'role': 'viewer'}})
    assert [m['id'] for m in _mine(api.as_user(lowered))] == [b['id']]
    # an admin's viewer token too, while the admin's own session does not
    res = create_api_token('root', 'ci', role='viewer')
    assert res.get('success'), res
    via_token = {'Authorization': f"Bearer {res['token']}"}
    assert [m['id'] for m in _mine(api.anon(), headers=via_token)] == [b['id']]


def test_unknown_or_missing_targets_are_refused(api, seed):
    seed.tenant('acme', [])
    admin = _root(api, seed)
    for body, status in (
            ({'scope': 'tenants', 'tenants': []}, 400),
            ({'scope': 'tenants'}, 400),
            ({'scope': 'tenants', 'tenants': ['nope']}, 400),
            ({'scope': 'tenants', 'tenants': 'acme'}, 400),
            ({'scope': 'tenants', 'tenants': ['acme\n']}, 400),
            ({'scope': 'roles', 'roles': []}, 400),
            ({'scope': 'roles', 'roles': ['no_such_role']}, 400),
            ({'scope': 'cluster'}, 400),
            ({'severity': 'fatal'}, 400),
            ({'scope': 'tenants', 'tenants': [f't{i}' for i in range(51)]}, 400)):
        r = admin.post(ADMIN_LIST, json=dict({'text': 'hello'}, **body))
        assert r.status_code == status, (body, r.data)
    assert _stored(seed.db) is None
    assert admin.post(ADMIN_LIST, json={'text': 'hello', 'scope': 'tenants', 'tenants': ['acme']}).status_code == 201
    assert admin.post(ADMIN_LIST, json={'text': 'hello', 'scope': 'roles', 'roles': ['user', 'viewer']}).status_code == 201


# -- expiry ------------------------------------------------------------------------------------

def test_it_runs_out_at_its_expiry(api, seed, monkeypatch):
    admin = _root(api, seed)
    b = _make(admin, expires_at=_iso(timedelta(hours=2)))
    mine = _mine(api.as_user(seed.user('watcher', role='viewer')))
    assert mine[0]['expires_at'] == b['expires_at'] and 7100 < mine[0]['expires_in'] <= 7200

    later = datetime.now(timezone.utc) + timedelta(hours=3)
    monkeypatch.setattr(bmod, '_now', lambda: later.replace(microsecond=0))
    assert _mine(api.as_user(seed.user('ops', role='user'))) == []
    listed = admin.get(ADMIN_LIST).get_json()['banners']
    assert [(x['id'], x['expired']) for x in listed] == [(b['id'], True)]
    # its text can still be edited, it stays out until the expiry moves
    r = admin.put(f'{ADMIN_LIST}/{b["id"]}', json={'text': 'still over'})
    assert r.status_code == 200 and r.get_json()['banner']['expired'] is True
    r = admin.put(f'{ADMIN_LIST}/{b["id"]}', json={'expires_at': _iso(timedelta(hours=1))})
    assert r.status_code == 400, r.data   # an hour from now is two hours ago at "later"
    r = admin.put(f'{ADMIN_LIST}/{b["id"]}', json={'expires_at': ''})
    assert r.status_code == 200 and r.get_json()['banner']['expired'] is False
    assert len(_mine(api.as_user(seed.user('ops', role='user')))) == 1


@pytest.mark.parametrize('value', ['a minute ago', '2026-10-06T18:00:00', 'tomorrow', 42, True,
                                   '2026-13-01T00:00:00Z'])
def test_an_expiry_that_is_past_or_not_a_time_with_a_zone_is_refused(api, seed, value):
    # the id stays the same on every xdist worker, the time is taken here
    if value == 'a minute ago':
        value = _iso(-timedelta(minutes=1))
    r = _root(api, seed).post(ADMIN_LIST, json={'text': 'hello', 'expires_at': value})
    assert r.status_code == 400, (value, r.data)
    assert _stored(seed.db) is None


def test_an_expiry_in_another_zone_is_kept_in_utc(api, seed):
    at = datetime.now(timezone(timedelta(hours=2))) + timedelta(days=1)
    b = _make(_root(api, seed), expires_at=at.isoformat())
    assert b['expires_at'] == at.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


# -- the text ------------------------------------------------------------------------------------

def test_the_text_is_one_line_of_plain_text(api, seed):
    admin = _root(api, seed)
    b = _make(admin, text='  <b>Bold</b>\n\tnext‮line\x00\x07 &amp; ⁦more⁩  ')
    # markup is kept as the characters it is, the browser shows it as text
    assert b['text'] == '<b>Bold</b> nextline &amp; more'
    assert _mine(api.as_user(seed.user('watcher', role='viewer')))[0]['text'] == b['text']
    assert admin.post(ADMIN_LIST, json={'text': 'x' * 500}).status_code == 201
    r = admin.post(ADMIN_LIST, json={'text': 'x' * 501})
    assert r.status_code == 400 and b'500' in r.data
    for empty in ('', '   ', '‮\n', None, 42, ['x']):
        assert admin.post(ADMIN_LIST, json={'text': empty}).status_code == 400, empty


def test_at_most_twenty(api, seed):
    admin = _root(api, seed)
    for i in range(bmod.MAX_BANNERS):
        _make(admin, text=f'banner {i}')
    r = admin.post(ADMIN_LIST, json={'text': 'one too many'})
    assert r.status_code == 409, r.data
    assert len(_stored(seed.db)) == bmod.MAX_BANNERS


def test_what_does_not_read_as_a_banner_is_shown_to_nobody(api, seed):
    good = {'id': 'a' * 16, 'text': 'fine', 'severity': 'info', 'scope': 'everyone', 'tenants': [],
            'roles': [], 'expires_at': None, 'rev': 1}
    seed.db.save_server_setting(bmod.BANNERS_KEY, [
        good,
        dict(good, id='b' * 16, scope='tenants', tenants='default'),      # not a list
        dict(good, id='c' * 16, scope='tenants', tenants=[]),             # names nobody
        dict(good, id='d' * 16, severity='<script>'),
        dict(good, id='e' * 16, expires_at='soon'),                        # unreadable: over
        dict(good, id='f' * 16, rev=0),
        dict(good, id='nope'),
        'text only',
    ])
    assert [m['id'] for m in _mine(api.as_user(seed.user('watcher', role='viewer')))] == ['a' * 16]
    seed.db.save_server_setting(bmod.BANNERS_KEY, {'not': 'a list'})
    assert _mine(api.as_user(seed.user('ops', role='user'))) == []


# -- who writes ------------------------------------------------------------------------------------

@pytest.mark.parametrize('kind', ['viewer', 'user', 'confined_settings_admin', 'pool_user', 'capped_admin',
                                  'capped_default_admin', 'admins_viewer_token'])
def test_below_an_unconfined_settings_admin_nothing_is_listed_or_changed(api, seed, kind):
    seed.tenant('globex', ['cluster_globex'])
    admin = _root(api, seed)
    b = _make(admin, text='Globex only', scope='tenants', tenants=['globex'])
    before = _stored(seed.db)
    headers = None
    if kind == 'viewer':
        c = api.as_user(seed.user('watcher', role='viewer'))
    elif kind == 'user':
        c = api.as_user(seed.user('ops', role='user'))
    elif kind == 'confined_settings_admin':
        # holds the permission, in a tenant of its own: may not write, not even for that tenant
        c = api.as_user(seed.user('gxadmin', role='user', tenant_id='globex',
                                  permissions=['admin.settings', 'admin.users']))
    elif kind == 'pool_user':
        seed.pool('cluster_globex', 'pool1', 'pooled', ['vm.view'])
        c = api.as_user(seed.user('pooled', role='viewer', tenant_id='globex'))
    elif kind == 'capped_admin':
        c = api.as_user(seed.user('gx', role='admin', tenant_id='globex',
                                  tenant_permissions={'globex': {'role': 'user'}}))
    elif kind == 'capped_default_admin':
        c = api.as_user(seed.user('lowered', role='admin',
                                  tenant_permissions={'default': {'role': 'viewer'}}))
    else:
        from pegaprox.utils.auth import create_api_token
        res = create_api_token('root', 'ci', role='viewer')
        assert res.get('success'), res
        c, headers = api.anon(), {'Authorization': f"Bearer {res['token']}"}

    for method, path, body in (('get', ADMIN_LIST, None),
                               ('post', ADMIN_LIST, {'text': 'mine', 'scope': 'tenants', 'tenants': ['globex']}),
                               ('put', f'{ADMIN_LIST}/{b["id"]}', {'text': 'changed'}),
                               ('delete', f'{ADMIN_LIST}/{b["id"]}', None)):
        kw = {'headers': headers} if headers else {}
        if body is not None:
            kw['json'] = body
        r = getattr(c, method)(path, **kw)
        assert r.status_code == 403, (kind, method, path, r.status_code, r.data)
    assert _stored(seed.db) == before
    if kind == 'confined_settings_admin':
        r = c.get(ADMIN_LIST)
        assert b'not limited' in r.data, r.data     # our gate, not the permission check
        # nor through the settings route the permission opens
        r = c.get('/api/settings/server')
        assert r.status_code == 200 and bmod.BANNERS_KEY not in r.get_json()


def test_a_settings_admin_who_sees_everything_writes_them(api, seed):
    """Counterproof for the gate above: the bar is the scope, not the admin role."""
    c = api.as_user(seed.user('delegate', role='user', permissions=['admin.settings']))
    assert c.post(ADMIN_LIST, json={'text': 'from the delegate'}).status_code == 201
    assert c.get(ADMIN_LIST).status_code == 200
    assert _audit(seed.db) == ['settings.banner_created']


def test_the_admin_list_offers_the_tenants_and_roles(api, seed):
    from pegaprox.utils import rbac
    seed.tenant('acme', [])
    rbac.save_custom_roles({'global': {'auditor': {'name': 'Auditor', 'permissions': ['vm.view']}},
                            'tenants': {'acme': {'acme_ops': {'name': 'Acme ops', 'permissions': []}}}})
    rbac.invalidate_roles_cache()
    data = _root(api, seed).get(ADMIN_LIST).get_json()
    assert {'id': 'acme', 'name': 'acme'} in data['choices']['tenants']
    roles = {r['id']: r for r in data['choices']['roles']}
    assert [r['id'] for r in data['choices']['roles']][:3] == ['admin', 'user', 'viewer']
    assert roles['auditor'] == {'id': 'auditor', 'name': 'Auditor', 'tenants': []}
    assert roles['acme_ops'] == {'id': 'acme_ops', 'name': 'Acme ops', 'tenants': ['acme']}
    assert data['limits'] == {'text': 500, 'count': 20, 'targets': 50}


# -- stored with the settings ----------------------------------------------------------------------

def test_a_save_of_the_whole_settings_leaves_them_alone(api, seed):
    """The ACME request and the server form save back every setting they read. A list read
    before a banner was added must not put the banner away again."""
    from pegaprox.api.helpers import load_server_settings, save_server_settings
    admin = _root(api, seed)
    stale = load_server_settings()
    b = _make(admin)
    assert save_server_settings(stale) is True
    assert [x['id'] for x in _stored(seed.db)] == [b['id']]
    stale[bmod.BANNERS_KEY] = []
    save_server_settings(stale)
    assert [x['id'] for x in _stored(seed.db)] == [b['id']]
    # the form neither shows nor takes them
    assert bmod.BANNERS_KEY not in admin.get('/api/settings/server').get_json()
    r = admin.post('/api/settings/server', json={bmod.BANNERS_KEY: [], 'session_timeout': 3600})
    assert r.status_code == 200, r.data
    assert [x['id'] for x in _stored(seed.db)] == [b['id']]


def test_they_travel_with_the_sync():
    from pegaprox.core import ha
    assert 'server_settings' in ha.SYNC_TABLES
    assert not ha._is_local_setting(bmod.BANNERS_KEY)


def test_a_standby_shows_them_and_neither_writes_nor_forwards_a_change(api, seed, monkeypatch):
    from pegaprox.core import ha
    import pegaprox.api.ha as ha_api
    admin = _root(api, seed)
    b = _make(admin)
    before = _stored(seed.db)

    forwarded = []

    def forward(read=False):
        from flask import jsonify, request
        forwarded.append((request.method, request.path))
        return jsonify({'success': True})
    monkeypatch.setattr(ha, 'is_standby', lambda: True)
    monkeypatch.setattr(ha_api, 'forward_to_active', forward)

    assert [m['id'] for m in _mine(api.as_user(seed.user('watcher', role='viewer')))] == [b['id']]
    assert admin.get(ADMIN_LIST).status_code == 200
    for method, path, body in (('post', ADMIN_LIST, {'text': 'from the standby'}),
                               ('put', f'{ADMIN_LIST}/{b["id"]}', {'text': 'changed'}),
                               ('delete', f'{ADMIN_LIST}/{b["id"]}', None)):
        kw = {'json': body} if body is not None else {}
        r = getattr(admin, method)(path, **kw)
        assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY', (method, r.data)
    assert forwarded == []
    assert _stored(seed.db) == before
    # counterproof: a forwarding standby hands other writes on
    assert admin.put('/api/user/preferences', json={'theme': 'nord'}).status_code == 200
    assert forwarded == [('PUT', '/api/user/preferences')]
