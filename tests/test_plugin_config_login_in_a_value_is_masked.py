"""The login inside a url or a connection string goes out masked in the plugin config editor.

database_url, a broker or redis url or an https_proxy stand under an address name, so the
editor showed them as stored, user and password included, and the Password= or
AccountKey= of a connection string as well. Their login shows masked now, with the
scheme and the host left to read, and the stored value comes back when the masked one
does. A masked login left on another host is refused, and a connection string is an
address the secrets next to it go to. Text with a key= but no ; is no connection string.
The notification plugin's own config route masks a login in ntfy_url the same way.
MK Nov 2026
"""
import importlib.util
import json
import os
import re

import flask
import pytest

import pegaprox.api.plugins as plugins_api

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

LOGINS = {
    'database_url': ('postgres://app:zz-pg-1@db.example:5432/app', 'postgres://********@db.example:5432/app'),
    'redis_url': ('redis://:zz-redis-2@kv.example:6379/0', 'redis://********@kv.example:6379/0'),
    'broker_url': ('amqp://app:zz-amqp-3@mq.example//', 'amqp://********@mq.example//'),
    'mongodb_uri': ('mongodb://app:zz-mongo-4@m1.example,m2.example/app',
                    'mongodb://********@m1.example,m2.example/app'),
    'https_proxy': ('http://proxy:zz-proxy-5@p.example:3128', 'http://********@p.example:3128'),
    'connection_string': ('Server=tcp:db.example,1433;Database=app;User Id=app;Password=zz-mssql-6;',
                          'Server=tcp:db.example,1433;Database=app;User Id=app;Password=********;'),
    'conn_str': ('DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=zz-azure-7==;'
                 'EndpointSuffix=core.windows.net',
                 'DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=********;'
                 'EndpointSuffix=core.windows.net'),
    'odbcConnStr': ('DRIVER={ODBC Driver 18};SERVER=db.example;UID=app;PWD={zz-odbc;8}',
                    'DRIVER={ODBC Driver 18};SERVER=db.example;UID=app;PWD=********'),
    'sql_conn_str': ('server=db.example;uid=app;pwd=zz-pwd-9', 'server=db.example;uid=app;pwd=********'),
    # a / in the password, a space before the scheme, a : in the key
    'pg_url': ('postgresql://app:zz-pg/12@db.example/app', 'postgresql://********@db.example/app'),
    'spaced_url': (' postgres://app:zz-pg-13@db.example/app', ' postgres://********@db.example/app'),
    'odbc': ('Driver={SQL};Server=db.example;Jet OLEDB:Database Password=zz-jet-14',
             'Driver={SQL};Server=db.example;Jet OLEDB:Database Password=********'),
}


@pytest.fixture
def admin(api, seed, tmp_path, monkeypatch):
    monkeypatch.setattr(plugins_api, 'PLUGINS_DIR', str(tmp_path))
    (tmp_path / 'demo').mkdir()
    client = api.as_user(seed.user('root', role='admin'))
    client.path = tmp_path / 'demo' / 'config.json'
    return client


def _store(client, cfg):
    client.path.write_text(json.dumps(cfg))


def _stored(client):
    return json.loads(client.path.read_text())


def _shown(client):
    r = client.get('/api/plugins/demo/config')
    assert r.status_code == 200, r.get_data(as_text=True)
    text = r.get_json()['config']
    assert 'zz-' not in text, text
    return json.loads(text)


def _save(client, cfg):
    return client.put('/api/plugins/demo/config', json={'config': json.dumps(cfg)})


def test_the_login_of_a_url_or_a_connection_string_is_masked(admin):
    cfg = {name: stored for name, (stored, _) in LOGINS.items()}
    _store(admin, cfg)
    assert _shown(admin) == {name: shown for name, (_, shown) in LOGINS.items()}


@pytest.mark.parametrize('name', list(LOGINS))
def test_its_mask_comes_back_as_the_stored_value_and_a_typed_one_is_taken(admin, name):
    stored, _ = LOGINS[name]
    _store(admin, {name: stored, 'title': 'db'})
    shown = _shown(admin)
    shown['title'] = 'db 2'
    assert _save(admin, shown).status_code == 200
    assert _stored(admin) == {name: stored, 'title': 'db 2'}
    typed = stored.replace('db.example', 'db2.example').replace('zz-', 'new-')
    assert _save(admin, dict(shown, **{name: typed})).status_code == 200
    assert _stored(admin) == {name: typed, 'title': 'db 2'}


@pytest.mark.parametrize('name', ['database_url', 'https_proxy', 'connection_string', 'odbcConnStr'])
def test_a_masked_login_left_on_another_host_is_refused(admin, name):
    stored, shown_as = LOGINS[name]
    _store(admin, {name: stored})
    host = re.search(r'[a-z0-9]+\.example', shown_as).group(0)
    r = _save(admin, {name: shown_as.replace(host, 'elsewhere.example')})
    assert r.status_code == 400 and r.get_json()['code'] == 'CREDENTIAL_REQUIRED', r.get_data(as_text=True)
    assert r.get_json()['fields'] == [name]
    assert _stored(admin) == {name: stored}


def test_a_connection_string_is_an_address_for_the_secrets_next_to_it(admin):
    cfg = {'connection_string': LOGINS['connection_string'][0], 'api_token': 'zz-tok-10'}
    _store(admin, cfg)
    shown = _shown(admin)
    shown['connection_string'] = 'Server=tcp:elsewhere.example,1433;Database=app;User Id=app;Password=new-1;'
    r = _save(admin, shown)
    assert r.status_code == 400 and r.get_json()['fields'] == ['api_token'], r.get_data(as_text=True)
    assert 'connection_string' in r.get_json()['error']
    assert _stored(admin) == cfg


def test_a_url_takes_its_login_to_its_own_host_and_a_bare_login_stays_with_the_server(admin):
    cfg = {'host': 'a.example', 'db': LOGINS['database_url'][0], 'options': 'uid=app;pwd=zz-opt-11'}
    _store(admin, cfg)
    shown = _shown(admin)
    assert shown['db'] == LOGINS['database_url'][1] and shown['options'] == 'uid=app;pwd=********'
    shown['host'] = 'b.example'
    # the url names the host its login is for, the options name none
    r = _save(admin, shown)
    assert r.status_code == 400 and r.get_json()['fields'] == ['options'], r.get_data(as_text=True)
    shown['options'] = 'uid=app;pwd=new-2'
    assert _save(admin, shown).status_code == 200
    assert _stored(admin) == dict(cfg, host='b.example', options='uid=app;pwd=new-2')


def test_urls_with_a_login_in_a_list_carry_handles_of_their_own(admin):
    a, b = 'amqp://app:zz-b1@b1.example//', 'amqp://app:zz-b2@b2.example//'
    _store(admin, {'brokers': [a, b, 'amqp://b3.example//']})
    shown = _shown(admin)['brokers']
    assert re.fullmatch(r'amqp://\*{8}@b1\.example//#[0-9a-f]{32}', shown[0])
    assert shown[2] == 'amqp://b3.example//'
    assert _save(admin, {'brokers': shown[1:]}).status_code == 200
    assert _stored(admin) == {'brokers': [b, 'amqp://b3.example//']}
    shown = _shown(admin)['brokers']
    assert _save(admin, {'brokers': shown[::-1]}).status_code == 200
    assert _stored(admin) == {'brokers': ['amqp://b3.example//', b]}


def test_a_value_with_neither_shows_as_it_is(admin):
    cfg = {'url': 'https://a.example/path@x', 'note': 'a=b;c=d', 'query': 'https://h.example/x?page=2',
           'db': 'postgres://db.example/app', 'empty': 'Password=;Server=x'}
    _store(admin, cfg)
    assert _shown(admin) == cfg


def test_text_with_a_key_but_no_semicolon_is_no_connection_string(admin):
    cfg = {'help': 'set key=foo to enable', 'host': 'a.example', 'password': 'zz-help-15'}
    _store(admin, cfg)
    shown = _shown(admin)
    assert shown['help'] == 'set key=foo to enable'
    # and it is no secret that would have to be typed again for a new host
    shown.update(host='b.example', password='new-15')
    r = _save(admin, shown)
    assert r.status_code == 200, r.get_data(as_text=True)
    assert _stored(admin) == dict(cfg, host='b.example', password='new-15')


def test_a_stored_login_that_holds_the_mask_is_never_taken_as_typed(admin):
    stored = 'postgres://app:zz********@db.example/app'
    _store(admin, {'db': stored, 'note': 'a ******** b'})
    # the editor never shows it, so whether a save of it is taken says nothing about what is stored
    r = _save(admin, {'db': stored, 'note': 'a ******** b'})
    assert r.status_code == 400 and r.get_json()['fields'] == ['db'], r.get_data(as_text=True)
    shown = _shown(admin)
    assert shown == {'db': 'postgres://********@db.example/app', 'note': 'a ******** b'}
    assert _save(admin, shown).status_code == 200
    assert _stored(admin) == {'db': stored, 'note': 'a ******** b'}


# ---- the notification plugin's own config route ----

NTFY = {'ntfy_enabled': True, 'ntfy_url': 'https://ops:zz-ntfy-16@n1.example', 'ntfy_topic': 'ops',
        'ntfy_token': '', 'apprise_enabled': False, 'apprise_urls': []}


@pytest.fixture
def plugin(db, tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location(
        'notifications_login_under_test', os.path.join(ROOT, 'plugins', 'notifications', '__init__.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    monkeypatch.setattr(mod, 'PLUGIN_DIR', str(tmp_path))
    monkeypatch.setattr(mod, '_require_admin', lambda: None)    # the admin gate has tests of its own
    (tmp_path / 'config.json').write_text(json.dumps(NTFY))
    mod.app = flask.Flask('notifications-login-test')
    return mod


def _route(mod, fn, body=None):
    with mod.app.test_request_context('/', method='POST', json=body):
        return getattr(mod, fn)()


def _plugin_stored(mod):
    with open(os.path.join(mod.PLUGIN_DIR, 'config.json')) as f:
        return json.load(f)


def test_the_plugin_route_shows_the_login_in_ntfy_url_masked(plugin):
    cfg = _route(plugin, '_get_config')
    assert cfg['ntfy_url'] == 'https://********@n1.example' and 'zz-' not in json.dumps(cfg)
    # sent back, it keeps the stored url
    assert _route(plugin, '_update_config', dict(cfg, ntfy_topic='ops-2')) == {'success': True}
    assert _plugin_stored(plugin) == dict(NTFY, ntfy_topic='ops-2')
    # and one typed anew is taken
    assert _route(plugin, '_update_config', {'ntfy_url': 'https://ops:new-16@n1.example'}) == {'success': True}
    assert _plugin_stored(plugin)['ntfy_url'] == 'https://ops:new-16@n1.example'


@pytest.mark.parametrize('sent', ['https://********@e2.example', 'https://********@n1.example/x',
                                  'https://********'])
def test_a_masked_ntfy_login_left_on_another_url_is_refused(plugin, sent):
    res = _route(plugin, '_update_config', {'ntfy_url': sent})
    assert isinstance(res, tuple) and res[1] == 400, res
    assert res[0]['code'] == 'CREDENTIAL_REQUIRED' and res[0]['fields'] == ['ntfy_url']
    assert _plugin_stored(plugin) == NTFY
