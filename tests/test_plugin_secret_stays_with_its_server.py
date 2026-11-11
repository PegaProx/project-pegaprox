"""A stored plugin secret is kept only for the server it was typed for.

Both the config editor in the settings and the notification plugin's own config route
kept a masked token while the same save pointed ntfy_url somewhere else, and the next
alert posted "Bearer <token>" to the new server. A save that changes a url, host,
server, endpoint or port in the object of a secret it keeps masked, or in an object
below that one, or that puts a new one into a list there, is refused with
CREDENTIAL_REQUIRED now and writes nothing, as the SMTP and LDAP settings do. A url
counts under any plain name, a flag, a count or a label under an address word does not,
and a secret kept in a list of its own, or in an entry without an address, goes to the
addresses next to that list. MK Nov 2026
"""
import importlib.util
import json
import os

import flask
import pytest

import pegaprox.api.plugins as plugins_api

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOKEN = 'tk_7d1f0c5e9b2a'
TG = 'tgram://123456:AAH-bot-token-0f3/987654'
NOTIFY = {'ntfy_enabled': True, 'ntfy_url': 'https://ntfy.example', 'ntfy_topic': 'ops',
          'ntfy_token': TOKEN, 'apprise_enabled': True, 'apprise_urls': [TG]}


# ---- the config editor in the settings ----

@pytest.fixture
def admin(api, seed, tmp_path, monkeypatch):
    monkeypatch.setattr(plugins_api, 'PLUGINS_DIR', str(tmp_path))
    (tmp_path / 'notifications').mkdir()
    (tmp_path / 'notifications' / 'config.json').write_text(json.dumps(NOTIFY))
    client = api.as_user(seed.user('root', role='admin'))
    client.path = tmp_path / 'notifications' / 'config.json'
    return client


def _shown(client):
    return json.loads(client.get('/api/plugins/notifications/config').get_json()['config'])


def _save(client, cfg):
    return client.put('/api/plugins/notifications/config', json={'config': json.dumps(cfg)})


def _refused(r, client):
    assert r.status_code == 400, r.get_data(as_text=True)
    assert r.get_json()['code'] == 'CREDENTIAL_REQUIRED'
    assert json.loads(client.path.read_text()) == NOTIFY


def test_the_editor_keeps_no_token_for_another_server(admin):
    shown = _shown(admin)
    shown['ntfy_url'] = 'https://ntfy.other.example'
    r = _save(admin, shown)
    _refused(r, admin)
    assert r.get_json()['fields'] == ['ntfy_token'] and 'ntfy_url' in r.get_json()['error']


def test_the_editor_keeps_no_token_when_the_server_goes(admin):
    shown = _shown(admin)
    del shown['ntfy_url']    # the plugin falls back to ntfy.sh
    _refused(_save(admin, shown), admin)


def test_the_editor_refuses_a_moved_target_inside_a_list(admin):
    cfg = {'targets': [{'name': 'ops', 'host': 'ops.example', 'password': 'pw-ops-51a0'}]}
    admin.path.write_text(json.dumps(cfg))
    shown = _shown(admin)
    shown['targets'][0]['host'] = 'elsewhere.example'
    r = _save(admin, shown)
    assert r.status_code == 400 and r.get_json()['code'] == 'CREDENTIAL_REQUIRED'
    assert r.get_json()['fields'] == ['targets[0].password']
    assert json.loads(admin.path.read_text()) == cfg


@pytest.mark.parametrize('cfg, change, fields', [
    ({'target': {'url': 'https://a.example'}, 'auth': {'token': 'tk-sibling-1'}},
     ('target', 'url'), ['auth.token']),
    ({'connection': {'host': 'db.example', 'port': 5432}, 'credentials': {'api_key': 'k-sibling-2'}},
     ('connection', 'host'), ['credentials.api_key']),
    ({'connection': {'host': 'db.example', 'port': 5432}, 'credentials': {'api_key': 'k-sibling-3'}},
     ('connection', 'port'), ['credentials.api_key']),
])
def test_the_editor_keeps_no_secret_for_a_server_in_another_object(admin, cfg, change, fields):
    admin.path.write_text(json.dumps(cfg))
    shown = _shown(admin)
    obj, k = change
    shown[obj][k] = 6432 if k == 'port' else 'elsewhere.example'
    r = _save(admin, shown)
    assert r.status_code == 400 and r.get_json()['code'] == 'CREDENTIAL_REQUIRED', r.get_data(as_text=True)
    assert r.get_json()['fields'] == fields and f'{obj}.{k}' in r.get_json()['error']
    assert json.loads(admin.path.read_text()) == cfg


@pytest.mark.parametrize('name, value, moved', [
    ('port', 25, 2525), ('smtp_port', 25, 2525), ('ntfy_uri', 'https://a.example', 'https://b.example'),
    ('domain', 'a.example', 'b.example'), ('address', '10.0.0.1', '10.0.0.2'), ('ip', '10.0.0.1', '10.0.0.2'),
    ('proxy', 'http://p1:3128', 'http://p2:3128'), ('auth_server', 'idp-a', 'idp-b'), ('smtpHost', 'mx-a', 'mx-b'),
    ('redis_addr', '10.0.0.1:6379', '10.0.0.2:6379'), ('listen_addr', '0.0.0.0', '10.0.0.2'),
    ('mqtt_broker', 'mq-a', 'mq-b'), ('sms_gateway', 'gw-a', 'gw-b'), ('relay', 'relay-a', 'relay-b'),
    ('api_base', 'https://a.example/v1', 'https://b.example/v1'),
])
def test_every_kind_of_address_counts(admin, name, value, moved):
    cfg = {'smtp': {name: value, 'password': 'pw-addr-71c2'}}
    admin.path.write_text(json.dumps(cfg))
    shown = _shown(admin)
    assert shown['smtp'][name] == value    # an address shows in clear
    shown['smtp'][name] = moved
    r = _save(admin, shown)
    assert r.status_code == 400 and r.get_json()['fields'] == ['smtp.password'], r.get_data(as_text=True)
    assert json.loads(admin.path.read_text()) == cfg


# a secret word keeps these masked, and each is an address all the same
SECRET_ADDRESSES = ('token_url', 'bot_token_url', 'push_token_url', 'secret_url', 'api_key_url', 'key_url',
                    'password_url', 'token_endpoint', 'token_uri', 'private_key_url', 'key_server',
                    'secret_host', 'api_key_host', 'passWordUrl')


@pytest.mark.parametrize('name', SECRET_ADDRESSES)
def test_a_secret_under_an_address_name_counts_as_an_address(admin, name):
    cfg = {'oauth': {name: 'https://a.example/zz-1', 'client_secret': 'zz-2', 'client_id': 'pp'}}
    admin.path.write_text(json.dumps(cfg))
    shown = _shown(admin)
    assert shown['oauth'] == {name: 'https://********', 'client_secret': '********', 'client_id': 'pp'}
    # its mask back keeps it, next to the secret it goes with
    shown['oauth']['client_id'] = 'pp2'
    assert _save(admin, shown).status_code == 200
    assert json.loads(admin.path.read_text()) == {'oauth': dict(cfg['oauth'], client_id='pp2')}
    # one typed over it is an address that changed
    shown = _shown(admin)
    shown['oauth'][name] = 'https://b.example/zz-3'
    r = _save(admin, shown)
    assert r.status_code == 400 and r.get_json()['fields'] == ['oauth.client_secret'], r.get_data(as_text=True)
    assert f'oauth.{name}' in r.get_json()['error']
    shown['oauth']['client_secret'] = 'zz-4'
    assert _save(admin, shown).status_code == 200
    assert json.loads(admin.path.read_text()) == {'oauth': {name: 'https://b.example/zz-3',
                                                            'client_secret': 'zz-4', 'client_id': 'pp2'}}


def test_a_secret_under_an_address_name_carries_its_own_address(admin):
    cfg = {'host': 'a.example', 'key_server': 'ks.example', 'token_url': 'https://idp.example/t',
           'password': 'zz-pw'}
    admin.path.write_text(json.dumps(cfg))
    shown = _shown(admin)
    shown.update(host='b.example', password='zz-pw-2')
    assert _save(admin, shown).status_code == 200, 'a kept key_server still goes to the key server it names'
    assert json.loads(admin.path.read_text()) == dict(cfg, host='b.example', password='zz-pw-2')


def _set(obj, path, value):
    for k in path[:-1]:
        obj = obj[k]
    if path[-1] == '+':
        obj.append(value)
    else:
        obj[path[-1]] = value


@pytest.mark.parametrize('cfg, change, fields, moved', [
    ({'api_token': 'tk-list-1', 'targets': [{'url': 'https://a.example'}]},
     (('targets', 0, 'url'), 'https://elsewhere.example'), ['api_token'], 'targets[].url'),
    ({'bearer': 'tk-list-2', 'instances': [{'name': 'x', 'host': 'a.example'}]},
     (('instances', 0, 'host'), 'elsewhere.example'), ['bearer'], 'instances[].host'),
    ({'token': 'tk-list-3', 'sites': [{'endpoint': 'https://a.example'}]},
     (('sites', '+'), {'endpoint': 'https://elsewhere.example'}), ['token'], 'sites[].endpoint'),
    ({'token': 'tk-list-4', 'targets': ['https://a.example']},
     (('targets', 0), 'https://elsewhere.example'), ['token'], 'targets[]'),
    ({'token': 'tk-list-5', 'targets': ['https://a.example']},
     (('targets', '+'), 'https://elsewhere.example'), ['token'], 'targets[]'),
    ({'auth': {'token': 'tk-list-6'}, 'pools': [{'members': [{'addr': '10.0.0.1'}]}]},
     (('pools', 0, 'members', 0, 'addr'), '10.0.0.9'), ['auth.token'], 'pools[].members[].addr'),
    ({'targets': [{'name': 'a', 'token': 'tk-list-7', 'mirrors': [{'url': 'https://m.example'}]}]},
     (('targets', 0, 'mirrors', '+'), {'url': 'https://elsewhere.example'}), ['targets[0].token'],
     'targets[0].mirrors[].url'),
    ({'api_keys': ['tk-list-8'], 'targets': [{'url': 'https://a.example'}]},
     (('targets', 0, 'url'), 'https://elsewhere.example'), ['api_keys[0]'], 'targets[].url'),
    ({'api_keys': ['tk-list-9'], 'targets': ['https://a.example']},
     (('targets', 0), 'https://elsewhere.example'), ['api_keys[0]'], 'targets[]'),
    ({'tokens': [['tk-list-10']], 'mirrors': [{'url': 'https://m.example'}]},
     (('mirrors', 0, 'url'), 'https://elsewhere.example'), ['tokens[0][0]'], 'mirrors[].url'),
    ({'api_keys': [{'name': 'ci', 'secret': 'tk-list-11'}], 'targets': [{'url': 'https://a.example'}]},
     (('targets', 0, 'url'), 'https://elsewhere.example'), ['api_keys[0].secret'], 'targets[].url'),
    ({'logins': [{'user': 'u', 'password': 'pw-list-12'}], 'targets': ['https://a.example']},
     (('targets', 0), 'https://elsewhere.example'), ['logins[0].password'], 'targets[]'),
    ({'targets': [{'name': 'auth', 'token': 'tk-list-13'}, {'name': 'srv', 'url': 'https://a.example'}]},
     (('targets', 1, 'url'), 'https://elsewhere.example'), ['targets[0].token'], 'targets[].url'),
], ids=['url in a list entry', 'host in a list entry', 'an entry added', 'a url entry changed',
        'a url entry added', 'deeper lists', 'a list in a list entry', 'a secret list and a url in an entry',
        'a secret list and a url entry', 'a list of secret lists', 'a named key and a url in an entry',
        'a login list and a url entry', 'a token entry next to a server entry'])
def test_the_editor_keeps_no_secret_for_a_server_inside_a_list(admin, cfg, change, fields, moved):
    admin.path.write_text(json.dumps(cfg))
    shown = _shown(admin)
    _set(shown, *change)
    r = _save(admin, shown)
    assert r.status_code == 400 and r.get_json()['code'] == 'CREDENTIAL_REQUIRED', r.get_data(as_text=True)
    assert r.get_json()['fields'] == fields and moved in r.get_json()['error']
    assert json.loads(admin.path.read_text()) == cfg


@pytest.mark.parametrize('edit', ['delete', 'reorder', 'rename', 'copy a stored address', 'own token'])
def test_a_list_of_servers_still_edits_around_a_kept_secret(admin, edit):
    cfg = {'api_token': 'tk-list-ok',
           'targets': [{'name': 'a', 'url': 'https://a.example'}, {'name': 'b', 'url': 'https://b.example'}],
           'mirrors': ['https://m1.example', 'https://m2.example'],
           'peers': [{'name': 'p1', 'url': 'https://p1.example', 'token': 'tk-p1'}]}
    admin.path.write_text(json.dumps(cfg))
    shown = _shown(admin)
    if edit == 'delete':
        shown.update(targets=shown['targets'][1:], mirrors=shown['mirrors'][1:])
    elif edit == 'reorder':
        shown.update(targets=shown['targets'][::-1], mirrors=shown['mirrors'][::-1])
    elif edit == 'rename':
        shown['targets'][0]['name'] = 'a2'
    elif edit == 'copy a stored address':
        shown['targets'][1]['url'] = 'https://a.example'
        shown['mirrors'].append('https://m1.example')
    else:
        # an entry with a token of its own saves once the shared token is typed again too
        shown['api_token'] = 'tk-list-new'
        shown['peers'].append({'name': 'p2', 'url': 'https://p2.example', 'token': 'tk-p2'})
    r = _save(admin, shown)
    assert r.status_code == 200, r.get_data(as_text=True)
    stored = json.loads(admin.path.read_text())
    want = json.loads(json.dumps(shown))
    want.setdefault('api_token', 'tk-list-ok')
    if want['api_token'] == '********':
        want['api_token'] = 'tk-list-ok'
    want['peers'][0]['token'] = 'tk-p1'
    assert stored == want


@pytest.mark.parametrize('edit', ['delete', 'reorder', 'copy a stored address'])
def test_a_secret_list_still_edits_around_the_servers_next_to_it(admin, edit):
    cfg = {'api_keys': ['tk-keys-1', 'tk-keys-2'],
           'targets': [{'name': 'a', 'url': 'https://a.example'}, {'name': 'b', 'url': 'https://b.example'}],
           'mirrors': ['https://m1.example', 'https://m2.example']}
    admin.path.write_text(json.dumps(cfg))
    shown = _shown(admin)
    if edit == 'delete':
        shown.update(targets=shown['targets'][1:], mirrors=shown['mirrors'][1:])
    elif edit == 'reorder':
        shown.update(targets=shown['targets'][::-1], mirrors=shown['mirrors'][::-1])
    else:
        shown['targets'][1]['url'] = 'https://a.example'
        shown['mirrors'].append('https://m1.example')
    r = _save(admin, shown)
    assert r.status_code == 200, r.get_data(as_text=True)
    assert json.loads(admin.path.read_text()) == dict(shown, api_keys=cfg['api_keys'])


@pytest.mark.parametrize('cfg, change, fields, moved', [
    ({'oauth': {'issuer': 'https://idp.example', 'client_secret': 'cs-url-1'}},
     (('oauth', 'issuer'), 'https://elsewhere.example'), ['oauth.client_secret'], 'oauth.issuer'),
    ({'api_token': 'tk-url-2', 'target': 'https://a.example'},
     (('target',), 'https://elsewhere.example'), ['api_token'], 'target'),
    ({'access_token': 'tk-url-3', 'instance': 'https://mastodon.example'},
     (('instance',), 'https://elsewhere.example'), ['access_token'], 'instance'),
    ({'api_token': 'tk-url-4', 'targets': [{'name': 'x', 'target': 'https://a.example'}]},
     (('targets', 0, 'target'), 'https://elsewhere.example'), ['api_token'], 'targets[].target'),
], ids=['issuer', 'target', 'instance', 'target in a list entry'])
def test_a_url_under_a_plain_name_is_an_address(admin, cfg, change, fields, moved):
    admin.path.write_text(json.dumps(cfg))
    shown = _shown(admin)
    _set(shown, *change)
    r = _save(admin, shown)
    assert r.status_code == 400 and r.get_json()['code'] == 'CREDENTIAL_REQUIRED', r.get_data(as_text=True)
    assert r.get_json()['fields'] == fields and moved in r.get_json()['error']
    assert json.loads(admin.path.read_text()) == cfg


@pytest.mark.parametrize('cfg, change', [
    ({'api_key': 'k-flag-1', 'show_ip_addresses': True}, {'show_ip_addresses': False}),
    ({'api_key': 'k-flag-2', 'proxy_enabled': True}, {'proxy_enabled': False}),
    ({'token': 'k-flag-3', 'verify_host': True}, {'verify_host': False}),
    ({'api_key': 'k-flag-4', 'url_timeout': 30}, {'url_timeout': 60}),
    ({'api_key': 'k-flag-5', 'max_hosts': 3}, {'max_hosts': 4}),
    ({'api_key': 'k-flag-6', 'server_label': 'Main'}, {'server_label': 'Main 2'}),
    ({'api_key': 'k-flag-7', 'proxy_mode': 'auto'}, {'proxy_mode': 'manual'}),
    ({'api_key': 'k-flag-8', 'host_display_name': 'Prod'}, {'host_display_name': 'Prod 2'}),
], ids=['show_ip_addresses', 'proxy_enabled', 'verify_host', 'url_timeout', 'max_hosts', 'server_label',
        'proxy_mode', 'host_display_name'])
def test_a_flag_a_count_or_a_label_under_an_address_word_moves_freely(admin, cfg, change):
    admin.path.write_text(json.dumps(cfg))
    shown = _shown(admin)
    shown.update(change)
    r = _save(admin, shown)
    assert r.status_code == 200, r.get_data(as_text=True)
    assert json.loads(admin.path.read_text()) == dict(cfg, **change)


def test_a_secret_that_only_looks_like_a_url_stays_with_its_server(admin):
    cfg = {'server': 'https://a.example', 'password': 'Ab://cd-71f0', 'webhook_url': 'https://hooks.example/x9'}
    admin.path.write_text(json.dumps(cfg))
    shown = _shown(admin)
    assert shown['password'] == 'Ab://********'
    shown['server'] = 'https://b.example'
    r = _save(admin, shown)
    assert r.status_code == 400 and r.get_json()['fields'] == ['password', 'webhook_url']
    assert json.loads(admin.path.read_text()) == cfg


def test_a_port_or_a_report_that_is_no_address_moves_freely(admin):
    cfg = {'smtp': {'host': 'mx.example', 'port': 25, 'password': 'pw-free-5b1e', 'report': 'daily',
                    'portal_title': 'Ops', 'description': 'mail'}}
    admin.path.write_text(json.dumps(cfg))
    shown = _shown(admin)
    shown['smtp'].update(report='weekly', portal_title='Ops 2', description='alert mail')
    assert _save(admin, shown).status_code == 200
    assert json.loads(admin.path.read_text())['smtp'] == dict(cfg['smtp'], report='weekly',
                                                              portal_title='Ops 2', description='alert mail')


def test_the_editor_saves_a_new_server_with_a_token_typed_for_it(admin):
    shown = _shown(admin)
    shown.update(ntfy_url='https://ntfy.other.example', ntfy_token='tk_other')
    assert _save(admin, shown).status_code == 200
    stored = json.loads(admin.path.read_text())
    assert stored['ntfy_url'] == 'https://ntfy.other.example' and stored['ntfy_token'] == 'tk_other'
    # the apprise urls carry their own address and stay
    assert stored['apprise_urls'] == [TG]


def test_the_editor_keeps_the_token_while_the_server_stays(admin):
    shown = _shown(admin)
    shown.update(ntfy_topic='ops-2', apprise_urls=shown['apprise_urls'] + ['gotify://host/new'])
    assert _save(admin, shown).status_code == 200
    assert json.loads(admin.path.read_text()) == dict(NOTIFY, ntfy_topic='ops-2',
                                                      apprise_urls=[TG, 'gotify://host/new'])


# ---- the plugin's own config route ----

@pytest.fixture
def plugin(db, tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location(
        'notifications_server_under_test', os.path.join(ROOT, 'plugins', 'notifications', '__init__.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    monkeypatch.setattr(mod, 'PLUGIN_DIR', str(tmp_path))
    monkeypatch.setattr(mod, '_require_admin', lambda: None)    # the admin gate has tests of its own
    (tmp_path / 'config.json').write_text(json.dumps(NOTIFY))
    mod.app = flask.Flask('notifications-server-test')
    return mod


def _update(mod, body):
    with mod.app.test_request_context('/', method='POST', json=body):
        return mod._update_config()


def _stored(mod):
    with open(os.path.join(mod.PLUGIN_DIR, 'config.json')) as f:
        return json.load(f)


@pytest.mark.parametrize('body', [
    {'ntfy_url': 'https://ntfy.other.example', 'ntfy_token': '********'},
    {'ntfy_url': 'https://ntfy.other.example'},
    {'ntfy_url': None, 'ntfy_token': '********'},
])
def test_the_route_keeps_no_token_for_another_server(plugin, body):
    res = _update(plugin, body)
    assert isinstance(res, tuple) and res[1] == 400, res
    assert res[0]['code'] == 'CREDENTIAL_REQUIRED'
    assert _stored(plugin) == NOTIFY


def test_the_route_saves_a_new_server_with_a_token_typed_for_it(plugin):
    assert _update(plugin, {'ntfy_url': 'https://ntfy.other.example', 'ntfy_token': 'tk_other'}) == {'success': True}
    stored = _stored(plugin)
    assert stored['ntfy_url'] == 'https://ntfy.other.example' and stored['ntfy_token'] == 'tk_other'


@pytest.mark.parametrize('body', [
    {'ntfy_url': 'https://ntfy.example/', 'ntfy_token': '********', 'ntfy_topic': 'ops-2'},
    {'ntfy_url': 'https://NTFY.example', 'ntfy_topic': 'ops-2'},
    {'ntfy_topic': 'ops-2'},
])
def test_the_route_keeps_the_token_while_the_server_stays(plugin, body):
    assert _update(plugin, body) == {'success': True}
    stored = _stored(plugin)
    assert stored['ntfy_token'] == TOKEN and stored['ntfy_topic'] == 'ops-2'


def test_a_server_without_a_stored_token_moves_freely(plugin):
    with open(os.path.join(plugin.PLUGIN_DIR, 'config.json'), 'w') as f:
        json.dump(dict(NOTIFY, ntfy_token=''), f)
    assert _update(plugin, {'ntfy_url': 'https://ntfy.other.example'}) == {'success': True}
    assert _stored(plugin)['ntfy_url'] == 'https://ntfy.other.example'


def test_after_a_refused_move_the_next_alert_takes_the_token_to_its_own_server(plugin, monkeypatch):
    import pegaprox.utils.url_security as url_security
    monkeypatch.setattr(url_security, 'resolve_and_pin_url', lambda url, **kw: url)
    monkeypatch.setattr(plugin, '_send_apprise', lambda alert, cfg: (True, None))
    posts = []

    class _Ok:
        status_code = 200

    def post(url, data=None, headers=None, timeout=None):
        posts.append((url, headers.get('Authorization')))
        return _Ok()

    monkeypatch.setattr(plugin.requests, 'post', post)
    _update(plugin, {'ntfy_url': 'https://ntfy.other.example', 'ntfy_token': '********'})
    plugin._notification_handler({'alert_name': 'CPU high', 'severity': 'warning', 'message': 'pve3 at 97%'})
    assert posts == [('https://ntfy.example/ops', f'Bearer {TOKEN}')]
