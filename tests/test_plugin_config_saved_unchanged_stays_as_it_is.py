"""Saving what the plugin config editor showed leaves config.json as it is.

The editor shows config.json masked and indented its own way, and saving that text
rewrote the file: every shipped config.json came back formatted anew although no value
had changed. A save that changes no value now leaves the file as it is, for each
config.json we ship, with its credentials filled in or blank, and for nested and list
shapes, and the handles the editor showed still hold after it. The notification
plugin's own config route keeps every value the same way. MK Nov 2026
"""
import glob
import importlib.util
import json
import os
import stat

import flask
import pytest

import pegaprox.api.plugins as plugins_api

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHIPPED = sorted(glob.glob(os.path.join(ROOT, 'plugins', '*', 'config.json')))
URLS = ['tgram://111111:AAH-fill-0f3/987654', 'discord://112233/fill-token-c4e1']


def _filled(obj, secret=False):
    """obj with a value in every credential the shipped file leaves blank."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            s = secret or plugins_api._is_secret_name(k)
            if s and v == '':
                v = f'fill-{k}-7c1e'
            elif s and v == []:
                v = list(URLS)
            out[k] = _filled(v, s)
        return out
    if isinstance(obj, list):
        return [_filled(x, secret) for x in obj]
    return obj


SHAPES = {
    'nested': {
        'title': 'Alerts', 'tokens': {'slack': 'xoxb-1', 'teams': {'bot': 'tb-2', 'ids': [3, 4.5]}},
        'targets': [{'name': 'ops', 'url': 'https://ops.example', 'token': 'tk-ops', 'port': 443},
                    {'id': 7, 'host': 'dev.example', 'password': 'pw-dev', 'tags': ['a', 'b']},
                    {'url': 'https://anon.example', 'api_key': 99}],
        'smtp': {'host': 'mx.example', 'port': 25, 'user': 'ops', 'smtpPass': 'sp-3', 'tls': True},
        'empty': {}, 'nothing': None, 'blank_token': '',
    },
    'same names': {'targets': [{'name': 'a', 'token': 'T1'}, {'name': 'a', 'token': 'T2'},
                               {'name': True, 'token': 'T3'}, {'name': 1, 'token': 'T4'}]},
    'mixed list': {'secrets': ['a', 1, 2.5, True, None, '', {'k': 'v', 'n': 5}, ['x', 3, ['y']], 'a', 1]},
    'lists of lists': {'api_keys': [['k1', 'k2'], ['k1'], []], 'plain': [[1, 2], ['x']]},
    'named secret entries': {'credentials': [{'name': 'ops', 'password': 'p1'}, {'label': 'dev', 'password': 'p2'},
                                             {'id': 3, 'password': 'p3'}, {'name': 'ops', 'password': 'p4'}]},
    'lists in entries': {'targets': [{'name': 'a', 'tokens': ['x', 'y', 'x']}, {'name': 'b', 'tokens': ['x']},
                                     {'tokens': [7, 'x']}]},
    'masks stored': {'banner': '*' * 20, 'note': '********', 'list': ['********', 'a ******** b'],
                     'token': '********', 'apprise_urls': ['tgram://********', URLS[0]]},
    'unicode': {'title': 'Grüße', 'password': 'pässwörd-☃', 'apprise_urls': ['mailto://ü:ß@x.example']},
    'logins': {'database_url': 'postgres://u:pw-1@db.example/x', 'brokers': ['amqp://u:pw-2@b.example//', 'x'],
               'conn_str': 'Server=db;Password={a;b}};', 'options': 'uid=u;pwd=pw-3'},
    'top level list': [{'name': 'ops', 'token': 'tk-1'}, {'name': 'dev', 'token': 'tk-2'}, 'plain'],
    'top level number': 42,
}


@pytest.fixture
def admin(api, seed, tmp_path, monkeypatch):
    monkeypatch.setattr(plugins_api, 'PLUGINS_DIR', str(tmp_path))
    client = api.as_user(seed.user('root', role='admin'))
    client.dir = tmp_path
    return client


def _round_trip(client, pid, content):
    """Write content as config.json, open it in the editor and save it unchanged."""
    (client.dir / pid).mkdir(exist_ok=True)
    path = client.dir / pid / 'config.json'
    path.write_bytes(content)
    r = client.get(f'/api/plugins/{pid}/config')
    assert r.status_code == 200, r.get_data(as_text=True)
    shown = r.get_json()['config']
    for text in (shown, json.dumps(json.loads(shown), indent=4, ensure_ascii=False)):    # the page re-indents it
        r = client.put(f'/api/plugins/{pid}/config', json={'config': text})
        assert r.status_code == 200, r.get_data(as_text=True)
        assert path.read_bytes() == content
    return json.loads(shown)


@pytest.mark.parametrize('path', SHIPPED, ids=[os.path.basename(os.path.dirname(p)) for p in SHIPPED])
def test_a_shipped_config_saved_unchanged_stays_as_it_is(admin, path):
    with open(path, 'rb') as f:
        content = f.read()
    _round_trip(admin, os.path.basename(os.path.dirname(path)), content)

    filled = _filled(json.loads(content))
    shown = _round_trip(admin, 'filled', json.dumps(filled, indent=2).encode())
    for s in ['-7c1e', 'AAH-fill', 'fill-token']:    # a handle is hex, so the marks hold a dash
        assert s not in json.dumps(shown)


@pytest.mark.parametrize('name', list(SHAPES))
def test_a_nested_or_list_shape_saved_unchanged_stays_as_it_is(admin, name):
    _round_trip(admin, 'demo', json.dumps(SHAPES[name], indent=1, ensure_ascii=name != 'unicode').encode())


def test_an_unchanged_save_still_makes_the_file_the_owners_alone(admin):
    with open(SHIPPED[0], 'rb') as f:
        content = f.read()
    (admin.dir / 'demo').mkdir()
    path = admin.dir / 'demo' / 'config.json'
    path.write_bytes(content)
    os.chmod(path, 0o644)
    shown = admin.get('/api/plugins/demo/config').get_json()['config']
    assert admin.put('/api/plugins/demo/config', json={'config': shown}).status_code == 200
    assert path.read_bytes() == content and stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_an_unchanged_save_keeps_the_handles_the_editor_showed(admin):
    (admin.dir / 'demo').mkdir()
    path = admin.dir / 'demo' / 'config.json'
    path.write_text(json.dumps({'apprise_urls': URLS, 'title': 'a'}))
    shown = json.loads(admin.get('/api/plugins/demo/config').get_json()['config'])
    assert admin.put('/api/plugins/demo/config', json={'config': json.dumps(shown)}).status_code == 200
    # nothing was written, so a second save from the same editor still finds the urls
    edited = dict(shown, apprise_urls=shown['apprise_urls'][::-1], title='b')
    r = admin.put('/api/plugins/demo/config', json={'config': json.dumps(edited)})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert json.loads(path.read_text()) == {'apprise_urls': URLS[::-1], 'title': 'b'}


def test_a_changed_value_is_still_written(admin):
    _round_trip(admin, 'demo', json.dumps(SHAPES['nested']).encode())
    shown = json.loads(admin.get('/api/plugins/demo/config').get_json()['config'])
    shown['title'] = 'Alerts 2'
    assert admin.put('/api/plugins/demo/config', json={'config': json.dumps(shown)}).status_code == 200
    assert json.loads((admin.dir / 'demo' / 'config.json').read_text()) == dict(SHAPES['nested'], title='Alerts 2')


@pytest.fixture
def plugin(db, tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location(
        'notifications_round_trip_under_test', os.path.join(ROOT, 'plugins', 'notifications', '__init__.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    monkeypatch.setattr(mod, 'PLUGIN_DIR', str(tmp_path))
    monkeypatch.setattr(mod, '_require_admin', lambda: None)    # the admin gate has tests of its own
    mod.app = flask.Flask('notifications-round-trip-test')
    return mod


@pytest.mark.parametrize('fill', [False, True])
def test_the_plugin_route_saves_its_shipped_config_unchanged(plugin, fill):
    with open(os.path.join(ROOT, 'plugins', 'notifications', 'config.json')) as f:
        cfg = json.load(f)
    if fill:
        cfg = _filled(cfg)
    with open(os.path.join(plugin.PLUGIN_DIR, 'config.json'), 'w') as f:
        json.dump(cfg, f, indent=4)
    with plugin.app.test_request_context('/'):
        shown = plugin._get_config()
    with plugin.app.test_request_context('/', method='POST', json=shown):
        assert plugin._update_config() == {'success': True}
    # the route writes the file each time, every value as it was
    with open(os.path.join(plugin.PLUGIN_DIR, 'config.json')) as f:
        assert json.load(f) == cfg
