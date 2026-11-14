"""The push notification plugin hands its ntfy token and apprise urls out masked.

GET .../notifications/api/config returned both as stored, and an apprise url carries
the login of its service (a Telegram bot token, a Discord webhook token, a mail
password). They are write-only now, like the SMTP password in the settings: the route
shows the scheme, and a masked value sent back keeps what is stored. Each url shows a
handle of its own, new on every read, and a mask that names no stored url is refused.
Whether a handle finds its url never depends on how many copies of it are stored, and
a handle holds until config.json is written again, from this route or from the config
editor. The file holding them is written for the owner only. MK Nov 2026
"""
import importlib.util
import hmac
import json
import os
import re
import stat
import types

import flask
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOKEN = 'tk_7d1f0c5e9b2a'
TG = 'tgram://123456:AAH-bot-token-0f3/987654'
DISCORD = 'discord://112233/webhook-token-c4e1'


@pytest.fixture
def plugin(db, tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location(
        'notifications_plugin_under_test', os.path.join(ROOT, 'plugins', 'notifications', '__init__.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    monkeypatch.setattr(mod, 'PLUGIN_DIR', str(tmp_path))
    monkeypatch.setattr(mod, '_require_admin', lambda: None)    # the admin gate has tests of its own
    (tmp_path / 'config.json').write_text(json.dumps({
        'ntfy_enabled': True, 'ntfy_url': 'https://ntfy.example', 'ntfy_topic': 'ops',
        'ntfy_token': TOKEN, 'apprise_enabled': True, 'apprise_urls': [TG, DISCORD]}))
    mod.app = flask.Flask('notifications-test')
    return mod


def _get(mod):
    with mod.app.test_request_context('/'):
        return mod._get_config()


def _update(mod, body):
    with mod.app.test_request_context('/', method='POST', json=body):
        return mod._update_config()


def _stored(mod):
    with open(os.path.join(mod.PLUGIN_DIR, 'config.json')) as f:
        return json.load(f)


def test_the_config_route_shows_neither_the_token_nor_the_urls(plugin):
    cfg = _get(plugin)
    text = json.dumps(cfg)
    assert TOKEN not in text and 'AAH-bot-token' not in text and 'webhook-token' not in text, text
    assert cfg['ntfy_token'] == '********'
    tg, dc = cfg['apprise_urls']
    assert re.fullmatch(r'tgram://\*{8}#[0-9a-f]{32}', tg) and re.fullmatch(r'discord://\*{8}#[0-9a-f]{32}', dc)
    # what is no credential is still there to edit
    assert cfg['ntfy_topic'] == 'ops' and cfg['ntfy_url'] == 'https://ntfy.example'


def test_saving_the_masked_form_back_keeps_what_is_stored(plugin):
    cfg = _get(plugin)
    cfg['ntfy_topic'] = 'ops-2'
    assert _update(plugin, cfg) == {'success': True}
    stored = _stored(plugin)
    assert stored['ntfy_token'] == TOKEN
    assert stored['apprise_urls'] == [TG, DISCORD]
    assert stored['ntfy_topic'] == 'ops-2'


def test_a_new_value_replaces_the_stored_one_and_a_dropped_url_goes(plugin):
    tg, _ = _get(plugin)['apprise_urls']
    _update(plugin, {'ntfy_token': 'tk_new', 'apprise_urls': [tg, 'gotify://host/new']})
    stored = _stored(plugin)
    assert stored['ntfy_token'] == 'tk_new'
    assert stored['apprise_urls'] == [TG, 'gotify://host/new']


@pytest.mark.parametrize('extra', ['discord://********', 'tgram://********#0000000000000000deadbeefdeadbeef'])
def test_a_masked_url_that_matches_nothing_is_refused(plugin, extra):
    tg, dc = _get(plugin)['apprise_urls']
    res = _update(plugin, {'apprise_urls': [dc, extra]})
    # without a handle the route gave out, a mask names no stored url: it is neither
    # saved as a target nor are the stored urls dropped
    assert isinstance(res, tuple) and res[1] == 400, res
    assert res[0]['code'] == 'CREDENTIAL_REQUIRED' and res[0]['fields'] == ['apprise_urls[1]']
    assert _stored(plugin)['apprise_urls'] == [TG, DISCORD]


def test_a_handle_from_before_the_url_changed_is_refused(plugin):
    stale = _get(plugin)['apprise_urls']
    _update(plugin, {'apprise_urls': [stale[0], 'gotify://host/new']})    # another tab
    res = _update(plugin, {'apprise_urls': stale})
    # that write ends both handles, the one whose url is still stored too
    assert isinstance(res, tuple) and res[0]['fields'] == ['apprise_urls[0]', 'apprise_urls[1]']
    assert _stored(plugin)['apprise_urls'] == [TG, 'gotify://host/new']


def test_a_typed_copy_of_a_stored_url_never_shows_its_handle(plugin):
    tg, dc = _get(plugin)['apprise_urls']
    assert _update(plugin, {'apprise_urls': [tg, dc, TG]}) == {'success': True}
    shown = _get(plugin)['apprise_urls']
    assert len(set(shown)) == 3 and tg not in shown
    # and every read gives new handles that still find their urls
    assert _update(plugin, {'apprise_urls': shown[::-1]}) == {'success': True}
    assert _stored(plugin)['apprise_urls'] == [TG, DISCORD, TG]


def test_a_handle_the_config_editor_showed_finds_its_url_here(plugin):
    import pegaprox.api.plugins as plugins_api
    with open(os.path.join(plugin.PLUGIN_DIR, 'config.json')) as f:
        cfg = json.load(f)
    shown = plugins_api._masked_config(cfg, 'notifications')['apprise_urls']
    assert _update(plugin, {'apprise_urls': shown[1:]}) == {'success': True}
    assert _stored(plugin)['apprise_urls'] == [DISCORD]
    # one the editor showed for another plugin finds nothing here
    other = plugins_api._masked_config(cfg, 'status_page')['apprise_urls']
    res = _update(plugin, {'apprise_urls': other[1:]})
    assert isinstance(res, tuple) and res[0]['fields'] == ['apprise_urls[0]']
    assert _stored(plugin)['apprise_urls'] == [DISCORD]


def test_deleting_the_first_of_two_bots_keeps_the_second(plugin):
    bot_b = 'tgram://222222:AAH-bot-b-7c1/987654'
    _update(plugin, {'apprise_urls': [TG, bot_b, DISCORD]})
    shown = _get(plugin)['apprise_urls']
    assert len(set(shown)) == 3
    _update(plugin, {'apprise_urls': shown[1:]})
    assert _stored(plugin)['apprise_urls'] == [bot_b, DISCORD]
    _update(plugin, {'apprise_urls': _get(plugin)['apprise_urls'][::-1]})
    assert _stored(plugin)['apprise_urls'] == [DISCORD, bot_b]


def test_deleting_the_first_of_two_services_keeps_the_other(plugin):
    _update(plugin, {'apprise_urls': _get(plugin)['apprise_urls'][1:]})
    assert _stored(plugin)['apprise_urls'] == [DISCORD]


@pytest.mark.parametrize('content', ['[1, 2]', '42', '"tgram://123456:AAH-bot-token-0f3/987654"'])
def test_a_config_that_is_no_object_reads_and_saves(plugin, content):
    with open(os.path.join(plugin.PLUGIN_DIR, 'config.json'), 'w') as f:
        f.write(content)
    cfg = _get(plugin)
    assert 'AAH-bot-token' not in json.dumps(cfg)
    assert _update(plugin, {'ntfy_topic': 'ops'}) == {'success': True}
    assert _stored(plugin)['ntfy_topic'] == 'ops'


def test_an_entry_that_is_no_url_comes_back_by_its_handle(plugin):
    odd = [5, None, {'x': 1}, ['y']]
    assert _update(plugin, {'apprise_urls': odd}) == {'success': True}
    assert _update(plugin, {'apprise_urls': _get(plugin)['apprise_urls']}) == {'success': True}
    assert _stored(plugin)['apprise_urls'] == odd
    # the null one too, wherever it sits now
    assert _update(plugin, {'apprise_urls': _get(plugin)['apprise_urls'][::-1]}) == {'success': True}
    assert _stored(plugin)['apprise_urls'] == odd[::-1]


def test_the_file_is_the_owners_alone(plugin):
    path = os.path.join(plugin.PLUGIN_DIR, 'config.json')
    os.chmod(path, 0o644)
    _update(plugin, {'ntfy_topic': 'ops'})
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_equal_urls_show_handles_of_their_own(plugin):
    _update(plugin, {'apprise_urls': [TG, TG, DISCORD]})
    shown = _get(plugin)['apprise_urls']
    assert len(set(shown)) == 3
    assert _update(plugin, {'apprise_urls': shown[1:]}) == {'success': True}
    assert _stored(plugin)['apprise_urls'] == [TG, DISCORD]


def test_an_update_goes_through_a_long_list_once(plugin, monkeypatch):
    urls = [f'tgram://{i}:AAH-bot-{i}/1' for i in range(300)]
    _update(plugin, {'apprise_urls': urls})
    shown = _get(plugin)['apprise_urls']
    calls = []
    monkeypatch.setattr(plugin, 'hmac', types.SimpleNamespace(
        new=lambda *a, **kw: calls.append(1) or hmac.new(*a, **kw), compare_digest=hmac.compare_digest))
    # one print for each stored url and one pad for each handle
    assert _update(plugin, {'apprise_urls': shown[::-1]}) == {'success': True}
    assert _stored(plugin)['apprise_urls'] == urls[::-1] and len(calls) <= 2 * len(urls)
    shown = _get(plugin)['apprise_urls']
    calls.clear()
    forged = [f'tgram://********#{i:016x}{"0" * 16}' for i in range(300)]
    assert _update(plugin, {'apprise_urls': forged + shown})[1] == 400
    assert len(calls) <= 3 * len(urls)


def _guess_then_an_old_handle(mod, guess):
    with open(os.path.join(mod.PLUGIN_DIR, 'config.json'), 'w') as f:
        json.dump({'apprise_enabled': True, 'apprise_urls': [TG]}, f)
    h = _get(mod)['apprise_urls'][0]
    assert _update(mod, {'apprise_urls': [h, h]}) == {'success': True}
    a0, a1 = _get(mod)['apprise_urls']
    assert _update(mod, {'apprise_urls': [a0, guess, DISCORD]}) == {'success': True}
    first = _update(mod, {'apprise_urls': [a0, a1]})
    assert _update(mod, {'apprise_urls': [guess]}) == {'success': True}
    second = _update(mod, {'apprise_urls': [h]})
    return first, second, _stored(mod)['apprise_urls']


def test_whether_a_guess_is_right_never_changes_the_answer(plugin):
    wrong = _guess_then_an_old_handle(plugin, 'tgram://123456:AAH-bot-token-0f2/987654')
    right = _guess_then_an_old_handle(plugin, TG)
    # a handle read before a write finds nothing after it, whatever the write held
    for res in wrong[:2] + right[:2]:
        assert isinstance(res, tuple) and res[1] == 400 and res[0]['code'] == 'CREDENTIAL_REQUIRED', res
    assert [r[0]['fields'] for r in wrong[:2]] == [r[0]['fields'] for r in right[:2]]
    assert right[2] == [TG]


def test_a_write_from_the_config_editor_ends_the_handles_given_out_here(plugin, api, seed, tmp_path, monkeypatch):
    import pegaprox.api.plugins as plugins_api
    (tmp_path / 'notifications').mkdir()
    os.replace(tmp_path / 'config.json', tmp_path / 'notifications' / 'config.json')
    monkeypatch.setattr(plugin, 'PLUGIN_DIR', str(tmp_path / 'notifications'))
    monkeypatch.setattr(plugins_api, 'PLUGINS_DIR', str(tmp_path))
    stale = _get(plugin)['apprise_urls']
    editor = api.as_user(seed.user('root', role='admin'))
    r = editor.put('/api/plugins/notifications/config',
                   json={'config': json.dumps(dict(_stored(plugin), ntfy_topic='ops-2'))})
    assert r.status_code == 200, r.get_data(as_text=True)
    res = _update(plugin, {'apprise_urls': stale[1:]})
    assert isinstance(res, tuple) and res[0]['fields'] == ['apprise_urls[0]'], res
    assert _stored(plugin)['apprise_urls'] == [TG, DISCORD]
    # and a write here ends the ones the editor showed
    shown = json.loads(editor.get('/api/plugins/notifications/config').get_json()['config'])
    assert _update(plugin, {'ntfy_topic': 'ops-3'}) == {'success': True}
    r = editor.put('/api/plugins/notifications/config', json={'config': json.dumps(dict(shown, ntfy_topic='ops-4'))})
    assert r.status_code == 400 and r.get_json()['fields'] == ['apprise_urls[0]', 'apprise_urls[1]']
    assert _stored(plugin)['ntfy_topic'] == 'ops-3'
