"""The push notification plugin hands its ntfy token and apprise urls out masked.

GET .../notifications/api/config returned both as stored, and an apprise url carries
the login of its service (a Telegram bot token, a Discord webhook token, a mail
password). They are write-only now, like the SMTP password in the settings: the route
shows the scheme, and a masked value sent back keeps what is stored. The file holding
them is written for the owner only. MK Nov 2026
"""
import importlib.util
import json
import os
import stat

import flask
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOKEN = 'tk_7d1f0c5e9b2a'
TG = 'tgram://123456:AAH-bot-token-0f3/987654'
DISCORD = 'discord://112233/webhook-token-c4e1'


@pytest.fixture
def plugin(tmp_path, monkeypatch):
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
    assert cfg['apprise_urls'] == ['tgram://********', 'discord://********']
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
    _update(plugin, {'ntfy_token': 'tk_new', 'apprise_urls': ['tgram://********', 'gotify://host/new']})
    stored = _stored(plugin)
    assert stored['ntfy_token'] == 'tk_new'
    assert stored['apprise_urls'] == [TG, 'gotify://host/new']


def test_a_masked_url_that_matches_nothing_is_not_saved_as_a_target(plugin):
    _update(plugin, {'apprise_urls': ['discord://********', 'mailto://********']})
    # the first place held the tgram url, so neither masked entry names a stored one
    assert _stored(plugin)['apprise_urls'] == []


def test_the_file_is_the_owners_alone(plugin):
    path = os.path.join(plugin.PLUGIN_DIR, 'config.json')
    os.chmod(path, 0o644)
    _update(plugin, {'ntfy_topic': 'ops'})
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
