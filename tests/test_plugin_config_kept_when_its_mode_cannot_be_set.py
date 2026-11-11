"""A plugin config.json keeps its content when its mode cannot be set.

Both writers opened config.json with O_TRUNC and set the mode after, so a file of
another owner, where fchmod fails with EPERM, was left empty. The mode is set first now:
EPERM is logged and the new content written, any other error leaves the file as it was.
MK Nov 2026
"""
import errno
import importlib.util
import json
import os

import flask
import pytest

import pegaprox.api.plugins as plugins_api

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BEFORE = {'ntfy_enabled': False, 'ntfy_url': 'https://ntfy.example', 'ntfy_topic': 'ops',
          'ntfy_token': '', 'apprise_enabled': False, 'apprise_urls': []}


@pytest.fixture
def fchmod_fails(monkeypatch):
    """fchmod on a config.json fails with the errno set on the fixture."""
    real = os.fchmod
    state = {'errno': errno.EPERM}

    def fake(fd, mode):
        if os.readlink(f'/proc/self/fd/{fd}').endswith('config.json'):
            raise OSError(state['errno'], os.strerror(state['errno']))
        return real(fd, mode)

    monkeypatch.setattr(os, 'fchmod', fake)
    return state


@pytest.fixture
def admin(api, seed, tmp_path, monkeypatch):
    monkeypatch.setattr(plugins_api, 'PLUGINS_DIR', str(tmp_path))
    (tmp_path / 'notifications').mkdir()
    client = api.as_user(seed.user('root', role='admin'))
    client.path = tmp_path / 'notifications' / 'config.json'
    client.path.write_text(json.dumps(BEFORE))
    return client


@pytest.fixture
def plugin(db, tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location(
        'notifications_mode_under_test', os.path.join(ROOT, 'plugins', 'notifications', '__init__.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    monkeypatch.setattr(mod, 'PLUGIN_DIR', str(tmp_path))
    monkeypatch.setattr(mod, '_require_admin', lambda: None)
    (tmp_path / 'config.json').write_text(json.dumps(BEFORE))
    mod.app = flask.Flask('notifications-mode-test')
    mod.path = tmp_path / 'config.json'
    return mod


def _update(mod, body):
    with mod.app.test_request_context('/', method='POST', json=body):
        return mod._update_config()


def test_the_editor_writes_a_file_of_another_owner(admin, fchmod_fails):
    raw = json.dumps(dict(BEFORE, ntfy_topic='ops-2'), indent=2)
    r = admin.put('/api/plugins/notifications/config', json={'config': raw})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert admin.path.read_text() == raw


def test_the_editor_leaves_the_file_as_it_was_on_another_error(admin, fchmod_fails):
    fchmod_fails['errno'] = errno.EIO
    r = admin.put('/api/plugins/notifications/config', json={'config': json.dumps({'ntfy_topic': 'x'})})
    assert r.status_code == 500
    assert json.loads(admin.path.read_text()) == BEFORE


def test_a_shorter_config_leaves_nothing_of_the_longer_one(admin):
    r = admin.put('/api/plugins/notifications/config', json={'config': '{"a": 1}'})
    assert r.status_code == 200
    assert admin.path.read_text() == '{"a": 1}'


def test_the_route_writes_a_file_of_another_owner(plugin, fchmod_fails):
    assert _update(plugin, {'ntfy_topic': 'ops-2'}) == {'success': True}
    assert json.loads(plugin.path.read_text()) == dict(BEFORE, ntfy_topic='ops-2')


def test_the_route_leaves_the_file_as_it_was_on_another_error(plugin, fchmod_fails):
    fchmod_fails['errno'] = errno.EIO
    with pytest.raises(OSError):
        _update(plugin, {'ntfy_topic': 'ops-2'})
    assert json.loads(plugin.path.read_text()) == BEFORE
