"""A plugin config.json keeps its content when its mode cannot be set.

Both writers opened config.json with O_TRUNC and set the mode after, so a file of
another owner, where fchmod fails with EPERM, was left empty. Then the mode was set
first, and on EPERM the secrets went into the file with the mode it had. Now the new
content goes to a new file created 0600 beside it, which takes its place: the file is
0600 whoever owned the old one, and an error, a folder PegaProx cannot write to among
them, leaves the old file as it was.
MK Nov 2026
"""
import errno
import importlib.util
import json
import os
import stat

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
def write_fails(monkeypatch):
    """The write of a file beside a config.json fails with EIO, a disk error on the way."""
    real = os.fsync

    def fake(fd):
        folder = os.path.dirname(os.readlink(f'/proc/self/fd/{fd}'))
        if os.path.exists(os.path.join(folder, 'config.json')):
            raise OSError(errno.EIO, os.strerror(errno.EIO))
        return real(fd)

    monkeypatch.setattr(os, 'fsync', fake)


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


def _beside(path):
    """The files a write left next to config.json."""
    return [n for n in os.listdir(path.parent) if n != 'config.json' and (path.parent / n).is_file()]


def _update(mod, body):
    with mod.app.test_request_context('/', method='POST', json=body):
        return mod._update_config()


def test_the_editor_writes_a_file_of_another_owner(admin, fchmod_fails):
    raw = json.dumps(dict(BEFORE, ntfy_topic='ops-2'), indent=2)
    r = admin.put('/api/plugins/notifications/config', json={'config': raw})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert admin.path.read_text() == raw


def test_the_editor_leaves_the_file_as_it_was_on_another_error(admin, write_fails):
    r = admin.put('/api/plugins/notifications/config', json={'config': json.dumps({'ntfy_topic': 'x'})})
    assert r.status_code == 500
    assert json.loads(admin.path.read_text()) == BEFORE
    assert _beside(admin.path) == []


def test_a_shorter_config_leaves_nothing_of_the_longer_one(admin):
    r = admin.put('/api/plugins/notifications/config', json={'config': '{"a": 1}'})
    assert r.status_code == 200
    assert admin.path.read_text() == '{"a": 1}'


def test_the_route_writes_a_file_of_another_owner(plugin, fchmod_fails):
    assert _update(plugin, {'ntfy_topic': 'ops-2'}) == {'success': True}
    assert json.loads(plugin.path.read_text()) == dict(BEFORE, ntfy_topic='ops-2')


def test_the_route_leaves_the_file_as_it_was_on_another_error(plugin, write_fails):
    with pytest.raises(OSError):
        _update(plugin, {'ntfy_topic': 'ops-2'})
    assert json.loads(plugin.path.read_text()) == BEFORE
    assert _beside(plugin.path) == []


# --- the secrets end in a file only the service can read ----------------------------

def _mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def test_the_editor_leaves_a_file_of_another_owner_owner_only(admin, fchmod_fails):
    """Its mode could not be set, and the token went into a file anyone on the host could read."""
    os.chmod(admin.path, 0o664)
    raw = json.dumps(dict(BEFORE, ntfy_token='tk_secret'), indent=2)
    r = admin.put('/api/plugins/notifications/config', json={'config': raw})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert admin.path.read_text() == raw
    assert _mode(admin.path) == 0o600


def test_the_route_leaves_a_file_of_another_owner_owner_only(plugin, fchmod_fails):
    os.chmod(plugin.path, 0o664)
    assert _update(plugin, {'ntfy_token': 'tk_secret'}) == {'success': True}
    assert json.loads(plugin.path.read_text()) == dict(BEFORE, ntfy_token='tk_secret')
    assert _mode(plugin.path) == 0o600


@pytest.fixture
def read_only(request):
    """The folder of config.json, read-only for the duration of a test."""
    if os.geteuid() == 0:
        pytest.skip('root writes to a read-only folder')
    folders = []

    def make(folder):
        os.chmod(folder, 0o555)
        folders.append(folder)
    yield make
    for folder in folders:
        os.chmod(folder, 0o755)


def test_the_editor_says_so_when_the_folder_is_read_only(admin, read_only):
    read_only(admin.path.parent)
    r = admin.put('/api/plugins/notifications/config',
                  json={'config': json.dumps(dict(BEFORE, ntfy_token='tk_secret'))})
    assert r.status_code == 500
    assert 'cannot write to the plugin folder' in r.get_json()['error'], r.get_json()
    assert json.loads(admin.path.read_text()) == BEFORE
    assert _beside(admin.path) == []


def test_the_route_says_so_when_the_folder_is_read_only(plugin, read_only):
    read_only(plugin.path.parent)
    res = _update(plugin, {'ntfy_token': 'tk_secret'})
    assert isinstance(res, tuple) and res[1] == 500, res
    assert 'cannot write to the plugin folder' in res[0]['error'], res
    assert json.loads(plugin.path.read_text()) == BEFORE
    assert _beside(plugin.path) == []


@pytest.fixture
def mounted_alone(monkeypatch):
    """config.json is a mount of its own: a rename onto it fails with EBUSY."""
    real = os.replace

    def fake(src, dst):
        if str(dst).endswith('config.json'):
            raise OSError(errno.EBUSY, os.strerror(errno.EBUSY))
        return real(src, dst)

    monkeypatch.setattr(os, 'replace', fake)


def test_the_editor_says_so_when_config_json_is_mounted_alone(admin, mounted_alone):
    r = admin.put('/api/plugins/notifications/config',
                  json={'config': json.dumps(dict(BEFORE, ntfy_token='tk_secret'))})
    assert r.status_code == 500
    assert 'mount the plugin folder' in r.get_json()['error'], r.get_json()
    assert json.loads(admin.path.read_text()) == BEFORE
    assert _beside(admin.path) == []


def test_the_route_says_so_when_config_json_is_mounted_alone(plugin, mounted_alone):
    res = _update(plugin, {'ntfy_token': 'tk_secret'})
    assert isinstance(res, tuple) and res[1] == 500, res
    assert 'mount the plugin folder' in res[0]['error'], res
    assert json.loads(plugin.path.read_text()) == BEFORE
    assert _beside(plugin.path) == []



@pytest.fixture
def chmod_fails(monkeypatch):
    """chmod of a config.json fails with EPERM, as on a file of another owner. The real
    chmod is handed back, for the mode the file starts with."""
    real = os.chmod

    def fake(path, mode, **kw):
        if str(path).endswith('config.json'):
            raise OSError(errno.EPERM, os.strerror(errno.EPERM))
        return real(path, mode, **kw)

    monkeypatch.setattr(os, 'chmod', fake)
    return real


def test_a_save_that_changes_nothing_leaves_a_file_of_another_owner_owner_only(admin, chmod_fails):
    """The editor's save of what it showed writes nothing and only sets the mode, which
    fails on a file of another owner: the token stayed readable to anyone on the host."""
    before = json.dumps(dict(BEFORE, ntfy_token='tk_secret'))
    admin.path.write_text(before)
    chmod_fails(admin.path, 0o664)
    generation = plugins_api._config_generation('notifications')
    r = admin.put('/api/plugins/notifications/config', json={'config': json.dumps(json.loads(before), indent=2)})
    assert r.status_code == 200, r.get_data(as_text=True)
    # the same text, owner only, and the handles read before it still hold
    assert admin.path.read_text() == before
    assert _mode(admin.path) == 0o600
    assert plugins_api._config_generation('notifications') == generation
    assert _beside(admin.path) == []


def test_a_save_that_changes_nothing_in_a_read_only_folder_still_answers(admin, chmod_fails, read_only):
    chmod_fails(admin.path, 0o664)
    read_only(admin.path.parent)
    r = admin.put('/api/plugins/notifications/config', json={'config': json.dumps(BEFORE, indent=2)})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert json.loads(admin.path.read_text()) == BEFORE
    assert _beside(admin.path) == []
