"""#1134 - the in-app updater replaces a plugin's code and keeps its settings.

It copied the whole release tree over the install, plugins/<id>/config.json included,
so every update put the status page key, the notification targets and the portal
settings back to the defaults. And it wrote the plugins next to the code, which is not
always where they are loaded from (PLUGINS_DIR).

The route runs for real here, against a temp install: __file__ of the settings module
decides the install folder, and the release comes from a stubbed requests.get.
"""
import io
import json
import os
import tarfile
import types

import pytest

import pegaprox.api.settings as settings

NEW = '9.9.9'
ARCHIVE_URL = 'https://archive.example.test/main.tar.gz'
RELEASE = {
    'pegaprox_multi_cluster.py': '# the new entry point\n',
    'version.json': json.dumps({'version': NEW}),
    'plugins/.gitkeep': '',
    'plugins/status_page/__init__.py': '# status page, new release\n',
    'plugins/status_page/status.html': '<html>new page</html>\n',
    'plugins/status_page/config.json': '{"auth_key": ""}\n',
    'plugins/notifications/__init__.py': '# notifications, new release\n',
    'plugins/notifications/config.json': '{"ntfy_enabled": false}\n',
}
ADMIN_SETTINGS = '{"auth_key": "set-by-the-admin"}\n'


class _Resp:
    def __init__(self, status, content=b'', data=None):
        self.status_code = status
        self.content = content
        self._data = data

    def json(self):
        return self._data

    def iter_content(self, size):
        yield self.content


def _archive():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w:gz') as tar:
        for rel, text in RELEASE.items():
            data = text.encode()
            info = tarfile.TarInfo(f'project-pegaprox-main/{rel}')
            info.size = len(data)
            info.mode = 0o644
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _server(with_archive):
    blob = _archive()

    def get(url, *a, **kw):
        if url in (settings.GITHUB_VERSION_URL, settings.MIRROR_VERSION_URL):
            return _Resp(200, data={'version': NEW, 'update_archive': ARCHIVE_URL})
        if url in (ARCHIVE_URL, settings.MIRROR_ARCHIVE_URL):
            return _Resp(200, blob) if with_archive else _Resp(404)
        if 'api.github.com/repos' in url:
            return _Resp(200, data={'tree': [{'path': p, 'type': 'blob'} for p in RELEASE]})
        for base in (settings.GITHUB_RAW_URL, settings.MIRROR_RAW_URL):
            if url.startswith(base + '/') and url[len(base) + 1:] in RELEASE:
                return _Resp(200, RELEASE[url[len(base) + 1:]].encode())
        return _Resp(404)
    return get


@pytest.fixture(params=['next to the code', 'elsewhere'])
def box(tmp_path, monkeypatch, request):
    install = tmp_path / 'opt-pegaprox'
    (install / 'pegaprox' / 'api').mkdir(parents=True)
    monkeypatch.setattr(settings, '__file__', str(install / 'pegaprox' / 'api' / 'settings.py'))
    # the updater writes into the folder three levels above __file__: the temp install
    assert os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(settings.__file__)))) == str(install)
    # deploy.sh runs in the install folder; a checkout started from elsewhere loads its
    # plugins from that working directory
    live = (install if request.param == 'next to the code' else tmp_path / 'workdir') / 'plugins'
    (live / 'status_page').mkdir(parents=True)
    (live / 'status_page' / '__init__.py').write_text('# status page, old release\n')
    (live / 'status_page' / 'config.json').write_text(ADMIN_SETTINGS)
    (live / 'my_plugin').mkdir()
    (live / 'my_plugin' / '__init__.py').write_text('# added by the admin\n')
    (live / 'my_plugin' / 'config.json').write_text('{"mine": true}\n')
    monkeypatch.setattr(settings, 'PLUGINS_DIR', str(live))
    monkeypatch.setattr(settings, 'CONFIG_DIR', str(tmp_path / 'config'))
    monkeypatch.setattr(settings, '_detect_install_method', lambda d: 'source')
    # no pip, and a failed crypto preflight: nothing restarts
    monkeypatch.setattr(settings.subprocess, 'run', lambda *a, **kw: types.SimpleNamespace(
        returncode=1, stdout='', stderr='not in a test'))
    return types.SimpleNamespace(install=install, live=live, elsewhere=request.param == 'elsewhere')


@pytest.mark.parametrize('with_archive', [True, False], ids=['archive', 'file-by-file'])
def test_an_update_replaces_the_code_and_keeps_the_settings(api, seed, box, monkeypatch, with_archive):
    monkeypatch.setattr(settings.requests, 'get', _server(with_archive))
    admin = api.as_user(seed.user('root', role='admin'))
    r = admin.post('/api/pegaprox/update', json={})
    assert r.status_code == 200, r.get_data(as_text=True)
    body = r.get_json()
    assert body['update_method'] == ('archive' if with_archive else 'individual')
    assert body['restarting'] is False and not body['files_failed'], body
    live = box.live
    # the update ran, into the temp install
    assert (box.install / 'pegaprox_multi_cluster.py').read_text() == RELEASE['pegaprox_multi_cluster.py']
    # the code of a plugin is the release's, its settings are the admin's
    assert (live / 'status_page' / '__init__.py').read_text() == RELEASE['plugins/status_page/__init__.py']
    assert (live / 'status_page' / 'status.html').read_text() == RELEASE['plugins/status_page/status.html']
    assert (live / 'status_page' / 'config.json').read_text() == ADMIN_SETTINGS
    assert 'plugins/status_page/config.json' in body['files_protected']
    # counterproof: a plugin without settings yet gets the release's defaults
    assert (live / 'notifications' / 'config.json').read_text() == RELEASE['plugins/notifications/config.json']
    assert 'plugins/notifications/config.json' not in body['files_protected']
    # a plugin the admin added is not touched
    assert (live / 'my_plugin' / 'config.json').read_text() == '{"mine": true}\n'
    assert (live / 'my_plugin' / '__init__.py').read_text() == '# added by the admin\n'
    # the plugins went where they are loaded from, nothing next to the code
    if box.elsewhere:
        assert not (box.install / 'plugins').exists()


def test_where_the_updater_writes(monkeypatch, tmp_path):
    live = tmp_path / 'live'
    (live / 'status_page').mkdir(parents=True)
    (live / 'status_page' / 'config.json').write_text('{}')
    monkeypatch.setattr(settings, 'PLUGINS_DIR', str(live))
    t = settings._update_target
    inst = str(tmp_path / 'inst')
    assert t(inst, 'plugins/status_page/config.json') is None
    assert t(inst, 'plugins/status_page/__init__.py') == str(live / 'status_page' / '__init__.py')
    assert t(inst, 'plugins/other/config.json') == str(live / 'other' / 'config.json')
    # only a plugin's own config.json is its settings
    assert t(inst, 'plugins/status_page/sub/config.json') == str(live / 'status_page' / 'sub' / 'config.json')
    assert t(inst, 'pegaprox/api/plugins.py') == os.path.join(inst, 'pegaprox/api/plugins.py')
    assert t(inst, 'config.json') == os.path.join(inst, 'config.json')
    assert t(inst, 'web/plugins/x.js') == os.path.join(inst, 'web/plugins/x.js')
