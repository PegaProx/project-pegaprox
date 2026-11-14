"""The language files of the page (web/i18n/<lang>.json) ship with every update.

The page names each file by its hash, so an install needs the files of its own build next to its
web/index.html. The archive and tree paths of both updaters copy all of web/, the package, the
image and deploy.sh too. version.json's update_files is the list an update goes by when the
tree cannot be read, and update.sh restores the page from its backup when a download fails: both
have to know the files.
NS Nov 2026

Without update_files either, both updaters fetch a short list of essentials, the page among
them. That list carries the language files, the module that serves them and sw.js, which
caches them per build, as well.
MK Nov 2026
"""
import ast
import json
import os
import re
import shutil
import subprocess
import types

from test_bundled_plugins_reach_every_install_1134 import CURL_STUB

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LANGS = ['de', 'es', 'fr', 'it', 'ko', 'pl', 'pt', 'ru', 'zh']


def _tracked():
    out = subprocess.run(['git', 'ls-files', 'web'], cwd=ROOT, capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    return out.stdout.split()


def test_every_language_file_is_in_the_manifest():
    with open(os.path.join(ROOT, 'version.json'), encoding='utf-8') as fh:
        manifest = set(json.load(fh)['update_files'])
    tracked = _tracked()
    assert sorted(f for f in tracked if f.startswith('web/i18n/')) == [f'web/i18n/{lang}.json' for lang in LANGS]
    # and the rest of the web interface, so the next file there cannot be forgotten either
    assert not [f for f in tracked if f not in manifest]


def test_a_failed_update_puts_the_language_files_back_with_the_page(tmp_path):
    inst = tmp_path / 'opt' / 'PegaProx'
    (inst / 'web' / 'i18n').mkdir(parents=True)
    shutil.copy(os.path.join(ROOT, 'update.sh'), inst)
    (inst / 'version.json').write_text(json.dumps({'version': '9.9.9'}))
    (inst / 'web' / 'index.html').write_text('<html>old page, de.json?v=old</html>\n')
    (inst / 'web' / 'i18n' / 'de.json').write_text('{"old": "Alt"}\n')
    # the tree names one file more than the server hands out: the download fails half way
    release = {
        'version.json': json.dumps({'version': '9.9.9'}),
        'web/index.html': '<html>new page, de.json?v=new</html>\n',
        'web/i18n/de.json': '{"new": "Neu"}\n',
    }
    srv = tmp_path / 'srv'
    for rel, text in release.items():
        (srv / 'raw' / rel).parent.mkdir(parents=True, exist_ok=True)
        (srv / 'raw' / rel).write_text(text)
    tree = list(release) + ['pegaprox/missing.py']
    (srv / 'tree.json').write_text(json.dumps({'tree': [{'path': p, 'type': 'blob'} for p in tree]}))
    stubs = tmp_path / 'stubs'
    stubs.mkdir()
    (stubs / 'curl').write_text(CURL_STUB)
    for cmd, code in (('systemctl', 3), ('dpkg', 1), ('pip3', 0)):
        (stubs / cmd).write_text(f'#!/bin/sh\nexit {code}\n')
    for stub in stubs.iterdir():
        stub.chmod(0o755)
    env = dict(os.environ, PATH=f'{stubs}:{os.environ.get("PATH", "")}', SRV=str(srv), HOME=str(tmp_path))
    env.pop('PEGAPROX_BRANCH', None)
    r = subprocess.run(['bash', str(inst / 'update.sh'), '--force'], env=env, stdin=subprocess.DEVNULL,
                       capture_output=True, text=True, timeout=120)
    out = r.stdout + r.stderr
    assert r.returncode == 1 and 'Restoring from backup' in out, out[-3000:]
    # the new files had landed before the failure, and went back with the page
    assert (inst / 'web' / 'index.html').read_text() == '<html>old page, de.json?v=old</html>\n'
    assert (inst / 'web' / 'i18n' / 'de.json').read_text() == '{"old": "Alt"}\n'
    backups = list((inst / 'backups').iterdir())
    assert len(backups) == 1 and (backups[0] / 'web' / 'i18n' / 'de.json').read_text() == '{"old": "Alt"}\n'


def _repo_language_files():
    return sorted(f for f in _tracked() if re.fullmatch(r'web/i18n/[a-z]+\.json', f))


def _in_app_essentials():
    with open(os.path.join(ROOT, 'pegaprox', 'api', 'settings.py'), encoding='utf-8') as fh:
        src = fh.read()
    m = re.search(r'# absolute fallback - at least get the essentials\n(?:[ \t]*#[^\n]*\n)*'
                  r'[ \t]*file_list = (\[[^\]]*\])', src)
    assert m, 'the essentials of the in-app update are not where this test reads them'
    return ast.literal_eval(m.group(1))


def test_the_essentials_of_the_in_app_update_carry_every_language_file():
    langs = _repo_language_files()
    assert langs == [f'web/i18n/{lang}.json' for lang in LANGS]
    essentials = _in_app_essentials()
    assert not [f for f in langs if f not in essentials]
    assert {'web/index.html', 'web/sw.js', 'pegaprox/utils/index_page.py'} <= set(essentials)
    # every entry is a file of the release: a name that is not there is a 404 on each update
    assert not [f for f in essentials if not os.path.isfile(os.path.join(ROOT, f))]


class _Resp:
    def __init__(self, status, content=b'', data=None):
        self.status_code = status
        self.content = content
        self._data = data

    def json(self):
        return self._data

    def iter_content(self, size):
        yield self.content


def test_the_in_app_update_without_any_file_list_brings_the_language_files(api, seed, tmp_path, monkeypatch):
    import pegaprox.api.settings as settings
    install = tmp_path / 'opt-pegaprox'
    (install / 'pegaprox' / 'api').mkdir(parents=True)
    (install / 'web' / 'i18n').mkdir(parents=True)
    (install / 'web' / 'index.html').write_text('<html>old page, de.json?v=old</html>\n')
    for lang in LANGS:
        (install / 'web' / 'i18n' / f'{lang}.json').write_text('{"old": "%s"}\n' % lang)
    monkeypatch.setattr(settings, '__file__', str(install / 'pegaprox' / 'api' / 'settings.py'))
    monkeypatch.setattr(settings, 'PLUGINS_DIR', str(install / 'plugins'))
    monkeypatch.setattr(settings, 'CONFIG_DIR', str(tmp_path / 'config'))
    monkeypatch.setattr(settings, '_detect_install_method', lambda d: 'source')
    monkeypatch.setattr(settings.subprocess, 'run', lambda *a, **kw: types.SimpleNamespace(
        returncode=1, stdout='', stderr='not in a test'))
    release = {f: f'new {f}\n' for f in _in_app_essentials()}
    release['version.json'] = json.dumps({'version': '9.9.9'})

    def get(url, *a, **kw):
        # no archive, no tree and no update_files: the essentials are all there is
        if url in (settings.GITHUB_VERSION_URL, settings.MIRROR_VERSION_URL):
            return _Resp(200, release['version.json'].encode(), data={'version': '9.9.9'})
        for base in (settings.GITHUB_RAW_URL, settings.MIRROR_RAW_URL):
            if url.startswith(base + '/') and url[len(base) + 1:] in release:
                return _Resp(200, release[url[len(base) + 1:]].encode())
        return _Resp(404)
    monkeypatch.setattr(settings.requests, 'get', get)

    r = api.as_user(seed.user('root', role='admin')).post('/api/pegaprox/update', json={})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['update_method'] == 'individual' and not r.get_json()['files_failed']
    assert (install / 'web' / 'index.html').read_text() == 'new web/index.html\n'
    for lang in LANGS:
        assert (install / 'web' / 'i18n' / f'{lang}.json').read_text() == f'new web/i18n/{lang}.json\n', lang
    assert (install / 'pegaprox' / 'utils' / 'index_page.py').read_text() == 'new pegaprox/utils/index_page.py\n'
    assert (install / 'web' / 'sw.js').read_text() == 'new web/sw.js\n'


def _update_sh_essentials():
    with open(os.path.join(ROOT, 'update.sh'), encoding='utf-8') as fh:
        m = re.search(r'for _ess in ((?:[^;\n]|\\\n)*); do', fh.read())
    assert m, 'the essentials of update.sh are not where this test reads them'
    return m.group(1).replace('\\\n', ' ').split()


def test_the_essentials_of_update_sh_carry_every_language_file():
    essentials = _update_sh_essentials()
    assert not [f for f in _repo_language_files() if f not in essentials]
    assert {'web/index.html', 'web/sw.js', 'pegaprox/utils/index_page.py'} <= set(essentials)
    # a name that is not in the release fails every update that comes this way
    assert not [f for f in essentials if not os.path.isfile(os.path.join(ROOT, f))]
    # both updaters go by the same list
    assert sorted(essentials) == sorted(_in_app_essentials())


def test_update_sh_without_any_file_list_brings_the_language_files(tmp_path):
    inst = tmp_path / 'opt' / 'PegaProx'
    (inst / 'web' / 'i18n').mkdir(parents=True)
    shutil.copy(os.path.join(ROOT, 'update.sh'), inst)
    (inst / 'version.json').write_text(json.dumps({'version': '9.9.9'}))
    (inst / 'web' / 'index.html').write_text('<html>old page, de.json?v=old</html>\n')
    for lang in LANGS:
        (inst / 'web' / 'i18n' / f'{lang}.json').write_text('{"old": "%s"}\n' % lang)
    # no archive, no tree, and a version.json without update_files
    release = {f: f'new {f}\n' for f in _update_sh_essentials()}
    release['version.json'] = json.dumps({'version': '9.9.9'})
    release['update.sh'] = open(os.path.join(ROOT, 'update.sh'), encoding='utf-8').read()
    srv = tmp_path / 'srv'
    for rel, text in release.items():
        (srv / 'raw' / rel).parent.mkdir(parents=True, exist_ok=True)
        (srv / 'raw' / rel).write_text(text)
    stubs = tmp_path / 'stubs'
    stubs.mkdir()
    (stubs / 'curl').write_text(CURL_STUB)
    for cmd, code in (('systemctl', 3), ('dpkg', 1), ('pip3', 0)):
        (stubs / cmd).write_text(f'#!/bin/sh\nexit {code}\n')
    for stub in stubs.iterdir():
        stub.chmod(0o755)
    env = dict(os.environ, PATH=f'{stubs}:{os.environ.get("PATH", "")}', SRV=str(srv), HOME=str(tmp_path))
    env.pop('PEGAPROX_BRANCH', None)
    r = subprocess.run(['bash', str(inst / 'update.sh'), '--force'], env=env, stdin=subprocess.DEVNULL,
                       capture_output=True, text=True, timeout=120)
    out = r.stdout + r.stderr
    assert r.returncode == 0 and 'downloading essentials' in out and 'Restoring from backup' not in out, out[-3000:]
    assert (inst / 'web' / 'index.html').read_text() == 'new web/index.html\n'
    for lang in LANGS:
        assert (inst / 'web' / 'i18n' / f'{lang}.json').read_text() == f'new web/i18n/{lang}.json\n', lang
    assert (inst / 'pegaprox' / 'utils' / 'index_page.py').read_text() == 'new pegaprox/utils/index_page.py\n'
    assert (inst / 'web' / 'sw.js').read_text() == 'new web/sw.js\n'
