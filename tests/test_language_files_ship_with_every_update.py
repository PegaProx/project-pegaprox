"""The language files of the page (web/i18n/<lang>.json) ship with every update.

The page names each file by its hash, so an install needs the files of its own build next to its
web/index.html. The archive and tree paths of both updaters copy all of web/, the package, the
image and deploy.sh too. version.json's update_files is the last list an update goes by when the
tree cannot be read, and update.sh restores the page from its backup when a download fails: both
have to know the files.
NS Nov 2026
"""
import json
import os
import shutil
import subprocess

from test_bundled_plugins_reach_every_install_1134 import CURL_STUB

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LANGS = ['de', 'es', 'fr', 'it', 'ko', 'pl', 'pt', 'zh']


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
