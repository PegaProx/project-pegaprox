"""A rollback puts back the tree the updater saved, or refuses and writes nothing (#1340).

The updater saves pegaprox/, web/ and static/ as directories and the launcher,
version.json and requirements.txt next to them. The rollback still looked for one .py
at the top of the backup, which is the launcher, copied it over pegaprox/api/settings.py
and answered success; the next start failed on the import of the settings routes. Every
test here runs the route against an install and a backup in a temporary directory.
"""
import os
import shutil
import threading
import types

import pytest

import pegaprox.api.settings as settings

BACKUP = 'pegaprox_1.4.1_before_the_update'
ROUTE = '/api/pegaprox/update/rollback'

OLD = {
    'pegaprox/__init__.py': '# old package\n',
    'pegaprox/api/settings.py': 'bp = "old settings"\n',
    'pegaprox/core/ha.py': '# old ha\n',
    'web/index.html': '<html>old page</html>\n',
    'web/i18n/de.json': '{"old": 1}\n',
    'static/app.css': '/* old */\n',
    'pegaprox_multi_cluster.py': '# old launcher\n',
    'version.json': '{"version": "1.4.1"}\n',
    'requirements.txt': 'flask==3.0.0\n',
}
NEW = {rel: text.replace('old', 'new') for rel, text in OLD.items()}
NEW['pegaprox/core/added_later.py'] = '# only the newer release has me\n'


def _write(root, files):
    for rel, text in files.items():
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as fh:
            fh.write(text)


def _read(root, rel):
    with open(os.path.join(root, rel)) as fh:
        return fh.read()


def _tree(root):
    """Every entry under root, a link as its target and a file as its text."""
    out = {}
    for base, dirs, files in os.walk(root):
        for name in dirs + files:
            path = os.path.join(base, name)
            rel = os.path.relpath(path, root)
            if os.path.islink(path):
                out[rel] = ('link', os.readlink(path))
            elif name in files:
                out[rel] = ('file', _read(root, rel))
    return out


def _state(lab):
    """What the rollback may touch and what it must not: the install, the backups, and
    what a link in either points at."""
    return {name: _tree(os.path.join(lab.root, name)) if os.path.isdir(os.path.join(lab.root, name))
            else os.path.lexists(os.path.join(lab.root, name))
            for name in ('install', 'config', 'elsewhere', 'secret.txt')}


def _backup_like_the_updater(install, backup):
    for item in ('pegaprox', 'web', 'static'):
        if os.path.isdir(os.path.join(install, item)):
            shutil.copytree(os.path.join(install, item), os.path.join(backup, item),
                            ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    for f in ('pegaprox_multi_cluster.py', 'version.json', 'requirements.txt'):
        if os.path.exists(os.path.join(install, f)):
            shutil.copy2(os.path.join(install, f), os.path.join(backup, f))


@pytest.fixture
def lab(api, seed, tmp_path, monkeypatch):
    """An install that was updated: the backup holds the older release, the install the
    newer one, and a plugin the backup knows nothing of."""
    install = str(tmp_path / 'install')
    backup = str(tmp_path / 'config' / 'backups' / BACKUP)
    _write(install, OLD)
    os.makedirs(backup)
    _backup_like_the_updater(install, backup)
    shutil.rmtree(install)
    _write(install, NEW)
    _write(install, {'plugins/mine/__init__.py': '# a plugin\n'})
    monkeypatch.setattr(settings, 'CONFIG_DIR', str(tmp_path / 'config'))
    # the route finds the install from where its module lies
    monkeypatch.setattr(settings, '__file__', os.path.join(install, 'pegaprox', 'api', 'settings.py'))
    admin = api.as_user(seed.user('root', role='admin'))
    started = []

    def rollback(name=BACKUP):
        # the restart it asks for is recorded, never run
        with monkeypatch.context() as mp:
            mp.setattr(threading, 'Thread', lambda target=None, **kw: types.SimpleNamespace(
                start=lambda: started.append(getattr(target, '__name__', target)), daemon=True))
            return admin.post(ROUTE, json={'backup': name})
    return types.SimpleNamespace(install=install, backup=backup, root=str(tmp_path),
                                 rollback=rollback, started=started)


def test_a_rollback_puts_back_the_tree_the_updater_saved(lab):
    r = lab.rollback()
    assert _read(lab.install, 'pegaprox/api/settings.py') == OLD['pegaprox/api/settings.py']
    assert r.status_code == 200, r.get_data(as_text=True)
    body = r.get_json()
    assert body['success'] is True and body['restored'] == ['backend', 'frontend']
    for rel, text in OLD.items():
        assert _read(lab.install, rel) == text, rel
    # it copies back and deletes nothing: what only the newer release has stays
    assert _read(lab.install, 'pegaprox/core/added_later.py') == NEW['pegaprox/core/added_later.py']
    assert _read(lab.install, 'plugins/mine/__init__.py') == '# a plugin\n'
    assert not [p for p in _tree(lab.install) if '.rollback-' in p]
    assert lab.started == ['restart_server']


def _drop(path):
    os.unlink(path)


def _link_to(target):
    def make(path):
        os.makedirs(os.path.dirname(target), exist_ok=True)
        if not os.path.exists(target):
            with open(target, 'w') as fh:
                fh.write('not part of any backup\n')
        os.unlink(path)
        os.symlink(target, path)
    return make


def _dir_link(root):
    def make(path):
        shutil.copytree(path, os.path.join(root, 'elsewhere'))
        shutil.rmtree(path)
        os.symlink(os.path.join(root, 'elsewhere'), path)
    return make


BROKEN = [
    ('no_launcher', 'backup', 'pegaprox_multi_cluster.py', lambda root: _drop,
     'The backup has no pegaprox_multi_cluster.py'),
    ('no_settings', 'backup', 'pegaprox/api/settings.py', lambda root: _drop,
     'The backup has no pegaprox/api/settings.py'),
    ('settings_a_link', 'backup', 'pegaprox/api/settings.py',
     lambda root: _link_to(os.path.join(root, 'elsewhere', 'settings.py')),
     'The backup has no pegaprox/api/settings.py'),
    ('a_file_a_link', 'backup', 'web/i18n/de.json',
     lambda root: _link_to(os.path.join(root, 'secret.txt')),
     'The backup holds a link: web/i18n/de.json'),
    ('a_dir_a_link', 'backup', 'static', _dir_link, 'static in the backup is no directory'),
    ('install_dir_a_link', 'install', 'web', _dir_link, 'in the install is a link'),
]


@pytest.mark.parametrize('where, rel, breaker, said', [b[1:] for b in BROKEN],
                         ids=[b[0] for b in BROKEN])
def test_a_backup_that_is_no_updater_backup_is_refused_and_nothing_written(lab, where, rel, breaker, said):
    breaker(lab.root)(os.path.join(getattr(lab, where), rel))
    before = _state(lab)
    r = lab.rollback()
    assert r.status_code == 400, r.get_data(as_text=True)
    assert said in r.get_json()['error'] and 'nothing was restored' in r.get_json()['error']
    assert _state(lab) == before
    assert lab.started == []


def test_a_copy_that_fails_leaves_the_install_as_it_was(lab, monkeypatch):
    real = shutil.copy2

    def copy2(src, dst, **kw):
        if src.endswith(os.path.join('web', 'i18n', 'de.json')):
            raise OSError(28, 'No space left on device')
        return real(src, dst, **kw)
    monkeypatch.setattr(settings.shutil, 'copy2', copy2)
    before = _state(lab)
    r = lab.rollback()
    assert r.status_code == 500, r.get_data(as_text=True)
    assert _state(lab) == before
    assert lab.started == []
