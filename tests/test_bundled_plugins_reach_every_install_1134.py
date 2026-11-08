"""#1134 - the bundled plugins reach every install, and an update keeps their settings.

The .deb never shipped plugins/ and the service loads them from /var/lib/pegaprox, so a
package install (and the VM and LXC appliances built from it) had none. The package now
ships them read-only in /usr/share/pegaprox/plugins and its postinst brings them in with
packaging/plugins/sync_plugins.py; the Docker image (at every start of the app),
update.sh and deploy.sh use the same script. The rule everywhere: a missing plugin is copied whole, an existing one gets
its code replaced and keeps its config.json, a plugin the admin added is not touched.

Everything here runs on temp folders: the script itself, the postinst with its paths moved
into a temp root, the start of the app with a seed folder, update.sh with curl, systemctl,
dpkg and pip3 replaced by stubs.
"""
import grp
import io
import json
import os
import pwd
import shutil
import subprocess
import sys
import tarfile
import types

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SYNC = os.path.join(ROOT, 'packaging', 'plugins', 'sync_plugins.py')
ADMIN_SETTINGS = '{"auth_key": "set-by-the-admin"}\n'


def _read(*rel):
    with open(os.path.join(ROOT, *rel), encoding='utf-8') as fh:
        return fh.read()


def _bundled_names():
    return sorted(n for n in os.listdir(os.path.join(ROOT, 'plugins'))
                  if not n.startswith(('.', '_')) and os.path.isdir(os.path.join(ROOT, 'plugins', n)))


def _copy_plugins(dst):
    shutil.copytree(os.path.join(ROOT, 'plugins'), dst,
                    ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    return dst


def _run_sync(*args):
    return subprocess.run([sys.executable, SYNC, *map(str, args)], capture_output=True, text=True,
                          timeout=60)


def _sync_module():
    # compiled by hand: an import would leave a __pycache__ in packaging/plugins
    mod = types.ModuleType('pp_sync_plugins_1134')
    mod.__file__ = SYNC
    with open(SYNC, encoding='utf-8') as fh:
        exec(compile(fh.read(), SYNC, 'exec'), mod.__dict__)
    return mod


def _files(folder):
    out = {}
    for base, dirs, files in os.walk(folder):
        dirs[:] = [d for d in dirs if d != '__pycache__']
        for fn in files:
            path = os.path.join(base, fn)
            with open(path, 'rb') as fh:
                out[os.path.relpath(path, folder)] = fh.read()
    return out


@pytest.fixture
def bundled(tmp_path):
    src = _copy_plugins(tmp_path / 'usr-share' / 'plugins')
    # what a build may leave behind is not shipped on
    (src / 'status_page' / '__pycache__').mkdir()
    (src / 'status_page' / '__pycache__' / 'x.cpython-312.pyc').write_bytes(b'\0')
    return src


@pytest.fixture
def target(tmp_path):
    return tmp_path / 'var-lib-pegaprox' / 'plugins'


# --- the script ---------------------------------------------------------------------------

def test_an_install_gets_every_bundled_plugin(bundled, target):
    r = _run_sync(bundled, target)
    assert r.returncode == 0, r.stdout + r.stderr
    names = _bundled_names()
    assert names and sorted(os.listdir(target)) == names, os.listdir(target)
    for name in names:
        assert _files(target / name) == _files(bundled / name), name
        assert f'{name} installed' in r.stdout
        assert (os.stat(target / name).st_mode & 0o777) == 0o750
    assert not (target / 'status_page' / '__pycache__').exists()
    assert (os.stat(target / 'status_page' / '__init__.py').st_mode & 0o777) == 0o640
    # a config.json may hold a key or a token later
    assert (os.stat(target / 'status_page' / 'config.json').st_mode & 0o777) == 0o600


def test_an_upgrade_replaces_the_code_and_keeps_the_settings(bundled, target):
    assert _run_sync(bundled, target).returncode == 0
    sp = target / 'status_page'
    (sp / 'config.json').write_text(ADMIN_SETTINGS)
    (sp / 'state.db').write_bytes(b'what the plugin wrote')
    (sp / '__pycache__').mkdir()
    (sp / '__pycache__' / 'x.pyc').write_bytes(b'cache')
    mine = target / 'my_plugin'
    mine.mkdir()
    (mine / 'manifest.json').write_text('{"name": "mine"}')
    (mine / 'config.json').write_text('{"mine": true}')
    before = {p: (os.stat(mine / p).st_mtime_ns, (mine / p).read_bytes()) for p in os.listdir(mine)}
    # the next release
    (bundled / 'status_page' / '__init__.py').write_text('# status page, next release\n')
    (bundled / 'status_page' / 'config.json').write_text('{"auth_key": "", "new_default": 1}\n')
    (bundled / 'status_page' / 'extra.html').write_text('<html>new page</html>')

    r = _run_sync(bundled, target)
    assert r.returncode == 0, r.stdout + r.stderr
    assert 'status_page updated, kept config.json' in r.stdout
    assert (sp / '__init__.py').read_text() == '# status page, next release\n'
    assert (sp / 'extra.html').read_text() == '<html>new page</html>'
    assert (sp / 'status.html').read_bytes() == (bundled / 'status_page' / 'status.html').read_bytes()
    assert (sp / 'config.json').read_text() == ADMIN_SETTINGS
    assert (sp / 'state.db').read_bytes() == b'what the plugin wrote'
    assert (sp / '__pycache__' / 'x.pyc').read_bytes() == b'cache'
    assert {p: (os.stat(mine / p).st_mtime_ns, (mine / p).read_bytes()) for p in os.listdir(mine)} == before
    assert 'my_plugin' not in r.stdout

    # counterproof: the settings are kept because they exist, not because config.json is
    # skipped - without one the release's defaults arrive, and a removed plugin comes back
    (sp / 'config.json').unlink()
    shutil.rmtree(target / 'hello_world')
    r = _run_sync(bundled, target)
    assert r.returncode == 0, r.stdout + r.stderr
    assert (sp / 'config.json').read_text() == '{"auth_key": "", "new_default": 1}\n'
    assert _files(target / 'hello_world') == _files(bundled / 'hello_world')
    assert 'hello_world installed' in r.stdout


def test_without_root_the_owner_is_left_alone(bundled, target):
    if os.geteuid() == 0:
        pytest.skip('runs as root')
    r = _run_sync(bundled, target, '--owner', 'root:root')
    assert r.returncode == 0, r.stdout + r.stderr
    for base, dirs, files in os.walk(target):
        for fn in dirs + files:
            assert os.lstat(os.path.join(base, fn)).st_uid == os.getuid()
    # counterproof: the owner is read, not ignored - one that does not exist is an error
    bad = _run_sync(bundled, target, '--owner', 'no-such-user-1134:no-such-group-1134')
    assert bad.returncode == 2 and '--owner' in bad.stderr


def test_with_an_owner_the_bundled_folders_are_handed_over_and_nothing_else(bundled, target, tmp_path,
                                                                           monkeypatch):
    mod = _sync_module()
    assert mod.sync(str(bundled), str(target), say=lambda s: None) == []
    sp = target / 'status_page'
    (sp / 'config.json').write_text(ADMIN_SETTINGS)
    (sp / 'data.json').write_text('{}')
    outside = tmp_path / 'outside.txt'
    outside.write_text('not ours')
    (sp / 'link').symlink_to(outside)
    os.link(outside, sp / 'hard')
    (target / 'my_plugin').mkdir()
    (target / 'my_plugin' / 'x').write_text('the admin')
    named, by_fd = [], []

    def chown(path, uid, gid, *, dir_fd=None, follow_symlinks=True):
        named.append((os.path.basename(str(path)), uid, gid, follow_symlinks))

    monkeypatch.setattr(mod.os, 'chown', chown)
    monkeypatch.setattr(mod.os, 'fchown', lambda fd, uid, gid: by_fd.append((uid, gid)))
    assert mod.sync(str(bundled), str(target), owner=(4321, 8765), say=lambda s: None) == []
    names = {n for n, *_ in named}
    assert {'config.json', 'data.json', '__init__.py', 'status.html'} <= names
    assert not names & {'link', 'hard', 'x', 'outside.txt'}, names
    assert all(u == 4321 and g == 8765 and follow is False for _n, u, g, follow in named)
    # the plugin folder itself, every folder and every file written go by their descriptor
    assert by_fd and all(o == (4321, 8765) for o in by_fd)
    assert len(by_fd) > len(_bundled_names())


def test_nothing_is_written_through_a_symlink(bundled, target, tmp_path):
    assert _run_sync(bundled, target).returncode == 0
    outside = tmp_path / 'outside'
    outside.mkdir()
    (outside / 'victim.py').write_text('precious')
    sp_init = target / 'status_page' / '__init__.py'
    sp_init.unlink()
    sp_init.symlink_to(outside / 'victim.py')
    shutil.rmtree(target / 'hello_world')
    (target / 'hello_world').symlink_to(outside, target_is_directory=True)

    r = _run_sync(bundled, target)
    assert r.returncode == 1
    assert 'hello_world is a symlink or not a directory, left alone' in r.stdout
    assert (outside / 'victim.py').read_text() == 'precious'
    assert sorted(os.listdir(outside)) == ['victim.py']
    assert not sp_init.is_symlink()
    assert sp_init.read_bytes() == (bundled / 'status_page' / '__init__.py').read_bytes()
    assert (target / 'hello_world').is_symlink()
    # the other plugins still went in
    assert 'client_portal updated' in r.stdout

    # a target that is a symlink itself is refused as a whole
    linked = tmp_path / 'linked-plugins'
    linked.symlink_to(outside, target_is_directory=True)
    r = _run_sync(bundled, linked)
    assert r.returncode == 1 and sorted(os.listdir(outside)) == ['victim.py']


def test_the_same_folder_is_left_as_it_is(bundled):
    before = _files(bundled)
    r = _run_sync(bundled, bundled)
    assert r.returncode == 0 and _files(bundled) == before


# --- .deb ---------------------------------------------------------------------------------

def _install_map():
    return [line.split() for line in _read('debian', 'install').splitlines() if line.strip()]


def test_the_package_ships_the_plugins_and_the_sync():
    entries = _install_map()
    assert ['plugins', 'usr/share/pegaprox'] in entries
    assert ['packaging/plugins/sync_plugins.py', 'usr/lib/pegaprox/packaging/plugins'] in entries
    # loaded from the unit's working directory: /var/lib/pegaprox/plugins
    assert 'WorkingDirectory=/var/lib/pegaprox' in _read('systemd', 'pegaprox.service').splitlines()
    postinst = _read('debian', 'pegaprox.postinst')
    call = ('/usr/bin/python3 /usr/lib/pegaprox/packaging/plugins/sync_plugins.py \\\n'
            '        /usr/share/pegaprox/plugins /var/lib/pegaprox/plugins --owner pegaprox:pegaprox \\\n'
            '        || echo ')
    assert call in postinst
    # after the user and the state directory, before the restart; #DEBHELPER# stays last (#1129)
    at = postinst.index(call)
    assert postinst.index('useradd') < at and postinst.index('chown pegaprox:pegaprox /var/lib/pegaprox') < at
    assert at < postinst.index('systemctl restart pegaprox.service')
    assert postinst.rstrip().splitlines()[-1] == '#DEBHELPER#'
    assert subprocess.run(['bash', '-n', os.path.join(ROOT, 'debian', 'pegaprox.postinst')]).returncode == 0


def _fake_root_postinst(tmp_path):
    """The real postinst with its paths moved into a temp root; useradd, chown and
    systemctl are stubs that write down how they were called."""
    root = tmp_path / 'root'
    _copy_plugins(root / 'usr' / 'share' / 'pegaprox' / 'plugins')
    (root / 'usr' / 'lib' / 'pegaprox' / 'packaging' / 'plugins').mkdir(parents=True)
    shutil.copy(SYNC, root / 'usr' / 'lib' / 'pegaprox' / 'packaging' / 'plugins')
    stubs = tmp_path / 'stubs'
    stubs.mkdir()
    calls = tmp_path / 'calls.log'
    for cmd in ('id', 'useradd', 'chown', 'systemctl'):
        (stubs / cmd).write_text(f'#!/bin/sh\necho "{cmd} $*" >> "{calls}"\nexit 0\n')
        (stubs / cmd).chmod(0o755)
    me = f'{pwd.getpwuid(os.getuid()).pw_name}:{grp.getgrgid(os.getgid()).gr_name}'
    text = _read('debian', 'pegaprox.postinst')
    for path in ('/var/lib/pegaprox', '/usr/share/pegaprox', '/usr/lib/pegaprox'):
        text = text.replace(path, str(root) + path)
    text = text.replace('--owner pegaprox:pegaprox', f'--owner {me}')
    script = tmp_path / 'postinst'
    script.write_text(text)
    env = dict(os.environ, PATH=f'{stubs}:{os.environ.get("PATH", "")}')

    def run(*args):
        return subprocess.run(['bash', str(script), *args], env=env, capture_output=True, text=True,
                              timeout=60)
    return root, calls, run


@pytest.mark.skipif(not os.path.exists('/usr/bin/python3'), reason='the postinst calls /usr/bin/python3')
def test_the_postinst_brings_the_plugins_on_install_and_on_upgrade(tmp_path):
    root, calls, run = _fake_root_postinst(tmp_path)
    live = root / 'var' / 'lib' / 'pegaprox' / 'plugins'
    share = root / 'usr' / 'share' / 'pegaprox' / 'plugins'
    r = run('configure')
    assert r.returncode == 0, r.stdout + r.stderr
    assert sorted(os.listdir(live)) == _bundled_names()
    # an admin's settings, a plugin of his own, then the next package
    (live / 'status_page' / 'config.json').write_text(ADMIN_SETTINGS)
    (live / 'my_plugin').mkdir()
    (live / 'my_plugin' / 'config.json').write_text('{"mine": true}')
    (share / 'status_page' / '__init__.py').write_text('# next release\n')
    r = run('configure', '1.3.0')
    assert r.returncode == 0, r.stdout + r.stderr
    assert (live / 'status_page' / '__init__.py').read_text() == '# next release\n'
    assert (live / 'status_page' / 'config.json').read_text() == ADMIN_SETTINGS
    assert (live / 'my_plugin' / 'config.json').read_text() == '{"mine": true}'
    assert calls.read_text().count('systemctl restart pegaprox.service') == 2


@pytest.mark.skipif(not os.path.exists('/usr/bin/python3'), reason='the postinst calls /usr/bin/python3')
def test_a_plugin_that_does_not_make_it_does_not_fail_the_package(tmp_path):
    """set -e: the sync failing must not stop the configure, nor the restart after it."""
    root, calls, run = _fake_root_postinst(tmp_path)
    shutil.rmtree(root / 'usr' / 'share' / 'pegaprox' / 'plugins')
    r = run('configure')
    assert r.returncode == 0, r.stdout + r.stderr
    assert 'not every bundled plugin could be brought into' in r.stderr
    assert 'systemctl restart pegaprox.service' in calls.read_text()


# --- Docker -------------------------------------------------------------------------------

def test_the_image_loads_its_plugins_from_the_config_volume():
    docker = _read('Dockerfile')
    lines = [ln.strip() for ln in docker.splitlines()]
    assert 'WORKDIR /app' in lines
    assert 'COPY --chown=pegaprox:pegaprox plugins/ plugins/' in lines
    assert 'COPY --chown=pegaprox:pegaprox packaging/plugins/sync_plugins.py packaging/plugins/sync_plugins.py' in lines
    assert 'ENV PEGAPROX_PLUGINS_DIR=/app/config/plugins \\' in lines
    assert 'PEGAPROX_PLUGINS_SEED=/app/plugins' in lines
    assert 'VOLUME ["/app/config", "/app/logs"]' in lines
    # the app brings them in, so an entrypoint a compose file or a pod overrides still does
    assert 'ENTRYPOINT ["python3", "pegaprox_multi_cluster.py"]' in lines
    assert 'entrypoint.sh' not in docker


@pytest.fixture
def seeded(tmp_path, monkeypatch):
    import pegaprox.api.plugins as plugins_api
    seed = tmp_path / 'app' / 'plugins'
    _copy_plugins(seed)
    live = tmp_path / 'config' / 'plugins'
    monkeypatch.setattr(plugins_api, 'PLUGINS_DIR', str(live))
    monkeypatch.setenv('PEGAPROX_PLUGINS_SEED', str(seed))
    return plugins_api, seed, live


def test_every_start_brings_the_image_plugins_and_keeps_their_settings(seeded):
    plugins_api, seed, live = seeded
    plugins_api.seed_bundled_plugins()
    assert sorted(os.listdir(live)) == _bundled_names()
    (live / 'status_page' / 'config.json').write_text(ADMIN_SETTINGS)
    (live / 'my_plugin').mkdir()
    (live / 'my_plugin' / 'config.json').write_text('{"mine": true}')
    # a new image
    (seed / 'status_page' / '__init__.py').write_text('# next image\n')
    plugins_api.seed_bundled_plugins()
    assert (live / 'status_page' / '__init__.py').read_text() == '# next image\n'
    assert (live / 'status_page' / 'config.json').read_text() == ADMIN_SETTINGS
    assert (live / 'my_plugin' / 'config.json').read_text() == '{"mine": true}'


def test_the_start_of_the_app_seeds_before_it_loads(seeded, monkeypatch):
    plugins_api, seed, live = seeded
    seen = []
    monkeypatch.setattr(plugins_api, '_get_plugin_states', lambda: {})
    monkeypatch.setattr(plugins_api, '_discover_plugins',
                        lambda: seen.append(sorted(os.listdir(live))) or [])
    plugins_api.load_enabled_plugins(object())
    assert seen == [_bundled_names()]


def test_no_seed_or_the_same_folder_brings_nothing(seeded, monkeypatch):
    plugins_api, seed, live = seeded
    monkeypatch.delenv('PEGAPROX_PLUGINS_SEED')
    plugins_api.seed_bundled_plugins()
    assert not live.exists()
    monkeypatch.setenv('PEGAPROX_PLUGINS_SEED', str(live))
    plugins_api.seed_bundled_plugins()
    assert not live.exists()
    # counterproof: with the seed set it does
    monkeypatch.setenv('PEGAPROX_PLUGINS_SEED', str(seed))
    plugins_api.seed_bundled_plugins()
    assert sorted(os.listdir(live)) == _bundled_names()


# --- update.sh ----------------------------------------------------------------------------

CURL_STUB = r'''#!/bin/bash
out=""; url=""
while [ $# -gt 0 ]; do
    case "$1" in
        -o) out="$2"; shift ;;
        http*) url="$1" ;;
    esac
    shift
done
raw=https://raw.githubusercontent.com/PegaProx/project-pegaprox/main/
case "$url" in
    https://github.com/PegaProx/project-pegaprox/archive/refs/heads/main.tar.gz|https://updates.pegaprox.com/archive/main.tar.gz)
        src="$SRV/main.tar.gz" ;;
    https://api.github.com/*) src="$SRV/tree.json" ;;
    "$raw"*) src="$SRV/raw/${url#$raw}" ;;
    https://updates.pegaprox.com/*) src="$SRV/raw/${url#https://updates.pegaprox.com/}" ;;
    *) exit 22 ;;
esac
[ -f "$src" ] || exit 22
if [ -n "$out" ]; then cp "$src" "$out"; else cat "$src"; fi
'''


def _update_box(tmp_path, with_archive, as_root=False):
    inst = tmp_path / 'opt' / 'PegaProx'
    inst.mkdir(parents=True)
    shutil.copy(os.path.join(ROOT, 'update.sh'), inst)
    (inst / 'version.json').write_text(json.dumps({'version': '9.9.9'}))
    (inst / 'plugins' / 'status_page').mkdir(parents=True)
    (inst / 'plugins' / 'status_page' / '__init__.py').write_text('# old release\n')
    (inst / 'plugins' / 'status_page' / 'config.json').write_text(ADMIN_SETTINGS)
    (inst / 'plugins' / 'my_plugin').mkdir()
    (inst / 'plugins' / 'my_plugin' / 'config.json').write_text('{"mine": true}')
    release = {
        'update.sh': _read('update.sh'),
        'version.json': json.dumps({'version': '9.9.9'}),
        'pegaprox_multi_cluster.py': '# the new entry point\n',
        'packaging/plugins/sync_plugins.py': _read('packaging', 'plugins', 'sync_plugins.py'),
        'plugins/status_page/__init__.py': '# next release\n',
        'plugins/status_page/status.html': '<html>new page</html>\n',
        'plugins/status_page/config.json': '{"auth_key": ""}\n',
        'plugins/notifications/__init__.py': '# notifications\n',
        'plugins/notifications/config.json': '{"ntfy_enabled": false}\n',
    }
    srv = tmp_path / 'srv'
    for rel, text in release.items():
        (srv / 'raw' / rel).parent.mkdir(parents=True, exist_ok=True)
        (srv / 'raw' / rel).write_text(text)
    (srv / 'tree.json').write_text(json.dumps({'tree': [{'path': p, 'type': 'blob'} for p in release]}))
    if with_archive:
        with tarfile.open(srv / 'main.tar.gz', 'w:gz') as tar:
            for rel, text in release.items():
                data = text.encode()
                info = tarfile.TarInfo(f'project-pegaprox-main/{rel}')
                info.size = len(data)
                info.mode = 0o644
                tar.addfile(info, io.BytesIO(data))
    stubs = tmp_path / 'stubs'
    stubs.mkdir()
    calls = tmp_path / 'calls.log'
    (stubs / 'curl').write_text(CURL_STUB)
    for cmd, code in (('systemctl', 3), ('dpkg', 1), ('pip3', 0)):
        (stubs / cmd).write_text(f'#!/bin/sh\necho "{cmd} $*" >> "{calls}"\nexit {code}\n')
    # writes down how the sync is called, then runs it
    (stubs / 'python3').write_text(f'#!/bin/sh\necho "python3 $*" >> "{calls}"\nexec "{sys.executable}" "$@"\n')
    for stub in stubs.iterdir():
        stub.chmod(0o755)
    env = dict(os.environ, PATH=f'{stubs}:{os.environ.get("PATH", "")}', SRV=str(srv), HOME=str(tmp_path))
    env.pop('PEGAPROX_BRANCH', None)
    # --force: the install-method guard would stop here inside a container. As root: in a
    # user namespace of its own, where this user is root
    r = subprocess.run([*(['unshare', '-r'] if as_root else []), 'bash', str(inst / 'update.sh'), '--force'],
                       env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120)
    return inst, r, calls


def _sync_calls(calls):
    return [ln for ln in calls.read_text().splitlines() if 'sync_plugins.py' in ln]


def _as_root_works():
    try:
        return subprocess.run(['unshare', '-r', 'true'], capture_output=True, timeout=30).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


@pytest.mark.skipif(shutil.which('rsync') is None, reason='the archive path copies with rsync')
@pytest.mark.parametrize('with_archive', [True, False], ids=['archive', 'file-by-file'])
def test_update_sh_replaces_the_code_and_keeps_the_settings(tmp_path, with_archive):
    inst, r, calls = _update_box(tmp_path, with_archive)
    assert r.returncode == 0, r.stdout[-3000:] + r.stderr[-3000:]
    assert ('falling back to individual files' in r.stdout) is not with_archive
    plugins = inst / 'plugins'
    assert (inst / 'pegaprox_multi_cluster.py').read_text() == '# the new entry point\n'
    assert (plugins / 'status_page' / '__init__.py').read_text() == '# next release\n'
    assert (plugins / 'status_page' / 'status.html').read_text() == '<html>new page</html>\n'
    assert (plugins / 'status_page' / 'config.json').read_text() == ADMIN_SETTINGS
    # counterproof: a plugin without settings gets the release's defaults
    assert (plugins / 'notifications' / 'config.json').read_text() == '{"ntfy_enabled": false}\n'
    assert (plugins / 'my_plugin' / 'config.json').read_text() == '{"mine": true}'
    log = calls.read_text() if calls.exists() else ''
    assert 'systemctl restart' not in log
    # the archive goes through the sync; not root, the owner of what it writes is the caller's
    assert bool(_sync_calls(calls)) is with_archive
    assert not any('--owner' in ln for ln in _sync_calls(calls))


def _owner_block():
    text = _read('update.sh')
    at = text.index('PLUGIN_OWNER=""')
    return text[at:text.index('python3 "$PLUGIN_SYNC"', at)]


@pytest.mark.skipif(shutil.which('rsync') is None or not _as_root_works(),
                    reason='runs update.sh as root in a user namespace (unshare -r), archive path copies with rsync')
def test_update_sh_as_root_hands_the_plugins_to_the_owner_of_the_install(tmp_path):
    """sudo ./update.sh where config/ is not next to the code (PEGAPROX_CONFIG_DIR, #826):
    nothing after the copy knew whom to give the files, and the sync writes 0640 and 0600 -
    the plugins stayed root's, and a service that does not run as root could not read its
    plugins any more. The rsync of 3f43b7e left them 0644."""
    inst, r, calls = _update_box(tmp_path, with_archive=True, as_root=True)
    assert r.returncode == 0, r.stdout[-3000:] + r.stderr[-3000:]
    assert 'Running as root' in r.stdout and not (inst / 'config').exists()
    # this user is root in there, so the install folder is root's in there as well
    assert len(_sync_calls(calls)) == 1 and _sync_calls(calls)[0].endswith(' --owner 0:0'), _sync_calls(calls)
    plugins = inst / 'plugins'
    assert (plugins / 'status_page' / '__init__.py').read_text() == '# next release\n'
    assert (plugins / 'status_page' / 'config.json').read_text() == ADMIN_SETTINGS

    # whom it picks: config/ like the ownership fix further down, else the install folder
    stubs = tmp_path / 'stat-stub'
    stubs.mkdir()
    (stubs / 'stat').write_text('#!/bin/sh\n'
                                'case "$3" in */config) echo 111:222 ;; */.) echo 333:444 ;; *) exit 1 ;; esac\n')
    (stubs / 'stat').chmod(0o755)
    env = dict(os.environ, PATH=f'{stubs}:{os.environ.get("PATH", "")}', SCRIPT_DIR=str(inst))
    script = _owner_block() + 'echo "owner=$PLUGIN_OWNER"\n'

    def owner(*prefix):
        out = subprocess.run([*prefix, 'bash', '-c', script], env=env, capture_output=True, text=True, timeout=30)
        assert out.returncode == 0, out.stderr
        return out.stdout.strip()
    assert owner('unshare', '-r') == 'owner=333:444'
    (inst / 'config').mkdir()
    assert owner('unshare', '-r') == 'owner=111:222'
    # counterproof: not root, no owner
    assert owner() == 'owner='


def test_deploy_sh_brings_the_plugins_both_ways():
    deploy = _read('deploy.sh')
    # from a checkout: the plugins never came along
    local = deploy[deploy.index('Running from existing checkout'):deploy.index('print_success "Files copied from local checkout"')]
    assert 'packaging/plugins/sync_plugins.py" "$SCRIPT_DIR/plugins" "$INSTALL_DIR/plugins"' in local
    # from a clone: through the sync, and out of the way of the copy of everything after it
    clone = deploy[deploy.index('git clone --depth 1'):]
    sync_at = clone.index('"$TEMP_DIR/pegaprox/plugins" "$INSTALL_DIR/plugins"')
    assert sync_at < clone.index('rm -rf "$TEMP_DIR/pegaprox/plugins"') < clone.index(
        'cp -r "$TEMP_DIR/pegaprox/"* "$INSTALL_DIR/"')
    for script in ('deploy.sh', 'update.sh'):
        assert subprocess.run(['bash', '-n', os.path.join(ROOT, script)]).returncode == 0, script


def test_the_update_manifest_carries_the_new_files():
    manifest = json.loads(_read('version.json'))['update_files']
    assert 'packaging/plugins/sync_plugins.py' in manifest
    assert 'packaging/docker/entrypoint.sh' not in manifest
