"""#1226 - the Debian package puts its master key in /etc/pegaprox before PegaProx starts.

With python3-sqlcipher3 in Depends the first start encrypts the database, and with no key
in /etc/pegaprox the key store makes one in the config directory, next to the database.
packaging/debian/master_key.py runs from the postinst and before every start (ExecStartPre)
and has to do the safe thing in each state an install can be in, above all the one where a
start with sqlcipher3 already encrypted the database with that config directory key: a new
key in /etc would win over it and the database would not open again.

The helper runs here as it does on a host, as a process, on a temp root with the current
user as the service user. The states a real install gets into are made by the real key store
and dbcrypto (a first start with nothing in /etc), and the checks afterwards resolve the key
the way the next start does.

NS Nov 2026
"""
import base64
import grp
import os
import pwd
import sqlite3
import stat
import subprocess
import sys
import types
from pathlib import Path

import pytest

from pegaprox.core import dbcrypto, keystore

ROOT = Path(__file__).resolve().parent.parent
HELPER = ROOT / 'packaging' / 'debian' / 'master_key.py'
ME = pwd.getpwuid(os.getuid()).pw_name
MY_GID = pwd.getpwuid(os.getuid()).pw_gid
needs_sqlcipher = pytest.mark.skipif(dbcrypto.BACKEND != 'sqlcipher', reason='needs sqlcipher3')


def _helper_module():
    # compiled by hand: an import would leave a __pycache__ in packaging/debian
    mod = types.ModuleType('pp_master_key_1226')
    mod.__file__ = str(HELPER)
    exec(compile(HELPER.read_text(encoding='utf-8'), str(HELPER), 'exec'), mod.__dict__)
    return mod


def _new_key():
    return base64.urlsafe_b64encode(os.urandom(32))


class Host:
    """The paths of a package install under a temp root."""

    def __init__(self, tmp):
        self.tmp = tmp
        self.key = tmp / 'etc' / 'pegaprox' / 'secret.key'
        self.state = tmp / 'var' / 'lib' / 'pegaprox'
        self.config = self.state / 'config'
        self.db = self.config / 'pegaprox.db'
        self.syslog = self.config / 'syslog.db'
        self.legacy = self.config / '.pegaprox.key'
        self.home = tmp / 'home'
        self.user_key = self.home / '.config' / 'pegaprox' / 'secret.key'
        (tmp / 'etc').mkdir()
        self.config.mkdir(parents=True)
        self.home.mkdir()

    def run(self, unit=None, path=None):
        args = [sys.executable, '-I', '-B', str(HELPER), '--key', str(self.key),
                '--state-dir', str(self.state), '--user', ME, '--key-owner', ME,
                '--home', str(self.home)]
        if unit:
            args += ['--unit', unit]
        env = dict(os.environ)
        if path:
            env['PATH'] = f'{path}:{env.get("PATH", "")}'
        return subprocess.run(args, capture_output=True, text=True, timeout=120, env=env)


@pytest.fixture
def host(tmp_path, monkeypatch):
    """A host, and the key store and dbcrypto of this process looking at it as the
    service does: no env tier, HOME of the service user, config/ in the state directory."""
    h = Host(tmp_path)
    for var in ('PEGAPROX_DB_KEY', 'PEGAPROX_KEY_FILE', 'CREDENTIALS_DIRECTORY'):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv('HOME', str(h.home))
    monkeypatch.setattr(keystore, 'SYSTEM_KEY_PATH', h.key)
    monkeypatch.setattr(keystore, '_legacy_key_path', lambda: h.legacy)
    monkeypatch.setattr(keystore, '_CACHED', None)
    monkeypatch.setattr(dbcrypto, '_AUTO_MIG_DONE', set())
    monkeypatch.setenv('PEGAPROX_PLAIN_BACKUP_RETENTION_S', '0')
    return h


def write_key(path, data=None, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    data = data or _new_key()
    path.write_bytes(data)
    path.chmod(mode)
    return data


def plain_db(path):
    c = sqlite3.connect(path)
    c.execute('PRAGMA journal_mode = WAL')
    c.execute('CREATE TABLE server_settings (key TEXT PRIMARY KEY, value TEXT)')
    c.execute("INSERT INTO server_settings VALUES ('port', '5000')")
    c.commit()
    c.close()


def encrypted_db(path, key_b64):
    import sqlcipher3
    raw = base64.urlsafe_b64decode(key_b64)
    c = sqlcipher3.connect(str(path))
    c.execute(f"PRAGMA key = \"x'{raw.hex()}'\"")
    c.execute('PRAGMA cipher_compatibility = 4')
    c.execute('PRAGMA journal_mode = WAL')
    c.execute('CREATE TABLE server_settings (key TEXT PRIMARY KEY, value TEXT)')
    c.commit()
    c.close()


def first_start(h):
    """What a start of PegaProx does with the database before anything else (app.main):
    resolve the key and encrypt what is still plain. Returns the key it used."""
    keystore.reset_cache()
    dbcrypto._AUTO_MIG_DONE.clear()
    for db in (h.db, h.syslog):
        if db.exists():
            dbcrypto.ensure_db_encrypted(str(db))
    mk = keystore.load_master_key()
    keystore.reset_cache()
    return mk


def next_start_state(h, db=None):
    """detect_db_state with the key the next start resolves: 'encrypted' when it opens."""
    keystore.reset_cache()
    try:
        return dbcrypto.detect_db_state(str(db or h.db))
    finally:
        keystore.reset_cache()


def _mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


# --- the states of an install -----------------------------------------------------------------

def test_a_fresh_install_gets_its_own_key_in_etc(host):
    r = host.run()
    assert r.returncode == 0, r.stdout + r.stderr
    data = host.key.read_bytes()
    assert len(data) == 44 and len(base64.urlsafe_b64decode(data)) == 32
    assert _mode(host.key) == 0o640 and os.stat(host.key).st_gid == MY_GID
    assert _mode(host.key.parent) == 0o750
    assert 'created the master key' in r.stdout
    assert not host.legacy.exists()
    mk = keystore.load_master_key()
    assert mk.source_path == str(host.key) and not mk.is_legacy
    keystore.reset_cache()
    # the key store reads it as it was written
    assert mk.key_b64 == data


@needs_sqlcipher
def test_a_plain_database_is_encrypted_with_the_new_key_not_with_the_one_next_to_it(host):
    """The case of the PR: an upgrade on a plain database, config/.pegaprox.key there from
    the field layer. The first start after the upgrade encrypts with the key in /etc."""
    plain_db(host.db)
    legacy = write_key(host.legacy)
    r = host.run()
    assert r.returncode == 0, r.stdout + r.stderr
    assert host.key.read_bytes() != legacy
    assert host.legacy.read_bytes() == legacy
    mk = first_start(host)
    assert mk.source_path == str(host.key)
    assert dbcrypto.file_state(str(host.db)) == 'encrypted'
    assert next_start_state(host) == 'encrypted'
    # the key in the config directory does not open it
    host.key.unlink()
    assert next_start_state(host) == 'unknown-key'


@needs_sqlcipher
@pytest.mark.parametrize('which', ['pegaprox.db', 'syslog.db'])
def test_a_database_a_start_encrypted_with_the_config_dir_key_keeps_that_key(host, which):
    """An install that started with sqlcipher3 before this: the key store made
    config/.pegaprox.key and encrypted the database with it. That key goes to /etc, byte
    for byte; a new one there would win the next start and lock the database out."""
    plain_db(host.db)
    plain_db(host.syslog)
    keystore.reset_cache()
    dbcrypto.ensure_db_encrypted(str(host.config / which))
    keystore.reset_cache()
    assert host.legacy.is_file() and not host.key.exists()
    legacy = host.legacy.read_bytes()

    r = host.run()
    assert r.returncode == 0, r.stdout + r.stderr
    assert host.key.read_bytes() == legacy
    assert host.legacy.read_bytes() == legacy
    assert _mode(host.key) == 0o640
    assert 'No new key was made' in r.stdout and str(host.legacy) in r.stdout
    assert next_start_state(host, host.config / which) == 'encrypted'
    mk = first_start(host)
    assert mk.source_path == str(host.key)
    # and the database that was still plain is encrypted with that same key now
    assert next_start_state(host, host.db) == next_start_state(host, host.syslog) == 'encrypted'


@needs_sqlcipher
def test_the_key_of_the_service_users_home_comes_before_the_config_dir(host):
    home_key = write_key(host.user_key)
    write_key(host.legacy)
    encrypted_db(host.db, home_key)
    r = host.run()
    assert r.returncode == 0, r.stdout + r.stderr
    assert host.key.read_bytes() == home_key
    assert next_start_state(host) == 'encrypted'


def test_files_sealed_before_the_database_keep_their_key(host):
    """clusters.enc and the others of the versions before the database are Fernet-sealed
    with the master key the key store resolves; the migration of a database that is not
    there yet reads them with it."""
    legacy = write_key(host.legacy)
    (host.config / 'clusters.enc').write_bytes(b'gAAAA-sealed')
    r = host.run()
    assert r.returncode == 0, r.stdout + r.stderr
    assert host.key.read_bytes() == legacy


@needs_sqlcipher
def test_a_key_in_etc_is_kept_as_it_is(host):
    data = write_key(host.key, mode=0o640)
    encrypted_db(host.db, data)
    write_key(host.legacy)
    before = os.stat(host.key)
    for _ in range(2):
        r = host.run()
        assert r.returncode == 0, r.stdout + r.stderr
        assert r.stdout == '' and r.stderr == ''
    after = os.stat(host.key)
    assert host.key.read_bytes() == data
    assert (after.st_ino, after.st_mtime_ns, after.st_mode) == (before.st_ino, before.st_mtime_ns, before.st_mode)


def test_running_it_again_changes_nothing(host):
    plain_db(host.db)
    assert host.run().returncode == 0
    data, ino = host.key.read_bytes(), os.stat(host.key).st_ino
    r = host.run()
    assert r.returncode == 0 and r.stdout == '' and r.stderr == ''
    assert host.key.read_bytes() == data and os.stat(host.key).st_ino == ino
    assert sorted(os.listdir(host.key.parent)) == ['secret.key']


def test_a_key_the_service_cannot_read_gets_the_mode_deploy_sh_gives_it(host):
    """deploy.sh before #417 wrote 0600 root:pegaprox: unreadable for the service. Here the
    key owner is the current user, as root is on a host."""
    data = write_key(host.key, mode=0o600)
    r = host.run()
    assert r.returncode == 0, r.stdout + r.stderr
    assert _mode(host.key) == 0o640 and host.key.read_bytes() == data
    assert 'the service could not read it' in r.stdout


@pytest.mark.parametrize('mode', [0o644, 0o660, 0o604])
def test_a_key_others_can_read_or_write_is_refused_and_left(host, mode):
    data = write_key(host.key, mode=mode)
    r = host.run()
    assert r.returncode == 1
    assert f'{mode:04o}' in r.stderr and 'Nothing was changed' in r.stderr
    assert _mode(host.key) == mode and host.key.read_bytes() == data


def test_a_key_file_without_a_key_is_refused(host):
    write_key(host.key, data=b'not a key\n', mode=0o640)
    r = host.run()
    assert r.returncode == 1 and 'holds no 32-byte key' in r.stderr


@needs_sqlcipher
def test_a_key_in_etc_that_does_not_open_the_database_is_reported_not_replaced(host):
    legacy = write_key(host.legacy)
    encrypted_db(host.db, legacy)
    other = write_key(host.key, mode=0o640)
    r = host.run()
    assert r.returncode == 1
    assert 'does not open it' in r.stderr and f'{host.legacy} opens it' in r.stderr
    assert host.key.read_bytes() == other


@needs_sqlcipher
def test_an_encrypted_database_the_known_keys_do_not_open_gets_no_key(host):
    write_key(host.legacy)
    encrypted_db(host.db, _new_key())
    r = host.run()
    assert r.returncode == 1 and 'does not open it' in r.stderr
    assert not host.key.exists()
    assert not host.key.parent.exists() or os.listdir(host.key.parent) == []


def test_an_encrypted_database_and_no_key_file_gets_no_key(host):
    """Encrypted with a key that is somewhere else (a credential, an env var the unit does
    not show here, a key restored to the wrong place): a new key is the one thing that is
    sure to be wrong. Told from the header alone, no sqlcipher3 needed."""
    host.db.write_bytes(os.urandom(8192))
    r = host.run()
    assert r.returncode == 1
    assert 'no key file this package knows of' in r.stderr
    assert not host.key.exists()


def test_a_database_it_cannot_read_gets_no_key(host):
    host.db.mkdir()
    r = host.run()
    assert r.returncode == 1 and 'cannot read' in r.stderr
    assert not host.key.exists()


def test_an_empty_database_file_counts_as_none(host):
    host.db.write_bytes(b'')
    r = host.run()
    assert r.returncode == 0, r.stdout + r.stderr
    assert host.key.is_file()


# --- what the unit says --------------------------------------------------------------------

def _fake_systemctl(tmp_path, show='', cat=''):
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir(exist_ok=True)
    (tmp_path / 'show.txt').write_text(show)
    (tmp_path / 'cat.txt').write_text(cat)
    script = bin_dir / 'systemctl'
    script.write_text('#!/bin/sh\n'
                      f'case "$1" in show) cat "{tmp_path}/show.txt" ;; cat) cat "{tmp_path}/cat.txt" ;; '
                      '*) exit 1 ;; esac\n')
    script.chmod(0o755)
    return bin_dir


@pytest.mark.parametrize('show,cat', [
    (f'Environment=PEGAPROX_DB_KEY={base64.urlsafe_b64encode(bytes(32)).decode()}\n', ''),
    ('', '[Service]\nLoadCredentialEncrypted=db-key:/etc/pegaprox/secret.key.cred\n'),
    ('', '[Service]\nLoadCredential=db-key\n'),
    ('', '[Service]\nImportCredential=db-*\n'),
], ids=['env-key', 'credential-encrypted', 'credential', 'import-glob'])
def test_a_key_the_admin_gives_the_unit_is_left_to_the_admin(host, tmp_path, show, cat):
    encrypted_db_header = os.urandom(8192)
    host.db.write_bytes(encrypted_db_header)
    r = host.run(unit='pegaprox.service', path=_fake_systemctl(tmp_path, show, cat))
    assert r.returncode == 0, r.stdout + r.stderr
    assert 'is not touched here' in r.stdout
    assert not host.key.exists() and host.db.read_bytes() == encrypted_db_header


def test_a_key_file_of_the_unit_counts_only_where_it_is(host, tmp_path):
    there = write_key(tmp_path / 'elsewhere.key')
    bin_dir = _fake_systemctl(tmp_path, f'Environment=PEGAPROX_KEY_FILE={tmp_path}/elsewhere.key\n')
    r = host.run(unit='pegaprox.service', path=bin_dir)
    assert r.returncode == 0 and 'PEGAPROX_KEY_FILE' in r.stdout and not host.key.exists()
    # the key store falls through to /etc when the file is not there, so this does too
    (tmp_path / 'elsewhere.key').unlink()
    r = host.run(unit='pegaprox.service', path=bin_dir)
    assert r.returncode == 0 and host.key.read_bytes() != there


def test_a_credential_reset_by_a_drop_in_does_not_count(host, tmp_path):
    cat = ('[Service]\nLoadCredentialEncrypted=db-key:/etc/pegaprox/secret.key.cred\n'
           '# /etc/systemd/system/pegaprox.service.d/override.conf\n[Service]\nLoadCredentialEncrypted=\n')
    r = host.run(unit='pegaprox.service', path=_fake_systemctl(tmp_path, '', cat))
    assert r.returncode == 0 and host.key.is_file()


@needs_sqlcipher
def test_the_config_dir_the_unit_moved_is_the_one_it_looks_at(host, tmp_path):
    """PEGAPROX_CONFIG_DIR (#826) relative to the WorkingDirectory of the unit, from an
    EnvironmentFile: the database there is encrypted with the key there."""
    work = tmp_path / 'srv'
    moved = work / 'state' / 'cfg'
    moved.mkdir(parents=True)
    legacy = write_key(moved / '.pegaprox.key')
    encrypted_db(moved / 'pegaprox.db', legacy)
    (tmp_path / 'pegaprox.env').write_text('# moved\nPEGAPROX_CONFIG_DIR="state/cfg"\n')
    show = (f'Environment=PATH=/usr/bin "PEGAPROX_X=a b"\n'
            f'EnvironmentFiles={tmp_path}/pegaprox.env (ignore_errors=yes)\n'
            f'WorkingDirectory=!{work}\n')
    r = host.run(unit='pegaprox.service', path=_fake_systemctl(tmp_path, show))
    assert r.returncode == 0, r.stdout + r.stderr
    assert host.key.read_bytes() == legacy


def test_unit_view_reads_show_and_cat(tmp_path, monkeypatch):
    (tmp_path / 'env').write_text("PEGAPROX_DB_KEY='from-file'\n; comment\nexport_like\n")
    show = ('Environment="PEGAPROX_CONFIG_DIR=/srv/a b" PEGAPROX_DB_KEY=inline\n'
            f'EnvironmentFiles={tmp_path}/env (ignore_errors=yes)\n'
            f'EnvironmentFiles={tmp_path}/missing (ignore_errors=yes)\n'
            'WorkingDirectory=!/var/lib/pegaprox\n'
            'LoadCredentialEncrypted=[unprintable]\n')
    cat = '[Service]\nSetCredential=other:x\nSetCredentialEncrypted=db-key: abc\n'
    monkeypatch.setenv('PATH', f'{_fake_systemctl(tmp_path, show, cat)}:{os.environ["PATH"]}')
    env, workdir, creds = _helper_module().unit_view('pegaprox.service')
    assert env['PEGAPROX_CONFIG_DIR'] == '/srv/a b'
    assert env['PEGAPROX_DB_KEY'] == 'from-file'     # EnvironmentFile= wins
    assert workdir == '/var/lib/pegaprox'
    assert creds == ['other', 'db-key']


def test_without_systemd_it_goes_by_the_state_dir(monkeypatch, tmp_path):
    monkeypatch.setenv('PATH', str(tmp_path))       # no systemctl at all
    assert _helper_module().unit_view('pegaprox.service') == ({}, None, [])


# --- reading and writing the key ----------------------------------------------------------------

_FIXED = bytes(range(7, 39))
_KEY_FILES = {
    'base64': base64.urlsafe_b64encode(_FIXED),
    'base64-newline': base64.urlsafe_b64encode(_FIXED) + b'\n',
    'base64-spaces-crlf': b'  ' + base64.urlsafe_b64encode(_FIXED) + b'\r\n',
    'hex': _FIXED.hex().encode(),
    'hex-upper-newline': _FIXED.hex().upper().encode() + b'\n',
    'ascii-32': b'A' * 32,
    'garbage': b'not a key',
    'empty': b'',
    'raw-32': bytes(range(200, 232)),
    'raw-40': bytes(range(200, 240)),
}


@pytest.mark.parametrize('data', list(_KEY_FILES.values()), ids=list(_KEY_FILES))
def test_the_key_is_read_the_way_the_key_store_reads_it(tmp_path, data):
    f = tmp_path / 'k'
    f.write_bytes(data)
    f.chmod(0o600)
    try:
        want = keystore._from_file(f, source='t').key_raw
    except RuntimeError:
        want = None
    assert _helper_module().decode_key(data) == want


def test_a_key_is_never_written_over_one_that_appeared(tmp_path):
    mod = _helper_module()
    target = tmp_path / 'etc' / 'secret.key'
    target.parent.mkdir()
    target.write_bytes(b'already there')
    with pytest.raises(FileExistsError):
        mod.write_new(str(target), _new_key(), os.getuid(), MY_GID, os.getuid())
    assert target.read_bytes() == b'already there'
    assert os.listdir(target.parent) == ['secret.key']


# --- the package -------------------------------------------------------------------------------

def _read(*rel):
    return (ROOT.joinpath(*rel)).read_text(encoding='utf-8')


HELPER_ARGS = ('/usr/lib/pegaprox/packaging/debian/master_key.py --key /etc/pegaprox/secret.key '
               '--state-dir /var/lib/pegaprox --user pegaprox --unit pegaprox.service')


def _joined(text):
    return ' '.join(text.replace('\\\n', ' ').split())


def test_the_package_ships_the_helper_and_the_unit_runs_it_as_root_before_every_start():
    assert ['packaging/debian/master_key.py', 'usr/lib/pegaprox/packaging/debian'] in [
        line.split() for line in _read('debian', 'install').splitlines()]
    unit = _read('systemd', 'pegaprox.service')
    pre = [ln for ln in unit.replace('\\\n', ' ').splitlines() if ln.startswith('ExecStartPre=')]
    assert len(pre) == 1
    # "+": as root, User= and the sandboxing do not apply to this one line
    assert ' '.join(pre[0].split()) == f'ExecStartPre=+/usr/bin/python3 -I -B {HELPER_ARGS}'
    assert unit.index('ExecStartPre=') < unit.index('ExecStart=/usr/bin/pegaprox/pegaprox-wrapper')
    assert 'User=pegaprox' in unit.splitlines() and 'WorkingDirectory=/var/lib/pegaprox' in unit.splitlines()


def test_the_postinst_runs_it_before_the_restart_and_only_where_systemd_runs():
    postinst = _read('debian', 'pegaprox.postinst')
    flat = _joined(postinst)
    call = f'/usr/bin/python3 -I -B {HELPER_ARGS} || echo'
    assert call in flat
    at = postinst.index('packaging/debian/master_key.py')
    assert postinst.index('useradd') < at and postinst.index('chown pegaprox:pegaprox /var/lib/pegaprox') < at
    assert at < postinst.index('systemctl daemon-reload') < postinst.index('systemctl restart pegaprox.service')
    guard = postinst.rindex('if [ -d /run/systemd/system ]; then', 0, at)
    assert 'fi' not in postinst[guard:at].split()
    assert postinst.rstrip().splitlines()[-1] == '#DEBHELPER#'


def _postinst_on(tmp_path, systemd_running=True, before=None):
    """The real postinst with its paths moved under a temp root (as in the #1134 test), the
    helper and the package it reads beside it; id, useradd, chown and systemctl are stubs."""
    root = tmp_path / 'root'
    lib = root / 'usr' / 'lib' / 'pegaprox'
    (lib / 'packaging' / 'debian').mkdir(parents=True)
    (lib / 'packaging' / 'debian' / 'master_key.py').write_bytes(HELPER.read_bytes())
    (lib / 'pegaprox').symlink_to(ROOT / 'pegaprox')
    (root / 'etc').mkdir()
    (root / 'var' / 'lib' / 'pegaprox' / 'config').mkdir(parents=True)
    if before:
        before(root / 'var' / 'lib' / 'pegaprox' / 'config')
    run_dir = tmp_path / 'run-systemd-system'
    if systemd_running:
        run_dir.mkdir()
    stubs = tmp_path / 'stubs'
    stubs.mkdir()
    calls = tmp_path / 'calls.log'
    for cmd in ('id', 'useradd', 'chown', 'systemctl'):
        (stubs / cmd).write_text(f'#!/bin/sh\necho "{cmd} $*" >> "{calls}"\nexit 0\n')
        (stubs / cmd).chmod(0o755)
    text = _read('debian', 'pegaprox.postinst')
    for path in ('/var/lib/pegaprox', '/usr/share/pegaprox', '/usr/lib/pegaprox', '/etc/pegaprox'):
        text = text.replace(path, str(root) + path)
    text = text.replace('/run/systemd/system', str(run_dir))
    text = text.replace('--user pegaprox', f'--user {ME} --key-owner {ME} --home {tmp_path}')
    me = f'{ME}:{grp.getgrgid(MY_GID).gr_name}'
    text = text.replace('--owner pegaprox:pegaprox', f'--owner {me}')
    script = tmp_path / 'postinst'
    script.write_text(text)
    env = dict(os.environ, PATH=f'{stubs}:{os.environ.get("PATH", "")}')
    r = subprocess.run(['bash', str(script), 'configure'], env=env, capture_output=True, text=True,
                       timeout=120)
    return root, calls, r


@pytest.mark.skipif(not os.path.exists('/usr/bin/python3'), reason='the postinst calls /usr/bin/python3')
def test_the_postinst_places_the_key_before_it_restarts(tmp_path):
    root, calls, r = _postinst_on(tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    key = root / 'etc' / 'pegaprox' / 'secret.key'
    assert key.is_file() and _mode(key) == 0o640
    assert 'created the master key' in r.stdout
    log = calls.read_text()
    assert log.index('systemctl daemon-reload') < log.index('systemctl restart pegaprox.service')


@pytest.mark.skipif(not os.path.exists('/usr/bin/python3'), reason='the postinst calls /usr/bin/python3')
def test_an_image_build_leaves_the_key_to_the_first_boot(tmp_path):
    """No systemd running (distrobuilder, a chroot, a container build): a key made here
    would be in every copy of the image."""
    root, calls, r = _postinst_on(tmp_path, systemd_running=False)
    assert r.returncode == 0, r.stdout + r.stderr
    assert not (root / 'etc' / 'pegaprox').exists()


@pytest.mark.skipif(not os.path.exists('/usr/bin/python3'), reason='the postinst calls /usr/bin/python3')
def test_a_refusal_is_said_and_does_not_fail_the_package(tmp_path):
    """The configure goes through; the unit's ExecStartPre refuses the start in its place."""
    # an encrypted database and no key anywhere
    root, calls, r = _postinst_on(tmp_path, before=lambda cfg: (cfg / 'pegaprox.db').write_bytes(os.urandom(8192)))
    assert r.returncode == 0, r.stdout + r.stderr
    assert 'no key file this package knows of' in r.stderr
    assert 'PegaProx does not start until it is' in r.stderr
    assert not (root / 'etc' / 'pegaprox' / 'secret.key').exists()
    assert 'systemctl restart pegaprox.service' in calls.read_text()
