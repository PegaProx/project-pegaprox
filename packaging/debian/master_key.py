#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Put the master key of a package install in /etc/pegaprox/secret.key before PegaProx starts.

NS Nov 2026 (#1226) - with python3-sqlcipher3 in Depends the first start encrypts the
database, and with no key in /etc/pegaprox the key store makes one in the config
directory (config/.pegaprox.key), right next to the database it protects. The postinst
and the unit (ExecStartPre, as root) run this, so the key is in place before every start.
An image built with the package gets its key on the first boot of each copy: the
postinst leaves it out where no systemd runs, as in an image build.

    master_key.py --key /etc/pegaprox/secret.key --state-dir /var/lib/pegaprox
                  --user pegaprox [--key-owner root] [--home DIR] [--unit pegaprox.service]

By what it finds, in the order the key store reads it (pegaprox/core/keystore.py):
- PEGAPROX_DB_KEY, a credential db-key or PEGAPROX_KEY_FILE in the unit: the key is the
  admin's, nothing is touched
- a key in --key: kept as it is. A root-owned one the service cannot read (0600, or
  another group) gets 0640 root:<group of the service user>, as deploy.sh does
- no key there and no database encrypted yet: a new key
- no key there and a database encrypted already (a start with sqlcipher3 before this
  existed): the key that opens it, ~/.config/pegaprox/secret.key of the service user or
  config/.pegaprox.key, goes there byte for byte, never a new one. The old file stays:
  config/.pegaprox.key is also the Fernet key the database layer reads old fields with
- whatever it cannot tell apart: nothing is written, and it says why

The config directory comes from the unit (WorkingDirectory, PEGAPROX_CONFIG_DIR) where
systemd answers, else <state-dir>/config. A symlink in /etc/pegaprox is followed, as the
key store does, but nothing it points to is changed here. Exit status 0 when the key is in
place or not ours to place, 1 when it refused, 2 on wrong arguments.
"""
import argparse
import base64
import fnmatch
import grp
import os
import pwd
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
from urllib.parse import quote

# the key store reads key files with its own decoder, so does this
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from pegaprox.core.keystore import _decode_key_string  # noqa: E402
from pegaprox.core.dbcrypto import file_state  # noqa: E402

DATABASES = ('pegaprox.db', 'syslog.db')
LEGACY_KEY = '.pegaprox.key'            # pegaprox.constants.KEY_FILE
# sealed with the master key by the versions before the database; the migration reads them
LEGACY_SEALED = ('clusters.enc', 'users.enc', 'sessions.enc', 'audit.log.enc')
CREDENTIALS = ('LoadCredential', 'LoadCredentialEncrypted', 'SetCredential',
               'SetCredentialEncrypted', 'ImportCredential')
KEY_MODE = 0o640
DIR_MODE = 0o750
# what keystore._enforce_perms turns down
LOOSE = stat.S_IWGRP | stat.S_IXGRP | stat.S_IRWXO


class Refused(Exception):
    pass


def info(msg):
    print(f'pegaprox: {msg}', flush=True)


def decode_key(data):
    """The 32 raw bytes of a key file as keystore._from_file reads them, None for no key."""
    data = data.strip()
    try:
        return _decode_key_string(data.decode('ascii') if all(c < 128 for c in data) else data)
    except ValueError:
        return None


# --- what systemd has for the unit ------------------------------------------------------

def _systemctl(*args):
    if not shutil.which('systemctl'):
        return ''
    try:
        p = subprocess.run(['systemctl', *args], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return ''
    return p.stdout if p.returncode == 0 else ''


def _env_file(path):
    out = {}
    try:
        with open(path, encoding='utf-8') as fh:
            lines = fh.read().splitlines()
    except (OSError, UnicodeDecodeError):
        return out
    for line in lines:
        line = line.strip()
        if not line or line.startswith(('#', ';')) or '=' not in line:
            continue
        name, _, value = line.partition('=')
        value = value.strip()
        if len(value) > 1 and value[0] == value[-1] and value[0] in '"\'':
            value = value[1:-1]
        out[name.strip()] = value
    return out


def unit_view(unit):
    """(environment, working directory, credential names) of the unit, ({}, None, []) where
    systemd does not answer. Credentials come from the unit files: show prints them as
    [unprintable]."""
    env, files, workdir, creds = {}, [], None, []
    if not unit:
        return env, workdir, creds
    for line in _systemctl('show', '-p', 'Environment', '-p', 'EnvironmentFiles',
                           '-p', 'WorkingDirectory', unit).splitlines():
        name, _, value = line.partition('=')
        if name == 'Environment':
            for item in shlex.split(value):
                k, _, v = item.partition('=')
                env[k] = v
        elif name == 'EnvironmentFiles' and value:
            files.append(value.split(' (')[0])
        elif name == 'WorkingDirectory' and value:
            workdir = value.lstrip('-!')
    # EnvironmentFile= wins over Environment=
    for path in files:
        env.update(_env_file(path))
    for line in _systemctl('cat', unit).splitlines():
        name, _, value = line.strip().partition('=')
        if name.strip() in CREDENTIALS:
            value = value.strip()
            if not value:
                creds = []          # an empty assignment resets the list
            else:
                creds.append(value.split(':')[0].strip())
    return env, workdir, creds


# --- the databases ----------------------------------------------------------------------

def opens(db_path, raw, uid, gid):
    """True when `raw` unlocks the SQLCipher database, False when SQLCipher says it is not
    a database with it, None when that cannot be told (no sqlcipher3, locked, unreadable).
    Opened as the service user, read-only, the way dbcrypto.connect keys it: a root-owned
    -shm next to it would lock the service out of its own database."""
    try:
        import sqlcipher3
    except Exception:
        return None
    pid = os.fork()
    if pid == 0:
        code = 3
        try:
            # SQLCipher writes its own error lines to stderr on a wrong key
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, 2)
            if os.geteuid() != uid:
                os.setgroups([])
                os.setgid(gid)
                os.setuid(uid)
            conn = sqlcipher3.connect(f'file:{quote(db_path)}?mode=ro', uri=True, timeout=10)
            try:
                conn.execute('PRAGMA cipher_memory_security = OFF')
                conn.execute(f"PRAGMA key = \"x'{raw.hex()}'\"")
                conn.execute('PRAGMA cipher_compatibility = 4')
                conn.execute('SELECT count(*) FROM sqlite_master').fetchone()
                code = 0
            finally:
                conn.close()
        except sqlcipher3.DatabaseError as e:
            code = 2 if 'not a database' in str(e) else 3
        except BaseException:
            code = 3
        os._exit(code)
    _, status = os.waitpid(pid, 0)
    return {0: True, 2: False}.get(os.waitstatus_to_exitcode(status))


def db_states(config_dir):
    states = {}
    for name in DATABASES:
        path = os.path.join(config_dir, name)
        states[path] = file_state(path)
    odd = [f'{p} ({s})' for p, s in states.items() if s not in ('missing', 'empty', 'plain', 'encrypted')]
    if odd:
        raise Refused(f'cannot read {", ".join(odd)}')
    return [p for p, s in states.items() if s == 'encrypted']


# --- the key file -----------------------------------------------------------------------

def _read_key(path):
    try:
        with open(path, 'rb') as fh:
            data = fh.read(4096)
    except OSError as e:
        raise Refused(f'cannot read {path}: {e.strerror}')
    raw = decode_key(data)
    if raw is None:
        raise Refused(f'{path} holds no 32-byte key')
    return data, raw


def _service_can_enter(st, uid, gid):
    if st.st_uid == uid:
        return bool(st.st_mode & stat.S_IXUSR)
    if st.st_gid == gid:
        return bool(st.st_mode & stat.S_IXGRP)
    return bool(st.st_mode & stat.S_IXOTH)


def _key_dir(path, owner, gid, uid, repair=True):
    """The directory of the key, made where it is missing. The key store takes a key the
    service cannot get to for none and goes on to the config directory, so the service has
    to get through it. A symlink is followed and what it points to is left alone, so one
    the service cannot enter is refused."""
    d = os.path.dirname(path)
    try:
        st = os.stat(d)
    except FileNotFoundError:
        if os.path.islink(d):
            raise Refused(f'{d} is a symlink to {os.readlink(d)}, which is not there')
        if repair:
            os.mkdir(d, DIR_MODE)
            os.chown(d, owner, gid)
            os.chmod(d, DIR_MODE)
        return
    if not stat.S_ISDIR(st.st_mode):
        raise Refused(f'{d} is not a directory')
    if _service_can_enter(st, uid, gid):
        return
    if os.path.islink(d):
        raise Refused(f'{d} points to {os.path.realpath(d)}, which the service user cannot enter. '
                      f'Give that one the group {grp.getgrgid(gid).gr_name} and g+rx')
    if repair and st.st_uid == owner:
        os.chown(d, owner, gid)
        os.chmod(d, stat.S_IMODE(st.st_mode) | stat.S_IRGRP | stat.S_IXGRP)
        info(f'{d}: the service user could not reach the key, its group is now {grp.getgrgid(gid).gr_name}')


def check_existing(path, owner, uid, gid):
    """The key in `path`, its permissions repaired where that is the known deploy.sh case.
    Through a symlink it is read and checked as the key store does, but not repaired: a
    target the service cannot read is refused."""
    _key_dir(path, owner, gid, uid, repair=False)
    if not os.path.exists(path):
        raise Refused(f'{path} is a symlink to {os.readlink(path)}, which is not there')
    st = os.stat(path)
    if not stat.S_ISREG(st.st_mode):
        raise Refused(f'{path} is not a regular file')
    mode = stat.S_IMODE(st.st_mode)
    if mode & LOOSE:
        raise Refused(f'{path} has mode {mode:04o}, PegaProx refuses a key that others can read '
                      'or write. Check who had access, then chmod 0640 it')
    _, raw = _read_key(path)
    if st.st_uid == owner and (st.st_gid != gid or not mode & stat.S_IRGRP):
        if os.path.islink(path):
            raise Refused(f'{path} points to {os.path.realpath(path)}, which is {mode:04o} with group '
                          f'id {st.st_gid}: the service cannot read it. Give that one {KEY_MODE:04o} '
                          f'and the group {grp.getgrgid(gid).gr_name}')
        os.chown(path, owner, gid)
        os.chmod(path, KEY_MODE)
        info(f'{path} was {mode:04o} with group id {st.st_gid}, the service could not read it: '
             f'now {KEY_MODE:04o} with group {grp.getgrgid(gid).gr_name}')
    _key_dir(path, owner, gid, uid)
    return raw


def write_new(path, data, owner, gid, uid):
    """`data` into `path`, 0640 owner:gid, complete or not at all. Never over a file that is
    there: link() fails on one that appeared in the meantime."""
    _key_dir(path, owner, gid, uid)
    tmp = f'{path}.new.{os.getpid()}'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        try:
            os.write(fd, data)
            os.fchown(fd, owner, gid)
            os.fchmod(fd, KEY_MODE)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.link(tmp, path)
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
    dfd = os.open(os.path.dirname(path), os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def _known_keys(home, config_dir):
    """The key files the key store reads after --key, in its order (tiers 5 and 6)."""
    return [os.path.join(home, '.config', 'pegaprox', 'secret.key'),
            os.path.join(config_dir, LEGACY_KEY)]


def _who_opens(db, keys, uid, gid):
    for cand in keys:
        try:
            _, raw = _read_key(cand)
        except Refused:
            continue
        if opens(db, raw, uid, gid):
            return cand
    return None


def place_key(a):
    pw = pwd.getpwnam(a.user)
    uid, gid = pw.pw_uid, pw.pw_gid
    owner = pwd.getpwnam(a.key_owner).pw_uid
    home = a.home or pw.pw_dir
    env, workdir, creds = unit_view(a.unit)
    if env.get('PEGAPROX_DB_KEY', '').strip():
        info(f'{a.unit} sets PEGAPROX_DB_KEY, its master key is not touched here')
        return 0
    if any(fnmatch.fnmatch('db-key', c) for c in creds):
        info(f'{a.unit} loads the credential db-key, its master key is not touched here')
        return 0
    key_file = env.get('PEGAPROX_KEY_FILE', '').strip()
    if key_file.startswith('~/'):
        key_file = os.path.join(home, key_file[2:])
    if key_file and os.path.isfile(key_file):
        info(f'{a.unit} reads its master key from {key_file} (PEGAPROX_KEY_FILE), it is not touched here')
        return 0

    base = home if workdir == '~' else workdir or a.state_dir
    config_dir = os.path.join(base, env.get('PEGAPROX_CONFIG_DIR', '').strip() or 'config')
    encrypted = db_states(config_dir)
    keys = _known_keys(home, config_dir)

    if os.path.lexists(a.key):
        raw = check_existing(a.key, owner, uid, gid)
        for db in encrypted:
            if opens(db, raw, uid, gid) is False:
                other = _who_opens(db, keys, uid, gid)
                raise Refused(f'{db} is encrypted, and {a.key} does not open it, PegaProx will not '
                              'start so. ' + (f'{other} opens it: check both, then copy that one to {a.key}'
                                              if other else 'Neither does a key file of the config directory'))
        return 0

    # the key the key store would take today, with nothing in --key
    current = next((k for k in keys if os.path.isfile(k)), None)
    sealed = [os.path.join(config_dir, n) for n in LEGACY_SEALED
              if os.path.exists(os.path.join(config_dir, n))]

    if encrypted or (current and sealed):
        if not current:
            raise Refused(f'{", ".join(encrypted)} is encrypted, and there is no key file this '
                          f'package knows of. Not making one: put the key that opens it in {a.key}')
        data, raw = _read_key(current)
        for db in encrypted:
            ok = opens(db, raw, uid, gid)
            if ok is None:
                raise Refused(f'cannot check whether {current} opens {db} (is python3-sqlcipher3 '
                              'installed?). Not copying a key that may be the wrong one')
            if not ok:
                other = _who_opens(db, keys, uid, gid)
                raise Refused(f'{db} is encrypted, and {current} does not open it. Not making a key: '
                              + (f'{other} opens it, copy that one to {a.key}' if other
                                 else f'put the key that opens it in {a.key}'))
        write_new(a.key, data, owner, gid, uid)
        info(f'copied {current} to {a.key}, the key {", ".join(encrypted + sealed)} '
             f'{"is" if len(encrypted + sealed) == 1 else "are"} encrypted with. No new key was made')
        if current == keys[-1]:
            info(f'{current} stays: the database layer reads old fields with it too, so a '
                 f'backup of {config_dir} still holds the key (docs/SECURITY.md)')
        return 0

    write_new(a.key, base64.urlsafe_b64encode(secrets.token_bytes(32)), owner, gid, uid)
    info(f'created the master key {a.key} ({KEY_MODE:04o} {a.key_owner}:{grp.getgrgid(gid).gr_name})')
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(description='Place the master key of a package install.')
    p.add_argument('--key', required=True, help='/etc/pegaprox/secret.key')
    p.add_argument('--state-dir', required=True, help='the working directory of the service')
    p.add_argument('--user', required=True, help='the user the service runs as')
    p.add_argument('--key-owner', default='root')
    p.add_argument('--home', help='home of the service user (default: from passwd)')
    p.add_argument('--unit', default='', help='the systemd unit, for its environment')
    a = p.parse_args(argv)
    try:
        return place_key(a)
    except Refused as e:
        print(f'pegaprox: {e}. Nothing was changed.', file=sys.stderr, flush=True)
    except (KeyError, OSError) as e:
        print(f'pegaprox: could not place the master key: {e}', file=sys.stderr, flush=True)
    return 1


if __name__ == '__main__':
    sys.exit(main())
