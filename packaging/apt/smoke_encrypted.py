#!/usr/bin/env python3
"""What a fresh package install has to show after its first start, checked from outside.

    sudo python3 -I packaging/apt/smoke_encrypted.py <keystore-status.json> <rootfs>

NS Nov 2026 (#1226) - the smoke test of apt-repo.yml installs the package on plain trixie
from the repository it just built, boots that tree and lets PegaProx start once. Then:
- --keystore-status (run as the service user, its JSON in the file) names
  /etc/pegaprox/secret.key, tier 4, and the database as SQLCipher and encrypted
- that key file is 0640 root:pegaprox and holds 32 bytes
- no file of the config directory holds the same key: config/.pegaprox.key is there, but
  it is the Fernet key of the field layer, not the one the database is encrypted with
Exit status 1 with every check that failed.
"""
import base64
import binascii
import json
import os
import stat
import sys

KEY = '/etc/pegaprox/secret.key'
CONFIG = '/var/lib/pegaprox/config'
DATABASE = CONFIG + '/pegaprox.db'


def _decode(data):
    data = data.strip()
    for decode in (base64.urlsafe_b64decode, lambda d: bytes.fromhex(d.decode('ascii'))):
        try:
            raw = decode(data)
        except (ValueError, binascii.Error):
            continue
        if len(raw) == 32:
            return raw
    return None


def _group_id(root, name):
    try:
        with open(os.path.join(root, 'etc/group'), encoding='utf-8') as fh:
            for line in fh:
                parts = line.strip().split(':')
                if len(parts) > 2 and parts[0] == name:
                    return int(parts[2])
    except OSError:
        pass
    return None


def check(status, root, owner=0):
    bad = []
    ks, db = status.get('keystore') or {}, status.get('db') or {}
    if ks.get('source_path') != KEY or ks.get('tier') != 4 or ks.get('is_legacy'):
        bad.append(f'the master key is {ks.get("source_path") or ks.get("source")} '
                   f'(tier {ks.get("tier")}), not {KEY}')
    if db.get('backend') != 'sqlcipher':
        # NS Nov 2026 - the status says why when the package is there and does not load
        why = db.get('sqlcipher_error')
        bad.append(f'the database backend is {db.get("backend")}: python3-sqlcipher3 '
                   + (f'is installed and does not load ({why})' if why else 'does not import'))
    state = (db.get('files') or {}).get(DATABASE)
    if state != 'encrypted' or db.get('encrypted_at_rest') is not True:
        bad.append(f'{DATABASE} is {state}, encrypted_at_rest {db.get("encrypted_at_rest")}')

    path = root + KEY
    try:
        st = os.lstat(path)
    except OSError as e:
        return bad + [f'{KEY}: {e.strerror}']
    group = _group_id(root, 'pegaprox')
    if (not stat.S_ISREG(st.st_mode) or stat.S_IMODE(st.st_mode) != 0o640
            or st.st_uid != owner or group is None or st.st_gid != group):
        bad.append(f'{KEY} is {stat.S_IMODE(st.st_mode):04o} {st.st_uid}:{st.st_gid}, '
                   f'not 0640 {owner}:{group}')
    with open(path, 'rb') as fh:
        raw = _decode(fh.read())
    if raw is None:
        return bad + [f'{KEY} holds no 32-byte key']
    for name in sorted(os.listdir(root + CONFIG)):
        p = os.path.join(root + CONFIG, name)
        if os.path.isfile(p) and not os.path.islink(p) and os.path.getsize(p) <= 4096:
            with open(p, 'rb') as fh:
                if _decode(fh.read()) == raw:
                    bad.append(f'{CONFIG}/{name} holds the master key, next to the database')
    return bad


def main(argv):
    if len(argv) != 3:
        sys.exit('usage: smoke_encrypted.py <keystore-status.json> <rootfs>')
    with open(argv[1], encoding='utf-8') as fh:
        text = fh.read()
    try:
        status = json.loads(text[text.index('{'):])
    except ValueError:
        print(f'smoke: no --keystore-status JSON in {argv[1]}:\n{text}', file=sys.stderr)
        return 1
    bad = check(status, argv[2].rstrip('/'))
    for line in bad:
        print(f'::error::{line}')
    if not bad:
        print(f'smoke: {DATABASE} is SQLCipher, its key is {KEY} (0640 root:pegaprox), and '
              f'no file in {CONFIG} holds it')
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
