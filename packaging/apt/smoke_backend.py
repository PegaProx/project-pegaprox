#!/usr/bin/env python3
"""The database backend PegaProx reports inside an appliance image, for release-images.yml.

    python3 -I packaging/apt/smoke_backend.py <keystore-status.json>

NS Nov 2026 (#1226) - the smoke tests of the LXC template and the VM image waited for port
5000 only, and PegaProx answers there on plain SQLite too: with a python3-sqlcipher3 whose
module does not load (the x86_64 one on arm64) it falls back and keeps running. The file
holds what `pegaprox-wrapper --keystore-status` printed in the image, as the service user in
/var/lib/pegaprox. Exit status 1 unless its database backend is sqlcipher and each database
file it lists is missing, empty or encrypted: the driver alone passes a database that was
left plain.
"""
import json
import sys

# before the first start there is no database, or an empty file
FINE = ('missing', 'empty', 'encrypted')


def db_status(text):
    """The db part of the --keystore-status JSON in text, None without one. The JSON starts
    on a line of its own, after whatever the start printed ahead of it."""
    offset = 0
    for line in text.splitlines(True):
        if line.strip() == '{':
            try:
                status, _ = json.JSONDecoder().raw_decode(text[offset:].lstrip())
            except ValueError:
                status = None
            if isinstance(status, dict):
                db = status.get('db')
                return db if isinstance(db, dict) else None
        offset += len(line)
    return None


def backend(text):
    """db.backend of the --keystore-status JSON in text, None without one."""
    db = db_status(text)
    return db.get('backend') if db else None


def main(argv):
    if len(argv) != 2:
        sys.exit('usage: smoke_backend.py <keystore-status.json>')
    try:
        with open(argv[1], encoding='utf-8', errors='replace') as fh:
            text = fh.read()
    except OSError as e:
        print(f'::error::no --keystore-status of PegaProx in the image: {argv[1]}: {e.strerror}')
        return 1
    db = db_status(text)
    got = db.get('backend') if db else None
    if got is None:
        print(f'::error::no --keystore-status JSON from PegaProx in the image, it printed:\n{text}')
        return 1
    if got != 'sqlcipher':
        print(f'::error::PegaProx in the image runs its database on {got}: python3-sqlcipher3 '
              'does not import there')
        return 1
    # releases up to 1.4.1 print no file list, those are checked by the driver only
    files = db.get('files')
    bad = sorted((str(path), str(state)) for path, state in files.items()
                 if state not in FINE) if isinstance(files, dict) else []
    for path, state in bad:
        print(f'::error::PegaProx in the image runs SQLCipher, but its database {path} is {state}')
    if bad:
        return 1
    print('smoke: PegaProx in the image runs its database on SQLCipher')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
