#!/usr/bin/env python3
"""The database backend PegaProx reports inside an appliance image, for release-images.yml.

    python3 -I packaging/apt/smoke_backend.py <keystore-status.json>

NS Nov 2026 (#1226) - the smoke tests of the LXC template and the VM image waited for port
5000 only, and PegaProx answers there on plain SQLite too: with a python3-sqlcipher3 whose
module does not load (the x86_64 one on arm64) it falls back and says so at INFO. The file
holds what `pegaprox-wrapper --keystore-status` printed in the image, as the service user in
/var/lib/pegaprox. Exit status 1 unless its database backend is sqlcipher.
"""
import json
import sys


def backend(text):
    """db.backend of the --keystore-status JSON in text, None without one. The JSON starts
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
                return db.get('backend') if isinstance(db, dict) else None
        offset += len(line)
    return None


def main(argv):
    if len(argv) != 2:
        sys.exit('usage: smoke_backend.py <keystore-status.json>')
    try:
        with open(argv[1], encoding='utf-8', errors='replace') as fh:
            text = fh.read()
    except OSError as e:
        print(f'::error::no --keystore-status of PegaProx in the image: {argv[1]}: {e.strerror}')
        return 1
    got = backend(text)
    if got == 'sqlcipher':
        print('smoke: PegaProx in the image runs its database on SQLCipher')
        return 0
    if got is None:
        print(f'::error::no --keystore-status JSON from PegaProx in the image, it printed:\n{text}')
    else:
        print(f'::error::PegaProx in the image runs its database on {got}: python3-sqlcipher3 '
              'does not import there')
    return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv))
