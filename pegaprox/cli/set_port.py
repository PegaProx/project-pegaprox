"""`pegaprox_multi_cluster.py --set-port <port>`: the listen port into the database.

MK Nov 2026 - deploy.sh and the setup of the appliances wrote the port with the sqlite3
CLI, which cannot open a SQLCipher database. On every encrypted install that write failed
and they fell back to "set it under Settings > Server". This goes through
dbcrypto.connect(), so it works on a plain database and on an encrypted one, with the key
the server itself resolves.

Run it as the user PegaProx runs as, in the directory it runs in, once the first start
has created the database. It takes effect at the next start. It never creates a key and
never encrypts: a database the server has not opened yet is the server's to set up.
"""
import json
import os
import sys

USAGE = 'usage: pegaprox_multi_cluster.py --set-port <1-65535>'


def main(argv) -> int:
    if len(argv) != 1 or not argv[0].isdigit() or not 1 <= int(argv[0]) <= 65535:
        print(USAGE, file=sys.stderr)
        return 2
    port = int(argv[0])

    from pegaprox import constants
    from pegaprox.core import dbcrypto, keystore
    db_path = os.path.abspath(constants.DATABASE_FILE)
    # root in /var/lib/pegaprox would leave a -wal and -shm the service cannot open
    if not constants.CONFIG_OWNED_BY_US:
        print(f'{os.path.dirname(db_path)} belongs to another user: run this as the user '
              'PegaProx runs as', file=sys.stderr)
        return 3
    state = dbcrypto.file_state(db_path)
    if state in ('missing', 'empty'):
        print(f'no database at {db_path} yet: start PegaProx once, then set the port',
              file=sys.stderr)
        return 4
    if dbcrypto.is_encrypted():
        if state == 'plain':
            print(f'{db_path} is still plain SQLite, the next start of PegaProx encrypts it: '
                  'set the port after that', file=sys.stderr)
            return 4
        if keystore.peek_master_key() is None:
            print('no master key found (--keystore-status says where it looked)', file=sys.stderr)
            return 4
    elif state != 'plain':
        print(f'{db_path} is encrypted, and sqlcipher3 does not import here', file=sys.stderr)
        return 4

    try:
        conn = dbcrypto.connect(db_path, timeout=30)
        try:
            # json like save_server_setting, which load_server_settings reads back
            conn.execute('INSERT OR REPLACE INTO server_settings (key, value) VALUES (?, ?)',
                         ('port', json.dumps(port)))
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        print(f'could not write the port into {db_path}: {e}', file=sys.stderr)
        return 5
    print(f'port {port} is in {db_path}, PegaProx listens on it from its next start')
    return 0
