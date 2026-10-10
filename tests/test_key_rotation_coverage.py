"""Key rotation has to reach every secret in the database.

_decrypt raises rather than returning garbage, so a column the rotation walks
past is not degraded — it is unreadable. The PBS and ESXi server credentials sat
in their own tables and were never rotated, which meant a rotation run for
compliance silently broke every backup job and every ESXi connection until
someone re-entered the passwords by hand. The VAPID private key was missed for a
different reason: it is nested inside the keypair object, so the settings loop
walked past it, and _load_vapid answers a failed decrypt by generating a new
keypair — dropping every push subscription.

The invariant test at the bottom is the point: it fails for the NEXT encrypted
column somebody adds without extending the rotation. MK
"""
import json
import os

import pytest

import pegaprox.core.db as dbmod


VAPID = 'webpush_vapid_keypair'


@pytest.fixture
def seeded(db):
    """One secret in every table the rotation is supposed to reach."""
    db.save_cluster('c1', {'name': 'c1', 'host': 'h', 'user': 'root@pam', 'pass': 'clusterpw'})
    db.conn.execute(
        "INSERT OR REPLACE INTO pbs_servers (id, name, host, port, user, pass_encrypted, "
        "api_token_secret_encrypted, ssh_key_encrypted) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        ('pbs1', 'pbs1', 'h', 8007, 'root@pam', db._encrypt('pbspw'),
         db._encrypt('pbstoken'), db._encrypt('pbskey')))
    db.conn.execute(
        "INSERT OR REPLACE INTO vmware_servers (id, name, host, port, username, pass_encrypted) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        ('esxi1', 'esxi1', 'h', 443, 'root', db._encrypt('esxipw')))
    db.conn.execute(
        "INSERT OR REPLACE INTO auto_install_profiles (id, name, answer_encrypted, token_hash) "
        "VALUES (?, ?, ?, ?)",
        ('ai1', 'rack-7', db._encrypt('[global]\nroot-password = "in the rack"\n'), 'deadbeef'))
    db.save_node_credential('c1', 'pve2', 'nodepw', 'root')
    db.save_server_setting('ldap_bind_password', db._encrypt('bindpw'))
    db.save_server_setting(VAPID, {'private_pem': db._encrypt('-----BEGIN PRIVATE KEY-----'),
                                   'public_b64': 'pub'})
    db.conn.commit()
    return db


def _col(db, table, col, row_id):
    cur = db.conn.cursor()
    cur.execute(f"SELECT {col} FROM {table} WHERE id = ?", (row_id,))
    return cur.fetchone()[0]


def test_every_secret_survives_a_rotation(seeded):
    res = seeded.rotate_encryption_key()

    assert res.get('success') is True, res
    assert seeded.get_cluster('c1')['pass'] == 'clusterpw'
    assert seeded._decrypt(_col(seeded, 'pbs_servers', 'pass_encrypted', 'pbs1')) == 'pbspw'
    assert seeded._decrypt(_col(seeded, 'pbs_servers', 'api_token_secret_encrypted', 'pbs1')) == 'pbstoken'
    assert seeded._decrypt(_col(seeded, 'pbs_servers', 'ssh_key_encrypted', 'pbs1')) == 'pbskey'
    assert seeded._decrypt(_col(seeded, 'vmware_servers', 'pass_encrypted', 'esxi1')) == 'esxipw'
    # MK Sep 2026 - the source-level guard below is satisfied by a mention, so the
    # answer file needs a real round trip: unreadable here means the next prepared
    # ISO gets a 500 instead of an install.
    assert 'in the rack' in seeded._decrypt(
        _col(seeded, 'auto_install_profiles', 'answer_encrypted', 'ai1'))
    # the root password of a single node (#1136)
    assert seeded.node_credential_secrets('c1') == {'pve2': 'nodepw'}
    settings = seeded.get_server_settings()
    assert seeded._decrypt(settings['ldap_bind_password']) == 'bindpw'
    assert seeded._decrypt(settings[VAPID]['private_pem']).startswith('-----BEGIN')


def test_rotation_reports_no_errors(seeded):
    res = seeded.rotate_encryption_key()

    assert res.get('errors') == [], res['errors']


def test_two_rotations_within_one_second_keep_the_backup_of_each(seeded, monkeypatch):
    """The backup of the old key is named by the second and was opened with 'wb'. A
    second rotation within that second wrote over the backup of the first, and the key
    from before it existed nowhere: whatever was still sealed under it (a config backup
    taken earlier, a copy the HA sync kept, #625) had no key left. MK Oct 2026"""
    class Frozen(dbmod.datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(2026, 10, 2, 10, 0, 0, tzinfo=tz)
    monkeypatch.setattr(dbmod, 'datetime', Frozen)
    keys, backups = [seeded.aes_key], []
    for _ in range(3):
        res = seeded.rotate_encryption_key()
        assert res.get('success') is True, res
        keys.append(seeded.aes_key)
        backups.append(res['key_backup'])

    first = os.path.join(dbmod.CONFIG_DIR, '.pegaprox_aes256.key.backup.20261002_100000')
    assert backups == [first, first + '.1', first + '.2']
    for path, key in zip(backups, keys):
        with open(path, 'rb') as fh:
            assert fh.read() == key
        assert os.stat(path).st_mode & 0o777 == 0o600
    assert len(set(keys)) == 4
    # the key file holds the last one, and the data went along every time
    with open(os.path.join(dbmod.CONFIG_DIR, '.pegaprox_aes256.key'), 'rb') as fh:
        assert fh.read() == keys[-1]
    assert seeded.get_cluster('c1')['pass'] == 'clusterpw'
    assert len(seeded.get_key_info()['backups']) == 3


def _encrypted_columns(db):
    """Every column in the live schema that holds ciphertext. ha_settings is the one
    that carries no _encrypted suffix — save_cluster seals it all the same."""
    cur = db.conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    out = []
    for (table,) in cur.fetchall():
        cur.execute(f"PRAGMA table_info({table})")
        for c in cur.fetchall():
            if c[1].endswith('_encrypted') or (table, c[1]) == ('clusters', 'ha_settings'):
                out.append((table, c[1]))
    return sorted(out)


def test_rotation_names_every_encrypted_column_in_the_schema(db):
    """The guard for the next one. A new *_encrypted column that rotate_encryption_key
    never names is a credential that a rotation makes permanently unreadable."""
    import inspect
    src = inspect.getsource(dbmod.PegaProxDB.rotate_encryption_key)

    missing = [f'{t}.{c}' for t, c in _encrypted_columns(db)
               if c not in src or t not in src]

    assert not missing, ('rotate_encryption_key does not touch: ' + ', '.join(missing))


def test_the_column_scan_actually_finds_columns(db):
    cols = _encrypted_columns(db)

    assert len(cols) >= 10, cols
    assert ('pbs_servers', 'pass_encrypted') in cols
