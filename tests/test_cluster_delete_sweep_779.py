# Regression test for #779 (zobsg): delete_cluster used to purge only clusters + xcpng_vmid_map,
# orphaning rows in ~20 other cluster_id-keyed tables. It now sweeps every table that carries a
# cluster_id column. The functional test below populates *every* such table generically and asserts
# the delete is exhaustive for the target cluster while leaving a second cluster's rows untouched —
# so it keeps covering new cluster-scoped tables as they're added, which is the point of the rewrite.
import pytest


def _cluster_id_tables(conn):
    """Every user table that actually carries a cluster_id column (mirrors the sweep in db.py)."""
    out = []
    tables = [r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchall()]
    for t in tables:
        cols = conn.execute('PRAGMA table_info("%s")' % t).fetchall()
        if any(c[1] == 'cluster_id' for c in cols):
            out.append((t, cols))
    return out


def _insert_row(conn, table, cols, cluster_id, salt):
    """Insert one minimal valid row for `cluster_id`. Returns True on success.

    Fills NOT NULL columns that lack a default; skips the INTEGER PRIMARY KEY (rowid alias, so
    it auto-assigns) so DELETE- and KEEP-cluster rows never collide on it. `salt` keeps any
    non-cluster_id text key distinct between the two clusters."""
    names, values = [], []
    for cid_, name, ctype, notnull, dflt, pk in cols:
        if pk and 'INT' in (ctype or '').upper():
            continue  # autoincrement rowid alias — let SQLite assign it
        if name == 'cluster_id':
            names.append(name); values.append(cluster_id); continue
        if not notnull and dflt is None and not pk:
            continue  # nullable, no default — leave it out
        # needs a value: NOT NULL / part of a PK / has a non-null default we still want distinct
        if 'INT' in (ctype or '').upper():
            values.append(1)
        else:
            values.append('z%s' % salt)  # salted so (cluster_id, <key>) stays unique per cluster
        names.append(name)
    placeholders = ','.join('?' for _ in names)
    collist = ','.join('"%s"' % n for n in names)
    try:
        conn.execute('INSERT INTO "%s" (%s) VALUES (%s)' % (table, collist, placeholders), values)
        return True
    except Exception:
        return False  # FK/CHECK/other constraint we can't satisfy generically — skip this table


def test_delete_cluster_sweeps_every_cluster_id_table(db):
    conn = db.conn
    tables = _cluster_id_tables(conn)
    assert tables, "no cluster_id-keyed tables discovered — schema/introspection broke"

    DELETE_CID, KEEP_CID = 'cid-delete-me', 'cid-keep-me'
    exercised = []
    for table, cols in tables:
        if table in db.KEPT_ON_CLUSTER_DELETE:
            continue  # the audit trail outlives the cluster, see the test below
        ok_del = _insert_row(conn, table, cols, DELETE_CID, salt='d')
        ok_keep = _insert_row(conn, table, cols, KEEP_CID, salt='k')
        if ok_del and ok_keep:
            exercised.append(table)
    conn.commit()
    # sanity: the batch insert must have actually populated a meaningful spread of tables,
    # otherwise the assertions below pass vacuously.
    assert len(exercised) >= 4, f"only populated {exercised!r} — test would be near-vacuous"

    # pre-condition: both clusters have rows everywhere we populated
    for table in exercised:
        assert conn.execute('SELECT COUNT(*) FROM "%s" WHERE cluster_id=?' % table, (DELETE_CID,)).fetchone()[0] >= 1

    db.delete_cluster(DELETE_CID)

    for table in exercised:
        left = conn.execute('SELECT COUNT(*) FROM "%s" WHERE cluster_id=?' % table, (DELETE_CID,)).fetchone()[0]
        kept = conn.execute('SELECT COUNT(*) FROM "%s" WHERE cluster_id=?' % table, (KEEP_CID,)).fetchone()[0]
        assert left == 0, f"{table}: {left} orphaned row(s) survived delete_cluster (#779 regression)"
        assert kept >= 1, f"{table}: sweep wrongly deleted the OTHER cluster's rows"


def test_a_deleted_cluster_keeps_its_audit_trail(db):
    # audit_log carries a cluster_id since #1121, and the sweep took the deleted cluster's
    # entries out of the hash chain: the integrity check then reported them missing
    for i in range(3):
        db.add_audit_entry('alice', f'cluster.e{i}', f'e {i}', '10.0.0.1', 'gone', 'info', cluster_id='cid-gone')
        db.add_audit_entry('bob', f'cluster.k{i}', f'k {i}', '10.0.0.2', 'kept', 'info', cluster_id='cid-kept')
    assert db.verify_audit_log_integrity()['intact'] is True

    db.delete_cluster('cid-gone')

    left = db.conn.execute("SELECT COUNT(*) FROM audit_log WHERE cluster_id = 'cid-gone'").fetchone()[0]
    assert left == 3, 'audit chain lost rows'
    res = db.verify_audit_log_integrity()
    assert res['intact'] is True, res
    assert res['chain']['missing'] == 0 and res['chain']['rows'] == 6


def test_delete_cluster_is_idempotent_on_missing(db):
    # deleting a cluster id that never existed must not raise (endpoint calls this in a try/except,
    # but the sweep itself should be clean too).
    db.delete_cluster('never-existed-xyz')
