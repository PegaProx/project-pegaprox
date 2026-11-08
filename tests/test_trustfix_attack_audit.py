"""Attacks on the audit hash chain: what someone with write access to the database (and
without the field key) can change while the integrity check still answers intact."""
from datetime import datetime, timedelta


def _add(db, n, prefix='e'):
    for i in range(n):
        db.add_audit_entry('alice', f'test.{prefix}{i}', f'{prefix} {i}', '10.0.0.1', 'c1', 'info')


def _rows(db):
    return [dict(r) for r in db.conn.execute(
        'SELECT * FROM audit_log WHERE chain_seq IS NOT NULL ORDER BY chain_seq')]


def _cutoff(days=90):
    return (datetime.now() - timedelta(days=days)).isoformat()


# ---- a chained row with its signature blanked ---------------------------------------------

def test_a_chained_row_with_its_signature_removed_is_not_intact(db):
    """Every chained row is signed when the instance has a key. Blank the signature of the
    newest rows, rewrite them, relink them with the (unkeyed) row hash: the walk counts
    them as 'unsigned' and still says intact."""
    _add(db, 4)
    rows = _rows(db)
    # rewrite the last two: who did it, and what
    for r in rows[2:]:
        r['user'], r['details'] = 'mallory', 'nothing to see'
    rows[3]['prev_hash'] = db._audit_row_hash(rows[2])
    for r in rows[2:]:
        db.conn.execute("UPDATE audit_log SET user = ?, details = ?, prev_hash = ?, "
                        "hmac_signature = '' WHERE id = ?",
                        (r['user'], r['details'], r['prev_hash'], r['id']))
    db.conn.commit()
    res = db.verify_audit_log_integrity()
    assert res['intact'] is False, res


# ---- retention trusts an unsigned timestamp -------------------------------------------------

def test_a_backdated_row_does_not_let_retention_wipe_the_fresh_log(db):
    """No key needed: set the newest row's timestamp into the past. The next retention
    prune cuts by number up to the newest row 'older than the cutoff', deletes every fresh
    row before it, signs that as a legitimate prune and the check answers intact."""
    _add(db, 10)
    db.audit_checkpoint()
    db.conn.execute("UPDATE audit_log SET timestamp = '2000-01-01T00:00:00' "
                    "WHERE chain_seq = (SELECT MAX(chain_seq) FROM audit_log)")
    db.conn.commit()
    db.prune_audit_log(_cutoff())
    left = len(_rows(db))
    res = db.verify_audit_log_integrity()
    # either the fresh rows survive retention, or the check says what happened
    assert left >= 9 or res['intact'] is False, (left, res['chain'])


def test_one_row_written_with_a_wrong_clock_does_not_take_the_rows_before_it(db):
    """A signed row with an old timestamp (an appliance that booted before NTP set its
    clock) in the middle of the chain: retention deletes every row up to it, though the
    rows before it are a day old and the retention is 90 days."""
    _add(db, 10)
    rows = _rows(db)
    # row 7 was written while the clock said 2000; signed and linked as the app would
    rows[6]['timestamp'] = '2000-01-01T00:00:00'
    for a, b in zip(rows[5:], rows[6:]):
        b['prev_hash'] = db._audit_row_hash(a)
    for r in rows[6:]:
        db.conn.execute('UPDATE audit_log SET timestamp = ?, prev_hash = ?, hmac_signature = ? '
                        'WHERE id = ?', (r['timestamp'], r['prev_hash'], db._audit_chain_hmac(r), r['id']))
    db.conn.commit()
    assert db.verify_audit_log_integrity()['intact'] is True
    db.prune_audit_log(_cutoff())
    seqs = [r['chain_seq'] for r in _rows(db)]
    # rows 1-6 are inside the retention window
    assert all(s in seqs for s in range(1, 7)), seqs


# ---- the legacy rows ----------------------------------------------------------------------

def _legacy(db, *stamps):
    for i, ts in enumerate(stamps):
        db.conn.execute("INSERT INTO audit_log (timestamp, user, action, details, ip_address, "
                        "hmac_signature) VALUES (?, 'bob', 'old.thing', ?, '', '')", (ts, f'old {i}'))
    db.conn.execute('DELETE FROM audit_checkpoints')
    db.conn.commit()
    db._ensure_audit_genesis()


def test_deleting_the_genesis_does_not_hide_a_deleted_legacy_row(db):
    recent = (datetime.now() - timedelta(days=5)).isoformat()
    _legacy(db, recent, recent, recent)
    _add(db, 2)
    assert db.verify_audit_log_integrity()['intact'] is True
    # no key needed: drop the checkpoint the legacy digest lives in, then the rows
    db.conn.execute("DELETE FROM audit_checkpoints WHERE kind = 'genesis'")
    db.conn.execute("DELETE FROM audit_log WHERE action = 'old.thing' AND details = 'old 1'")
    db.conn.commit()
    res = db.verify_audit_log_integrity()
    assert res['intact'] is False, res


def test_a_prune_does_not_sign_a_legacy_deletion_away(db):
    """A legacy row deleted by hand is reported; the next retention prune recomputes the
    digest over what is left and signs it, after which the check says intact."""
    recent = (datetime.now() - timedelta(days=5)).isoformat()
    _legacy(db, '2020-01-01T00:00:00', recent, recent)
    _add(db, 2)
    db.conn.execute("DELETE FROM audit_log WHERE action = 'old.thing' AND details = 'old 2'")
    db.conn.commit()
    assert db.verify_audit_log_integrity()['intact'] is False
    db.prune_audit_log(_cutoff())
    res = db.verify_audit_log_integrity()
    assert res['intact'] is False, res


# ---- the tail together with the checkpoint over it -----------------------------------------

def test_a_cut_tail_and_its_checkpoint_are_noticed(db):
    """The checkpoints live in the same database as the rows. Delete the newest rows and the
    periodic checkpoint that covers them: no hole in the numbers, nothing truncated."""
    _add(db, 5)
    db.audit_checkpoint()
    _add(db, 5, 'late')
    db.audit_checkpoint()
    db.conn.execute('DELETE FROM audit_log WHERE chain_seq > 5')
    db.conn.execute('DELETE FROM audit_checkpoints WHERE chain_seq > 5')
    db.conn.commit()
    res = db.verify_audit_log_integrity()
    assert res['intact'] is False, res['chain']


# ---- SIEM ---------------------------------------------------------------------------------

def test_a_syslog_line_carries_the_entry_place_in_the_chain(db, monkeypatch):
    """The JSON targets get chain_seq and chain_hash; a syslog target gets neither, so its
    copy cannot say which entry a checkpoint covers or which one went missing."""
    from pegaprox.api import siem
    sent = []
    monkeypatch.setattr(siem, 'enqueue', lambda ev: sent.append(ev))
    db.add_audit_entry('alice', 'vm.start', 'started 100')
    row = _rows(db)[-1]
    line = siem._to_syslog_5424(sent[-1])
    assert db._audit_row_hash(row) in line, line


def test_a_forwarded_checkpoint_says_which_instance_chain_it_signs(db, monkeypatch):
    """Every instance keeps a chain of its own (audit_log and audit_checkpoints are local,
    a standby forwards too), so an active and its standby both send seq 1, 2, 3... The JSON
    line carries no host or instance id: the SIEM copy cannot tell the two chains apart."""
    from pegaprox.api import siem
    sent = []
    monkeypatch.setattr(siem, 'enqueue', lambda ev: sent.append(ev))
    monkeypatch.setattr(siem, 'has_targets', lambda: True)
    _add(db, 2)
    db.audit_checkpoint()
    line = siem._to_json_line(sent[-1])
    assert line.get('event_type') == 'audit_checkpoint'
    assert any(k in line for k in ('host', 'hostname', 'instance', 'instance_id', 'node_id')), line
