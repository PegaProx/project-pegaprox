"""An audit entry with a lone UTF-16 surrogate in it is stored, not dropped.

A client can send "\\ud800" in a JSON string (a VM name, a user name) and Python hands it
on as a str no UTF-8 encoder takes. The chain hash encodes the row, so add_audit_entry
raised, log_audit logged "Failed to save audit entry" and the row never reached the
database. The bad characters are replaced (U+FFFD) before the row is hashed and stored,
so what is stored is what was signed and the chain still verifies. The text log line of
the same entry went through sanitize_log_message unchanged, and a UTF-8 log file handler
raised on it inside emit(): the line was lost with a "Logging error" on stderr. That
sanitizer replaces them too.
NS Nov 2026
"""
import json
import logging

import pytest

from pegaprox.utils.audit import log_audit

BAD = '\ud800'
SHOWN = '\ufffd'


def _rows(db, action=None):
    q = 'SELECT * FROM audit_log WHERE chain_seq IS NOT NULL'
    args = ()
    if action:
        q += ' AND action = ?'
        args = (action,)
    return [dict(r) for r in db.conn.execute(q + ' ORDER BY chain_seq', args)]


def test_a_client_can_send_one():
    # what Flask's JSON parser hands the route
    assert json.loads('{"name": "vm-\\ud800"}')['name'] == 'vm-' + BAD


def test_log_audit_keeps_the_row_with_the_character_replaced(db):
    log_audit('alice', 'vm.renamed', f"Renamed VM 100 to 'vm-{BAD}'", cluster='Lab')
    rows = _rows(db, 'vm.renamed')
    assert len(rows) == 1, 'the entry was dropped'
    assert rows[0]['details'] == f"Renamed VM 100 to 'vm-{SHOWN}' [Lab]"
    assert rows[0]['user'] == 'alice' and rows[0]['cluster'] == 'Lab'


@pytest.mark.parametrize('field', ['user', 'action', 'details', 'ip', 'cluster', 'cluster_id'])
def test_every_field_is_stored(db, field):
    kw = {'user': 'alice', 'action': 'test.surrogate', 'details': 'd', 'ip': '10.0.0.1',
          'cluster': 'Lab', 'cluster_id': 'c1'}
    kw[field] = kw[field] + BAD + 'x'
    db.add_audit_entry(**kw)
    rows = _rows(db)
    assert len(rows) == 1, 'the entry was dropped'
    col = 'ip_address' if field == 'ip' else field
    assert rows[0][col] == kw[field].replace(BAD, SHOWN)


def test_the_chain_verifies_across_it(db):
    db.add_audit_entry('alice', 'test.before', 'plain', '10.0.0.1', 'Lab')
    db.add_audit_entry('mallory' + BAD, 'test.bad', 'name ' + BAD + '\udfff end', '10.0.0.1', 'Lab' + BAD)
    db.add_audit_entry('alice', 'test.after', 'plain', '10.0.0.1', 'Lab')
    rows = _rows(db)
    assert [r['action'] for r in rows] == ['test.before', 'test.bad', 'test.after']
    assert rows[1]['details'] == 'name ' + SHOWN + SHOWN + ' end'
    # the next row links to the stored one, so the hash was taken over what is stored
    assert rows[2]['prev_hash'] == db._audit_row_hash(rows[1])
    res = db.verify_audit_log_integrity()
    assert res['intact'] is True, res
    assert res['verified'] == 3 and res['chain']['broken_links'] == 0 and res['chain']['edited'] == 0


def test_a_valid_character_outside_the_bmp_is_left_alone(db):
    db.add_audit_entry('alice', 'test.emoji', 'tag \U0001F680 and \u00e4', '10.0.0.1', 'Lab')
    assert _rows(db)[0]['details'] == 'tag \U0001F680 and \u00e4'
    assert db.verify_audit_log_integrity()['intact'] is True


def test_the_siem_gets_what_was_stored(db, monkeypatch):
    from pegaprox.api import siem
    sent = []
    monkeypatch.setattr(siem, 'enqueue', sent.append)
    db.add_audit_entry('alice', 'test.siem', 'x' + BAD, '10.0.0.1', 'Lab')
    assert sent and sent[-1]['details'] == 'x' + SHOWN
    assert sent[-1]['chain_hash'] == db._audit_row_hash(_rows(db)[0])


def test_the_log_sanitizer_replaces_them():
    from pegaprox.utils.sanitization import sanitize_log_message
    # compared as ascii(): a failure report with a raw surrogate in its diff kills an xdist worker
    assert ascii(sanitize_log_message('vm-' + BAD + '\udfff!')) == ascii('vm-' + SHOWN + SHOWN + '!')
    # a pair that is whole is one character in Python and stays
    assert sanitize_log_message('tag \U0001F680') == 'tag \U0001F680'
    assert sanitize_log_message('a\nb') == 'a b'


def test_the_text_log_line_is_written(db, tmp_path):
    path = tmp_path / 'pegaprox.log'
    handler = logging.FileHandler(path, encoding='utf-8')
    handler.setLevel(logging.INFO)
    errors = []
    handler.handleError = lambda record: errors.append(record)
    root = logging.getLogger()
    level, others = root.level, root.handlers[:]
    # only this handler: pytest's own capture keeps the raw record, and a report carrying a
    # raw surrogate is what an xdist worker cannot send back
    root.handlers = [handler]
    root.setLevel(logging.INFO)
    try:
        log_audit('alice' + BAD, 'vm.renamed', f"Renamed VM 100 to 'vm-{BAD}'", cluster='Lab')
    finally:
        root.handlers = others
        root.setLevel(level)
        handler.close()
    # a count, not the records: their repr carries the raw message
    lost = len(errors)
    assert lost == 0, 'the handler could not write the line'
    text = path.read_text(encoding='utf-8')
    assert f"Audit: alice{SHOWN} - vm.renamed [Lab] - Renamed VM 100 to 'vm-{SHOWN}'" in text, text
