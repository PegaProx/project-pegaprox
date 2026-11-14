"""The startup line counts the audit entries the database holds.

load_audit_log kept the entries in a list, and its `global` rebound audit.py's own name,
so the pegaprox.globals list the startup line counted stayed empty: "Loaded 0 audit
entries" on every start, whatever the table held. log_audit put each new entry into that
private copy as well, up to 10000 of them, and nothing read it. Every reader of the audit
trail goes to SQLite. MK
"""
import inspect

import pegaprox.utils.audit as audit


def test_the_count_is_what_the_table_holds(db):
    for i in range(3):
        audit.log_audit('alice', 'vm.start', f'Started VM {100 + i}')

    assert audit.load_audit_log() == 3


def test_the_startup_line_prints_that_count():
    import pegaprox.app as app
    src = inspect.getsource(app.main)

    assert 'n_audit = load_audit_log()' in src
    assert 'Loaded {n_audit} audit entries' in src
    assert 'len(g.audit_log)' not in src


def test_log_audit_keeps_no_copy_in_memory(db):
    for i in range(5):
        audit.log_audit('alice', 'vm.start', f'Started VM {100 + i}')

    copies = [name for name, v in vars(audit).items() if isinstance(v, list) and len(v) >= 5]
    assert not copies, f'audit.py holds the entries in {copies}'
