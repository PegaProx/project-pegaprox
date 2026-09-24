"""Handlers that catch sqlite3's exception classes on a dbcrypto connection.

On the install requirements.txt produces for Linux x86_64 — the only platform it pulls
sqlcipher3-binary for — dbcrypto opens every database through sqlcipher3. That driver is a
pysqlite fork and builds its own exception tree straight off Exception, so
sqlite3.IntegrityError does not match what a SQLCipher connection raises and the handler is
dead code. It stays invisible because it is correct everywhere the suite usually runs:
macOS, ARM and Windows have no sqlcipher3, dbcrypto falls back to sqlite3, and the same
handler matches. Reported Sep 2026 with the class identities measured on the shipping wheel.

Two sites had it — the WebAuthn duplicate-key path (500 instead of 409) and the syslog FTS
fallback (couldn't fall back). The AST check below is the part that matters going forward.
MK
"""
import ast
import sqlite3
import pathlib

import pytest

from pegaprox.core import dbcrypto

_ROOT = pathlib.Path(__file__).resolve().parent.parent / 'pegaprox'


def _except_sqlite3_sites():
    """Every `except sqlite3.X` outside dbcrypto.py, as (relpath, lineno, attr)."""
    hits = []
    for py in _ROOT.rglob('*.py'):
        if py.name == 'dbcrypto.py':
            continue          # the module that owns the choice may name both drivers
        try:
            tree = ast.parse(py.read_text(encoding='utf-8'))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.ExceptHandler) or node.type is None:
                continue
            for t in ast.walk(node.type):
                if (isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name)
                        and t.value.id == 'sqlite3'):
                    hits.append((str(py.relative_to(_ROOT.parent)), node.lineno, t.attr))
    return hits


def test_no_handler_catches_sqlite3_classes_outside_dbcrypto():
    hits = _except_sqlite3_sites()
    assert not hits, (
        "these handlers catch sqlite3's exception classes, which never match on a "
        "SQLCipher connection — import the class from pegaprox.core.dbcrypto instead:\n"
        + '\n'.join(f"  {f}:{ln} — except sqlite3.{a}" for f, ln, a in hits))


@pytest.mark.skipif(dbcrypto.BACKEND != 'sqlcipher',
                    reason='no sqlcipher3 here — sqlite3 IS the active driver, nothing to prove')
def test_the_two_trees_really_are_disjoint():
    """Pins the premise. If a future sqlcipher3 ever subclasses sqlite3's exceptions this
    whole file is pointless and should say so rather than quietly keep passing."""
    assert dbcrypto.IntegrityError is not sqlite3.IntegrityError
    assert not issubclass(dbcrypto.IntegrityError, sqlite3.IntegrityError)
    assert not issubclass(dbcrypto.OperationalError, sqlite3.OperationalError)


@pytest.mark.skipif(dbcrypto.BACKEND != 'sqlcipher', reason='needs the sqlcipher3 driver')
def test_a_unique_violation_is_caught_by_the_dbcrypto_class(tmp_path):
    """The concrete shape from the WebAuthn route: duplicate INSERT on a real connection."""
    conn = dbcrypto.connect(str(tmp_path / 'x.db'))
    try:
        conn.execute('CREATE TABLE t (id TEXT PRIMARY KEY)')
        conn.execute("INSERT INTO t VALUES ('a')")
        with pytest.raises(dbcrypto.IntegrityError):
            conn.execute("INSERT INTO t VALUES ('a')")
        # and the old spelling would have sailed straight past
        try:
            conn.execute("INSERT INTO t VALUES ('a')")
        except sqlite3.IntegrityError:
            pytest.fail("sqlite3.IntegrityError matched — premise of #822 is wrong")
        except dbcrypto.IntegrityError:
            pass
    finally:
        conn.close()


def test_webauthn_still_answers_409_for_a_duplicate_key():
    """The route's own intent: a key you already registered is a 409, not a 500."""
    import inspect
    from pegaprox.api import webauthn
    src = inspect.getsource(webauthn)
    tree = ast.parse(src)
    handlers = [n for n in ast.walk(tree) if isinstance(n, ast.ExceptHandler)
                and isinstance(n.type, ast.Name) and n.type.id == 'IntegrityError']
    assert handlers, "the duplicate-credential handler is gone"
    assert any('409' in ast.dump(h) for h in handlers), \
        "the IntegrityError handler no longer answers 409"
