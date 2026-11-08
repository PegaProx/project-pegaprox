"""Snapshots in metrics_history the way PegaProx stores them, for the tests that read them.

The tests of the history readers built a metrics_history table of their own in an in-memory
sqlite and handed its SQL to a fake run_heavy_read. A snapshot is stored in parts now
(pegaprox/background/metrics_store.py), so they write through the real writer into the test's
own database (the db fixture) and read through the real run_heavy_read, which runs the SQL that
ships; what each read asked for and got is recorded. Rows as an older PegaProx wrote them (one
JSON blob, fmt 0) can be written as well, for the readers' other half.
MK Oct 2026
"""
import json

from pegaprox import constants
from pegaprox.background import metrics_store
from pegaprox.core import dbcrypto


def sql_text(sql):
    """The SQL of a read, a statement list (run_heavy_read's list form) as one text."""
    return sql if isinstance(sql, str) else '\n'.join(one for one, _args in sql)


class History:
    """The metrics_history of the test's database and the heavy reads made of it."""

    def __init__(self):
        # per run_heavy_read call: (sql text, cache_key, what the read handed back), the SQL
        # alone, and (cache_key, what it handed back), which is what the cache keeps
        self.reads = []
        self.seen = []
        self.keyed = []

    def write(self, rows, legacy=False):
        """[(timestamp, {'clusters': ...})] in that order; the ids written. Through the real
        writer (metrics_store.save_many: the rows and their parts in one transaction), or as
        an older PegaProx wrote them with legacy=True."""
        if legacy:
            return self.write_legacy(rows)
        return metrics_store.save_many([(ts, snap) for ts, snap in rows])

    def write_legacy(self, rows):
        conn = dbcrypto.connect(constants.DATABASE_FILE)
        try:
            ids = []
            for ts, snap in rows:
                cur = conn.execute('INSERT INTO metrics_history (timestamp, data) VALUES (?, ?)',
                                   (ts, json.dumps({k: v for k, v in snap.items() if k != 'timestamp'})))
                ids.append(cur.lastrowid)
            conn.commit()
            return ids
        finally:
            conn.close()

    def stored(self, sql, params=()):
        """Rows of a query on the test's database."""
        conn = dbcrypto.connect(constants.DATABASE_FILE)
        try:
            return [tuple(r) for r in conn.execute(sql, params).fetchall()]
        finally:
            conn.close()


def recorded(monkeypatch):
    """A History whose `reads` fill as the code reads (run_heavy_read wrapped, not replaced)."""
    history = History()
    real = dbcrypto.run_heavy_read

    def recording(sql, params=(), cache_key=None, ttl=None, transform=None):
        out = real(sql, params, cache_key=cache_key, ttl=ttl, transform=transform)
        history.reads.append((sql_text(sql), cache_key, out))
        history.seen.append(sql_text(sql))
        history.keyed.append((cache_key, out))
        return out
    monkeypatch.setattr(dbcrypto, 'run_heavy_read', recording)
    return history
