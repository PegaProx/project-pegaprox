"""Every synchronized table has a data class, and every cluster table has the column.

The three-leader-sites design (docs/ha-sites.md) splits SYNC_TABLES into
'global' (the group leader writes them, the snapshot carries them),
'cluster' (the cluster's home site writes them, row-level changes to the
others), and 'local' (never replicated, in LOCAL_TABLES). A table that
joins SYNC_TABLES without a class is replicated to every site but no
site knows whether it may write it: the test fails before that ships.
MK Nov 2026
"""
import re

import pytest


def _tables():
    """{table: class} from the source, and the SYNC_TABLES tuple."""
    from pegaprox.core import ha
    src = open(ha.__file__, encoding='utf-8').read()
    sync = set(re.findall(r"'([a-z_0-9]+)'",
                          re.search(r'SYNC_TABLES = \((.*?)\n\)', src, re.S).group(1)))
    classes = dict(ha.TABLE_CLASS)
    return sync, classes


def test_every_sync_table_has_a_class():
    sync, classes = _tables()
    missing = sorted(sync - set(classes))
    assert not missing, f'synced without a class: {missing}'


def test_no_extra_classes():
    _, classes = _tables()
    from pegaprox.core import ha
    src = open(ha.__file__, encoding='utf-8').read()
    sync = set(re.findall(r"'([a-z_0-9]+)'",
                          re.search(r'SYNC_TABLES = \((.*?)\n\)', src, re.S).group(1)))
    extra = sorted(set(classes) - sync)
    assert not extra, f'classed but not synced: {extra}'


def test_every_cluster_table_has_a_cluster_id_column():
    """A cluster table without cluster_id cannot get row-level changes: there is
    no way to tell which site owns a row."""
    _, classes = _tables()
    cluster_tables = sorted(t for t, c in classes.items() if c == 'cluster')
    assert cluster_tables, 'no cluster tables found, the parse broke'
    from pegaprox.core.db import get_db
    db = get_db()
    missing = []
    for t in cluster_tables:
        cols = [r[1] for r in db.conn.execute(f'PRAGMA table_info({t})').fetchall()]
        if 'cluster_id' not in cols:
            missing.append(t)
    assert not missing, f'cluster tables without cluster_id: {missing}'


def test_the_switch_off_default():
    """With the switch off, every table is written by the group leader as today:
    the classes are in the code but nothing reads them yet."""
    _, classes = _tables()
    assert 'server_settings' in classes and classes['server_settings'] == 'global'
    assert 'vm_acls' in classes and classes['vm_acls'] == 'cluster'
