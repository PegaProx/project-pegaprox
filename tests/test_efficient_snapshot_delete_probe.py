"""Deleting an efficient snapshot keeps its record unless the node said its LVs are gone.

The delete lists the LVs of the volume group once, removes the snapshot LVs still in that
list and skips the ones that are not. Only a listing that worked says an LV is gone: a node
that could not be asked (no SSH, or a write gate that refused the session) and a listing
that failed (lvs answers 5 for many failures, an existing LV included) say nothing, so
nothing is removed and the record stays. The record would otherwise go while the LV stays
on the volume group with nothing pointing at it, or a half-removed snapshot would stay
offered for a rollback.

MK Nov 2026
"""
from unittest.mock import MagicMock

from pegaprox.core import manager as mgr_mod
from pegaprox.core.manager import PegaProxManager

SNAP = {'id': 's1', 'snapname': 'before-upgrade', 'vg_name': 'vg0',
        'disks': [{'snap_lv': 'snap-101-a'}, {'snap_lv': 'snap-101-b'}]}


def _delete(monkeypatch, listing):
    """listing: (exit code, the LV names lvs prints)."""
    db = MagicMock(get_efficient_snapshot=lambda sid: SNAP)
    monkeypatch.setattr(mgr_mod, 'get_db', lambda: db)
    calls = []

    def ssh(node, cmd, timeout=30):
        calls.append(cmd)
        if cmd.startswith('lvs '):
            code, names = listing
            return code, '\n'.join(f'  {n}' for n in names), ('SSH connection to n1 failed'
                                                              if code == -1 else '')
        return 0, '', ''
    fake = MagicMock(logger=MagicMock(), _node_ssh_exec=ssh)
    out = PegaProxManager.delete_efficient_snapshot(fake, 'n1', 101, 's1')
    return out, db, calls


def _removed(calls):
    return [c.rsplit('/', 1)[1] for c in calls if c.startswith('lvremove')]


def test_a_node_that_could_not_be_asked_keeps_the_record(monkeypatch):
    out, db, calls = _delete(monkeypatch, (-1, []))
    assert out['success'] is False and 'kept' in out['error']
    db.delete_efficient_snapshot.assert_not_called()
    assert _removed(calls) == []


def test_a_listing_that_failed_keeps_the_record_and_removes_nothing(monkeypatch):
    # lvs answers 5 for many failures: the LVs may well still be there
    out, db, calls = _delete(monkeypatch, (5, ['snap-101-a', 'snap-101-b']))
    assert out['success'] is False and 'kept' in out['error']
    db.delete_efficient_snapshot.assert_not_called()
    assert _removed(calls) == []


def test_an_lv_the_listing_does_not_show_is_gone(monkeypatch):
    # counterproof: a listing that worked and lacks the LVs - nothing to remove, the record goes
    out, db, calls = _delete(monkeypatch, (0, ['vm-101-disk-0']))
    assert out['success'] is True
    db.delete_efficient_snapshot.assert_called_once_with('s1')
    assert _removed(calls) == []


def test_the_lvs_the_listing_shows_are_removed(monkeypatch):
    out, db, calls = _delete(monkeypatch, (0, ['vm-101-disk-0', 'snap-101-a', 'snap-101-b']))
    assert out['success'] is True
    assert _removed(calls) == ['snap-101-a', 'snap-101-b']
    db.delete_efficient_snapshot.assert_called_once_with('s1')
