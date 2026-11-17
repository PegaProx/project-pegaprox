"""Deleting an efficient snapshot keeps its record when the node cannot be asked.

The delete looks for each snapshot LV first and skips the ones that are gone. A probe
that never reached the node (no SSH, or a write gate that refused the session) said
nothing about the LV, so it must not count as "gone": the record would be deleted and the
LV left behind on the volume group with nothing pointing at it.

MK Nov 2026
"""
from unittest.mock import MagicMock

from pegaprox.core import manager as mgr_mod
from pegaprox.core.manager import PegaProxManager

SNAP = {'id': 's1', 'snapname': 'before-upgrade', 'vg_name': 'vg0',
        'disks': [{'snap_lv': 'snap-101-a'}, {'snap_lv': 'snap-101-b'}]}


def _delete(monkeypatch, probe_code):
    db = MagicMock(get_efficient_snapshot=lambda sid: SNAP)
    monkeypatch.setattr(mgr_mod, 'get_db', lambda: db)
    calls = []

    def ssh(node, cmd, timeout=30):
        calls.append(cmd)
        if cmd.startswith('lvs '):
            return probe_code, '', 'SSH connection to n1 failed' if probe_code == -1 else ''
        return 0, '', ''
    fake = MagicMock(logger=MagicMock(), _node_ssh_exec=ssh)
    out = PegaProxManager.delete_efficient_snapshot(fake, 'n1', 101, 's1')
    return out, db, calls


def test_a_probe_that_reached_no_node_keeps_the_record(monkeypatch):
    out, db, calls = _delete(monkeypatch, -1)
    assert out['success'] is False and 'kept' in out['error']
    db.delete_efficient_snapshot.assert_not_called()
    assert not any(c.startswith('lvremove') for c in calls)


def test_an_lv_that_is_gone_is_skipped_and_the_record_goes(monkeypatch):
    # counterproof: lvs answered "no such LV" (exit 5) - gone, nothing to remove
    out, db, calls = _delete(monkeypatch, 5)
    assert out['success'] is True
    db.delete_efficient_snapshot.assert_called_once_with('s1')
    assert not any(c.startswith('lvremove') for c in calls)


def test_an_lv_that_is_there_is_removed(monkeypatch):
    out, db, calls = _delete(monkeypatch, 0)
    assert out['success'] is True
    assert sum(c.startswith('lvremove') for c in calls) == 2
