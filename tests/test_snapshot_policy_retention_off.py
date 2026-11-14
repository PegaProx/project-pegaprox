"""A snapshot policy with both retention rules off keeps what it has.

The edit form sends a cleared or 0 "keep last" with 0 days. The next run made its snapshot and then took
every snapshot of the policy on every target, that one too.
"""
import time
from types import SimpleNamespace

import pytest

from pegaprox.api import snapshots as sn
from pegaprox.core import ha

PID = 'abcdef012345678'
PREFIX = f'pegaprox-{PID[:12]}-'


def _mgr(ages):
    now = time.time()
    snaps = [{'name': f'{PREFIX}{i}', 'snaptime': now - age * 86400} for i, age in enumerate(ages)]
    snaps.append({'name': 'by-hand', 'snaptime': now - 400 * 86400})
    deleted = []
    # answers what the manager answers once PVE took the delete
    return SimpleNamespace(list_snapshots=lambda *a: snaps,
                           delete_snapshot=lambda node, vmid, kind, name: deleted.append(name) or {'success': True}), deleted


def _prune(monkeypatch, count, days, ages=(0, 1, 2, 40)):
    monkeypatch.setattr(ha, 'confirm_step', lambda what: True)
    mgr, deleted = _mgr(ages)
    pruned = sn._prune(mgr, 'pve1', 100, 'qemu', {'id': PID, 'retention_count': count, 'retention_days': days})
    return pruned, deleted


def test_both_off_deletes_nothing(monkeypatch):
    assert _prune(monkeypatch, 0, 0) == (0, [])


@pytest.mark.parametrize('count,days,left', [(2, 0, {0, 1}), (1, 0, {0}), (0, 10, {0, 1, 2}), (1, 10, {0, 1, 2})])
def test_a_rule_that_is_on_still_prunes(monkeypatch, count, days, left):
    pruned, deleted = _prune(monkeypatch, count, days)
    gone = {int(name[len(PREFIX):]) for name in deleted}
    assert gone == {0, 1, 2, 3} - left and pruned == len(deleted)
    assert 'by-hand' not in deleted
