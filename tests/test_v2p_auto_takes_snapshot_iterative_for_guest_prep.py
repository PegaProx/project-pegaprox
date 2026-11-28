"""Auto takes Snapshot-Iterative for a run with the in-guest Windows preparation.

Stage 1 of the preparation runs after the clone and writes several GB into the guest (drivers,
guest tools). Live Clone copied all of it at the switchover, in the downtime: 34 minutes for a
lab Windows guest that Snapshot-Iterative moved with 9, its catch-up rounds carrying the writes
while the source still ran. Auto picks Snapshot-Iterative for it now and stays on Live Clone
where that cannot run; the review says so for an explicit Live Clone, and checks
Snapshot-Iterative before the start.

MK Nov 2026
"""
import pytest

import pegaprox.core.v2p as v2p
from pegaprox.core import v2p_guestprep

import test_v2p_tpm_and_folder_copy as farm


def _with_guest_prep(monkeypatch, r):
    """the probe found the guest ready; stage 1 then falls back (the guest is prepared offline
    after the copy), so nothing past the transfer talks to a guest"""
    def probe(vmware_mgr, pve_mgr, task):
        task._guest_prep = {'on': True, 'state': 'ready', 'os': 'Windows Server 2025', 'drivers': '', 'why': ''}

    def stage1(vmware_mgr, pve_mgr, task):
        r.log.append(('stage1', r.esxi.tracking))
        task._guest_prep.update(on=False, state='fallback', why='lab: offline after the copy')
    monkeypatch.setattr(v2p_guestprep, 'probe', probe)
    monkeypatch.setattr(v2p, '_guest_prep_stage1', stage1)
    return r


def _modes(r):
    return [ln for ln in r.task.log_lines if '=== TRANSFER MODE' in ln]


def test_auto_with_the_in_guest_preparation_runs_snapshot_iterative(monkeypatch):
    r = _with_guest_prep(monkeypatch, farm.Run(monkeypatch, mode='auto')).go()
    assert r.task.status == 'completed', r.task.error
    assert any('Auto -> Snapshot-Iterative (live clone + change tracking rounds)' in ln for ln in _modes(r)), _modes(r)
    # stage 1 ran with change tracking on, the rounds carry what it wrote, and it went off again
    assert ('stage1', True) in r.log
    assert ('esxi_api', 'tracking', True) in r.log and r.esxi.tracking is False
    assert any(e[:2] == ('esxi_api', 'changed_areas') for e in r.log)
    assert any('CATCH-UP ROUNDS' in ln for ln in r.task.log_lines)
    assert any('COMPLETED (snapshot_zero, downtime ~' in ln for ln in r.task.log_lines)


def test_auto_without_the_preparation_stays_on_live_clone(monkeypatch):
    r = farm.Run(monkeypatch, mode='auto').go()
    assert r.task.status == 'completed', r.task.error
    assert any('Auto -> vmkfstools_clone (VDDK-free live clone)' in ln for ln in _modes(r)), _modes(r)
    assert not any(e[:2] == ('esxi_api', 'tracking') for e in r.log)


def test_auto_stays_on_live_clone_where_snapshot_iterative_cannot_run(monkeypatch):
    r = _with_guest_prep(monkeypatch, farm.Run(monkeypatch, mode='auto'))
    r.esxi.snaps.append({'snapshot': 'snapshot-0', 'name': 'before-upgrade'})
    r.go()
    assert r.task.status == 'completed', r.task.error
    assert any('Auto -> vmkfstools_clone' in ln for ln in _modes(r)), _modes(r)
    assert any(ln.split('] ', 1)[-1].startswith('Auto stays on Live Clone for the in-guest preparation: The VM has '
                                                 'snapshots (before-upgrade)') for ln in r.task.log_lines)
    assert not any(e[:2] == ('esxi_api', 'tracking') for e in r.log)


def test_auto_goes_on_with_live_clone_when_tracking_cannot_be_switched_on(monkeypatch):
    r = _with_guest_prep(monkeypatch, farm.Run(monkeypatch, mode='auto'))
    monkeypatch.setattr(r.esxi, 'set_change_tracking',
                        lambda vm_id, on: {'error': 'Another task is already in progress.'})
    r.go()
    assert r.task.status == 'completed', r.task.error
    assert any('Auto goes on with Live Clone: change tracking could not be switched on for the source VM '
               '(Another task is already in progress.)' in ln for ln in r.task.log_lines)
    assert not any('CATCH-UP ROUNDS' in ln for ln in r.task.log_lines)


def test_the_fallback_to_pre_sync_switches_the_tracking_off_again(monkeypatch):
    # the clone snapshot fails: Auto hands over to the pre-sync flow, and the change tracking it
    # switched on for Snapshot-Iterative goes back as on every other way out
    r = _with_guest_prep(monkeypatch, farm.Run(monkeypatch, mode='auto', clone_snap_fails=True,
                                               ssh_key='/tmp/v2p-key-fixed')).go()
    assert ('esxi_api', 'tracking', True) in r.log
    assert ('esxi_api', 'tracking', False) in r.log and r.esxi.tracking is False


def test_an_explicit_snapshot_iterative_still_fails_where_it_cannot_run(monkeypatch):
    r = farm.Run(monkeypatch, mode='snapshot_zero')
    r.esxi.snaps.append({'snapshot': 'snapshot-0', 'name': 'before-upgrade'})
    r.go()
    assert r.task.status == 'failed' and 'The VM has snapshots (before-upgrade)' in r.task.error
