"""One drift scan per cluster at a time.

"Scan now" pressed while a scan of the same cluster was still running (a second click, or
the scheduled pass) started a second scan next to it. Both read the open deviations before
either wrote, so the same drift was recorded twice. The second scan is now skipped with the
reason "a scan of this cluster is already running"; the scheduled scanner goes through the
same gate. The gate opens again when the scan ends, also when it raised.

Fake PVE and fixtures are those of test_drift_more_kinds.py.
"""
import threading

import pytest

from pegaprox.api import drift

from test_drift_more_kinds import CL, pve, estate, admin, _events  # noqa: F401

REASON = 'a scan of this cluster is already running'


class _Held:
    """Wraps one drift step so its first call waits until the test lets it go, before the
    step runs or (after=True) once it has run."""

    def __init__(self, monkeypatch, name, after=False):
        self.inside = threading.Event()
        self.go = threading.Event()
        self.calls = 0
        real = getattr(drift, name)

        def wrapped(*a, **kw):
            self.calls += 1
            if self.calls != 1:
                return real(*a, **kw)
            out = real(*a, **kw) if after else None
            self.inside.set()
            assert self.go.wait(10), 'the test never let the scan go on'
            return out if after else real(*a, **kw)
        monkeypatch.setattr(drift, name, wrapped)


def _start(target, *args):
    out = {}

    def run():
        try:
            out['result'] = target(*args)
        except Exception as e:      # noqa: BLE001 - handed to the test
            out['error'] = e
    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t, out


# admin comes before pve in these signatures: the api fixture starts from an empty manager
# registry, so the fake cluster has to be put in after it

def test_scan_now_during_a_running_scan_is_skipped_and_says_why(admin, pve, monkeypatch):
    held = _Held(monkeypatch, '_fetch_state')
    t, first = _start(drift._scan_cluster, CL, True)
    assert held.inside.wait(5)
    r = admin.post(f'/api/clusters/{CL}/drift/scan', json={})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json() == {'error': REASON, 'status': 'skipped'}
    # the skipped one read nothing
    assert held.calls == 1
    held.go.set()
    t.join(10)
    assert first['result']['ok'] is True and first['result']['seeded_baselines'] > 0


def test_the_gate_opens_again_when_the_scan_is_done(admin, pve):
    assert drift._scan_cluster(CL, True)['ok'] is True
    j = admin.post(f'/api/clusters/{CL}/drift/scan', json={}).get_json()
    assert j.get('ok') is True, j


def test_the_gate_opens_again_when_the_scan_raised(pve, monkeypatch):
    real = drift._fetch_state

    def boom(*a, **kw):
        raise RuntimeError('read blew up')
    monkeypatch.setattr(drift, '_fetch_state', boom)
    with pytest.raises(RuntimeError):
        drift._scan_cluster(CL)
    monkeypatch.setattr(drift, '_fetch_state', real)
    assert drift._scan_cluster(CL, True)['ok'] is True


def test_another_cluster_is_not_held_up(pve, monkeypatch):
    held = _Held(monkeypatch, '_fetch_state')
    t, _ = _start(drift._scan_cluster, CL, True)
    assert held.inside.wait(5)
    try:
        # gets past the gate and answers for itself
        assert drift._scan_cluster('c_other') == {'error': 'cluster not found'}
    finally:
        held.go.set()
        t.join(10)


def test_the_same_drift_is_recorded_once_when_a_second_scan_comes_in(admin, pve, db, monkeypatch):
    """The scan reads the open deviations first and writes after; two side by side both
    found none open and both wrote one."""
    drift._scan_cluster(CL, autobaseline=True)
    pve.routes['/nodes/n1/qemu/101/config'] = dict(pve.routes['/nodes/n1/qemu/101/config'], cores=4)
    # the first scan has read what is open (nothing) and has not written yet
    held = _Held(monkeypatch, '_open_deviation_diffs', after=True)
    t, first = _start(drift._scan_cluster, CL)
    assert held.inside.wait(5)
    second = admin.post(f'/api/clusters/{CL}/drift/scan', json={}).get_json()
    held.go.set()
    t.join(10)
    rows = _events(db, kind='vm_config', status='open')
    assert len(rows) == 1, f'the same drift was recorded {len(rows)} times'
    assert first['result']['events_count'] == 1
    assert second == {'error': REASON, 'status': 'skipped'}


def test_the_scheduled_pass_leaves_a_running_scan_be(pve, monkeypatch):
    from pegaprox.core import ha
    monkeypatch.setattr(drift, '_collapse_repeats', lambda: None)
    monkeypatch.setattr(drift, '_prune_events', lambda: 0)
    monkeypatch.setattr(ha, 'is_active', lambda: True)
    held = _Held(monkeypatch, '_fetch_state')
    t, _ = _start(drift._scan_cluster, CL, True)
    assert held.inside.wait(5)

    # one pass of the loop, then it stops at its sleep
    def stop(_sec):
        drift._scanner_running = False
    monkeypatch.setattr(drift.time, 'sleep', stop)
    monkeypatch.setattr(drift, '_scanner_running', True)
    try:
        drift._scanner_loop()
        assert held.calls == 1, 'the scheduled pass read the cluster a second time'
    finally:
        held.go.set()
        t.join(10)
    # and with nothing running it scans as before
    monkeypatch.setattr(drift, '_scanner_running', True)
    drift._scanner_loop()
    assert held.calls == 2
