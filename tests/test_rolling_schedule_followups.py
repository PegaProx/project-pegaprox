"""What came after scheduled rolling updates moved onto the engine of a run started by hand.

A run that pauses now waits for a human, at 03:00 as well, so the channels that muted their
monitoring on rolling_update.started hear rolling_update.paused once per hold (not once per
look of the wait), for a run started by hand and a scheduled one alike. A save of the schedule
keeps the stored channels, Ceph gate, pause switch and reboot wait when the body does not carry
them (the dialog sends only some), and answers 400 for a switch that is not a boolean, as the
manual route does. A scheduled run that a restart left paused and that is then cancelled without
its worker gets its scheduled.rolling_update end entry like one its worker winds down. The audit
line of a saved schedule says when the safety switches are not at their defaults.
"""
import sqlite3
import time

import pytest

from pegaprox.core import rolling_runs
from test_rolling_runs_survive_restart import (CID, _a_fresh_process, _Cluster, _die, _FastTime,  # noqa: F401
                                               _restart, _until, _worker_gone, fast, root)
from test_rolling_scheduled_like_manual import (SCHEDULE, _arm, _audit, _paused, _resume, _Scheduled,
                                                _state, _tick, clock)  # noqa: F401

PAUSED = 'rolling_update.paused'


@pytest.fixture
def alerts(monkeypatch):
    """Every lifecycle alert that went out, with the channel ids it went to."""
    from pegaprox.utils import webhooks
    out = []
    monkeypatch.setattr(webhooks, 'send_to_channels', lambda alert, ids: out.append((dict(alert), list(ids))))
    return out


@pytest.fixture
def naps(fast, monkeypatch):
    """The sleeps of the engine, counted: the wait of a hold looks every 2 s."""
    import pegaprox.api.settings as settings_mod
    count = [0]

    class _Counted(_FastTime):
        @staticmethod
        def sleep(_s):
            count[0] += 1
            time.sleep(0.001)

    monkeypatch.setattr(settings_mod, 'time', _Counted())
    return count


def _events(alerts):
    return [a['event'] for a, _ in alerts]


def _paused_alerts(alerts):
    return [(a, ids) for a, ids in alerts if a['event'] == PAUSED]


def _many_looks(naps, more=60):
    base = naps[0]
    assert _until(lambda: naps[0] > base + more), 'the wait of the hold did not go round'


# -- 1. the paused event -------------------------------------------------------------------------

def test_a_scheduled_run_announces_its_pause_once_however_long_it_waits(api, seed, db, root, clock, naps, alerts):
    cluster = api.set_manager(CID, _Scheduled(update_fails={'pve1'}))
    _arm(api, root, notify_channels=['ops'])
    _tick()
    assert _paused(cluster), _state(cluster).get('logs')
    _many_looks(naps)
    held = _paused_alerts(alerts)
    assert len(held) == 1, _events(alerts)
    alert, ids = held[0]
    assert ids == ['ops']
    assert alert['severity'] == 'warning' and alert['cluster_id'] == CID
    assert alert['alert_name'] == 'Rolling update paused on Testi'
    assert 'pve1' in alert['message'] and 'node_failure' in alert['message'], alert['message']
    _resume(api, root)
    _worker_gone()
    assert _state(cluster)['status'] == 'completed', _state(cluster)['logs']
    assert _events(alerts) == ['rolling_update.started', PAUSED, 'rolling_update.finished']


def test_each_hold_of_the_run_is_announced_once(api, seed, db, root, clock, naps, alerts):
    cluster = api.set_manager(CID, _Scheduled(update_fails={'pve1', 'pve2'}))
    _arm(api, root, notify_channels=['ops'])
    _tick()
    assert _paused(cluster)
    _many_looks(naps)
    _resume(api, root)
    assert _until(lambda: _state(cluster).get('status') == 'paused'
                  and (_state(cluster).get('paused_details') or {}).get('node') == 'pve2'), _state(cluster)['logs']
    _many_looks(naps)
    held = _paused_alerts(alerts)
    assert [('pve1' in a['message'], 'pve2' in a['message']) for a, _ in held] == [(True, False), (False, True)]
    assert api.as_user(root).delete(f'/api/clusters/{CID}/updates/rolling').status_code == 200
    _worker_gone()
    assert _events(alerts) == ['rolling_update.started', PAUSED, PAUSED, 'rolling_update.finished']


def test_a_run_started_by_hand_announces_its_pause_as_well(api, seed, db, root, naps, alerts):
    cluster = api.set_manager(CID, _Scheduled(evac_errors={'pve1'}))
    r = api.as_user(root).post(f'/api/clusters/{CID}/updates/rolling',
                               json={'include_reboot': False, 'skip_up_to_date': False, 'notify_channels': ['ops']})
    assert r.status_code == 200, r.data
    assert _paused(cluster)
    _many_looks(naps)
    held = _paused_alerts(alerts)
    assert len(held) == 1 and held[0][1] == ['ops'], _events(alerts)
    assert 'pve1' in held[0][0]['message'] and 'evacuation_failures' in held[0][0]['message']
    assert held[0][0]['severity'] == 'warning'
    rolling_runs.change(cluster, status='cancelled')
    _worker_gone()


def test_a_run_without_channels_sends_nothing_when_it_pauses(api, seed, db, root, clock, naps, alerts):
    cluster = api.set_manager(CID, _Scheduled(update_fails={'pve1'}))
    _arm(api, root)
    _tick()
    assert _paused(cluster)
    _many_looks(naps)
    assert alerts == []
    rolling_runs.change(cluster, status='cancelled')
    _worker_gone()
    assert alerts == []


# -- 2. a save keeps what it does not carry ------------------------------------------------------

STORED = {'notify_channels': ['ops', 'pager'], 'ceph_health_gate': 'degraded',
          'pause_on_evacuation_error': False, 'wait_for_reboot': False}


def _options(got):
    return {k: got[k] for k in STORED}


def test_saving_only_a_time_keeps_the_stored_run_options(api, seed, db, root):
    api.set_manager(CID, _Scheduled())
    _arm(api, root, **STORED)
    c = api.as_user(root)
    assert _options(c.get(SCHEDULE).get_json()) == STORED
    r = c.post(SCHEDULE, json={'enabled': True, 'day': 'daily', 'time': '04:00', 'include_reboot': False})
    assert r.status_code == 200, r.data
    got = c.get(SCHEDULE).get_json()
    assert got['time'] == '04:00' and _options(got) == STORED
    # what the scheduler reads, too
    import pegaprox.api.schedules as sch
    assert _options(sch.load_all_update_schedules()[CID]) == STORED
    # null is no value either
    r = c.post(SCHEDULE, json={'enabled': True, 'time': '04:00', 'include_reboot': False,
                               **{k: None for k in STORED}})
    assert r.status_code == 200, r.data
    assert _options(c.get(SCHEDULE).get_json()) == STORED


def test_the_dialog_body_sets_what_it_sends_and_keeps_the_rest(api, seed, db, root):
    api.set_manager(CID, _Scheduled())
    _arm(api, root, **STORED)
    c = api.as_user(root)
    # the body of the schedule dialog (security.js): wait_for_reboot, never the other three
    dialog = {'enabled': True, 'schedule_type': 'recurring', 'day': 'sunday', 'time': '03:00',
              'include_reboot': False, 'skip_evacuation': False, 'wait_for_reboot': True,
              'skip_up_to_date': True, 'evacuation_timeout': 1800, 'reboot_timeout': 600,
              'migrate_templates': False, 'relax_anti_affinity': False}
    assert c.post(SCHEDULE, json=dialog).status_code == 200
    assert _options(c.get(SCHEDULE).get_json()) == dict(STORED, wait_for_reboot=True)


def test_a_body_that_carries_the_options_sets_them(api, seed, db, root):
    api.set_manager(CID, _Scheduled())
    _arm(api, root, **STORED)
    c = api.as_user(root)
    back = {'notify_channels': [], 'ceph_health_gate': 'off', 'pause_on_evacuation_error': True,
            'wait_for_reboot': True}
    assert c.post(SCHEDULE, json={'enabled': True, 'include_reboot': False, **back}).status_code == 200
    assert _options(c.get(SCHEDULE).get_json()) == back


def test_a_stored_schedule_that_cannot_be_read_is_not_overwritten(api, seed, db, root, monkeypatch):
    api.set_manager(CID, _Scheduled())
    _arm(api, root, **STORED)
    import pegaprox.api.schedules as sch

    class _Locked:
        class conn:
            @staticmethod
            def cursor():
                raise sqlite3.OperationalError('database is locked')

            @staticmethod
            def commit():
                pass

    with monkeypatch.context() as m:
        m.setattr(sch, 'get_db', lambda: _Locked())
        r = api.as_user(root).post(SCHEDULE, json={'enabled': True, 'time': '05:00', 'include_reboot': False})
    assert r.status_code == 500, r.data
    got = api.as_user(root).get(SCHEDULE).get_json()
    assert got['time'] == '03:00' and _options(got) == STORED


# -- 4. the switches are booleans ----------------------------------------------------------------

# the older switches too: "false" as a string was truthy and skipped the evacuation
@pytest.mark.parametrize('key', ['wait_for_reboot', 'pause_on_evacuation_error', 'enabled', 'include_reboot',
                                 'skip_evacuation', 'skip_up_to_date'])
@pytest.mark.parametrize('bad', ['false', 'yes', 2, [], {}])
def test_a_switch_that_is_not_a_boolean_is_refused(api, seed, db, root, key, bad):
    api.set_manager(CID, _Scheduled())
    r = api.as_user(root).post(SCHEDULE, json={'enabled': True, 'include_reboot': False, key: bad})
    assert r.status_code == 400, r.data
    assert key in r.get_json()['error']
    import pegaprox.api.schedules as sch
    assert sch.load_all_update_schedules() == {}


def test_zero_and_one_are_switches_as_on_the_manual_route(api, seed, db, root):
    api.set_manager(CID, _Scheduled())
    c = api.as_user(root)
    r = c.post(SCHEDULE, json={'enabled': True, 'include_reboot': False,
                               'wait_for_reboot': 0, 'pause_on_evacuation_error': 0})
    assert r.status_code == 200, r.data
    got = c.get(SCHEDULE).get_json()
    assert got['wait_for_reboot'] is False and got['pause_on_evacuation_error'] is False
    assert c.post(SCHEDULE, json={'enabled': True, 'include_reboot': False,
                                  'wait_for_reboot': 1, 'pause_on_evacuation_error': 1}).status_code == 200
    got = c.get(SCHEDULE).get_json()
    assert got['wait_for_reboot'] is True and got['pause_on_evacuation_error'] is True



@pytest.mark.parametrize('key', ['evacuation_timeout', 'reboot_timeout'])
def test_a_timeout_is_a_number_of_seconds_held_to_its_range(api, seed, db, root, key):
    api.set_manager(CID, _Scheduled())
    c = api.as_user(root)
    r = c.post(SCHEDULE, json={'enabled': True, 'include_reboot': False, key: 'soon'})
    assert r.status_code == 400 and key in r.get_json()['error'], r.data
    assert c.post(SCHEDULE, json={'enabled': True, 'include_reboot': False, key: 99999}).status_code == 200
    assert c.get(SCHEDULE).get_json()[key] == 7200

# -- 5. the end of a scheduled run cancelled without its worker -----------------------------------

def _scheduled(cluster):
    import pegaprox.api.schedules as sch
    sch.execute_scheduled_rolling_update(cluster, CID, {'cluster_id': CID, 'action': 'rolling_update',
                                                        'config': {'include_reboot': False}})


def test_a_scheduled_run_cancelled_after_a_restart_writes_its_end(api, seed, db, root, fast, monkeypatch):
    cluster = api.set_manager(CID, _Cluster(die_at=('updating', 'pve2')))
    _scheduled(cluster)
    _worker_gone()
    assert _audit(db, 'scheduled.rolling_update') == []
    fresh = _restart(api.set_manager(CID, _Cluster(include_maintenance=('pve2',))), monkeypatch=monkeypatch)
    assert rolling_runs.current(fresh)['paused_reason'] == 'interrupted'
    assert not rolling_runs.worker_here(CID, fresh)
    r = api.as_user(root).delete(f'/api/clusters/{CID}/updates/rolling')
    assert r.status_code == 200, r.data
    assert 'not_undone' in r.get_json(), 'the cancel did not take the run down itself'
    assert rolling_runs.current(fresh)['status'] == 'cancelled'
    assert _audit(db, 'scheduled.rolling_update') == [
        ('scheduler', 'Scheduled rolling update cancelled: 1 updated, 0 skipped, 0 failed [Testi]', 'Testi')]
    # the user's own entry stays as it was
    assert [u for u, _, _ in _audit(db, 'node.rolling_update_cancelled')] == ['root']


def test_a_run_by_hand_cancelled_after_a_restart_writes_no_scheduled_end(api, seed, db, root, fast, monkeypatch):
    _die(api, root, db, ('updating', 'pve1'))
    _restart(api.set_manager(CID, _Cluster(include_maintenance=('pve1',))), monkeypatch=monkeypatch)
    r = api.as_user(root).delete(f'/api/clusters/{CID}/updates/rolling')
    assert r.status_code == 200 and 'not_undone' in r.get_json(), r.data
    assert _audit(db, 'scheduled.rolling_update') == []


def test_the_end_entry_never_stops_a_cancel(api, seed, db, root, fast, monkeypatch):
    import pegaprox.api.settings as settings_mod
    cluster = api.set_manager(CID, _Cluster(die_at=('updating', 'pve2')))
    _scheduled(cluster)
    _worker_gone()
    fresh = _restart(api.set_manager(CID, _Cluster(include_maintenance=('pve2',))), monkeypatch=monkeypatch)

    def broken(user, action, *a, **k):
        if action == 'scheduled.rolling_update':
            raise sqlite3.OperationalError('disk I/O error')
    monkeypatch.setattr(settings_mod, 'log_audit', broken)
    r = api.as_user(root).delete(f'/api/clusters/{CID}/updates/rolling')
    assert r.status_code == 200, r.data
    assert rolling_runs.current(fresh)['status'] == 'cancelled'


# -- 6. the audit line of a saved schedule -------------------------------------------------------

def _schedule_audit(db):
    return [d for _, d, _ in _audit(db, 'update.schedule')]


def test_the_audit_line_names_the_switches_off_their_defaults(api, seed, db, root):
    api.set_manager(CID, _Scheduled())
    _arm(api, root, pause_on_evacuation_error=False, ceph_health_gate='strict', notify_channels=['ops', 'pager'])
    assert _schedule_audit(db)[-1] == ('Update schedule enabled for Testi (pause_on_evacuation_error off, '
                                       'ceph_health_gate=strict, 2 alert channel(s)) [Testi]')
    # one at a time
    _arm(api, root, pause_on_evacuation_error=True, ceph_health_gate='off', notify_channels=[])
    assert _schedule_audit(db)[-1] == 'Update schedule enabled for Testi [Testi]'
    _arm(api, root, ceph_health_gate='degraded')
    assert _schedule_audit(db)[-1] == 'Update schedule enabled for Testi (ceph_health_gate=degraded) [Testi]'


def test_the_audit_line_names_what_a_save_kept(api, seed, db, root):
    """A save that keeps a stored switch off says so: the line is what the schedule now is."""
    api.set_manager(CID, _Scheduled())
    _arm(api, root, pause_on_evacuation_error=False)
    _arm(api, root, time='04:00')
    assert _schedule_audit(db)[-1] == 'Update schedule enabled for Testi (pause_on_evacuation_error off) [Testi]'
