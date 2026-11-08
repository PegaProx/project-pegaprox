# #747 — the rolling-update Ceph wait must skip a benign steady-state HEALTH_WARN (slow ops in
# BlueStore) instead of burning 120s/node waiting for a HEALTH_OK that never comes — WITHOUT
# weakening the real protection: it must still hold through any genuine recovery/rebalance, or a
# rolling update becomes a rolling outage on HCI.

from pegaprox.api.settings import _ceph_recovery_pending


# ---- proceed (no wait): settled clusters, benign warnings ----

def test_health_ok_does_not_wait():
    assert _ceph_recovery_pending({'status': 'HEALTH_OK', 'osd_up': 6, 'osd_in': 6,
                                   'pgs': '1024 active+clean', 'warnings': []}) is False


def test_slow_ops_only_does_not_wait():
    # the reporter's exact case: OSD_SLOW_OPS in BlueStore, everything else clean
    assert _ceph_recovery_pending({'status': 'HEALTH_WARN', 'osd_up': 6, 'osd_in': 6,
                                   'pgs': '1024 active+clean', 'warnings': ['OSD_SLOW_OPS']}) is False


def test_benign_clock_skew_and_leftover_flag_do_not_wait():
    assert _ceph_recovery_pending({'status': 'HEALTH_WARN', 'osd_up': 6, 'osd_in': 6,
                                   'pgs': '1024 active+clean', 'warnings': ['MON_CLOCK_SKEW', 'OSDMAP_FLAGS']}) is False


def test_empty_or_none_does_not_wait():
    assert _ceph_recovery_pending(None) is False
    assert _ceph_recovery_pending({}) is False


# ---- keep waiting (SAFETY): recovery / rebalance / data-at-risk ----

def test_recovering_pgs_wait():
    assert _ceph_recovery_pending({'status': 'HEALTH_WARN', 'osd_up': 6, 'osd_in': 6,
                                   'pgs': '1000 active+clean, 24 active+recovering', 'warnings': ['PG_DEGRADED']}) is True


def test_backfilling_pgs_wait():
    # data-safe movement _ceph_gate_unsafe tolerates — but the WAIT must still hold through it
    assert _ceph_recovery_pending({'status': 'HEALTH_WARN', 'osd_up': 6, 'osd_in': 6,
                                   'pgs': '1000 active+clean, 24 active+remapped+backfilling', 'warnings': []}) is True


def test_degraded_undersized_pgs_wait():
    assert _ceph_recovery_pending({'status': 'HEALTH_WARN', 'osd_up': 5, 'osd_in': 6,
                                   'pgs': '900 active+clean, 124 active+undersized+degraded', 'warnings': ['PG_DEGRADED']}) is True


def test_recovery_beyond_top3_pg_states_caught_by_check_id():
    # pgs summary only carries the top 3 states; a recovery hidden past them is still caught by the
    # health check-id, so we don't under-wait
    assert _ceph_recovery_pending({'status': 'HEALTH_WARN', 'osd_up': 6, 'osd_in': 6,
                                   'pgs': '1024 active+clean', 'warnings': ['PG_AVAILABILITY']}) is True


def test_osd_down_waits():
    assert _ceph_recovery_pending({'status': 'HEALTH_WARN', 'osd_up': 5, 'osd_in': 6,
                                   'pgs': '1024 active+clean', 'warnings': ['OSD_DOWN']}) is True


def test_health_err_and_unknown_wait():
    assert _ceph_recovery_pending({'status': 'HEALTH_ERR', 'osd_up': 6, 'osd_in': 6, 'pgs': '', 'warnings': []}) is True
    assert _ceph_recovery_pending({'status': 'unknown', 'osd_up': 0, 'osd_in': 0, 'pgs': '', 'warnings': []}) is True
