"""The same snapshot showed two different times depending on the page.

The cluster-wide overview formatted server-side and handed over a string:

    snap_dt = datetime.fromtimestamp(snap_ts, tz=timezone.utc)
    ... "snapshot_date": snap_dt.strftime('%Y-%m-%d %H:%M')

and dashboard.js printed it verbatim, so it read UTC. The per-VM snapshot lists
in vm_config.js and vm_modals.js did `new Date(snap.snaptime * 1000)
.toLocaleString()` — browser-local, and going around the shared fmtDate() so
they ignored the 12h/24h preference as well. In CEST that is a two-hour
disagreement about one snapshot, and an operator quite reasonably read it as a
bug in the snapshot itself.

The fix is to stop deciding the timezone on the server: the overview now also
carries the raw epoch and all three places render it through fmtDate(), which
already handles epoch seconds and already respects the time-format setting.
snapshot_date stays in the payload — the table sorts on it, and an older
frontend against a newer backend should keep working.

This file guards the backend half. The rendering half is three one-line changes
in the bundle, verified by the strings landing in web/index.html. #939. MK
"""
from datetime import datetime, timezone

import pytest


def _overview_rows(api, seed, snaptime):
    mgr = api.make_fake_manager('cluster_1')
    mgr.get_vm_resources.return_value = [
        {'vmid': 100, 'name': 'web01', 'type': 'qemu', 'node': 'pve1', 'status': 'running'},
    ]
    mgr.get_snapshots.return_value = [
        {'name': 'before-upgrade', 'snaptime': snaptime},
        {'name': 'current', 'snaptime': snaptime},          # PVE's pseudo-entry
    ]
    api.set_manager('cluster_1', mgr)
    admin = api.as_user(seed.user('boss', role='admin'))
    r = admin.get('/api/snapshots/overview?days=0')
    assert r.status_code == 200, r.data
    return r.get_json()['snapshots']


def test_the_overview_hands_over_the_raw_epoch(api, seed):
    """The property: the client must be able to render the instant itself instead of
    being given somebody else's idea of what timezone to use."""
    ts = 1758500000
    rows = _overview_rows(api, seed, ts)
    if not rows:
        pytest.skip('the fake manager did not produce a row for this build')

    row = rows[0]
    assert 'snapshot_ts' in row, 'no raw timestamp, so the client can only reprint UTC'
    assert row['snapshot_ts'] == ts


def test_the_string_and_the_epoch_describe_the_same_instant(api, seed):
    """The two must not drift apart — snapshot_date is still what older frontends
    print and what the table sorts on."""
    ts = 1758500000
    rows = _overview_rows(api, seed, ts)
    if not rows:
        pytest.skip('the fake manager did not produce a row for this build')

    row = rows[0]
    expected = datetime.fromtimestamp(row['snapshot_ts'], tz=timezone.utc)
    assert row['snapshot_date'] == expected.strftime('%Y-%m-%d %H:%M')
