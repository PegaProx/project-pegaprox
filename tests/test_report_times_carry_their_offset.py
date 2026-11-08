"""Report times have to say which zone they are in.

The metrics collector, the CVE scan and the syslog receiver store
datetime.now().isoformat(): server-local and without an offset. The report endpoints
handed that string on, and a browser reads an ISO string without an offset as its
own local time, so with the server in one zone and the browser in another every chart
label and scan time was off by the difference.

The stored format stays as it is. The answer carries the server's UTC offset, so the
instant is the same wherever it is read. The server runs in Asia/Kolkata here (+05:30,
no DST), a zone the test machine is unlikely to be in by accident.
"""
import os
import time
import types
from datetime import datetime, timedelta, timezone

import pytest

import metrics_history_fixture as mhf

CLUSTER = 'cluster_1'
SERVER_TZ = 'Asia/Kolkata'
OFFSET = timedelta(hours=5, minutes=30)


@pytest.fixture
def server_tz():
    before = os.environ.get('TZ')
    os.environ['TZ'] = SERVER_TZ
    time.tzset()
    try:
        yield
    finally:
        if before is None:
            os.environ.pop('TZ', None)
        else:
            os.environ['TZ'] = before
        time.tzset()


def _instant(naive_iso):
    """The moment a stored server-local string stands for."""
    return datetime.fromisoformat(naive_iso).replace(tzinfo=timezone(OFFSET))


def _assert_same_moment(sent, stored):
    got = datetime.fromisoformat(sent)
    assert got.utcoffset() is not None, f'{sent!r} has no offset: the browser reads it as its own time'
    assert got.utcoffset() == OFFSET, sent
    assert got == _instant(stored), (sent, stored)


@pytest.fixture
def history(server_tz, db, monkeypatch):
    """Four snapshots in the test's own database, written as PegaProx writes them."""
    h = mhf.recorded(monkeypatch)
    snap = {'clusters': {CLUSTER: {'name': 'Cluster One', 'totals': {
        'cpu_total': 100, 'cpu_used': 25, 'mem_total': 1000, 'mem_used': 500,
        'vms_running': 2, 'cts_running': 1}}}}
    now = datetime.now()
    stamps = [(now - timedelta(minutes=m)).isoformat() for m in (40, 30, 20, 10)]
    h.write([(ts, snap) for ts in stamps])
    yield types.SimpleNamespace(stamps=stamps, stored=h.stored)


def _admin(api, seed):
    m = api.make_fake_manager(cluster_id=CLUSTER)
    m.is_connected = False
    m.config.name = 'Cluster One'
    api.set_manager(CLUSTER, m)
    return api.as_user(seed.user('root', role='admin')), m


def test_the_cluster_report_timeline_carries_the_offset(api, seed, history):
    admin, _ = _admin(api, seed)
    body = admin.get(f'/api/clusters/{CLUSTER}/reports/summary?period=day').get_json()
    assert len(body['timestamps']) == len(history.stamps)
    for sent, stored in zip(body['timestamps'], history.stamps):
        _assert_same_moment(sent, stored)


def test_the_cross_cluster_reports_carry_it_too(api, seed, history):
    admin, _ = _admin(api, seed)
    timeline = admin.get('/api/reports/timeline?period=day').get_json()
    for sent, stored in zip(timeline['timestamps'], history.stamps):
        _assert_same_moment(sent, stored)
    summary = admin.get('/api/reports/summary?period=day').get_json()
    _assert_same_moment(summary['start_time'], history.stamps[0])
    _assert_same_moment(summary['end_time'], history.stamps[-1])


def test_the_stored_rows_keep_their_format(api, seed, history):
    admin, _ = _admin(api, seed)
    admin.get(f'/api/clusters/{CLUSTER}/reports/summary?period=week')
    rows = [r[0] for r in history.stored('SELECT timestamp FROM metrics_history ORDER BY id')]
    assert rows == history.stamps


def test_the_window_still_counts_in_server_time(api, seed, history):
    """The cutoff compares stored strings; only the answer changed."""
    admin, _ = _admin(api, seed)
    hour = admin.get(f'/api/clusters/{CLUSTER}/reports/summary?period=hour').get_json()
    assert hour['data_points'] == 4


# -- the CVE scan ------------------------------------------------------------------------

def test_a_cve_scan_says_when_in_which_zone(api, seed, server_tz):
    admin, m = _admin(api, seed)
    m.is_connected = True
    stored = datetime.now().replace(microsecond=0).isoformat()
    m.get_node_status.return_value = {'pve1': {'status': 'online'}}
    m.scan_node_packages.side_effect = lambda node: {'node': node, 'timestamp': stored, 'cves': []}

    body = admin.post(f'/api/clusters/{CLUSTER}/reports/cve-scan').get_json()
    _assert_same_moment(body['nodes'][0]['timestamp'], stored)
    scanned = datetime.fromisoformat(body['scanned_at'])
    assert scanned.utcoffset() == OFFSET
    assert abs((scanned - _instant(stored)).total_seconds()) < 60

    one = admin.post(f'/api/clusters/{CLUSTER}/nodes/pve1/cve-scan').get_json()
    _assert_same_moment(one['timestamp'], stored)


# -- the syslog list (same file, same stored format) --------------------------------------

@pytest.fixture
def syslog_db(server_tz, tmp_path, monkeypatch):
    import pegaprox.api.reports as reports
    import pegaprox.background.syslog_server as sl
    path = str(tmp_path / 'syslog.db')
    monkeypatch.setattr(sl, 'DB_FILE', path)
    monkeypatch.setattr(reports, 'DB_FILE', path)
    conn = sl._open_db()
    conn.execute('CREATE TABLE IF NOT EXISTS logs (id INTEGER PRIMARY KEY AUTOINCREMENT, '
                 'timestamp TEXT, source_ip TEXT, hostname TEXT, facility INTEGER, severity INTEGER, '
                 'severity_text TEXT, message TEXT, protocol TEXT)')
    stored = (datetime.now() - timedelta(minutes=5)).isoformat()
    conn.execute('INSERT INTO logs (timestamp, source_ip, hostname, facility, severity, severity_text, '
                 'message, protocol) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                 (stored, '10.0.0.5', 'pve1', 3, 6, 'info', 'hello', 'UDP'))
    conn.commit()
    conn.close()
    return stored


def test_a_syslog_row_carries_the_offset(api, seed, syslog_db):
    admin, _ = _admin(api, seed)
    r = admin.get('/api/syslog/events')
    assert r.status_code == 200, r.get_data(as_text=True)[:300]
    items = r.get_json()['items']
    assert [i['message'] for i in items] == ['hello']
    _assert_same_moment(items[0]['timestamp'], syslog_db)


def test_a_syslog_search_still_matches_the_stored_text(api, seed, syslog_db):
    admin, _ = _admin(api, seed)
    day = syslog_db[:10]
    items = admin.get(f'/api/syslog/events?search={day}').get_json()['items']
    assert len(items) == 1
