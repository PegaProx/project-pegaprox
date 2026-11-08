"""The Prometheus exporter: storage, replication, backup age and guest disk I/O.

/api/metrics gains, per cluster:
  - pegaprox_storage_*: used and total bytes and whether it is active, per storage, from the
    /cluster/resources?type=storage read the health pill and the storage overview share
    (shared storage once, not once per node) and the SR list of an XCP-ng pool
  - pegaprox_replication_*: the last successful sync and the failure state per job, from the
    job list and the status of every source node (alert_events.read_replication)
  - pegaprox_guest_last_backup_*: the newest backup per guest from the scan behind the VM
    list's backup pill: the snapshot lists of the linked PBS datastores and the vzdump files
    on the backup storages. Nothing is asked per guest.
  - pegaprox_guest_disk_read/write_bytes_total next to the network counters, from the
    /cluster/resources rows the scrape reads anyway
The replication and backup reads run in the background and a scrape hands out the last one;
pegaprox_cluster_source_up says whether what is there is complete. The endpoint's gate
(admin token, metrics.view, metrics_public) is untouched.
The clusters are faked at the API paths they are asked.
MK Oct 2026
"""
import re
import time
import types

import pytest

import pegaprox.api.clusters as clusters_mod
import pegaprox.api.metrics_exporter as mx
import pegaprox.api.pbs as pbs_mod
from pegaprox.core.cache import StorageDataCache

GiB = 1024 ** 3
STORAGE = '/cluster/resources?type=storage'
NOW = time.time()


@pytest.fixture(autouse=True)
def _fresh_now():
    # the exporter measures ages at scrape time; a NOW from import time is minutes old by
    # the time this file runs late in a parallel suite
    global NOW
    NOW = time.time()


class _Resp:
    def __init__(self, code, data):
        self.status_code, self._data = code, data

    def json(self):
        return {'data': self._data}


class _Pve:
    host, api_port, cluster_type = 'pve.example', 8006, 'proxmox'

    def __init__(self, name, guests=(), storage=(), code=200):
        self.config = types.SimpleNamespace(name=name)
        self.is_connected = True
        self.guests = [dict(g) for g in guests]
        self.paths = {STORAGE: (code, [dict(s) for s in storage]),
                      '/cluster/replication': (200, []), '/nodes': (200, [])}
        self.calls = []

    def answer(self, path, data, code=200):
        self.paths[path] = (code, data)

    def _api_get(self, url, timeout=10, **_kw):
        path = url.split('/api2/json', 1)[1]
        self.calls.append(path)
        code, data = self.paths.get(path, (404, None))
        return _Resp(code, data)

    def get_node_status(self):
        return {'pve1': {'status': 'online', 'cpu': 0.1, 'mem_percent': 5, 'uptime': 10}}

    def get_node_apt_updates(self, node):
        return []

    def get_ceph_health_summary(self):
        return None

    def get_vm_resources(self, max_age=0):
        return [dict(g) for g in self.guests]

    def count(self, path):
        return self.calls.count(path)


class _Xen:
    cluster_type = 'xcpng'

    def __init__(self, name, srs, vms):
        self.config = types.SimpleNamespace(name=name)
        self.is_connected = True
        self.srs, self.vms = srs, vms

    def get_storages(self, node=None):
        return [dict(s) for s in self.srs]

    def get_node_status(self):
        return {}

    def get_vm_resources(self, max_age=0):
        return [dict(v) for v in self.vms]


class _Pbs:
    def __init__(self, linked, snapshots, connected=True):
        self.linked_clusters = linked
        self.connected = connected
        self.name = 'backup01'
        self.snapshots = snapshots
        self.reads = []

    def get_datastores(self):
        return {'data': [{'store': 'ds1'}]}

    def get_snapshots(self, store, ns=None, backup_type=None, backup_id=None):
        self.reads.append(store)
        return {'data': [dict(s) for s in self.snapshots]}


def _stor(node, storage, used, total, plugintype='lvmthin', shared=0, status='available'):
    return {'id': f'storage/{node}/{storage}', 'type': 'storage', 'node': node, 'storage': storage,
            'status': status, 'plugintype': plugintype, 'shared': shared, 'content': 'images',
            'disk': used * GiB, 'maxdisk': total * GiB}


STORAGE_ROWS = [
    _stor('pve1', 'local-lvm', 90, 100),
    _stor('pve1', 'nfs-vm', 300, 1000, 'nfs', shared=1),
    _stor('pve2', 'local-lvm', 40, 200),
    _stor('pve2', 'nfs-vm', 300, 1000, 'nfs', shared=1),
    # pve3 is down: pvestatd keeps its last figures and says unknown
    _stor('pve3', 'nfs-vm', 280, 1000, 'nfs', shared=1, status='unknown'),
    _stor('pve3', 'local-lvm', 99, 100, status='unknown'),
]

GUESTS = [
    {'vmid': 101, 'type': 'qemu', 'node': 'pve1', 'name': 'web01', 'status': 'running',
     'mem': GiB, 'maxmem': 2 * GiB, 'netin': 500, 'netout': 600, 'diskread': 7000, 'diskwrite': 8000},
    {'vmid': 102, 'type': 'lxc', 'node': 'pve1', 'name': 'db01', 'status': 'running',
     'netin': 1, 'netout': 2, 'diskread': 30, 'diskwrite': 40},
    {'vmid': 103, 'type': 'qemu', 'node': 'pve2', 'name': 'files', 'status': 'stopped',
     'netin': 0, 'netout': 0, 'diskread': 0, 'diskwrite': 0},
    {'vmid': 104, 'type': 'qemu', 'node': 'pve2', 'name': 'lab', 'status': 'stopped'},
    {'vmid': 900, 'type': 'qemu', 'node': 'pve1', 'name': 'tpl', 'status': 'stopped', 'template': 1},
]


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    monkeypatch.setattr(mx, '_auth_ok', lambda: True)
    # the reads that run in the background run in the scrape here, so a scrape shows them
    monkeypatch.setattr(mx, '_spawn', lambda fn: fn(), raising=False)
    monkeypatch.setattr(mx, '_repl_reads', {}, raising=False)
    monkeypatch.setattr(mx, '_reads_running', set(), raising=False)
    monkeypatch.setattr(mx, '_pressure_reads', {})
    monkeypatch.setattr(mx, '_pressure_absent', {})
    from pegaprox.background import alert_events
    monkeypatch.setattr(alert_events, '_clock', {})
    monkeypatch.setattr(clusters_mod, '_health_storage_cache', StorageDataCache(), raising=False)
    monkeypatch.setattr(pbs_mod, '_backup_status_cache', {})


# --- reading the exposition ----------------------------------------------------------------

_LABEL = re.compile(r'(\w+)="((?:[^"\\]|\\.)*)"')


def _samples(body, name):
    out = []
    for line in body.splitlines():
        if not line or line.startswith('#'):
            continue
        series, value = line.rsplit(' ', 1)
        if series.split('{', 1)[0] != name:
            continue
        labels = dict(_LABEL.findall(series.split('{', 1)[1])) if '{' in series else {}
        out.append((labels, float(value)))
    return out


def _find(body, metric, /, **match):
    return [(lbl, v) for lbl, v in _samples(body, metric)
            if all(lbl.get(k) == str(want) for k, want in match.items())]


def _one(body, metric, /, **match):
    hits = _find(body, metric, **match)
    assert len(hits) == 1, f'{metric} {match}: {len(hits)} samples in\n' + \
        '\n'.join(line for line in body.splitlines() if line.startswith(metric))
    return hits[0][1]


def _scrape(api):
    r = api.anon().get('/api/metrics')
    assert r.status_code == 200, r.get_data(as_text=True)[:300]
    return r.get_data(as_text=True)


# --- storage -------------------------------------------------------------------------------

def test_storage_used_and_total_per_storage_and_cluster(api):
    api.set_manager('c1', _Pve('Testi', GUESTS, STORAGE_ROWS))
    api.set_manager('x1', _Xen('Xen', [
        {'storage': 'Local storage', 'type': 'ext', 'total': 100 * GiB, 'used': 60 * GiB,
         'status': 'available', 'shared': False, 'uuid': 'sr-a'},
        {'storage': 'Local storage', 'type': 'ext', 'total': 200 * GiB, 'used': 10 * GiB,
         'status': 'available', 'shared': False, 'uuid': 'sr-b'},
        {'storage': 'NFS SR', 'type': 'nfs', 'total': 400 * GiB, 'used': 100 * GiB,
         'status': 'available', 'shared': True, 'uuid': 'sr-c'}], []))
    body = _scrape(api)

    local = dict(cluster_id='c1', cluster='Testi', node='pve1', storage='local-lvm', type='lvmthin', shared='0')
    assert _one(body, 'pegaprox_storage_used_bytes', **local) == 90 * GiB
    assert _one(body, 'pegaprox_storage_total_bytes', **local) == 100 * GiB
    assert _one(body, 'pegaprox_storage_active', **local) == 1

    # shared storage once for the cluster, not once per node, and where it is not mounted
    nfs = dict(cluster_id='c1', storage='nfs-vm')
    assert len(_find(body, 'pegaprox_storage_total_bytes', **nfs)) == 1
    assert _one(body, 'pegaprox_storage_used_bytes', **nfs) == 300 * GiB
    assert _one(body, 'pegaprox_storage_active', **nfs) == 1
    assert _one(body, 'pegaprox_storage_inactive_nodes', **nfs) == 1
    assert _find(body, 'pegaprox_storage_active', **nfs)[0][0].get('node', '') == ''

    # pvestatd's last figures of a storage that is down are not current
    down = dict(cluster_id='c1', node='pve3', storage='local-lvm')
    assert _one(body, 'pegaprox_storage_active', **down) == 0
    assert _find(body, 'pegaprox_storage_used_bytes', **down) == []
    assert _find(body, 'pegaprox_storage_total_bytes', **down) == []

    # every XCP-ng host calls its local SR the same: the uuid keeps them apart
    assert _one(body, 'pegaprox_storage_used_bytes', cluster_id='x1', sr_uuid='sr-a') == 60 * GiB
    assert _one(body, 'pegaprox_storage_used_bytes', cluster_id='x1', sr_uuid='sr-b') == 10 * GiB
    assert _one(body, 'pegaprox_storage_total_bytes', cluster_id='x1', storage='NFS SR', shared='1') == 400 * GiB

    assert _one(body, 'pegaprox_cluster_source_up', cluster_id='c1', source='storage') == 1
    assert _one(body, 'pegaprox_cluster_source_up', cluster_id='x1', source='storage') == 1


def test_a_storage_list_that_cannot_be_read_says_so(api):
    api.set_manager('c1', _Pve('Testi', GUESTS, STORAGE_ROWS, code=500))
    body = _scrape(api)
    assert _one(body, 'pegaprox_cluster_source_up', cluster_id='c1', source='storage') == 0
    assert _find(body, 'pegaprox_storage_active', cluster_id='c1') == []


# --- replication ---------------------------------------------------------------------------

def _jobs(*jobs):
    return [dict({'type': 'local', 'schedule': '*/15'}, **j) for j in jobs]


def test_replication_last_sync_and_failure_per_job(api):
    c1 = api.set_manager('c1', _Pve('Testi', GUESTS))
    c1.answer('/cluster/replication', _jobs(
        {'id': '101-0', 'guest': 101, 'source': 'pve1', 'target': 'pve2'},
        {'id': '102-0', 'guest': 102, 'source': 'pve1', 'target': 'pve2'},
        {'id': '103-0', 'guest': 103, 'source': 'pve2', 'target': 'pve1', 'disable': 1},
        {'id': '104-0', 'guest': 104, 'source': 'pve3', 'target': 'pve1'}))
    c1.answer('/nodes/pve1/replication', [
        {'id': '101-0', 'fail_count': 3, 'error': 'no space left', 'last_sync': int(NOW) - 7200},
        {'id': '102-0', 'fail_count': 0, 'last_sync': int(NOW) - 3600}])
    c1.answer('/nodes/pve2/replication', [{'id': '103-0', 'fail_count': 0, 'last_sync': 0}])
    c1.answer('/nodes/pve3/replication', None, code=595)
    body = _scrape(api)

    failing = dict(cluster_id='c1', job='101-0', vmid='101', node='pve1', target='pve2')
    assert _one(body, 'pegaprox_replication_failed', **failing) == 1
    assert _one(body, 'pegaprox_replication_fail_count', **failing) == 3
    assert _one(body, 'pegaprox_replication_last_sync_timestamp_seconds', **failing) == int(NOW) - 7200

    fine = dict(cluster_id='c1', job='102-0')
    assert _one(body, 'pegaprox_replication_failed', **fine) == 0
    assert _one(body, 'pegaprox_replication_enabled', **fine) == 1
    assert 3600 <= _one(body, 'pegaprox_replication_last_sync_age_seconds', **fine) < 3700

    # a disabled job has nothing to alert on
    assert _one(body, 'pegaprox_replication_enabled', job='103-0') == 0
    assert _find(body, 'pegaprox_replication_failed', job='103-0') == []
    # the source node of 104-0 did not answer: unknown, not fine
    assert _one(body, 'pegaprox_replication_enabled', job='104-0') == 1
    assert _find(body, 'pegaprox_replication_failed', job='104-0') == []
    assert _find(body, 'pegaprox_replication_last_sync_timestamp_seconds', job='104-0') == []
    assert _one(body, 'pegaprox_cluster_source_up', cluster_id='c1', source='replication') == 0

    c1.answer('/nodes/pve3/replication', [{'id': '104-0', 'fail_count': 0, 'last_sync': 0}])
    mx._repl_reads.clear()
    body = _scrape(api)
    # never synced: the timestamp says 0 and there is no age to give
    assert _one(body, 'pegaprox_replication_last_sync_timestamp_seconds', job='104-0') == 0
    assert _find(body, 'pegaprox_replication_last_sync_age_seconds', job='104-0') == []
    assert _one(body, 'pegaprox_cluster_source_up', cluster_id='c1', source='replication') == 1


# --- backup age ----------------------------------------------------------------------------

def _backup_estate(api, pbs_connected=True):
    from pegaprox.globals import pbs_managers
    c1 = api.set_manager('c1', _Pve('Testi', GUESTS))
    c1.answer('/nodes', [{'node': 'pve1', 'status': 'online'}])
    c1.answer('/nodes/pve1/storage', [
        {'storage': 'local', 'type': 'dir', 'content': 'iso,backup'},
        {'storage': 'pbs-ds1', 'type': 'pbs', 'content': 'backup'},
        {'storage': 'local-lvm', 'type': 'lvmthin', 'content': 'images'}])
    c1.answer('/nodes/pve1/storage/local/content?content=backup', [
        {'volid': 'local:backup/vzdump-qemu-103-x.vma.zst', 'vmid': 103, 'ctime': int(NOW) - 86400 * 3},
        # a guest that is gone: no series for it
        {'volid': 'local:backup/vzdump-qemu-555-x.vma.zst', 'vmid': 555, 'ctime': int(NOW) - 60}])
    pbs = _Pbs(['c1'], [
        {'backup-type': 'vm', 'backup-id': '101', 'backup-time': int(NOW) - 86400 * 2},
        {'backup-type': 'vm', 'backup-id': '101', 'backup-time': int(NOW) - 7200},
        {'backup-type': 'ct', 'backup-id': '102', 'backup-time': int(NOW) - 600},
        {'backup-type': 'vm', 'backup-id': '900', 'backup-time': int(NOW) - 600}], connected=pbs_connected)
    pbs_managers['pbs1'] = pbs
    return c1, pbs


def test_backup_age_per_guest_from_the_snapshot_lists_and_vzdump_files(api):
    c1, pbs = _backup_estate(api)
    body = _scrape(api)

    web = dict(cluster_id='c1', vmid='101', name='web01', type='vm', node='pve1')
    assert _one(body, 'pegaprox_guest_last_backup_timestamp_seconds', **web) == int(NOW) - 7200
    assert 7200 <= _one(body, 'pegaprox_guest_last_backup_age_seconds', **web) < 7300
    assert _one(body, 'pegaprox_guest_last_backup_timestamp_seconds', vmid='102', type='lxc') == int(NOW) - 600
    assert _one(body, 'pegaprox_guest_last_backup_timestamp_seconds', vmid='103') == int(NOW) - 86400 * 3
    # no backup anywhere: 0, and no age to give
    assert _one(body, 'pegaprox_guest_last_backup_timestamp_seconds', vmid='104') == 0
    assert _find(body, 'pegaprox_guest_last_backup_age_seconds', vmid='104') == []
    # templates and guests that are gone get no series
    assert _find(body, 'pegaprox_guest_last_backup_timestamp_seconds', vmid='900') == []
    assert _find(body, 'pegaprox_guest_last_backup_timestamp_seconds', vmid='555') == []
    assert _one(body, 'pegaprox_cluster_source_up', cluster_id='c1', source='backups') == 1

    # per datastore and per storage, never per guest
    assert pbs.reads == ['ds1']
    assert not any(re.search(r'/(qemu|lxc)/\d+', p) for p in c1.calls), c1.calls
    assert c1.count('/nodes/pve1/storage/local/content?content=backup') == 1
    assert c1.count('/nodes/pve1/storage/pbs-ds1/content?content=backup') == 0


def test_the_vm_list_and_the_exporter_share_one_scan(api, seed):
    """The pill the VM list shows and the series come from the same cached scan."""
    c1, pbs = _backup_estate(api)
    _scrape(api)
    root = api.as_user(seed.user('root', role='admin'))
    r = root.get('/api/clusters/c1/vms-backup-status')
    assert r.status_code == 200, r.get_data(as_text=True)
    rows = {row['vmid']: row for row in r.get_json()}
    assert rows[101]['last_backup_ts'] == int(NOW) - 7200
    assert rows[101]['status'] == 'ok'
    assert pbs.reads == ['ds1'] and c1.count('/nodes') == 1

    # and the other way round: a scan the VM list made serves the scrape
    pbs_mod._backup_status_cache.clear()
    assert root.get('/api/clusters/c1/vms-backup-status').status_code == 200
    _scrape(api)
    assert pbs.reads == ['ds1', 'ds1'] and c1.count('/nodes') == 2


def test_a_partial_backup_scan_is_not_handed_out(api, monkeypatch):
    """A scan that ran out of time may lack a guest's newest backup and make it look older
    than it is. The series stay away and source_up says why."""
    api.set_manager('c1', _Pve('Testi', GUESTS))
    pbs_mod._backup_status_cache['c1'] = (
        time.time(), [{'vmid': 101, 'last_backup_ts': int(NOW) - 86400 * 30}],
        pbs_mod._BACKUP_STATUS_TTL_PARTIAL)
    monkeypatch.setattr(mx, '_spawn', lambda fn: None)
    body = _scrape(api)
    assert _find(body, 'pegaprox_guest_last_backup_timestamp_seconds', cluster_id='c1') == []
    assert _one(body, 'pegaprox_cluster_source_up', cluster_id='c1', source='backups') == 0


# --- pace ----------------------------------------------------------------------------------

def test_the_slow_reads_never_hold_up_a_scrape(api, monkeypatch):
    """Replication, backup, clock and node pressure reads start in the background: the
    scrape that starts them does not wait, one read per cluster and source runs at a time,
    and the next scrape hands out what it found."""
    c1, pbs = _backup_estate(api)
    c1.answer('/cluster/replication', _jobs({'id': '101-0', 'guest': 101, 'source': 'pve1', 'target': 'pve2'}))
    c1.answer('/nodes/pve1/replication', [{'id': '101-0', 'fail_count': 0, 'last_sync': int(NOW) - 60}])
    started = []
    monkeypatch.setattr(mx, '_spawn', started.append)

    body = _scrape(api)
    assert len(started) == 4 and c1.calls.count('/cluster/replication') == 0 and pbs.reads == []
    assert not any(p.startswith('/nodes/pve1/time') or '/rrddata' in p for p in c1.calls)
    assert _find(body, 'pegaprox_replication_failed') == []
    assert _one(body, 'pegaprox_cluster_source_up', source='replication') == 0
    assert _one(body, 'pegaprox_cluster_source_up', source='backups') == 0
    assert _one(body, 'pegaprox_cluster_source_up', source='clock') == 0

    _scrape(api)
    assert len(started) == 4, 'a second read started while the first still runs'

    for fn in started:
        fn()
    body = _scrape(api)
    assert len(started) == 4, 'read again although the last read is fresh'
    assert _one(body, 'pegaprox_replication_failed', job='101-0') == 0
    assert _one(body, 'pegaprox_guest_last_backup_timestamp_seconds', vmid='101') == int(NOW) - 7200
    assert _one(body, 'pegaprox_cluster_source_up', source='replication') == 1
    assert _one(body, 'pegaprox_cluster_source_up', source='backups') == 1


def test_reads_are_shared_across_scrapes(api):
    """Prometheus comes back every 15 seconds: storage is read once per 30 seconds,
    replication once a minute, the backup scan once in ten."""
    c1, pbs = _backup_estate(api)
    c1.answer('/cluster/resources?type=storage', [_stor('pve1', 'local-lvm', 1, 2)])
    for _ in range(3):
        _scrape(api)
    assert c1.count(STORAGE) == 1
    assert c1.count('/cluster/replication') == 1
    assert pbs.reads == ['ds1'] and c1.count('/nodes') == 1


# --- guest disk and network counters -------------------------------------------------------

def test_guest_disk_counters_next_to_the_network_ones(api):
    api.set_manager('c1', _Pve('Testi', GUESTS))
    api.set_manager('x1', _Xen('Xen', [], [
        {'vmid': 301, 'type': 'qemu', 'node': 'xcp1', 'name': 'xen-vm', 'status': 'running',
         'netin': 0, 'netout': 0}]))
    body = _scrape(api)
    web = dict(cluster_id='c1', vmid='101', name='web01', type='vm', node='pve1')
    assert _one(body, 'pegaprox_guest_disk_read_bytes_total', **web) == 7000
    assert _one(body, 'pegaprox_guest_disk_write_bytes_total', **web) == 8000
    assert _one(body, 'pegaprox_guest_network_receive_bytes_total', **web) == 500
    assert _one(body, 'pegaprox_guest_network_transmit_bytes_total', **web) == 600
    assert _one(body, 'pegaprox_guest_disk_read_bytes_total', vmid='102', type='lxc') == 30
    assert '# TYPE pegaprox_guest_disk_read_bytes_total counter' in body
    # a cluster type that does not count them gets no series, not a zero
    assert _find(body, 'pegaprox_guest_disk_read_bytes_total', cluster_id='x1') == []


# --- the exposition ------------------------------------------------------------------------

def test_each_new_metric_is_one_group_without_duplicate_series(api):
    """Prometheus drops a duplicate series and the exposition format wants each metric in
    one group, HELP and TYPE first - with two clusters the new families must not be
    written cluster by cluster."""
    _backup_estate(api)
    c2 = api.set_manager('c2', _Pve('Branch', GUESTS, STORAGE_ROWS))
    c2.answer('/cluster/replication', _jobs({'id': '101-0', 'guest': 101, 'source': 'pve1', 'target': 'pve2'}))
    c2.answer('/nodes/pve1/replication', [{'id': '101-0', 'fail_count': 0, 'last_sync': int(NOW) - 60}])
    lines = _scrape(api).splitlines()
    samples = [line.rsplit(' ', 1)[0] for line in lines if line and not line.startswith('#')]
    assert len(samples) == len(set(samples)), 'duplicate series'

    for name, mtype, _help in mx._ESTATE_FAMILIES:
        idx = [i for i, line in enumerate(lines)
               if line.split('{', 1)[0].split(' ', 1)[0] == name]
        assert idx, f'{name} has no samples'
        assert idx == list(range(idx[0], idx[0] + len(idx))), f'{name} is split into several groups'
        assert lines[idx[0] - 1] == f'# TYPE {name} {mtype}'
        assert lines[idx[0] - 2].startswith(f'# HELP {name} ')
        assert sum(1 for line in lines if line.startswith(f'# TYPE {name} ')) == 1
    assert not any('\u2014' in line for line in lines)


def test_the_gate_is_unchanged(api, monkeypatch):
    """Cross-tenant by design, as before: only an admin token, metrics.view or
    metrics_public reach it, and a refused scrape carries none of the new series."""
    _backup_estate(api)
    monkeypatch.undo()
    r = api.anon().get('/api/metrics')
    assert r.status_code == 401
    assert 'pegaprox_storage' not in r.get_data(as_text=True)
