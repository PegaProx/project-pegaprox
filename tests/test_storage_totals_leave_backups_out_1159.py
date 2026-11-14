"""The storage figure of a cluster is the room for VM and CT disks (#1159).

A PBS datastore or a share that only takes backups, ISOs and templates was added to the
storage total of a cluster like any other storage: an 80 TB PBS next to 4 TB of guest storage
showed up as 84 TB. Only a storage whose content names images or rootdir counts now. Two
places add storage up: GET /api/clusters/<id>/datacenter/status (the All Clusters overview,
the cluster group view, the Datacenter summary and the Cloud dashboard read it), which also
counted a shared storage once per node, and the Cluster Storage card of the Corporate cluster
overview, which adds up the /datastores answer in the browser. Lists of storages and the
per-storage Prometheus series keep every storage.
The runtime test drives the built bundle in headless Chromium against the fake server of
tests/test_ha_ui.py and skips where Playwright is not installed.
"""
import os
import re
import types

import pytest

from pegaprox.api.helpers import guest_storage_totals, holds_guest_disks

from test_ha_ui import CLUSTER, SSE_TOKEN, VM, _App, _FakeServer, browser  # noqa: F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GiB = 1024 ** 3
CID = 'c1'


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


# --- the rule ----------------------------------------------------------------------------------

@pytest.mark.parametrize('content,counts', [
    ('images,rootdir', True),
    ('rootdir', True),
    ('backup,images,iso,vztmpl', True),      # the 'local' dir of a default install
    (['images'], True),
    ('backup', False),                       # what a PBS datastore always says
    ('backup,iso,vztmpl,snippets,import', False),
    ('iso', False),
    ('none', False),                         # the iSCSI target under a shared LVM
    ('', False),
    (None, False),
])
def test_only_a_storage_for_guest_disks_counts(content, counts):
    assert holds_guest_disks({'storage': 's', 'content': content}) is counts


def test_the_totals_add_up_the_guest_storages_only():
    rows = [{'storage': 'ceph-vm', 'content': 'images,rootdir', 'used': 3, 'total': 10},
            {'storage': 'pbs', 'content': 'backup', 'used': 20, 'total': 80},
            {'storage': 'local', 'content': 'iso,vztmpl', 'used': 1, 'total': 1},
            {'storage': 'odd', 'used': 5, 'total': 5}]
    assert guest_storage_totals(rows) == (3, 10)


# --- GET /api/clusters/<id>/datacenter/status ------------------------------------------------

def _stor(node, storage, used, total, plugintype, content, shared=0, status='available'):
    return {'id': f'storage/{node}/{storage}', 'type': 'storage', 'node': node, 'storage': storage,
            'status': status, 'plugintype': plugintype, 'shared': shared, 'content': content,
            'disk': used * GiB, 'maxdisk': total * GiB}


def _node(name, online=True):
    return {'id': f'node/{name}', 'type': 'node', 'node': name, 'status': 'online' if online else 'offline',
            'maxcpu': 8, 'cpu': 0.1, 'maxmem': 64 * GiB, 'mem': 16 * GiB}


# pve3 is down: pvestatd keeps its last figures and says unknown
RESOURCES = [_node('pve1'), _node('pve2'), _node('pve3', online=False)]
for _n in ('pve1', 'pve2', 'pve3'):
    _st = 'available' if _n != 'pve3' else 'unknown'
    RESOURCES += [
        _stor(_n, 'ceph-vm', 300, 1000, 'rbd', 'images,rootdir', shared=1, status=_st),
        _stor(_n, 'san-lvm', 100, 500, 'lvm', 'images,rootdir', shared=1, status=_st),
        _stor(_n, 'pbs-backup', 2000, 8000, 'pbs', 'backup', shared=1, status=_st),
        _stor(_n, 'nfs-backup', 1000, 4000, 'nfs', 'backup,iso,vztmpl', shared=1, status=_st),
    ]
RESOURCES += [
    _stor('pve1', 'local-lvm', 50, 200, 'lvmthin', 'images,rootdir'),
    _stor('pve1', 'local', 10, 100, 'dir', 'backup,import,iso,vztmpl'),
    _stor('pve2', 'local-lvm', 70, 200, 'lvmthin', 'images,rootdir'),
    _stor('pve2', 'local', 20, 100, 'dir', 'backup,images,iso,vztmpl'),
    _stor('pve3', 'local-lvm', 99, 200, 'lvmthin', 'images,rootdir', status='unknown'),
    _stor('pve3', 'local', 99, 100, 'dir', 'backup,images,iso,vztmpl', status='unknown'),
]
STATUS = [{'type': 'cluster', 'name': 'Testi', 'quorate': 1, 'version': 3},
          {'type': 'node', 'name': 'pve1', 'online': 1}, {'type': 'node', 'name': 'pve2', 'online': 1},
          {'type': 'node', 'name': 'pve3', 'online': 0}]
# ceph-vm and san-lvm once, local-lvm of pve1 and pve2, the local dir of pve2 (it takes images)
GUEST_USED, GUEST_TOTAL = (300 + 100 + 50 + 70 + 20) * GiB, (1000 + 500 + 200 + 200 + 100) * GiB


class _Resp:
    def __init__(self, data):
        self.status_code, self._data = 200, data

    def json(self):
        return {'data': self._data}


class _Session:
    def __init__(self, paths):
        self.paths = paths

    def get(self, url, timeout=None, **kw):
        return _Resp(self.paths[url.split('/api2/json', 1)[1]])


class _Pve:
    host, api_port, cluster_type = 'pve.example', 8006, 'proxmox'
    is_connected = True

    def __init__(self, resources):
        self.config = types.SimpleNamespace(name='Testi')
        self.paths = {'/cluster/status': STATUS, '/cluster/resources': resources}

    def _create_session(self):
        return _Session(self.paths)

    def _mark_host_failure(self, host):
        raise AssertionError('both reads answered')


class _Xen:
    cluster_type = 'xcpng'
    is_connected = True

    def __init__(self, srs):
        self.config = types.SimpleNamespace(name='Pool')
        self.srs = srs

    def get_cluster_status(self):
        return {'total_cpu': 8, 'total_mem': 64 * GiB, 'used_mem': 16 * GiB}

    def get_nodes(self):
        return [{'node': 'xcp1', 'status': 'online'}]

    def get_vms(self):
        return []

    def get_storages(self, node=None):
        return [dict(s) for s in self.srs]


def _status(api, seed, manager):
    api.set_manager(CID, manager)
    r = api.as_user(seed.user('root', role='admin')).get(f'/api/clusters/{CID}/datacenter/status')
    assert r.status_code == 200, r.get_json()
    return r.get_json()['resources']['storage']


def test_the_cluster_total_leaves_backup_storage_out_and_counts_shared_storage_once(api, seed):
    storage = _status(api, seed, _Pve(RESOURCES))
    assert storage == {'used': GUEST_USED, 'total': GUEST_TOTAL, 'percent': 27.0}


def test_a_cluster_with_backup_storage_only_has_no_room_for_guests(api, seed):
    rows = [r for r in RESOURCES if r['type'] == 'node' or r.get('content', '').startswith('backup,import')
            or r.get('plugintype') in ('pbs', 'nfs')]
    storage = _status(api, seed, _Pve(rows))
    assert storage == {'used': 0, 'total': 0, 'percent': 0}


def test_an_xcpng_pool_still_counts_its_storage_repositories(api, seed):
    srs = [{'storage': 'Local storage', 'type': 'ext', 'total': 100 * GiB, 'used': 60 * GiB,
            'status': 'available', 'shared': False, 'content': 'images'},
           {'storage': 'NFS SR', 'type': 'nfs', 'total': 400 * GiB, 'used': 100 * GiB,
            'status': 'available', 'shared': True, 'content': 'images'}]
    storage = _status(api, seed, _Xen(srs))
    assert storage == {'used': 160 * GiB, 'total': 500 * GiB, 'percent': 32.0}


# --- the source and the bundle ---------------------------------------------------------------

def test_one_rule_in_the_frontend_and_the_corporate_card_uses_it():
    consts = _read('web', 'src', 'constants.js')
    assert 'function holdsGuestDisks(ds) {' in consts
    assert 'function guestStorageTotals(datastores) {' in consts
    dash = _read('web', 'src', 'dashboard.js')
    card = dash[dash.index("<div className=\"corp-overview-label\">{t('clusterStorage')}</div>") - 6000:
                dash.index("<div className=\"corp-overview-label\">{t('clusterStorage')}</div>")]
    assert 'const guestDs = guestStorageTotals(clusterDatastores);' in card
    # no second sum of the datastores beside it
    assert not re.search(r'allDs\.reduce\(', card)
    bundle = _read('web', 'index.html')
    for needle in ('function holdsGuestDisks(', 'function guestStorageTotals(', 'guestStorageTotals(clusterDatastores)'):
        assert needle in bundle, needle


def test_no_em_dash_in_the_new_code():
    consts = _read('web', 'src', 'constants.js')
    start = consts.index('// LW Oct 2026 (#1159)')
    block = consts[start:consts.index('// ====', start)]
    helpers = _read('pegaprox', 'api', 'helpers.py')
    start = helpers.index('# MK Oct 2026 (#1159)')
    block += helpers[start:helpers.index('def node_shell_address(', start)]
    assert '\u2014' not in block and '\u2013' not in block


# --- runtime: the Cluster Storage card of the Corporate cluster overview ------------------------

def _ds(storage, used, total, stype, content, shared, node=None):
    d = {'storage': storage, 'type': stype, 'content': content, 'shared': shared, 'active': 1, 'enabled': 1,
         'used': used * GiB, 'total': total * GiB, 'avail': (total - used) * GiB, 'used_fraction': used / total,
         'path': '', 'nodes': ''}
    if shared:
        d.update(active_on=['pve1', 'pve2'], inactive_on=[])
    return d


# what GET /api/clusters/<id>/datastores answers: a shared storage once, local ones per node
DATASTORES = {
    'shared': [
        _ds('ceph-vm', 300, 1000, 'rbd', 'images,rootdir', True),
        _ds('san-lvm', 100, 500, 'lvm', 'images,rootdir', True),
        _ds('pbs-backup', 2000, 8000, 'pbs', 'backup', True),
        _ds('nfs-backup', 1000, 4000, 'nfs', 'backup,iso,vztmpl', True),
    ],
    'local': {
        'pve1': [_ds('local-lvm', 50, 200, 'lvmthin', 'images,rootdir', False),
                 _ds('local', 10, 100, 'dir', 'vztmpl,import,backup,iso', False)],
        'pve2': [_ds('local-lvm', 70, 200, 'lvmthin', 'rootdir,images', False),
                 _ds('local', 20, 100, 'dir', 'iso,vztmpl,backup,images', False)],
    },
    'nodes': ['pve1', 'pve2'],
    'offline_nodes': [],
}
_M = {'status': 'online', 'cpu_percent': 5.0, 'mem_percent': 20.0, 'disk_percent': 10.0, 'score': 42.0,
      'uptime': 86400, 'loadavg': [0.1, 0.2, 0.3], 'netin': 0, 'netout': 0, 'mem_used': 8 * GiB,
      'mem_total': 32 * GiB, 'disk_used': 10 * GiB, 'disk_total': 100 * GiB, 'pveversion': 'pve-manager/9.0.3',
      'kversion': 'Linux 6.14.8-2-pve', 'cpuinfo': {'cpus': 8, 'cores': 4, 'sockets': 1},
      'maintenance_mode': False, 'is_updating': False}
METRICS = {'pve1': dict(_M), 'pve2': dict(_M)}

CARD_JS = '''() => {
    const card = Array.from(document.querySelectorAll('.corp-overview-card'))
        .find(c => (c.querySelector('.corp-overview-label') || {}).textContent === 'Cluster Storage');
    if (!card) return null;
    return {value: card.querySelector('.corp-overview-value').textContent.trim(),
            sub: card.querySelector('.corp-overview-sub').textContent.trim()};
}'''


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(**kw):
        extra = {('GET', f'/api/clusters/{CID}/datastores'): (200, DATASTORES)}
        extra.update(SSE_TOKEN)
        app = _App(browser, _FakeServer(clusters=[CLUSTER], resources=[VM], metrics=METRICS, extra=extra, **kw))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def test_runtime_the_corporate_card_counts_the_room_for_guests(open_app):
    app = open_app(role='standalone', layout='corporate')
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.wait_for_function(f'() => {{ const c = ({CARD_JS})(); return c && c.sub !== "0 / 0"; }}', timeout=10000)
    # wait for the datastores to replace the node disk fallback
    page.wait_for_function(f'() => ({CARD_JS})().sub.endsWith("2000.0 GB") || ({CARD_JS})().sub.endsWith("14100.0 GB")',
                           timeout=10000)
    card = page.evaluate(CARD_JS)
    # ceph-vm 1000 + san-lvm 500 + local-lvm 2x 200 + the local dir of pve2, which takes images;
    # not the PBS datastore, the NFS backup share or the local dir of pve1
    assert card == {'value': '27.0%', 'sub': '540.0 GB / 2000.0 GB'}, card
    assert ('GET', f'/api/clusters/{CID}/datastores') in app.server.calls
    assert not app.errors, app.errors
