"""What an account confined to some guests sees of Ceph and of the clone's storage (#1218).

The server refuses such an account the cluster's Ceph and its datastores. The node dialog
and Datacenter > Ceph read the refusal as "Ceph Not Installed" and offered to initialize
Ceph, and the clone dialog lost its storage picker, which came from the datastores alone.
Now the Ceph views say that the account has no access, and the clone dialog lists the
storages of the target node, which the server answers for a node of the caller's guests.

The built bundle runs in headless Chromium against the fake server of tests/test_ha_ui.py,
with the reads of this change answered by the REAL routes as the account shown: a VM-ACL
user of the owning tenant (VM 100 on pve1, 101 on pve3) and the admin. Skips where
Playwright is not installed. Run without -n.
LW Nov 2026
"""
import json
import os
import re
import time
from unittest.mock import MagicMock

import pytest

from test_ha_ui import _FakeServer, _App, browser, CLUSTER, VM_CONFIG, NODE_METRICS  # noqa: F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CID = 'c1'
VM100 = {'vmid': 100, 'name': 'web01', 'type': 'qemu', 'status': 'running', 'node': 'pve1',
         'cpu': 0.05, 'cpu_percent': 5, 'maxcpu': 2, 'mem': 1073741824, 'maxmem': 4294967296,
         'mem_percent': 25, 'disk': 0, 'maxdisk': 34359738368, 'uptime': 3600}
VM101 = dict(VM100, vmid=101, name='db01', node='pve3')
VM200 = dict(VM100, vmid=200, name='other-app', node='pve2')
NODES = ('pve1', 'pve2', 'pve3')
# the reads the real routes answer, everything else the fake server
REAL = re.compile(r'^/api/clusters/c1/(metrics|nodes|nodes-status|node-progress|datastores|datacenter/storage|'
                  r'datacenter/ceph|nodes/[^/]+/storage|nodes/[^/]+/ceph/[a-z]+)$')
DATASTORES = {'shared': [{'storage': 'nfs-shared', 'type': 'nfs', 'content': 'images,rootdir',
                          'avail': 10 * 2**30, 'total': 20 * 2**30, 'used': 10 * 2**30, 'shared': 1}],
              'local': {n: [{'storage': 'local-lvm', 'type': 'lvmthin', 'content': 'images,rootdir',
                             'avail': 50 * 2**30, 'total': 100 * 2**30, 'used': 50 * 2**30}] for n in NODES},
              'nodes': list(NODES)}
NODE_STORAGE = [{'storage': 'local-lvm', 'type': 'lvmthin', 'content': 'images,rootdir', 'avail': 50 * 2**30,
                 'total': 100 * 2**30, 'active': 1, 'enabled': 1},
                {'storage': 'local', 'type': 'dir', 'content': 'iso,vztmpl', 'avail': 9 * 2**30,
                 'total': 20 * 2**30, 'active': 1, 'enabled': 1}]
KINDS = {'confined': ('portal', 'portal', 'user'), 'admin': ('root', 'admin', 'admin')}
NOT_INSTALLED = ('Ceph Not Installed', 'Initialize Ceph', 'Ceph not configured on this node')
NO_ACCESS = 'No access to Ceph'


def _resp(status, data):
    r = MagicMock()
    r.status_code = status
    r.json.return_value = {'data': data}
    r.text = ''
    return r


def _pve_get(url, *a, **kw):
    if url.endswith('/ceph/status'):
        return _resp(200, {'health': {'status': 'HEALTH_OK', 'checks': {}}, 'fsid': 'fsid-secret',
                           'pgmap': {'bytes_used': 1, 'bytes_total': 2, 'num_pgs': 32},
                           'osdmap': {'num_osds': 3, 'num_up_osds': 3, 'num_in_osds': 3}})
    if url.endswith('/ceph/pool'):
        return _resp(200, [{'pool_name': 'rbd-secret', 'size': 3, 'min_size': 2, 'pg_num': 32}])
    if url.endswith('/api2/json/nodes'):
        return _resp(200, [{'node': n, 'status': 'online', 'cpu': 0.05, 'mem': 1, 'maxmem': 4} for n in NODES])
    return _resp(200, [])


class _RealReads(_FakeServer):
    def __init__(self, client, ui_user, ui_role, **kw):
        super().__init__(admin=(ui_role == 'admin'), **kw)
        self.client = client
        self.real = []
        from pegaprox.models.permissions import ROLE_PERMISSIONS, ROLE_USER, ROLE_ADMIN
        perms = list(ROLE_PERMISSIONS[ROLE_ADMIN if ui_role == 'admin' else ROLE_USER])
        user = {'username': ui_user, 'role': ui_role, 'display_name': ui_user,
                'ui_layout': kw.get('layout', 'modern'), 'layout_chosen': True, 'theme': '',
                'language': 'en', 'permissions': perms, 'enabled': True, 'auth_source': 'local'}
        self.extra[('GET', '/api/auth/check')] = (200, {'authenticated': True, 'session_id': 'sid', 'user': user,
                                                        'ha': {'role': 'standalone'}, 'default_theme': 'proxmoxDark'})
        self.extra[('GET', '/api/clusters/c1/vms/pve1/qemu/100/config')] = (200, VM_CONFIG)

    def handle(self, route):
        req = route.request
        url = re.sub(r'^https?://[^/]+', '', req.url)
        path = url.split('?')[0]
        if REAL.match(path):
            fn = getattr(self.client, req.method.lower())
            try:
                kw = {'json': json.loads(req.post_data)} if req.post_data else {}
                r = fn(url, **kw)
                status, body = r.status_code, r.get_data()
            except Exception as e:
                status, body = 500, json.dumps({'error': f'test harness: {e}'}).encode()
            self.real.append((req.method, path, status))
            return route.fulfill(status=status, body=body, headers={'Content-Type': 'application/json'})
        return super().handle(route)


@pytest.fixture
def world(api, seed):
    import pegaprox.api.vms as vmsmod
    seed.tenant('acme', clusters=[CID])
    for vmid in (100, 101):
        seed.vm_acl(CID, vmid, users=['portal'])
    seed.vm_acl(CID, 200, users=['someone_else'])
    m = api.make_fake_manager(CID)
    m.is_connected = True
    m.host, m.api_port = '192.0.2.10', 8006
    m.config.host, m.config.name = 'pve1.example', 'Testi'
    m.get_node_status.return_value = {n: dict(NODE_METRICS['pve1']) for n in NODES}
    m.get_vm_resources.return_value = [VM100, VM101, VM200]
    m.nodes_in_maintenance, m.nodes_updating, m.ha_node_status = {}, {}, {}
    m._cached_metrics = None
    m._cached_nodes = None
    m._create_session.return_value.get.side_effect = _pve_get
    m.get_storage_list.return_value = NODE_STORAGE
    api.set_manager(CID, m)
    # a datastores answer of a moment ago in the shared cache, fresh for the test
    vmsmod._datastores_cache[CID] = (time.time() + 3600, DATASTORES)
    clients = {'confined': api.as_user(seed.user('portal', role='user', tenant_id='acme')),
               'admin': api.as_user(seed.user('root', role='admin'))}
    try:
        yield clients, m
    finally:
        vmsmod._datastores_cache.pop(CID, None)


@pytest.fixture
def open_app(browser, world):
    apps = []

    def _open(kind, layout='modern'):
        _api_user, ui_user, ui_role = KINDS[kind]
        resources = [VM100, VM101] if kind == 'confined' else [VM100, VM101, VM200]
        app = _App(browser, _RealReads(world[0][kind], ui_user, ui_role, role='standalone', layout=layout,
                                       clusters=[CLUSTER], resources=resources))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _real(app, path):
    return [s for _m, p, s in app.server.real if p == path]


def _says_not_installed(text):
    return [w for w in NOT_INSTALLED if w in text]


def _ceph_settled(page):
    """Wait until the Ceph pane says something: a refusal, no Ceph, or its health."""
    said = re.compile('|'.join(re.escape(w) for w in (NO_ACCESS, 'HEALTH_OK') + NOT_INSTALLED))
    page.get_by_text(said).first.wait_for(timeout=8000)
    page.wait_for_timeout(300)


# --- source ----------------------------------------------------------------------------------

def test_the_two_strings_are_in_every_language_once():
    with open(os.path.join(ROOT, 'web', 'src', 'translations.js'), encoding='utf-8') as fh:
        tr = fh.read()
    for key in ('cephNoAccess', 'cephNoAccessDesc'):
        assert len(re.findall(rf'^\s*{key}:', tr, re.M)) == 9, key


# --- runtime ---------------------------------------------------------------------------------

@pytest.mark.parametrize('kind', sorted(KINDS))
def test_runtime_the_node_dialog_says_a_ceph_refusal(open_app, kind):
    app = open_app(kind)
    page = app.page
    page.get_by_text('Testi').first.click()
    page.locator('button[title="Node Configuration"]').first.wait_for(timeout=8000)
    page.locator('button[title="Node Configuration"]').first.click()
    page.get_by_text('Proxmox Node').first.wait_for(timeout=5000)
    page.locator('button', has_text='Ceph').last.click()
    _ceph_settled(page)
    body = page.locator('body').inner_text()
    status = _real(app, '/api/clusters/c1/nodes/pve1/ceph/status')
    if kind == 'confined':
        assert status and set(status) == {403}, status
        assert not _says_not_installed(body), _says_not_installed(body)
        assert NO_ACCESS in body
        assert 'fsid-secret' not in body and 'rbd-secret' not in body
    else:
        assert set(status) == {200} and NO_ACCESS not in body
    assert not app.errors, app.errors


@pytest.mark.parametrize('kind', sorted(KINDS))
def test_runtime_datacenter_ceph_says_a_refusal(open_app, kind):
    app = open_app(kind)
    page = app.page
    page.get_by_text('Testi').first.click()
    page.locator('button', has_text='Datacenter').first.click()
    page.wait_for_timeout(800)
    page.locator('button', has_text='Ceph').first.click()
    _ceph_settled(page)
    body = page.locator('body').inner_text()
    reads = _real(app, '/api/clusters/c1/datacenter/ceph')
    if kind == 'confined':
        assert reads and set(reads) == {403}, reads
        assert not _says_not_installed(body), _says_not_installed(body)
        assert NO_ACCESS in body
    else:
        assert set(reads) == {200} and NO_ACCESS not in body
    assert not app.errors, app.errors


def test_runtime_the_classic_corporate_node_view_says_a_ceph_refusal(open_app):
    app = open_app('confined', layout='corporate')
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    child = page.locator('.corp-tree-child', has_text='pve1').first
    child.wait_for(timeout=8000)
    child.click()
    strip = page.locator('.corp-tab-strip').last
    strip.get_by_text('Configure').wait_for(timeout=5000)
    strip.get_by_text('Configure').click()
    page.locator('.corp-subnav-item', has_text='Ceph').first.click()
    _ceph_settled(page)
    body = page.locator('body').inner_text()
    assert not _says_not_installed(body), _says_not_installed(body)
    assert NO_ACCESS in body
    assert set(_real(app, '/api/clusters/c1/nodes/pve1/ceph/status')) == {403}
    assert not app.errors, app.errors


def _open_clone(app):
    page = app.page
    page.get_by_text('Testi').first.click()
    page.locator('button', has_text='Resources').first.click()
    page.get_by_text('web01').first.wait_for(timeout=5000)
    page.wait_for_timeout(500)
    page.locator('button[title="More Actions"]').first.click()
    page.wait_for_timeout(300)
    page.locator('button', has_text='Clone').first.click()
    modal = page.locator('div.fixed', has_text='Target Node').last
    modal.wait_for(timeout=5000)
    return modal


def _selects(modal):
    return modal.evaluate('''m => Array.from(m.querySelectorAll('select'))
        .map(s => Array.from(s.options).map(o => o.value))''')


@pytest.mark.parametrize('kind', sorted(KINDS))
def test_runtime_the_clone_dialog_keeps_its_storage_picker(open_app, kind):
    app = open_app(kind)
    page = app.page
    modal = _open_clone(app)
    page.wait_for_timeout(1500)
    # the storage picker: its first option keeps the source storage
    picker = [s for s in _selects(modal) if '' in s]
    assert picker, ('no storage picker', _selects(modal))
    if kind == 'confined':
        assert set(_real(app, '/api/clusters/c1/datastores')) == {403}
        # the target node's own storages for guest disks; an ISO store is no clone target
        assert picker[0] == ['', 'local-lvm'], picker
        assert _real(app, '/api/clusters/c1/nodes/pve1/storage') == [200]
        modal.locator('select').first.select_option('pve3')
        page.wait_for_timeout(800)
        assert _real(app, '/api/clusters/c1/nodes/pve3/storage') == [200]
        assert [s for s in _selects(modal) if '' in s][0] == ['', 'local-lvm']
    else:
        assert set(picker[0]) == {'', 'nfs-shared', 'local-lvm'}, picker
        assert not [p for _m, p, _s in app.server.real if re.fullmatch(r'/api/clusters/c1/nodes/[^/]+/storage', p)]
    assert not app.errors, app.errors
