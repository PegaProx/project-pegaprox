"""Corporate Redesigned, the blueprints above the template library (#1220): the list with what each
blueprint holds (source, hardware, network), the editor and the body it sends, Edit and Delete only
for the blueprints the account may change, the deploy dialog (where to, the template the server would
use or build, the ipconfig0 of a static address) and the progress it reads while it is open.

A blueprint's source is a library image or an existing PVE template picked per cluster in
the deploy dialog (Windows goes this way: no Cloud-Init user, keys, search domain or upgrade, a
password on every deploy). The editor has explicit grids and the defaults of the server, the deploy
dialog checks the bridges of the target node and shows the notes the server answers with. The
recent deploys are listed by the page around the section, which hands it a template to start a
blueprint from (prefillTemplate) and hears of saves and deletes (onSaved, onDeleted). What the section
reads itself is told apart from the page's reads by a wrapped mount (_wrapped) that records them.

Only Corporate Redesigned has the section: classic Corporate, Modern and Cloud draw the library as
before. Runtime tests drive the built bundle in headless Chromium against the guard fake of
tests/test_corp_redesigned_guard_ui.py with the blueprint routes as the server answers them (_BpServer).
The counterproof runs this file against an older bundle: PEGAPROX_CR_BUNDLE=<path to index.html>.
LW Nov 2026
"""
import copy
import json
import os
import re
import time

import pytest

from test_corp_redesigned_guard_ui import DETERMINISTIC, _GuardApp, _GuardServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LAYOUT = 'corporate-redesigned'
_BUNDLE_FILE = os.environ.get('PEGAPROX_CR_BUNDLE')
BUNDLE = open(_BUNDLE_FILE, encoding='utf-8').read() if _BUNDLE_FILE else None
DASHES = (chr(0x2014), chr(0x2013))
TPL_TAB = 'Cloud-Init Template Library'
# the name of that sub tab in Corporate Redesigned
CR_TAB = 'Blueprints & Images'

CATALOG = {'templates': [
    {'id': 'debian-13', 'name': 'Debian 13 (Trixie)', 'distro': 'debian', 'version': '13', 'default_user': 'debian',
     'cores': 1, 'memory': 1024, 'disk_gb': 8},
    {'id': 'almalinux-10', 'name': 'AlmaLinux 10', 'distro': 'almalinux', 'version': '10', 'default_user': 'almalinux',
     'cores': 2, 'memory': 2048, 'disk_gb': 10, 'cpu': 'x86-64-v3'},
    {'id': 'c0ffee12', 'name': 'Company Ubuntu', 'distro': 'ubuntu', 'version': '24.04', 'default_user': 'ops',
     'cores': 2, 'memory': 2048, 'disk_gb': 20, 'custom': True},
]}


def _bp(bid, name, **kw):
    out = {'id': bid, 'name': name, 'description': '', 'source_kind': 'library', 'os': 'linux', 'templates': {},
           'template_id': 'debian-13', 'template_name': 'Debian 13 (Trixie)',
           'template_missing': False, 'cores': 2, 'memory': 2048, 'disk_gb': 20, 'cpu': '',
           'nics': [{'bridge': 'vmbr0', 'vlan': None, 'model': 'virtio', 'firewall': True}],
           'ciuser': 'debian', 'sshkeys': 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOpen admin@lab', 'ip_mode': 'dhcp',
           'nameserver': '', 'searchdomain': '', 'ciupgrade': True, 'tags': ['web'], 'start': True,
           'created_by': 'admin', 'created_at': '2026-11-08T09:00:00', 'updated_at': '2026-11-08T09:00:00', 'can_edit': True}
    out.update(kw)
    return out


WEB = _bp('b1', 'web-small', description='Small web front end')
DB = _bp('b2', 'db-static', template_id='almalinux-10', template_name='AlmaLinux 10', cores=4, memory=8192, disk_gb=0,
         ip_mode='static', start=False, nics=[{'bridge': 'vmbr0', 'vlan': 20, 'model': 'virtio', 'firewall': False},
                                              {'bridge': 'vmbr1', 'vlan': None, 'model': 'e1000', 'firewall': False}])
OTHER = _bp('b3', 'from-colleague', created_by='alice', can_edit=False)
GONE = _bp('b4', 'old-image', template_id='gone1', template_name='', template_missing=True)
# a Windows template blueprint with the template of c1 remembered and the template's own NICs, and
# a Linux one on an SDN VNet with no template remembered yet
WIN = _bp('b5', 'win-desktop', source_kind='template', os='windows', template_id='', template_name='', templates={'c1': 9100},
          nics=[], ciuser='', sshkeys='', searchdomain='', ciupgrade=True, cores=4, memory=8192, disk_gb=80)
GOLD = _bp('b6', 'rocky-golden', source_kind='template', os='linux', template_id='', template_name='', disk_gb=0,
           nics=[{'bridge': 'vnet7', 'vlan': None, 'model': 'virtio', 'firewall': False}])
RECENT = [{'id': 'r1', 'blueprint_id': 'b1', 'blueprint_name': 'web-small', 'cluster_id': 'c1', 'node': 'pve1', 'vmid': 120,
           'name': 'web-01', 'template_vmid': 9001, 'build_dep_id': '', 'status': 'completed', 'step': 'done', 'progress': 100,
           'error': '', 'started_by': 'admin', 'started_at': '2026-11-08T08:40:00.123456', 'finished_at': '2026-11-08T08:42:00'},
          {'id': 'r2', 'blueprint_id': 'b2', 'blueprint_name': 'db-static', 'cluster_id': 'c1', 'node': 'pve2', 'vmid': 121,
           'name': 'db-01', 'template_vmid': None, 'build_dep_id': 'x9', 'status': 'failed', 'step': 'template', 'progress': 20,
           'error': 'download failed (rc=8)', 'started_by': 'admin', 'started_at': '2026-11-08T08:50:00', 'finished_at': '2026-11-08T08:51:00'}]
NODES = [{'node': 'pve1', 'status': 'online'}, {'node': 'pve2', 'status': 'online'}, {'node': 'pve3', 'status': 'offline'}]
STORES = {'pve1': [{'storage': 'local-lvm', 'content': 'images,rootdir', 'enabled': 1, 'active': 1},
                   {'storage': 'local', 'content': 'iso,vztmpl,backup', 'enabled': 1, 'active': 1},
                   {'storage': 'ceph', 'content': 'images', 'enabled': 1, 'active': 1}],
          'pve2': [{'storage': 'local-zfs', 'content': 'images,rootdir', 'enabled': 1, 'active': 1}]}
NET = [{'iface': 'vmbr0', 'type': 'bridge'}, {'iface': 'vmbr1', 'type': 'OVSBridge'}, {'iface': 'eno1', 'type': 'eth'}]
# pve2 has no vmbr1
NET2 = [{'iface': 'vmbr0', 'type': 'bridge'}, {'iface': 'eno1', 'type': 'eth'}]
VNETS = [{'vnet': 'vnet7', 'zone': 'evpn1', 'type': 'vnet'}]
# the template the server would use per node: pve1 has one, pve2 builds it first
TEMPLATE = {'pve1': {'template': {'vmid': 9001, 'node': 'pve1', 'storage': 'local-lvm', 'shared': False}, 'build_needed': False},
            'pve2': {'template': None, 'build_needed': True}}
# the PVE templates of c1 the probe route lists for a template source, filtered by the blueprint's os
PVE_TEMPLATES = [
    {'vmid': 9100, 'name': 'win2022-golden', 'node': 'pve1', 'ostype': 'win11', 'windows': True, 'cloudinit': True,
     'boot_disk': 'scsi0', 'disk_storages': ['local-lvm'], 'shared': False},
    {'vmid': 9101, 'name': 'win11-plain', 'node': 'pve1', 'ostype': 'win11', 'windows': True, 'cloudinit': False,
     'boot_disk': 'sata0', 'disk_storages': ['local-lvm'], 'shared': False},
    {'vmid': 9102, 'name': 'win2019', 'node': 'pve2', 'ostype': 'win10', 'windows': True, 'cloudinit': True,
     'boot_disk': 'scsi0', 'disk_storages': ['local-zfs'], 'shared': False},
    {'vmid': 9200, 'name': 'rocky-9-golden', 'node': 'pve1', 'ostype': 'l26', 'windows': False, 'cloudinit': True,
     'boot_disk': 'virtio0', 'disk_storages': ['ceph'], 'shared': True},
]


class _BpServer(_GuardServer):
    """The guard fake with the blueprint routes, the library catalog and the node reads the
    dialogs make. progress: the rows a deployment read hands out in turn. refuse: (status, body)
    a deploy answers with instead of 202; warnings: the notes of a 202."""

    def __init__(self, blueprints=None, progress=None, deploy_status=202, refuse=None, warnings=None, **kw):
        extra = kw.pop('extra', {}) or {}
        reads = {('GET', '/api/templates/catalog'): (200, CATALOG),
                 ('GET', '/api/clusters/c1/templates/deployments'): (200, {'deployments': []}),
                 ('GET', '/api/clusters/c1/templates/existing'): (200, {'templates': []}),
                 ('GET', '/api/clusters/c1/nodes'): (200, NODES),
                 ('GET', '/api/clusters/c1/nextid'): (200, {'vmid': 105}),
                 ('GET', '/api/clusters/c1/nodes/pve1/network'): (200, NET),
                 ('GET', '/api/clusters/c1/nodes/pve2/network'): (200, NET2),
                 ('GET', '/api/clusters/c1/datacenter/sdn/vnets'): (200, VNETS)}
        reads.update({('GET', f'/api/clusters/c1/nodes/{n}/storage'): (200, s) for n, s in STORES.items()})
        reads.update(extra)
        super().__init__(extra=reads, **kw)
        self.bps = copy.deepcopy([WEB, DB, OTHER, GONE, WIN, GOLD] if blueprints is None else blueprints)
        self.progress = list(progress or [])
        self.prog_reads = []
        self.deploy_status = deploy_status
        self.refuse = refuse
        self.warnings = warnings
        self.pve_templates = copy.deepcopy(PVE_TEMPLATES)
        self.recent = copy.deepcopy(RECENT)

    def bp_route(self, method, path, body, url):
        if path == '/api/blueprints':
            if method == 'GET':
                return 200, {'blueprints': self.bps}
            if not str(body.get('name') or '').strip():
                return 400, {'error': 'Enter a name for the blueprint', 'field': 'name'}
            if body.get('name') == 'boom':
                return 500, {'error': 'database is locked'}
            if any(b['name'] == body['name'] for b in self.bps):
                return 409, {'error': f"A blueprint named '{body['name']}' exists already", 'field': 'name'}
            tpl = next((x for x in CATALOG['templates'] if x['id'] == body.get('template_id')), None)
            new = _bp(f'n{len(self.bps) + 1}', body['name'], **{k: v for k, v in body.items() if k != 'name'})
            new.update(template_name=tpl['name'] if tpl else '', template_missing=tpl is None and body.get('source_kind') != 'template')
            self.bps.append(new)
            return 201, {'blueprint': new}
        if path == '/api/blueprints/deployments':
            return 200, {'deployments': self.recent}
        m = re.fullmatch(r'/api/blueprints/deployments/([^/]+)', path)
        if m:
            self.prog_reads.append(time.time())
            row = self.progress.pop(0) if len(self.progress) > 1 else (self.progress[0] if self.progress else None)
            return (200, row) if row else (404, {'error': 'not found'})
        m = re.fullmatch(r'/api/blueprints/([^/]+)(/deploy)?', path)
        if m:
            have = next((b for b in self.bps if b['id'] == m.group(1)), None)
            if have is None:
                return 404, {'error': 'Blueprint not found'}
            if m.group(2):
                if self.refuse:
                    return self.refuse
                if self.deploy_status != 202:
                    return self.deploy_status, {'error': 'The tenant VMID range is 200-299'}
                out = {'deployment_id': 'd1', 'vmid': body.get('vmid', 105), 'name': body.get('name'), 'status': 'queued',
                       'build_needed': have['source_kind'] == 'library' and body.get('node') == 'pve2'}
                if self.warnings:
                    out['warnings'] = self.warnings
                return 202, out
            if method == 'DELETE':
                self.bps.remove(have)
                return 200, {'success': True}
            if method == 'PUT':
                have.update(body, updated_at='2026-11-08T10:00:00')
                return 200, {'blueprint': have}
        m = re.fullmatch(r'/api/clusters/c1/blueprints/([^/]+)/template', path)
        if m:
            node = (re.search(r'[?&]node=([^&]+)', url) or [None, ''])[1]
            have = next((b for b in self.bps if b['id'] == m.group(1)), None)
            if have and have['source_kind'] == 'template':
                win = have['os'] == 'windows'
                rows = [dict(x, usable_on_node=x['node'] == node or x['shared']) for x in self.pve_templates if x['windows'] == win]
                return 200, {'source_kind': 'template', 'mapped': have['templates'].get('c1'), 'templates': rows}
            return 200, dict(TEMPLATE.get(node, {'template': None, 'build_needed': True}), source_kind='library')
        return None

    def handle(self, route):
        req = route.request
        path = re.sub(r'^https?://[^/]+', '', req.url).split('?')[0]
        if path.startswith('/api/blueprints') or re.fullmatch(r'/api/clusters/c1/blueprints/[^/]+/template', path):
            self.calls.append((req.method, path))
            self.urls.append(req.url)
            body = json.loads(req.post_data) if req.post_data else {}
            if req.method != 'GET':
                self.bodies.setdefault(path, []).append(body)
            out = self.bp_route(req.method, path, body, req.url)
            if out is not None:
                return route.fulfill(status=out[0], body=json.dumps(out[1]), headers={'Content-Type': 'application/json'})
        return super().handle(route)


@pytest.fixture(scope='module')
def browser():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        pytest.skip('Playwright is not installed')
    try:
        pw = sync_playwright().start()
    except Exception as e:
        pytest.skip(f'Playwright does not start here: {e}')
    try:
        br = pw.chromium.launch(headless=True, args=DETERMINISTIC)
    except Exception as e:
        pw.stop()
        pytest.skip(f'no Chromium for Playwright: {e}')
    yield br
    br.close()
    pw.stop()


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(layout=LAYOUT, viewport=(1600, 1000), bundle=None, **kw):
        server = _BpServer(bundle=bundle or BUNDLE, layout=layout, **kw)
        app = _GuardApp(browser, server, viewport=viewport)
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.close()


def _need(page, selector, what, timeout=8000):
    try:
        page.locator(selector).first.wait_for(timeout=timeout)
    except Exception:
        raise AssertionError(f'{what} (no {selector})') from None


def _wait(page, pred, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        page.wait_for_timeout(100)
    return pred()


def _templates(app, layout=LAYOUT):
    """Automation > Cloud-Init Template Library (Blueprints & Images in the redesign) of Testi."""
    page = app.page
    if layout == 'modern':
        page.get_by_text('Testi').first.click()
    else:
        page.locator('.corp-tree-item', has_text='Testi').first.click()
    if layout == LAYOUT:
        page.locator('[data-cr-tab="automation"]').click()
    else:
        page.locator('button', has_text=re.compile(r'^\s*Automation\s*$')).first.click()
    app.mark = len(app.server.calls)
    page.locator('button', has_text=CR_TAB if layout == LAYOUT else TPL_TAB).first.click()
    return page


def _page(app):
    page = _templates(app)
    _need(page, '[data-cr-bp]', 'the blueprints are on the template sub tab of Corporate Redesigned')
    _need(page, '[data-cr-bp-row]', 'the blueprint list is filled')
    return page


def _count(app, method, path, since=None):
    return len([c for c in app.server.calls[getattr(app, 'mark', 0) if since is None else since:] if c == (method, path)])


def _no_errors(app):
    assert [e for e in app.errors if 'not mocked' not in e] == [], app.errors


def _row(page, bid):
    return page.locator('[data-cr-table="bp-list"] tbody tr', has=page.locator(f'[data-cr-bp-row="{bid}"]'))


def _box(page, selector):
    return page.locator(selector).first.bounding_box()


# the mount of CrBlueprints wrapped in a component that hands it prefillTemplate, onSaved and
# onDeleted the way the page around it does, so the test can set them while the section is
# mounted, and an authFetch that records what the section reads itself (the page around it may
# read the same routes for its own lists)
_WRAP = """() => {
    window.__crBpSaved = [];
    window.__crBpDeleted = [];
    window.__crBpUrls = [];
    window.__crBpWrap = (C) => window.__crBpW || (window.__crBpW = function CrBpTestMount(p) {
        const [pre, setPre] = React.useState(null);
        window.__crBpPrefill = setPre;
        const fetchSpy = React.useMemo(() => (url, opts) => { window.__crBpUrls.push(String(url)); return p.authFetch(url, opts); }, [p.authFetch]);
        return React.createElement(C, Object.assign({}, p, { authFetch: fetchSpy, prefillTemplate: pre,
            onSaved: (bp, isNew) => window.__crBpSaved.push([bp.id, isNew]),
            onDeleted: (bp) => window.__crBpDeleted.push(bp.id) }));
    });
}"""


def _wrapped_bundle():
    html = BUNDLE if BUNDLE is not None else open(os.path.join(ROOT, 'web', 'index.html'), encoding='utf-8').read()
    mount = 'React.createElement(CrBlueprints,{'
    assert html.count(mount) == 1
    return html.replace(mount, 'React.createElement(window.__crBpWrap ? window.__crBpWrap(CrBlueprints) : CrBlueprints,{')


def _wrapped(open_app, **kw):
    app = open_app(bundle=_wrapped_bundle(), **kw)
    app.page.evaluate(_WRAP)
    return app


def _own_reads(app, path=None):
    """The paths CrBlueprints read itself through the wrapped mount (only those equal to path)."""
    paths = [re.sub(r'^https?://[^/]+', '', u).split('?')[0] for u in app.page.evaluate('() => window.__crBpUrls')]
    return [x for x in paths if path is None or x == path]


# --- the list ----------------------------------------------------------------------------------

def test_runtime_the_list_shows_each_blueprint_and_reads_once(open_app):
    app = _wrapped(open_app)
    page = _page(app)
    page.wait_for_timeout(400)
    rows = page.evaluate("""() => [...document.querySelectorAll('[data-cr-bp-row]')].map(e => e.dataset.crBpRow)""")
    assert sorted(rows) == ['b1', 'b2', 'b3', 'b4', 'b5', 'b6']
    web = _row(page, 'b1').inner_text()
    assert 'web-small' in web and 'Small web front end' in web and 'Debian 13 (Trixie)' in web
    assert '2 vCPU · 2 GB · 20 GB' in web and 'DHCP' in web
    db = _row(page, 'b2').inner_text()
    assert '4 vCPU · 8 GB · image size' in db and 'Static' in db
    # an image the library dropped: said, and no deploy
    assert _row(page, 'b4').locator('[data-cr-bp-image="missing"]').count() == 1
    assert page.locator('[data-cr-bp-deploy="b4"]').is_disabled()
    # one read of the list, nothing per row, and no list of deploys (the page around it reads that
    # once for its own list, the section never)
    assert _own_reads(app) == ['/api/blueprints']
    # no progress read without an open deploy
    assert app.server.prog_reads == []
    _no_errors(app)


def test_runtime_the_list_says_source_network_and_that_it_is_for_all_clusters(open_app):
    page = _page(open_app())
    head = page.locator('[data-cr-nc-sec="bp"] .cr-nc-titleline')
    assert head.locator('[data-cr-bp-scope="all"]').inner_text().strip() == 'Shared across clusters'
    assert head.locator('.cr-badge', has_text=re.compile(r'^6$')).count() == 1
    # Source: the image of a library blueprint, the kind of template of a template blueprint
    # with the VMID this cluster remembers
    assert _row(page, 'b1').locator('[data-cr-bp-source-cell="library"]').inner_text() == 'Debian 13 (Trixie)'
    win = _row(page, 'b5').locator('[data-cr-bp-source-cell="template"]')
    assert win.get_attribute('data-cr-bp-os') == 'windows' and win.locator('.cr-badge').inner_text().strip() == 'Template (Windows)'
    assert win.locator('.cr-bp-src-vmid').inner_text() == 'Template 9100 on this cluster'
    gold = _row(page, 'b6').locator('[data-cr-bp-source-cell="template"]')
    assert gold.inner_text().strip() == 'Template (Linux)' and gold.locator('.cr-bp-src-vmid').count() == 0
    # Network: every NIC with its bridge and VLAN, or the NICs the template has
    assert page.locator('[data-cr-bp-net="b2"]').inner_text() == 'net0 vmbr0 VLAN 20, net1 vmbr1'
    assert page.locator('[data-cr-bp-net="b1"]').inner_text() == 'net0 vmbr0'
    assert page.locator('[data-cr-bp-net="b5"]').inner_text() == "template's NICs"
    assert '4 vCPU · 8 GB · 80 GB' in _row(page, 'b5').inner_text()
    assert 'template size' in _row(page, 'b6').inner_text()
    heads = page.evaluate("() => [...document.querySelectorAll('[data-cr-table=\"bp-list\"] thead th')].map(h => h.textContent.trim())")
    assert heads[:6] == ['Name', 'Source', 'CPU / RAM / disk', 'Network', 'IP', 'By'], heads
    # a template blueprint deploys whatever image the library has
    assert page.locator('[data-cr-bp-deploy="b5"]').is_enabled()


def test_runtime_the_row_actions_leave_primary_to_new_blueprint(open_app):
    page = _page(open_app())
    cls = lambda sel: page.locator(sel).first.get_attribute('class')
    assert 'cr-btn-primary' in cls('[data-cr-bp-new]')
    assert 'cr-btn-primary' not in cls('[data-cr-bp-deploy="b1"]') and 'cr-btn-xs' in cls('[data-cr-bp-deploy="b1"]')
    dele = page.locator('[data-cr-bp-delete="b1"]')
    assert 'cr-btn-danger' in dele.get_attribute('class') and 'cr-btn-xs' in dele.get_attribute('class')
    assert dele.locator('svg').count() == 1 and dele.get_attribute('aria-label') == 'Delete the blueprint web-small?'
    assert page.evaluate("() => document.querySelectorAll('[data-cr-table=\"bp-list\"] .cr-btn-primary').length") == 0


def test_runtime_the_list_has_no_toolbar_of_its_own(open_app):
    # a column menu alone would draw an empty strip with an eye icon above the header
    page = _page(open_app())
    table = page.locator('[data-cr-table="bp-list"]')
    assert table.locator('thead th').count() >= 6
    assert table.locator('.cr-table-toolbar').count() == 0 and table.locator('[data-cr-colmenu]').count() == 0


def test_runtime_no_recent_deploys_card_here(open_app):
    app = _wrapped(open_app)
    page = _page(app)
    page.wait_for_timeout(500)
    assert page.locator('[data-cr-nc-sec="bp-recent"]').count() == 0
    assert page.locator('[data-cr-table="bp-recent"]').count() == 0
    assert _own_reads(app, '/api/blueprints/deployments') == []


def test_runtime_an_empty_list_is_a_state_with_its_text(open_app):
    app = open_app(blueprints=[])
    page = _templates(app)
    _need(page, '[data-cr-bp-empty]', 'an empty list says so')
    empty = page.locator('[data-cr-bp-empty]')
    assert empty.get_attribute('data-cr-nc-state') == 'info' and 'cr-callout' in empty.get_attribute('class')
    assert 'No blueprint yet' in empty.inner_text()
    assert page.locator('[data-cr-bp-scope="all"]').count() == 1


def test_runtime_edit_and_delete_only_where_the_account_may(open_app):
    page = _page(open_app())
    assert page.locator('[data-cr-bp-edit="b1"]').count() == 1 and page.locator('[data-cr-bp-delete="b1"]').count() == 1
    assert page.locator('[data-cr-bp-edit="b3"]').count() == 0 and page.locator('[data-cr-bp-delete="b3"]').count() == 0
    # a colleague's blueprint still deploys
    assert page.locator('[data-cr-bp-deploy="b3"]').is_enabled()


def test_runtime_delete_asks_first_and_reads_the_list_again(open_app):
    app = open_app()
    page = _page(app)
    page.locator('[data-cr-bp-delete="b1"]').click()
    _need(page, '[data-cr-nc-confirm="bp-delete"]', 'Delete asks before it deletes')
    assert ('DELETE', '/api/blueprints/b1') not in app.server.calls
    page.locator('[data-cr-nc-confirm-go="bp-delete"]').click()
    assert _wait(page, lambda: ('DELETE', '/api/blueprints/b1') in app.server.calls)
    assert _wait(page, lambda: page.locator('[data-cr-bp-row="b1"]').count() == 0)
    assert _count(app, 'GET', '/api/blueprints') == 2


def test_runtime_a_delete_is_told_to_the_page_around_it(open_app):
    app = _wrapped(open_app)
    page = _page(app)
    page.locator('[data-cr-bp-delete="b2"]').click()
    page.locator('[data-cr-nc-confirm-go="bp-delete"]').click()
    assert _wait(page, lambda: page.evaluate('() => window.__crBpDeleted') == ['b2'])
    assert page.evaluate('() => window.__crBpSaved') == []
    # a delete the server refuses is not
    app.server.bps = [b for b in app.server.bps if b['id'] != 'b1']
    page.locator('[data-cr-bp-delete="b1"]').click()
    page.locator('[data-cr-nc-confirm-go="bp-delete"]').click()
    assert _wait(page, lambda: ('DELETE', '/api/blueprints/b1') in app.server.calls)
    page.wait_for_timeout(300)
    assert page.evaluate('() => window.__crBpDeleted') == ['b2']
    assert page.locator('[data-cr-nc-confirm="bp-delete"]').count() == 1


# --- the editor --------------------------------------------------------------------------------

def _fill(page, key, value):
    page.locator(f'[data-cr-bp-input="{key}"]').fill(value)


def _new(page):
    page.locator('[data-cr-bp-new]').click()
    _need(page, '[data-cr-bp-editor="new"]', 'New blueprint opens the editor')
    page.locator('[data-cr-bp-input="template_id"] option[value="c0ffee12"]').wait_for(state='attached', timeout=4000)


def test_runtime_create_sends_the_body_the_server_takes(open_app):
    app = open_app()
    page = _page(app)
    _new(page)
    _fill(page, 'name', '  app-tier ')
    page.locator('[data-cr-bp-input="template_id"]').select_option('c0ffee12')
    _fill(page, 'cores', '4')
    _fill(page, 'memory', '6')
    _fill(page, 'disk_gb', '40')
    page.locator('[data-cr-bp-nic-vlan="0"]').fill('30')
    page.locator('[data-cr-bp-nic-add]').click()
    page.locator('[data-cr-bp-nic-bridge="1"]').fill('vmbr1')
    page.locator('[data-cr-bp-nic-model="1"]').select_option('e1000')
    page.locator('[data-cr-bp-nic-fw="1"]').check()
    _fill(page, 'ciuser', 'ops')
    _fill(page, 'sshkeys', 'ssh-ed25519 AAAAC3Nza key1@lab\n\n  ecdsa-sha2-nistp256 AAAAE2Vj key2@lab  ')
    page.locator('[data-cr-bp-input="ip_mode"]').select_option('static')
    _fill(page, 'nameserver', '10.0.0.53')
    _fill(page, 'tags', 'app, prod ,')
    page.locator('[data-cr-bp-input="start"]').uncheck()
    page.locator('[data-cr-bp-editor-save]').click()
    assert _wait(page, lambda: ('POST', '/api/blueprints') in app.server.calls)
    body = app.server.bodies['/api/blueprints'][-1]
    assert body == {'name': 'app-tier', 'description': '', 'source_kind': 'library', 'os': 'linux', 'template_id': 'c0ffee12',
                    'cores': 4, 'memory': 6144, 'disk_gb': 40,
                    'cpu': '', 'nics': [{'bridge': 'vmbr0', 'vlan': 30, 'model': 'virtio', 'firewall': False},
                                        {'bridge': 'vmbr1', 'vlan': None, 'model': 'e1000', 'firewall': True}],
                    'ciuser': 'ops', 'sshkeys': 'ssh-ed25519 AAAAC3Nza key1@lab\necdsa-sha2-nistp256 AAAAE2Vj key2@lab',
                    'ip_mode': 'static', 'nameserver': '10.0.0.53', 'searchdomain': '', 'ciupgrade': True,
                    'tags': ['app', 'prod'], 'start': False}
    assert _wait(page, lambda: page.locator('[data-cr-bp-editor]').count() == 0)
    assert _wait(page, lambda: page.locator('[data-cr-bp-row="n7"]').count() == 1)


def test_runtime_a_new_blueprint_starts_with_the_defaults_of_the_server(open_app):
    app = open_app()
    page = _page(app)
    _new(page)
    # package upgrade and start on, the disk empty for the size of the image, which it names
    assert page.locator('[data-cr-bp-input="ciupgrade"]').is_checked()
    assert page.locator('[data-cr-bp-input="start"]').is_checked()
    disk = page.locator('[data-cr-bp-input="disk_gb"]')
    assert disk.input_value() == '' and disk.get_attribute('placeholder') == 'image size'
    page.locator('[data-cr-bp-input="template_id"]').select_option('debian-13')
    assert disk.get_attribute('placeholder') == 'image size (8 GB)'
    assert 'Empty keeps the size' in page.locator('[data-cr-nc-field="bp-disk_gb"] [data-cr-nc-hint]').inner_text()
    assert page.locator('[data-cr-bp-input="name"]').get_attribute('maxlength') == '64'
    assert page.locator('label[for="cr-nc-bp-ip_mode"]').inner_text() == 'IP configuration'
    # start and upgrade side by side under Deploy options; the password sentence under the keys
    opts = page.locator('[data-cr-nc-group="bp-opts"]')
    assert opts.locator('h4').inner_text().strip().lower() == 'deploy options'
    assert opts.locator('[data-cr-bp-input="start"]').count() == 1 and opts.locator('[data-cr-bp-input="ciupgrade"]').count() == 1
    s, u = _box(page, '[data-cr-nc-group="bp-opts"] [data-cr-bp-input="start"]'), _box(page, '[data-cr-nc-group="bp-opts"] [data-cr-bp-input="ciupgrade"]')
    assert abs(s['y'] - u['y']) < 2 and u['x'] > s['x']
    keys_hint = page.locator('[data-cr-nc-field="bp-sshkeys"] [data-cr-nc-hint]').inner_text()
    assert 'One key per line.' in keys_hint and 'keeps no password' in keys_hint
    assert page.locator('[data-cr-nc-group="bp-more"]').count() == 0
    # an empty disk goes out as 0, the size of the image
    _fill(page, 'name', 'plain')
    page.locator('[data-cr-bp-editor-save]').click()
    assert _wait(page, lambda: ('POST', '/api/blueprints') in app.server.calls)
    body = app.server.bodies['/api/blueprints'][-1]
    assert body['disk_gb'] == 0 and body['ciupgrade'] is True and body['start'] is True and body['template_id'] == 'debian-13'


def test_runtime_the_editor_grids_put_their_fields_in_rows(open_app):
    page = _page(open_app())
    _new(page)
    top = [_box(page, f'[data-cr-nc-field="bp-{k}"]') for k in ('name', 'template_id', 'tags')]
    assert len({round(b['y']) for b in top}) == 1 and top[0]['x'] < top[1]['x'] < top[2]['x'], top
    desc = _box(page, '[data-cr-nc-field="bp-description"]')
    assert desc['y'] > top[0]['y'] and desc['width'] > 2.5 * top[2]['width']
    hw = {k: _box(page, f'[data-cr-nc-field="bp-{k}"]') for k in ('cores', 'memory', 'disk_gb', 'cpu')}
    assert len({round(b['y']) for b in hw.values()}) == 1, hw
    assert hw['cores']['width'] < hw['disk_gb']['width'] < hw['cpu']['width'] and hw['cores']['width'] < hw['memory']['width']
    ci = [_box(page, f'[data-cr-nc-field="bp-{k}"]') for k in ('ciuser', 'ip_mode', 'nameserver', 'searchdomain')]
    assert len({round(b['y']) for b in ci}) == 1, ci
    # a phone width stacks them two by two, nothing wider than the dialog
    page.set_viewport_size({'width': 700, 'height': 900})
    page.wait_for_timeout(200)
    a, b, c = (_box(page, f'[data-cr-nc-field="bp-{k}"]') for k in ('name', 'template_id', 'tags'))
    assert round(a['y']) == round(b['y']) < round(c['y'])
    assert page.evaluate("() => { const b = document.querySelector('[data-cr-upd-dialog=\"bp-editor\"] .cr-sb-dbody'); return b.scrollWidth <= b.clientWidth; }")


def test_runtime_memory_in_mb_and_the_checks_before_saving(open_app):
    app = open_app()
    page = _page(app)
    page.locator('[data-cr-bp-new]').click()
    _need(page, '[data-cr-bp-editor="new"]', 'the editor opens')
    page.locator('[data-cr-bp-input="memUnit"]').select_option('MB')
    _fill(page, 'memory', '32')
    _fill(page, 'cores', '0')
    _fill(page, 'disk_gb', 'big')
    page.locator('[data-cr-bp-nic-bridge="0"]').fill('vmbr 0')
    page.locator('[data-cr-bp-nic-vlan="0"]').fill('5000')
    page.locator('[data-cr-bp-editor-save]').click()
    page.wait_for_timeout(300)
    assert ('POST', '/api/blueprints') not in app.server.calls
    errs = page.evaluate("""() => Object.fromEntries([...document.querySelectorAll('[data-cr-bp-editor] [data-cr-nc-field]')]
        .filter(f => f.querySelector('[data-cr-nc-hint="error"]')).map(f => [f.dataset.crNcField, f.querySelector('[data-cr-nc-hint]').textContent]))""")
    assert set(errs) == {'bp-name', 'bp-template_id', 'bp-cores', 'bp-memory', 'bp-disk_gb', 'bp-nic0-bridge', 'bp-nic0-vlan'}, errs
    assert '64' in errs['bp-memory'] and '4194304' in errs['bp-memory']
    # fixed, the memory goes out in MB as typed
    _fill(page, 'name', 'tiny')
    page.locator('[data-cr-bp-input="template_id"]').select_option('debian-13')
    _fill(page, 'cores', '1')
    _fill(page, 'memory', '512')
    _fill(page, 'disk_gb', '')
    page.locator('[data-cr-bp-nic-bridge="0"]').fill('vmbr0')
    page.locator('[data-cr-bp-nic-vlan="0"]').fill('')
    page.locator('[data-cr-bp-editor-save]').click()
    assert _wait(page, lambda: ('POST', '/api/blueprints') in app.server.calls)
    assert app.server.bodies['/api/blueprints'][-1]['memory'] == 512


def test_runtime_a_refusal_of_the_server_stands_at_its_field(open_app):
    app = open_app()
    page = _page(app)
    _new(page)
    _fill(page, 'name', 'web-small')
    page.locator('[data-cr-bp-input="template_id"]').select_option('debian-13')
    page.locator('[data-cr-bp-editor-save]').click()
    hint = page.locator('[data-cr-nc-field="bp-name"] [data-cr-nc-hint="error"]')
    hint.wait_for(timeout=4000)
    assert "exists already" in hint.inner_text()
    assert page.locator('[data-cr-bp-editor]').count() == 1


def test_runtime_a_failed_save_brings_the_general_error_into_view(open_app):
    app = open_app(viewport=(1280, 640))
    page = _page(app)
    _new(page)
    _fill(page, 'name', 'boom')
    page.locator('[data-cr-bp-input="template_id"]').select_option('debian-13')
    body = '[data-cr-upd-dialog="bp-editor"] .cr-sb-dbody'
    page.evaluate(f"() => {{ const b = document.querySelector('{body}'); b.scrollTop = b.scrollHeight; }}")
    assert page.evaluate(f"() => document.querySelector('{body}').scrollTop") > 100
    page.locator('[data-cr-bp-editor-save]').click()
    note = page.locator('[data-cr-upd-note="bp-save"]')
    note.wait_for(timeout=4000)
    assert 'database is locked' in note.inner_text() and 'HTTP 500' in note.inner_text()
    page.wait_for_timeout(300)
    seen = page.evaluate(f"""() => {{ const b = document.querySelector('{body}').getBoundingClientRect();
        const n = document.querySelector('[data-cr-upd-note="bp-save"]').getBoundingClientRect();
        return n.top >= b.top - 1 && n.bottom <= b.bottom + 1; }}""")
    assert seen, 'the error on top of the form is scrolled into view'


def test_runtime_edit_fills_the_form_and_puts_the_whole_object(open_app):
    app = open_app()
    page = _page(app)
    page.locator('[data-cr-bp-edit="b2"]').click()
    _need(page, '[data-cr-bp-editor="b2"]', 'Edit opens the editor of that blueprint')
    assert page.locator('[data-cr-bp-input="name"]').input_value() == 'db-static'
    assert page.locator('[data-cr-bp-input="memory"]').input_value() == '8'
    assert page.locator('[data-cr-bp-input="memUnit"]').input_value() == 'GB'
    assert page.locator('[data-cr-bp-input="disk_gb"]').input_value() == ''
    assert page.locator('[data-cr-bp-nic-vlan="0"]').input_value() == '20'
    assert page.locator('[data-cr-bp-nic-model="1"]').input_value() == 'e1000'
    assert page.locator('[data-cr-bp-source="library"]').get_attribute('aria-pressed') == 'true'
    # the bridges of a node of this cluster are suggested, read once
    assert page.evaluate("() => [...document.querySelectorAll('#cr-bp-bridges option')].map(o => o.value)") == ['vmbr0', 'vmbr1']
    _fill(page, 'cores', '8')
    page.locator('[data-cr-bp-editor-save]').click()
    assert _wait(page, lambda: ('PUT', '/api/blueprints/b2') in app.server.calls)
    body = app.server.bodies['/api/blueprints/b2'][-1]
    assert body['cores'] == 8 and body['memory'] == 8192 and body['disk_gb'] == 0 and body['ip_mode'] == 'static'
    assert body['nics'][1] == {'bridge': 'vmbr1', 'vlan': None, 'model': 'e1000', 'firewall': False}
    assert body['source_kind'] == 'library' and body['template_id'] == 'almalinux-10'
    assert _count(app, 'GET', '/api/clusters/c1/nodes/pve1/network') == 1


# --- a template source, Windows ---------------------------------------------------------------

def test_runtime_a_windows_template_blueprint_leaves_out_what_windows_ignores(open_app):
    app = open_app()
    page = _page(app)
    _new(page)
    page.locator('[data-cr-bp-source="template"]').click()
    # no library image for a template source, an operating system instead
    assert page.locator('[data-cr-bp-input="template_id"]').count() == 0
    os_pick = page.locator('[data-cr-bp-input="os"]')
    assert os_pick.input_value() == 'linux'
    assert [o.strip() for o in os_pick.locator('option').all_inner_texts()] == ['Linux', 'Windows']
    assert page.locator('[data-cr-bp-input="ciuser"]').count() == 1
    assert 'Cloud-Init user of the template' in page.locator('[data-cr-nc-field="bp-ciuser"] [data-cr-nc-hint]').inner_text()
    assert page.locator('[data-cr-bp-input="disk_gb"]').get_attribute('placeholder') == 'template size'
    os_pick.select_option('windows')
    for k in ('ciuser', 'sshkeys', 'searchdomain', 'ciupgrade'):
        assert page.locator(f'[data-cr-bp-input="{k}"]').count() == 0, k
    note = page.locator('[data-cr-bp-win-note]').inner_text()
    assert 'cloudbase-init' in note and 'administrator account' in note and 'search domains' in note
    assert page.locator('[data-cr-bp-input="ip_mode"]').count() == 1 and page.locator('[data-cr-bp-input="nameserver"]').count() == 1
    # the template's own network
    page.locator('[data-cr-bp-input="keepNet"]').check()
    assert page.locator('[data-cr-bp-nic]').count() == 0 and page.locator('[data-cr-bp-nic-add]').count() == 0
    assert page.locator('[data-cr-bp-keepnet]').count() == 1
    _fill(page, 'name', 'win-server')
    _fill(page, 'cores', '4')
    _fill(page, 'memory', '8')
    page.locator('[data-cr-bp-editor-save]').click()
    assert _wait(page, lambda: ('POST', '/api/blueprints') in app.server.calls)
    body = app.server.bodies['/api/blueprints'][-1]
    assert body == {'name': 'win-server', 'description': '', 'source_kind': 'template', 'os': 'windows', 'template_id': '',
                    'cores': 4, 'memory': 8192, 'disk_gb': 0, 'cpu': '', 'nics': [], 'ciuser': '', 'sshkeys': '',
                    'ip_mode': 'dhcp', 'nameserver': '', 'searchdomain': '', 'ciupgrade': True, 'tags': [], 'start': True}


def test_runtime_editing_a_windows_blueprint_reads_no_catalog(open_app):
    app = open_app()
    page = _page(app)
    page.wait_for_timeout(500)
    mark = len(app.server.calls)
    page.locator('[data-cr-bp-edit="b5"]').click()
    _need(page, '[data-cr-bp-editor="b5"]', 'Edit opens the Windows blueprint')
    page.wait_for_timeout(400)
    assert page.locator('[data-cr-bp-source="template"]').get_attribute('aria-pressed') == 'true'
    assert page.locator('[data-cr-bp-input="os"]').input_value() == 'windows'
    assert page.locator('[data-cr-bp-input="keepNet"]').is_checked()
    assert page.locator('[data-cr-bp-input="disk_gb"]').input_value() == '80'
    assert _count(app, 'GET', '/api/templates/catalog', mark) == 0
    # back to a library image: the image list is read then, the NICs come back
    page.locator('[data-cr-bp-source="library"]').click()
    page.locator('[data-cr-bp-input="template_id"] option[value="debian-13"]').wait_for(state='attached', timeout=4000)
    assert _count(app, 'GET', '/api/templates/catalog', mark) == 1
    assert page.locator('[data-cr-bp-nic="0"]').count() == 1 and page.locator('[data-cr-bp-input="keepNet"]').count() == 0


# --- the deploy --------------------------------------------------------------------------------

RUNNING = {'id': 'd1', 'blueprint_id': 'b1', 'status': 'running', 'step': 'clone', 'progress': 40, 'vmid': 105, 'node': 'pve1',
           'name': 'web-small', 'log': '[2026-11-08T09:00:01] cloning 9001 to 105\n', 'error': ''}
DONE = dict(RUNNING, status='completed', step='done', progress=100,
            log=RUNNING['log'] + '[2026-11-08T09:00:30] configured\n[2026-11-08T09:00:31] done\n')
FAILED = dict(RUNNING, status='failed', step='resize', progress=70, error='resize failed: storage full')


def _deploy(page, bid='b1'):
    page.locator(f'[data-cr-bp-deploy="{bid}"]').click()
    _need(page, f'[data-cr-bp-deploy-form="{bid}"]', 'Deploy opens the deploy dialog')
    page.locator('[data-cr-bp-dep="storage"] option[value="local-lvm"]').wait_for(state='attached', timeout=4000)


def test_runtime_the_deploy_dialog_reads_where_to_and_says_which_template(open_app):
    app = open_app()
    page = _page(app)
    _deploy(page)
    # online nodes only, the storages of the node that take disk images, the next free VMID
    assert page.evaluate("() => [...document.querySelectorAll('[data-cr-bp-dep=\"node\"] option')].map(o => o.value)") == ['pve1', 'pve2']
    assert page.evaluate("() => [...document.querySelectorAll('[data-cr-bp-dep=\"storage\"] option')].map(o => o.value)") == ['local-lvm', 'ceph']
    assert page.locator('[data-cr-bp-dep="vmid"]').input_value() == '105'
    assert page.locator('[data-cr-bp-dep="name"]').input_value() == 'web-small'
    page.locator('[data-cr-bp-tpl="existing"]').wait_for(timeout=4000)
    assert page.locator('[data-cr-bp-tpl="existing"]').get_attribute('data-cr-bp-tpl-vmid') == '9001'
    page.locator('[data-cr-bp-dep="node"]').select_option('pve2')
    page.locator('[data-cr-bp-tpl="build"]').wait_for(timeout=4000)
    assert page.locator('[data-cr-bp-dep="storage"]').input_value() == 'local-zfs'
    assert any('template?node=pve2' in u for u in app.server.urls)
    # no static address for a DHCP blueprint, no template pick for a library one
    assert page.locator('[data-cr-bp-dep="ip"]').count() == 0
    assert page.locator('[data-cr-bp-dep="template_vmid"]').count() == 0
    # the summary says the network
    assert 'network: net0 vmbr0, IP: DHCP' in page.locator('[data-cr-bp-summary]').inner_text()
    _no_errors(app)


def test_runtime_dhcp_sends_no_ipconfig0(open_app):
    app = open_app(progress=[DONE])
    page = _page(app)
    _deploy(page)
    page.locator('[data-cr-bp-dep="password"]').fill('s3cret')
    page.locator('[data-cr-bp-deploy-go]').click()
    assert _wait(page, lambda: ('POST', '/api/blueprints/b1/deploy') in app.server.calls)
    body = app.server.bodies['/api/blueprints/b1/deploy'][-1]
    assert body == {'cluster_id': 'c1', 'node': 'pve1', 'storage': 'local-lvm', 'name': 'web-small', 'start': True,
                    'vmid': 105, 'cipassword': 's3cret'}


def test_runtime_static_builds_ipconfig0_and_checks_it(open_app):
    app = open_app(progress=[DONE])
    page = _page(app)
    _deploy(page, 'b2')
    assert page.locator('[data-cr-bp-dep="start"]').is_checked() is False   # the blueprint's default
    page.locator('[data-cr-bp-dep="ip"]').fill('10.0.0.300/24')
    page.locator('[data-cr-bp-dep="gw"]').fill('gateway')
    page.locator('[data-cr-bp-dep="vmid"]').fill('42')
    page.locator('[data-cr-bp-dep="name"]').fill('-db')
    page.locator('[data-cr-bp-deploy-go]').click()
    page.wait_for_timeout(300)
    assert ('POST', '/api/blueprints/b2/deploy') not in app.server.calls
    errs = page.evaluate("""() => [...document.querySelectorAll('[data-cr-bp-deploy-form] [data-cr-nc-field]')]
        .filter(f => f.querySelector('[data-cr-nc-hint="error"]')).map(f => f.dataset.crNcField).sort()""")
    assert errs == ['bp-gw', 'bp-ip', 'bp-vmid', 'bp-vmname'], errs
    page.locator('[data-cr-bp-dep="ip"]').fill('10.0.0.5/24')
    page.locator('[data-cr-bp-dep="gw"]').fill('10.0.0.1')
    page.locator('[data-cr-bp-dep="vmid"]').fill('')
    page.locator('[data-cr-bp-dep="name"]').fill('db-01')
    page.locator('[data-cr-bp-deploy-go]').click()
    assert _wait(page, lambda: ('POST', '/api/blueprints/b2/deploy') in app.server.calls)
    body = app.server.bodies['/api/blueprints/b2/deploy'][-1]
    assert body['ipconfig0'] == 'ip=10.0.0.5/24,gw=10.0.0.1' and 'vmid' not in body and body['start'] is False
    assert 'cipassword' not in body and 'template_vmid' not in body


def test_runtime_an_ipv6_address_takes_ip6_and_gw6(open_app):
    app = open_app(progress=[DONE])
    page = _page(app)
    _deploy(page, 'b2')
    page.locator('[data-cr-bp-dep="ip"]').fill('2001:db8::5/64')
    page.locator('[data-cr-bp-deploy-go]').click()
    assert _wait(page, lambda: ('POST', '/api/blueprints/b2/deploy') in app.server.calls)
    assert app.server.bodies['/api/blueprints/b2/deploy'][-1]['ipconfig0'] == 'ip6=2001:db8::5/64'


def test_runtime_a_bridge_the_node_lacks_is_said_under_the_summary(open_app):
    app = open_app()
    page = _page(app)
    mark = len(app.server.calls)
    _deploy(page, 'b2')
    page.wait_for_timeout(400)
    # pve1 has vmbr0 and vmbr1
    assert page.locator('[data-cr-bp-bridge-missing]').count() == 0
    page.locator('[data-cr-bp-dep="node"]').select_option('pve2')
    _need(page, '[data-cr-bp-bridge-missing]', 'a bridge pve2 does not have is said')
    miss = page.locator('[data-cr-bp-bridge-missing]')
    assert miss.get_attribute('data-cr-bp-bridge-missing') == 'vmbr1'
    assert 'vmbr1 is no bridge of pve2 and no SDN VNet' in miss.inner_text()
    # under the summary
    assert _box(page, '[data-cr-upd-note="bp-bridges"]')['y'] > _box(page, '[data-cr-bp-summary]')['y']
    assert _count(app, 'GET', '/api/clusters/c1/nodes/pve2/network', mark) == 1
    assert _count(app, 'GET', '/api/clusters/c1/datacenter/sdn/vnets', mark) == 1
    # a warning, not a block: the server has the last word
    assert page.locator('[data-cr-bp-deploy-go]').is_enabled()


def test_runtime_an_sdn_vnet_is_no_missing_bridge_and_kept_nics_read_no_network(open_app):
    app = open_app()
    page = _page(app)
    mark = len(app.server.calls)
    page.locator('[data-cr-bp-deploy="b6"]').click()
    _need(page, '[data-cr-bp-deploy-form="b6"]', 'the deploy dialog of the VNet blueprint opens')
    page.locator('[data-cr-bp-dep="template_vmid"] option[value="9200"]').wait_for(state='attached', timeout=4000)
    page.wait_for_timeout(400)
    assert _count(app, 'GET', '/api/clusters/c1/nodes/pve1/network', mark) == 1
    assert page.locator('[data-cr-bp-bridge-missing]').count() == 0
    page.locator('[data-cr-bp-deploy-cancel]').click()
    mark = len(app.server.calls)
    page.locator('[data-cr-bp-deploy="b5"]').click()
    _need(page, '[data-cr-bp-deploy-form="b5"]', 'the deploy dialog of the Windows blueprint opens')
    page.locator('[data-cr-bp-dep="template_vmid"] option[value="9100"]').wait_for(state='attached', timeout=4000)
    page.wait_for_timeout(400)
    later = app.server.calls[mark:]
    assert not [c for c in later if c[1].endswith('/network') or c[1].endswith('/sdn/vnets')], later
    assert "network: template's NICs" in page.locator('[data-cr-bp-summary]').inner_text()


def test_runtime_unreadable_vnets_still_warn_with_the_hedge(open_app):
    app = open_app(extra={('GET', '/api/clusters/c1/datacenter/sdn/vnets'): (403, {'error': 'Permission denied'})})
    page = _page(app)
    _deploy(page, 'b2')
    page.locator('[data-cr-bp-dep="node"]').select_option('pve2')
    _need(page, '[data-cr-bp-bridge-missing]', 'the bridge check runs without the VNets')
    assert 'Unless it is an SDN VNet of this cluster' in page.locator('[data-cr-bp-bridge-missing]').inner_text()


def test_runtime_a_windows_deploy_picks_a_template_and_needs_a_password(open_app):
    app = open_app(progress=[RUNNING])
    page = _page(app)
    page.locator('[data-cr-bp-deploy="b5"]').click()
    _need(page, '[data-cr-bp-deploy-form="b5"]', 'the deploy dialog opens')
    pick = page.locator('[data-cr-bp-dep="template_vmid"]')
    page.locator('[data-cr-bp-dep="template_vmid"] option[value="9100"]').wait_for(state='attached', timeout=4000)
    # the Windows templates of the cluster: the remembered one picked, the ones a deploy onto
    # pve1 cannot clone offered with the reason and not to be picked
    assert pick.input_value() == '9100'
    opts = page.evaluate("""() => [...document.querySelectorAll('[data-cr-bp-dep="template_vmid"] option')]
        .map(o => [o.value, o.disabled, o.textContent])""")
    assert opts[0][0] == '' and [o[0] for o in opts[1:]] == ['9100', '9101', '9102']
    assert opts[1] == ['9100', False, 'win2022-golden (9100) · pve1 · win11']
    assert opts[2] == ['9101', True, 'win11-plain (9101) · pve1 · win11 (no Cloud-Init drive)']
    assert opts[3] == ['9102', True, 'win2019 (9102) · pve2 · win10 (on pve2, disks not on shared storage)']
    assert 'used on this cluster before' in page.locator('[data-cr-nc-field="bp-template_vmid"] [data-cr-nc-hint]').inner_text()
    # Windows: no library template note, a password hint that says where PVE keeps it
    assert page.locator('[data-cr-bp-tpl]').count() == 0
    hint = page.locator('[data-cr-nc-field="bp-password"] [data-cr-nc-hint]').inner_text()
    assert 'Required for Windows' in hint and 'plain text in the VM config' in hint
    # a name past 15 characters warns, a missing password stops the deploy
    page.locator('[data-cr-bp-dep="name"]').fill('win-desktop-finance-01')
    warn = page.locator('[data-cr-nc-field="bp-vmname"] [data-cr-nc-hint="warning"]')
    assert 'first 15 characters' in warn.inner_text()
    page.locator('[data-cr-bp-deploy-go]').click()
    page.wait_for_timeout(300)
    assert ('POST', '/api/blueprints/b5/deploy') not in app.server.calls
    assert 'Enter a password' in page.locator('[data-cr-nc-field="bp-password"] [data-cr-nc-hint="error"]').inner_text()
    page.locator('[data-cr-bp-dep="password"]').fill('Adm1n!pass')
    page.locator('[data-cr-bp-deploy-go]').click()
    assert _wait(page, lambda: ('POST', '/api/blueprints/b5/deploy') in app.server.calls)
    body = app.server.bodies['/api/blueprints/b5/deploy'][-1]
    assert body == {'cluster_id': 'c1', 'node': 'pve1', 'storage': 'local-lvm', 'name': 'win-desktop-finance-01', 'start': True,
                    'vmid': 105, 'template_vmid': 9100, 'cipassword': 'Adm1n!pass'}
    _need(page, '[data-cr-bp-progress="d1"]', 'the progress view follows the template deploy')
    # the template steps never show for a template source
    assert page.locator('[data-cr-bp-step="template"]').count() == 0


def test_runtime_the_template_pick_is_as_wide_as_its_field(open_app):
    # long names (win2022-golden (9100) · pve1 · win11) are not cut off at the cap of the narrow selects
    page = _page(open_app())
    page.locator('[data-cr-bp-deploy="b5"]').click()
    _need(page, '[data-cr-bp-deploy-form="b5"]', 'the deploy dialog opens')
    page.locator('[data-cr-bp-dep="template_vmid"] option[value="9100"]').wait_for(state='attached', timeout=4000)
    field, pick = _box(page, '[data-cr-nc-field="bp-template_vmid"]'), _box(page, '[data-cr-bp-dep="template_vmid"]')
    assert field['width'] > 500 and abs(pick['width'] - field['width']) < 2, (field, pick)
    node, cluster = _box(page, '[data-cr-nc-field="bp-node"]'), _box(page, '[data-cr-bp-dep="node"]')
    assert abs(cluster['width'] - node['width']) < 2 and node['width'] < field['width']


def test_runtime_the_windows_password_is_the_administrator_one_and_can_be_shown(open_app):
    app = open_app()
    page = _page(app)
    page.locator('[data-cr-bp-deploy="b5"]').click()
    _need(page, '[data-cr-bp-deploy-form="b5"]', 'the deploy dialog opens')
    assert page.locator('label[for="cr-nc-bp-password"]').inner_text() == 'Administrator password'
    pw, show = page.locator('[data-cr-bp-dep="password"]'), page.locator('[data-cr-bp-pw-show]')
    pw.fill('Adm1n!pass')
    assert pw.get_attribute('type') == 'password' and show.get_attribute('aria-pressed') == 'false'
    assert show.get_attribute('aria-label') == 'Show password'
    # typed once and never shown again: it can be looked at before the deploy
    show.click()
    assert pw.get_attribute('type') == 'text' and pw.input_value() == 'Adm1n!pass' and show.get_attribute('aria-pressed') == 'true'
    show.click()
    assert pw.get_attribute('type') == 'password'
    a, b = _box(page, '[data-cr-bp-dep="password"]'), _box(page, '[data-cr-bp-pw-show]')
    assert abs((a['y'] + a['height'] / 2) - (b['y'] + b['height'] / 2)) < 2 and b['x'] >= a['x'] + a['width']
    field = _box(page, '[data-cr-nc-field="bp-password"]')
    assert b['x'] + b['width'] <= field['x'] + field['width'] + 1
    # a Linux blueprint keeps the Cloud-Init password
    page.locator('[data-cr-bp-deploy-cancel]').click()
    _deploy(page, 'b1')
    assert page.locator('label[for="cr-nc-bp-password"]').inner_text() == 'Cloud-Init password'
    assert page.locator('[data-cr-bp-pw-show]').count() == 1


def test_runtime_another_node_keeps_only_a_template_it_can_clone(open_app):
    app = open_app()
    page = _page(app)
    page.locator('[data-cr-bp-deploy="b5"]').click()
    _need(page, '[data-cr-bp-deploy-form="b5"]', 'the deploy dialog opens')
    pick = page.locator('[data-cr-bp-dep="template_vmid"]')
    page.locator('[data-cr-bp-dep="template_vmid"] option[value="9100"]').wait_for(state='attached', timeout=4000)
    assert _wait(page, lambda: pick.input_value() == '9100')
    page.locator('[data-cr-bp-dep="node"]').select_option('pve2')
    # on pve2 the remembered 9100 (local disks on pve1) cannot be cloned: no pick, 9102 can
    # (the list is read again for that node, the options are gone meanwhile)
    assert _wait(page, lambda: page.evaluate("() => document.querySelector('[data-cr-bp-dep=\"template_vmid\"] option[value=\"9100\"]')?.disabled === true"))
    assert pick.input_value() == ''
    assert page.evaluate("() => document.querySelector('[data-cr-bp-dep=\"template_vmid\"] option[value=\"9102\"]').disabled") is False
    page.locator('[data-cr-bp-dep="password"]').fill('x')
    page.locator('[data-cr-bp-deploy-go]').click()
    page.wait_for_timeout(300)
    assert ('POST', '/api/blueprints/b5/deploy') not in app.server.calls
    assert 'Pick a template of this cluster.' == page.locator('[data-cr-nc-field="bp-template_vmid"] [data-cr-nc-hint="error"]').inner_text()
    pick.select_option('9102')
    page.locator('[data-cr-bp-deploy-go]').click()
    assert _wait(page, lambda: ('POST', '/api/blueprints/b5/deploy') in app.server.calls)
    body = app.server.bodies['/api/blueprints/b5/deploy'][-1]
    assert body['template_vmid'] == 9102 and body['node'] == 'pve2' and body['storage'] == 'local-zfs'


def test_runtime_a_template_of_another_node_offers_shared_storage_only(open_app):
    # PVE clones a template of another node into shared storage only and the server refuses the rest
    pve2 = [{'storage': 'local-zfs', 'content': 'images,rootdir', 'enabled': 1, 'active': 1, 'shared': 0},
            {'storage': 'ceph', 'content': 'images', 'enabled': 1, 'active': 1, 'shared': 1}]
    app = open_app(extra={('GET', '/api/clusters/c1/nodes/pve2/storage'): (200, pve2)})
    page = _page(app)
    page.locator('[data-cr-bp-deploy="b6"]').click()
    _need(page, '[data-cr-bp-deploy-form="b6"]', 'the deploy dialog opens')
    stores = lambda: page.evaluate("() => [...document.querySelectorAll('[data-cr-bp-dep=\"storage\"] option')].map(o => o.value)")
    page.locator('[data-cr-bp-dep="template_vmid"] option[value="9200"]').wait_for(state='attached', timeout=4000)
    page.locator('[data-cr-bp-dep="node"]').select_option('pve2')
    assert _wait(page, lambda: stores() == ['local-zfs', 'ceph'])
    hint = page.locator('[data-cr-nc-field="bp-storage"] [data-cr-nc-hint]')
    assert hint.count() == 0 or 'shared storage only' not in hint.inner_text()
    # rocky-9-golden sits on pve1: on pve2 only ceph is left, and picked
    page.locator('[data-cr-bp-dep="template_vmid"] option[value="9200"]').wait_for(state='attached', timeout=4000)
    page.locator('[data-cr-bp-dep="template_vmid"]').select_option('9200')
    assert _wait(page, lambda: stores() == ['ceph'])
    assert page.locator('[data-cr-bp-dep="storage"]').input_value() == 'ceph'
    assert 'The template is on pve1: a clone onto this node goes to shared storage only.' == hint.inner_text()
    page.locator('[data-cr-bp-deploy-go]').click()
    assert _wait(page, lambda: ('POST', '/api/blueprints/b6/deploy') in app.server.calls)
    body = app.server.bodies['/api/blueprints/b6/deploy'][-1]
    assert body['template_vmid'] == 9200 and body['node'] == 'pve2' and body['storage'] == 'ceph'


def test_runtime_a_node_without_shared_storage_says_so_for_a_template_elsewhere(open_app):
    app = open_app()
    page = _page(app)
    page.locator('[data-cr-bp-deploy="b6"]').click()
    _need(page, '[data-cr-bp-deploy-form="b6"]', 'the deploy dialog opens')
    page.locator('[data-cr-bp-dep="template_vmid"] option[value="9200"]').wait_for(state='attached', timeout=4000)
    page.locator('[data-cr-bp-dep="node"]').select_option('pve2')
    page.locator('[data-cr-bp-dep="template_vmid"] option[value="9200"]').wait_for(state='attached', timeout=4000)
    page.locator('[data-cr-bp-dep="template_vmid"]').select_option('9200')
    sel = page.locator('[data-cr-bp-dep="storage"]')
    assert _wait(page, lambda: sel.is_disabled())
    hint = page.locator('[data-cr-nc-field="bp-storage"] [data-cr-nc-hint]')
    assert hint.get_attribute('data-cr-nc-hint') == 'warning'
    assert hint.inner_text().startswith('The template is on pve1 and this node has no shared storage for disk images.')
    page.locator('[data-cr-bp-deploy-go]').click()
    page.wait_for_timeout(300)
    assert ('POST', '/api/blueprints/b6/deploy') not in app.server.calls


def test_runtime_a_linux_template_without_a_remembered_one_asks_for_it(open_app):
    app = open_app(progress=[DONE])
    page = _page(app)
    page.locator('[data-cr-bp-deploy="b6"]').click()
    _need(page, '[data-cr-bp-deploy-form="b6"]', 'the deploy dialog opens')
    page.locator('[data-cr-bp-dep="template_vmid"] option[value="9200"]').wait_for(state='attached', timeout=4000)
    opts = page.evaluate("() => [...document.querySelectorAll('[data-cr-bp-dep=\"template_vmid\"] option')].map(o => o.value)")
    assert opts == ['', '9200']
    assert page.locator('[data-cr-bp-dep="template_vmid"]').input_value() == ''
    assert 'remembers this template' in page.locator('[data-cr-nc-field="bp-template_vmid"] [data-cr-nc-hint]').inner_text()
    assert 'Optional' in page.locator('[data-cr-nc-field="bp-password"] [data-cr-nc-hint]').inner_text()
    page.locator('[data-cr-bp-dep="template_vmid"]').select_option('9200')
    page.locator('[data-cr-bp-deploy-go]').click()
    assert _wait(page, lambda: ('POST', '/api/blueprints/b6/deploy') in app.server.calls)
    body = app.server.bodies['/api/blueprints/b6/deploy'][-1]
    assert body['template_vmid'] == 9200 and 'cipassword' not in body
    # the list is read again: the deploy may have remembered the template for the cluster
    assert _wait(page, lambda: _count(app, 'GET', '/api/blueprints') == 2)


def test_runtime_a_cluster_without_a_fitting_template_says_how_to_get_one(open_app):
    app = open_app()
    app.server.pve_templates = [x for x in PVE_TEMPLATES if not x['windows']]
    page = _page(app)
    page.locator('[data-cr-bp-deploy="b5"]').click()
    _need(page, '[data-cr-bp-deploy-form="b5"]', 'the deploy dialog opens')
    hint = page.locator('[data-cr-nc-field="bp-template_vmid"] [data-cr-nc-hint="warning"]')
    hint.wait_for(timeout=4000)
    assert 'This cluster has no Windows template' in hint.inner_text() and 'Cloud-Init drive' in hint.inner_text()
    assert page.locator('[data-cr-bp-dep="template_vmid"]').is_disabled()


def test_runtime_a_refusal_naming_a_field_stands_there(open_app):
    app = open_app(refuse=(400, {'error': 'template 9100 has no Cloud-Init drive', 'field': 'template_vmid'}))
    page = _page(app)
    page.locator('[data-cr-bp-deploy="b5"]').click()
    _need(page, '[data-cr-bp-deploy-form="b5"]', 'the deploy dialog opens')
    page.locator('[data-cr-bp-dep="template_vmid"] option[value="9100"]').wait_for(state='attached', timeout=4000)
    page.locator('[data-cr-bp-dep="password"]').fill('pw')
    page.locator('[data-cr-bp-deploy-go]').click()
    hint = page.locator('[data-cr-nc-field="bp-template_vmid"] [data-cr-nc-hint="error"]')
    hint.wait_for(timeout=4000)
    assert 'no Cloud-Init drive' in hint.inner_text()
    assert page.locator('[data-cr-upd-note="bp-deploy"]').count() == 0


def test_runtime_a_refused_bridge_stands_on_top(open_app):
    app = open_app(refuse=(400, {'error': 'bridge vmbr1 is neither on pve2 nor an SDN VNet', 'field': 'nics'}))
    page = _page(app)
    _deploy(page, 'b2')
    page.locator('[data-cr-bp-dep="ip"]').fill('10.0.0.5/24')
    page.locator('[data-cr-bp-deploy-go]').click()
    note = page.locator('[data-cr-upd-note="bp-deploy"]')
    note.wait_for(timeout=4000)
    assert 'vmbr1 is neither' in note.inner_text()


def test_runtime_the_notes_of_the_server_show_in_the_progress(open_app):
    notes = ['qemu-server on pve1 could not be read, Windows Cloud-Init needs 8.2.4 or newer',
             'Windows uses the first 15 characters of the name as its computer name']
    app = open_app(progress=[RUNNING], warnings=notes)
    page = _page(app)
    _deploy(page)
    page.locator('[data-cr-bp-deploy-go]').click()
    _need(page, '[data-cr-bp-progress="d1"]', 'the progress view opens')
    box = page.locator('[data-cr-upd-note="bp-warnings"]')
    assert 'The server takes the deploy with these notes:' in box.inner_text()
    assert page.locator('[data-cr-bp-warnings] li').all_inner_texts() == notes


def test_runtime_the_progress_is_read_until_the_deploy_ends(open_app):
    app = open_app(progress=[RUNNING, RUNNING, DONE])
    page = _page(app)
    _deploy(page)
    page.locator('[data-cr-bp-deploy-go]').click()
    _need(page, '[data-cr-bp-progress="d1"]', 'the dialog shows the progress of the deploy it started')
    assert _wait(page, lambda: page.locator('[data-cr-bp-progress][data-cr-bp-status="completed"]').count() == 1, timeout=12)
    page.locator('[data-cr-bp-open-guest="105"]').wait_for(timeout=2000)
    reads = len(app.server.prog_reads)
    assert reads == 3
    # completed: no further read while the dialog stays open
    page.wait_for_timeout(3500)
    assert len(app.server.prog_reads) == reads
    steps = page.evaluate("() => Object.fromEntries([...document.querySelectorAll('[data-cr-bp-step]')].map(s => [s.dataset.crBpStep, s.dataset.state]))")
    assert 'template' not in steps and set(steps.values()) == {'done'}, steps
    # the log is folded while nothing failed
    assert 'configured' in page.locator('[data-cr-bp-log]').text_content()
    assert page.locator('[data-cr-upd-note="bp-warnings"]').count() == 0


def test_runtime_a_failed_deploy_stops_the_reads_and_says_why(open_app):
    app = open_app(progress=[FAILED])
    page = _page(app)
    _deploy(page)
    page.locator('[data-cr-bp-deploy-go]').click()
    page.locator('[data-cr-bp-error]').wait_for(timeout=6000)
    assert 'storage full' in page.locator('[data-cr-bp-error]').inner_text()
    reads = len(app.server.prog_reads)
    page.wait_for_timeout(3500)
    assert len(app.server.prog_reads) == reads == 1
    assert page.locator('[data-cr-bp-step="resize"]').get_attribute('data-state') == 'failed'
    assert page.locator('[data-cr-bp-open-guest]').count() == 0


def test_runtime_closing_the_dialog_stops_the_reads(open_app):
    app = _wrapped(open_app, progress=[RUNNING])
    page = _page(app)
    _deploy(page)
    page.locator('[data-cr-bp-deploy-go]').click()
    _need(page, '[data-cr-bp-progress="d1"]', 'the progress view opens')
    assert _wait(page, lambda: len(app.server.prog_reads) >= 2, timeout=8)
    page.locator('[data-cr-bp-deploy-close]').click()
    assert _wait(page, lambda: page.locator('[data-cr-bp-progress]').count() == 0)
    reads = len(app.server.prog_reads)
    page.wait_for_timeout(3500)
    assert len(app.server.prog_reads) == reads
    # no list of deploys here: the page around it reads that
    assert _own_reads(app, '/api/blueprints/deployments') == []


def test_runtime_a_refused_deploy_stays_in_the_dialog_with_the_reason(open_app):
    app = open_app(deploy_status=403)
    page = _page(app)
    _deploy(page)
    page.locator('[data-cr-bp-deploy-go]').click()
    note = page.locator('[data-cr-upd-note="bp-deploy"]')
    note.wait_for(timeout=4000)
    assert 'tenant VMID range' in note.inner_text()
    assert page.locator('[data-cr-bp-progress]').count() == 0 and app.server.prog_reads == []


# --- the props for the page around it ---------------------------------------------------------

def test_runtime_prefill_template_opens_a_new_blueprint_of_that_image(open_app):
    app = _wrapped(open_app)
    page = _page(app)
    assert page.locator('[data-cr-bp-editor]').count() == 0
    page.evaluate("() => window.__crBpPrefill({ template_id: 'almalinux-10' })")
    _need(page, '[data-cr-bp-editor="new"]', 'prefillTemplate opens the editor for a new blueprint')
    page.locator('[data-cr-bp-input="template_id"] option[value="almalinux-10"]').wait_for(state='attached', timeout=4000)
    assert page.locator('[data-cr-bp-input="template_id"]').input_value() == 'almalinux-10'
    assert 'x86-64-v3' in page.locator('[data-cr-nc-field="bp-cpu"] [data-cr-nc-hint]').inner_text()
    page.locator('[data-cr-bp-editor-cancel]').click()
    assert _wait(page, lambda: page.locator('[data-cr-bp-editor]').count() == 0)
    # the same image again, as a new object, opens it again; a plain id works too
    page.evaluate("() => window.__crBpPrefill({ template_id: 'almalinux-10' })")
    _need(page, '[data-cr-bp-editor="new"]', 'the same image opens the editor again')
    page.locator('[data-cr-bp-editor-cancel]').click()
    assert _wait(page, lambda: page.locator('[data-cr-bp-editor]').count() == 0)
    page.evaluate("() => window.__crBpPrefill('c0ffee12')")
    _need(page, '[data-cr-bp-editor="new"]', 'a template_id string opens the editor')
    page.locator('[data-cr-bp-input="template_id"] option[value="c0ffee12"]').wait_for(state='attached', timeout=4000)
    assert page.locator('[data-cr-bp-input="template_id"]').input_value() == 'c0ffee12'
    _fill(page, 'name', 'from-the-image-row')
    page.locator('[data-cr-bp-editor-save]').click()
    assert _wait(page, lambda: page.evaluate('() => window.__crBpSaved.length') == 1)
    assert page.evaluate('() => window.__crBpSaved') == [['n7', True]]
    assert app.server.bodies['/api/blueprints'][-1]['template_id'] == 'c0ffee12'
    _no_errors(app)


# --- only in Corporate Redesigned --------------------------------------------------------------

@pytest.mark.parametrize('layout', ['corporate', 'modern'])
def test_runtime_classic_layouts_draw_the_library_without_blueprints(open_app, layout):
    app = open_app(layout=layout)
    page = _templates(app, layout)
    page.get_by_text('Debian 13 (Trixie)').first.wait_for(timeout=8000)
    page.wait_for_timeout(500)
    assert page.locator('[data-cr-bp]').count() == 0
    assert _count(app, 'GET', '/api/blueprints') == 0


# --- source ------------------------------------------------------------------------------------

def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def test_the_section_is_mounted_for_corporate_redesigned_only():
    dash = _read('web', 'src', 'dashboard.js')
    # the sub tab of the redesign draws the blueprints with the images under them (cr_images.js)
    assert not re.search(r'<CrBlueprints\b', dash)
    mounts = [m.start() for m in re.finditer(r'<CrBlueprintsTab\b', dash)]
    assert len(mounts) == 1
    head = dash[dash.rindex('{automationSubTab', 0, mounts[0]):mounts[0]]
    assert "automationSubTab === 'templates' && isCorpRedesigned && selectedCluster?.id" in head
    assert "canRead={holds('vm.create')} canWrite={can('vm.create')}" in dash
    page = _read('web', 'src', 'cr_images.js')
    assert len(re.findall(r'<CrBlueprints\b', page)) == 1
    assert 'canRead={canRead} canWrite={canWrite} nav={nav}' in page


def test_the_props_for_the_page_around_it():
    src = _read('web', 'src', 'cr_blueprints.js')
    sig = re.search(r'function CrBlueprints\(\{([^}]*)\}\)', src).group(1)
    assert [p.strip() for p in sig.split(',')] == ['cluster', 'clusters', 'authFetch', 'addToast', 'canRead', 'canWrite', 'nav',
                                                   'prefillTemplate', 'onSaved', 'onDeleted', 'onDeployed']
    page = src[src.index('function CrBlueprints'):]
    # the callbacks are optional: the mount of today passes none
    for cb in ('onSaved', 'onDeleted', 'onDeployed'):
        assert f"typeof {cb} === 'function'" in page, cb
    assert 'if (prefillId && canRead && write) openEditor(null, prefillId);' in page and '}, [prefillTemplate]);' in page


def test_windows_never_sends_what_pve_ignores():
    src = _read('web', 'src', 'cr_blueprints.js')
    body = src[src.index('function crBpBody'):src.index('function crBpCheck')]
    for part in ("ciuser: win ? '' :", "sshkeys: win ? '' :", "searchdomain: win ? '' :", 'ciupgrade: win ? true :',
                 "template_id: tpl ? '' : f.template_id", 'nics: tpl && f.keepNet ? [] :'):
        assert part in body, part


def test_every_key_is_in_all_nine_languages_ahead_of_the_pinned_chain():
    used = set(re.findall(r"'(crBp[A-Za-z]+)'", _read('web', 'src', 'cr_blueprints.js')))
    assert len(used) > 140
    src = _read('web', 'src', 'translations.js')
    starts = [(m.start(), m.group(1)) for m in re.finditer(r'^            ([a-z]{2}): \{$', src, re.M)]
    ends = [s for s, _ in starts[1:]] + [len(src)]
    blocks = {lang: src[a:b] for (a, lang), b in zip(starts, ends)}
    assert set(blocks) == {'de', 'en', 'zh', 'pl', 'fr', 'es', 'pt', 'ko', 'it'}
    for lang, block in blocks.items():
        marker = block.index('// LW Oct 2026 (#625) - the banners of a group that fails over automatically')
        for k in used:
            m = re.search(rf'^                {k}: "(.*)",$', block, re.M)
            assert m, (lang, k)
            assert m.start() < marker, (lang, k)
            assert not any(d in m.group(1) for d in DASHES), (lang, k)
            assert len(re.findall(rf'^                {k}: ', block, re.M)) == 1, (lang, k)


def test_no_crbp_key_is_left_unused():
    src = _read('web', 'src', 'translations.js')
    keys = set(re.findall(r'^                (crBp[A-Za-z]+): ', src, re.M))
    code = ''.join(_read('web', 'src', f) for f in sorted(os.listdir(os.path.join(ROOT, 'web', 'src')))
                   if f.endswith('.js') and f != 'translations.js')
    assert sorted(k for k in keys if not re.search(rf"['\"`]{k}['\"`]", code)) == []


def test_the_placeholders_survive_every_translation():
    src = _read('web', 'src', 'translations.js')
    en_block = src[src.index('            en: {'):src.index('            zh: {')]
    en = dict(re.findall(r'^                (crBp[A-Za-z]+): "(.*)",$', en_block, re.M))
    for k, v in re.findall(r'^                (crBp[A-Za-z]+): "(.*)",$', src, re.M):
        assert sorted(re.findall(r'\{[a-z]+\}', v)) == sorted(re.findall(r'\{[a-z]+\}', en[k])), (k, v)


def test_the_module_is_built_shipped_and_has_no_dash():
    src = _read('web', 'src', 'cr_blueprints.js')
    assert not any(d in src for d in DASHES)
    build = _read('web', 'Dev', 'build.sh')
    assert build.index('    cr_blueprints.js\n') < build.index('    dashboard.js\n')
    assert 'web/src/cr_blueprints.js' in json.loads(_read('version.json'))['update_files']
    # it writes only through the blueprint routes
    sends = [ln for ln in src.split('\n') if 'await crBpSend(authFetch' in ln]
    assert len(sends) == 3 and all('${API_URL}/blueprints' in ln for ln in sends), sends
    assert 'setInterval' not in src


def test_the_progress_poll_lives_only_in_the_open_progress_view():
    src = _read('web', 'src', 'cr_blueprints.js')
    assert src.count('setTimeout(tick, CR_BP_POLL)') == 1
    prog = src[src.index('function CrBpProgress'):src.index('function CrBpDeploy')]
    assert 'setTimeout(tick, CR_BP_POLL)' in prog and 'clearTimeout(timer)' in prog


def test_the_editor_grids_are_scoped_and_fold_on_a_phone():
    html = _read('web', 'index.html.original')
    sec = html[html.index('/* -- 43. blueprints above the template library (#1220)'):html.index('/* -- 14. phones')]
    for cls in ('cr-bp-grid-top', 'cr-bp-grid-hw', 'cr-bp-grid-ci', 'cr-bp-source', 'cr-bp-opts'):
        assert f'.{cls}' in sec, cls
    assert 'grid-template-columns: minmax(64px, 0.5fr) minmax(0, 1.2fr) minmax(0, 1fr) minmax(0, 1.4fr)' in sec
    assert '@media (max-width: 820px)' in sec and '@media (max-width: 520px)' in sec
