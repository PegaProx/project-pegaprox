"""Corporate Redesigned, the blueprints above the template library (#1220): the list with what each
blueprint holds, the editor and the body it sends, Edit and Delete only for the blueprints the
account may change, the deploy dialog (where to, the template the server would use or build, the
ipconfig0 of a static address) and the progress it reads while it is open.

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

CATALOG = {'templates': [
    {'id': 'debian-13', 'name': 'Debian 13 (Trixie)', 'distro': 'debian', 'version': '13', 'default_user': 'debian',
     'cores': 1, 'memory': 1024, 'disk_gb': 8},
    {'id': 'almalinux-10', 'name': 'AlmaLinux 10', 'distro': 'almalinux', 'version': '10', 'default_user': 'almalinux',
     'cores': 2, 'memory': 2048, 'disk_gb': 10, 'cpu': 'x86-64-v3'},
    {'id': 'c0ffee12', 'name': 'Company Ubuntu', 'distro': 'ubuntu', 'version': '24.04', 'default_user': 'ops',
     'cores': 2, 'memory': 2048, 'disk_gb': 20, 'custom': True},
]}


def _bp(bid, name, **kw):
    out = {'id': bid, 'name': name, 'description': '', 'template_id': 'debian-13', 'template_name': 'Debian 13 (Trixie)',
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
# the template the server would use per node: pve1 has one, pve2 builds it first
TEMPLATE = {'pve1': {'template': {'vmid': 9001, 'node': 'pve1', 'storage': 'local-lvm', 'shared': False}, 'build_needed': False},
            'pve2': {'template': None, 'build_needed': True}}


class _BpServer(_GuardServer):
    """The guard fake with the blueprint routes, the library catalog and the
    node reads the dialogs make. progress: the rows a deployment read hands out in turn."""

    def __init__(self, blueprints=None, progress=None, deploy_status=202, **kw):
        extra = kw.pop('extra', {}) or {}
        reads = {('GET', '/api/templates/catalog'): (200, CATALOG),
                 ('GET', '/api/clusters/c1/templates/deployments'): (200, {'deployments': []}),
                 ('GET', '/api/clusters/c1/templates/existing'): (200, {'templates': []}),
                 ('GET', '/api/clusters/c1/nodes'): (200, NODES),
                 ('GET', '/api/clusters/c1/nextid'): (200, {'vmid': 105}),
                 ('GET', '/api/clusters/c1/nodes/pve1/network'): (200, NET)}
        reads.update({('GET', f'/api/clusters/c1/nodes/{n}/storage'): (200, s) for n, s in STORES.items()})
        reads.update(extra)
        super().__init__(extra=reads, **kw)
        self.bps = copy.deepcopy([WEB, DB, OTHER, GONE] if blueprints is None else blueprints)
        self.progress = list(progress or [])
        self.prog_reads = []
        self.deploy_status = deploy_status
        self.recent = copy.deepcopy(RECENT)

    def bp_route(self, method, path, body, url):
        if path == '/api/blueprints':
            if method == 'GET':
                return 200, {'blueprints': self.bps}
            if not str(body.get('name') or '').strip():
                return 400, {'error': 'Enter a name for the blueprint', 'field': 'name'}
            if any(b['name'] == body['name'] for b in self.bps):
                return 409, {'error': f"A blueprint named '{body['name']}' exists already", 'field': 'name'}
            tpl = next((x for x in CATALOG['templates'] if x['id'] == body.get('template_id')), None)
            new = _bp(f'n{len(self.bps) + 1}', body['name'], **{k: v for k, v in body.items() if k != 'name'})
            new.update(template_name=tpl['name'] if tpl else '', template_missing=tpl is None)
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
                if self.deploy_status != 202:
                    return self.deploy_status, {'error': 'The tenant VMID range is 200-299'}
                return 202, {'deployment_id': 'd1', 'vmid': body.get('vmid', 105), 'name': body.get('name'), 'status': 'queued',
                             'build_needed': body.get('node') == 'pve2'}
            if method == 'DELETE':
                self.bps.remove(have)
                return 200, {'success': True}
            if method == 'PUT':
                have.update(body, updated_at='2026-11-08T10:00:00')
                return 200, {'blueprint': have}
        m = re.fullmatch(r'/api/clusters/c1/blueprints/([^/]+)/template', path)
        if m:
            node = (re.search(r'[?&]node=([^&]+)', url) or [None, ''])[1]
            return 200, TEMPLATE.get(node, {'template': None, 'build_needed': True})
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

    def _open(layout=LAYOUT, viewport=(1600, 1000), **kw):
        server = _BpServer(bundle=BUNDLE, layout=layout, **kw)
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
    """Automation > Cloud-Init Template Library of Testi."""
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
    page.locator('button', has_text=TPL_TAB).first.click()
    return page


def _page(app):
    page = _templates(app)
    _need(page, '[data-cr-bp]', 'the blueprints are on the template sub tab of Corporate Redesigned')
    _need(page, '[data-cr-bp-row]', 'the blueprint list is filled')
    return page


def _count(app, method, path):
    return len([c for c in app.server.calls[getattr(app, 'mark', 0):] if c == (method, path)])


def _no_errors(app):
    assert [e for e in app.errors if 'not mocked' not in e] == [], app.errors


def _row(page, bid):
    return page.locator('[data-cr-table="bp-list"] tbody tr', has=page.locator(f'[data-cr-bp-row="{bid}"]'))


# --- the list ----------------------------------------------------------------------------------

def test_runtime_the_list_shows_each_blueprint_and_reads_once(open_app):
    app = open_app()
    page = _page(app)
    page.wait_for_timeout(400)
    rows = page.evaluate("""() => [...document.querySelectorAll('[data-cr-bp-row]')].map(e => e.dataset.crBpRow)""")
    assert sorted(rows) == ['b1', 'b2', 'b3', 'b4']
    web = _row(page, 'b1').inner_text()
    assert 'web-small' in web and 'Small web front end' in web and 'Debian 13 (Trixie)' in web
    assert '2 vCPU · 2 GB · 20 GB' in web and 'DHCP' in web
    db = _row(page, 'b2').inner_text()
    assert '4 vCPU · 8 GB · image size' in db and 'Static' in db
    assert _row(page, 'b2').locator('td').nth(3).inner_text().strip() == '2'
    # an image the library dropped: said, and no deploy
    assert _row(page, 'b4').locator('[data-cr-bp-image="missing"]').count() == 1
    assert page.locator('[data-cr-bp-deploy="b4"]').is_disabled()
    # one read of the list and one of the recent deploys of this cluster, nothing per row
    assert _count(app, 'GET', '/api/blueprints') == 1
    assert _count(app, 'GET', '/api/blueprints/deployments') == 1
    assert any('cluster_id=c1' in u for u in app.server.urls if '/api/blueprints/deployments' in u)
    # no progress read without an open deploy
    assert app.server.prog_reads == []
    _no_errors(app)


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


def test_runtime_the_recent_deploys_of_this_cluster(open_app):
    page = _page(open_app())
    table = page.locator('[data-cr-table="bp-recent"]')
    table.wait_for(timeout=4000)
    text = table.inner_text()
    assert 'web-small' in text and 'web-01 (120)' in text and 'db-01 (121)' in text
    assert page.locator('[data-cr-table="bp-recent"] [data-cr-bp-state="completed"]').count() == 1
    assert page.locator('[data-cr-table="bp-recent"] [data-cr-bp-state="failed"]').count() == 1
    # a completed guest is a link, a failed one is not
    assert page.locator('[data-cr-bp-guest="120"]').count() == 1 and page.locator('[data-cr-bp-guest="121"]').count() == 0


# --- the editor --------------------------------------------------------------------------------

def _fill(page, key, value):
    page.locator(f'[data-cr-bp-input="{key}"]').fill(value)


def test_runtime_create_sends_the_body_the_server_takes(open_app):
    app = open_app()
    page = _page(app)
    page.locator('[data-cr-bp-new]').click()
    _need(page, '[data-cr-bp-editor="new"]', 'New blueprint opens the editor')
    # the image list is the library's, read when the editor opens
    page.locator('[data-cr-bp-input="template_id"] option[value="c0ffee12"]').wait_for(state='attached', timeout=4000)
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
    assert body == {'name': 'app-tier', 'description': '', 'template_id': 'c0ffee12', 'cores': 4, 'memory': 6144, 'disk_gb': 40,
                    'cpu': '', 'nics': [{'bridge': 'vmbr0', 'vlan': 30, 'model': 'virtio', 'firewall': False},
                                        {'bridge': 'vmbr1', 'vlan': None, 'model': 'e1000', 'firewall': True}],
                    'ciuser': 'ops', 'sshkeys': 'ssh-ed25519 AAAAC3Nza key1@lab\necdsa-sha2-nistp256 AAAAE2Vj key2@lab',
                    'ip_mode': 'static', 'nameserver': '10.0.0.53', 'searchdomain': '', 'ciupgrade': False,
                    'tags': ['app', 'prod'], 'start': False}
    assert _wait(page, lambda: page.locator('[data-cr-bp-editor]').count() == 0)
    assert _wait(page, lambda: page.locator('[data-cr-bp-row="n5"]').count() == 1)


def test_runtime_memory_in_mb_and_the_checks_before_saving(open_app):
    app = open_app()
    page = _page(app)
    page.locator('[data-cr-bp-new]').click()
    _need(page, '[data-cr-bp-editor="new"]', 'the editor opens')
    page.locator('[data-cr-bp-input="memUnit"]').select_option('MB')
    _fill(page, 'memory', '32')
    _fill(page, 'cores', '0')
    page.locator('[data-cr-bp-nic-bridge="0"]').fill('vmbr 0')
    page.locator('[data-cr-bp-nic-vlan="0"]').fill('5000')
    page.locator('[data-cr-bp-editor-save]').click()
    page.wait_for_timeout(300)
    assert ('POST', '/api/blueprints') not in app.server.calls
    errs = page.evaluate("""() => Object.fromEntries([...document.querySelectorAll('[data-cr-bp-editor] [data-cr-nc-field]')]
        .filter(f => f.querySelector('[data-cr-nc-hint="error"]')).map(f => [f.dataset.crNcField, f.querySelector('[data-cr-nc-hint]').textContent]))""")
    assert set(errs) == {'bp-name', 'bp-template_id', 'bp-cores', 'bp-memory', 'bp-nic0-bridge', 'bp-nic0-vlan'}, errs
    assert '64' in errs['bp-memory'] and '4194304' in errs['bp-memory']
    # fixed, the memory goes out in MB as typed
    _fill(page, 'name', 'tiny')
    page.locator('[data-cr-bp-input="template_id"]').select_option('debian-13')
    _fill(page, 'cores', '1')
    _fill(page, 'memory', '512')
    page.locator('[data-cr-bp-nic-bridge="0"]').fill('vmbr0')
    page.locator('[data-cr-bp-nic-vlan="0"]').fill('')
    page.locator('[data-cr-bp-editor-save]').click()
    assert _wait(page, lambda: ('POST', '/api/blueprints') in app.server.calls)
    assert app.server.bodies['/api/blueprints'][-1]['memory'] == 512


def test_runtime_a_refusal_of_the_server_stands_at_its_field(open_app):
    app = open_app()
    page = _page(app)
    page.locator('[data-cr-bp-new]').click()
    _need(page, '[data-cr-bp-editor="new"]', 'the editor opens')
    page.locator('[data-cr-bp-input="template_id"] option[value="debian-13"]').wait_for(state='attached', timeout=4000)
    _fill(page, 'name', 'web-small')
    page.locator('[data-cr-bp-input="template_id"]').select_option('debian-13')
    page.locator('[data-cr-bp-editor-save]').click()
    hint = page.locator('[data-cr-nc-field="bp-name"] [data-cr-nc-hint="error"]')
    hint.wait_for(timeout=4000)
    assert "exists already" in hint.inner_text()
    assert page.locator('[data-cr-bp-editor]').count() == 1


def test_runtime_edit_fills_the_form_and_puts_the_whole_object(open_app):
    app = open_app()
    page = _page(app)
    page.locator('[data-cr-bp-edit="b2"]').click()
    _need(page, '[data-cr-bp-editor="b2"]', 'Edit opens the editor of that blueprint')
    assert page.locator('[data-cr-bp-input="name"]').input_value() == 'db-static'
    assert page.locator('[data-cr-bp-input="memory"]').input_value() == '8'
    assert page.locator('[data-cr-bp-input="memUnit"]').input_value() == 'GB'
    assert page.locator('[data-cr-bp-nic-vlan="0"]').input_value() == '20'
    assert page.locator('[data-cr-bp-nic-model="1"]').input_value() == 'e1000'
    # the bridges of a node of this cluster are suggested, read once
    assert page.evaluate("() => [...document.querySelectorAll('#cr-bp-bridges option')].map(o => o.value)") == ['vmbr0', 'vmbr1']
    _fill(page, 'cores', '8')
    page.locator('[data-cr-bp-editor-save]').click()
    assert _wait(page, lambda: ('PUT', '/api/blueprints/b2') in app.server.calls)
    body = app.server.bodies['/api/blueprints/b2'][-1]
    assert body['cores'] == 8 and body['memory'] == 8192 and body['disk_gb'] == 0 and body['ip_mode'] == 'static'
    assert body['nics'][1] == {'bridge': 'vmbr1', 'vlan': None, 'model': 'e1000', 'firewall': False}
    assert _count(app, 'GET', '/api/clusters/c1/nodes/pve1/network') == 1


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
    assert any('node=pve2' in u for u in app.server.urls if u.endswith('template?node=pve2') or 'template?node=pve2' in u)
    # no static address for a DHCP blueprint
    assert page.locator('[data-cr-bp-dep="ip"]').count() == 0
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
    assert 'cipassword' not in body


def test_runtime_an_ipv6_address_takes_ip6_and_gw6(open_app):
    app = open_app(progress=[DONE])
    page = _page(app)
    _deploy(page, 'b2')
    page.locator('[data-cr-bp-dep="ip"]').fill('2001:db8::5/64')
    page.locator('[data-cr-bp-deploy-go]').click()
    assert _wait(page, lambda: ('POST', '/api/blueprints/b2/deploy') in app.server.calls)
    assert app.server.bodies['/api/blueprints/b2/deploy'][-1]['ipconfig0'] == 'ip6=2001:db8::5/64'


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
    app = open_app(progress=[RUNNING])
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
    # the recent deploys are read again on close
    assert _count(app, 'GET', '/api/blueprints/deployments') >= 2


def test_runtime_a_refused_deploy_stays_in_the_dialog_with_the_reason(open_app):
    app = open_app(deploy_status=403)
    page = _page(app)
    _deploy(page)
    page.locator('[data-cr-bp-deploy-go]').click()
    note = page.locator('[data-cr-upd-note="bp-deploy"]')
    note.wait_for(timeout=4000)
    assert 'tenant VMID range' in note.inner_text()
    assert page.locator('[data-cr-bp-progress]').count() == 0 and app.server.prog_reads == []


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
    mounts = [m.start() for m in re.finditer(r'<CrBlueprints\b', dash)]
    assert len(mounts) == 1
    head = dash[dash.rindex('{automationSubTab', 0, mounts[0]):mounts[0]]
    assert "automationSubTab === 'templates' && isCorpRedesigned && selectedCluster?.id" in head
    assert "canRead={holds('vm.create')} canWrite={can('vm.create')}" in dash


def test_every_key_is_in_all_nine_languages_ahead_of_the_pinned_chain():
    used = set(re.findall(r"'(crBp[A-Za-z]+)'", _read('web', 'src', 'cr_blueprints.js')))
    assert len(used) > 100
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
