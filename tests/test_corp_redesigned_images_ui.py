"""Corporate Redesigned, the Blueprints & Images sub tab (#1220): the images of the template library
as a table with what this cluster has of each and how many blueprints name it, the library's own
buttons (build a template here, add a custom image, delete one) for administrators only, New
blueprint handing the image to the blueprint editor, one list of the recent deploys and template
builds for this cluster or all clusters, and the ways there (the Resources button, the cluster menu
and Ctrl+K).

Classic Corporate, Modern and Cloud keep the Cloud-Init Template Library with its cards. Runtime
tests drive the built bundle in headless Chromium against the blueprint fake of
tests/test_corp_redesigned_blueprints_ui.py with the library routes as templates_lib.py answers them.
The counterproof runs this file against an older bundle: PEGAPROX_CR_BUNDLE=<path to index.html>.
LW Nov 2026
"""
import copy
import json
import os
import re
import time

import pytest

from test_corp_redesigned_blueprints_ui import (CATALOG, DB, GONE, NODES, OTHER, RECENT, STORES, WEB, _BpServer, _bp,
                                                _count, _need, _no_errors, _wait)
from test_corp_redesigned_guard_ui import DETERMINISTIC, _GuardApp
from test_ha_ui import CLUSTER

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LAYOUT = 'corporate-redesigned'
_BUNDLE_FILE = os.environ.get('PEGAPROX_CR_BUNDLE')
BUNDLE = open(_BUNDLE_FILE, encoding='utf-8').read() if _BUNDLE_FILE else None
DASHES = (chr(0x2014), chr(0x2013))
CR_TAB = 'Blueprints & Images'
TPL_TAB = 'Cloud-Init Template Library'

UBUNTU = {'id': 'ubuntu-2404', 'name': 'Ubuntu 24.04 LTS (Noble)', 'distro': 'ubuntu', 'version': '24.04', 'default_user': 'ubuntu',
          'cores': 2, 'memory': 2048, 'disk_gb': 10, 'description': 'Previous LTS - broad compatibility.', 'tags': ['lts', 'general']}
# the catalog of the blueprint tests with descriptions and tags, as templates_lib.catalog answers it
IMAGES = [dict(CATALOG['templates'][0], description='Lean Debian generic-cloud image.', tags=['lean', 'recommended']),
          dict(CATALOG['templates'][1], description='RHEL-compatible.', tags=['rhel']),
          UBUNTU,
          dict(CATALOG['templates'][2], description='Our hardened base', tags=['internal', 'custom'], created_by='admin',
               image_url='https://mirror.example/company.qcow2')]
# the library's builds on c1, newest first: AlmaLinux on its way, Debian done (9001 is still there,
# 8999 is gone), the company image failed; x9 is the build the db-static deploy of RECENT started
BUILDS = [
    {'id': 't-run', 'cluster_id': 'c1', 'node': 'pve2', 'template_id': 'almalinux-10', 'template_name': 'AlmaLinux 10',
     'vmid': 9002, 'storage': 'local-zfs', 'status': 'running', 'progress': 40, 'error': '', 'started_by': 'admin',
     'started_at': '2026-11-08T09:10:00.000001', 'finished_at': None},
    {'id': 'x9', 'cluster_id': 'c1', 'node': 'pve2', 'template_id': 'almalinux-10', 'template_name': 'AlmaLinux 10',
     'vmid': 9005, 'storage': 'local-zfs', 'status': 'failed', 'progress': 20, 'error': 'download failed (rc=8)',
     'started_by': 'admin', 'started_at': '2026-11-08T08:50:01', 'finished_at': '2026-11-08T08:51:00'},
    {'id': 't-ok', 'cluster_id': 'c1', 'node': 'pve1', 'template_id': 'debian-13', 'template_name': 'Debian 13 (Trixie)',
     'vmid': 9001, 'storage': 'local-lvm', 'status': 'completed', 'progress': 100, 'error': '', 'started_by': 'admin',
     'started_at': '2026-11-08T08:30:00', 'finished_at': '2026-11-08T08:32:00'},
    {'id': 't-bad', 'cluster_id': 'c1', 'node': 'pve1', 'template_id': 'c0ffee12', 'template_name': 'Company Ubuntu',
     'vmid': 9003, 'storage': 'local-lvm', 'status': 'failed', 'progress': 10, 'error': 'download failed (rc=4)',
     'started_by': 'ops', 'started_at': '2026-11-08T07:00:00', 'finished_at': '2026-11-08T07:00:30'},
    {'id': 't-old', 'cluster_id': 'c1', 'node': 'pve1', 'template_id': 'debian-13', 'template_name': 'Debian 13 (Trixie)',
     'vmid': 8999, 'storage': 'local-lvm', 'status': 'completed', 'progress': 100, 'error': '', 'started_by': 'admin',
     'started_at': '2026-10-01T08:00:00', 'finished_at': '2026-10-01T08:02:00'},
]
# nothing on its way: no read again
STILL = [dict(b, status='failed', error='stopped') if b['status'] == 'running' else b for b in BUILDS]
EXISTING = [{'vmid': 9001, 'name': 'tpl-debian-13', 'node': 'pve1', 'maxdisk': 8589934592, 'maxmem': 1073741824},
            {'vmid': 7000, 'name': 'by-hand', 'node': 'pve1', 'maxdisk': 0, 'maxmem': 0}]
# All clusters: a second Proxmox VE cluster, one whose list fails and an XCP-ng pool that has none
C2 = dict(CLUSTER, id='c2', name='Lab', display_name='Lab', host='10.0.1.1')
C3 = dict(CLUSTER, id='c3', name='Edge', display_name='Edge', host='10.0.2.1')
X1 = dict(CLUSTER, id='x1', name='Pool1', display_name='Pool1', host='10.0.3.1', cluster_type='xcpng')
C2_BUILDS = [{'id': 'l1', 'cluster_id': 'c2', 'node': 'lab1', 'template_id': 'debian-13', 'template_name': 'Debian 13 (Trixie)',
              'vmid': 9100, 'storage': 'ceph', 'status': 'completed', 'progress': 100, 'error': '', 'started_by': 'ops',
              'started_at': '2026-11-08T09:30:00', 'finished_at': '2026-11-08T09:32:00'}]
ALL_DEPLOYS = RECENT + [{'id': 'r3', 'blueprint_id': 'b1', 'blueprint_name': 'web-small', 'cluster_id': 'c2', 'node': 'lab1',
                         'vmid': 140, 'name': 'web-lab', 'template_vmid': 9100, 'build_dep_id': '', 'status': 'running',
                         'step': 'clone', 'progress': 50, 'error': '', 'started_by': 'ops',
                         'started_at': '2026-11-08T09:40:00', 'finished_at': None}]


class _ImgServer(_BpServer):
    """The blueprint fake with the library routes of templates_lib.py: the catalog and its custom
    images, the templates and builds of c1 (builds may be a list of answers handed out in turn),
    the build and the custom image writes, and the reads of All clusters."""

    def __init__(self, images=None, builds=None, existing=None, build_status=200, **kw):
        super().__init__(**kw)
        self.images = copy.deepcopy(IMAGES if images is None else images)
        seq = builds if builds is not None else BUILDS
        self.build_seq = [copy.deepcopy(b) for b in (seq if seq and isinstance(seq[0], list) else [seq])]
        self.existing = copy.deepcopy(EXISTING if existing is None else existing)
        self.build_status = build_status
        self.build_reads = []

    def img_route(self, method, path, body, url):
        if path == '/api/templates/catalog':
            return 200, {'templates': self.images}
        if path == '/api/templates/custom' and method == 'POST':
            new = dict(body, id='custom-new-1', custom=True, tags=list(body.get('tags') or []) + ['custom'])
            self.images.append(new)
            return 200, {'template': new}
        m = re.fullmatch(r'/api/templates/custom/([^/]+)', path)
        if m and method == 'DELETE':
            self.images = [i for i in self.images if i['id'] != m.group(1)]
            return 200, {'ok': True}
        if path == '/api/clusters/c1/templates/existing':
            return 200, {'templates': self.existing}
        if path == '/api/clusters/c1/templates/deployments':
            self.build_reads.append(time.time())
            rows = self.build_seq.pop(0) if len(self.build_seq) > 1 else self.build_seq[0]
            return 200, {'deployments': rows}
        if path == '/api/clusters/c2/templates/deployments':
            return 200, {'deployments': C2_BUILDS}
        if path == '/api/clusters/c3/templates/deployments':
            return 500, {'error': 'internal error'}
        if path == '/api/clusters/c1/templates/deploy' and method == 'POST':
            if self.build_status != 200:
                return self.build_status, {'error': 'The tenant VMID range is 200-299'}
            return 200, {'deployment_id': 'nb1', 'vmid': body.get('vmid', 9010), 'name': body.get('name', 'tpl-x'), 'status': 'queued',
                         'quota_warning': 'cores at 90%'}
        if path == '/api/blueprints/deployments' and 'cluster_id=' not in url:
            return 200, {'deployments': ALL_DEPLOYS}
        return None

    def handle(self, route):
        req = route.request
        path = re.sub(r'^https?://[^/]+', '', req.url).split('?')[0]
        body = json.loads(req.post_data) if req.post_data else {}
        out = self.img_route(req.method, path, body, req.url)
        if out is None:
            return super().handle(route)
        self.calls.append((req.method, path))
        self.urls.append(req.url)
        if req.method != 'GET':
            self.bodies.setdefault(path, []).append(body)
        return route.fulfill(status=out[0], body=json.dumps(out[1]), headers={'Content-Type': 'application/json'})


# the bundle with a probe around CrBlueprints: every render notes the prefillTemplate it was given,
# so New blueprint is checked on this side of the contract whatever the blueprint editor does with it
_PROBE = ('function CrBlueprints(__props) { (window.__bpPrefill = window.__bpPrefill || []).push(__props && __props.prefillTemplate); '
          'return CrBlueprintsInner(__props); }\n        function CrBlueprintsInner(')


def _bundle(probe=False):
    if not probe:
        return BUNDLE
    src = BUNDLE if BUNDLE is not None else open(os.path.join(ROOT, 'web', 'index.html'), encoding='utf-8').read()
    assert src.count('function CrBlueprints(') == 1
    return src.replace('function CrBlueprints(', _PROBE)


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

    def _open(layout=LAYOUT, viewport=(1600, 1000), probe=False, clusters=None, **kw):
        server = _ImgServer(bundle=_bundle(probe), layout=layout, **kw)
        if clusters is not None:
            server.clusters = list(clusters)
        app = _GuardApp(browser, server, viewport=viewport)
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.close()


def _cluster(app, layout=LAYOUT):
    page = app.page
    if layout == 'modern':
        page.get_by_text('Testi').first.click()
    else:
        page.locator('.corp-tree-item', has_text='Testi').first.click()
    return page


def _templates(app, layout=LAYOUT):
    """Automation > Blueprints & Images (Cloud-Init Template Library outside the redesign) of Testi."""
    page = _cluster(app, layout)
    if layout == LAYOUT:
        page.locator('[data-cr-tab="automation"]').click()
    else:
        page.locator('button', has_text=re.compile(r'^\s*Automation\s*$')).first.click()
    app.mark = len(app.server.calls)
    page.locator('button', has_text=CR_TAB if layout == LAYOUT else TPL_TAB).first.click()
    return page


def _page(app):
    page = _templates(app)
    _need(page, '[data-cr-img]', 'the images are on the Blueprints & Images sub tab')
    _need(page, '[data-cr-img-row]', 'the image table is filled')
    return page


def _here(page):
    return page.evaluate("""() => Object.fromEntries([...document.querySelectorAll('[data-cr-table="img-list"] tbody tr')]
        .filter(tr => tr.querySelector('[data-cr-img-row]'))
        .map(tr => [tr.querySelector('[data-cr-img-row]').dataset.crImgRow, tr.querySelector('[data-cr-img-here]').dataset.crImgHere]))""")


def _img_row(page, iid):
    return page.locator('[data-cr-table="img-list"] tbody tr', has=page.locator(f'[data-cr-img-row="{iid}"]'))


def _recent(page):
    return page.evaluate("""() => [...document.querySelectorAll('[data-cr-table^="img-recent"] tbody tr')]
        .filter(tr => tr.querySelector('[data-cr-img-kind]'))
        .map(tr => [tr.querySelector('[data-cr-img-kind]').dataset.crImgKind, tr.innerText.replace(/\\s+/g, ' ').trim()])""")


# --- the images --------------------------------------------------------------------------------

def test_runtime_the_sub_tab_draws_the_images_as_a_table(open_app):
    app = open_app(builds=STILL)
    page = _page(app)
    assert page.locator('button', has_text=CR_TAB).count() == 1
    assert page.locator('button', has_text=TPL_TAB).count() == 0
    # the cards of the classic library are not drawn in the redesign
    assert page.get_by_text('Curated catalog of cloud images').count() == 0
    rows = page.evaluate("() => [...document.querySelectorAll('[data-cr-img-row]')].map(e => e.dataset.crImgRow)")
    assert rows == ['debian-13', 'almalinux-10', 'ubuntu-2404', 'c0ffee12']
    deb = _img_row(page, 'debian-13').inner_text()
    assert 'Debian 13 (Trixie)' in deb and 'Lean Debian generic-cloud image.' in deb
    assert '1 vCPU · 1 GB · 8 GB' in deb and 'lean' in deb and 'recommended' in deb
    # the default user stands under the hardware
    assert _img_row(page, 'debian-13').locator('[data-cr-img-user="debian"]').inner_text() == 'user debian'
    # a custom image says so once, its "custom" tag is not repeated among the tags
    co = _img_row(page, 'c0ffee12')
    assert co.locator('[data-cr-img-custom]').count() == 1 and 'internal' in co.inner_text()
    assert co.locator('.cr-img-tags').inner_text().split() == ['internal']
    assert _img_row(page, 'ubuntu-2404').locator('[data-cr-img-custom]').count() == 0
    # the blueprints that name each image (WEB and OTHER name Debian, DB AlmaLinux)
    used = page.evaluate("""() => Object.fromEntries([...document.querySelectorAll('[data-cr-table="img-list"] tbody tr')]
        .filter(tr => tr.querySelector('[data-cr-img-row]'))
        .map(tr => [tr.querySelector('[data-cr-img-row]').dataset.crImgRow, tr.querySelector('[data-cr-img-used]').dataset.crImgUsed]))""")
    assert used == {'debian-13': '2', 'almalinux-10': '1', 'ubuntu-2404': '0', 'c0ffee12': '0'}
    page.wait_for_timeout(400)
    # one read each: the blueprint list and the deploys of this cluster are shared with the blueprints above
    for path in ('/api/blueprints', '/api/templates/catalog', '/api/clusters/c1/templates/existing',
                 '/api/clusters/c1/templates/deployments', '/api/blueprints/deployments'):
        assert _count(app, 'GET', path) == 1, path
    _no_errors(app)


def test_runtime_on_this_cluster_says_what_the_library_built_here(open_app):
    app = open_app(builds=STILL)
    page = _page(app)
    assert _here(page) == {'debian-13': 'present', 'almalinux-10': 'failed', 'ubuntu-2404': 'none', 'c0ffee12': 'failed'}
    # the template of a finished build that is still there; 8999 is gone, 7000 was made by hand
    cell = _img_row(page, 'debian-13').locator('[data-cr-img-here]')
    assert cell.inner_text().strip() == 'Template 9001 on pve1'
    assert _img_row(page, 'c0ffee12').locator('[data-cr-img-here]').get_attribute('title') == 'download failed (rc=4)'
    assert 'first blueprint deploy builds one' in _img_row(page, 'ubuntu-2404').locator('[data-cr-img-here]').get_attribute('title')


def test_runtime_a_build_on_its_way_is_read_until_it_ends(open_app):
    done = [dict(b, status='completed', progress=100) if b['id'] == 't-run' else b for b in BUILDS]
    app = open_app(builds=[BUILDS, [dict(b, progress=80) if b['id'] == 't-run' else b for b in BUILDS], done])
    page = _page(app)
    cell = _img_row(page, 'almalinux-10').locator('[data-cr-img-here]')
    assert cell.get_attribute('data-cr-img-here') == 'building'
    assert 'Building on pve2: 40%' in cell.inner_text()
    assert _wait(page, lambda: 'Building on pve2: 80%' in cell.inner_text(), timeout=8)
    # the template turns up in the cluster's list a moment after the build
    app.server.existing.append({'vmid': 9002, 'name': 'tpl-almalinux-10', 'node': 'pve2'})
    assert _wait(page, lambda: cell.get_attribute('data-cr-img-here') == 'present', timeout=12)
    assert cell.inner_text().strip() == 'Template 9002 on pve2'
    # one more read after the last run ended, then none
    reads = len(app.server.build_reads)
    page.wait_for_timeout(5000)
    assert len(app.server.build_reads) <= reads + 1
    settled = len(app.server.build_reads)
    page.wait_for_timeout(4800)
    assert len(app.server.build_reads) == settled


def test_runtime_no_read_again_while_nothing_runs(open_app):
    app = open_app(builds=STILL)
    page = _page(app)
    page.wait_for_timeout(5000)
    assert len(app.server.build_reads) == 1


def test_runtime_new_blueprint_hands_the_image_to_the_blueprints(open_app):
    app = open_app(probe=True, builds=STILL)
    page = _page(app)
    page.evaluate('() => { window.__bpPrefill = []; }')
    page.locator('[data-cr-img-new="almalinux-10"]').click()
    assert _wait(page, lambda: page.evaluate('() => window.__bpPrefill.slice(-1)[0]') == '')
    seen = page.evaluate('() => window.__bpPrefill')
    assert 'almalinux-10' in seen and seen.index('almalinux-10') < len(seen) - 1, seen
    # cleared once handed over, so the same image goes over again
    page.keyboard.press('Escape')
    page.evaluate('() => { window.__bpPrefill = []; }')
    page.locator('[data-cr-img-new="almalinux-10"]').click()
    assert _wait(page, lambda: 'almalinux-10' in page.evaluate('() => window.__bpPrefill'))


def test_runtime_new_blueprint_opens_the_editor_with_the_image(open_app):
    src = open(os.path.join(ROOT, 'web', 'src', 'cr_blueprints.js'), encoding='utf-8').read()
    if 'prefillTemplate' not in src:
        pytest.skip('cr_blueprints.js takes no prefillTemplate yet (the blueprint editor side of #1220)')
    page = _page(open_app())
    page.locator('[data-cr-img-new="almalinux-10"]').click()
    _need(page, '[data-cr-bp-editor="new"]', 'New blueprint of an image opens the blueprint editor')
    page.locator('[data-cr-bp-input="template_id"] option[value="almalinux-10"]').wait_for(state='attached', timeout=4000)
    assert page.locator('[data-cr-bp-input="template_id"]').input_value() == 'almalinux-10'


# --- the library's buttons ---------------------------------------------------------------------

def _build(page, iid='debian-13'):
    page.locator(f'[data-cr-img-build="{iid}"]').click()
    _need(page, f'[data-cr-img-build-form="{iid}"]', 'Build template here opens its dialog')
    page.locator('[data-cr-img-b="storage"] option[value="local-lvm"]').wait_for(state='attached', timeout=4000)


def test_runtime_build_template_here_sends_the_body_of_the_classic_dialog(open_app):
    app = open_app(builds=STILL)
    page = _page(app)
    _build(page)
    # online nodes, the storages of the node that take disk images
    assert page.evaluate("() => [...document.querySelectorAll('[data-cr-img-b=\"node\"] option')].map(o => o.value)") == ['pve1', 'pve2']
    assert page.evaluate("() => [...document.querySelectorAll('[data-cr-img-b=\"storage\"] option')].map(o => o.value)") == ['local-lvm', 'ceph']
    assert page.locator('[data-cr-img-b="name"]').get_attribute('placeholder') == 'tpl-debian-13'
    page.locator('[data-cr-img-b="vmid"]').fill('42')
    page.locator('[data-cr-img-b="name"]').fill('tpl deb')
    page.locator('[data-cr-img-build-go]').click()
    page.wait_for_timeout(300)
    assert ('POST', '/api/clusters/c1/templates/deploy') not in app.server.calls
    errs = page.evaluate("""() => [...document.querySelectorAll('[data-cr-img-build-form] [data-cr-nc-field]')]
        .filter(f => f.querySelector('[data-cr-nc-hint="error"]')).map(f => f.dataset.crNcField).sort()""")
    assert errs == ['img-name', 'img-vmid'], errs
    page.locator('[data-cr-img-b="node"]').select_option('pve2')
    page.locator('[data-cr-img-b="storage"] option[value="local-zfs"]').wait_for(state='attached', timeout=4000)
    page.locator('[data-cr-img-b="vmid"]').fill('9100')
    page.locator('[data-cr-img-b="name"]').fill('tpl-deb13')
    reads = _count(app, 'GET', '/api/clusters/c1/templates/deployments')
    page.locator('[data-cr-img-build-go]').click()
    assert _wait(page, lambda: ('POST', '/api/clusters/c1/templates/deploy') in app.server.calls)
    assert app.server.bodies['/api/clusters/c1/templates/deploy'][-1] == {
        'template_id': 'debian-13', 'node': 'pve2', 'storage': 'local-zfs', 'vmid': 9100, 'name': 'tpl-deb13'}
    assert _wait(page, lambda: page.locator('[data-cr-img-build-form]').count() == 0)
    # the builds are read again, the start and the quota say so
    assert _wait(page, lambda: _count(app, 'GET', '/api/clusters/c1/templates/deployments') > reads)
    assert page.get_by_text('Template build started').count() >= 1
    assert page.get_by_text('Quota: cores at 90%').count() >= 1


def test_runtime_an_empty_vmid_and_name_are_left_to_the_server(open_app):
    app = open_app(builds=STILL)
    page = _page(app)
    _build(page, 'ubuntu-2404')
    page.locator('[data-cr-img-build-go]').click()
    assert _wait(page, lambda: ('POST', '/api/clusters/c1/templates/deploy') in app.server.calls)
    assert app.server.bodies['/api/clusters/c1/templates/deploy'][-1] == {'template_id': 'ubuntu-2404', 'node': 'pve1', 'storage': 'local-lvm'}


def test_runtime_a_refused_build_stays_in_the_dialog(open_app):
    app = open_app(builds=STILL, build_status=403)
    page = _page(app)
    _build(page)
    page.locator('[data-cr-img-build-go]').click()
    note = page.locator('[data-cr-upd-note="img-build"]')
    note.wait_for(timeout=4000)
    assert 'tenant VMID range' in note.inner_text() and 'HTTP 403' in note.inner_text()
    assert page.locator('[data-cr-img-build-form]').count() == 1


def test_runtime_add_custom_image_checks_and_sends_the_classic_body(open_app):
    app = open_app(builds=STILL)
    page = _page(app)
    page.locator('[data-cr-img-add]').click()
    _need(page, '[data-cr-img-add-form]', 'Add custom image opens its dialog')
    page.locator('[data-cr-img-a="image_url"]').fill('ftp://mirror/img')
    page.locator('[data-cr-img-a="cores"]').fill('0')
    page.locator('[data-cr-img-add-go]').click()
    page.wait_for_timeout(300)
    assert ('POST', '/api/templates/custom') not in app.server.calls
    errs = page.evaluate("""() => [...document.querySelectorAll('[data-cr-img-add-form] [data-cr-nc-field]')]
        .filter(f => f.querySelector('[data-cr-nc-hint="error"]')).map(f => f.dataset.crNcField).sort()""")
    assert errs == ['img-cores', 'img-image_url', 'img-name'], errs
    for k, v in (('name', ' Rocky 9 GenericCloud '), ('image_url', 'https://dl.rockylinux.org/rocky9.qcow2'), ('cores', '4'),
                 ('memory', '4096'), ('disk_gb', '20'), ('tags', 'rhel, ,lab'), ('default_user', 'rocky')):
        page.locator(f'[data-cr-img-a="{k}"]').fill(v)
    reads = _count(app, 'GET', '/api/templates/catalog')
    page.locator('[data-cr-img-add-go]').click()
    assert _wait(page, lambda: ('POST', '/api/templates/custom') in app.server.calls)
    assert app.server.bodies['/api/templates/custom'][-1] == {
        'name': 'Rocky 9 GenericCloud', 'description': '', 'distro': 'custom', 'version': '',
        'image_url': 'https://dl.rockylinux.org/rocky9.qcow2', 'default_user': 'rocky', 'cores': 4, 'memory': 4096,
        'disk_gb': 20, 'tags': ['rhel', 'lab']}
    assert _wait(page, lambda: page.locator('[data-cr-img-add-form]').count() == 0)
    assert _wait(page, lambda: page.locator('[data-cr-img-row="custom-new-1"]').count() == 1)
    assert _count(app, 'GET', '/api/templates/catalog') == reads + 1


def test_runtime_delete_asks_says_who_names_the_image_and_reads_again(open_app):
    named = _bp('b9', 'company-web', template_id='c0ffee12', template_name='Company Ubuntu')
    app = open_app(builds=STILL, blueprints=[WEB, DB, named])
    page = _page(app)
    # built-in images have no delete
    assert page.locator('[data-cr-img-delete]').count() == 1
    page.locator('[data-cr-img-delete="c0ffee12"]').click()
    _need(page, '[data-cr-nc-confirm="img-delete"]', 'Delete asks before it deletes')
    assert '1 blueprint(s) name this image' in page.locator('[data-cr-upd-note="img-delete-used"]').inner_text()
    assert ('DELETE', '/api/templates/custom/c0ffee12') not in app.server.calls
    page.locator('[data-cr-nc-confirm-go="img-delete"]').click()
    assert _wait(page, lambda: ('DELETE', '/api/templates/custom/c0ffee12') in app.server.calls)
    assert _wait(page, lambda: page.locator('[data-cr-img-row="c0ffee12"]').count() == 0)
    assert _count(app, 'GET', '/api/blueprints') >= 2


def _perm_user(**kw):
    return dict(admin=False, permissions=['cluster.view', 'vm.view', 'vm.create'], **kw)


def test_runtime_a_non_admin_sees_the_library_buttons_off_and_why(open_app):
    app = open_app(builds=STILL, **_perm_user())
    page = _page(app)
    why = 'prepared by administrators'
    for sel in ('[data-cr-img-add]', '[data-cr-img-build="debian-13"]', '[data-cr-img-delete="c0ffee12"]'):
        assert page.locator(sel).is_disabled(), sel
        assert why in page.locator(sel).get_attribute('title'), sel
    assert why in page.locator('[data-cr-img-adminonly]').inner_text()
    # a blueprint of an image is theirs to make
    assert page.locator('[data-cr-img-new="debian-13"]').is_enabled()


def test_runtime_without_vm_create_no_blueprint_reads_and_no_new_blueprint(open_app):
    app = open_app(builds=STILL, admin=False, permissions=['cluster.view', 'vm.view'])
    page = _page(app)
    assert page.locator('[data-cr-img-new="debian-13"]').is_disabled()
    assert 'vm.create' in page.locator('[data-cr-img-new="debian-13"]').get_attribute('title')
    assert page.locator('[data-cr-table="img-list"] th[data-cr-col="used"]').count() == 0
    page.wait_for_timeout(400)
    assert _count(app, 'GET', '/api/blueprints') == 0
    # the recent deploys need cluster.view only
    assert _count(app, 'GET', '/api/blueprints/deployments') == 1


# --- the recent deploys ------------------------------------------------------------------------

def test_runtime_one_list_of_deploys_and_builds_for_this_cluster(open_app):
    app = open_app(builds=STILL)
    page = _page(app)
    page.locator('[data-cr-table="img-recent"]').wait_for(timeout=4000)
    rows = _recent(page)
    # newest first, both kinds
    assert [k for k, _ in rows] == ['tpl', 'tpl', 'vm', 'vm', 'tpl', 'tpl', 'tpl'], rows
    kinds = dict((k, txt) for k, txt in rows)
    assert 'VM from blueprint' in kinds['vm'] and 'Template build' in kinds['tpl']
    texts = [txt for _, txt in rows]
    # the build the db-static deploy started says so; a deploy names its guest, a build its template
    assert any('AlmaLinux 10' in x and 'for db-static' in x and 'download failed (rc=8)' in x for x in texts), texts
    assert any('web-small' in x and 'web-01 (120)' in x for x in texts), texts
    assert any('Template 9001' in x and 'Debian 13 (Trixie)' in x for x in texts), texts
    # a guest a deploy finished opens; a failed one and a template do not
    assert page.locator('[data-cr-img-guest="120"]').count() == 1
    assert page.locator('[data-cr-img-guest="121"]').count() == 0 and page.locator('[data-cr-img-guest="9001"]').count() == 0
    assert page.locator('[data-cr-table="img-recent"] th[data-cr-col="cluster"]').count() == 0


def test_runtime_all_clusters_reads_every_proxmox_cluster_once(open_app):
    app = open_app(builds=STILL, clusters=[CLUSTER, C2, C3, X1])
    page = _page(app)
    page.locator('[data-cr-table="img-recent"]').wait_for(timeout=4000)
    page.locator('[data-cr-img-scope="all"]').click()
    _need(page, '[data-cr-table="img-recent-all"]', 'All clusters draws its own table')
    assert _wait(page, lambda: page.locator('[data-cr-img-cover="3/3"]').count() == 1)
    # the blueprint deploys of every cluster in one read, the template builds of each PVE cluster
    alls = [u for u in app.server.urls if '/api/blueprints/deployments' in u and 'cluster_id=' not in u]
    assert len(alls) == 1
    for cid in ('c1', 'c2', 'c3'):
        assert _count(app, 'GET', f'/api/clusters/{cid}/templates/deployments') >= 1, cid
    assert _count(app, 'GET', '/api/clusters/x1/templates/deployments') == 0
    assert 'Template builds of 2 of 3 clusters.' in page.locator('[data-cr-img-cover]').inner_text()
    assert page.locator('[data-cr-img-unread="c3"]').count() == 1 and 'Edge' in page.locator('[data-cr-img-unread]').inner_text()
    clusters = page.evaluate("() => [...document.querySelectorAll('[data-cr-img-cluster]')].map(e => e.dataset.crImgCluster)")
    assert clusters[:2] == ['c2', 'c2'] and set(clusters) == {'c1', 'c2'}, clusters
    assert 'Lab' in page.locator('[data-cr-table="img-recent-all"] tbody tr').first.inner_text()
    # back and forth reads nothing again; Refresh does
    page.locator('[data-cr-img-scope="cluster"]').click()
    page.locator('[data-cr-img-scope="all"]').click()
    page.wait_for_timeout(300)
    assert len([u for u in app.server.urls if '/api/blueprints/deployments' in u and 'cluster_id=' not in u]) == 1
    page.locator('[data-cr-img-recent-refresh]').click()
    assert _wait(page, lambda: len([u for u in app.server.urls if '/api/blueprints/deployments' in u and 'cluster_id=' not in u]) == 2)


# --- the ways there ----------------------------------------------------------------------------

def _shown(page):
    _need(page, '[data-cr-img]', 'the way leads to the Blueprints & Images sub tab')
    assert page.locator('.corp-tab-strip button.active', has_text=CR_TAB).count() == 1


def test_runtime_the_resources_button_leads_there(open_app):
    app = open_app(builds=STILL)
    page = _cluster(app)
    page.locator('[data-cr-tab="resources"]').click()
    btn = page.locator('[data-cr-bp-nav="resources"]')
    btn.wait_for(timeout=8000)
    assert btn.inner_text().strip() == 'Deploy from blueprint'
    btn.click()
    _shown(page)


def test_runtime_the_cluster_menu_leads_there(open_app):
    app = open_app(builds=STILL)
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click(button='right')
    item = page.get_by_text('New VM from blueprint', exact=True)
    item.first.wait_for(timeout=5000)
    # right under New VM and New Container
    labels = page.evaluate("""() => [...document.querySelectorAll('.corp-ctx-item')].map(b => b.innerText.trim()).slice(0, 4)""")
    assert labels == ['New VM', 'New Container', 'New VM from blueprint', 'Rename Cluster'], labels
    item.first.click()
    _shown(page)


def test_runtime_ctrl_k_leads_there(open_app):
    app = open_app(builds=STILL)
    page = app.page
    page.locator('[data-cr-palette]').first.click()
    page.get_by_placeholder(re.compile('Type to search')).fill('blueprint')
    hit = page.locator('[data-cmdpal-idx]', has_text='New VM from blueprint')
    hit.first.wait_for(timeout=5000)
    hit.first.click()
    _shown(page)


def test_runtime_no_way_there_without_vm_create(open_app):
    app = open_app(builds=STILL, admin=False, permissions=['cluster.view', 'vm.view'])
    page = _cluster(app)
    page.locator('[data-cr-tab="resources"]').click()
    page.get_by_text('Create new VM').first.wait_for(timeout=8000)
    assert page.locator('[data-cr-bp-nav]').count() == 0
    page.locator('.corp-tree-item', has_text='Testi').first.click(button='right')
    # the menu is open (its Refresh needs no permission), without the entry
    page.get_by_text('Refresh', exact=True).first.wait_for(timeout=5000)
    assert page.get_by_text('New VM from blueprint', exact=True).count() == 0


# --- only in Corporate Redesigned --------------------------------------------------------------

@pytest.mark.parametrize('layout', ['corporate', 'modern'])
def test_runtime_classic_layouts_keep_the_library_and_have_no_way_there(open_app, layout):
    app = open_app(layout=layout)
    page = _templates(app, layout)
    page.get_by_text('Debian 13 (Trixie)').first.wait_for(timeout=8000)
    page.wait_for_timeout(500)
    assert page.get_by_text('Curated catalog of cloud images').count() == 1
    assert page.locator('button', has_text=CR_TAB).count() == 0
    assert page.locator('[data-cr-img], [data-cr-img-page]').count() == 0
    assert _count(app, 'GET', '/api/blueprints') == 0 and _count(app, 'GET', '/api/blueprints/deployments') == 0
    page.locator('button', has_text=re.compile(r'^\s*Resources\s*$')).first.click()
    page.get_by_text('Create new VM').first.wait_for(timeout=8000)
    assert page.locator('[data-cr-bp-nav]').count() == 0
    page.keyboard.press('Control+k')
    page.get_by_placeholder(re.compile('Type to search')).fill('blueprint')
    page.wait_for_timeout(400)
    assert page.locator('[data-cmdpal-idx]', has_text='from blueprint').count() == 0


# --- source ------------------------------------------------------------------------------------

def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def _blocks():
    src = _read('web', 'src', 'translations.js')
    starts = [(m.start(), m.group(1)) for m in re.finditer(r'^            ([a-z]{2}): \{$', src, re.M)]
    ends = [s for s, _ in starts[1:]] + [len(src)]
    return {lang: src[a:b] for (a, lang), b in zip(starts, ends)}


def _keys():
    used = set()
    for name in ('cr_images.js', 'dashboard.js'):
        used |= set(re.findall(r"'(cr(?:Img|BpNav)[A-Za-z]+)'", _read('web', 'src', name)))
    return used


def test_every_key_is_in_all_nine_languages_ahead_of_the_blueprint_keys():
    used = _keys()
    assert len(used) > 90 and {'crBpNavTab', 'crBpNavDeploy', 'crBpNavNewVm'} <= used
    blocks = _blocks()
    assert set(blocks) == {'de', 'en', 'zh', 'pl', 'fr', 'es', 'pt', 'ko', 'it'}
    en = dict(re.findall(r'^                (cr(?:Img|BpNav)[A-Za-z]+): "(.*)",$', blocks['en'], re.M))
    for lang, block in blocks.items():
        # the blueprint editor appends its keys after the crBp group: these stand before its first line
        first_bp = re.search(r'^                crBp(?!Nav)[A-Za-z]+: ', block, re.M).start()
        pinned = block.index('// LW Oct 2026 (#625) - the banners of a group that fails over automatically')
        for k in used:
            found = re.findall(rf'^                {k}: "(.*)",$', block, re.M)
            assert len(found) == 1, (lang, k)
            at = re.search(rf'^                {k}: ', block, re.M).start()
            assert at < first_bp < pinned, (lang, k)
            assert not any(d in found[0] for d in DASHES), (lang, k)
            assert sorted(re.findall(r'\{[a-z]+\}', found[0])) == sorted(re.findall(r'\{[a-z]+\}', en[k])), (lang, k)


def test_the_module_is_built_shipped_and_plain():
    src = _read('web', 'src', 'cr_images.js')
    assert not any(d in src for d in DASHES)
    for bad in ('window.confirm', 'setInterval', 'localStorage', 'sessionStorage'):
        assert bad not in src, bad
    assert not re.search(r'(?<![\w.])confirm\(', src)
    build = _read('web', 'Dev', 'build.sh')
    assert build.index('    cr_blueprints.js\n') < build.index('    cr_images.js\n') < build.index('    dashboard.js\n')
    assert 'web/src/cr_images.js' in json.loads(_read('version.json'))['update_files']
    # it writes only through the library's routes, as the classic tab does
    sends = [ln.strip() for ln in src.split('\n') if 'await crImgSend(authFetch' in ln]
    assert len(sends) == 3, sends
    assert any("`${base}/templates/deploy`, 'POST'" in s for s in sends)
    assert any("`${API_URL}/templates/custom`, 'POST'" in s for s in sends)
    assert any("`${API_URL}/templates/custom/${encodeURIComponent(del.id)}`, 'DELETE'" in s for s in sends)
    # one poll, armed only while something runs (or once after) and cleared with the page
    assert src.count('setTimeout(readHere, CR_IMG_POLL)') == 1
    assert 'if (!again) return undefined;' in src and 'return () => clearTimeout(timer);' in src


def test_the_page_hands_the_blueprints_their_props_and_clears_the_image_after():
    src = _read('web', 'src', 'cr_images.js')
    page = src[src.index('function CrBlueprintsTab('):]
    assert 'prefillTemplate={prefill} onSaved={readBps}' in page
    assert "useEffect(() => { if (prefill) setPrefill(''); }, [prefill]);" in page
    # the sections share one fetch: the same list asked at the same moment goes out once
    assert 'const shared = useMemo(() => crImgShared(authFetch), [authFetch]);' in page
    assert page.count('authFetch={shared}') == 3
    helper = src[src.index('function crImgShared('):src.index('async function crImgSend(')]
    assert 'if (opts !== undefined || typeof url !== \'string\') return authFetch(url, opts);' in helper
    assert 'r.clone()' in helper and '.finally(() => flying.delete(url))' in helper


def test_the_classic_library_stays_for_every_other_layout():
    dash = _read('web', 'src', 'dashboard.js')
    assert "{ id: 'templates', label: isCorpRedesigned ? t('crBpNavTab') : (t('templateLibrary') || 'Templates'), icon: Icons.Package }," in dash
    mount = dash.index('<TemplatesLibraryTab\n')
    assert dash[dash.rindex('{automationSubTab', 0, mount):mount].startswith(
        "{automationSubTab === 'templates' && !isCorpRedesigned && (")
    assert len(re.findall(r'<TemplatesLibraryTab\b', dash)) == 1
    assert "isAdmin={isAdmin} nav={crTaskNav} />" in dash[dash.index('<CrBlueprintsTab '):]


def test_the_ways_there_are_corporate_redesigned_only():
    dash = _read('web', 'src', 'dashboard.js')
    assert ("openBlueprints: (cid) => { if (crIntoCluster(cid)) { crClearPick(); setActiveTab('automation'); "
            "setAutomationSubTab('templates'); } },") in dash
    # the Resources button
    btn = dash.index('data-cr-bp-nav="resources"')
    assert "{isCorpRedesigned && can('vm.create') && (" in dash[btn - 400:btn]
    # the cluster menu: the redesign and a Proxmox VE cluster, the entry asks for vm.create
    menu = dash[dash.index('const buildContextMenuItemsRaw = '):dash.index('const buildContextMenuItems = ')]
    assert ("...(isCorpRedesigned && (!cluster.cluster_type || cluster.cluster_type === 'proxmox') ? [\n"
            "                            { perm: 'vm.create', label: t('crBpNavNewVm'),") in menu
    # Ctrl+K: an action of the redesign only
    pal = dash[dash.index('<CommandPalette'):]
    pal = pal[:pal.index('/>')]
    assert "extraActions={isCorpRedesigned && can('vm.create') && " in pal
    assert "else if (id === 'cr-blueprints' && crTaskNav) {" in pal
    fn = dash[dash.index('function CommandPalette('):dash.index('// Fuzzy-ish scoring')]
    assert '...(extraActions || []),' in fn and 'onAction, extraActions, t]);' in fn
