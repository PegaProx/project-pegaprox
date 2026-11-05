"""Automation > App Containers (containers from OCI images), at runtime.

The source checks read web/src; the runtime tests drive the built bundle (web/index.html)
in headless Chromium against the fake server of tests/test_ha_ui.py, in Modern,
Corporate and Cloud, as an active instance and as a standby, in English and German. They
skip where Playwright is not installed. The routes behind the page are tested in
tests/test_oci_catalog.py.
LW Oct 2026
"""
import json
import os
import re

import pytest

from test_ha_ui import CLUSTER, VM, SSE_TOKEN, _App, _FakeServer, _toasts, _wait_for_call, browser  # noqa: F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHOTS = os.environ.get('PEGAPROX_SHOTS', '')
LANGS = ['de', 'en', 'zh', 'pl', 'fr', 'es', 'pt', 'ko', 'it', 'ru']

CATALOG = {'images': [
    {'id': 'nginx', 'name': 'nginx', 'reference': 'docker.io/library/nginx:stable-alpine',
     'description': 'Web server and reverse proxy.', 'category': 'web', 'ports': [80],
     'cores': 1, 'memory': 256, 'disk_gb': 2},
    {'id': 'redis', 'name': 'Redis', 'reference': 'docker.io/library/redis:8-alpine',
     'description': 'In-memory key-value store.', 'category': 'database', 'ports': [6379],
     'cores': 1, 'memory': 512, 'disk_gb': 2},
], 'min_pve': '9.1', 'technology_preview': True}
NODES = {'nodes': [
    {'node': 'pve1', 'status': 'online', 'pve_version': '9.1.1', 'supported': True, 'reason': ''},
    {'node': 'pve2', 'status': 'online', 'pve_version': '8.4.14', 'supported': False, 'reason': 'too_old'},
], 'min_pve': '9.1'}
STORAGES = [
    {'storage': 'local', 'type': 'dir', 'content': 'iso,vztmpl,backup', 'enabled': 1, 'active': 1},
    {'storage': 'local-lvm', 'type': 'lvmthin', 'content': 'images,rootdir', 'enabled': 1, 'active': 1},
    {'storage': 'isos', 'type': 'nfs', 'content': 'iso', 'enabled': 1, 'active': 1},
]
NETWORKS = [{'iface': 'vmbr0', 'type': 'bridge', 'source': 'local'}, {'iface': 'vmbr1', 'type': 'bridge', 'source': 'local'}]
JOB = {'id': 'j1', 'cluster_id': 'c1', 'node': 'pve1', 'reference': 'docker.io/library/nginx:stable-alpine',
       'storage': 'local', 'vmid': 105, 'hostname': 'web', 'status': 'pulling', 'reused': False, 'error': '',
       'started_by': 'admin', 'started_at': '2026-10-05T10:00:00', 'finished_at': ''}
FAILED = dict(JOB, id='j0', status='failed', vmid=104, error='The pull failed: manifest unknown',
              started_at='2026-10-05T09:00:00')

READS = {
    ('GET', '/api/oci/catalog'): (200, CATALOG),
    ('GET', '/api/clusters/c1/oci/nodes'): (200, NODES),
    ('GET', '/api/clusters/c1/oci/jobs'): (200, {'jobs': [FAILED]}),
    ('GET', '/api/clusters/c1/nodes/pve1/storage'): (200, STORAGES),
    ('GET', '/api/clusters/c1/nodes/pve1/networks'): (200, NETWORKS),
    ('POST', '/api/clusters/c1/oci/deploy'): (200, {'job': JOB}),
    # what the Automation tab reads besides
    ('GET', '/api/schedules'): (200, []),
    ('GET', '/api/clusters/c1/scripts'): (200, []),
    ('GET', '/api/alert-channels'): (200, []),
}


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(**kw):
        extra = dict(READS)
        extra.update(SSE_TOKEN)
        extra.update(kw.pop('extra', {}))
        app = _App(browser, _FakeServer(clusters=[CLUSTER], resources=[VM], extra=extra, **kw))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _shot(page, name):
    if SHOTS:
        os.makedirs(SHOTS, exist_ok=True)
        page.screenshot(path=os.path.join(SHOTS, name), full_page=False)


def _to_apps(app, layout='modern'):
    page = app.page
    if layout == 'cloud':
        page.locator('.cloud-nav-item', has_text=re.compile(r'App Containers|App-Container')).first.click()
    else:
        if layout == 'corporate':
            page.locator('.corp-tree-item', has_text='Testi').first.click()
        else:
            page.get_by_text('Testi').first.click()
        page.locator('button', has_text=re.compile(r'^\s*(Automation|Automatisierung)\s*$')).first.click()
        page.get_by_role('button', name=re.compile(r'^\s*(App Containers|App-Container)\s*$')).first.click()
    page.locator('[data-oci-catalog]').wait_for(timeout=8000)
    page.locator('[data-oci-image="nginx"]').wait_for(timeout=5000)
    page.wait_for_timeout(300)
    return page


def _sent(app, method, path):
    out, i = [], 0
    for m, p in app.server.calls:
        if p != path:
            continue
        if m == method:
            out.append(app.server.bodies[path][i])
        i += 1
    return out


# --- source -------------------------------------------------------------------------------------

def _src(name):
    with open(os.path.join(ROOT, 'web', 'src', name), encoding='utf-8') as fh:
        return fh.read()


def _component():
    src = _src('dashboard.js')
    start = src.index('function OciCatalogTab(')
    return src[start:src.index('\n        }\n', start)]


def test_every_string_of_the_tab_is_in_all_nine_languages_once():
    tr = _src('translations.js')
    used = set(re.findall(r"""(?:\bt|fill)\('(oci[A-Za-z0-9]+)'""", _component()))
    used |= set(re.findall(r"""t\('(oci[A-Za-z0-9]+)'\)""", _src('cloud.js')))
    assert len(used) > 40, used
    starts = [(m.start(), m.group(1)) for m in re.finditer(r'\n            ([a-z]{2}): \{\n', tr)]
    assert [lang for _, lang in starts] == LANGS
    for i, (pos, lang) in enumerate(starts):
        block = tr[pos:starts[i + 1][0] if i + 1 < len(starts) else len(tr)]
        for key in used:
            n = len(re.findall(rf'\n\s+{key}: ', block))
            assert n == 1, (lang, key, n)
    # the Austrian flag of 'de' stays where it is
    assert re.search(r"code: 'de', flag: '\U0001F1E6\U0001F1F9'", _src('contexts.js'))


def test_the_icons_exist_and_no_long_dash_slipped_in():
    icons = _src('icons.js')
    for name in set(re.findall(r'Icons\.([A-Za-z]+)', _component())) | {'Container'}:
        assert re.search(rf'\n\s+{name}: ', icons), name
    added = _component() + ''.join(re.findall(r"(?s)// app containers from OCI images - LW Oct 2026\n(.*?)\n\s*//", _src('translations.js')))
    assert '\N{EM DASH}' not in added and '\N{EN DASH}' not in added


# --- runtime -------------------------------------------------------------------------------------

@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_pick_an_image_choose_where_and_create(open_app, layout):
    app = open_app(role='standalone', layout=layout)
    page = _to_apps(app, layout)
    tab = page.locator('[data-oci-catalog]')
    text = tab.inner_text()
    for needle in ('App containers from OCI images', 'TECHNOLOGY PREVIEW', 'technology preview',
                   'docker.io/library/nginx:stable-alpine', '1 CPU · 256 MB RAM · 2 GB disk',
                   'listens on 80', 'Any image', '1 of 2 nodes run Proxmox VE 9.1 or newer',
                   'Recent runs', 'manifest unknown'):
        assert needle in text, needle
    _shot(page, f'{layout}-catalog.png')

    page.locator('[data-oci-deploy="nginx"]').click()
    dialog = page.locator('[data-oci-dialog]')
    dialog.wait_for(timeout=5000)
    page.wait_for_function('() => document.querySelector(\'[data-oci-field="storage"]\').value === "local"', timeout=5000)
    # the node too old for it is listed, with the reason, and cannot be picked
    options = dialog.locator('[data-oci-field="node"] option')
    assert options.count() == 2
    assert options.nth(0).inner_text() == 'pve1 (PVE 9.1.1)'
    assert options.nth(1).is_disabled() and 'PVE 8.4.14, needs 9.1' in options.nth(1).inner_text()
    # only the storages that take what goes there
    assert dialog.locator('[data-oci-field="storage"] option').all_inner_texts() == ['local']
    assert dialog.locator('[data-oci-field="rootfs_storage"] option').all_inner_texts() == ['local-lvm']
    assert dialog.locator('[data-oci-field="bridge"]').input_value() == 'vmbr0'
    assert dialog.locator('[data-oci-field="hostname"]').input_value() == 'nginx'
    dialog.locator('[data-oci-field="hostname"]').fill('web')
    dialog.locator('[data-oci-field="memory"]').fill('512')
    dialog.locator('[data-oci-field="vlan"]').fill('20')
    dialog.locator('[data-oci-field="static"]').check()
    # a static address needs the address, or the server would fall back to DHCP
    assert dialog.locator('[data-oci-submit]').is_disabled()
    dialog.locator('[data-oci-field="ip"]').fill('10.0.0.5/24')
    assert dialog.locator('[data-oci-submit]').is_enabled()
    dialog.locator('[data-oci-field="gw"]').fill('10.0.0.1')
    dialog.locator('[data-oci-field="env"]').fill('TZ=Europe/Vienna\n\nGREETING=hello there\n')
    _shot(page, f'{layout}-dialog.png')
    dialog.locator('[data-oci-submit]').click()
    assert _wait_for_call(app, ('POST', '/api/clusters/c1/oci/deploy'))
    body = _sent(app, 'POST', '/api/clusters/c1/oci/deploy')[-1]
    assert body == {'reference': 'docker.io/library/nginx:stable-alpine', 'node': 'pve1', 'storage': 'local',
                    'rootfs_storage': 'local-lvm', 'disk_gb': 2, 'bridge': 'vmbr0', 'hostname': 'web',
                    'cores': 1, 'memory': '512', 'swap': 512, 'ip': '10.0.0.5/24', 'gw': '10.0.0.1',
                    'start': True, 'env': ['TZ=Europe/Vienna', 'GREETING=hello there'], 'vlan': '20'}
    dialog.wait_for(state='detached', timeout=5000)
    assert any('Pull and create started for CT 105' in x for x in _toasts(page)), _toasts(page)
    assert not app.errors, app.errors


def test_runtime_any_image_waits_for_a_tag_and_shows_the_server_refusal(open_app):
    refusal = {('POST', '/api/clusters/c1/oci/deploy'): (400, {
        'error': 'Not an image reference PVE can pull: [registry/]name:tag, the name in lower case'})}
    app = open_app(role='standalone', layout='modern', extra=refusal)
    page = _to_apps(app)
    field = page.locator('[data-oci-custom-ref]')
    button = page.locator('[data-oci-deploy="custom"]')
    assert button.is_disabled()
    field.fill('ghcr.io/Owner/app')
    assert button.is_disabled()
    field.fill('ghcr.io/Owner/app:1.0')
    assert button.is_enabled()
    button.click()
    dialog = page.locator('[data-oci-dialog]')
    dialog.wait_for(timeout=5000)
    assert dialog.locator('[data-oci-field="hostname"]').input_value() == 'app'
    page.wait_for_function('() => document.querySelector(\'[data-oci-field="storage"]\').value === "local"', timeout=5000)
    dialog.locator('[data-oci-submit]').click()
    dialog.locator('[data-oci-error]').wait_for(timeout=5000)
    assert 'name in lower case' in dialog.locator('[data-oci-error]').inner_text()
    assert _sent(app, 'POST', '/api/clusters/c1/oci/deploy')[-1]['reference'] == 'ghcr.io/Owner/app:1.0'
    assert not app.errors, app.errors


def test_runtime_a_cluster_without_a_new_enough_node_explains_and_offers_nothing(open_app):
    old = {('GET', '/api/clusters/c1/oci/nodes'): (200, {'nodes': [
        {'node': 'pve1', 'status': 'online', 'pve_version': '8.4.14', 'supported': False, 'reason': 'too_old'},
        {'node': 'pve2', 'status': 'offline', 'pve_version': '', 'supported': False, 'reason': 'offline'}],
        'min_pve': '9.1'})}
    app = open_app(role='standalone', layout='modern', extra=old)
    page = _to_apps(app)
    note = page.locator('[data-oci-no-node]')
    note.wait_for(timeout=5000)
    assert 'containers from OCI images need Proxmox VE 9.1 or newer' in note.inner_text()
    assert 'pve1: PVE 8.4.14, needs 9.1' in note.inner_text() and 'pve2: offline' in note.inner_text()
    assert page.locator('[data-oci-deploy="nginx"]').is_disabled()
    assert page.locator('[data-oci-deploy="custom"]').is_disabled()
    _shot(page, 'modern-no-node.png')
    assert not app.errors, app.errors


def test_runtime_a_caller_the_server_refuses_sees_why_and_no_button(open_app):
    denied = {('GET', '/api/clusters/c1/oci/nodes'): (403, {'error': 'Permission denied'}),
              ('GET', '/api/clusters/c1/oci/jobs'): (200, {'jobs': []})}
    app = open_app(role='standalone', layout='modern', admin=False, extra=denied)
    page = _to_apps(app)
    page.locator('[data-oci-denied]').wait_for(timeout=5000)
    assert 'needs the permission to create guests' in page.locator('[data-oci-denied]').inner_text()
    assert page.locator('[data-oci-deploy="nginx"]').is_disabled()
    assert ('POST', '/api/clusters/c1/oci/deploy') not in app.server.calls
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'cloud'])
def test_runtime_a_standby_shows_the_catalog_and_creates_nothing(open_app, layout):
    app = open_app(role='standby', layout=layout)
    page = _to_apps(app, layout)
    button = page.locator('[data-oci-deploy="nginx"]')
    assert button.is_disabled()
    assert 'standby' in (button.get_attribute('title') or '')
    assert page.locator('[data-oci-deploy="custom"]').is_disabled()
    _shot(page, f'{layout}-standby.png')
    assert ('POST', '/api/clusters/c1/oci/deploy') not in app.server.calls
    assert not app.errors, app.errors


def test_runtime_cloud_mounts_the_same_tab_and_creates(open_app):
    app = open_app(role='standalone', layout='cloud')
    page = _to_apps(app, 'cloud')
    assert 'TECHNOLOGY PREVIEW' in page.locator('[data-oci-catalog]').inner_text()
    page.locator('[data-oci-deploy="redis"]').click()
    dialog = page.locator('[data-oci-dialog]')
    dialog.wait_for(timeout=5000)
    page.wait_for_function('() => document.querySelector(\'[data-oci-field="rootfs_storage"]\').value === "local-lvm"', timeout=5000)
    _shot(page, 'cloud-dialog.png')
    dialog.locator('[data-oci-submit]').click()
    assert _wait_for_call(app, ('POST', '/api/clusters/c1/oci/deploy'))
    body = _sent(app, 'POST', '/api/clusters/c1/oci/deploy')[-1]
    assert body['reference'] == 'docker.io/library/redis:8-alpine' and body['ip'] == 'dhcp' and 'gw' not in body
    assert not app.errors, app.errors


def test_runtime_running_jobs_are_followed_until_they_finish(open_app):
    app = open_app(role='standalone', layout='modern', extra={
        ('GET', '/api/clusters/c1/oci/jobs'): (200, {'jobs': [JOB]})})
    page = _to_apps(app)
    row = page.locator('[data-oci-job="j1"]')
    row.wait_for(timeout=5000)
    assert row.get_attribute('data-oci-job-status') == 'pulling'
    app.server.extra[('GET', '/api/clusters/c1/oci/jobs')] = (200, {'jobs': [dict(JOB, status='completed')]})
    page.wait_for_function('() => document.querySelector(\'[data-oci-job="j1"]\').dataset.ociJobStatus === "completed"',
                           timeout=8000)
    assert 'done' in row.inner_text()
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_in_german(open_app, layout):
    app = open_app(role='standalone', layout=layout, language='de')
    page = _to_apps(app, layout)
    text = page.locator('[data-oci-catalog]').inner_text()
    for needle in ('App-Container aus OCI-Images', 'TECHNOLOGIEVORSCHAU', 'Beliebiges Image', 'Letzte Läufe',
                   '1 von 2 Nodes laufen mit Proxmox VE 9.1 oder neuer'):
        assert needle in text, needle
    page.locator('[data-oci-deploy="nginx"]').click()
    dialog = page.locator('[data-oci-dialog]')
    dialog.wait_for(timeout=5000)
    assert 'Container anlegen: nginx' in dialog.inner_text()
    assert 'Laden und anlegen' in dialog.inner_text()
    _shot(page, f'{layout}-de-dialog.png')
    assert not app.errors, app.errors
