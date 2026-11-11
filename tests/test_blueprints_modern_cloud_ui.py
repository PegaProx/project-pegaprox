"""Blueprints in Modern and Cloud (#1220): Automation > Blueprints & Templates of Modern and the page of
the same name in Cloud draw the blueprints of the redesign above the library cards (web/src/blueprints.js),
Modern in its look, Cloud with the buttons, fields, tables, chips and switches of its shell. The list with
what each blueprint holds, the editor and the body it sends (a library image and a Windows template), the
deploy dialog (where to, the template the server would use or build, the shared storage a template of
another node needs, the Windows password and the 15 characters of its computer name, the keys that go
into the VM), the progress and the recent deploys of this cluster or of all of them. In Modern the
Resources button and Ctrl+K lead there, in Cloud the button next to New VM; an account without vm.create
reads nothing, a standby shows the list and changes nothing. Classic Corporate keeps the library alone.
At 1280 px the Resources row, the header and the list fit in German and Italian, the chips read on the
light palettes, a dialog keeps the focus, and Cloud says so of a guest its list does not have.

The rules are the redesign's (crBpUseEditor, crBpUseDeploy, crBpUseProgress in cr_blueprints.js), so
these tests drive what the two looks draw of them; the ones that are the same in both run in each
(LAYOUTS). Runtime tests use the fake of tests/test_corp_redesigned_blueprints_ui.py (_BpServer). The
counterproof runs this file against an older bundle: PEGAPROX_CR_BUNDLE=<path to index.html>.
LW Nov 2026
"""
import copy
import json
import os
import re

import pytest

from test_corp_redesigned_blueprints_ui import (  # noqa: F401 (browser is a fixture)
    BUNDLE, DASHES, DB, DONE, FAILED, GOLD, OTHER, RECENT, RUNNING, WEB, WIN, _BpServer, _bp, _box, _count, _need,
    _no_errors, _wait, browser)
from test_corp_redesigned_guard_ui import RESOURCES, _GuardApp
from test_ha_ui import BASE, CLUSTER, VM

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# the sub tab: its name in Modern, and the one classic Corporate (and the older bundles) keep
TAB = re.compile(r'^\s*(Blueprints & Templates|Cloud-Init Template Library)\s*$')
LIB = 'Cloud-Init Template Library'
LAYOUTS = ['modern', 'cloud']
# the page in the Cloud nav (Templates before)
CLOUD_PAGE = re.compile(r'^\s*(Blueprints & Templates|Templates)\s*$')
# a deploy of the second cluster for All clusters
ELSEWHERE = dict(RECENT[0], id='r3', cluster_id='c2', node='lab1', vmid=300, name='web-lab', started_at='2026-11-08T09:10:00')
# the guests the deploys made, as the list of the cluster has them once they are there: the one of the
# progress (105) and the finished one of the recent deploys (120)
MADE = dict(VM, vmid=105, name='web-small')
WEB_01 = dict(VM, vmid=120, name='web-01')


class _MdServer(_BpServer):
    """_BpServer whose deploy list goes by ?cluster_id= as the server filters it."""

    def __init__(self, **kw):
        super().__init__(**kw)
        self.recent = copy.deepcopy(RECENT) + [dict(ELSEWHERE)]

    def bp_route(self, method, path, body, url):
        if path == '/api/blueprints/deployments':
            cid = (re.search(r'[?&]cluster_id=([^&]+)', url) or [None, ''])[1]
            return 200, {'deployments': [r for r in self.recent if not cid or r['cluster_id'] == cid]}
        return super().bp_route(method, path, body, url)


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(layout='modern', viewport=(1600, 1000), bundle=None, storage=None, clusters=None, **kw):
        server = _MdServer(bundle=bundle or BUNDLE, layout=layout, **kw)
        if clusters is not None:
            server.clusters = clusters
        app = _GuardApp(browser, server, viewport=viewport, storage=storage)
        app.layout = layout
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.close()


def _templates(app):
    """Automation > Blueprints & Templates of Testi (Cloud-Init Template Library before), in Cloud the
    page of that name (Templates before) of the cluster it picked, Testi."""
    page = app.page
    if app.layout == 'cloud':
        app.mark = len(app.server.calls)
        page.locator('.cloud-nav-item', has_text=CLOUD_PAGE).first.click()
        return page
    page.get_by_text('Testi').first.click()
    page.locator('button', has_text=re.compile(r'^\s*Automation\s*$')).first.click()
    app.mark = len(app.server.calls)
    page.locator('button', has_text=TAB).first.click()
    return page


def _page(app):
    page = _templates(app)
    where = 'on the Blueprints & Templates page of Cloud' if app.layout == 'cloud' else 'on the template sub tab of Modern'
    _need(page, '[data-bp]', f'the blueprints are {where}')
    _need(page, '[data-bp-row]', 'the blueprint list is filled')
    return page


def _guest_opened(app, name):
    """Open guest led to the guest list of its cluster: Resources of Modern, the guest on the VMs page of Cloud."""
    page = app.page
    assert _wait(page, lambda: page.locator('[data-bp]').count() == 0)
    if app.layout == 'cloud':
        assert _wait(page, lambda: page.locator('.cloud-breadcrumb-leaf').count() == 1
                     and page.locator('.cloud-breadcrumb-leaf').inner_text().strip() == name)
        assert page.locator('.cloud-nav-item-active').inner_text().strip() == 'Virtual Machines'
        return
    page.get_by_text('Create new VM').first.wait_for(timeout=8000)


def _row(page, bid):
    return page.locator(f'[data-bp-row="{bid}"]')


def _fill(page, key, value):
    page.locator(f'[data-bp-input="{key}"]').fill(value)


def _errors(page, scope):
    return page.evaluate("""(scope) => [...document.querySelectorAll(scope + ' [data-bp-field]')]
        .filter(f => f.querySelector('[data-bp-hint="error"]')).map(f => f.dataset.bpField).sort()""", scope)


def _hint(page, field):
    return page.locator(f'[data-bp-field="{field}"] [data-bp-hint]')


# --- the list ----------------------------------------------------------------------------------

def test_runtime_modern_lists_the_blueprints_above_the_library(open_app):
    app = open_app()
    page = _page(app)
    page.wait_for_timeout(400)
    rows = page.evaluate("() => [...document.querySelectorAll('[data-bp-row]')].map(e => e.dataset.bpRow)")
    # by name
    assert rows == ['b2', 'b3', 'b4', 'b6', 'b1', 'b5'], rows
    web = _row(page, 'b1').inner_text()
    assert 'web-small' in web and 'Small web front end' in web and 'Debian 13 (Trixie)' in web and '2 vCPU · 2 GB · 20 GB' in web
    assert page.locator('[data-bp-row="b1"] [data-bp-tag="web"]').count() == 1
    assert page.locator('[data-bp-row="b3"] [data-bp-by]').get_attribute('data-bp-by') == 'alice'
    assert page.locator('[data-bp-net="b2"]').inner_text() == 'net0 vmbr0 VLAN 20, net1 vmbr1'
    assert page.locator('[data-bp-row="b2"] [data-bp-ip]').inner_text() == 'IP Static'
    assert '4 vCPU · 8 GB · image size' in _row(page, 'b2').inner_text()
    # a template source: the kind of template, the one this cluster remembers, the template's NICs
    win = page.locator('[data-bp-row="b5"] [data-bp-source-cell="template"]')
    assert win.get_attribute('data-bp-os') == 'windows' and 'Template (Windows)' in win.inner_text()
    assert page.locator('[data-bp-row="b5"] [data-bp-mapped]').inner_text() == 'Template 9100 on this cluster'
    assert page.locator('[data-bp-net="b5"]').inner_text() == "template's NICs"
    assert page.locator('[data-bp-row="b6"] [data-bp-mapped]').count() == 0
    # an image the library dropped: said, and no deploy
    assert page.locator('[data-bp-row="b4"] [data-bp-image="missing"]').count() == 1
    assert page.locator('[data-bp-deploy="b4"]').is_disabled() and page.locator('[data-bp-deploy="b5"]').is_enabled()
    # how many, and that they are kept for every cluster
    assert page.locator('[data-bp-count]').inner_text().strip() == '6'
    assert page.locator('[data-bp-scope="all"]').inner_text().strip() == 'Shared across clusters'
    heads = page.evaluate("() => [...document.querySelectorAll('[data-bp-table] thead th')].map(h => h.textContent.trim())")
    assert heads == ['Name', 'Source', 'CPU / RAM / disk', 'Network', 'Deploy'], heads
    # above the library cards, which stay
    lib = page.get_by_text(LIB, exact=True).first
    lib.wait_for(timeout=8000)
    assert _box(page, '[data-bp]')['y'] < lib.bounding_box()['y']
    assert page.locator('[data-bp-layout="modern"]').count() == 1
    # one read of the list and one of the deploys of this cluster; nothing of a running deploy
    assert _count(app, 'GET', '/api/blueprints') == 1
    assert [u for u in app.server.urls if '/api/blueprints/deployments' in u] == [f'{BASE}/api/blueprints/deployments?cluster_id=c1']
    assert app.server.prog_reads == []
    _no_errors(app)


def test_runtime_the_sub_tab_has_its_new_name(open_app):
    page = _page(open_app())
    assert page.locator('button', has_text=re.compile(r'^\s*Blueprints & Templates\s*$')).count() == 1
    assert page.locator('button', has_text=re.compile(r'^\s*Cloud-Init Template Library\s*$')).count() == 0
    german = open_app(language='de')
    page = german.page
    page.get_by_text('Testi').first.click()
    page.locator('button', has_text=re.compile(r'^\s*Automatisierung\s*$')).first.click()
    page.locator('button', has_text=re.compile(r'^\s*Blueprints & Templates\s*$')).first.click()
    _need(page, '[data-bp]', 'the German tab label leads to the blueprints')


@pytest.mark.parametrize('layout', LAYOUTS)
def test_runtime_edit_and_delete_only_where_the_account_may_and_delete_asks(open_app, layout):
    app = open_app(layout=layout)
    page = _page(app)
    assert page.locator('[data-bp-edit="b1"]').count() == 1 and page.locator('[data-bp-delete="b1"]').count() == 1
    assert page.locator('[data-bp-edit="b3"]').count() == 0 and page.locator('[data-bp-delete="b3"]').count() == 0
    assert page.locator('[data-bp-deploy="b3"]').is_enabled()
    # Deploy stands in one column, with or without Edit and Delete in front of it
    a, b = _box(page, '[data-bp-deploy="b1"]'), _box(page, '[data-bp-deploy="b3"]')
    assert abs((a['x'] + a['width']) - (b['x'] + b['width'])) < 1
    page.locator('[data-bp-delete="b1"]').click()
    _need(page, '[data-bp-confirm="delete"]', 'Delete asks before it deletes')
    assert 'Only the blueprint goes' in page.locator('[data-bp-confirm="delete"]').inner_text()
    assert ('DELETE', '/api/blueprints/b1') not in app.server.calls
    page.locator('[data-bp-confirm-go]').click()
    assert _wait(page, lambda: ('DELETE', '/api/blueprints/b1') in app.server.calls)
    assert _wait(page, lambda: _row(page, 'b1').count() == 0)
    assert _count(app, 'GET', '/api/blueprints') == 2


def test_runtime_an_empty_list_says_so(open_app):
    app = open_app(blueprints=[])
    page = _templates(app)
    _need(page, '[data-bp-empty]', 'an empty list says so')
    assert 'No blueprint yet' in page.locator('[data-bp-empty]').inner_text()


# --- the editor --------------------------------------------------------------------------------

def _new(page):
    page.locator('[data-bp-new]').click()
    _need(page, '[data-bp-editor="new"]', 'New blueprint opens the editor')
    page.locator('[data-bp-input="template_id"] option[value="c0ffee12"]').wait_for(state='attached', timeout=4000)


@pytest.mark.parametrize('layout', LAYOUTS)
def test_runtime_a_library_blueprint_is_checked_and_sends_the_body_the_server_takes(open_app, layout):
    app = open_app(layout=layout)
    page = _page(app)
    _new(page)
    assert page.locator('[data-bp-source="library"]').get_attribute('aria-pressed') == 'true'
    assert page.locator('[data-bp-input="disk_gb"]').get_attribute('placeholder') == 'image size'
    # what keeps it from being saved stands at its field
    page.locator('[data-bp-input="memUnit"]').select_option('MB')
    _fill(page, 'memory', '32')
    _fill(page, 'cores', '0')
    page.locator('[data-bp-nic-vlan="0"]').fill('5000')
    page.locator('[data-bp-editor-save]').click()
    page.wait_for_timeout(300)
    assert ('POST', '/api/blueprints') not in app.server.calls
    assert _errors(page, '[data-bp-editor]') == ['cores', 'memory', 'name', 'nic0-vlan', 'template_id']
    page.locator('[data-bp-input="memUnit"]').select_option('GB')
    _fill(page, 'name', '  app-tier ')
    page.locator('[data-bp-input="template_id"]').select_option('c0ffee12')
    _fill(page, 'cores', '4')
    _fill(page, 'memory', '6')
    _fill(page, 'disk_gb', '40')
    page.locator('[data-bp-nic-vlan="0"]').fill('30')
    page.locator('[data-bp-nic-add]').click()
    page.locator('[data-bp-nic-bridge="1"]').fill('vmbr1')
    page.locator('[data-bp-nic-model="1"]').select_option('e1000')
    page.locator('[data-bp-nic-fw="1"]').check()
    _fill(page, 'ciuser', 'ops')
    _fill(page, 'sshkeys', 'ssh-ed25519 AAAAC3Nza key1@lab\n\n  ecdsa-sha2-nistp256 AAAAE2Vj key2@lab  ')
    page.locator('[data-bp-input="ip_mode"]').select_option('static')
    _fill(page, 'nameserver', '10.0.0.53')
    _fill(page, 'tags', 'app, prod ,')
    page.locator('[data-bp-input="start"]').uncheck()
    page.locator('[data-bp-editor-save]').click()
    assert _wait(page, lambda: ('POST', '/api/blueprints') in app.server.calls)
    assert app.server.bodies['/api/blueprints'][-1] == {
        'name': 'app-tier', 'description': '', 'source_kind': 'library', 'os': 'linux', 'template_id': 'c0ffee12',
        'cores': 4, 'memory': 6144, 'disk_gb': 40, 'cpu': '',
        'nics': [{'bridge': 'vmbr0', 'vlan': 30, 'model': 'virtio', 'firewall': False},
                 {'bridge': 'vmbr1', 'vlan': None, 'model': 'e1000', 'firewall': True}],
        'ciuser': 'ops', 'sshkeys': 'ssh-ed25519 AAAAC3Nza key1@lab\necdsa-sha2-nistp256 AAAAE2Vj key2@lab',
        'ip_mode': 'static', 'nameserver': '10.0.0.53', 'searchdomain': '', 'ciupgrade': True, 'tags': ['app', 'prod'], 'start': False}
    assert _wait(page, lambda: page.locator('[data-bp-editor]').count() == 0)
    assert _wait(page, lambda: _row(page, 'n7').count() == 1)


def test_runtime_a_refusal_of_the_server_stands_at_its_field(open_app):
    app = open_app()
    page = _page(app)
    _new(page)
    _fill(page, 'name', 'web-small')
    page.locator('[data-bp-input="template_id"]').select_option('debian-13')
    page.locator('[data-bp-editor-save]').click()
    hint = page.locator('[data-bp-field="name"] [data-bp-hint="error"]')
    hint.wait_for(timeout=4000)
    assert 'exists already' in hint.inner_text()
    # one the form has no field for stands on top
    _fill(page, 'name', 'boom')
    page.locator('[data-bp-editor-save]').click()
    note = page.locator('[data-bp-note="save"]')
    note.wait_for(timeout=4000)
    assert 'database is locked' in note.inner_text() and 'HTTP 500' in note.inner_text()


@pytest.mark.parametrize('layout', LAYOUTS)
def test_runtime_a_windows_template_blueprint_leaves_out_what_windows_ignores(open_app, layout):
    app = open_app(layout=layout)
    page = _page(app)
    _new(page)
    page.locator('[data-bp-source="template"]').click()
    assert page.locator('[data-bp-input="template_id"]').count() == 0
    os_pick = page.locator('[data-bp-input="os"]')
    assert [o.strip() for o in os_pick.locator('option').all_inner_texts()] == ['Linux', 'Windows']
    assert 'Cloud-Init user of the template' in _hint(page, 'ciuser').inner_text()
    os_pick.select_option('windows')
    for k in ('ciuser', 'sshkeys', 'searchdomain', 'ciupgrade'):
        assert page.locator(f'[data-bp-input="{k}"]').count() == 0, k
    # with the why
    note = page.locator('[data-bp-win-note]').inner_text()
    assert 'cloudbase-init' in note and 'administrator account' in note and 'search domains' in note
    page.locator('[data-bp-input="keepNet"]').check()
    assert page.locator('[data-bp-nic]').count() == 0 and page.locator('[data-bp-keepnet]').count() == 1
    _fill(page, 'name', 'win-server')
    _fill(page, 'cores', '4')
    _fill(page, 'memory', '8')
    page.locator('[data-bp-editor-save]').click()
    assert _wait(page, lambda: ('POST', '/api/blueprints') in app.server.calls)
    assert app.server.bodies['/api/blueprints'][-1] == {
        'name': 'win-server', 'description': '', 'source_kind': 'template', 'os': 'windows', 'template_id': '',
        'cores': 4, 'memory': 8192, 'disk_gb': 0, 'cpu': '', 'nics': [], 'ciuser': '', 'sshkeys': '',
        'ip_mode': 'dhcp', 'nameserver': '', 'searchdomain': '', 'ciupgrade': True, 'tags': [], 'start': True}


@pytest.mark.parametrize('layout', LAYOUTS)
def test_runtime_edit_fills_the_form_and_puts_it(open_app, layout):
    app = open_app(layout=layout)
    page = _page(app)
    page.locator('[data-bp-edit="b2"]').click()
    _need(page, '[data-bp-editor="b2"]', 'Edit opens the editor of that blueprint')
    assert page.locator('[data-bp-input="name"]').input_value() == 'db-static'
    assert page.locator('[data-bp-input="memory"]').input_value() == '8' and page.locator('[data-bp-input="memUnit"]').input_value() == 'GB'
    assert page.locator('[data-bp-nic-model="1"]').input_value() == 'e1000'
    # the bridges of a node of this cluster are suggested, read once
    assert _wait(page, lambda: page.evaluate("() => [...document.querySelectorAll('#bp-bridges option')].map(o => o.value)") == ['vmbr0', 'vmbr1'])
    _fill(page, 'cores', '8')
    page.locator('[data-bp-editor-save]').click()
    assert _wait(page, lambda: ('PUT', '/api/blueprints/b2') in app.server.calls)
    body = app.server.bodies['/api/blueprints/b2'][-1]
    assert body['cores'] == 8 and body['memory'] == 8192 and body['template_id'] == 'almalinux-10' and body['ip_mode'] == 'static'
    assert _count(app, 'GET', '/api/clusters/c1/nodes/pve1/network') == 1


# --- the deploy --------------------------------------------------------------------------------

def _deploy(page, bid='b1'):
    page.locator(f'[data-bp-deploy="{bid}"]').click()
    _need(page, f'[data-bp-deploy-form="{bid}"]', 'Deploy opens the deploy dialog')


def _options(page, field):
    return page.evaluate(f"() => [...document.querySelectorAll('[data-bp-dep=\"{field}\"] option')].map(o => o.value)")


@pytest.mark.parametrize('layout', LAYOUTS)
def test_runtime_a_library_deploy_reads_where_to_and_sends_its_body(open_app, layout):
    app = open_app(layout=layout, progress=[DONE])
    page = _page(app)
    _deploy(page)
    page.locator('[data-bp-dep="storage"] option[value="local-lvm"]').wait_for(state='attached', timeout=4000)
    # online nodes only, the storages of the node that take disk images, the next free VMID
    assert _options(page, 'node') == ['pve1', 'pve2'] and _options(page, 'storage') == ['local-lvm', 'ceph']
    assert page.locator('[data-bp-dep="vmid"]').input_value() == '105' and page.locator('[data-bp-dep="name"]').input_value() == 'web-small'
    page.locator('[data-bp-tpl="existing"]').wait_for(timeout=4000)
    assert page.locator('[data-bp-tpl="existing"]').get_attribute('data-bp-tpl-vmid') == '9001'
    assert 'network: net0 vmbr0, IP: DHCP' in page.locator('[data-bp-summary]').inner_text()
    assert page.locator('[data-bp-dep="ip"]').count() == 0 and page.locator('[data-bp-dep="template_vmid"]').count() == 0
    # pve2 has no template of the image: it is built first
    page.locator('[data-bp-dep="node"]').select_option('pve2')
    page.locator('[data-bp-tpl="build"]').wait_for(timeout=4000)
    page.locator('[data-bp-dep="node"]').select_option('pve1')
    page.locator('[data-bp-tpl="existing"]').wait_for(timeout=4000)
    page.locator('[data-bp-dep="password"]').fill('s3cret')
    page.locator('[data-bp-deploy-go]').click()
    assert _wait(page, lambda: ('POST', '/api/blueprints/b1/deploy') in app.server.calls)
    assert app.server.bodies['/api/blueprints/b1/deploy'][-1] == {
        'cluster_id': 'c1', 'node': 'pve1', 'storage': 'local-lvm', 'name': 'web-small', 'start': True, 'vmid': 105, 'cipassword': 's3cret'}
    _no_errors(app)


def test_runtime_a_static_address_is_checked_and_goes_as_ipconfig0(open_app):
    app = open_app(progress=[DONE])
    page = _page(app)
    _deploy(page, 'b2')
    page.locator('[data-bp-dep="storage"] option[value="local-lvm"]').wait_for(state='attached', timeout=4000)
    assert page.locator('[data-bp-dep="start"]').is_checked() is False
    page.locator('[data-bp-dep="ip"]').fill('10.0.0.300/24')
    page.locator('[data-bp-dep="gw"]').fill('gateway')
    page.locator('[data-bp-dep="name"]').fill('-db')
    page.locator('[data-bp-deploy-go]').click()
    page.wait_for_timeout(300)
    assert ('POST', '/api/blueprints/b2/deploy') not in app.server.calls
    assert _errors(page, '[data-bp-deploy-form]') == ['gw', 'ip', 'vmname']
    page.locator('[data-bp-dep="ip"]').fill('10.0.0.5/24')
    page.locator('[data-bp-dep="gw"]').fill('10.0.0.1')
    page.locator('[data-bp-dep="name"]').fill('db-01')
    page.locator('[data-bp-deploy-go]').click()
    assert _wait(page, lambda: ('POST', '/api/blueprints/b2/deploy') in app.server.calls)
    body = app.server.bodies['/api/blueprints/b2/deploy'][-1]
    assert body['ipconfig0'] == 'ip=10.0.0.5/24,gw=10.0.0.1' and body['start'] is False and 'cipassword' not in body


def test_runtime_a_bridge_the_node_lacks_is_said(open_app):
    app = open_app()
    page = _page(app)
    _deploy(page, 'b2')
    page.locator('[data-bp-dep="node"]').select_option('pve2')
    _need(page, '[data-bp-bridge-missing]', 'a bridge pve2 does not have is said')
    miss = page.locator('[data-bp-bridge-missing]')
    assert miss.get_attribute('data-bp-bridge-missing') == 'vmbr1' and 'vmbr1 is no bridge of pve2' in miss.inner_text()
    assert page.locator('[data-bp-deploy-go]').is_enabled()


@pytest.mark.parametrize('layout', LAYOUTS)
def test_runtime_a_template_of_another_node_offers_shared_storage_only(open_app, layout):
    pve2 = [{'storage': 'local-zfs', 'content': 'images,rootdir', 'enabled': 1, 'active': 1, 'shared': 0},
            {'storage': 'ceph', 'content': 'images', 'enabled': 1, 'active': 1, 'shared': 1}]
    app = open_app(layout=layout, extra={('GET', '/api/clusters/c1/nodes/pve2/storage'): (200, pve2)})
    page = _page(app)
    _deploy(page, 'b6')
    page.locator('[data-bp-dep="template_vmid"] option[value="9200"]').wait_for(state='attached', timeout=4000)
    # no template remembered for this cluster: none picked, the deploy would remember it
    assert page.locator('[data-bp-dep="template_vmid"]').input_value() == ''
    assert 'remembers this template' in _hint(page, 'template_vmid').inner_text()
    page.locator('[data-bp-dep="node"]').select_option('pve2')
    assert _wait(page, lambda: _options(page, 'storage') == ['local-zfs', 'ceph'])
    # rocky-9-golden sits on pve1: on pve2 only the shared ceph is left, and picked
    page.locator('[data-bp-dep="template_vmid"] option[value="9200"]').wait_for(state='attached', timeout=4000)
    page.locator('[data-bp-dep="template_vmid"]').select_option('9200')
    assert _wait(page, lambda: _options(page, 'storage') == ['ceph'])
    assert page.locator('[data-bp-dep="storage"]').input_value() == 'ceph'
    assert _hint(page, 'storage').inner_text() == 'The template is on pve1: a clone onto this node goes to shared storage only.'
    page.locator('[data-bp-deploy-go]').click()
    assert _wait(page, lambda: ('POST', '/api/blueprints/b6/deploy') in app.server.calls)
    body = app.server.bodies['/api/blueprints/b6/deploy'][-1]
    assert body['template_vmid'] == 9200 and body['node'] == 'pve2' and body['storage'] == 'ceph'


def test_runtime_a_node_without_shared_storage_says_so(open_app):
    app = open_app()
    page = _page(app)
    _deploy(page, 'b6')
    page.locator('[data-bp-dep="template_vmid"] option[value="9200"]').wait_for(state='attached', timeout=4000)
    page.locator('[data-bp-dep="node"]').select_option('pve2')
    page.locator('[data-bp-dep="template_vmid"] option[value="9200"]').wait_for(state='attached', timeout=4000)
    page.locator('[data-bp-dep="template_vmid"]').select_option('9200')
    assert _wait(page, lambda: page.locator('[data-bp-dep="storage"]').is_disabled())
    hint = _hint(page, 'storage')
    assert hint.get_attribute('data-bp-hint') == 'warning'
    assert hint.inner_text().startswith('The template is on pve1 and this node has no shared storage for disk images.')
    page.locator('[data-bp-deploy-go]').click()
    page.wait_for_timeout(300)
    assert ('POST', '/api/blueprints/b6/deploy') not in app.server.calls


@pytest.mark.parametrize('layout', LAYOUTS)
def test_runtime_a_windows_deploy_needs_the_administrator_password_and_warns_past_15(open_app, layout):
    app = open_app(layout=layout, progress=[RUNNING])
    page = _page(app)
    _deploy(page, 'b5')
    pick = page.locator('[data-bp-dep="template_vmid"]')
    page.locator('[data-bp-dep="template_vmid"] option[value="9100"]').wait_for(state='attached', timeout=4000)
    # the remembered one picked, the ones pve1 cannot clone offered with the reason and not to be picked
    assert _wait(page, lambda: pick.input_value() == '9100')
    opts = page.evaluate("""() => [...document.querySelectorAll('[data-bp-dep="template_vmid"] option')].map(o => [o.value, o.disabled, o.textContent])""")
    assert opts[1:] == [['9100', False, 'win2022-golden (9100) · pve1 · win11'],
                        ['9101', True, 'win11-plain (9101) · pve1 · win11 (no Cloud-Init drive)'],
                        ['9102', True, 'win2019 (9102) · pve2 · win10 (on pve2, disks not on shared storage)']]
    assert 'used on this cluster before' in _hint(page, 'template_vmid').inner_text()
    assert page.locator('[data-bp-tpl]').count() == 0
    assert page.locator('label[for="bp-f-password"]').inner_text() == 'Administrator password'
    assert 'Required for Windows' in _hint(page, 'password').inner_text()
    # typed once: it can be looked at before the deploy
    pw, show = page.locator('[data-bp-dep="password"]'), page.locator('[data-bp-pw-show]')
    pw.fill('Adm1n!pass')
    assert pw.get_attribute('type') == 'password' and show.get_attribute('aria-label') == 'Show password'
    show.click()
    assert pw.get_attribute('type') == 'text' and show.get_attribute('aria-pressed') == 'true'
    show.click()
    pw.fill('')
    # a name past 15 characters warns, a missing password stops the deploy
    page.locator('[data-bp-dep="name"]').fill('win-desktop-finance-01')
    warn = page.locator('[data-bp-field="vmname"] [data-bp-hint="warning"]')
    assert 'first 15 characters' in warn.inner_text()
    page.locator('[data-bp-deploy-go]').click()
    page.wait_for_timeout(300)
    assert ('POST', '/api/blueprints/b5/deploy') not in app.server.calls
    assert 'Enter a password' in page.locator('[data-bp-field="password"] [data-bp-hint="error"]').inner_text()
    pw.fill('Adm1n!pass')
    page.locator('[data-bp-deploy-go]').click()
    assert _wait(page, lambda: ('POST', '/api/blueprints/b5/deploy') in app.server.calls)
    assert app.server.bodies['/api/blueprints/b5/deploy'][-1] == {
        'cluster_id': 'c1', 'node': 'pve1', 'storage': 'local-lvm', 'name': 'win-desktop-finance-01', 'start': True,
        'vmid': 105, 'template_vmid': 9100, 'cipassword': 'Adm1n!pass'}
    _need(page, '[data-bp-progress="d1"]', 'the progress view follows the deploy')
    assert page.locator('[data-bp-step="template"]').count() == 0


@pytest.mark.parametrize('layout', LAYOUTS)
def test_runtime_the_deploy_dialog_names_the_keys_and_who_saved_them(open_app, layout):
    bare = _bp('b7', 'bare-keys', ciuser='', created_by='bob',
               sshkeys='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOpenkey12\n# retired\nssh-rsa AAAAB3NzaC1yc2E ci build box')
    app = open_app(layout=layout, blueprints=[OTHER, WIN, bare])
    page = _page(app)
    note = page.locator('[data-bp-access]')
    _deploy(page, 'b3')
    assert note.get_attribute('data-bp-access') == 'alice'
    assert note.inner_text() == 'Goes into the VM: the SSH keys admin@lab for the user debian, saved in the blueprint by alice.'
    page.locator('[data-bp-deploy-cancel]').click()
    _deploy(page, 'b7')
    assert note.inner_text() == ('Goes into the VM: the SSH keys ssh-ed25519 …penkey12, ci build box for the default user '
                                 'of the image, saved in the blueprint by bob.')
    page.locator('[data-bp-deploy-cancel]').click()
    _deploy(page, 'b5')
    page.wait_for_timeout(300)
    assert note.count() == 0


@pytest.mark.parametrize('layout', LAYOUTS)
def test_runtime_the_server_notes_show_and_the_progress_is_read_until_done(open_app, layout):
    notes = ['Windows uses the first 15 characters of the name as its computer name']
    app = open_app(layout=layout, progress=[RUNNING, RUNNING, DONE], warnings=notes, resources=RESOURCES + [MADE])
    page = _page(app)
    _deploy(page)
    page.locator('[data-bp-dep="storage"] option[value="local-lvm"]').wait_for(state='attached', timeout=4000)
    page.locator('[data-bp-deploy-go]').click()
    _need(page, '[data-bp-progress="d1"]', 'the dialog shows the progress of the deploy it started')
    assert page.locator('[data-bp-warnings] li').all_inner_texts() == notes
    assert _wait(page, lambda: page.locator('[data-bp-progress][data-bp-status="completed"]').count() == 1, timeout=12)
    reads = len(app.server.prog_reads)
    assert reads == 3
    page.wait_for_timeout(3000)
    assert len(app.server.prog_reads) == reads
    steps = page.evaluate("() => Object.fromEntries([...document.querySelectorAll('[data-bp-step]')].map(s => [s.dataset.bpStep, s.dataset.state]))")
    assert 'template' not in steps and set(steps.values()) == {'done'}, steps
    assert 'configured' in page.locator('[data-bp-log]').text_content()
    # Open guest leads to the guest list of its cluster
    page.locator('[data-bp-open-guest="105"]').click()
    _guest_opened(app, 'web-small')


def test_runtime_a_failed_deploy_stops_the_reads_and_says_why(open_app):
    app = open_app(progress=[FAILED])
    page = _page(app)
    _deploy(page)
    page.locator('[data-bp-dep="storage"] option[value="local-lvm"]').wait_for(state='attached', timeout=4000)
    page.locator('[data-bp-deploy-go]').click()
    page.locator('[data-bp-failed]').wait_for(timeout=6000)
    assert 'storage full' in page.locator('[data-bp-failed]').inner_text()
    page.wait_for_timeout(3000)
    assert len(app.server.prog_reads) == 1
    assert page.locator('[data-bp-step="resize"]').get_attribute('data-state') == 'failed'
    assert page.locator('[data-bp-open-guest]').count() == 0


def test_runtime_a_refused_deploy_stays_in_the_dialog(open_app):
    app = open_app(deploy_status=403)
    page = _page(app)
    _deploy(page)
    page.locator('[data-bp-dep="storage"] option[value="local-lvm"]').wait_for(state='attached', timeout=4000)
    page.locator('[data-bp-deploy-go]').click()
    note = page.locator('[data-bp-note="deploy"]')
    note.wait_for(timeout=4000)
    assert 'tenant VMID range' in note.inner_text()
    assert page.locator('[data-bp-progress]').count() == 0 and app.server.prog_reads == []


# --- the recent deploys ------------------------------------------------------------------------

@pytest.mark.parametrize('layout', LAYOUTS)
def test_runtime_recent_deploys_of_this_cluster_or_of_all(open_app, layout):
    app = open_app(layout=layout, resources=RESOURCES + [WEB_01])
    page = _page(app)
    box = page.locator('[data-bp-recent="cluster"]')
    box.locator('[data-bp-recent-row]').first.wait_for(timeout=8000)
    # this cluster: newest first, the failure with its reason, a finished guest to open
    assert page.evaluate("() => [...document.querySelectorAll('[data-bp-recent-row]')].map(r => r.dataset.bpRecentRow)") == ['r2', 'r1']
    failed = page.locator('[data-bp-recent-row="r2"]').inner_text()
    assert 'db-static' in failed and 'Failed' in failed and 'download failed (rc=8)' in failed
    assert page.locator('[data-bp-recent-row="r1"] [data-bp-guest="120"]').count() == 1
    assert page.locator('[data-bp-recent-row="r2"] [data-bp-guest]').count() == 0
    assert page.locator('[data-bp-recent-cluster]').count() == 0
    # all clusters: one read without the cluster, a column of the cluster
    page.locator('[data-bp-recent-scope="all"]').click()
    page.locator('[data-bp-recent="all"] [data-bp-recent-row="r3"]').wait_for(timeout=8000)
    assert f'{BASE}/api/blueprints/deployments' in app.server.urls
    assert page.locator('[data-bp-recent-row="r3"] [data-bp-recent-cluster]').inner_text() == 'c2'
    assert page.locator('[data-bp-recent-row="r1"] [data-bp-recent-cluster]').inner_text() == 'Testi'
    assert page.locator('[data-bp-recent-scope="all"]').get_attribute('aria-pressed') == 'true'
    # a finished guest opens in the guest list of its cluster
    page.locator('[data-bp-recent-scope="cluster"]').click()
    page.locator('[data-bp-guest="120"]').first.click()
    _guest_opened(app, 'web-01')
    _no_errors(app)


@pytest.mark.parametrize('layout', LAYOUTS)
def test_runtime_recent_deploys_say_when_there_are_none_and_follow_a_new_one(open_app, layout):
    app = open_app(layout=layout, progress=[RUNNING])
    app.server.recent = []
    page = _page(app)
    _need(page, '[data-bp-recent-empty]', 'no deploy yet is said')
    assert page.locator('[data-bp-recent-empty]').inner_text() == 'No guest has been deployed from a blueprint on this cluster yet.'
    before = len([u for u in app.server.urls if '/api/blueprints/deployments?' in u])
    # a deploy the section started is read in: the list asks again
    app.server.recent = [dict(RECENT[0], id='d1', status='running', step='clone', progress=40, vmid=105, name='web-small')]
    _deploy(page)
    page.locator('[data-bp-dep="storage"] option[value="local-lvm"]').wait_for(state='attached', timeout=4000)
    page.locator('[data-bp-deploy-go]').click()
    _need(page, '[data-bp-progress="d1"]', 'the progress view opens')
    page.locator('[data-bp-deploy-close]').click()
    page.locator('[data-bp-recent-row="d1"]').wait_for(timeout=6000)
    assert page.locator('[data-bp-recent-row="d1"] [data-bp-state="running"]').count() == 1
    # and again while it runs
    reads = lambda: len([u for u in app.server.urls if '/api/blueprints/deployments?' in u])
    seen = reads()
    assert seen >= before + 1
    assert _wait(page, lambda: reads() >= seen + 1, timeout=7)


# --- the ways there ----------------------------------------------------------------------------

def test_runtime_the_resources_button_leads_there(open_app):
    app = open_app()
    page = app.page
    page.get_by_text('Testi').first.click()
    page.locator('button', has_text=re.compile(r'^\s*Resources\s*$')).first.click()
    btn = page.locator('[data-bp-nav="resources"]')
    btn.wait_for(timeout=8000)
    assert btn.inner_text().strip() == 'Deploy VM from blueprint'
    # next to the create buttons
    create = page.locator('button', has_text=re.compile(r'^\s*Create new Container\s*$')).first
    assert abs(create.bounding_box()['y'] - btn.bounding_box()['y']) < 2
    btn.click()
    _need(page, '[data-bp-row]', 'the Resources button leads to the blueprints')
    assert page.locator('button.bg-proxmox-orange', has_text=re.compile(r'^\s*Blueprints & Templates\s*$')).count() == 1


def test_runtime_ctrl_k_leads_there(open_app):
    app = open_app()
    page = app.page
    page.locator('body').click(position={'x': 5, 'y': 400})
    page.keyboard.press('Control+k')
    page.get_by_placeholder(re.compile('Type to search')).fill('blueprint')
    hit = page.locator('[data-cmdpal-idx]', has_text='Deploy VM from blueprint')
    hit.first.wait_for(timeout=5000)
    hit.first.click()
    _need(page, '[data-bp-row]', 'the palette action leads to the blueprints of the cluster')


# --- who may ------------------------------------------------------------------------------------

def test_runtime_without_vm_create_nothing_is_read_and_there_is_no_way_there(open_app):
    app = open_app(admin=False, permissions=['cluster.view', 'vm.view'])
    page = _templates(app)
    _need(page, '[data-bp-noperm]', 'an account without vm.create is told why')
    page.wait_for_timeout(500)
    assert page.locator('[data-bp-row], [data-bp-recent]').count() == 0
    assert [c for c in app.server.calls if c[1].startswith('/api/blueprints')] == []
    page.locator('button', has_text=re.compile(r'^\s*Resources\s*$')).first.click()
    page.get_by_text('Create new VM').first.wait_for(timeout=8000)
    assert page.locator('[data-bp-nav]').count() == 0
    page.keyboard.press('Control+k')
    page.get_by_placeholder(re.compile('Type to search')).fill('blueprint')
    page.wait_for_timeout(400)
    assert page.locator('[data-cmdpal-idx]', has_text='from blueprint').count() == 0


def test_runtime_a_standby_shows_the_list_and_changes_nothing(open_app):
    app = open_app(role='standby')
    page = _page(app)
    _need(page, '[data-bp-standby]', 'a standby says why nothing can be changed here')
    new = page.locator('[data-bp-new]')
    assert new.is_disabled() and 'standby' in new.get_attribute('title')
    assert page.locator('[data-bp-deploy="b1"]').is_disabled() and page.locator('[data-bp-edit="b1"]').is_disabled()
    assert page.locator('[data-bp-delete="b1"]').is_disabled()
    # the reads stay
    page.locator('[data-bp-recent-row]').first.wait_for(timeout=8000)
    page.locator('button', has_text=re.compile(r'^\s*Resources\s*$')).first.click()
    page.wait_for_timeout(800)
    assert page.locator('[data-bp-nav]').count() == 0


# --- Cloud ---------------------------------------------------------------------------------------

def _cloud_nav(page, label):
    page.locator('.cloud-nav-item', has_text=re.compile(rf'^\s*{re.escape(label)}\s*$')).first.click()


def _classes(page, selector):
    return (page.locator(selector).first.get_attribute('class') or '').split()


def test_runtime_cloud_draws_them_with_the_controls_of_its_shell(open_app):
    app = open_app(layout='cloud')
    page = _page(app)
    page.wait_for_timeout(400)
    assert page.locator('[data-bp-layout="cloud"]').count() == 1
    # in the frame of the mounted pages, above the library, which stays
    assert page.locator('.cloud-mounted [data-bp]').count() == 1
    lib = page.get_by_text(LIB, exact=True).first
    lib.wait_for(timeout=8000)
    sec = _box(page, '[data-bp]')
    assert sec['y'] + sec['height'] <= lib.bounding_box()['y']
    assert page.evaluate("() => [...document.querySelectorAll('[data-bp-row]')].map(e => e.dataset.bpRow)") == ['b2', 'b3', 'b4', 'b6', 'b1', 'b5']
    # the buttons, table cards, chips and switches of the shell
    assert 'cloud-btn-primary' in _classes(page, '[data-bp-new]') and 'cloud-btn' in _classes(page, '[data-bp-refresh]')
    assert 'cloud-btn-sm' in _classes(page, '[data-bp-deploy="b1"]') and 'cloud-icon-btn' in _classes(page, '[data-bp-edit="b1"]')
    assert 'cloud-table' in _classes(page, '[data-bp-table]')
    assert page.locator('.cloud-card.cloud-table-card [data-bp-table]').count() == 1
    assert 'cloud-count-chip' in _classes(page, '[data-bp-count]') and 'cloud-chip' in _classes(page, '[data-bp-scope="all"]')
    assert 'cloud-chip-tag' in _classes(page, '[data-bp-row="b1"] [data-bp-tag="web"]')
    assert 'cloud-chip' in _classes(page, '[data-bp-row="b5"] [data-bp-source-cell="template"] span')
    assert page.locator('.cloud-card.cloud-table-card[data-bp-recent] > .cloud-toolbar').count() == 1
    assert page.locator('[data-bp-recent] .cloud-segment [data-bp-recent-scope="cluster"].is-active').count() == 1
    assert page.locator('[data-bp-recent] table.cloud-table [data-bp-recent-row="r1"]').count() == 1
    assert page.locator('[data-bp] .bg-proxmox-orange, [data-bp] .bg-proxmox-card').count() == 0
    # and in the dialogs
    page.locator('[data-bp-new]').click()
    _need(page, '[data-bp-editor="new"]', 'New blueprint opens the editor')
    assert 'cloud-input' in _classes(page, '[data-bp-input="name"]') and 'cloud-input' in _classes(page, '[data-bp-input="ip_mode"]')
    assert page.locator('[data-bp-editor] .cloud-segment [data-bp-source="library"].is-active').count() == 1
    assert page.locator('[data-bp-modal="editor"] > .bp-cloud-dialog').count() == 1
    assert 'cloud-btn-primary' in _classes(page, '[data-bp-editor-save]') and 'cloud-icon-btn' in _classes(page, '[data-bp-modal-close]')
    # one read of the list and one of the deploys of this cluster
    assert _count(app, 'GET', '/api/blueprints') == 1
    assert [u for u in app.server.urls if '/api/blueprints/deployments' in u] == [f'{BASE}/api/blueprints/deployments?cluster_id=c1']
    _no_errors(app)


# the surface of a card and of a dialog, the text, the muted text and the text of a primary button of the
# two Cloud themes
CLOUD_THEME = {'dark': ('rgb(22, 48, 74)', 'rgb(230, 241, 248)', 'rgb(138, 164, 184)', 'rgb(4, 20, 28)'),
               'light': ('rgb(255, 255, 255)', 'rgb(22, 34, 46)', 'rgb(106, 122, 137)', 'rgb(255, 255, 255)')}


@pytest.mark.parametrize('theme', ['dark', 'light'])
def test_runtime_cloud_takes_the_colours_of_its_dark_and_light_theme(open_app, theme):
    app = open_app(layout='cloud', storage={'pegaprox-cloud-theme': theme})
    page = _page(app)
    assert page.evaluate('() => document.body.dataset.cloudTheme') == theme
    css = lambda sel, prop: page.evaluate('([s, p]) => getComputedStyle(document.querySelector(s))[p]', [sel, prop])
    card, text, muted, on_primary = CLOUD_THEME[theme]
    assert css('[data-bp-recent]', 'backgroundColor') == card
    assert css('[data-bp-row="b1"] td .bp-fg', 'color') == text and css('[data-bp] h2', 'color') == text
    assert css('[data-bp-row="b1"] td .text-gray-500', 'color') == muted
    assert css('[data-bp-new]', 'color') == on_primary
    page.locator('[data-bp-delete="b1"]').click()
    _need(page, '[data-bp-confirm="delete"]', 'Delete asks before it deletes')
    assert css('[data-bp-modal="delete"] > .bp-cloud-dialog', 'backgroundColor') == card
    assert css('[data-bp-confirm="delete"]', 'color') == text
    # the danger button of the shell is pink on the dark theme, a darker red on the light one
    assert css('[data-bp-confirm-go]', 'color') == ('rgb(244, 134, 138)' if theme == 'dark' else 'rgb(185, 28, 28)')
    _no_errors(app)


@pytest.mark.parametrize('layout', LAYOUTS)
def test_runtime_a_dialog_dims_the_whole_window(open_app, layout):
    page = _page(open_app(layout=layout))
    page.locator('[data-bp-delete="b1"]').click()
    _need(page, '[data-bp-modal="delete"]', 'Delete opens its dialog')
    # the section spaces its children; the backdrop of a dialog is one of them and starts at the top all the same
    box = page.evaluate("""() => { const r = document.querySelector('[data-bp-modal]').getBoundingClientRect();
        return [r.top, r.left, r.width, r.height, innerWidth, innerHeight]; }""")
    assert box[:4] == [0, 0, box[4], box[5]], box


def test_runtime_cloud_names_the_page_after_both(open_app):
    page = _page(open_app(layout='cloud'))
    assert page.locator('.cloud-nav-item-active').inner_text().strip() == 'Blueprints & Templates'
    assert page.locator('.cloud-breadcrumb-leaf').inner_text().strip() == 'Blueprints & Templates'
    assert page.locator('.cloud-nav-item', has_text=re.compile(r'^\s*Templates\s*$')).count() == 0


def _nav_names():
    """bpNavTab of each language as the build under test has it (de, en, zh, pl, fr, es, pt, ko, it, ru). LW Nov 2026 -
    the bundle carries English and build.sh writes the others to web/i18n/<lang>.json; an older bundle has all of them."""
    langs = ['de', 'en', 'zh', 'pl', 'fr', 'es', 'pt', 'ko', 'it', 'ru']
    names = re.findall(r'bpNavTab:\s*"([^"]+)"', BUNDLE or _read('web', 'index.html'))
    if len(names) == len(langs):
        return dict(zip(langs, names))
    assert len(names) == 1
    out = {lang: json.loads(_read('web', 'i18n', f'{lang}.json'))['bpNavTab'] for lang in langs if lang != 'en'}
    out['en'] = names[0]
    return out


@pytest.mark.parametrize('lang', ['de', 'en', 'zh', 'pl', 'fr', 'es', 'pt', 'ko', 'it', 'ru'])
def test_runtime_cloud_the_name_of_the_page_stays_on_one_line_of_the_nav(open_app, lang):
    page = open_app(layout='cloud', language=lang).page
    _cloud_nav(page, _nav_names()[lang])
    _need(page, '[data-bp]', f'the name of the page in {lang} leads to the blueprints')
    # the active entry is bold: it is as high as an entry of one line (German wrapped there)
    page.wait_for_timeout(200)
    heights = page.evaluate("""() => [...document.querySelectorAll('.cloud-nav-item')].map(e => [
        e.classList.contains('cloud-nav-item-active'), Math.round(e.getBoundingClientRect().height)])""")
    active = [h for on, h in heights if on]
    assert len(active) == 1 and active[0] == min(h for on, h in heights if not on), heights


def test_runtime_cloud_the_vms_page_leads_there(open_app):
    app = open_app(layout='cloud')
    page = app.page
    _cloud_nav(page, 'Virtual Machines')
    btn = page.locator('[data-bp-nav="cloud-vms"]')
    btn.wait_for(timeout=8000)
    assert btn.inner_text().strip() == 'Deploy VM from blueprint' and 'cloud-btn' in _classes(page, '[data-bp-nav="cloud-vms"]')
    # in the header of the page, in front of New VM
    new = page.locator('.cloud-page-header-actions button', has_text=re.compile(r'^\s*New VM\s*$'))
    a, b = btn.bounding_box(), new.bounding_box()
    assert abs(a['y'] - b['y']) < 2 and a['x'] < b['x']
    # a container comes from no blueprint
    _cloud_nav(page, 'Containers')
    page.locator('.cloud-page-title', has_text='Containers').wait_for(timeout=8000)
    assert page.locator('[data-bp-nav]').count() == 0
    _cloud_nav(page, 'Virtual Machines')
    page.locator('[data-bp-nav="cloud-vms"]').click()
    _need(page, '[data-bp-row]', 'the button leads to the blueprints of the cluster')
    assert page.locator('.cloud-nav-item-active').inner_text().strip() == 'Blueprints & Templates'


def test_runtime_cloud_without_vm_create_reads_nothing_and_has_no_button(open_app):
    app = open_app(layout='cloud', admin=False, permissions=['cluster.view', 'vm.view'])
    page = _templates(app)
    _need(page, '[data-bp-noperm]', 'an account without vm.create is told why')
    page.wait_for_timeout(500)
    assert page.locator('[data-bp-row], [data-bp-recent]').count() == 0
    assert [c for c in app.server.calls if c[1].startswith('/api/blueprints')] == []
    _cloud_nav(page, 'Virtual Machines')
    page.locator('.cloud-page-title', has_text='Virtual Machines').wait_for(timeout=8000)
    page.wait_for_timeout(300)
    assert page.locator('[data-bp-nav]').count() == 0


def test_runtime_cloud_on_a_standby_lists_them_and_changes_nothing(open_app):
    app = open_app(layout='cloud', role='standby')
    page = _page(app)
    _need(page, '[data-bp-standby]', 'a standby says why nothing can be changed here')
    new = page.locator('[data-bp-new]')
    assert new.is_disabled() and 'standby' in new.get_attribute('title')
    assert page.locator('[data-bp-deploy="b1"]').is_disabled() and page.locator('[data-bp-edit="b1"]').is_disabled()
    assert page.locator('[data-bp-delete="b1"]').is_disabled()
    page.locator('[data-bp-recent-row]').first.wait_for(timeout=8000)
    _cloud_nav(page, 'Virtual Machines')
    page.locator('.cloud-page-title', has_text='Virtual Machines').wait_for(timeout=8000)
    page.wait_for_timeout(300)
    assert page.locator('[data-bp-nav]').count() == 0


# --- 1280 px, the light palettes, the keyboard -------------------------------------------------

# the way to the blueprints in German and Italian: Automation, then the sub tab or the Cloud page
AUTOMATION = {'de': 'Automatisierung', 'it': 'Automazione'}
# the contrast of the text of an element on what lies under it (the tints laid over the first opaque
# background up the tree, else white)
CONTRAST = """(sel) => {
    const el = document.querySelector(sel);
    const rgb = (s) => { const m = s.match(/[\\d.]+/g).map(Number); return [m[0], m[1], m[2], m.length > 3 ? m[3] : 1]; };
    const lum = (c) => { const f = (v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); };
        return 0.2126 * f(c[0]) + 0.7152 * f(c[1]) + 0.0722 * f(c[2]); };
    const layers = [];
    for (let e = el; e; e = e.parentElement) {
        const c = rgb(getComputedStyle(e).backgroundColor);
        if (c[3] > 0) layers.push(c);
        if (c[3] >= 1) break;
    }
    let bg = [255, 255, 255];
    for (const [r, g, b, a] of layers.reverse()) bg = [r * a + bg[0] * (1 - a), g * a + bg[1] * (1 - a), b * a + bg[2] * (1 - a)];
    const [hi, lo] = [lum(rgb(getComputedStyle(el).color)), lum(bg)].sort((x, y) => y - x);
    return Math.round((hi + 0.05) / (lo + 0.05) * 100) / 100;
}"""
# the chips of the list and of the recent deploys
CHIPS = {'count': '[data-bp-count]', 'all clusters': '[data-bp-scope="all"]', 'template': '[data-bp-row="b5"] [data-bp-source-cell] span',
         'image removed': '[data-bp-row="b4"] [data-bp-image="missing"] > span', 'completed': '[data-bp-recent-row="r1"] [data-bp-state]',
         'failed': '[data-bp-recent-row="r2"] [data-bp-state]'}


def _page_in(app, lang):
    """_page for an account that reads the app in German or Italian."""
    page = app.page
    name = _nav_names()[lang]
    if app.layout == 'cloud':
        _cloud_nav(page, name)
    else:
        page.get_by_text('Testi').first.click()
        page.locator('button', has_text=re.compile(rf'^\s*{AUTOMATION[lang]}\s*$')).first.click()
        page.locator('button', has_text=re.compile(rf'^\s*{re.escape(name)}\s*$')).first.click()
    _need(page, '[data-bp-row]', f'the blueprints in {lang}')
    page.wait_for_timeout(300)
    return page


def _resources(page, label='Resources'):
    page.get_by_text('Testi').first.click()
    page.locator('button', has_text=re.compile(rf'^\s*{label}\s*$')).first.click()
    page.locator('[data-bp-nav="resources"]').wait_for(timeout=8000)


def test_runtime_the_resources_row_wraps_whole_buttons(open_app):
    # in German the four buttons are wider than the row at 1280 px
    page = open_app(language='de', viewport=(1280, 800)).page
    _resources(page, 'Ressourcen')
    # each button: where it starts, on how many lines its label stands, and that it ends in the row
    row = page.evaluate("""() => { const row = document.querySelector('[data-bp-nav="resources"]').parentElement, box = row.getBoundingClientRect();
        return [...row.children].map(k => {
            const tops = new Set(), walk = document.createTreeWalker(k, NodeFilter.SHOW_TEXT), range = document.createRange();
            for (let n = walk.nextNode(); n; n = walk.nextNode()) {
                if (!n.textContent.trim()) continue;
                range.selectNodeContents(n);
                for (const q of range.getClientRects()) tops.add(Math.round(q.top));
            }
            const r = k.getBoundingClientRect();
            return [Math.round(r.y), tops.size, r.right <= box.right + 0.5]; }); }""")
    # the row breaks between them, no label breaks in two
    assert len(row) == 4 and len({y for y, _, _ in row}) > 1, row
    assert all(lines == 1 and inside for _, lines, inside in row), row


def test_runtime_the_resources_button_lands_on_the_top_of_the_page(open_app):
    page = open_app(viewport=(1280, 800)).page
    _resources(page)
    page.evaluate('() => window.scrollTo(0, document.documentElement.scrollHeight)')
    page.locator('[data-bp-nav="resources"]').click()
    _need(page, '[data-bp-row]', 'the Resources button leads to the blueprints')
    page.wait_for_timeout(300)
    assert page.evaluate('() => window.scrollY') == 0
    # the title of the section is in view, under the header
    top = _box(page, '[data-bp] h2')['y']
    assert page.evaluate("() => document.querySelector('header').getBoundingClientRect().bottom") <= top < 800


def test_runtime_an_esxi_cluster_has_no_way_to_the_blueprints(open_app):
    esxi = dict(CLUSTER, id='e1', name='ESXI-Test', display_name='ESXI-Test', cluster_type='esxi', host='10.0.0.9')
    app = open_app(clusters=[esxi, CLUSTER])
    page = app.page
    page.get_by_text('ESXI-Test').first.click()
    page.locator('button', has_text=re.compile(r'^\s*Resources\s*$')).first.click()
    page.get_by_text('Create new VM').first.wait_for(timeout=8000)
    page.wait_for_timeout(500)
    assert page.locator('[data-bp-nav]').count() == 0
    # its Proxmox VE neighbour has it
    _resources(page)


@pytest.mark.parametrize('layout', LAYOUTS)
def test_runtime_at_1280_the_buttons_stay_on_the_title_row(open_app, layout):
    page = _page_in(open_app(layout=layout, language='de', viewport=(1280, 800)), 'de')
    head, new, sec = _box(page, '[data-bp] h2'), _box(page, '[data-bp-new]'), _box(page, '[data-bp]')
    assert abs(new['y'] - head['y']) < 4, (head, new)
    assert abs((new['x'] + new['width']) - (sec['x'] + sec['width'])) < 1.5, (new, sec)


@pytest.mark.parametrize('layout', LAYOUTS)
def test_runtime_the_cloud_init_fields_fill_their_row(open_app, layout):
    page = _page(open_app(layout=layout))
    page.locator('[data-bp-edit="b2"]').click()
    _need(page, '[data-bp-editor="b2"]', 'Edit opens the editor')
    page.wait_for_timeout(300)
    box = page.evaluate("""() => { const g = document.querySelector('[data-bp-group="ci"]').getBoundingClientRect();
        const f = (id) => document.querySelector(`[data-bp-group="ci"] [data-bp-field="${id}"]`).getBoundingClientRect();
        return { left: g.left, right: g.right, search: f('searchdomain').right, keys: [f('sshkeys').left, f('sshkeys').right] }; }""")
    # the four fields end where the group ends, the keys run under them over the whole width
    assert abs(box['search'] - box['right']) < 1.5, box
    assert abs(box['keys'][0] - box['left']) < 1 and abs(box['keys'][1] - box['right']) < 1.5, box


@pytest.mark.parametrize('layout', LAYOUTS)
def test_runtime_at_1280_the_list_fits_in_italian_and_with_a_long_name(open_app, layout):
    fits = """() => { const sc = document.querySelector('[data-bp-table]').parentElement; const c = sc.getBoundingClientRect();
        const d = [...document.querySelectorAll('[data-bp-deploy]')].map(b => b.getBoundingClientRect().right);
        return [sc.scrollWidth - sc.clientWidth, Math.max(...d) <= c.right]; }"""
    page = _page_in(open_app(layout=layout, language='it', viewport=(1280, 800)), 'it')
    assert page.evaluate(fits) == [0, True]
    # a name of 64 characters without a break
    long = _bp('l1', 'x' * 64, tags=['production'])
    page = _page(open_app(layout=layout, viewport=(1280, 800), blueprints=[long, copy.deepcopy(WEB)]))
    assert page.evaluate(fits) == [0, True]
    assert _row(page, 'b1').inner_text().count('2 vCPU · 2 GB · 20 GB') == 1


@pytest.mark.parametrize('layout', LAYOUTS)
def test_runtime_a_dialog_takes_the_focus_and_hands_it_back(open_app, layout):
    page = _page(open_app(layout=layout))
    inside = "() => document.querySelector('[data-bp-modal=\"editor\"]').contains(document.activeElement)"
    page.locator('[data-bp-new]').click()
    _need(page, '[data-bp-editor="new"]', 'New blueprint opens the editor')
    assert page.evaluate(inside)
    # Tab goes round the fields of the dialog, either way, and never to the page behind it
    for key in ['Tab'] * 40 + ['Shift+Tab'] * 5:
        page.keyboard.press(key)
        assert page.evaluate(inside), key
    page.keyboard.press('Escape')
    assert _wait(page, lambda: page.locator('[data-bp-modal]').count() == 0)
    assert page.evaluate("() => document.activeElement && document.activeElement.hasAttribute('data-bp-new')")


@pytest.mark.parametrize('layout', LAYOUTS)
def test_runtime_a_glyph_in_a_chip_is_as_small_as_its_text(open_app, layout):
    page = _page(open_app(layout=layout))
    for sel in (CHIPS['all clusters'], CHIPS['image removed']):
        # icons.js draws the globe and the triangle at 20 px whatever class they are given
        size = page.locator(f'{sel} svg').evaluate('e => [e.getBoundingClientRect().width, e.getBoundingClientRect().height]')
        assert size == [12, 12], (sel, size)
        # and the chip is as high as it is without its glyph
        heights = page.evaluate("""(sel) => { const e = document.querySelector(sel), g = e.querySelector('svg');
            const a = e.getBoundingClientRect().height; g.style.display = 'none';
            const b = e.getBoundingClientRect().height; g.style.display = ''; return [a, b]; }""", sel)
        assert heights[0] == heights[1], (sel, heights)


@pytest.mark.parametrize('layout', LAYOUTS)
def test_runtime_the_chips_read_on_the_light_palette(open_app, layout):
    if layout == 'cloud':
        app = open_app(layout=layout, storage={'pegaprox-cloud-theme': 'light'})
    else:
        app = open_app()
        app.page.evaluate("applyTheme('corporateLight')")
    page = _page(app)
    page.locator('[data-bp-recent-row]').first.wait_for(timeout=8000)
    ratios = {k: page.evaluate(CONTRAST, sel) for k, sel in CHIPS.items()}
    assert all(r >= 4.5 for r in ratios.values()), ratios
    # the triangle is in the colour of its chip
    tri = page.evaluate(f"""() => [getComputedStyle(document.querySelector('{CHIPS["image removed"]}')).color,
        getComputedStyle(document.querySelector('{CHIPS["image removed"]} svg')).color]""")
    assert tri[0] == tri[1], tri
    if layout == 'modern':
        # and the way there on the Resources page reads too
        _resources(page)
        assert page.evaluate(CONTRAST, '[data-bp-nav="resources"]') >= 4.5


def test_runtime_cloud_at_900_px_the_page_does_not_scroll_sideways(open_app):
    page = _page(open_app(layout='cloud', viewport=(900, 700)))
    page.wait_for_timeout(300)
    assert page.evaluate('() => document.documentElement.scrollWidth') <= 900


def test_runtime_cloud_a_guest_that_is_gone_is_said_not_opened(open_app):
    # 120 was deployed and deleted since: the list of the cluster no longer has it
    app = open_app(layout='cloud')
    page = _page(app)
    page.locator('[data-bp-guest="120"]').first.click()
    _need(page, 'text=Guest 120 is not in the list of this cluster', 'a guest the cluster does not list is said', timeout=4000)
    page.wait_for_timeout(300)
    # no page of a guest of unknown state with a Start button: the blueprints stay
    assert page.locator('[data-bp]').count() == 1
    assert page.locator('.cloud-nav-item-active').inner_text().strip() == 'Blueprints & Templates'
    _no_errors(app)


LAB = dict(CLUSTER, id='c2', name='Lab', display_name='Lab', host='10.0.0.2')


@pytest.mark.parametrize('vmid', [100, 300])
def test_runtime_cloud_a_guest_of_another_cluster_waits_for_the_list_of_that_cluster(open_app, vmid):
    # Lab lists 100 (the fake has one list for every cluster), not 300
    app = open_app(layout='cloud', clusters=[CLUSTER, LAB])
    app.server.recent = [dict(ELSEWHERE, vmid=vmid, name='web01' if vmid == 100 else 'web-lab')]
    page = _page(app)
    page.locator('[data-bp-recent-scope="all"]').click()
    page.locator(f'[data-bp-guest="{vmid}"]').click()
    if vmid == 100:
        _guest_opened(app, 'web01')
    else:
        _need(page, 'text=Guest 300 is not in the list of this cluster', 'a guest the list of Lab does not have is said', timeout=6000)
        # the VMs page of Lab, without a page of a guest of unknown state
        assert page.locator('.cloud-nav-item-active').inner_text().strip() == 'Virtual Machines'
        assert page.locator('.cloud-breadcrumb-leaf').inner_text().strip() == 'Virtual Machines'
    _no_errors(app)


# --- classic Corporate stays as it is -----------------------------------------------------------

def test_runtime_classic_corporate_keeps_the_library_alone(open_app):
    app = open_app(layout='corporate')
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.locator('button', has_text=re.compile(r'^\s*Automation\s*$')).first.click()
    page.locator('button', has_text=re.compile(r'^\s*Cloud-Init Template Library\s*$')).first.click()
    page.get_by_text('Debian 13 (Trixie)').first.wait_for(timeout=8000)
    page.wait_for_timeout(500)
    assert page.locator('[data-bp], [data-cr-bp]').count() == 0
    assert [c for c in app.server.calls if c[1].startswith('/api/blueprints')] == []
    page.locator('button', has_text=re.compile(r'^\s*Resources\s*$')).first.click()
    page.get_by_text('Create new VM').first.wait_for(timeout=8000)
    assert page.locator('[data-bp-nav], [data-cr-bp-nav]').count() == 0
    page.keyboard.press('Control+k')
    page.get_by_placeholder(re.compile('Type to search')).fill('blueprint')
    page.wait_for_timeout(400)
    assert page.locator('[data-cmdpal-idx]', has_text='from blueprint').count() == 0


# --- source ------------------------------------------------------------------------------------

def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def test_modern_mounts_the_section_and_classic_corporate_does_not():
    dash = _read('web', 'src', 'dashboard.js')
    mounts = [m.start() for m in re.finditer(r'<Blueprints\b', dash)]
    assert len(mounts) == 1
    head = dash[dash.rindex('{automationSubTab', 0, mounts[0]):mounts[0]]
    assert "automationSubTab === 'templates' && !isCorporate && selectedCluster?.id" in head
    assert "canRead={holds('vm.create')} canWrite={can('vm.create')} nav={mdBpNav} />" in dash[mounts[0]:]
    # above the library, which every layout but the redesign keeps
    assert mounts[0] < dash.index('<TemplatesLibraryTab\n')
    assert ("label: isCorpRedesigned ? t('crBpNavTab') : isCorporate ? (t('templateLibrary') || 'Templates') : t('bpNavTab')") in dash
    # the ways there: the Resources button of Modern, Ctrl+K for the redesign and Modern
    btn = dash.index('data-bp-nav="resources"')
    assert ("{!isCorporate && can('vm.create') && (!selectedCluster.cluster_type || selectedCluster.cluster_type === 'proxmox') && ("
            in dash[btn - 400:btn])
    assert "extraActions={(isCorpRedesigned || !isCorporate) && can('vm.create') && " in dash
    assert "if (c) (crTaskNav || mdBpNav).openBlueprints(c.id);" in dash
    nav = dash[dash.index('const mdBpNav = '):dash.index('const crGlobalView = ')]
    assert nav.startswith('const mdBpNav = !isCorporate ? {') and 'openGuest: (cid, guest) =>' in nav and 'nodesOf: (cid) =>' in nav


def test_cloud_mounts_the_section_above_the_library_and_names_the_page():
    cloud = _read('web', 'src', 'cloud.js')
    mounts = [m.start() for m in re.finditer(r'<Blueprints\b', cloud)]
    assert len(mounts) == 1
    case = cloud[cloud.index("case 'templates':"):cloud.index("case 'insights':")]
    at = case.index('<Blueprints ')
    assert at < case.index('<TemplatesLibraryTab') and '<div className="cloud-mounted cloud-body">' in case[:at]
    assert ('canRead={canBp} canWrite={canBp && !haReadOnly} nav={bpNav} cloud />') in case
    assert "const canBp = holdsPerm('vm.create');" in cloud and 'haReadOnly } = useAuth();' in cloud
    # the nav and the crumb say what the page holds now
    assert "{ id: 'templates', label: t('bpNavTab'), icon: 'Copy' }," in cloud
    assert "templates: T('bpNavTab') || 'Blueprints & Templates'," in cloud and 'cloudNavTemplates' not in cloud
    # the button of the VMs page only, for whoever may deploy, not on a standby, on a Proxmox VE cluster
    assert "const toBlueprints = canBp && !haReadOnly && pveCluster ? () => selectSection('templates') : undefined;" in cloud
    vms = [ln for ln in cloud.split('\n') if '<CloudInstanceList ' in ln]
    assert len(vms) == 2 and 'kind="qemu"' in vms[0] and 'onBlueprints={toBlueprints}' in vms[0] and 'onBlueprints' not in vms[1]
    assert "{onBlueprints && kind !== 'lxc' && (" in cloud and 'data-bp-nav="cloud-vms"' in cloud
    nav = cloud[cloud.index('const bpNav = {'):cloud.index('const pveCluster = ')]
    assert 'nodesOf: (id) => (id === cid ? clusterMetrics : null),' in nav and "setSection('vms');" in nav


def test_the_cloud_look_is_scoped_to_the_cloud_layout():
    html = _read('web', 'index.html.original')
    start = html.index('/* in Cloud they take the controls of the shell (blueprints.js)')
    block = html[start:html.index('/* icon button */', start)]
    rules = [ln.strip() for ln in block.split('\n') if '{' in ln]
    assert len(rules) == 12 and all(r.startswith('body[data-layout="cloud"]') for r in rules), rules
    src = _read('web', 'src', 'blueprints.js')
    # Modern keeps its controls: the kit hands it the very classes it had
    assert "modern: { input: BP_INPUT, btn: BP_BTN, go: BP_BTN_GO, small: BP_BTN_ROW, icon: BP_BTN_ICON }," in src
    assert not re.search(r'className=\{BP_(INPUT|BTN|BTN_GO|BTN_ROW|BTN_ICON)\}', src)


def test_one_set_of_rules_for_both_looks():
    src = _read('web', 'src', 'blueprints.js')
    for hook in ('crBpUseEditor({ bp, templateId, authFetch, t, onSaved })', 'crBpUseDeploy({ bp, clusters, clusterId, authFetch, t, onStarted })',
                 'crBpUseProgress(dep, onRow, t)'):
        assert hook in src, hook
    cr = _read('web', 'src', 'cr_blueprints.js')
    for fn in ('function crBpUseEditor(', 'function crBpUseDeploy(', 'function crBpUseProgress('):
        assert cr.count(fn) == 1, fn
    # each look calls each of them once: the redesign's dialogs and these
    for call in ('crBpUseEditor({ bp, templateId, authFetch, t, onSaved })', 'crBpUseDeploy({ bp, clusters, clusterId, authFetch, t, onStarted })',
                 'crBpUseProgress(dep, onRow, t)'):
        calls = lambda text: len(re.findall(r'(?<!function )' + re.escape(call), text))
        assert calls(cr) == 1 and calls(src) == 1, call
    # it sends only the delete itself (the save and the deploy are the hooks'), and polls no interval
    sends = [ln for ln in src.split('\n') if 'crBpSend(authFetch' in ln]
    assert len(sends) == 1 and "${API_URL}/blueprints/${encodeURIComponent(del.id)}`, 'DELETE'" in sends[0], sends
    assert 'setInterval' not in src and src.count('setTimeout(() => read(scope), BP_RECENT_POLL)') == 1
    for bad in ('window.confirm', 'localStorage', 'sessionStorage', '<CrBlueprints', 'cr-btn'):
        assert bad not in src, bad
    assert not re.search(r'(?<![\w.])confirm\(', src)


def test_the_mount_takes_the_props_cloud_needs():
    src = _read('web', 'src', 'blueprints.js')
    sig = re.search(r'function BpSection\(\{([^}]*)\}\)', src).group(1)
    assert [p.strip() for p in sig.split(',')] == ['cluster', 'clusters', 'authFetch', 'addToast', 'canRead', 'canWrite', 'nav']
    # the look is set once, for the section, its dialogs and the note of the boundary
    mount = src[src.index('function Blueprints(props) {'):]
    assert "const cloud = props.cloud === undefined ? isCloud : !!props.cloud;" in mount
    assert '<BpCloud.Provider value={cloud}>' in mount and '<BpBoundary t={t}><BpSection {...props} /></BpBoundary>' in mount
    assert src.count('const BpCloud = createContext(false);') == 1 and 'BpBoundary.contextType = BpCloud;' in src
    # inside .cloud-mounted the palette text follows Cloud as well
    html = _read('web', 'index.html.original')
    assert '.bp-fg { color: var(--color-text, #FFFFFF); }' in html
    assert 'body[data-layout="cloud"] .cloud-mounted .bp-muted { color: var(--cloud-text-secondary, #b3c6d4); }' in html
    assert 'text-white' not in re.sub(r"bg-proxmox-orange[^'`\"]*text-white|bg-red-600[^'`\"]*text-white|'bg-proxmox-orange text-white'", '', src)


def test_the_module_is_built_shipped_and_has_no_dash():
    src = _read('web', 'src', 'blueprints.js')
    assert not any(d in src for d in DASHES)
    build = _read('web', 'Dev', 'build.sh')
    assert build.index('    cr_images.js\n') < build.index('    blueprints.js\n') < build.index('    dashboard.js\n')
    assert 'web/src/blueprints.js' in json.loads(_read('version.json'))['update_files']
    assert 'function BpSection(' in _read('web', 'index.html')


NEW_KEYS = ('bpNavTab', 'bpRecentDesc', 'bpRecentNone', 'bpRecentNoneAll', 'bpColBlueprint')


def test_every_key_is_in_every_language_after_the_blueprint_keys():
    used = set(re.findall(r"'((?:crBp|crImg|bp)[A-Za-z]+)'", _read('web', 'src', 'blueprints.js')))
    used |= set(re.findall(r"t\('(bp[A-Za-z]+)'\)", _read('web', 'src', 'dashboard.js') + _read('web', 'src', 'cloud.js')))
    assert set(NEW_KEYS) <= used and len(used) > 120
    src = _read('web', 'src', 'translations.js')
    starts = [(m.start(), m.group(1)) for m in re.finditer(r'^            ([a-z]{2}): \{$', src, re.M)]
    ends = [s for s, _ in starts[1:]] + [len(src)]
    blocks = {lang: src[a:b] for (a, lang), b in zip(starts, ends)}
    assert set(blocks) == {'de', 'en', 'zh', 'pl', 'fr', 'es', 'pt', 'ko', 'it', 'ru'}
    en = dict(re.findall(r'^                ((?:crBp|crImg|bp)[A-Za-z]+): "(.*)",$', blocks['en'], re.M))
    for lang, block in blocks.items():
        lines = block.split('\n')
        at = next(i for i, ln in enumerate(lines) if ln.startswith('                crBpAccessNoUser: '))
        # right after the last key of the redesign's blueprints, ahead of the pinned chain
        assert [ln.split(':')[0].strip() for ln in lines[at + 1:at + 1 + len(NEW_KEYS)]] == list(NEW_KEYS), lang
        pinned = block.index('// LW Oct 2026 (#625) - the banners of a group that fails over automatically')
        for k in used:
            found = re.findall(rf'^                {k}: "(.*)",$', block, re.M)
            assert len(found) == 1, (lang, k)
            assert re.search(rf'^                {k}: ', block, re.M).start() < pinned, (lang, k)
            assert not any(d in found[0] for d in DASHES), (lang, k)
            assert sorted(re.findall(r'\{[a-z]+\}', found[0])) == sorted(re.findall(r'\{[a-z]+\}', en[k])), (lang, k)
    # translated, not the English text; German names the page as English does (crBpNavTab too)
    for k in ('bpNavTab', 'bpRecentDesc', 'bpRecentNone', 'bpRecentNoneAll'):
        for lang in blocks:
            if lang != 'en' and (lang, k) != ('de', 'bpNavTab'):
                assert re.search(rf'^                {k}: "(.*)",$', blocks[lang], re.M).group(1) != en[k], (lang, k)
