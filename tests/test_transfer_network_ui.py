"""The transfer network in the cluster settings.

Next to the authentication of the connection sits the network remote migrations into
the cluster dial its nodes in: a CIDR field that checks what is typed, a preview of each
node's address in a network before it is saved, the datacenter migration network for
reference, and a test from a node of a source cluster whether the addresses answer on
8006. A standby that does not hand writes on shows it locked. A cross-cluster migration
that could not use the target's transfer network says so in a toast.
Runtime tests drive the built bundle in headless Chromium against the fake server of
tests/test_ha_ui.py; they skip where Playwright is not installed.
LW Oct 2026
"""
import json
import os
import re
import time
from urllib.parse import parse_qs, urlparse

import pytest

from test_ha_ui import (CLUSTER, LANGS, SSE_TOKEN, VM, _App, _FakeServer, _blocks, _classes,  # noqa: F401
                        browser)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

KEYS = ['xferNetTitle', 'xferNetDesc', 'xferNetPlaceholder', 'xferNetInvalid', 'xferNetSaved',
        'xferNetLoadError', 'xferNetOff', 'xferNetDcNet', 'xferNetDcNetNone', 'xferNetDcNetUnread',
        'xferNetDcNetHint', 'xferNetNodes', 'xferNetMissing', 'xferNetNoAddress', 'xferNetResolving',
        'xferNetUnreadable', 'xferNetNodeOffline', 'xferNetAnswers', 'xferNetNoAnswer',
        'xferNetCheckDesc', 'xferNetCheckCluster', 'xferNetCheckNode', 'xferNetCheckRun',
        'xferNetCheckSaveFirst', 'xferNetCheckFailed', 'xferNetCheckDone', 'xferNetFallback']


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def _component():
    src = _read('web', 'src', 'dashboard.js')
    start = src.index('// LW Oct 2026 - the transfer network of a PVE cluster')
    return src[start:src.index('// LW Oct 2026 - the connection check of one PVE cluster', start)]


def _mount():
    src = _read('web', 'src', 'dashboard.js')
    start = src.index('{/* LW Oct 2026 - where remote migrations into this cluster dial its nodes')
    return src[start:src.index('{/* HA Section */}', start)]


def _toast():
    src = _read('web', 'src', 'dashboard.js')
    start = src.index('// LW Oct 2026 - a target with a transfer network that this migration could not use')
    return src[start:src.index('setTimeout(', start)]


def _all():
    return _component() + _mount() + _toast()


# -- source -------------------------------------------------------------------------------------

def test_every_new_key_exists_once_per_language():
    for lang, block in _blocks().items():
        for key in KEYS:
            assert len(re.findall(r'^ +%s:' % key, block, re.M)) == 1, (lang, key)


def test_the_keys_sit_with_the_connection_settings():
    for lang, block in _blocks().items():
        lines = block.splitlines()
        at = next(i for i, line in enumerate(lines) if re.match(r'^ +dontChangePvePassword:', line))
        assert [re.match(r'^ +(\w+):', line).group(1) for line in lines[at + 1:at + 1 + len(KEYS)]] == KEYS, lang


def test_every_new_key_is_used_and_nothing_else_is_new():
    used = set(re.findall(r"'(xferNet\w*)'", _all()))
    assert used == set(KEYS)
    # no key of this prefix anywhere else in the source
    others = ''.join(_read('web', 'src', f) for f in os.listdir(os.path.join(ROOT, 'web', 'src'))
                     if f.endswith('.js') and f not in ('translations.js', 'dashboard.js'))
    assert 'xferNet' not in others


def test_placeholders_survive_translation():
    blocks = _blocks()
    for key in KEYS:
        en = re.search(r'^ +%s: (.*),$' % key, blocks['en'], re.M).group(1)
        for lang, block in blocks.items():
            value = re.search(r'^ +%s: (.*),$' % key, block, re.M).group(1)
            assert sorted(re.findall(r'\{\w+\}', value)) == sorted(re.findall(r'\{\w+\}', en)), (lang, key)


def test_no_dash_in_what_this_change_added():
    lines = [line for block in _blocks().values() for line in block.splitlines()
             if re.match(r'^ +(%s):' % '|'.join(KEYS), line)]
    assert len(lines) == len(KEYS) * len(LANGS)
    for text in [_all()] + lines:
        assert '\u2014' not in text and '\u2013' not in text


def test_the_austrian_flag_stays():
    assert "{ code: 'de', flag: '\U0001F1E6\U0001F1F9'" in _read('web', 'src', 'contexts.js')


def test_every_class_is_in_the_static_tailwind_build():
    css = _read('static', 'css', 'tailwind.min.css') + _read('web', 'index.html.original')
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    names = _classes(_all())
    missing = sorted(n for n in names if n not in have)
    assert not missing, f'not in static/css/tailwind.min.css: {missing}'


def test_the_icons_exist():
    icons = _read('web', 'src', 'icons.js')
    used = set(re.findall(r'Icons\.(\w+)', _all()))
    assert used
    for name in used:
        assert re.search(r'^ +%s: \(' % name, icons, re.M), name


def test_it_is_locked_on_a_standby_and_only_for_pve():
    comp = _component()
    assert comp.count('<fieldset disabled={haReadOnly || !canEdit}') == 2
    assert comp.count("data-ha-locked={haReadOnly ? '' : undefined}") == 2
    mount = _mount()
    assert "(selectedCluster.cluster_type || 'proxmox') === 'proxmox' && can('cluster.view')" in mount
    assert "canEdit={can('cluster.config')} haReadOnly={haReadOnly}" in mount


def test_the_bundle_carries_it():
    bundle = _read('web', 'index.html')
    for needle in ('function TransferNetworkSection(', '/transfer-network/check', 'data-transfer-network',
                   'xferNetFallback', 'data-xfer-node'):
        assert needle in bundle, needle


# -- runtime ------------------------------------------------------------------------------------

NET = '10.20.0.0/24'
VIEW = '/api/clusters/c1/transfer-network'
CHECK = '/api/clusters/c1/transfer-network/check'
XC = dict(CLUSTER, transfer_network=NET)
FAR = {'id': 'c2', 'name': 'Far', 'display_name': 'Far', 'host': '10.9.0.1', 'connected': True,
       'status': 'running', 'cluster_type': 'proxmox', 'enabled': True}
ADDR = {'pve1': ('10.20.0.11', 'bond1'), 'pve2': ('10.20.0.12', 'bond1')}


def _rows(network, pending=False):
    rows = []
    for n in ('pve1', 'pve2', 'pve3'):
        if not network:
            rows.append({'node': n, 'online': True, 'address': None, 'iface': None, 'state': 'off'})
        elif pending:
            rows.append({'node': n, 'online': True, 'address': None, 'iface': None, 'state': 'pending'})
        elif network == NET and n in ADDR:
            rows.append({'node': n, 'online': True, 'address': ADDR[n][0], 'iface': ADDR[n][1], 'state': 'ok'})
        elif network == '10.0.0.0/24':
            rows.append({'node': n, 'online': True, 'address': '10.0.0.1' + n[-1], 'iface': 'vmbr0', 'state': 'ok'})
        else:
            rows.append({'node': n, 'online': True, 'address': None, 'iface': None, 'state': 'none'})
    return rows


class _XferServer(_FakeServer):
    """The view as the server answers it: the saved network or ?network=, pending reads first."""

    saved = NET
    pending_first = 0

    def handle(self, route):
        req = route.request
        parsed = urlparse(req.url)
        if parsed.path == VIEW and req.method == 'GET':
            q = parse_qs(parsed.query, keep_blank_values=True)
            network = q['network'][0] if 'network' in q else self.saved
            if network == '10.20.0.5/24':
                network = NET
            pending = self.pending_first > 0
            self.pending_first -= 1
            rows = _rows(network, pending)
            body = {'network': network, 'nodes': rows, 'pending': pending,
                    'missing': sum(1 for r in rows if r['state'] in ('none', 'unreadable')),
                    'migration_network': '10.30.0.0/24', 'cluster_id': 'c1', 'saved': self.saved}
            self.extra[('GET', VIEW)] = (200, body)
        if parsed.path == '/api/clusters/c1/config' and req.method == 'PATCH':
            body = json.loads(req.post_data or '{}')
            if 'transfer_network' in body:
                self.saved = '10.20.0.0/24' if body['transfer_network'] == '10.20.0.5/24' else body['transfer_network']
        return super().handle(route)


CHECKED = {'network': NET, 'source_node': 'far1', 'port': 8006, 'cluster_id': 'c1', 'source_cluster': 'c2',
           'nodes': [{'node': 'pve1', 'address': '10.20.0.11', 'status': 'ok', 'ms': 3},
                     {'node': 'pve2', 'address': '10.20.0.12', 'status': 'fail', 'ms': 4001},
                     {'node': 'pve3', 'address': None, 'status': 'none'}]}


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(cluster=None, saved=NET, pending_first=0, **kw):
        extra = dict(SSE_TOKEN)
        extra[('PATCH', '/api/clusters/c1/config')] = (200, {'message': 'ok'})
        extra[('GET', '/api/clusters/c2/nodes')] = (200, [{'node': 'far2', 'status': 'online'},
                                                           {'node': 'far1', 'status': 'online'},
                                                           {'node': 'far3', 'status': 'offline'}])
        extra[('POST', CHECK)] = (200, CHECKED)
        extra.update(kw.pop('extra', {}))
        kw.setdefault('role', 'standalone')
        server = _XferServer(clusters=[cluster or dict(XC, transfer_network=saved), FAR], resources=[VM],
                             extra=extra, **kw)
        server.saved = saved
        server.pending_first = pending_first
        app = _App(browser, server)
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _wait_for(page, fn, seconds=6):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if fn():
            return True
        page.wait_for_timeout(100)
    return fn()


def _open_settings(app, tab='Settings'):
    page = app.page
    page.get_by_text('Testi').first.click()
    page.get_by_role('button', name=tab, exact=True).first.click()
    page.locator('[data-transfer-network]').wait_for(timeout=8000)
    page.wait_for_timeout(300)
    return page


def _views(app):
    return [u for u in app.server.urls if urlparse(u).path == VIEW]


def _state(page, node):
    return page.locator(f'[data-xfer-node="{node}"]').get_attribute('data-xfer-state')


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_the_nodes_show_their_address(open_app, layout):
    app = open_app(layout=layout)
    page = _open_settings(app)
    page.locator('[data-xfer-node="pve1"]').wait_for(timeout=5000)
    sec = page.locator('[data-transfer-network]')
    assert 'Transfer Network' in sec.inner_text()
    assert page.input_value('#xfer-net-input') == NET
    assert page.locator('[data-xfer-heading]').inner_text().strip() == f'Address of each node in {NET}'
    assert '10.20.0.11' in page.locator('[data-xfer-node="pve1"]').inner_text()
    assert '(bond1)' in page.locator('[data-xfer-node="pve1"]').inner_text()
    assert _state(page, 'pve3') == 'none'
    assert 'no address in this network' in page.locator('[data-xfer-node="pve3"]').inner_text()
    assert page.locator('[data-xfer-missing]').inner_text().strip().startswith('1 of 3 nodes have no address')
    dc = page.locator('[data-xfer-dc]').inner_text()
    assert '10.30.0.0/24' in dc and 'Datacenter > Options > Migration Settings' in dc
    # nothing changed yet: no save
    assert page.locator('[data-xfer-save]').is_disabled()
    assert len(_views(app)) == 1
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_a_network_is_checked_previewed_and_saved(open_app, layout):
    app = open_app(layout=layout, saved='')
    page = _open_settings(app)
    page.locator('[data-xfer-off]').wait_for(timeout=5000)
    assert page.locator('[data-xfer-node]').count() == 0
    assert page.locator('[data-xfer-check]').count() == 0
    page.fill('#xfer-net-input', '10.20.0.1')
    page.locator('[data-xfer-invalid]').wait_for(timeout=3000)
    assert page.locator('[data-xfer-save]').is_disabled()
    before = len(_views(app))
    page.wait_for_timeout(900)
    assert len(_views(app)) == before, 'an invalid network is not asked for'
    page.fill('#xfer-net-input', '10.0.0.0/24')
    assert _wait_for(page, lambda: any('network=10.0.0.0%2F24' in u for u in _views(app)))
    page.locator('[data-xfer-node="pve3"][data-xfer-state="ok"]').wait_for(timeout=5000)
    page.fill('#xfer-net-input', '10.20.0.5/24')
    page.locator('[data-xfer-node="pve3"][data-xfer-state="none"]').wait_for(timeout=5000)
    assert page.locator('[data-xfer-invalid]').count() == 0
    page.locator('[data-xfer-save]').click()
    assert _wait_for(page, lambda: app.server.bodies.get('/api/clusters/c1/config'))
    assert app.server.bodies['/api/clusters/c1/config'][-1] == {'transfer_network': '10.20.0.5/24'}
    # the stored network address comes back into the field
    assert _wait_for(page, lambda: page.input_value('#xfer-net-input') == NET)
    page.get_by_text('Transfer network saved').first.wait_for(timeout=3000)
    page.locator('[data-xfer-check]').wait_for(timeout=3000)
    assert not app.errors, app.errors


def test_runtime_nodes_still_read_are_asked_for_again(open_app):
    app = open_app(layout='modern', pending_first=2)
    page = _open_settings(app)
    page.locator('[data-xfer-node="pve1"][data-xfer-state="pending"]').wait_for(timeout=5000)
    assert 'reading network config...' in page.locator('[data-xfer-node="pve1"]').inner_text()
    page.locator('[data-xfer-node="pve1"][data-xfer-state="ok"]').wait_for(timeout=10000)
    n = len(_views(app))
    assert n == 3
    page.wait_for_timeout(2500)
    assert len(_views(app)) == n, 'no polling once everything is read'
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_the_check_runs_from_a_source_node(open_app, layout):
    app = open_app(layout=layout)
    page = _open_settings(app)
    box = page.locator('[data-xfer-check]')
    box.wait_for(timeout=5000)
    run = page.locator('[data-xfer-run]')
    assert run.is_disabled()
    page.locator('[data-xfer-src-cluster]').select_option('c2')
    assert _wait_for(page, lambda: page.locator('[data-xfer-src-node] option').count() == 3)
    # online nodes only, sorted
    assert page.locator('[data-xfer-src-node] option').all_inner_texts()[1:] == ['far1', 'far2']
    page.locator('[data-xfer-src-node]').select_option('far1')
    run.click()
    page.locator('[data-xfer-check-done]').wait_for(timeout=5000)
    assert app.server.bodies[CHECK] == [{'source_cluster': 'c2', 'source_node': 'far1'}]
    assert page.locator('[data-xfer-check-done]').inner_text().strip() == '1 of 2 addresses answer from far1'
    assert page.locator('[data-xfer-node="pve1"] [data-xfer-probe="ok"]').inner_text().strip() == 'answers (3 ms)'
    assert page.locator('[data-xfer-node="pve2"] [data-xfer-probe="fail"]').inner_text().strip() == 'no answer'
    assert page.locator('[data-xfer-node="pve3"] [data-xfer-probe]').count() == 0
    assert not app.errors, app.errors


def test_runtime_a_refused_check_shows_the_servers_words(open_app):
    refused = {'error': 'SSH to this cluster is switched off', 'code': 'SSH_DISABLED'}
    app = open_app(layout='modern', extra={('POST', CHECK): (409, refused)})
    page = _open_settings(app)
    page.locator('[data-xfer-src-cluster]').select_option('c2')
    assert _wait_for(page, lambda: page.locator('[data-xfer-src-node] option').count() == 3)
    page.locator('[data-xfer-src-node]').select_option('far2')
    page.locator('[data-xfer-run]').click()
    page.locator('[data-xfer-check-error]').wait_for(timeout=5000)
    assert page.locator('[data-xfer-check-error]').inner_text().strip() == 'SSH to this cluster is switched off'
    assert not app.errors, app.errors


def test_runtime_an_unsaved_network_is_not_tested(open_app):
    app = open_app(layout='modern')
    page = _open_settings(app)
    page.locator('[data-xfer-src-cluster]').select_option('c2')
    assert _wait_for(page, lambda: page.locator('[data-xfer-src-node] option').count() == 3)
    page.locator('[data-xfer-src-node]').select_option('far1')
    page.fill('#xfer-net-input', '10.0.0.0/24')
    page.locator('[data-xfer-save-first]').wait_for(timeout=3000)
    assert page.locator('[data-xfer-run]').is_disabled()
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_a_standby_shows_it_locked(open_app, layout):
    app = open_app(layout=layout, role='standby')
    page = _open_settings(app)
    page.locator('[data-xfer-node="pve1"]').wait_for(timeout=5000)
    assert page.locator('fieldset[data-ha-locked][data-xfer-edit]').count() == 1
    assert page.locator('fieldset[data-ha-locked][data-xfer-check]').count() == 1
    assert not page.locator('#xfer-net-input').is_enabled()
    assert page.locator('[data-xfer-save]').is_disabled() and page.locator('[data-xfer-run]').is_disabled()
    assert page.locator('[data-xfer-src-cluster]').is_disabled()
    page.wait_for_timeout(500)
    assert '/api/clusters/c1/config' not in app.server.bodies and CHECK not in app.server.bodies
    assert not app.errors, app.errors


def test_runtime_without_cluster_config_it_only_shows(open_app):
    app = open_app(layout='modern', admin=False, permissions=['cluster.view'])
    page = _open_settings(app)
    page.locator('[data-xfer-node="pve1"]').wait_for(timeout=5000)
    assert not page.locator('#xfer-net-input').is_enabled()
    assert page.locator('fieldset[data-ha-locked][data-xfer-edit]').count() == 0
    assert not app.errors, app.errors


def test_runtime_an_xcpng_pool_has_none(open_app):
    app = open_app(layout='modern', cluster=dict(XC, cluster_type='xcpng'))
    page = app.page
    page.get_by_text('Testi').first.click()
    page.get_by_role('button', name='Settings', exact=True).first.click()
    page.get_by_text('Automatic Migration').first.wait_for(timeout=8000)
    page.wait_for_timeout(500)
    assert page.locator('[data-transfer-network]').count() == 0
    assert not _views(app)
    assert not app.errors, app.errors


def test_runtime_german(open_app):
    app = open_app(layout='modern', language='de')
    page = _open_settings(app, tab='Einstellungen')
    page.locator('[data-xfer-node="pve3"]').wait_for(timeout=5000)
    text = page.locator('[data-transfer-network]').inner_text()
    assert 'Transfernetz' in text and 'keine Adresse in diesem Netz' in text
    assert f'Adresse jedes Knotens in {NET}' in text
    assert 'xferNet' not in text
    assert not app.errors, app.errors


def _migrate_across(app):
    from test_ha_ui import _open_resources, _toasts
    page = app.page
    _open_resources(app)
    page.get_by_text('web01').first.click()
    page.get_by_role('button', name='More Actions').first.click()
    page.get_by_role('button', name='Cross-Cluster Migrate').first.click()
    page.get_by_text('Cross-Cluster Migration').first.wait_for(timeout=5000)
    page.locator('select', has=page.locator('option', has_text='Far')).first.select_option('c2')
    go = page.locator('button.bg-cyan-600')
    assert _wait_for(page, lambda: go.count() == 1 and go.is_enabled(), seconds=8)
    go.click()
    assert _wait_for(page, lambda: app.server.bodies.get('/api/cross-cluster-migrate'))
    assert app.server.bodies['/api/cross-cluster-migrate'][-1]['target_node'] == 'pve3'
    page.wait_for_timeout(600)
    return _toasts(page)


def _cross_extra(answer):
    return {('GET', '/api/clusters/c1/vms/pve1/qemu/100/config'): (200, {'scsi0': 'local-lvm:vm-100-disk-0,size=8G'}),
            ('GET', '/api/clusters/c2/nodes'): (200, [{'node': 'pve3', 'status': 'online',
                                                       'cpu_percent': 1, 'mem_percent': 2}]),
            ('GET', '/api/clusters/c2/nodes/pve3/storage'): (200, [{'storage': 'local-lvm', 'type': 'lvmthin'}]),
            ('GET', '/api/clusters/c2/nodes/pve3/networks'): (200, [{'iface': 'vmbr0', 'type': 'bridge'}]),
            ('POST', '/api/cross-cluster-migrate'): (200, answer)}


STARTED = {'message': 'Cross-cluster migration started: qemu/100 from c1 to c2/pve3', 'task': 'UPID:x'}


def test_runtime_a_migration_that_could_not_use_it_says_so(open_app):
    answer = dict(STARTED, transfer_network={'network': NET, 'node': 'pve3', 'via': 'management',
                                             'host': None, 'reason': 'no_address'})
    app = open_app(layout='modern', extra=_cross_extra(answer))
    toasts = _migrate_across(app)
    assert any(f'The transfer network {NET} could not be used for pve3' in x for x in toasts), toasts
    assert not app.errors, app.errors


@pytest.mark.parametrize('xfer', [None, {'network': NET, 'node': 'pve3', 'via': 'transfer',
                                         'host': '10.20.0.13', 'reason': None}])
def test_runtime_a_migration_over_it_or_without_it_says_nothing_more(open_app, xfer):
    answer = dict(STARTED, **({'transfer_network': xfer} if xfer else {}))
    app = open_app(layout='modern', extra=_cross_extra(answer))
    toasts = _migrate_across(app)
    assert any('Cross-cluster migration started' in x for x in toasts), toasts
    assert not any('transfer network' in x for x in toasts), toasts
    assert not app.errors, app.errors
