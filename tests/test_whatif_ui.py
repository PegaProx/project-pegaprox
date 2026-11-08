"""The what-if simulator in the web UI: Reports > What-if in Modern and Corporate, the
Reports group of the cloud layout.

The source checks hold the strings (every key in all nine languages, once, with its
placeholders, no em dash), the classes (the Tailwind build is static) and the icons. The
runtime tests drive the built bundle in headless Chromium against the fake server of
tests/test_ha_ui.py; the report it hands out is what the real engine answers for a small
cluster, so the view is tested against the shape the route sends. They skip where
Playwright is not installed.
LW Oct 2026
"""
import json
import re

import pytest

from pegaprox.core import whatif
from test_ha_ui import (CLUSTER, LANGS, NODE_METRICS, SSE_TOKEN, VM, _App, _blocks, _classes,  # noqa: F401
                        _FakeServer, _read, browser)
from test_whatif import NETS, THR, _cfg, _cluster, _manager, _vm

URL = '/api/clusters/c1/whatif'


@pytest.fixture(scope='module')
def dash():
    return _read('web', 'src', 'dashboard.js')


@pytest.fixture(scope='module')
def view(dash):
    start = dash.index('        // LW Oct 2026 - What-if simulator of a cluster')
    return dash[start:dash.index('        // NS Apr 2026 \u2014 Compliance Dashboard', start)]


def _used_keys():
    keys = set()
    for name in ('dashboard.js', 'cloud.js'):
        keys |= set(re.findall(r"'(whatif[A-Z]\w*)'", _read('web', 'src', name)))
    return sorted(keys)


# -- source -----------------------------------------------------------------------------------

def test_the_view_uses_its_own_keys():
    keys = _used_keys()
    assert len(keys) > 150, len(keys)
    # every code the engine sends has its key, so no reason shows in English only
    view_src = _read('web', 'src', 'dashboard.js')
    for table, codes in (('WHATIF_REASONS', whatif.REASONS), ('WHATIF_LIMITS', whatif.LIMITS),
                         ('WHATIF_ASSUMPTIONS', whatif.ASSUMPTIONS)):
        block = view_src[view_src.index(f'const {table} = {{'):]
        block = block[:block.index('};')]
        mapped = set(re.findall(r'(\w+): \'whatif', block))
        assert mapped == set(codes), (table, sorted(mapped ^ set(codes)))


@pytest.mark.parametrize('lang', LANGS)
def test_every_key_exists_once_per_language(lang):
    block = _blocks()[lang]
    for key in _used_keys():
        n = len(re.findall(r'^ +%s: ' % key, block, re.M))
        assert n == 1, f'{key} appears {n} times in {lang}'
    defined = set(re.findall(r'^ +(whatif\w+): ', block, re.M))
    assert defined == set(_used_keys()), sorted(defined ^ set(_used_keys()))


def test_placeholders_survive_translation():
    blocks = _blocks()
    for key in _used_keys():
        en = re.search(r'^ +%s: (.*),$' % key, blocks['en'], re.M).group(1)
        for lang, block in blocks.items():
            value = re.search(r'^ +%s: (.*),$' % key, block, re.M).group(1)
            assert sorted(re.findall(r'\{\w+\}', value)) == sorted(re.findall(r'\{\w+\}', en)), (lang, key)


def test_the_english_of_the_server_is_the_english_of_the_view():
    en = _blocks()['en']
    view_src = _read('web', 'src', 'dashboard.js')
    for table, codes in (('WHATIF_REASONS', whatif.REASONS), ('WHATIF_LIMITS', whatif.LIMITS),
                         ('WHATIF_ASSUMPTIONS', whatif.ASSUMPTIONS)):
        block = view_src[view_src.index(f'const {table} = {{'):]
        block = block[:block.index('};')]
        for code, key in re.findall(r"(\w+): '(whatif\w+)'", block):
            text = re.search(r"^ +%s: '(.*)',$" % key, en, re.M).group(1).replace("\\'", "'")
            assert text == codes[code], (code, text, codes[code])


def test_no_em_dash_in_the_new_code(view):
    lines = [line for block in _blocks().values() for line in block.splitlines() if 'whatif' in line]
    for text in [view, _read('pegaprox', 'core', 'whatif.py'), _read('pegaprox', 'api', 'whatif.py')] + lines:
        assert '\u2014' not in text and '\u2013' not in text


def test_every_class_is_in_the_static_tailwind_build(view):
    css = _read('static', 'css', 'tailwind.min.css') + _read('web', 'index.html.original')
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    names = _classes(view)
    names -= {'field', 'label'}   # the class-string constants of the view
    missing = sorted(n for n in names if n not in have)
    assert not missing, f'not in static/css/tailwind.min.css: {missing}'


def test_every_icon_exists(view):
    icons = _read('web', 'src', 'icons.js')
    used = set(re.findall(r'Icons\.(\w+)', view)) | {'Scale'}
    for name in used:
        assert re.search(r'^ {12}%s: ' % name, icons, re.M), name


def test_both_layouts_and_the_cloud_mount_it(dash):
    assert "{ id: 'whatif', label: t('whatifTitle'), icon: Icons.Scale }," in dash
    assert "{reportSubTab === 'whatif' && selectedCluster?.id && (" in dash
    cloud = _read('web', 'src', 'cloud.js')
    assert "{ id: 'whatif', label: t('whatifTitle'), icon: 'Scale' }," in cloud
    assert "case 'whatif':" in cloud and '<WhatIfTab clusterId={cid} authFetch={authFetch} />' in cloud


def test_the_bundle_was_rebuilt():
    bundle = _read('web', 'index.html')
    assert 'function WhatIfTab(' in bundle
    for key in _used_keys():
        assert key in bundle, key


# -- runtime ------------------------------------------------------------------------------------

def _report(**body):
    """What the route answers for the small cluster of tests/test_whatif.py."""
    guests = [_vm(100, 'pve1'), _vm(101, 'pve1'), _vm(102, 'pve1'), _vm(103, 'pve2')]
    configs = {100: _cfg(), 101: _cfg(), 102: _cfg('local-lvm', tag=20), 103: _cfg(tag=20)}
    content = [{'volid': 'local-lvm:vm-102-disk-0', 'vmid': 102}]
    extra = dict(NETS)
    extra[('/nodes/pve1/storage/local-lvm/content', 'images')] = content
    extra[('/nodes/pve1/storage/local-lvm/content', 'rootdir')] = []
    m = _manager(_cluster(guests, configs, ha=[('vm:100', 'started'), ('vm:102', 'started')],
                          rules=[{'rule': 'apart', 'type': 'resource-affinity', 'affinity': 'negative',
                                  'resources': 'vm:100,vm:103'}], extra=extra), guests)
    out = whatif.options(m) if body.get('type') == 'options' else whatif.run(m, whatif.parse_scenario(body), dict(THR))
    out = json.loads(json.dumps(out))
    if body.get('type') == 'options':
        out['thresholds'] = {'cpu': 80.0, 'memory': 90.0, 'cpu_source': 'default', 'memory_source': 'alert_rule'}
    else:
        out.update(guests_hidden=0, guests_truncated=0)
    return out


OPTIONS = _report(type='options')


def _reads(report=None, options=None):
    extra = dict(SSE_TOKEN)
    extra[('GET', '/api/clusters/c1/reports/summary')] = (200, {'period': 'day', 'data_points': 0, 'timestamps': []})
    extra[('GET', '/api/clusters/c1/reports/top-vms')] = (200, [])
    extra[('GET', URL + '/options')] = (200, options or OPTIONS)
    extra[('POST', URL)] = (200, report or _report(type='node_failure', nodes=['pve1']))
    return extra


@pytest.fixture
def open_view(browser):  # noqa: F811
    apps = []

    def _open(layout='modern', role='standalone', language='en', **kw):
        app = _App(browser, _FakeServer(role=role, layout=layout, language=language, clusters=[CLUSTER],
                                        resources=[VM], metrics=NODE_METRICS, extra=_reads(**kw)))
        apps.append(app)
        page = app.page
        if layout == 'cloud':
            label = 'Was-wäre-wenn' if language == 'de' else 'What-if'
            page.locator('.cloud-shell').get_by_text(label, exact=True).first.click()
        else:
            page.get_by_text('Testi').first.click()
            page.wait_for_timeout(500)
            page.locator('body').click(position={'x': 5, 'y': 400})
            page.keyboard.press('g')
            page.keyboard.press('p')
            label = 'Was-wäre-wenn' if language == 'de' else 'What-if'
            page.locator('button', has_text=label).first.click()
        page.locator('[data-whatif="picker"] [data-whatif-scenario]').first.wait_for(timeout=10000)
        page.locator('[data-whatif-node], [data-whatif-field]').first.wait_for(timeout=10000)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _posted(app):
    return app.server.bodies.get(URL, [])


@pytest.mark.parametrize('layout', ['modern', 'corporate', 'cloud'])
def test_runtime_a_node_failure_report(open_view, layout):
    app = open_view(layout)
    page = app.page
    run = page.locator('[data-whatif="run"]')
    assert run.is_disabled()            # no node picked yet
    assert page.get_by_text('Pick at least one node.').first.is_visible()
    page.locator('[data-whatif-node="pve1"]').check()
    run.click()
    page.locator('[data-whatif="report"]').wait_for(timeout=5000)
    assert _posted(app)[-1] == {'type': 'node_failure', 'memory': 'configured', 'nodes': ['pve1']}
    counts = {o: page.locator(f'[data-whatif-count="{o}"] .text-2xl').inner_text()
              for o in ('down', 'restarted', 'unaffected')}
    assert counts == {'down': '2', 'restarted': '1', 'unaffected': '1'}, counts
    row = page.locator('[data-whatif-guest="100"]')
    assert 'Restarted' in row.inner_text() and 'pve3' in row.inner_text()
    assert 'restarted by Proxmox HA' in row.inner_text()
    assert row.locator('[data-whatif-basis="assumed"]').count() == 1      # where it lands
    down = page.locator('[data-whatif-guest="102"]').inner_text()
    assert 'a disk of it is on storage of pve1 only' in down
    assert page.locator('[data-whatif-limit="not_ha"]').inner_text().startswith('Guests not managed by HA, staying down: 1')
    pve1 = page.locator('[data-whatif-node-row="pve1"]').inner_text()
    assert 'failed' in pve1 and '25.0%' in pve1
    assert page.locator('[data-whatif-assumption="no_service_model"]').is_visible()
    assert 'Services that depend on other guests are not modeled' in page.locator('[data-whatif="assumptions"]').inner_text()
    # the outcome tiles filter the guest table
    page.locator('[data-whatif-count="restarted"]').click()
    assert page.locator('[data-whatif-guest]').count() == 1
    text = page.locator('[data-whatif="view"]').inner_text()
    assert '\u2014' not in text
    assert not app.errors, app.errors


def test_runtime_headroom_shows_the_failures_checked(open_view):
    app = open_view('modern', report=_report(type='headroom', depth=1))
    page = app.page
    page.locator('[data-whatif-scenario="headroom"]').click()
    page.locator('[data-whatif-field="depth"]').select_option('2')
    page.locator('[data-whatif="run"]').click()
    page.locator('[data-whatif="headroom"]').wait_for(timeout=5000)
    assert _posted(app)[-1] == {'type': 'headroom', 'memory': 'configured', 'depth': 2, 'guests': 'all'}
    assert page.locator('[data-whatif="headroom"] tbody tr').count() == 3
    assert page.locator('[data-whatif="guests"]').count() == 0
    assert page.locator('[data-whatif-count]').count() == 0      # no outcome tiles for a headroom check
    assert 'highest with pve1 down' in page.locator('[data-whatif="nodes"]').inner_text()
    assert not app.errors, app.errors


def test_runtime_storage_and_network_scenarios_send_what_was_picked(open_view):
    app = open_view('corporate', report=_report(type='storage_failure', storage='local-lvm', node='pve1'))
    page = app.page
    page.locator('[data-whatif-scenario="storage_failure"]').click()
    options = page.locator('[data-whatif-field="storage"] option').all_inner_texts()
    assert options == ['-', 'ceph (shared)', 'local-lvm (local)'], options
    page.locator('[data-whatif-field="storage"]').select_option('local-lvm')
    page.locator('[data-whatif-field="where"]').select_option('pve1')
    page.locator('[data-whatif="run"]').click()
    page.locator('[data-whatif="report"]').wait_for(timeout=5000)
    assert _posted(app)[-1] == {'type': 'storage_failure', 'memory': 'configured', 'storage': 'local-lvm', 'node': 'pve1'}
    assert 'its disk scsi0 is on local-lvm' in page.locator('[data-whatif-guest="102"]').inner_text()
    assert page.locator('[data-whatif-limit="no_ha_reaction"]').is_visible()

    app.server.extra[('POST', URL)] = (200, _report(type='network_failure', bridge='vmbr0', vlan=20))
    page.locator('[data-whatif-scenario="network_failure"]').click()
    page.locator('[data-whatif-field="bridge"]').select_option('vmbr0')
    page.locator('[data-whatif-field="vlan"]').fill('20')
    page.locator('[data-whatif-field="cpu"]').fill('70')
    page.locator('[data-whatif="run"]').click()
    page.wait_for_function('() => document.querySelector("[data-whatif-guest=\\"103\\"]")', timeout=5000)
    assert _posted(app)[-1] == {'type': 'network_failure', 'memory': 'configured', 'bridge': 'vmbr0', 'vlan': 20,
                                'thresholds': {'cpu': 70}}
    assert 'every network interface is on vmbr0.20' in page.locator('[data-whatif-guest="103"]').inner_text()
    assert not app.errors, app.errors


def test_runtime_the_view_speaks_german(open_view):
    app = open_view('modern', language='de')
    page = app.page
    assert page.get_by_text('Was-wäre-wenn').first.is_visible()
    page.locator('[data-whatif-node="pve1"]').check()
    page.locator('[data-whatif="run"]', has_text='Simulieren').click()
    page.locator('[data-whatif="report"]').wait_for(timeout=5000)
    assert 'nicht von HA verwaltet' in page.locator('[data-whatif-guest="101"]').inner_text()
    assert 'Neu gestartet' in page.locator('[data-whatif-guest="100"]').inner_text()
    assert 'Dienste, die von anderen Gästen abhängen' in page.locator('[data-whatif="assumptions"]').inner_text()
    assert '(aus Alarmregeln)' in page.locator('[data-whatif="picker"]').inner_text()
    assert not app.errors, app.errors


def test_runtime_a_standby_runs_it_too(open_view):
    app = open_view('modern', role='standby')
    page = app.page
    page.locator('[data-whatif-node="pve1"]').check()
    page.locator('[data-whatif="run"]').click()
    page.locator('[data-whatif="report"]').wait_for(timeout=5000)
    assert page.locator('[data-whatif="error"]').count() == 0
    assert not app.errors, app.errors


def test_runtime_a_confined_caller_is_told_what_is_not_listed(open_view):
    report = dict(_report(type='node_failure', nodes=['pve1']), guests_hidden=2)
    report['guests'] = report['guests'][:1]
    app = open_view('modern', report=report)
    page = app.page
    page.locator('[data-whatif-node="pve1"]').check()
    page.locator('[data-whatif="run"]').click()
    page.get_by_text('Affected guests outside your access, counted but not listed: 2').wait_for(timeout=5000)
    assert not app.errors, app.errors


def test_runtime_an_xcpng_pool_is_not_simulated(open_view, browser):  # noqa: F811
    app = _App(browser, _FakeServer(role='standalone', layout='modern', clusters=[CLUSTER], resources=[VM],
                                    metrics=NODE_METRICS, extra=_reads(options={'supported': False})))
    try:
        page = app.page
        page.get_by_text('Testi').first.click()
        page.wait_for_timeout(500)
        page.locator('body').click(position={'x': 5, 'y': 400})
        page.keyboard.press('g')
        page.keyboard.press('p')
        page.locator('button', has_text='What-if').first.click()
        page.get_by_text('The what-if simulator covers Proxmox VE clusters.').wait_for(timeout=5000)
        assert not app.errors, app.errors
    finally:
        app.ctx.close()
