"""The two evacuation options in the schedule dialog and the maintenance dialog of a node
(#763, #954).

The schedule dialog of the rolling update shows them like the dialog of a run started by
hand, with the plan of the cluster as it is now; they are saved with the schedule and come
back when it is opened again. The maintenance dialog of a node (the node card in Modern,
the node row and the node view in Corporate) shows them with the plan of that node: its
templates, the rules over its guests, and rules another maintenance holds off already.
Both off on each opening, gone on XCP-ng.

The source checks read web/src and the bundle. The runtime tests drive the built bundle in
headless Chromium; the plans come from the real routes of the app over a manager whose
Proxmox answers are faked (tests/test_rolling_options_everywhere_763_954.py). They skip
where Playwright is not installed.

LW Oct 2026
"""
import os
import re

import pytest

from test_ha_ui import (BASE, LANGS, NODE_METRICS, _App, _FakeServer, _blocks, _classes,  # noqa: F401
                        browser)
from test_rolling_options_ui_763_954 import CLUSTER, READS, _to_updates
from test_rolling_options_everywhere_763_954 import MGUESTS, _stateful
from test_rolling_templates_affinity_763_954 import SAN_TEMPLATE, _manager, _Pve, _reads
from pegaprox.models.tasks import MaintenanceTask

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHOTS = os.environ.get('PEGAPROX_UI_SHOTS', '')
NEW_KEY = r'(?:maintEvac|evacHeld|schedEvac)\w+'


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def _shared():
    src = _read('web', 'src', 'security.js')
    return src[src.index('// LW Oct 2026 (#763, #954) - the two evacuation options and what'):
               src.index('// update Manager Section Component (for Settings tab)')]


def _dialogs():
    """The places that use the options: the schedule dialog and the maintenance dialog that every
    node's maintenance goes through (NS Oct 2026: the three node dialogs became one)."""
    sec = _read('web', 'src', 'security.js')
    tables = _read('web', 'src', 'tables.js')
    nodes = _read('web', 'src', 'node_modals.js')
    out = [sec[sec.index('{/* LW Oct 2026 (#763, #954) - the same two options for the scheduled run */}'):
               sec.index('{/* NS: GitHub #40 - Advanced Options */}')]]
    at = sec.index('function MaintenanceDialog(')
    out.append(sec[at:sec.index('// LW Oct 2026 (#763, #954) - the two evacuation options and what', at)])
    assert '<MaintenanceEvacOptions' in out[-1]
    # every node dialog of the pages asks through it, with its own options
    for src in (tables, tables[tables.index('function NodeCompactRow('):], nodes):
        at = src.index('<MaintenanceDialog')
        assert 'options={maintOptions} onOptions={setMaintOptions}' in src[at:at + 300]
    return out


def _used_keys():
    keys = set()
    for name in ('security.js', 'tables.js', 'node_modals.js', 'dashboard.js'):
        keys |= set(re.findall(r"t\('(%s)'\)" % NEW_KEY, _read('web', 'src', name)))
    return sorted(keys)


# -- source ------------------------------------------------------------------------------------

def test_the_new_strings_are_their_own_keys():
    assert _used_keys() == sorted(['maintEvacTemplatesHint', 'maintEvacTemplatesStay', 'maintEvacNoTemplates',
                                   'maintEvacRelax', 'maintEvacRelaxHint', 'maintEvacRulesOff', 'maintEvacNoRules',
                                   'evacHeldMaintenance', 'evacHeldRolling', 'schedEvacPlanNow'])


@pytest.mark.parametrize('lang', LANGS)
def test_every_new_key_exists_once_per_language(lang):
    block = _blocks()[lang]
    for key in _used_keys() + ['rollEvacStillOff']:
        n = len(re.findall(r'^ +%s: ' % key, block, re.M))
        assert n == 1, f'{key} appears {n} times in {lang}'


def test_no_key_is_defined_that_nothing_uses():
    used = set(_used_keys())
    for lang, block in _blocks().items():
        assert set(re.findall(r'^ +(%s): ' % NEW_KEY, block, re.M)) == used, lang


def test_placeholders_survive_translation():
    blocks = _blocks()
    for key in _used_keys() + ['rollEvacStillOff']:
        en = re.search(r'^ +%s: (.*),$' % key, blocks['en'], re.M).group(1)
        for lang, block in blocks.items():
            value = re.search(r'^ +%s: (.*),$' % key, block, re.M).group(1)
            assert sorted(re.findall(r'\{\w+\}', value)) == sorted(re.findall(r'\{\w+\}', en)), (lang, key)


def test_the_austrian_flag_stays_on_german():
    assert "{ code: 'de', flag: '\U0001F1E6\U0001F1F9'," in _read('web', 'src', 'contexts.js')


def test_no_dash_of_the_long_kind_in_the_new_code_and_strings():
    lines = [line for block in _blocks().values() for line in block.splitlines()
             if re.search(NEW_KEY, line) or 'rollEvacStillOff' in line]
    for text in [_shared()] + _dialogs() + lines:
        assert '\u2014' not in text and '–' not in text


def test_every_class_is_in_the_static_tailwind_build():
    css = _read('static', 'css', 'tailwind.min.css') + _read('web', 'index.html.original')
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    names = _classes(_shared())
    for part in _dialogs():
        names |= _classes(part)
    missing = sorted(n for n in names if n not in have)
    assert not missing, f'not in static/css/tailwind.min.css: {missing}'


def test_no_icon_is_used_that_does_not_exist():
    icons = set(re.findall(r'^            ([A-Z][A-Za-z0-9]*):', _read('web', 'src', 'icons.js'), re.M))
    used = set()
    for part in [_shared()] + _dialogs():
        used |= set(re.findall(r'Icons\.([A-Z][A-Za-z0-9]*)', part))
    assert used <= icons, sorted(used - icons)


def test_the_options_go_out_with_the_schedule_and_the_maintenance():
    sec = _read('web', 'src', 'security.js')
    save = sec[sec.index('const saveUpdateSchedule = async'):sec.index('// Load schedule on mount')]
    assert 'migrate_templates: scheduleMigrateTemplates && !scheduleSkipEvacuation,' in save
    assert 'relax_anti_affinity: scheduleRelaxAntiAffinity && !scheduleSkipEvacuation,' in save
    dash = _read('web', 'src', 'dashboard.js')
    toggle = dash[dash.index('const handleMaintenanceToggle = async (nodeName, enable, options, forCluster) => {'):]
    toggle = toggle[:toggle.index('\n            };')]
    assert 'migrate_templates: options?.migrate_templates === true,' in toggle
    assert 'relax_anti_affinity: options?.relax_anti_affinity === true,' in toggle
    # the node's plan comes from the route that needs the maintenance permission
    assert '/nodes/${encodeURIComponent(node)}/maintenance-plan`' in _shared()


def test_the_bundle_was_rebuilt():
    bundle = _read('web', 'index.html')
    for needle in ('function MaintenanceEvacOptions(', '/maintenance-plan`', 'createElement(EvacOptions,{kind:"schedule"',
                   'scheduleRelaxAntiAffinity', 'maint-dialog'):
        assert needle in bundle, needle
    for key in _used_keys():
        assert key in bundle, key


# -- runtime -----------------------------------------------------------------------------------

PLAN = '/api/clusters/cluster_1/updates/rolling/plan'
NODE_PLAN = re.compile(r'^/api/clusters/cluster_1/nodes/[^/]+/maintenance-plan$')
METRICS = {n: dict(NODE_METRICS['pve1']) for n in ('pve4', 'pve5')}
SCHEDULE = '/api/clusters/cluster_1/updates/schedule'
MAINT = '/api/clusters/cluster_1/nodes/pve5/maintenance'


class _Server(_FakeServer):
    """The page from the fake server, the plans from the app."""

    def __init__(self, client, **kw):
        kw.setdefault('clusters', [CLUSTER])
        kw.setdefault('resources', [])
        kw.setdefault('metrics', METRICS)
        kw.setdefault('role', 'standalone')
        extra = dict(READS)
        extra.update({('POST', SCHEDULE): (200, {'success': True}),
                      ('PUT', MAINT): (200, {'message': 'Entering maintenance mode for pve5'})})
        extra.update(kw.pop('extra', {}))
        super().__init__(extra=extra, **kw)
        self.client = client

    def handle(self, route):
        req = route.request
        path = re.sub(r'^https?://[^/]+', '', req.url).split('?')[0]
        if not req.url.startswith(BASE) or not (path == PLAN or NODE_PLAN.match(path)):
            return super().handle(route)
        self.calls.append((req.method, path))
        r = self.client.get(path)
        return route.fulfill(status=r.status_code, body=r.get_data(), headers={'Content-Type': 'application/json'})


@pytest.fixture
def real_app(browser, api, seed):  # noqa: F811
    apps = []
    pve = _Pve(_reads(v9000=SAN_TEMPLATE))
    rules = _stateful(pve)
    mgr = _manager(pve, MGUESTS)
    # pve4 is in maintenance and holds web-apart off already
    mgr.nodes_in_maintenance = {'pve4': MaintenanceTask('pve4')}
    rules[0]['disable'] = 1
    seed.db.save_suspended_ha_rules('cluster_1', ['web-apart'], owner='maintenance:pve4')
    api.set_manager('cluster_1', mgr)
    admin = seed.user('admin', role='admin')

    def _open(layout='modern', **kw):
        app = _App(browser, _Server(api.as_user(admin), layout=layout, **kw))
        app.page.on('dialog', lambda d: d.accept())   # the capacity question after the dialog
        app.pve = pve
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _shot(app, name):
    if SHOTS:
        os.makedirs(SHOTS, exist_ok=True)
        app.page.screenshot(path=os.path.join(SHOTS, f'{name}.png'))


def _open_schedule(app, layout):
    page = app.page
    head = _to_updates(app, layout)
    button = page.locator('button[title^="Schedule"]')
    if not button.count():
        head.click()
    button.first.wait_for(timeout=8000)
    button.first.click()
    dialog = page.locator('[data-testid="schedule-dialog"]')
    dialog.wait_for(timeout=5000)
    return dialog


def _wait_plan(dialog, kind):
    dialog.locator(f'[data-testid="{kind}-plan-rules"] div').first.wait_for(timeout=8000)
    dialog.page.wait_for_timeout(300)


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_the_schedule_dialog_offers_and_saves_both_options(real_app, layout):
    app = real_app(layout=layout)
    dialog = _open_schedule(app, layout)
    assert dialog.locator('[data-testid="schedule-evac-options"]').count() == 0, 'only with the schedule on'
    dialog.locator('div.w-12.h-6').first.click()
    options = dialog.locator('[data-testid="schedule-evac-options"]')
    options.wait_for(timeout=5000)
    _wait_plan(dialog, 'schedule')
    text = options.inner_text()
    assert 'Shown for the cluster as it is now. The scheduled run looks again when it starts.' in text
    assert 'Move templates with the evacuation' in text
    assert 'Let negative affinity rules give way during the update' in text
    assert '2 template(s) stay on their nodes and cannot be used while their node reboots.' in text
    assert 'Already off for the maintenance of pve4: web-apart' in text
    assert not dialog.locator('[data-testid="schedule-move-templates"]').is_checked()
    dialog.locator('[data-testid="schedule-move-templates"]').check()
    dialog.locator('[data-testid="schedule-relax-affinity"]').check()
    assert 'Switched off before the first evacuation and on again at the end' in options.inner_text()
    _shot(app, f'schedule-options-{layout}')
    dialog.locator('button', has_text=re.compile(r'^\s*Save\s*$')).click()
    app.page.wait_for_timeout(500)
    body = [b for b in app.server.bodies[SCHEDULE] if b][-1]
    assert body['migrate_templates'] is True and body['relax_anti_affinity'] is True
    assert app.pve.puts == [] and app.pve.migrations == [], 'reading the plan changed something'
    assert not app.errors, app.errors


def test_runtime_a_saved_schedule_brings_its_options_back_and_skipping_takes_them(real_app):
    saved = {'enabled': True, 'schedule_type': 'recurring', 'day': 'sunday', 'time': '03:00',
             'include_reboot': False, 'skip_evacuation': False, 'migrate_templates': True,
             'relax_anti_affinity': False}
    app = real_app(layout='modern', extra={('GET', SCHEDULE): (200, saved)})
    dialog = _open_schedule(app, 'modern')
    _wait_plan(dialog, 'schedule')
    assert dialog.locator('[data-testid="schedule-move-templates"]').is_checked()
    assert not dialog.locator('[data-testid="schedule-relax-affinity"]').is_checked()
    dialog.locator('label', has_text='Skip VM evacuation').locator('input').check()
    assert dialog.locator('[data-testid="schedule-move-templates"]').is_disabled()
    assert dialog.locator('[data-testid="schedule-plan-templates"]').count() == 0
    dialog.locator('button', has_text=re.compile(r'^\s*Save\s*$')).click()
    app.page.wait_for_timeout(500)
    body = [b for b in app.server.bodies[SCHEDULE] if b][-1]
    assert body['skip_evacuation'] is True
    assert body['migrate_templates'] is False and body['relax_anti_affinity'] is False
    assert not app.errors, app.errors


def _check_maintenance_dialog(app, dialog, name):
    options = dialog.locator('[data-testid="maint-evac-options"]')
    options.wait_for(timeout=8000)
    _wait_plan(dialog, 'maint')
    text = options.inner_text()
    assert 'Let negative affinity rules give way during the maintenance' in text
    assert '1 template(s) stay on this node and cannot be used while it is down.' in text
    # the rules over a guest of pve5 only, the one pve4 holds said as such
    assert 'ct-apart: ct:201, vm:200' in text
    assert 'elsewhere' not in text and 'other-kind' not in text
    assert 'Already off for the maintenance of pve4: web-apart' in text
    assert not dialog.locator('[data-testid="maint-move-templates"]').is_checked()
    assert not dialog.locator('[data-testid="maint-relax-affinity"]').is_checked()
    dialog.locator('[data-testid="maint-move-templates"]').check()
    moves = dialog.locator('[data-template="9000"]')
    assert moves.get_attribute('data-moves') == 'yes'
    assert 'tpl9000 (9000, pve5): moves offline to one of pve3, pve4' in moves.inner_text()
    dialog.locator('[data-testid="maint-relax-affinity"]').check()
    assert ('Switched off before the evacuation and on again when the node leaves maintenance'
            in options.inner_text())
    _shot(app, name)


def _maintenance_body(app):
    deadline = 40
    while deadline and MAINT not in app.server.bodies:
        app.page.wait_for_timeout(100)
        deadline -= 1
    return app.server.bodies[MAINT][-1]


def test_runtime_the_node_card_asks_with_both_options_in_modern(real_app):
    app = real_app(layout='modern')
    page = app.page
    page.get_by_text('Testi').first.click()
    button = page.locator('button[title="Enter Maintenance Mode"]')
    button.first.wait_for(timeout=8000)
    # the card of pve5 (pve4 comes first)
    page.locator('button[title="Enter Maintenance Mode"]').nth(1).click()
    dialog = page.locator('[data-testid="maint-dialog"]')
    dialog.wait_for(timeout=5000)
    assert 'pve5' in dialog.inner_text()
    _check_maintenance_dialog(app, dialog, 'maintenance-options-modern')
    dialog.locator('button', has_text='Enable maintenance').click()
    body = _maintenance_body(app)
    assert body == {'enable': True, 'migrate_templates': True, 'relax_anti_affinity': True}
    assert ('GET', '/api/clusters/cluster_1/nodes/pve5/maintenance-plan') in app.server.calls
    assert app.pve.puts == [] and app.pve.migrations == []
    assert not app.errors, app.errors


def test_runtime_both_options_are_off_on_each_opening(real_app):
    app = real_app(layout='modern')
    page = app.page
    page.get_by_text('Testi').first.click()
    page.locator('button[title="Enter Maintenance Mode"]').first.wait_for(timeout=8000)
    page.locator('button[title="Enter Maintenance Mode"]').nth(1).click()
    dialog = page.locator('[data-testid="maint-dialog"]')
    _wait_plan(dialog, 'maint')
    dialog.locator('[data-testid="maint-relax-affinity"]').check()
    dialog.locator('button', has_text='Cancel').click()
    page.locator('button[title="Enter Maintenance Mode"]').nth(1).click()
    _wait_plan(dialog, 'maint')
    assert not dialog.locator('[data-testid="maint-relax-affinity"]').is_checked()
    dialog.locator('button', has_text='Enable maintenance').click()
    body = _maintenance_body(app)
    assert body == {'enable': True, 'migrate_templates': False, 'relax_anti_affinity': False}
    assert not app.errors, app.errors


def test_runtime_the_node_row_asks_with_both_options_in_corporate(real_app):
    app = real_app(layout='corporate')
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    row = page.locator('.corp-node-row', has_text='pve5').first
    row.wait_for(timeout=8000)
    row.get_by_text('pve5').first.click()
    row.locator('.corp-toolbar').wait_for(timeout=3000)
    row.locator('.corp-toolbar button', has_text='Enter Maintenance Mode').click()
    dialog = page.locator('[data-testid="maint-dialog"]')
    dialog.wait_for(timeout=5000)
    _check_maintenance_dialog(app, dialog, 'maintenance-options-corporate-row')
    dialog.locator('button').last.click()
    body = _maintenance_body(app)
    assert body == {'enable': True, 'migrate_templates': True, 'relax_anti_affinity': True}
    assert not app.errors, app.errors


def test_runtime_the_node_view_asks_with_both_options_in_corporate(real_app):
    app = real_app(layout='corporate')
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    child = page.locator('.corp-tree-child', has_text='pve5').first
    child.wait_for(timeout=8000)
    child.click()
    page.locator('.corp-toolbar button', has_text='Actions').last.click()
    page.locator('.corp-dropdown button', has_text=re.compile(r'^\s*Maintenance\s*$')).last.click()
    dialog = page.locator('[data-testid="maint-dialog"]')
    dialog.wait_for(timeout=5000)
    assert 'pve5' in dialog.inner_text()
    _check_maintenance_dialog(app, dialog, 'maintenance-options-corporate-view')
    dialog.locator('button').last.click()
    body = _maintenance_body(app)
    assert body == {'enable': True, 'migrate_templates': True, 'relax_anti_affinity': True}
    assert not app.errors, app.errors


def test_runtime_an_xcpng_host_shows_neither_option(real_app, api):
    app = real_app(layout='modern')
    api.set_manager('cluster_1', api.make_fake_manager('cluster_1', cluster_type='xcpng'))
    page = app.page
    page.get_by_text('Testi').first.click()
    page.locator('button[title="Enter Maintenance Mode"]').first.wait_for(timeout=8000)
    page.locator('button[title="Enter Maintenance Mode"]').nth(1).click()
    dialog = page.locator('[data-testid="maint-dialog"]')
    dialog.wait_for(timeout=5000)
    deadline = 50
    while deadline and ('GET', '/api/clusters/cluster_1/nodes/pve5/maintenance-plan') not in app.server.calls:
        page.wait_for_timeout(100)
        deadline -= 1
    page.wait_for_timeout(300)
    assert dialog.locator('[data-testid="maint-evac-options"]').count() == 0
    dialog.locator('button', has_text='Enable maintenance').click()
    assert _maintenance_body(app) == {'enable': True, 'migrate_templates': False, 'relax_anti_affinity': False}
    assert not app.errors, app.errors


def test_runtime_the_maintenance_dialog_speaks_german(real_app):
    app = real_app(layout='modern', language='de')
    page = app.page
    page.get_by_text('Testi').first.click()
    page.locator('button[title="Wartungsmodus aktivieren"], button[title="Enter Maintenance Mode"]').first.wait_for(
        timeout=8000)
    page.locator('button[title="Wartungsmodus aktivieren"], button[title="Enter Maintenance Mode"]').nth(1).click()
    dialog = page.locator('[data-testid="maint-dialog"]')
    _wait_plan(dialog, 'maint')
    text = dialog.inner_text()
    assert 'Negative Affinitätsregeln während der Wartung nachgeben lassen' in text
    assert 'Bereits aus für die Wartung von pve4: web-apart' in text
    assert not app.errors, app.errors
