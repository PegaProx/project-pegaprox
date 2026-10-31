"""The two evacuation options in the rolling update dialog (#763, #954).

"Move templates with the evacuation" and "Let negative affinity rules give way during the
update", both off as before. When the dialog opens it reads the plan route once, and
under each box says what ticking it changes: which template moves where and which stays
and why; which Proxmox HA rules stay on or are switched off for the run, which of them
block an evacuation, and what happens to PegaProx's own anti-affinity rules. The dialog
is the same in Modern, Corporate and Cloud. On a standby there is no button to open it.

The source checks read web/src and the bundle. The runtime tests drive the built bundle
in headless Chromium: the page comes from the fake server of tests/test_ha_ui.py, the plan
from the real route of the app over a cluster manager whose Proxmox answers are faked in
tests/test_rolling_templates_affinity_763_954.py. They skip where Playwright is not
installed.

LW Oct 2026
"""
import json
import os
import re

import pytest

from test_ha_ui import (BASE, LANGS, _App, _FakeServer, _blocks, _classes,  # noqa: F401 (browser is a fixture)
                        browser)
from test_rolling_templates_affinity_763_954 import (RULES, SAN_TEMPLATE, _Pve, _manager, _reads, _running,
                                                     _template)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHOTS = os.environ.get('PEGAPROX_UI_SHOTS', '')


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def _component():
    src = _read('web', 'src', 'security.js')
    start = src.index('function UpdateManagerSection(')
    return src[start:src.index('\n        function ', start + 10)]


def _shared():
    """The options and their plan, shared with the schedule and the maintenance dialog of a
    node since they came there too (useEvacPlan, EvacOptions, MaintenanceEvacOptions)."""
    src = _read('web', 'src', 'security.js')
    return src[src.index('// LW Oct 2026 (#763, #954) - the two evacuation options and what'):
               src.index('// update Manager Section Component (for Settings tab)')]


def _new_code():
    comp = _component()
    parts = [comp[comp.index('// LW Oct 2026 (#763, #954) - what moving the templates'):comp.index('// Cancel rolling update')],
             comp[comp.index('{/* LW Oct 2026 (#763, #954) - two evacuation options'):comp.index('{/* NS: Advanced options toggle */}')],
             _shared()]
    return parts


def _used_keys():
    return sorted(set(re.findall(r"t\('(rollEvac\w+)'\)", _read('web', 'src', 'security.js'))))


# -- source ------------------------------------------------------------------------------------

def test_the_new_strings_are_their_own_keys():
    keys = _used_keys()
    assert len(keys) == 24, keys


@pytest.mark.parametrize('lang', LANGS)
def test_every_new_key_exists_once_per_language(lang):
    block = _blocks()[lang]
    for key in _used_keys():
        n = len(re.findall(r'^ +%s: ' % key, block, re.M))
        assert n == 1, f'{key} appears {n} times in {lang}'


def test_no_key_is_defined_that_nothing_uses():
    used = set(_used_keys())
    for lang, block in _blocks().items():
        assert set(re.findall(r'^ +(rollEvac\w+): ', block, re.M)) == used, lang


def test_placeholders_survive_translation():
    blocks = _blocks()
    for key in _used_keys():
        en = re.search(r'^ +%s: (.*),$' % key, blocks['en'], re.M).group(1)
        for lang, block in blocks.items():
            value = re.search(r'^ +%s: (.*),$' % key, block, re.M).group(1)
            assert sorted(re.findall(r'\{\w+\}', value)) == sorted(re.findall(r'\{\w+\}', en)), (lang, key)


def test_the_austrian_flag_stays_on_german():
    assert "{ code: 'de', flag: '\U0001F1E6\U0001F1F9'," in _read('web', 'src', 'contexts.js')


def test_no_em_dash_in_the_new_code_and_strings():
    lines = [line for block in _blocks().values() for line in block.splitlines() if 'rollEvac' in line]
    for text in _new_code() + lines:
        assert '\u2014' not in text and '\u2013' not in text


def test_every_class_is_in_the_static_tailwind_build():
    css = _read('static', 'css', 'tailwind.min.css') + _read('web', 'index.html.original')
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    names = set()
    for part in _new_code():
        names |= _classes(part)
    names |= {'max-h-[90vh]', 'overflow-y-auto'}   # the dialog scrolls now that it is taller
    missing = sorted(n for n in names if n not in have)
    assert not missing, f'not in static/css/tailwind.min.css: {missing}'


def test_no_icon_is_used_that_does_not_exist():
    icons = set(re.findall(r'^            ([A-Z][A-Za-z0-9]*):', _read('web', 'src', 'icons.js'), re.M))
    used = set()
    for part in _new_code():
        used |= set(re.findall(r'Icons\.([A-Z][A-Za-z0-9]*)', part))
    assert used <= icons, sorted(used - icons)


def test_the_plan_is_read_once_per_opening_and_never_per_guest():
    shared = _shared()
    effect = shared[shared.index('function useEvacPlan('):shared.index('function EvacOptions(')]
    assert effect.count('fetch(') == 1
    assert 'if (!open) return undefined;' in effect and '}, [open, url]);' in effect
    assert 'fetch(' not in shared[shared.index('function EvacOptions('):]
    comp = _component()
    reads = comp[comp.index('// LW Oct 2026 (#763, #954) - what moving the templates'):comp.index('// Cancel rolling update')]
    assert 'const rollingPlanUrl = `${API_URL}/clusters/${clusterId}/updates/rolling/plan`;' in reads
    assert 'const rollingPlan = useEvacPlan(rollingPlanUrl, showConfirm);' in reads


def test_the_options_go_out_with_the_start_and_only_with_an_evacuation():
    comp = _component()
    start = comp[comp.index('const startRollingUpdate = async'):comp.index('// Cancel rolling update')]
    assert 'migrate_templates: migrateTemplates && !skipEvacuation,' in start
    assert 'relax_anti_affinity: relaxAntiAffinity && !skipEvacuation,' in start


def test_the_bundle_was_rebuilt():
    bundle = _read('web', 'index.html')
    for needle in ('-move-templates', '-relax-affinity', '-plan-rules', '/updates/rolling/plan',
                   'function EvacOptions(', 'createElement(EvacOptions,{kind:"rolling"'):
        assert needle in bundle, needle
    for key in _used_keys():
        assert key in bundle, key


# -- runtime -----------------------------------------------------------------------------------

CLUSTER = {'id': 'cluster_1', 'name': 'Testi', 'display_name': 'Testi', 'host': '10.0.0.1',
           'connected': True, 'status': 'running', 'cluster_type': 'proxmox', 'enabled': True}
CHECK = {'success': True, 'summary': {'total_updates': 3, 'nodes_with_updates': 2, 'nodes_failed': 0,
                                      'total_nodes': 3, 'pbs_with_updates': 0, 'total_pbs': 0},
         'nodes': {'pve1': {'count': 2, 'updates': [{'Package': 'pve-manager'}]},
                   'pve3': {'count': 1, 'updates': [{'Package': 'qemu-server'}]}},
         'pbs': {}, 'cached': False}
READS = {
    ('GET', '/api/clusters/cluster_1/updates/status'): (200, {'success': True, 'rolling_update': None}),
    ('POST', '/api/clusters/cluster_1/updates/check'): (200, CHECK),
    ('GET', '/api/clusters/cluster_1/updates/schedule'): (200, {'enabled': False}),
    ('GET', '/api/alert-channels'): (200, []),
    ('POST', '/api/clusters/cluster_1/updates/rolling'): (200, {'success': True, 'message': 'Rolling update started'}),
    ('POST', '/api/sse/token'): (200, {}),
}
PLAN = '/api/clusters/cluster_1/updates/rolling/plan'
GUESTS = [_running(100, node='pve1'), _template(9000, node='pve5', name='debian-12'),
          _template(9001, node='pve5', name='win-zfs')]


class _Server(_FakeServer):
    """The page from the fake server, the plan from the app."""

    def __init__(self, client, **kw):
        kw.setdefault('clusters', [CLUSTER])
        kw.setdefault('resources', [])
        kw.setdefault('role', 'standalone')
        extra = dict(READS)
        extra.update(kw.pop('extra', {}))
        super().__init__(extra=extra, **kw)
        self.client = client

    def handle(self, route):
        req = route.request
        path = re.sub(r'^https?://[^/]+', '', req.url).split('?')[0]
        if not req.url.startswith(BASE) or path != PLAN:
            return super().handle(route)
        self.calls.append((req.method, path))
        r = self.client.get(path)
        return route.fulfill(status=r.status_code, body=r.get_data(), headers={'Content-Type': 'application/json'})


@pytest.fixture
def real_app(browser, api, seed):  # noqa: F811
    apps = []
    reads = _reads(v9000=SAN_TEMPLATE, v9001={'scsi0': 'local-zfs:base-9001-disk-0,size=8G'})
    reads['/cluster/ha/rules'] = RULES
    pve = _Pve(reads)
    mgr = _manager(pve, GUESTS)
    # three nodes online: keep-apart (three guests) leaves no room with one of them out
    mgr.get_node_status = lambda: {n: {'status': 'online', 'score': i} for i, n in enumerate(('pve1', 'pve3', 'pve5'))}
    mgr._derive_proxlb_tag_rules = lambda *a, **k: {'rules': [
        {'name': 'web apart', 'type': 'separate', 'vms': ['100', '101'], 'enabled': True, 'enforce': True}],
        'pins': {}, 'ignored': set()}
    api.set_manager('cluster_1', mgr)
    admin = seed.user('admin', role='admin')

    def _open(layout='modern', **kw):
        app = _App(browser, _Server(api.as_user(admin), layout=layout, **kw))
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


def _to_updates(app, layout, cluster_name='Testi'):
    page = app.page
    if layout == 'cloud':
        page.locator('.cloud-nav-item', has_text='Update Manager').first.click()
    else:
        if layout == 'corporate':
            page.locator('.corp-tree-item', has_text=cluster_name).first.click()
        else:
            page.get_by_text(cluster_name).first.click()
        page.wait_for_timeout(500)
        page.locator('button', has_text=re.compile(r'^\s*Settings\s*$')).last.click()
    head = page.get_by_text('Update Manager').last
    head.wait_for(timeout=8000)
    return head


def _open_dialog(app, layout):
    page = app.page
    head = _to_updates(app, layout)
    start = page.locator('button', has_text='Start Rolling Update')
    if not start.count():
        head.click()
    start.first.wait_for(timeout=8000)
    start.first.click()
    dialog = page.locator('[data-testid="rolling-confirm"]')
    dialog.wait_for(timeout=5000)
    dialog.locator('[data-template="9000"], [data-testid="rolling-plan-templates"] span').first.wait_for(timeout=8000)
    page.wait_for_timeout(300)
    return dialog


def _start_body(app):
    return app.server.bodies['/api/clusters/cluster_1/updates/rolling'][-1]


@pytest.mark.parametrize('layout', ['modern', 'corporate', 'cloud'])
def test_runtime_the_dialog_says_what_each_option_changes(real_app, layout):
    app = real_app(layout=layout)
    dialog = _open_dialog(app, layout)
    templates = dialog.locator('[data-testid="rolling-plan-templates"]')
    rules = dialog.locator('[data-testid="rolling-plan-rules"]')
    # both off: the templates stay, the rules stay on, and the dialog says so
    assert not dialog.locator('[data-testid="rolling-move-templates"]').is_checked()
    assert not dialog.locator('[data-testid="rolling-relax-affinity"]').is_checked()
    assert '2 template(s) stay on their nodes and cannot be used while their node reboots.' in templates.inner_text()
    text = rules.inner_text()
    assert 'These Proxmox HA rules stay on.' in text
    assert 'keep-apart: vm:100, vm:101, vm:102 - as many guests as nodes, blocks the evacuation' in text
    assert 'db-apart: vm:200, ct:201' in text and 'already-off' not in text and 'together' not in text
    assert '1 PegaProx anti-affinity rule(s): they never block an evacuation.' in text
    _shot(app, f'rolling-options-off-{layout}')

    dialog.locator('[data-testid="rolling-move-templates"]').check()
    moves = templates.locator('[data-template="9000"]')
    assert moves.get_attribute('data-moves') == 'yes'
    assert 'debian-12 (9000, pve5): moves offline to one of pve3, pve4' in moves.inner_text()
    stays = templates.locator('[data-template="9001"]')
    assert stays.get_attribute('data-moves') == 'no'
    assert 'win-zfs (9001, pve5): stays: no other node has storage local-zfs' in stays.inner_text()

    dialog.locator('[data-testid="rolling-relax-affinity"]').check()
    text = rules.inner_text()
    assert 'Switched off before the first evacuation and on again at the end' in text
    assert ('1 PegaProx anti-affinity rule(s): their guests may share a node until the update has ended, '
            'then the balancer moves them apart.') in text
    _shot(app, f'rolling-options-on-{layout}')

    dialog.locator('button', has_text='Start Rolling Update').click()
    app.page.wait_for_timeout(500)
    body = _start_body(app)
    assert body['migrate_templates'] is True and body['relax_anti_affinity'] is True
    assert [c for c in app.server.calls if c == ('GET', PLAN)] == [('GET', PLAN)], 'the plan is read once'
    assert app.pve.puts == [] and app.pve.migrations == [], 'reading the plan changed something'
    assert not app.errors, app.errors


def test_runtime_skipping_the_evacuation_takes_both_options_with_it(real_app):
    app = real_app(layout='modern')
    dialog = _open_dialog(app, 'modern')
    dialog.locator('[data-testid="rolling-move-templates"]').check()
    dialog.locator('[data-testid="rolling-relax-affinity"]').check()
    dialog.locator('input[type="checkbox"]').nth(2).wait_for()
    dialog.locator('label', has_text='Skip VM evacuation').locator('input').check()
    assert dialog.locator('[data-testid="rolling-move-templates"]').is_disabled()
    assert not dialog.locator('[data-testid="rolling-move-templates"]').is_checked()
    assert dialog.locator('[data-testid="rolling-plan-templates"]').count() == 0
    dialog.locator('button', has_text='Start Rolling Update').click()
    app.page.wait_for_timeout(500)
    body = _start_body(app)
    assert body['skip_evacuation'] is True
    assert body['migrate_templates'] is False and body['relax_anti_affinity'] is False
    assert not app.errors, app.errors


def test_runtime_the_dialog_speaks_german(real_app):
    app = real_app(layout='modern', language='de')
    page = app.page
    page.get_by_text('Testi').first.click()
    page.wait_for_timeout(500)
    page.locator('button', has_text=re.compile(r'^\s*Einstellungen\s*$')).last.click()
    start = page.locator('button', has_text='Rolling Update starten')
    if not start.count():
        page.get_by_text('Update Manager').last.click()
    start.first.wait_for(timeout=8000)
    start.first.click()
    dialog = page.locator('[data-testid="rolling-confirm"]')
    dialog.locator('[data-testid="rolling-plan-rules"] [data-rule="keep-apart"]').wait_for(timeout=8000)
    assert 'Vorlagen bei der Evakuierung mitnehmen' in dialog.inner_text()
    assert 'Negative Affinitätsregeln während des Updates nachgeben lassen' in dialog.inner_text()
    dialog.locator('[data-testid="rolling-move-templates"]').check()
    assert 'bleibt: kein anderer Node hat den Speicher local-zfs' in dialog.inner_text()
    assert not app.errors, app.errors


def test_runtime_an_xcpng_pool_shows_neither_option(real_app, api):
    app = real_app(layout='modern')
    api.set_manager('cluster_1', api.make_fake_manager('cluster_1', cluster_type='xcpng'))
    page = app.page
    _to_updates(app, 'modern')
    start = page.locator('button', has_text='Start Rolling Update')
    if not start.count():
        page.get_by_text('Update Manager').last.click()
    start.first.wait_for(timeout=8000)
    start.first.click()
    dialog = page.locator('[data-testid="rolling-confirm"]')
    dialog.wait_for(timeout=5000)
    deadline = 50
    while deadline and ('GET', PLAN) not in app.server.calls:
        page.wait_for_timeout(100)
        deadline -= 1
    page.wait_for_timeout(300)
    assert dialog.locator('[data-testid="rolling-evac-options"]').count() == 0
    dialog.locator('button', has_text='Start Rolling Update').click()
    page.wait_for_timeout(500)
    assert _start_body(app)['migrate_templates'] is False
    assert not app.errors, app.errors


def test_runtime_a_standby_offers_no_rolling_update_and_reads_no_plan(real_app):
    app = real_app(layout='modern', role='standby')
    page = app.page
    head = _to_updates(app, 'modern')
    head.click()
    page.wait_for_timeout(800)
    assert page.locator('button', has_text='Start Rolling Update').count() == 0
    assert ('GET', PLAN) not in app.server.calls
    assert not app.errors, app.errors
