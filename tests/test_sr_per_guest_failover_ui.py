"""Site Recovery guest by guest in the UI.

Emergency failover and failback open a picker of the plan's guests: every guest the
action can take is ticked to begin with, the others are listed with where they are. All
ticked sends no list (the whole plan, as before); fewer sends {"vmids": [...]}. The
confirmation of the emergency failover stays the one it was. The plan shows how much of
it is failed over, in its header and its card, the guests tab says where each guest is
and that its replication is paused, and a run's results list the guests it passed over.
A standby shows all of it and offers neither action.

The source checks read web/src and the bundle; the runtime tests drive the built bundle in
headless Chromium against the fake server of tests/test_ha_ui.py, in Modern, Corporate and
Cloud, as an active instance and as a standby. The routes are tested in
tests/test_sr_per_guest_failover.py.
LW Oct 2026
"""
import json
import os
import re

import pytest

from test_ha_ui import CLUSTER, VM, _App, _FakeServer, _classes, browser  # noqa: F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHOTS = os.environ.get('PEGAPROX_SHOTS', '')
KEYS = ['srGuestLocation', 'srGuestAtSource', 'srGuestFailedOver', 'srReplicationHeld', 'srFailoverPartial',
        'srFailoverAll', 'srPickEmergencyHint', 'srPickFailbackHint', 'srPickCount', 'srPickMore',
        'srPickStartEmergency', 'srPickStartFailback', 'srConfirmFailback', 'srSkipFailedOver', 'srSkipNotFailedOver']
PLACEHOLDERS = {'srFailoverPartial': ('{n}', '{total}'), 'srPickCount': ('{n}', '{total}'), 'srPickMore': ('{n}',),
                'srPickStartEmergency': ('{n}',), 'srPickStartFailback': ('{n}',)}


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def _lines(text, needle, n=1):
    """The n lines from the one that holds needle: what this change wrote, not its neighbours."""
    i = text.index(needle)
    start = text.rfind('\n', 0, i) + 1
    return '\n'.join(text[start:].split('\n')[:n])


def _block():
    dash = _read('web', 'src', 'dashboard.js')
    i = dash.index('// LW Oct 2026 - a recovery plan can be failed over guest by guest')
    parts = [dash[i:dash.index('// NS 2026-06-05', i)]]
    i = dash.index('// LW Oct 2026 - emergency failover and failback of single guests')
    parts.append(dash[i:dash.index('// readiness check with modal', i)])
    for needle, n in (('data-sr-action="emergency"', 2), ('<td className="py-2" data-sr-guest-location', 1),
                      ("<td className=\"py-2\">{vm.failed_over", 3), ('{r.skipped ? <span', 1),
                      ('{r.skipped ? (r.reason', 1),
                      ('{guestPick && canFailover', 4), ('plan.failed_over_count > 0', 1),
                      ('<SrFailoverBadge plan={pd}', 1)):
        parts.append(_lines(dash, needle, n))
    return '\n'.join(parts)


# --- source --------------------------------------------------------------------------------

@pytest.mark.parametrize('key', KEYS)
def test_every_new_string_is_in_every_language_once(key):
    found = len(re.findall(rf'^\s*{key}:', _read('web', 'src', 'translations.js'), re.M))
    assert found == 9, f'{key} is in {found} of 9 language blocks'


def test_the_new_keys_sit_with_the_site_recovery_strings():
    tr = _read('web', 'src', 'translations.js').split('\n')
    anchors = [i for i, line in enumerate(tr) if re.match(r'^\s+confirmEmergency:', line)]
    assert len(anchors) == 9
    for i in anchors:
        assert [re.match(r'^\s+(\w+):', tr[i + 1 + n]).group(1) for n in range(len(KEYS))] == KEYS


def test_every_new_key_is_used():
    dash = _read('web', 'src', 'dashboard.js')
    used = set(re.findall(r"t\('(sr(?:Guest|Replication|Failover|Pick|Confirm|Skip)[A-Za-z]*)'\)", dash))
    assert used == set(KEYS), (sorted(used - set(KEYS)), sorted(set(KEYS) - used))


def test_placeholders_survive_translation():
    tr = _read('web', 'src', 'translations.js')
    for key, phs in PLACEHOLDERS.items():
        values = re.findall(rf'^\s*{key}: ["\'](.*)["\'],$', tr, re.M)
        assert len(values) == 9 and all(all(p in v for p in phs) for v in values), (key, values)


def test_no_em_dash_in_what_this_change_added():
    block = _block()
    assert '\u2014' not in block and '\u2013' not in block
    tr = _read('web', 'src', 'translations.js')
    for key in KEYS:
        for v in re.findall(rf'^\s*{key}: (.*),$', tr, re.M):
            assert '\u2014' not in v and '\u2013' not in v, (key, v)


def test_the_icons_exist():
    have = set(re.findall(r'^\s{12}([A-Z][A-Za-z0-9]*):', _read('web', 'src', 'icons.js'), re.M))
    used = set(re.findall(r'Icons\.([A-Za-z]+)', _block()))
    assert used and used <= have, sorted(used - have)


def test_every_class_is_in_the_static_tailwind_build():
    shell = '\n'.join(line for line in _read('web', 'index.html.original').split('\n')
                      if 'data-corp-theme="light"' not in line)
    css = _read('static', 'css', 'tailwind.min.css') + shell
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    missing = sorted(n for n in _classes(_block()) if n not in have)
    assert not missing, f'not in static/css/tailwind.min.css: {missing}'


def test_the_bundle_was_rebuilt():
    built = _read('web', 'index.html')
    for needle in ('function SrGuestPicker(', 'function SrFailoverBadge(', 'function SrGuestPlace(',
                   'data-sr-pick-start', 'srPickStartEmergency', 'srReplicationHeld'):
        assert needle in built, needle


# --- runtime -------------------------------------------------------------------------------

REMOTE = dict(CLUSTER, id='c2', name='Remote', display_name='Remote', host='10.0.0.2')


def _vm(vmid, name, failed_over='', group=0):
    return {'id': f'v{vmid}', 'vmid': vmid, 'vm_name': name, 'vm_type': 'qemu', 'boot_group': group,
            'boot_delay': 30, 'failed_over': failed_over,
            'failed_over_at': '2026-10-07T08:00:00' if failed_over else '',
            'last_replication': '2026-10-07T07:00:00'}


def _plan(vms, status='completed'):
    moved = sum(1 for v in vms if v['failed_over'])
    state = 'none' if not moved else ('all' if moved == len(vms) else 'partial')
    return {'id': 'p1', 'name': 'DR-Plan-One', 'source_cluster': 'c1', 'target_cluster': 'c2', 'status': status,
            'vms': vms, 'vm_count': len(vms), 'failed_over_count': moved, 'failover_state': state,
            'network_mappings': {}, 'storage_mappings': {}, 'auto_failover': False}


PARTIAL = _plan([_vm(100, 'web01', 'emergency'), _vm(101, 'db01'), _vm(102, 'app01', group=1)])
EVENT = {'id': 'ev1', 'plan_id': 'p1', 'event_type': 'emergency', 'status': 'completed',
         'started_at': '2026-10-07T08:00:00', 'completed_at': '2026-10-07T08:01:00', 'triggered_by': 'system',
         'details': {'100': {'success': True, 'skipped': True, 'error': '', 'vm_name': 'web01',
                             'reason': 'failed over already'},
                     '101': {'success': True, 'error': '', 'vm_name': 'db01'}}}


def _open(browser, layout='modern', role='active', language='en', plan=PARTIAL):
    from pegaprox.utils.rbac import get_user_permissions
    perms = sorted(get_user_permissions({'username': 'admin', 'role': 'admin'}))
    listed = {k: v for k, v in plan.items() if k != 'vms'}
    server = _FakeServer(role=role, layout=layout, language=language, clusters=[CLUSTER, REMOTE], resources=[VM],
                         permissions=perms,
                         extra={('GET', '/api/site-recovery/plans'): (200, [listed]),
                                ('GET', '/api/site-recovery/plans/p1'): (200, plan),
                                ('GET', '/api/site-recovery/plans/p1/events'): (200, [EVENT]),
                                ('GET', '/api/cross-cluster-replications'): (200, []),
                                ('POST', '/api/site-recovery/plans/p1/emergency'):
                                    (200, {'message': 'Emergency failover started', 'status': 'running'}),
                                ('POST', '/api/site-recovery/plans/p1/failback'):
                                    (200, {'message': 'Failback started', 'status': 'running'}),
                                ('POST', '/api/sse/token'): (200, {})})
    app = _App(browser, server)
    app.dialogs = []
    app.answer = True

    def on_dialog(d):
        app.dialogs.append(d.message)
        d.accept() if app.answer else d.dismiss()
    app.page.on('dialog', on_dialog)
    return app


@pytest.fixture
def open_app(browser):
    apps = []

    def _go(**kw):
        app = _open(browser, **kw)
        apps.append(app)
        return app
    yield _go
    for app in apps:
        app.ctx.close()


def _to_plan(app, layout):
    page = app.page
    if layout == 'cloud':
        page.locator('.cloud-nav-item', has_text='Site Recovery').first.click()
    else:
        page.get_by_text('Testi').first.click()
        page.locator('button', has_text='Site Recovery').first.click()
    card = page.locator('div.cursor-pointer', has_text='DR-Plan-One').first
    card.wait_for(timeout=5000)
    badge = card.locator('[data-sr-failover-state]')
    app.card_badge = badge.inner_text() if badge.count() else None
    card.click()
    page.locator('h2', has_text='DR-Plan-One').wait_for(timeout=5000)


def _snap(app, name):
    if SHOTS:
        os.makedirs(SHOTS, exist_ok=True)
        app.page.screenshot(path=os.path.join(SHOTS, name), full_page=False)


def _posts(app, action):
    return app.server.bodies.get(f'/api/site-recovery/plans/p1/{action}', [])


@pytest.mark.parametrize('layout', ['modern', 'corporate', 'cloud'])
def test_runtime_an_emergency_failover_of_one_guest(open_app, layout):
    app = open_app(layout=layout)
    page = app.page
    _to_plan(app, layout)
    assert app.card_badge == 'Partially failed over: 1 of 3'
    badge = page.locator('h2', has_text='DR-Plan-One').locator('xpath=..').locator('[data-sr-failover-state="partial"]')
    assert badge.inner_text() == 'Partially failed over: 1 of 3'

    page.locator('[data-sr-action="emergency"]').click()
    picker = page.locator('[data-sr-pick="emergency"]')
    picker.wait_for(timeout=5000)
    assert 'The others stay at the source and keep replicating.' in picker.inner_text()
    # the guest failed over already is listed, not offered
    assert picker.locator('[data-sr-pick-row="100"] input').is_disabled()
    assert 'Failed over' in picker.locator('[data-sr-pick-row="100"]').inner_text()
    assert picker.locator('[data-sr-pick-row="101"] input').is_checked()
    assert picker.locator('[data-sr-pick-row="102"] input').is_checked()
    assert picker.locator('[data-sr-pick-count]').inner_text() == '2 of 2 selected'
    picker.locator('[data-sr-pick-row="102"]').click()
    assert not picker.locator('[data-sr-pick-row="102"] input').is_checked()
    start = picker.locator('[data-sr-pick-start]')
    assert start.inner_text() == 'Start emergency failover (1)'
    _snap(app, f'sr-pick-emergency-{layout}.png')

    # the confirmation it always had; turned down, nothing is sent and the picker stays
    app.answer = False
    start.click()
    page.wait_for_timeout(300)
    assert app.dialogs == ['Start emergency failover? Source VMs will NOT be shut down.']
    assert _posts(app, 'emergency') == [] and picker.is_visible()
    app.answer = True
    start.click()
    page.wait_for_function('() => !document.querySelector(\'[data-sr-pick]\')', timeout=5000)
    assert _posts(app, 'emergency') == [{'vmids': [101]}]
    assert not app.errors, app.errors


def test_runtime_every_guest_ticked_sends_the_whole_plan(open_app):
    app = open_app()
    page = app.page
    _to_plan(app, 'modern')
    page.locator('[data-sr-action="emergency"]').click()
    picker = page.locator('[data-sr-pick="emergency"]')
    # untick everything, the start button goes grey; tick it all again
    picker.locator('[data-sr-pick-all]').click()
    assert picker.locator('[data-sr-pick-count]').inner_text() == '0 of 2 selected'
    assert picker.locator('[data-sr-pick-start]').is_disabled()
    picker.locator('[data-sr-pick-all]').click()
    picker.locator('[data-sr-pick-start]').click()
    page.wait_for_function('() => !document.querySelector(\'[data-sr-pick]\')', timeout=5000)
    # no list: the route takes the guests still at the source, as before
    assert _posts(app, 'emergency') == [{}]
    assert not app.errors, app.errors


def test_runtime_the_search_narrows_the_list_and_select_all_follows_it(open_app):
    app = open_app()
    page = app.page
    _to_plan(app, 'modern')
    page.locator('[data-sr-action="emergency"]').click()
    picker = page.locator('[data-sr-pick="emergency"]')
    picker.locator('[data-sr-pick-all]').click()
    picker.locator('input[placeholder="Search"]').fill('app')
    assert picker.locator('[data-sr-pick-row]').count() == 1
    picker.locator('[data-sr-pick-all]').click()
    assert picker.locator('[data-sr-pick-count]').inner_text() == '1 of 2 selected'
    picker.locator('[data-sr-pick-start]').click()
    page.wait_for_function('() => !document.querySelector(\'[data-sr-pick]\')', timeout=5000)
    assert _posts(app, 'emergency') == [{'vmids': [102]}]
    assert not app.errors, app.errors


def test_runtime_a_long_plan_renders_a_page_of_its_guests(open_app):
    many = _plan([_vm(1000 + i, f'g{i}') for i in range(450)], status='ready')
    app = open_app(plan=many)
    page = app.page
    _to_plan(app, 'modern')
    page.locator('[data-sr-action="emergency"]').click()
    picker = page.locator('[data-sr-pick="emergency"]')
    assert picker.locator('[data-sr-pick-row]').count() == 200
    assert picker.locator('[data-sr-pick-more]').inner_text() == '250 more - narrow the search'
    assert picker.locator('[data-sr-pick-count]').inner_text() == '450 of 450 selected'
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_failback_of_the_failed_over_guest(open_app, layout):
    app = open_app(layout=layout)
    page = app.page
    _to_plan(app, layout)
    page.locator('[data-sr-action="failback"]').click()
    picker = page.locator('[data-sr-pick="failback"]')
    picker.wait_for(timeout=5000)
    assert picker.locator('[data-sr-pick-row="100"] input').is_checked()
    assert picker.locator('[data-sr-pick-row="101"] input').is_disabled()
    assert picker.locator('[data-sr-pick-count]').inner_text() == '1 of 1 selected'
    assert picker.locator('[data-sr-pick-start]').inner_text() == 'Start failback (1)'
    picker.locator('[data-sr-pick-start]').click()
    page.wait_for_function('() => !document.querySelector(\'[data-sr-pick]\')', timeout=5000)
    assert app.dialogs == ['Migrate the selected guests back to the source cluster?']
    assert _posts(app, 'failback') == [{}]
    assert not app.errors, app.errors


def test_runtime_no_failback_button_while_every_guest_is_at_the_source(open_app):
    home = _plan([_vm(100, 'web01'), _vm(101, 'db01')])
    app = open_app(plan=home)
    page = app.page
    _to_plan(app, 'modern')
    assert app.card_badge is None
    assert page.locator('[data-sr-action="emergency"]').is_enabled()
    assert page.locator('[data-sr-action="failback"]').count() == 0
    assert page.locator('[data-sr-failover-state]').count() == 0
    assert not app.errors, app.errors


def test_runtime_a_plan_failed_over_whole_offers_failback_only(open_app):
    gone = _plan([_vm(100, 'web01', 'planned'), _vm(101, 'db01', 'emergency')])
    app = open_app(plan=gone)
    page = app.page
    _to_plan(app, 'modern')
    assert app.card_badge == 'All guests failed over'
    assert page.locator('[data-sr-action="emergency"]').is_disabled()
    assert page.locator('[data-sr-action="failback"]').is_enabled()
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_the_guests_tab_says_where_each_guest_is(open_app, layout):
    app = open_app(layout=layout)
    page = app.page
    _to_plan(app, layout)
    page.locator('button', has_text='Protected VMs').first.click()
    page.locator('[data-sr-guest-location="100"]').wait_for(timeout=5000)
    assert page.locator('[data-sr-guest-location="100"]').inner_text() == 'Failed over'
    assert page.locator('[data-sr-guest-location="101"]').inner_text() == 'At source'
    row = page.locator('tr', has=page.locator('[data-sr-guest-location="100"]'))
    assert 'Paused until failback' in row.inner_text()
    _snap(app, f'sr-guest-location-{layout}.png')
    assert not app.errors, app.errors


def test_runtime_a_run_lists_the_guests_it_passed_over(open_app):
    app = open_app()
    page = app.page
    _to_plan(app, 'modern')
    page.locator('button', has_text='Failover History').first.click()
    page.locator('div.cursor-pointer', has_text='emergency').first.click()
    skipped = page.locator('[data-sr-result="100"]')
    skipped.wait_for(timeout=5000)
    assert 'Skipped' in skipped.inner_text() and 'failed over already' in skipped.inner_text()
    assert 'OK' in page.locator('[data-sr-result="101"]').inner_text()
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate', 'cloud'])
def test_runtime_a_standby_shows_the_state_and_offers_neither_action(open_app, layout):
    app = open_app(layout=layout, role='standby')
    page = app.page
    _to_plan(app, layout)
    assert app.card_badge == 'Partially failed over: 1 of 3'
    assert page.locator('[data-sr-failover-state="partial"]').count() >= 1
    assert page.locator('[data-sr-action]').count() == 0
    assert page.locator('[data-sr-pick]').count() == 0
    assert not [c for c in app.server.calls if c[0] == 'POST' and '/site-recovery/' in c[1]]
    assert not app.errors, app.errors


def test_runtime_in_german(open_app):
    app = open_app(language='de')
    page = app.page
    _to_plan(app, 'modern')
    assert app.card_badge == 'Teilweise umgeschaltet: 1 von 3'
    page.locator('[data-sr-action="emergency"]').click()
    picker = page.locator('[data-sr-pick="emergency"]')
    assert picker.locator('[data-sr-pick-count]').inner_text() == '2 von 2 ausgewählt'
    assert picker.locator('[data-sr-pick-start]').inner_text() == 'Notfall-Failover starten (2)'
    _snap(app, 'sr-pick-emergency-de.png')
    assert not app.errors, app.errors
