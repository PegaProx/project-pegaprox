"""The cluster settings show the two plb_pin_ switches of #811 and the guests off their pin.

proxlb_pins_strict decides whether a pin also stops a node drain, proxlb_pins_auto_migrate
whether the balance check moves an off-pin guest back on its own. Both sit under the ProxLB
tags switch and only show while it is on, on a Proxmox VE cluster. The list beside them reads
/proxlb-pins/violations; "Move back now" is the reconcile route with force, offered only where
the server says the caller may. Re-configure keeps both switches.
Runtime tests drive the built bundle in headless Chromium against the fake server of
tests/test_ha_ui.py; they skip where Playwright is not installed.
LW Oct 2026
"""
import os
import re
import time

import pytest

from test_ha_ui import (CLUSTER, LANGS, SSE_TOKEN, VM, _App, _FakeServer, _blocks, _classes,  # noqa: F401
                        _toasts, browser)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

KEYS = ['proxlbPinsStrict', 'proxlbPinsStrictDesc', 'proxlbPinsAutoMigrate', 'proxlbPinsAutoMigrateDesc',
        'proxlbPinsHeldBack', 'proxlbPinOffTitle', 'proxlbPinOffNone', 'proxlbPinOffWhere',
        'proxlbPinWhyDrift', 'proxlbPinWhyUnavailable', 'proxlbPinWhyIgnored', 'proxlbPinWhyStopped',
        'proxlbPinUnresolved', 'proxlbPinMoveBack', 'proxlbPinMoving', 'proxlbPinMoveDone',
        'proxlbPinMoveFailed', 'proxlbPinDryRun', 'proxlbPinLoadError', 'proxlbPinShowAll']


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def _component():
    src = _read('web', 'src', 'dashboard.js')
    start = src.index('// LW Oct 2026 (#811) - the guests that sit off')
    return src[start:src.index('// NS May 2026', start)]


def _settings_block():
    src = _read('web', 'src', 'dashboard.js')
    start = src.index('{/* LW Oct 2026 (#811) - what a pin does in a node drain')
    return src[start:src.index('</>)}', start)]


# -- source -------------------------------------------------------------------------------------

def test_every_new_key_exists_once_per_language():
    for lang, block in _blocks().items():
        for key in KEYS:
            assert len(re.findall(r'^ +%s:' % key, block, re.M)) == 1, (lang, key)


def test_every_new_key_is_used_and_nothing_else_is_new():
    used = set(re.findall(r"'(proxlbPins?[A-Z]\w*)'", _component() + _settings_block()))
    assert used == set(KEYS)


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
    for text in [_component(), _settings_block()] + lines:
        assert '\u2014' not in text and '\u2013' not in text


def test_every_class_is_in_the_static_tailwind_build():
    css = _read('static', 'css', 'tailwind.min.css') + _read('web', 'index.html.original')
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    names = _classes(_component()) | _classes(_settings_block())
    missing = sorted(n for n in names if n not in have)
    assert not missing, f'not in static/css/tailwind.min.css: {missing}'


def test_the_icons_exist():
    icons = _read('web', 'src', 'icons.js')
    used = set(re.findall(r'Icons\.(\w+)', _component() + _settings_block()))
    assert used
    for name in used:
        assert re.search(r'^ +%s: \(' % name, icons, re.M), name


def test_the_switches_are_locked_on_a_standby_and_send_a_real_boolean():
    block = _settings_block()
    assert "<fieldset disabled={haReadOnly}" in block and "data-ha-locked={haReadOnly ? '' : undefined}" in block
    # a <button>, so the fieldset disables it (Toggle is a div with an onClick)
    assert 'type="button" role="switch"' in block
    assert 'updateConfig(field, !selectedCluster[field])' in block
    assert "(selectedCluster.cluster_type || 'proxmox') === 'proxmox'" in block


def test_reconfigure_carries_the_pin_switches():
    src = _read('web', 'src', 'create_modals.js')
    assert 'proxlb_pins_auto_migrate: rc.proxlb_pins_auto_migrate === true' in src
    assert 'proxlb_pins_strict: rc.proxlb_pins_strict === true' in src


def test_the_bundle_carries_it():
    bundle = _read('web', 'index.html')
    for needle in ('function ProxlbPinGuests(', '/proxlb-pins/reconcile', 'data-proxlb-pin-switches',
                   'proxlb_pins_strict:rc.proxlb_pins_strict===true'):
        assert needle in bundle, needle


# -- runtime ------------------------------------------------------------------------------------

VIOLATIONS = '/api/clusters/c1/proxlb-pins/violations'
RECONCILE = '/api/clusters/c1/proxlb-pins/reconcile'
PIN_CLUSTER = dict(CLUSTER, proxlb_tags_enabled=True, proxlb_pins_strict=False, proxlb_pins_auto_migrate=False,
                   auto_migrate=True, dry_run=False, migration_threshold=20, migration_tolerance=10,
                   check_interval=300)
TYPO = dict(VM, vmid=104, name='typo01')


def _row(vmid, name, reason='drift', status='running', ignored=False, node='pve2', pinned=('pve1',)):
    return {'vmid': vmid, 'name': name, 'type': 'qemu', 'status': status, 'node': node,
            'pinned_nodes': list(pinned), 'reason': reason, 'ignored': ignored}


ROWS = [_row(100, 'web01'), _row(101, 'db01', reason='unavailable', pinned=('pve3',)),
        _row(102, 'cold01', status='stopped'), _row(103, 'keep01', ignored=True)]
UNRESOLVED = [{'vmid': 104, 'node': 'pve9'}]


def _answer(rows=ROWS, unresolved=UNRESOLVED, can=True, enabled=True):
    return {'enabled': enabled, 'auto_migrate': False, 'can_reconcile': can,
            'violations': rows, 'unresolved': unresolved}


class _PinServer(_FakeServer):
    """A reconcile moves web01 back: the next read of the list no longer has it."""

    def handle(self, route):
        req = route.request
        path = re.sub(r'^https?://[^/]+', '', req.url).split('?')[0]
        if req.method == 'POST' and path == RECONCILE and ('POST', RECONCILE) in self.extra:
            _, before = self.extra[('GET', VIOLATIONS)]
            self.extra[('GET', VIOLATIONS)] = (200, dict(before, violations=before['violations'][1:]))
        return super().handle(route)


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(cluster=None, answer=None, reconcile=True, **kw):
        extra = dict(SSE_TOKEN)
        extra[('GET', VIOLATIONS)] = (200, answer if answer is not None else _answer())
        extra[('PATCH', '/api/clusters/c1/config')] = (200, {'message': 'ok'})
        if reconcile:
            extra[('POST', RECONCILE)] = (200, {'violations': ROWS, 'auto_migrate': True,
                                                'migrated': [dict(ROWS[0], target='pve1')],
                                                'failed': [], 'deferred': []})
        extra.update(kw.pop('extra', {}))
        kw.setdefault('role', 'standalone')
        app = _App(browser, _PinServer(clusters=[cluster or PIN_CLUSTER], resources=[VM, TYPO],
                                       extra=extra, **kw))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _wait_for(page, fn, seconds=5):
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
    page.get_by_text('Automatic Migration' if tab == 'Settings' else 'Testi').first.wait_for(timeout=5000)
    page.wait_for_timeout(300)
    return page


def _reads(app):
    return app.server.calls.count(('GET', VIOLATIONS))


def _switch(page, field):
    return page.locator(f'[data-pin-switch="{field}"]')


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_the_switches_show_under_the_tags_and_save(open_app, layout):
    app = open_app(layout=layout)
    page = _open_settings(app)
    page.locator('[data-proxlb-pin-switches]').wait_for(timeout=5000)
    for field in ('proxlb_pins_strict', 'proxlb_pins_auto_migrate'):
        assert _switch(page, field).get_attribute('aria-checked') == 'false'
        assert _switch(page, field).is_enabled()
    text = page.locator('[data-proxlb-pin-switches]').inner_text()
    assert 'Pins also bind node drains' in text and 'Move guests back to their pinned node' in text
    assert 'Off: a node drain moves a pinned guest to another of its pinned nodes' in text
    assert 'On: the guest stays on the drained node and the maintenance reports it as failed.' in text
    assert 'stays there and is only listed below' in text
    # the switch is not locked off the standby
    assert page.locator('fieldset[data-ha-locked]').count() == 0

    _switch(page, 'proxlb_pins_strict').click()
    assert _wait_for(page, lambda: app.server.bodies.get('/api/clusters/c1/config'))
    assert app.server.bodies['/api/clusters/c1/config'][-1] == {'proxlb_pins_strict': True}
    assert _switch(page, 'proxlb_pins_strict').get_attribute('aria-checked') == 'true'
    # the label switches it as well
    page.locator('label[for="pin-switch-proxlb_pins_auto_migrate"]').click()
    assert _wait_for(page, lambda: len(app.server.bodies['/api/clusters/c1/config']) == 2)
    assert app.server.bodies['/api/clusters/c1/config'][-1] == {'proxlb_pins_auto_migrate': True}
    assert not app.errors, app.errors


def test_runtime_the_guests_off_their_pin_with_the_reason(open_app):
    app = open_app(layout='modern')
    page = _open_settings(app)
    page.locator('[data-pin-row="100"]').wait_for(timeout=5000)
    assert page.locator('[data-pin-count]').inner_text() == '4'
    why = {r: page.locator(f'[data-pin-row="{r}"]').inner_text() for r in (100, 101, 102, 103)}
    assert 'web01 (100)' in why[100] and 'on pve2, pinned to pve1' in why[100]
    assert 'can go back, a pinned node is available' in why[100]
    assert 'no pinned node available (offline, in maintenance or excluded)' in why[101]
    assert 'on pve2, pinned to pve3' in why[101]
    assert 'stopped, only running guests are moved back' in why[102]
    assert 'also tagged plb_ignore, stays where it is' in why[103]
    # a tag naming no node: the name comes from the guest list, the page has no other
    typo = page.locator('[data-pin-unresolved="104"]').inner_text()
    assert 'typo01 (104)' in typo and 'plb_pin_pve9' in typo and 'names no node of this cluster' in typo
    # read once on opening, not polled
    page.wait_for_timeout(2500)
    assert _reads(app) == 1
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_move_back_now_reconciles_and_reads_the_list_again(open_app, layout):
    app = open_app(layout=layout)
    page = _open_settings(app)
    button = page.locator('[data-pin-move-back]')
    button.wait_for(timeout=5000)
    assert button.inner_text().strip() == 'Move back now'
    button.click()
    assert _wait_for(page, lambda: ('POST', RECONCILE) in app.server.calls)
    assert app.server.bodies[RECONCILE] == [{'force': True}]
    assert _wait_for(page, lambda: _reads(app) == 2)
    page.locator('[data-pin-row="100"]').wait_for(state='detached', timeout=5000)
    assert page.locator('[data-pin-count]').inner_text() == '3'
    assert _wait_for(page, lambda: any('1 moved back, 0 failed, 0 postponed' in t for t in _toasts(page)))
    # what is left is nothing the reconcile moves: no pinned node, stopped, plb_ignore
    assert page.locator('[data-pin-move-back]').count() == 0
    assert not app.errors, app.errors


def test_runtime_a_failed_return_names_the_guest(open_app):
    app = open_app(layout='modern', reconcile=False, extra={('POST', RECONCILE): (200, {
        'violations': ROWS, 'auto_migrate': True, 'migrated': [], 'deferred': [ROWS[0]],
        'failed': [dict(ROWS[0], error='migration failed')]})})
    page = _open_settings(app)
    page.locator('[data-pin-move-back]').click()
    page.locator('[data-pin-last-failed]').wait_for(timeout=5000)
    assert page.locator('[data-pin-last-failed]').inner_text().strip() == 'web01 (100): migration failed'
    assert _wait_for(page, lambda: any('0 moved back, 1 failed, 1 postponed' in t for t in _toasts(page)))
    assert not app.errors, app.errors


@pytest.mark.parametrize('who', ['server-says-no', 'no-vm-migrate'])
def test_runtime_no_move_back_for_who_may_not(open_app, who):
    if who == 'server-says-no':
        # an admin of the browser's permission list the server still turns away (a capped one)
        app = open_app(layout='modern', answer=_answer(can=False))
    else:
        app = open_app(layout='modern', admin=False, permissions=['cluster.view'])
    page = _open_settings(app)
    page.locator('[data-pin-row="100"]').wait_for(timeout=5000)
    assert page.locator('[data-pin-move-back]').count() == 0
    # without cluster.config the switches show what is set and change nothing
    if who == 'no-vm-migrate':
        assert not _switch(page, 'proxlb_pins_strict').is_enabled()
    assert not app.errors, app.errors


def test_runtime_dry_run_keeps_the_button_but_says_why_it_does_nothing(open_app):
    app = open_app(layout='modern', cluster=dict(PIN_CLUSTER, dry_run=True))
    page = _open_settings(app)
    button = page.locator('[data-pin-move-back]')
    button.wait_for(timeout=5000)
    assert not button.is_enabled()
    page.get_by_text('Dry Run is on, so Move back now changes nothing.').wait_for(timeout=3000)
    assert not app.errors, app.errors


@pytest.mark.parametrize('auto_migrate,dry_run,held', [(False, False, True), (True, True, True), (True, False, False)])
def test_runtime_the_return_says_when_it_is_held_back(open_app, auto_migrate, dry_run, held):
    app = open_app(layout='modern', cluster=dict(PIN_CLUSTER, proxlb_pins_auto_migrate=True,
                                                  auto_migrate=auto_migrate, dry_run=dry_run))
    page = _open_settings(app)
    page.locator('[data-proxlb-pin-switches]').wait_for(timeout=5000)
    assert _switch(page, 'proxlb_pins_auto_migrate').get_attribute('aria-checked') == 'true'
    assert (page.locator('[data-pin-held-back]').count() == 1) == held
    assert not app.errors, app.errors


@pytest.mark.parametrize('cluster', [dict(PIN_CLUSTER, proxlb_tags_enabled=False),
                                     dict(PIN_CLUSTER, cluster_type='xcpng')], ids=['tags-off', 'xcpng'])
def test_runtime_nothing_while_the_tags_are_off_and_nothing_on_xcpng(open_app, cluster):
    app = open_app(layout='modern', cluster=cluster)
    page = _open_settings(app)
    page.wait_for_timeout(800)
    assert page.locator('[data-proxlb-pin-switches]').count() == 0
    assert page.locator('[data-proxlb-pin-guests]').count() == 0
    assert _reads(app) == 0
    assert not app.errors, app.errors


def test_runtime_switching_the_tags_on_brings_the_pins_and_reads_the_list(open_app):
    app = open_app(layout='modern', cluster=dict(PIN_CLUSTER, proxlb_tags_enabled=False))
    page = _open_settings(app)
    page.locator('label', has_text=re.compile(r'^ProxLB VM Tags$')).locator('.toggle-switch').click()
    page.locator('[data-proxlb-pin-switches]').wait_for(timeout=5000)
    page.locator('[data-pin-row="100"]').wait_for(timeout=5000)
    assert _reads(app) == 1
    assert not app.errors, app.errors


def test_runtime_a_list_the_save_has_not_reached_yet_is_read_again(open_app):
    # the tags were just switched on, the server answers before the save arrived
    app = open_app(layout='modern', answer=_answer(enabled=False, rows=[], unresolved=[]))
    page = _open_settings(app)
    assert _wait_for(page, lambda: _reads(app) == 1)
    app.server.extra[('GET', VIOLATIONS)] = (200, _answer())
    assert _wait_for(page, lambda: _reads(app) == 2, seconds=4)
    page.locator('[data-pin-row="100"]').wait_for(timeout=3000)
    page.wait_for_timeout(2000)
    assert _reads(app) == 2
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_a_standby_shows_the_switches_locked_and_moves_nothing(open_app, layout):
    app = open_app(layout=layout, role='standby', reconcile=False)
    page = _open_settings(app)
    page.locator('[data-proxlb-pin-switches]').wait_for(timeout=5000)
    assert page.locator('fieldset[data-ha-locked][data-proxlb-pin-switches]').count() == 1
    assert page.evaluate('() => document.querySelector("[data-proxlb-pin-switches]").disabled')
    assert not _switch(page, 'proxlb_pins_strict').is_enabled()
    _switch(page, 'proxlb_pins_strict').click(force=True)
    page.wait_for_timeout(900)
    assert '/api/clusters/c1/config' not in app.server.bodies
    # the list reads, the return is the active's
    page.locator('[data-pin-row="100"]').wait_for(timeout=5000)
    assert page.locator('[data-pin-move-back]').count() == 0
    assert not app.errors, app.errors


def test_runtime_a_long_list_shows_the_first_rows_until_asked(open_app):
    rows = [_row(1000 + i, f'g{i}') for i in range(60)]
    app = open_app(layout='modern', answer=_answer(rows=rows, unresolved=[]))
    page = _open_settings(app)
    page.locator('[data-pin-row="1000"]').wait_for(timeout=5000)
    assert page.locator('[data-pin-row]').count() == 50
    page.get_by_role('button', name='Show all 60').click()
    assert page.locator('[data-pin-row]').count() == 60
    assert not app.errors, app.errors


def test_runtime_german(open_app):
    app = open_app(layout='modern', language='de')
    page = app.page
    page.get_by_text('Testi').first.click()
    page.get_by_role('button', name='Einstellungen', exact=True).first.click()
    page.locator('[data-proxlb-pin-switches]').wait_for(timeout=5000)
    text = page.locator('[data-proxlb-pin-switches]').inner_text()
    assert 'Pins gelten auch beim Node-Drain' in text and 'Gäste auf ihren Pin-Node zurückholen' in text
    page.get_by_text('Jetzt zurückholen').wait_for(timeout=5000)
    assert 'proxlbPin' not in page.locator('[data-proxlb-pin-guests]').inner_text()
    assert not app.errors, app.errors


# -- re-configure ------------------------------------------------------------------------------

EXPORT = {'name': 'Testi', 'host': '10.0.0.1', 'user': 'root@pam', 'ssl_verification': False,
          'migration_threshold': 20, 'migration_tolerance': 10, 'check_interval': 300, 'auto_migrate': True,
          'balance_containers': False, 'balance_local_disks': False, 'proxlb_tags_enabled': True,
          'proxlb_pins_auto_migrate': True, 'proxlb_pins_strict': True, 'dry_run': False,
          'cluster_type': 'proxmox', 'vnc_tunnel': False, 'ssh_disabled': False}


def test_runtime_reconfigure_keeps_the_pin_switches(open_app):
    """The dialog sends the cluster's settings with the new connection, the server builds the
    new manager from that body alone: a switch it leaves out is switched off (#762)."""
    app = open_app(layout='modern', extra={
        ('POST', '/api/auth/verify-password'): (200, {'success': True}),
        ('GET', '/api/clusters/c1/config/export'): (200, EXPORT),
        ('POST', '/api/clusters/c1/reconfigure'): (200, {'success': True}),
    })
    page = app.page
    page.locator('button[title="Re-configure Cluster"]').first.click()
    page.get_by_placeholder('Your Password').fill('correct horse')
    page.get_by_placeholder('Your Password').press('Enter')
    secret = page.locator('input[type="password"][placeholder="Password"]')
    secret.wait_for(timeout=5000)
    secret.fill('new-secret')
    secret.press('Enter')
    assert _wait_for(page, lambda: app.server.bodies.get('/api/clusters/c1/reconfigure'))
    body = app.server.bodies['/api/clusters/c1/reconfigure'][0]
    assert body['proxlb_pins_strict'] is True and body['proxlb_pins_auto_migrate'] is True
    assert body['proxlb_tags_enabled'] is True
    assert not app.errors, app.errors
