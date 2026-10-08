"""ZFS pools in the web UI: the pool view next to the node's ZFS list, and the alert rule.

Modern opens a pool from its card in the Disks tab of the node dialog, Corporate from
its row under Configure > ZFS, as a panel below the table. The answers of the fake
server are what the route builds (pegaprox/utils/zpool.py) from what Proxmox answers
(tests/test_zfs_pool_health.py). Source checks read web/src and the bundle; the runtime
tests drive the built bundle in headless Chromium against the fake server of
tests/test_ha_ui.py, in both layouts, as an active instance and as a standby, in English
and German. They skip where Playwright is not installed.
LW Oct 2026
"""
import os
import re

import pytest

from pegaprox.utils import zpool
from test_ha_ui import (CLUSTER, NODE_METRICS, NODE_READS, SSE_TOKEN, VM, _App, _FakeServer, _classes,  # noqa: F401
                        _wait_for_call, browser)
from test_zfs_pool_health import CKSUM, DEGRADED, _listed, _status

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHOTS = os.environ.get('PEGAPROX_SHOTS', '')

KEYS = ['zfsPoolDetails', 'zfsPoolUnreadable', 'zfsPoolAction', 'zfsDataErrors', 'zfsNoDataErrors',
        'zfsLastScan', 'zfsScrub', 'zfsResilver', 'zfsScanNone', 'zfsScanFinished', 'zfsScanResult',
        'zfsScanRunning', 'zfsScanPaused', 'zfsScanCanceled', 'zfsDevices', 'zfsColState', 'zfsColRead',
        'zfsColWrite', 'zfsColChecksum', 'zfsColNote', 'zfsTruncated', 'zfsProblemDevices',
        'zfsAlertTitle', 'zfsAlertHelp', 'zfsAlertLevel', 'zfsAlertAny', 'zfsAlertStateOnly']


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def _between(src, start, end):
    s = src.index(start)
    return src[s:src.index(end, s)]


def _component():
    return _between(_read('web', 'src', 'node_modals.js'), '// LW Oct 2026 - one ZFS pool in full',
                    '// Node Management Modal Component')


def _modern_card(nm):
    return _between(nm, '{/* ZFS Pools - LW Oct 2026', '{/* APT Repos tab */}')


def _corporate_tab(nm):
    return _between(nm, '{/* LW Oct 2026 - the pools and the pool view only read',
                    '                                </div>\n                            </div>\n                        )}')


def _added_blocks():
    """The pieces this change wrote into code that is older."""
    nm = _read('web', 'src', 'node_modals.js')
    dash = _read('web', 'src', 'dashboard.js')
    return [
        _component(),
        _modern_card(nm),
        _corporate_tab(nm),
        _between(dash, "{alertMetricSel === 'zfs_health' && (", "{alertMetricSel !== 'rolling_update' && ("),
        _between(dash, "if (alert.metric === 'zfs_health')", 'return `${alert.metric?.toUpperCase()}'),
    ]


# --- source --------------------------------------------------------------------------------

@pytest.mark.parametrize('key', KEYS)
def test_every_new_string_is_in_every_language_once(key):
    found = len(re.findall(rf'^\s*{key}:', _read('web', 'src', 'translations.js'), re.M))
    assert found == 9, f'{key} is in {found} of 9 language blocks - the UI would show the key'


def test_every_new_key_is_used_and_nothing_uses_a_missing_one():
    src = _read('web', 'src', 'node_modals.js') + _read('web', 'src', 'dashboard.js')
    used = set(re.findall(r"t\('(zfs(?!Storage)[A-Za-z]*)'\)", src))
    # the scan states go through t(scanSays) from one table
    table = _between(_component(), 'const scanSays = {', '}[scan.state]')
    assert 't(scanSays)' in _component()
    used |= set(re.findall(r"'(zfsScan[A-Za-z]+)'", table))
    assert used == set(KEYS), (sorted(used - set(KEYS)), sorted(set(KEYS) - used))


def test_placeholders_survive_translation():
    tr = _read('web', 'src', 'translations.js')
    wanted = [(k, ('{kind}', '{when}')) for k in ('zfsScanFinished', 'zfsScanRunning', 'zfsScanPaused',
                                                  'zfsScanCanceled')]
    wanted += [('zfsScanResult', ('{repaired}', '{errors}', '{duration}')), ('zfsProblemDevices', ('{n}',))]
    for key, marks in wanted:
        values = re.findall(rf'^\s*{key}: "(.*)",$', tr, re.M)
        assert len(values) == 9 and all(m in v for v in values for m in marks), (key, values)


def test_the_german_block_keeps_its_flag():
    tr = _read('web', 'src', 'translations.js')
    assert tr.index('            de: {') < tr.index('zfsPoolDetails: "Pool-Details"') < tr.index('            en: {')


def test_no_em_dash_in_what_this_change_added():
    for block in _added_blocks():
        assert '\u2014' not in block and '\u2013' not in block, block[:120]
    tr = _read('web', 'src', 'translations.js')
    for key in KEYS:
        for v in re.findall(rf'^\s*{key}: (".*"),$', tr, re.M):
            assert '\u2014' not in v and '\u2013' not in v, (key, v)


def test_the_icons_exist():
    icons = _read('web', 'src', 'icons.js')
    assert re.search(r'HardDrive: \(\{ className, style \} = \{\}\) => \(', icons)
    used = set(re.findall(r'<Icons\.([A-Za-z]+)', ''.join(_added_blocks())))
    assert {'HardDrive', 'Database', 'RefreshCw', 'RotateCw', 'X'} <= used, used
    for name in used:
        assert re.search(rf'^\s*{name}: \(', icons, re.M), name


def test_every_class_is_in_the_static_tailwind_build():
    css = _read('static', 'css', 'tailwind.min.css') + _read('web', 'index.html.original')
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    names = set()
    for block in _added_blocks():
        names |= _classes(block)
        # the class names picked by a condition: 'p-2', `${cell} text-right`, the tone table
        for lit in re.findall(r"'((?:[a-z][a-z0-9:/\-\.\[\]]* ?)+)'", block):
            if re.fullmatch(r'(?:(?:corp-|bg-|text-|p-|px-|py-|mt-|mb-|space-|rounded|font-|border)[^ ]* ?)+', lit):
                names.update(lit.split())
    names -= {'field', 'cell'}
    missing = sorted(n for n in names if n not in have)
    assert not missing, f'not in the static CSS: {missing}'


def test_a_late_answer_stays_with_its_pool():
    comp = _component()
    assert 'let current = true;' in comp and 'return () => { current = false; };' in comp
    assert comp.count('if (!current) return;') == 1 and 'if (current) setView' in comp
    # the view shows an answer only for the pool on screen
    assert "const d = view.key === key ? view.data : null;" in comp


def test_the_pool_views_sit_outside_the_standby_locks():
    """A standby reads the pools like SMART: the views sit outside the locked fieldsets,
    and what creates storage keeps its lock."""
    nm = _read('web', 'src', 'node_modals.js')
    card = _modern_card(nm)
    before = nm[:nm.index('{/* ZFS Pools - LW Oct 2026')]
    # the storage cards' lock closes right before the card
    assert before.rstrip().endswith('</fieldset>')
    assert card.count('<fieldset {...haLock} className="contents">') == 1
    locked = _between(card, '<fieldset {...haLock}', '</fieldset>')
    assert "openDiskModal('zfs')" in locked and "openDiskModal('directory')" in locked
    assert 'data-zfs-open' not in locked and 'fieldset' not in _between(card, '{z.name && (', '</button>')
    corp = nm[:nm.index('{/* LW Oct 2026 - the pools and the pool view only read')]
    assert corp.rstrip().endswith('</fieldset>')
    assert '<fieldset' not in _corporate_tab(nm)


def test_the_corporate_selection_ends_with_the_node():
    nm = _read('web', 'src', 'node_modals.js')
    reset = _between(nm, '// LW: Feb 2026 - reset data and load summary when node changes', 'useEffect(() => {\n                let cancelled')
    assert 'setZfsPool(null)' in reset


def test_the_bundle_was_rebuilt():
    built = _read('web', 'index.html')
    for needle in ('function ZfsPoolDetail(', 'data-zfs-open', 'data-zfs-vdev', 'zfsScanFinished',
                   'React.createElement("option",{value:"zfs_health"}', 'zfsAlertStateOnly'):
        assert needle in built, needle


# --- runtime -------------------------------------------------------------------------------

NODE = '/api/clusters/c1/nodes/pve1'
POOL = NODE + '/disks/zfs/tank'


def _answer(text):
    return dict(zpool.pool_detail(_status(text)), node='pve1')


def _reads(detail=None, code=200, pools=(('tank', 'DEGRADED'), ('rpool', 'ONLINE'))):
    reads = dict(NODE_READS)
    reads[('GET', NODE + '/disks/zfs')] = (200, _listed(*pools))
    reads[('GET', POOL)] = (code, detail if detail is not None else _answer(DEGRADED))
    reads.update(SSE_TOKEN)
    return reads


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(**kw):
        extra = kw.pop('extra', None) or _reads()
        kw.setdefault('role', 'active')
        app = _App(browser, _FakeServer(clusters=[CLUSTER], resources=[VM], metrics=NODE_METRICS, extra=extra, **kw))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _shot(page, name):
    if SHOTS:
        os.makedirs(SHOTS, exist_ok=True)
        page.screenshot(path=os.path.join(SHOTS, name), full_page=False)


def _modern_pool(app, disks='Disks'):
    page = app.page
    page.get_by_text('Testi').first.click()
    page.locator('button[title="Node Configuration"]').first.wait_for(timeout=5000)
    page.locator('button[title="Node Configuration"]').first.click()
    page.locator('button', has_text=disks).last.click()
    page.locator('[data-zfs-open="tank"]').wait_for(timeout=8000)
    page.locator('[data-zfs-open="tank"]').click()
    page.locator('[data-zfs-panel]').wait_for(timeout=5000)
    page.wait_for_timeout(300)
    return page


def _corporate_pool(app):
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.locator('.corp-tree-child', has_text='pve1').first.click()
    page.locator('.corp-tab-strip').last.get_by_text('Configure').click()
    page.locator('.corp-subnav-item', has_text=re.compile(r'^\s*ZFS\s*$')).first.click()
    page.locator('[data-zfs-open="tank"]').wait_for(timeout=8000)
    page.locator('[data-zfs-open="tank"]').click()
    page.locator('[data-zfs-panel]').wait_for(timeout=5000)
    page.wait_for_timeout(300)
    return page


def _vdevs(page):
    return page.eval_on_selector_all('[data-zfs-vdev]', 'rows => rows.map(r => r.getAttribute("data-zfs-vdev"))')


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_a_degraded_pool_shows_its_devices_and_its_scrub(open_app, layout):
    app = open_app(layout=layout)
    page = _modern_pool(app) if layout == 'modern' else _corporate_pool(app)
    panel = page.locator('[data-zfs-panel]')
    assert _vdevs(page) == ['tank', 'mirror-0', '/dev/sdb1', '10485834897452934531']
    gone = page.locator('[data-zfs-vdev="10485834897452934531"]')
    assert gone.locator('[data-zfs-state="UNAVAIL"]').count() == 1
    assert '(was /dev/sdc1)' not in gone.inner_text() and 'was /dev/sdc1' in gone.inner_text()
    assert page.locator('[data-zfs-vdev="/dev/sdb1"] [data-zfs-state="ONLINE"]').count() == 1
    text = panel.inner_text()
    assert '2 device(s) need attention' in text
    assert 'One or more devices could not be opened.' in page.locator('[data-zfs-status]').inner_text()
    assert "Attach the missing device and online it using 'zpool online'." in text
    scan = page.locator('[data-zfs-scan]').inner_text()
    assert 'Last scrub' in scan and 'Scrub finished on Sun Oct 5 00:24:03 2026' in scan
    assert '0B repaired, 0 errors, took 00:00:02' in scan
    assert 'No known data errors' in page.locator('[data-zfs-data-errors]').inner_text()
    assert app.server.calls.count(('GET', POOL)) == 1
    _shot(page, f'{layout}_zfs_pool.png')

    page.locator('[data-zfs-panel] button[title="Refresh"]').click()
    assert _wait_for_call(app, ('GET', POOL)) and app.server.calls.count(('GET', POOL)) >= 1
    deadline = 30
    while app.server.calls.count(('GET', POOL)) < 2 and deadline:
        page.wait_for_timeout(100)
        deadline -= 1
    assert app.server.calls.count(('GET', POOL)) == 2
    if layout == 'corporate':
        row = page.locator('.corp-datagrid tr', has=page.locator('[data-zfs-open="tank"]'))
        assert 'corp-row-selected' in (row.get_attribute('class') or '')
        assert row.locator('.corp-badge-maintenance').inner_text() == 'DEGRADED'
        page.locator('[data-zfs-panel] button[title="Close"]').click()
    else:
        # the backdrop closes it; low on the left, clear of the banner a few seconds in
        page.mouse.click(5, 600)
    page.locator('[data-zfs-panel]').wait_for(state='hidden', timeout=3000)
    assert not [c for c in app.server.calls if c[0] != 'GET' and c[1].startswith(NODE)]
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_error_counts_a_running_scrub_and_data_errors(open_app, layout):
    detail = _answer(CKSUM)
    detail['data_errors'] = detail['errors'] = "3 data errors, use '-v' for a list"
    app = open_app(layout=layout, extra=_reads(detail, pools=(('tank', 'ONLINE'),)))
    page = _modern_pool(app) if layout == 'modern' else _corporate_pool(app)
    cells = page.locator('[data-zfs-vdev="/dev/sdb1"] td')
    assert [cells.nth(i).inner_text().strip() for i in range(2, 5)] == ['0', '0', '12']
    red = cells.nth(4).locator('span').evaluate('e => getComputedStyle(e).color')
    calm = cells.nth(2).locator('span').evaluate('e => getComputedStyle(e).color')
    assert red != calm and red in ('rgb(248, 113, 113)', 'rgb(245, 79, 71)'), (red, calm)
    scan = page.locator('[data-zfs-scan]').inner_text()
    assert 'Scrub in progress since Sun Oct 5 00:24:01 2026' in scan and '22.8%' in scan
    assert "3 data errors, use '-v' for a list" in page.locator('[data-zfs-data-errors]').inner_text()
    assert '1 device(s) need attention' in page.locator('[data-zfs-problems]').inner_text()
    _shot(page, f'{layout}_zfs_errors.png')
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_a_pool_that_cannot_be_read_says_why(open_app, layout):
    refused = _reads({'error': 'Pool tank could not be read on node pve1 (HTTP 500)'}, code=502)
    app = open_app(layout=layout, extra=refused)
    page = _modern_pool(app) if layout == 'modern' else _corporate_pool(app)
    err = page.locator('[data-zfs-error]')
    err.wait_for(timeout=3000)
    assert err.inner_text().strip() == 'The pool could not be read: Pool tank could not be read on node pve1 (HTTP 500)'
    assert page.locator('[data-zfs-vdev]').count() == 0
    assert not [e for e in app.errors if 'status of 502' not in e], app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_a_standby_shows_the_pool_and_changes_nothing(open_app, layout):
    app = open_app(layout=layout, role='standby')
    page = _modern_pool(app) if layout == 'modern' else _corporate_pool(app)
    assert '10485834897452934531' in _vdevs(page)
    assert page.locator('[data-zfs-panel] button[title="Refresh"]').is_enabled()
    if layout == 'modern':
        # what creates storage stays locked next to it
        page.mouse.click(5, 600)
        page.locator('[data-zfs-panel]').wait_for(state='hidden', timeout=3000)
        assert page.locator('button', has_text='Create ZFS').first.is_disabled()
        assert page.locator('button', has_text='Create LVM').first.is_disabled()
    else:
        page.locator('[data-zfs-panel] button[title="Close"]').click()
        page.locator('[data-zfs-panel]').wait_for(state='hidden', timeout=3000)
    assert not [c for c in app.server.calls if c[0] != 'GET' and c[1].startswith('/api/clusters')]
    assert not app.errors, app.errors


def test_runtime_it_speaks_german(open_app):
    app = open_app(layout='modern', language='de')
    page = app.page
    page.get_by_text('Testi').first.click()
    page.locator('button[title="Node Konfiguration"]').first.click()
    page.locator('button', has_text='Disks').last.click()
    opener = page.locator('[data-zfs-open="tank"]')
    opener.wait_for(timeout=8000)
    assert opener.inner_text().strip() == 'Pool-Details'
    opener.click()
    page.locator('[data-zfs-panel]').wait_for(timeout=5000)
    page.wait_for_timeout(300)
    scan = page.locator('[data-zfs-scan]').inner_text()
    assert 'Letzter Scrub' in scan and 'Scrub beendet am Sun Oct 5 00:24:03 2026' in scan
    assert '0B repariert, 0 Fehler, Dauer 00:00:02' in scan
    assert 'Keine bekannten Datenfehler' in page.locator('[data-zfs-data-errors]').inner_text()
    heads = page.locator('[data-zfs-panel] thead th').all_inner_texts()
    assert [h.strip() for h in heads][1:] == ['Zustand', 'Lesen', 'Schreiben', 'Prüfsumme', 'Hinweis']
    _shot(page, 'modern_zfs_pool_de.png')
    assert not app.errors, app.errors


# --- the alert rule --------------------------------------------------------------------

RULE = {'id': 'z1', 'name': 'Pools', 'cluster_id': 'c1', 'metric': 'zfs_health', 'operator': 'event',
        'threshold': 1, 'target_type': 'node', 'target_id': 'pve1', 'channels': [], 'enabled': True,
        'notify_resolved': True, 'severity': 'auto'}
INCIDENT = {'id': 'i9', 'alert_id': 'z1', 'severity': 'warning', 'metric': 'zfs_health', 'operator': 'event',
            'message': 'ZFS pool tank on node pve1 is DEGRADED: 10485834897452934531 UNAVAIL (was /dev/sdc1)',
            'target_type': 'node', 'target_name': 'pve1', 'current_value': 2, 'threshold': 1,
            'triggered_at': '2026-10-05T01:00:00', 'last_fired_at': '2026-10-05T01:00:00', 'acked_at': None,
            'acked_by': None, 'escalation_step': 0, 'object_key': 'zfs:pve1:tank', 'muted_until': None}
ALERT_READS = {
    ('GET', '/api/clusters/c1/alerts'): (200, {'alerts': [RULE]}),
    ('GET', '/api/clusters/c1/active-alerts'): (200, {'active_alerts': [INCIDENT]}),
    ('GET', '/api/clusters/c1/alert-mutes'): (200, {'mutes': []}),
    ('GET', '/api/alert-channels'): (200, []),
    ('GET', '/api/schedules'): (200, []),
    ('GET', '/api/clusters/c1/scripts'): (200, []),
    ('POST', '/api/clusters/c1/alerts'): (200, {'success': True, 'alert': {}}),
    ('PUT', '/api/clusters/c1/alerts/z1'): (200, {'success': True, 'alert': {}}),
}


def _to_alerts(app, layout='modern'):
    page = app.page
    if layout == 'corporate':
        page.locator('.corp-tree-item', has_text='Testi').first.click()
    else:
        page.get_by_text('Testi').first.click()
    page.locator('button', has_text=re.compile(r'^\s*(Automation|Automatisierung)\s*$')).first.click()
    page.get_by_role('button', name=re.compile(r'^\s*(Alerts|Alarme)\s*$')).first.click()
    page.locator('[data-alert-rule="z1"]').wait_for(timeout=8000)
    page.wait_for_timeout(300)
    return page


def _alert_app(open_app, **kw):
    extra = dict(ALERT_READS)
    extra.update(SSE_TOKEN)
    return open_app(extra=extra, **kw)


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_the_rule_and_its_incident_in_the_list(open_app, layout):
    app = _alert_app(open_app, layout=layout, role='standalone')
    page = _to_alerts(app, layout)
    assert 'ZFS pools: Not ONLINE only' in page.locator('[data-alert-rule="z1"]').inner_text()
    assert 'is DEGRADED' in page.locator('[data-active-alert="i9"]').inner_text()
    # a mute of the incident offers the whole node
    page.locator('[data-active-alert="i9"] button[title="Mute"]').click()
    assert 'every rule for pve1' in page.locator('[data-mute-menu]').inner_text()
    assert not app.errors, app.errors


def test_runtime_the_dialog_asks_for_what_a_zfs_rule_needs(open_app):
    app = _alert_app(open_app, layout='modern', role='standalone')
    page = _to_alerts(app)
    page.locator('button', has_text='New Alert').first.click()
    metric = page.locator('select[name="metric"]')
    metric.wait_for(timeout=3000)
    assert page.locator('select[name="target_type"] option[value="vm"]').count() == 1
    metric.select_option('zfs_health')
    fields = page.locator('[data-event-fields="zfs_health"]')
    assert fields.locator('select[name="threshold"] option').all_inner_texts() == [
        'Not ONLINE, or errors', 'Not ONLINE only']
    assert 'every 5 minutes' in page.locator('[data-event-help]').inner_text()
    # a pool is on a node or anywhere in the cluster, never on a guest
    assert page.locator('select[name="target_type"] option').evaluate_all('o => o.map(x => x.value)') == [
        'cluster', 'node']
    assert page.locator('select[name="operator"]').count() == 0
    assert page.locator('input[name="notify_resolved"]').is_checked()
    page.locator('input[name="name"]').fill('Pools')
    page.locator('select[name="target_type"]').select_option('node')
    page.locator('input[name="target_id"]').fill('pve1')
    fields.locator('select[name="threshold"]').select_option('1')
    _shot(page, 'modern_alerts_dialog_zfs.png')
    page.locator('form button[type="submit"]').click()
    assert _wait_for_call(app, ('POST', '/api/clusters/c1/alerts'))
    # the list is read again on the same path right after, with no body
    body = [b for b in app.server.bodies['/api/clusters/c1/alerts'] if b][-1]
    for k, v in {'name': 'Pools', 'metric': 'zfs_health', 'operator': 'event', 'threshold': 1,
                 'target_type': 'node', 'target_id': 'pve1', 'notify_resolved': True}.items():
        assert body.get(k) == v, (k, body)
    assert not app.errors, app.errors


def test_runtime_editing_a_zfs_rule_keeps_its_level(open_app):
    app = _alert_app(open_app, layout='modern', role='standalone')
    page = _to_alerts(app)
    page.locator('[data-alert-rule="z1"] button[title="Edit Alert"]').click()
    page.locator('[data-event-fields="zfs_health"]').wait_for(timeout=3000)
    assert page.locator('[data-event-fields="zfs_health"] select[name="threshold"]').input_value() == '1'
    page.locator('form button[type="submit"]').click()
    assert _wait_for_call(app, ('PUT', '/api/clusters/c1/alerts/z1'))
    assert app.server.bodies['/api/clusters/c1/alerts/z1'][-1]['threshold'] == 1
    assert not app.errors, app.errors
