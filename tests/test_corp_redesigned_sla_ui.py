"""Corporate Redesigned, the Backup SLA sub tab of the Datastore view (round 11): the tiles, the target
edited in place, the coverage beside it and the guest table, the state every guest is listed under and
the field that decides it, and the Save against the request the classic sub tab sends.

Runtime tests drive the built bundle in headless Chromium against the guard fake of
tests/test_corp_redesigned_guard_ui.py with the Backup SLA read (SLA_READS). The counterproof runs this
file against an older bundle: PEGAPROX_CR_BUNDLE=<path to index.html>.
LW Nov 2026
"""
import copy
import os
import re
import time

import pytest

from test_corp_redesigned_guard_ui import (DETERMINISTIC, FIXED, RESOURCES, SLA_READS, SLA_REPORT, VM, _GuardApp,
                                           _GuardServer, _sla_vm)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LAYOUT = 'corporate-redesigned'
_BUNDLE_FILE = os.environ.get('PEGAPROX_CR_BUNDLE')
BUNDLE = open(_BUNDLE_FILE, encoding='utf-8').read() if _BUNDLE_FILE else None
SHOTS = os.environ.get('PEGAPROX_UI_SHOTS', '')
DASHES = (chr(0x2014), chr(0x2013))
SLA = '/api/clusters/c1/backup-sla'
CONFIG = '/api/clusters/c1/backup-sla/config'
COVERAGE = '/api/backup-coverage'

# the guests no backup job selects, as /backup-coverage answers (clusters.py): one of another cluster
COVERAGE_OK = {'guests': [{'cluster_id': 'c1', 'cluster_name': 'Testi', 'vmid': 102, 'name': 'mail01', 'type': 'qemu',
                           'node': 'pve2', 'status': 'stopped', 'template': False, 'tags': []},
                          {'cluster_id': 'c1', 'cluster_name': 'Testi', 'vmid': 103, 'name': 'proxy01', 'type': 'lxc',
                           'node': 'pve1', 'status': 'running', 'template': False, 'tags': []},
                          {'cluster_id': 'c9', 'cluster_name': 'Other', 'vmid': 100, 'name': 'elsewhere', 'type': 'qemu',
                           'node': 'x1', 'status': 'running', 'template': False, 'tags': []}],
               'clusters': [{'cluster_id': 'c1', 'cluster_name': 'Testi', 'state': 'ok', 'count': 2, 'checked_at': FIXED - 60},
                            {'cluster_id': 'c9', 'cluster_name': 'Other', 'state': 'ok', 'count': 1, 'checked_at': FIXED - 60}]}


def _reads(over=None):
    r = dict(SLA_READS)
    r[('PUT', CONFIG)] = (200, {'ok': True, 'max_age_hours': 48})
    r[('GET', COVERAGE)] = (200, COVERAGE_OK)
    r.update(over or {})
    return r


# every state from the field that decides it, and one the route does not know
def _states_fixture():
    vms = [_sla_vm(201, 'expired01', 'breached', 30.0), _sla_vm(202, 'missing01', 'no-backup', None),
           _sla_vm(203, 'risk01', 'warning', 20.5, source='local', vtype='ct'), _sla_vm(204, 'ok01', 'ok', 7.0),
           _sla_vm(205, 'odd01', 'later', 3.0)]
    report = dict(SLA_REPORT, vms=vms, summary={'total': 5, 'ok': 1, 'warning': 1, 'breached': 1, 'no_backup': 1,
                                                'disabled': 0, 'compliance_pct': 20.0})
    return {('GET', SLA): (200, report), ('GET', COVERAGE): (200, dict(COVERAGE_OK, guests=[]))}


EXPECT = {201: 'breached', 202: 'missing', 203: 'warning', 204: 'ok', 205: 'unknown'}


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

    def _open(extra=None, layout=LAYOUT, theme='', viewport=(1600, 1000), **kw):
        server = _GuardServer(bundle=BUNDLE, layout=layout, extra=_reads(extra), **kw)
        app = _GuardApp(browser, server, corp_theme=theme, viewport=viewport)
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.close()


def _need(page, selector, what, timeout=8000):
    try:
        page.locator(selector).first.wait_for(timeout=timeout)
    except Exception:
        raise AssertionError(f'{what} (no {selector})') from None


def _open_sub(app, label='Backup SLA'):
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.locator('[data-cr-tab="datastore"]').click()
    # the start page reads the backup jobs for its own panel: count from the sub tab on
    app.mark = len(app.server.calls)
    page.locator('.corp-tab-strip button', has_text=label).first.click()
    return page


def _tab(app, rows=True):
    """The Backup SLA sub tab of Testi in the navigation of Corporate Redesigned."""
    page = _open_sub(app)
    _need(page, '[data-cr-sla]', 'the Backup SLA sub tab is the page of Corporate Redesigned')
    if rows:
        _need(page, '[data-cr-sla] [data-cr-sla-row]', 'the guest table is filled')
    page.wait_for_timeout(300)
    return page


def _shot(page, name):
    if SHOTS:
        os.makedirs(SHOTS, exist_ok=True)
        page.screenshot(path=os.path.join(SHOTS, f'sla-{name}.png'), full_page=True)


def _states(page):
    """vmid -> the state its row is listed under, in the order of the rows."""
    return {int(k): v for k, v in page.evaluate("""() => ([...document.querySelectorAll('[data-cr-table="sla-guests"] tbody tr')]
        .filter(tr => tr.querySelector('[data-cr-sla-row]'))
        .map(tr => [Number(tr.querySelector('[data-cr-sla-row]').dataset.crSlaRow),
                    tr.querySelector('[data-cr-sla-state]').dataset.crSlaState]))""")}


def _row(page, vmid):
    return page.locator('[data-cr-table="sla-guests"] tbody tr', has=page.locator(f'[data-cr-sla-row="{vmid}"]'))


def _tile(page, key):
    return page.locator(f'[data-cr-stat="sla-{key}"] .cr-stat-value').inner_text().strip()


def _wait(page, pred, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        page.wait_for_timeout(100)
    return pred()


def _count(app, method, path):
    """The requests since the sub tab was opened."""
    return len([c for c in app.server.calls[getattr(app, 'mark', 0):] if c == (method, path)])


def _no_errors(app):
    assert [e for e in app.errors if 'not mocked' not in e] == [], app.errors


# --- the parts and the states ------------------------------------------------------------------

def test_runtime_the_page_has_its_parts_and_keeps_the_sub_tab_strip(open_app):
    app = open_app()
    page = _tab(app)
    heads = page.locator('[data-cr-sla] h2.cr-sla-h').all_inner_texts()
    assert [h.strip().lower() for h in heads] == ['sla overview', 'target and coverage', 'guests']
    for sec in ('sla-target', 'sla-coverage', 'sla-guests'):
        assert page.locator(f'[data-cr-nc-sec="{sec}"]').count() == 1, sec
    # the strip of the Datastore tab stays, its button reads the SLA as classic does
    assert page.locator('.corp-tab-strip button.active', has_text='Backup SLA').count() == 1
    # the classic sub tab is not drawn beside it
    assert page.get_by_text('Max backup age (hours)', exact=True).count() == 0
    # one read of the SLA and one of the backup jobs, nothing per guest
    assert _count(app, 'GET', SLA) == 1 and _count(app, 'GET', COVERAGE) == 1
    assert not [c for c in app.server.calls if re.search(r'/qemu/|/lxc/|recovery-report', c[1])]
    # the target as a key value grid
    target = page.locator('[data-cr-nc-kv="sla-target"]')
    assert target.locator('[data-cr-nc-k="max"] dd').inner_text().strip() == '24 h'
    assert target.locator('[data-cr-nc-k="warn"] dd').inner_text().strip().startswith('19.2 h')
    assert target.locator('[data-cr-nc-k="breached"] dd').inner_text().strip() == '24 h'
    _shot(page, 'overview')
    _no_errors(app)


def test_runtime_every_guest_is_listed_under_the_state_its_fields_decide(open_app):
    app = open_app(_states_fixture())
    page = _tab(app)
    page.wait_for_function('() => document.querySelectorAll("[data-cr-table=sla-guests] [data-cr-sla-row]").length === 5', timeout=8000)
    states = _states(page)
    assert states == EXPECT
    # the most urgent first: expired, missing, at risk, compliant, then what the route did not say
    assert list(states) == [201, 202, 203, 204, 205]
    # missing and expired are two states, with two tiles
    assert [_tile(page, k) for k in ('ok', 'warning', 'breached', 'missing')] == ['1', '1', '1', '1']
    assert _tile(page, 'compliance') == '20%'
    assert _row(page, 201).locator('[data-cr-sla-state]').inner_text().strip() == 'Expired'
    assert _row(page, 202).locator('[data-cr-sla-state]').inner_text().strip() == 'Missing backup'
    assert _row(page, 205).locator('[data-cr-sla-state]').inner_text().strip() == 'Not reported'
    # the time left, from the target and the age the server measured
    assert _row(page, 201).locator('[data-cr-sla-left]').inner_text().strip() == '6.0 h over'
    assert _row(page, 203).locator('[data-cr-sla-left]').inner_text().strip() == '3.5 h left'
    assert _row(page, 202).locator('[data-cr-sla-left]').count() == 0
    assert 'none found' in _row(page, 202).inner_text()
    assert 'Backup storage' in _row(page, 203).inner_text() and 'Backup server' in _row(page, 201).inner_text()
    _shot(page, 'states')
    _no_errors(app)


def test_runtime_without_a_target_nothing_is_compliant_at_risk_or_expired(open_app):
    vms = [_sla_vm(301, 'has01', 'disabled', 400.0), _sla_vm(302, 'none01', 'disabled', None)]
    off = dict(SLA_REPORT, enabled=False, max_age_hours=0, vms=vms,
               summary={'total': 2, 'ok': 0, 'warning': 0, 'breached': 0, 'no_backup': 0, 'disabled': 2, 'compliance_pct': None})
    app = open_app({('GET', SLA): (200, off)})
    page = _tab(app)
    assert _states(page) == {302: 'missing', 301: 'off'}
    _need(page, '[data-cr-sla-off]', 'the page says no target is set')
    for k in ('compliance', 'ok', 'warning', 'breached'):
        assert _tile(page, k) == 'not configured', k
    # a guest without any backup is still missing, whatever the target
    assert _tile(page, 'missing') == '1'
    assert page.locator('[data-cr-stat="sla-ok"]').evaluate('e => e.tagName') == 'DIV'
    chips = page.locator('[data-cr-sla-chips] button').evaluate_all('bs => bs.map(b => b.dataset.crSlaChip)')
    assert chips == ['all', 'attention', 'missing', 'nojob']
    assert page.locator('[data-cr-nc-kv="sla-target"] [data-cr-nc-k="max"] dd').inner_text().strip() == 'Off'
    assert page.locator('[data-cr-nc-kv="sla-target"] [data-cr-nc-k="warn"] dd').inner_text().strip() == 'not evaluated, no target set'
    _no_errors(app)


def test_runtime_a_tile_filters_the_table_and_a_second_click_lifts_it(open_app):
    app = open_app(_states_fixture())
    page = _tab(app)
    page.locator('[data-cr-stat="sla-breached"]').click()
    page.wait_for_timeout(300)
    assert list(_states(page)) == [201]
    assert page.locator('[data-cr-stat="sla-breached"]').get_attribute('aria-pressed') == 'true'
    assert page.locator('[data-cr-sla-chips] button.active').get_attribute('data-cr-sla-chip') == 'breached'
    page.locator('[data-cr-stat="sla-breached"]').click()
    page.wait_for_timeout(300)
    assert len(_states(page)) == 5
    page.locator('[data-cr-sla-chips] button[data-cr-sla-chip="attention"]').click()
    page.wait_for_timeout(300)
    assert sorted(_states(page)) == [201, 202, 203]
    # search over vmid, name and node
    page.locator('[data-cr-table="sla-guests"] input[type="search"], [data-cr-table="sla-guests"] .cr-table-search input').first.fill('risk')
    page.wait_for_timeout(300)
    assert list(_states(page)) == [203]
    _no_errors(app)


def test_runtime_the_backup_jobs_say_which_guests_no_job_selects(open_app):
    app = open_app()
    page = _tab(app)
    page.wait_for_function('() => document.querySelector("[data-cr-stat=sla-nojob] .cr-stat-value")?.textContent === "2"', timeout=8000)
    assert _row(page, 102).locator('[data-cr-sla-job]').get_attribute('data-cr-sla-job') == 'none'
    assert _row(page, 103).locator('[data-cr-sla-job]').get_attribute('data-cr-sla-job') == 'none'
    # vmid 100 of another cluster is not this cluster's 100
    assert _row(page, 100).locator('[data-cr-sla-job]').get_attribute('data-cr-sla-job') == 'in'
    page.locator('[data-cr-stat="sla-nojob"]').click()
    page.wait_for_timeout(300)
    assert sorted(_states(page)) == [102, 103]
    assert page.locator('[data-cr-nc-kv="sla-coverage"] [data-cr-nc-k="nojob"] dd').inner_text().strip() == '2'
    # Refresh reads both again, the jobs anew
    page.locator('[data-cr-sla-refresh]').click()
    assert _wait(page, lambda: _count(app, 'GET', SLA) == 2 and _count(app, 'GET', COVERAGE) == 2)
    assert any(u.endswith('/api/backup-coverage?refresh=1') for u in app.server.urls)
    _no_errors(app)


@pytest.mark.parametrize('answer,why', [
    ((200, dict(COVERAGE_OK, clusters=[dict(COVERAGE_OK['clusters'][0], state='denied')])), 'refused'),
    ((403, {'error': 'Permission denied'}), 'Permission denied'),
])
def test_runtime_backup_jobs_not_read_are_not_reported_as_covered(open_app, answer, why):
    app = open_app({('GET', COVERAGE): answer})
    page = _tab(app)
    page.wait_for_timeout(500)
    assert _tile(page, 'nojob') == 'not reported'
    assert why in page.locator('[data-cr-stat="sla-nojob"]').inner_text()
    assert page.locator('[data-cr-stat="sla-nojob"]').evaluate('e => e.tagName') == 'DIV'
    assert _row(page, 100).locator('[data-cr-sla-job]').inner_text().strip() == 'not reported'
    assert page.locator('[data-cr-sla-chips] button[data-cr-sla-chip="nojob"]').count() == 0
    _no_errors(app)


# --- the target ----------------------------------------------------------------------------------

def _classic_body(open_app, value='48'):
    """The body the classic sub tab sends with the same field value, in the same session."""
    app = open_app(layout='corporate')
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.locator('button', has_text=re.compile(r'^\s*Datastore\s*$')).first.click()
    page.locator('.corp-tab-strip button', has_text='Backup SLA').first.click()
    page.get_by_text('proxy01', exact=True).first.wait_for(timeout=8000)
    page.locator('input[type="number"][max="8760"]').fill(value)
    page.locator('button', has_text=re.compile(r'^\s*Save\s*$')).first.click()
    assert _wait(page, lambda: ('PUT', CONFIG) in app.server.calls)
    return app.server.bodies[CONFIG][-1]


def test_runtime_the_target_is_edited_in_place_and_saves_the_classic_body(open_app):
    classic = _classic_body(open_app)
    app = open_app()
    page = _tab(app)
    sec = page.locator('[data-cr-nc-sec="sla-target"]')
    sec.locator('[data-cr-sla-edit]').click()
    assert sec.get_attribute('data-cr-nc-editing') == ''
    sec.locator('[data-cr-sla-field="max"]').fill('48')
    # before Save: what differs from the stored value, and nothing is sent yet
    change = sec.locator('[data-cr-nc-changes="sla-target"] li[data-cr-nc-change="max_age_hours"]')
    assert re.sub(r'\s+', ' ', change.inner_text()).strip() == 'Max backup age 24 h 48 h'
    assert '38.4 h' in sec.locator('[data-cr-nc-note]').inner_text()
    assert ('PUT', CONFIG) not in app.server.calls
    # Refresh waits until the change is saved or dropped
    assert page.locator('[data-cr-sla-refresh]').is_disabled()
    # Cancel drops the edit
    sec.locator('[data-cr-nc-cancel="sla-target"]').click()
    assert sec.locator('[data-cr-nc-k="max"] dd').inner_text().strip() == '24 h'
    sec.locator('[data-cr-sla-edit]').click()
    assert sec.locator('[data-cr-sla-field="max"]').input_value() == '24'
    assert sec.locator('[data-cr-nc-save="sla-target"]').is_disabled()
    sec.locator('[data-cr-sla-field="max"]').fill('48')
    sec.locator('[data-cr-nc-save="sla-target"]').click()
    assert _wait(page, lambda: ('PUT', CONFIG) in app.server.calls)
    assert app.server.bodies[CONFIG][-1] == classic == {'max_age_hours': 48}
    # the classic handler reads the SLA again; the edit bar closes on a save that went through
    assert _wait(page, lambda: _count(app, 'GET', SLA) == 2)
    assert _wait(page, lambda: sec.get_attribute('data-cr-nc-editing') is None)
    _no_errors(app)


def test_runtime_an_empty_field_is_said_as_off_and_a_refused_save_keeps_the_edit(open_app):
    app = open_app({('PUT', CONFIG): (400, {'error': 'max_age_hours must be 0..8760'})})
    page = _tab(app)
    sec = page.locator('[data-cr-nc-sec="sla-target"]')
    sec.locator('[data-cr-sla-edit]').click()
    sec.locator('[data-cr-sla-field="max"]').fill('')
    change = sec.locator('[data-cr-nc-changes="sla-target"] li[data-cr-nc-change="max_age_hours"]')
    assert re.sub(r'\s+', ' ', change.inner_text()).strip() == 'Max backup age 24 h Off'
    sec.locator('[data-cr-sla-field="max"]').fill('9000')
    assert sec.locator('[data-cr-nc-hint="warning"]').count() == 1
    sec.locator('[data-cr-nc-save="sla-target"]').click()
    assert _wait(page, lambda: ('PUT', CONFIG) in app.server.calls)
    assert app.server.bodies[CONFIG][-1] == {'max_age_hours': 9000}
    page.get_by_text('max_age_hours must be 0..8760').first.wait_for(timeout=5000)
    page.wait_for_timeout(300)
    assert sec.get_attribute('data-cr-nc-editing') == ''
    assert _count(app, 'GET', SLA) == 1
    _no_errors(app)


# --- reads that fail, permissions -------------------------------------------------------------------

def test_runtime_a_read_that_fails_says_why_instead_of_an_empty_page(open_app):
    app = open_app({('GET', SLA): (503, {'enabled': False, 'error': 'cluster offline'})})
    page = _tab(app, rows=False)
    _need(page, '[data-cr-sla-error]', 'the failed read is said')
    assert 'cluster offline' in page.locator('[data-cr-sla-error]').inner_text()
    assert _tile(page, 'compliance') == 'not reported'
    assert _tile(page, 'missing') == 'not reported'
    assert page.locator('[data-cr-sla-row]').count() == 0
    # Retry is the classic read
    page.locator('[data-cr-nc-retry="sla-read"]').click()
    assert _wait(page, lambda: _count(app, 'GET', SLA) == 2)
    _no_errors(app)


def test_runtime_without_cluster_config_the_target_is_read_only(open_app):
    app = open_app(admin=False, permissions=['backup.view', 'storage.view', 'vm.view', 'node.view', 'cluster.view'])
    page = _tab(app)
    assert page.locator('[data-cr-sla-edit]').is_disabled()
    assert 'cluster configuration permission' in page.locator('[data-cr-sla-readonly]').inner_text()
    _no_errors(app)


def test_runtime_a_standby_reads_and_writes_nothing(open_app):
    app = open_app(role='standby')
    page = _tab(app)
    _need(page, '[data-cr-nc-for="sla-standby"]', 'the standby says it is read only')
    assert page.locator('[data-cr-sla-edit]').is_disabled()
    assert ('PUT', CONFIG) not in app.server.calls
    _no_errors(app)


def test_runtime_templates_are_marked_and_a_guest_name_opens_the_guest(open_app):
    tpl = dict(VM, vmid=104, name='tpl01', template=1, status='stopped')
    vms = SLA_REPORT['vms'] + [_sla_vm(104, 'tpl01', 'no-backup', None)]
    app = open_app({('GET', SLA): (200, dict(SLA_REPORT, vms=vms))}, resources=RESOURCES + [tpl])
    page = _tab(app)
    assert 'Template' in _row(page, 104).inner_text()
    assert page.locator('[data-cr-nc-kv="sla-coverage"] [data-cr-nc-k="template"] dd').inner_text().strip().startswith('1')
    assert '1 templates' in page.locator('[data-cr-sla-basis]').inner_text()
    # a guest the page knows opens on its own page
    _row(page, 100).locator('button.cr-link').click()
    page.locator('[data-cr-sla]').wait_for(state='detached', timeout=8000)
    assert page.locator('[data-cr-tab="datastore"][aria-selected="true"]').count() == 0
    _no_errors(app)


def test_runtime_in_german(open_app):
    app = open_app(language='de')
    page = _open_sub(app, 'Backup SLA')
    _need(page, '[data-cr-sla] [data-cr-sla-row]', 'the guest table is filled')
    heads = page.locator('[data-cr-sla] h2.cr-sla-h').all_inner_texts()
    assert [h.strip().lower() for h in heads] == ['sla im überblick', 'ziel und abdeckung', 'gäste']
    assert page.locator('[data-cr-stat="sla-breached"] .cr-stat-label').inner_text().strip().lower() == 'abgelaufen'
    assert page.locator('[data-cr-stat="sla-missing"] .cr-stat-label').inner_text().strip().lower() == 'backup fehlt'
    _no_errors(app)


def test_runtime_10000_guests_one_read_and_a_virtual_table(open_app):
    states = ['ok', 'warning', 'breached', 'no-backup']
    vms = [_sla_vm(1000 + i, f'g{i:05d}', states[i % 4], None if i % 4 == 3 else float(i % 30), node=f'pve{i % 200}')
           for i in range(10000)]
    report = dict(SLA_REPORT, vms=vms, summary={'total': 10000, 'ok': 2500, 'warning': 2500, 'breached': 2500, 'no_backup': 2500,
                                               'disabled': 0, 'compliance_pct': 25.0})
    app = open_app({('GET', SLA): (200, report)})
    page = app.page
    t0 = time.time()
    _tab(app)
    page.wait_for_function('() => document.querySelector("[data-cr-stat=sla-missing] .cr-stat-value")?.textContent === "2500"', timeout=15000)
    assert time.time() - t0 < 12
    assert page.locator('[data-cr-table="sla-guests"] tbody tr').count() < 120
    page.locator('[data-cr-stat="sla-warning"]').click()
    page.wait_for_function('() => document.querySelector("[data-cr-table=sla-guests] .cr-table-count")?.textContent.startsWith("2500")', timeout=8000)
    assert _count(app, 'GET', SLA) == 1 and _count(app, 'GET', COVERAGE) == 1
    _no_errors(app)


@pytest.mark.parametrize('width', [1600, 1280, 1024])
def test_runtime_no_sideways_scroll(open_app, width):
    app = open_app(_states_fixture(), viewport=(width, 900))
    page = _tab(app)
    over = page.evaluate("""() => { const el = document.querySelector('[data-cr-sla]');
        return { page: document.documentElement.scrollWidth - document.documentElement.clientWidth,
                 view: el.scrollWidth - el.clientWidth }; }""")
    assert over['page'] <= 0 and over['view'] <= 0, over
    _shot(page, f'w{width}')
    _no_errors(app)


# --- source ----------------------------------------------------------------------------------------

def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def test_the_keys_are_in_every_language_once_and_before_the_banners():
    tr = _read('web', 'src', 'translations.js')
    src = _read('web', 'src', 'cr_sla.js') + _read('web', 'src', 'storage.js')
    used = set(re.findall(r"'(crSla[A-Za-z]+)'", src))
    assert used
    starts = [(m.group(1), m.start()) for m in re.finditer(r'^            ([a-z][a-z]): \{', tr, re.M)]
    for i, (lang, at) in enumerate(starts):
        block = tr[at:starts[i + 1][1] if i + 1 < len(starts) else len(tr)]
        found = set(re.findall(r'^\s*(crSla[A-Za-z]+):', block, re.M))
        # every language carries them since the translation stage, once and before the banners
        assert found == used, (lang, sorted(used ^ found))
        for key in used:
            assert len(re.findall(rf'^\s*{key}:', block, re.M)) == 1, (lang, key)
        assert block.index('crSlaAppliesAll:') < block.index('haNoLeader:'), lang
        for v in re.findall(r'^\s*crSla[A-Za-z]+: (".*"),$', block, re.M):
            assert not any(d in v for d in DASHES), v
    assert not any(d in _read('web', 'src', 'cr_sla.js') for d in DASHES)


def test_the_variant_is_gated_and_in_the_build_and_the_classic_sub_tab_stays():
    storage = _read('web', 'src', 'storage.js')
    assert ") : activeTab === 'sla' && isCorpRedesigned ? (" in storage
    assert storage.index('<CrBackupSla ') < storage.index("{t('maxBackupAge') || 'Max backup age (hours)'}")
    # the variant gets the classic read and Save, it sends no write of its own
    sla = _read('web', 'src', 'cr_sla.js')
    assert 'onSave={saveSlaConfig} onRefresh={refreshSla}' in storage
    assert 'backup-sla' not in sla.replace('GET backup-sla', '').replace('PUT backup-sla/config', '')
    assert "method: 'PUT'" not in sla and "method: 'POST'" not in sla and "method: 'DELETE'" not in sla
    assert 'cr_sla.js' in _read('web', 'Dev', 'build.sh')
    assert 'function CrBackupSla(' in _read('web', 'index.html')
