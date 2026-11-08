"""The drift view shows the firewall, HA rules, backup jobs and access, with the policy checks.

Filters by kind and category, a badge for policy violations and incidents, the list of
policy checks with what the last scan could judge, and the admin action "confirm as
incident". A kind the last scan could not read says "Not checked" instead of a zero.
Runtime tests drive the built bundle in headless Chromium against the fake server of
tests/test_ha_ui.py; they skip where Playwright is not installed.
LW Oct 2026
"""
import os
import re

import pytest

from test_ha_ui import CLUSTER, SSE_TOKEN, VM, _App, _FakeServer, browser  # noqa: F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEY_PREFIXES = ('driftKind', 'driftCat', 'driftPolicy', 'driftCheck_', 'driftIncident', 'driftAll',
                'driftNotChecked', 'driftPartlyChecked', 'driftNoBaselineYet', 'driftOpViolation', 'driftConfirm', 'driftWithdraw')


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def test_every_new_key_is_in_all_nine_languages():
    src = _read('web', 'src', 'translations.js')
    used = set(re.findall(r"t\('(drift[A-Za-z_]+)'\)", _read('web', 'src', 'dashboard.js')))
    used |= {f'driftCheck_{c}' for c in ('access_admin_role', 'access_token_expiry',
                                          'firewall_cluster_enabled', 'backup_none_disabled')}
    new = {k for k in used if k.startswith(KEY_PREFIXES)}
    assert len(new) >= 30
    for key in sorted(new):
        assert len(re.findall(rf'^\s*{key}:', src, re.M)) == 9, key


def test_no_dash_in_what_this_change_added():
    src = _read('web', 'src', 'dashboard.js')
    start = src.index('const DRIFT_KINDS')
    block = src[start:src.index('// MK May 2026', start)]
    added = [l for l in block.splitlines() if 'LW Oct 2026' in l or 'Policy' in l or 'incident' in l.lower()]
    assert added and all('\u2014' not in l and '\u2013' not in l for l in added)


# --- runtime ---------------------------------------------------------------------------------

def _ev(eid, kind, scope, category, op='changed', severity='warning'):
    return {'id': eid, 'cluster_id': 'c1', 'kind': kind, 'scope': scope, 'severity': severity,
            'summary': f'{kind} {scope}', 'detected_at': '2026-10-05T10:00:00', 'status': 'open',
            'category': category,
            'diff': [{'path': 'who@pve', 'op': op, 'before': None, 'after': 'Administrator on /'}]}


DEVIATION = _ev(21, 'access', 'acl', 'deviation', 'added', 'critical')
VIOLATION = _ev(22, 'access', 'policy:access_admin_role', 'policy_violation', 'violation', 'critical')
CHECKS = [
    {'id': 'access_admin_role', 'kind': 'access', 'severity': 'critical', 'enabled': True, 'status': 'fail',
     'allow': ['root@pam'], 'violations': [{'path': 'user:who@pve', 'detail': 'Administrator on /'}]},
    {'id': 'access_token_expiry', 'kind': 'access', 'severity': 'warning', 'enabled': True,
     'status': 'not_checked', 'violations': []},
    {'id': 'firewall_cluster_enabled', 'kind': 'firewall', 'severity': 'warning', 'enabled': False,
     'status': 'disabled', 'violations': []},
    {'id': 'backup_none_disabled', 'kind': 'backup_jobs', 'severity': 'warning', 'enabled': True,
     'status': 'pass', 'violations': []},
]
READS = {
    ('GET', '/api/clusters/c1/drift/status'): (200, {
        'cluster_id': 'c1', 'open_total': 2, 'baselines': 30, 'last_event_at': '2026-10-05T10:00:00',
        'by_kind': {'access': {'critical': 2, 'warning': 0, 'info': 0}},
        'by_severity': {'critical': 2, 'warning': 0, 'info': 0},
        'by_category': {'deviation': 1, 'policy_violation': 1, 'incident': 0},
        'kinds': {'vm_config': 'checked', 'storage': 'checked', 'network': 'checked', 'cluster_options': 'checked',
                  'firewall': 'not_checked', 'ha_rules': 'no_baseline', 'backup_jobs': 'checked', 'access': 'partial'}}),
    ('GET', '/api/clusters/c1/drift/events'): (200, {'events': [DEVIATION, VIOLATION]}),
    ('GET', '/api/clusters/c1/drift/policy'): (200, {'checks': CHECKS, 'last_scan_at': '2026-10-05T10:00:00'}),
    ('POST', '/api/drift/events/21/incident'): (200, {'ok': True, 'category': 'incident'}),
    ('PUT', '/api/clusters/c1/drift/policy'): (200, {'ok': True, 'checks': CHECKS}),
}
TAB = {'en': ('Compliance', 'Config Drift Detection'), 'pl': ('Zgodność', 'Wykrywanie zmian konfiguracji')}


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(**kw):
        extra = dict(SSE_TOKEN)
        extra.update(READS)
        kw.setdefault('role', 'standalone')
        server = _FakeServer(clusters=[CLUSTER], resources=[VM], extra=extra, **kw)
        app = _App(browser, server)
        app.server = server
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _open_drift(app, language='en'):
    page = app.page
    compliance, drift = TAB[language]
    page.get_by_text('Testi').first.click()
    page.locator('button', has_text=re.compile(rf'^\s*{compliance}\s*$')).first.click()
    page.locator('button', has_text=re.compile(rf'^\s*{drift}\s*$')).first.click()
    page.locator('[data-drift-policy]').wait_for(timeout=8000)
    return page


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_new_kinds_policy_and_what_was_not_read(open_app, layout):
    app = open_app(layout=layout)
    page = _open_drift(app)
    assert page.locator('[data-drift-kind]').count() == 8
    # a kind that was not read says so; one that was is silent
    assert page.locator('[data-drift-kind="firewall"] [data-drift-unread="not_checked"]').inner_text().strip() == 'Not checked'
    assert page.locator('[data-drift-kind="access"] [data-drift-unread="partial"]').inner_text().strip() == 'Partly checked'
    assert page.locator('[data-drift-kind="storage"] [data-drift-unread]').count() == 0
    # read but nothing to compare with: neither a zero nor "checked"
    assert page.locator('[data-drift-kind="ha_rules"] [data-drift-unread="no_baseline"]').inner_text().strip() == 'No baseline yet'

    checks = {c: page.locator(f'[data-drift-check="{c}"]').inner_text() for c in
              ('access_admin_role', 'access_token_expiry', 'firewall_cluster_enabled', 'backup_none_disabled')}
    assert 'Violated' in checks['access_admin_role'] and 'user:who@pve: Administrator on /' in checks['access_admin_role']
    assert 'Not checked' in checks['access_token_expiry'] and 'Passed' not in checks['access_token_expiry']
    assert 'Off' in checks['firewall_cluster_enabled']
    assert 'Passed' in checks['backup_none_disabled']
    assert not app.errors, app.errors


def test_runtime_filters_ask_the_server_by_kind_and_category(open_app):
    app = open_app(layout='modern')
    page = _open_drift(app)
    page.locator('[data-drift-filter="kind"]').select_option('access')
    page.wait_for_timeout(500)
    page.locator('[data-drift-filter="category"]').select_option('policy_violation')
    page.wait_for_timeout(500)
    urls = [u for u in app.server.urls if '/drift/events' in u]
    assert any('kind=access' in u and 'category' not in u for u in urls), urls
    assert any('kind=access' in u and 'category=policy_violation' in u for u in urls), urls
    # the options are the kinds and categories the server knows
    opts = page.locator('[data-drift-filter="kind"] option').all_inner_texts()
    assert {'Firewall', 'HA Rules', 'Backup Jobs', 'Access'} <= set(opts)
    assert not app.errors, app.errors


def test_runtime_an_event_shows_its_category_and_an_admin_confirms_an_incident(open_app):
    app = open_app(layout='modern')
    page = _open_drift(app)
    assert page.locator('[data-drift-category="policy_violation"]').inner_text().strip() == 'Policy violation'
    # a plain deviation carries no badge; a violation has no baseline to promote
    assert page.locator('[data-drift-category="deviation"]').count() == 0
    assert page.get_by_role('button', name='Promote').count() == 1
    assert page.locator('[data-drift-incident]').count() == 2
    page.on('dialog', lambda d: d.accept())
    page.locator('[data-drift-incident="21"]').click()
    page.wait_for_timeout(500)
    assert ('POST', '/api/drift/events/21/incident') in app.server.calls
    assert not app.errors, app.errors


def test_runtime_a_non_admin_cannot_confirm_or_change_the_policy(open_app):
    app = open_app(layout='modern', admin=False, permissions=['admin.audit'])
    page = app.page
    page.get_by_text('Testi').first.click()
    page.locator('button', has_text=re.compile(r'^\s*Compliance\s*$')).first.click()
    page.locator('button', has_text=re.compile(r'^\s*Config Drift Detection\s*$')).first.click()
    page.locator('[data-drift-policy]').wait_for(timeout=8000)
    assert page.locator('[data-drift-incident]').count() == 0
    assert page.locator('[data-drift-check] input').count() == 0
    assert not app.errors, app.errors


def test_runtime_the_policy_is_switched_and_the_allow_list_saved(open_app):
    app = open_app(layout='modern')
    page = _open_drift(app)
    page.locator('[data-drift-check="firewall_cluster_enabled"] input[type=checkbox]').click()
    page.wait_for_timeout(500)
    assert ('PUT', '/api/clusters/c1/drift/policy') in app.server.calls
    app.server.calls.clear()
    box = page.locator('[data-drift-check="access_admin_role"] input[type=text], [data-drift-check="access_admin_role"] input:not([type])')
    box.fill('root@pam, ops@pve')
    page.locator('[data-drift-check="access_admin_role"]').get_by_role('button', name='Save').click()
    page.wait_for_timeout(500)
    assert ('PUT', '/api/clusters/c1/drift/policy') in app.server.calls
    assert not app.errors, app.errors


def test_runtime_the_new_text_is_translated(open_app):
    app = open_app(layout='modern', language='pl')
    page = _open_drift(app, 'pl')
    assert 'Kontrole polityki' in page.locator('[data-drift-policy]').inner_text()
    assert page.locator('[data-drift-kind="firewall"] [data-drift-unread]').inner_text().strip() == 'Niesprawdzone'
    assert page.locator('[data-drift-kind="ha_rules"] [data-drift-unread]').inner_text().strip() == 'Brak jeszcze konfiguracji bazowej'
    assert page.locator('[data-drift-category="policy_violation"]').inner_text().strip() == 'Naruszenie polityki'
    assert not app.errors, app.errors
