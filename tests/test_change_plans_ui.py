"""The Changes view: list with a state filter, the plan form, and the buttons the server allows.

NS Oct 2026 - runtime tests drive the built bundle in headless Chromium against the fake
server of tests/test_ha_ui.py, here with a small change-plan API of its own. They skip where
Playwright is not installed. Modern, Corporate and the cloud layout; the drift view shows a
"planned" badge on a deviation inside an approved plan.
"""
import json
import os
import re

import pytest

from test_ha_ui import BASE, CLUSTER, SSE_TOKEN, VM, _App, _FakeServer, browser  # noqa: F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROUTE = '/api/changes'


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def test_every_key_the_view_uses_is_in_all_nine_languages():
    src = _read('web', 'src', 'translations.js')
    dash = _read('web', 'src', 'dashboard.js')
    start = dash.index('const CHG_KINDS')
    block = dash[start:dash.index('// LW Oct 2026 - the flight recorder', start)]
    used = set(re.findall(r"'(chg[A-Za-z_]+)'", block)) | set(re.findall(r"t\('(chg[A-Za-z_]+)'\)", block))
    used |= {'chgBlockedOwn_plan', 'chgBlockedOut_of_scope', 'driftPlanned', 'driftPlannedCount', 'chgTab'}
    used |= {'chgSt' + s for s in ('Draft', 'Submitted', 'Approved', 'Rejected', 'Cancelled', 'Done', 'Expired')}
    used.discard('chgBlocked')   # the stem of the two keys named above
    assert len(used) >= 45, sorted(used)
    for key in sorted(used):
        assert len(re.findall(rf'^\s*{key}:', src, re.M)) == 9, key


def test_the_new_text_has_no_dash():
    src = _read('web', 'src', 'dashboard.js')
    start = src.index('const CHG_KINDS')
    block = src[start:src.index('// LW Oct 2026 - the flight recorder', start)]
    assert '\u2014' not in block and '\u2013' not in block
    tr = _read('web', 'src', 'translations.js')
    assert not [l for l in tr.splitlines() if re.match(r'\s*(chg[A-Za-z_]+|driftPlanned[A-Za-z]*):', l) and '\u2014' in l]


# --- a small change-plan API ------------------------------------------------------------------

def _plan(pid, title, by, status='submitted', kind='guests', targets=(101,), **kw):
    p = {'id': pid, 'cluster_id': 'c1', 'title': title, 'description': '', 'status': status,
         'scope': {'kind': kind, 'targets': list(targets)},
         'window_start': '2030-01-01T10:00:00Z', 'window_end': '2030-01-01T12:00:00Z',
         'requested_by': by, 'approved_by': '', 'rejected_by': '', 'reject_reason': ''}
    p.update(kw)
    return p


class _ChangesServer(_FakeServer):
    """GET/POST /api/changes with the contract of pegaprox/api/changes.py: the page is told
    what it may do (`can`) and why Approve is off (`approve_blocked`)."""

    def __init__(self, *a, plans=None, **kw):
        super().__init__(*a, **kw)
        self.plans = [dict(p) for p in (plans or [])]
        self.me = 'admin'
        self.seq = 0

    def view(self, p):
        mine = p['requested_by'] == self.me
        st = p['status']
        blocked = ''
        if st == 'submitted':
            blocked = 'own_plan' if mine else p.get('blocked', '')
        reason = {'own_plan': 'you requested this plan: a second person approves it',
                  'out_of_scope': 'only an administrator approves a change that affects the whole cluster'}.get(blocked, '')
        out = dict(p, display_status=st, expired=False, mine=mine, approve_blocked=blocked,
                   approve_blocked_reason=reason)
        open_ = st in ('draft', 'submitted', 'approved')
        out['can'] = {'edit': mine and st == 'draft', 'submit': mine and st == 'draft',
                      'approve': st == 'submitted' and not blocked, 'reject': st == 'submitted' and not blocked,
                      'cancel': open_, 'done': st == 'approved'}
        return out

    def handle(self, route):
        req = route.request
        path = re.sub(r'^https?://[^/]+', '', req.url).split('?')[0]
        if not (req.url.startswith(BASE) and (path == ROUTE or path.startswith(ROUTE + '/'))):
            return super().handle(route)
        self.calls.append((req.method, path))
        self.urls.append(req.url)
        try:
            body = json.loads(req.post_data) if req.post_data else {}
        except Exception:
            body = {}
        self.bodies.setdefault(path, []).append(body)
        status, data = self.api(req.method, path, body, req.url)
        return route.fulfill(status=status, body=json.dumps(data), headers={'Content-Type': 'application/json'})

    def api(self, method, path, body, url):
        if method == 'GET':
            want = re.search(r'[?&]status=(\w+)', url)
            rows = [p for p in self.plans if not want or p['status'] == want.group(1)]
            return 200, {'changes': [self.view(p) for p in rows], 'me': self.me}
        if method == 'POST' and path == ROUTE:
            self.seq += 1
            p = _plan(f'n{self.seq}', body['title'], self.me, status='draft', kind=body['scope']['kind'],
                      targets=body['scope']['targets'], window_start=body['window_start'],
                      window_end=body['window_end'], description=body.get('description', ''))
            self.plans.append(p)
            return 201, self.view(p)
        m = re.fullmatch(ROUTE + r'/([\w-]+)(?:/(\w+))?', path)
        p = next((x for x in self.plans if m and x['id'] == m.group(1)), None)
        if p is None:
            return 404, {'error': 'not found'}
        action = m.group(2)
        if method == 'PUT':
            p.update({k: v for k, v in body.items() if k in ('title', 'description')})
            return 200, self.view(p)
        after = {'submit': 'submitted', 'approve': 'approved', 'reject': 'rejected', 'cancel': 'cancelled',
                 'done': 'done'}[action]
        if action == 'approve':
            p['approved_by'] = self.me
        if action == 'reject':
            p.update(rejected_by=self.me, reject_reason=body.get('reason', ''))
        p['status'] = after
        return 200, self.view(p)


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(plans=None, **kw):
        extra = dict(SSE_TOKEN)
        extra.update(kw.pop('extra', {}))
        kw.setdefault('role', 'standalone')
        server = _ChangesServer(clusters=[CLUSTER], resources=[VM], extra=extra, plans=plans, **kw)
        app = _App(browser, server)
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _open_changes(app):
    page = app.page
    layout = app.server.layout
    if layout == 'cloud':
        page.locator('.cloud-nav').get_by_text('Changes', exact=True).click()
    else:
        if layout == 'corporate':
            page.locator('.corp-tree-item', has_text='Testi').first.click()
        else:
            page.get_by_text('Testi').first.click()
        page.locator('button', has_text=re.compile(r'^\s*Compliance\s*$')).first.click()
        page.locator('[data-compliance-sub="changes"]').click()
    page.locator('[data-changes-tab]').wait_for(timeout=8000)
    return page


def _posts(app, suffix=''):
    return [b for b in app.server.bodies.get(ROUTE + suffix, []) if b]


PLANS = [_plan('p-bob', 'Patch the web tier', 'bob'),
         _plan('p-own', 'Resize the database', 'admin', targets=(102,)),
         _plan('p-wide', 'Replace the storage controller', 'bob', kind='storage', targets=('ceph',),
               blocked='out_of_scope'),
         _plan('p-ok', 'Done last week', 'bob', status='done')]


@pytest.mark.parametrize('layout', ['modern', 'corporate', 'cloud'])
def test_runtime_buttons_follow_what_the_server_allows(open_app, layout):
    app = open_app(plans=PLANS, layout=layout)
    page = _open_changes(app)
    page.locator('[data-change="p-bob"]').wait_for(timeout=5000)
    # another admin's plan: Approve and Reject are on
    assert page.locator('[data-change="p-bob"] [data-change-action="approve"]').is_enabled()
    assert page.locator('[data-change="p-bob"] [data-change-action="reject"]').is_enabled()
    # one's own plan: Approve is off, with the reason next to it and as its title
    own = page.locator('[data-change="p-own"] [data-change-action="approve"]')
    assert own.is_disabled()
    assert 'second person' in page.locator('[data-change="p-own"] [data-change-blocked="own_plan"]').inner_text()
    assert 'second person' in (own.get_attribute('title') or '')
    # outside the approval scope: off as well, with its own reason
    wide = page.locator('[data-change="p-wide"] [data-change-action="approve"]')
    assert wide.is_disabled()
    assert 'outside what you may approve' in page.locator('[data-change="p-wide"] [data-change-blocked="out_of_scope"]').inner_text()
    # a finished plan has no Approve at all
    assert page.locator('[data-change="p-ok"] [data-change-action="approve"]').count() == 0
    assert page.locator('[data-change="p-ok"] [data-change-badge]').inner_text().strip() == 'Done'
    # clicking a disabled button asks nothing
    own.click(force=True)
    page.wait_for_timeout(300)
    assert ('POST', ROUTE + '/p-own/approve') not in app.server.calls
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate', 'cloud'])
def test_runtime_create_submit_and_approve_by_another_admin(open_app, layout):
    app = open_app(plans=[PLANS[0]], layout=layout)
    page = _open_changes(app)
    page.locator('[data-change-new]').click()
    form = page.locator('[data-change-form]')
    form.locator('[data-change-field="title"]').fill('Kernel update web tier')
    form.locator('[data-change-field="targets"]').fill('101, 102')
    form.locator('[data-change-field="start"]').fill('2030-01-01T10:00')
    form.locator('[data-change-field="end"]').fill('2030-01-01T12:30')
    form.locator('[data-change-save-submit]').click()
    page.locator('[data-change="n1"]').wait_for(timeout=5000)
    body = _posts(app)[-1]
    assert body['cluster_id'] == 'c1' and body['title'] == 'Kernel update web tier'
    assert body['scope'] == {'kind': 'guests', 'targets': [101, 102]}
    stamp = re.compile(r'^\d{4}-\d\d-\d\dT\d\d:\d\d:00Z$')
    assert stamp.match(body['window_start']) and stamp.match(body['window_end'])
    assert body['window_start'] < body['window_end']
    assert ('POST', ROUTE + '/n1/submit') in app.server.calls
    assert page.locator('[data-change="n1"] [data-change-badge]').inner_text().strip() == 'Waiting for approval'
    assert page.locator('[data-change-form]').count() == 0
    # it is the requester's own: no way to approve it here
    assert page.locator('[data-change="n1"] [data-change-action="approve"]').is_disabled()

    # another administrator's plan is approved with one click
    page.locator('[data-change="p-bob"] [data-change-action="approve"]').click()
    page.wait_for_function("document.querySelector('[data-change=\"p-bob\"] [data-change-badge]').innerText.trim() === 'Approved'",
                           timeout=5000)
    assert ('POST', ROUTE + '/p-bob/approve') in app.server.calls
    assert 'Approved by admin' in page.locator('[data-change="p-bob"]').inner_text()
    assert not app.errors, app.errors


def test_runtime_a_draft_is_saved_edited_and_submitted(open_app):
    app = open_app(layout='modern')
    page = _open_changes(app)
    assert 'No change plans' in page.locator('[data-changes-tab]').inner_text()
    page.locator('[data-change-new]').click()
    page.locator('[data-change-field="title"]').fill('Storage move')
    page.locator('[data-change-field="kind"]').select_option('storage')
    page.locator('[data-change-field="targets"]').fill('ceph')
    page.locator('[data-change-save]').click()
    page.locator('[data-change="n1"]').wait_for(timeout=5000)
    assert _posts(app)[-1]['scope'] == {'kind': 'storage', 'targets': ['ceph']}
    assert page.locator('[data-change="n1"] [data-change-badge]').inner_text().strip() == 'Draft'
    page.locator('[data-change="n1"] [data-change-action="edit"]').click()
    assert page.locator('[data-change-field="title"]').input_value() == 'Storage move'
    page.locator('[data-change-field="title"]').fill('Storage move, second try')
    page.locator('[data-change-save]').click()
    page.wait_for_function("document.querySelector('[data-change=\"n1\"]').innerText.includes('second try')", timeout=5000)
    assert app.server.bodies[ROUTE + '/n1'][-1]['title'] == 'Storage move, second try'
    page.locator('[data-change="n1"] [data-change-action="submit"]').click()
    page.wait_for_function("document.querySelector('[data-change=\"n1\"] [data-change-badge]').innerText.trim() === 'Waiting for approval'",
                           timeout=5000)
    assert not app.errors, app.errors


def test_runtime_a_rejection_asks_for_the_reason(open_app):
    app = open_app(plans=[PLANS[0]], layout='modern')
    page = _open_changes(app)
    page.locator('[data-change="p-bob"] [data-change-action="reject"]').click()
    confirm = page.locator('[data-change-reject-confirm]')
    assert confirm.is_disabled()
    page.locator('[data-change-reason]').fill('collides with the backup window')
    confirm.click()
    page.wait_for_function("document.querySelector('[data-change=\"p-bob\"] [data-change-badge]').innerText.trim() === 'Rejected'",
                           timeout=5000)
    assert app.server.bodies[ROUTE + '/p-bob/reject'][-1] == {'reason': 'collides with the backup window'}
    assert 'collides with the backup window' in page.locator('[data-change="p-bob"]').inner_text()
    assert not app.errors, app.errors


def test_runtime_the_state_filter_asks_the_server(open_app):
    app = open_app(plans=PLANS, layout='modern')
    page = _open_changes(app)
    page.locator('[data-change-filter]').select_option('done')
    page.wait_for_function("document.querySelectorAll('[data-change]').length === 1", timeout=5000)
    assert any('status=done' in u and 'cluster=c1' in u for u in app.server.urls)
    assert page.locator('[data-change="p-ok"]').count() == 1


def test_runtime_a_holder_of_the_view_permission_alone_sees_the_plans_and_no_button_to_start_one(open_app):
    app = open_app(plans=PLANS, layout='modern', admin=False, permissions=['changes.view'])
    page = app.page
    page.get_by_text('Testi').first.click()
    page.locator('button', has_text=re.compile(r'^\s*Compliance\s*$')).first.click()
    # no hardening or drift to read: the Changes sub tab is the only one
    assert page.locator('[data-compliance-sub]').count() == 1
    page.locator('[data-change="p-bob"]').wait_for(timeout=5000)
    assert page.locator('[data-change-new]').count() == 0
    assert not app.errors, app.errors


def test_runtime_a_standby_that_does_not_forward_shows_the_plans_without_buttons(open_app):
    app = open_app(plans=PLANS, layout='modern', role='standby')
    page = _open_changes(app)
    page.locator('[data-change="p-bob"]').wait_for(timeout=5000)
    assert page.locator('[data-change-action]').count() == 0 and page.locator('[data-change-new]').count() == 0
    assert not app.errors, app.errors


def test_runtime_german_labels(open_app):
    app = open_app(plans=[PLANS[1]], layout='modern', language='de')
    page = app.page
    page.get_by_text('Testi').first.click()
    page.locator('button', has_text=re.compile(r'^\s*Compliance\s*$')).first.click()
    page.locator('[data-compliance-sub="changes"]').click()
    page.locator('[data-change="p-own"]').wait_for(timeout=5000)
    text = page.locator('[data-change="p-own"]').inner_text()
    assert 'Wartet auf Freigabe' in text and 'Beantragt von admin' in text
    assert 'zweite Person' in text
    assert not app.errors, app.errors


# --- drift: the planned badge -------------------------------------------------------------------

def _drift_event(eid, scope, change_id=None, title=''):
    ev = {'id': eid, 'cluster_id': 'c1', 'kind': 'vm_config', 'scope': scope, 'severity': 'warning',
          'summary': f'vm_config {scope}', 'detected_at': '2026-10-05T10:00:00', 'status': 'open',
          'category': 'deviation', 'change_id': change_id,
          'diff': [{'path': 'cores', 'op': 'changed', 'before': 2, 'after': 4}]}
    if change_id:
        ev['change_title'] = title
    return ev


DRIFT = {
    ('GET', '/api/clusters/c1/drift/status'): (200, {
        'cluster_id': 'c1', 'open_total': 2, 'baselines': 3, 'last_event_at': '2026-10-05T10:00:00', 'planned': 1,
        'by_kind': {'vm_config': {'critical': 0, 'warning': 2, 'info': 0}},
        'by_severity': {'critical': 0, 'warning': 2, 'info': 0},
        'by_category': {'deviation': 2, 'policy_violation': 0, 'incident': 0}, 'kinds': {}}),
    ('GET', '/api/clusters/c1/drift/events'): (200, {'events': [
        _drift_event(31, 'qemu/101', 'p1', 'Resize web tier'), _drift_event(32, 'qemu/102')]}),
    ('GET', '/api/clusters/c1/drift/policy'): (200, {'checks': [], 'last_scan_at': None}),
}


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_a_planned_deviation_shows_the_plan_and_keeps_its_category(open_app, layout):
    app = open_app(layout=layout, extra=DRIFT)
    page = app.page
    if layout == 'corporate':
        page.locator('.corp-tree-item', has_text='Testi').first.click()
    else:
        page.get_by_text('Testi').first.click()
    page.locator('button', has_text=re.compile(r'^\s*Compliance\s*$')).first.click()
    page.locator('button', has_text=re.compile(r'^\s*Config Drift Detection\s*$')).first.click()
    badge = page.locator('[data-drift-planned="p1"]')
    badge.wait_for(timeout=8000)
    assert badge.inner_text().strip() == 'Planned: Resize web tier'
    # the other deviation has none, and neither shows a category badge: both stay deviations
    assert page.locator('[data-drift-planned]').count() == 1
    assert page.locator('[data-drift-category]').count() == 0
    assert '1 of the open deviations' in page.locator('[data-drift-planned-count]').inner_text()
    assert not app.errors, app.errors
