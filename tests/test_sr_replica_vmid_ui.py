"""Site Recovery in the UI: the VMID a guest has on the DR site, and the job a guest row links.

An emergency failover starts the replica a replication job keeps, under that job's VMID
(tests/test_sr_replica_vmid.py). The UI now says so:

  * the guests tab names the VMID a failed-over guest runs under on the DR cluster when it
    is not its own, and a run's results do the same for each guest
  * each guest row shows the replication job it links and lets it be changed, with every
    job of that guest between the plan's clusters to pick from. The job's label names the
    VMID it keeps the replica under, which is what tells two jobs of one guest apart, and
    what the refusal "link the one to use in the plan" asks for
  * a refused change says why

The source checks read web/src and the bundle; the runtime tests drive the built bundle in
headless Chromium against the fake server of tests/test_ha_ui.py, in Modern, Corporate,
Corporate Redesigned and Cloud.
LW Nov 2026
"""
import os
import re

import pytest

from test_ha_ui import _classes, browser  # noqa: F401
from test_sr_per_guest_failover_ui import _open, _plan, _to_plan, _vm

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHOTS = os.environ.get('PEGAPROX_SHOTS', '')
KEYS = ['srLinkedJob', 'srNoJobLinked', 'srOnTargetAs']


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def _added():
    """The lines of dashboard.js this change wrote."""
    dash = _read('web', 'src', 'dashboard.js').split('\n')
    return '\n'.join(line for line in dash
                     if any(k in line for k in ('srOnTargetAs', 'data-sr-guest-job', 'srNoJobLinked',
                                                'srLinkedJob', 'srJobLabel(', 'jobsOf[', 'jobsById[')))


# --- source --------------------------------------------------------------------------------

@pytest.mark.parametrize('key', KEYS)
def test_every_new_string_is_in_every_language_once(key):
    found = len(re.findall(rf'^\s*{key}:', _read('web', 'src', 'translations.js'), re.M))
    assert found == 10, f'{key} is in {found} of 10 language blocks'


def test_the_new_keys_sit_with_the_site_recovery_strings():
    tr = _read('web', 'src', 'translations.js').split('\n')
    anchors = [i for i, line in enumerate(tr) if re.match(r'^\s+srSkipNotFailedOver:', line)]
    assert len(anchors) == 10
    for i in anchors:
        assert [re.match(r'^\s+(\w+):', tr[i + 1 + n]).group(1) for n in range(len(KEYS))] == KEYS


def test_the_placeholders_survive_translation():
    values = re.findall(r'^\s*srOnTargetAs: [\'"](.*)[\'"],$', _read('web', 'src', 'translations.js'), re.M)
    assert len(values) == 10 and all('{cluster}' in v and '{vmid}' in v for v in values), values


def test_every_new_key_is_used():
    dash = _read('web', 'src', 'dashboard.js')
    for key in KEYS:
        assert f"t('{key}')" in dash, key


def test_no_em_dash_in_what_this_change_added():
    tr = _read('web', 'src', 'translations.js')
    added = _added() + '\n' + '\n'.join(re.findall(rf'^\s*(?:{"|".join(KEYS)}): .*$', tr, re.M))
    assert '\u2014' not in added and '\u2013' not in added


def test_every_class_is_in_the_static_tailwind_build():
    shell = '\n'.join(line for line in _read('web', 'index.html.original').split('\n')
                      if 'data-corp-theme="light"' not in line)
    css = _read('static', 'css', 'tailwind.min.css') + shell
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    missing = sorted(n for n in _classes(_added()) if n not in have)
    assert not missing, f'not in static/css/tailwind.min.css: {missing}'


def test_the_bundle_was_rebuilt():
    built = _read('web', 'index.html')
    for needle in ('srOnTargetAs', 'data-sr-guest-job', 'data-sr-result-dr', 'data-sr-guest-dr-vmid', 'srNoJobLinked'):
        assert needle in built, needle


# --- runtime -------------------------------------------------------------------------------

def _guest(vmid, name, failed_over='', job='', dr_vmid=None):
    vm = _vm(vmid, name, failed_over)
    vm.update(replication_job_id=job, failed_over_vmid=dr_vmid)
    return vm


# 100 failed over in an emergency and runs as 9100 on Remote; 101 has two jobs to Remote that
# keep the replica under different VMIDs and links neither, and one to another cluster
PLAN = _plan([_guest(100, 'web01', 'emergency', 'j-a', 9100), _guest(101, 'db01'), _guest(102, 'app01')])
JOBS = [{'id': 'j-a', 'vmid': 100, 'source_cluster': 'c1', 'target_cluster': 'c2', 'schedule': '0 */6 * * *',
         'target_vmid': 9100},
        {'id': 'j-own', 'vmid': 101, 'source_cluster': 'c1', 'target_cluster': 'c2', 'schedule': '0 */2 * * *',
         'target_vmid': None},
        {'id': 'j-pinned', 'vmid': 101, 'source_cluster': 'c1', 'target_cluster': 'c2', 'schedule': '0 */2 * * *',
         'target_vmid': 9101},
        {'id': 'j-far', 'vmid': 101, 'source_cluster': 'c1', 'target_cluster': 'c9', 'schedule': '0 1 * * *',
         'target_vmid': 7101}]
RUN = {'id': 'ev2', 'plan_id': 'p1', 'event_type': 'emergency', 'status': 'completed',
       'started_at': '2026-11-05T08:00:00', 'completed_at': '2026-11-05T08:01:00', 'triggered_by': 'system',
       'details': {'100': {'success': True, 'error': '', 'vm_name': 'web01', 'dr_vmid': 9100},
                   '101': {'success': True, 'error': '', 'vm_name': 'db01', 'dr_vmid': 101}}}
PUT = '/api/site-recovery/plans/p1/vms/v101'
LAYOUTS = ['modern', 'corporate', 'corporate-redesigned', 'cloud']


@pytest.fixture
def open_app(browser):
    apps = []

    def _go(layout, put=(200, {'message': 'VM updated'}), language='en'):
        app = _open(browser, layout=layout, plan=PLAN, language=language)
        app.server.extra[('GET', '/api/cross-cluster-replications')] = (200, JOBS)
        app.server.extra[('GET', '/api/site-recovery/plans/p1/events')] = (200, [RUN])
        app.server.extra[('PUT', PUT)] = put
        apps.append(app)
        return app
    yield _go
    for app in apps:
        app.ctx.close()


def _go_to_plan(app, layout):
    if layout != 'corporate-redesigned':
        return _to_plan(app, layout)
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.locator('[data-cr-tab="site-recovery"]').click()
    page.locator('div.cursor-pointer', has_text='DR-Plan-One').first.click()
    page.locator('h2', has_text='DR-Plan-One').wait_for(timeout=5000)


def _tab(app, name):
    app.page.locator('button', has_text=name).first.click()


def _snap(app, name):
    if SHOTS:
        os.makedirs(SHOTS, exist_ok=True)
        app.page.screenshot(path=os.path.join(SHOTS, name), full_page=False)


def _over(page):
    return page.evaluate('() => document.documentElement.scrollWidth - window.innerWidth')


@pytest.mark.parametrize('layout', LAYOUTS)
def test_runtime_a_guest_row_links_the_job_to_use(open_app, layout):
    app = open_app(layout)
    page = app.page
    _go_to_plan(app, layout)
    _tab(app, 'Protected VMs')
    page.locator('[data-sr-guest-job="101"]').wait_for(timeout=5000)
    # where a failed-over guest runs on the DR site, and the job that keeps it there
    assert page.locator('[data-sr-guest-location="100"]').inner_text() == 'Failed over on Remote as 9100'
    assert page.locator('[data-sr-guest-location="101"]').inner_text() == 'At source'
    assert page.locator('[data-sr-guest-job="100"]').inner_text() == '0 */6 * * *, on Remote as 9100'
    assert page.locator('[data-sr-guest-job="101"]').inner_text() == 'Not linked'
    assert _over(page) == 0
    _snap(app, f'sr-guest-job-{layout}.png')

    page.locator('[data-sr-guest-job="101"] span').first.click()
    pick = page.locator('[data-sr-guest-job="101"] select')
    pick.wait_for(timeout=5000)
    # its own jobs between the plan's clusters, told apart by the replica's VMID
    assert pick.locator('option').all_inner_texts() == [
        'Not linked', '0 */2 * * *, on Remote as 101', '0 */2 * * *, on Remote as 9101']
    _snap(app, f'sr-guest-job-pick-{layout}.png')
    pick.select_option('j-pinned')
    page.wait_for_function('() => !document.querySelector(\'[data-sr-guest-job="101"] select\')', timeout=5000)
    assert app.server.bodies.get(PUT) == [{'replication_job_id': 'j-pinned'}]
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', LAYOUTS)
def test_runtime_a_run_names_the_vmid_each_guest_has_on_the_dr_site(open_app, layout):
    app = open_app(layout)
    page = app.page
    _go_to_plan(app, layout)
    _tab(app, 'Failover History')
    page.locator('div.cursor-pointer', has_text='emergency').first.click()
    row = page.locator('[data-sr-result="100"]')
    row.wait_for(timeout=5000)
    assert row.locator('td').first.inner_text() == '100 on Remote as 9100'
    # under its own VMID there is nothing to add
    assert page.locator('[data-sr-result="101"] td').first.inner_text() == '101'
    assert page.locator('[data-sr-result="101"] [data-sr-result-dr]').count() == 0
    _snap(app, f'sr-result-dr-vmid-{layout}.png')
    assert not app.errors, app.errors


def test_runtime_a_refused_link_says_why(open_app):
    app = open_app('modern', put=(400, {'error': "replication_job_id names no replication job of this guest "
                                                 "between the plan's clusters"}))
    page = app.page
    _go_to_plan(app, 'modern')
    _tab(app, 'Protected VMs')
    page.locator('[data-sr-guest-job="101"] span').first.click()
    page.locator('[data-sr-guest-job="101"] select').select_option('j-own')
    page.get_by_text('names no replication job of this guest').first.wait_for(timeout=5000)
    assert not app.errors, app.errors


def test_runtime_in_german(open_app):
    app = open_app('modern', language='de')
    page = app.page
    _go_to_plan(app, 'modern')
    _tab(app, 'Geschützte VMs')
    page.locator('[data-sr-guest-job="101"]').wait_for(timeout=5000)
    assert page.locator('[data-sr-guest-location="100"]').inner_text() == 'Umgeschaltet auf Remote als 9100'
    assert page.locator('[data-sr-guest-job="100"]').inner_text() == '0 */6 * * *, auf Remote als 9100'
    assert page.locator('[data-sr-guest-job="101"]').inner_text() == 'Nicht verknüpft'
    assert not app.errors, app.errors
