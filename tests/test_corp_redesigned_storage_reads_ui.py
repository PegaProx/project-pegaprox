"""Corporate Redesigned, the storage views against what the server answers now.

Storage Balancing takes the balancing status at its word: a member it could not use is left out
with the server's own state (missing, inactive, unavailable, no size, unreadable), never "counted at
0 %"; a member of one node that the server read on that node is a member with figures; a running
container is a move the server refuses, so it carries the reason and no preview; why no member could
be read (read_error) is said; and the tolerance the server keeps is offered in the create dialog and
on a group. A failed read of the datastore list, of the ESXi hosts or of one host's VMs is shown as
failed with a retry, never as "No datastores", "No ESXi hosts connected" or the VMs of the host
picked before. The auto-sync switch of ISO Sync is offered, and an upload to a node's own storage is
copied once its Proxmox VE task ended well. ISO Sync names the nodes the server could not read.

The fake serves the shapes of pegaprox/api/storage.py (status members with usable/state/node/shared,
recommendations with movable/blocked/blocked_reason, tolerance on create and PUT), vms.py
(/datastores, the upload answer with its upid), esxi-hosts and the iso-sync routes (with unread).
PEGAPROX_CR_BUNDLE=<file> serves another bundle (the counterproof). Skips without Playwright.
LW Nov 2026
"""
import copy
import json
import re

import pytest

from test_corp_redesigned_storage_ui import (CEPH_A, DATASTORES, GIB, G_CEPH, STATUS_CEPH, _SbServer, _balancing, _cells,
                                             _errors as _sb_errors, _group, _open_group, _rec, _sbad, _sst, _verdict)
from test_corp_redesigned_storage_ui import BUNDLE, LAYOUT, browser, playwright  # noqa: F401 (fixtures)
from test_corp_redesigned_guard_ui import FIXED, TASKS, _GuardApp, _upid
from test_ha_ui import BASE

DS_PATH = '/api/clusters/c1/datastores'


class _ReadServer(_SbServer):
    """The balancing fake, whose /datastores read can fail (both the dashboard's and the tab's read):
    ds_answer (status, body) or 'abort'; and the upload route of vms.py."""

    def __init__(self, ds_answer=None, **kw):
        super().__init__(**kw)
        self.ds_answer = ds_answer
        self.ds_reads = 0
        self.uploads = []

    def handle(self, route):
        req = route.request
        path = re.sub(r'^https?://[^/]+', '', req.url).split('?')[0]
        if req.url.startswith(BASE) and req.method == 'GET' and path == DS_PATH:
            self.ds_reads += 1
            if self.ds_answer == 'abort':
                self.calls.append((req.method, path))
                return route.abort('connectionrefused')
            if self.ds_answer:
                self.calls.append((req.method, path))
                code, body = self.ds_answer
                return route.fulfill(status=code, body=json.dumps(body), headers={'Content-Type': 'application/json'})
        m = re.fullmatch(r'/api/clusters/c1/datastores/([^/]+)/upload', path)
        if req.url.startswith(BASE) and req.method == 'POST' and m:
            self.calls.append((req.method, path))
            self.uploads.append(m.group(1))
            # vms.py upload_to_datastore: the PVE task that stores the file
            return route.fulfill(status=200, headers={'Content-Type': 'application/json'},
                                 body=json.dumps({'success': True, 'message': 'Upload started: small.iso',
                                                  'upid': _upid('pve1', 77, 'imgcopy', '')}))
        return super().handle(route)


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(layout=LAYOUT, storage=None, viewport=(1600, 1000), **kw):
        app = _GuardApp(browser, _ReadServer(layout=layout, bundle=BUNDLE, **kw), storage=storage, viewport=viewport)
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.close()


def _errors(app):
    # the console lines of the dashboard's and the tab's authFetch for a request that got no answer
    return [e for e in _sb_errors(app) if 'authFetch err: TypeError: Failed to fetch' not in e]


def _need(page, selector, what, timeout=8000):
    try:
        page.locator(selector).first.wait_for(timeout=timeout)
    except Exception:
        raise AssertionError(f'{what} (no {selector})') from None


def _browse(app):
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.locator('[data-cr-tab="datastore"]').click()
    _need(page, '[data-cr-ds]', 'the Browse tab of the layout')
    return page


def _puts(app):
    return [w for w in app.server.writes if w[0] == 'PUT']


# --- the tolerance the server keeps ----------------------------------------------------------

def test_runtime_e1_a_group_offers_its_tolerance_and_sends_it(open_app):
    g = _group('a1b2c3d4', 'Ceph pools', ['ceph-a', 'ceph-b'], tolerance=3)
    app = open_app(groups=[g, copy.deepcopy(G_CEPH) | {'id': 'z9', 'name': 'Zeta'}])
    page = _balancing(app)
    _open_group(page, 'Ceph pools')
    sel = page.locator('[data-cr-sb-tolerance]')
    _need(page, '[data-cr-sb-tolerance]', 'a group has the tolerance of the classic slider')
    assert sel.input_value() == '3'
    assert sel.locator('option').count() == 21, 'the classic range 0 to 20'
    # the trigger the server works with: threshold 20 plus the stored 3
    assert 'Acts above 23 points' in page.locator('[data-cr-sb-cadence]').inner_text()
    sel.select_option('8')
    page.wait_for_function('() => /Acts above 28 points/.test(document.querySelector("[data-cr-sb-cadence]").innerText)', timeout=5000)
    assert _puts(app) == [('PUT', '/api/clusters/c1/storage-clusters/a1b2c3d4', {'tolerance': 8})], _puts(app)
    assert app.server.groups[0]['tolerance'] == 8
    assert 'server margin of 8' in page.locator('[data-cr-sb-kv]').inner_text()
    assert _errors(app) == []


def test_runtime_e1_the_create_dialog_asks_for_the_tolerance(open_app):
    app = open_app(groups=[])
    page = _balancing(app)
    page.locator('[data-cr-sb-empty] [data-cr-sb-create]').click()
    dlg = page.locator('div.fixed.inset-0', has=page.locator('h3', has_text='Create Storage Cluster'))
    dlg.wait_for(timeout=4000)
    assert dlg.get_by_text('Migration Tolerance').count() == 1
    ranges = dlg.locator('input[type="range"]')
    assert ranges.count() == 2, 'threshold and tolerance, as classic'
    # the tolerance slider set to 12 the way a user drags it
    ranges.nth(1).evaluate('''(el) => { const set = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
        set.call(el, '12'); el.dispatchEvent(new Event('input', { bubbles: true })); el.dispatchEvent(new Event('change', { bubbles: true })); }''')
    dlg.locator('input[type="text"]').fill('Fast pools')
    for name in ('ceph-a', 'ceph-b'):
        dlg.locator('label', has_text=re.compile(rf'^\s*{name}\s*$')).locator('input').check()
    dlg.locator('button', has_text=re.compile(r'^\s*Create\s*$')).click()
    page.locator('[data-cr-table="sb-groups"] tbody tr.cr-row', has_text='Fast pools').wait_for(timeout=5000)
    post = [w for w in app.server.writes if w[0] == 'POST' and w[1].endswith('/storage-clusters')]
    assert len(post) == 1 and post[0][2]['tolerance'] == 12, post
    assert _errors(app) == []


# --- a move the server refuses ----------------------------------------------------------------

def test_runtime_e2_a_running_container_carries_the_reason_and_no_preview(open_app):
    app = open_app()
    page = _balancing(app)
    _open_group(page, 'Ceph pools')
    # ct01 runs: the status marks it movable false, blocked ct_running (storage.py:1159-1163)
    assert page.locator('[data-cr-sb-preview="101|rootfs|ceph-b"]').count() == 0
    cell = page.locator('[data-cr-sb-refused="ct_running"]')
    assert cell.count() == 1 and 'only while it is stopped' in cell.get_attribute('title')
    note = page.locator('[data-cr-sb-refused-note]').inner_text()
    assert '1 of them cannot be moved now' in note and 'Container is running' in note, note
    recs = {r['guest']: r for r in _cells(page, 'sb-recs')}
    assert recs['ct01 CT 101']['risks'] == 'Blocked', recs
    # the two VM disks keep their preview
    assert page.locator('[data-cr-sb-preview]').count() == 2
    assert _errors(app) == []


def test_runtime_e2_a_stopped_container_moves_without_the_old_warning(open_app):
    st = dict(STATUS_CEPH, recommendations=[_rec(101, 'ct01', 'stopped', 'rootfs', 'ceph-a', 'ceph-b', 8 * GIB, 82.0, 41.5)])
    app = open_app(statuses={'a1b2c3d4': (200, st)})
    page = _balancing(app)
    _open_group(page, 'Ceph pools')
    page.locator('[data-cr-sb-preview="101|rootfs|ceph-b"]').click()
    dlg = page.locator('[data-cr-sb-dialog]')
    dlg.wait_for(timeout=4000)
    risks = dlg.locator('[data-cr-sb-risk]').evaluate_all('rs => rs.map(r => r.dataset.crSbRisk)')
    # the server moves a stopped container with move_volume now: no "PVE will likely refuse"
    assert 'crSbRiskContainer' not in risks and 'will likely refuse' not in dlg.inner_text(), risks
    assert not dlg.locator('[data-cr-sb-confirm]').is_disabled()
    dlg.locator('[data-cr-sb-confirm]').click()
    dlg.wait_for(state='detached', timeout=5000)
    posts = [w for w in app.server.writes if w[0] == 'POST']
    assert posts == [('POST', '/api/clusters/c1/storage-balancing/migrate', {'vmid': 101, 'disk': 'rootfs', 'target': 'ceph-b'})], posts
    assert _errors(app) == []


# --- the members as the server judged them -----------------------------------------------

def test_runtime_e3_an_unusable_member_has_the_servers_state_and_no_zero(open_app):
    ds = dict(DATASTORES, shared=DATASTORES['shared'] + [
        dict(CEPH_A, storage='pbs-wui', type='pbs', content='backup,images')])
    g = _group('u1', 'Odd', ['ceph-a', 'ceph-b', 'pbs-wui', 'old-nfs'])
    st = {'id': 'u1', 'name': 'Odd', 'enabled': True, 'imbalance': 40.5, 'threshold': 20, 'tolerance': 5, 'read_error': None,
          'storages': [_sst('ceph-a', 'rbd', 1000, 820), _sst('ceph-b', 'rbd', 1000, 415),
                       _sbad('pbs-wui', 'pbs', 'unavailable'), _sbad('old-nfs', None, 'missing', node='pve1', shared=None)],
          'recommendations': [], '_stats': {}}
    app = open_app(datastores=ds, groups=[g], statuses={'u1': (200, st)})
    page = _balancing(app)
    _open_group(page, 'Odd')
    why = page.locator('[data-cr-sb-why][data-cr-sb-from="server"]').evaluate_all('xs => xs.map(x => [x.dataset.crSbWhy, x.textContent])')
    assert why == [['unavailable', 'Not available on any node that is online'], ['missing', 'Not listed by pve1']], why
    detail = page.locator('[data-cr-sb-detail]').inner_text()
    assert 'Counted by the server at 0%' not in detail and 'takes it as 0%' not in detail, detail
    assert page.locator('[data-cr-sb-note="counted"]').count() == 0
    assert page.locator('[data-cr-sb-member="pbs-wui"] [data-cr-sb-nofig]').inner_text() == 'Left out of the spread'
    # the spread is the server's over the two it could read
    assert _verdict(page) == 'above' and page.locator('[data-cr-sb-own]').count() == 0
    assert _errors(app) == []


def test_runtime_e4_why_no_member_could_be_read_is_said(open_app):
    st = {'id': 'a1b2c3d4', 'name': 'Ceph pools', 'enabled': True, 'imbalance': None, 'threshold': 20, 'tolerance': 5,
          'storages': [_sbad('ceph-a', None, 'unreadable'), _sbad('ceph-b', None, 'unreadable')],
          'read_error': 'The node list could not be read (HTTP 500)', 'recommendations': [], '_stats': {}}
    app = open_app(statuses={'a1b2c3d4': (200, st)})
    page = _balancing(app)
    _open_group(page, 'Ceph pools')
    assert _verdict(page) == 'unknown'
    err = page.locator('[data-cr-sb-read-error]')
    _need(page, '[data-cr-sb-read-error]', 'the reason of the server under "cannot be judged"')
    assert 'The node list could not be read (HTTP 500)' in err.inner_text()
    # the members say they could not be read, the old "first node" sentence is gone
    assert page.locator('[data-cr-sb-why="unreadable"]').count() == 2
    assert 'first node' not in page.locator('[data-cr-sb-detail]').inner_text()
    assert _errors(app) == []


# --- a member of one node ----------------------------------------------------------------------

def test_runtime_e8_a_local_member_the_server_read_is_a_member_with_figures(open_app):
    g = _group('l1', 'With local', ['ceph-a', 'local'])
    st = {'id': 'l1', 'name': 'With local', 'enabled': True, 'imbalance': 52.0, 'threshold': 20, 'tolerance': 5, 'read_error': None,
          'storages': [_sst('ceph-a', 'rbd', 1000, 820), _sst('local', 'dir', 100, 30, node='pve1', shared=False)],
          'recommendations': [_rec(100, 'web01', 'running', 'scsi0', 'ceph-a', 'local', 8 * GIB, 82.0, 30.0)], '_stats': {}}
    app = open_app(groups=[g], statuses={'l1': (200, st)})
    page = _balancing(app)
    _open_group(page, 'With local')
    member = page.locator('[data-cr-sb-member="local"]')
    assert member.get_attribute('data-cr-sb-usable') == '1'
    assert member.locator('[data-cr-sb-why]').count() == 0, 'no "Not shared" badge for a member the server read'
    assert member.locator('[data-cr-sb-local="pve1"]').inner_text().strip().endswith('local storage, figures of pve1')
    assert member.locator('[data-cr-sb-pct]').inner_text() == '30.0%'
    assert page.locator('[data-cr-sb-risk-n="blocked"]').count() == 0
    page.locator('[data-cr-sb-preview="100|scsi0|local"]').click()
    dlg = page.locator('[data-cr-sb-dialog]')
    dlg.wait_for(timeout=4000)
    risks = dlg.locator('[data-cr-sb-risk]').evaluate_all('rs => rs.map(r => r.dataset.crSbRisk)')
    assert 'crSbRiskTargetDown' not in risks and not dlg.locator('[data-cr-sb-confirm]').is_disabled(), risks
    dlg.locator('[data-cr-sb-cancel]').click()
    assert _errors(app) == []


# --- a failed read of the datastore list ---------------------------------------------------------

@pytest.mark.parametrize('case', ['503', '500', 'abort'])
def test_runtime_e5_a_failed_datastore_read_is_not_an_empty_estate(open_app, case):
    answer = {'503': (503, {'error': 'Cluster not connected', 'offline': True}),
              '500': (500, {'error': 'Failed to get datastores'}), 'abort': 'abort'}[case]
    app = open_app(ds_answer=answer, storage={'pegaprox-sidebar-view': 'datastores'})
    page = _browse(app)
    note = page.locator('[data-cr-ds-list-failed="unread"]')
    _need(page, '[data-cr-ds-list-failed="unread"]', 'the Browse panel says the list could not be read')
    text = note.inner_text()
    assert 'could not be read' in text, text
    if case == '503':
        assert 'Cluster not connected - HTTP 503' in text, text
    assert page.locator('.cr-ds-side .cr-ds-count').first.inner_text() == '-'
    assert 'No datastores' not in page.locator('[data-cr-ds]').inner_text()
    # the sidebar says it too, with its own retry
    tree = page.locator('[data-cr-ds-tree-failed="unread"]')
    _need(page, '[data-cr-ds-tree-failed="unread"]', 'the sidebar datastore view says the read failed')
    assert tree.inner_text().startswith('Datastores could not be read')
    # the retry reads again and shows what the server has now
    app.server.ds_answer = None
    note.locator('button', has_text='Retry').click()
    _need(page, '[data-cr-ds-row="s:ceph-a@"]', 'the retry fills the list')
    assert page.locator('[data-cr-ds-list-failed]').count() == 0
    assert _errors(app) == []


def test_runtime_e5_balancing_does_not_judge_members_against_an_unread_list(open_app):
    app = open_app(ds_answer=(503, {'error': 'Cluster not connected', 'offline': True}))
    page = _balancing(app)
    page.locator('[data-cr-table="sb-groups"] tbody tr.cr-row').nth(2).wait_for(timeout=5000)
    states = [r['state'] for r in _cells(page, 'sb-groups')]
    assert states == ['List not read'] * 3, states
    assert 'not found' not in page.locator('[data-cr-table="sb-groups"]').inner_text()
    assert 'Cluster not connected' in page.locator('[data-cr-sb-note="ds-failed"]').inner_text()
    assert _errors(app) == []


# --- the ESXi reads ------------------------------------------------------------------------------

ESXI_TWO = [{'id': 'e1', 'host': '10.10.0.11', 'connected': True}, {'id': 'e2', 'host': '10.10.0.12', 'connected': True}]
ESXI_A_VMS = [{'id': 'vm-1', 'name': 'db-a', 'guest_os': 'Debian 12', 'num_cpu': 2, 'memory_mb': 4096, 'volid': 'esxi-a:db-a'},
              {'id': 'vm-2', 'name': 'web-a', 'guest_os': 'Debian 12', 'num_cpu': 2, 'memory_mb': 2048, 'volid': 'esxi-a:web-a'}]


def test_runtime_e6_a_failed_vm_read_never_shows_the_host_before(open_app):
    app = open_app(esxi=ESXI_TWO, extra={('GET', '/api/clusters/c1/esxi-hosts/e1/vms'): (200, ESXI_A_VMS),
                                         ('GET', '/api/clusters/c1/esxi-hosts/e2/vms'): (500, {'error': 'Failed to get VM list from ESXi'})})
    page = _browse(app)
    page.locator('[data-cr-ds-group="esxi"]').click()
    page.locator('[data-cr-ds-row="e:e1"]').click()
    page.locator('[data-cr-table="ds-esxi"] tbody tr.cr-row', has_text='db-a').wait_for(timeout=5000)
    page.locator('[data-cr-ds-row="e:e2"]').click()
    err = page.locator('[data-cr-ds-esxi-error]')
    _need(page, '[data-cr-ds-esxi-error]', 'the VM read of the second host says it failed')
    assert 'Failed to get VM list from ESXi - HTTP 500' in err.inner_text()
    assert page.locator('[data-cr-ds-head="esxi"] .cr-ds-where').inner_text() == '10.10.0.12'
    assert 'db-a' not in page.locator('.cr-ds-main').inner_text(), 'the VMs of the host before are not under this one'
    assert _errors(app) == []


def test_runtime_e6_a_failed_host_list_is_not_no_hosts(open_app):
    app = open_app(extra={('GET', '/api/clusters/c1/esxi-hosts'): (500, {'error': 'Database is locked'})})
    page = _browse(app)
    _need(page, '[data-cr-ds-esxi-hosts-failed]', 'the side panel says the host list could not be read')
    assert 'Database is locked' in page.locator('[data-cr-ds-esxi-hosts-failed]').inner_text()
    page.locator('[data-cr-ds-group="esxi"]').click()
    side = page.locator('.cr-ds-side').inner_text()
    assert 'No ESXi hosts connected' not in side and 'Not read' in side, side
    assert page.locator('[data-cr-ds-group="esxi"] [data-cr-ds-group-n]').inner_text() == '-'
    assert _errors(app) == []


# --- a content read Proxmox VE refused ------------------------------------------------

def test_runtime_e9_a_refused_content_read_is_said_by_its_code(open_app):
    app = open_app()
    app.server.content_status['ceph-a'] = (502, {'error': 'Could not read the content of storage ceph-a on pve1: permission denied',
                                                 'code': 'PVE_READ_FAILED', 'upstream_status': 500, 'node': 'pve1', 'storage': 'ceph-a'})
    page = _browse(app)
    page.locator('[data-cr-ds-row="s:ceph-a@"]').click()
    err = page.locator('[data-cr-table="ds-content"] td.cr-state-error')
    err.wait_for(timeout=5000)
    assert err.inner_text().strip().startswith('Proxmox VE could not answer it - Could not read the content'), err.inner_text()
    assert page.locator('[data-cr-table="ds-content"]').get_by_text('This storage is empty').count() == 0
    assert _errors(app) == []


# --- auto-sync after an upload -------------------------------------------------------------------

def test_runtime_e10_the_switch_is_offered_and_kept_in_the_browser(open_app):
    app = open_app()
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.locator('[data-cr-tab="datastore"]').click()
    page.locator('.corp-tab-strip button', has_text='ISO Sync').first.click()
    box = page.locator('[data-cr-iso-auto]')
    _need(page, '[data-cr-iso-auto]', 'ISO Sync offers the auto-sync switch of the classic checkbox')
    assert not box.is_checked() and not box.is_disabled()
    box.check()
    assert page.evaluate("() => localStorage.getItem('autosync-c1')") == 'true'
    assert page.locator('[data-cr-iso-auto-state]').get_attribute('data-cr-iso-auto-state') == 'on'
    box.uncheck()
    assert page.evaluate("() => localStorage.getItem('autosync-c1')") == 'false'
    assert _errors(app) == []


def test_runtime_e10_an_upload_is_copied_once_its_task_ended_well(open_app):
    up = _upid('pve1', 77, 'imgcopy', '')
    app = open_app(storage={'autosync-c1': 'true'}, tasks=list(TASKS),
                   extra={('POST', '/api/clusters/c1/iso-sync'): (200, {'success': True, 'message': 'Sync started for small.iso'})})
    page = _browse(app)
    page.locator('[data-cr-ds-row="s:local@pve1"]').click()
    page.locator('[data-cr-ds-action="upload"]').click()
    page.locator('input[type="file"]').set_input_files(files=[{'name': 'small.iso', 'mimeType': 'application/octet-stream', 'buffer': b'x' * 64}])
    page.locator('div.fixed.inset-0 button', has_text=re.compile(r'^\s*Upload\s*$')).click()
    page.wait_for_function('() => !document.querySelector("input[type=file]")', timeout=8000)
    assert app.server.uploads == ['local']
    # the task is running: nothing is copied yet
    app.server.extra[('GET', '/api/clusters/c1/tasks')] = (200, list(TASKS) + [
        {'upid': up, 'node': 'pve1', 'type': 'imgcopy', 'status': 'running', 'starttime': FIXED - 5, 'user': 'root@pam'}])
    page.evaluate("() => window.dispatchEvent(new CustomEvent('cr-tc-open', { detail: { cluster: 'c1', q: '' } }))")
    page.locator('[data-cr-tc-refresh]').first.click()
    page.wait_for_timeout(800)
    assert ('POST', '/api/clusters/c1/iso-sync') not in app.server.calls
    # it ended well: one copy of that file from that node and storage
    app.server.extra[('GET', '/api/clusters/c1/tasks')] = (200, list(TASKS) + [
        {'upid': up, 'node': 'pve1', 'type': 'imgcopy', 'status': 'stopped', 'exitstatus': 'OK', 'starttime': FIXED - 5,
         'endtime': FIXED - 1, 'user': 'root@pam'}])
    page.locator('[data-cr-tc-refresh]').first.click()
    page.wait_for_function('() => true')
    for _ in range(40):
        if app.server.bodies.get('/api/clusters/c1/iso-sync'):
            break
        page.wait_for_timeout(100)
    assert app.server.bodies.get('/api/clusters/c1/iso-sync') == [
        {'source_node': 'pve1', 'storage': 'local', 'filename': 'small.iso', 'content_type': 'iso'}], app.server.bodies.get('/api/clusters/c1/iso-sync')
    page.locator('[data-cr-tc-refresh]').first.click()
    page.wait_for_timeout(500)
    assert len(app.server.bodies['/api/clusters/c1/iso-sync']) == 1, 'one copy per upload'
    assert _errors(app) == []


def test_runtime_e10_without_the_switch_an_upload_is_not_copied(open_app):
    up = _upid('pve1', 77, 'imgcopy', '')
    app = open_app(tasks=list(TASKS) + [{'upid': up, 'node': 'pve1', 'type': 'imgcopy', 'status': 'stopped', 'exitstatus': 'OK',
                                         'starttime': FIXED - 5, 'endtime': FIXED - 1, 'user': 'root@pam'}])
    page = _browse(app)
    page.locator('[data-cr-ds-row="s:local@pve1"]').click()
    page.locator('[data-cr-ds-action="upload"]').click()
    page.locator('input[type="file"]').set_input_files(files=[{'name': 'small.iso', 'mimeType': 'application/octet-stream', 'buffer': b'x' * 64}])
    page.locator('div.fixed.inset-0 button', has_text=re.compile(r'^\s*Upload\s*$')).click()
    page.wait_for_function('() => !document.querySelector("input[type=file]")', timeout=8000)
    page.evaluate("() => window.dispatchEvent(new CustomEvent('cr-tc-open', { detail: { cluster: 'c1', q: '' } }))")
    page.locator('[data-cr-tc-refresh]').first.click()
    page.wait_for_timeout(800)
    assert ('POST', '/api/clusters/c1/iso-sync') not in app.server.calls
    assert _errors(app) == []


# --- nodes the ISO sync status could not read ----------------------------------------

def test_runtime_e11_a_node_the_server_could_not_read_is_named_with_its_reason(open_app):
    status = {'nodes': ['pve1'], 'files': [{'name': 'debian-12.iso', 'storage': 'local', 'size': 600 * 1024 ** 2}],
              'matrix': {'local:debian-12.iso': {'pve1': True}},
              'unread': {'pve2': 'The storage list of pve2 could not be read (HTTP 500)'}}
    app = open_app(extra={('GET', '/api/clusters/c1/iso-sync/status'): (200, status),
                          ('GET', '/api/clusters/c1/iso-sync/last-result'): (200, {})})
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.locator('[data-cr-tab="datastore"]').click()
    page.locator('.corp-tab-strip button', has_text='ISO Sync').first.click()
    _need(page, '[data-cr-iso-unread-nodes]', 'the page names the node the server could not read')
    text = page.locator('[data-cr-iso-unread-nodes]').inner_text()
    assert 'pve2 (The storage list of pve2 could not be read (HTTP 500))' in text, text
    assert page.locator('[data-cr-iso-node-unread="pve2"]').inner_text() == 'Not read'
    assert _errors(app) == []
