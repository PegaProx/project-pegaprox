"""The bulk migration dialog, its progress and the card that keeps it in reach (#952).

The bulk bar of the table (Modern, Corporate), the bulk bar of the Cloud list and the
"Migrate all" of a node open one dialog: target, live, local disks and how the guests go,
one at a time from four guests on, a few at a time or all at once. The run is the
server's; the page shows its progress in a dialog and a card above the toasts that stays
through other pages and a reload, and says what a restart of PegaProx does to it.

The source checks read web/src and the bundle. The runtime tests drive the built bundle in
headless Chromium: the page around it comes from the fake server of tests/test_ha_ui.py,
the bulk migrate route and the run routes are the real routes of the app, whose run
works against the faked cluster manager of tests/test_bulk_migrate_runs_952.py. They skip
where Playwright is not installed.

LW Oct 2026
"""
import json
import os
import re
import time

import pytest

from test_ha_ui import (BASE, LANGS, _App, _FakeServer, _blocks, _classes,  # noqa: F401 (browser is a fixture)
                        browser)
from test_bulk_migrate_runs_952 import _Pve, _wait

from pegaprox.core import bulk_migrate as bulk

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def _function(src, head):
    start = src.index(head)
    nxt = src.find('\n        function ', start + 10)
    return src[start:nxt if nxt > 0 else len(src)]


# -- source ------------------------------------------------------------------------------------

def _used_keys():
    keys = set()
    for name in ('vm_modals.js', 'dashboard.js', 'cloud.js', 'settings_modal.js', 'tables.js'):
        keys.update(re.findall(r"t\('(migRun\w+)'\)", _read('web', 'src', name)))
    return sorted(keys)


def _new_code():
    modals = _read('web', 'src', 'vm_modals.js')
    dash = _read('web', 'src', 'dashboard.js')
    cloud = _read('web', 'src', 'cloud.js')
    parts = [modals[modals.index('// Bulk Migrate Modal Component'):modals.index('// LW Oct 2026 - the bulk bar of the guest table')],
             modals[modals.index('// LW Oct 2026 (#952) - the bulk migrations of the signed-in user'):modals.index('// Cross-Cluster Migration Modal')],
             _function(modals, 'function NodeGuestsModal('),
             dash[dash.index('// LW Oct 2026 (#952) - a bulk migration is a run'):dash.index('const handleCreateVm')],
             cloud[cloud.index('LW Oct 2026 (#952) - one dialog'):cloud.index("<button type=\"button\" className=\"cloud-sel-clear\"")]]
    return parts


def test_the_new_strings_are_their_own_keys():
    keys = _used_keys()
    assert len(keys) == 29, keys
    assert {'migRunOne', 'migRunServerNote', 'migRunGone', 'migRunAuditFinished'} <= set(keys)


@pytest.mark.parametrize('lang', LANGS)
def test_every_new_key_exists_once_per_language(lang):
    block = _blocks()[lang]
    for key in _used_keys():
        n = len(re.findall(r'^ +%s: ' % key, block, re.M))
        assert n == 1, f'{key} appears {n} times in {lang}'
    # what the node dialog asked before is gone with it
    assert not re.search(r'^ +nodeGuestsParallel: ', block, re.M)


def test_no_key_is_defined_that_nothing_uses():
    used = set(_used_keys())
    for lang, block in _blocks().items():
        assert set(re.findall(r'^ +(migRun\w+): ', block, re.M)) == used, lang


def test_placeholders_survive_translation():
    blocks = _blocks()
    for key in _used_keys():
        en = re.search(r'^ +%s: (.*),$' % key, blocks['en'], re.M).group(1)
        for lang, block in blocks.items():
            value = re.search(r'^ +%s: (.*),$' % key, block, re.M).group(1)
            assert sorted(re.findall(r'\{\w+\}', value)) == sorted(re.findall(r'\{\w+\}', en)), (lang, key)


def test_the_austrian_flag_stays_on_german():
    assert "{ code: 'de', flag: '\U0001F1E6\U0001F1F9'," in _read('web', 'src', 'contexts.js')


def test_no_em_dash_in_the_new_code():
    lines = [line for block in _blocks().values() for line in block.splitlines() if 'migRun' in line]
    for text in _new_code() + lines:
        assert '\u2014' not in text and '\u2013' not in text


def test_every_class_is_in_the_static_tailwind_build():
    css = _read('static', 'css', 'tailwind.min.css') + _read('web', 'index.html.original')
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    names = set()
    for part in _new_code():
        names |= _classes(part)
    missing = sorted(n for n in names if n not in have)
    assert not missing, f'not in static/css/tailwind.min.css: {missing}'


def test_every_icon_exists():
    icons = set(re.findall(r'^            ([A-Z][A-Za-z0-9]*):', _read('web', 'src', 'icons.js'), re.M))
    used = set()
    for part in _new_code():
        used |= set(re.findall(r'Icons\.([A-Z][A-Za-z0-9]*)', part))
    assert used and used <= icons, sorted(used - icons)


def test_the_page_polls_per_run_and_never_per_guest():
    """The card reads the list of runs while one of them runs, the dialog its run: two
    requests a few seconds apart whatever the number of guests."""
    modals = _read('web', 'src', 'vm_modals.js')
    runs = _function(modals, 'function BulkMigrateRuns(')
    progress = _function(modals, 'function BulkMigrateProgress(')
    assert 'const MIG_RUN_LIST_MS = 4000;' in modals and 'const MIG_RUN_DETAIL_MS = 2500;' in modals
    assert runs.count('authFetch(') == 1 and '`${API_URL}/bulk-migrations`' in runs
    assert 'if (!anyRunning) return undefined;' in runs
    assert progress.count('authFetch(') == 2 and 'if (!running) return undefined;' in progress
    for part in (runs, progress):
        assert '/vms/' not in part and '/tasks' not in part


def test_the_bundle_was_rebuilt():
    bundle = _read('web', 'index.html')
    for needle in ('function BulkMigrateRuns(', 'function BulkMigrateProgress(', 'function MigRunPlan(',
                   'mig-run-card', 'bulk-migrate-run', '/bulk-migrations'):
        assert needle in bundle, needle
    for key in _used_keys():
        assert key in bundle, key
    assert 'node-guests-workers' not in bundle


# -- runtime: the built bundle against the real routes ----------------------------------------

SHOTS = os.environ.get('PEGAPROX_UI_SHOTS', '')
CLUSTER = {'id': 'cluster_1', 'name': 'Testi', 'display_name': 'Testi', 'host': '10.0.0.1',
           'connected': True, 'status': 'running', 'cluster_type': 'proxmox', 'enabled': True}
_LOAD = {'cpu': 0.05, 'cpu_percent': 5, 'maxcpu': 2, 'mem': 1073741824, 'maxmem': 4294967296,
         'mem_percent': 25, 'disk': 0, 'maxdisk': 34359738368, 'uptime': 3600}
GUESTS = [
    dict(_LOAD, vmid=100, name='web01', type='qemu', status='running', node='pve1'),
    dict(_LOAD, vmid=101, name='db01', type='qemu', status='running', node='pve1'),
    dict(_LOAD, vmid=102, name='cache01', type='qemu', status='running', node='pve1'),
    dict(_LOAD, vmid=200, name='ct01', type='lxc', status='running', node='pve1'),
    dict(_LOAD, vmid=201, name='ct02', type='lxc', status='stopped', node='pve1'),
]
_NODE = {'status': 'online', 'cpu_percent': 5.0, 'mem_percent': 20.0, 'disk_percent': 10.0, 'score': 42.0,
         'uptime': 86400, 'loadavg': [0.1, 0.2, 0.3], 'netin': 0, 'netout': 0, 'mem_used': 6871947673,
         'mem_total': 34359738368, 'disk_used': 10737418240, 'disk_total': 107374182400,
         'pveversion': 'pve-manager/9.0.3', 'kversion': 'Linux 6.14.8-2-pve',
         'cpuinfo': {'cpus': 8, 'cores': 4, 'sockets': 1}, 'maintenance_mode': False, 'is_updating': False}
METRICS = {'pve1': dict(_NODE), 'pve2': dict(_NODE), 'pve3': dict(_NODE, status='offline')}
# what the page sends to the app instead of the fake server
REAL = re.compile(r'^/api/(clusters/cluster_1/vms/bulk-migrate|bulk-migrations(/[0-9a-f]+(/cancel)?)?)$')


class _Server(_FakeServer):
    """The page from the fake server; the bulk migration routes from the app."""

    def __init__(self, client, **kw):
        kw.setdefault('clusters', [CLUSTER])
        kw.setdefault('resources', [dict(g) for g in GUESTS])
        kw.setdefault('metrics', METRICS)
        kw.setdefault('role', 'standalone')
        super().__init__(**kw)
        self.client = client
        self.sent = []

    def handle(self, route):
        req = route.request
        path = re.sub(r'^https?://[^/]+', '', req.url).split('?')[0]
        if not req.url.startswith(BASE) or not REAL.match(path):
            return super().handle(route)
        raw = req.post_data or ''
        self.calls.append((req.method, path))
        if req.method != 'GET':
            self.sent.append((req.method, path, json.loads(raw) if raw else None))
            if self.role == 'standby':
                return route.fulfill(status=409, headers={'Content-Type': 'application/json'}, body=json.dumps(
                    {'error': 'This is a standby instance.', 'code': 'HA_STANDBY'}))
            r = getattr(self.client, req.method.lower())(path, data=raw, headers={'Content-Type': 'application/json'})
        else:
            r = self.client.get(path)
        return route.fulfill(status=r.status_code, body=r.get_data(), headers={'Content-Type': 'application/json'})


@pytest.fixture
def real_app(browser, api, seed, monkeypatch):  # noqa: F811
    monkeypatch.setattr(bulk, 'POLL_SECONDS', 0.05)
    bulk.reset_for_tests()
    apps = []

    def _open(user=None, layout='modern', **kw):
        who = user or seed.user('admin', role='admin')
        if not hasattr(_open, 'pve'):
            _open.pve = _Pve(api, guests=GUESTS)
        app = _App(browser, _Server(api.as_user(who), layout=layout, **kw))
        app.pve = _open.pve
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()
    for run in bulk.runs():
        bulk.cancel(run, 'teardown')
    deadline = time.time() + 5
    while time.time() < deadline and any(r.state == 'running' for r in bulk.runs()):
        for p in _Pve.alive:
            p.finish_all()
        time.sleep(0.02)
    _Pve.alive.clear()
    bulk.reset_for_tests()


def _shot(app, name):
    if SHOTS:
        os.makedirs(SHOTS, exist_ok=True)
        app.page.screenshot(path=os.path.join(SHOTS, f'{name}.png'))


def _open_resources(app, layout):
    page = app.page
    if layout == 'corporate':
        page.locator('.corp-tree-item', has_text='Testi').first.click()
    else:
        page.get_by_text('Testi').first.click()
    page.locator('button', has_text='Resources').first.click()
    page.get_by_text('web01').first.wait_for(timeout=5000)
    if layout == 'modern':
        page.locator('button[title="List View"]').first.click()
    page.locator('table thead input[type="checkbox"]').first.wait_for(timeout=5000)
    page.wait_for_timeout(200)


def _tick(app, *vmids):
    page = app.page
    for vmid in vmids:
        row = page.locator('table tbody tr', has=page.locator('td', has_text=re.compile(rf'^{vmid}$')))
        row.locator('input[type="checkbox"]').first.check()


def _dialog(app):
    app.page.locator('button[data-bulk="migrate"]').first.click()
    modal = app.page.locator('[data-testid="bulk-migrate-modal"]')
    modal.wait_for(timeout=3000)
    return modal


def _mode(modal):
    return modal.locator('[data-mig-mode] input:checked').evaluate('e => e.closest("[data-mig-mode]").dataset.migMode')


def _row_states(app):
    return app.page.evaluate('''() => Object.fromEntries(Array.from(document.querySelectorAll(
        '[data-testid="mig-run-rows"] [data-guest]')).map(r => [r.dataset.guest, r.querySelector('[data-state]').dataset.state]))''')


def _wait_rows(app, want, seconds=10):
    for _ in range(int(seconds * 10)):
        if _row_states(app) == want:
            return
        app.page.wait_for_timeout(100)
    assert _row_states(app) == want


def _until(app, cond, seconds=10, what='condition'):
    # page.wait_for_timeout and not time.sleep: the routes of the page are answered in between
    for _ in range(int(seconds * 10)):
        if cond():
            return
        app.page.wait_for_timeout(100)
    assert cond(), f'timed out waiting for {what}'


def _bodies(app):
    return [b for m, p, b in app.server.sent if p.endswith('/vms/bulk-migrate')]


def test_runtime_one_at_a_time_from_the_table_survives_other_pages_and_a_reload(real_app):
    app = real_app(layout='modern')
    page, pve = app.page, None
    _open_resources(app, 'modern')
    _tick(app, 100, 101, 102, 200)
    modal = _dialog(app)
    # four guests: one at a time unless picked otherwise
    assert _mode(modal) == 'sequential'
    assert 'closing this window, going to another page or reloading does not stop it' in modal.inner_text()
    assert modal.locator('[data-testid="bulk-migrate-target"]').evaluate(
        's => Array.from(s.options).map(o => o.value)') == ['', 'pve2', 'pve3']
    assert modal.locator('[data-testid="bulk-migrate-run"]').is_disabled()
    modal.locator('[data-testid="bulk-migrate-target"]').select_option('pve2')
    _shot(app, 'bulk-migrate-dialog-modern')
    modal.locator('[data-testid="bulk-migrate-run"]').click()
    progress = page.locator('[data-testid="mig-run-modal"]')
    progress.wait_for(timeout=5000)
    pve = app.pve
    assert _bodies(app) == [{'vms': [{'vmid': v, 'node': 'pve1', 'type': t} for v, t in
                                     ((100, 'qemu'), (101, 'qemu'), (102, 'qemu'), (200, 'lxc'))],
                             'target': 'pve2', 'online': True, 'with_local_disks': False, 'mode': 'sequential'}]
    _wait_rows(app, {'100': 'migrating', '101': 'wait', '102': 'wait', '200': 'wait'})
    assert 'Bulk migration to pve2' in progress.inner_text() and 'One at a time' in progress.inner_text()
    _shot(app, 'bulk-migrate-progress-modern')
    pve.finish(100)
    _wait_rows(app, {'100': 'done', '101': 'migrating', '102': 'wait', '200': 'wait'})
    assert pve.order() == [100, 101] and pve.peak == 1

    # closed and elsewhere in the app: the card stays and opens it again
    progress.locator('[data-testid="mig-run-close"]').click()
    card = page.locator('[data-testid="mig-run-card"]')
    card.wait_for(timeout=3000)
    assert 'Migrating to pve2' in card.inner_text()
    _until(app, lambda: '1 of 4 done, 0 failed' in card.inner_text(), what='the card to count the first one')
    page.locator('button', has_text='Overview').first.click()
    page.wait_for_timeout(300)
    assert card.count() == 1
    _shot(app, 'bulk-migrate-card-modern')

    # a reload: the run is the server's, the card comes back
    page.reload()
    app.wait_for_app()
    card.wait_for(timeout=8000)
    pve.finish(101)
    card.click()
    progress.wait_for(timeout=3000)
    _wait_rows(app, {'100': 'done', '101': 'done', '102': 'migrating', '200': 'wait'})
    pve.finish(102, 'migration aborted')
    _wait_rows(app, {'100': 'done', '101': 'done', '102': 'failed', '200': 'migrating'})
    assert 'migration aborted' in progress.locator('[data-testid="mig-run-rows"]').inner_text()
    pve.finish(200)
    _wait_rows(app, {'100': 'done', '101': 'done', '102': 'failed', '200': 'done'})
    _until(app, lambda: 'finished' in progress.inner_text(), what='the run to read finished')
    assert '3 of 4 done, 1 failed' in progress.inner_text()
    assert progress.locator('[data-testid="mig-run-cancel"]').count() == 0
    progress.locator('[data-testid="mig-run-close"]').click()
    # the card says it is over until it is put away
    page.locator('[data-testid="mig-run-card"][data-state="done"]').wait_for(timeout=8000)
    assert 'Bulk migration to pve2 finished' in card.inner_text()
    _shot(app, 'bulk-migrate-card-done-modern')
    card.locator('[data-testid="mig-run-dismiss"]').click()
    assert card.count() == 0
    page.reload()
    app.wait_for_app()
    page.wait_for_timeout(800)
    assert card.count() == 0
    assert not app.errors, app.errors


def test_runtime_a_few_at_a_time_and_cancel_the_rest_in_corporate(real_app):
    app = real_app(layout='corporate')
    page = app.page
    _open_resources(app, 'corporate')
    _tick(app, 100, 101, 102, 200, 201)
    modal = _dialog(app)
    modal.locator('[data-mig-mode="parallel"] input[type="radio"]').check()
    modal.locator('[data-testid="mig-run-parallel"]').fill('2')
    modal.locator('[data-testid="bulk-migrate-target"]').select_option('pve2')
    modal.locator('[data-testid="bulk-migrate-local"]').check()
    _shot(app, 'bulk-migrate-dialog-corporate')
    modal.locator('[data-testid="bulk-migrate-run"]').click()
    progress = page.locator('[data-testid="mig-run-modal"]')
    progress.wait_for(timeout=5000)
    body = _bodies(app)[0]
    assert (body['mode'], body['parallel'], body['with_local_disks']) == ('parallel', 2, True)
    _wait_rows(app, {'100': 'migrating', '101': 'migrating', '102': 'wait', '200': 'wait', '201': 'wait'})
    assert app.pve.peak == 2
    _shot(app, 'bulk-migrate-progress-corporate')
    progress.locator('[data-testid="mig-run-cancel"]').click()
    assert 'Migrations already running finish' in progress.locator('[data-testid="mig-run-cancel-ask"]').inner_text()
    progress.locator('[data-testid="mig-run-cancel-yes"]').click()
    _wait_rows(app, {'100': 'migrating', '101': 'migrating', '102': 'cancelled', '200': 'cancelled', '201': 'cancelled'})
    assert 'Cancelled by admin' in progress.inner_text()
    assert ('POST', f"/api/bulk-migrations/{bulk.runs()[0].id}/cancel", None) in app.server.sent
    app.pve.finish_all()
    _wait_rows(app, {'100': 'done', '101': 'done', '102': 'cancelled', '200': 'cancelled', '201': 'cancelled'})
    _until(app, lambda: 'cancelled -' in progress.inner_text(), what='the run to read cancelled')
    assert app.pve.order() == [100, 101]
    _shot(app, 'bulk-migrate-cancelled-corporate')
    assert not app.errors, app.errors


def test_runtime_the_server_forgets_the_run_and_the_page_says_so(real_app):
    app = real_app(layout='modern')
    page = app.page
    _open_resources(app, 'modern')
    _tick(app, 100, 101, 102, 200)
    modal = _dialog(app)
    modal.locator('[data-testid="bulk-migrate-target"]').select_option('pve2')
    modal.locator('[data-testid="bulk-migrate-run"]').click()
    progress = page.locator('[data-testid="mig-run-modal"]')
    _wait_rows(app, {'100': 'migrating', '101': 'wait', '102': 'wait', '200': 'wait'})
    progress.locator('[data-testid="mig-run-close"]').click()
    page.locator('[data-testid="mig-run-card"][data-state="running"]').wait_for(timeout=3000)
    # what a restart does: the process and its runs are gone while they run
    held = bulk.runs()
    bulk.reset_for_tests()
    card = page.locator('[data-testid="mig-run-card"][data-state="lost"]')
    card.wait_for(timeout=10000)
    assert 'Bulk migration to pve2 interrupted' in card.inner_text()
    card.click()
    gone = progress.locator('[data-testid="mig-run-gone"]')
    gone.wait_for(timeout=5000)
    assert 'PegaProx restarted or another instance took over' in gone.inner_text()
    _shot(app, 'bulk-migrate-gone-modern')
    # the worker of the run that was let go ends here, not in the next test
    for run in held:
        bulk.cancel(run, 'test')
    app.pve.finish_all()
    _wait(lambda: all(r.state != 'running' for r in held), what='the run let go to end')
    assert not app.errors, app.errors


def test_runtime_the_server_refusal_stays_in_the_dialog(real_app, seed):
    """A VM-ACL user who sees more rows than they may move: the route names the guest."""
    seed.tenant('acme', clusters=['cluster_1'])
    seed.vm_acl('cluster_1', 100, users=['portal'])
    # MK Nov 2026 - one of theirs on pve2, the target: a confined caller moves guests onto
    # a node of theirs only, and the refusal here is the one about 101
    seed.vm_acl('cluster_1', 300, users=['portal'])
    app = real_app(user=seed.user('portal', role='user', tenant_id='acme'), layout='modern')
    with app.pve.lock:
        app.pve.guests[300] = dict(GUESTS[0], vmid=300, name='there01', node='pve2')
    _open_resources(app, 'modern')
    _tick(app, 100, 101)
    modal = _dialog(app)
    # two guests: all at once, as the call always did
    assert _mode(modal) == 'all'
    modal.locator('[data-testid="bulk-migrate-target"]').select_option('pve2')
    modal.locator('[data-testid="bulk-migrate-run"]').click()
    err = modal.locator('[data-testid="bulk-migrate-error"]')
    err.wait_for(timeout=5000)
    assert 'Not on this cluster or out of reach: 101' in err.inner_text()
    assert app.pve.started == [] and bulk.runs() == []
    assert not modal.locator('[data-testid="bulk-migrate-run"]').is_disabled()
    assert not app.errors, app.errors


def test_runtime_cloud_migrates_its_selection_all_at_once(real_app):
    app = real_app(layout='cloud')
    page = app.page
    page.get_by_text('Virtual Machines').first.click()
    page.get_by_text('web01').first.wait_for(timeout=5000)
    for name in ('web01', 'db01'):
        page.locator('tr', has_text=name).locator('input[type="checkbox"]').first.check()
    page.locator('.cloud-bulkbar button[data-bulk="migrate"]').click()
    modal = page.locator('[data-testid="bulk-migrate-modal"]')
    modal.wait_for(timeout=3000)
    assert _mode(modal) == 'all'
    modal.locator('[data-testid="bulk-migrate-target"]').select_option('pve2')
    _shot(app, 'bulk-migrate-dialog-cloud')
    modal.locator('[data-testid="bulk-migrate-run"]').click()
    page.locator('[data-testid="mig-run-modal"]').wait_for(timeout=5000)
    _wait_rows(app, {'100': 'started', '101': 'started'})
    assert 'PegaProx does not wait for them' in page.locator('[data-testid="mig-run-modal"]').inner_text()
    assert app.pve.running() == [100, 101]
    _shot(app, 'bulk-migrate-progress-cloud')
    assert not app.errors, app.errors


def test_runtime_migrate_all_of_a_node_goes_one_at_a_time(real_app):
    app = real_app(layout='modern')
    page = app.page
    page.get_by_text('Testi').first.click()
    page.locator('button[data-node-guests="pve1"]').wait_for(timeout=5000)
    page.locator('button[data-node-guests="pve1"]').click()
    page.locator('[role="menu"] [data-action="migrateall"]').click()
    modal = page.locator('[data-testid="node-guests-modal"]')
    modal.wait_for(timeout=3000)
    assert _mode(modal) == 'sequential'
    assert modal.locator('[data-testid="node-guests-workers"]').count() == 0
    modal.locator('label[data-guest="201"] input').uncheck()
    _shot(app, 'bulk-migrate-node-modern')
    modal.locator('[data-testid="node-guests-run"]').click()
    page.locator('[data-testid="mig-run-modal"]').wait_for(timeout=5000)
    assert page.locator('[data-testid="node-guests-modal"]').count() == 0
    assert _bodies(app) == [{'vms': [{'vmid': v, 'node': 'pve1', 'type': t} for v, t in
                                     ((100, 'qemu'), (101, 'qemu'), (102, 'qemu'), (200, 'lxc'))],
                             'target': 'pve2', 'online': True, 'with_local_disks': False, 'mode': 'sequential'}]
    assert not [c for c in app.server.calls if '/guests/' in c[1]]
    _wait_rows(app, {'100': 'migrating', '101': 'wait', '102': 'wait', '200': 'wait'})
    assert not app.errors, app.errors


def test_runtime_a_standby_shows_the_progress_and_offers_no_cancel(real_app, seed):
    """A run of the active, read on a standby whose writes are refused: the card and the
    dialog are there, the cancel and the Migrate of the Cloud bar are not."""
    admin = seed.user('admin', role='admin')
    active = real_app(user=admin, layout='modern')
    _open_resources(active, 'modern')
    _tick(active, 100, 101, 102, 200)
    modal = _dialog(active)
    modal.locator('[data-testid="bulk-migrate-target"]').select_option('pve2')
    modal.locator('[data-testid="bulk-migrate-run"]').click()
    active.page.locator('[data-testid="mig-run-modal"]').wait_for(timeout=5000)

    standby = real_app(user=admin, layout='cloud', role='standby')
    page = standby.page
    card = page.locator('[data-testid="mig-run-card"]')
    card.wait_for(timeout=8000)
    card.click()
    page.locator('[data-testid="mig-run-modal"]').wait_for(timeout=3000)
    _wait_rows(standby, {'100': 'migrating', '101': 'wait', '102': 'wait', '200': 'wait'})
    assert page.locator('[data-testid="mig-run-cancel"]').count() == 0
    page.locator('[data-testid="mig-run-close"]').click()
    page.get_by_text('Virtual Machines').first.click()
    page.get_by_text('web01').first.wait_for(timeout=5000)
    page.locator('tr', has_text='web01').locator('input[type="checkbox"]').first.check()
    page.wait_for_timeout(200)
    assert page.locator('.cloud-bulkbar button[data-bulk="migrate"]').count() == 0
    assert [s for s in standby.server.sent] == []
    for a in (active, standby):
        assert not a.errors, a.errors
