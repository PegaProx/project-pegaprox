"""The Check step of the bulk and the cross-cluster migrate dialogs.

Before Start, Check asks the server's migration preflight and shows the guests grouped
ready / with warnings / blocked with the reasons, what the target nodes hold afterwards,
and on request the planned steps of the run with what an abort leaves behind. A block
that may be overridden has a tick box and wants a confirmation; Start then sends the
guests that move and the blocks overridden. Changing an option after the check says so.

The source checks read web/src and the bundle. The runtime tests drive the built bundle in
headless Chromium: the page around it comes from the fake server of tests/test_ha_ui.py,
the preflight and the bulk migration are the real routes of the app against the faked
clusters of tests/test_migration_preflight.py. They skip where Playwright is not installed.

LW Oct 2026
"""
import os
import re

import pytest

from test_ha_ui import (BASE, LANGS, _App, _blocks, _classes,  # noqa: F401 (browser is a fixture)
                        browser, CLUSTER as C1, VM)
from test_bulk_migrate_ui_952 import (_Server as _BulkServer, _dialog, _open_resources, _tick, _until,
                                      GUESTS, METRICS)
from test_migration_preflight import (_fresh, _Pve, _guest, _node, _store, _net, CFG,  # noqa: F401 (autouse)
                                      _audit)

from pegaprox.core import bulk_migrate as bulk

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHOTS = os.environ.get('PEGAPROX_UI_SHOTS', '')


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def _used_keys():
    keys = set()
    for name in ('vm_modals.js', 'dashboard.js'):
        keys.update(re.findall(r"t\('(migPf\w+)'\)", _read('web', 'src', name)))
    keys.update(re.findall(r"'(migPf\w+)'", _new_code()[0]))
    return sorted(keys)


def _between(src, head, tail):
    start = src.index(head)
    return src[start:src.index(tail, start)]


def _new_code():
    """The shared Check step with the bulk dialog, and what the cross-cluster dialog got"""
    modals = _read('web', 'src', 'vm_modals.js')
    bulk_part = _between(modals, '// LW Oct 2026 - the Check step of the migrate dialogs',
                         '// LW Oct 2026 - the bulk bar of the guest table')
    cross = '\n'.join((
        _between(modals, 'const buildPayload = () => {', '// need at least one storage selected'),
        _between(modals, '{targetCluster && targetNode && (check.result ? (', "<strong>{t('autoTokenInfo')"),
        _between(modals, '<button onClick={runCheck} disabled={!targetCluster', "{t('crossClusterMigrate')}"),
    ))
    return [bulk_part, cross]


# -- source ------------------------------------------------------------------------------------

def test_the_new_strings_are_their_own_keys():
    keys = _used_keys()
    assert len(keys) == 18, keys


@pytest.mark.parametrize('lang', LANGS)
def test_every_new_key_exists_once_per_language(lang):
    block = _blocks()[lang]
    for key in _used_keys():
        n = len(re.findall(r'^ +%s: ' % key, block, re.M))
        assert n == 1, f'{key} appears {n} times in {lang}'
    assert set(re.findall(r'^ +(migPf\w+): ', block, re.M)) == set(_used_keys())


def test_placeholders_survive_translation():
    blocks = _blocks()
    for key in _used_keys():
        en = re.search(r'^ +%s: (.*),$' % key, blocks['en'], re.M).group(1)
        for lang, block in blocks.items():
            value = re.search(r'^ +%s: (.*),$' % key, block, re.M).group(1)
            assert sorted(re.findall(r'\{\w+\}', value)) == sorted(re.findall(r'\{\w+\}', en)), (lang, key)


def test_no_em_dash_in_the_new_code():
    lines = [line for block in _blocks().values() for line in block.splitlines() if 'migPf' in line]
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


def test_a_standby_gets_no_start_but_may_check():
    """The preflight reads only: Check stays, Start goes where the active acts"""
    bulk_part, cross = _new_code()
    assert "{!haReadOnly && (\n                    <button onClick={handleMigrate}" in bulk_part
    assert '{!haReadOnly && (' in cross and 'data-testid="xc-migrate-run"' in cross
    assert 'haReadOnly' not in bulk_part[bulk_part.index('data-testid="bulk-migrate-check"') - 200:
                                         bulk_part.index('data-testid="bulk-migrate-check"')]


def test_the_check_asks_the_server_once_and_never_per_guest():
    bulk_part, cross = _new_code()
    assert bulk_part.count('fetch(') == 1 and '/migration-preflight`' in bulk_part
    assert '/cross-cluster-migrate/preflight`' in cross
    assert '/vms/${' not in bulk_part


def test_the_bundle_was_rebuilt():
    bundle = _read('web', 'index.html')
    for needle in ('function MigPreflightView(', 'function useMigPreflight(', 'bulk-migrate-check',
                   'xc-migrate-check', '/migration-preflight', '/cross-cluster-migrate/preflight'):
        assert needle in bundle, needle
    for key in _used_keys():
        assert key in bundle, key


# -- runtime: the built bundle against the real routes ----------------------------------------

REAL = re.compile(r'^/api/(clusters/cluster_1/(vms/bulk-migrate|migration-preflight)|bulk-migrations(/[0-9a-f]+(/cancel)?)?'
                  r'|cross-cluster-migrate/preflight)$')
GB = 1024 ** 3


class _Server(_BulkServer):
    """The page from the fake server; the preflight and the bulk migration from the app"""

    def handle(self, route):
        req = route.request
        path = re.sub(r'^https?://[^/]+', '', req.url).split('?')[0]
        if not req.url.startswith(BASE) or not REAL.match(path):
            return super(_BulkServer, self).handle(route)
        import json
        raw = req.post_data or ''
        self.calls.append((req.method, path))
        if req.method != 'GET':
            self.sent.append((req.method, path, json.loads(raw) if raw else None))
            r = getattr(self.client, req.method.lower())(path, data=raw, headers={'Content-Type': 'application/json'})
        else:
            r = self.client.get(path)
        return route.fulfill(status=r.status_code, body=r.get_data(), headers={'Content-Type': 'application/json'})


def _server_guests():
    out = []
    for g in GUESTS:
        out.append(_guest(g['vmid'], node=g['node'], kind=g['type'], status=g['status'], name=g['name']))
    return out


@pytest.fixture
def app_of(browser, api, seed, monkeypatch):  # noqa: F811
    monkeypatch.setattr(bulk, 'POLL_SECONDS', 0.05)
    apps = []

    def _open(layout='modern', configs=None, guests=None, **kw):
        cluster = _Pve(api, cid='cluster_1', guests=guests or _server_guests(), configs=configs,
                       nodes={'pve1': _node(), 'pve2': _node(), 'pve3': _node(status='offline')})
        app = _App(browser, _Server(api.as_user(seed.user('admin', role='admin')), layout=layout, **kw))
        app.cluster = cluster
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _shot(app, name):
    if SHOTS:
        os.makedirs(SHOTS, exist_ok=True)
        app.page.screenshot(path=os.path.join(SHOTS, f'{name}.png'))


def _sent(app, path):
    return [b for m, p, b in app.server.sent if p.endswith(path)]


def _check(modal):
    modal.locator('[data-testid="bulk-migrate-target"]').select_option('pve2')
    modal.locator('[data-testid="bulk-migrate-check"]').click()
    modal.locator('[data-testid="mig-pf"]').wait_for(timeout=8000)
    return modal.locator('[data-testid="mig-pf"]')


def test_runtime_modern_check_groups_override_and_start(app_of):
    configs = {100: CFG, 101: dict(CFG, hostpci0='mapping=gpu1,pcie=1'), 102: CFG}
    guests = _server_guests()
    guests[2]['maxmem'] = 200 * GB
    app = app_of(layout='modern', configs=configs, guests=guests)
    page = app.page
    _open_resources(app, 'modern')
    _tick(app, 100, 101, 102)
    modal = _dialog(app)
    assert 'per guest ready, with warnings or blocked' in modal.locator('[data-testid="mig-pf-hint"]').inner_text()
    view = _check(modal)
    assert _sent(app, '/migration-preflight') == [{'vms': [100, 101, 102], 'target': 'pve2', 'online': True,
                                                   'with_local_disks': False, 'mode': 'all'}]
    assert view.locator('[data-testid="mig-pf-totals"]').inner_text() == '1 ready, 1 with warnings, 1 blocked'
    blocked = view.locator('[data-pf-group="blocked"] [data-pf-guest="102"]')
    assert 'pve2 runs out of memory' in blocked.inner_text() and 'cache01' in blocked.inner_text()
    assert 'resource mapping' in view.locator('[data-pf-group="warning"] [data-pf-guest="101"]').inner_text()
    assert view.locator('[data-pf-group="ready"] [data-pf-guest="100"]').count() == 1
    assert 'pve2 RAM' in view.locator('[data-testid="mig-pf-capacity"]').inner_text()
    run = modal.locator('[data-testid="bulk-migrate-run"]')
    assert run.inner_text().strip() == 'Migrate 2 guests' and run.is_enabled()
    # the dry run: the steps of the run and what an abort leaves
    view.locator('[data-testid="mig-pf-steps-toggle"]').click()
    steps = view.locator('[data-testid="mig-pf-steps"]')
    assert steps.locator('li[data-step="run"]').inner_text().startswith('All at once')
    assert steps.locator('li[data-step="migrate"]').count() == 2
    assert 'Skip 102 (cache01): pve2 runs out of memory' in steps.locator('li[data-step="skip"]').inner_text()
    assert 'Cancelling the run starts no further guest' in steps.inner_text()
    _shot(app, 'preflight-bulk-modern')
    # an override wants its confirmation first
    view.locator('[data-pf-override="102"]').check()
    assert not run.is_enabled()
    confirm = view.locator('[data-testid="mig-pf-confirm"]')
    assert 'Override 1 block(s) knowingly' in confirm.inner_text()
    confirm.locator('input').check()
    assert run.inner_text().strip() == 'Migrate 3 guests' and run.is_enabled()
    # another option: the check no longer holds and says so, Start goes back to every guest
    modal.locator('[data-testid="bulk-migrate-local"]').check()
    view.locator('[data-testid="mig-pf-stale"]').wait_for(timeout=3000)
    modal.locator('[data-testid="bulk-migrate-local"]').uncheck()
    assert view.locator('[data-testid="mig-pf-stale"]').count() == 0
    run.click()
    page.locator('[data-testid="mig-run-modal"]').wait_for(timeout=8000)
    body = _sent(app, '/vms/bulk-migrate')[0]
    assert [v['vmid'] for v in body['vms']] == [100, 101, 102]
    assert body['override'] == [102] and body['confirm_override'] is True and body['mode'] == 'all'
    _until(app, lambda: len(app.cluster.started) == 3, what='three migrations')
    (entry,) = _audit('vm.migrate_block_overridden')
    assert '102 (pve2 runs out of memory' in entry['details']
    assert not app.errors, app.errors


def test_runtime_corporate_start_sends_only_what_moves(app_of):
    configs = {100: CFG, 101: dict(CFG, lock='backup'), 102: CFG}
    app = app_of(layout='corporate', configs=configs)
    page = app.page
    _open_resources(app, 'corporate')
    _tick(app, 100, 101, 102)
    modal = _dialog(app)
    view = _check(modal)
    row = view.locator('[data-pf-group="blocked"] [data-pf-guest="101"]')
    assert 'It is locked (backup)' in row.inner_text()
    # a lock is Proxmox's: nothing to override
    assert view.locator('[data-pf-override]').count() == 0
    run = modal.locator('[data-testid="bulk-migrate-run"]')
    assert run.inner_text().strip() == 'Migrate 2 guests'
    _shot(app, 'preflight-bulk-corporate')
    run.click()
    page.locator('[data-testid="mig-run-modal"]').wait_for(timeout=8000)
    body = _sent(app, '/vms/bulk-migrate')[0]
    assert [v['vmid'] for v in body['vms']] == [100, 102] and 'override' not in body
    assert not app.errors, app.errors


def test_runtime_nothing_movable_disables_start(app_of):
    configs = {100: dict(CFG, lock='backup'), 101: dict(CFG, lock='snapshot')}
    app = app_of(layout='modern', configs=configs)
    _open_resources(app, 'modern')
    _tick(app, 100, 101)
    modal = _dialog(app)
    _check(modal)
    assert modal.locator('[data-testid="mig-pf-none"]').inner_text() == 'As it is, no guest moves'
    assert not modal.locator('[data-testid="bulk-migrate-run"]').is_enabled()
    assert _sent(app, '/vms/bulk-migrate') == []
    assert not app.errors, app.errors


def test_runtime_cloud_checks_its_selection(app_of):
    app = app_of(layout='cloud', configs={100: CFG, 101: dict(CFG, net0='virtio=x,bridge=vmbr9')})
    page = app.page
    page.get_by_text('Virtual Machines').first.click()
    page.get_by_text('web01').first.wait_for(timeout=5000)
    for name in ('web01', 'db01'):
        page.locator('tr', has_text=name).locator('input[type="checkbox"]').first.check()
    page.locator('.cloud-bulkbar button[data-bulk="migrate"]').click()
    modal = page.locator('[data-testid="bulk-migrate-modal"]')
    modal.wait_for(timeout=3000)
    view = _check(modal)
    assert 'bridge vmbr9, which pve2 does not have' in view.locator('[data-pf-guest="101"]').inner_text()
    assert modal.locator('[data-testid="bulk-migrate-run"]').inner_text().strip() == 'Migrate 1 guests'
    _shot(app, 'preflight-bulk-cloud')
    assert not app.errors, app.errors


def test_runtime_german_says_it_in_german(app_of):
    app = app_of(layout='modern', language='de', configs={100: CFG})
    _open_resources_de(app)
    _tick(app, 100)
    modal = _dialog(app)
    assert 'pro Gast bereit, mit Warnungen oder blockiert' in modal.inner_text()
    view = _check(modal)
    assert view.locator('[data-testid="mig-pf-totals"]').inner_text() == '1 bereit, 0 mit Warnungen, 0 blockiert'
    assert 'migPf' not in modal.inner_text()
    assert not app.errors, app.errors


def _open_resources_de(app):
    page = app.page
    page.get_by_text('Testi').first.click()
    page.locator('button', has_text='Ressourcen').first.click()
    page.get_by_text('web01').first.wait_for(timeout=5000)
    page.locator('button[title="Listenansicht"], button[title="List View"]').first.click()
    page.locator('table thead input[type="checkbox"]').first.wait_for(timeout=5000)
    page.wait_for_timeout(200)


# -- runtime: the cross-cluster dialog ------------------------------------------------------------

FAR = {'id': 'cluster_2', 'name': 'Far', 'display_name': 'Far', 'host': '10.9.0.1', 'connected': True,
       'status': 'running', 'cluster_type': 'proxmox', 'enabled': True}
SRC_CFG = {'scsi0': 'local-lvm:vm-100-disk-0,size=8G', 'net0': 'virtio=BC:24:11:00:00:01,bridge=vmbr0'}
STARTED = {'message': 'Cross-cluster migration started: qemu/100 from cluster_1 to cluster_2/pve3', 'task': 'UPID:x'}


@pytest.fixture
def xc_app(browser, api, seed):  # noqa: F811
    apps = []

    def _open(layout='modern', src_cfg=None, far_guests=()):
        _Pve(api, cid='cluster_1', guests=[_guest(100, name='web01')], configs={100: src_cfg or SRC_CFG})
        _Pve(api, cid='cluster_2', name='Far', guests=far_guests, nodes={'pve3': _node()},
             storages=[_store('pve3', 'local-lvm')], networks={'pve3': _net('vmbr0')})
        extra = {('GET', '/api/clusters/cluster_1/vms/pve1/qemu/100/config'): (200, src_cfg or SRC_CFG),
                 ('GET', '/api/clusters/cluster_2/nodes'): (200, [{'node': 'pve3', 'status': 'online',
                                                                    'cpu_percent': 1, 'mem_percent': 2}]),
                 ('GET', '/api/clusters/cluster_2/nodes/pve3/storage'): (200, [{'storage': 'local-lvm', 'type': 'lvmthin'}]),
                 ('GET', '/api/clusters/cluster_2/nodes/pve3/networks'): (200, [{'iface': 'vmbr0', 'type': 'bridge'}]),
                 ('POST', '/api/cross-cluster-migrate'): (200, STARTED)}
        vm = dict(VM)
        server = _Server(api.as_user(seed.user('admin', role='admin')), layout=layout,
                         clusters=[dict(C1, id='cluster_1'), FAR], resources=[vm], metrics=METRICS, extra=extra)
        app = _App(browser, server)
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _cross_dialog(app):
    page = app.page
    page.get_by_text('Testi').first.click()
    page.locator('button', has_text='Resources').first.click()
    page.get_by_text('web01').first.wait_for(timeout=5000)
    page.get_by_text('web01').first.click()
    page.get_by_role('button', name='More Actions').first.click()
    page.get_by_role('button', name='Cross-Cluster Migrate').first.click()
    page.get_by_text('Cross-Cluster Migration').first.wait_for(timeout=5000)
    page.locator('select', has=page.locator('option', has_text='Far')).first.select_option('cluster_2')
    check = page.locator('[data-testid="xc-migrate-check"]')
    _until(app, lambda: check.count() == 1 and check.is_enabled() and
           page.locator('[data-testid="xc-migrate-run"]').is_enabled(), what='the target to load')
    return page


def test_runtime_cross_cluster_a_block_keeps_start_off(xc_app):
    app = xc_app(far_guests=[_guest(100, node='pve3')])
    page = _cross_dialog(app)
    page.locator('[data-testid="xc-migrate-check"]').click()
    view = page.locator('[data-testid="mig-pf"]')
    view.wait_for(timeout=8000)
    sent = _sent(app, '/cross-cluster-migrate/preflight')[0]
    assert (sent['vmid'], sent['target_node'], sent['target_storage_map']) == (100, 'pve3', {'local-lvm': 'local-lvm'})
    assert 'VMID 100 is taken on Far' in view.locator('[data-pf-group="blocked"]').inner_text()
    assert not page.locator('[data-testid="xc-migrate-run"]').is_enabled()
    view.locator('[data-testid="mig-pf-steps-toggle"]').click()
    assert 'Create a temporary API token on Far' in view.locator('[data-testid="mig-pf-steps"]').inner_text()
    _shot(app, 'preflight-cross-modern')
    assert 'POST' not in [m for m, p in app.server.calls if p == '/api/cross-cluster-migrate']
    assert not app.errors, app.errors


def test_runtime_cross_cluster_an_override_goes_with_start(xc_app):
    app = xc_app(src_cfg=dict(SRC_CFG, parent='before-upgrade'))
    page = _cross_dialog(app)
    page.locator('[data-testid="xc-migrate-check"]').click()
    view = page.locator('[data-testid="mig-pf"]')
    view.wait_for(timeout=8000)
    assert 'It has snapshots' in view.locator('[data-pf-guest="100"]').inner_text()
    run = page.locator('[data-testid="xc-migrate-run"]')
    assert not run.is_enabled()
    view.locator('[data-pf-override="100"]').check()
    assert not run.is_enabled()
    view.locator('[data-testid="mig-pf-confirm"] input').check()
    assert run.is_enabled()
    run.click()
    _until(app, lambda: app.server.bodies.get('/api/cross-cluster-migrate'), what='the migration')
    body = app.server.bodies['/api/cross-cluster-migrate'][-1]
    assert body['override'] == [100] and body['confirm_override'] is True and body['vmid'] == 100
    assert not app.errors, app.errors
