"""The bulk bar of the guest table, all guests of a node, and the favorites group.

The bulk bar acts on the guests ticked in the table through the per-guest routes a single
row uses, a few at a time, and lists what each guest answered. A node starts, shuts down
or migrates all its guests through the node route. Starred clusters, nodes and guests show
in a group at the top of the sidebar.

The source checks read web/src and the bundle. The runtime tests drive the built bundle in
headless Chromium: the page around it comes from the fake server of tests/test_ha_ui.py,
the favorites, the per-guest routes and the node route are the real routes of the app as
the signed-in admin, against a faked cluster manager. What the page sends is what the
server takes, and the manager sees what Proxmox would get. They skip where Playwright is
not installed.

LW Oct 2026
"""
import json
import os
import re

import pytest

from test_ha_ui import (BASE, LANGS, _App, _FakeServer, _blocks, _classes,  # noqa: F401 (browser is a fixture)
                        browser)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def _function(src, head):
    start = src.index(head)
    nxt = src.find('\n        function ', start + 10)
    return src[start:nxt if nxt > 0 else len(src)]


@pytest.fixture(scope='module')
def modals():
    return _read('web', 'src', 'vm_modals.js')


@pytest.fixture(scope='module')
def tables():
    return _read('web', 'src', 'tables.js')


@pytest.fixture(scope='module')
def dash():
    return _read('web', 'src', 'dashboard.js')


# -- source ------------------------------------------------------------------------------------

def _used_keys():
    keys = set()
    for name in ('vm_modals.js', 'tables.js', 'dashboard.js', 'cloud.js', 'settings_modal.js'):
        src = _read('web', 'src', name)
        keys.update(re.findall(r"t\('((?:guestBulk|nodeGuests|fav|auditNodeGuests)\w*)'\)", src))
        keys.update(re.findall(r"'((?:guestBulk|nodeGuests)\w+)'", src))
    keys.discard('nodeGuests')
    return sorted(keys)


def test_the_new_strings_are_their_own_keys():
    keys = _used_keys()
    # nodeGuestsParallel went with #952: migrating a node's guests asks the bulk run's question
    assert len(keys) == 40, keys
    assert {'favoritesGroup', 'favAdd', 'favRemove', 'nodeGuestsTitleMigrate', 'guestBulkSummary'} <= set(keys)


@pytest.mark.parametrize('lang', LANGS)
def test_every_new_key_exists_once_per_language(lang):
    block = _blocks()[lang]
    for key in _used_keys():
        n = len(re.findall(r'^ +%s: ' % key, block, re.M))
        assert n == 1, f'{key} appears {n} times in {lang}'


def test_placeholders_survive_translation():
    blocks = _blocks()
    for key in _used_keys():
        en = re.search(r'^ +%s: (.*),$' % key, blocks['en'], re.M).group(1)
        for lang, block in blocks.items():
            value = re.search(r'^ +%s: (.*),$' % key, block, re.M).group(1)
            assert sorted(re.findall(r'\{\w+\}', value)) == sorted(re.findall(r'\{\w+\}', en)), (lang, key)


def test_the_austrian_flag_stays_on_german():
    assert "{ code: 'de', flag: '\U0001F1E6\U0001F1F9'," in _read('web', 'src', 'contexts.js')


def _new_code(modals, tables, dash):
    parts = [modals[modals.index('const GUEST_BULK_PARALLEL'):modals.index('// Cross-Cluster Migration Modal')]]
    parts.append(tables[tables.index('const openBulk = (action)'):tables.index("const canStar = acts && !!onToggleFavorite;")])
    parts.append(dash[dash.index('const openFavorite = (kind, f)'):dash.index('// LW: Feb 2026 - corporate inline inventory tree')])
    parts.append(dash[dash.index('const favoriteGuestLive = useMemo'):dash.index('const [cloudBulk, setCloudBulk]')])
    return parts


def test_no_em_dash_in_the_new_code(modals, tables, dash):
    lines = [line for block in _blocks().values() for line in block.splitlines()
             if re.match(r'^ +(guestBulk|nodeGuests|fav|auditNodeGuests)\w*: ', line)]
    for text in _new_code(modals, tables, dash) + lines:
        assert '\u2014' not in text and '\u2013' not in text


def test_every_class_is_in_the_static_tailwind_build(modals, tables, dash):
    css = _read('static', 'css', 'tailwind.min.css') + _read('web', 'index.html.original')
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    names = set()
    for part in _new_code(modals, tables, dash):
        names |= _classes(part)
    # the stars and the guests menu of the table and the node card
    for head in ('{canStar && (', '{!haReadOnly && onToggleFavorite && (', '{!haReadOnly && onGuestsAction'):
        for m in re.finditer(re.escape(head), tables):
            names |= _classes(tables[m.start():m.start() + 2500])
    missing = sorted(n for n in names if n not in have)
    assert not missing, f'not in static/css/tailwind.min.css: {missing}'


def test_every_icon_exists(modals, tables, dash):
    icons = set(re.findall(r'^            ([A-Z][A-Za-z0-9]*):', _read('web', 'src', 'icons.js'), re.M))
    used = set()
    for part in _new_code(modals, tables, dash):
        used |= set(re.findall(r'Icons\.([A-Z][A-Za-z0-9]*)', part))
    assert used and used <= icons, sorted(used - icons)


def test_the_bulk_dialog_uses_the_per_guest_routes(modals):
    body = _function(modals, 'function GuestBulkActionModal(')
    # power through /<action>, the force stop with the body of a single row's force stop
    assert "res = await authFetch(`${base}/${action}`, action === 'stop' ? json('POST', { force: true }) : { method: 'POST' });" in body
    assert "res = await authFetch(`${base}/snapshots`, json('POST', {" in body
    assert "res = await authFetch(`${base}/config`, json('PUT', next.length ? { tags: next.join(';') } : { delete: 'tags' }));" in body
    # a few at a time
    assert 'const GUEST_BULK_PARALLEL = 4;' in modals
    assert 'Math.min(GUEST_BULK_PARALLEL, items.length)' in modals


def test_the_bundle_was_rebuilt():
    bundle = _read('web', 'index.html')
    for needle in ('function GuestBulkActionModal(', 'function NodeGuestsModal(', 'guest-bulk-modal',
                   'sidebar-favorites', 'node-guests-run', '/guests/${action}'):
        assert needle in bundle, needle
    for key in _used_keys():
        assert key in bundle, key


# -- runtime: the built bundle against the real routes ----------------------------------------

SHOTS = os.environ.get('PEGAPROX_UI_SHOTS', '')
CLUSTER = {'id': 'c1', 'name': 'Testi', 'display_name': 'Testi', 'host': '10.0.0.1',
           'connected': True, 'status': 'running', 'cluster_type': 'proxmox', 'enabled': True}
_LOAD = {'cpu': 0.05, 'cpu_percent': 5, 'maxcpu': 2, 'mem': 1073741824, 'maxmem': 4294967296,
         'mem_percent': 25, 'disk': 0, 'maxdisk': 34359738368, 'uptime': 3600}
GUESTS = [
    dict(_LOAD, vmid=100, name='web01', type='qemu', status='running', node='pve1', tags='prod;web'),
    dict(_LOAD, vmid=101, name='db01', type='qemu', status='running', node='pve1'),
    dict(_LOAD, vmid=102, name='tpl01', type='qemu', status='stopped', node='pve1', template=1),
    dict(_LOAD, vmid=200, name='ct01', type='lxc', status='running', node='pve2', tags='prod'),
    dict(_LOAD, vmid=201, name='ct02', type='lxc', status='stopped', node='pve1'),
]
_NODE = {'status': 'online', 'cpu_percent': 5.0, 'mem_percent': 20.0, 'disk_percent': 10.0, 'score': 42.0,
         'uptime': 86400, 'loadavg': [0.1, 0.2, 0.3], 'netin': 0, 'netout': 0, 'mem_used': 6871947673,
         'mem_total': 34359738368, 'disk_used': 10737418240, 'disk_total': 107374182400,
         'pveversion': 'pve-manager/9.0.3', 'kversion': 'Linux 6.14.8-2-pve',
         'cpuinfo': {'cpus': 8, 'cores': 4, 'sockets': 1}, 'maintenance_mode': False, 'is_updating': False}
METRICS = {'pve1': dict(_NODE), 'pve2': dict(_NODE), 'pve3': dict(_NODE)}
# what the page sends to the app instead of the fake server
REAL = re.compile(r'^/api/(user/favorites|clusters/c1/(vms/[^/]+/(qemu|lxc)/\d+/(start|shutdown|stop|reboot|snapshots|config)'
                  r'|nodes/[^/]+/guests/\w+))$')


class _Server(_FakeServer):
    """The page from the fake server; favorites, guest routes and the node route from the app.

    With park set, the guest routes wait until the test lets them through, so the number
    in flight at once can be counted."""

    def __init__(self, client, **kw):
        kw.setdefault('clusters', [CLUSTER])
        kw.setdefault('resources', [dict(g) for g in GUESTS])
        kw.setdefault('metrics', METRICS)
        kw.setdefault('role', 'standalone')
        super().__init__(**kw)
        self.client = client
        self.park = False
        self.parked = []
        self.peak = 0
        self.sent = []

    def handle(self, route):
        req = route.request
        path = re.sub(r'^https?://[^/]+', '', req.url)
        bare = path.split('?')[0]
        # the reads of a guest (its config, its snapshots) stay with the fake server
        if not req.url.startswith(BASE) or not REAL.match(bare) or (req.method == 'GET' and '/vms/' in bare):
            return super().handle(route)
        raw = req.post_data or ''
        self.calls.append((req.method, bare))
        if req.method != 'GET':
            self.sent.append((req.method, bare, json.loads(raw) if raw else None))
            if self.role == 'standby':
                return route.fulfill(status=409, headers={'Content-Type': 'application/json'}, body=json.dumps(
                    {'error': 'This is a standby instance.', 'code': 'HA_STANDBY'}))
        if self.park and '/vms/' in bare:
            self.parked.append((route, req.method, path, raw))
            self.peak = max(self.peak, len(self.parked))
            return None
        return self._forward(route, req.method, path, raw)

    def _forward(self, route, method, path, raw):
        if method == 'GET':
            r = self.client.get(path)
        else:
            r = getattr(self.client, method.lower())(path.split('?')[0], data=raw,
                                                      headers={'Content-Type': 'application/json'})
        return route.fulfill(status=r.status_code, body=r.get_data(), headers={'Content-Type': 'application/json'})

    def let_one_through(self):
        route, method, path, raw = self.parked.pop(0)
        self._forward(route, method, path, raw)


class _Proxmox:
    """The cluster manager, as far as these routes call it, with a log of the calls."""

    def __init__(self, api, fail=(), guests=GUESTS):
        self.calls = []
        self.fail = set(fail)
        m = api.make_fake_manager(cluster_id='c1', get_vm_resources=[dict(g) for g in guests],
                                  get_node_status={n: {'status': 'online'} for n in METRICS})
        m.is_connected = True
        m.config.name = 'Testi'
        m.nodes = {n: {'status': 'online'} for n in METRICS}
        m.vm_action.side_effect = self._power
        m.create_snapshot.side_effect = self._snapshot
        m.update_vm_config.side_effect = self._config
        m.node_guests_action.side_effect = self._node
        self.mgr = api.set_manager('c1', m)

    def _refused(self, vmid):
        return {'success': False, 'error': '{"data":null,"message":"VM %d is locked (backup)\\n"}' % vmid}

    def _power(self, node, vmid, vm_type, action, force=False):
        self.calls.append(('power', node, vmid, vm_type, action, force))
        return self._refused(vmid) if vmid in self.fail else {'success': True, 'data': f'UPID:{node}:{vmid}:{action}'}

    def _snapshot(self, node, vmid, vm_type, snapname, description, vmstate):
        self.calls.append(('snapshot', node, vmid, vm_type, snapname, description, bool(vmstate)))
        return self._refused(vmid) if vmid in self.fail else {'success': True, 'task': f'UPID:{node}:{vmid}:snap'}

    def _config(self, node, vmid, vm_type, updates):
        self.calls.append(('config', node, vmid, vm_type, dict(updates)))
        return {'success': True, 'message': 'Configuration updated'}

    def _node(self, node, action, vmids, target=None, maxworkers=1, with_local_disks=False):
        self.calls.append(('node', node, action, list(vmids), target, maxworkers, with_local_disks))
        if 'node' in self.fail:
            return {'success': False, 'error': '{"data":null,"message":"cluster not ready - no quorum?\\n"}'}
        return {'success': True, 'task': f'UPID:{node}:{action}'}

    def of(self, kind):
        return [c[1:] for c in self.calls if c[0] == kind]


@pytest.fixture
def real_app(browser, api, seed):  # noqa: F811
    apps = []

    def _open(user=None, fail=(), guests=GUESTS, **kw):
        who = user or seed.user('admin', role='admin')
        pve = _Proxmox(api, fail=fail, guests=guests)
        app = _App(browser, _Server(api.as_user(who), resources=[dict(g) for g in guests], **kw))
        app.pve = pve
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _shot(app, name):
    if SHOTS:
        os.makedirs(SHOTS, exist_ok=True)
        app.page.screenshot(path=os.path.join(SHOTS, f'{name}.png'))


def _open_resources(app, layout, first='web01'):
    page = app.page
    if layout == 'corporate':
        page.locator('.corp-tree-item', has_text='Testi').first.click()
    else:
        page.get_by_text('Testi').first.click()
    page.locator('button', has_text='Resources').first.click()
    page.get_by_text(first).first.wait_for(timeout=5000)
    if layout == 'modern':
        page.locator('button[title="List View"]').first.click()
    page.locator('table thead input[type="checkbox"]').first.wait_for(timeout=5000)
    page.wait_for_timeout(200)


def _tick(app, *vmids):
    page = app.page
    for vmid in vmids:
        row = page.locator('table tbody tr', has=page.locator('td', has_text=re.compile(rf'^{vmid}$')))
        row.locator('input[type="checkbox"]').first.check()


def _bulk(app, action):
    app.page.locator(f'button[data-bulk="{action}"]').first.click()
    modal = app.page.locator('[data-testid="guest-bulk-modal"]')
    modal.wait_for(timeout=3000)
    return modal


def _states(app):
    return app.page.evaluate('''() => Object.fromEntries(Array.from(document.querySelectorAll(
        '[data-testid="guest-bulk-results"] [data-guest]')).map(r => {
            const s = r.querySelector('[data-state]');
            return [r.dataset.guest, s ? s.dataset.state : ''];
        }))''')


def _wait_states(app, want, seconds=8):
    for _ in range(int(seconds * 10)):
        if _states(app) == want:
            return
        app.page.wait_for_timeout(100)
    assert _states(app) == want


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_bulk_shutdown_lists_each_guest_and_the_failure(real_app, layout):
    app = real_app(layout=layout, fail=(101,))
    page = app.page
    _open_resources(app, layout)
    _tick(app, 100, 101, 102, 201)
    modal = _bulk(app, 'shutdown')
    text = modal.inner_text()
    assert 'Shutdown: 4 guests' in text
    # the stopped container and the template stay out, and say why
    skipped = modal.locator('[data-testid="guest-bulk-skipped"]').inner_text()
    assert 'tpl01' in skipped and 'ct02' in skipped and 'not running' in skipped and 'template' in skipped
    _shot(app, f'bulk-shutdown-confirm-{layout}')
    modal.locator('[data-testid="guest-bulk-run"]').click()
    _wait_states(app, {'100': 'started', '101': 'failed'})
    results = modal.locator('[data-testid="guest-bulk-results"]').inner_text()
    # the reason Proxmox gave, as text and not as its JSON
    assert 'VM 101 is locked (backup)' in results and '"message"' not in results
    assert '1 of 2 done, 1 failed' in modal.inner_text()
    _shot(app, f'bulk-shutdown-results-{layout}')
    assert sorted(app.pve.of('power')) == [('pve1', 100, 'qemu', 'shutdown', False),
                                            ('pve1', 101, 'qemu', 'shutdown', False)]
    assert sorted(c for c in app.server.sent if '/vms/' in c[1]) == [
        ('POST', '/api/clusters/c1/vms/pve1/qemu/100/shutdown', None),
        ('POST', '/api/clusters/c1/vms/pve1/qemu/101/shutdown', None)]
    modal.locator('[data-testid="guest-bulk-close"]').click()
    assert page.locator('[data-testid="guest-bulk-modal"]').count() == 0
    assert not app.errors, app.errors


MANY = [dict(_LOAD, vmid=300 + i, name=f'lab{i:02d}', type='qemu', status='stopped', node='pve1') for i in range(10)]


def test_runtime_four_requests_at_a_time_and_none_lost(real_app):
    app = real_app(layout='corporate', guests=MANY)
    page = app.page
    _open_resources(app, 'corporate', first='lab00')
    page.locator('table thead input[type="checkbox"]').first.check()
    modal = _bulk(app, 'start')
    assert 'Start: 10 guests' in modal.inner_text()
    app.server.park = True
    modal.locator('[data-testid="guest-bulk-run"]').click()
    for _ in range(50):
        if len(app.server.parked) == 4:
            break
        page.wait_for_timeout(100)
    page.wait_for_timeout(500)
    # four in flight, the rest waits, and nobody may close the dialog meanwhile
    assert len(app.server.parked) == 4
    assert modal.locator('[data-testid="guest-bulk-close"]').is_disabled()
    assert 'in progress' in modal.inner_text() and 'waiting' in modal.inner_text()
    while app.server.parked or len(app.pve.of('power')) < 10:
        if app.server.parked:
            app.server.let_one_through()
        page.wait_for_timeout(60)
        assert len(app.server.parked) <= 4
    assert app.server.peak == 4
    _wait_states(app, {str(g['vmid']): 'started' for g in MANY})
    assert sorted(c[1] for c in app.pve.of('power')) == [g['vmid'] for g in MANY]
    assert '10 of 10 done, 0 failed' in modal.inner_text()
    assert not modal.locator('[data-testid="guest-bulk-close"]').is_disabled()
    assert not app.errors, app.errors


def test_runtime_force_stop_warns_and_sends_what_a_single_force_stop_sends(real_app):
    app = real_app(layout='modern')
    _open_resources(app, 'modern')
    _tick(app, 100, 200)
    modal = _bulk(app, 'stop')
    assert 'Force Stop: 2 guests' in modal.inner_text()
    assert 'like pulling the plug' in modal.inner_text()
    _shot(app, 'bulk-force-stop-modern')
    modal.locator('[data-testid="guest-bulk-run"]').click()
    _wait_states(app, {'100': 'started', '200': 'started'})
    assert sorted(c for c in app.server.sent if '/vms/' in c[1]) == [
        ('POST', '/api/clusters/c1/vms/pve1/qemu/100/stop', {'force': True}),
        ('POST', '/api/clusters/c1/vms/pve2/lxc/200/stop', {'force': True})]
    assert sorted(app.pve.of('power')) == [('pve1', 100, 'qemu', 'stop', True), ('pve2', 200, 'lxc', 'stop', True)]
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_snapshot_of_several_guests_with_ram_where_it_applies(real_app, layout):
    app = real_app(layout=layout)
    page = app.page
    _open_resources(app, layout)
    _tick(app, 100, 102, 200, 201)
    modal = _bulk(app, 'snapshot')
    # the template takes no snapshot
    assert 'tpl01' in modal.locator('[data-testid="guest-bulk-skipped"]').inner_text()
    name = modal.locator('[data-testid="guest-bulk-snapname"]')
    name.fill('1-bad name')
    assert modal.locator('[data-testid="guest-bulk-run"]').is_disabled()
    assert 'Starts with a letter' in modal.inner_text()
    name.fill('before-patch')
    modal.locator('input[placeholder="Snapshot description..."]').fill('patch night')
    modal.locator('[data-testid="guest-bulk-vmstate"]').check()
    _shot(app, f'bulk-snapshot-{layout}')
    modal.locator('[data-testid="guest-bulk-run"]').click()
    _wait_states(app, {'100': 'started', '200': 'started', '201': 'started'})
    # RAM only for the running VM: a container has none to save, a stopped VM neither
    assert sorted(app.pve.of('snapshot')) == [
        ('pve1', 100, 'qemu', 'before-patch', 'patch night', True),
        ('pve1', 201, 'lxc', 'before-patch', 'patch night', False),
        ('pve2', 200, 'lxc', 'before-patch', 'patch night', False)]
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_tags_are_added_and_removed_on_the_proxmox_config(real_app, layout):
    app = real_app(layout=layout)
    page = app.page
    _open_resources(app, layout)
    _tick(app, 100, 101, 200)
    modal = _bulk(app, 'tags')
    text = modal.locator('[data-testid="guest-bulk-tagtext"]')
    text.fill('web, -bad')
    assert modal.locator('[data-testid="guest-bulk-run"]').is_disabled()
    text.fill('web, Patch2026')
    _shot(app, f'bulk-tags-{layout}')
    modal.locator('[data-testid="guest-bulk-run"]').click()
    _wait_states(app, {'100': 'done', '101': 'done', '200': 'done'})
    # what a guest had stays, in its order; a tag it had in another case is not added twice
    assert sorted(app.pve.of('config')) == [
        ('pve1', 100, 'qemu', {'tags': 'prod;web;Patch2026'}),
        ('pve1', 101, 'qemu', {'tags': 'web;Patch2026'}),
        ('pve2', 200, 'lxc', {'tags': 'prod;web;Patch2026'})]
    modal.locator('[data-testid="guest-bulk-close"]').click()

    app.pve.calls.clear()
    modal = _bulk(app, 'tags')
    modal.locator('[data-testid="guest-bulk-tags-remove"]').click()
    modal.locator('[data-testid="guest-bulk-tagtext"]').fill('PROD')
    modal.locator('[data-testid="guest-bulk-run"]').click()
    # the page still lists the tags it read last: 101 had no prod, 200 had nothing else
    _wait_states(app, {'100': 'done', '101': 'skipped', '200': 'done'})
    assert 'no change' in modal.locator('[data-testid="guest-bulk-results"]').inner_text()
    assert sorted(app.pve.of('config')) == [
        ('pve1', 100, 'qemu', {'tags': 'web'}),
        ('pve2', 200, 'lxc', {'delete': 'tags'})]
    assert not app.errors, app.errors


def test_runtime_the_server_refuses_per_guest_and_the_dialog_says_so(real_app, seed):
    """The page of an admin, the session of a VM-ACL user who may act on 100 only: the
    route asks about each guest, and the refusal of the other one is listed."""
    seed.tenant('acme', clusters=['c1'])
    seed.vm_acl('c1', 100, users=['portal'])
    app = real_app(user=seed.user('portal', role='user', tenant_id='acme'), layout='corporate')
    _open_resources(app, 'corporate')
    _tick(app, 100, 101)
    modal = _bulk(app, 'reboot')
    modal.locator('[data-testid="guest-bulk-run"]').click()
    _wait_states(app, {'100': 'started', '101': 'failed'})
    assert 'Permission denied: vm.restart' in modal.inner_text()
    assert app.pve.of('power') == [('pve1', 100, 'qemu', 'reboot', False)]
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_a_standby_offers_no_bulk_action_and_no_star(real_app, layout):
    app = real_app(layout=layout, role='standby')
    page = app.page
    _open_resources(app, layout)
    _tick(app, 100, 101)
    page.wait_for_timeout(200)
    assert page.locator('button[data-bulk]').count() == 0
    assert page.locator('button[data-fav]').count() == 0
    assert app.pve.calls == []
    assert not app.errors, app.errors


def test_runtime_cloud_runs_its_bulk_bar_through_the_dialog(real_app):
    app = real_app(layout='cloud')
    page = app.page
    page.get_by_text('Virtual Machines').first.click()
    page.get_by_text('web01').first.wait_for(timeout=5000)
    asked = []
    page.on('dialog', lambda d: (asked.append(d.message), d.dismiss()))
    for name in ('web01', 'db01'):
        page.locator('tr', has_text=name).locator('input[type="checkbox"]').first.check()
    bar = page.locator('.cloud-bulkbar')
    assert 'Snapshot' in bar.inner_text() and 'Tags' in bar.inner_text()
    bar.locator('button', has_text='Shutdown').click()
    modal = page.locator('[data-testid="guest-bulk-modal"]')
    modal.wait_for(timeout=3000)
    _shot(app, 'bulk-cloud')
    modal.locator('[data-testid="guest-bulk-run"]').click()
    _wait_states(app, {'100': 'started', '101': 'started'})
    # one dialog, not a prompt per guest
    assert asked == []
    assert sorted(app.pve.of('power')) == [('pve1', 100, 'qemu', 'shutdown', False),
                                            ('pve1', 101, 'qemu', 'shutdown', False)]
    assert not app.errors, app.errors


# -- all guests of a node ------------------------------------------------------------------------

def _node_menu(app, node):
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    child = page.locator('.corp-inline-tree .corp-tree-child', has_text=node).first
    child.wait_for(timeout=5000)
    child.click(button='right')
    menu = page.locator('.corp-context-menu').first
    menu.wait_for(timeout=3000)
    return menu


def _submenu(app, menu, parent, item):
    menu.locator('.corp-ctx-item', has_text=parent).first.hover()
    sub = app.page.locator('.corp-context-menu').nth(1)
    sub.wait_for(timeout=3000)
    sub.locator('.corp-ctx-item', has_text=item).first.click()


def test_runtime_shut_down_all_guests_of_a_node_from_the_corporate_tree(real_app):
    app = real_app(layout='corporate')
    page = app.page
    menu = _node_menu(app, 'pve1')
    _shot(app, 'node-menu-corporate')
    _submenu(app, menu, 'All guests', 'Shut down all')
    modal = page.locator('[data-testid="node-guests-modal"]')
    modal.wait_for(timeout=3000)
    assert 'Shut down guests on pve1' in modal.inner_text()
    # the running guests of pve1, not the stopped ones and not those of pve2
    assert sorted(modal.locator('[data-guest]').evaluate_all('els => els.map(e => e.dataset.guest)')) == ['100', '101']
    assert '2 of 2 selected' in modal.inner_text()
    modal.locator('label[data-guest="101"] input').uncheck()
    assert '1 of 2 selected' in modal.inner_text()
    _shot(app, 'node-shutdown-all-corporate')
    modal.locator('[data-testid="node-guests-run"]').click()
    modal.locator('[data-testid="node-guests-result"]').wait_for(timeout=5000)
    assert 'Task started on pve1 for 1 guests.' in modal.inner_text()
    assert [c for c in app.server.sent if '/guests/' in c[1]] == [
        ('POST', '/api/clusters/c1/nodes/pve1/guests/stopall', {'vms': [100]})]
    assert app.pve.of('node') == [('pve1', 'stopall', [100], None, 1, False)]
    modal.locator('[data-testid="node-guests-close"]').click()
    assert page.locator('[data-testid="node-guests-modal"]').count() == 0
    assert not app.errors, app.errors


def test_runtime_migrate_all_guests_of_a_node_from_the_modern_card(real_app):
    """#952: the guests of a node move as a bulk run of the server, which follows each
    migration (tests/test_bulk_migrate_ui_952.py drives the run itself); the answers of the
    run routes here are canned."""
    run = {'id': 'feedc0de00000001', 'cluster_id': 'c1', 'target': 'pve3', 'mode': 'parallel', 'parallel': 2,
           'state': 'running', 'mine': True, 'total': 4, 'counts': {'wait': 4}, 'current': [], 'rows': [],
           'cancelled_by': '', 'reason': '', 'may_cancel': True}
    app = real_app(layout='modern', extra={
        ('POST', '/api/clusters/c1/vms/bulk-migrate'): (202, {'run': run}),
        ('GET', '/api/bulk-migrations'): (200, {'runs': [run]}),
        ('GET', f"/api/bulk-migrations/{run['id']}"): (200, {'run': run})})
    page = app.page
    page.get_by_text('Testi').first.click()
    page.locator('button[data-node-guests="pve1"]').wait_for(timeout=5000)
    page.locator('button[data-node-guests="pve1"]').click()
    menu = page.locator('[role="menu"]').first
    assert [a for a in menu.locator('[data-action]').evaluate_all('els => els.map(e => e.dataset.action)')] == [
        'startall', 'stopall', 'migrateall']
    _shot(app, 'node-menu-modern')
    menu.locator('[data-action="migrateall"]').click()
    modal = page.locator('[data-testid="node-guests-modal"]')
    modal.wait_for(timeout=3000)
    # every guest of pve1, the template too; the targets are the other nodes
    assert sorted(modal.locator('[data-guest]').evaluate_all('els => els.map(e => e.dataset.guest)')) == [
        '100', '101', '102', '201']
    target = modal.locator('[data-testid="node-guests-target"]')
    assert target.evaluate('s => Array.from(s.options).map(o => o.value)') == ['pve2', 'pve3']
    target.select_option('pve3')
    # four guests: one at a time unless picked otherwise
    assert modal.locator('[data-mig-mode="sequential"] input').is_checked()
    modal.locator('[data-mig-mode="parallel"] input[type="radio"]').check()
    modal.locator('[data-testid="mig-run-parallel"]').fill('2')
    modal.locator('label', has_text='Move local disks along').locator('input').check()
    _shot(app, 'node-migrate-all-modern')
    modal.locator('[data-testid="node-guests-run"]').click()
    page.locator('[data-testid="mig-run-modal"]').wait_for(timeout=5000)
    assert page.locator('[data-testid="node-guests-modal"]').count() == 0
    assert app.server.bodies['/api/clusters/c1/vms/bulk-migrate'] == [{
        'vms': [{'vmid': 100, 'node': 'pve1', 'type': 'qemu'}, {'vmid': 101, 'node': 'pve1', 'type': 'qemu'},
                {'vmid': 102, 'node': 'pve1', 'type': 'qemu'}, {'vmid': 201, 'node': 'pve1', 'type': 'lxc'}],
        'target': 'pve3', 'online': True, 'with_local_disks': True, 'mode': 'parallel', 'parallel': 2}]
    # the node endpoint of Proxmox is not asked for it any more
    assert [c for c in app.server.sent if '/guests/' in c[1]] == [] and app.pve.of('node') == []
    assert not app.errors, app.errors


def test_runtime_a_refusal_of_proxmox_stays_in_the_dialog(real_app):
    app = real_app(layout='modern', fail=('node',))
    page = app.page
    page.get_by_text('Testi').first.click()
    page.locator('button[data-node-guests="pve1"]').click()
    page.locator('[role="menu"] [data-action="startall"]').click()
    modal = page.locator('[data-testid="node-guests-modal"]')
    modal.wait_for(timeout=3000)
    assert sorted(modal.locator('[data-guest]').evaluate_all('els => els.map(e => e.dataset.guest)')) == ['201']
    assert 'not set to start at boot' in modal.inner_text()
    modal.locator('[data-testid="node-guests-run"]').click()
    modal.locator('[data-testid="node-guests-error"]').wait_for(timeout=5000)
    assert 'no quorum' in modal.inner_text()
    # the form stays for another try
    assert not modal.locator('[data-testid="node-guests-run"]').is_disabled()
    assert not app.errors, app.errors


def test_runtime_who_may_not_act_gets_no_guests_entry(real_app):
    """A viewer still stars, the guests of a node are not theirs to act on; a standby
    shows neither."""
    app = real_app(layout='corporate', admin=False)
    menu = _node_menu(app, 'pve1')
    text = menu.inner_text()
    assert 'All guests' not in text and 'Add to favorites' in text, text
    app.page.keyboard.press('Escape')

    standby = real_app(layout='corporate', role='standby')
    menu = _node_menu(standby, 'pve1')
    text = menu.inner_text()
    assert 'All guests' not in text and 'favorites' not in text, text
    standby.page.keyboard.press('Escape')
    standby.page.mouse.click(5, 900)
    standby.page.locator('.corp-inline-tree .corp-tree-child', has_text='db01').first.click(button='right')
    vm_menu = standby.page.locator('.corp-context-menu').first
    vm_menu.wait_for(timeout=3000)
    assert 'favorites' not in vm_menu.inner_text()

    modern = real_app(layout='modern', role='standby')
    modern.page.get_by_text('Testi').first.click()
    modern.page.locator('button[title="Node Configuration"]').first.wait_for(timeout=5000)
    assert modern.page.locator('button[data-node-guests]').count() == 0
    assert modern.page.locator('button[data-fav]').count() == 0
    for a in (app, standby, modern):
        assert not a.errors, a.errors


# -- favorites ---------------------------------------------------------------------------------

def _fav_rows():
    import pegaprox.core.db as dbmod
    return sorted(tuple(r) for r in dbmod.get_db().conn.execute(
        'SELECT username, kind, cluster_id, vmid, node FROM user_favorites'))


def _group(app):
    return app.page.locator('[data-testid="sidebar-favorites"]')


def _group_rows(app):
    return _group(app).locator('[data-fav-row]').evaluate_all('els => els.map(e => e.dataset.favRow)')


def _wait_rows(app, want, seconds=5):
    for _ in range(int(seconds * 10)):
        if _group(app).count() and sorted(_group_rows(app)) == sorted(want):
            return
        app.page.wait_for_timeout(100)
    assert sorted(_group_rows(app)) == sorted(want)


def _ctx_click(app, locator, entry):
    locator.click(button='right')
    menu = app.page.locator('.corp-context-menu').first
    menu.wait_for(timeout=3000)
    menu.locator('.corp-ctx-item', has_text=entry).first.click()
    app.page.wait_for_timeout(300)


def test_runtime_stars_from_the_corporate_menus_fill_the_group_and_stay(real_app):
    app = real_app(layout='corporate')
    page = app.page
    assert _group(app).count() == 0
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.locator('.corp-inline-tree .corp-tree-child', has_text='db01').first.wait_for(timeout=5000)
    _ctx_click(app, page.locator('.corp-inline-tree .corp-tree-child', has_text='db01').first, 'Add to favorites')
    _ctx_click(app, page.locator('.corp-inline-tree .corp-tree-child', has_text='pve2').first, 'Add to favorites')
    _ctx_click(app, page.locator('.corp-tree-item', has_text='Testi').first, 'Add to favorites')
    _wait_rows(app, ['c:c1', 'n:c1:pve2', 'v:c1:101'])
    assert _fav_rows() == [('admin', 'cluster', 'c1', None, ''), ('admin', 'node', 'c1', None, 'pve2'),
                           ('admin', 'vm', 'c1', 101, '')]
    # the menu says what a second click does
    page.locator('.corp-inline-tree .corp-tree-child', has_text='db01').first.click(button='right')
    assert 'Remove from favorites' in page.locator('.corp-context-menu').first.inner_text()
    page.keyboard.press('Escape')
    page.mouse.click(5, 900)
    # above the clusters, flat rows
    assert page.evaluate('''() => {
        const g = document.querySelector('[data-testid="sidebar-favorites"]');
        const c = document.querySelector('.corp-tree-item');
        return !!(g.compareDocumentPosition(c) & Node.DOCUMENT_POSITION_FOLLOWING);
    }''')
    assert _group(app).locator('.corp-inline-tree, .corp-pool-tree').count() == 0
    _shot(app, 'favorites-corporate')

    # a new page reads them from the server, and a row opens what it names
    page.reload()
    app.wait_for_app()
    _wait_rows(app, ['c:c1', 'n:c1:pve2', 'v:c1:101'])
    _group(app).locator('[data-fav-row="v:c1:101"]').click()
    page.locator('.corp-breadcrumb-current', has_text='db01').first.wait_for(timeout=5000)

    # shut and open per viewer, through a reload
    page.locator('[data-testid="sidebar-favorites-toggle"]').click()
    assert _group(app).locator('[data-fav-row]').count() == 0
    assert page.evaluate("() => localStorage.getItem('pegaprox-sidebar-favorites-admin')") == '1'
    page.reload()
    app.wait_for_app()
    _group(app).wait_for(timeout=5000)
    page.wait_for_timeout(500)
    assert _group(app).locator('[data-fav-row]').count() == 0
    page.locator('[data-testid="sidebar-favorites-toggle"]').click()
    _wait_rows(app, ['c:c1', 'n:c1:pve2', 'v:c1:101'])

    # the star of a row takes it off
    _group(app).locator('[data-unstar="n:c1:pve2"]').click()
    _wait_rows(app, ['c:c1', 'v:c1:101'])
    assert _fav_rows() == [('admin', 'cluster', 'c1', None, ''), ('admin', 'vm', 'c1', 101, '')]
    assert not app.errors, app.errors


def test_runtime_stars_in_modern_from_the_card_menu_and_the_node_card(real_app):
    app = real_app(layout='modern')
    page = app.page
    page.get_by_text('Testi').first.click()
    star = page.locator('xpath=//h3[normalize-space()="pve2"]/ancestor::div[contains(@class,"card-hover")][1]//button[@data-fav]')
    star.wait_for(timeout=5000)
    star.click()
    page.locator('button', has_text='Resources').first.click()
    page.get_by_text('db01').first.wait_for(timeout=5000)
    card = page.locator('xpath=//div[contains(@class,"rounded-xl") and contains(@class,"overflow-hidden")]'
                        '[.//div[normalize-space()="db01"]]').first
    card.locator('button[title="More Actions"]').click()
    page.locator('button[data-fav="off"]', has_text='Add to favorites').first.click()
    _wait_rows(app, ['n:c1:pve2', 'v:c1:101'])
    _shot(app, 'favorites-modern')
    # the table shows the star lit
    page.locator('button[title="List View"]').first.click()
    lit = page.locator('table tbody tr', has_text='db01').locator('button[data-fav]')
    assert lit.get_attribute('data-fav') == 'on'
    assert lit.get_attribute('title') == 'Remove from favorites'
    # the node row opens the overview of the node
    _group(app).locator('[data-fav-row="n:c1:pve2"]').click()
    page.wait_for_timeout(600)
    assert page.locator('button', has_text='Overview').first.get_attribute('class').find('bg-proxmox-orange') >= 0
    page.reload()
    app.wait_for_app()
    _wait_rows(app, ['n:c1:pve2', 'v:c1:101'])
    # unstar from the table
    page.get_by_text('Testi').first.click()
    page.locator('button', has_text='Resources').first.click()
    page.locator('button[title="List View"]').first.click()
    page.locator('table tbody tr', has_text='db01').locator('button[data-fav="on"]').click()
    _wait_rows(app, ['n:c1:pve2'])
    assert _fav_rows() == [('admin', 'node', 'c1', None, 'pve2')]
    assert not app.errors, app.errors


def test_runtime_a_standby_shows_the_group_without_stars_to_change(real_app, seed):
    from test_favorites import _insert
    admin = seed.user('admin', role='admin')
    _insert('admin', vmid=100, vm_type='qemu', name='web01', cluster_id='c1')
    app = real_app(user=admin, layout='modern', role='standby')
    _wait_rows(app, ['v:c1:100'])
    assert _group(app).locator('[data-unstar]').count() == 0
    assert not app.errors, app.errors
