"""All Guests: the guest table of every cluster, in Modern and Corporate.

The source checks read web/src and the bundle. The runtime tests drive the built bundle in
headless Chromium: the page around it comes from the fake server of tests/test_ha_ui.py,
the table's page route and the per-guest routes the dialogs call are the real routes of
the app, as the user of the session, against faked cluster managers. So what the table
lists is what the server scoped for that user, and what an action sends is what the
server takes. They skip where Playwright is not installed. The route itself is tested in
tests/test_global_guest_table.py.
LW Oct 2026
"""
import json
import os
import re

import pytest

from test_ha_ui import (BASE, LANGS, _App, _FakeServer, _blocks, _classes, _toasts,  # noqa: F401 (browser is a fixture)
                        browser)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHOTS = os.environ.get('PEGAPROX_UI_SHOTS', '')
GiB = 1024 ** 3

KEYS = ['allGuestsTitle', 'allGuestsDesc', 'allGuestsHint', 'allGuestsSearch', 'allGuestsAnyCluster',
        'allGuestsAnyStatus', 'allGuestsAnyType', 'allGuestsOther', 'allGuestsTemplates', 'allGuestsNoPermission',
        'allGuestsLeftOut', 'allGuestsOneCluster', 'allGuestsEmpty', 'allGuestsNoMatch', 'allGuestsFailed',
        'allGuestsRange', 'allGuestsPrevPage', 'allGuestsNextPage', 'allGuestsNotListed', 'allGuestsOffline',
        'allGuestsUnreadable', 'allGuestsOpen', 'allGuestsPickPage']


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def _view():
    src = _read('web', 'src', 'tables.js')
    return src[src.index('// LW Oct 2026 - All Guests: every guest'):]


def _sidebar():
    dash = _read('web', 'src', 'dashboard.js')
    start = dash.index('{/* LW Oct 2026 - All Guests, one table')
    return dash[start:dash.index('</button>', start)]


def _links():
    vm = _read('web', 'src', 'vm_modals.js')
    return '\n'.join(vm[m.start() - 200:vm.index('</button>', m.start())] for m in re.finditer('data-all-guests-link', vm))


# --- source --------------------------------------------------------------------------------

@pytest.mark.parametrize('lang', LANGS)
def test_every_new_key_is_in_every_language_once(lang):
    block = _blocks()[lang]
    for key in KEYS:
        n = len(re.findall(rf'^ +{key}: ', block, re.M))
        assert n == 1, f'{key} appears {n} times in {lang}'


def test_every_new_key_is_used_and_nothing_uses_a_missing_one():
    src = ''.join(_read('web', 'src', n) for n in ('tables.js', 'dashboard.js', 'vm_modals.js'))
    used = set(re.findall(r"t\('(allGuests[A-Za-z]*)'\)", src))
    assert used == set(KEYS), (sorted(used - set(KEYS)), sorted(set(KEYS) - used))


def test_placeholders_survive_translation():
    blocks = _blocks()
    for key in KEYS:
        en = re.search(rf'^ +{key}: (.*),$', blocks['en'], re.M).group(1)
        for lang, block in blocks.items():
            value = re.search(rf'^ +{key}: (.*),$', block, re.M).group(1)
            assert sorted(re.findall(r'\{\w+\}', value)) == sorted(re.findall(r'\{\w+\}', en)), (lang, key, value)


def test_no_em_dash_in_what_this_change_added():
    for block in (_view(), _sidebar(), _links()):
        assert '\u2014' not in block and '\u2013' not in block
    for block in _blocks().values():
        for line in block.splitlines():
            if re.match(r'^ +allGuests\w*: ', line):
                assert '\u2014' not in line and '\u2013' not in line, line


def test_the_austrian_flag_stays_on_german():
    assert "{ code: 'de', flag: '\U0001F1E6\U0001F1F9'," in _read('web', 'src', 'contexts.js')


def test_the_icons_exist():
    icons = set(re.findall(r'^ {12}([A-Z][A-Za-z0-9]*):', _read('web', 'src', 'icons.js'), re.M))
    used = set(re.findall(r'Icons\.([A-Za-z]+)', _view() + _sidebar() + _links()))
    assert used and used <= icons, sorted(used - icons)


def test_every_class_is_in_the_static_tailwind_build():
    shell = '\n'.join(line for line in _read('web', 'index.html.original').split('\n')
                      if 'data-corp-theme="light"' not in line)
    css = _read('static', 'css', 'tailwind.min.css') + shell
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    names = _classes(_view()) | _classes(_sidebar()) | _classes(_links())
    missing = sorted(n for n in names if n not in have)
    assert not missing, f'not in static/css/tailwind.min.css: {missing}'


def test_it_reads_one_route_and_acts_through_the_bulk_dialogs():
    view = _view()
    # one page from the server, the node list of a cluster for the migration target
    assert view.count('authFetch(`${API_URL}/inventory/guests/page?${p.toString()}`)') == 1
    assert view.count('authFetch(`${API_URL}/clusters/${encodeURIComponent(cid)}/metrics`)') == 1
    assert 'method:' not in view and 'fetch(`' not in view.replace('authFetch(`', '')
    # the actions are the dialogs of the guest table, which call the per-guest routes
    assert '<GuestBulkActionModal action={bulk.action} guests={bulk.guests} authFetch={authFetch}' in view
    assert '<BulkMigrateModal vms={migrate.vms} nodes={migrate.nodes} clusterId={migrate.clusterId}' in view
    # every stored size is read and written inside a try
    for m in re.finditer(r'localStorage\.(get|set)Item\(ALL_GUESTS_SIZE_KEY', view):
        line = view[view.rindex('\n', 0, m.start()):view.index('\n', m.start())]
        assert 'try {' in line and 'catch (e)' in line, line


def test_a_standby_gets_no_selection_and_no_action():
    view = _view()
    assert 'const acts = !haReadOnly;' in view
    # the checkboxes and both action bars hang off acts
    assert view.count('{acts && pickedList.length > 0 && (') == 2
    assert view.count('{acts && <th') == 2 and view.count('{acts && <td') == 2


def test_both_layouts_have_an_entry_and_the_overview_links_to_it():
    dash = _read('web', 'src', 'dashboard.js')
    assert 'onClick={openGuests}' in _sidebar() and 'data-sidebar-guests' in _sidebar()
    assert "{ id: 'guests', show: true, active: sidebarGuests, label: t('allGuestsTitle'), onClick: openGuests," in dash
    assert dash.index(') : sidebarGuests ? (') < dash.index('<AllClustersOverview')
    assert 'onOpenGuests={openGuests}' in dash
    assert _links().count('onClick={onOpenGuests}') == 2


def test_the_bundle_was_rebuilt():
    built = _read('web', 'index.html')
    for needle in ('function AllGuestsView(', '/inventory/guests/page?', 'data-all-guests-row', 'data-sidebar-guests',
                   'allGuestsNoPermission', 'pegaprox-all-guests-size'):
        assert needle in built, needle


# --- runtime: the built bundle against the real routes ----------------------------------------

def _c(cid, name, connected=True):
    return {'id': cid, 'name': name, 'display_name': name, 'host': '10.0.0.1', 'connected': connected,
            'status': 'running' if connected else 'offline', 'cluster_type': 'proxmox', 'enabled': True}


C1 = dict(_c('c1', 'Testi'), display_name='Testi (Vienna)')
C2 = _c('c2', 'Branch')
C3 = _c('c3', 'Cold', connected=False)
_LOAD = {'cpu': 0.05, 'maxcpu': 2, 'mem': GiB, 'maxmem': 4 * GiB, 'disk': 0, 'maxdisk': 32 * GiB, 'uptime': 3600}
GUESTS_C1 = [
    dict(_LOAD, vmid=100, name='web01', type='qemu', status='running', node='pve1', tags='prod;web', cpu=0.25,
         uptime=90000),
    dict(_LOAD, vmid=101, name='db01', type='qemu', status='running', node='pve2', cpu=0.6),
    dict(_LOAD, vmid=102, name='tpl01', type='qemu', status='stopped', node='pve1', template=1, cpu=0, mem=0, uptime=0),
    dict(_LOAD, vmid=200, name='ct01', type='lxc', status='running', node='pve2', tags='prod', disk=2 * GiB,
         maxdisk=8 * GiB, cpu=0.1),
]
GUESTS_C2 = [
    dict(_LOAD, vmid=300, name='erp', type='qemu', status='running', node='b1', cpu=0.9),
    dict(_LOAD, vmid=301, name='lab', type='qemu', status='stopped', node='b1', cpu=0, mem=0, uptime=0),
]
BY_NAME = ['c1:200', 'c1:101', 'c2:300', 'c2:301', 'c1:102', 'c1:100']
_NODE = {'status': 'online', 'cpu_percent': 5.0, 'mem_percent': 20.0, 'uptime': 86400, 'maintenance_mode': False}
METRICS = {'pve1': dict(_NODE), 'pve2': dict(_NODE), 'pve3': dict(_NODE), 'pve4': dict(_NODE, status='offline')}
PAGE = '/api/inventory/guests/page'
REAL = re.compile(r'^/api/(inventory/guests/page|clusters/c[123]/vms/[^/]+/(qemu|lxc)/\d+/(start|shutdown|stop|reboot|snapshots))$')


class _Server(_FakeServer):
    """The page from the fake server; the table and the per-guest routes from the app."""

    def __init__(self, client, **kw):
        kw.setdefault('clusters', [C1, C2, C3])
        kw.setdefault('resources', [])
        kw.setdefault('metrics', METRICS)
        kw.setdefault('role', 'standalone')
        super().__init__(**kw)
        self.client = client
        self.sent = []

    def handle(self, route):
        req = route.request
        path = re.sub(r'^https?://[^/]+', '', req.url)
        bare = path.split('?')[0]
        if not req.url.startswith(BASE) or not REAL.match(bare) or (req.method, bare) in self.extra:
            return super().handle(route)
        raw = req.post_data or ''
        self.calls.append((req.method, bare))
        self.urls.append(req.url)
        if req.method != 'GET':
            self.sent.append((req.method, bare, json.loads(raw) if raw else None))
            if self.role == 'standby':
                return route.fulfill(status=409, headers={'Content-Type': 'application/json'}, body=json.dumps(
                    {'error': 'This is a standby instance.', 'code': 'HA_STANDBY'}))
        if req.method == 'GET':
            r = self.client.get(path)
        else:
            r = getattr(self.client, req.method.lower())(bare, data=raw, headers={'Content-Type': 'application/json'})
        return route.fulfill(status=r.status_code, body=r.get_data(), headers={'Content-Type': 'application/json'})


class _Clusters:
    """The cluster managers the routes call, with a log of what the guests were asked to do."""

    def __init__(self, api, c1=GUESTS_C1, c2=GUESTS_C2):
        self.calls = []
        for cid, name, guests in (('c1', 'Testi', c1), ('c2', 'Branch', c2), ('c3', 'Cold', [])):
            m = api.make_fake_manager(cluster_id=cid, get_vm_resources=[dict(g) for g in guests],
                                      get_pools=[], get_node_status={n: {'status': 'online'} for n in METRICS})
            m.is_connected = cid != 'c3'
            m.config.name = name
            m.vm_action.side_effect = lambda node, vmid, vm_type, action, force=False, _c=cid: self._power(
                _c, node, vmid, vm_type, action, force)
            m.create_snapshot.side_effect = lambda node, vmid, vm_type, snapname, description, vmstate, _c=cid: \
                self._snap(_c, node, vmid, vm_type, snapname, vmstate)
            api.set_manager(cid, m)

    def _power(self, cid, node, vmid, vm_type, action, force):
        self.calls.append(('power', cid, node, vmid, vm_type, action, force))
        return {'success': True, 'data': f'UPID:{node}:{vmid}:{action}'}

    def _snap(self, cid, node, vmid, vm_type, snapname, vmstate):
        self.calls.append(('snapshot', cid, node, vmid, vm_type, snapname, bool(vmstate)))
        return {'success': True, 'task': f'UPID:{node}:{vmid}:snap'}

    def of(self, kind):
        return sorted(c[1:] for c in self.calls if c[0] == kind)


@pytest.fixture
def real_app(browser, api, seed):  # noqa: F811
    apps = []

    def _open(user=None, c1=GUESTS_C1, c2=GUESTS_C2, **kw):
        who = user or seed.user('admin', role='admin')
        managers = _Clusters(api, c1, c2)
        app = _App(browser, _Server(api.as_user(who), **kw))
        app.pve = managers
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _shot(app, name):
    if SHOTS:
        os.makedirs(SHOTS, exist_ok=True)
        app.page.screenshot(path=os.path.join(SHOTS, f'{name}.png'))


def _open_table(app, layout):
    page = app.page
    if layout == 'corporate':
        page.locator('[data-corp-tool="guests"]').click()
    else:
        page.locator('[data-sidebar-guests]').click()
    page.locator('[data-all-guests]').wait_for(timeout=10000)
    page.locator('[data-all-guests-row]').first.wait_for(timeout=10000)
    page.wait_for_timeout(200)


def _rows(page):
    return page.locator('[data-all-guests-row]').evaluate_all('rs => rs.map(r => r.dataset.allGuestsRow)')


def _wait_rows(app, want, seconds=6):
    for _ in range(int(seconds * 10)):
        if _rows(app.page) == want:
            return
        app.page.wait_for_timeout(100)
    assert _rows(app.page) == want


def _cells(page, key):
    return page.locator(f'[data-all-guests-row="{key}"] td').evaluate_all('ts => ts.map(t => t.innerText.trim())')


def _pages(app):
    return [u.split(PAGE, 1)[1] for u in app.server.urls if PAGE in u]


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
def test_runtime_every_guest_of_every_cluster_in_one_table(real_app, layout):
    app = real_app(layout=layout)
    page = app.page
    _open_table(app, layout)
    assert _rows(page) == BY_NAME
    assert _pages(app) == ['?limit=100&offset=0&sort=name&dir=asc']
    # checkbox, ID, name, cluster, node, status, CPU, RAM, disk, uptime, IP, tags
    web = _cells(page, 'c1:100')
    assert web[1:11] == ['100', 'web01', 'Testi (Vienna)', 'pve1', 'Running', '25%', '1.0 GB / 4.0 GB', '32.0 GB',
                         '1d 1h', '-']
    assert re.sub(r'[\s,]+', ' ', web[11]) == 'prod web'
    # a container reports its used disk; a stopped guest shows its size and no figures
    assert _cells(page, 'c1:200')[8] == '2.0 GB / 8.0 GB'
    assert _cells(page, 'c2:301')[3:10] == ['Branch', 'b1', 'Stopped', '-', '4.0 GB', '32.0 GB', '-']
    assert 'Template' in _cells(page, 'c1:102')[2].replace('TEMPLATE', 'Template')
    assert page.locator('[data-all-guests-total]').inner_text().strip('() ') == '6'
    assert page.locator('[data-all-guests-count="running"]').inner_text().strip() == '4 Running'
    assert page.locator('[data-all-guests-count="stopped"]').inner_text().strip() == '2 Stopped'
    assert page.locator('[data-all-guests-range]').inner_text() == '1-6 of 6'
    assert page.locator('[data-all-guests-unlisted]').inner_text() == 'Not listed: Cold (offline)'
    # the entry is lit, All Clusters is not
    if layout == 'corporate':
        assert page.locator('[data-corp-tool="guests"]').evaluate('b => b.style.borderLeft') != ''
        assert page.locator('.corp-header-title').inner_text().strip() == 'All Guests'
    _shot(app, f'all-guests-{layout}')
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_sort_filter_and_search_ask_the_server(real_app, layout):
    app = real_app(layout=layout)
    page = app.page
    _open_table(app, layout)
    page.locator('[data-all-guests-sort="cpu"]').click()
    _wait_rows(app, ['c2:300', 'c1:101', 'c1:100', 'c1:200', 'c2:301', 'c1:102'])
    assert _pages(app)[-1] == '?limit=100&offset=0&sort=cpu&dir=desc'
    # the other way round; two idle guests keep the order of their clusters either way
    page.locator('[data-all-guests-sort="cpu"]').click()
    _wait_rows(app, ['c2:301', 'c1:102', 'c1:200', 'c1:100', 'c1:101', 'c2:300'])
    assert _pages(app)[-1] == '?limit=100&offset=0&sort=cpu&dir=asc'
    page.locator('[data-all-guests-sort="name"]').click()
    _wait_rows(app, BY_NAME)

    page.locator('[data-all-guests-search]').fill('web')
    _wait_rows(app, ['c1:100'])
    assert 'q=web' in _pages(app)[-1]
    page.locator('[data-all-guests-search]').fill('nothing-like-it')
    page.locator('[data-all-guests-empty]').wait_for(timeout=5000)
    assert page.locator('[data-all-guests-empty]').inner_text() == 'No guest matches the filters.'
    page.locator('[data-all-guests-search]').fill('')
    _wait_rows(app, BY_NAME)

    page.locator('[data-all-guests-status]').select_option('stopped')
    _wait_rows(app, ['c2:301', 'c1:102'])
    page.locator('[data-all-guests-type]').select_option('template')
    _wait_rows(app, ['c1:102'])
    page.locator('[data-all-guests-status]').select_option('')
    page.locator('[data-all-guests-type]').select_option('')
    page.locator('[data-all-guests-tag]').select_option('prod')
    _wait_rows(app, ['c1:200', 'c1:100'])
    page.locator('[data-all-guests-tag]').select_option('')
    # the cluster list names a cluster as the page does
    options = page.locator('[data-all-guests-cluster] option').evaluate_all('os => os.map(o => o.textContent)')
    assert options == ['All clusters', 'Branch', 'Cold', 'Testi (Vienna)']
    page.locator('[data-all-guests-cluster]').select_option('c2')
    _wait_rows(app, ['c2:300', 'c2:301'])
    assert 'cluster=c2' in _pages(app)[-1]
    # a status count filters as well
    page.locator('[data-all-guests-count="running"]').click()
    _wait_rows(app, ['c2:300'])
    assert not app.errors, app.errors


MANY = [dict(_LOAD, vmid=1000 + i, name=f'lab{i:03d}', type='qemu', status='running', node='b1') for i in range(120)]


def test_runtime_pages_of_a_large_list(real_app):
    app = real_app(layout='modern', c2=MANY)
    page = app.page
    _open_table(app, 'modern')
    assert len(_rows(page)) == 100
    assert page.locator('[data-all-guests-range]').inner_text() == '1-100 of 124'
    page.locator('[data-all-guests-size]').select_option('50')
    for _ in range(50):
        if len(_rows(page)) == 50:
            break
        page.wait_for_timeout(100)
    assert page.locator('[data-all-guests-range]').inner_text() == '1-50 of 124'
    assert page.locator('[data-all-guests-prev]').is_disabled()
    page.locator('[data-all-guests-next]').click()
    page.wait_for_function('() => document.querySelector("[data-all-guests-range]").innerText === "51-100 of 124"', timeout=5000)
    assert _pages(app)[-1] == '?limit=50&offset=50&sort=name&dir=asc'
    page.locator('[data-all-guests-next]').click()
    page.wait_for_function('() => document.querySelector("[data-all-guests-range]").innerText === "101-124 of 124"', timeout=5000)
    assert page.locator('[data-all-guests-next]').is_disabled() and len(_rows(page)) == 24
    # a pick stays picked on another page
    page.locator('[data-all-guests-pick="c2:1119"]').check()
    page.locator('[data-all-guests-prev]').click()
    page.wait_for_function('() => document.querySelector("[data-all-guests-range]").innerText === "51-100 of 124"', timeout=5000)
    page.locator('[data-all-guests-pick-page]').check()
    assert page.locator('[data-all-guests-picked]').inner_text().strip() == '51 selected'
    # the size is the user's: a reload keeps it
    page.reload(wait_until='load')
    app.wait_for_app()
    _open_table(app, 'modern')
    assert page.locator('[data-all-guests-size]').input_value() == '50' and len(_rows(page)) == 50
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_a_bulk_action_reaches_the_guests_of_two_clusters(real_app, layout):
    app = real_app(layout=layout)
    page = app.page
    _open_table(app, layout)
    for key in ('c1:100', 'c2:300', 'c2:301', 'c1:102'):
        page.locator(f'[data-all-guests-pick="{key}"]').check()
    assert page.locator('[data-all-guests-picked]').inner_text().strip() == '4 selected'
    page.locator('[data-all-guests-action="shutdown"]').click()
    modal = page.locator('[data-testid="guest-bulk-modal"]')
    modal.wait_for(timeout=3000)
    assert 'Shutdown: 4 guests' in modal.inner_text()
    skipped = modal.locator('[data-testid="guest-bulk-skipped"]').inner_text()
    assert 'tpl01' in skipped and 'lab' in skipped
    _shot(app, f'all-guests-bulk-{layout}')
    modal.locator('[data-testid="guest-bulk-run"]').click()
    _wait_states(app, {'100': 'started', '300': 'started'})
    assert app.pve.of('power') == [('c1', 'pve1', 100, 'qemu', 'shutdown', False),
                                   ('c2', 'b1', 300, 'qemu', 'shutdown', False)]
    assert sorted(c[1] for c in app.server.sent) == ['/api/clusters/c1/vms/pve1/qemu/100/shutdown',
                                                      '/api/clusters/c2/vms/b1/qemu/300/shutdown']
    before = len(_pages(app))
    modal.locator('[data-testid="guest-bulk-close"]').click()
    # the table reads again after the dialog is done
    for _ in range(40):
        if len(_pages(app)) > before:
            break
        page.wait_for_timeout(100)
    assert len(_pages(app)) > before

    # a force stop sends what a single row's force stop sends
    app.pve.calls.clear()
    page.locator('[data-all-guests-clear]').click()
    page.locator('[data-all-guests-pick="c1:101"]').check()
    page.locator('[data-all-guests-action="stop"]').click()
    modal.wait_for(timeout=3000)
    modal.locator('[data-testid="guest-bulk-run"]').click()
    _wait_states(app, {'101': 'started'})
    assert app.server.sent[-1] == ('POST', '/api/clusters/c1/vms/pve2/qemu/101/stop', {'force': True})
    assert not app.errors, app.errors


def test_runtime_a_snapshot_of_guests_of_two_clusters(real_app):
    app = real_app(layout='corporate')
    page = app.page
    _open_table(app, 'corporate')
    for key in ('c1:200', 'c2:301'):
        page.locator(f'[data-all-guests-pick="{key}"]').check()
    page.locator('[data-all-guests-action="snapshot"]').click()
    modal = page.locator('[data-testid="guest-bulk-modal"]')
    modal.wait_for(timeout=3000)
    modal.locator('[data-testid="guest-bulk-snapname"]').fill('before-patch')
    modal.locator('[data-testid="guest-bulk-run"]').click()
    _wait_states(app, {'200': 'started', '301': 'started'})
    assert app.pve.of('snapshot') == [('c1', 'pve2', 200, 'lxc', 'before-patch', False),
                                      ('c2', 'b1', 301, 'qemu', 'before-patch', False)]
    assert not app.errors, app.errors


def test_runtime_each_row_offers_what_its_guest_takes_from_the_user(real_app, seed):
    """The page of a viewer whose ACL grants one guest of Testi: Branch they only see."""
    seed.tenant('acme', ['c1', 'c2'])
    seed.vm_acl('c1', 101, users=['portal'])
    app = real_app(user=seed.user('portal', role='viewer', tenant_id='acme'), layout='modern', admin=False,
                   permissions=['vm.view'])
    page = app.page
    _open_table(app, 'modern')
    # of Testi only the guest of the ACL, all of Branch
    assert _rows(page) == ['c1:101', 'c2:300', 'c2:301']
    page.locator('[data-all-guests-pick="c2:300"]').check()
    for action in ('start', 'shutdown', 'reboot', 'stop', 'snapshot', 'migrate'):
        assert page.locator(f'[data-all-guests-action="{action}"]').is_disabled(), action
    page.locator('[data-all-guests-pick="c1:101"]').check()
    button = page.locator('[data-all-guests-action="reboot"]')
    assert not button.is_disabled()
    assert button.get_attribute('title') == 'You may not do this to 1 of the selected guests'
    button.click()
    modal = page.locator('[data-testid="guest-bulk-modal"]')
    modal.wait_for(timeout=3000)
    assert 'Reboot: 1 guests' in modal.inner_text() and 'erp' not in modal.inner_text()
    page.wait_for_timeout(300)
    assert any('1 of the selected guests left out' in x for x in _toasts(page)), _toasts(page)
    modal.locator('[data-testid="guest-bulk-run"]').click()
    _wait_states(app, {'101': 'started'})
    assert app.pve.of('power') == [('c1', 'pve2', 101, 'qemu', 'reboot', False)]
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_migration_moves_guests_within_one_cluster(real_app, layout):
    run = {'id': 'feedc0de00000002', 'cluster_id': 'c1', 'target': 'pve3', 'mode': 'sequential', 'parallel': 1,
           'state': 'running', 'mine': True, 'total': 2, 'counts': {'wait': 2}, 'current': [], 'rows': [],
           'cancelled_by': '', 'reason': '', 'may_cancel': True}
    app = real_app(layout=layout, extra={
        ('POST', '/api/clusters/c1/vms/bulk-migrate'): (202, {'run': run}),
        ('GET', '/api/bulk-migrations'): (200, {'runs': [run]}),
        ('GET', f"/api/bulk-migrations/{run['id']}"): (200, {'run': run})})
    page = app.page
    _open_table(app, layout)
    page.locator('[data-all-guests-pick="c1:100"]').check()
    page.locator('[data-all-guests-pick="c2:300"]').check()
    button = page.locator('[data-all-guests-action="migrate"]')
    assert button.is_disabled()
    assert button.get_attribute('title') == \
        'Migration moves guests within one cluster: select guests of one cluster only'
    page.locator('[data-all-guests-pick="c2:300"]').uncheck()
    page.locator('[data-all-guests-pick="c1:101"]').check()
    button.click()
    modal = page.locator('[data-testid="bulk-migrate-modal"]')
    modal.wait_for(timeout=5000)
    assert ('GET', '/api/clusters/c1/metrics') in app.server.calls
    # the online nodes of the cluster; the guests sit on two of them, so all three are offered
    target = modal.locator('[data-testid="bulk-migrate-target"]')
    assert target.evaluate('s => Array.from(s.options).map(o => o.value)') == ['', 'pve1', 'pve2', 'pve3']
    target.select_option('pve3')
    _shot(app, f'all-guests-migrate-{layout}')
    modal.locator('[data-testid="bulk-migrate-run"]').click()
    page.locator('[data-testid="mig-run-modal"]').wait_for(timeout=5000)
    # the run of the server (#952), two guests start at once unless picked otherwise
    assert app.server.bodies['/api/clusters/c1/vms/bulk-migrate'] == [{
        'vms': [{'vmid': 100, 'node': 'pve1', 'type': 'qemu'}, {'vmid': 101, 'node': 'pve2', 'type': 'qemu'}],
        'target': 'pve3', 'online': True, 'with_local_disks': False, 'mode': 'all'}]
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_a_standby_lists_the_guests_and_offers_nothing_to_do(real_app, layout):
    app = real_app(layout=layout, role='standby')
    page = app.page
    _open_table(app, layout)
    assert _rows(page) == BY_NAME
    assert page.locator('[data-all-guests-pick]').count() == 0
    assert page.locator('[data-all-guests-pick-page]').count() == 0
    assert page.locator('[data-all-guests-action]').count() == 0
    page.locator('[data-all-guests-refresh]').click()
    page.wait_for_timeout(500)
    _shot(app, f'all-guests-standby-{layout}')
    assert not [c for c in app.server.calls if c[0] != 'GET' and c[1] not in ('/api/sse/token', '/api/sse/subscribe')]
    assert app.pve.calls == []
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_the_overview_links_to_it_and_a_name_opens_the_guest(real_app, layout):
    app = real_app(layout=layout, resources=[dict(g) for g in GUESTS_C1])
    page = app.page
    link = page.locator('[data-all-guests-link]')
    link.wait_for(timeout=10000)
    assert 'All Guests' in link.inner_text()
    _shot(app, f'all-guests-overview-link-{layout}')
    link.click()
    page.locator('[data-all-guests-row]').first.wait_for(timeout=10000)
    page.locator('[data-all-guests-open="c1:100"]').click()
    page.wait_for_function('() => !document.querySelector("[data-all-guests]")', timeout=5000)
    page.get_by_text('web01').first.wait_for(timeout=5000)
    assert ('GET', '/api/clusters/c1/resources') in app.server.calls
    # and back through the sidebar
    _open_table(app, layout)
    page.locator('.pp-sidebar button', has_text='All Clusters').first.click()
    page.wait_for_function('() => !document.querySelector("[data-all-guests]")', timeout=5000)
    assert not app.errors, app.errors


def test_runtime_a_failed_read_says_so(real_app):
    app = real_app(layout='corporate', extra={('GET', PAGE): (500, {'error': 'boom'})})
    page = app.page
    page.locator('[data-corp-tool="guests"]').click()
    page.locator('[data-all-guests-failed]').wait_for(timeout=10000)
    assert page.locator('[data-all-guests-failed]').inner_text() == 'The guest list could not be read.'
    assert page.locator('[data-all-guests-row]').count() == 0


def test_runtime_it_speaks_german(real_app):
    app = real_app(layout='modern', language='de')
    page = app.page
    page.locator('[data-sidebar-guests]').click()
    page.locator('[data-all-guests-row]').first.wait_for(timeout=10000)
    text = page.locator('[data-all-guests]').inner_text()
    assert 'Alle Gäste' in text and 'Nicht aufgeführt: Cold (offline)' in text and '1-6 von 6' in text
    assert page.locator('[data-all-guests-search]').get_attribute('placeholder') == 'Name, ID, Node, IP oder Tag'
    assert 'Alle Gäste' in page.locator('[data-sidebar-guests]').inner_text()
    _shot(app, 'all-guests-de')
    assert not app.errors, app.errors


FLEET = [dict(_LOAD, vmid=10000 + i, name=f'fleet-{i:05d}', type='qemu', status='running' if i % 3 else 'stopped',
              node=f'b{i % 100:02d}') for i in range(10000)]


def test_runtime_ten_thousand_guests_render_a_page(real_app):
    app = real_app(layout='corporate', c2=FLEET)
    page = app.page
    _open_table(app, 'corporate')
    assert len(_rows(page)) == 100
    assert page.locator('[data-all-guests-range]').inner_text() == '1-100 of 10,004'
    page.locator('[data-all-guests-size]').select_option('500')
    for _ in range(80):
        if len(_rows(page)) == 500:
            break
        page.wait_for_timeout(100)
    assert len(_rows(page)) == 500
    page.locator('[data-all-guests-search]').fill('fleet-0999')
    _wait_rows(app, [f'c2:{10000 + i}' for i in range(9990, 10000)])
    assert not app.errors, app.errors
