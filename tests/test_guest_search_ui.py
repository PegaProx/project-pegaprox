"""MAC addresses, IPs and notes in the command palette (Ctrl+K) and the header search.

The palette searched the loaded resources of the open cluster: names, ids, nodes.
MAC addresses and notes are not in there, so it asks /api/global/search once the
typing pauses and lists the guests the server found by MAC, IP or notes, with the
field and the value that matched. The header search shows the same.

The source checks read web/src and the bundle. The runtime tests drive the built
bundle in headless Chromium: the page around it from the fake server of
tests/test_ha_ui.py, the search from the real route of the app, as the signed-in
user, against an index seeded with guest configs. The palette exists in Modern and
Corporate; the Cloud shell has none. They skip where Playwright is not installed.
LW Oct 2026
"""
import os
import re

import pytest

from test_ha_ui import BASE, _App, _FakeServer, browser  # noqa: F401 (browser is a fixture)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LANGS = ['de', 'en', 'zh', 'pl', 'fr', 'es', 'pt', 'ko', 'it']
KEYS = ['searchMatchMac', 'searchMatchIp', 'searchMatchNotes', 'cmdPalSearchingIndex', 'cmdPalIndexHint']


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


@pytest.fixture(scope='module')
def dash():
    return _read('web', 'src', 'dashboard.js')


@pytest.fixture(scope='module')
def palette(dash):
    start = dash.index('const SEARCH_INDEX_FIELDS = ')
    return dash[start:dash.index('function PasswordExpiryBanner(', start)]


def _blocks():
    src = _read('web', 'src', 'translations.js')
    starts = sorted((m.start(), m.group(1)) for m in re.finditer(r'^ {12}([a-z]{2}): \{$', src, re.M))
    out = {}
    for i, (pos, lang) in enumerate(starts):
        end = starts[i + 1][0] if i + 1 < len(starts) else len(src)
        out[lang] = src[pos:end]
    return out


# -- source ---------------------------------------------------------------------------------------

def test_the_palette_asks_the_server_and_keeps_the_newest_answer(palette):
    assert "authFetch(`${API_URL}/global/search?q=${encodeURIComponent(q)}&type=all`, { signal: ctrl.signal })" in palette
    # one request after the typing pauses, the one before it cancelled
    assert '}, 250);' in palette
    assert 'return () => { clearTimeout(timer); ctrl.abort(); };' in palette
    # an answer is shown for the query it was asked for only
    assert 'if (remote.q === query.trim()) {' in palette
    assert "h.vmid != null && SEARCH_INDEX_FIELDS.includes(h.match_field)" in palette


def test_the_dashboard_hands_the_palette_the_fetch_and_the_jump(dash):
    mount = dash[dash.index('<CommandPalette'):]
    mount = mount[:mount.index('/>')]
    assert 'authFetch={authFetch}' in mount
    assert 'onPickHit={(hit) => { setShowCommandPalette(false); navigateToResult(hit); }}' in mount


@pytest.mark.parametrize('lang', LANGS)
def test_every_new_key_exists_once_per_language(lang):
    block = _blocks()[lang]
    for key in KEYS:
        n = len(re.findall(r'^ +%s: ' % key, block, re.M))
        assert n == 1, f'{key} appears {n} times in {lang}'


def test_every_new_key_is_used(dash):
    for key in KEYS:
        assert f"t('{key}')" in dash, key


def test_no_em_dash_in_the_new_code(palette, dash):
    header = dash[dash.index('{/* LW Oct 2026 - a hit by MAC, notes'):]
    header = header[:header.index('</span>')]
    new_strings = [line for block in _blocks().values() for line in block.splitlines()
                   if any(f' {k}: ' in line for k in KEYS)]
    def part(start, end):
        at = palette.index(start)
        return palette[at:palette.index(end, at)]
    new_code = [
        part('const SEARCH_INDEX_FIELDS', '// LW Apr 2026'),
        part('// LW Oct 2026 - MAC addresses, IPs and notes', '// Base catalog'),
        part("// the server's hits by MAC", '// reset highlight'),
        part('{r.match && (', '<span className="text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded"\n'),
        part('{remoteLoading ? (', '<span className="ml-auto">'),
    ]
    for text in new_code + [header] + new_strings:
        assert '\u2014' not in text


def test_every_class_is_in_the_static_tailwind_build(palette, dash):
    css = _read('static', 'css', 'tailwind.min.css') + _read('web', 'index.html.original')
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    chip = palette[palette.index('{r.match && ('):]
    chip = chip[:chip.index('</div>\n                                            )}')]
    header = dash[dash.index('{/* LW Oct 2026 - a hit by MAC, notes'):]
    header = header[:header.index('</span>')]
    names = set()
    for block in (chip, header):
        for m in re.finditer(r'className=(?:"([^"]*)"|\{`([^`]*)`\})', block):
            txt = re.sub(r'\$\{[^}]*\}', ' ', m.group(1) if m.group(1) is not None else m.group(2))
            names.update(n for n in txt.split() if re.match(r'^[a-z]', n))
    names.add('font-mono')
    missing = sorted(n for n in names if n not in have)
    assert not missing, f'not in static/css/tailwind.min.css: {missing}'


def test_the_icons_exist(palette):
    icons = _read('web', 'src', 'icons.js')
    for name in set(re.findall(r"icon: h\.type === 'ct' \? '(\w+)' : '(\w+)'", palette)[0]):
        assert re.search(r'^ +%s: ' % name, icons, re.M), name


def test_the_bundle_was_rebuilt():
    bundle = _read('web', 'index.html')
    for needle in ('SEARCH_INDEX_FIELDS', 'function searchMatchLabel(', 'data-cmdpal-match', 'data-search-match',
                   '/global/search?q=${encodeURIComponent(q)}&type=all', 'onPickHit'):
        assert needle in bundle, needle
    for key in KEYS:
        assert key in bundle, key


# -- runtime: the built bundle against the real search route ----------------------------------------

REAL = ('/api/global/search',)
MAC_DB = 'BC:24:11:AA:BB:02'
C1 = {'id': 'c1', 'name': 'Testi', 'display_name': 'Testi', 'host': '10.0.0.1',
      'connected': True, 'status': 'running', 'cluster_type': 'proxmox', 'enabled': True}
C2 = dict(C1, id='c2', name='Zweit', display_name='Zweit', host='10.0.0.2')
VM = {'cpu': 0.05, 'cpu_percent': 5, 'maxcpu': 2, 'mem': 1073741824, 'maxmem': 4294967296,
      'mem_percent': 25, 'disk': 0, 'maxdisk': 34359738368, 'uptime': 3600}
C1_VMS = [dict(VM, vmid=100, name='web01', type='qemu', status='running', node='pve1',
               ip='10.1.0.10', ip_addresses=['10.1.0.10', '172.16.5.10'])]
C2_VMS = [dict(VM, vmid=201, name='db-primary', type='qemu', status='stopped', node='pve2'),
          dict(VM, vmid=301, name='cache', type='lxc', status='running', node='pve2')]
CONFIGS = {
    ('c1', 'qemu', 100): {'net0': 'virtio=BC:24:11:AA:BB:01,bridge=vmbr0', 'description': 'shop frontend'},
    ('c2', 'qemu', 201): {'net0': f'virtio={MAC_DB},bridge=vmbr0', 'ipconfig0': 'ip=10.2.0.20/24',
                          'description': 'Primary database.\nBackup window 02:00, ask ops first.'},
    ('c2', 'lxc', 301): {'net0': 'name=eth0,hwaddr=BC:24:11:CC:DD:03,ip=192.168.9.30/24'},
}
PLACEHOLDER = {'modern': 'Search all clusters...', 'corporate': 'Search in all inventories...'}


class _Server(_FakeServer):
    """The page from the fake server, the search from the app."""

    def __init__(self, client, **kw):
        super().__init__(role='standalone', clusters=[C1, C2], resources=C1_VMS, **kw)
        self.client = client

    def handle(self, route):
        req = route.request
        path = re.sub(r'^https?://[^/]+', '', req.url)
        bare = path.split('?')[0]
        if not req.url.startswith(BASE) or bare not in REAL:
            return super().handle(route)
        self.calls.append((req.method, bare))
        self.urls.append(req.url)
        r = self.client.get(path)
        return route.fulfill(status=r.status_code, body=r.get_data(),
                             headers={'Content-Type': 'application/json'})


@pytest.fixture
def real_app(browser, api, seed):  # noqa: F811
    from pegaprox.background import guest_index
    for cid, vms in (('c1', C1_VMS), ('c2', C2_VMS)):
        m = api.make_fake_manager(cluster_id=cid, get_vm_resources=[dict(v) for v in vms])
        m.is_connected = True
        m.config.name = {'c1': 'Testi', 'c2': 'Zweit'}[cid]
        m.nodes = {}
        api.set_manager(cid, m)
    for (cid, vm_type, vmid), cfg in CONFIGS.items():
        guest_index.ingest(cid, vm_type, vmid, cfg)
    apps = []

    def _open(user=None, **kw):
        user = user or seed.user('admin', role='admin')
        app = _App(browser, _Server(api.as_user(user), **kw))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _palette(app, text):
    page = app.page
    page.locator('body').click(position={'x': 5, 'y': 400})
    page.keyboard.press('Control+k')
    box = page.get_by_placeholder('Type to search clusters, VMs, actions…')
    box.wait_for(timeout=5000)
    box.fill(text)
    return box


def _match_rows(page, timeout=5000):
    page.locator('[data-cmdpal-match]').first.wait_for(timeout=timeout)
    page.wait_for_timeout(150)
    rows = page.locator('[data-cmdpal-idx]', has=page.locator('[data-cmdpal-match]'))
    out = []
    for i in range(rows.count()):
        row = rows.nth(i)
        match = row.locator('[data-cmdpal-match]')
        # the label as written (the chip shows it in capitals), then the value
        label, value = (' '.join((s.text_content() or '').split()) for s in match.locator('span').all())
        out.append((row.locator('.text-sm').first.inner_text(), match.get_attribute('data-cmdpal-match'),
                    f'{label} {value}'))
    return out


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_a_mac_in_any_spelling_finds_the_guest_in_another_cluster(real_app, layout):
    app = real_app(layout=layout)
    page = app.page
    for spelling in ('bc-24-11-aa-bb-02', 'BC2411AABB02', 'bc:24:11:aa:bb:02'):
        box = _palette(app, spelling)
        rows = _match_rows(page)
        assert rows == [('db-primary', 'mac', f'MAC {MAC_DB} (net0)')], (spelling, rows)
        sub = page.locator('[data-cmdpal-idx]', has=page.locator('[data-cmdpal-match]')).first.inner_text()
        assert 'VMID 201' in sub and 'Zweit' in sub, sub
        box.press('Escape')
        page.wait_for_timeout(200)
    # the request went out once per query after the pause, never per keystroke
    asked = [u for u in app.server.urls if '/api/global/search' in u]
    assert len(asked) == 3, asked
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_picking_the_hit_opens_that_guest(real_app, layout):
    app = real_app(layout=layout)
    page = app.page
    box = _palette(app, MAC_DB)
    _match_rows(page)
    box.press('Enter')
    page.get_by_placeholder('Type to search clusters, VMs, actions…').wait_for(state='detached', timeout=3000)
    # the cluster of the hit is open, on the resources, with the guest picked
    page.wait_for_timeout(800)
    assert any(c[1].startswith('/api/clusters/c2/') for c in app.server.calls), app.server.calls[-15:]
    if layout == 'corporate':
        page.locator('.corp-breadcrumb-current', has_text='db-primary').wait_for(timeout=3000)
    assert not app.errors, app.errors


def test_runtime_notes_and_every_ip_show_what_matched(real_app):
    app = real_app(layout='modern')
    page = app.page
    _palette(app, 'backup window')
    rows = _match_rows(page)
    assert rows == [('db-primary', 'notes', 'Notes Primary database. Backup window 02:00, ask ops first.')], rows
    _palette(app, '172.16.5')
    rows = _match_rows(page)
    assert rows == [('web01', 'ip', 'IP 172.16.5.10')], rows
    _palette(app, '192.168.9.30')
    assert _match_rows(page) == [('cache', 'ip', 'IP 192.168.9.30 (net0)')]
    assert not app.errors, app.errors


def test_runtime_names_stay_with_the_open_cluster(real_app):
    """The server finds db-primary in Zweit by its name: that is the header search's job,
    the palette adds what only the index knows."""
    app = real_app(layout='modern')
    page = app.page
    _palette(app, 'db-primary')
    page.wait_for_function('() => !document.querySelector("[data-cmdpal-searching]")', timeout=5000)
    page.wait_for_timeout(200)
    assert any('/api/global/search' in u for u in app.server.urls)
    assert page.locator('[data-cmdpal-idx]', has_text='db-primary').count() == 0
    assert not app.errors, app.errors


def test_runtime_a_pool_user_sees_no_foreign_mac(real_app, seed):
    import time
    import pegaprox.utils.rbac as rbac
    seed.tenant('tenant_x', clusters=['c2'])
    user = seed.user('mallory', role='viewer', tenant_id='tenant_x')
    seed.pool('c2', 'pool_1', 'mallory', ['pool.view', 'vm.view'])
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache['c2'] = {'data': {'301:lxc': 'pool_1'}, 'timestamp': time.time(),
                                             'refreshing': False}
    app = real_app(user=user, layout='modern', admin=False)
    page = app.page
    _palette(app, 'mac:bc:24:11')
    rows = _match_rows(page)
    assert rows == [('cache', 'mac', 'MAC BC:24:11:CC:DD:03 (net0)')], rows
    _palette(app, MAC_DB)
    page.wait_for_function('() => !document.querySelector("[data-cmdpal-searching]")', timeout=5000)
    page.wait_for_timeout(200)
    assert page.locator('[data-cmdpal-match]').count() == 0
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_the_header_search_says_what_matched(real_app, layout):
    app = real_app(layout=layout)
    page = app.page
    page.fill(f'input[placeholder="{PLACEHOLDER[layout]}"]', 'bc2411aabb02')
    chip = page.locator('.pp-search-results [data-search-match]').first
    chip.wait_for(timeout=5000)
    assert chip.get_attribute('data-search-match') == 'mac'
    assert ' '.join(chip.inner_text().split()) == f'MAC: {MAC_DB} (net0)'
    # an IP hit on the address the row shows anyway gets no chip
    page.fill(f'input[placeholder="{PLACEHOLDER[layout]}"]', '10.1.0.10')
    page.locator('.pp-search-results', has_text='web01').wait_for(timeout=5000)
    page.wait_for_timeout(300)
    assert page.locator('.pp-search-results [data-search-match]').count() == 0
    assert not app.errors, app.errors


def test_runtime_german_labels(real_app):
    app = real_app(layout='modern', language='de')
    page = app.page
    page.locator('body').click(position={'x': 5, 'y': 400})
    page.keyboard.press('Control+k')
    box = page.get_by_placeholder('Suche Cluster, VMs, Aktionen…')
    box.wait_for(timeout=5000)
    page.get_by_text('Findet auch MAC, IP und Notizen').wait_for(timeout=3000)
    box.fill('backup window')
    rows = _match_rows(page)
    assert rows[0][1:] == ('notes', 'Notizen Primary database. Backup window 02:00, ask ops first.'), rows
    assert not app.errors, app.errors
