"""Storage across all clusters and the inventory CSV, on the All Clusters overview.

The source checks read web/src and the bundle; the runtime tests drive the built bundle in
headless Chromium against the fake server of tests/test_ha_ui.py, in Modern and Corporate,
as an active instance and as a standby, in English and German. They skip where Playwright
is not installed. The routes behind the page are tested in
tests/test_overviews_storage_inventory.py.
LW Oct 2026
"""
import csv
import io
import os
import re
import time

import pytest

from test_ha_ui import CLUSTER, SSE_TOKEN, VM, _App, _FakeServer, _classes, _toasts, _wait_for_call, browser  # noqa: F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHOTS = os.environ.get('PEGAPROX_SHOTS', '')

KEYS = ['allStorageTitle', 'allStorageDesc', 'allStorageThreshold', 'allStorageOverOnly', 'allStorageAbove',
        'allStorageShared', 'allStorageUsed', 'allStorageTotal', 'allStorageUsage', 'allStorageNodes',
        'allStorageInactive', 'allStorageInactiveOn', 'allStorageNotListed', 'allStorageOffline',
        'allStorageUnreadable', 'allStorageConfined', 'allStorageShowAll', 'allStorageEmpty',
        'allStorageNoMatch', 'allStorageFailed', 'allStorageExpand',
        'inventoryCsv', 'inventoryCsvTitle', 'inventoryCsvExported', 'inventoryCsvEmpty', 'inventoryCsvFailed',
        'inventoryCsvMissing']
HEADER = ['Cluster', 'VMID', 'Name', 'Type', 'Node', 'Status', 'Template', 'vCPU', 'CPU%', 'Mem (MiB)',
          'MemMax (MiB)', 'Disk allocated (GiB)', 'Disk used (GiB)', 'IP addresses', 'HA state', 'Pool', 'Tags']


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def _block(src, start, end):
    at = src.index(start)
    return src[at:src.index(end, at)]


def _panel():
    return _block(_read('web', 'src', 'vm_modals.js'), '// LW Oct 2026 - every storage of every cluster in one table',
                  '// LW Oct 2026 - the guests no backup job covers')


def _export():
    return _block(_read('web', 'src', 'ui.js'), '// LW Oct 2026 - the guest inventory as CSV',
                  '\n        // NS')


def _mounts():
    vm = _read('web', 'src', 'vm_modals.js')
    body = _block(vm, 'function AllClustersOverview(', 'function GroupSettingsModal(')
    dash = _read('web', 'src', 'dashboard.js')
    button = _block(dash, 'quick CSV export of the current VM list', '/* Snapshot Overview Sub-Tab')
    return body, button


# --- source --------------------------------------------------------------------------------

@pytest.mark.parametrize('key', KEYS)
def test_every_new_string_is_in_every_language_once(key):
    found = len(re.findall(rf'^\s*{key}:', _read('web', 'src', 'translations.js'), re.M))
    assert found == 9, f'{key} is in {found} of 9 language blocks - the UI would show the key'


def test_every_new_key_is_used_and_nothing_uses_a_missing_one():
    src = _read('web', 'src', 'vm_modals.js') + _read('web', 'src', 'ui.js') + _read('web', 'src', 'dashboard.js')
    used = set(re.findall(r"t\('((?:allStorage|inventoryCsv)[A-Za-z]*)'\)", src))
    assert used == set(KEYS), (sorted(used - set(KEYS)), sorted(set(KEYS) - used))


def test_placeholders_survive_translation():
    tr = _read('web', 'src', 'translations.js')
    for key, phs in (('allStorageAbove', ('{n}', '{p}')), ('allStorageNodes', ('{n}',)),
                     ('allStorageInactiveOn', ('{nodes}',)), ('allStorageShowAll', ('{n}',)),
                     ('inventoryCsvExported', ('{n}',)), ('inventoryCsvMissing', ('{clusters}',))):
        values = re.findall(rf'^\s*{key}: "(.*)",$', tr, re.M)
        assert len(values) == 9 and all(ph in v for v in values for ph in phs), (key, values)


def test_no_em_dash_in_what_this_change_added():
    body, button = _mounts()
    for block in (_panel(), _export(), button):
        assert '\u2014' not in block and '\u2013' not in block, block[:120]
    tr = _read('web', 'src', 'translations.js')
    for key in KEYS:
        for v in re.findall(rf'^\s*{key}: (".*"),$', tr, re.M):
            assert '\u2014' not in v and '\u2013' not in v, (key, v)


def test_the_icons_exist():
    icons = _read('web', 'src', 'icons.js')
    have = set(re.findall(r'^\s{12}([A-Z][A-Za-z0-9]*):', icons, re.M))
    used = set(re.findall(r'Icons\.([A-Za-z]+)', _panel() + _export()))
    assert used and used <= have, sorted(used - have)
    # the panel sizes these two itself: they have to take a class
    for name in ('HardDrive', 'Search'):
        assert re.search(rf'^\s{{12}}{name}: \(\{{[^}}]*className', icons, re.M), name


def test_every_class_is_in_the_static_tailwind_build():
    shell = '\n'.join(line for line in _read('web', 'index.html.original').split('\n')
                      if 'data-corp-theme="light"' not in line)
    css = _read('static', 'css', 'tailwind.min.css') + shell
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    body, button = _mounts()
    mounts = '\n'.join(re.findall(r'<InventoryCsvButton[^>]*/>', body))
    assert mounts.count('className=') == 2
    names = _classes(_panel()) | _classes(_export()) | _classes(button) | _classes(mounts)
    missing = sorted(n for n in names if n not in have)
    assert not missing, f'not in static/css/tailwind.min.css: {missing}'


def test_both_only_read():
    """Refresh reads, the chevron folds, the export downloads: nothing here writes, so a
    standby shows both unchanged."""
    for block in (_panel(), _export()):
        assert 'method:' not in block and 'POST' not in block and 'DELETE' not in block
        assert 'authFetch(' not in block
    assert _panel().count('fetch(`${API_URL}/storage-overview') == 1
    assert _export().count('fetch(`${API_URL}/inventory/guests${q}`') == 1


def test_both_are_on_the_overview_in_both_layouts():
    body, button = _mounts()
    assert body.count('<StorageOverview clusters={clusters} />') == 2
    assert body.count("<InventoryCsvButton clusters={clusters} addToast={addToast} label={t('inventoryCsv')}") == 2
    # the cluster's own export goes to the same route for its cluster
    assert '<InventoryCsvButton' in button and 'clusterId={selectedCluster.id}' in button
    assert 'addToast={addToast}' in _block(_read('web', 'src', 'dashboard.js'), '<AllClustersOverview', '/>')


def test_the_bundle_was_rebuilt():
    built = _read('web', 'index.html')
    for needle in ('function StorageOverview(', 'function InventoryCsvButton(', 'function inventoryCsvColumns(',
                   '/storage-overview', '/inventory/guests', 'data-storage-overview-row', 'Disk allocated (GiB)',
                   'allStorageInactiveOn', 'inventoryCsvMissing'):
        assert needle in built, needle


# --- runtime -------------------------------------------------------------------------------

GiB = 1024 ** 3


def _st(cid, name, node, storage, type_, used, total, shared=False, active=True, nodes=1, inactive_on=()):
    pct = round(used * 100.0 / total, 1) if active and total else None
    return {'cluster_id': cid, 'cluster_name': name, 'node': node, 'storage': storage, 'type': type_,
            'content': 'images', 'shared': shared, 'used': used * GiB if active else None,
            'total': total * GiB if active else None, 'percent': pct, 'active': active, 'nodes': nodes,
            'inactive_on': list(inactive_on)}


STORAGE = {
    'storages': [
        _st('c2', 'Branch', 'b1', 'local-zfs', 'zfspool', 96, 100),
        _st('c1', 'Testi', '', 'nfs-iso', 'nfs', 300, 1000, shared=True, nodes=3, inactive_on=['pve3']),
        _st('c1', 'Testi', 'pve1', 'local-lvm', 'lvmthin', 90, 100),
        _st('c1', 'Testi', 'pve2', 'local', 'dir', 79, 100),
        _st('c1', 'Testi', 'pve2', 'local-lvm', 'lvmthin', 40, 200),
        _st('c1', 'Testi', 'pve3', 'local-lvm', 'lvmthin', 99, 100, active=False),
    ],
    'clusters': [
        {'cluster_id': 'c2', 'cluster_name': 'Branch', 'state': 'ok', 'count': 1},
        {'cluster_id': 'c3', 'cluster_name': 'Cold', 'state': 'offline', 'count': 0},
        {'cluster_id': 'c4', 'cluster_name': 'Pooled', 'state': 'confined', 'count': 0},
        {'cluster_id': 'c1', 'cluster_name': 'Testi', 'state': 'ok', 'count': 5},
    ],
}
ST = ('GET', '/api/storage-overview')
INV = ('GET', '/api/inventory/guests')
# what the default order shows: the fullest first, an inactive one with no figure last
BY_USAGE = ['c2:b1:local-zfs', 'c1:pve1:local-lvm', 'c1:pve2:local', 'c1:*:nfs-iso', 'c1:pve2:local-lvm',
            'c1:pve3:local-lvm']


def _g(cid, name, vmid, guest, type_, node, status, **kw):
    row = {'cluster_id': cid, 'cluster_name': name, 'vmid': vmid, 'name': guest, 'type': type_, 'node': node,
           'status': status, 'template': False, 'vcpus': 2, 'cpu': 0.05, 'mem': GiB, 'memory': 4 * GiB,
           'disk_allocated': 32 * GiB, 'disk_used': None, 'ip_addresses': [], 'ha_state': '', 'pool': '',
           'tags': []}
    row.update(kw)
    return row


INVENTORY = {
    'guests': [
        _g('c2', 'Branch', 201, 'erp', 'qemu', 'b1', 'running', vcpus=8, cpu=0.5, mem=8 * GiB, memory=16 * GiB,
           disk_allocated=100 * GiB),
        _g('c1', 'Testi', 100, 'web01', 'qemu', 'pve1', 'running', disk_used=12 * GiB,
           ip_addresses=['10.0.0.11', 'fd00::11'], ha_state='started', pool='prod', tags=['prod', 'web']),
        # a name a spreadsheet would run as a formula
        _g('c1', 'Testi', 102, '=HYPERLINK("x")', 'lxc', 'pve2', 'stopped', template=True, cpu=0, mem=0,
           disk_allocated=8 * GiB, disk_used=0),
    ],
    'clusters': [
        {'cluster_id': 'c2', 'cluster_name': 'Branch', 'state': 'ok', 'count': 1},
        {'cluster_id': 'c3', 'cluster_name': 'Cold', 'state': 'offline', 'count': 0},
        {'cluster_id': 'c1', 'cluster_name': 'Testi', 'state': 'ok', 'count': 2},
    ],
}
# the cluster as the page knows it carries another display name than the server's config name
SHOWN = dict(CLUSTER, display_name='Testi (Vienna)')


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(storage=(200, STORAGE), inventory=(200, INVENTORY), **kw):
        extra = dict(SSE_TOKEN)
        extra[ST] = storage
        extra[INV] = inventory
        extra.update(kw.pop('extra', {}))
        kw.setdefault('role', 'standalone')
        kw.setdefault('clusters', [SHOWN])
        app = _App(browser, _FakeServer(resources=[VM], extra=extra, **kw))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _shot(page, name):
    if SHOTS:
        os.makedirs(SHOTS, exist_ok=True)
        page.screenshot(path=os.path.join(SHOTS, name), full_page=False)


def _storage_on(app):
    panel = app.page.locator('[data-storage-overview]')
    panel.wait_for(timeout=10000)
    app.page.locator('[data-storage-overview-row]').first.wait_for(timeout=5000)
    panel.scroll_into_view_if_needed()
    app.page.wait_for_timeout(200)
    return panel


def _rows(page):
    return page.locator('[data-storage-overview-row]').evaluate_all('rs => rs.map(r => r.dataset.storageOverviewRow)')


def _over(page):
    return page.locator('[data-storage-overview-row][data-over="1"]').evaluate_all(
        'rs => rs.map(r => r.dataset.storageOverviewRow)')


def _tint(page, key, layout):
    """The background a row shows: Corporate paints it on the cells, Modern on the row."""
    cell = ' td:nth-child(3)' if layout == 'corporate' else ''
    return page.locator(f'[data-storage-overview-row="{key}"]{cell}').evaluate('e => getComputedStyle(e).backgroundColor')


def _cells(page, key):
    return page.locator(f'[data-storage-overview-row="{key}"] td').evaluate_all('ts => ts.map(t => t.innerText.trim())')


def _download(page, button):
    with page.expect_download(timeout=8000) as info:
        button.click()
    dl = info.value
    with open(dl.path(), encoding='utf-8-sig') as fh:
        return dl.suggested_filename, list(csv.reader(io.StringIO(fh.read())))


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_the_storage_of_every_cluster_fullest_first(open_app, layout):
    app = open_app(layout=layout)
    page = app.page
    panel = _storage_on(app)
    assert 'Storage across all clusters' in panel.inner_text()
    assert _rows(page) == BY_USAGE
    assert page.locator('[data-storage-overview-count]').inner_text().strip('() ') == '6'
    # above 85 % by default: highlighted, and the header says how many
    assert _over(page) == ['c2:b1:local-zfs', 'c1:pve1:local-lvm']
    assert page.locator('[data-storage-overview-above]').inner_text() == '2 above 85%'
    # and it shows on an odd and on an even row alike (Corporate stripes its cells)
    red = 'rgba(245, 79, 71, 0.08)' if layout == 'corporate' else 'rgba(239, 68, 68, 0.1)'
    assert [_tint(page, key, layout) for key in BY_USAGE[:3]] == [red, red, _tint(page, BY_USAGE[2], layout)]
    assert _tint(page, BY_USAGE[2], layout) != red
    # cluster, node, storage, type, shared, used, total, usage, status
    assert _cells(page, 'c1:pve1:local-lvm') == ['Testi (Vienna)', 'pve1', 'local-lvm', 'lvmthin', 'No',
                                                 '90.0 GB', '100.0 GB', '90.0%', 'Active']
    shared = _cells(page, 'c1:*:nfs-iso')
    assert shared[:5] == ['Testi (Vienna)', '3 nodes', 'nfs-iso', 'nfs', 'Yes'] and shared[7] == '30.0%'
    assert 'Active' in shared[8] and 'inactive on pve3' in shared[8]
    # a storage that is down shows no stale figures
    assert _cells(page, 'c1:pve3:local-lvm')[5:] == ['-', '-', '-', 'Inactive']
    # a cluster the page does not list keeps the server's name
    assert _cells(page, 'c2:b1:local-zfs')[0] == 'Branch'
    assert page.locator('[data-storage-overview-unlisted]').inner_text() == \
        'Not listed: Cold (offline), Pooled (your access covers single guests only)'
    _shot(page, f'{layout}_storage_overview.png')
    assert [c for c in app.server.calls if c == ST] == [ST]
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_sort_filter_and_threshold(open_app, layout):
    app = open_app(layout=layout)
    page = app.page
    _storage_on(app)
    sort = lambda col: page.locator(f'[data-storage-overview-sort="{col}"]').click()  # noqa: E731
    sort('storage')
    assert _rows(page) == ['c1:pve2:local', 'c1:pve1:local-lvm', 'c1:pve2:local-lvm', 'c1:pve3:local-lvm',
                           'c2:b1:local-zfs', 'c1:*:nfs-iso']
    sort('storage')
    assert _rows(page)[0] == 'c1:*:nfs-iso'
    sort('total')
    assert _rows(page)[0] == 'c1:*:nfs-iso' and _rows(page)[-1] == 'c1:pve3:local-lvm'
    sort('cluster')
    assert _rows(page)[0] == 'c2:b1:local-zfs'
    sort('percent')
    assert _rows(page) == BY_USAGE

    page.locator('[data-storage-overview-search]').fill('nfs')
    assert _rows(page) == ['c1:*:nfs-iso']
    page.locator('[data-storage-overview-search]').fill('nothing-like-it')
    assert page.locator('[data-storage-overview-empty]').inner_text() == 'No storage matches the filter.'
    page.locator('[data-storage-overview-search]').fill('')

    page.locator('[data-storage-overview-over]').check()
    assert _rows(page) == ['c2:b1:local-zfs', 'c1:pve1:local-lvm']
    page.locator('[data-storage-overview-threshold]').fill('70')
    assert _rows(page) == ['c2:b1:local-zfs', 'c1:pve1:local-lvm', 'c1:pve2:local']
    assert page.locator('[data-storage-overview-above]').inner_text() == '3 above 70%'
    _shot(page, f'{layout}_storage_overview_filtered.png')
    # the threshold is the user's: a reload keeps it
    page.reload(wait_until='load')
    app.wait_for_app()
    _storage_on(app)
    assert page.locator('[data-storage-overview-threshold]').input_value() == '70'
    assert _over(page) == ['c2:b1:local-zfs', 'c1:pve1:local-lvm', 'c1:pve2:local']
    assert not app.errors, app.errors


def test_runtime_a_folded_panel_reads_nothing(open_app):
    app = open_app(layout='modern')
    page = app.page
    panel = _storage_on(app)
    panel.locator('button[title="Collapse"]').click()
    assert page.locator('[data-storage-overview-row]').count() == 0
    page.reload(wait_until='load')
    app.wait_for_app()
    page.locator('[data-storage-overview]').wait_for(timeout=10000)
    before = app.server.calls.count(ST)
    page.wait_for_timeout(800)
    assert page.locator('[data-storage-overview-row]').count() == 0
    assert app.server.calls.count(ST) == before == 1
    page.locator('[data-storage-overview] button[title="Expand"]').click()
    page.locator('[data-storage-overview-row]').first.wait_for(timeout=3000)
    assert app.server.calls.count(ST) == 2
    # refresh asks again
    page.locator('[data-storage-overview] button[title="Refresh"]').click()
    assert _wait_for_call(app, ST) and app.server.calls.count(ST) >= 3
    assert not app.errors, app.errors


def test_runtime_without_storage_view_there_is_no_panel_and_no_read(open_app):
    app = open_app(layout='modern', admin=False, permissions=['vm.view', 'cluster.view'])
    app.page.wait_for_timeout(1500)
    assert app.page.locator('[data-storage-overview]').count() == 0
    assert ST not in app.server.calls
    # the export is there: the server decides guest by guest
    assert app.page.locator('[data-inventory-csv="all"]').count() == 1
    assert not app.errors, app.errors


def test_runtime_a_refusal_hides_the_panel_and_a_failure_says_so(open_app):
    app = open_app(layout='modern', admin=False, permissions=['vm.view', 'storage.view'],
                   storage=(403, {'error': 'Permission denied'}))
    assert _wait_for_call(app, ST)
    app.page.wait_for_timeout(500)
    assert app.page.locator('[data-storage-overview]').count() == 0
    app = open_app(layout='corporate', storage=(500, {'error': 'boom'}))
    app.page.locator('[data-storage-overview-failed]').wait_for(timeout=10000)
    assert app.page.locator('[data-storage-overview-failed]').inner_text() == 'The storage overview could not be read.'
    assert app.page.locator('[data-storage-overview-empty]').count() == 0


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_the_inventory_of_every_cluster_as_csv(open_app, layout):
    app = open_app(layout=layout)
    page = app.page
    button = page.locator('[data-inventory-csv="all"]')
    button.wait_for(timeout=10000)
    assert button.inner_text().strip() == 'Inventory CSV'
    assert button.get_attribute('title') == \
        'The guests you may see, as CSV: vCPU, memory, disk, IP addresses, HA state, pool and tags'
    name, rows = _download(page, button)
    assert re.fullmatch(r'pegaprox-inventory-\d{4}-\d{2}-\d{2}\.csv', name), name
    assert rows[0] == HEADER
    assert rows[1] == ['Branch', '201', 'erp', 'qemu', 'b1', 'running', '', '8', '50', '8192', '16384',
                       '100.0', '', '', '', '', '']
    assert rows[2] == ['Testi (Vienna)', '100', 'web01', 'qemu', 'pve1', 'running', '', '2', '5', '1024', '4096',
                       '32.0', '12.0', '10.0.0.11 fd00::11', 'started', 'prod', 'prod;web']
    # a formula is written as text
    assert rows[3][:7] == ['Testi (Vienna)', '102', '\'=HYPERLINK("x")', 'lxc', 'pve2', 'stopped', 'yes']
    # an empty disk is 0.0, not a blank cell
    assert rows[3][11:13] == ['8.0', '0.0'] and len(rows) == 4
    assert [u for u in app.server.urls if '/api/inventory/guests' in u][-1].endswith('/api/inventory/guests')
    page.wait_for_timeout(300)
    toasts = _toasts(page)
    assert any('Exported 3 guests' in x for x in toasts), toasts
    assert any('Not in the export: Cold' in x for x in toasts), toasts
    _shot(page, f'{layout}_inventory_export.png')
    assert not app.errors, app.errors


def _open_resources(app, layout):
    page = app.page
    if layout == 'corporate':
        page.locator('.corp-tree-item', has_text='Testi').first.click()
    else:
        page.get_by_text('Testi').first.click()
    page.locator('button', has_text='Resources').first.click()
    page.get_by_text('web01').first.wait_for(timeout=5000)
    page.wait_for_timeout(300)


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_the_cluster_export_carries_the_inventory(open_app, layout):
    one = {'guests': [g for g in INVENTORY['guests'] if g['cluster_id'] == 'c1'],
           'clusters': [INVENTORY['clusters'][2]]}
    app = open_app(layout=layout, inventory=(200, one))
    page = app.page
    _open_resources(app, layout)
    button = page.locator('[data-inventory-csv="c1"]')
    assert button.inner_text().strip() == 'Export CSV'
    name, rows = _download(page, button)
    assert re.fullmatch(r'pegaprox-Testi-vms-\d{4}-\d{2}-\d{2}\.csv', name), name
    assert rows[0] == HEADER and [r[1] for r in rows[1:]] == ['100', '102']
    assert rows[1][7:] == ['2', '5', '1024', '4096', '32.0', '12.0', '10.0.0.11 fd00::11', 'started', 'prod', 'prod;web']
    assert [u for u in app.server.urls if '/api/inventory/guests' in u][-1].endswith('/api/inventory/guests?cluster=c1')
    page.wait_for_timeout(300)
    assert any('Exported 2 guests' in x for x in _toasts(page)), _toasts(page)
    assert not app.errors, app.errors


def test_runtime_a_failed_export_says_so(open_app):
    app = open_app(layout='modern', inventory=(500, {'error': 'boom'}))
    page = app.page
    page.locator('[data-inventory-csv="all"]').click()
    assert _wait_for_call(app, INV)
    page.wait_for_timeout(500)
    assert any('The inventory could not be read' in x for x in _toasts(page)), _toasts(page)
    app = open_app(layout='modern', inventory=(200, {'guests': [], 'clusters': []}))
    app.page.locator('[data-inventory-csv="all"]').click()
    assert _wait_for_call(app, INV)
    app.page.wait_for_timeout(500)
    assert any('No guests to export' in x for x in _toasts(app.page)), _toasts(app.page)


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_a_standby_shows_both_and_sends_nothing(open_app, layout):
    app = open_app(layout=layout, role='standby')
    page = app.page
    panel = _storage_on(app)
    assert _rows(page) == BY_USAGE
    # refresh reads, the chevron and the title fold the panel; nothing else is a button
    buttons = panel.locator('button').evaluate_all(
        "bs => bs.map(b => b.hasAttribute('data-storage-overview-fold') ? 'fold' : b.title)")
    assert set(buttons) <= {'Refresh', 'Collapse', 'fold'}, buttons
    panel.locator('button[title="Refresh"]').click()
    _, rows = _download(page, page.locator('[data-inventory-csv="all"]'))
    assert len(rows) == 4
    page.wait_for_timeout(300)
    _shot(page, f'{layout}_overviews_standby.png')
    assert not [c for c in app.server.calls if c[0] != 'GET' and c[1] not in ('/api/sse/token', '/api/sse/subscribe')]
    assert not app.errors, app.errors


def test_runtime_it_speaks_german(open_app):
    app = open_app(layout='modern', language='de')
    page = app.page
    panel = _storage_on(app)
    text = panel.inner_text()
    assert 'Speicher aller Cluster' in text and '2 über 85%' in text
    assert 'Nicht aufgeführt: Cold (offline), Pooled (Ihr Zugriff umfasst nur einzelne Gäste)' in text
    assert 'inaktiv auf pve3' in text and '3 Nodes' in text
    assert page.locator('[data-inventory-csv="all"]').inner_text().strip() == 'Inventar als CSV'
    _shot(page, 'modern_storage_overview_de.png')
    assert not app.errors, app.errors
