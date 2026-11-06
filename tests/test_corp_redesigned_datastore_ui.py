"""The datastores of Corporate Redesigned (Preview) in the browser.

The Browse tab of a cluster's Datastore tab keeps its two panels (the storages grouped by node
on the left, the content of the picked one on the right) and fills the height down to the task
bar. Every storage row and the head of the picked one carry the same meter (the storage pair of
round 3: warning from 70 %, critical above 85 %; it was 80/90 of the overview alerts until then), the
free space PVE reports, and the state the API reports; a field the API did not send shows nothing.
The content is a CrTable with type chips, search, sort and a column menu, the owner guest links
into the inventory, and every action is the one classic offers, through its own handler, its
permission and its confirmation. The datastore view of the sidebar gets the same meter and
state. Classic Corporate (dark and light) and Modern keep their Datastore tab to the pixel.

PEGAPROX_CR_BUNDLE=<file> serves another bundle (the counterproof against the stage D build).
Runs against the fake server of tests/test_ha_ui.py and skips without Playwright. LW Oct 2026
"""
import decimal
import json
import os
import re
import subprocess
import time
import urllib.parse

import pytest

from test_corp_redesigned_guard_ui import (BASE_REV, DETERMINISTIC, FIXED, _GuardApp, _GuardServer, _settle,
                                           diff_box, keep)
from test_ha_ui import BASE, CLUSTER

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LAYOUT = 'corporate-redesigned'
_BUNDLE_FILE = os.environ.get('PEGAPROX_CR_BUNDLE')
BUNDLE = open(_BUNDLE_FILE, encoding='utf-8').read() if _BUNDLE_FILE else None
GIB = 1024 ** 3
MIB = 1024 ** 2
CTIME = FIXED - 7200  # 2026-10-30 07:00 UTC


def _st(name, kind, content, total_gib, used_gib, **kw):
    s = {'storage': name, 'type': kind, 'content': content, 'total': int(total_gib * GIB), 'used': int(used_gib * GIB),
         'avail': int((total_gib - used_gib) * GIB), 'active': 1, 'enabled': 1, 'shared': False}
    s.update(kw)
    return s


def _off(name, kind, content):
    """A storage of an offline node, as the server lists it (node_offline, zeros)."""
    return {'storage': name, 'type': kind, 'content': content, 'total': 0, 'used': 0, 'avail': 0, 'used_fraction': 0,
            'active': 0, 'enabled': True, 'shared': False, 'node_offline': True}


CEPH = _st('ceph-rbd', 'rbd', 'images,rootdir', 1000, 925, shared=True, active_on=['pve1', 'pve2'], inactive_on=[])
PBS = _st('backupsrv', 'pbs', 'backup', 500, 50, shared=True, active_on=['pve1', 'pve2'], inactive_on=[])
CEPHFS = _st('cephfs', 'cephfs', 'iso,vztmpl,backup', 400, 100, shared=True, active_on=['pve1'], inactive_on=['pve2'])
NFS = dict(_st('nfs-old', 'nfs', 'backup', 0, 0, shared=True, active_on=[], inactive_on=['pve1', 'pve2']), active=0)
LOCAL1 = _st('local', 'dir', 'iso,vztmpl,backup,snippets', 100, 30)
LVM1 = _st('local-lvm', 'lvmthin', 'images,rootdir', 200, 170)
RAW1 = _st('iscsi-raw', 'iscsi', 'images', 0, 0)
OLD1 = dict(_st('old-dir', 'dir', 'iso', 0, 0), enabled=0, active=0)
LOCAL2 = _st('local', 'dir', 'iso,vztmpl,backup', 100, 79)
# what an older or another backend sends: no active, enabled or shared field at all
BARE2 = {'storage': 'bare', 'type': 'dir', 'content': 'iso', 'total': 50 * GIB, 'used': 5 * GIB}
DATASTORES = {'shared': [CEPH, PBS, CEPHFS, NFS],
              'local': {'pve1': [LOCAL1, LVM1, RAW1, OLD1], 'pve2': [LOCAL2, BARE2],
                        'pve3': [_off('local', 'dir', 'iso,vztmpl,backup'), _off('local-lvm', 'lvmthin', 'images,rootdir')]},
              'nodes': ['pve1', 'pve2', 'pve3'], 'offline_nodes': ['pve3']}


def _vol(volid, content, size, **kw):
    r = {'volid': volid, 'content': content, 'size': size, 'storage': volid.split(':')[0], 'node': 'pve1'}
    r.update(kw)
    return r


ISO = _vol('local:iso/debian-12.4.0-amd64-netinst.iso', 'iso', 658 * MIB, format='iso', size_human='658.0 MB', ctime=CTIME - 86400 * 9)
ISO_APPROX = _vol('local:iso/win2022.iso', 'iso', 5 * GIB, format='iso', size_human='5.0 GB', size_is_approx=True, ctime=CTIME - 86400 * 30)
TMPL = _vol('local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst', 'vztmpl', 120 * MIB, format='tzst', size_human='120.0 MB', ctime=CTIME - 86400 * 40)
SNIP = _vol('local:snippets/user-data.yaml', 'snippets', 2048, format='snippet', size_human='2.0 KB', ctime=CTIME - 86400 * 2)
BK100 = _vol('local:backup/vzdump-qemu-100-2026_10_30-07_00_00.vma.zst', 'backup', 3 * GIB, format='vma.zst', size_human='3.0 GB',
             ctime=CTIME, vmid=100, subtype='qemu', notes='web01 nightly', protected=1)
BK555 = _vol('local:backup/vzdump-lxc-555-2026_10_29-07_00_00.tar.zst', 'backup', 700 * MIB, format='tar.zst', size_human='700.0 MB',
             ctime=CTIME - 86400, vmid=555, subtype='lxc', notes='', protected=0)
LOCAL_CONTENT = [ISO, ISO_APPROX, TMPL, SNIP, BK100, BK555]
CEPH_CONTENT = [_vol('ceph-rbd:vm-100-disk-0', 'images', 32 * GIB, format='raw', size_human='32.0 GB', vmid=100),
                _vol('ceph-rbd:vm-101-disk-0', 'rootdir', 8 * GIB, format='raw', size_human='8.0 GB', vmid=101),
                _vol('ceph-rbd:vm-102-disk-0', 'images', 64 * GIB, format='raw', size_human='64.0 GB', vmid=102),
                _vol('ceph-rbd:vm-555-disk-1', 'images', 16 * GIB, format='raw', size_human='16.0 GB', vmid=555)]
CONTENT = {('local', 'pve1'): LOCAL_CONTENT, ('ceph-rbd', 'pve1'): CEPH_CONTENT, ('local-lvm', 'pve1'): [],
           ('backupsrv', 'pve1'): [_vol('backupsrv:backup/vm/100/2026-10-30T07:00:00Z', 'backup', 3 * GIB, format='pbs-vm',
                                        size_human='3.0 GB', ctime=CTIME, vmid=100, subtype='qemu', verification={'state': 'ok'})],
           ('local', 'pve2'): [ISO], ('bare', 'pve2'): [], ('cephfs', 'pve1'): [TMPL]}
ESXI = [{'id': 'e1', 'host': 'esx01.lab', 'connected': True}]
ESXI_VMS = [{'id': 'vm-7', 'name': 'legacy-app', 'guest_os': 'Debian 11', 'num_cpu': 2, 'memory_mb': 4096, 'volid': '[ds1] legacy-app/legacy-app.vmx'}]


class _DsServer(_GuardServer):
    """The guard fake plus /datastores, the content of each storage per node, deletes, and the
    reads of the dialogs. Content reads can be held to see the loading state and a race."""

    def __init__(self, datastores=None, content=None, esxi=None, bundle=None, extra=None, others=None, **kw):
        reads = {('GET', '/api/clusters/c1/storage-clusters'): (200, []),
                 ('GET', '/api/clusters/c1/esxi-hosts'): (200, list(ESXI if esxi is None else esxi)),
                 ('GET', '/api/clusters/c1/esxi-hosts/e1/vms'): (200, ESXI_VMS),
                 ('GET', '/api/clusters/c1/templates/available'): (200, []),
                 ('GET', '/api/clusters/c1/nextid'): (200, {'vmid': 900}),
                 ('GET', '/api/batch-restores'): (200, {'runs': []})}
        reads.update(extra or {})
        super().__init__(bundle=BUNDLE if bundle is None else bundle, extra=reads, **kw)
        self.datastores = DATASTORES if datastores is None else datastores
        self.others = dict(others or {})    # cluster id -> its /datastores, for the sidebar
        self.content = dict(CONTENT if content is None else content)
        self.content_status = {}    # storage name -> (status, body)
        self.hold = set()           # storage names whose content reads wait for release()
        self.held_content = []
        self.content_reads = []     # (storage, node)
        self.deletes = []           # (storage, volid, node)

    def _content(self, name, node):
        rows = self.content.get((name, node))
        if rows is None and node is None:
            rows = next((v for (n, _), v in self.content.items() if n == name), None)
        return rows if rows is not None else []

    def release_content(self, name):
        keep_, go = [], []
        for item in self.held_content:
            (go if item[1] == name else keep_).append(item)
        self.held_content = keep_
        for route, n, node in go:
            route.fulfill(status=200, body=json.dumps(self._content(n, node)), headers={'Content-Type': 'application/json'})

    def handle(self, route):
        req = route.request
        if req.url.startswith(BASE):
            path = re.sub(r'^https?://[^/]+', '', req.url).split('?')[0]
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(req.url).query)
            node = (query.get('node') or [None])[0] or None

            def answer(data, status=200):
                self.calls.append((req.method, path))
                self.urls.append(req.url)
                return route.fulfill(status=status, body=json.dumps(data), headers={'Content-Type': 'application/json'})

            if req.method == 'GET' and path == '/api/clusters/c1/datastores':
                return answer(self.datastores)
            m = re.fullmatch(r'/api/clusters/([^/]+)/datastores', path)
            if m and req.method == 'GET' and m.group(1) in self.others:
                return answer(self.others[m.group(1)])
            m = re.fullmatch(r'/api/clusters/c1/datastores/([^/]+)/content', path)
            if m and req.method == 'GET':
                name = urllib.parse.unquote(m.group(1))
                self.content_reads.append((name, node))
                if name in self.content_status:
                    status, body = self.content_status[name]
                    return answer(body, status)
                if name in self.hold:
                    self.calls.append((req.method, path))
                    self.held_content.append((route, name, node))
                    return None
                return answer(self._content(name, node))
            m = re.fullmatch(r'/api/clusters/c1/datastores/([^/]+)/content/(.+)', path)
            if m and req.method == 'DELETE':
                self.deletes.append((urllib.parse.unquote(m.group(1)), urllib.parse.unquote(m.group(2)), node))
                return answer({'success': True})
        return super().handle(route)


@pytest.fixture(scope='module')
def browser():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        pytest.skip('Playwright is not installed')
    try:
        pw = sync_playwright().start()
    except Exception as e:
        pytest.skip(f'Playwright does not start here: {e}')
    try:
        br = pw.chromium.launch(headless=True, args=DETERMINISTIC)
    except Exception as e:
        pw.stop()
        pytest.skip(f'no Chromium for Playwright: {e}')
    yield br
    br.close()
    pw.stop()


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(layout=LAYOUT, theme='', storage=None, viewport=(1600, 1000), **kw):
        app = _GuardApp(browser, _DsServer(layout=layout, **kw), corp_theme=theme, storage=storage, viewport=viewport)
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.close()


# --- helpers -----------------------------------------------------------------------------------

def _need(page, selector, what, timeout=8000):
    """Wait for a selector; a missing one fails with the property it stands for."""
    try:
        page.locator(selector).first.wait_for(timeout=timeout)
    except Exception:
        raise AssertionError(f'{what} (no {selector})') from None


def _tab(app):
    """The Datastore tab of Testi, in the layout's own navigation."""
    page = app.page
    if app.server.layout == 'modern':
        page.get_by_text('Testi').first.click()
        page.locator('button', has_text=re.compile(r'^\s*Datastore\s*$')).first.click()
    elif app.server.layout == 'corporate':
        page.locator('.corp-tree-item', has_text='Testi').first.click()
        page.locator('button', has_text=re.compile(r'^\s*Datastore\s*$')).first.click()
    else:
        page.locator('.corp-tree-item', has_text='Testi').first.click()
        page.locator('[data-cr-tab="datastore"]').click()
        _need(page, '[data-cr-ds]', 'the Browse tab is the two-panel view of the preview')
    return page


def _pick(page, key, title=None):
    """Click a storage row of the left panel and wait for its content."""
    _need(page, f'[data-cr-ds-row="{key}"]', f'{key} is a row of the storage list')
    page.locator(f'[data-cr-ds-row="{key}"]').click()
    name = title or key[2:].split('@')[0]
    page.wait_for_function('n => { const h = document.querySelector("[data-cr-ds-title]"); return h && h.textContent === n; }',
                           arg=name, timeout=8000)
    page.wait_for_function('() => !document.querySelector("[data-cr-table=\\"ds-content\\"] [aria-busy=\\"true\\"]")', timeout=8000)
    page.wait_for_timeout(150)


def _table(page):
    """Header labels and the cell texts of every row in the DOM of the content table."""
    return page.evaluate('''() => {
        const t = document.querySelector('[data-cr-table="ds-content"]');
        if (!t) return null;
        const head = Array.from(t.querySelectorAll('thead th')).map(th => th.dataset.crCol);
        const rows = Array.from(t.querySelectorAll('tbody tr.cr-row')).map(tr => Array.from(tr.children).map(td => td.innerText.replace(/\\s+/g, ' ').trim()));
        return { head, rows };
    }''')


def _col(tab, key):
    i = tab['head'].index(key)
    return [r[i] for r in tab['rows']]


def _bytes(b):
    """formatBytes of ui.js."""
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    i = 0
    while b >= 1024 and i < len(units) - 1:
        b /= 1024
        i += 1
    return f'{b:.1f} {units[i]}'


def _fixed(v, digits=0):
    """Number.prototype.toFixed: halves round up, not to even."""
    q = decimal.Decimal(1).scaleb(-digits)
    return str(decimal.Decimal(repr(v)).quantize(q, rounding=decimal.ROUND_HALF_UP))


def _focused(page, key):
    """Wait until the row with that key holds the focus (React moves it after the render)."""
    try:
        page.wait_for_function('k => document.activeElement && document.activeElement.dataset.crDsRow === k', arg=key, timeout=4000)
    except Exception:
        raise AssertionError(f'the focus is on {key} (it is on {page.evaluate("() => document.activeElement.dataset.crDsRow || document.activeElement.tagName")})') from None


def _crumbs(page):
    return [x.strip() for x in page.locator('.cr-crumbs li .cr-crumb-text').all_inner_texts()]


def _menu(page):
    page.locator('.corp-context-menu').first.wait_for(timeout=4000)
    return [x.strip() for x in page.locator('.corp-context-menu .corp-ctx-item').all_inner_texts()]


# --- the layout --------------------------------------------------------------------------------

GEOMETRY = """() => {
    const ds = document.querySelector('[data-cr-ds]').getBoundingClientRect();
    const bar = document.querySelector('.cr-taskcenter').getBoundingClientRect();
    const main = document.querySelector('.cr-main').getBoundingClientRect();
    const inside = Array.from(document.querySelectorAll('[data-cr-ds] *')).filter(e => e.getClientRects().length);
    // the boxes of the view (rows inside a scroll box are clipped by it)
    const boxes = document.querySelectorAll('[data-cr-ds] > section, [data-cr-ds] .cr-ds-list, [data-cr-ds] .cr-ds-head, [data-cr-ds] .cr-table-wrap, [data-cr-ds] .cr-table-scroll');
    const below = Array.from(boxes).filter(e => e.getBoundingClientRect().bottom > bar.top + 0.5).length;
    const scrollers = inside.filter(e => { const cs = getComputedStyle(e);
        return /(auto|scroll)/.test(cs.overflowY) && e.scrollHeight > e.clientHeight + 1; })
        .map(e => e.matches('[data-cr-ds-list]') ? 'list' : e.matches('.cr-table-scroll') ? 'table' : e.className);
    return { top: ds.top, bottom: ds.bottom, bar: bar.top, mainBottom: main.bottom, below, scrollers,
             scrollY: window.scrollY, fixedHeights: Array.from(document.querySelectorAll('[data-cr-ds] [class*="max-h-"]')).length };
}"""


@pytest.mark.parametrize('size', [(1600, 1000), (1280, 720)], ids=['1600', '1280'])
def test_runtime_the_two_panels_fill_the_height_down_to_the_task_bar(open_app, size):
    many = dict(CONTENT)
    many[('local', 'pve1')] = [_vol(f'local:iso/img-{i:03d}.iso', 'iso', i * MIB, format='iso', size_human=f'{i}.0 MB')
                               for i in range(1, 121)]
    app = open_app(viewport=size, content=many)
    page = _tab(app)
    _pick(page, 's:local@pve1')
    g = page.evaluate(GEOMETRY)
    # the view ends 8 px above the task bar, and nothing of it lies under the bar
    assert abs(g['bottom'] - (g['bar'] - 8)) <= 2, ('the panels end above the task bar', g)
    assert g['below'] == 0, ('nothing of the view under the task bar', g)
    # nothing else in the content column below it: the page scrolls only to its footer
    assert abs(g['mainBottom'] - g['bottom'] - 8) <= 1, ('the view is the last thing in the content column', g)
    assert g['fixedHeights'] == 0, ('no fixed small heights', g)
    # the panels scroll inside, each on its own: the 120 entries in the table, the storages in the list
    # once they do not fit, and nothing else inside the view
    assert 'table' in g['scrollers'] and set(g['scrollers']) <= {'list', 'table'}, ('two scroll boxes at most', g)
    # a wheel at the end of the table does not run on into the page
    box = page.locator('[data-cr-table="ds-content"] .cr-table-scroll').bounding_box()
    page.mouse.move(box['x'] + 200, box['y'] + 100)
    for _ in range(12):
        page.mouse.wheel(0, 1200)
    page.wait_for_timeout(300)
    assert page.evaluate('() => window.scrollY') == 0, 'the page did not scroll with the table'
    assert page.locator('[data-cr-table="ds-content"] tbody tr.cr-row').last.inner_text().startswith('img-120.iso')
    # the drawer of the task center opens over it and closes again; the height stays
    page.locator('[data-cr-tc-toggle]').click()
    page.wait_for_timeout(300)
    page.locator('[data-cr-tc-toggle]').click()
    page.wait_for_timeout(300)
    again = page.evaluate(GEOMETRY)
    assert abs(again['bottom'] - (again['bar'] - 8)) <= 2, again
    # a window that changes its height takes the panels with it
    page.set_viewport_size({'width': size[0], 'height': size[1] - 120})
    page.wait_for_timeout(400)
    smaller = page.evaluate(GEOMETRY)
    assert abs(smaller['bottom'] - (smaller['bar'] - 8)) <= 2, smaller
    assert app.errors == []


# --- meters and states -------------------------------------------------------------------------

ROWS_JS = """() => Array.from(document.querySelectorAll('[data-cr-ds-row^="s:"]')).map(r => ({
    key: r.dataset.crDsRow,
    cap: r.querySelector('[data-cr-ds-cap]') ? r.querySelector('[data-cr-ds-cap]').dataset.crDsCap : null,
    used: r.querySelector('[data-cr-ds-used]') ? r.querySelector('[data-cr-ds-used]').textContent : null,
    tone: r.querySelector('.cr-meter') ? (r.querySelector('.cr-meter').className.match(/cr-tone-(\\w+)/) || [])[1] : null,
    pct: r.querySelector('.cr-meter-val') ? r.querySelector('.cr-meter-val').textContent : null,
    warn: r.querySelector('[data-cr-ds-warn]') ? r.querySelector('[data-cr-ds-warn]').dataset.crDsWarn : null,
    states: Array.from(r.querySelectorAll('[data-cr-ds-state]')).map(b => b.dataset.crDsState + ':' + b.textContent),
    text: r.innerText.replace(/\\s+/g, ' ').trim(),
}))"""


def _rows_info(page):
    return {r['key']: r for r in page.evaluate(ROWS_JS)}


def test_runtime_every_row_shows_the_meter_and_the_state_of_the_fake_data(open_app):
    app = open_app()
    page = _tab(app)
    _need(page, '[data-cr-ds-group="n:pve3"]', 'one group per node')
    rows = _rows_info(page)
    expect = {
        's:ceph-rbd@': CEPH, 's:backupsrv@': PBS, 's:cephfs@': CEPHFS, 's:local@pve1': LOCAL1, 's:local-lvm@pve1': LVM1,
        's:local@pve2': LOCAL2, 's:bare@pve2': BARE2,
    }
    for key, s in expect.items():
        r = rows[key]
        pct = s['used'] / s['total'] * 100
        assert r['cap'] == _fixed(pct, 2), (key, r)
        assert r['pct'] == _fixed(pct) + '%', (key, r)
        assert r['used'] == f"{_bytes(s['used'])} / {_bytes(s['total'])}", (key, r)
        tone = 'error' if pct > 85 else 'warning' if pct >= 70 else 'success'
        assert r['tone'] == tone, (key, r)
        assert r['warn'] == (tone if tone != 'success' else None), (key, r)
    # the states the fields tell, and nothing for fields that are not there
    assert rows['s:cephfs@']['states'] == ['partial:1/2 Nodes'], rows['s:cephfs@']
    assert rows['s:nfs-old@']['states'] == ['inactive:Inactive'] and rows['s:nfs-old@']['cap'] is None
    assert rows['s:old-dir@pve1']['states'] == ['disabled:Disabled'] and rows['s:old-dir@pve1']['cap'] is None
    # raw block storage: active, but PVE reports no usage, so no meter and no 0 %
    raw = rows['s:iscsi-raw@pve1']
    assert raw['states'] == [] and raw['cap'] == 'raw' and raw['pct'] is None and 'no usage stats' in raw['text'], raw
    for key in ('s:local@pve3', 's:local-lvm@pve3'):
        # an offline node's storages: the server sends zeros, which are no usage
        assert rows[key]['states'] == ['offline:Node offline'] and rows[key]['cap'] is None, rows[key]
        assert '0.0 B' not in rows[key]['text'] and '0%' not in rows[key]['text'], rows[key]
    assert rows['s:bare@pve2']['states'] == [], rows['s:bare@pve2']
    assert 'Offline' in page.locator('[data-cr-ds-group="n:pve3"]').inner_text()
    # the head of the picked storage carries the same meter, its state and where it lives
    _pick(page, 's:ceph-rbd@')
    head = page.locator('[data-cr-ds-head]')
    assert head.locator('[data-cr-ds-cap]').get_attribute('data-cr-ds-cap') == '92.50'
    assert head.locator('[data-cr-ds-used]').inner_text() == f"{_bytes(CEPH['used'])} of {_bytes(CEPH['total'])}"
    assert head.locator('.cr-ds-cap-free').inner_text() == f"{_bytes(CEPH['avail'])} free"
    assert head.locator('[data-cr-ds-warn]').get_attribute('data-cr-ds-warn') == 'error'
    states = head.locator('[data-cr-ds-state]').evaluate_all('bs => bs.map(b => b.dataset.crDsState)')
    assert states == ['active', 'shared'], states
    # a shared storage several nodes mount reads through the first one, and can be read from the other
    assert app.server.content_reads[-1] == ('ceph-rbd', 'pve1')
    assert page.locator('[data-cr-ds-viewfrom] option').evaluate_all('os => os.map(o => o.value)') == ['pve1', 'pve2']
    _pick(page, 's:bare@pve2')
    assert page.locator('[data-cr-ds-head] [data-cr-ds-state]').count() == 0
    assert page.locator('[data-cr-ds-head] [data-cr-ds-cap]').get_attribute('data-cr-ds-cap') == '10.00'
    _pick(page, 's:nfs-old@')
    assert 'Inactive' in page.locator('[data-cr-ds-head]').inner_text()
    assert page.locator('[data-cr-ds-head] [data-cr-ds-cap]').count() == 0
    assert app.errors == []


def test_runtime_the_meter_takes_the_storage_thresholds(open_app):
    # LW Oct 2026 - round 3 moved the storage views from the 80/90 of the overview alerts to the
    # spec's pair: below 70 normal, 70 to 85 warning (both ends), above 85 critical
    tones = {'t69': 69.9, 't70': 70, 't84': 84.9, 't85': 85, 't86': 85.1}
    ds = {'shared': [], 'nodes': ['pve1'],
          'local': {'pve1': [_st(k, 'dir', 'iso', 1000, v * 10) for k, v in tones.items()]}}
    app = open_app(datastores=ds)
    page = _tab(app)
    _need(page, '[data-cr-ds-row="s:t86@pve1"]', 'the storages of pve1 are rows')
    rows = _rows_info(page)
    got = {k: (rows[f's:{k}@pve1']['tone'], rows[f's:{k}@pve1']['warn']) for k in tones}
    assert got == {'t69': ('success', None), 't70': ('warning', 'warning'), 't84': ('warning', 'warning'),
                   't85': ('warning', 'warning'), 't86': ('error', 'error')}, got
    # the same colour in the head
    _pick(page, 's:t86@pve1')
    assert 'cr-tone-error' in page.locator('[data-cr-ds-head] .cr-meter').get_attribute('class')
    assert app.errors == []


def test_a_meter_track_with_a_fixed_basis_also_has_that_width():
    """Firefox sizes an auto-width meter from its contents and leaves the flex basis of the track
    out, so the percentage spilled over the used/total text next to it. Every fixed track basis
    in the preview's CSS needs the same width."""
    css = BUNDLE or open(os.path.join(ROOT, 'web', 'index.html'), encoding='utf-8').read()
    rules = re.findall(r'body\[data-layout="corporate"\]\[data-corp-variant="redesigned"\] ([^{}]*\.cr-meter-track) \{([^}]*)\}', css)
    fixed = []
    for sel, body in rules:
        m = re.search(r'flex(?:-basis)?:\s*(?:0 0 )?(\d+)px', body)
        if not m:
            continue
        fixed.append(sel)
        assert re.search(rf'(?<![-\w])width:\s*{m.group(1)}px', body), f'{sel} has a {m.group(1)}px basis but no width: {body.strip()}'
    assert len(fixed) >= 4, fixed


# --- the content -------------------------------------------------------------------------------

# fmtDate's parts to the minute, as the created column shows it, in the UI language of the fake
# (English), not the browser's (round 8, A-1)
DATE_JS = """(secs) => secs.map(s => new Intl.DateTimeFormat('en', { year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', hour12: false }).format(new Date(s * 1000)))"""


def test_runtime_the_content_table_is_the_fake_content_with_chips_search_sort_and_columns(open_app):
    app = open_app()
    page = _tab(app)
    _pick(page, 's:local@pve1')
    tab = _table(page)
    # a column for each field the rows have (no verification here), the newest first
    assert tab['head'] == ['name', 'content', 'owner', 'format', 'size', 'created', 'notes', 'protected', 'del'], tab['head']
    order = [BK100, BK555, SNIP, ISO, ISO_APPROX, TMPL]
    assert _col(tab, 'name') == ['vzdump-qemu-100-2026_10_30-07_00_00.vma.zst', 'vzdump-lxc-555-2026_10_29-07_00_00.tar.zst',
                                 'user-data.yaml', 'debian-12.4.0-amd64-netinst.iso', 'win2022.iso',
                                 'debian-12-standard_12.7-1_amd64.tar.zst']
    assert _col(tab, 'content') == ['Backup', 'Backup', 'Snippet', 'ISO image', 'ISO image', 'Container template']
    assert _col(tab, 'owner') == ['web01 100', '555', '', '', '', '']
    assert _col(tab, 'format') == [r['format'] for r in order]
    # the size PVE reported, with ~ where it is approximate
    assert _col(tab, 'size') == ['3.0 GB', '700.0 MB', '2.0 KB', '658.0 MB', '~5.0 GB', '120.0 MB']
    assert _col(tab, 'created') == page.evaluate(DATE_JS, [r['ctime'] for r in order])
    assert _col(tab, 'notes') == ['web01 nightly', '', '', '', '', '']
    table = page.locator('[data-cr-table="ds-content"]')
    assert table.locator('[data-cr-ds-protected]').count() == 1
    assert table.locator('tbody tr.cr-row').nth(0).locator('[data-cr-ds-protected]').count() == 1
    # classic's trash: backups, and ISOs and templates no guest owns; never a snippet
    dels = table.locator('tbody tr.cr-row').evaluate_all('rs => rs.map(r => !!r.querySelector("[data-cr-ds-del]"))')
    assert dels == [True, True, False, True, True, True], dels
    # the type chips count what is there
    chips = page.locator('[data-cr-ds-type]').evaluate_all('bs => bs.map(b => [b.dataset.crDsType, b.innerText.replace(/\\s+/g, " ").trim()])')
    assert chips == [['all', 'All 6'], ['backup', 'Backup 2'], ['iso', 'ISO image 2'], ['vztmpl', 'Container template 1'],
                     ['snippets', 'Snippet 1']], chips
    page.locator('[data-cr-ds-type="iso"]').click()
    assert _col(_table(page), 'name') == ['debian-12.4.0-amd64-netinst.iso', 'win2022.iso']
    assert page.locator('[data-cr-ds-type="iso"]').get_attribute('aria-pressed') == 'true'
    page.locator('[data-cr-ds-type="all"]').click()
    # the search reads the whole volume id and the owner
    search = table.locator('input[type="search"]')
    search.fill('debian')
    assert _col(_table(page), 'name') == ['debian-12.4.0-amd64-netinst.iso', 'debian-12-standard_12.7-1_amd64.tar.zst']
    search.fill('web01')
    assert _col(_table(page), 'name') == ['vzdump-qemu-100-2026_10_30-07_00_00.vma.zst']
    search.fill('')
    # sort by size, both ways
    table.locator('th[data-cr-col="size"] .cr-th-btn').click()
    assert _col(_table(page), 'size') == ['2.0 KB', '120.0 MB', '658.0 MB', '700.0 MB', '3.0 GB', '~5.0 GB']
    table.locator('th[data-cr-col="size"] .cr-th-btn').click()
    assert _col(_table(page), 'size') == ['~5.0 GB', '3.0 GB', '700.0 MB', '658.0 MB', '120.0 MB', '2.0 KB']
    # the column menu hides a column and keeps it hidden
    table.locator('[data-cr-colmenu]').click()
    offered = table.locator('.cr-menu input[data-cr-col]').evaluate_all('cs => cs.map(c => c.dataset.crCol)')
    assert offered == ['name', 'content', 'owner', 'format', 'size', 'created', 'notes', 'protected', 'del'], offered
    table.locator('.cr-menu input[data-cr-col="notes"]').uncheck()
    page.keyboard.press('Escape')
    assert 'notes' not in _table(page)['head']
    assert json.loads(page.evaluate('() => localStorage.getItem("cr-table:ds-content")'))['h'] == {'notes': True}
    # a storage without dates, notes or protection has no column for them, not even in the menu
    _pick(page, 's:ceph-rbd@')
    assert _table(page)['head'] == ['name', 'content', 'owner', 'format', 'size', 'del']
    table.locator('[data-cr-colmenu]').click()
    assert table.locator('.cr-menu input[data-cr-col]').evaluate_all('cs => cs.map(c => c.dataset.crCol)') == \
        ['name', 'content', 'owner', 'format', 'size', 'del']
    page.locator('.cr-click-away').click(position={'x': 5, 'y': 300})
    # PBS: the verification state where the rows have it
    _pick(page, 's:backupsrv@')
    tab = _table(page)
    assert 'verify' in tab['head'] and _col(tab, 'verify') == ['ok'], tab
    assert app.errors == []


def test_runtime_the_owner_opens_its_guest_and_an_unknown_one_stays_text(open_app):
    app = open_app()
    page = _tab(app)
    _pick(page, 's:ceph-rbd@')
    table = page.locator('[data-cr-table="ds-content"]')
    assert _col(_table(page), 'owner') == ['web01 100', 'ct01 101', 'db01 102', '555']
    # a guest the inventory does not hold (or the user may not see) is its id, not a link
    assert table.locator('[data-cr-ds-owner="555"]').count() == 0
    assert table.locator('[data-cr-ds-owner-plain="555"]').get_attribute('title') == 'Not in the inventory you can see'
    table.locator('[data-cr-ds-owner="100"]').click()
    page.locator('[data-cr-objhead="vm"]').wait_for(timeout=8000)
    assert _crumbs(page) == ['All', 'Testi', 'Resources', 'web01'], _crumbs(page)
    assert 'web01' in page.locator('[data-cr-objhead="vm"]').inner_text()
    # and back: a container opens the container view
    page.locator('[data-cr-tab="datastore"]').click()
    _pick(page, 's:ceph-rbd@')
    page.locator('[data-cr-table="ds-content"] [data-cr-ds-owner="101"]').click()
    page.locator('[data-cr-objhead="ct"]').wait_for(timeout=8000)
    assert _crumbs(page)[-1] == 'ct01'
    assert app.errors == []


# --- actions: only what classic offers, through its handlers ----------------------------------

# cephfs holds templates, an ISO and a backup (every upload and restore action), local-lvm is a
# type classic rescans, backupsrv holds backups only
PARITY_CONTENT = dict(CONTENT)
PARITY_CONTENT[('cephfs', 'pve1')] = [TMPL, ISO, BK100]
PARITY = ('cephfs', 'local-lvm', 'backupsrv')
CLASSIC_BUTTONS = {
    'templates': "button:text-matches('^\\\\s*Templates\\\\s*$')", 'url': "button:text-matches('^\\\\s*From URL\\\\s*$')",
    'upload': "button:text-matches('^\\\\s*Upload\\\\s*$')", 'rescan': "button:text-matches('^\\\\s*Rescan\\\\s*$')",
    'restore': '[data-br-open]', 'recent': '[data-br-recent-open]',
}
PERMS = {
    'admin': (True, [], {'cephfs': ['templates', 'url', 'upload', 'restore', 'recent'], 'local-lvm': ['rescan'],
                         'backupsrv': ['restore', 'recent']}),
    'uploader': (False, ['storage.view', 'storage.upload'], {'cephfs': ['templates', 'url', 'upload'], 'local-lvm': [],
                                                             'backupsrv': []}),
    'viewer': (False, ['storage.view'], {'cephfs': [], 'local-lvm': [], 'backupsrv': []}),
    'restorer': (False, ['storage.view', 'vm.backup', 'backup.view', 'storage.config'],
                 {'cephfs': ['restore', 'recent'], 'local-lvm': ['rescan'], 'backupsrv': ['restore', 'recent']}),
}


def _classic_actions(app, name):
    page = app.page
    page.locator('div.cursor-pointer', has=page.locator('.font-medium', has_text=re.compile(r'^\s*' + re.escape(name)))).first.click()
    page.get_by_text(f'Content: {name}').first.wait_for(timeout=8000)
    page.wait_for_timeout(600)
    return [k for k, sel in CLASSIC_BUTTONS.items() if page.locator(sel).count()]


@pytest.mark.parametrize('who', list(PERMS))
def test_runtime_the_actions_are_classic_s_for_the_same_permissions(open_app, who):
    admin, perms, want = PERMS[who]
    seen = {}
    for layout in ('corporate', 'modern', LAYOUT):
        app = open_app(layout=layout, admin=admin, permissions=perms, content=PARITY_CONTENT)
        page = _tab(app)
        got = {}
        for name in PARITY:
            if layout == LAYOUT:
                _pick(page, f's:{name}@')  if name != 'local-lvm' else _pick(page, 's:local-lvm@pve1')
                got[name] = page.locator('[data-cr-ds-head] [data-cr-ds-action]').evaluate_all(
                    'bs => bs.map(b => b.dataset.crDsAction).filter(a => a !== "refresh")')
            else:
                page.wait_for_timeout(300)
                got[name] = _classic_actions(app, name)
        seen[layout] = got
        assert app.errors == [], (layout, app.errors)
    assert seen['corporate'] == want and seen['modern'] == want, seen
    assert seen[LAYOUT] == want, ('the preview offers what classic offers', seen)


def test_runtime_delete_goes_through_the_classic_confirmation(open_app):
    app = open_app()
    page = _tab(app)
    _pick(page, 's:local@pve1')
    table = page.locator('[data-cr-table="ds-content"]')
    row = table.locator('tbody tr.cr-row', has_text='debian-12.4.0-amd64-netinst.iso')
    assert row.locator('[data-cr-ds-del]').get_attribute('aria-label') == 'Delete debian-12.4.0-amd64-netinst.iso'
    row.locator('[data-cr-ds-del]').click()
    dialog = page.locator('div.fixed.inset-0', has_text='Confirm Delete')
    dialog.wait_for(timeout=4000)
    assert 'debian-12.4.0-amd64-netinst.iso' in dialog.inner_text()
    dialog.locator('button', has_text='Cancel').click()
    page.wait_for_timeout(300)
    assert app.server.deletes == [] and row.count() == 1
    row.locator('[data-cr-ds-del]').click()
    dialog.wait_for(timeout=4000)
    dialog.locator('button', has_text=re.compile(r'^\s*Delete\s*$')).click()
    page.wait_for_function('() => !Array.from(document.querySelectorAll("[data-cr-table=\\"ds-content\\"] tbody tr.cr-row")).some(r => r.innerText.includes("netinst"))', timeout=5000)
    # one request, the volume id and the node the storage was read from
    assert app.server.deletes == [('local', ISO['volid'], 'pve1')], app.server.deletes
    assert _col(_table(page), 'name').count('debian-12.4.0-amd64-netinst.iso') == 0
    assert app.errors == []


def test_runtime_without_storage_delete_there_is_no_delete_anywhere(open_app):
    app = open_app(admin=False, permissions=['storage.view', 'vm.backup', 'backup.view'])
    page = _tab(app)
    _pick(page, 's:local@pve1')
    tab = _table(page)
    assert 'del' not in tab['head'] and page.locator('[data-cr-ds-del]').count() == 0
    row = page.locator('[data-cr-table="ds-content"] tbody tr.cr-row', has_text='debian-12.4.0-amd64-netinst.iso')
    row.click(button='right')
    page.wait_for_timeout(300)
    # an ISO row has nothing else to offer, so no menu opens
    assert page.locator('.corp-context-menu').count() == 0
    row = page.locator('[data-cr-table="ds-content"] tbody tr.cr-row', has_text='vzdump-qemu-100')
    row.click(button='right')
    assert _menu(page) == ['Open guest', 'Restore several', 'Batch restores']
    page.keyboard.press('Escape')
    assert app.errors == []


def test_runtime_the_context_menus_open_by_mouse_and_keys_with_classic_actions(open_app):
    app = open_app()
    page = _tab(app)
    _pick(page, 's:local@pve1')
    table = page.locator('[data-cr-table="ds-content"]')
    # a backup: its guest, the two restore dialogs and the delete of classic
    backup = table.locator('tbody tr.cr-row', has_text='vzdump-qemu-100')
    backup.click(button='right')
    assert _menu(page) == ['Open guest', 'Restore several', 'Batch restores', 'Delete']
    page.keyboard.press('Escape')
    assert page.locator('.corp-context-menu').count() == 0
    # the keyboard: the ContextMenu key and Shift+F10 on the focused row, Escape gives the focus back
    backup.focus()
    page.wait_for_function('() => (document.activeElement.innerText || "").startsWith("vzdump-qemu-100")', timeout=4000)
    page.keyboard.press('ContextMenu')
    assert _menu(page) == ['Open guest', 'Restore several', 'Batch restores', 'Delete']
    page.keyboard.press('Escape')
    assert page.evaluate('() => document.activeElement.innerText').startswith('vzdump-qemu-100')
    page.keyboard.press('ArrowDown')
    page.wait_for_function('() => (document.activeElement.innerText || "").startsWith("vzdump-lxc-555")', timeout=4000)
    page.keyboard.press('Shift+F10')
    # the backup of a guest this inventory does not hold: no "Open guest"
    assert _menu(page) == ['Restore several', 'Batch restores', 'Delete']
    # Delete from the menu is the same confirmation, nothing is sent before it
    page.locator('.corp-context-menu .corp-ctx-item', has_text='Delete').click()
    dialog = page.locator('div.fixed.inset-0', has_text='Confirm Delete')
    dialog.wait_for(timeout=4000)
    assert 'vzdump-lxc-555' in dialog.inner_text() and app.server.deletes == []
    dialog.locator('button', has_text='Cancel').click()
    # restore from the menu opens the classic batch restore dialog
    backup.click(button='right')
    page.locator('.corp-context-menu .corp-ctx-item', has_text='Restore several').click()
    page.locator('[data-br-pick]').wait_for(timeout=5000)
    page.locator('[data-testid="batch-restore-modal"] button', has_text=re.compile(r'^\s*Cancel\s*$')).first.click()
    page.wait_for_timeout(300)
    # a disk image of a guest: only its guest (classic deletes no disk here)
    _pick(page, 's:ceph-rbd@')
    page.locator('[data-cr-table="ds-content"] tbody tr.cr-row', has_text='vm-100-disk-0').click(button='right')
    assert _menu(page) == ['Open guest']
    page.keyboard.press('Escape')
    # the storage list: open it, plus the dialogs classic has for its type; the storage is picked first
    page.locator('[data-cr-ds-row="s:local-lvm@pve1"]').click(button='right')
    assert _menu(page) == ['Open', 'Rescan']
    page.locator('.corp-context-menu .corp-ctx-item', has_text='Rescan').click()
    page.locator('div.fixed.inset-0', has_text='Rescan Storage').wait_for(timeout=4000)
    assert page.locator('[data-cr-ds-title]').inner_text() == 'local-lvm'
    assert app.server.content_reads[-1] == ('local-lvm', 'pve1')
    page.locator('div.fixed.inset-0', has_text='Rescan Storage').locator('button', has_text=re.compile(r'^\s*Cancel\s*$')).click()
    page.locator('[data-cr-ds-row="s:local@pve1"]').focus()
    page.keyboard.press('Shift+F10')
    assert _menu(page) == ['Open', 'Templates', 'From URL', 'Upload']
    page.keyboard.press('Escape')
    assert page.evaluate('() => document.activeElement.dataset.crDsRow') == 's:local@pve1'
    assert app.errors == []


# Escape closes the menu from a document listener, so the render after it leaves its effect
# pending for a moment. An arrow key in that moment once lost the move: React ran the pending
# effect after the key and it focused the row of its own render again (round 4, stage K). Both
# keys go in one task here, so the effect is always still pending when the arrow comes.
_ESCAPE_THEN_ARROW = """() => {
    document.querySelector('.corp-context-menu').dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true }));
    const back = document.activeElement;
    back.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowDown', bubbles: true, cancelable: true }));
    return back.dataset.rowIndex || back.dataset.crDsRow || '';
}"""


def test_runtime_an_arrow_key_right_after_the_menu_closes_moves_the_focus(open_app):
    app = open_app()
    page = _tab(app)
    _pick(page, 's:local@pve1')
    # the content table
    page.locator('[data-cr-table="ds-content"] tbody tr.cr-row', has_text='vzdump-qemu-100').focus()
    page.keyboard.press('ContextMenu')
    _menu(page)
    assert page.evaluate(_ESCAPE_THEN_ARROW) == '0'
    page.wait_for_function('() => (document.activeElement.innerText || "").startsWith("vzdump-lxc-555")', timeout=4000)
    page.wait_for_timeout(300)
    assert page.evaluate('() => document.activeElement.dataset.rowIndex') == '1'
    # the storage list on the left, the same way
    page.locator('[data-cr-ds-row="s:local@pve1"]').focus()
    page.keyboard.press('Shift+F10')
    _menu(page)
    assert page.evaluate(_ESCAPE_THEN_ARROW) == 's:local@pve1'
    page.wait_for_function('() => document.activeElement.dataset.crDsRow === "s:local-lvm@pve1"', timeout=4000)
    page.wait_for_timeout(300)
    assert page.evaluate('() => document.activeElement.dataset.crDsRow') == 's:local-lvm@pve1'
    assert app.errors == []


# --- look --------------------------------------------------------------------------------------

@pytest.mark.parametrize('theme,accent,ink', [('', 'rgb(85, 182, 208)', 'rgb(13, 28, 34)'),
                                              ('light', 'rgb(11, 111, 153)', 'rgb(255, 255, 255)')], ids=['dark', 'light'])
def test_runtime_the_primary_button_takes_the_tokens_of_the_preview(open_app, theme, accent, ink):
    app = open_app(theme=theme)
    page = _tab(app)
    _pick(page, 's:local@pve1')
    up = page.locator('[data-cr-ds-action="upload"]')
    assert 'cr-btn-primary' in up.get_attribute('class')
    assert up.evaluate('e => [getComputedStyle(e).backgroundColor, getComputedStyle(e).color]') == [accent, ink]
    # the others are the quiet ones, none of the classic blue, green or purple
    colours = page.locator('[data-cr-ds-head] .cr-btn:not(.cr-btn-primary)').evaluate_all(
        'bs => bs.map(b => getComputedStyle(b).backgroundColor)')
    assert colours and len(set(colours)) == 1, colours
    assert not page.locator('[data-cr-ds] .bg-blue-600, [data-cr-ds] .bg-green-600, [data-cr-ds] .bg-purple-600').count()
    panel = page.locator('.cr-ds-side').evaluate('e => getComputedStyle(e).backgroundColor')
    assert panel == ('rgb(255, 255, 255)' if theme == 'light' else 'rgb(32, 51, 62)'), panel
    assert app.errors == []


# --- scale -------------------------------------------------------------------------------------

def test_runtime_5000_entries_in_one_storage_stay_smooth(open_app):
    big = [_vol(f'local:backup/vzdump-qemu-{1000 + i}-2026_10_{1 + i % 28:02d}-07_00_00.vma.zst', 'backup', (i % 97 + 1) * GIB,
                format='vma.zst', size_human=f'{i % 97 + 1}.0 GB', ctime=CTIME - i * 600, vmid=1000 + i, notes=f'job {i % 13}',
                protected=1 if i % 50 == 0 else 0) for i in range(4500)]
    big += [_vol(f'local:iso/image-{i:04d}.iso', 'iso', (i + 1) * MIB, format='iso', size_human=f'{i + 1}.0 MB',
                 ctime=CTIME - i * 900) for i in range(500)]
    content = dict(CONTENT)
    content[('local', 'pve1')] = big
    app = open_app(content=content)
    page = _tab(app)
    t0 = time.time()
    _pick(page, 's:local@pve1')
    drawn = time.time() - t0
    table = page.locator('[data-cr-table="ds-content"]')
    assert table.locator('.cr-table-count').inner_text() == '5000 of 5000'
    trs = table.locator('tbody tr').count()
    assert trs < 120, trs
    assert drawn < 3.0, drawn

    def timed(fn, until):
        t = time.time()
        fn()
        page.wait_for_function(until, timeout=10000)
        return time.time() - t
    first_row = '() => (document.querySelector("[data-cr-table=\\"ds-content\\"] tbody tr.cr-row") || {}).innerText || ""'
    sort = timed(lambda: table.locator('th[data-cr-col="size"] .cr-th-btn').click(),
                 f'() => ({first_row})().includes("1.0 MB")')
    search = timed(lambda: table.locator('input[type="search"]').fill('image-0499'),
                   '() => document.querySelector("[data-cr-table=\\"ds-content\\"] .cr-table-count").textContent === "1 of 5000"')
    table.locator('input[type="search"]').fill('')
    chip = timed(lambda: page.locator('[data-cr-ds-type="iso"]').click(),
                 '() => document.querySelector("[data-cr-table=\\"ds-content\\"] .cr-table-count").textContent === "500 of 5000"')
    assert max(sort, search, chip) < 1.0, (sort, search, chip)
    # the last row is reachable by scrolling the table
    page.locator('[data-cr-ds-type="all"]').click()
    table.locator('.cr-table-scroll').evaluate('e => { e.scrollTop = e.scrollHeight; e.dispatchEvent(new Event("scroll")); }')
    page.wait_for_timeout(300)
    assert table.locator('tbody tr').count() < 120
    assert app.errors == []
    print(f'5000 entries: drawn {drawn:.2f}s, sort {sort:.2f}s, search {search:.2f}s, chip {chip:.2f}s, {trs} tr')


def _many_nodes(n=200):
    nodes = [f'node{i:03d}' for i in range(n)]
    local = {nd: [_st('local', 'dir', 'iso,vztmpl,backup', 100, (i * 7) % 100), _st('local-lvm', 'lvmthin', 'images,rootdir', 500, (i * 13) % 500),
                  _st('nvme', 'zfspool', 'images,rootdir', 2000, (i * 29) % 2000)] for i, nd in enumerate(nodes)}
    return {'shared': [CEPH, PBS], 'local': local, 'nodes': nodes}


def test_runtime_200_nodes_in_the_storage_list_stay_smooth(open_app):
    app = open_app(datastores=_many_nodes())
    page = _tab(app)
    _need(page, '[data-cr-ds-group="n:node000"]', 'a group per node')
    # above 12 nodes only the shared group starts open; the list is a window, not 800 rows
    info = page.evaluate('''() => ({ rows: document.querySelectorAll('[data-cr-ds-row]').length,
        open: Array.from(document.querySelectorAll('[data-cr-ds-group]')).filter(g => g.getAttribute('aria-expanded') === 'true').map(g => g.dataset.crDsGroup),
        groups: document.querySelectorAll('[data-cr-ds-group]').length })''')
    assert info['open'] == ['shared'], info
    assert info['rows'] < 120, info
    # the filter finds one storage among 602 and opens its group
    t = time.time()
    page.locator('[data-cr-ds-filter]').fill('node150')
    page.locator('[data-cr-ds-row="s:local-lvm@node150"]').wait_for(timeout=5000)
    took = time.time() - t
    assert took < 1.0, took
    assert page.locator('[data-cr-ds-row]').count() == 4  # the group and its three storages
    page.locator('[data-cr-ds-row="s:local-lvm@node150"]').click()
    page.wait_for_function('() => document.querySelector("[data-cr-ds-title]")?.textContent === "local-lvm"', timeout=5000)
    assert app.server.content_reads[-1] == ('local-lvm', 'node150')
    page.locator('[data-cr-ds-filter]').fill('')
    # "problems only": the storages from 70 % on (the storage warning) and nothing else
    page.locator('[data-cr-ds-problems]').click()
    keys = page.evaluate('() => Array.from(document.querySelectorAll("[data-cr-ds-row^=\\"s:\\"]")).map(r => r.dataset.crDsRow)')
    assert keys and all(k.startswith(('s:ceph-rbd@', 's:local@', 's:local-lvm@', 's:nvme@')) for k in keys)
    bad = page.evaluate('''() => Array.from(document.querySelectorAll('[data-cr-ds-row^="s:"] [data-cr-ds-cap]')).map(c => +c.dataset.crDsCap)''')
    assert bad and min(bad) >= 70, bad
    # a narrowed group says how many of its storages it shows
    assert page.locator('[data-cr-ds-group="shared"] [data-cr-ds-group-n]').inner_text() == '1/2'
    page.locator('[data-cr-ds-problems]').click()
    # the keyboard reaches the end of the list and opens a group there
    page.locator('[data-cr-ds-group="shared"]').focus()
    t = time.time()
    page.keyboard.press('End')
    page.wait_for_function('() => document.activeElement?.dataset?.crDsRow === "g:esxi"', timeout=5000)
    page.keyboard.press('ArrowUp')
    page.wait_for_function('() => document.activeElement?.dataset?.crDsRow === "g:n:node199"', timeout=5000)
    page.keyboard.press('ArrowRight')
    page.wait_for_function('() => document.querySelector("[data-cr-ds-group=\\"n:node199\\"]").getAttribute("aria-expanded") === "true"', timeout=5000)
    page.keyboard.press('ArrowDown')
    page.keyboard.press('Enter')
    page.wait_for_function('() => document.querySelector("[data-cr-ds-title]")?.textContent === "local"', timeout=5000)
    assert app.server.content_reads[-1] == ('local', 'node199')
    assert time.time() - t < 3.0
    assert page.locator('[data-cr-ds-row]').count() < 120
    assert app.errors == []


def test_runtime_the_storage_list_is_a_tree_for_the_keyboard(open_app):
    app = open_app()
    page = _tab(app)
    _need(page, '[data-cr-ds-group="shared"]', 'the shared group')
    tree = page.locator('[data-cr-ds-list] [role="tree"]')
    assert tree.get_attribute('aria-label') == 'Datastores'
    # one tab stop: the first row
    page.locator('[data-cr-ds-filter]').focus()
    page.keyboard.press('Tab')
    _focused(page, 'g:shared')
    page.keyboard.press('ArrowDown')
    # the shared storages in classic's order (by name)
    _focused(page, 's:backupsrv@')
    page.keyboard.press('ArrowDown')
    _focused(page, 's:ceph-rbd@')
    page.keyboard.press('Enter')
    page.wait_for_function('() => document.querySelector("[data-cr-ds-title]")?.textContent === "ceph-rbd"', timeout=5000)
    assert page.locator('[data-cr-ds-row="s:ceph-rbd@"]').get_attribute('aria-selected') == 'true'
    # Left goes to the group, Left again folds it, Right opens it
    page.keyboard.press('ArrowLeft')
    _focused(page, 'g:shared')
    page.keyboard.press('ArrowLeft')
    assert page.locator('[data-cr-ds-group="shared"]').get_attribute('aria-expanded') == 'false'
    assert page.locator('[data-cr-ds-row="s:ceph-rbd@"]').count() == 0
    page.keyboard.press('ArrowRight')
    assert page.locator('[data-cr-ds-group="shared"]').get_attribute('aria-expanded') == 'true'
    # every row names itself, levels and positions for a screen reader
    info = page.evaluate('''() => Array.from(document.querySelectorAll('[data-cr-ds-row]')).map(r => [r.getAttribute('role'), r.getAttribute('aria-level'),
        (r.getAttribute('aria-label') || r.innerText).trim().length > 0, r.getAttribute('aria-posinset'), r.getAttribute('aria-setsize')])''')
    assert all(x[0] == 'treeitem' and x[1] in ('1', '2') and x[2] and x[3] and x[4] for x in info), info
    assert app.errors == []


# --- the datastore view of the sidebar ---------------------------------------------------------

SIDE_JS = """() => Array.from(document.querySelectorAll('[data-cr-ds-tree="c1"] [data-cr-ds-node]')).map(r => [
    r.dataset.crDsNode, r.querySelector('.cr-meter-val') ? r.querySelector('.cr-meter-val').textContent : null,
    r.querySelector('[data-cr-ds-warn]') ? r.querySelector('[data-cr-ds-warn]').dataset.crDsWarn : null,
    (r.querySelector('.cr-dot').className.match(/cr-dot-(\\w+)/) || [])[1] || null,
    Array.from(r.querySelectorAll('.cr-ds-group-flag, .cr-ds-node-flag')).map(f => f.textContent).join(',')])"""


def test_runtime_the_sidebar_datastore_view_shows_meter_and_state_and_opens_the_storage(open_app):
    app = open_app(storage={'pegaprox-sidebar-view': 'datastores'})
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    _need(page, '[data-cr-ds-tree="c1"] [data-cr-ds-node]', 'the sidebar rows of the preview')
    rows = page.evaluate(SIDE_JS)
    assert rows == [
        ['backupsrv@', '10%', None, 'success', ''], ['ceph-rbd@', _fixed(92.5) + '%', 'error', 'success', ''],
        ['cephfs@', '25%', None, 'warning', ''], ['nfs-old@', None, None, 'error', 'Inactive'],
        ['iscsi-raw@pve1', None, None, 'success', ''], ['local@pve1', '30%', None, 'success', ''],
        ['local-lvm@pve1', '85%', 'warning', 'success', ''], ['old-dir@pve1', None, None, None, 'Disabled'],
        ['bare@pve2', '10%', None, None, ''], ['local@pve2', '79%', 'warning', 'success', ''],
        ['local@pve3', None, None, 'error', 'Offline'], ['local-lvm@pve3', None, None, 'error', 'Offline'],
    ], rows
    assert 'Offline' in page.locator('[data-cr-ds-tree="c1"] .cr-ds-tree-off').inner_text()
    title = page.locator('[data-cr-ds-node="ceph-rbd@"]').get_attribute('title')
    assert title == f"ceph-rbd (rbd). 92.5% - {_bytes(CEPH['used'])} of {_bytes(CEPH['total'])}, {_bytes(CEPH['avail'])} free", title
    # a click opens the Datastore tab on that storage of that node
    page.locator('[data-cr-ds-node="local-lvm@pve1"]').click()
    page.wait_for_function('() => document.querySelector("[data-cr-ds-title]")?.textContent === "local-lvm"', timeout=8000)
    assert app.server.content_reads[-1] == ('local-lvm', 'pve1')
    assert _crumbs(page) == ['All', 'Testi', 'Datastore', 'local-lvm'], _crumbs(page)
    assert page.locator('[data-cr-ds-node="local-lvm@pve1"]').get_attribute('aria-current') == 'true'
    # a storage picked in the tab afterwards stays picked through the next datastore refresh (15 s)
    _pick(page, 's:ceph-rbd@')
    polls = app.server.calls.count(('GET', '/api/clusters/c1/datastores'))
    deadline = time.time() + 20
    while time.time() < deadline and app.server.calls.count(('GET', '/api/clusters/c1/datastores')) == polls:
        page.wait_for_timeout(250)
    assert app.server.calls.count(('GET', '/api/clusters/c1/datastores')) > polls, 'no datastore refresh came'
    page.wait_for_timeout(800)
    assert page.locator('[data-cr-ds-title]').inner_text() == 'ceph-rbd'
    assert app.server.content_reads[-1] == ('ceph-rbd', 'pve1')
    # and by keyboard: down to the next row, Enter
    page.locator('[data-cr-ds-node="local-lvm@pve1"]').focus()
    page.keyboard.press('ArrowDown')
    assert page.evaluate('() => document.activeElement.dataset.crDsNode') == 'old-dir@pve1'
    page.keyboard.press('ArrowDown')
    page.keyboard.press('Enter')
    page.wait_for_function('() => document.querySelector("[data-cr-ds-title]")?.textContent === "bare"', timeout=8000)
    assert app.server.content_reads[-1] == ('bare', 'pve2')
    assert app.errors == []


def test_runtime_a_second_click_on_the_same_sidebar_storage_opens_it_again(open_app):
    app = open_app(storage={'pegaprox-sidebar-view': 'datastores'})
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    _need(page, '[data-cr-ds-tree="c1"] [data-cr-ds-node]', 'the sidebar rows of the preview')
    title = '() => document.querySelector("[data-cr-ds-title]")?.textContent'
    page.locator('[data-cr-ds-node="local-lvm@pve1"]').click()
    page.wait_for_function(f'() => ({title})() === "local-lvm"', timeout=8000)
    for again in range(2):
        _pick(page, 's:ceph-rbd@')
        # the same sidebar row once more, by mouse and then by keyboard: each one is a pick of its own
        if again:
            page.locator('[data-cr-ds-node="local-lvm@pve1"]').focus()
            page.keyboard.press('Enter')
        else:
            page.locator('[data-cr-ds-node="local-lvm@pve1"]').click()
        try:
            page.wait_for_function(f'() => ({title})() === "local-lvm"', timeout=3000)
        except Exception:
            raise AssertionError('a second click on the same sidebar storage opens it again, the tab still shows '
                                 + str(page.evaluate(title))) from None
        assert app.server.content_reads[-1] == ('local-lvm', 'pve1'), app.server.content_reads[-3:]
    assert app.errors == []


# --- the rest of the tab -----------------------------------------------------------------------

def test_runtime_esxi_hosts_sub_tabs_and_the_dialogs_are_the_classic_ones(open_app):
    app = open_app()
    page = _tab(app)
    # the ESXi hosts, last as in classic
    groups = page.locator('[data-cr-ds-group]').evaluate_all('gs => gs.map(g => g.dataset.crDsGroup)')
    assert groups == ['shared', 'n:pve1', 'n:pve2', 'n:pve3', 'esxi'], groups
    page.locator('[data-cr-ds-group="esxi"]').click()
    page.locator('[data-cr-ds-row="e:e1"]').click()
    _need(page, '[data-cr-ds-head="esxi"]', 'an ESXi host shows its VMs')
    page.locator('[data-cr-table="ds-esxi"] tbody tr.cr-row', has_text='legacy-app').wait_for(timeout=5000)
    asked = []
    page.once('dialog', lambda d: (asked.append(d.message), d.dismiss()))
    page.locator('[data-cr-ds-action="disconnect"]').click()
    page.wait_for_timeout(300)
    # classic's own question, and nothing sent when it is declined
    assert asked == ['Disconnect this ESXi host?'] or (len(asked) == 1 and 'ESXi' in asked[0]), asked
    assert not [c for c in app.server.calls if c[0] == 'DELETE']
    page.locator('[data-cr-ds-head="esxi"] button[aria-label="Close"]').click()
    _need(page, '[data-cr-ds-empty]', 'closing the host shows the empty right panel again')
    page.locator('[data-cr-ds-action="connect-esxi"]').click()
    connect = page.locator('div.fixed.inset-0', has_text='Connect ESXi Host')
    connect.wait_for(timeout=4000)
    connect.locator('button', has_text=re.compile(r'^\s*Cancel\s*$')).click()
    # the dialogs of the head are classic's
    _pick(page, 's:local@pve1')
    for action, text in (('upload', 'Upload File'), ('url', 'Download from URL'), ('templates', 'Download Container Templates')):
        page.locator(f'[data-cr-ds-action="{action}"]').click()
        dlg = page.locator('div.fixed.inset-0', has=page.locator('h3', has_text=text))
        dlg.wait_for(timeout=4000)
        if action == 'templates':
            dlg.locator('h3', has_text=text).locator('xpath=../..').locator('button').first.click()
        else:
            dlg.locator('button', has_text=re.compile(r'^\s*Cancel\s*$')).click()
        page.wait_for_timeout(200)
        assert page.locator('div.fixed.inset-0', has=page.locator('h3', has_text=text)).count() == 0, action
    assert ('GET', '/api/clusters/c1/templates/available') in app.server.calls
    page.locator('[data-cr-ds-action="restore"]').click()
    page.locator('[data-br-pick]').wait_for(timeout=5000)
    assert page.locator('[data-br-row]').evaluate_all('rs => rs.map(r => r.dataset.brRow)') == ['100', '555']
    page.locator('[data-testid="batch-restore-modal"] button', has_text=re.compile(r'^\s*Cancel\s*$')).first.click()
    # the other sub tabs are still there and come back to Browse
    for label in ('Storage Balancing', 'ISO Sync', 'Backup SLA', 'Restore tests'):
        page.locator('.corp-tab-strip button', has_text=label).first.click()
        page.wait_for_timeout(300)
        assert page.locator('[data-cr-ds]').count() == 0, label
    page.locator('.corp-tab-strip button', has_text='Browse').first.click()
    _need(page, '[data-cr-ds]', 'Browse comes back')
    assert app.errors == []


def test_runtime_loading_empty_error_and_the_last_click_wins(open_app):
    app = open_app()
    app.server.hold.add('local')
    page = _tab(app)
    page.locator('[data-cr-ds-row="s:local@pve1"]').click()
    page.wait_for_function('() => document.querySelector("[data-cr-ds-title]")?.textContent === "local"', timeout=5000)
    state = page.locator('[data-cr-table="ds-content"] td.cr-state')
    state.wait_for(timeout=4000)
    assert state.inner_text().strip() == 'Loading...'
    # a second click before the first answer: the late answer of the first must not land
    _pick(page, 's:ceph-rbd@')
    assert _col(_table(page), 'name')[0] == 'vm-100-disk-0'
    app.server.release_content('local')
    page.wait_for_timeout(600)
    assert page.locator('[data-cr-ds-title]').inner_text() == 'ceph-rbd'
    assert _col(_table(page), 'name') == ['vm-100-disk-0', 'vm-101-disk-0', 'vm-102-disk-0', 'vm-555-disk-1']
    # an empty storage
    _pick(page, 's:local-lvm@pve1')
    assert state.inner_text().strip() == 'This storage is empty'
    # a refused read says why, and refresh reads again
    app.server.content_status['backupsrv'] = (503, {'error': 'Cluster temporarily unreachable', 'offline': True})
    _pick(page, 's:backupsrv@')
    err = page.locator('[data-cr-table="ds-content"] td.cr-state-error')
    err.wait_for(timeout=4000)
    assert err.get_attribute('role') == 'alert' and err.inner_text().strip() == 'Cluster temporarily unreachable'
    assert page.locator('[data-cr-ds-head] [data-cr-ds-action]').evaluate_all('bs => bs.map(b => b.dataset.crDsAction)') == ['refresh']
    del app.server.content_status['backupsrv']
    page.locator('[data-cr-ds-action="refresh"]').click()
    page.locator('[data-cr-table="ds-content"] tbody tr.cr-row').first.wait_for(timeout=5000)
    assert _col(_table(page), 'verify') == ['ok']
    assert app.errors == []


def test_runtime_every_control_of_the_view_has_a_name(open_app):
    app = open_app()
    page = _tab(app)
    _pick(page, 's:local@pve1')
    page.locator('[data-cr-ds-group="esxi"]').click()
    nameless = page.evaluate('''() => Array.from(document.querySelectorAll('[data-cr-ds] button, [data-cr-ds] input, [data-cr-ds] select, [data-cr-ds] [role="treeitem"], [data-cr-ds] [tabindex="0"]'))
        .filter(e => e.getClientRects().length)
        .filter(e => !((e.getAttribute('aria-label') || '').trim() || (e.innerText || '').trim() || (e.getAttribute('title') || '').trim()
            || (e.labels && e.labels.length && e.labels[0].innerText.trim())))
        .map(e => e.outerHTML.slice(0, 120))''')
    assert nameless == [], nameless
    assert app.errors == []


# --- classic is untouched ----------------------------------------------------------------------

def _base_bundle():
    pytest.importorskip('PIL')
    try:
        return subprocess.run(['git', 'show', f'{BASE_REV}:web/index.html'], cwd=ROOT, capture_output=True,
                              check=True, timeout=60).stdout
    except (OSError, subprocess.SubprocessError):
        pytest.skip(f'the base revision {BASE_REV} is not in this clone')


def _shoot_classic(browser, bundle, layout, theme, view):
    """The classic Datastore tab with backupsrv open (and the datastore view of the sidebar)."""
    storage = {'pegaprox-sidebar-view': 'datastores'} if view == 'sidebar' else None
    app = _GuardApp(browser, _DsServer(bundle=bundle, layout=layout), corp_theme=theme, storage=storage)
    try:
        page = _tab(app)
        if view == 'sidebar':
            page.locator('.corp-tree-child', has_text='local-lvm').first.wait_for(timeout=8000)
        page.locator('div.cursor-pointer', has=page.locator('.font-medium', has_text=re.compile(r'^\s*backupsrv'))).first.click()
        page.get_by_text('Content: backupsrv').first.wait_for(timeout=8000)
        return _settle(app)
    finally:
        app.close()


CLASSIC = {'corporate-dark': ('corporate', '', 'tab'), 'corporate-light': ('corporate', 'light', 'tab'),
           'modern': ('modern', '', 'tab'), 'corporate-sidebar': ('corporate', '', 'sidebar'),
           'corporate-light-sidebar': ('corporate', 'light', 'sidebar')}


@pytest.mark.parametrize('run', list(CLASSIC))
def test_runtime_the_classic_datastore_tab_is_the_pixels_of_the_base(browser, run):
    """The pixel guard has no datastore view; this is the same comparison for this one. The base
    bundle and the bundle under test, the same fake, viewport and clock, 0 differing pixels."""
    base = _base_bundle()
    new = BUNDLE.encode('utf-8') if BUNDLE else open(os.path.join(ROOT, 'web', 'index.html'), 'rb').read()
    layout, theme, view = CLASSIC[run]
    a = _shoot_classic(browser, base, layout, theme, view)
    b = _shoot_classic(browser, new, layout, theme, view)
    found = diff_box(a, b)
    if found is None:
        return
    # a busy machine can land one load an anti-aliased line apart: a real change differs again
    a2 = _shoot_classic(browser, base, layout, theme, view)
    b2 = _shoot_classic(browser, new, layout, theme, view)
    if diff_box(a2, b2) is None:
        return
    where = keep(f'datastore-{run}', base=a, new=b, again=a2)
    pytest.fail(f'{run}: {found[1]} pixels differ from {BASE_REV} in {found[0]}. Shots: {where or "-"}')


def test_runtime_the_datastore_comparison_sees_a_one_rule_change(browser):
    """Counterproof: one extra rule on the classic rows is seen, so a zero above means nothing
    moved, not that the comparison is blind to this view."""
    base = _base_bundle()
    nudged = base.replace(b'</head>', b'<style>body[data-layout="corporate"] .font-medium { letter-spacing: 0.3px; }</style></head>', 1)
    assert nudged != base
    a = _shoot_classic(browser, base, 'corporate', '', 'tab')
    b = _shoot_classic(browser, nudged, 'corporate', '', 'tab')
    found = diff_box(a, b)
    assert found is not None and found[1] > 50, found


def test_runtime_on_a_phone_the_panels_stack_and_nothing_scrolls_sideways(open_app):
    app = open_app(viewport=(400, 860))
    page = app.page
    page.wait_for_timeout(500)
    # the sidebar is a drawer on a phone: open it when the tree lies outside the screen
    box = page.locator('.corp-tree-item', has_text='Testi').first.bounding_box()
    if not box or box['x'] < 0 or box['x'] >= 400:
        page.locator('.cr-header button').first.click()
        page.wait_for_timeout(400)
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.locator('[data-cr-tab="datastore"]').click()
    _need(page, '[data-cr-ds]', 'the Browse tab of the preview')
    _pick(page, 's:local@pve1')
    info = page.evaluate('''() => { const side = document.querySelector('.cr-ds-side').getBoundingClientRect();
        const main = document.querySelector('.cr-ds-main').getBoundingClientRect();
        return { over: document.documentElement.scrollWidth - window.innerWidth, stacked: main.top >= side.bottom - 1,
                 height: document.querySelector('[data-cr-ds]').style.height,
                 tableScrolls: getComputedStyle(document.querySelector('[data-cr-table="ds-content"] .cr-table-scroll')).overflowX }; }''')
    assert info['over'] <= 0, info
    assert info['stacked'] and info['height'] == '' and info['tableScrolls'] == 'auto', info
    assert app.errors == []


# --- stage X (round 4): a key right after a keyboard move ------------------------------------------

def test_runtime_enter_right_after_an_arrow_key_opens_the_row_the_arrow_moved_to(open_app):
    # The focus of a keyboard move came from a passive effect: Enter pressed right after ArrowDown (a
    # separate input task, before that effect ran) still reached the row before. In the storage list
    # Enter on the group then folded it instead of opening its first storage. Four groups in a row,
    # with the keys as fast as the keyboard sends them.
    app = open_app(datastores=_many_nodes())
    page = _tab(app)
    _need(page, '[data-cr-ds-group="n:node000"]', 'a group per node')
    page.locator('[data-cr-ds-group="shared"]').focus()
    page.keyboard.press('End')
    page.wait_for_function('() => document.activeElement?.dataset?.crDsRow === "g:esxi"', timeout=5000)
    for node in ('node199', 'node198', 'node197', 'node196'):
        page.keyboard.press('ArrowUp')
        page.wait_for_function(f'() => document.activeElement?.dataset?.crDsRow === "g:n:{node}"', timeout=5000)
        page.keyboard.press('ArrowRight')
        page.wait_for_function(f'() => document.querySelector(\'[data-cr-ds-group="n:{node}"]\').getAttribute("aria-expanded") === "true"', timeout=5000)
        page.keyboard.press('ArrowDown')
        page.keyboard.press('Enter')
        try:
            page.wait_for_function(f'() => document.querySelector("[data-cr-ds-title]")?.textContent === "local" '
                                   f'&& document.activeElement?.dataset?.crDsRow === "s:local@{node}"', timeout=4000)
        except Exception:
            focus = page.evaluate('() => document.activeElement?.dataset?.crDsRow')
            folded = page.locator('[data-cr-ds-group="n:%s"]' % node).get_attribute('aria-expanded')
            raise AssertionError(f'Enter after ArrowDown opens local@{node}: focus {focus}, group open {folded}') from None
        assert app.server.content_reads[-1] == ('local', node)
        # back to the group, fold it, and on to the one above
        page.keyboard.press('ArrowLeft')
        page.wait_for_function(f'() => document.activeElement?.dataset?.crDsRow === "g:n:{node}"', timeout=5000)
        page.keyboard.press('ArrowLeft')
        page.wait_for_function(f'() => document.querySelector(\'[data-cr-ds-group="n:{node}"]\').getAttribute("aria-expanded") === "false"', timeout=5000)
    assert app.errors == []
