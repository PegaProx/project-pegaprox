"""LVM, LVM-Thin, ZFS, Repositories and Ceph of a node in Corporate Redesigned (Preview), in the browser.

Round 7 draws these Configure sub tabs of a Proxmox VE node as section cards (web/src/cr_nodestore.js),
from the reads the view already makes: the one disks read (disks, disks/lvm, disks/lvmthin,
disks/zfs), the repos read and the four Ceph reads. LVM reads the tree PVE answers (the classic table
reads a list and stays empty), thin pools show data and metadata usage, ZFS pools their health and
space with the shared pool detail one click away. Repositories come in groups with the update
channel said plainly; a switch waits for Save and then goes through the classic handler with the
classic request. Ceph shows its health checks, capacity, placement groups, OSDs, monitors and pools,
and a node without Ceph says so. A read that failed says why; an answer that cannot tell empty from
failed says that too; a value nobody reported is said, never shown as healthy. The round 6 disk list
sits on the same card.

The pure parts are checked through window.PegaProxNodeStore. PEGAPROX_CR_BUNDLE=<file> serves another
bundle (the counterproof against the build before this stage). Skips without Playwright. LW Nov 2026
"""
import json
import os
import re

import pytest

from pegaprox.utils import zpool
from test_corp_redesigned_guard_ui import (DETERMINISTIC, NODE_CEPH_MON, NODE_CEPH_OSD, NODE_CEPH_POOL,
                                           NODE_CEPH_STATUS, NODE_DISKS, NODE_IP, NODE_LVM, NODE_LVMTHIN, NODE_NET,
                                           NODE_REPOS, NODE_SUMMARY, NODE_ZFS, _GuardApp, _GuardServer,
                                           _corp_cluster, _exact)
from test_zfs_pool_health import DEGRADED, _status

LAYOUT = 'corporate-redesigned'
_BUNDLE_FILE = os.environ.get('PEGAPROX_CR_BUNDLE')
BUNDLE = open(_BUNDLE_FILE, encoding='utf-8').read() if _BUNDLE_FILE else None

NODE = '/api/clusters/c1/nodes/pve1'
DISKS, LVM, THIN, ZFS = (NODE + p for p in ('/disks', '/disks/lvm', '/disks/lvmthin', '/disks/zfs'))
POOL = ZFS + '/tank'
REPOS, APT = NODE + '/repos', NODE + '/repos/refresh'
CEPH_STATUS, CEPH_OSD, CEPH_MON, CEPH_POOL = (NODE + '/ceph/' + p for p in ('status', 'osd', 'mon', 'pool'))
LABEL = {'disks': 'Disks', 'lvm': 'LVM', 'lvmthin': 'LVM-Thin', 'zfs': 'ZFS', 'repos': 'Repositories', 'ceph': 'Ceph'}
DETAIL = dict(zpool.pool_detail(_status(DEGRADED)), node='pve1')


class _StoreServer(_GuardServer):
    """The guard fake with the node's storage, repository and Ceph reads and the classic writes;
    each answer settable while the page runs: a (code, body) pair, 'hold' or 'abort'."""

    def __init__(self, routes=None, **kw):
        super().__init__(bundle=BUNDLE, **kw)
        self.routes = {
            ('GET', NODE + '/ip'): (200, NODE_IP), ('GET', NODE + '/summary'): (200, NODE_SUMMARY),
            ('GET', NODE + '/network'): (200, NODE_NET), ('GET', NODE + '/network/changes'): (200, {'changes': ''}),
            ('GET', DISKS): (200, NODE_DISKS), ('GET', LVM): (200, NODE_LVM), ('GET', THIN): (200, NODE_LVMTHIN),
            ('GET', ZFS): (200, NODE_ZFS), ('GET', POOL): (200, DETAIL),
            ('GET', REPOS): (200, NODE_REPOS), ('POST', APT): (200, {'success': True, 'message': 'apt update started'}),
            ('GET', CEPH_STATUS): (200, NODE_CEPH_STATUS), ('GET', CEPH_OSD): (200, NODE_CEPH_OSD),
            ('GET', CEPH_MON): (200, NODE_CEPH_MON), ('GET', CEPH_POOL): (200, NODE_CEPH_POOL),
        }
        for r in NODE_REPOS['repositories']:
            self.routes[('PUT', f"{REPOS}/{r['id']}")] = (200, {'success': True, 'repo': r['id']})
        self.routes.update(routes or {})
        self.sent = []
        self.held = []

    def handle(self, route):
        req = route.request
        path = re.sub(r'^https?://[^/]+', '', req.url).split('?')[0]
        how = self.routes.get((req.method, path))
        if how is None:
            return super().handle(route)
        self.calls.append((req.method, path))
        if req.method != 'GET':
            self.sent.append((req.method, path, req.post_data))
        if how == 'abort':
            return route.abort('connectionrefused')
        if how == 'hold':
            self.held.append(route)
            return None
        code, data = how
        return route.fulfill(status=code, body=json.dumps(data), headers={'Content-Type': 'application/json'})

    def reads(self, path):
        return len([c for c in self.calls if c == ('GET', path)])


@pytest.fixture(scope='module')
def playwright():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        pytest.skip('Playwright is not installed')
    try:
        pw = sync_playwright().start()
    except Exception as e:
        pytest.skip(f'Playwright does not start here: {e}')
    yield pw
    pw.stop()


@pytest.fixture(scope='module')
def browser(playwright):
    try:
        br = playwright.chromium.launch(headless=True, args=DETERMINISTIC)
    except Exception as e:
        pytest.skip(f'no Chromium for Playwright: {e}')
    yield br
    br.close()


@pytest.fixture(scope='module')
def firefox(playwright):
    try:
        br = playwright.firefox.launch(headless=True)
    except Exception as e:
        pytest.skip(f'no Firefox for Playwright: {e}')
    yield br
    br.close()


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(layout=LAYOUT, viewport=(1600, 1000), br=None, **kw):
        app = _GuardApp(br or browser, _StoreServer(layout=layout, **kw), viewport=viewport)
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.close()


def _no_errors(app):
    assert not [e for e in app.errors if 'pageerror' in e], app.errors


def _open_cfg(page, sub, redesigned=True):
    _corp_cluster(page)
    page.locator('.corp-tree-child', has_text='pve1').first.click()
    if redesigned:
        page.locator('[data-cr-tabs="node"] [role="tab"]', has_text='Configure').click()
    else:
        page.locator('.corp-tab-strip button', has_text='Configure').first.click()
    _sub(page, sub)


def _sub(page, sub):
    page.locator('.corp-subnav-item', has_text=_exact(LABEL[sub])).first.click()


def _sec(page, sid):
    sec = page.locator(f'[data-cr-nc-sec="{sid}"]')
    sec.wait_for(timeout=8000)
    return sec


def _kv(scope, k):
    # round 9 B2: a key value grid (dd) or a table cell; LVM, LVM-Thin, ZFS and the repositories are tables now
    return scope.locator(f'[data-cr-nc-k="{k}"] > dd, td[data-cr-nc-k="{k}"], span[data-cr-nc-k="{k}"]').first.inner_text().strip()


def _wait_sent(app, n=1):
    for _ in range(50):
        if len(app.server.sent) >= n:
            return app.server.sent
        app.page.wait_for_timeout(100)
    raise AssertionError(f'expected {n} writes, got {app.server.sent}')


def _classic_reads(open_app, sub, text, paths):
    """How often classic Corporate asks each path on the first visit of a sub tab (the sub nav
    click and the load rule of the view each start the read while nothing is there yet)."""
    app = open_app(layout='corporate')
    _open_cfg(app.page, sub, redesigned=False)
    app.page.locator(CFG).get_by_text(text).first.wait_for(timeout=8000)
    app.page.wait_for_timeout(400)
    return [app.server.reads(p) for p in paths]


def _wait_reads(app, path, n):
    for _ in range(50):
        if app.server.reads(path) >= n:
            return
        app.page.wait_for_timeout(100)
    raise AssertionError(f'expected {n} reads of {path}, got {app.server.reads(path)}')


# the classic configure content beside its sub nav
CFG = '.corp-subnav + div'


# --- the pure parts -----------------------------------------------------------------------------

@pytest.fixture(scope='module')
def store_page(browser):
    app = _GuardApp(browser, _StoreServer(layout=LAYOUT))
    if not app.page.evaluate('() => !!window.PegaProxNodeStore'):
        app.close()
        pytest.fail('the bundle has no node storage helpers (window.PegaProxNodeStore)')
    yield app.page
    app.close()


def _call(page, fn, *args):
    return page.evaluate(f'(a) => window.PegaProxNodeStore.{fn}(...a)', list(args))


def test_rules_lvm_reads_the_tree_pve_answers(store_page):
    thins = _call(store_page, 'thin', NODE_LVMTHIN)
    m = _call(store_page, 'lvm', NODE_LVM, thins)
    assert m['state'] == 'ok' and [v['name'] for v in m['vgs']] == ['pve', 'ceph-5a1f']
    pve = m['vgs'][0]
    assert (pve['size'], pve['free'], pve['used'], pve['lvcount']) == (999070629888, 17184063488, 999070629888 - 17184063488, 4)
    assert pve['pvs'] == [{'name': '/dev/nvme0n1p3', 'size': 999070629888, 'free': 17184063488}]
    assert pve['thin'] == ['data'] and m['vgs'][1]['thin'] == []
    # a tree without groups is a real "none"; the [] the route answers for a failed read is not
    assert _call(store_page, 'lvm', {'leaf': 0, 'children': []}, [])['state'] == 'none'
    assert _call(store_page, 'lvm', [], [])['state'] == 'empty'
    # a group without numbers keeps them missing (no 0 B)
    bare = _call(store_page, 'lvm', {'leaf': 0, 'children': [{'name': 'vg0', 'children': []}]}, [])['vgs'][0]
    assert bare['size'] is None and bare['free'] is None and bare['used'] is None and bare['lvcount'] is None


def test_rules_thin_pools_and_zfs_pools(store_page):
    t = _call(store_page, 'thin', NODE_LVMTHIN + [{'lv': 'data2', 'vg': 'vg2', 'lv_size': '1000'}])
    assert t[0] == {'lv': 'data', 'vg': 'pve', 'size': 852819443712, 'used': 240580365071,
                    'metaSize': 8698986496, 'metaUsed': 85250067}
    assert t[1]['size'] == 1000 and t[1]['used'] is None and t[1]['metaSize'] is None
    z = _call(store_page, 'zfs', NODE_ZFS + [{'name': 'rpool', 'health': 'ONLINE'}, {'name': 'old', 'health': 'FAULTED'},
                                             {'name': 'quiet'}, {'name': 'odd', 'health': 'SPLIT'}])
    assert [(p['name'], p['tone']) for p in z] == [('tank', 'warning'), ('rpool', 'success'), ('old', 'error'),
                                                   ('quiet', 'none'), ('odd', 'neutral')]
    assert (z[0]['frag'], z[0]['dedup'], z[0]['alloc']) == (3, 1.0, 1099511627776)
    assert z[1]['size'] is None and z[1]['frag'] is None


def _repos(**enabled):
    rows = json.loads(json.dumps(NODE_REPOS['repositories']))
    for r in rows:
        if r['id'] in enabled:
            r['enabled'] = enabled[r['id']]
    return rows


def test_rules_repositories_and_the_update_channel(store_page):
    m = _call(store_page, 'repos', NODE_REPOS['repositories'])
    assert m['channel'] == 'free' and m['twice'] == []
    assert [r['repo']['id'] for r in m['groups']['on']] == ['pve-no-subscription', 'ceph-squid']
    assert [r['repo']['id'] for r in m['groups']['off']] == ['pve-enterprise', 'other-4711']
    assert [r['repo']['id'] for r in m['groups']['absent']] == ['ceph-reef', 'ceph-quincy', 'ceph-enterprise']
    nosub = m['groups']['on'][0]
    assert nosub['line'] == 'deb http://download.proxmox.com/debian/pve trixie pve-no-subscription'
    assert nosub['file'] == '/etc/apt/sources.list.d/proxmox.sources' and nosub['index'] == 0
    assert _call(store_page, 'repos', _repos(**{'pve-enterprise': True, 'pve-no-subscription': False}))['channel'] == 'enterprise'
    assert _call(store_page, 'repos', _repos(**{'pve-enterprise': True}))['channel'] == 'both'
    assert _call(store_page, 'repos', _repos(**{'pve-no-subscription': False}))['channel'] == 'none'
    # the enterprise Ceph line matched under its release and under Ceph Enterprise
    rows = _repos()
    for r in rows:
        if r['id'] in ('ceph-reef', 'ceph-enterprise'):
            r.update(exists=True, enabled=True, actual_file='/etc/apt/sources.list.d/ceph.sources', file='/etc/apt/sources.list.d/ceph.sources', index=3)
    assert _call(store_page, 'repos', rows)['twice'] == [['Ceph Reef (18.x)', 'Ceph Enterprise']]


def test_rules_ceph(store_page):
    full = _call(store_page, 'ceph', [NODE_CEPH_STATUS, NODE_CEPH_OSD, NODE_CEPH_MON, NODE_CEPH_POOL])
    assert (full['state'], full['status'], full['tone']) == ('ok', 'HEALTH_WARN', 'warning')
    assert [c['name'] for c in full['checks']] == ['OSD_NEARFULL', 'POOL_NO_REDUNDANCY']
    assert full['osds'] == {'total': 3, 'up': 3, 'in': 2} and full['pgs']['total'] == 97 and full['pgs']['clean'] == 97
    assert full['mons'] == {'total': 3, 'quorum': ['pve1', 'pve2']}
    assert full['bytes']['total'] == 2899102924800
    assert [full[k]['state'] for k in ('osd', 'mon', 'pool')] == ['ok', 'ok', 'ok']
    assert _call(store_page, 'ceph', [{'available': False}, [], [], []])['state'] == 'none'
    assert _call(store_page, 'ceph', [{}, [], [], []])['state'] == 'blank'
    failed = _call(store_page, 'ceph', [{'__crFail': {'status': 502, 'error': 'node down', 'code': ''}}, [], [], []])
    assert failed['state'] == 'failed' and failed['fail']['error'] == 'node down'
    assert _call(store_page, 'ceph', None)['state'] == 'unread'
    # before Quincy the OSD map sits one level deeper; a status without numbers keeps them missing
    old = _call(store_page, 'ceph', [{'health': {'status': 'HEALTH_OK'}, 'osdmap': {'osdmap': {'num_osds': 4, 'num_up_osds': 4, 'num_in_osds': 4}}}, [], [], []])
    assert old['osds'] == {'total': 4, 'up': 4, 'in': 4} and old['tone'] == 'success'
    assert old['pgs']['total'] is None and old['pgs']['clean'] is None and old['mons']['total'] is None
    assert old['osd']['state'] == 'empty'


# --- LVM, LVM-Thin, ZFS --------------------------------------------------------------------------

def test_runtime_lvm_volume_groups_from_the_tree(open_app):
    app = open_app()
    page = app.page
    _open_cfg(page, 'lvm')
    sec = _sec(page, 'lvm')
    vg = sec.locator('[data-cr-nv-vg="pve"]')
    vg.wait_for(timeout=8000)
    assert sec.locator('[data-cr-nv-vg]').count() == 2
    assert _kv(vg, 'size') == '930.5 GB' and _kv(vg, 'free') == '16.0 GB'
    assert '914.5 GB of 930.5 GB allocated (98.3%)' in _kv(vg, 'alloc')
    # a plain share: allocation is not a warning by itself
    assert vg.locator('[data-cr-nv-usage]').get_attribute('data-cr-nv-tone') == 'info'
    assert vg.locator('[data-cr-nv-pv="/dev/nvme0n1p3"]').count() == 1 and _kv(vg, 'thin') == 'data'
    assert _kv(vg, 'lvs') == '4'
    assert _kv(sec.locator('[data-cr-nv-vg="ceph-5a1f"]'), 'thin') == 'none'
    # the disks read for all four sub tabs, as often as classic Corporate makes it
    page.wait_for_timeout(400)
    assert [app.server.reads(p) for p in (DISKS, LVM, THIN, ZFS)] == _classic_reads(open_app, 'lvm', 'VG', (DISKS, LVM, THIN, ZFS))
    _no_errors(app)


def test_runtime_lvm_read_states(open_app):
    app = open_app(routes={('GET', LVM): (502, {'error': 'Node pve1 did not answer'})})
    page = app.page
    _open_cfg(page, 'lvm')
    sec = _sec(page, 'lvm')
    err = sec.locator('[data-cr-nc-state="error"][data-cr-nc-for="lvm"]')
    err.wait_for(timeout=8000)
    assert 'Node pve1 did not answer' in err.inner_text()
    # Retry is the disks read of the view (all four)
    app.server.routes[('GET', LVM)] = (200, [])
    before = [app.server.reads(p) for p in (DISKS, LVM, THIN, ZFS)]
    err.locator('[data-cr-nc-retry="lvm"]').click()
    empty = sec.locator('[data-cr-nc-state="empty"][data-cr-nc-for="lvm"]')
    empty.wait_for(timeout=8000)
    # the route fails a failed read now, so an empty answer carries no doubt
    assert 'This node has no LVM volume groups.' in empty.inner_text() and 'failed' not in empty.inner_text()
    assert [app.server.reads(p) for p in (DISKS, LVM, THIN, ZFS)] == [n + 1 for n in before]
    app.server.routes[('GET', LVM)] = (200, {'leaf': 0, 'children': []})
    app.server.routes[('GET', DISKS)] = 'hold'
    sec.locator('[data-cr-nv-refresh="lvm"]').click()
    page.wait_for_function('() => document.querySelector("[data-cr-nv-refresh=lvm]").disabled', timeout=8000)
    app.server.held.pop().fulfill(status=200, body=json.dumps(NODE_DISKS), headers={'Content-Type': 'application/json'})
    sec.locator('[data-cr-nc-state="empty"]', has_text='has no LVM volume groups').wait_for(timeout=8000)
    _no_errors(app)


def test_runtime_lvm_loading_state(open_app):
    app = open_app(routes={('GET', THIN): 'hold'})
    page = app.page
    _open_cfg(page, 'lvm')
    _sec(page, 'lvm').locator('[data-cr-nc-state="loading"]').wait_for(timeout=8000)
    app.server.held.pop().fulfill(status=200, body=json.dumps(NODE_LVMTHIN), headers={'Content-Type': 'application/json'})
    _sec(page, 'lvm').locator('[data-cr-nv-vg="pve"]').wait_for(timeout=8000)


def test_runtime_thin_pools_with_data_and_metadata(open_app):
    app = open_app(routes={('GET', THIN): (200, NODE_LVMTHIN + [{'lv': 'fast', 'vg': 'nvme', 'lv_size': 100 * 1024 ** 3,
                                                                  'used': 95 * 1024 ** 3}])})
    page = app.page
    _open_cfg(page, 'lvmthin')
    sec = _sec(page, 'lvmthin')
    pool = sec.locator('[data-cr-nv-thin="pve/data"]')
    pool.wait_for(timeout=8000)
    assert '224.1 GB of 794.3 GB used (28.2%)' in _kv(pool, 'data')
    assert '81.3 MB of 8.1 GB used (1.0%)' in _kv(pool, 'meta')
    fast = sec.locator('[data-cr-nv-thin="nvme/fast"]')
    assert fast.locator('[data-cr-nv-usage]').get_attribute('data-cr-nv-tone') == 'error'
    # PVE sent no metadata numbers for this one: said, not drawn as 0
    assert _kv(fast, 'meta') == 'not reported'
    assert fast.locator('[data-cr-nc-k="meta"] [data-cr-nc-missing]').count() == 1
    assert '2 pools' in sec.locator('.cr-nc-head').inner_text()
    _no_errors(app)


def test_runtime_thin_pools_empty_answer(open_app):
    app = open_app(routes={('GET', THIN): (200, [])})
    page = app.page
    _open_cfg(page, 'lvmthin')
    st = _sec(page, 'lvmthin').locator('[data-cr-nc-state="empty"]')
    st.wait_for(timeout=8000)
    # the route fails a failed read now, so an empty answer carries no doubt
    assert 'No thin pools in the answer.' in st.inner_text() and 'failed' not in st.inner_text()


def test_runtime_zfs_pool_cards_and_the_pool_detail(open_app):
    app = open_app(routes={('GET', ZFS): (200, NODE_ZFS + [{'name': 'quiet', 'size': 1000}])})
    page = app.page
    _open_cfg(page, 'zfs')
    sec = _sec(page, 'zfs')
    tank = sec.locator('[data-cr-nv-pool="tank"]')
    tank.wait_for(timeout=8000)
    assert tank.locator('[data-cr-nv-health="warning"]').inner_text().strip() == 'DEGRADED'
    assert _kv(tank, 'frag') == '3%' and _kv(tank, 'dedup') == '1.00x' and _kv(tank, 'free') == '2.6 TB'
    assert '1.0 TB of 3.6 TB allocated (27.6%)' in _kv(tank, 'alloc')
    quiet = sec.locator('[data-cr-nv-pool="quiet"]')
    # no health from the node: neutral and said, never ONLINE
    assert quiet.locator('[data-cr-nv-health="none"]').inner_text().strip() == 'Health not reported'
    assert quiet.locator('.cr-badge-success').count() == 0
    assert _kv(quiet, 'frag') == 'not reported' and _kv(quiet, 'alloc') == 'not reported'
    assert _kv(quiet, 'free') == 'not reported' and _kv(quiet, 'size') == '1000.0 B'
    assert 'Not online: 1' in sec.locator('[data-cr-nv-zfs-bad]').inner_text()
    # the shared pool detail: one read on the click, none on open
    assert app.server.reads(POOL) == 0
    tank.locator('[data-zfs-open="tank"]').click()
    sec.locator('[data-zfs-panel]').wait_for(timeout=8000)
    assert app.server.reads(POOL) == 1
    assert 'cr-nv-open' in tank.get_attribute('class')
    tank.locator('[data-zfs-open="tank"]').click()
    page.wait_for_function('() => !document.querySelector("[data-zfs-panel]")', timeout=8000)
    _no_errors(app)


# --- Repositories --------------------------------------------------------------------------------

def test_runtime_repositories_grouped_with_the_update_channel(open_app):
    app = open_app()
    page = app.page
    _open_cfg(page, 'repos')
    sec = _sec(page, 'repos')
    sec.locator('[data-cr-nr-repo="pve-no-subscription"]').wait_for(timeout=8000)
    groups = {g: sec.locator(f'[data-cr-nc-group="{g}"] [data-cr-nr-repo]').count() for g in ('on', 'off', 'absent')}
    assert groups == {'on': 2, 'off': 2, 'absent': 3}
    chan = sec.locator('[data-cr-nr-channel]')
    assert chan.get_attribute('data-cr-nr-channel') == 'free'
    assert 'takes Proxmox VE updates from the no-subscription repository' in chan.inner_text()
    ent = sec.locator('[data-cr-nr-repo="pve-enterprise"]')
    assert ent.get_attribute('data-cr-nr-state') == 'off' and ent.locator('[data-cr-nr-sub]').count() == 1
    assert _kv(ent, 'line') == 'deb https://enterprise.proxmox.com/debian/pve trixie pve-enterprise'
    assert 'entry 1' in _kv(ent, 'file')
    reef = sec.locator('[data-cr-nr-repo="ceph-reef"]')
    assert reef.get_attribute('data-cr-nr-state') == 'absent' and _kv(reef, 'line') == 'not in the sources of the node'
    assert sec.locator('[data-cr-nr-repo="other-4711"] [data-cr-nr-other]').count() == 1
    assert '2 of 7 enabled' in sec.locator('.cr-nc-head').inner_text()
    _no_errors(app)


def test_runtime_both_channels_and_a_line_under_two_names(open_app):
    rows = _repos(**{'pve-enterprise': True})
    for r in rows:
        if r['id'] in ('ceph-reef', 'ceph-enterprise'):
            r.update(exists=True, enabled=True, actual_file='/etc/apt/sources.list.d/ceph.sources', index=3)
    app = open_app(routes={('GET', REPOS): (200, {'success': True, 'node': 'pve1', 'repositories': rows})})
    page = app.page
    _open_cfg(page, 'repos')
    sec = _sec(page, 'repos')
    chan = sec.locator('[data-cr-nr-channel="both"]')
    chan.wait_for(timeout=8000)
    assert chan.locator('[data-cr-nc-state="warning"]').count() == 1
    twice = sec.locator('[data-cr-nc-for="repos-twice"]')
    assert 'Ceph Reef (18.x), Ceph Enterprise' in twice.inner_text()


def _classic_toggle(app, row):
    page = app.page
    _open_cfg(page, 'repos', redesigned=False)
    rows = page.locator(CFG + ' tbody tr')
    rows.nth(row).locator('button').wait_for(timeout=8000)
    rows.nth(row).locator('button').click()
    return _wait_sent(app)


@pytest.mark.parametrize('rid,row', [('pve-enterprise', 0), ('other-4711', 6)])
def test_runtime_a_switch_waits_for_save_and_sends_the_classic_request(open_app, rid, row):
    app = open_app()
    page = app.page
    _open_cfg(page, 'repos')
    sec = _sec(page, 'repos')
    item = sec.locator(f'[data-cr-nr-repo="{rid}"]')
    item.locator(f'[data-cr-nr-flip="{rid}"]').click()
    # nothing is sent yet: the card is marked, the section is in its edit state with the change
    assert item.get_attribute('data-cr-nr-pending') == '' and 'will be enabled' in item.inner_text()
    assert sec.get_attribute('data-cr-nc-editing') == ''
    bar = sec.locator('[data-cr-nc-editbar="repos"]')
    assert bar.locator('[data-cr-nc-count]').get_attribute('data-cr-nc-count') == '1'
    change = bar.locator(f'[data-cr-nc-change="{rid}"]')
    assert 'Disabled' in change.locator('.cr-nc-ch-from').inner_text() and 'Enabled' in change.locator('.cr-nc-ch-to').inner_text()
    page.wait_for_timeout(300)
    assert app.server.sent == []
    reads = app.server.reads(REPOS)
    bar.locator('[data-cr-nc-save="repos"]').click()
    sent = _wait_sent(app)
    # the classic handler reloads the list after a switch that went through
    _wait_reads(app, REPOS, reads + 1)
    page.wait_for_function('() => !document.querySelector("[data-cr-nc-editbar=repos]")', timeout=8000)
    want = _classic_toggle(open_app(layout='corporate'), row)
    assert sent[0][:2] == ('PUT', f'{REPOS}/{rid}')
    assert sent == want, (sent, want)
    _no_errors(app)


def test_runtime_disabling_an_enabled_repository_says_so_in_the_request(open_app):
    app = open_app()
    page = app.page
    _open_cfg(page, 'repos')
    sec = _sec(page, 'repos')
    item = sec.locator('[data-cr-nr-repo="pve-no-subscription"]')
    assert item.locator('[data-cr-nr-flip]').inner_text().strip() == 'Disable'
    item.locator('[data-cr-nr-flip]').click()
    assert 'will be disabled' in item.inner_text()
    # Undo takes the switch back without a request
    item.locator('[data-cr-nr-flip]').click()
    assert sec.locator('[data-cr-nc-editbar="repos"]').count() == 0
    item.locator('[data-cr-nr-flip]').click()
    sec.locator('[data-cr-nc-save="repos"]').click()
    sent = _wait_sent(app)
    # the button says Disable, so the request does (the classic table reads Enabled, which this
    # route does not send, and asks to enable every row)
    assert sent == [('PUT', f'{REPOS}/pve-no-subscription', json.dumps({'enabled': False}, separators=(',', ':')))]
    _no_errors(app)


def test_runtime_a_refused_switch_stays_with_its_hint(open_app):
    # round 8 (R7-4): an entry that is not set up cannot be switched any more (test_corp_redesigned_decisions_ui),
    # so the refusal comes for one the node lists
    app = open_app(routes={('PUT', f'{REPOS}/pve-enterprise'): (400, {'error': 'Repository not found. Manual setup required.'})})
    page = app.page
    _open_cfg(page, 'repos')
    sec = _sec(page, 'repos')
    sec.locator('[data-cr-nr-flip="pve-enterprise"]').click()
    sec.locator('[data-cr-nr-flip="pve-no-subscription"]').click()
    bar = sec.locator('[data-cr-nc-editbar="repos"]')
    assert bar.locator('[data-cr-nc-count]').get_attribute('data-cr-nc-count') == '2'
    assert bar.locator('[data-cr-nc-save="repos"]').is_enabled()
    bar.locator('[data-cr-nc-save="repos"]').click()
    _wait_sent(app, 2)
    page.get_by_text('Repository not found. Manual setup required.').first.wait_for(timeout=8000)
    page.wait_for_function('() => document.querySelectorAll("[data-cr-nr-pending]").length === 1', timeout=8000)
    assert sec.locator('[data-cr-nr-repo="pve-enterprise"]').get_attribute('data-cr-nr-pending') == ''
    assert bar.locator('[data-cr-nc-count]').get_attribute('data-cr-nc-count') == '1'
    sec.locator('[data-cr-nc-cancel="repos"]').click()
    assert sec.locator('[data-cr-nc-editbar="repos"]').count() == 0


def _repos_with(**enabled):
    body = json.loads(json.dumps(NODE_REPOS))
    for r in body['repositories']:
        if r['id'] in enabled:
            r['enabled'] = enabled[r['id']]
    return body


def test_runtime_a_switch_the_node_already_has_leaves_the_edit_bar(open_app):
    """Two switches, the second answer held: the first went through and the list was read again, so it
    is no longer waiting. It must not turn into "Enabled -> Disabled" in the bar."""
    app = open_app()
    page = app.page
    _open_cfg(page, 'repos')
    sec = _sec(page, 'repos')
    sec.locator('[data-cr-nr-flip="pve-enterprise"]').click()
    sec.locator('[data-cr-nr-flip="ceph-squid"]').click()
    bar = sec.locator('[data-cr-nc-editbar="repos"]')
    assert 'will be disabled' in sec.locator('[data-cr-nr-repo="ceph-squid"]').inner_text()
    app.server.routes[('PUT', f'{REPOS}/ceph-squid')] = 'hold'
    app.server.routes[('GET', REPOS)] = (200, _repos_with(**{'pve-enterprise': True}))
    reads = app.server.reads(REPOS)
    bar.locator('[data-cr-nc-save="repos"]').click()
    _wait_reads(app, REPOS, reads + 1)
    for _ in range(50):
        if app.server.held:
            break
        page.wait_for_timeout(100)
    assert app.server.held, app.server.sent
    ent = sec.locator('[data-cr-nr-repo="pve-enterprise"]')
    page.wait_for_function('() => document.querySelector(\'[data-cr-nr-repo="pve-enterprise"]\').dataset.crNrState === "on"', timeout=8000)
    assert ent.get_attribute('data-cr-nr-pending') is None
    assert 'will be' not in ent.inner_text()
    assert bar.locator('[data-cr-nc-change="pve-enterprise"]').count() == 0
    assert bar.locator('[data-cr-nc-count]').get_attribute('data-cr-nc-count') == '1'
    squid = bar.locator('[data-cr-nc-change="ceph-squid"]')
    assert 'Enabled' in squid.locator('.cr-nc-ch-from').inner_text() and 'Disabled' in squid.locator('.cr-nc-ch-to').inner_text()
    app.server.routes[('GET', REPOS)] = (200, _repos_with(**{'pve-enterprise': True, 'ceph-squid': False}))
    app.server.held.pop().fulfill(status=200, body=json.dumps({'success': True}), headers={'Content-Type': 'application/json'})
    page.wait_for_function('() => !document.querySelector("[data-cr-nc-editbar=repos]")', timeout=8000)
    assert [s[1] for s in app.server.sent] == [f'{REPOS}/pve-enterprise', f'{REPOS}/ceph-squid']
    _no_errors(app)


def test_runtime_a_refused_switch_keeps_what_it_asks_for(open_app):
    """A refused switch stays in the bar with the state it asks for; when a later read shows the node
    has that state already, it leaves the bar instead of flipping into the opposite request."""
    app = open_app(routes={('PUT', f'{REPOS}/pve-enterprise'): (500, {'error': 'pveproxy did not answer'})})
    page = app.page
    _open_cfg(page, 'repos')
    sec = _sec(page, 'repos')
    item = sec.locator('[data-cr-nr-repo="pve-enterprise"]')
    item.locator('[data-cr-nr-flip]').click()
    sec.locator('[data-cr-nc-save="repos"]').click()
    _wait_sent(app)
    page.get_by_text('pveproxy did not answer').first.wait_for(timeout=8000)
    bar = sec.locator('[data-cr-nc-editbar="repos"]')
    page.wait_for_function('() => !document.querySelector("[data-cr-nc-save=repos]").disabled', timeout=8000)
    assert 'will be enabled' in item.inner_text()
    # someone enabled it on the node meanwhile; the refreshed list says so
    app.server.routes[('GET', REPOS)] = (200, _repos_with(**{'pve-enterprise': True}))
    reads = app.server.reads(REPOS)
    sec.locator('[data-cr-nv-refresh="repos"]').click()
    _wait_reads(app, REPOS, reads + 1)
    page.wait_for_function('() => document.querySelector(\'[data-cr-nr-repo="pve-enterprise"]\').dataset.crNrState === "on"', timeout=8000)
    assert bar.count() == 0
    assert item.get_attribute('data-cr-nr-pending') is None and 'will be' not in item.inner_text()
    assert sec.get_attribute('data-cr-nc-editing') is None
    # the switch offers the way back, as for any enabled entry
    assert item.locator('[data-cr-nr-flip]').inner_text().strip() == 'Disable'
    assert len(app.server.sent) == 1


def test_runtime_apt_update_sends_the_classic_request(open_app):
    app = open_app()
    page = app.page
    _open_cfg(page, 'repos')
    sec = _sec(page, 'repos')
    sec.locator('[data-cr-nr-apt]').click()
    sent = _wait_sent(app)
    page.get_by_text('apt update started').first.wait_for(timeout=8000)
    classic = open_app(layout='corporate')
    _open_cfg(classic.page, 'repos', redesigned=False)
    classic.page.locator(CFG + ' button', has_text='apt update').click()
    assert sent == _wait_sent(classic) == [('POST', APT, None)]


def test_runtime_repositories_failed_read(open_app):
    app = open_app(routes={('GET', REPOS): (500, {'error': 'Failed to get repositories'})})
    page = app.page
    _open_cfg(page, 'repos')
    sec = _sec(page, 'repos')
    err = sec.locator('[data-cr-nc-state="error"][data-cr-nc-for="repos"]')
    err.wait_for(timeout=8000)
    assert 'Failed to get repositories' in err.inner_text()
    app.server.routes[('GET', REPOS)] = (200, NODE_REPOS)
    page.wait_for_timeout(300)
    before = app.server.reads(REPOS)
    assert [before] == _classic_reads(open_app, 'repos', 'apt update', (REPOS,))
    err.locator('[data-cr-nc-retry="repos"]').click()
    sec.locator('[data-cr-nr-repo="pve-enterprise"]').wait_for(timeout=8000)
    assert app.server.reads(REPOS) == before + 1


def test_runtime_repositories_loading_state(open_app):
    app = open_app(routes={('GET', REPOS): 'hold'})
    page = app.page
    _open_cfg(page, 'repos')
    _sec(page, 'repos').locator('[data-cr-nc-state="loading"][data-cr-nc-for="repos"]').wait_for(timeout=8000)
    app.server.held.pop().fulfill(status=200, body=json.dumps(NODE_REPOS), headers={'Content-Type': 'application/json'})
    _sec(page, 'repos').locator('[data-cr-nr-repo="pve-enterprise"]').wait_for(timeout=8000)


# --- Ceph ------------------------------------------------------------------------------------------

def test_runtime_ceph_as_cards(open_app):
    app = open_app()
    page = app.page
    _open_cfg(page, 'ceph')
    sec = _sec(page, 'ceph')
    assert sec.get_attribute('data-cr-nx-state') == 'ok'
    assert sec.locator('[data-cr-nx-health="warning"]').inner_text().strip() == 'HEALTH_WARN'
    assert '1 nearfull osd(s)' in sec.locator('[data-cr-nx-check="OSD_NEARFULL"]').inner_text()
    assert '1.2 TB of 2.6 TB used (44.4%)' in _kv(sec, 'used')
    assert _kv(sec, 'pgs') == '97' and _kv(sec, 'clean') == '97' and 'active+clean+scrubbing: 1' in _kv(sec, 'states')
    assert _kv(sec, 'osds') == '3 up, 2 in, of 3' and _kv(sec, 'mons') == '3, 2 in quorum' and _kv(sec, 'pools') == '2'
    osd = _sec(page, 'ceph-osd')
    assert osd.locator('[data-cr-nx-osd]').count() == 3
    assert 'out' in osd.locator('[data-cr-nx-osd="osd.2"]').inner_text()
    assert osd.locator('[data-cr-nx-osd="osd.2"] [data-cr-nc-missing]').count() == 1
    mon = _sec(page, 'ceph-mon')
    assert [mon.locator(f'[data-cr-nx-mon="{n}"] [data-cr-nx-quorum]').get_attribute('data-cr-nx-quorum')
            for n in ('pve1', 'pve2', 'pve3')] == ['yes', 'yes', 'no']
    pool = _sec(page, 'ceph-pool')
    assert pool.locator('[data-cr-nx-pool="rbd-vm"] [data-cr-nx-repl="1"]').get_attribute('class') == 'cr-nc-warn'
    assert '43.0%' in pool.locator('[data-cr-nx-pool="rbd-vm"]').inner_text()
    # the four reads, as often as classic Corporate makes them on the first visit
    paths = (CEPH_STATUS, CEPH_OSD, CEPH_MON, CEPH_POOL)
    assert [app.server.reads(p) for p in paths] == _classic_reads(open_app, 'ceph', 'HEALTH_WARN', paths)
    _no_errors(app)


def test_runtime_ceph_reported_as_not_available_is_not_said_as_no_ceph(open_app):
    """The route answers {available: false} for PVE's 501 and for its 500, and PVE answers 500 for an
    installed Ceph whose cluster does not answer (monitors down). So the card says both, as a warning
    with Retry, never as a calm "this node has no Ceph"."""
    app = open_app(routes={('GET', CEPH_STATUS): (200, {'available': False}), ('GET', CEPH_OSD): (200, []),
                           ('GET', CEPH_MON): (200, []), ('GET', CEPH_POOL): (200, [])})
    page = app.page
    _open_cfg(page, 'ceph')
    sec = _sec(page, 'ceph')
    st = sec.locator('[data-cr-nc-state="warning"][data-cr-nc-for="ceph"]')
    st.wait_for(timeout=8000)
    text = st.inner_text()
    assert 'reported as not available' in text and 'not installed or not set up' in text
    assert 'or its cluster did not answer' in text and 'same answer for both' in text
    assert sec.get_attribute('data-cr-nx-state') == 'none'
    assert page.locator('[data-cr-nc-sec="ceph-osd"]').count() == 0
    assert sec.locator('.cr-badge-success, [data-cr-nc-state="empty"]').count() == 0
    # Retry asks again; once the cluster answers, its status is drawn
    app.server.routes.update({('GET', CEPH_STATUS): (200, NODE_CEPH_STATUS), ('GET', CEPH_OSD): (200, NODE_CEPH_OSD),
                              ('GET', CEPH_MON): (200, NODE_CEPH_MON), ('GET', CEPH_POOL): (200, NODE_CEPH_POOL)})
    reads = app.server.reads(CEPH_STATUS)
    page.wait_for_function('() => !document.querySelector("[data-cr-nc-retry=ceph]").disabled', timeout=8000)
    st.locator('[data-cr-nc-retry="ceph"]').click()
    _wait_reads(app, CEPH_STATUS, reads + 1)
    page.wait_for_function('() => document.querySelector("[data-cr-nc-sec=ceph]").getAttribute("data-cr-nx-state") === "ok"', timeout=8000)
    _no_errors(app)


def test_runtime_ceph_blank_failed_and_missing_lists(open_app):
    app = open_app(routes={('GET', CEPH_STATUS): (200, {})})
    page = app.page
    _open_cfg(page, 'ceph')
    sec = _sec(page, 'ceph')
    blank = sec.locator('[data-cr-nc-state="warning"][data-cr-nc-for="ceph"]')
    blank.wait_for(timeout=8000)
    assert 'came back empty' in blank.inner_text()
    app.server.routes[('GET', CEPH_STATUS)] = (403, {'error': 'Access denied: node.view'})
    blank.locator('[data-cr-nc-retry="ceph"]').click()
    err = sec.locator('[data-cr-nc-state="error"][data-cr-nc-for="ceph"]')
    err.wait_for(timeout=8000)
    assert 'Access denied: node.view' in err.inner_text()
    app.server.routes[('GET', CEPH_STATUS)] = (200, NODE_CEPH_STATUS)
    app.server.routes[('GET', CEPH_OSD)] = (200, [])
    err.locator('[data-cr-nc-retry="ceph"]').click()
    miss = _sec(page, 'ceph-osd').locator('[data-cr-nc-state="warning"]')
    miss.wait_for(timeout=8000)
    assert 'The status counts 3, but the list came back empty' in miss.inner_text()


# --- standby, disks, classic, layout ------------------------------------------------------------

def test_runtime_a_standby_reads_but_does_not_write(open_app):
    app = open_app(role='standby')
    page = app.page
    _open_cfg(page, 'repos')
    sec = _sec(page, 'repos')
    sec.locator('[data-cr-nr-repo="pve-enterprise"]').wait_for(timeout=8000)
    assert sec.locator('[data-cr-nr-flip="pve-enterprise"]').is_disabled()
    assert sec.locator('[data-cr-nr-apt]').is_disabled()
    assert sec.locator('[data-cr-nr-ro]').count() == 1
    page.wait_for_timeout(300)
    before = app.server.reads(REPOS)
    sec.locator('[data-cr-nv-refresh="repos"]').click()
    _wait_reads(app, REPOS, before + 1)
    _sub(page, 'zfs')
    zfs = _sec(page, 'zfs')
    zfs.locator('[data-zfs-open="tank"]').click()
    zfs.locator('[data-zfs-panel]').wait_for(timeout=8000)
    assert app.server.sent == []


def test_runtime_a_standby_reads_the_disk_list_too(open_app):
    """Disks only reads (the list, SMART per disk, the pool detail); on a standby it stays as usable as
    LVM, ZFS, Repositories and Ceph, outside the disabled part of the view."""
    app = open_app(role='standby')
    page = app.page
    _open_cfg(page, 'disks')
    sec = _sec(page, 'disks')
    sec.locator('[data-cr-nd-row="nvme0n1"]').wait_for(timeout=8000)
    assert sec.evaluate('e => !e.closest("fieldset[disabled]")')
    page.wait_for_function('() => !document.querySelector("[data-cr-nd-reload]").disabled', timeout=8000)
    assert sec.locator('[data-cr-nd-readall]').is_enabled()
    reads = app.server.reads(DISKS)
    sec.locator('[data-cr-nd-reload]').click()
    _wait_reads(app, DISKS, reads + 1)
    assert app.server.sent == []
    _no_errors(app)


def test_runtime_the_disk_list_sits_on_the_section_card(open_app):
    app = open_app()
    page = app.page
    _open_cfg(page, 'disks')
    sec = _sec(page, 'disks')
    assert sec.get_attribute('data-cr-nd') == ''
    sec.locator('[data-cr-nd-row="nvme0n1"]').wait_for(timeout=8000)
    assert sec.locator('.cr-nc-head [data-cr-nd-readall]').count() == 1
    assert sec.locator('.cr-nc-head [data-cr-nd-failed]').inner_text() == 'Health failed: 1'
    assert 'SMART is read per disk' in sec.locator('.cr-nc-desc').inner_text()


def test_runtime_classic_corporate_is_unchanged(open_app):
    app = open_app(layout='corporate')
    page = app.page
    _open_cfg(page, 'lvm', redesigned=False)
    page.locator(CFG + ' table thead', has_text='VG').wait_for(timeout=8000)
    for sub, text in (('lvmthin', 'Pool'), ('repos', 'apt update'), ('ceph', 'HEALTH_WARN'), ('zfs', 'DEGRADED')):
        _sub(page, sub)
        page.locator(CFG).get_by_text(text).first.wait_for(timeout=8000)
        assert page.locator('[data-cr-nc-sec]').count() == 0, sub
    page.locator('[data-zfs-open="tank"]').click()
    page.locator('[data-zfs-panel]').wait_for(timeout=8000)
    assert page.locator('.corp-datagrid tr.corp-row-selected').count() == 1


_NO_SIDEWAYS = '() => document.scrollingElement.scrollWidth <= window.innerWidth'


@pytest.mark.parametrize('engine,width', [('chromium', 1600), ('chromium', 1280), ('chromium', 1024),
                                          ('firefox', 1600), ('firefox', 1280), ('firefox', 1024)])
def test_runtime_layout_without_sideways_scroll(open_app, firefox, browser, engine, width):
    long_repo = dict(NODE_REPOS['repositories'][6], id='other-9', name='download.proxmox.com',
                     content=dict(NODE_REPOS['repositories'][6]['content'],
                                  URIs=['http://download.proxmox.com/debian/' + 'very-long-path-segment/' * 8]))
    repos = dict(NODE_REPOS, repositories=NODE_REPOS['repositories'] + [long_repo])
    app = open_app(viewport=(width, 900), br=firefox if engine == 'firefox' else browser,
                   routes={('GET', REPOS): (200, repos)})
    page = app.page
    _open_cfg(page, 'disks')
    _sec(page, 'disks').locator('[data-cr-nd-row="sdd"]').wait_for(timeout=8000)
    assert page.evaluate(_NO_SIDEWAYS), 'disks'
    for sub, probe in (('lvm', '[data-cr-nv-vg="pve"]'), ('lvmthin', '[data-cr-nv-thin="pve/data"]'),
                       ('zfs', '[data-cr-nv-pool="tank"]'), ('ceph', '[data-cr-nx-check="OSD_NEARFULL"]')):
        _sub(page, sub)
        _sec(page, sub).locator(probe).wait_for(timeout=8000)
        assert page.evaluate(_NO_SIDEWAYS), sub
    _sub(page, 'zfs')
    _sec(page, 'zfs').locator('[data-zfs-open="tank"]').click()
    page.locator('[data-zfs-panel]').wait_for(timeout=8000)
    assert page.evaluate(_NO_SIDEWAYS), 'zfs detail'
    _sub(page, 'repos')
    sec = _sec(page, 'repos')
    sec.locator('[data-cr-nr-flip="pve-enterprise"]').click()
    sec.locator('[data-cr-nc-editbar="repos"]').wait_for(timeout=8000)
    assert page.evaluate(_NO_SIDEWAYS), 'repos editing'
    # round 8 (R7-3): a staged switch asks before another sub tab; cancelled here
    sec.locator('[data-cr-nc-cancel="repos"]').click()
    for t in ('ceph-osd', 'ceph-pool'):
        _sub(page, 'ceph')
        box = _sec(page, t).locator('.cr-nn-scroll')
        assert box.evaluate('e => e.scrollWidth <= e.clientWidth + 1') or width < 1100, t
    _no_errors(app)
