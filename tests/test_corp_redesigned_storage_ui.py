"""Storage balancing of Corporate Redesigned (Preview) in the browser.

The Storage Balancing sub tab of a cluster's Datastore tab is drawn by CrStorageBalancing. The
overview of the storage clusters is worked out from the group list and the datastores the tab
already holds: no balancing status is read per group, only for the group picked. A member that
is inactive, missing or reports no usage is said to be and left out of the spread, and a status
that failed, was refused, came back empty or malformed is never "within the threshold". The
switches and the threshold wait for the server and show a refusal instead of the new value. A
recommended move opens a calculated preview (labelled as not checked by Proxmox) with the risks
known from the data; one disk per approval goes to the existing migrate route, a refusal is shown
in the dialog and the task id is kept. No storage cluster: an empty state with the prerequisites
and the classic create dialog. The Browse tab colours storage use 70/85, shows the free space on
its rows and the sidebar rows and says that health is not reported. Classic Corporate and Modern
keep the classic tab (the pixel guard proves it to the pixel).

The fake serves the shapes of pegaprox/api/storage.py (group dicts with auto_balance, check_interval,
last_auto_run; status with storages, imbalance, threshold, recommendations, rate_limited; migrate
{success, message, upid}) and the gates storage.view / storage.config. PEGAPROX_CR_BUNDLE=<file>
serves another bundle (the counterproof against the build before stage G). Skips without
Playwright. LW Oct 2026
"""
import copy
import json
import os
import re
import time
import urllib.parse

import pytest

from test_corp_redesigned_datastore_ui import _DsServer, _st
from test_corp_redesigned_guard_ui import DETERMINISTIC, FIXED, TASKS, _GuardApp, _upid
from test_ha_ui import BASE

LAYOUT = 'corporate-redesigned'
_BUNDLE_FILE = os.environ.get('PEGAPROX_CR_BUNDLE')
BUNDLE = open(_BUNDLE_FILE, encoding='utf-8').read() if _BUNDLE_FILE else None
GIB = 1024 ** 3

CEPH_A = _st('ceph-a', 'rbd', 'images,rootdir', 1000, 820, shared=True, active_on=['pve1', 'pve2'], inactive_on=[])
CEPH_B = _st('ceph-b', 'rbd', 'images,rootdir', 1000, 415, shared=True, active_on=['pve1', 'pve2'], inactive_on=[])
NFS_1 = _st('nfs-1', 'nfs', 'images', 500, 100, shared=True, active_on=['pve1'], inactive_on=['pve2'])
NFS_OLD = dict(_st('nfs-old', 'nfs', 'images', 0, 0, shared=True, active_on=[], inactive_on=['pve1', 'pve2']), active=0)
ISOS = _st('isos', 'cephfs', 'iso,vztmpl', 400, 40, shared=True, active_on=['pve1', 'pve2'], inactive_on=[])
DATASTORES = {'shared': [CEPH_A, CEPH_B, ISOS, NFS_1, NFS_OLD],
              'local': {'pve1': [_st('local', 'dir', 'iso,backup', 100, 30), _st('local-lvm', 'lvmthin', 'images,rootdir', 200, 50)],
                        'pve2': [_st('local', 'dir', 'iso,backup', 100, 30)]},
              'nodes': ['pve1', 'pve2'], 'offline_nodes': []}


def _group(gid, name, storages, threshold=20, enabled=True, auto=False, last=None, **kw):
    g = {'id': gid, 'name': name, 'storages': list(storages), 'threshold': threshold, 'enabled': enabled,
         'auto_balance': auto, 'max_concurrent': 1, 'check_interval': 3600, 'last_auto_run': last,
         'created': '2026-10-01T10:00:00.000000', 'type': 'ceph', 'nodes': []}
    g.update(kw)
    return g


G_CEPH = _group('a1b2c3d4', 'Ceph pools', ['ceph-a', 'ceph-b'], auto=True, last='2026-10-30T08:00:00.000000')
G_MIXED = _group('m1x2y3z4', 'Mixed', ['ceph-b', 'nfs-1', 'nfs-old'], threshold=15)
G_GONE = _group('g9h8i7j6', 'Old pair', ['ceph-a', 'renamed-store'], enabled=False)
GROUPS = [G_CEPH, G_MIXED, G_GONE]


def _sst(name, kind, total_gib, used_gib, node='pve1', shared=True):
    """A member the server could read, as storage.py _shared_member / _member_stats send it."""
    total, used = total_gib * GIB, used_gib * GIB
    return {'storage': name, 'type': kind, 'total': total, 'used': used, 'avail': total - used,
            'usage_percent': round(used / total * 100, 1), 'usable': True, 'state': 'ok', 'node': node, 'shared': shared}


def _sbad(name, kind, state, node=None, shared=True):
    """A member the server could not use: no figures, its state (storage.py:580-645), left out of the spread."""
    return {'storage': name, 'type': kind, 'total': None, 'used': None, 'avail': None, 'usage_percent': None,
            'usable': False, 'state': state, 'node': node, 'shared': shared}


def _rec(vmid, name, status, disk, src, tgt, size, src_pct, tgt_pct):
    ct = disk == 'rootfs' or disk.startswith('mp')
    rec = {'type': 'move_disk', 'vmid': vmid, 'vm_name': name, 'vm_type': 'lxc' if ct else 'qemu', 'vm_status': status,
           'disk': disk, 'source': src, 'target': tgt, 'disk_size': size, 'movable': True,
           'reason': f'Balance: {src} ({src_pct}%) → {tgt} ({tgt_pct}%)'}
    if ct and status == 'running':
        # storage.py CT_RUNNING_REASON: the migrate route answers 409 for it
        rec.update(movable=False, blocked='ct_running',
                   blocked_reason='Proxmox VE moves the volume of a container only while the container is stopped')
    return rec


STATUS_CEPH = {'id': 'a1b2c3d4', 'name': 'Ceph pools', 'enabled': True, 'imbalance': 40.5, 'threshold': 20, 'tolerance': 5,
               'storages': [_sst('ceph-a', 'rbd', 1000, 820), _sst('ceph-b', 'rbd', 1000, 415)], 'read_error': None,
               'recommendations': [_rec(100, 'web01', 'running', 'scsi0', 'ceph-a', 'ceph-b', 32 * GIB, 82.0, 41.5),
                                   _rec(101, 'ct01', 'running', 'rootfs', 'ceph-a', 'ceph-b', 8 * GIB, 82.0, 41.5),
                                   _rec(102, 'db01', 'stopped', 'scsi1', 'ceph-a', 'ceph-b', 0, 82.0, 41.5)],
               '_stats': {'rate_limiter': {}, 'cache': {}, 'cache_hit': False}}
# nfs-old is inactive: the server leaves it out of the spread (41.5 - 20) and never sends a disk to it
STATUS_MIXED = {'id': 'm1x2y3z4', 'name': 'Mixed', 'enabled': True, 'imbalance': 21.5, 'threshold': 15, 'tolerance': 5,
                'storages': [_sst('ceph-b', 'rbd', 1000, 415), _sst('nfs-1', 'nfs', 500, 100), _sbad('nfs-old', 'nfs', 'unavailable')],
                'read_error': None, 'recommendations': [_rec(100, 'web01', 'running', 'scsi1', 'ceph-b', 'nfs-1', 16 * GIB, 41.5, 20.0)],
                '_stats': {}}
STATUS_GONE = {'id': 'g9h8i7j6', 'name': 'Old pair', 'enabled': False, 'imbalance': None, 'threshold': 20, 'tolerance': 5,
               'storages': [_sst('ceph-a', 'rbd', 1000, 820), _sbad('renamed-store', None, 'missing', node='pve1', shared=None)],
               'read_error': None, 'recommendations': [], '_stats': {}}
STATUSES = {'a1b2c3d4': (200, STATUS_CEPH), 'm1x2y3z4': (200, STATUS_MIXED), 'g9h8i7j6': (200, STATUS_GONE)}
UPID = 'UPID:pve1:0000A1B2:00C0FFEE:6721F000:qmmove:100:root@pam:'


class _SbServer(_DsServer):
    """The datastore fake plus the storage cluster routes of pegaprox/api/storage.py with their gates.

    groups: the list; statuses: id -> (code, body), 'abort' or 'hold'; refuse: 'put' | 'delete' |
    'create' -> (code, body); migrate: (code, body) of the move; perms: what a non-admin holds."""

    def __init__(self, groups=None, statuses=None, list_answer=None, refuse=None, migrate=None, perms=None,
                 admin=True, tasks=None, datastores=None, **kw):
        extra = dict(kw.pop('extra', {}) or {})
        if tasks is not None:
            extra[('GET', '/api/clusters/c1/tasks')] = (200, tasks)
        self.sb_perms = set(perms or [])
        super().__init__(datastores=DATASTORES if datastores is None else datastores, admin=admin,
                         permissions=sorted(self.sb_perms), extra=extra, **kw)
        self.groups = copy.deepcopy(GROUPS if groups is None else groups)
        self.statuses = dict(STATUSES if statuses is None else statuses)
        self.list_answer = list_answer          # (code, body) or 'abort' instead of the list
        self.refuse = dict(refuse or {})
        self.migrate = migrate
        self.writes = []                        # (method, path, body)
        self.status_reads = []                  # group ids
        self.held_status = []

    def holds(self, perm):
        return self.admin or perm in self.sb_perms

    def release_status(self, body=None):
        held, self.held_status = self.held_status, []
        for route, gid in held:
            code, data = body or self.statuses.get(gid, (404, {'error': 'Storage cluster not found'}))
            route.fulfill(status=code, body=json.dumps(data), headers={'Content-Type': 'application/json'})

    def handle(self, route):
        req = route.request
        if not req.url.startswith(BASE):
            return super().handle(route)
        path = re.sub(r'^https?://[^/]+', '', req.url).split('?')[0]
        if not (path.startswith('/api/clusters/c1/storage-clusters') or path == '/api/clusters/c1/storage-balancing/migrate'):
            return super().handle(route)
        self.calls.append((req.method, path))
        self.urls.append(req.url)
        try:
            body = json.loads(req.post_data) if req.post_data else None
        except Exception:
            body = None

        def answer(data, status=200):
            return route.fulfill(status=status, body=json.dumps(data), headers={'Content-Type': 'application/json'})

        if req.method != 'GET':
            self.writes.append((req.method, path, body))
            if self.role == 'standby':
                return answer({'error': 'This is a standby instance.', 'code': 'HA_STANDBY'}, 409)
            if not self.holds('storage.config'):
                return answer({'error': 'Permission denied', 'code': 'MISSING_PERMISSION', 'required': 'storage.config'}, 403)
        elif not self.holds('storage.view'):
            return answer({'error': 'Permission denied', 'code': 'MISSING_PERMISSION', 'required': 'storage.view'}, 403)

        if path == '/api/clusters/c1/storage-clusters':
            if req.method == 'GET':
                if self.list_answer == 'abort':
                    return route.abort('connectionrefused')
                if self.list_answer:
                    return answer(self.list_answer[1], self.list_answer[0])
                return answer(self.groups)
            if 'create' in self.refuse:
                return answer(self.refuse['create'][1], self.refuse['create'][0])
            data = body or {}
            if not str(data.get('name', '')).strip():
                return answer({'error': 'Name is required'}, 400)
            if len(data.get('storages') or []) < 2:
                return answer({'error': 'At least 2 storages required'}, 400)
            # storage.py create: the tolerance is kept, bounded to 0..20 (5 when it is not a number)
            try:
                tol = max(0, min(20, int(data.get('tolerance', 5))))
            except (TypeError, ValueError):
                tol = 5
            new = _group('n0n0n0n0', data['name'].strip(), data['storages'], threshold=data.get('threshold', 20),
                         auto=data.get('auto_balance', False), tolerance=tol)
            new.pop('type')
            new.pop('nodes')
            self.groups.append(new)
            return answer(new, 201)
        if path == '/api/clusters/c1/storage-balancing/migrate':
            data = body or {}
            if not all([data.get('vmid'), data.get('disk'), data.get('target')]):
                return answer({'error': 'Missing required parameters: vmid, disk, target'}, 400)
            if self.migrate == 'hold':
                self.held_status.append((route, '__migrate__'))
                return None
            code, data = self.migrate or (200, {'success': True, 'message': 'Disk migration started', 'upid': UPID})
            return answer(data, code)
        m = re.fullmatch(r'/api/clusters/c1/storage-clusters/([^/]+)/status', path)
        if m and req.method == 'GET':
            gid = urllib.parse.unquote(m.group(1))
            self.status_reads.append(gid)
            how = self.statuses.get(gid, (404, {'error': 'Storage cluster not found'}))
            if how == 'abort':
                return route.abort('connectionrefused')
            if how == 'hold':
                self.held_status.append((route, gid))
                return None
            return answer(how[1], how[0])
        m = re.fullmatch(r'/api/clusters/c1/storage-clusters/([^/]+)', path)
        if m:
            gid = urllib.parse.unquote(m.group(1))
            g = next((x for x in self.groups if x['id'] == gid), None)
            if g is None:
                return answer({'error': 'Storage cluster not found'}, 404)
            if req.method == 'PUT':
                if 'put' in self.refuse:
                    return answer(self.refuse['put'][1], self.refuse['put'][0])
                for k in ('name', 'storages', 'threshold', 'enabled', 'auto_balance', 'max_concurrent', 'check_interval'):
                    if k in (body or {}):
                        g[k] = body[k]
                if 'tolerance' in (body or {}):
                    try:
                        g['tolerance'] = max(0, min(20, int(body['tolerance'])))
                    except (TypeError, ValueError):
                        g['tolerance'] = 5
                return answer(g)
            if req.method == 'DELETE':
                if 'delete' in self.refuse:
                    return answer(self.refuse['delete'][1], self.refuse['delete'][0])
                self.groups = [x for x in self.groups if x['id'] != gid]
                return answer({'success': True})
        return answer({'error': 'not mocked'}, 404)


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

    def _open(layout=LAYOUT, theme='', storage=None, viewport=(1600, 1000), br=None, **kw):
        app = _GuardApp(br or browser, _SbServer(layout=layout, bundle=BUNDLE, **kw), corp_theme=theme,
                        storage=storage, viewport=viewport)
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.close()


# --- helpers -----------------------------------------------------------------------------------

def _need(page, selector, what, timeout=8000):
    try:
        page.locator(selector).first.wait_for(timeout=timeout)
    except Exception:
        raise AssertionError(f'{what} (no {selector})') from None


def _balancing(app, ready='[data-cr-sb-list="ok"]'):
    """Testi, its Datastore tab, the Storage Balancing sub tab."""
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.locator('[data-cr-tab="datastore"]').click()
    page.locator('.corp-tab-strip button', has_text='Storage Balancing').first.click()
    _need(page, '[data-cr-sb]', 'the balancing tab of the preview is CrStorageBalancing')
    if ready:
        _need(page, ready, f'the group list read ends in {ready}')
    return page


def _open_group(page, name, settle=True):
    page.locator('[data-cr-table="sb-groups"] tbody tr.cr-row', has_text=name).first.click()
    _need(page, '[data-cr-sb-detail]', 'a picked group shows its detail')
    if settle:
        page.wait_for_function('() => { const v = document.querySelector("[data-cr-sb-verdict]"); return v && v.dataset.crSbVerdict !== "loading"; }',
                               timeout=8000)


def _verdict(page):
    return page.locator('[data-cr-sb-verdict]').get_attribute('data-cr-sb-verdict')


def _cells(page, table):
    return page.evaluate('''(id) => {
        const t = document.querySelector(`[data-cr-table="${id}"]`);
        if (!t) return null;
        const head = Array.from(t.querySelectorAll('thead th')).map(th => th.dataset.crCol);
        return Array.from(t.querySelectorAll('tbody tr.cr-row')).map(tr => {
            const o = {};
            Array.from(tr.children).forEach((td, i) => { o[head[i]] = td.innerText.replace(/\\s+/g, ' ').trim(); });
            return o;
        });
    }''', table)


def _errors(app):
    """Page errors, without the console line DatastoreTab's authFetch writes for a request that got no answer."""
    return [e for e in app.errors if 'fetch failed: TypeError: Failed to fetch' not in e]


def _status_calls(app):
    return [c for c in app.server.calls if c[1].endswith('/status') and '/storage-clusters/' in c[1]]


# --- no storage cluster -----------------------------------------------------------------------

def test_runtime_no_storage_cluster_is_an_empty_state_with_prerequisites_and_the_create_flow(open_app):
    app = open_app(groups=[])
    page = _balancing(app)
    empty = page.locator('[data-cr-sb-empty]')
    empty.wait_for(timeout=5000)
    text = empty.inner_text()
    assert 'No storage clusters configured' in text and 'groups two or more shared storages' in text, text
    # the prerequisites from what the page holds: 5 shared storages, 4 of them available, storage.config
    pres = empty.locator('[data-cr-sb-pre]').evaluate_all('ls => ls.map(l => [l.dataset.crSbPre, l.innerText.trim()])')
    assert pres == [['ok', 'At least 2 shared storages: 5 in this cluster, 4 of them available'],
                    ['ok', 'The storage.config permission']], pres
    assert 'tenant owns this cluster' in text
    # no table, no detail, no invented content, and no status read
    assert page.locator('[data-cr-table="sb-groups"]').count() == 0 and page.locator('[data-cr-sb-detail]').count() == 0
    assert _status_calls(app) == []
    # the primary action opens the classic create dialog, with the tolerance the server keeps (since 3d10eb84)
    page.locator('[data-cr-sb-empty] [data-cr-sb-create]').click()
    dlg = page.locator('div.fixed.inset-0', has=page.locator('h3', has_text='Create Storage Cluster'))
    dlg.wait_for(timeout=4000)
    assert dlg.get_by_text('Migration Tolerance').count() == 1 and dlg.locator('input[type="range"]').count() == 2
    dlg.locator('input[type="text"]').fill('Fast pools')
    for name in ('ceph-a', 'ceph-b'):
        dlg.locator('label', has_text=re.compile(rf'^\s*{name}\s*$')).locator('input').check()
    dlg.locator('button', has_text=re.compile(r'^\s*Create\s*$')).click()
    page.locator('[data-cr-table="sb-groups"] tbody tr.cr-row', has_text='Fast pools').wait_for(timeout=5000)
    post = [w for w in app.server.writes if w[0] == 'POST' and w[1].endswith('/storage-clusters')]
    assert len(post) == 1 and post[0][2]['name'] == 'Fast pools' and post[0][2]['storages'] == ['ceph-a', 'ceph-b'], post
    assert post[0][2]['threshold'] == 20
    assert page.locator('[data-cr-sb-empty]').count() == 0
    assert _errors(app) == []


@pytest.mark.parametrize('case', ['one_shared', 'no_config', 'standby'])
def test_runtime_a_missing_prerequisite_disables_create_and_says_why(open_app, case):
    kw = {'groups': []}
    if case == 'one_shared':
        kw['datastores'] = dict(DATASTORES, shared=[CEPH_A])
    elif case == 'no_config':
        kw.update(admin=False, perms=['storage.view'])
    else:
        kw['role'] = 'standby'
    app = open_app(**kw)
    page = _balancing(app)
    btn = page.locator('[data-cr-sb-empty] [data-cr-sb-create]')
    btn.wait_for(timeout=5000)
    assert btn.is_disabled()
    why = page.locator('[data-cr-sb-create-why]').inner_text()
    pres = page.locator('[data-cr-sb-pre]').evaluate_all('ls => ls.map(l => l.dataset.crSbPre)')
    if case == 'one_shared':
        assert why == 'Needs at least 2 shared storages in this cluster' and pres == ['no', 'ok'], (why, pres)
    elif case == 'no_config':
        assert why == 'Needs the storage.config permission' and pres == ['ok', 'no'], (why, pres)
    else:
        assert why == 'Read-only standby' and pres == ['ok', 'no'], (why, pres)
        assert page.locator('[data-cr-sb-note="standby"]').count() == 1
    assert not [w for w in app.server.writes]
    assert _errors(app) == []


@pytest.mark.parametrize('case', ['forbidden', 'error', 'offline', 'malformed'])
def test_runtime_a_failed_list_read_is_not_an_empty_list(open_app, case):
    answer = {'forbidden': (403, {'error': 'Permission denied', 'code': 'MISSING_PERMISSION'}),
              'error': (500, {'error': 'Database is locked'}), 'offline': 'abort',
              'malformed': (200, {'clusters': []})}[case]
    app = open_app(list_answer=answer)
    page = _balancing(app, ready=None)
    _need(page, f'[data-cr-sb-list="{case}"]', f'the list read ends as {case}')
    note = page.locator(f'[data-cr-sb-note="list-{case}"]')
    text = note.inner_text()
    assert ('You may not read the storage clusters' if case == 'forbidden' else 'could not be read') in text, text
    if case == 'error':
        assert 'Database is locked - HTTP 500' in text, text
    assert page.locator('[data-cr-sb-empty]').count() == 0, 'a failed read never says "no storage clusters"'
    assert page.locator('[data-cr-table="sb-groups"]').count() == 0
    # retry reads again and shows what the server has now
    app.server.list_answer = None
    note.locator('button', has_text='Retry').click()
    _need(page, '[data-cr-sb-list="ok"]', 'the retry reads the list again')
    page.locator('[data-cr-table="sb-groups"] tbody tr.cr-row').first.wait_for(timeout=5000)
    assert _errors(app) == []


# --- one, several, different backends, offline and missing members -------------------------------

def test_runtime_the_overview_is_worked_out_from_the_datastores_without_a_status_read(open_app):
    app = open_app()
    page = _balancing(app)
    page.locator('[data-cr-table="sb-groups"] tbody tr.cr-row').nth(2).wait_for(timeout=5000)
    rows = {r['name'].split(' Off')[0]: r for r in _cells(page, 'sb-groups')}
    assert set(rows) == {'Ceph pools', 'Mixed', 'Old pair'}, rows
    ceph, mixed, old = rows['Ceph pools'], rows['Mixed'], rows['Old pair']
    # sums of the readable members, from /datastores: 1235 GiB of 2000 used, 765 free, spread 82 - 41.5
    assert ceph['use'] == '62%' and ceph['cap'] == '1.2 TB / 2.0 TB' and ceph['free'] == '765.0 GB', ceph
    assert ceph['spread'] == '40.5 / 20 pts' and ceph['auto'] == 'Armed' and ceph['state'] == 'All 2 readable', ceph
    assert ceph['last'].startswith('2026-10-30 08:00'), ceph
    # the inactive nfs-old is left out of the sums and of the spread (41.5 - 20), and named
    assert mixed['use'] == '34%' and mixed['cap'] == '515.0 GB / 1.5 TB' and mixed['spread'] == '21.5 / 15 pts', mixed
    assert mixed['state'] == '1 of 3 not readable' and mixed['auto'] == 'Off', mixed
    assert page.locator('[data-cr-sb-mixed]').count() == 1, 'the mixed group (rbd, nfs) carries a warning'
    # a member the datastore list does not know is "not found", and one readable member has no spread
    assert old['state'] == '1 not found' and old['spread'] == '-' and old['auto'] == 'Off', old
    assert page.locator('[data-cr-sb-off]').count() == 1
    # the spread above the threshold is marked, and mounted on is from active_on / inactive_on
    over = page.locator('[data-cr-sb-spread]').evaluate_all('xs => xs.map(x => x.dataset.crSbOver || null)')
    assert over == ['1', '1', None], over
    assert page.locator('[data-cr-sb-gnodes]').evaluate_all('xs => xs.map(x => x.textContent)') == \
        ['2 nodes', '2 nodes (1 partial)', '2 nodes'], 'nfs-1 is not mounted on pve2 (nfs-old is not counted, it is down)'
    # opening the tab asked the server for no status at all
    assert _status_calls(app) == []
    assert _errors(app) == []


def test_runtime_one_group_reads_its_status_once_on_click_and_draws_the_distribution(open_app):
    app = open_app()
    page = _balancing(app)
    _open_group(page, 'Ceph pools')
    assert app.server.status_reads == ['a1b2c3d4']
    assert _verdict(page) == 'above'
    assert page.locator('[data-cr-sb-verdict]').inner_text().strip() == 'Above the threshold: moves are recommended'
    members = page.locator('[data-cr-sb-member]').evaluate_all('''ms => ms.map(m => [m.dataset.crSbMember, m.dataset.crSbUsable,
        m.dataset.crSbTone, (m.querySelector('[data-cr-sb-pct]') || {}).textContent, (m.querySelector('[data-cr-sb-dev]') || {}).textContent])''')
    # 82 % is a warning of the storage pair (70 to 85), 41.5 % normal; deviation from the mean 61.75
    assert members == [['ceph-a', '1', 'warning', '82.0%', '+20.3'], ['ceph-b', '1', 'success', '41.5%', '-20.3']], members
    assert page.locator('[data-cr-sb-member="ceph-a"] [data-cr-sb-used]').inner_text() == '820.0 GB of 1000.0 GB, 180.0 GB free'
    assert page.locator('[data-cr-sb-member="ceph-a"] [data-cr-sb-node]').evaluate_all('cs => cs.map(c => c.textContent)') == ['pve1', 'pve2']
    # the server's figures, the threshold and when auto-balance acts (threshold + the fixed margin 5)
    kv = page.locator('[data-cr-sb-kv]').inner_text()
    assert '40.5 pts' in kv and '20.0 pts' in kv and '25.0 pts' in kv and 'server margin of 5' in kv, kv
    assert page.locator('[data-cr-sb-imbalance]').get_attribute('data-cr-sb-imbalance') == '40.5'
    stats = page.locator('[data-cr-stat^="sb-"]').evaluate_all('ss => ss.map(s => [s.dataset.crStat, s.querySelector(".cr-stat-value").textContent])')
    assert stats == [['sb-total', '2.0 TB'], ['sb-used', '1.2 TB'], ['sb-free', '765.0 GB'], ['sb-use', '61.8%'], ['sb-readable', '2 / 2']], stats
    assert 'not reported here' in page.locator('[data-cr-sb-basis]').inner_text()
    # auto-balance is armed: said with what it does, and the last check in server time
    assert 'without asking, and deletes the source copy' in page.locator('[data-cr-sb-note="armed"]').inner_text()
    assert '2026-10-30 08:00' in page.locator('[data-cr-sb-last]').inner_text()
    assert 'Checks every 1 h, one disk per check' in page.locator('[data-cr-sb-cadence]').inner_text()
    # the recommendations with the guest's node from the inventory and a calculated impact
    recs = _cells(page, 'sb-recs')
    assert [r['guest'] for r in recs] == ['web01 VM 100', 'ct01 CT 101', 'db01 VM 102'], recs
    assert [r['node'] for r in recs] == ['pve1', 'pve1', 'pve2'], recs
    assert recs[0]['impact'] == '82%→79% / 42%→45%' and recs[2]['impact'] == 'unknown' and recs[2]['size'] == 'unknown', recs
    # no second read without a click on refresh
    page.wait_for_timeout(600)
    assert app.server.status_reads == ['a1b2c3d4']
    page.locator('[data-cr-sb-refresh]').click()
    page.wait_for_function('() => document.querySelector("[data-cr-sb-verdict]").dataset.crSbVerdict === "above"')
    assert app.server.status_reads == ['a1b2c3d4', 'a1b2c3d4']
    assert _errors(app) == []


def test_runtime_an_offline_member_is_left_out_and_never_the_quiet_target(open_app):
    app = open_app()
    page = _balancing(app)
    _open_group(page, 'Mixed')
    m = page.locator('[data-cr-sb-member]').evaluate_all('ms => ms.map(m => [m.dataset.crSbMember, m.dataset.crSbUsable, (m.querySelector("[data-cr-sb-why]") || {}).dataset?.crSbWhy || null])')
    # LW Nov 2026 - the server leaves an unusable member out and says why (state unavailable): the page
    # takes its word, so the member is left out of the spread, without a 0 % or a "counted" note
    assert m == [['ceph-b', '1', None], ['nfs-1', '1', 'partial'], ['nfs-old', '0', 'unavailable']], m
    off = page.locator('[data-cr-sb-member="nfs-old"]')
    assert off.locator('[data-cr-sb-pct]').count() == 0 and 'Left out of the spread' in off.inner_text()
    assert 'Not available on any node that is online' in off.inner_text()
    assert page.locator('[data-cr-sb-note="counted"]').count() == 0 and '%' not in off.inner_text()
    # the server's spread and the page's agree (41.5 - 20), so no second figure is drawn
    assert page.locator('[data-cr-sb-imbalance]').get_attribute('data-cr-sb-imbalance') == '21.5'
    assert page.locator('[data-cr-sb-own]').count() == 0
    assert 'mixes storage types (nfs, rbd)' in page.locator('[data-cr-sb-note="mixed"]').inner_text()
    # the recommendation goes to nfs-1, never to the member that is down
    assert page.locator('[data-cr-sb-preview]').evaluate_all('bs => bs.map(b => b.dataset.crSbPreview)') == ['100|scsi1|nfs-1']
    page.locator('[data-cr-sb-preview]').first.click()
    dlg = page.locator('[data-cr-sb-dialog]')
    dlg.wait_for(timeout=4000)
    risks = dlg.locator('[data-cr-sb-risk]').evaluate_all('rs => rs.map(r => [r.dataset.crSbRisk, r.dataset.crSbLevel])')
    assert ['crSbRiskTargetDown', 'block'] not in risks and ['crSbRiskTypes', 'warn'] in risks, risks
    dlg.locator('[data-cr-sb-cancel]').click()
    assert not [w for w in app.server.writes if w[0] == 'POST']
    assert _errors(app) == []


def test_runtime_a_member_that_is_gone_and_a_group_that_is_off(open_app):
    app = open_app()
    page = _balancing(app)
    _open_group(page, 'Old pair')
    # the server's own word for a member it does not find (storage.py state missing, read on pve1)
    assert page.locator('[data-cr-sb-member="renamed-store"] [data-cr-sb-why="missing"]').inner_text() == 'Not listed by pve1'
    # one member read by the server: its spread of 0 says nothing, so nothing is "within"
    assert _verdict(page) == 'unknown'
    assert 'read 1 of the members' in page.locator('[data-cr-sb-note="few"]').inner_text()
    assert page.get_by_text('Within the threshold').count() == 0
    assert 'switched off' in page.locator('[data-cr-sb-note="off"]').inner_text()
    assert page.locator('[data-cr-sb-enabled]').get_attribute('data-cr-sb-enabled') == '0'
    assert page.locator('[data-cr-sb-recs]').count() == 0
    assert _errors(app) == []


@pytest.mark.parametrize('case', ['error', 'limited', 'forbidden', 'gone', 'offline', 'malformed', 'empty', 'ratelimited'])
def test_runtime_a_status_that_failed_or_says_nothing_is_never_balanced(open_app, case):
    within = dict(STATUS_CEPH, imbalance=3.0, recommendations=[])
    statuses = dict(STATUSES)
    statuses['a1b2c3d4'] = {
        'error': (500, {'error': 'Failed to get storage cluster status'}),
        'limited': (429, {'error': 'API rate limit exceeded, please try again'}),
        'forbidden': (403, {'error': 'Permission denied', 'code': 'MISSING_PERMISSION'}),
        'gone': (404, {'error': 'Storage cluster not found'}),
        'offline': 'abort',
        'malformed': (200, []),
        'empty': (200, dict(within, storages=[], imbalance=0)),
        'ratelimited': (200, dict(STATUS_CEPH, recommendations=[], rate_limited=True)),
    }[case]
    app = open_app(statuses=statuses)
    page = _balancing(app)
    _open_group(page, 'Ceph pools')
    v = _verdict(page)
    if case == 'empty':
        assert v == 'unknown' and 'read 0 of the members' in page.locator('[data-cr-sb-note="few"]').inner_text()
    elif case == 'ratelimited':
        assert v == 'above' and 'request limit' in page.locator('[data-cr-sb-note="ratelimited"]').inner_text()
        assert page.locator('[data-cr-sb-norecs]').count() == 0
    else:
        assert v == 'unread', v
        state = {'gone': 'notfound'}.get(case, case)
        note = page.locator(f'[data-cr-sb-note="status-{state}"]')
        text = note.inner_text()
        expect = {'error': 'Failed to get storage cluster status - HTTP 500', 'limited': 'Too many requests',
                  'forbidden': 'You may not read the balancing status', 'gone': 'does not know this storage cluster',
                  'offline': 'PegaProx could not be reached', 'malformed': 'not a balancing status'}[case]
        assert expect in text, text
    assert page.get_by_text('Within the threshold').count() == 0 and page.get_by_text('Balanced', exact=True).count() == 0
    if case != 'ratelimited':
        assert page.locator('[data-cr-sb-recs]').count() == 0
    # the members stay on screen with the figures of the datastore list, labelled as such
    assert page.locator('[data-cr-sb-member]').count() == 2
    if case not in ('empty', 'ratelimited'):
        assert page.locator('[data-cr-sb-basis]').inner_text().startswith('Figures from the datastore list')
    assert _errors(app) == []


def test_runtime_a_late_status_of_the_group_before_does_not_land(open_app):
    statuses = dict(STATUSES)
    statuses['a1b2c3d4'] = 'hold'
    app = open_app(statuses=statuses)
    page = _balancing(app)
    _open_group(page, 'Ceph pools', settle=False)
    assert _verdict(page) == 'loading' and 'Reading the balancing status' in page.locator('[data-cr-sb-verdict]').inner_text()
    _open_group(page, 'Mixed')
    app.server.release_status((200, STATUS_CEPH))
    page.wait_for_timeout(500)
    assert page.locator('.cr-sb-dtitle').inner_text() == 'Mixed'
    assert page.locator('[data-cr-sb-imbalance]').get_attribute('data-cr-sb-imbalance') == '21.5'
    assert _errors(app) == []


def test_runtime_high_use_and_missing_capacity_figures(open_app):
    full = _st('ceph-full', 'rbd', 'images', 100, 86, shared=True, active_on=['pve1', 'pve2'], inactive_on=[])
    edge = _st('ceph-edge', 'rbd', 'images', 100, 70, shared=True, active_on=['pve1', 'pve2'], inactive_on=[])
    raw = _st('iscsi-lun', 'iscsi', 'images', 0, 0, shared=True, active_on=['pve1', 'pve2'], inactive_on=[])
    ds = dict(DATASTORES, shared=[full, edge, raw])
    g = _group('h1', 'Hot', ['ceph-full', 'ceph-edge', 'iscsi-lun'])
    # the server reads the LUN without a size as no_size and leaves it out (86 - 70)
    st = {'id': 'h1', 'name': 'Hot', 'enabled': True, 'imbalance': 16.0, 'threshold': 20, 'recommendations': [], 'read_error': None,
          'storages': [_sst('ceph-full', 'rbd', 100, 86), _sst('ceph-edge', 'rbd', 100, 70), _sbad('iscsi-lun', 'iscsi', 'no_size', node='pve1')]}
    app = open_app(datastores=ds, groups=[g], statuses={'h1': (200, st)})
    page = _balancing(app)
    row = _cells(page, 'sb-groups')[0]
    assert row['use'] == '78%' and row['state'] == '1 of 3 not readable' and row['spread'] == '16.0 / 20 pts', row
    _open_group(page, 'Hot')
    tones = page.locator('[data-cr-sb-member]').evaluate_all('ms => ms.map(m => [m.dataset.crSbMember, m.dataset.crSbTone, m.dataset.crSbUsable])')
    # above 85 critical, 70 is already a warning; no usage reported is no figure and no 0 %
    assert tones == [['ceph-full', 'error', '1'], ['ceph-edge', 'warning', '1'], ['iscsi-lun', 'neutral', '0']], tones
    assert page.locator('[data-cr-sb-member="iscsi-lun"] [data-cr-sb-why="no_size"]').inner_text() == 'Reports no size'
    assert '0.0 B' not in page.locator('[data-cr-sb-member="iscsi-lun"]').inner_text()
    assert _errors(app) == []


# --- the preview and the move ----------------------------------------------------------------------

def test_runtime_the_preview_is_a_calculation_and_cancel_sends_nothing(open_app):
    app = open_app()
    page = _balancing(app)
    _open_group(page, 'Ceph pools')
    btn = page.locator('[data-cr-sb-preview="100|scsi0|ceph-b"]')
    btn.click()
    dlg = page.locator('[data-cr-sb-dialog]')
    dlg.wait_for(timeout=4000)
    assert dlg.get_attribute('role') == 'dialog' and dlg.get_attribute('aria-modal') == 'true'
    assert dlg.locator('h2').inner_text() == 'Move scsi0 of web01'
    assert dlg.locator('[data-cr-sb-calc]').inner_text() == 'Calculated preview, not checked by Proxmox'
    assert 'on pve1' in dlg.locator('[data-cr-sb-fact="guest"]').inner_text()
    assert dlg.locator('[data-cr-sb-fact="size"]').inner_text().startswith('32.0 GB')
    plan = dlg.locator('[data-cr-sb-plan]').evaluate_all('''rs => rs.map(r => [r.dataset.crSbPlan,
        Array.from(r.querySelectorAll('td')).slice(-2).map(td => td.innerText.trim())])''')
    # (820 - 32) / 1000 and (415 + 32) / 1000; the spread of the readable members after the move
    assert plan == [['src', ['82.0%', '78.8%']], ['tgt', ['41.5%', '44.7%']], ['spread', ['40.5 pts', '34.1 pts']]], plan
    assert [r for r in dlg.locator('[data-cr-sb-risk]').evaluate_all('rs => rs.map(r => r.dataset.crSbRisk)')] == ['crSbRiskRunning']
    assert 'free space on the target' in dlg.locator('[data-cr-sb-checks]').inner_text()
    assert dlg.get_by_text('the source is deleted').count() == 1
    # the focus is in the dialog, Tab stays in it, Escape closes it and hands the focus back
    assert page.evaluate('() => !!document.activeElement.closest("[data-cr-sb-dialog]")')
    for _ in range(6):
        page.keyboard.press('Tab')
        assert page.evaluate('() => !!document.activeElement.closest("[data-cr-sb-dialog]")')
    page.keyboard.press('Escape')
    assert page.locator('[data-cr-sb-dialog]').count() == 0
    # the focus goes back in an effect, a moment after the dialog left
    page.wait_for_function('() => document.activeElement && document.activeElement.dataset.crSbPreview === "100|scsi0|ceph-b"', timeout=3000)
    # Cancel too; nothing was sent either way
    btn.click()
    dlg.wait_for(timeout=4000)
    dlg.locator('[data-cr-sb-cancel]').click()
    assert not [w for w in app.server.writes if w[0] == 'POST']
    assert _errors(app) == []


def test_runtime_one_disk_per_approval_keeps_the_task_id_and_opens_the_task_center(open_app):
    app = open_app()
    page = _balancing(app)
    _open_group(page, 'Ceph pools')
    page.locator('[data-cr-sb-preview="100|scsi0|ceph-b"]').click()
    page.locator('[data-cr-sb-confirm]').click()
    page.locator('[data-cr-sb-dialog]').wait_for(state='detached', timeout=5000)
    posts = [w for w in app.server.writes if w[0] == 'POST']
    assert posts == [('POST', '/api/clusters/c1/storage-balancing/migrate', {'vmid': 100, 'disk': 'scsi0', 'target': 'ceph-b'})], posts
    msg = page.locator('[data-cr-sb-note="msg-success"]')
    assert 'Moving scsi0 to ceph-b started' in msg.inner_text()
    assert page.locator('[data-cr-sb-upid]').inner_text() == UPID
    assert 'from before this move' in msg.inner_text()
    # the row says it started (no second move from it) and keeps the id; the status is not re-read
    assert page.locator('[data-cr-sb-started]').get_attribute('data-cr-sb-started') == UPID
    assert page.locator('[data-cr-sb-preview="100|scsi0|ceph-b"]').count() == 0
    assert app.server.status_reads == ['a1b2c3d4']
    # open in tasks: the drawer of the task center, filtered on the guest
    msg.locator('[data-cr-sb-tasks]').click()
    page.locator('#cr-tc-drawer').wait_for(timeout=4000)
    assert page.locator('[data-cr-tc-q]').input_value() == '100'
    assert _errors(app) == []


@pytest.mark.parametrize('case', ['vmconfig', 'locked', 'upstream'])
def test_runtime_a_refused_move_is_said_in_the_dialog(open_app, case):
    answer = {'vmconfig': (403, {'error': 'Access denied: you do not have permission to modify this VM'}),
              'locked': (400, {'error': 'VM 100 is locked (backup)'}),
              'upstream': (500, {'error': {'storage': "storage 'ceph-b' does not exist"}})}[case]
    app = open_app(migrate=answer)
    page = _balancing(app)
    _open_group(page, 'Ceph pools')
    alerts = []
    page.on('dialog', lambda d: (alerts.append(d.message), d.dismiss()))
    page.locator('[data-cr-sb-preview="100|scsi0|ceph-b"]').click()
    page.locator('[data-cr-sb-confirm]').click()
    err = page.locator('[data-cr-sb-dialog] [data-cr-sb-note="move-error"]')
    err.wait_for(timeout=5000)
    text = err.inner_text()
    expect = {'vmconfig': 'Not started: Access denied: you do not have permission to modify this VM - HTTP 403',
              'locked': 'Not started: VM 100 is locked (backup) - HTTP 400',
              'upstream': "Not started: storage: storage 'ceph-b' does not exist - HTTP 500"}[case]
    assert text.strip() == expect, text
    assert err.get_attribute('role') == 'alert' and alerts == []
    # nothing counts as started, the dialog stays for another try or a cancel
    assert page.locator('[data-cr-sb-started]').count() == 0
    assert not page.locator('[data-cr-sb-confirm]').is_disabled()
    assert _errors(app) == []


def test_runtime_a_move_cannot_start_twice(open_app):
    app = open_app(migrate='hold')
    page = _balancing(app)
    _open_group(page, 'Ceph pools')
    page.locator('[data-cr-sb-preview="100|scsi0|ceph-b"]').click()
    confirm = page.locator('[data-cr-sb-confirm]')
    confirm.click()
    page.wait_for_function('() => document.querySelector("[data-cr-sb-confirm]").disabled')
    assert confirm.inner_text().strip() == 'Starting...'
    confirm.click(force=True)
    page.keyboard.press('Escape')
    page.wait_for_timeout(300)
    assert page.locator('[data-cr-sb-dialog]').count() == 1, 'a move in flight is not closed away'
    assert len([w for w in app.server.writes if w[0] == 'POST']) == 1
    app.server.release_status((200, {'success': True, 'message': 'Disk migration started', 'upid': UPID}))
    page.locator('[data-cr-sb-dialog]').wait_for(state='detached', timeout=5000)
    assert len([w for w in app.server.writes if w[0] == 'POST']) == 1
    assert _errors(app) == []


def test_runtime_containers_unknown_sizes_and_full_targets_carry_their_risks(open_app):
    small_b = _sst('ceph-b', 'rbd', 1000, 980)
    # a stopped container: the server moves it (move_volume), so only what the data says is a risk
    recs = [r if r['vmid'] != 101 else _rec(101, 'ct01', 'stopped', 'rootfs', 'ceph-a', 'ceph-b', 8 * GIB, 82.0, 41.5)
            for r in STATUS_CEPH['recommendations']]
    st = dict(STATUS_CEPH, storages=[_sst('ceph-a', 'rbd', 1000, 820), small_b], recommendations=recs)
    ds = dict(DATASTORES, shared=[CEPH_A, _st('ceph-b', 'rbd', 'images', 1000, 980, shared=True, active_on=['pve1'], inactive_on=['pve2']),
                                  ISOS, NFS_1, NFS_OLD])
    app = open_app(statuses={'a1b2c3d4': (200, st)}, datastores=ds)
    page = _balancing(app)
    _open_group(page, 'Ceph pools')
    def risks(key):
        page.locator(f'[data-cr-sb-preview="{key}"]').click()
        dlg = page.locator('[data-cr-sb-dialog]')
        dlg.wait_for(timeout=4000)
        got = dlg.locator('[data-cr-sb-risk]').evaluate_all('rs => rs.map(r => r.dataset.crSbRisk)')
        after = dlg.locator('[data-cr-sb-plan="src"] [data-cr-sb-after]').inner_text()
        dlg.locator('[data-cr-sb-cancel]').click()
        return got, after
    ct, _ = risks('101|rootfs|ceph-b')
    # a container volume on a target set up for VM disks only; the move call itself is the right one now
    assert 'crSbRiskContentCt' in ct and 'crSbRiskContainer' not in ct and 'crSbRiskFree' not in ct, ct
    # no size read, and db01 runs on pve2, which does not mount ceph-b
    db, after = risks('102|scsi1|ceph-b')
    assert 'crSbRiskSize' in db and 'crSbRiskNode' in db and after == 'unknown', (db, after)
    # 20 GB free for a 32 GB disk; running is said, not counted as a risk to check
    web, _ = risks('100|scsi0|ceph-b')
    assert 'crSbRiskFree' in web and 'crSbRiskRunning' in web, web
    assert page.locator('[data-cr-sb-risk-n]').evaluate_all('xs => xs.map(x => x.dataset.crSbRiskN)') == ['1', '1', '2']
    assert not [w for w in app.server.writes if w[0] == 'POST']
    assert _errors(app) == []


# --- the switches, the threshold and the members wait for the server ---------------------------------

def _toggle(page, which):
    return page.locator(f'[data-cr-sb-toggle="{which}"]')


def test_runtime_a_refused_switch_goes_back_and_says_why(open_app):
    app = open_app(refuse={'put': (403, {'error': 'Access denied'})})
    page = _balancing(app)
    _open_group(page, 'Mixed')
    assert _toggle(page, 'enabled').is_checked()
    _toggle(page, 'enabled').click()
    msg = page.locator('[data-cr-sb-note="msg-error"]')
    msg.wait_for(timeout=5000)
    assert msg.inner_text().strip() == 'Not changed: Access denied - HTTP 403'
    page.wait_for_function('() => document.querySelector("[data-cr-sb-toggle=\\"enabled\\"]").checked && !document.querySelector("[data-cr-sb-toggle=\\"enabled\\"]").disabled')
    # the list did not take it either, and no status was read for a change that did not happen
    assert page.locator('[data-cr-sb-enabled]').get_attribute('data-cr-sb-enabled') == '1'
    assert app.server.status_reads == ['m1x2y3z4']
    puts = [w for w in app.server.writes if w[0] == 'PUT']
    assert puts == [('PUT', '/api/clusters/c1/storage-clusters/m1x2y3z4', {'enabled': False})], puts
    # the threshold the same way
    page.locator('[data-cr-sb-threshold]').select_option('30')
    page.wait_for_function('() => document.querySelector("[data-cr-sb-threshold]").value === "15" && !document.querySelector("[data-cr-sb-threshold]").disabled')
    assert _errors(app) == []


def test_runtime_an_accepted_change_takes_the_server_answer_and_reads_the_status_again(open_app):
    app = open_app()
    page = _balancing(app)
    _open_group(page, 'Mixed')
    _toggle(page, 'enabled').click()
    page.wait_for_function('() => document.querySelector("[data-cr-sb-enabled]").dataset.crSbEnabled === "0"')
    assert 'switched off' in page.locator('[data-cr-sb-note="off"]').inner_text()
    assert page.locator('[data-cr-table="sb-groups"] [data-cr-sb-off]').count() == 2
    page.wait_for_function('() => document.querySelector("[data-cr-sb-verdict]").dataset.crSbVerdict !== "loading"')
    assert app.server.status_reads == ['m1x2y3z4', 'm1x2y3z4'], 'enabled changes what the server recommends: read again'
    page.locator('[data-cr-sb-threshold]').select_option('30')
    page.wait_for_function('() => document.querySelector("[data-cr-sb-threshold]").value === "30"')
    # members: add one through the classic body (the whole list), remove one (more than two left)
    page.locator('[data-cr-sb-add]').select_option('isos')
    page.locator('[data-cr-sb-member="isos"]').wait_for(timeout=5000)
    page.locator('[data-cr-sb-remove="nfs-old"]').click()
    page.wait_for_function('() => !document.querySelector("[data-cr-sb-member=\\"nfs-old\\"]")')
    puts = [w[2] for w in app.server.writes if w[0] == 'PUT']
    assert puts == [{'enabled': False}, {'threshold': 30}, {'storages': ['ceph-b', 'nfs-1', 'nfs-old', 'isos']},
                    {'storages': ['ceph-b', 'nfs-1', 'isos']}], puts
    assert _errors(app) == []


def test_runtime_arming_auto_balance_asks_first(open_app):
    app = open_app()
    page = _balancing(app)
    _open_group(page, 'Mixed')
    asked = []
    page.once('dialog', lambda d: (asked.append(d.message), d.dismiss()))
    _toggle(page, 'auto').click()
    page.wait_for_timeout(300)
    assert len(asked) == 1 and 'every 1 h' in asked[0] and 'above 20 points' in asked[0] and 'deletes the source copy' in asked[0], asked
    assert not [w for w in app.server.writes if w[0] == 'PUT'] and not _toggle(page, 'auto').is_checked()
    page.once('dialog', lambda d: d.accept())
    _toggle(page, 'auto').click()
    page.locator('[data-cr-sb-armed]').wait_for(timeout=5000)
    assert [w[2] for w in app.server.writes if w[0] == 'PUT'] == [{'auto_balance': True}]
    assert 'Auto-balance is armed' in page.locator('[data-cr-sb-note="armed"]').inner_text()
    # switching it off asks nothing
    _toggle(page, 'auto').click()
    page.wait_for_function('() => !document.querySelector("[data-cr-sb-armed]")')
    assert [w[2] for w in app.server.writes if w[0] == 'PUT'] == [{'auto_balance': True}, {'auto_balance': False}]
    assert _errors(app) == []


def test_runtime_delete_keeps_the_classic_question_and_says_what_it_does_not_do(open_app):
    app = open_app(refuse={'delete': (403, {'error': 'Access denied to this cluster'})})
    page = _balancing(app)
    _open_group(page, 'Old pair')
    # no note about a stored copy that comes back: the server of Testing removes it (429d083a)
    assert page.locator('[data-cr-sb-delnote]').count() == 0
    assert 'can come back' not in page.locator('[data-cr-sb-detail]').inner_text()
    asked = []
    page.once('dialog', lambda d: (asked.append(d.message), d.dismiss()))
    page.locator('[data-cr-sb-delete]').click()
    page.wait_for_timeout(300)
    assert asked == ['Delete this storage cluster?'] and not [w for w in app.server.writes if w[0] == 'DELETE'], asked
    page.once('dialog', lambda d: d.accept())
    page.locator('[data-cr-sb-delete]').click()
    msg = page.locator('[data-cr-sb-note="msg-error"]')
    msg.wait_for(timeout=5000)
    assert msg.inner_text().strip() == 'Not changed: Access denied to this cluster - HTTP 403'
    assert page.locator('[data-cr-table="sb-groups"] tbody tr.cr-row', has_text='Old pair').count() == 1
    app.server.refuse = {}
    page.once('dialog', lambda d: d.accept())
    page.locator('[data-cr-sb-delete]').click()
    page.locator('[data-cr-sb-note="msg-success"]').wait_for(timeout=5000)
    assert page.locator('[data-cr-sb-msg="success"]').inner_text() == 'Storage cluster Old pair deleted.'
    assert page.locator('[data-cr-table="sb-groups"] tbody tr.cr-row', has_text='Old pair').count() == 0
    assert page.locator('[data-cr-sb-detail]').count() == 0
    assert _errors(app) == []


# --- who may do what ----------------------------------------------------------------------------------

@pytest.mark.parametrize('who', ['viewer', 'standby'])
def test_runtime_without_storage_config_or_on_a_standby_nothing_writes(open_app, who):
    kw = {'admin': False, 'perms': ['storage.view', 'vm.view']} if who == 'viewer' else {'role': 'standby'}
    app = open_app(**kw)
    page = _balancing(app)
    assert page.locator('[data-cr-sb-create]').count() == 0
    _open_group(page, 'Ceph pools')
    for which in ('enabled', 'auto'):
        assert _toggle(page, which).is_disabled(), which
    assert page.locator('[data-cr-sb-threshold]').is_disabled()
    assert page.locator('[data-cr-sb-delete]').count() == 0 and page.locator('[data-cr-sb-add]').count() == 0
    assert page.locator('[data-cr-sb-preview]').count() == 0
    assert _cells(page, 'sb-recs')[0]['act'] == 'Read only'
    if who == 'standby':
        assert 'changed on the active instance' in page.locator('[data-cr-sb-note="standby"]').inner_text()
        assert 'the active instance runs it' in page.locator('[data-cr-sb-note="armed"]').inner_text()
    # reading stays allowed: the status was read
    assert app.server.status_reads == ['a1b2c3d4'] and app.server.writes == []
    assert _errors(app) == []


def test_runtime_a_view_only_caller_gets_the_server_refusal_for_the_status(open_app):
    app = open_app(admin=False, perms=['vm.view'])
    page = _balancing(app, ready='[data-cr-sb-list="forbidden"]')
    assert 'You may not read the storage clusters' in page.locator('[data-cr-sb-note="list-forbidden"]').inner_text()
    assert page.locator('[data-cr-sb-empty]').count() == 0
    assert _errors(app) == []


# --- what the task list says about disk moves --------------------------------------------------------

def test_runtime_recent_disk_moves_come_from_the_task_list(open_app):
    moves = [
        {'upid': _upid('pve1', 9, 'qmmove', 102), 'node': 'pve2', 'type': 'qmmove', 'vmid': '102', 'status': 'stopped',
         'exitstatus': 'OK', 'starttime': FIXED - 7000, 'endtime': FIXED - 6800, 'user': 'root@pam', 'pegaprox_user': 'admin'},
        {'upid': _upid('pve1', 8, 'move_volume', 101), 'node': 'pve1', 'type': 'move_volume', 'vmid': '101', 'status': 'stopped',
         'exitstatus': 'command failed', 'starttime': FIXED - 9000, 'endtime': FIXED - 8990, 'user': 'root@pam'},
    ]
    app = open_app(tasks=TASKS + moves)
    page = _balancing(app)
    _open_group(page, 'Ceph pools')
    rows = _cells(page, 'sb-recent')
    assert [(r['op'], r['guest'], r['state']) for r in rows] == [('VM disk move', 'db01', 'Done'), ('CT volume move', 'ct01', 'Failed')], rows
    assert 'PVE does not record the storages' in page.locator('[data-cr-sb-recent]').inner_text()
    assert page.locator('[data-cr-sb-here]').count() == 0
    # the guest opens from the list
    page.locator('[data-cr-table="sb-recent"] button.cr-link', has_text='ct01').click()
    page.wait_for_function('() => (document.querySelector(".cr-crumbs") || {}).innerText?.includes("ct01")', timeout=5000)
    assert _errors(app) == []


def test_runtime_without_disk_moves_there_is_no_history_section(open_app):
    app = open_app()
    page = _balancing(app)
    _open_group(page, 'Ceph pools')
    assert page.locator('[data-cr-sb-recent]').count() == 0
    assert _errors(app) == []


# --- the Browse gaps ------------------------------------------------------------------------------------

def test_runtime_browse_shows_free_space_health_not_reported_and_the_storage_pair(open_app):
    app = open_app(storage={'pegaprox-sidebar-view': 'datastores'})
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    _need(page, '[data-cr-ds-tree="c1"] [data-cr-ds-node]', 'the sidebar rows of the preview')
    side = page.evaluate('''() => Array.from(document.querySelectorAll('[data-cr-ds-tree="c1"] [data-cr-ds-node]')).map(r => [
        r.dataset.crDsNode, (r.querySelector('[data-cr-ds-free]') || {}).textContent || null, r.getAttribute('title')])''')
    got = {k: (f, ttl) for k, f, ttl in side}
    assert got['ceph-a@'][0] == '180.0 GB' and got['ceph-a@'][1].endswith(', 180.0 GB free'), got['ceph-a@']
    assert got['nfs-old@'][0] is None, 'an inactive storage has no free figure'
    page.locator('[data-cr-ds-node="ceph-a@"]').click()
    _need(page, '[data-cr-ds-head]', 'the storage opens in the Browse tab')
    rows = page.evaluate('''() => Object.fromEntries(Array.from(document.querySelectorAll('[data-cr-ds-row^="s:"]')).map(r => [
        r.dataset.crDsRow, [(r.querySelector('[data-cr-ds-free]') || {}).textContent || null,
                            r.querySelector('.cr-meter') ? (r.querySelector('.cr-meter').className.match(/cr-tone-(\\w+)/) || [])[1] : null]]))''')
    # 82 % is a warning of the storage pair, 41.5 % normal, 10 % normal
    assert rows['s:ceph-a@'] == ['180.0 GB free', 'warning'] and rows['s:ceph-b@'] == ['585.0 GB free', 'success'], rows
    head = page.locator('[data-cr-ds-head]')
    assert head.locator('[data-cr-ds-health="unreported"]').inner_text() == 'Health not reported'
    assert 'not how its data is' in head.locator('[data-cr-ds-health]').get_attribute('title')
    meter = head.locator('.cr-meter').get_attribute('title')
    # the scale says its limits and nothing more (the "not configurable yet" note is gone)
    assert 'warning from 70%, critical above 85%' in meter and 'not configurable' not in meter, meter
    assert '70% used or more' in page.locator('[data-cr-ds-problems]').get_attribute('title')
    assert _errors(app) == []


# --- classic stays classic --------------------------------------------------------------------------

@pytest.mark.parametrize('layout', ['corporate', 'modern'])
def test_runtime_classic_layouts_keep_the_classic_balancing_tab(open_app, layout):
    app = open_app(layout=layout)
    page = app.page
    if layout == 'modern':
        page.get_by_text('Testi').first.click()
    else:
        page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.locator('button', has_text=re.compile(r'^\s*Datastore\s*$')).first.click()
    page.locator('button', has_text=re.compile(r'^\s*Storage Balancing\s*$')).first.click()
    page.get_by_text('Storage Clusters', exact=True).first.wait_for(timeout=8000)
    page.locator('div.cursor-pointer', has=page.locator('span', has_text=re.compile(r'^\s*Ceph pools\s*$'))).first.click()
    page.get_by_text('40.5%').first.wait_for(timeout=8000)
    assert page.locator('[data-cr-sb]').count() == 0
    # classic still has its tolerance slider, and reads the status of the clicked group
    assert page.get_by_text('Migration Tolerance').count() >= 1
    assert app.server.status_reads == ['a1b2c3d4']
    assert _errors(app) == []


# --- language, names, layout, scale ------------------------------------------------------------------

def test_runtime_german(open_app):
    app = open_app(language='de')
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.locator('[data-cr-tab="datastore"]').click()
    page.locator('.corp-tab-strip button', has_text='Storage Balancing').first.click()
    _need(page, '[data-cr-sb-list="ok"]', 'the list read')
    assert page.locator('.cr-pagehead-title').first.inner_text() == 'Speicherausgleich'
    _open_group(page, 'Ceph pools')
    assert page.locator('[data-cr-sb-verdict]').inner_text().strip() == 'Über der Schwelle: Verschiebungen werden empfohlen'
    assert page.locator('[data-cr-sb-preview]').first.inner_text().strip() == 'Verschiebung ansehen'
    assert _errors(app) == []


def test_runtime_every_control_has_a_name(open_app):
    app = open_app()
    page = _balancing(app)
    _open_group(page, 'Mixed')
    page.locator('[data-cr-sb-preview]').first.click()
    page.locator('[data-cr-sb-dialog]').wait_for(timeout=4000)
    nameless = page.evaluate('''() => Array.from(document.querySelectorAll('[data-cr-sb] button, [data-cr-sb] input, [data-cr-sb] select, [data-cr-sb-dialog] button, [data-cr-sb] [tabindex="0"]'))
        .filter(e => e.getClientRects().length)
        .filter(e => !((e.getAttribute('aria-label') || '').trim() || (e.innerText || '').trim() || (e.getAttribute('title') || '').trim()
            || (e.labels && e.labels.length && e.labels[0].innerText.trim())))
        .map(e => e.outerHTML.slice(0, 140))''')
    assert nameless == [], nameless
    assert _errors(app) == []


GEOMETRY = """() => {
    const vw = window.innerWidth;
    const bar = document.querySelector('.cr-taskcenter').getBoundingClientRect();
    const boxes = (sel) => Array.from(document.querySelectorAll(sel)).map(e => e.getBoundingClientRect());
    const overlap = (a, b) => a.left < b.right - 0.5 && b.left < a.right - 0.5 && a.top < b.bottom - 0.5 && b.top < a.bottom - 0.5;
    const panels = boxes('[data-cr-sb-dist], [data-cr-sb-imb]');
    const lines = Array.from(document.querySelectorAll('[data-cr-sb-member] .cr-sb-mline')).map(l => {
        const kids = Array.from(l.children).map(c => c.getBoundingClientRect()).filter(r => r.width);
        let hit = 0;
        for (let i = 0; i < kids.length; i++) for (let j = i + 1; j < kids.length; j++) if (overlap(kids[i], kids[j])) hit++;
        return hit;
    });
    const dlg = document.querySelector('[data-cr-sb-dialog]');
    const d = dlg ? dlg.getBoundingClientRect() : null;
    const settings = Array.from(document.querySelectorAll('[data-cr-sb-settings] > *')).map(c => c.getBoundingClientRect());
    let sHit = 0;
    for (let i = 0; i < settings.length; i++) for (let j = i + 1; j < settings.length; j++) if (overlap(settings[i], settings[j])) sHit++;
    return { over: document.documentElement.scrollWidth - vw, panelsOverlap: panels.length === 2 && overlap(panels[0], panels[1]),
             lineHits: lines.reduce((a, b) => a + b, 0), settingHits: sHit,
             dialog: d ? { top: d.top, bottom: d.bottom, left: d.left, right: d.right, bar: bar.top, vw } : null };
}"""


@pytest.mark.parametrize('engine', ['chromium', 'firefox'])
@pytest.mark.parametrize('size', [(1280, 800), (1600, 1000)], ids=['1280', '1600'])
def test_runtime_nothing_overlaps_in_chromium_and_firefox(open_app, request, engine, size):
    br = request.getfixturevalue('firefox') if engine == 'firefox' else None
    app = open_app(viewport=size, br=br)
    page = _balancing(app)
    _open_group(page, 'Mixed')
    g = page.evaluate(GEOMETRY)
    assert g['over'] <= 0 and not g['panelsOverlap'] and g['lineHits'] == 0 and g['settingHits'] == 0, g
    page.locator('[data-cr-sb-preview]').first.click()
    page.locator('[data-cr-sb-dialog]').wait_for(timeout=4000)
    g = page.evaluate(GEOMETRY)
    d = g['dialog']
    assert d['top'] >= 0 and d['bottom'] <= d['bar'] + 0.5 and d['left'] >= 0 and d['right'] <= d['vw'], g
    assert _errors(app) == []


def test_runtime_200_nodes_and_40_groups_stay_smooth_without_a_read_per_group(open_app):
    nodes = [f'node{i:03d}' for i in range(200)]
    shared = [_st(f'pool{i:02d}', 'rbd', 'images,rootdir', 1000, 100 + i * 20, shared=True, active_on=nodes[:-1], inactive_on=nodes[-1:])
              for i in range(40)]
    local = {n: [_st('local', 'dir', 'iso,backup', 100, 10), _st('local-lvm', 'lvmthin', 'images,rootdir', 500, 50)] for n in nodes}
    groups = [_group(f'g{i:03d}', f'Group {i:02d}', [f'pool{i:02d}', f'pool{(i + 1) % 40:02d}', f'pool{(i + 7) % 40:02d}']) for i in range(40)]
    app = open_app(datastores={'shared': shared, 'local': local, 'nodes': nodes, 'offline_nodes': []}, groups=groups, statuses={})
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.locator('[data-cr-tab="datastore"]').click()
    t = time.time()
    page.locator('.corp-tab-strip button', has_text='Storage Balancing').first.click()
    page.locator('[data-cr-table="sb-groups"] tbody tr.cr-row').nth(39).wait_for(timeout=8000)
    took = time.time() - t
    assert took < 2.0, took
    assert _status_calls(app) == []
    assert page.locator('[data-cr-sb-gnodes]').first.inner_text() == '199 nodes (1 partial)'
    # the member chips of a big cluster are a count plus the nodes that do not mount it
    _open_group(page, 'Group 00')
    chips = page.locator('[data-cr-sb-member="pool00"] .cr-sb-chip').evaluate_all('cs => cs.map(c => c.textContent)')
    assert chips == ['on 199 nodes', 'node199'], chips
    assert _errors(app) == []


# --- after the review of round 3 -------------------------------------------------------------------

@pytest.mark.parametrize('drop', ['imbalance', 'threshold'])
def test_runtime_a_status_without_the_servers_spread_cannot_be_judged(open_app, drop):
    body = copy.deepcopy(STATUS_CEPH)
    body['recommendations'] = []
    body[drop] = None
    groups = [dict(G_CEPH, threshold=None) if drop == 'threshold' else G_CEPH, G_MIXED, G_GONE]
    app = open_app(statuses={'a1b2c3d4': (200, body)}, groups=groups)
    page = _balancing(app)
    _open_group(page, 'Ceph pools')
    v = page.locator('[data-cr-sb-verdict]')
    assert v.get_attribute('data-cr-sb-verdict') == 'unknown', v.inner_text()
    assert v.get_attribute('data-cr-sb-why') == drop
    assert {'imbalance': 'no imbalance figure', 'threshold': 'no threshold'}[drop] in v.inner_text()
    assert page.locator('[data-cr-sb-nomove]').count() == 0
    assert 'Within the threshold' not in page.locator('[data-cr-sb-imb]').inner_text()
    assert _errors(app) == []


def test_runtime_a_thin_disk_larger_than_its_source_use_gives_bounds_not_a_negative_use(open_app):
    # the declared size (900 GiB) is more than ceph-a uses at all (820 GiB)
    body = copy.deepcopy(STATUS_CEPH)
    body['storages'] = [_sst('ceph-a', 'rbd', 1000, 820), _sst('ceph-b', 'rbd', 4000, 415)]
    body['recommendations'] = [_rec(100, 'web01', 'running', 'scsi0', 'ceph-a', 'ceph-b', 900 * GIB, 82.0, 10.4)]
    app = open_app(statuses={'a1b2c3d4': (200, body)})
    page = _balancing(app)
    _open_group(page, 'Ceph pools')
    impact = page.locator('[data-cr-sb-impact]').first
    src, tgt = (float(x) for x in impact.get_attribute('data-cr-sb-impact').split('|'))
    assert src == 0.0 and abs(tgt - 32.9) < 0.05, (src, tgt)
    assert '≥' in impact.inner_text() and '-' not in impact.inner_text().replace('→', ''), impact.inner_text()
    page.locator('[data-cr-sb-preview="100|scsi0|ceph-b"]').click()
    dlg = page.locator('[data-cr-sb-dialog]')
    dlg.wait_for(timeout=4000)
    assert dlg.locator('[data-cr-sb-plan="src"] [data-cr-sb-after]').inner_text().strip() == 'at least 0.0%'
    assert dlg.locator('[data-cr-sb-plan="tgt"] [data-cr-sb-after]').inner_text().strip() == 'at most 32.9%'
    thin = dlg.locator('[data-cr-sb-risk="crSbRiskThin"]')
    assert 'the disk is thin' in thin.inner_text() and thin.get_attribute('data-cr-sb-level') == 'info'
    assert _errors(app) == []


def test_runtime_open_in_tasks_keeps_the_filters_the_user_stored(open_app):
    kept = {'status': 'failed', 'type': '', 'cluster': '', 'q': 'pve2'}
    app = open_app(storage={'cr-tc-filters': json.dumps(kept)})
    page = _balancing(app)
    _open_group(page, 'Ceph pools')
    page.locator('[data-cr-sb-preview="100|scsi0|ceph-b"]').click()
    page.locator('[data-cr-sb-confirm]').click()
    page.locator('[data-cr-sb-dialog]').wait_for(state='detached', timeout=5000)
    page.locator('[data-cr-sb-note="msg-success"] [data-cr-sb-tasks]').click()
    page.locator('#cr-tc-drawer').wait_for(timeout=4000)
    # the drawer opens on the guest of the move, for now
    assert page.locator('[data-cr-tc-q]').input_value() == '100'
    stored = json.loads(page.evaluate("() => localStorage.getItem('cr-tc-filters')"))
    assert stored == kept, stored
    assert _errors(app) == []


@pytest.mark.parametrize('width', [1280, 1600])
def test_runtime_the_overview_headers_are_not_cut(open_app, width):
    app = open_app(viewport=(width, 900))
    page = _balancing(app)
    page.locator('[data-cr-table="sb-groups"] thead th[data-cr-col="auto"]').wait_for(timeout=6000)
    # the laid-out text against the box it gets (an ellipsis can hide a cut of a pixel from scrollWidth)
    cut = page.evaluate('''() => Array.from(document.querySelectorAll('[data-cr-table="sb-groups"] thead th .cr-th-text'))
        .filter(e => { const r = document.createRange(); r.selectNodeContents(e);
                       return r.getBoundingClientRect().width > e.getBoundingClientRect().width + 0.5; })
        .map(e => e.textContent)''')
    assert cut == [], cut
    # and the wider columns do not make the table scroll sideways
    scroll = page.evaluate('''() => { const s = document.querySelector('[data-cr-table="sb-groups"] .cr-table-scroll'); return [s.scrollWidth, s.clientWidth]; }''')
    assert scroll[0] <= scroll[1], scroll
    assert _errors(app) == []
