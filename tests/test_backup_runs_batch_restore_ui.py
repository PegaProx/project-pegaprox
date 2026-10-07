"""The run history of a backup job and the batch restore, as the browser shows them.

The source checks read web/src and the bundle; the runtime tests drive the built bundle in
headless Chromium against the fake server of tests/test_ha_ui.py, in Modern, Corporate and
Cloud, as an active instance and as a standby, in English and German. They skip where
Playwright is not installed. The routes behind them are tested in tests/test_backup_job_runs.py
and tests/test_batch_restore.py.
LW Oct 2026
"""
import json
import os
import re
import time

import pytest

from test_ha_ui import CLUSTER, VM, SSE_TOKEN, _App, _FakeServer, _classes, browser  # noqa: F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHOTS = os.environ.get('PEGAPROX_SHOTS', '')
LANGS = ['de', 'en', 'zh', 'pl', 'fr', 'es', 'pt', 'ko', 'it']


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def _ui_block():
    src = _read('web', 'src', 'ui.js')
    start = src.index('// LW Oct 2026 - what the runs of a backup job did')
    end = 'try { window.PegaProxBatchRestoreModal = BatchRestoreModal; } catch (_) {}'
    return src[start:src.index(end, start) + len(end)]


def _call_sites():
    dc, cloud, storage = _read('web', 'src', 'datacenter.js'), _read('web', 'src', 'cloud.js'), _read('web', 'src', 'storage.js')
    a = dc[dc.index('{/* LW Oct 2026 - what its runs did, read only */}'):]
    a = a[:a.index('</button>') + 9]
    b = '\n'.join(line for line in cloud[cloud.index('function CloudBackups('):cloud.index('// ── Firewall (datacenter rules)')]
                  .split('\n') if 'runsOf' in line or 'bkpRunsHistory' in line or '{mut.acts && (<>' in line)
    c = storage[storage.index('{/* LW Oct 2026 - several of its backups in one go, and the batches before */}'):]
    c = c[:c.index('<button\n')]
    d = storage[storage.index('{batchRestore && selectedStorage && ('):storage.index('{/* Delete Confirm Modal */}')]
    return a, b, c, d


def _keys():
    used = set(re.findall(r"t\('((?:bkpRuns|batchRestore)[A-Za-z]*)'\)", _ui_block() + ''.join(_call_sites())))
    return sorted(used)


# --- source --------------------------------------------------------------------------------

def test_every_new_string_is_in_every_language_once():
    tr = _read('web', 'src', 'translations.js')
    keys = _keys()
    assert len(keys) > 60
    for key in keys:
        found = len(re.findall(rf'^\s*{key}:', tr, re.M))
        assert found == 9, f'{key} is in {found} of 9 language blocks - the UI would show the key'


def test_no_key_of_the_two_features_is_left_unused():
    tr = _read('web', 'src', 'translations.js')
    defined = set(re.findall(r'^\s*((?:bkpRuns|batchRestore)[A-Za-z]*):', tr, re.M))
    assert defined == set(_keys()), (sorted(defined - set(_keys())), sorted(set(_keys()) - defined))


def test_every_language_block_holds_them_once():
    tr = _read('web', 'src', 'translations.js')
    starts = [(m.group(1), m.start()) for m in re.finditer(r'^            ([a-z][a-z]): \{', tr, re.M)]
    assert [s[0] for s in starts] == LANGS
    for i, (lang, at) in enumerate(starts):
        block = tr[at:starts[i + 1][1] if i + 1 < len(starts) else len(tr)]
        for key in _keys():
            assert len(re.findall(rf'^\s*{key}:', block, re.M)) == 1, (lang, key)


def test_placeholders_survive_translation():
    tr = _read('web', 'src', 'translations.js')
    for key in _keys():
        values = re.findall(rf'^\s*{key}: "(.*)",$', tr, re.M)
        assert len(values) == 9, key
        wanted = set(re.findall(r'\{(\w+)\}', values[LANGS.index('en')]))
        for v in values:
            assert set(re.findall(r'\{(\w+)\}', v)) == wanted, (key, v)


DASHES = (chr(0x2014), chr(0x2013))


def test_no_em_dash_in_what_this_change_added():
    for block in (_ui_block(),) + _call_sites():
        assert not any(d in block for d in DASHES), block[:120]
    tr = _read('web', 'src', 'translations.js')
    for key in _keys():
        for v in re.findall(rf'^\s*{key}: (".*"),$', tr, re.M):
            assert not any(d in v for d in DASHES), (key, v)


def test_the_icons_exist():
    icons = _read('web', 'src', 'icons.js')
    have = set(re.findall(r'^\s{12}([A-Z][A-Za-z0-9]*):', icons, re.M))
    used = set(re.findall(r'Icons\.([A-Za-z]+)', _ui_block() + ''.join(_call_sites())))
    used |= set(re.findall(r'CloudIconBtn icon="([A-Za-z]+)"', _call_sites()[1]))
    assert used <= have, sorted(used - have)


def test_every_class_is_in_the_static_tailwind_build():
    shell = '\n'.join(line for line in _read('web', 'index.html.original').split('\n')
                      if 'data-corp-theme="light"' not in line)
    css = _read('static', 'css', 'tailwind.min.css') + shell
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    names = _classes(_ui_block())
    for block in _call_sites():
        names |= _classes(block)
    missing = sorted(n for n in names if n not in have)
    assert not missing, f'not in static/css/tailwind.min.css: {missing}'


def test_the_history_is_offered_outside_what_a_standby_hides():
    """Reading the runs changes nothing: Cloud shows its button outside the mut.acts block"""
    cloud = _call_sites()[1]
    assert cloud.count('{mut.acts && (<>') == 1
    # after the gated block, so the row actions still open with it (the standby check in
    # test_ha_ui reads them that way)
    assert cloud.index('<CloudIconBtn icon="Clock"') > cloud.index('{mut.acts && (<>')
    assert re.search(r'</>\)\}\n\s*<CloudIconBtn icon="Clock" title=\{t\(\'bkpRunsHistory\'\)', _read('web', 'src', 'cloud.js'))
    storage = _call_sites()[2]
    # restoring asks vm.backup, which hasPerm withholds on a standby; the list of batches is a read
    assert "hasPerm('vm.backup')" in storage and "hasPerm('backup.view')" in storage


def test_the_bundle_was_rebuilt():
    built = _read('web', 'index.html')
    for needle in ('function BackupJobRunsModal(', 'function BatchRestoreModal(', '/backup-restore/batch',
                   '/batch-restores/', 'data-bkp-history', 'data-br-open', 'bkpRunsHistory', 'batchRestoreButton'):
        assert needle in built, needle


# --- runtime: the run history ----------------------------------------------------------------

T0 = int(time.time()) - 7200
U1 = f'UPID:pve1:00000001:00000001:{T0:08X}:vzdump::root@pam:'
U2 = f'UPID:pve2:00000002:00000001:{T0 + 3:08X}:vzdump::root@pam:'
JOB = {'id': 'backup-all', 'enabled': 1, 'schedule': '21:00', 'storage': 'pbs', 'mode': 'snapshot', 'all': 1}
RUN_OLD = T0 - 86400


def _run(start, state, tasks, scheduled=True, by=''):
    return {'id': tasks[0]['upid'], 'start': start, 'end': start + 300, 'duration': 300, 'state': state,
            'failed_tasks': sum(1 for t in tasks if t['status'] not in ('OK',)), 'scheduled': scheduled,
            'started_by': by, 'tasks': tasks}


def _task(node, upid, status='OK'):
    return {'node': node, 'upid': upid, 'start': T0, 'end': T0 + 300, 'status': status, 'user': 'root@pam'}


RUNS = {'runs': [_run(T0, 'failed', [_task('pve1', U1, 'job errors'), _task('pve2', U2)]),
                 _run(RUN_OLD, 'ok', [_task('pve1', U1.replace('1:00000001:', '1:00000009:'))], scheduled=False, by='alice')],
        'partial': True, 'unread_nodes': ['pve3'], 'job_id': 'backup-all', 'days': 14, 'limit': 20}


def _guest(vmid, state, node='pve1', upid=U1, kind='qemu', error=''):
    return {'vmid': vmid, 'type': kind, 'node': node, 'upid': upid, 'state': state, 'took': '00:01:23' if state == 'ok' else '',
            'size': '1.2GB' if state == 'ok' else '', 'error': error, 'started': '', 'ended': '', 'archive': '',
            'first': 2, 'last': 8}


GUESTS = {'guests': [_guest(100, 'ok'), _guest(101, 'failed', error='No space left on device'),
                     _guest(200, 'ok', 'pve2', U2, 'lxc')],
          'tasks': [{'node': 'pve1', 'upid': U1, 'readable': True, 'status': 'job errors', 'guests': 2},
                    {'node': 'pve2', 'upid': U2, 'readable': True, 'status': 'OK', 'guests': 1}],
          'missing': []}
LOG = {'lines': ['INFO: Starting Backup of VM 101 (qemu)', 'ERROR: Backup of VM 101 failed - No space left on device'],
       'start': 8, 'more': False}
BASE = '/api/clusters/c1/datacenter/backup/backup-all/runs'


def _history_reads(runs=RUNS, guests=GUESTS):
    extra = dict(SSE_TOKEN)
    extra.update({('GET', '/api/clusters/c1/datacenter/backup'): (200, [JOB]), ('GET', BASE): (200, runs),
                  ('GET', BASE + '/guests'): (200, guests), ('GET', BASE + '/log'): (200, LOG)})
    return extra


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(extra, **kw):
        kw.setdefault('role', 'standalone')
        app = _App(browser, _FakeServer(clusters=[CLUSTER], resources=[VM], extra=extra, **kw))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _shot(page, name):
    if SHOTS:
        os.makedirs(SHOTS, exist_ok=True)
        page.screenshot(path=os.path.join(SHOTS, name), full_page=False)


def _open_history(app, layout):
    page = app.page
    if layout == 'cloud':
        page.locator('.cloud-shell').get_by_text('Backups', exact=True).first.click()
        page.locator('.cloud-table-row', has_text='21:00').first.wait_for(timeout=5000)
        page.locator('.cloud-table-row button[title="Run history"]').first.click()
    else:
        if layout == 'corporate':
            page.locator('.corp-tree-item', has_text='Testi').first.click()
        else:
            page.get_by_text('Testi').first.click()
        page.locator('button', has_text='Datacenter').first.click()
        page.locator('button', has_text=re.compile(r'^\s*Backup\s*$')).first.click()
        page.locator('[data-bkp-history="backup-all"]').first.click()
    page.locator('[data-bkp-runs="backup-all"]').wait_for(timeout=8000)
    page.locator('[data-bkp-run]').first.wait_for(timeout=5000)
    return page


def _urls(app, part):
    return [u for u in app.server.urls if part in u]


@pytest.mark.parametrize('layout', ['modern', 'corporate', 'cloud'])
def test_runtime_the_runs_of_a_job_their_guests_and_a_log(open_app, layout):
    app = open_app(_history_reads(), layout=layout)
    page = _open_history(app, layout)
    modal = page.locator('[data-testid="bkp-runs-modal"]')
    text = modal.inner_text()
    assert 'Runs of backup-all' in text and '21:00 - pbs - All' in text
    assert 'Not read: pve3 (offline or not answering)' in text
    assert 'Not every task has been read yet' in text
    rows = page.locator('[data-bkp-run]')
    assert rows.count() == 2
    assert [rows.nth(i).get_attribute('data-state') for i in range(2)] == ['failed', 'ok']
    first, second = rows.nth(0).inner_text(), rows.nth(1).inner_text()
    assert 'Failed' in first and '1 node(s) failed' in first and 'Schedule' in first and '5m 0s' in first
    assert 'alice' in second and 'OK' in second
    # nothing about the guests is read before a run is opened
    assert not _urls(app, '/runs/guests') and not _urls(app, '/runs/log')
    rows.nth(0).click()
    page.locator('[data-bkp-guest="101"]').wait_for(timeout=5000)
    (asked,) = _urls(app, '/runs/guests')
    assert asked.count('upid=') == 2 and 'UPID%3Apve1' in asked and 'UPID%3Apve2' in asked
    order = page.locator('[data-bkp-guest]').evaluate_all('rs => rs.map(r => r.dataset.bkpGuest)')
    assert order == ['101', '100', '200']        # what failed first
    failed = page.locator('[data-bkp-guest="101"]').inner_text()
    assert 'No space left on device' in failed and 'Failed' in failed
    assert '3 guests, 1 failed' in modal.inner_text()
    page.locator('[data-bkp-only-failed]').check()
    assert page.locator('[data-bkp-guest]').count() == 1
    page.locator('[data-bkp-log="101"]').click()
    page.locator('[data-bkp-logbox] pre').wait_for(timeout=5000)
    assert 'ERROR: Backup of VM 101 failed' in page.locator('[data-bkp-logbox] pre').inner_text()
    (log,) = _urls(app, '/runs/log')
    assert 'vmid=101' in log and 'UPID%3Apve1' in log
    _shot(page, f'bkp_runs_{layout}.png')
    # another period asks again
    page.locator('[data-bkp-days]').select_option('30')
    deadline = time.time() + 4
    while time.time() < deadline and not any('days=30' in u for u in app.server.urls):
        page.wait_for_timeout(100)
    assert any('days=30' in u for u in app.server.urls)
    page.locator('[data-bkp-close]').click()
    assert page.locator('[data-bkp-runs]').count() == 0
    assert not app.errors, app.errors


def test_runtime_a_run_of_many_nodes_is_read_a_few_tasks_at_a_time(open_app):
    tasks = [_task(f'pve{i}', f'UPID:pve{i}:0000000{i % 9}:00000001:{T0:08X}:vzdump::root@pam:') for i in range(20)]
    runs = {'runs': [_run(T0, 'ok', tasks)], 'partial': False, 'unread_nodes': [], 'days': 14, 'limit': 20}
    job = dict(JOB, all=0, vmid='100,101,102')
    extra = _history_reads(runs, {'guests': [_guest(100, 'ok')], 'tasks': [], 'missing': [101, 102]})
    extra[('GET', '/api/clusters/c1/datacenter/backup')] = (200, [job])
    app = open_app(extra, layout='modern')
    page = _open_history(app, 'modern')
    page.locator('[data-bkp-run]').first.click()
    page.locator('[data-bkp-missing]').wait_for(timeout=5000)
    reads = _urls(app, '/runs/guests')
    assert [u.count('upid=') for u in reads] == [16, 4]
    # each read answers what it saw: missing is what none of them backed up
    assert page.locator('[data-bkp-missing]').inner_text() == 'Not backed up in this run: 101, 102'
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'cloud'])
def test_runtime_a_standby_shows_the_history_too(open_app, layout):
    app = open_app(_history_reads(), layout=layout, role='standby')
    page = _open_history(app, layout)
    assert page.locator('[data-bkp-run]').count() == 2
    page.locator('[data-bkp-run]').first.click()
    page.locator('[data-bkp-guest="100"]').wait_for(timeout=5000)
    assert not [c for c in app.server.calls if c[0] != 'GET' and 'backup' in c[1]]
    assert not app.errors, app.errors


def test_runtime_the_history_speaks_german(open_app):
    app = open_app(_history_reads(), layout='modern', language='de')
    page = app.page
    page.get_by_text('Testi').first.click()
    page.locator('button', has_text='Datacenter').first.click()
    page.locator('button', has_text=re.compile(r'^\s*Backup\s*$')).first.click()
    assert page.locator('[data-bkp-history="backup-all"]').get_attribute('title') == 'Verlauf der Läufe'
    page.locator('[data-bkp-history="backup-all"]').click()
    page.locator('[data-bkp-run]').first.wait_for(timeout=5000)
    text = page.locator('[data-testid="bkp-runs-modal"]').inner_text()
    assert 'Läufe von backup-all' in text and 'Nicht gelesen: pve3' in text and 'Zeitplan' in text
    assert not app.errors, app.errors


def test_runtime_a_refused_history_says_why(open_app):
    extra = _history_reads()
    extra[('GET', BASE)] = (404, {'error': 'Backup job not found'})
    app = open_app(extra, layout='modern')
    page = app.page
    page.get_by_text('Testi').first.click()
    page.locator('button', has_text='Datacenter').first.click()
    page.locator('button', has_text=re.compile(r'^\s*Backup\s*$')).first.click()
    page.locator('[data-bkp-history="backup-all"]').click()
    page.locator('[data-bkp-error]').wait_for(timeout=5000)
    assert page.locator('[data-bkp-error]').inner_text() == 'Backup job not found'
    assert not app.errors, app.errors


# --- runtime: the batch restore ---------------------------------------------------------------

NOW = int(time.time())
PBS = {'storage': 'backupsrv', 'type': 'pbs', 'content': 'backup', 'shared': 1, 'total': 500 * 2 ** 30,
       'used': 50 * 2 ** 30, 'avail': 450 * 2 ** 30, 'active': 1, 'enabled': 1, 'used_fraction': 0.1}
ZFS = {'storage': 'local-zfs', 'type': 'zfspool', 'content': 'images,rootdir', 'shared': 0, 'total': 100 * 2 ** 30,
       'used': 10 * 2 ** 30, 'avail': 90 * 2 ** 30, 'active': 1, 'enabled': 1, 'node': 'pve1', 'used_fraction': 0.1}
DATASTORES = {'shared': [PBS], 'local': {'pve1': [ZFS], 'pve2': []}, 'nodes': ['pve1', 'pve2']}


def _bk(vmid, kind, age_h, notes=''):
    t = NOW - age_h * 3600
    iso = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(t))
    return {'volid': f"backupsrv:backup/{'vm' if kind == 'qemu' else 'ct'}/{vmid}/{iso}", 'content': 'backup',
            'ctime': t, 'format': 'pbs-' + ('vm' if kind == 'qemu' else 'ct'), 'size': 2 ** 30, 'subtype': kind,
            'vmid': vmid, 'notes': notes, 'size_human': '1.0 GB', 'storage': 'backupsrv', 'node': 'pve1'}


CONTENT = [_bk(100, 'qemu', 2, 'web01'), _bk(100, 'qemu', 26, 'web01'), _bk(101, 'qemu', 3, 'db01'),
           _bk(200, 'lxc', 4, 'ct1')]
RUN_ID = 'abc123def4567890'


def _batch(state='running', counts=None, rows=None, may_cancel=True, mode='new'):
    rows = rows or [
        {'vmid': 100, 'type': 'qemu', 'volid': CONTENT[1]['volid'], 'target_vmid': 900, 'node': 'pve1',
         'state': 'restoring', 'note': '', 'task': 'UPID:x', 'began': NOW, 'ended': None},
        {'vmid': 200, 'type': 'lxc', 'volid': CONTENT[3]['volid'], 'target_vmid': 901, 'node': 'pve1',
         'state': 'wait', 'note': '', 'task': None, 'began': None, 'ended': None}]
    return {'id': RUN_ID, 'cluster_id': 'c1', 'cluster': 'Testi', 'user': 'admin', 'mine': True,
            'storage': 'backupsrv', 'mode': mode, 'node': 'pve1', 'target_storage': '', 'run': 'sequential',
            'parallel': None, 'state': state, 'reason': '', 'cancelled_by': '', 'created': NOW, 'finished': None,
            'total': len(rows), 'counts': counts or {'restoring': 1, 'wait': 1}, 'current': [100], 'rows': rows,
            'may_cancel': may_cancel}


def _restore_reads(post=None):
    extra = dict(SSE_TOKEN)
    extra.update({
        ('GET', '/api/clusters/c1/datastores'): (200, DATASTORES),
        ('GET', '/api/clusters/c1/datastores/backupsrv/content'): (200, CONTENT),
        ('GET', '/api/clusters/c1/storage-clusters'): (200, []),
        ('GET', '/api/clusters/c1/next-vmid'): (200, {'vmid': 900}),
        ('POST', '/api/clusters/c1/backup-restore/batch'): post or (202, {'run': _batch()}),
        ('GET', f'/api/batch-restores/{RUN_ID}'): (200, {'run': _batch()}),
        ('POST', f'/api/batch-restores/{RUN_ID}/cancel'): (200, {'run': dict(_batch(), cancelled_by='admin', may_cancel=False)}),
        ('GET', '/api/batch-restores'): (200, {'runs': [dict(_batch(state='done', counts={'done': 2}), rows=None),
                                                        dict(_batch(), id='other', cluster_id='c9')]}),
    })
    return extra


def _open_storage(app, layout):
    page = app.page
    if layout == 'corporate':
        page.locator('.corp-tree-item', has_text='Testi').first.click()
    else:
        page.get_by_text('Testi').first.click()
    page.locator('button', has_text=re.compile(r'^\s*Datastore\s*$')).first.click()
    page.get_by_text('backupsrv').first.click()
    page.get_by_text('Content: backupsrv').first.wait_for(timeout=8000)
    page.wait_for_timeout(400)
    return page


def _body(app):
    return app.server.bodies.get('/api/clusters/c1/backup-restore/batch', [])


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_restore_several_into_new_guests(open_app, layout):
    app = open_app(_restore_reads(), layout=layout)
    page = _open_storage(app, layout)
    page.locator('[data-br-open]').click()
    page.locator('[data-br-pick]').wait_for(timeout=5000)
    # one row per guest, the newest backup preselected, an older one to choose
    assert page.locator('[data-br-row]').evaluate_all('rs => rs.map(r => r.dataset.brRow)') == ['100', '101', '200']
    assert page.locator('[data-br-backup="100"] option').count() == 2
    assert page.locator('[data-br-next]').is_disabled()
    page.locator('[data-br-check="100"]').check()
    page.locator('[data-br-backup="100"]').select_option(CONTENT[1]['volid'])
    page.locator('[data-br-check="200"]').check()
    assert page.locator('[data-br-count]').inner_text() == '2 picked'
    # the filter narrows what is shown, not what is picked
    page.locator('[data-br-filter]').fill('db0')
    assert page.locator('[data-br-row]').evaluate_all('rs => rs.map(r => r.dataset.brRow)') == ['101']
    page.locator('[data-br-filter]').fill('')
    _shot(page, f'br_pick_{layout}.png')
    page.locator('[data-br-next]').click()
    page.locator('[data-br-options]').wait_for(timeout=5000)
    first = page.locator('[data-br-first]')
    deadline = time.time() + 4
    while time.time() < deadline and first.input_value() != '900':
        page.wait_for_timeout(100)
    assert first.input_value() == '900'
    # the target storages that hold disks, on the node picked
    assert page.locator('[data-br-storage] option').evaluate_all('os => os.map(o => o.value)') == ['', 'local-zfs']
    page.locator('[data-br-storage]').select_option('local-zfs')
    page.locator('[data-br-how]').select_option('3')
    first.fill('950')
    _shot(page, f'br_options_{layout}.png')
    page.locator('[data-br-start]').click()
    page.locator('[data-br-run-row="100"]').wait_for(timeout=5000)
    assert _body(app) == [{'items': [{'volid': CONTENT[1]['volid']}, {'volid': CONTENT[3]['volid']}],
                           'mode': 'new', 'target_node': 'pve1', 'run': 'parallel', 'parallel': 3,
                           'target_storage': 'local-zfs', 'first_vmid': 950}]
    row = page.locator('[data-br-run-row="100"]')
    assert row.get_attribute('data-state') == 'restoring' and '100 > 900' in row.inner_text()
    assert page.locator('[data-br-run-row="200"]').get_attribute('data-state') == 'wait'
    assert 'closing this window does not stop it' in page.locator('[data-testid="batch-restore-modal"]').inner_text()
    _shot(page, f'br_run_{layout}.png')
    # the rest is cancelled only after asking
    page.locator('[data-br-cancel]').click()
    page.locator('[data-br-cancel-ask]').wait_for(timeout=3000)
    assert not [c for c in app.server.calls if c[1].endswith('/cancel')]
    page.locator('[data-br-cancel-yes]').click()
    page.get_by_text('Cancelled by admin').first.wait_for(timeout=5000)
    assert ('POST', f'/api/batch-restores/{RUN_ID}/cancel') in app.server.calls
    assert page.locator('[data-br-cancel]').count() == 0
    assert not app.errors, app.errors


def test_runtime_cloud_restores_several_from_its_storage_config(open_app):
    app = open_app(_restore_reads(), layout='cloud')
    page = app.page
    page.locator('.cloud-shell').get_by_text('Storage Config', exact=True).first.click()
    page.get_by_text('backupsrv').first.click()
    page.locator('[data-br-open]').wait_for(timeout=8000)
    page.locator('[data-br-open]').click()
    page.locator('[data-br-check="101"]').check()
    page.locator('[data-br-next]').click()
    page.locator('[data-br-start]').click()
    page.locator('[data-br-run-row="100"]').wait_for(timeout=5000)
    assert _body(app)[0]['items'] == [{'volid': CONTENT[2]['volid']}]
    assert not app.errors, app.errors


def test_runtime_overwriting_wants_the_box_ticked(open_app):
    app = open_app(_restore_reads(), layout='modern')
    page = _open_storage(app, 'modern')
    page.locator('[data-br-open]').click()
    page.locator('[data-br-check="101"]').check()
    page.locator('[data-br-next]').click()
    page.locator('[data-br-mode="overwrite"]').click()
    assert page.locator('[data-br-mode="overwrite"]').get_attribute('data-on') == '1'
    assert page.locator('[data-br-first]').count() == 0
    assert page.locator('[data-br-start]').is_disabled()
    assert '1 existing guest(s) are replaced' in page.locator('[data-br-confirm-row]').inner_text()
    page.locator('[data-br-confirm]').check()
    assert not page.locator('[data-br-start]').is_disabled()
    page.locator('[data-br-start]').click()
    page.locator('[data-br-run]').wait_for(timeout=5000)
    (body,) = _body(app)
    assert body['mode'] == 'overwrite' and body['confirm'] is True and 'first_vmid' not in body
    assert body['items'] == [{'volid': CONTENT[2]['volid']}]
    assert not app.errors, app.errors


def test_runtime_a_refused_batch_names_each_backup(open_app):
    refused = (403, {'error': '1 of these backups cannot be restored by you - nothing was started',
                     'refused': [{'volid': CONTENT[2]['volid'], 'vmid': 101, 'error': 'Permission denied for source backup'}]})
    app = open_app(_restore_reads(post=refused), layout='modern')
    page = _open_storage(app, 'modern')
    page.locator('[data-br-open]').click()
    page.locator('[data-br-check="101"]').check()
    page.locator('[data-br-next]').click()
    page.locator('[data-br-start]').click()
    page.locator('[data-br-refused]').wait_for(timeout=5000)
    assert 'nothing was started' in page.locator('[data-br-error]').inner_text()
    assert page.locator('[data-br-refused]').inner_text() == '101: Permission denied for source backup'
    # still on the options, nothing to follow
    assert page.locator('[data-br-options]').count() == 1
    assert not app.errors, app.errors


def test_runtime_the_batches_before_open_from_the_storage(open_app):
    app = open_app(_restore_reads(), layout='modern')
    page = _open_storage(app, 'modern')
    page.locator('[data-br-recent-open]').click()
    page.locator('[data-br-runs]').wait_for(timeout=5000)
    page.locator('[data-br-recent]').first.wait_for(timeout=5000)
    # the batches of this cluster only
    assert page.locator('[data-br-recent]').evaluate_all('rs => rs.map(r => r.dataset.brRecent)') == [RUN_ID]
    assert '2 done, 0 failed of 2' in page.locator('[data-br-recent]').first.inner_text()
    page.locator('[data-br-recent]').first.click()
    page.locator('[data-br-run-row="100"]').wait_for(timeout=5000)
    assert not app.errors, app.errors


def test_runtime_a_standby_restores_nothing_and_still_shows_the_batches(open_app):
    app = open_app(_restore_reads(), layout='modern', role='standby')
    page = _open_storage(app, 'modern')
    assert page.locator('[data-br-open]').count() == 0
    assert page.locator('[data-br-recent-open]').count() == 1
    page.locator('[data-br-recent-open]').click()
    page.locator('[data-br-recent]').first.click()
    page.locator('[data-br-run-row="100"]').wait_for(timeout=5000)
    # may_cancel says yes, the standby does not offer it
    assert page.locator('[data-br-cancel]').count() == 0
    assert not app.errors, app.errors


def test_runtime_a_caller_without_vm_backup_gets_no_restore(open_app):
    app = open_app(_restore_reads(), layout='modern', admin=False,
                   permissions=['vm.view', 'cluster.view', 'storage.view', 'backup.view'])
    page = _open_storage(app, 'modern')
    assert page.locator('[data-br-open]').count() == 0
    assert page.locator('[data-br-recent-open]').count() == 1
    assert not app.errors, app.errors


def test_runtime_the_restore_dialog_speaks_german(open_app):
    app = open_app(_restore_reads(), layout='modern', language='de')
    page = app.page
    page.get_by_text('Testi').first.click()
    page.locator('button', has_text=re.compile(r'^\s*Datenspeicher\s*$|^\s*Datastore\s*$')).first.click()
    page.get_by_text('backupsrv').first.click()
    page.locator('[data-br-open]').wait_for(timeout=8000)
    assert 'Mehrere wiederherstellen' in page.locator('[data-br-open]').inner_text()
    page.locator('[data-br-open]').click()
    text = page.locator('[data-testid="batch-restore-modal"]').inner_text()
    assert 'Mehrere Backups wiederherstellen' in text and '0 gewählt' in text
    assert not app.errors, app.errors
