"""The classic Storage Balancing tab and the Datastore tab's sidebar pick, in the browser.

  * a status that could not be read (refused, failed, the wrong shape, or a group whose members
    could not be compared) is said to be so, never "Balanced"; the answer for a group picked
    before does not stay on screen under the next one
  * a member left out of the comparison says why, a container volume that cannot move now has
    no Migrate button but the reason
  * Enabled, Auto-Balance, the threshold and the tolerance go back to the value the server
    confirmed last when it refuses a change, and say why; an answer that is overtaken by a later
    change of the same field does not decide what is shown; a threshold and a tolerance change
    made right after each other are both sent
  * the create dialog explains the tolerance in the worker's terms and starts again at 5
  * a refused migration, added or removed storage says so, also when the answer is no JSON or
    there is none; a storage whose content could not be read shows that, not the content of
    the storage picked before
  * the Auto-Balance Active box is shown only for a group that is enabled
  * a storage picked in the sidebar opens at once, and the 15 s refresh neither undoes a storage
    picked in the tab nor the sub tab

Source checks read web/src and the bundle; the runtime tests drive the built bundle in headless
Chromium (and Firefox for the new boxes) against the fake server of tests/test_ha_ui.py. They skip
where Playwright is not installed. The routes behind them: tests/test_storage_balancing_members.py.
NS Nov 2026
"""
import json
import os
import re
import time

import pytest

from test_ha_ui import CLUSTER, NODE_METRICS, SSE_TOKEN, VM, _App, _FakeServer, _toasts, _wait_for_call

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHOTS = os.environ.get('PEGAPROX_SHOTS', '')
LANGS = ['de', 'en', 'zh', 'pl', 'fr', 'es', 'pt', 'ko', 'it', 'ru']
KEYS = ['sbStatusUnreadable', 'sbCannotJudge', 'sbCannotJudgeHint', 'sbMemberUnreadable', 'sbMemberMissing',
        'sbMemberDisabled', 'sbMemberInactive', 'sbMemberUnavailable', 'sbMemberNoSize', 'sbMemberLocal',
        'sbCtRunning', 'storageToleranceDesc']
GiB = 2 ** 30


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def _between(src, start, end):
    s = src.index(start)
    return src[s:src.index(end, s) + len(end)]


def _blocks():
    storage = _read('web', 'src', 'storage.js')
    return [
        _between(storage, 'the cluster effect runs before the shared data effect', '}, [initialStorage, initialNode, initialPick, datastores]);'),
        _between(storage, '// a refused, failed or empty status read', 'const createStorageCluster'),
        _between(storage, '// The switches and sliders showed', 'const deleteStorageCluster'),
        _between(storage, 'const addStorageToCluster', 'const handleDelete'),
        _between(storage, ') : contentError ? (', ') : storageContent.length === 0 ? ('),
        _between(storage, '// the picked balancing group as configured', 'if (loading) {'),
        _between(storage, '{/* Storage Cluster Details */}', '{/* Create Storage Cluster Modal */}'),
    ]


# --- source --------------------------------------------------------------------------------

def test_every_new_string_is_in_every_language_once_next_to_the_balancing_keys():
    tr = _read('web', 'src', 'translations.js')
    starts = [(m.group(1), m.start()) for m in re.finditer(r'^            ([a-z][a-z]): \{', tr, re.M)]
    assert [s[0] for s in starts] == LANGS
    for i, (lang, at) in enumerate(starts):
        block = tr[at:starts[i + 1][1] if i + 1 < len(starts) else len(tr)]
        lines = [ln.strip().split(':', 1)[0] for ln in block.splitlines()]
        at_key = lines.index('storageBalanced')
        assert lines[at_key + 1:at_key + 1 + len(KEYS)] == KEYS, lang
        for key in KEYS:
            assert len(re.findall(rf'^\s*{key}:', block, re.M)) == 1, (lang, key)
    en = dict(re.findall(r"^\s*(sb[A-Za-z]+|storageToleranceDesc): '(.*)',$", tr[starts[1][1]:starts[2][1]], re.M))
    for lang, at in starts:
        nxt = [s for s in starts if s[1] > at]
        block = tr[at:nxt[0][1] if nxt else len(tr)]
        for key in KEYS:
            v = re.search(rf"^\s*{key}: '(.*)',$", block, re.M).group(1)
            assert set(re.findall(r'\{(\w+)\}', v)) == set(re.findall(r'\{(\w+)\}', en[key])), (lang, key)
            if lang != 'en':
                assert v != en[key], (lang, key)
    assert "{ code: 'de', flag: '🇦🇹'" in _read('web', 'src', 'contexts.js')


def test_the_content_read_error_is_in_every_language_next_to_storage_empty():
    tr = _read('web', 'src', 'translations.js')
    starts = [m.start() for m in re.finditer(r'^            [a-z][a-z]: \{', tr, re.M)] + [len(tr)]
    seen = []
    for at, end in zip(starts, starts[1:]):
        lines = [ln.strip() for ln in tr[at:end].splitlines()]
        keys = [ln.split(':', 1)[0] for ln in lines]
        assert keys.count('storageContentUnreadable') == 1
        assert keys[keys.index('storageEmpty') + 1] == 'storageContentUnreadable'
        seen.append(lines[keys.index('storageContentUnreadable')])
    assert len(set(seen)) == len(LANGS), seen


def test_every_used_key_exists():
    used = set()
    for block in _blocks():
        used |= set(re.findall(r"t\('((?:sb|storageTolerance)[A-Za-z]*)'\)", block))
    assert used == set(KEYS), sorted(used ^ set(KEYS))
    assert "t('storageContentUnreadable')" in ''.join(_blocks())


def test_no_dash_or_handle_in_what_this_change_added():
    for block in _blocks():
        assert chr(0x2014) not in block and chr(0x2013) not in block, block[:120]
    tr = _read('web', 'src', 'translations.js')
    for key in KEYS:
        for v in re.findall(rf'^\s*{key}: (.*),$', tr, re.M):
            assert chr(0x2014) not in v and chr(0x2013) not in v, (key, v)


def test_the_icons_exist():
    icons = _read('web', 'src', 'icons.js')
    have = set(re.findall(r'^\s{12}([A-Z][A-Za-z0-9]*):', icons, re.M))
    used = set()
    for block in _blocks():
        used |= set(re.findall(r'Icons\.([A-Za-z]+)', block))
    assert used and used <= have, sorted(used - have)


def test_every_class_is_in_the_static_tailwind_build():
    from test_ha_ui import _classes
    shell = '\n'.join(line for line in _read('web', 'index.html.original').split('\n')
                      if 'data-corp-theme="light"' not in line)
    css = _read('static', 'css', 'tailwind.min.css') + shell
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    names = set()
    for block in _blocks():
        names |= _classes(block)
    missing = sorted(n for n in names if n not in have and n not in {'active', 'custom-slider', 'group'})
    assert not missing, f'not in static/css/tailwind.min.css: {missing}'


def test_the_sidebar_hands_its_selection_to_the_tab():
    dash = _read('web', 'src', 'dashboard.js')
    assert 'initialPick={selectedSidebarDatastore}' in dash


def test_the_bundle_was_rebuilt():
    built = _read('web', 'index.html')
    for needle in ('sbStatusUnreadable', 'sbCannotJudgeHint', 'data-sb-status', 'data-sb-blocked', 'pendingPickRef',
                   'initialPick', 'storageToleranceDesc', 'data-sb-member', 'sbMemberUnavailable', 'settingState',
                   'storageContentUnreadable', 'data-sb-read-error', 'data-content-error'):
        assert needle in built, needle


# --- runtime -------------------------------------------------------------------------------

def _ds(name, pct, shared=1, **kw):
    total = 100 * GiB
    d = {'storage': name, 'type': 'rbd' if shared else 'dir', 'content': 'images,rootdir', 'shared': shared,
         'total': total, 'used': int(total * pct / 100), 'avail': int(total * (100 - pct) / 100), 'active': 1,
         'enabled': 1, 'used_fraction': pct / 100, 'active_on': ['pve1'], 'inactive_on': []}
    d.update(kw)
    return d


DATASTORES = {'shared': [_ds('ceph-a', 80), _ds('ceph-b', 30)], 'local': {'pve1': [_ds('local', 10, shared=0)]},
              'nodes': ['pve1']}


def _group(gid='g1', name='fast', **kw):
    g = {'id': gid, 'name': name, 'storages': ['ceph-a', 'ceph-b'], 'threshold': 20, 'tolerance': 7, 'enabled': True,
         'auto_balance': False, 'max_concurrent': 1, 'check_interval': 3600, 'last_auto_run': None}
    g.update(kw)
    return g


def _member(name, pct=None, state='ok', shared=True):
    usable = state == 'ok'
    return {'storage': name, 'type': 'rbd', 'total': 100 * GiB if usable else None,
            'used': int(pct * GiB) if usable else None, 'avail': int((100 - pct) * GiB) if usable else None,
            'usage_percent': pct if usable else None, 'usable': usable, 'state': state, 'node': 'pve1', 'shared': shared}


def _rec(vmid, name, vm_type='qemu', movable=True):
    r = {'type': 'move_disk', 'vmid': vmid, 'vm_name': name, 'vm_type': vm_type, 'vm_status': 'running',
         'disk': 'scsi0' if vm_type == 'qemu' else 'rootfs', 'source': 'ceph-a', 'target': 'ceph-b',
         'disk_size': 8 * GiB, 'movable': movable, 'reason': 'Balance: ceph-a (80.0%) to ceph-b (30.0%)'}
    if not movable:
        r.update(blocked='ct_running', blocked_reason='Proxmox VE moves the volume of a container only while the container is stopped')
    return r


def _status(gid='g1', name='fast', storages=None, imbalance=50.0, recs=None, **kw):
    st = {'id': gid, 'name': name, 'enabled': True, 'threshold': 20, 'tolerance': 7,
          'storages': storages if storages is not None else [_member('ceph-a', 80.0), _member('ceph-b', 30.0)],
          'imbalance': imbalance, 'recommendations': recs if recs is not None else []}
    st.update(kw)
    return st


def _reads(groups=None, status=None, over=None):
    groups = groups if groups is not None else [_group()]
    extra = dict(SSE_TOKEN)
    extra.update({
        ('GET', '/api/clusters/c1/datastores'): (200, DATASTORES),
        ('GET', '/api/clusters/c1/storage-clusters'): (200, groups),
        ('GET', '/api/clusters/c1/datastores/ceph-a/content'): (200, [
            {'volid': 'ceph-a:vm-100-disk-0', 'content': 'images', 'format': 'raw', 'size': 8 * GiB, 'vmid': 100}]),
        ('GET', '/api/clusters/c1/datastores/ceph-b/content'): (200, [
            {'volid': 'ceph-b:vm-101-disk-0', 'content': 'images', 'format': 'raw', 'size': 4 * GiB, 'vmid': 101}]),
    })
    for g in groups:
        extra[('GET', f"/api/clusters/c1/storage-clusters/{g['id']}/status")] = (200, (status or {}).get(g['id'], _status(g['id'], g['name'])))
        extra[('PUT', f"/api/clusters/c1/storage-clusters/{g['id']}")] = (200, g)
    extra.update(over or {})
    return extra


@pytest.fixture(scope='module')
def engines():
    """One Playwright for the module (a second sync one does not start next to it), each
    browser launched when a test first asks for it."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        pytest.skip('Playwright is not installed')
    try:
        pw = sync_playwright().start()
    except Exception as e:
        pytest.skip(f'Playwright does not start here: {e}')
    launched = {}

    def get(name):
        if name not in launched:
            try:
                launched[name] = getattr(pw, name).launch(headless=True)
            except Exception as e:
                pytest.skip(f'no {name} for Playwright: {e}')
        return launched[name]
    yield get
    for br in launched.values():
        br.close()
    pw.stop()


@pytest.fixture
def open_app(engines):
    apps = []

    def _open(extra=None, engine='chromium', clock=False, **kw):
        kw.setdefault('role', 'standalone')
        app = _App(engines(engine), _FakeServer(clusters=[CLUSTER], resources=[VM], metrics=NODE_METRICS,
                                                extra=extra if extra is not None else _reads(), **kw), clock=clock)
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _shot(page, name):
    if SHOTS:
        os.makedirs(SHOTS, exist_ok=True)
        page.screenshot(path=os.path.join(SHOTS, name), full_page=False)


def _open_cluster(app, layout):
    page = app.page
    if layout == 'corporate':
        page.locator('.corp-tree-item', has_text='Testi').first.click()
    else:
        page.get_by_text('Testi').first.click()
    page.locator('button', has_text=re.compile(r'^\s*Datastore\s*$')).first.click()
    return page


def _balancing(app, layout, group='fast', gid='g1'):
    page = _open_cluster(app, layout)
    page.locator('button', has_text='Storage Balancing').first.click()
    page.locator('div.cursor-pointer', has_text=group).first.click()
    assert _wait_for_call(app, ('GET', f'/api/clusters/c1/storage-clusters/{gid}/status'), seconds=8)
    page.wait_for_timeout(500)
    return page


def _detail(page):
    return page.locator('.lg\\:col-span-2').first


def _toggle(page, label):
    return page.locator('label', has_text=label).locator('.toggle-switch').first


def _set_range(page, index, value):
    page.locator('input[type="range"]').nth(index).evaluate(
        """(el, v) => { const set = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
                        set.call(el, String(v)); el.dispatchEvent(new Event('input', { bubbles: true })); }""", value)


@pytest.mark.parametrize('engine', ['chromium', 'firefox'])
@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_a_group_whose_members_cannot_be_compared_is_not_balanced(open_app, layout, engine):
    st = _status(storages=[_member('ceph-a', 80.0), _member('ceph-b', state='inactive')], imbalance=None)
    app = open_app(_reads(status={'g1': st}), layout=layout, engine=engine)
    page = _balancing(app, layout)
    detail = _detail(page)
    text = detail.inner_text()
    assert 'Balanced' not in text and 'well balanced' not in text, text
    assert page.locator('[data-sb-status="unknown"]').count() == 1
    assert 'Cannot be judged' in text and 'Fewer than two member storages' in text
    member = page.locator('[data-sb-member="ceph-b"]')
    assert member.get_attribute('data-state') == 'inactive'
    assert 'not active on pve1' in member.inner_text() and '%' not in member.inner_text()
    assert '80%' in page.locator('[data-sb-member="ceph-a"]').inner_text()
    # nothing sticks out of its card
    assert page.evaluate('() => document.documentElement.scrollWidth <= window.innerWidth')
    _shot(page, f'sb_unjudged_{layout}_{engine}.png')
    assert not app.errors, app.errors


@pytest.mark.parametrize('engine', ['chromium', 'firefox'])
@pytest.mark.parametrize('answer', [(500, {'error': 'Failed to get storage cluster status'}), (200, [])])
def test_runtime_a_status_that_could_not_be_read_says_so(open_app, answer, engine):
    app = open_app(_reads(over={('GET', '/api/clusters/c1/storage-clusters/g1/status'): answer}),
                   layout='modern', engine=engine)
    page = _balancing(app, 'modern')
    text = _detail(page).inner_text()
    assert 'Balanced' not in text and 'well balanced' not in text, text
    assert 'The balancing status could not be read' in text, text
    box = page.locator('[data-sb-status="unreadable"]')
    if answer[0] == 500:
        assert 'Failed to get storage cluster status' in box.inner_text()
    # the configured members are listed as not read, and the switches stay usable
    for name in ('ceph-a', 'ceph-b'):
        assert page.locator(f'[data-sb-member="{name}"]').get_attribute('data-state') == 'unreadable'
    assert _toggle(page, 'Auto-Balance').is_visible()
    _shot(page, f'sb_unreadable_{answer[0]}_{engine}.png')
    assert not app.errors, app.errors


def test_runtime_the_next_groups_failed_read_does_not_show_the_previous_group(open_app):
    groups = [_group('g1', 'fast'), _group('g2', 'slow')]
    app = open_app(_reads(groups, over={('GET', '/api/clusters/c1/storage-clusters/g2/status'): (429, {'error': 'API rate limit exceeded, please try again'})}),
                   layout='modern')
    page = _balancing(app, 'modern', 'fast')
    assert 'Action Recommended' in _detail(page).inner_text()
    page.locator('div.cursor-pointer', has_text='slow').first.click()
    page.wait_for_timeout(800)
    # not fast's figures under slow's selection
    head = _detail(page).locator('h3').first.inner_text()
    assert head == 'slow'
    assert 'Action Recommended' not in _detail(page).inner_text()
    assert 'API rate limit exceeded' in _detail(page).inner_text()
    assert page.locator('[data-sb-member="ceph-a"]').get_attribute('data-state') == 'unreadable'


def test_runtime_a_running_containers_volume_has_no_migrate_button(open_app):
    st = _status(recs=[_rec(100, 'web01'), _rec(300, 'ct-db', 'lxc', movable=False)])
    app = open_app(_reads(status={'g1': st}), layout='corporate')
    page = _balancing(app, 'corporate')
    # one Migrate button, the VM's; the container's row says why it has none
    migrate = _detail(page).locator('button', has_text=re.compile(r'^\s*Migrate\s*$'))
    assert migrate.count() == 1
    ct = page.locator('[data-sb-blocked="ct_running"]')
    assert ct.count() == 1
    assert 'only while it is stopped' in ct.inner_text()
    assert not app.errors, app.errors


def test_runtime_a_refused_auto_balance_switch_goes_back_and_says_why(open_app):
    app = open_app(_reads(over={('PUT', '/api/clusters/c1/storage-clusters/g1'): (403, {'error': 'Access denied'})}),
                   layout='modern')
    page = _balancing(app, 'modern')
    toggle = _toggle(page, 'Auto-Balance')
    assert 'active' not in toggle.get_attribute('class')
    toggle.click()
    assert _wait_for_call(app, ('PUT', '/api/clusters/c1/storage-clusters/g1'))
    page.wait_for_timeout(400)
    assert app.server.bodies['/api/clusters/c1/storage-clusters/g1'][-1] == {'auto_balance': True}
    assert 'active' not in toggle.get_attribute('class')
    assert 'Auto-Balance Active' not in _detail(page).inner_text()
    assert any('Access denied' in x for x in _toasts(page)), _toasts(page)


def test_runtime_the_enabled_switch_moves_when_the_server_takes_it(open_app):
    app = open_app(_reads(over={('PUT', '/api/clusters/c1/storage-clusters/g1'): (200, _group(enabled=False))}),
                   layout='modern')
    page = _balancing(app, 'modern')
    toggle = _toggle(page, 'Enabled')
    assert 'active' in toggle.get_attribute('class')
    toggle.click()
    assert _wait_for_call(app, ('PUT', '/api/clusters/c1/storage-clusters/g1'))
    page.wait_for_timeout(400)
    assert 'active' not in toggle.get_attribute('class')
    assert not _toasts(page)


def test_runtime_a_refused_threshold_goes_back_and_says_why(open_app):
    app = open_app(_reads(over={('PUT', '/api/clusters/c1/storage-clusters/g1'): (403, {'error': 'Access denied'})}),
                   layout='corporate')
    page = _balancing(app, 'corporate')
    slider = page.locator('input[type="range"]').nth(0)
    assert slider.input_value() == '20'
    _set_range(page, 0, 35)
    assert slider.input_value() == '35'
    assert _wait_for_call(app, ('PUT', '/api/clusters/c1/storage-clusters/g1'))
    page.wait_for_timeout(400)
    assert app.server.bodies['/api/clusters/c1/storage-clusters/g1'][-1] == {'threshold': 35}
    assert slider.input_value() == '20'
    assert any('Access denied' in x for x in _toasts(page)), _toasts(page)


def test_runtime_the_tolerance_is_the_stored_one_and_a_refusal_puts_it_back(open_app):
    app = open_app(_reads(over={('PUT', '/api/clusters/c1/storage-clusters/g1'): (403, {'error': 'Access denied'})}),
                   layout='modern')
    page = _balancing(app, 'modern')
    tol = page.locator('input[type="range"]').nth(1)
    assert tol.input_value() == '7'
    _set_range(page, 1, 12)
    assert _wait_for_call(app, ('PUT', '/api/clusters/c1/storage-clusters/g1'))
    page.wait_for_timeout(400)
    assert app.server.bodies['/api/clusters/c1/storage-clusters/g1'][-1] == {'tolerance': 12}
    assert tol.input_value() == '7'
    assert any('Access denied' in x for x in _toasts(page)), _toasts(page)
    # what the value does, in the worker's terms
    assert 'threshold plus this value' in _detail(page).inner_text()


def test_runtime_a_threshold_and_a_tolerance_change_are_both_sent(open_app):
    app = open_app(layout='modern')
    page = _balancing(app, 'modern')
    _set_range(page, 0, 30)
    _set_range(page, 1, 9)
    page.wait_for_timeout(1200)
    sent = [b for b in app.server.bodies.get('/api/clusters/c1/storage-clusters/g1', []) if b]
    assert {'threshold': 30} in sent and {'tolerance': 9} in sent, sent


class _HeldPuts:
    """PUTs of one URL held back until the test answers them, in any order it likes."""

    def __init__(self, page, path):
        self.page, self.held = page, []
        page.route(f'**{path}', self._take)

    def _take(self, route):
        if route.request.method != 'PUT':
            return route.fallback()
        self.held.append((route, json.loads(route.request.post_data or '{}')))

    def wait(self, n, seconds=6):
        deadline = time.time() + seconds
        while time.time() < deadline and len(self.held) < n:
            self.page.wait_for_timeout(100)
        assert len(self.held) >= n, [b for _, b in self.held]

    def answer(self, i, status, body):
        self.held[i][0].fulfill(status=status, body=json.dumps(body), headers={'Content-Type': 'application/json'})
        self.page.wait_for_timeout(400)


def _two_threshold_changes(app):
    page = _balancing(app, 'modern')
    held = _HeldPuts(page, '/api/clusters/c1/storage-clusters/g1')
    slider = page.locator('input[type="range"]').nth(0)
    assert slider.input_value() == '20'
    _set_range(page, 0, 35)
    held.wait(1)
    # the second change starts while the first one is still on its way
    _set_range(page, 0, 40)
    held.wait(2)
    assert [b for _, b in held.held] == [{'threshold': 35}, {'threshold': 40}]
    return page, held, slider


def test_runtime_two_refused_changes_end_on_the_value_the_server_kept(open_app):
    app = open_app(layout='modern')
    page, held, slider = _two_threshold_changes(app)
    held.answer(0, 403, {'error': 'Access denied'})
    held.answer(1, 403, {'error': 'Access denied'})
    # not 35, which was never saved
    assert slider.input_value() == '20'
    assert any('Access denied' in x for x in _toasts(page)), _toasts(page)


def test_runtime_a_late_answer_to_an_older_change_does_not_overwrite_the_newer_one(open_app):
    app = open_app(layout='modern')
    page, held, slider = _two_threshold_changes(app)
    held.answer(1, 200, _group(threshold=40))
    held.answer(0, 200, _group(threshold=35))
    assert slider.input_value() == '40'
    assert not _toasts(page)


def test_runtime_a_refused_newer_change_goes_back_to_what_the_older_one_saved(open_app):
    app = open_app(layout='modern')
    page, held, slider = _two_threshold_changes(app)
    held.answer(0, 200, _group(threshold=35))
    held.answer(1, 403, {'error': 'Access denied'})
    assert slider.input_value() == '35'
    assert any('Access denied' in x for x in _toasts(page)), _toasts(page)


def test_runtime_the_create_dialog_explains_the_tolerance_and_starts_again_at_5(open_app):
    app = open_app(_reads(over={('POST', '/api/clusters/c1/storage-clusters'): (201, _group('g9', 'new'))}),
                   layout='modern')
    page = _open_cluster(app, 'modern')
    page.locator('button', has_text='Storage Balancing').first.click()
    page.locator('div.cursor-pointer', has_text='fast').first.wait_for(timeout=5000)

    def dialog():
        page.locator('button[title="Create Cluster"]:visible').first.click()
        box = page.locator('div.fixed.inset-0', has_text='Create Storage Cluster').first
        box.wait_for(timeout=5000)
        return box
    box = dialog()
    # the node balancing text said "0 = disabled", which is not what 0 does here
    assert 'threshold plus this value' in box.inner_text(), box.inner_text()
    assert 'ping-pong' not in box.inner_text()
    box.locator('input[type="text"]').first.fill('new')
    for name in ('ceph-a', 'ceph-b'):
        box.locator('label', has_text=name).locator('input[type="checkbox"]').check()
    tol = box.locator('input[type="range"]').nth(1)
    tol.evaluate("""(el) => { const set = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
                              set.call(el, '12'); el.dispatchEvent(new Event('input', { bubbles: true })); }""")
    assert tol.input_value() == '12'
    reads = app.server.calls.count(('GET', '/api/clusters/c1/storage-clusters'))
    box.locator('button', has_text=re.compile(r'^\s*Create\s*$')).click()
    assert _wait_for_call(app, ('POST', '/api/clusters/c1/storage-clusters'))
    # the list is read again after the create. The fake server keeps {} for that read under the
    # same path, so [-1] was what was sent only as long as the read had not come yet
    for _ in range(50):
        if app.server.calls.count(('GET', '/api/clusters/c1/storage-clusters')) > reads:
            break
        page.wait_for_timeout(100)
    sent = [b for b in app.server.bodies['/api/clusters/c1/storage-clusters'] if b]
    assert sent[-1]['tolerance'] == 12
    page.wait_for_timeout(500)
    box = dialog()
    assert box.locator('input[type="range"]').nth(1).input_value() == '5'
    assert not app.errors, app.errors


def _dialogs(page):
    seen = []

    def on(d):
        seen.append((d.type, d.message))
        d.accept()
    page.on('dialog', on)
    return seen


@pytest.mark.parametrize('failure', ['not_json', 'no_answer'])
def test_runtime_a_failed_migration_says_so(open_app, failure):
    app = open_app(_reads(status={'g1': _status(recs=[_rec(100, 'web01')])}), layout='modern')
    page = _balancing(app, 'modern')
    seen = _dialogs(page)

    def refuse(route):
        if failure == 'no_answer':
            return route.abort('connectionrefused')
        route.fulfill(status=502, body='<html><body>Bad Gateway</body></html>', headers={'Content-Type': 'text/html'})
    page.route('**/api/clusters/c1/storage-balancing/migrate', refuse)
    _detail(page).locator('button', has_text=re.compile(r'^\s*Migrate\s*$')).first.click()
    page.wait_for_timeout(1000)
    alerts = [m for kind, m in seen if kind == 'alert']
    assert alerts and 'Migration failed' in alerts[-1], seen
    if failure == 'not_json':
        assert 'HTTP 502' in alerts[-1], alerts


@pytest.mark.parametrize('engine', ['chromium', 'firefox'])
def test_runtime_a_storage_whose_content_could_not_be_read_shows_that_not_the_one_before(open_app, engine):
    app = open_app(_reads(over={('GET', '/api/clusters/c1/datastores/ceph-b/content'): (500, {'error': 'Proxmox VE did not answer'})}),
                   layout='modern', engine=engine)
    page = _open_cluster(app, 'modern')
    page.locator('div.rounded-lg.cursor-pointer', has_text='ceph-a').first.click()
    page.get_by_text('vm-100-disk-0').first.wait_for(timeout=5000)
    page.locator('div.rounded-lg.cursor-pointer', has_text='ceph-b').first.click()
    assert _wait_for_call(app, ('GET', '/api/clusters/c1/datastores/ceph-b/content'))
    page.wait_for_timeout(600)
    assert _shown(page) == 'ceph-b'
    box = page.locator('[data-content-error]')
    assert box.count() == 1
    assert 'could not be read' in box.inner_text() and 'Proxmox VE did not answer' in box.inner_text()
    assert page.get_by_text('vm-100-disk-0').count() == 0
    assert page.evaluate('() => document.documentElement.scrollWidth <= window.innerWidth')
    _shot(page, f'content_unreadable_{engine}.png')


@pytest.mark.parametrize('enabled', [True, False])
def test_runtime_the_auto_balance_box_needs_an_enabled_group(open_app, enabled):
    g = _group(auto_balance=True, enabled=enabled)
    app = open_app(_reads([g], status={'g1': _status(enabled=enabled)}), layout='modern')
    page = _balancing(app, 'modern')
    assert ('Auto-Balance Active' in _detail(page).inner_text()) is enabled


DATASTORES_3 = dict(DATASTORES, shared=DATASTORES['shared'] + [_ds('ceph-c', 50)])


@pytest.mark.parametrize('change', ['add', 'remove'])
def test_runtime_a_refused_member_change_says_why(open_app, change):
    storages = ['ceph-a', 'ceph-b'] if change == 'add' else ['ceph-a', 'ceph-b', 'ceph-c']
    st = _status(storages=[_member(n, 50.0) for n in storages])
    app = open_app(_reads([_group(storages=storages)], status={'g1': st},
                          over={('GET', '/api/clusters/c1/datastores'): (200, DATASTORES_3),
                                ('PUT', '/api/clusters/c1/storage-clusters/g1'): (403, {'error': 'Access denied'})}),
                   layout='modern')
    page = _balancing(app, 'modern')
    if change == 'add':
        _detail(page).locator('select').first.select_option('ceph-c')
    else:
        page.locator('[data-sb-member="ceph-c"] button').first.click()
    assert _wait_for_call(app, ('PUT', '/api/clusters/c1/storage-clusters/g1'))
    page.wait_for_timeout(500)
    assert any('Access denied' in x for x in _toasts(page)), _toasts(page)


@pytest.mark.parametrize('engine', ['chromium', 'firefox'])
@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_a_status_where_nothing_could_be_read_says_why(open_app, layout, engine):
    st = _status(storages=[_member('ceph-a', state='unreadable'), _member('ceph-b', state='unavailable')],
                 imbalance=None, read_error='No node of the cluster is online')
    app = open_app(_reads(status={'g1': st}), layout=layout, engine=engine)
    page = _balancing(app, layout)
    assert page.locator('[data-sb-read-error]').inner_text() == 'No node of the cluster is online'
    assert 'not available on any node that is online' in page.locator('[data-sb-member="ceph-b"]').inner_text()
    assert page.evaluate('() => document.documentElement.scrollWidth <= window.innerWidth')
    _shot(page, f'sb_read_error_{layout}_{engine}.png')
    assert not app.errors, app.errors


# --- the Datastore tab and the sidebar ------------------------------------------------------

def _sidebar_datastores(app):
    page = app.page
    page.locator('.corp-view-switcher button[title="Datastore View"]').click()
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.locator('.corp-tree-child', has_text='ceph-a').first.wait_for(timeout=8000)
    return page


def _shown(page):
    """The storage whose content the Browse tab shows."""
    el = page.locator('h3', has_text=re.compile(r'^\s*Content: ')).first
    return el.inner_text().split(':', 1)[1].strip() if el.count() else None


def _refresh(app, page):
    """Let the 15 s poll of the dashboard run once."""
    reads = len([c for c in app.server.calls if c == ('GET', '/api/clusters/c1/datastores')])
    page.clock.run_for(16000)
    page.wait_for_timeout(800)
    assert len([c for c in app.server.calls if c == ('GET', '/api/clusters/c1/datastores')]) > reads, 'no refresh ran'


def test_runtime_a_sidebar_pick_opens_at_once(open_app):
    app = open_app(layout='corporate', clock=True)
    page = _sidebar_datastores(app)
    page.locator('.corp-tree-child', has_text='ceph-a').first.click()
    # without waiting for the 15 s refresh
    page.wait_for_timeout(1500)
    assert _shown(page) == 'ceph-a'
    assert not app.errors, app.errors


def test_runtime_a_refresh_keeps_the_storage_picked_in_the_tab(open_app):
    app = open_app(layout='corporate', clock=True)
    page = _sidebar_datastores(app)
    page.locator('.corp-tree-child', has_text='ceph-a').first.click()
    page.wait_for_timeout(800)
    if _shown(page) != 'ceph-a':
        _refresh(app, page)
    assert _shown(page) == 'ceph-a'
    page.locator('div.rounded-lg.cursor-pointer', has_text='ceph-b').first.click()
    page.wait_for_timeout(500)
    assert _shown(page) == 'ceph-b'
    _refresh(app, page)
    assert _shown(page) == 'ceph-b'
    # the same storage clicked in the sidebar again opens it again
    page.locator('.corp-tree-child', has_text='ceph-a').first.click()
    page.wait_for_timeout(800)
    assert _shown(page) == 'ceph-a'
    assert not app.errors, app.errors


def test_runtime_a_refresh_keeps_the_sub_tab(open_app):
    app = open_app(layout='corporate', clock=True)
    page = _sidebar_datastores(app)
    page.locator('.corp-tree-child', has_text='ceph-a').first.click()
    page.wait_for_timeout(800)
    page.locator('button', has_text='Storage Balancing').first.click()
    page.locator('div.cursor-pointer', has_text='fast').first.wait_for(timeout=5000)
    _refresh(app, page)
    assert page.locator('.corp-tab-strip button.active', has_text='Storage Balancing').count() == 1
    assert page.locator('div.cursor-pointer', has_text='fast').first.is_visible()
