"""Disk and storage actions of a node in Corporate Redesigned, in the browser (round 10).

The classic node dialog (NodeModal) initializes a disk with GPT, wipes it, and creates an LVM volume
group, an LVM-Thin pool, a directory and a ZFS pool. Corporate Redesigned offers the same on
Configure > Disks (all of them), LVM, LVM-Thin and ZFS (each its own create), with the classic
requests: every test here drives the classic dialog (Modern layout) with the same answers and
compares method, URL and body. Initialize GPT and Wipe name the disk, say what is lost and arm only
on the device name typed in; the wipe also sends confirm_name, the field its route refuses to go
without. A create shows what will be created before it is sent. After an answer the disks read is
made again once; a refusal stays in the dialog with what the server said. A standby and a user
without storage.config see the actions off with why. A disk in use says why it has no Initialize
GPT and Wipe (the classic dialog offers them for unused disks only).

PEGAPROX_CR_BUNDLE=<file> serves another bundle (the counterproof). Skips without Playwright. LW Nov 2026
"""
import copy
import json
import re

import pytest

from test_corp_redesigned_guard_ui import NODE_DISKS, _GuardApp, _exact, _modern_cluster
from test_corp_redesigned_node_storage_ui import (DISKS, LVM, NODE, THIN, ZFS, _StoreServer, _open_cfg, _sec, _sub,
                                                  _wait_reads, browser, firefox, playwright)  # noqa: F401

# two more disks PVE lists as unused: one says so, one leaves 'used' out (both count in the classic dialog)
DISKS_FREE = copy.deepcopy(NODE_DISKS) + [
    {'devpath': '/dev/sde', 'type': 'ssd', 'size': 480103981056, 'model': 'SSD_480', 'serial': 'FREE0001', 'vendor': 'ATA     ',
     'health': 'PASSED', 'wearout': 99, 'used': 'unused', 'gpt': 0, 'rpm': 0, 'osdid': -1},
    {'devpath': '/dev/sdf', 'type': 'ssd', 'size': 480103981056, 'model': 'SSD_480', 'serial': 'FREE0002', 'vendor': 'ATA     ',
     'health': 'PASSED', 'wearout': 99, 'gpt': 0, 'rpm': 0, 'osdid': -1},
]
UPID = 'UPID:pve1:000A1B2C:0F00BA11:6720F000:diskinit:sdd:root@pam:'
W = {k: NODE + '/disks/' + k for k in ('initgpt', 'wipe', 'lvm', 'lvmthin', 'zfs', 'directory')}
OK = (200, {'success': True, 'task': UPID})
LISTS = (DISKS, LVM, THIN, ZFS)


class _DiskServer(_StoreServer):
    def __init__(self, routes=None, **kw):
        writes = {('POST', p): OK for p in W.values()}
        writes[('GET', DISKS)] = (200, DISKS_FREE)
        writes.update(routes or {})
        super().__init__(routes=writes, **kw)


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(layout='corporate-redesigned', viewport=(1600, 1000), br=None, **kw):
        app = _GuardApp(br or browser, _DiskServer(layout=layout, **kw), viewport=viewport)
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.close()


def _sent(app, n=1, path=None):
    for _ in range(60):
        got = [(m, p, json.loads(b) if b else None) for m, p, b in app.server.sent if path is None or p == path]
        if len(got) >= n:
            return got
        app.page.wait_for_timeout(100)
    raise AssertionError(f'expected {n} writes, got {app.server.sent}')


def _no_errors(app):
    assert not [e for e in app.errors if 'pageerror' in e], app.errors


# --- the classic dialog: what it sends ------------------------------------------------------------

def _classic(open_app):
    app = open_app(layout='modern')
    page = app.page
    page.on('dialog', lambda d: d.accept())
    _modern_cluster(page)
    page.locator('button[title="Node Configuration"]').first.click()
    page.locator('button', has_text=_exact('Disks')).last.click()
    page.get_by_text('/dev/sdf').first.wait_for(timeout=8000)
    return app


def _classic_row(page, dev):
    return page.locator('tr', has=page.locator('span.font-mono', has_text=_exact(dev))).first


def _classic_modal(page):
    return page.locator('div.fixed.inset-0', has=page.locator('h3', has_text='Create')).last


def _classic_send(open_app, action):
    app = _classic(open_app)
    page = app.page
    if action in ('initgpt', 'wipe'):
        _classic_row(page, '/dev/sdd').locator(f'button[title="{"Initialize GPT" if action == "initgpt" else "Wipe Disk"}"]').click()
        return _sent(app)[0]
    opener = {'lvm': 'Create LVM', 'lvmthin': 'Create LVM-Thin', 'directory': 'Directory', 'zfs': 'Create ZFS'}[action]
    page.locator('button', has_text=_exact(opener)).first.click()
    modal = _classic_modal(page)
    modal.wait_for(timeout=8000)
    if action in ('lvm', 'directory'):
        modal.locator('select').first.select_option('/dev/sde')
    if action == 'lvmthin':
        modal.locator('select').first.select_option('pve')
    if action == 'directory':
        modal.locator('select').nth(1).select_option('xfs')
    if action == 'zfs':
        for dev in ('/dev/sde', '/dev/sdf'):
            modal.locator('label', has_text=dev).locator('input[type="checkbox"]').check()
        modal.locator('select').nth(0).select_option('mirror')
        modal.locator('select').nth(1).select_option('zstd')
        modal.locator('select').nth(2).select_option('13')
        modal.locator('label', has_text='Add to').locator('input[type="checkbox"]').uncheck()
    modal.locator('input:not([type="checkbox"])').last.fill({'lvm': 'vg2', 'lvmthin': 'thin2', 'directory': 'dir2', 'zfs': 'tank2'}[action])
    modal.locator('button', has_text=_exact('Create')).click()
    return _sent(app)[0]


# --- the variant ----------------------------------------------------------------------------------

def _disks(app):
    page = app.page
    _open_cfg(page, 'disks')
    sec = _sec(page, 'disks')
    sec.locator('[data-cr-nd-row="sdf"]').wait_for(timeout=8000)
    page.wait_for_timeout(200)
    return sec


def _dialog(page, did):
    d = page.locator(f'[data-cr-upd-dialog="{did}"]')
    d.wait_for(timeout=5000)
    return d


def _variant_create(page, open_btn, action):
    open_btn.click()
    d = _dialog(page, f'do-new-{action}')
    if action in ('lvm', 'directory'):
        d.locator('[data-cr-do-field="device"]').select_option('/dev/sde')
    if action == 'lvmthin':
        d.locator('[data-cr-do-field="vgname"]').select_option('pve')
    if action == 'directory':
        d.locator('[data-cr-do-field="filesystem"]').select_option('xfs')
    if action == 'zfs':
        for dev in ('sde', 'sdf'):
            d.locator(f'[data-cr-do-dev="{dev}"]').check()
        d.locator('[data-cr-do-field="raidlevel"]').select_option('mirror')
        d.locator('[data-cr-do-field="compression"]').select_option('zstd')
        d.locator('[data-cr-do-field="ashift"]').select_option('13')
        d.locator('[data-cr-do-field="add_storage"] input').uncheck()
    assert d.locator('[data-cr-do-next]').is_disabled(), 'Review waits for a name, as the classic Create does'
    d.locator('[data-cr-do-field="name"]').fill({'lvm': 'vg2', 'lvmthin': 'thin2', 'directory': 'dir2', 'zfs': 'tank2'}[action])
    d.locator('[data-cr-do-next]').click()
    d.locator(f'[data-cr-do-review="{action}"]').wait_for(timeout=5000)
    return d


@pytest.mark.parametrize('action', ['lvm', 'lvmthin', 'directory', 'zfs'])
def test_runtime_a_new_storage_from_the_disks_tab_sends_the_classic_request(open_app, action):
    want = _classic_send(open_app, action)
    app = open_app()
    page = app.page
    sec = _disks(app)
    reads = [app.server.reads(p) for p in LISTS]
    d = _variant_create(page, sec.locator(f'[data-cr-do-create] [data-cr-do-new="{action}"]'), action)
    # what will be created, before anything is sent
    review = d.locator(f'[data-cr-do-review="{action}"]').inner_text()
    assert app.server.sent == []
    name = {'lvm': 'vg2', 'lvmthin': 'thin2', 'directory': 'dir2', 'zfs': 'tank2'}[action]
    assert name in review and 'pve1' in review
    if action == 'zfs':
        assert 'Mirror' in review and '/dev/sde, /dev/sdf' in review and 'Not added as storage' in review and 'zstd' in review.lower()
    if action == 'lvmthin':
        assert 'pve' in review
    else:
        assert d.locator('[data-cr-do-format]').count() == 1
    d.locator('[data-cr-do-go]').click()
    got = _sent(app)
    assert got == [want], (got, want)
    # the answer is shown, the lists are read again, once each
    sec.locator('[data-cr-do-done]').wait_for(timeout=8000)
    assert UPID in sec.locator('[data-cr-do-task]').inner_text()
    for p, n in zip(LISTS, reads):
        _wait_reads(app, p, n + 1)
    page.wait_for_timeout(400)
    assert [app.server.reads(p) for p in LISTS] == [n + 1 for n in reads]
    assert page.locator('[data-cr-upd-dialog]').count() == 0
    _no_errors(app)


@pytest.mark.parametrize('action,sub', [('lvm', 'lvm'), ('lvmthin', 'lvmthin'), ('zfs', 'zfs')])
def test_runtime_each_storage_tab_creates_its_own_kind(open_app, action, sub):
    want = _classic_send(open_app, action)
    app = open_app()
    page = app.page
    _open_cfg(page, sub)
    sec = _sec(page, sub)
    btn = sec.locator(f'.cr-nc-head [data-cr-do-new="{action}"]')
    btn.wait_for(timeout=8000)
    d = _variant_create(page, btn, action)
    d.locator('[data-cr-do-go]').click()
    assert _sent(app) == [want]
    sec.locator('[data-cr-do-done]').wait_for(timeout=8000)
    _no_errors(app)


@pytest.mark.parametrize('action', ['initgpt', 'wipe'])
def test_runtime_initialize_and_wipe_send_the_classic_request_after_the_typed_name(open_app, action):
    want = _classic_send(open_app, action)
    app = open_app()
    page = app.page
    sec = _disks(app)
    reads = [app.server.reads(p) for p in LISTS]
    attr = 'data-cr-do-gpt' if action == 'initgpt' else 'data-cr-do-wipe'
    btn = sec.locator(f'[{attr}="sdd"]')
    assert 'cr-btn-danger' in btn.get_attribute('class')
    assert btn.get_attribute('aria-label') == ('Initialize GPT on /dev/sdd' if action == 'initgpt' else 'Wipe /dev/sdd')
    btn.click()
    d = _dialog(page, f'nc-do-{action}')
    text = d.inner_text()
    assert '/dev/sdd' in text and 'pve1' in text and 'lost' in text and 'cannot be restored' in text
    go = d.locator(f'[data-cr-nc-confirm-go="do-{action}"]')
    assert 'cr-btn-danger' in go.get_attribute('class')
    box = d.locator('[data-cr-do-typename-input]')
    for wrong in ('', 'sd', 'sdd1', '/dev/sdd', 'SDD', 'sde'):
        box.fill(wrong)
        assert go.is_disabled(), wrong
    assert app.server.sent == []
    box.fill('sdd')
    assert go.is_enabled()
    go.click()
    got = _sent(app)
    if action == 'wipe':
        # the classic body, and confirm_name: the wipe route refuses to go without it (datacenter.py)
        assert got == [(want[0], want[1], {**want[2], 'confirm_name': want[2]['disk']})], (got, want)
    else:
        assert got == [want], (got, want)
    sec.locator('[data-cr-do-done]').wait_for(timeout=8000)
    for p, n in zip(LISTS, reads):
        _wait_reads(app, p, n + 1)
    assert page.locator('[data-cr-upd-dialog]').count() == 0
    _no_errors(app)


@pytest.mark.parametrize('where', ['gpt', 'create'])
def test_runtime_a_refusal_stays_in_the_dialog_with_the_reason(open_app, where):
    said = 'disk /dev/sdd is still in use by a mounted file system'
    route = W['initgpt'] if where == 'gpt' else W['lvm']
    app = open_app(routes={('POST', route): (500, {'error': said})})
    page = app.page
    sec = _disks(app)
    reads = app.server.reads(DISKS)
    if where == 'gpt':
        sec.locator('[data-cr-do-gpt="sdd"]').click()
        d = _dialog(page, 'nc-do-initgpt')
        d.locator('[data-cr-do-typename-input]').fill('sdd')
        d.locator('[data-cr-nc-confirm-go="do-initgpt"]').click()
    else:
        d = _variant_create(page, sec.locator('[data-cr-do-create] [data-cr-do-new="lvm"]'), 'lvm')
        d.locator('[data-cr-do-go]').click()
    d.locator('[data-cr-do-error]').wait_for(timeout=8000)
    assert said in d.locator('[data-cr-do-error]').inner_text()
    assert sec.locator('[data-cr-do-done]').count() == 0
    _wait_reads(app, DISKS, reads + 1)
    # no row was drawn for it: the list is what the read said
    assert sec.locator('[data-cr-nd-row]').count() == len(DISKS_FREE)
    assert len(app.server.sent) == 1
    _no_errors(app)


def test_runtime_a_disk_in_use_says_why_it_has_no_wipe(open_app):
    app = open_app()
    sec = _disks(app)
    for dev, used in (('nvme0n1', 'LVM'), ('sda', 'ZFS'), ('sdc', 'LVM')):
        assert sec.locator(f'[data-cr-do-gpt="{dev}"], [data-cr-do-wipe="{dev}"]').count() == 0, dev
        tag = sec.locator(f'[data-cr-do-inuse="{dev}"]')
        assert tag.inner_text() == 'In use' and f'({used})' in tag.get_attribute('title'), dev
    for dev in ('sdd', 'sde', 'sdf'):
        assert sec.locator(f'[data-cr-do-acts="{dev}"] button').count() == 2, dev
    line = sec.locator('[data-cr-do-unused]')
    assert line.get_attribute('data-cr-do-unused') == '3' and 'sdd, sde, sdf' in line.inner_text()
    _no_errors(app)


def test_runtime_no_unused_disk_and_no_volume_group_are_said_in_the_form(open_app):
    used = [dict(d, used='LVM') for d in DISKS_FREE]
    app = open_app(routes={('GET', DISKS): (200, used), ('GET', LVM): (200, {'leaf': 0, 'children': []})})
    page = app.page
    _open_cfg(page, 'disks')
    sec = _sec(page, 'disks')
    sec.locator('[data-cr-do-unused="0"]').wait_for(timeout=8000)
    sec.locator('[data-cr-do-create] [data-cr-do-new="zfs"]').click()
    d = _dialog(page, 'do-new-zfs')
    assert 'No unused disk' in d.inner_text()
    d.locator('[data-cr-do-field="name"]').fill('tank2')
    assert d.locator('[data-cr-do-next]').is_disabled()
    d.locator('[data-cr-do-cancel]').click()
    sec.locator('[data-cr-do-create] [data-cr-do-new="lvmthin"]').click()
    d = _dialog(page, 'do-new-lvmthin')
    assert 'No volume group read on pve1' in d.inner_text()
    assert app.server.sent == []
    _no_errors(app)


def test_runtime_a_zfs_level_with_too_few_disks_is_a_hint_not_a_block(open_app):
    app = open_app()
    page = app.page
    sec = _disks(app)
    sec.locator('[data-cr-do-create] [data-cr-do-new="zfs"]').click()
    d = _dialog(page, 'do-new-zfs')
    d.locator('[data-cr-do-dev="sde"]').check()
    d.locator('[data-cr-do-field="raidlevel"]').select_option('raidz')
    assert 'RAIDZ needs at least 3 disks, 1 selected.' in d.inner_text()
    d.locator('[data-cr-do-field="name"]').fill('tank2')
    assert d.locator('[data-cr-do-next]').is_enabled()
    _no_errors(app)


@pytest.mark.parametrize('who', ['standby', 'perm'])
def test_runtime_a_standby_and_a_user_without_storage_config_see_the_actions_off(open_app, who):
    kw = {'role': 'standby'} if who == 'standby' else {
        'admin': False, 'permissions': ['cluster.view', 'node.view', 'vm.view', 'storage.view']}
    app = open_app(**kw)
    page = app.page
    sec = _disks(app)
    sel = '[data-cr-do-gpt], [data-cr-do-wipe], [data-cr-do-new]'
    n = sec.locator(sel).count()
    assert n == 2 * 3 + 4, n
    assert sec.locator(sel).evaluate_all('els => els.filter(e => !e.disabled).length') == 0
    note = sec.locator(f'[data-cr-do-gate="{who}"]')
    assert note.count() == 1
    assert ('standby' if who == 'standby' else 'storage.config') in note.inner_text()
    assert sec.locator('[data-cr-do-wipe="sdd"]').get_attribute('title') == note.inner_text()
    # the reads stay open: SMART of each disk, Refresh
    assert sec.locator('[data-cr-nd-smart="sdd"]').is_enabled() and sec.locator('[data-cr-nd-reload]').count() == 1
    for sub in ('lvm', 'lvmthin', 'zfs'):
        _sub(page, sub)
        s = _sec(page, sub)
        btn = s.locator(f'[data-cr-do-new="{sub}"]')
        btn.wait_for(timeout=8000)
        assert btn.is_disabled(), sub
        assert s.locator(f'[data-cr-do-gate="{who}"]').count() == 1, sub
    assert app.server.sent == []
    _no_errors(app)


def test_runtime_classic_corporate_is_unchanged(open_app):
    app = open_app(layout='corporate')
    page = app.page
    _open_cfg(page, 'disks', redesigned=False)
    page.get_by_text('/dev/sdf').first.wait_for(timeout=8000)
    assert page.locator('[data-cr-do-create], [data-cr-do-gpt], [data-cr-do-new]').count() == 0
    _sub(page, 'lvm')
    page.wait_for_timeout(300)
    assert page.locator('[data-cr-do-new]').count() == 0
    _no_errors(app)


def test_rules_the_bodies_are_the_classic_ones(open_app):
    app = open_app()
    ops = app.page.evaluate('() => !!window.PegaProxNodeDiskOps')
    assert ops, 'the bundle has no disk action helpers (window.PegaProxNodeDiskOps)'
    got = app.page.evaluate("""() => {
        const o = window.PegaProxNodeDiskOps;
        const f = { device: '/dev/sdx', name: 'n', vgname: 'pve', devices: ['/dev/sdx', '/dev/sdy'], raidlevel: 'mirror',
                    compression: 'on', ashift: 12, filesystem: 'ext4', add_storage: true };
        return { lvm: o.body('lvm', f), thin: o.body('lvmthin', f), zfs: o.body('zfs', f), dir: o.body('directory', f),
                 gpt: o.diskBody('initgpt', '/dev/sdx'), wipe: o.diskBody('wipe', '/dev/sdx'),
                 valid: [o.valid('lvm', { ...f, device: '' }), o.valid('zfs', { ...f, devices: [] }), o.valid('lvmthin', { ...f, name: '' }), o.valid('directory', f)],
                 unused: o.unused([{ devpath: '/dev/a', used: 'unused' }, { devpath: '/dev/b' }, { devpath: '/dev/c', used: 'LVM' }, { devpath: '/dev/d', used: '' }]).map(d => d.devpath) };
    }""")
    assert got['lvm'] == {'endpoint': 'disks/lvm', 'body': {'device': '/dev/sdx', 'name': 'n', 'add_storage': True}}
    assert got['thin'] == {'endpoint': 'disks/lvmthin', 'body': {'device': 'pve', 'name': 'n', 'add_storage': True}}
    assert got['zfs']['body'] == {'devices': ['/dev/sdx', '/dev/sdy'], 'name': 'n', 'raidlevel': 'mirror', 'compression': 'on', 'ashift': 12, 'add_storage': True}
    assert got['dir']['body'] == {'device': '/dev/sdx', 'name': 'n', 'filesystem': 'ext4', 'add_storage': True}
    assert got['gpt'] == {'disk': '/dev/sdx'} and got['wipe'] == {'disk': '/dev/sdx', 'confirm_name': '/dev/sdx'}
    assert got['valid'] == [False, False, False, True]
    assert got['unused'] == ['/dev/a', '/dev/b', '/dev/d']


_NO_SIDEWAYS = '() => document.scrollingElement.scrollWidth <= window.innerWidth'
_TABLE_FITS = 'e => e.scrollWidth <= e.clientWidth + 1'


@pytest.mark.parametrize('engine,width', [('chromium', 1600), ('chromium', 1280), ('chromium', 1024),
                                          ('firefox', 1600), ('firefox', 1280), ('firefox', 1024)])
def test_runtime_layout_without_sideways_scroll(open_app, firefox, browser, engine, width):
    app = open_app(viewport=(width, 900), br=firefox if engine == 'firefox' else browser)
    page = app.page
    sec = _disks(app)
    assert page.evaluate(_NO_SIDEWAYS), 'disks'
    scroll = sec.locator('.cr-nn-scroll')
    if width >= 1280:
        assert scroll.evaluate(_TABLE_FITS), 'the disk table clips or scrolls a column'
    else:
        # at 1024 the card is about 460 px wide and the eight columns scroll in their own box, as they did
        # before this round; the actions column stays as narrow as one button and is reached there
        assert scroll.evaluate("e => getComputedStyle(e).overflowX") == 'auto'
        w_act = sec.locator('table thead th').last.evaluate('e => e.getBoundingClientRect().width')
        assert w_act <= 80, w_act
        sec.locator('[data-cr-do-wipe="sdf"]').scroll_into_view_if_needed()
    card = sec.bounding_box()
    for b in sec.locator('[data-cr-do-acts="sdf"] button, [data-cr-nd-smart="sdf"]').all():
        box = b.bounding_box()
        assert box['x'] >= card['x'] - 1 and box['x'] + box['width'] <= card['x'] + card['width'] + 1, (width, box, card)
    sec.locator('[data-cr-do-wipe="sdd"]').click()
    _dialog(page, 'nc-do-wipe')
    assert page.evaluate(_NO_SIDEWAYS), 'wipe dialog'
    page.keyboard.press('Escape')
    page.wait_for_function('() => !document.querySelector("[data-cr-upd-dialog]")', timeout=5000)
    d = _variant_create(page, sec.locator('[data-cr-do-create] [data-cr-do-new="zfs"]'), 'zfs')
    assert page.evaluate(_NO_SIDEWAYS), 'zfs review'
    d.locator('[data-cr-do-back]').click()
    assert page.evaluate(_NO_SIDEWAYS), 'zfs form'
    page.keyboard.press('Escape')
    for sub, probe in (('lvm', '[data-cr-nv-vg="pve"]'), ('lvmthin', '[data-cr-nv-thin="pve/data"]'), ('zfs', '[data-cr-nv-pool="tank"]')):
        _sub(page, sub)
        s = _sec(page, sub)
        s.locator(probe).wait_for(timeout=8000)
        assert page.evaluate(_NO_SIDEWAYS), sub
        head = s.locator('.cr-nc-head').bounding_box()
        nb = s.locator(f'[data-cr-do-new="{sub}"]').bounding_box()
        assert nb['x'] + nb['width'] <= head['x'] + head['width'] + 1, (sub, width)
    _no_errors(app)
