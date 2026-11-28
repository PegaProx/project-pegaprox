"""The Windows preparation of an ESXi migration in the UI.

A Windows guest is prepared fully automatically, without a login: the wizard and the bulk
dialog show the preparation and the two-stage boot (SATA first, then VirtIO SCSI) ticked and
send nothing for them but a box the user unticked (null leaves the preset to the server). The
preparation inside the running guest is optional, folded away under its own section: an
administrator login that goes along with the start only, never into the browser's storage, and
is gone when the wizard closes. The review lists what the server resolved, the result says
where the boot disk ended up.

Runtime tests drive the built bundle in headless Chromium against the fake server of
tests/test_ha_ui.py; they skip where Playwright is not installed.
LW Nov 2026
"""
import json
import os
import re

import pytest

from test_ha_ui import _classes, browser  # noqa: F401 (browser: a fixture)
from test_esxi_mapping_verify import WIZ_DRY, WIZ_PLAN, PLAN_SOURCE, _migrate_bodies, _pick_target
from test_esxi_bulk import CHECK, BULK, RUN, _bodies, _item, _pick_targets, _wait_bodies, dialog  # noqa: F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LANGS = ['de', 'en', 'zh', 'pl', 'fr', 'es', 'pt', 'ko', 'it', 'ru']
KEYS = ['v2pWinTitle', 'v2pWinAuto', 'v2pWinAutoDesc', 'v2pWinAutoOff', 'v2pWinIso', 'v2pWinIsoPath',
        'v2pWinLiveMirror', 'v2pWinHardwareHint', 'v2pTwoStage', 'v2pTwoStageDesc', 'v2pTwoStageOffLiveMirror',
        'v2pTwoStageOffBus', 'v2pTwoStageNeedsAgent', 'v2pTwoStageNeedsDrivers', 'v2pGuestPrepSection',
        'v2pGuestPrep', 'v2pGuestPrepDesc', 'v2pGuestPrepOff', 'v2pGuestUser', 'v2pGuestUserHint',
        'v2pGuestPassword', 'v2pGuestLoginNotStored', 'v2pGuestLoginCheck', 'v2pGuestLoginChecking',
        'v2pGuestLoginOk', 'v2pGuestLoginFailed', 'v2pGuestPrepNeedsLogin', 'v2pGuestPrepScript',
        'v2pGuestPrepScriptDesc', 'v2pGuestPrepScriptFailed', 'v2pGuestPrepFellBack', 'v2pGuestPrepDone',
        'v2pReviewWinPrep', 'v2pReviewWinAuto', 'v2pReviewWinGuest', 'v2pReviewWinOff', 'v2pReviewWinHw',
        'v2pReviewIsoPresent', 'v2pReviewIsoDownload', 'v2pReviewIsoMissing', 'v2pReviewTwoStage',
        'v2pReviewTwoStageOn', 'v2pReviewTwoStageTemp', 'v2pReviewGuestPrep', 'v2pReviewGuestToolsOn',
        'v2pReviewGuestToolsOff', 'v2pResultBootDisk', 'v2pResultKeptSata', 'v2pResultWinFirstBoot',
        'v2pFirstBootApplied', 'v2pFirstBootPartial', 'v2pFirstBootFailed', 'v2pFirstBootRestored',
        'v2pFirstBootStaged', 'v2pFirstBootNotStaged', 'v2pBadgeKeptSata', 'v2pPkgForGuestPrep',
        'v2pPkgForVirtioIso', 'esxiBulkWinHint', 'esxiBulkGuestLoginHint', 'esxiBulkGuestLoginOwn',
        'esxiBulkGuestPrepNeedsLogin', 'esxiBulkTagWinAuto', 'esxiBulkTagWinOff', 'esxiBulkTagToolsOff']
SECRET = 'Wind0ws-Adm1n-S3ntinel!'
# the words of the project's naming rule, spelled so this file does not carry them
NAMING = re.compile(r'\b(' + 'vm' + 'ware|vc' + 'enter)\b', re.I)
OWN_SECRET = 'Own-Gu3st-S3ntinel?'


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def _blocks():
    src = _read('web', 'src', 'translations.js')
    starts = [(m.group(1), m.start()) for m in re.finditer(r'^            ([a-z]{2}): \{', src, re.M)]
    ends = [pos for _, pos in starts[1:]] + [len(src)]
    return {lang: src[pos:end] for (lang, pos), end in zip(starts, ends)}


def _slice(src, start, end):
    at = src.index(start)
    return src[at:src.index(end, at)]


def _added_markup():
    src = _read('web', 'src', 'dashboard.js')
    return '\n'.join([
        _slice(src, '{/* LW Nov 2026 - a Windows guest is prepared without a login', '{/* NS Apr 2026'),
        _slice(src, '{/* LW Nov 2026 - the Windows guests of the run are prepared', "{t('esxiBulkSshUser')}"),
        _slice(src, 'function V2pWinReview(', 'function EsxiBulkMigrate('),
        _slice(src, "{t('esxiBulkGuestLoginOwn')}", '{r && r.nics.length > 0 && ('),
    ])


# -- source -----------------------------------------------------------------------------------

def test_every_language_has_each_label_once_and_in_its_own_words():
    blocks = _blocks()
    assert list(blocks) == LANGS
    for key in KEYS:
        values = {}
        for lang, block in blocks.items():
            found = re.findall(rf"^\s*{key}: '((?:[^'\\]|\\.)+)',", block, re.M)
            assert len(found) == 1, (key, lang, found)
            values[lang] = found[0]
        assert all(v != values['en'] for lang, v in values.items() if lang != 'en'), (key, values)
        for v in values.values():
            assert chr(0x2014) not in v, (key, v)
            assert not NAMING.search(v), (key, v)
        # a placeholder the code fills is in every language
        for ph in re.findall(r'\{[a-z]+\}', values['en']):
            assert all(ph in v for v in values.values()), (key, ph, values)


def test_the_keys_follow_the_esxi_wizard_keys_and_stay_out_of_the_pinned_tail():
    for lang, block in _blocks().items():
        at = block.index('virtioSshfsBootWarn:')
        nxt = block[at:].split('\n')[1:len(KEYS) + 1]
        assert [ln.strip().split(':')[0] for ln in nxt] == KEYS, lang
        assert block.index('v2pWinTitle:') < block.index('// LW Oct 2026 (#625) - the banners')


def test_the_markup_uses_classes_the_static_build_has_and_says_everything_through_t():
    css = _read('static', 'css', 'tailwind.min.css')
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    markup = _added_markup()
    missing = sorted(n for n in _classes(markup) if n not in have and n not in ('small', 'input', 'field'))
    assert not missing, missing
    assert chr(0x2014) not in markup
    assert not NAMING.search(markup)
    # no placeholder a user reads outside a translation key
    assert not re.findall(r'placeholder="[^"]+"', markup)


def test_the_login_goes_along_with_the_start_only_and_dies_with_the_wizard():
    src = _read('web', 'src', 'dashboard.js')
    body = _slice(src, 'const buildVmwareMigrateBody = (dryRun) => {', 'const v2pReviewIsCurrent')
    assert ('if (!body.guest_prep) {\n                    delete body.guest_user;\n'
            '                    delete body.guest_password;') in body
    dry = body[body.index('if (dryRun) {'):]
    assert 'delete body.esxi_password;' in dry and 'delete body.guest_password;' in dry
    # closed, or opened for another guest: the login and the per guest choices go
    assert ("? {...f, guest_prep: false, guest_user: '', guest_password: '', two_stage_boot: null, "
            "install_virtio_drivers: null} : f));") in src
    card = _added_markup()
    assert card.count('type="password" autoComplete="off"') == 3      # wizard, bulk run, bulk guest
    assert 'localStorage' not in card and 'sessionStorage' not in card
    # the bulk check never carries a login, the start does
    bulk = _slice(src, 'function EsxiBulkMigrate(', 'function EsxiBulkRuns(')
    assert 'if (!dryRun && form.guest_prep) Object.assign(m, ownLogin(g.id) || {});' in bulk
    assert 'if (!dryRun && form.guest_prep && guestUser && guestPassword) {' in bulk


def test_the_bundle_carries_it():
    bundle = _read('web', 'index.html')
    assert "v2pWinTitle:'Windows guest'" in bundle and 'data-v2p-win-auto' in bundle
    assert 'data-esxi-bulk-guest-prep' in bundle and 'data-v2p-twostage-result' in bundle
    assert json.loads(_read('web', 'i18n', 'de.json'))['v2pTwoStage'] == 'Erster Start auf SATA, dann VirtIO SCSI'


# -- the keys as the UI sends them, against the real routes --------------------------------------

from test_esxi_mapping_verify import route  # noqa: E402,F401 (a fixture)
from test_esxi_bulk import env  # noqa: E402,F401 (a fixture)
from test_v2p_node_packages_1252 import probe  # noqa: E402,F401 (a fixture)
from test_v2p_winprep_api import _windows  # noqa: E402


def _wizard_body(**kw):
    # the Windows keys of buildVmwareMigrateBody: null is the preset, an unticked box false
    body = {'target_cluster': 'pve-cl', 'target_node': 'pve1', 'target_storage': 'local-lvm',
            'transfer_mode': 'offline', 'install_virtio_drivers': None, 'virtio_iso_path': '',
            'two_stage_boot': None, 'guest_prep': False, 'allow_package_install': True}
    body.update(kw)
    return body


def test_the_wizards_keys_pass_the_real_route(route, probe, monkeypatch):
    import pegaprox.core.v2p as v2p
    monkeypatch.setattr(v2p, '_node_cannot_reach', lambda *a, **k: '')
    _windows(route.esxi)
    route.esxi.guest_state = lambda vm_id: {'data': {'power_state': 'POWERED_ON', 'tools_running': True,
                                                     'ops_ready': True, 'family': 'windowsGuest',
                                                     'full_name': 'Windows', 'soap': True}}
    url = '/api/vmware/vw1/vms/vm-42/migrate'
    p = route.admin.post(url, json=_wizard_body(dry_run=True)).get_json()
    assert p['ok'] is True, p['errors']
    assert p['windows_prep']['on'] is True and p['two_stage']['on'] is True
    p = route.admin.post(url, json=_wizard_body(dry_run=True, install_virtio_drivers=False,
                                                two_stage_boot=False)).get_json()
    assert p['ok'] is True and p['windows_prep']['on'] is False and p['two_stage']['on'] is False
    # the review of a ticked preparation in the guest before the login is typed
    p = route.admin.post(url, json=_wizard_body(dry_run=True, guest_prep=True, guest_user='')).get_json()
    assert p['ok'] is True, p['errors']
    assert p['windows_prep']['guest_prep'] is True
    r = route.admin.post(url, json=_wizard_body(esxi_password='pw', guest_prep=True, guest_user='Administrator',
                                                guest_password=SECRET))
    assert r.status_code == 202, r.get_data(as_text=True)
    assert SECRET not in r.get_data(as_text=True)
    task = route.wait_started()[0]
    assert task._guest_password == SECRET and task.guest_user == 'Administrator'


def test_the_bulk_dialogs_keys_pass_the_real_route(env, probe):
    base = {'transfer_mode': 'offline', 'guest_prep': False, 'allow_package_install': True}
    # the preset is no key, an unticked box false
    r = env.post(dry_run=True, esxi_password=None, two_stage_boot=False, **base)
    assert r.status_code == 200, r.get_data(as_text=True)
    r = env.post(dry_run=True, esxi_password=None, **dict(base, guest_prep=True))
    assert r.status_code == 200, r.get_data(as_text=True)
    r = env.post(**dict(base, guest_prep=True), guest_user='Administrator', guest_password=SECRET,
                 vms=['vm-1', {'vm_id': 'vm-2', 'guest_user': 'LAB\\deploy', 'guest_password': OWN_SECRET}])
    assert r.status_code == 202, r.get_data(as_text=True)
    assert SECRET not in r.get_data(as_text=True) and OWN_SECRET not in r.get_data(as_text=True)


# -- runtime: the wizard ------------------------------------------------------------------------

WIN_SOURCE = dict(PLAN_SOURCE, name='winsrv01', guest_os='Microsoft Windows Server 2022 (64-bit)',
                  guest_OS='Microsoft Windows Server 2022 (64-bit)',
                  hardware={'firmware': 'efi', 'disk_bus': 'scsi', 'scsi_controller': 'pvscsi'})
WIN_PLAN = dict(WIZ_PLAN, source=WIN_SOURCE)
ISO_WARNING = ('virtio-win.iso is not on node pve1: the migration downloads it from fedorapeople.org into '
               '/var/lib/vz/template/iso first')
WIN_DRY = dict(
    WIZ_DRY, warnings=[ISO_WARNING],
    windows_prep={'windows': True, 'on': True, 'offline': True, 'guest_prep': False, 'scsihw': 'virtio-scsi-single',
                  'net_driver': 'virtio', 'iso': 'missing', 'errors': [], 'warnings': [ISO_WARNING]},
    two_stage={'on': True, 'why': 'a Windows guest', 'first_bus': 'sata', 'final_bus': 'scsi',
               'scsihw': 'virtio-scsi-single', 'temp_disk': True, 'drivers_from': 'injection',
               'errors': [], 'warnings': []},
    node_packages={'node': 'pve1', 'checked': True, 'error': None, 'allow_install': True, 'apt_command': None,
                   'items': [{'package': 'virtio-win.iso', 'feature': 'virtio_iso', 'purpose': 'x',
                              'needed': False, 'installed': False}]})
LOGIN = '/api/vmware/v1/vms/vm-1/guest-login'
STORAGE_JS = '''() => { const out = [];
    for (const s of [localStorage, sessionStorage]) for (let i = 0; i < s.length; i++) {
        const k = s.key(i); out.push(k + '=' + s.getItem(k)); }
    return out.join('\\n'); }'''


@pytest.fixture
def wizard_win(browser):
    from test_ha_ui import _App, _FakeServer, ESXI_READS, SSE_TOKEN
    apps = []

    def _open(plan=None, dry=None, layout='modern'):
        extra = {**ESXI_READS, **SSE_TOKEN,
                 ('GET', '/api/vmware/v1/vms/vm-1/migration-plan'): (200, plan or WIN_PLAN),
                 ('POST', '/api/vmware/v1/vms/vm-1/migrate'): (200, dry or WIN_DRY),
                 ('POST', LOGIN): (200, {'ok': True, 'tools_running': True, 'windows': True, 'error': None}),
                 ('GET', '/api/vmware/migrations'): (200, [])}
        app = _App(browser, _FakeServer(role='standalone', layout=layout, extra=extra))
        apps.append(app)
        page = app.page
        _open_wizard(page)
        return app, page
    yield _open
    for app in apps:
        app.ctx.close()


def _open_wizard(page, first=True):
    if first:
        page.get_by_text('esx01').first.click()
        page.get_by_text('legacy01').first.wait_for(timeout=8000)
        page.get_by_text('legacy01').first.click()
        page.locator('button:visible', has_text='Migration').first.wait_for(timeout=8000)
        page.locator('button:visible', has_text='Migration').first.click()
    page.locator('button:visible', has_text='Start Migration Wizard').first.click()
    page.locator('option', has_text='Select cluster...').first.wait_for(state='attached', timeout=5000)


def _review(page):
    page.locator('button', has_text='Review and start').click()


def _check_again(page):
    page.locator('button', has_text='Check again').first.click()


def _start_button(page):
    return page.locator('button', has_text=re.compile(r'^\s*Start Migration\s*$'))


def _wait_for(page, cond, what, tries=50):
    for _ in range(tries):
        if cond():
            return
        page.wait_for_timeout(100)
    assert cond(), what


def _dry(app):
    return [b for b in _migrate_bodies(app) if b.get('dry_run') and 'check_packages' not in b]


def _sent(app):
    return [b for b in _migrate_bodies(app) if not b.get('dry_run')]


@pytest.mark.parametrize('layout', ['modern', 'corporate-redesigned'])
def test_runtime_a_windows_guest_gets_the_automatic_path_without_being_asked(wizard_win, layout):
    app, page = wizard_win(layout=layout)
    page.locator('[data-v2p-win]').wait_for(timeout=5000)
    auto, two = page.locator('[data-v2p-win-auto]'), page.locator('[data-v2p-two-stage]')
    assert auto.is_checked() and two.is_checked() and two.is_enabled()
    page.get_by_text('Log: C:\\ProgramData\\KVMMigration\\migrate.log in the guest').first.wait_for(timeout=2000)
    # the login is optional and folded away
    assert not page.locator('[data-v2p-guest-prep]').is_visible()
    assert page.locator('[data-v2p-guest-password]').count() == 0
    page.locator('button', has_text='\N{WRENCH}').first.click()
    page.locator('[data-v2p-win-hw-hint]').wait_for(timeout=2000)
    page.locator('button', has_text='\N{DIRECT HIT}').first.click()
    _pick_target(page)
    page.locator('input[placeholder="ESXi password"]').fill('pw')
    _review(page)
    page.get_by_text('The plan fits the target node.').first.wait_for(timeout=5000)
    review = _dry(app)[-1]
    assert review['install_virtio_drivers'] is None and review['two_stage_boot'] is None
    assert review['guest_prep'] is False and 'guest_user' not in review and 'guest_password' not in review
    lines = page.locator('[data-v2p-review-winprep]').inner_text()
    assert 'Preparation: automatic, on Proxmox VE after the copy' in lines, lines
    assert 'Controller virtio-scsi-single, network virtio' in lines, lines
    assert 'virtio-win.iso: downloaded to the node first' in lines, lines
    assert ('Two-stage boot: first boot from sata0, then scsi0, with a 1 GiB temporary disk for the first boot'
            in page.locator('[data-v2p-review-twostage]').inner_text())
    assert 'Windows preparation: VirtIO drivers and guest agent' in \
        page.locator('[data-v2p-package="virtio-win.iso"]').inner_text()
    page.get_by_text(ISO_WARNING).first.wait_for(timeout=2000)
    page.locator('label', has_text='keep this in mind').locator('input').check()
    start = _start_button(page)
    assert start.is_enabled()
    start.click()
    _wait_for(page, lambda: _sent(app), 'started')
    sent = dict(_sent(app)[-1])
    assert sent.pop('esxi_password') == 'pw'
    expect = dict(review)
    expect.pop('dry_run')
    assert sent == expect, 'Start sent something other than what the review checked'
    assert not app.errors, app.errors


def test_runtime_a_box_unticked_goes_along_as_false_and_ticked_again_as_the_preset(wizard_win):
    app, page = wizard_win()
    _pick_target(page)
    page.locator('input[placeholder="ESXi password"]').fill('pw')
    two = page.locator('[data-v2p-two-stage]')
    two.uncheck()
    _review(page)
    page.get_by_text('The plan fits the target node.').first.wait_for(timeout=5000)
    assert _dry(app)[-1]['two_stage_boot'] is False
    two.check()
    _check_again(page)
    _wait_for(page, lambda: _dry(app)[-1]['two_stage_boot'] is None, 'ticked again is the preset')
    # without the preparation there are no drivers: the two-stage boot says why it is off
    page.locator('[data-v2p-win-auto]').uncheck()
    assert two.is_disabled() and not two.is_checked()
    page.get_by_text('Needs the VirtIO drivers: leave the automatic preparation on').first.wait_for(timeout=2000)
    page.get_by_text('Off: the guest keeps the disk controller and NICs of the source').first.wait_for(timeout=2000)
    _check_again(page)
    _wait_for(page, lambda: _dry(app)[-1]['install_virtio_drivers'] is False, 'unticked is false')
    page.locator('[data-v2p-win-auto]').check()
    assert two.is_enabled() and two.is_checked()
    # Live Mirror boots the guest itself
    page.locator('button', has_text='\N{DIRECT HIT}').first.click()
    page.locator('select', has=page.locator('option[value="sshfs_boot"]')).first.select_option('sshfs_boot')
    assert two.is_disabled()
    page.get_by_text('Not with Live Mirror: the mirror boots the guest itself.').first.wait_for(timeout=2000)
    page.locator('[data-v2p-win-mirror]').wait_for(timeout=2000)
    assert not app.errors, app.errors


def test_runtime_the_login_in_the_guest_is_optional_sent_with_the_start_only_and_never_stored(wizard_win):
    app, page = wizard_win()
    page.locator('[data-v2p-guest-prep-section] summary').click()
    page.locator('[data-v2p-guest-prep]').check()
    user, pw = page.locator('[data-v2p-guest-user]'), page.locator('[data-v2p-guest-password]')
    assert pw.get_attribute('type') == 'password'
    assert pw.get_attribute('autocomplete') == 'off' and user.get_attribute('autocomplete') == 'off'
    _pick_target(page)
    page.locator('input[placeholder="ESXi password"]').fill('pw')
    page.locator('label', has_text='keep this in mind').locator('input').check()
    _review(page)
    page.get_by_text('The plan fits the target node.').first.wait_for(timeout=5000)
    # asked for and not given: Start stays off and says why
    assert _start_button(page).is_disabled()
    page.locator('[data-v2p-guest-prep-needs-login]').wait_for(timeout=2000)
    user.fill('Administrator')
    pw.fill(SECRET)
    # one login check, with what was typed; a refusal says why
    app.server.extra[('POST', LOGIN)] = (200, {'ok': False, 'tools_running': True, 'windows': True,
                                              'error': 'the guest refused the login'})
    page.locator('[data-v2p-guest-login-check]').click()
    page.locator('[data-v2p-guest-login-result]', has_text='Login check failed: the guest refused the login').wait_for(timeout=3000)
    app.server.extra[('POST', LOGIN)] = (200, {'ok': True, 'tools_running': True, 'windows': True, 'error': None})
    page.locator('[data-v2p-guest-login-check]').click()
    page.locator('[data-v2p-guest-login-result]', has_text='The login works in the guest.').wait_for(timeout=3000)
    assert app.server.bodies[LOGIN][-1] == {'guest_user': 'Administrator', 'guest_password': SECRET}
    # the account is part of what the review checks, its password is not
    _check_again(page)
    _wait_for(page, lambda: _dry(app)[-1].get('guest_user') == 'Administrator', 'reviewed with the account')
    review = _dry(app)[-1]
    assert review['guest_prep'] is True and 'guest_password' not in review
    assert SECRET not in json.dumps(_dry(app))
    page.get_by_text('The plan fits the target node.').first.wait_for(timeout=5000)
    assert SECRET not in page.evaluate(STORAGE_JS)
    start = _start_button(page)
    assert start.is_enabled()
    start.click()
    _wait_for(page, lambda: _sent(app), 'started')
    sent = dict(_sent(app)[-1])
    assert sent.pop('guest_password') == SECRET and sent.pop('esxi_password') == 'pw'
    expect = dict(review)
    expect.pop('dry_run')
    assert sent == expect
    assert SECRET not in page.evaluate(STORAGE_JS)
    # the next wizard starts without it
    page.locator('[data-v2p-win]').wait_for(state='detached', timeout=5000)
    _open_wizard(page, first=False)
    page.locator('[data-v2p-guest-prep-section] summary').click()
    box = page.locator('[data-v2p-guest-prep]')
    assert not box.is_checked()
    box.check()
    assert page.locator('[data-v2p-guest-user]').input_value() == ''
    assert page.locator('[data-v2p-guest-password]').input_value() == ''
    assert SECRET not in page.evaluate(STORAGE_JS)
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate-redesigned'])
def test_runtime_the_in_guest_preparation_picks_auto_over_live_clone(wizard_win, layout):
    # LW Nov 2026 - Live Clone copies what stage 1 writes (drivers, guest tools) in the downtime;
    # Auto takes Snapshot-Iterative for it and Live Clone where that cannot run (an explicit
    # Snapshot-Iterative refuses a VM with snapshots): ticking the preparation picks Auto
    app, page = wizard_win(layout=layout)
    mode = page.locator('select:has(option[value="snapshot_zero"])').first
    assert mode.input_value() == 'vmkfstools_clone'
    page.locator('[data-v2p-guest-prep-section] summary').click()
    page.locator('[data-v2p-guest-prep]').check()
    _wait_for(page, lambda: mode.input_value() == 'auto', 'the mode stayed ' + mode.input_value())
    # unticked it keeps the mode, and a mode picked by hand is left alone
    page.locator('[data-v2p-guest-prep]').uncheck()
    assert mode.input_value() == 'auto'
    mode.select_option('offline')
    page.locator('[data-v2p-guest-prep]').check()
    page.wait_for_timeout(200)
    assert mode.input_value() == 'offline'


def test_runtime_cancel_drops_the_typed_login(wizard_win):
    app, page = wizard_win()
    page.locator('[data-v2p-guest-prep-section] summary').click()
    page.locator('[data-v2p-guest-prep]').check()
    page.locator('[data-v2p-guest-user]').fill('Administrator')
    page.locator('[data-v2p-guest-password]').fill(SECRET)
    page.locator('button:visible', has_text=re.compile(r'^\s*Cancel\s*$')).last.click()
    _open_wizard(page, first=False)
    page.locator('[data-v2p-guest-prep-section] summary').click()
    assert not page.locator('[data-v2p-guest-prep]').is_checked()
    assert page.locator('[data-v2p-guest-password]').count() == 0
    assert SECRET not in page.evaluate(STORAGE_JS)
    assert not app.errors, app.errors


def test_runtime_the_script_for_a_manual_run_downloads(wizard_win):
    app, page = wizard_win()
    page.route('**/api/vmware/guest-prep-script', lambda route: route.fulfill(
        status=200, body='param()\r\n',
        headers={'Content-Type': 'text/plain; charset=us-ascii',
                 'Content-Disposition': 'attachment; filename="Prepare-KvmMigration.ps1"'}))
    page.locator('[data-v2p-guest-prep-section] summary').click()
    with page.expect_download(timeout=8000) as dl:
        page.locator('[data-v2p-guest-prep-script]').click()
    assert dl.value.suggested_filename == 'Prepare-KvmMigration.ps1'
    page.get_by_text('Prepare-KvmMigration.ps1" as administrator, then migrate').first.wait_for(timeout=2000)
    assert not app.errors, app.errors


def test_runtime_a_linux_guest_sees_none_of_it(wizard_win):
    app, page = wizard_win(plan=WIZ_PLAN, dry=WIZ_DRY)
    _pick_target(page)
    page.locator('input[placeholder="ESXi password"]').fill('pw')
    _review(page)
    page.get_by_text('The plan fits the target node.').first.wait_for(timeout=5000)
    assert page.locator('[data-v2p-win]').count() == 0
    assert page.locator('[data-v2p-review-winprep]').count() == 0
    # null: the server decides, and it leaves a Linux guest alone
    assert _dry(app)[-1]['install_virtio_drivers'] is None
    assert not app.errors, app.errors


def test_runtime_the_servers_word_shows_the_card_when_the_plan_has_no_os(wizard_win):
    hidden = dict(WIZ_PLAN, source={k: v for k, v in PLAN_SOURCE.items() if k not in ('guest_os', 'guest_OS')})
    app, page = wizard_win(plan=hidden)
    assert page.locator('[data-v2p-win]').count() == 0
    _pick_target(page)
    page.locator('[data-v2p-win]').wait_for(timeout=5000)
    assert page.locator('[data-v2p-win-auto]').is_checked()
    assert not app.errors, app.errors


# -- runtime: the result ------------------------------------------------------------------------

SATA_WARNING = ('The guest agent did not answer within 15 min of the first boot on SATA. The boot disk stays on '
                'sata0 and VirtIO SCSI was not switched on.')


def _task(mid, name, two_stage, windows_prep, warnings):
    return {'id': mid, 'vmware_id': 'v1', 'vm_id': 'vm-1', 'vm_name': name, 'target_cluster': 'c1',
            'target_node': 'pve1', 'target_storage': 'local-lvm', 'proxmox_vmid': 130,
            'phase': 'completed', 'status': 'completed', 'progress': 100, 'error': None,
            'wait_for_confirmation': False, 'awaiting_confirmation': False,
            'started_at': '2026-11-27T10:00:00', 'completed_at': '2026-11-27T10:30:00',
            'disk_progress': {}, 'phase_times': {}, 'total_downtime_seconds': 300,
            'warnings': warnings, 'log': ['[10:30:00] Phase: completed'],
            'guest_prep': {'on': False, 'state': 'off', 'os': '', 'drivers': '', 'why': ''},
            'two_stage': two_stage, 'windows_prep': windows_prep, 'config': {}}


KEPT = _task('m7', 'winsata01', {'on': True, 'state': 'kept_sata', 'boot_disk': 'sata0', 'why': 'no agent'},
             {'windows': True, 'on': True, 'state': 'staged', 'first_boot': 'applied', 'why': ''}, [SATA_WARNING])
SWITCHED = _task('m8', 'winscsi01', {'on': True, 'state': 'switched', 'boot_disk': 'scsi0', 'why': ''},
                 {'windows': True, 'on': True, 'state': 'staged', 'first_boot': 'partial', 'why': ''}, [])


@pytest.fixture
def tasks_app(browser):
    from test_ha_ui import _App, _FakeServer, ESXI_READS, SSE_TOKEN
    apps = []

    def _open(layout='modern'):
        extra = {**ESXI_READS, **SSE_TOKEN,
                 ('GET', '/api/vmware/migrations'): (200, [KEPT, SWITCHED]),
                 ('GET', '/api/vmware/migrations/m7'): (200, KEPT),
                 ('GET', '/api/vmware/migrations/m8'): (200, SWITCHED),
                 ('GET', '/api/audit'): (200, [])}
        app = _App(browser, _FakeServer(role='standalone', layout=layout, extra=extra))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


@pytest.mark.parametrize('layout', ['modern', 'corporate-redesigned'])
def test_runtime_the_result_says_where_the_boot_disk_ended_up(tasks_app, layout):
    app = tasks_app(layout=layout)
    page = app.page
    page.get_by_text('esx01').first.click()
    page.get_by_text('legacy01').first.wait_for(timeout=8000)
    page.locator('button', has_text='Tasks & Events').first.click()
    badge = page.locator('span[data-v2p-kept-sata]')
    badge.first.wait_for(timeout=8000)
    assert badge.count() == 1 and badge.first.inner_text().strip() == 'stayed on SATA'
    page.get_by_text('winsata01').first.click()
    res = page.locator('[data-v2p-twostage-result]').first
    res.wait_for(timeout=8000)
    assert res.inner_text().strip() == 'Boot disk: sata0 (stayed on SATA, see the warnings)'
    assert 'Windows first boot: done' in page.locator('[data-v2p-winprep-result]').first.inner_text()
    warn = page.locator('div[data-v2p-warnings]').first
    warn.wait_for(timeout=3000)
    assert SATA_WARNING in warn.inner_text()
    page.get_by_text('winscsi01').first.click()
    page.get_by_text('(m8)').first.wait_for(timeout=8000)
    page.locator('[data-v2p-twostage-result]', has_text='Boot disk: scsi0 (VirtIO SCSI)').first.wait_for(timeout=3000)
    page.locator('[data-v2p-winprep-result]', has_text='partly done, tried again at the next boot').first.wait_for(timeout=3000)
    assert not app.errors, app.errors


# -- runtime: the bulk dialog -------------------------------------------------------------------

def _win_item(vm_id, name):
    it = _item(vm_id, name)
    it.update(windows_prep={'windows': True, 'on': True, 'offline': True, 'guest_prep': True, 'scsihw': 'virtio-scsi-single',
                            'net_driver': 'virtio', 'iso': None, 'errors': [], 'warnings': []},
              two_stage={'on': True, 'why': 'a Windows guest', 'first_bus': 'sata', 'final_bus': 'scsi'},
              guest_prep={'on': True, 'tools_running': False, 'os': 'Windows Server 2022'})
    return it


WIN_CHECK = dict(CHECK, items=[_win_item('vm-1', 'legacy01'), _item('vm-2', 'legacy02', nics=2, disks=2)])


def test_runtime_the_bulk_dialog_prepares_windows_guests_and_sends_the_logins_with_the_start_only(dialog):
    app, page = dialog(check=WIN_CHECK)
    page.locator('[data-esxi-bulk-all]').check()
    page.get_by_text('Selected: 2').first.wait_for(timeout=2000)
    page.locator('[data-esxi-bulk-bar] button', has_text='Migrate to Proxmox').click()
    dlg = page.locator('[data-esxi-bulk]')
    dlg.locator('option', has_text='Testi').first.wait_for(state='attached', timeout=5000)
    _pick_targets(page)
    dlg.locator('input[placeholder="ESXi password"]').fill('pw-1')
    assert page.locator('[data-esxi-bulk-win-auto]').is_checked()
    assert page.locator('[data-esxi-bulk-two-stage]').is_checked()
    # the preset is no key at all, an unticked box is false
    page.locator('[data-esxi-bulk-two-stage]').uncheck()
    dlg.locator('button', has_text='Check the guests').click()
    _wait_bodies(app, page, 1)
    first = _bodies(app)[-1]
    assert 'install_virtio_drivers' not in first and first['two_stage_boot'] is False and first['guest_prep'] is False
    # the preparation in the guest, with one login for the run and an own one for legacy02
    dlg.locator('button', has_text='Settings').first.click()
    page.locator('[data-esxi-bulk-two-stage]').check()
    page.locator('[data-esxi-bulk-guest-prep-section] summary').click()
    page.locator('[data-esxi-bulk-guest-prep]').check()
    dlg.locator('button', has_text='Check the guests').click()
    _wait_bodies(app, page, 2)
    check = _bodies(app)[-1]
    assert check['guest_prep'] is True and 'two_stage_boot' not in check
    assert 'guest_user' not in check and 'guest_password' not in check
    page.locator('[data-esxi-bulk-guest="vm-2"] button').first.click()
    own = page.locator('[data-esxi-bulk-guest-login="vm-2"] input')
    own.nth(0).fill('LAB\\deploy')
    own.nth(1).fill(OWN_SECRET)
    assert own.nth(1).get_attribute('type') == 'password'
    dlg.locator('button', has_text='Review and start').click()
    page.get_by_text('Every guest fits the target node.').first.wait_for(timeout=5000)
    # legacy01 has none of its own and the run has none yet
    start = dlg.locator('[data-esxi-bulk-start]')
    assert start.is_disabled()
    page.locator('[data-esxi-bulk-needs-login]').wait_for(timeout=2000)
    tag = page.locator('[data-esxi-bulk-win-tag="vm-1"]')
    assert tag.inner_text().strip() == 'Windows: automatic'
    assert page.locator('[data-esxi-bulk-twostage-tag="vm-1"]').inner_text().strip() == 'Two-stage boot'
    page.locator('[data-esxi-bulk-review="vm-1"]').get_by_text('guest tools not running').wait_for(timeout=2000)
    assert page.locator('[data-esxi-bulk-win-tag="vm-2"]').count() == 0
    n = len(_bodies(app))
    dlg.locator('button', has_text='Settings').first.click()
    page.locator('[data-esxi-bulk-guest-user]').fill('Administrator')
    page.locator('[data-esxi-bulk-guest-password]').fill(SECRET)
    dlg.locator('button', has_text=re.compile(r'^\s*Review\s*$')).first.click()
    _wait_for(page, start.is_enabled, 'a login is no part of the check')
    assert len(_bodies(app)) == n
    assert SECRET not in page.evaluate(STORAGE_JS) and OWN_SECRET not in page.evaluate(STORAGE_JS)
    app.server.extra[('POST', BULK)] = (202, {'run': RUN})
    start.click()
    _wait_bodies(app, page, n + 1)
    sent = dict(_bodies(app)[-1])
    assert (sent.pop('guest_user'), sent.pop('guest_password'), sent.pop('esxi_password')) == \
        ('Administrator', SECRET, 'pw-1')
    assert sent['vms'] == ['vm-1', {'vm_id': 'vm-2', 'guest_user': 'LAB\\deploy', 'guest_password': OWN_SECRET}]
    sent['vms'] = check['vms']
    expect = dict(check)
    expect.pop('dry_run')
    assert sent == expect
    assert SECRET not in json.dumps(_bodies(app)[:-1]) and OWN_SECRET not in json.dumps(_bodies(app)[:-1])
    assert SECRET not in page.evaluate(STORAGE_JS) and OWN_SECRET not in page.evaluate(STORAGE_JS)
    assert not app.errors, app.errors
