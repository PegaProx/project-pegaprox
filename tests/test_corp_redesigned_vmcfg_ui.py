"""The configuration dialog of a QEMU VM in Corporate Redesigned (Preview), in the browser.

Round 5 keeps ConfigModal's state, fetches and save, and gives a QEMU VM in the preview one
pending changes panel instead of the red restart tags: each change with its old and new value,
whether it applies to the running VM or waits for the next start and why, the problems to fix
and the changes that already wait. Saving is only possible from the review, sends the request
the classic form sends for the same edit and never restarts anything. After the save the
dialog reads GET .../qemu/<vmid>/pending (pegaprox/api/vms.py get_vm_pending_api) and shows
that answer as the one of Proxmox VE. The General tab comes in sections, the keys without a
field are listed read only on the Options tab, a container keeps the classic dialog.

The restart classes are predicted by a pure function with a table of rules taken from
qemu-server (cr33/qemu_src/hotplug_logic.pm and QemuServer.pm); the first block checks one case
per rule against that code. PEGAPROX_CR_BUNDLE=<file> serves another bundle (the counterproof
against the build before round 5). Skips without Playwright. LW Nov 2026
"""
import copy
import os
import re

import pytest

from test_corp_redesigned_guard_ui import CFG_RAW, CFG_RICH, DETERMINISTIC, _GuardApp, _corp_cluster, _exact
from test_corp_redesigned_vm_ui import _open_guest, _VmServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LAYOUT = 'corporate-redesigned'
_BUNDLE_FILE = os.environ.get('PEGAPROX_CR_BUNDLE')
BUNDLE = open(_BUNDLE_FILE, encoding='utf-8').read() if _BUNDLE_FILE else None

CFG_URL = '/api/clusters/c1/vms/pve1/qemu/100/config'
PENDING_URL = '/api/clusters/c1/vms/pve1/qemu/100/pending'


def _cfg(status='running', **raw_over):
    """CFG_RICH (the guard's running web01) with keys of its raw config replaced or (None) removed,
    and the parsed sections following, the way manager.py get_vm_config fills them."""
    cfg = copy.deepcopy(CFG_RICH)
    raw = dict(CFG_RAW)
    for k, v in raw_over.items():
        if v is None:
            raw.pop(k, None)
        else:
            raw[k] = v
    cfg['raw'] = raw
    for section in ('general', 'hardware', 'options'):
        for k in list(cfg[section]):
            if k in raw_over:
                cfg[section][k] = raw.get(k, '')
    cfg['status'] = dict(cfg['status'], status=status)
    return cfg


class _CfgServer(_VmServer):
    """The guest view fake with the rich config, a PUT of the config that answers like vms.py and
    the pending route; each answer settable while the page runs."""

    def __init__(self, cfg=None, pending=None, put=None, **kw):
        super().__init__(config=(200, cfg or _cfg()), **kw)
        self.routes[('GET', PENDING_URL)] = pending or (200, {'pending': []})
        self.routes[('PUT', CFG_URL)] = put or (200, {'success': True, 'message': 'Configuration updated'})

    def puts(self):
        return [w for w in self.writes if w[0] == 'PUT' and w[1] == CFG_URL]


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
        app = _GuardApp(br or browser, _CfgServer(layout=layout, bundle=BUNDLE, **kw), viewport=viewport)
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.close()


def _no_errors(app):
    assert not app.errors, app.errors


def _open_config(page, tab=None):
    """The dialog of web01 from the guest page of the preview, on General or on a tab."""
    _open_guest(page, 'web01')
    page.locator('[data-cr-objhead="vm"] .cr-objhead-actions > button', has_text='Configure').click()
    page.locator('.corp-vm-modal').wait_for(timeout=8000)
    if tab:
        page.locator('.corp-vm-modal-tab', has_text=_exact(tab)).click()


def _panel(page):
    page.locator('[data-cr-vc-panel]').wait_for(timeout=8000)
    return page.locator('[data-cr-vc-panel]')


def _review(page):
    page.locator('[data-cr-vc-review-open]').click()
    page.locator('[data-cr-vc-review]').wait_for(timeout=5000)


def _rows(page):
    return page.evaluate('''() => Array.from(document.querySelectorAll('[data-cr-vc-row]')).map(r => ({
        key: r.dataset.crVcRow, cls: r.dataset.crVcClass, rule: r.dataset.crVcRule, text: r.innerText}))''')


def _vc_input(page, key):
    """A field of the preview's Hardware tab by the config key (or key.part) it writes."""
    return page.locator(f'[data-cr-vc-input="{key}"]').first


def _hw_input(page, label):
    """The input of a classic ConfigInputField on the Hardware tab, by its label (the classic one
    carries its restart tag inside the label)."""
    return page.locator(f'xpath=//div[contains(@class, "corp-vm-modal-body")]//label[starts-with(normalize-space(.), "{label}")]'
                        '/following-sibling::div[1]//input').first


# --- the rules: one case per rule of qemu-server ------------------------------------------------------

# running web01 as hotplug_logic.pm sees it: the config it runs with, its hotplug option, the body
BASE_CONF = {'cores': 2, 'sockets': 2, 'memory': 8192, 'balloon': 2048, 'ostype': 'l26', 'machine': 'pc-q35-8.1',
             'hotplug': 'network,disk,usb', 'agent': '1', 'boot': 'order=scsi0;ide2;net0',
             'scsi0': 'local-lvm:vm-100-disk-0,iothread=1,size=32G', 'ide2': 'none,media=cdrom',
             'net0': 'virtio=BC:24:11:AA:BB:CC,bridge=vmbr0,firewall=1'}
NET0 = 'virtio=BC:24:11:AA:BB:CC,bridge=vmbr0,firewall=1'
SCSI0 = 'local-lvm:vm-100-disk-0,iothread=1,size=32G'
# (case, key, value (None: a delete), conf overrides (None: the key unset), running, expected class, rule)
CASES = [
    ('stopped VM: written now, used at the next start', 'cores', 4, {}, False, 'next', 'stopped'),
    ('fast-plug option (HL 1-14)', 'name', 'web02', {}, True, 'now', 'fast-plug'),
    ('fast-plug delete (HL 188-189)', 'description', None, {}, True, 'now', 'fast-plug'),
    ('cloud-init option (HL 16-18)', 'ipconfig0', 'ip=dhcp', {}, True, 'now', 'cloudinit'),
    ('cgroup: cpulimit (HL 317-320)', 'cpulimit', 2, {}, True, 'now', 'cgroup'),
    ('hotplug option without cpu/memory (HL 229-233)', 'hotplug', 'network,disk', {}, True, 'now', 'hotplug-option'),
    ('hotplug option adding memory (HL 230-231)', 'hotplug', 'network,disk,usb,memory', {}, True, 'restart', 'hotplug-option'),
    ('hotplug option delete with cpu on (HL 150-151)', 'hotplug', None, {'hotplug': 'network,cpu'}, True, 'restart', 'hotplug-option'),
    ('tablet without usb hotplug (HL 235)', 'tablet', 1, {'hotplug': '0'}, True, 'restart', 'tablet'),
    ('tablet off with usb hotplug (HL 251-253)', 'tablet', 0, {}, True, 'now', 'tablet'),
    ('tablet on: a device plug (HL 236-250)', 'tablet', 1, {}, True, 'maybe', 'tablet'),
    ('usb on l26, machine 8.1 (HL 135-139)', 'usb0', 'host=1234:5678', {}, True, 'maybe', 'usb'),
    ('usb with an unpinned machine (HL 134)', 'usb0', 'host=1234:5678', {'machine': 'q35'}, True, 'open', 'usb'),
    ('usb with machine 6.2 (HL 137)', 'usb0', 'host=1234:5678', {'machine': 'pc-q35-6.2'}, True, 'restart', 'usb'),
    ('usb on win7 (HL 139)', 'usb0', 'host=1234:5678', {'ostype': 'win7'}, True, 'restart', 'usb'),
    ('usb with hotplug 1 = network,disk,usb (QS 1120)', 'usb0', 'host=1234:5678', {'hotplug': '1'}, True, 'maybe', 'usb'),
    ('vcpus without cpu hotplug (HL 265)', 'vcpus', 3, {}, True, 'restart', 'vcpus'),
    ('vcpus with cpu hotplug (HL 266, QS 4246-4300)', 'vcpus', 3, {'hotplug': 'network,disk,usb,cpu'}, True, 'maybe', 'vcpus'),
    ('vcpus above sockets x cores (QS 4259-4260)', 'vcpus', 8, {'hotplug': 'network,disk,usb,cpu'}, True, 'restart', 'vcpus'),
    ('balloon target change (HL 267-279)', 'balloon', 1024, {}, True, 'now', 'balloon'),
    ('balloon unset to a target: stays on (HL 269-271)', 'balloon', 1024, {'balloon': None}, True, 'now', 'balloon'),
    ('balloon off (HL 272)', 'balloon', 0, {}, True, 'restart', 'balloon'),
    ('balloon delete while off (HL 184)', 'balloon', None, {'balloon': 0}, True, 'restart', 'balloon'),
    # round 8 (N1): a live change that still runs on the node (tap_plug, set_io_throttle, change_medium) can stay
    # pending when it fails there, so it is no "applies now" but "PVE may keep it pending"
    ('net: bridge only (QS 4960-5024)', 'net0', NET0.replace('vmbr0', 'vmbr1'), {}, True, 'maybe', 'net'),
    ('net: model with network hotplug (QS 4940-4957)', 'net0', NET0.replace('virtio=', 'e1000='), {}, True, 'maybe', 'net'),
    ('net: model without network hotplug (QS 4950)', 'net0', NET0.replace('virtio=', 'e1000='), {'hotplug': 'disk'}, True, 'restart', 'net'),
    ('net: a new interface (QS 5029-5038)', 'net1', 'virtio,bridge=vmbr0', {}, True, 'maybe', 'net'),
    ('net: delete without network hotplug (HL 191)', 'net0', None, {'hotplug': '0'}, True, 'restart', 'net'),
    ('unused volume: the API handles it first (outside HL)', 'unused0', None, {'unused0': 'local-lvm:vm-100-disk-9'}, True, 'open', 'unused'),
    ('efidisk0 always waits (HL 293)', 'efidisk0', 'local-lvm:vm-100-disk-1,efitype=4m,size=4M', {}, True, 'restart', 'efi-tpm'),
    ('drive: cache on the same volume (QS 5079-5091)', 'scsi0', SCSI0 + ',cache=writeback', {}, True, 'restart', 'drive'),
    ('drive: a throttle (QS 5093-5137)', 'scsi0', SCSI0 + ',mbps_rd=100', {}, True, 'maybe', 'drive'),
    ('drive: backup flag, written (QS 5138-5140)', 'scsi0', SCSI0 + ',backup=0', {}, True, 'now', 'drive'),
    ('drive: a new scsi disk (QS 5160-5163)', 'scsi1', 'local-lvm:8', {}, True, 'maybe', 'drive'),
    ('drive: a new sata disk (QS 5160)', 'sata1', 'local-lvm:8', {}, True, 'restart', 'drive'),
    ('drive: unplug of a boot disk (QS 3963-3964)', 'scsi0', None, {}, True, 'restart', 'drive'),
    ('drive: CD/DVD medium (QS 5143-5156)', 'ide2', 'local:iso/a.iso,media=cdrom', {}, True, 'maybe', 'drive'),
    ('drive: disk to CD/DVD (QS 5061)', 'scsi0', 'local:iso/a.iso,media=cdrom', {}, True, 'restart', 'drive'),
    ('drive: new disk without disk hotplug (QS 5160)', 'scsi1', 'local-lvm:8', {'hotplug': 'network'}, True, 'restart', 'drive'),
    ('memory without memory hotplug (HL 312)', 'memory', 16384, {}, True, 'restart', 'memory'),
    ('memory with memory hotplug (HL 313, Memory.pm)', 'memory', 16384, {'hotplug': 'network,disk,usb,memory'}, True, 'maybe', 'memory'),
    ('agent: only the trim option (QS 5031-5052)', 'agent', '1,fstrim_cloned_disks=1', {}, True, 'now', 'agent'),
    ('agent: switched on (QS 5034)', 'agent', '1', {'agent': '0'}, True, 'restart', 'agent'),
    ('agent: another sub-key (QS 5041-5044)', 'agent', '1,type=isa', {}, True, 'restart', 'agent'),
    ('everything else waits (HL 323-325)', 'cores', 4, {}, True, 'restart', 'not-hotpluggable'),
    ('everything else, a delete (HL 211-212)', 'smbios1', None, {}, True, 'restart', 'not-hotpluggable'),
]
RULE_IDS = ['fast-plug', 'cloudinit', 'cgroup', 'hotplug-option', 'tablet', 'usb', 'vcpus', 'balloon', 'net', 'unused', 'efi-tpm',
            'drive', 'memory', 'agent', 'not-hotpluggable']


@pytest.fixture(scope='module')
def rules_page(browser):
    app = _GuardApp(browser, _CfgServer(layout=LAYOUT, bundle=BUNDLE))
    has = app.page.evaluate('() => !!window.PegaProxVmCfgRules')
    if not has:
        app.close()
        pytest.fail('the bundle has no restart rules (window.PegaProxVmCfgRules)')
    yield app.page
    app.close()


def _classify(page, key, value, conf, running=True, pending_known=True, changes=None):
    return page.evaluate('''([key, value, conf, running, known, changes]) => window.PegaProxVmCfgRules.classify(
        key, value === null ? undefined : value, {running, conf, changes: changes || {}, pendingKnown: known})''',
                         [key, value, conf, running, pending_known, changes])


@pytest.mark.parametrize('case,key,value,over,running,cls,rule', CASES, ids=[c[0] for c in CASES])
def test_rules_classify_like_qemu_server(rules_page, case, key, value, over, running, cls, rule):
    conf = dict(BASE_CONF)
    for k, v in over.items():
        if v is None:
            conf.pop(k, None)
        else:
            conf[k] = v
    got = _classify(rules_page, key, value, conf, running)
    assert (got['cls'], got['rule']) == (cls, rule), (case, got)
    assert got['why'].startswith('crVcWhy'), got


def test_rules_table_has_each_rule_once_with_its_source(rules_page):
    rules = rules_page.evaluate('() => window.PegaProxVmCfgRules.rules')
    assert [r['id'] for r in rules] == RULE_IDS
    assert all(r['src'] and r['keys'] for r in rules), rules
    # every rule has a case above
    assert {c[6] for c in CASES} >= set(RULE_IDS)


def test_rules_promise_nothing_while_the_pending_list_is_unknown(rules_page):
    """A rule that compares with the running config says "cannot be predicted" instead of "applies
    now" when the pending list did not load; a rule that does not read it keeps its answer."""
    bridge = _classify(rules_page, 'net0', NET0.replace('vmbr0', 'vmbr1'), dict(BASE_CONF), pending_known=False)
    assert (bridge['cls'], bridge['rule'], bridge['why']) == ('open', 'net', 'crVcWhyPendingUnknown')
    name = _classify(rules_page, 'name', 'web02', dict(BASE_CONF), pending_known=False)
    assert name['cls'] == 'now'


def test_rules_unset_hotplug_is_network_disk_usb(rules_page):
    """HL 126-127: an unset hotplug option counts as '1', which is network,disk,usb (QS 1120), never
    cpu or memory."""
    conf = {k: v for k, v in BASE_CONF.items() if k != 'hotplug'}
    assert _classify(rules_page, 'net1', 'virtio,bridge=vmbr0', conf)['cls'] == 'maybe'
    assert _classify(rules_page, 'memory', 16384, conf)['cls'] == 'restart'
    assert _classify(rules_page, 'vcpus', 3, conf)['cls'] == 'restart'


# --- the panel ----------------------------------------------------------------------------------

def test_runtime_a_change_shows_once_in_the_panel_with_its_class(open_app):
    app = open_app()
    page = app.page
    _open_config(page)
    panel = _panel(page)
    assert panel.get_attribute('data-cr-vc-panel') == 'bar'
    assert 'No unsaved changes' in panel.inner_text()
    page.locator('#cr-vc-name').fill('web02')
    mark = page.locator('[data-cr-vc-mark="name"]')
    assert 'Changed, was web01' in mark.inner_text()
    assert page.locator('[data-cr-vc-count]').get_attribute('data-cr-vc-count') == '1'
    # no save before the review, and the header has no Apply either
    assert page.locator('[data-cr-vc-save]').count() == 0
    assert page.locator('.corp-vm-modal-actions button', has_text='Apply').count() == 0
    _review(page)
    rows = _rows(page)
    assert [(r['key'], r['cls'], r['rule']) for r in rows] == [('name', 'now', 'fast-plug')]
    assert 'web01' in rows[0]['text'] and 'web02' in rows[0]['text'] and 'Applies now' in rows[0]['text']
    assert 'writes it to the configuration at once' in rows[0]['text']
    _no_errors(app)


def test_runtime_a_restart_change_is_the_only_warning(open_app):
    app = open_app()
    page = app.page
    _open_config(page, 'Hardware')
    page.get_by_text('Sockets').first.wait_for(timeout=8000)
    _vc_input(page, 'sockets').fill('4')
    page.locator('.corp-vm-modal-tab', has_text=_exact('General')).click()
    page.locator('#cr-vc-name').fill('web02')
    assert page.locator('[data-cr-vc-restart]').inner_text().strip() == '1 needs a restart'
    _review(page)
    rows = {r['key']: r for r in _rows(page)}
    assert rows['sockets']['cls'] == 'restart' and 'does not change this on a running VM' in rows['sockets']['text']
    assert rows['name']['cls'] == 'now'
    chips = page.evaluate('''() => Array.from(document.querySelectorAll('[data-cr-vc-row] .cr-vc-chip')).map(c => [
        c.closest('[data-cr-vc-row]').dataset.crVcRow, c.classList.contains('cr-vc-chip-warn')])''')
    assert dict(chips) == {'sockets': True, 'name': False}
    _no_errors(app)


def test_runtime_the_variant_draws_no_red_restart_tags(open_app):
    app = open_app()
    page = app.page
    _open_config(page, 'Hardware')
    page.get_by_text('Sockets').first.wait_for(timeout=8000)
    assert page.locator('.corp-vm-modal', has_text='NEEDS RESTART').count() == 0
    page.locator('.corp-vm-modal-tab', has_text=_exact('Options')).click()
    page.get_by_text('Boot Order').first.wait_for(timeout=8000)
    assert page.locator('.corp-vm-modal .bg-red-500\\/20', has_text=re.compile('restart', re.I)).count() == 0
    _no_errors(app)


def test_runtime_revert_and_typing_back_take_the_change_away(open_app):
    app = open_app()
    page = app.page
    _open_config(page)
    _panel(page)
    page.locator('#cr-vc-name').fill('web02')
    page.locator('[data-cr-vc-mark="name"] button', has_text='Revert').click()
    assert page.locator('#cr-vc-name').input_value() == 'web01'
    assert page.locator('[data-cr-vc-count]').get_attribute('data-cr-vc-count') == '0'
    page.locator('#cr-vc-name').fill('web02')
    page.locator('#cr-vc-name').fill('web01')
    assert page.locator('[data-cr-vc-count]').get_attribute('data-cr-vc-count') == '0'
    assert page.locator('[data-cr-vc-mark]').count() == 0
    _no_errors(app)


def test_runtime_an_invalid_name_blocks_the_save_and_says_what_to_change(open_app):
    app = open_app()
    page = app.page
    _open_config(page)
    _panel(page)
    page.locator('#cr-vc-name').fill('web_01')
    errors = page.locator('[data-cr-vc-errors]')
    assert 'The name "web_01" is not a DNS name' in errors.inner_text()
    assert 'Use letters, digits and hyphens' in errors.inner_text()
    _review(page)
    assert page.locator('[data-cr-vc-save]').is_disabled()
    page.locator('#cr-vc-name').fill('web-01')
    assert page.locator('[data-cr-vc-errors]').count() == 0
    assert not page.locator('[data-cr-vc-save]').is_disabled()
    assert not app.server.puts()
    _no_errors(app)


def test_runtime_a_change_to_a_waiting_key_is_a_conflict(open_app):
    app = open_app(pending=(200, {'pending': [{'key': 'sockets', 'value': 2, 'pending': 4}]}))
    page = app.page
    _open_config(page, 'Hardware')
    page.get_by_text('Sockets').first.wait_for(timeout=8000)
    _vc_input(page, 'sockets').fill('3')
    _review(page)
    conflict = page.locator('[data-cr-vc-conflict="sockets"]')
    assert 'sockets already has a change waiting for the next start (4). Saving replaces it.' in conflict.inner_text()
    _no_errors(app)


# --- the save and what PVE answers after it -----------------------------------------------------------

def _save(page):
    _review(page)
    page.locator('[data-cr-vc-save]').click()
    page.wait_for_function('() => { const r = document.querySelector("[data-cr-vc-result]"); return r && r.dataset.crVcResult !== "reading"; }',
                           timeout=8000)
    return page.locator('[data-cr-vc-result]')


@pytest.mark.parametrize('case', ['listed', 'nothing', 'failed'])
def test_runtime_after_the_save_the_answer_of_proxmox_ve(open_app, case):
    after = {'listed': (200, {'pending': [{'key': 'sockets', 'value': 2, 'pending': 4}]}),
             'nothing': (200, {'pending': []}),
             'failed': (502, {'error': 'Could not read the pending changes', 'upstream_status': 500})}[case]
    app = open_app()
    page = app.page
    _open_config(page, 'Hardware')
    page.get_by_text('Sockets').first.wait_for(timeout=8000)
    _vc_input(page, 'sockets').fill('4')
    page.locator('.corp-vm-modal-tab', has_text=_exact('General')).click()
    page.locator('#cr-vc-name').fill('web02')
    app.server.routes[('GET', PENDING_URL)] = after
    result = _save(page)
    text = result.inner_text()
    assert 'Reported by Proxmox VE after the save' in text
    assert app.server.puts() == [('PUT', CFG_URL, {'sockets': 4, 'name': 'web02'})]
    reads = [c for c in app.server.calls if c == ('GET', PENDING_URL)]
    assert len(reads) == 2, reads   # on open and after the save
    if case == 'listed':
        assert result.get_attribute('data-cr-vc-result') == 'ok'
        assert '1 of 2 changes wait for the next start.' in text
        verdict = dict(page.evaluate('''() => Array.from(document.querySelectorAll('[data-cr-vc-res]')).map(r => [r.dataset.crVcRes, r.dataset.crVcVerdict])'''))
        assert verdict == {'sockets': 'pending', 'name': 'applied'}
    elif case == 'nothing':
        assert 'Nothing of this save is pending: it is in effect.' in text
        verdict = dict(page.evaluate('''() => Array.from(document.querySelectorAll('[data-cr-vc-res]')).map(r => [r.dataset.crVcRes, r.dataset.crVcVerdict])'''))
        assert verdict == {'sockets': 'applied', 'name': 'applied'}
        # the prediction said restart for sockets; PVE's answer is shown and the prediction next to it
        assert '(predicted: Needs a restart)' in page.locator('[data-cr-vc-res="sockets"]').inner_text()
    else:
        assert result.get_attribute('data-cr-vc-result') == 'error'
        assert 'could not be read (HTTP 500)' in text and 'Proxmox VE decides' in text
        assert page.locator('[data-cr-vc-res]').count() == 0
    # nothing but the config write: no start, stop, reboot or reset of the VM
    assert [w[:2] for w in app.server.writes] == [('PUT', CFG_URL)]
    assert page.locator('[data-cr-vc-count]').get_attribute('data-cr-vc-count') == '0'
    _no_errors(app)


def test_runtime_a_refused_save_keeps_the_changes_and_reads_the_pending_list(open_app):
    app = open_app(put=(500, {'error': 'hotplug problem - vcpus'}))
    page = app.page
    _open_config(page)
    _panel(page)
    page.locator('#cr-vc-name').fill('web02')
    result = _save(page)
    assert result.get_attribute('data-cr-vc-saved') == '0'
    assert 'The save was not accepted' in result.inner_text()
    assert page.locator('[data-cr-vc-count]').get_attribute('data-cr-vc-count') == '1'
    _no_errors(app)


def test_runtime_a_stopped_vm_saves_for_its_next_start(open_app):
    app = open_app(cfg=_cfg(status='stopped'))
    page = app.page
    _open_config(page, 'Hardware')
    page.get_by_text('Sockets').first.wait_for(timeout=8000)
    _vc_input(page, 'sockets').fill('4')
    _review(page)
    row = _rows(page)[0]
    assert (row['cls'], row['rule']) == ('next', 'stopped') and 'At the next start' in row['text']
    assert page.locator('[data-cr-vc-restart]').count() == 0
    page.locator('[data-cr-vc-save]').click()
    page.wait_for_function('() => document.querySelector("[data-cr-vc-result=ok]")', timeout=8000)
    assert 'The VM is not running; it uses the new configuration at its next start.' in page.locator('[data-cr-vc-result]').inner_text()
    _no_errors(app)


# --- the same request as the classic form -----------------------------------------------------------------

def _edit_general(page, variant):
    """Rename to web02, add the tag db, write a description, set sockets to 4 (Hardware tab)."""
    if variant:
        page.locator('#cr-vc-name').fill('web02')
        tag = page.get_by_placeholder('Add a tag, then Enter')
        tag.fill('db')
        tag.press('Enter')
        page.locator('[data-cr-vc-sec="description"] button', has_text=_exact('Edit')).click()
        page.locator('[data-cr-vc-sec="description"] textarea').fill('New text')
    else:
        page.locator('input[value="web01"]').first.fill('web02')
        tag = page.get_by_placeholder('Add tag...')
        tag.fill('db')
        tag.press('Enter')
        page.locator('.corp-vm-modal-body button', has_text=_exact('Edit')).first.click()
        page.locator('.corp-vm-modal-body textarea').first.fill('New text')
    page.locator('.corp-vm-modal-tab', has_text=_exact('Hardware')).click()
    page.get_by_text('Sockets').first.wait_for(timeout=8000)
    (_vc_input(page, 'sockets') if variant else _hw_input(page, 'Sockets')).fill('4')


def test_runtime_the_save_sends_what_the_classic_form_sends(browser):
    bodies = {}
    for layout in ('corporate', LAYOUT):
        server = _CfgServer(layout=layout, bundle=BUNDLE)
        app = _GuardApp(browser, server)
        try:
            page = app.page
            if layout == 'corporate':
                _corp_cluster(page)
                page.locator('.corp-tree-child', has_text='web01').first.click()
                page.locator('.corp-toolbar button', has_text=_exact('Configure')).first.click()
                page.locator('input[value="web01"]').first.wait_for(timeout=8000)
                _edit_general(page, False)
                page.locator('.corp-vm-modal button', has_text=_exact('Save')).last.click()
            else:
                _open_config(page)
                _panel(page)
                _edit_general(page, True)
                _review(page)
                page.locator('[data-cr-vc-save]').click()
            for _ in range(50):
                if server.puts():
                    break
                page.wait_for_timeout(100)
            bodies[layout] = server.puts()
            assert not app.errors, (layout, app.errors)
        finally:
            app.close()
    assert bodies['corporate'] == [('PUT', CFG_URL, {'name': 'web02', 'tags': 'prod;web;db', 'description': 'New text',
                                                     'sockets': 4})], bodies
    assert bodies[LAYOUT] == bodies['corporate']


# --- the General tab, the other settings, the container ------------------------------------------

def test_runtime_the_general_tab_in_sections(open_app):
    app = open_app()
    page = app.page
    _open_config(page)
    page.locator('[data-cr-vc-general]').wait_for(timeout=8000)
    secs = page.evaluate('() => Array.from(document.querySelectorAll("[data-cr-vc-sec]")).map(s => s.dataset.crVcSec)')
    assert secs == ['identity', 'os', 'tags', 'description']
    ro = page.evaluate('() => Object.fromEntries(Array.from(document.querySelectorAll("[data-cr-vc-ro]")).map(e => [e.dataset.crVcRo, e.innerText.trim()]))')
    assert ro == {'vmid': '100', 'node': 'pve1', 'cluster': 'Testi'}
    assert page.locator('#cr-vc-ostype').input_value() == 'l26'
    assert page.locator('#cr-vc-ostype option').count() == 13
    tags = page.evaluate('() => Array.from(document.querySelectorAll("[data-cr-vc-tag]")).map(e => e.dataset.crVcTag)')
    assert tags == ['prod', 'web']
    assert 'behind' in page.locator('[data-cr-vc-sec="description"] .cr-vc-md strong').inner_text()
    state = page.locator('[data-cr-vc-state]').inner_text()
    assert 'Running' in state and '3.1%' in state and '3.0 GB' in state
    # a bad tag is said in place, nothing is added
    tag = page.get_by_placeholder('Add a tag, then Enter')
    tag.fill('Bad Tag')
    tag.press('Enter')
    assert '"Bad Tag" is not a valid tag' in page.locator('[data-cr-vc-tag-error]').inner_text()
    assert page.locator('[data-cr-vc-count]').get_attribute('data-cr-vc-count') == '0'
    page.locator('[data-cr-vc-tag="web"] button').click()
    assert page.locator('[data-cr-vc-mark="tags"]').count() == 1
    _no_errors(app)


def test_runtime_the_other_settings_list_every_key_without_a_field(open_app):
    app = open_app(cfg=_cfg(args='-no-hpet', cipassword='secret-hash'))
    page = app.page
    _open_config(page, 'Options')
    other = page.locator('[data-cr-vc-other]')
    other.wait_for(timeout=8000)
    keys = page.evaluate('() => Array.from(document.querySelectorAll("[data-cr-vc-other-key]")).map(e => e.dataset.crVcOtherKey)')
    assert keys == ['args', 'cipassword', 'meta', 'tablet']   # cpuunits has a field on Hardware, startup on Options now
    assert 'digest' not in keys and 'cores' not in keys and 'net0' not in keys
    assert page.locator('[data-cr-vc-other-key="tablet"] dd').inner_text() == '0'
    assert page.locator('[data-cr-vc-other-key="cipassword"] dd').inner_text() == '**********'
    assert 'secret-hash' not in other.inner_text()
    _no_errors(app)


def test_runtime_a_container_keeps_the_classic_dialog(open_app):
    app = open_app()
    page = app.page
    _open_guest(page, 'ct01', kind='ct')
    page.locator('[data-cr-objhead="ct"] .cr-objhead-actions > button', has_text='Configure').click()
    page.locator('.corp-vm-modal').wait_for(timeout=8000)
    page.locator('input[value="ct01"]').first.wait_for(timeout=8000)
    assert page.locator('[data-cr-vc-panel], [data-cr-vc-general]').count() == 0
    assert page.locator('.corp-vm-modal button', has_text=_exact('Save')).count() == 1
    assert not [c for c in app.server.calls if c[1].endswith('/pending')]
    _no_errors(app)


def test_runtime_classic_corporate_is_unchanged(browser):
    server = _CfgServer(layout='corporate', bundle=BUNDLE)
    app = _GuardApp(browser, server)
    try:
        page = app.page
        _corp_cluster(page)
        page.locator('.corp-tree-child', has_text='web01').first.click()
        page.locator('.corp-toolbar button', has_text=_exact('Configure')).first.click()
        page.locator('input[value="web01"]').first.wait_for(timeout=8000)
        page.locator('.corp-vm-modal-tab', has_text=_exact('Hardware')).click()
        page.get_by_text('Sockets').first.wait_for(timeout=8000)
        assert page.locator('.corp-vm-modal', has_text='NEEDS RESTART').count() == 1
        assert page.locator('[data-cr-vc-panel], [data-cr-vc-general], [data-cr-vc-other]').count() == 0
        assert not [c for c in server.calls if c[1].endswith('/pending')]
        assert not app.errors, app.errors
    finally:
        app.close()


# --- layout ------------------------------------------------------------------------------------------

@pytest.mark.parametrize('engine', ['chromium', 'firefox'])
@pytest.mark.parametrize('width', [1600, 1280])
def test_runtime_the_dialog_fits_without_sideways_scroll(browser, firefox, engine, width):
    br = browser if engine == 'chromium' else firefox
    server = _CfgServer(layout=LAYOUT, bundle=BUNDLE)
    app = _GuardApp(br, server, viewport=(width, 900))
    try:
        page = app.page
        _open_config(page)
        _panel(page)
        page.locator('#cr-vc-name').fill('web02')
        _review(page)
        over = page.evaluate('''() => [document.documentElement, document.querySelector('.corp-vm-modal-body'),
            document.querySelector('[data-cr-vc-panel]'), document.querySelector('[data-cr-vc-general]')]
            .map(e => e.scrollWidth - e.clientWidth)''')
        assert all(o <= 0 for o in over), over
        cols = page.evaluate('() => getComputedStyle(document.querySelector(".cr-vc-cols")).gridTemplateColumns.split(" ").length')
        assert cols == 2
        assert not app.errors, app.errors
    finally:
        app.close()
