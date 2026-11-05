"""Follow-ups to the review of the VM configuration dialog in Corporate Redesigned (Preview).

- A key that waits for the next start, set back to the value the VM runs with, is no restart:
  update_vm writes it and cleanup_pending drops the waiting entry (pve-guest-common
  AbstractConfig.pm 139-170, qemu-server API2/Qemu.pm 2617-2622). The same for a key that only waits
  to be added and is deleted again.
- After a refused or partly failed save only the keys of the failed request can be "not saved", and
  PVE applies and writes what it can before it raises the error (API2/Qemu.pm 2641): the dialog reads
  the config once after a refused config write and counts a key stored as sent as saved.
- The RNG and virtiofs cards carry no permanent yellow restart pill in the variant.
- A live update of the config (the pegaprox-vm-config event) reads the pending list again.
- The reasons for a live NIC, disk limit or CD/DVD change say that a failure leaves it pending.

PEGAPROX_CR_BUNDLE=<file> serves another bundle (the counterproof). Skips without Playwright.
LW Nov 2026
"""
import os

import pytest

from test_corp_redesigned_guard_ui import _GuardApp, _corp_cluster, _exact
from test_corp_redesigned_vmcfg_ui import (BASE_CONF, BUNDLE, CFG_URL, LAYOUT, ROOT, NET0 as NET0_VALUE, PENDING_URL, _CfgServer,  # noqa: F401
                                           _cfg, _no_errors, _open_config, _panel, _review, _rows, _save, _vc_input,
                                           browser, firefox, open_app, playwright)
from test_corp_redesigned_vmcfg_tabs_ui import NET0, _app, _flip, _pending_reads, _tab


# --- a change back to what the VM runs with ----------------------------------------------------------

@pytest.fixture(scope='module')
def rules_page(browser):
    app = _GuardApp(browser, _CfgServer(layout=LAYOUT, bundle=BUNDLE))
    app.page.wait_for_function('() => !!window.PegaProxVmCfgRules', timeout=15000)
    yield app.page
    app.close()


def _classify(page, key, value, pending, running=True, known=True):
    return page.evaluate('''([key, value, pending, running, known, conf]) => window.PegaProxVmCfgRules.classify(
        key, value === null ? undefined : value, {running, conf, changes: {}, pendingKnown: known, pending})''',
                         [key, value, pending, running, known, _running_conf(pending)])


def _running_conf(pending):
    """BASE_CONF as the VM runs with it: each waiting key at its current value, a waiting add out."""
    conf = dict(BASE_CONF)
    for p in pending:
        if 'value' in p:
            conf[p['key']] = p['value']
        else:
            conf.pop(p['key'], None)
    return conf


E1000 = NET0_VALUE.replace('virtio=', 'e1000=')
# (case, key, value (None: a delete), pending rows, running, pending list read, class, rule)
PENDING_CASES = [
    ('sockets back to the running 2 while 4 waits', 'sockets', 2, [{'key': 'sockets', 'value': 2, 'pending': 4}],
     True, True, 'now', 'cancels-pending'),
    ('the same, as text', 'sockets', '2', [{'key': 'sockets', 'value': '2', 'pending': '4'}], True, True, 'now', 'cancels-pending'),
    ('a third value replaces what waits', 'sockets', 3, [{'key': 'sockets', 'value': 2, 'pending': 4}],
     True, True, 'restart', 'not-hotpluggable'),
    ('net0 back to the running model while e1000 waits', 'net0', NET0_VALUE, [{'key': 'net0', 'value': NET0_VALUE, 'pending': E1000}],
     True, True, 'now', 'cancels-pending'),
    ('a key that waits as a delete, set back to its value', 'smbios1', 'uuid=1', [{'key': 'smbios1', 'value': 'uuid=1', 'delete': 1}],
     True, True, 'now', 'cancels-pending'),
    ('a key that only waits to be added, deleted again', 'serial0', None, [{'key': 'serial0', 'pending': 'socket'}],
     True, True, 'now', 'cancels-pending'),
    ('a delete of a key that runs and waits for a change', 'smbios1', None, [{'key': 'smbios1', 'value': 'uuid=1', 'pending': 'uuid=2'}],
     True, True, 'restart', 'not-hotpluggable'),
    ('the pending list was not read: no promise', 'sockets', 2, [{'key': 'sockets', 'value': 2, 'pending': 4}],
     True, False, 'restart', 'not-hotpluggable'),
    ('a stopped VM keeps its class', 'sockets', 2, [{'key': 'sockets', 'value': 2, 'pending': 4}], False, True, 'next', 'stopped'),
]


@pytest.mark.parametrize('case,key,value,pending,running,known,cls,rule', PENDING_CASES, ids=[c[0] for c in PENDING_CASES])
def test_rules_a_change_back_to_the_running_value_drops_what_waits(rules_page, case, key, value, pending, running, known, cls, rule):
    got = _classify(rules_page, key, value, pending, running, known)
    assert (got['cls'], got['rule']) == (cls, rule), (case, got)
    if rule == 'cancels-pending':
        assert got['why'] == 'crVcWhyCancels', got


def test_rules_the_cancel_step_names_its_source(rules_page):
    before = rules_page.evaluate('() => window.PegaProxVmCfgRules.before || []')
    assert [b['id'] for b in before] == ['cancels-pending']
    assert 'cleanup_pending' in before[0]['src'] and '2617-2622' in before[0]['src']


def test_runtime_a_change_back_to_the_running_value_needs_no_restart(open_app):
    # PVE: sockets runs with 2, 4 waits for the next start; the form (pending-merged) shows 4
    app = open_app(cfg=_cfg(sockets=4), pending=(200, {'pending': [{'key': 'sockets', 'value': 2, 'pending': 4}]}))
    page = app.page
    _open_config(page, 'Hardware')
    page.get_by_text('Sockets').first.wait_for(timeout=8000)
    _vc_input(page, 'sockets').fill('2')
    _review(page)
    rows = _rows(page)
    assert [(r['key'], r['cls'], r['rule']) for r in rows] == [('sockets', 'now', 'cancels-pending')], rows
    assert 'Proxmox VE drops the change that waits for the next start, so nothing needs a restart.' in rows[0]['text']
    assert page.locator('[data-cr-vc-restart]').count() == 0
    # not a conflict: the save takes the waiting change out, it does not replace it with another
    assert page.locator('[data-cr-vc-conflict="sockets"]').count() == 0
    _no_errors(app)


# --- the result of a refused or partly failed save ---------------------------------------------------

def _verdicts(page):
    return {r[0]: (r[1], r[2]) for r in page.evaluate('''() => Array.from(document.querySelectorAll('[data-cr-vc-res]')).map(r =>
        [r.dataset.crVcRes, r.dataset.crVcVerdict, r.querySelector('.cr-vc-chip').innerText])''')}


@pytest.mark.parametrize('engine', ['chromium', 'firefox'])
def test_runtime_a_refused_save_tells_applied_waiting_and_unsaved_apart(open_app, firefox, engine):
    """PVE took name (fast plug) and wrote sockets to pending, then raised the error; cores never got
    written. The result says so per key, from the pending list and the config read after the error."""
    app = open_app(put=(400, {'error': 'parameter verification failed'}), viewport=(1280, 900),
                   br=firefox if engine == 'firefox' else None)
    page = app.page
    _open_config(page, 'Hardware')
    page.get_by_text('Sockets').first.wait_for(timeout=8000)
    _vc_input(page, 'sockets').fill('4')
    _vc_input(page, 'cores').fill('3')
    page.locator('.corp-vm-modal-tab', has_text=_exact('General')).click()
    page.locator('#cr-vc-name').fill('web02')
    # what PVE has after the refused request: the config pending-merged, the pending list
    app.server.routes[('GET', CFG_URL)] = (200, _cfg(name='web02', sockets=4))
    app.server.routes[('GET', PENDING_URL)] = (200, {'pending': [{'key': 'sockets', 'value': 2, 'pending': 4}]})
    reads = len([c for c in app.server.calls if c == ('GET', CFG_URL)])
    result = _save(page)
    assert result.get_attribute('data-cr-vc-saved') == '0'
    assert _verdicts(page) == {'name': ('applied', 'in effect'), 'sockets': ('pending', 'waits for the next start'),
                               'cores': ('unsaved', 'not saved')}
    assert 'Proxmox VE can have taken part of it before the error' in result.inner_text()
    # the config was read once after the refused write; what it stores is no change any more
    assert len([c for c in app.server.calls if c == ('GET', CFG_URL)]) == reads + 1
    assert page.locator('[data-cr-vc-count]').get_attribute('data-cr-vc-count') == '1'
    if page.locator('[data-cr-vc-review]').count() == 0:
        _review(page)
    assert [r['key'] for r in _rows(page)] == ['cores']
    # the longer result fits at 1280: no sideways scroll of the page or the panel
    assert page.evaluate('() => document.documentElement.scrollWidth <= window.innerWidth')
    assert page.evaluate('() => { const p = document.querySelector("[data-cr-vc-panel]"); return p.scrollWidth <= p.clientWidth; }')
    # the save sent the classic body once and nothing else
    assert [w for w in app.server.writes if w[0] != 'GET'] == [('PUT', CFG_URL, {'sockets': 4, 'cores': 3, 'name': 'web02'})]
    _no_errors(app)


@pytest.mark.parametrize('failing', ['config', 'interface'])
def test_runtime_one_failed_request_of_a_save_does_not_unsave_the_other(open_app, failing):
    app = _app(open_app)
    page = app.page
    if failing == 'config':
        app.server.routes[('PUT', CFG_URL)] = (500, {'error': 'Configuration update failed'})
    else:
        app.server.routes[('PUT', NET0)] = (400, {'error': "bridge 'vmbr0' does not exist"})
    _tab(page, 'Network', '[data-cr-vc-net]')
    page.wait_for_timeout(300)
    _vc_input(page, 'net0.tag').fill('40')
    page.locator('.corp-vm-modal-tab', has_text=_exact('Options')).click()
    page.locator('[data-cr-vc-opts]').wait_for(timeout=5000)
    _flip(page, 'protection')
    if failing == 'config':
        app.server.routes[('GET', CFG_URL)] = (200, _cfg(net0='virtio=BC:24:11:AA:BB:CC,bridge=vmbr0,tag=40,firewall=1'))
    result = _save(page)
    assert result.get_attribute('data-cr-vc-saved') == '0'
    got = _verdicts(page)
    if failing == 'config':
        assert got == {'net0': ('applied', 'in effect'), 'protection': ('unsaved', 'not saved')}
    else:
        assert got == {'net0': ('unsaved', 'not saved'), 'protection': ('applied', 'in effect')}
    _no_errors(app)


# --- no permanent restart pill on the RNG and virtiofs cards -----------------------------------------

def test_runtime_the_rng_and_virtiofs_cards_carry_no_restart_pill(open_app):
    app = open_app()
    page = app.page
    _open_config(page, 'Hardware')
    page.locator('[data-cr-vc-hw]').wait_for(timeout=8000)
    for slot, card in (('rng', '[data-rng-card]'), ('virtiofs', '[data-vfs-card]')):
        loc = page.locator(f'[data-cr-vc-slot="{slot}"] {card}')
        assert loc.count() == 1, slot
        assert 'Changes active after restart' not in loc.inner_text(), slot
    _no_errors(app)


def test_runtime_classic_corporate_keeps_the_pill(browser):
    server = _CfgServer(layout='corporate', bundle=BUNDLE)
    app = _GuardApp(browser, server)
    try:
        page = app.page
        _corp_cluster(page)
        page.locator('.corp-tree-child', has_text='web01').first.click()
        page.locator('.corp-toolbar button', has_text=_exact('Configure')).first.click()
        page.locator('input[value="web01"]').first.wait_for(timeout=8000)
        page.locator('.corp-vm-modal-tab', has_text=_exact('Hardware')).click()
        page.locator('[data-rng-card]').wait_for(timeout=8000)
        assert 'Changes active after restart' in page.locator('[data-rng-card]').inner_text()
        assert 'Changes active after restart' in page.locator('[data-vfs-card]').inner_text()
        assert not app.errors, app.errors
    finally:
        app.close()


# --- a live update of the config reads the pending list again --------------------------------------

def test_runtime_a_live_config_update_reads_the_pending_list_again(open_app):
    app = open_app()
    page = app.page
    _open_config(page, 'Hardware')
    page.get_by_text('Sockets').first.wait_for(timeout=8000)
    _panel(page)
    page.wait_for_function('() => document.querySelector("[data-cr-vc-panel]")', timeout=5000)
    for _ in range(50):
        if _pending_reads(app) >= 1:
            break
        page.wait_for_timeout(100)
    before = _pending_reads(app)
    # another admin set sockets to 4 on the running VM: it waits, the event brings the merged config
    app.server.routes[('GET', PENDING_URL)] = (200, {'pending': [{'key': 'sockets', 'value': 2, 'pending': 4}]})
    page.evaluate('''() => window.dispatchEvent(new CustomEvent('pegaprox-vm-config',
        {detail: {vmid: 100, vm_type: 'qemu', config: {raw: {sockets: 4}}}}))''')
    for _ in range(50):
        if _pending_reads(app) > before:
            break
        page.wait_for_timeout(100)
    assert _pending_reads(app) == before + 1
    # the prediction compares with what runs (2): a change to 3 replaces the waiting 4
    _vc_input(page, 'sockets').fill('3')
    _review(page)
    assert page.locator('[data-cr-vc-conflict="sockets"]').count() == 1
    _no_errors(app)


# --- the reasons of a live change say what a failure does ------------------------------------------

def test_runtime_a_live_interface_change_says_a_failure_stays_pending(open_app):
    app = _app(open_app)
    page = app.page
    _tab(page, 'Network', '[data-cr-vc-net]')
    page.wait_for_timeout(300)
    _vc_input(page, 'net0.tag').fill('40')
    _review(page)
    row = [r for r in _rows(page) if r['key'] == 'net0'][0]
    # round 8 (N1): no "applies now" for a live change the node can fail
    assert row['cls'] == 'maybe', row
    assert 'Proxmox VE can keep it pending instead (a missing bridge, for example), then the save reports the error.' in row['text']
    _no_errors(app)


def test_runtime_a_disk_flag_change_is_written_at_once(open_app):
    # round 8 (N1): a disk change with no limit in it goes to the configuration only; a limit is
    # "PVE may keep it pending" (test_corp_redesigned_decisions_ui)
    app = _app(open_app)
    page = app.page
    _tab(page, 'Disks', '[data-cr-vc-disks]')
    _flip(page, 'scsi0.backup')
    _review(page)
    row = _rows(page)[0]
    assert (row['key'], row['cls']) == ('scsi0', 'now'), row
    assert 'Disk settings such as backup or replication are written to the configuration at once' in row['text']
    _no_errors(app)


def test_the_cd_reason_says_a_failure_stays_pending(rules_page):
    # a medium change has its own request in the dialog; the rule's reason is checked in the bundle
    got = _classify(rules_page, 'ide2', 'local:iso/a.iso,media=cdrom', [])
    assert (got['cls'], got['why']) == ('maybe', 'crVcWhyCdrom'), got
    bundle = BUNDLE or open(os.path.join(ROOT, 'web', 'index.html'), encoding='utf-8').read()
    assert 'the change applies at once when Proxmox VE accepts it. Proxmox VE can keep it pending instead, then the save reports the error."' in bundle
    assert '"Das Medium eines CD/DVD-Laufwerks wird im Betrieb gewechselt: Der Wechsel wirkt sofort, wenn Proxmox VE ihn annimmt.' in bundle


# --- what already waits, told on open ----------------------------------------------------------------

WAITING = {'pending': [{'key': 'sockets', 'value': 2, 'pending': 4}, {'key': 'rng0', 'value': 'source=/dev/urandom', 'delete': 1}]}


def _bar(page):
    return page.evaluate('''() => {
        const chip = document.querySelector('[data-cr-vc-waiting]');
        const unread = document.querySelector('[data-cr-vc-pend-unread-bar]');
        return {count: document.querySelector('[data-cr-vc-count]').dataset.crVcCount,
                chip: chip && {n: chip.dataset.crVcWaiting, text: chip.innerText, warn: chip.classList.contains('cr-vc-chip-warn')},
                unread: unread && unread.innerText,
                wide: document.documentElement.scrollWidth > window.innerWidth};
    }''')


@pytest.mark.parametrize('engine', ['chromium', 'firefox'])
def test_runtime_what_already_waits_is_told_on_open(open_app, firefox, engine):
    """Nothing edited yet: the bar still says that two changes wait for the next start, and lists
    them as PVE reports them."""
    app = open_app(cfg=_cfg(sockets=4), pending=(200, WAITING), viewport=(1280, 900),
                   br=firefox if engine == 'firefox' else None)
    page = app.page
    _open_config(page)
    page.locator('[data-cr-vc-waiting]').wait_for(timeout=8000)
    bar = _bar(page)
    assert bar['count'] == '0' and bar['unread'] is None and not bar['wide'], bar
    assert bar['chip'] == {'n': '2', 'text': '2 changes wait for the next start', 'warn': True}, bar
    page.locator('[data-cr-vc-waiting]').click()
    rows = page.evaluate('''() => Array.from(document.querySelectorAll('[data-cr-vc-waiting-row]')).map(r =>
        [r.dataset.crVcWaitingRow, r.innerText.replace(/\\s+/g, ' ')])''')
    assert [r[0] for r in rows] == ['sockets', 'rng0'], rows
    assert '2' in rows[0][1] and '4' in rows[0][1] and rows[1][1].endswith('removed'), rows
    assert 'as reported by Proxmox VE' in page.locator('[data-cr-vc-waiting-list]').inner_text()
    assert not _bar(page)['wide']
    _no_errors(app)


def test_runtime_a_stopped_vm_tells_what_waits_without_the_warning(open_app):
    app = open_app(cfg=_cfg(status='stopped', sockets=4), pending=(200, {'pending': WAITING['pending'][:1]}))
    page = app.page
    _open_config(page)
    page.locator('[data-cr-vc-waiting]').wait_for(timeout=8000)
    assert _bar(page)['chip'] == {'n': '1', 'text': '1 change waits for the next start', 'warn': False}
    _no_errors(app)


def test_runtime_a_failed_pending_read_is_told_on_open(open_app):
    app = open_app(pending=(502, {'error': 'Could not read the pending changes', 'upstream_status': 500}))
    page = app.page
    _open_config(page)
    page.locator('[data-cr-vc-pend-unread-bar]').wait_for(timeout=8000)
    bar = _bar(page)
    assert bar['chip'] is None and bar['unread'] == 'Waiting changes could not be read', bar
    _no_errors(app)


def test_runtime_nothing_waiting_adds_nothing_to_the_bar(open_app):
    app = open_app()
    page = app.page
    _open_config(page)
    page.locator('[data-cr-vc-count]').wait_for(timeout=8000)
    page.wait_for_timeout(500)
    bar = _bar(page)
    assert bar['chip'] is None and bar['unread'] is None, bar
    _no_errors(app)


# --- the CPU type select, grouped by family ----------------------------------------------------------

def test_runtime_the_cpu_types_are_grouped_by_family(open_app):
    """The cluster's list (host and max first, the rest by name, as get_cpu_types answers) is shown
    in groups; the vendor split is PVE's own, a custom model goes to its own group, nothing is lost."""
    cpu_types = ['host', 'max', '486', 'Broadwell', 'custom-fleet', 'EPYC-Genoa', 'EPYC-Turin', 'GraniteRapids-v3',
                 'kvm64', 'Opteron_G5', 'phenom', 'qemu64', 'x86-64-v2-AES', 'x86-64-v3']
    app = _app(open_app)
    app.server.routes[('GET', '/api/hardware-options')] = (200, {'cpu_types': cpu_types, 'network_models': [],
                                                                 'scsi_controllers': [], 'machine_types': []})
    page = app.page
    _tab(page, 'Hardware', '[data-cr-vc-input="cputype"]')
    page.wait_for_function('''() => !!document.querySelector('[data-cr-vc-input="cputype"] option[value="custom-fleet"]')''',
                           timeout=8000)
    groups = page.evaluate('''() => Array.from(document.querySelectorAll('[data-cr-vc-input="cputype"] optgroup')).map(g =>
        [g.dataset.crVcCpuGroup, g.label, Array.from(g.querySelectorAll('option')).map(o => o.value)])''')
    assert groups == [
        ['host', 'Host CPU', ['host', 'max']],
        ['level', 'x86-64 levels (portable)', ['x86-64-v2-AES', 'x86-64-v3']],
        ['generic', 'Generic QEMU/KVM', ['kvm64', 'qemu64']],
        ['intel', 'Intel', ['486', 'Broadwell', 'GraniteRapids-v3']],
        ['amd', 'AMD', ['EPYC-Genoa', 'EPYC-Turin', 'Opteron_G5', 'phenom']],
        ['custom', 'Custom models of this cluster', ['custom-fleet']],
    ], groups
    # the stored type is still the selected one, inside its group
    assert _vc_input(page, 'cputype').input_value() == 'x86-64-v2-AES'
    _no_errors(app)
