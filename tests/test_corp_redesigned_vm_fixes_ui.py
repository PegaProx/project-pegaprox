"""Guests in Corporate Redesigned: what the summary, the Snapshots tab and the configuration
dialog show, in the browser.

- An XCP-ng guest: its config (no raw, a 'networks' list) is read as read, the hardware comes from its
  own fields (vCPUs, memory and sizes in bytes, VIFs), its description is shown (classic Corporate
  too), Proxmox HA and the QEMU guest agent are not applicable, the addresses come from its row.
- The hardware, the description and the agent line are read again when the configuration dialog
  closes or a vm_config frame names the guest; the old panel stays until the answer is in.
- A lock the guest list gains or loses asks the lock route again, so the line and Unlock follow it.
- A failed snapshot, backup, replication, history or firewall read is said with Retry (redesign
  only), never an empty list or a 'Disabled' switch; classic Corporate keeps its tabs.
- The empty Snapshots tab has its hint (the key existed in no language).
- The agent line keeps the classic link to the guest agent's guide, the agent info the login times.
- Memory given as a property string ('current=4096') is read like the dialog reads it.
- A guest-info answer of the wrong shape does not take the header down.

The fake serves the shapes of pegaprox/api/vms.py (lock, guest-info, config, snapshots, backups,
firewall), pegaprox/core/xcpng.py (get_vms, get_vm_config) and pegaprox/api/clusters.py
(proxmox-ha/resources). PEGAPROX_CR_BUNDLE=<file> serves another bundle (the counterproof against
the bundle before this round). Skips without Playwright. LW Nov 2026
"""
import copy

import pytest

from test_corp_redesigned_dashboard_ui import CLUSTERS
from test_corp_redesigned_guard_ui import _exact
from test_corp_redesigned_vm_ui import (AGENT_DOWN, GIB, GUEST_INFO, LAYOUT, LOCK_BACKUP, LOCK_OK, WEB_RAW, _calls,  # noqa: F401
                                        _health, _no_errors, _open_guest, _read_guests_again, _settled_health,
                                        _vm_config, _wait, browser, open_app, playwright)

Q100 = '/api/clusters/c1/vms/pve1/qemu/100'

# --- XCP-ng --------------------------------------------------------------------------------------

# get_vms of core/xcpng.py: type qemu, the addresses of the guest metrics in the row
XCP_VM = {'vmid': 100, 'name': 'web01', 'status': 'running', 'type': 'qemu', 'node': 'pve1', 'cpu': 0.05,
          'cpu_percent': 5, 'maxcpu': 4, 'mem': 2 * GIB, 'maxmem': 4 * GIB, 'mem_percent': 50, 'disk': 0,
          'maxdisk': 32 * GIB, 'uptime': 3600, 'netin': 0, 'netout': 0, 'template': '', 'tags': [], 'lock': '',
          'uuid': '9b1d3c1e-0000-4000-8000-000000000001', 'ip_addresses': ['10.0.0.70']}
# get_vm_config of core/xcpng.py as the route unwraps it (vms.py _get_vm_config_response): no raw
XCP_CFG = {'name': 'web01', 'description': 'XCP guest: billing front end', 'memory': 4 * GIB, 'vcpus': 4,
           'vcpus_at_startup': 2, 'power_state': 'Running', 'os_version': {'name': 'Debian 12'},
           'platform': {'device-model': 'qemu-upstream-compat'}, 'uuid': XCP_VM['uuid'],
           'disks': [{'id': '0', 'size': 32 * GIB, 'used': 9 * GIB, 'storage': 'Local storage', 'name': 'web01 0',
                      'uuid': 'vdi-1', 'bootable': True}],
           'cdroms': [{'device': '3', 'empty': True}],
           'networks': [{'id': '0', 'mac': 'aa:bb:cc:00:11:22', 'network': 'Pool-wide network', 'bridge': 'xenbr0', 'mtu': '1500'}],
           'boot_params': '', 'ha_restart_priority': ''}
XCP_LOCK = {'locked': False, 'lock_reason': None, 'lock_description': None, 'unlock_command': 'qm unlock 100'}


def _xcp(open_app, layout=LAYOUT):
    app = open_app(layout=layout, guests=[XCP_VM], lock=(200, XCP_LOCK), agent=(200, AGENT_DOWN), config=(200, XCP_CFG),
                   fsinfo=(200, {'agent_running': False, 'filesystems': [], 'reason': None}))
    app.server.clusters = [dict(CLUSTERS[0], cluster_type='xcpng')] + [dict(c) for c in CLUSTERS[1:]]
    # the cluster list was read on load: read it again with the XCP-ng type
    app.page.reload()
    app.wait_for_app()
    return app


def _group(page, gid):
    return page.locator(f'[data-cr-vm-hwgroup="{gid}"]').inner_text()


def test_runtime_an_xcpng_guest_is_read_from_its_own_config(open_app):
    app = _xcp(open_app)
    page = app.page
    _open_guest(page, 'web01')
    # the config answered 200: it is read, not "could not be read" (the 'networks' key broke the parse)
    page.locator('[data-cr-vm-hw="ok"]').wait_for(timeout=8000)
    assert page.locator('[data-cr-vm-hw-note]').count() == 0
    assert _group(page, 'cpu').splitlines()[1:] == ['4 vCPUs', '2 at boot'], _group(page, 'cpu')
    assert '4.0 GB' in _group(page, 'memory'), _group(page, 'memory')
    disks = _group(page, 'disks')
    assert 'Local storage · 32.0 GB' in disks and 'CD/DVD 3' in disks and 'empty' in disks, disks
    assert 'VIF 0' in _group(page, 'network') and 'Pool-wide network · xenbr0 · aa:bb:cc:00:11:22' in _group(page, 'network')
    hw = page.locator('[data-cr-vm-hw]').inner_text()
    # no Proxmox VE defaults invented for it
    for word in ('kvm64', 'SeaBIOS', 'i440fx', 'LSI', 'sockets'):
        assert word not in hw, (word, hw)
    assert page.locator('[data-cr-vm-hwgroup="firmware"]').count() == 0
    # the description of the guest, and its addresses from the row
    assert 'XCP guest: billing front end' in page.locator('[data-cr-vm-facts]').inner_text()
    assert '10.0.0.70' in page.locator('[data-cr-vm-facts]').inner_text()
    assert page.locator('[data-cr-objhead="vm"] [data-cr-meta="ip"] dd').inner_text().strip() == '10.0.0.70'
    h = _settled_health(page, ids=('agent', 'lock'))
    assert h['ha'][:2] == ['na', 'Not applicable'] and 'Proxmox VE guests only' in h['ha'][2], h['ha']
    assert h['agent'][:2] == ['na', 'Not applicable'], h['agent']
    assert page.locator('[data-cr-vm-ha-toggle]').count() == 0
    assert not _calls(app, '/proxmox-ha/')
    assert page.locator('[data-cr-vm-fs="na"]').count() == 1
    _no_errors(app)


def test_runtime_classic_corporate_shows_the_xcpng_description_without_invented_firmware(open_app):
    app = _xcp(open_app, layout='corporate')
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.locator('.corp-tree-child', has_text='web01').first.click()
    page.get_by_text('XCP guest: billing front end').first.wait_for(timeout=8000)
    body = page.locator('body').inner_text()
    assert 'i440fx' not in body and 'kvm64' not in body, body[:2000]
    _no_errors(app)


# --- the config read again -------------------------------------------------------------------------

def test_runtime_the_hardware_is_read_again_when_the_dialog_closes(open_app):
    app = open_app()
    page = app.page
    _open_guest(page, 'web01')
    page.locator('[data-cr-vm-hw="ok"]').wait_for(timeout=8000)
    assert '2 sockets x 2 cores = 4 vCPUs' in _group(page, 'cpu')
    reads = len(_calls(app, f'{Q100}/config', 'GET'))
    page.locator('[data-cr-objhead="vm"] .cr-objhead-actions > button', has_text='Configure').click()
    page.locator('.corp-vm-modal').wait_for(timeout=8000)
    page.wait_for_timeout(800)
    in_dialog = len(_calls(app, f'{Q100}/config', 'GET'))
    # what PVE holds after a save elsewhere in the dialog: the next read answers it, and is held a while
    app.server.routes[('GET', f'{Q100}/config')] = 'hold'
    page.locator('.corp-vm-modal-header button', has_text=_exact('Close')).click()
    page.locator('.corp-vm-modal').wait_for(state='detached', timeout=5000)
    assert _wait(page, lambda: len(app.server.held) >= 1, 5), app.server.calls[-10:]
    assert len(_calls(app, f'{Q100}/config', 'GET')) == in_dialog + 1 and in_dialog > reads
    # the old panel stays while the read is out
    assert page.locator('[data-cr-vm-hw="ok"]').count() == 1 and '2 sockets x 2 cores' in _group(page, 'cpu')
    app.server.release((200, _vm_config(dict(WEB_RAW, sockets=4))))
    assert _wait(page, lambda: '4 sockets x 2 cores = 8 vCPUs' in _group(page, 'cpu'), 5), _group(page, 'cpu')
    _no_errors(app)


def test_runtime_a_vm_config_frame_of_this_guest_reads_it_again(open_app):
    app = open_app()
    page = app.page
    _open_guest(page, 'web01')
    page.locator('[data-cr-vm-hw="ok"]').wait_for(timeout=8000)
    reads = len(_calls(app, f'{Q100}/config', 'GET'))
    app.server.routes[('GET', f'{Q100}/config')] = (200, _vm_config(dict(WEB_RAW, description='Moved behind the new proxy')))
    # a frame of another guest is not this one; a burst of this guest's frames is one read
    page.evaluate('''() => {
        const f = (vmid) => window.dispatchEvent(new CustomEvent('pegaprox-vm-config', {detail: {cluster_id: 'c1', vmid, node: 'pve1', vm_type: 'qemu'}}));
        f(102); f(100); f(100); f(100);
    }''')
    assert _wait(page, lambda: 'Moved behind the new proxy' in page.locator('[data-cr-vm-facts]').inner_text(), 5)
    page.wait_for_timeout(600)
    assert len(_calls(app, f'{Q100}/config', 'GET')) == reads + 1
    _no_errors(app)


# --- the lock follows the guest list ----------------------------------------------------------------

def _row_lock(app, vmid, lock):
    rows = copy.deepcopy(app.server.resources)
    for r in rows:
        if r.get('vmid') == vmid:
            if lock:
                r['lock'] = lock
            else:
                r.pop('lock', None)
    app.server.resources = rows


def test_runtime_a_lock_set_after_open_shows_with_unlock(open_app):
    app = open_app()
    page = app.page
    _open_guest(page, 'web01')
    assert _settled_health(page)['lock'][:2] == ['healthy', 'Not locked']
    reads = len(_calls(app, f'{Q100}/lock'))
    app.server.routes[('GET', f'{Q100}/lock')] = (200, dict(LOCK_BACKUP, lock_reason='snapshot', lock_description='Snapshot in progress',
                                                         unlock_command='qm unlock 100'))
    _row_lock(app, 100, 'snapshot')
    _read_guests_again(page)
    assert _wait(page, lambda: _health(page)['lock'][:2] == ['warning', 'Locked: snapshot'], 8), _health(page)['lock']
    assert page.locator('[data-cr-vm-locked="snapshot"]').count() == 1
    assert page.locator('[data-cr-vm-unlock]').count() == 1
    assert len(_calls(app, f'{Q100}/lock')) == reads + 1
    _no_errors(app)


def test_runtime_a_lock_that_ended_after_open_goes_with_its_unlock(open_app):
    app = open_app()
    page = app.page
    _open_guest(page, 'app01')
    assert _settled_health(page)['lock'][:2] == ['warning', 'Locked: backup']
    assert page.locator('[data-cr-vm-unlock]').count() == 1
    app.server.routes[('GET', '/api/clusters/c1/vms/pve1/qemu/103/lock')] = (200, dict(LOCK_OK, unlock_command='qm unlock 103'))
    _row_lock(app, 103, '')
    _read_guests_again(page)
    assert _wait(page, lambda: _health(page)['lock'][:2] == ['healthy', 'Not locked'], 8), _health(page)['lock']
    assert page.locator('[data-cr-vm-locked]').count() == 0 and page.locator('[data-cr-vm-unlock]').count() == 0
    _no_errors(app)


def test_runtime_an_unchanged_row_asks_the_lock_route_nothing_more(open_app):
    app = open_app()
    page = app.page
    _open_guest(page, 'web01')
    _settled_health(page)
    reads = len(_calls(app, f'{Q100}/lock'))
    _read_guests_again(page)
    page.wait_for_timeout(2500)
    assert len(_calls(app, f'{Q100}/lock')) == reads
    _no_errors(app)


# --- failed reads of the tabs ------------------------------------------------------------------------

FAILED_TABS = {
    ('GET', f'{Q100}/snapshots'): (500, {'error': 'Could not read the snapshots'}),
    ('GET', f'{Q100}/efficient-snapshots'): (200, []),
    ('GET', f'{Q100}/backups'): (500, {'error': 'Could not read the backups'}),
    ('GET', '/api/clusters/c1/replication'): (502, {'error': 'Could not read the replication jobs'}),
    ('GET', '/api/cross-cluster-replications'): (200, []),
    ('GET', '/api/clusters/c1/nodes/pve1/tasks'): (502, {'error': 'Could not read the task list', 'code': 'PVE_READ_FAILED'}),
    ('GET', '/api/clusters/c1/audit'): (200, []),
    ('GET', f'{Q100}/firewall/options'): (500, {'error': 'Could not read the firewall options'}),
    ('GET', f'{Q100}/firewall/rules'): (200, []), ('GET', f'{Q100}/firewall/aliases'): (200, []),
    ('GET', f'{Q100}/firewall/ipset'): (200, []), ('GET', f'{Q100}/firewall/refs'): (200, []),
}


def _failing(open_app, layout=LAYOUT):
    app = open_app(layout=layout)
    app.server.routes.update(FAILED_TABS)
    return app


def test_runtime_a_failed_snapshot_read_is_said_with_retry_not_no_snapshots(open_app):
    app = _failing(open_app)
    page = app.page
    _open_guest(page, 'web01')
    page.locator('[data-cr-tabs="guest"] [data-cr-tab="snapshots"]').click()
    note = page.locator('[data-cr-vm-snaps-fail="std"]')
    note.wait_for(timeout=8000)
    assert 'The snapshots could not be read (HTTP 500)' in note.inner_text(), note.inner_text()
    assert page.get_by_text('No snapshots found').count() == 0
    reads = len(_calls(app, f'{Q100}/snapshots'))
    # Retry reads again; an empty answer is then the empty state with its hint
    app.server.routes[('GET', f'{Q100}/snapshots')] = (200, [{'name': 'current', 'description': 'You are here!'}])
    note.locator('[data-cr-vm-snaps-retry]').click()
    page.get_by_text('No snapshots found').first.wait_for(timeout=5000)
    assert len(_calls(app, f'{Q100}/snapshots')) == reads + 1
    assert page.locator('[data-cr-vm-snaps-fail]').count() == 0
    assert page.get_by_text('Take a snapshot to keep the current state of the guest.').count() == 1
    assert page.get_by_text('noSnapshotsHint').count() == 0
    _no_errors(app)


def test_runtime_classic_corporate_has_the_snapshot_hint_and_its_old_empty_tab(open_app):
    app = _failing(open_app, layout='corporate')
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.locator('.corp-tree-child', has_text='web01').first.click()
    page.locator('.corp-tab-strip button', has_text='Snapshots').first.click()
    page.get_by_text('No snapshots found').first.wait_for(timeout=8000)
    assert page.locator('[data-cr-vm-snaps-fail]').count() == 0
    assert page.get_by_text('Take a snapshot to keep the current state of the guest.').count() == 1
    assert page.get_by_text('noSnapshotsHint').count() == 0
    _no_errors(app)


def _dialog_tab(page, label):
    page.locator('.corp-vm-modal-tab', has_text=_exact(label)).click()


def test_runtime_failed_reads_in_the_dialog_tabs_are_said_with_retry(open_app):
    app = _failing(open_app)
    page = app.page
    _open_guest(page, 'web01')
    page.locator('[data-cr-objhead="vm"] .cr-objhead-actions > button', has_text='Configure').click()
    modal = page.locator('.corp-vm-modal')
    modal.wait_for(timeout=8000)

    _dialog_tab(page, 'Snapshots')
    note = modal.locator('[data-cr-vc-tabfail="snapshots"]')
    note.wait_for(timeout=5000)
    assert 'Snapshots could not be read (snapshots: HTTP 500)' in note.inner_text(), note.inner_text()
    assert modal.get_by_text('No snapshots found').count() == 0

    _dialog_tab(page, 'Backups')
    note = modal.locator('[data-cr-vc-tabfail="backups"]')
    note.wait_for(timeout=5000)
    assert modal.get_by_text('No backups found').count() == 0
    # the tab reads its list on entry too: let that read land before Retry is counted
    page.wait_for_timeout(800)
    reads = len(_calls(app, f'{Q100}/backups'))
    note.locator('[data-cr-vc-tabfail-retry]').click()
    assert _wait(page, lambda: len(_calls(app, f'{Q100}/backups')) == reads + 1, 5), (reads, len(_calls(app, f'{Q100}/backups')))

    _dialog_tab(page, 'Replication')
    note = modal.locator('[data-cr-vc-tabfail="replication"]')
    note.wait_for(timeout=5000)
    assert note.get_attribute('data-cr-vc-tabfail-parts') == 'replication'
    # the cross-cluster list was read and is empty: only it says so
    assert modal.get_by_text('No Replication Jobs').count() == 1

    _dialog_tab(page, 'History')
    note = modal.locator('[data-cr-vc-tabfail="history"]')
    note.wait_for(timeout=5000)
    assert 'HTTP 502' in note.inner_text()
    assert modal.get_by_text('No Proxmox tasks found for this VM').count() == 0

    _dialog_tab(page, 'Firewall')
    note = modal.locator('[data-cr-vc-tabfail="firewall"]')
    note.wait_for(timeout=5000)
    assert note.get_attribute('data-cr-vc-tabfail-parts') == 'options'
    modal.locator('button', has_text=_exact('Firewall Options')).first.click()
    switch = modal.locator('[data-cr-vc-fw-switch]')
    switch.wait_for(timeout=5000)
    # an options read that failed is no 'Disabled', and the switch writes nothing on a guess
    assert switch.get_attribute('data-cr-vc-fw-switch') == 'unread' and switch.is_disabled()
    assert switch.inner_text().strip() == 'Not read'
    _no_errors(app)


def test_runtime_classic_corporate_keeps_its_dialog_tabs(open_app):
    app = _failing(open_app, layout='corporate')
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.locator('.corp-tree-child', has_text='web01').first.click()
    page.locator('.corp-tab-strip button', has_text='Configure').first.click()
    modal = page.locator('.corp-vm-modal')
    modal.wait_for(timeout=8000)
    _dialog_tab(page, 'Backups')
    modal.get_by_text('No backups found').first.wait_for(timeout=5000)
    assert page.locator('[data-cr-vc-tabfail]').count() == 0
    _dialog_tab(page, 'Firewall')
    page.wait_for_timeout(800)
    assert page.locator('[data-cr-vc-tabfail]').count() == 0 and page.locator('[data-cr-vc-fw-switch]').count() == 0
    _no_errors(app)


# --- the agent line and the agent info ------------------------------------------------------------------

def test_runtime_a_silent_agent_links_its_install_guide(open_app):
    app = open_app(agent=(200, AGENT_DOWN))
    page = app.page
    _open_guest(page, 'web01')
    assert _settled_health(page)['agent'][:2] == ['warning', 'Does not answer']
    link = page.locator('[data-cr-vm-hhref="agent"]')
    assert link.count() == 1
    assert link.get_attribute('href') == 'https://pve.proxmox.com/wiki/Qemu-guest-agent'
    assert link.get_attribute('target') == '_blank' and 'noopener' in link.get_attribute('rel')
    _no_errors(app)


def test_runtime_the_agent_info_lists_each_user_with_the_login_time(open_app):
    app = open_app()
    page = app.page
    _open_guest(page, 'web01')
    users = page.locator('[data-cr-vm-users]')
    users.wait_for(timeout=8000)
    # crFmtDate of the login second, as the page formats it
    want = page.evaluate('(s) => crFmtDate(s * 1000)', GUEST_INFO['users'][0]['login_time']) if page.evaluate(
        "() => typeof crFmtDate === 'function'") else None
    text = users.inner_text().strip()
    assert text.startswith('root (') and text.endswith(')'), text
    if want:
        assert text == f'root ({want})', text
    assert '2026' in text, text
    _no_errors(app)


# --- memory as a property string ---------------------------------------------------------------------

@pytest.mark.parametrize('memory,want', [('current=2048', '2.0 GB'), ('2048,current=2048', '2.0 GB'), ('garbage', '4.0 GB')])
def test_runtime_memory_as_a_property_string_is_read(open_app, memory, want):
    cfg = _vm_config(dict(WEB_RAW, memory=memory))
    cfg['hardware']['memory'] = memory
    # web01's row says 4 GiB: an unreadable value falls back to it, never '-'
    app = open_app(config=(200, cfg))
    page = app.page
    _open_guest(page, 'web01')
    page.locator('[data-cr-vm-hw="ok"]').wait_for(timeout=8000)
    lines = _group(page, 'memory').splitlines()
    assert lines[1] == want and '-' not in lines[1:2], lines
    _no_errors(app)


# --- a guest-info answer of the wrong shape -------------------------------------------------------------

@pytest.mark.parametrize('ips', ['10.0.0.50', {'eth0': '10.0.0.50'}, [None, 7, '10.0.0.51']])
def test_runtime_addresses_of_the_wrong_shape_do_not_take_the_header_down(open_app, ips):
    app = open_app(agent=(200, dict(GUEST_INFO, ip_addresses=ips)))
    page = app.page
    _open_guest(page, 'web01')
    _settled_health(page)
    head = page.locator('[data-cr-objhead="vm"]')
    assert head.count() == 1
    ip = head.locator('[data-cr-meta="ip"] dd')
    assert (ip.inner_text().strip() if ip.count() else '') == ('10.0.0.51' if isinstance(ips, list) else '')
    _no_errors(app)
