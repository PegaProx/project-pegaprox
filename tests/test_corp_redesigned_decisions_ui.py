"""Decisions before the push in Corporate Redesigned (Preview), in the browser (round 8, stage B2).

- A live change of a running VM that still runs on the node (bridge, VLAN, firewall, rate or link
  of an interface, the limits of a disk, the medium of a CD/DVD drive) is not promised as "applies
  now": Proxmox VE applies it at once when it accepts it and can keep it pending. A disk change
  that only writes the configuration (backup, replication) keeps "applies now".
- Network Apply: when the waiting changes touch the path PegaProx uses to reach the node, the node
  name is typed to enable Apply (the checkbox stays for every other case); while the interface list
  read has failed, Apply is off, the dialog says why and offers Retry.
- The node summary badge says "No warning in the data read".
- Every certificate upload asks first, with and without the restart, and names what it replaces.
- Unsaved edits in a node configuration card: another configure sub tab, another node tab, Back or a
  click that leaves the node view asks first (keep editing or discard). No beforeunload prompt.
- A repository that is not set up on the node gets a disabled Enable switch with the reason.

PEGAPROX_CR_BUNDLE=<file> serves another bundle (the counterproof against the bundle before this
stage). Skips without Playwright. LW Nov 2026
"""
import json
import time

import pytest

import test_corp_redesigned_node_cfg_ui as cfg
import test_corp_redesigned_node_net_ui as net
import test_corp_redesigned_node_storage_ui as store
import test_corp_redesigned_node_ui as nodeui
from test_corp_redesigned_guard_ui import NODE_DNS, _GuardApp, _corp_cluster, _exact
from test_corp_redesigned_vmcfg_tabs_ui import _app as _vc_app, _tab as _vc_tab
from test_corp_redesigned_vmcfg_ui import (BASE_CONF, BUNDLE, LAYOUT, NET0, SCSI0, _CfgServer as _VcServer,  # noqa: F401
                                           _review, _rows, _vc_input, browser, firefox, open_app, playwright)

NO_SIDEWAYS = '() => document.scrollingElement.scrollWidth <= window.innerWidth'


@pytest.fixture
def opener(browser):
    """Opens the app on one of the fakes of the node tests: opener(net._NetServer, changes=...)."""
    apps = []

    def _open(server_cls, layout=LAYOUT, viewport=(1600, 1000), br=None, clusters=None, **kw):
        server = server_cls(layout=layout, **kw)
        if clusters is not None:
            server.clusters = list(clusters)
        app = _GuardApp(br or browser, server, viewport=viewport)
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.close()


def _no_errors(app):
    assert not [e for e in app.errors if 'pageerror' in e], app.errors


def _bundle():
    import os
    path = os.environ.get('PEGAPROX_CR_BUNDLE') or os.path.join(os.path.dirname(__file__), '..', 'web', 'index.html')
    return open(path, encoding='utf-8').read()


# --- 5. live VM changes promise no "applies now" ---------------------------------------------------

@pytest.fixture(scope='module')
def rules_page(browser):
    app = _GuardApp(browser, _VcServer(layout=LAYOUT, bundle=BUNDLE))
    app.page.wait_for_function('() => !!window.PegaProxVmCfgRules', timeout=15000)
    yield app.page
    app.close()


def _classify(page, key, value, conf=None, known=True):
    return page.evaluate('''([key, value, conf, known]) => window.PegaProxVmCfgRules.classify(key, value,
        {running: true, conf, changes: {}, pendingKnown: known, pending: []})''', [key, value, conf or BASE_CONF, known])


LIVE = [
    ('interface bridge', 'net0', NET0.replace('vmbr0', 'vmbr1'), 'maybe', 'crVcWhyNetLive'),
    ('interface firewall off', 'net0', NET0.replace('firewall=1', 'firewall=0'), 'maybe', 'crVcWhyNetLive'),
    ('disk limit', 'scsi0', SCSI0 + ',mbps_rd=100', 'maybe', 'crVcWhyDiskLive'),
    ('CD/DVD medium', 'ide2', 'local:iso/a.iso,media=cdrom', 'maybe', 'crVcWhyCdrom'),
    ('disk backup flag only', 'scsi0', SCSI0 + ',backup=0', 'now', 'crVcWhyDiskWritten'),
]


@pytest.mark.parametrize('case,key,value,cls,why', LIVE, ids=[c[0] for c in LIVE])
def test_rules_a_live_change_is_not_promised_as_applies_now(rules_page, case, key, value, cls, why):
    got = _classify(rules_page, key, value)
    assert (got['cls'], got['why']) == (cls, why), got


def test_rules_a_limit_compared_as_a_number_and_an_unknown_pending_list(rules_page):
    conf = dict(BASE_CONF, scsi0=SCSI0 + ',mbps_rd=100.0')
    # 100 and 100.0 are the same limit for Proxmox VE (safe_num_ne): nothing goes to the running disk
    got = _classify(rules_page, 'scsi0', SCSI0 + ',mbps_rd=100,backup=0', conf)
    assert (got['cls'], got['why']) == ('now', 'crVcWhyDiskWritten'), got
    # while the pending list is unknown a live change is no prediction, as before
    got = _classify(rules_page, 'net0', NET0.replace('vmbr0', 'vmbr1'), known=False)
    assert (got['cls'], got['why']) == ('open', 'crVcWhyPendingUnknown'), got


def test_runtime_a_live_interface_change_says_it_can_stay_pending(open_app):
    app = _vc_app(open_app)
    page = app.page
    _vc_tab(page, 'Network', '[data-cr-vc-net]')
    page.wait_for_timeout(300)
    _vc_input(page, 'net0.tag').fill('40')
    _review(page)
    row = [r for r in _rows(page) if r['key'] == 'net0'][0]
    assert row['cls'] == 'maybe', row
    assert 'Applies now' not in row['text'] and 'PVE may keep it pending' in row['text'], row
    assert 'the change applies at once when Proxmox VE accepts it on the node. Proxmox VE can keep it pending instead' in row['text']
    _no_errors(app)


def test_the_live_texts_in_english_and_german():
    b = _bundle()
    for want in ('"Bandwidth and IOPS limits go to the running disk: they apply at once when Proxmox VE accepts them. '
                 'Proxmox VE can keep a limit pending instead, then the save reports the error."',
                 '"The medium of a CD/DVD drive is changed live: the change applies at once when Proxmox VE accepts it. '
                 'Proxmox VE can keep it pending instead, then the save reports the error."',
                 'Die Änderung wirkt sofort, wenn Proxmox VE sie auf dem Node annimmt. Proxmox VE kann sie stattdessen wartend lassen',
                 '"Bandbreiten- und IOPS-Limits gehen an die laufende Disk: Sie wirken sofort, wenn Proxmox VE sie annimmt.',
                 'crVcWhyDiskWritten:"Disk settings such as backup or replication are written to the configuration at once',
                 'crVcWhyDiskWritten:"Disk-Einstellungen wie Backup oder Replikation werden sofort in die Konfiguration geschrieben'):
        assert want in b, want


# --- 6. Apply on the management path: type the node name -------------------------------------------

def _apply_dialog(page):
    page.locator('[data-cr-nn-apply]').click()
    dlg = page.locator('[data-cr-upd-dialog="nn-apply"]')
    dlg.wait_for(timeout=5000)
    return dlg


def test_runtime_apply_on_the_management_path_asks_for_the_node_name(opener):
    app = opener(net._NetServer, clusters=[net.CLUSTER_ON_NODE])
    page = app.page
    net._open_network(page)
    net._settled_changes(page, 'some')
    dlg = _apply_dialog(page)
    dlg.locator('[data-cr-nn-mgmt="touch"]').wait_for(timeout=5000)
    # no checkbox: the node name is typed
    assert dlg.locator('[data-cr-nn-ack]').count() == 0
    box = dlg.locator('[data-cr-nn-typename-input]')
    assert box.count() == 1
    assert 'Type the node name pve1 to confirm' in dlg.locator('[data-cr-nn-typename]').inner_text()
    go = dlg.locator('[data-cr-nn-apply-go]')
    assert go.is_disabled()
    for wrong in ('pve', 'PVE1', 'pve2'):
        box.fill(wrong)
        assert go.is_disabled(), wrong
    box.fill('pve1')
    assert go.is_enabled() and 'cr-btn-danger' in go.get_attribute('class')
    assert app.server.sent == []
    go.click()
    dlg.wait_for(state='detached', timeout=5000)
    # the same request as before and as classic: PUT .../network without a body
    assert app.server.sent == [('PUT', net.NET, None)]
    _no_errors(app)


def test_runtime_apply_off_the_management_path_keeps_the_checkbox(opener):
    app = opener(net._NetServer, changes=(200, {'changes': net.DIFF_VMBR1}), clusters=[net.CLUSTER_ON_NODE])
    page = app.page
    net._open_network(page)
    net._settled_changes(page, 'some')
    dlg = _apply_dialog(page)
    assert dlg.locator('[data-cr-nn-mgmt="clear"]').count() == 1
    assert dlg.locator('[data-cr-nn-typename-input]').count() == 0
    go = dlg.locator('[data-cr-nn-apply-go]')
    assert go.is_disabled()
    dlg.locator('[data-cr-nn-ack]').check()
    assert go.is_enabled()
    _no_errors(app)


# --- 7. Apply is off while the interface list read has failed ----------------------------------------

def test_runtime_a_failed_list_read_locks_apply_and_offers_retry(opener):
    app = opener(net._NetServer, net=(500, {'error': 'boom'}))
    page = app.page
    net._open_network(page)
    page.locator('[data-cr-nn-list="error"]').wait_for(timeout=8000)
    dlg = _apply_dialog(page)
    lock = dlg.locator('[data-cr-nn-apply-list="error"]')
    lock.wait_for(timeout=5000)
    assert 'The interface list of pve1 could not be read' in lock.inner_text() and 'Apply stays off' in lock.inner_text()
    confirm = dlg.locator('[data-cr-nn-ack], [data-cr-nn-typename-input]').first
    assert confirm.is_disabled() and dlg.locator('[data-cr-nn-apply-go]').is_disabled()
    reads = app.server.reads(net.NET)
    app.server.routes[('GET', net.NET)] = (200, net.NODE_NET)
    lock.locator('[data-cr-nn-apply-retry]').click()
    # the dialog stays open while the list is read again
    for _ in range(50):
        if app.server.reads(net.NET) > reads:
            break
        page.wait_for_timeout(100)
    assert app.server.reads(net.NET) == reads + 1
    # read: the lock is gone and the dialog shows what waits
    lock.wait_for(state='detached', timeout=8000)
    assert dlg.is_visible()
    dlg.locator('[data-cr-nn-summary-state="some"]').wait_for(timeout=8000)
    dlg.locator('[data-cr-nn-typename-input]').fill('pve1')
    assert dlg.locator('[data-cr-nn-apply-go]').is_enabled()
    assert app.server.sent == []
    _no_errors(app)


# --- 8. the summary badge -----------------------------------------------------------------------------

def test_runtime_the_summary_badge_says_it_judged_the_data_read(opener):
    app = opener(nodeui._NodeServer)
    page = app.page
    nodeui._open_summary(page)
    assert page.locator('[data-cr-ns]').get_attribute('data-cr-ns-overall') == 'normal'
    assert page.locator('[data-cr-ns-badge]').inner_text().strip() == 'No warning in the data read'
    b = _bundle()
    assert 'crNsOvNormal:"No warning in the data read"' in b and 'crNsOvNormal:"Keine Warnung in den gelesenen Daten"' in b
    _no_errors(app)


# --- 9. every certificate upload asks first ---------------------------------------------------------

@pytest.mark.parametrize('restart', [True, False])
def test_runtime_every_certificate_upload_asks_first(opener, restart):
    app = opener(cfg._CfgServer)
    page = app.page
    cfg._open_cfg(page, 'certs')
    sec = cfg._sec(page, 'certs')
    sec.locator('[data-cr-nc-cert="pve-ssl.pem"]').wait_for(timeout=8000)
    sec.locator('[data-cr-nc-cert-open]').click()
    sec.locator('#cr-nc-cert-pem').fill(cfg.PEM_CERT)
    sec.locator('#cr-nc-cert-key').fill(cfg.PEM_KEY)
    if not restart:
        sec.locator('[data-cr-nc-restart] input').uncheck()
    sec.locator('[data-cr-nc-save="certs"]').click()
    dlg = page.locator('[data-cr-upd-dialog="nc-certs"]')
    dlg.wait_for(timeout=3000)
    page.wait_for_timeout(300)
    assert app.server.sent == []
    text = dlg.inner_text()
    assert 'The custom certificate and key of pve1 are replaced with the ones you pasted.' in text
    restart_line = dlg.locator('[data-cr-nc-confirm-restart]')
    if restart:
        assert 'Upload the certificate and restart pveproxy on pve1?' in text
        assert restart_line.get_attribute('data-cr-nc-confirm-restart') == 'on' and 'pveproxy restarts' in restart_line.inner_text()
        assert dlg.locator('[data-cr-nc-confirm-go="certs"]').inner_text().strip() == 'Upload and restart'
    else:
        assert 'Upload the certificate to pve1?' in text and 'restart pveproxy on' not in text
        assert restart_line.get_attribute('data-cr-nc-confirm-restart') == 'off'
        assert 'keeps the old certificate until it restarts' in restart_line.inner_text()
        assert dlg.locator('[data-cr-nc-confirm-go="certs"]').inner_text().strip() == 'Upload'
    # Cancel sends nothing and keeps the form
    dlg.locator('[data-cr-nc-confirm-cancel="certs"]').click()
    dlg.wait_for(state='detached', timeout=3000)
    assert app.server.sent == [] and sec.locator('#cr-nc-cert-pem').input_value() == cfg.PEM_CERT
    sec.locator('[data-cr-nc-save="certs"]').click()
    page.locator('[data-cr-nc-confirm-go="certs"]').click()
    sent = cfg._wait_sent(app)
    assert sent[0][:2] == ('POST', cfg.CUSTOM)
    assert json.loads(sent[0][2]) == {'certificates': cfg.PEM_CERT, 'key': cfg.PEM_KEY, 'restart': restart, 'force': True}
    _no_errors(app)


# --- 10. unsaved edits ask before they are dropped -----------------------------------------------------

def _leave(page):
    dlg = page.locator('[data-cr-upd-dialog="nc-leave"]')
    dlg.wait_for(timeout=3000)
    return dlg


def _edit_dns(page, value='10.0.0.99'):
    cfg._open_cfg(page, 'dns')
    sec = cfg._sec(page, 'dns')
    sec.locator('[data-cr-nc-edit="dns"]').click()
    sec.locator('[data-cr-nc-input="dns1"]').fill(value)
    return sec


def test_runtime_a_sub_tab_switch_with_unsaved_edits_asks_first(opener):
    app = opener(cfg._CfgServer)
    page = app.page
    sec = _edit_dns(page)
    page.locator('.corp-subnav-item', has_text=_exact('Syslog')).first.click()
    dlg = _leave(page)
    assert 'DNS on pve1: the changes are not saved yet' in dlg.inner_text()
    assert dlg.locator('[data-cr-nc-leave]').get_attribute('data-cr-nc-leave') == 'dns'
    # keep editing: nothing changes
    dlg.locator('[data-cr-nc-leave-keep]').click()
    dlg.wait_for(state='detached', timeout=3000)
    assert page.locator('.corp-subnav-item.active').inner_text().strip() == 'DNS'
    assert sec.locator('[data-cr-nc-input="dns1"]').input_value() == '10.0.0.99'
    # Escape keeps editing as well
    page.locator('.corp-subnav-item', has_text=_exact('Hosts File')).first.click()
    _leave(page)
    page.keyboard.press('Escape')
    page.locator('[data-cr-upd-dialog="nc-leave"]').wait_for(state='detached', timeout=3000)
    assert sec.locator('[data-cr-nc-input="dns1"]').input_value() == '10.0.0.99'
    # discard: the switch goes on, and the edit is gone when the card comes back
    page.locator('.corp-subnav-item', has_text=_exact('Syslog')).first.click()
    _leave(page).locator('[data-cr-nc-leave-discard]').click()
    cfg._sec(page, 'syslog')
    assert page.locator('.corp-subnav-item.active').inner_text().strip() == 'Syslog'
    page.locator('.corp-subnav-item', has_text=_exact('DNS')).first.click()
    dns = cfg._sec(page, 'dns')
    assert dns.get_attribute('data-cr-nc-editing') is None
    assert dns.locator('[data-cr-nc-k="dns1"] dd').inner_text().strip() == NODE_DNS['dns1']
    assert app.server.sent == []
    _no_errors(app)


def test_runtime_no_question_without_a_change(opener):
    app = opener(cfg._CfgServer)
    page = app.page
    cfg._open_cfg(page, 'dns')
    sec = cfg._sec(page, 'dns')
    sec.locator('[data-cr-nc-edit="dns"]').click()
    # the edit state is open but nothing differs from the stored value
    page.locator('.corp-subnav-item', has_text=_exact('Syslog')).first.click()
    cfg._sec(page, 'syslog')
    assert page.locator('[data-cr-upd-dialog="nc-leave"]').count() == 0
    # a change typed back to the stored value is no change either
    page.locator('.corp-subnav-item', has_text=_exact('DNS')).first.click()
    sec = cfg._sec(page, 'dns')
    sec.locator('[data-cr-nc-edit="dns"]').click()
    sec.locator('[data-cr-nc-input="dns1"]').fill('10.0.0.99')
    sec.locator('[data-cr-nc-input="dns1"]').fill(NODE_DNS['dns1'])
    page.locator('[data-cr-tabs="node"] [role="tab"]', has_text='Summary').click()
    page.locator('[data-cr-ns]').wait_for(timeout=8000)
    assert page.locator('[data-cr-upd-dialog="nc-leave"]').count() == 0
    _no_errors(app)


def test_runtime_a_node_tab_switch_and_back_ask_first(opener):
    app = opener(cfg._CfgServer)
    page = app.page
    _edit_dns(page)
    page.locator('[data-cr-tabs="node"] [role="tab"]', has_text='Summary').click()
    dlg = _leave(page)
    dlg.locator('[data-cr-nc-leave-keep]').click()
    assert page.locator('[data-cr-tabs="node"] [role="tab"][aria-selected="true"]').inner_text().strip() == 'Configure'
    # the arrow keys of the tab strip ask the same way
    page.locator('[data-cr-tabs="node"] [role="tab"][aria-selected="true"]').press('ArrowRight')
    _leave(page).locator('[data-cr-nc-leave-keep]').click()
    assert page.locator('[data-cr-tabs="node"] [role="tab"][aria-selected="true"]').inner_text().strip() == 'Configure'
    # Back to the list asks too; discard goes back
    page.locator('[data-cr-objhead="node"] button[aria-label]').first.click()
    _leave(page).locator('[data-cr-nc-leave-discard]').click()
    page.locator('[data-cr-objhead="node"]').wait_for(state='detached', timeout=5000)
    _no_errors(app)


def test_runtime_leaving_the_node_view_asks_first(opener):
    app = opener(cfg._CfgServer)
    page = app.page
    _edit_dns(page)
    # another node in the tree: held, keep editing stays on pve1 with the edit
    page.locator('.corp-tree-child', has_text='pve2').first.click()
    dlg = _leave(page)
    dlg.locator('[data-cr-nc-leave-keep]').click()
    assert page.locator('[data-cr-objhead="node"] .cr-objhead-name').inner_text().strip() == 'pve1'
    assert cfg._sec(page, 'dns').locator('[data-cr-nc-input="dns1"]').input_value() == '10.0.0.99'
    # a guest in the tree: discard goes on with the same click
    page.locator('.corp-tree-child', has_text='web01').first.click()
    _leave(page).locator('[data-cr-nc-leave-discard]').click()
    page.locator('[data-cr-objhead="node"]').wait_for(state='detached', timeout=8000)
    assert page.locator('[data-cr-upd-dialog="nc-leave"]').count() == 0
    _no_errors(app)


def test_runtime_discard_on_another_node_opens_it_without_the_edit(opener):
    app = opener(cfg._CfgServer)
    page = app.page
    _edit_dns(page)
    page.locator('.corp-tree-child', has_text='pve2').first.click()
    _leave(page).locator('[data-cr-nc-leave-discard]').click()
    page.wait_for_function('() => (document.querySelector("[data-cr-objhead=node] .cr-objhead-name") || {}).textContent === "pve2"',
                           timeout=8000)
    # nothing is held any more: a later click is not asked about
    page.locator('.corp-tree-child', has_text='pve1').first.click()
    page.wait_for_function('() => (document.querySelector("[data-cr-objhead=node] .cr-objhead-name") || {}).textContent === "pve1"',
                           timeout=8000)
    assert page.locator('[data-cr-upd-dialog="nc-leave"]').count() == 0
    _no_errors(app)


def test_runtime_the_certificate_form_and_a_staged_repository_ask_too(opener):
    app = opener(store._StoreServer, routes={('GET', cfg.CERTS): (200, cfg.NODE_CERTS), ('GET', cfg.DNS): (200, NODE_DNS),
                                             ('GET', cfg.HOSTS): (200, cfg.NODE_HOSTS), ('GET', cfg.TIME): (200, cfg.NODE_TIME),
                                             ('GET', cfg.SYSLOG): (200, cfg.NODE_SYSLOG)})
    page = app.page
    store._open_cfg(page, 'repos')
    sec = store._sec(page, 'repos')
    sec.locator('[data-cr-nr-flip="pve-enterprise"]').click()
    page.locator('.corp-subnav-item', has_text=_exact('Ceph')).first.click()
    dlg = _leave(page)
    assert 'Repositories on pve1' in dlg.inner_text()
    dlg.locator('[data-cr-nc-leave-discard]').click()
    page.locator('.corp-subnav-item.active', has_text=_exact('Ceph')).wait_for(timeout=5000)
    page.locator('.corp-subnav-item', has_text=_exact('Certificates')).first.click()
    certs = cfg._sec(page, 'certs')
    certs.locator('[data-cr-nc-cert="pve-ssl.pem"]').wait_for(timeout=8000)
    certs.locator('[data-cr-nc-cert-open]').click()
    certs.locator('#cr-nc-cert-pem').fill(cfg.PEM_CERT)
    page.locator('.corp-subnav-item', has_text=_exact('Syslog')).first.click()
    dlg = _leave(page)
    assert 'Certificates on pve1' in dlg.inner_text()
    dlg.locator('[data-cr-nc-leave-discard]').click()
    page.locator('.corp-subnav-item', has_text=_exact('Certificates')).first.click()
    certs = cfg._sec(page, 'certs')
    certs.locator('[data-cr-nc-cert-open]').wait_for(timeout=8000)
    # discarded: the form is closed and empty
    assert certs.locator('[data-cr-nc-certform]').count() == 0
    assert app.server.sent == []
    _no_errors(app)


def test_runtime_no_beforeunload_prompt(opener):
    app = opener(cfg._CfgServer)
    page = app.page
    _edit_dns(page)
    asked = []
    page.on('dialog', lambda d: (asked.append(d.type), d.dismiss()))
    assert page.evaluate('() => window.onbeforeunload') is None
    page.close(run_before_unload=True)
    for _ in range(20):
        if page.is_closed():
            break
        time.sleep(0.1)
    assert asked == []


# --- 11. a repository that is not set up cannot be switched -------------------------------------------

def test_runtime_a_repository_not_set_up_gets_no_switch(opener):
    app = opener(store._StoreServer)
    page = app.page
    store._open_cfg(page, 'repos')
    sec = store._sec(page, 'repos')
    reef = sec.locator('[data-cr-nr-repo="ceph-reef"]')
    assert reef.get_attribute('data-cr-nr-state') == 'absent'
    flip = reef.locator('[data-cr-nr-flip="ceph-reef"]')
    assert flip.inner_text().strip() == 'Enable' and flip.is_disabled()
    # the reason is said once above the group, and each switch points to it
    why = sec.locator('[data-cr-nc-group="absent"] [data-cr-nr-why]')
    assert why.count() == 1
    assert 'The node refuses to switch an entry it does not have, so there is no switch here.' in why.inner_text()
    assert flip.get_attribute('title') == why.inner_text().strip()
    assert flip.get_attribute('aria-describedby') == why.get_attribute('id')
    # every entry that is not set up, and only those
    absent = sec.locator('[data-cr-nr-state="absent"]')
    assert absent.count() == 3 and sec.locator('[data-cr-nr-state="absent"] [data-cr-nr-flip]:disabled').count() == 3
    assert sec.locator('[data-cr-nr-state="on"] [data-cr-nr-flip]:disabled, [data-cr-nr-state="off"] [data-cr-nr-flip]:disabled').count() == 0
    flip.dispatch_event('click')
    page.wait_for_timeout(200)
    assert reef.get_attribute('data-cr-nr-pending') is None and sec.locator('[data-cr-nc-editbar="repos"]').count() == 0
    assert app.server.sent == []
    _no_errors(app)


# --- layout --------------------------------------------------------------------------------------

@pytest.mark.parametrize('engine', ['chromium', 'firefox'])
@pytest.mark.parametrize('width', [1600, 1280, 1024])
def test_runtime_layout_without_sideways_scroll(opener, firefox, browser, engine, width):
    br = firefox if engine == 'firefox' else browser
    # the summary badge
    app = opener(nodeui._NodeServer, viewport=(width, 900), br=br)
    page = app.page
    nodeui._open_summary(page)
    badge = page.locator('[data-cr-ns-badge]')
    assert page.evaluate(NO_SIDEWAYS)
    assert badge.evaluate('e => { const b = e.firstElementChild || e; return b.scrollWidth <= b.clientWidth + 1; }')
    # the Apply dialog with the typed name, and with the list lock
    app = opener(net._NetServer, viewport=(width, 900), br=br, clusters=[net.CLUSTER_ON_NODE])
    page = app.page
    net._open_network(page)
    net._settled_changes(page, 'some')
    dlg = _apply_dialog(page)
    box = dlg.locator('[data-cr-nn-typename-input]')
    assert box.is_visible() and page.evaluate(NO_SIDEWAYS)
    assert dlg.evaluate('e => e.scrollWidth <= e.clientWidth + 1')
    app = opener(net._NetServer, viewport=(width, 900), br=br, net=(500, {'error': 'boom'}))
    page = app.page
    net._open_network(page)
    page.locator('[data-cr-nn-list="error"]').wait_for(timeout=8000)
    dlg = _apply_dialog(page)
    retry = dlg.locator('[data-cr-nn-apply-retry]')
    assert retry.is_visible() and page.evaluate(NO_SIDEWAYS)
    # the reason beside a repository that cannot be switched, and the question before a discard
    app = opener(store._StoreServer, viewport=(width, 900), br=br)
    page = app.page
    store._open_cfg(page, 'repos')
    sec = store._sec(page, 'repos')
    why = sec.locator('[data-cr-nc-group="absent"] [data-cr-nr-why]')
    assert why.is_visible() and page.evaluate(NO_SIDEWAYS)
    sec.locator('[data-cr-nr-flip="pve-enterprise"]').click()
    page.locator('.corp-subnav-item', has_text=_exact('Ceph')).first.click()
    dlg = _leave(page)
    assert dlg.locator('[data-cr-nc-leave-discard]').is_visible() and dlg.locator('[data-cr-nc-leave-keep]').is_visible()
    assert page.evaluate(NO_SIDEWAYS) and dlg.evaluate('e => e.scrollWidth <= e.clientWidth + 1')
