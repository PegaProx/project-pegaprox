"""Nodes in Corporate Redesigned (and the classic fixes beside them), in the browser.

- Header: the state badge and the CPU / memory figures follow the node's health card (an offline or
  unknown node is not 'Online' with 'CPU 0.0%'); an address /ip fell back to is marked as a stand-in.
- Actions > Update asks first: the redesign with the Updates tab's dialog (reboot as the last check and
  node.reboot say, force only after a second question on NOT_IN_MAINTENANCE), classic Corporate with
  its node card's question. Nothing is sent before the answer.
- An XCP-ng host's summary is read as read; swap and root are not applicable there, never missing.
- The leave guard holds a click on another cluster's tree row and Enter on a tree row; the chevron folds.
- The open task log is read once for a finished task, not on every render of the dashboard.
- The certificate card reverts to the self-signed certificate, the Ceph card has the Ceph writes of
  the node dialog; each asks first.
- A SMART answer without data is "No data", not read and not counted as read.
- Refresh on Tasks, Disks and Hardware shows Updating while the answer is out.
- A first visit of a sub tab reads once (classic Corporate too).
- A node read the server now fails with a code is said in words; an empty list carries no doubt.

The fakes serve the shapes of pegaprox/api/nodes.py, vms.py (start_node_update with its codes),
settings.py (updates-overview), ceph.py and the failure shape of a node read. PEGAPROX_CR_BUNDLE=<file>
serves another bundle (the counterproof against the bundle before this round). Skips without
Playwright. LW Nov 2026
"""
import json
import re

import pytest

import test_corp_redesigned_node_cfg_ui as ncfg
import test_corp_redesigned_node_hw_ui as nhw
import test_corp_redesigned_node_storage_ui as nst
from test_corp_redesigned_dashboard_ui import CLUSTERS
from test_corp_redesigned_guard_ui import FIXED, METRICS, NODE_CERTS, _GuardApp, _corp_cluster, _exact
from test_corp_redesigned_node_ui import (LAYOUT, NODE, OK, TASKS, _NodeServer, _no_errors, _open_summary,  # noqa: F401 (fixtures)
                                          _open_tasks, _tab, _tile, browser, playwright)

GIB = 1024 ** 3


@pytest.fixture
def opener(browser):
    apps = []

    def _open(server_cls=_NodeServer, layout=LAYOUT, viewport=(1600, 1000), clusters=None, **kw):
        server = server_cls(layout=layout, **kw)
        if clusters is not None:
            server.clusters = list(clusters)
        app = _GuardApp(browser, server, viewport=viewport)
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.close()


def _wait(page, fn, seconds=6):
    for _ in range(int(seconds * 10)):
        if fn():
            return True
        page.wait_for_timeout(100)
    return fn()


def _ns(page):
    return {'overall': page.locator('[data-cr-ns]').get_attribute('data-cr-ns-overall'),
            'sum': page.locator('[data-cr-ns-sum]').get_attribute('data-cr-ns-sum') if page.locator('[data-cr-ns-sum]').count() else None,
            'missing': page.locator('[data-cr-ns-missing]').get_attribute('data-cr-ns-missing') if page.locator('[data-cr-ns-missing]').count() else ''}


# --- the header ----------------------------------------------------------------------------------

def _placeholder(status, offline):
    """The row manager.py puts in /metrics for a node it could not read."""
    return {'status': status, 'cpu_percent': 0, 'mem_percent': 0, 'mem_used': 0, 'mem_total': 0, 'disk_percent': 0,
            'disk_used': 0, 'disk_total': 0, 'netin': 0, 'netout': 0, 'score': 0, 'uptime': 0, 'maintenance_mode': False,
            'maintenance_task': None, 'maintenance_acknowledged': False, 'offline': offline}


@pytest.mark.parametrize('status,offline,badge', [('unknown', True, 'offline'), ('offline', True, 'offline'), ('unknown', False, 'unknown')])
def test_runtime_the_header_says_what_the_health_card_says(opener, status, offline, badge):
    app = opener(metrics={'pve1': dict(METRICS['pve1']), 'pve2': _placeholder(status, offline)})
    page = app.page
    _corp_cluster(page)
    page.locator('.corp-tree-child', has_text='pve2').first.click()
    head = page.locator('[data-cr-objhead="node"]')
    head.wait_for(timeout=8000)
    page.locator('[data-cr-ns]').wait_for(timeout=8000)
    assert head.locator('[data-cr-state]').get_attribute('data-cr-state') == badge
    # the zeros of a node that is not online are no measurement
    assert head.locator('[data-cr-meta="cpu"]').count() == 0 and head.locator('[data-cr-meta="mem"]').count() == 0
    assert '0.0%' not in head.inner_text()
    _no_errors(app)


def test_runtime_an_online_node_keeps_its_live_figures(opener):
    app = opener()
    page = app.page
    _open_summary(page)
    head = page.locator('[data-cr-objhead="node"]')
    assert head.locator('[data-cr-state]').get_attribute('data-cr-state') == 'online'
    assert head.locator('[data-cr-meta="cpu"] dd').inner_text().strip() == '5.0%'
    assert head.locator('[data-cr-meta="mem"]').count() == 1
    _no_errors(app)


def test_runtime_a_stand_in_address_is_marked_in_the_header(opener):
    app = opener(routes={('GET', NODE + '/ip'): (200, {'ip': '10.0.0.1', 'node': 'pve1', 'source': 'cluster_host_fallback'})})
    page = app.page
    _open_summary(page)
    ip = page.locator('[data-cr-objhead="node"] [data-cr-meta="ip"] dd')
    assert _wait(page, lambda: ip.count() == 1 and '10.0.0.1' in ip.inner_text())
    assert ip.locator('[data-cr-node-ip-standin]').count() == 1
    assert 'stand-in, not read from the node' in ip.inner_text(), ip.inner_text()
    _no_errors(app)


def test_runtime_an_address_read_from_the_node_is_not_marked(opener):
    app = opener()
    page = app.page
    _open_summary(page)
    ip = page.locator('[data-cr-objhead="node"] [data-cr-meta="ip"] dd')
    assert _wait(page, lambda: ip.count() == 1 and '10.0.0.11' in ip.inner_text())
    assert ip.locator('[data-cr-node-ip-standin]').count() == 0
    _no_errors(app)


# --- Actions > Update ------------------------------------------------------------------------------

UPDATE = NODE + '/update'
NOT_IN_MAINT = (400, {'error': 'Node pve1 is not in maintenance mode', 'code': 'NOT_IN_MAINTENANCE', 'node': 'pve1'})
OVERVIEW = {'hosts': [{'ok': True, 'count': 5, 'security': None, 'kernel': True, 'channel': 'no-subscription', 'repo_warnings': 0,
                       'subscription': 'notfound', 'cluster_id': 'c1', 'cluster_name': 'Testi', 'kind': 'node', 'name': 'pve1',
                       'pbs_id': None, 'checked_at': FIXED - 600, 'stale': False}],
            'clusters': [{'cluster_id': 'c1', 'cluster_name': 'Testi', 'state': 'ok', 'count': 5, 'checked_at': FIXED - 600,
                          'stale': False, 'rolling': None}]}


def _update_sent(app):
    return [(c[0], c[1], json.loads(c[2]) if c[2] else None) for c in app.server.sent if c[1] == UPDATE]


class _UpdServer(_NodeServer):
    """The node fake that keeps the body of every write."""

    def __init__(self, **kw):
        super().__init__(**kw)
        self.sent = []

    def handle(self, route):
        req = route.request
        path = re.sub(r'^https?://[^/]+', '', req.url).split('?')[0]
        if req.method != 'GET' and (req.method, path) in self.routes:
            self.sent.append((req.method, path, req.post_data))
        return super().handle(route)


def _actions(page, redesigned=True):
    if redesigned:
        page.locator('[data-cr-objhead="node"] .cr-objhead-actions button', has_text='Actions').first.click()
    else:
        page.locator('.corp-toolbar button', has_text='Actions').first.click()
    page.locator('[data-corp-node-update]').click()


def test_runtime_update_from_the_header_asks_with_the_updates_dialog(opener):
    app = opener(_UpdServer, routes={('GET', '/api/updates-overview'): (200, OVERVIEW), ('POST', UPDATE): NOT_IN_MAINT})
    page = app.page
    _open_summary(page)
    _actions(page)
    dlg = page.locator('[data-cr-upd-dialog="node-update"]')
    dlg.wait_for(timeout=5000)
    # the last check's count and kernel flag, from the server's copy
    assert _wait(page, lambda: '5 pending packages in the last check' in dlg.inner_text()), dlg.inner_text()
    box = dlg.locator('[data-cr-upd-opt="node-reboot"]')
    assert _wait(page, lambda: box.is_checked())
    assert _update_sent(app) == []
    box.uncheck()
    dlg.locator('[data-cr-upd-confirm="node-update"]').click()
    # not in maintenance: the dialog asks again before it sends force
    dlg.locator('[data-cr-upd-confirm="node-force"]').wait_for(timeout=5000)
    assert _update_sent(app) == [('POST', UPDATE, {'reboot': False})]
    app.server.routes[('POST', UPDATE)] = (200, {'success': True, 'message': 'Update started', 'task': {'status': 'starting', 'node': 'pve1'}})
    dlg.locator('[data-cr-upd-confirm="node-force"]').click()
    dlg.wait_for(state='detached', timeout=5000)
    assert _update_sent(app) == [('POST', UPDATE, {'reboot': False}), ('POST', UPDATE, {'reboot': False, 'force': True})]
    _no_errors(app)


def test_runtime_update_from_the_header_can_be_cancelled(opener):
    app = opener(_UpdServer, routes={('GET', '/api/updates-overview'): (200, OVERVIEW), ('POST', UPDATE): (200, {'success': True})})
    page = app.page
    _open_summary(page)
    _actions(page)
    dlg = page.locator('[data-cr-upd-dialog="node-update"]')
    dlg.wait_for(timeout=5000)
    dlg.locator('[data-cr-upd-cancel]').click()
    dlg.wait_for(state='detached', timeout=5000)
    page.wait_for_timeout(300)
    assert _update_sent(app) == []
    _no_errors(app)


def _release_overview(app, status, body):
    for r in app.server.held:
        r.fulfill(status=status, body=json.dumps(body), headers={'Content-Type': 'application/json'})
    app.server.held = []


def _held_question(opener):
    app = opener(_UpdServer, routes={('GET', '/api/updates-overview'): 'hold', ('POST', UPDATE): (200, {'success': True})})
    page = app.page
    _open_summary(page)
    _actions(page)
    dlg = page.locator('[data-cr-upd-dialog="node-update"]')
    dlg.wait_for(timeout=5000)
    assert _wait(page, lambda: len(app.server.held) >= 1)
    return app, page, dlg, dlg.locator('[data-cr-upd-opt="node-reboot"]'), dlg.locator('[data-cr-upd-confirm="node-update"]')


def test_runtime_the_update_question_waits_for_the_last_check_and_keeps_the_choice(opener):
    app, page, dlg, box, start = _held_question(opener)
    # the reboot default comes with the server's copy: nothing can be chosen or started before it
    assert box.is_disabled() and start.is_disabled()
    body = json.loads(json.dumps(OVERVIEW))
    body['hosts'][0]['kernel'] = False
    _release_overview(app, 200, body)
    assert _wait(page, lambda: not start.is_disabled())
    assert '5 pending packages in the last check' in dlg.inner_text()
    assert not box.is_checked()
    box.check()
    page.wait_for_timeout(400)
    assert box.is_checked()
    start.click()
    dlg.wait_for(state='detached', timeout=5000)
    assert _update_sent(app) == [('POST', UPDATE, {'reboot': True})]
    _no_errors(app)


def test_runtime_a_kernel_in_the_last_check_ticks_the_reboot_before_it_can_be_started(opener):
    app, page, dlg, box, start = _held_question(opener)
    # unticked while the kernel flag is unknown, and nothing that could be started on it
    assert not box.is_checked() and start.is_disabled()
    _release_overview(app, 200, OVERVIEW)
    assert _wait(page, lambda: not start.is_disabled())
    # the box is ticked by the time it can be touched, and it stays as it is shown
    assert box.is_checked()
    page.wait_for_timeout(400)
    assert box.is_checked()
    box.uncheck()
    start.click()
    dlg.wait_for(state='detached', timeout=5000)
    assert _update_sent(app) == [('POST', UPDATE, {'reboot': False})]
    _no_errors(app)


def test_runtime_a_failed_last_check_still_lets_the_update_be_asked(opener):
    app, page, dlg, box, start = _held_question(opener)
    _release_overview(app, 500, {'error': 'boom'})
    assert _wait(page, lambda: not start.is_disabled())
    assert '- pending packages' in dlg.inner_text(), dlg.inner_text()
    assert not box.is_checked()
    start.click()
    dlg.wait_for(state='detached', timeout=5000)
    assert _update_sent(app) == [('POST', UPDATE, {'reboot': False})]
    _no_errors(app)


def test_runtime_classic_corporate_asks_before_the_update(opener):
    app = opener(_UpdServer, layout='corporate', routes={('POST', UPDATE): (200, {'success': True, 'message': 'Update started'})})
    page = app.page
    _corp_cluster(page)
    page.locator('.corp-tree-child', has_text='pve1').first.click()
    _actions(page, redesigned=False)
    ask = page.locator('[data-corp-node-update-ask]')
    ask.wait_for(timeout=5000)
    page.wait_for_timeout(300)
    assert _update_sent(app) == []
    ask.locator('button', has_text=_exact('Cancel')).click()
    ask.wait_for(state='detached', timeout=5000)
    assert _update_sent(app) == []
    _actions(page, redesigned=False)
    ask.wait_for(timeout=5000)
    # the node card's question: the reboot box as classic sets it, and the body says it either way
    assert ask.locator('input[type="checkbox"]').is_checked()
    ask.locator('button', has_text=re.compile(r'Start')).click()
    assert _wait(page, lambda: len(_update_sent(app)) == 1)
    assert _update_sent(app) == [('POST', UPDATE, {'reboot': True})]
    _no_errors(app)


# --- XCP-ng host summary ---------------------------------------------------------------------------

XCP_METRICS = {'pve1': {'status': 'online', 'cpu_percent': 7.5, 'mem_used': 8 * GIB, 'mem_total': 32 * GIB, 'mem_percent': 25.0,
                        'disk_used': None, 'disk_total': None, 'disk_percent': None, 'netin': 0, 'netout': 0,
                        'uptime': 86400, 'score': 32.5, 'loadavg': [0.5, 0.4, 0.3], 'cpuinfo': {'cores': 8, 'sockets': 1},
                        'pveversion': 'XCP-ng 8.3.0', 'maintenance_mode': False, 'offline': False}}
# get_node_details of core/xcpng.py
XCP_DETAILS = {'hostname': 'pve1', 'uuid': 'host-uuid-1', 'address': '10.0.0.11', 'enabled': True,
               'cpu_model': 'Intel(R) Xeon(R) Silver 4210R', 'cpu_count': 8, 'cpu_socket_count': 1,
               'memory_total': 32 * GIB, 'memory_free': 24 * GIB, 'xen_version': '4.17.4-3', 'product_version': '8.3.0',
               'product_brand': 'XCP-ng', 'kernel_version': '4.19.0+1', 'build_number': 'release/yangtze/master/58',
               'bios_vendor': 'Dell Inc.', 'system_manufacturer': 'Dell Inc.', 'system_product': 'PowerEdge R640',
               'pci_devices': []}
# and with the Proxmox keys XAPI has: no swap, no rootfs
XCP_SUMMARY = dict(XCP_DETAILS, node='pve1', status='online', pveversion='XCP-ng 8.3.0', kversion='4.19.0+1',
                   cpuinfo={'model': 'Intel(R) Xeon(R) Silver 4210R', 'cpus': 8, 'sockets': 1},
                   memory={'total': 32 * GIB, 'used': 8 * GIB, 'free': 24 * GIB}, uptime=86400, loadavg=[0.5])


@pytest.mark.parametrize('summary', [XCP_DETAILS, XCP_SUMMARY], ids=['details', 'contract'])
def test_runtime_an_xcpng_host_summary_is_read_and_has_no_swap_or_root(opener, summary):
    app = opener(metrics=XCP_METRICS, clusters=[dict(CLUSTERS[0], cluster_type='xcpng')],
                 routes={('GET', NODE + '/summary'): (200, summary),
                         ('GET', NODE + '/ip'): (200, {'ip': '10.0.0.11', 'node': 'pve1', 'source': 'xapi_host_address'})})
    page = app.page
    _open_summary(page)
    assert _wait(page, lambda: _ns(page)['overall'] == 'normal', 8), _ns(page)
    st = _ns(page)
    assert st['sum'] is None, st
    assert 'swap' not in st['missing'].split() and 'root' not in st['missing'].split(), st
    for tid in ('swap', 'root'):
        assert 'Not applicable' in _tile(page, tid).inner_text(), _tile(page, tid).inner_text()
    _no_errors(app)


def test_runtime_a_proxmox_node_without_root_figures_still_names_them(opener):
    metrics = {'pve1': dict(METRICS['pve1'], disk_used=None, disk_total=None), 'pve2': dict(METRICS['pve2'])}
    summary = {'pveversion': 'pve-manager/9.0.3/abcdef', 'uptime': 86400, 'cpuinfo': {'cpus': 8}, 'loadavg': ['0.10', '0.20', '0.30']}
    app = opener(metrics=metrics, routes={('GET', NODE + '/summary'): (200, summary)})
    page = app.page
    _open_summary(page)
    assert _wait(page, lambda: 'root' in _ns(page)['missing'].split()), _ns(page)
    assert 'swap' in _ns(page)['missing'].split()
    assert 'Not applicable' not in _tile(page, 'root').inner_text()
    _no_errors(app)


# --- the leave guard and the tree ------------------------------------------------------------------

def _dirty_dns(app):
    page = app.page
    ncfg._open_cfg(page, 'dns')
    sec = ncfg._sec(page, 'dns')
    sec.locator('[data-cr-nc-k="dns2"]').wait_for(timeout=8000)
    sec.locator('[data-cr-nc-edit="dns"]').click()
    sec.locator('#cr-nc-dns-dns2').fill('8.8.8.8')
    page.wait_for_timeout(300)
    return sec


def test_runtime_another_clusters_tree_row_asks_before_the_edits_go(opener):
    app = opener(ncfg._CfgServer, clusters=[dict(c) for c in CLUSTERS])
    page = app.page
    sec = _dirty_dns(app)
    row = page.locator('.corp-tree-item', has_text='Prod').first
    assert row.get_attribute('role') == 'treeitem' and row.get_attribute('aria-expanded') is not None
    row.click()
    page.locator('[data-cr-nc-leave]').wait_for(timeout=3000)
    page.locator('[data-cr-nc-leave-keep]').click()
    page.wait_for_timeout(300)
    assert page.locator('[data-cr-objhead="node"]').count() == 1
    assert sec.locator('#cr-nc-dns-dns2').input_value() == '8.8.8.8'
    # Enter on the row picks the cluster in its key handler: held the same way
    row.focus()
    page.keyboard.press('Enter')
    page.locator('[data-cr-nc-leave]').wait_for(timeout=3000)
    page.locator('[data-cr-nc-leave-keep]').click()
    page.wait_for_timeout(300)
    assert page.locator('[data-cr-objhead="node"]').count() == 1
    # the chevron only folds the cluster: no question, the view stays
    row.locator(':scope > span').first.click()
    page.wait_for_timeout(500)
    assert page.locator('[data-cr-nc-leave]').count() == 0 and page.locator('[data-cr-objhead="node"]').count() == 1
    # discard goes where the click went
    row.click()
    page.locator('[data-cr-nc-leave]').wait_for(timeout=3000)
    page.locator('[data-cr-nc-leave-discard]').click()
    assert _wait(page, lambda: page.locator('[data-cr-objhead="node"]').count() == 0)
    assert not [s for s in app.server.sent if s[0] == 'PUT']
    _no_errors(app)


# --- the task log ---------------------------------------------------------------------------------

def test_runtime_a_finished_tasks_log_is_read_once_while_the_dashboard_renders(opener):
    app = opener()
    page = app.page
    _open_tasks(page)
    page.locator(f'[data-cr-nt-row="{OK}"]').click()
    page.locator(f'[data-cr-nt-log="{OK}"]').wait_for(timeout=5000)
    log = ('GET', f'{TASKS}/<{OK}>/log')
    assert _wait(page, lambda: app.server.calls.count(log) >= 1)
    # the dashboard renders meanwhile: its polls, and its refresh key three times
    for _ in range(3):
        page.wait_for_timeout(2500)
        page.locator('[data-cr-nt] .cr-nn-title').click()
        page.keyboard.press('r')
    page.wait_for_timeout(3000)
    assert app.server.calls.count(log) == 1, app.server.calls.count(log)
    _no_errors(app)


# --- certificates and Ceph --------------------------------------------------------------------------

CUSTOM_CERT = {'filename': 'pveproxy-ssl.pem', 'subject': '/CN=pve1.example.com', 'issuer': "/C=US/O=Let's Encrypt/CN=R11",
               'notbefore': FIXED - 30 * 86400, 'notafter': FIXED + 60 * 86400, 'fingerprint': 'DE:AD:BE:EF',
               'public-key-type': 'id-ecPublicKey', 'public-key-bits': 256, 'san': ['pve1.example.com']}


def test_runtime_the_certificate_card_reverts_to_self_signed_after_asking(opener):
    app = opener(ncfg._CfgServer, routes={('GET', ncfg.CERTS): (200, NODE_CERTS + [CUSTOM_CERT]),
                                         ('DELETE', ncfg.CUSTOM): (200, {'message': 'Custom certificate deleted'})})
    urls = []
    app.page.on('request', lambda r: urls.append((r.method, r.url)) if r.method == 'DELETE' else None)
    page = app.page
    ncfg._open_cfg(page, 'certs')
    sec = ncfg._sec(page, 'certs')
    sec.locator('[data-cr-nc-cert-revert]').wait_for(timeout=8000)
    sec.locator('[data-cr-nc-cert-revert]').click()
    ask = page.locator('[data-cr-nc-confirm="certs-revert"]')
    ask.wait_for(timeout=3000)
    assert 'pveproxy restarts' in ask.inner_text()
    page.locator('[data-cr-nc-confirm-cancel="certs-revert"]').click()
    page.wait_for_timeout(300)
    assert not urls
    sec.locator('[data-cr-nc-cert-revert]').click()
    page.locator('[data-cr-nc-confirm-go="certs-revert"]').click()
    assert _wait(page, lambda: len(urls) == 1)
    assert urls[0][1].endswith('/api/clusters/c1/nodes/pve1/certificates/custom?restart=true'), urls
    _no_errors(app)


def test_runtime_without_a_custom_certificate_there_is_nothing_to_revert(opener):
    app = opener(ncfg._CfgServer)
    page = app.page
    ncfg._open_cfg(page, 'certs')
    sec = ncfg._sec(page, 'certs')
    sec.locator('[data-cr-nc-cert-open]').wait_for(timeout=8000)
    assert sec.locator('[data-cr-nc-cert-revert]').count() == 0
    _no_errors(app)


CEPH_WRITES = {('POST', NODE + '/ceph/stop'): (200, 'UPID:pve1:stop'), ('POST', NODE + '/ceph/osd/0/out'): (200, None),
               ('POST', NODE + '/ceph/osd/2/in'): (200, None), ('POST', NODE + '/ceph/osd/1/scrub'): (200, None),
               ('POST', NODE + '/ceph/init'): (200, None)}


def _ceph_go(page, op, confirm_id):
    page.locator(f'[data-cr-nx-op="{op}"]').click()
    page.locator(f'[data-cr-nc-confirm="{confirm_id}"]').wait_for(timeout=3000)
    page.locator(f'[data-cr-nc-confirm-go="{confirm_id}"]').click()
    page.locator('[data-cr-nx-op-done="success"]').wait_for(timeout=5000)
    page.locator('[data-cr-nx-op-done] button').click()


def test_runtime_the_ceph_card_has_the_node_dialogs_writes_each_asked_first(opener):
    app = opener(nst._StoreServer, routes=CEPH_WRITES)
    page = app.page
    nst._open_cfg(page, 'ceph')
    nst._sec(page, 'ceph')
    for op in ('start', 'stop', 'restart'):
        assert page.locator(f'[data-cr-nx-op="{op}"]').count() == 1
    # a question that is cancelled sends nothing
    page.locator('[data-cr-nx-op="stop"]').click()
    page.locator('[data-cr-nc-confirm="ceph-stop"]').wait_for(timeout=3000)
    page.locator('[data-cr-nc-confirm-cancel="ceph-stop"]').click()
    page.wait_for_timeout(300)
    assert app.server.sent == []
    _ceph_go(page, 'stop', 'ceph-stop')
    _ceph_go(page, 'out:0', 'ceph-out')
    _ceph_go(page, 'in:2', 'ceph-in')
    _ceph_go(page, 'scrub:1', 'ceph-scrub')
    assert [s[1] for s in app.server.sent] == [NODE + '/ceph/stop', NODE + '/ceph/osd/0/out', NODE + '/ceph/osd/2/in',
                                              NODE + '/ceph/osd/1/scrub'], app.server.sent
    _no_errors(app)


def test_runtime_a_refused_ceph_write_is_said(opener):
    app = opener(nst._StoreServer, routes={('POST', NODE + '/ceph/restart'): (403, {'error': 'Permission denied: ceph.manage'})})
    page = app.page
    nst._open_cfg(page, 'ceph')
    nst._sec(page, 'ceph')
    page.locator('[data-cr-nx-op="restart"]').click()
    page.locator('[data-cr-nc-confirm-go="ceph-restart"]').click()
    done = page.locator('[data-cr-nx-op-done="error"]')
    done.wait_for(timeout=5000)
    assert 'Permission denied: ceph.manage' in done.inner_text()
    _no_errors(app)


def test_runtime_a_node_without_ceph_offers_to_set_it_up(opener):
    app = opener(nst._StoreServer, routes={('GET', nst.CEPH_STATUS): (200, {'available': False}), **CEPH_WRITES})
    page = app.page
    nst._open_cfg(page, 'ceph')
    page.locator('[data-cr-nc-sec="ceph"][data-cr-nx-state="none"]').wait_for(timeout=8000)
    _ceph_go(page, 'init', 'ceph-init')
    assert [s[1] for s in app.server.sent] == [NODE + '/ceph/init']
    _no_errors(app)


# --- SMART without data -----------------------------------------------------------------------------

def test_runtime_a_smart_answer_without_data_is_no_reading(opener):
    app = opener(nhw._HwServer)
    page = app.page
    nhw._open_disks(page)
    nhw._drow(page, 'sdb').wait_for(timeout=8000)
    nhw._read_all(page, 3)
    # 200 {} is what get_node_disk_smart answers when it could not ask the node
    assert nhw._cell(page, 'sdb', 'temp') == 'No data'
    assert nhw._drow(page, 'sdb').locator('[data-cr-nd-smart-blank]').count() == 1
    assert 'SMART read for 3 of 5 disks' in page.locator('[data-cr-nd-note]').inner_text()
    # the dialog says so too, never an empty reading
    page.locator('[data-cr-nd-smart="sdb"]').click()
    page.get_by_text('The SMART read came back without any data').first.wait_for(timeout=5000)
    _no_errors(app)


# --- Updating on a Refresh ---------------------------------------------------------------------------

def test_runtime_refresh_on_tasks_shows_updating_until_the_answer(opener):
    app = opener()
    page = app.page
    _open_tasks(page)
    bar = page.locator('[data-cr-nt] .cr-nn-bar')
    assert bar.locator('[data-cr-nc-updating]').count() == 0
    app.server.routes[('GET', TASKS)] = 'hold'
    page.locator('[data-cr-nt-reload]').click()
    assert _wait(page, lambda: len(app.server.held) >= 1)
    assert bar.locator('[data-cr-nc-updating]').count() == 1
    assert page.locator('[data-cr-nt] [data-cr-nt-row]').count() > 0
    from test_corp_redesigned_guard_ui import NODE_TASK_LIST
    for r in app.server.held:
        r.fulfill(status=200, body=json.dumps(NODE_TASK_LIST), headers={'Content-Type': 'application/json'})
    app.server.held = []
    assert _wait(page, lambda: bar.locator('[data-cr-nc-updating]').count() == 0)
    _no_errors(app)


def test_runtime_refresh_on_disks_and_hardware_shows_updating(opener):
    app = opener(nhw._HwServer)
    page = app.page
    nhw._open_disks(page)
    nhw._drow(page, 'sdb').wait_for(timeout=8000)
    app.server.routes[('GET', nhw.DISKS)] = 'hold'
    page.locator('[data-cr-nd-reload]').click()
    assert _wait(page, lambda: len(app.server.held) >= 1)
    assert page.locator('[data-cr-nc-sec="disks"] [data-cr-nc-updating]').count() == 1
    from test_corp_redesigned_guard_ui import NODE_DISKS
    for r in app.server.held:
        r.fulfill(status=200, body=json.dumps(NODE_DISKS), headers={'Content-Type': 'application/json'})
    app.server.held = []
    assert _wait(page, lambda: page.locator('[data-cr-nc-sec="disks"] [data-cr-nc-updating]').count() == 0)
    _tab(page, 'Hardware')
    page.locator('[data-cr-nh-reload]').wait_for(timeout=8000)
    assert _wait(page, lambda: page.locator('[data-cr-nh] [data-cr-nc-updating]').count() == 0)
    app.server.routes[('GET', nhw.SENSORS)] = 'hold'
    page.locator('[data-cr-nh-reload]').click()
    assert _wait(page, lambda: len(app.server.held) >= 1)
    assert page.locator('[data-cr-nh] .cr-nn-bar [data-cr-nc-updating]').count() == 1
    _no_errors(app)


# --- a first visit reads once -------------------------------------------------------------------------

@pytest.mark.parametrize('layout', [LAYOUT, 'corporate'])
def test_runtime_a_first_visit_of_a_sub_tab_reads_once(opener, layout):
    app = opener(nst._StoreServer, layout=layout)
    page = app.page
    red = layout == LAYOUT
    nst._open_cfg(page, 'disks', redesigned=red)
    assert _wait(page, lambda: app.server.reads(nst.DISKS) >= 1)
    page.wait_for_timeout(1200)
    assert [app.server.reads(p) for p in (nst.DISKS, nst.LVM, nst.THIN, nst.ZFS)] == [1, 1, 1, 1]
    nst._sub(page, 'ceph')
    assert _wait(page, lambda: app.server.reads(nst.CEPH_STATUS) >= 1)
    page.wait_for_timeout(1200)
    assert [app.server.reads(p) for p in (nst.CEPH_STATUS, nst.CEPH_OSD, nst.CEPH_MON, nst.CEPH_POOL)] == [1, 1, 1, 1]
    # a click on the open sub tab reads nothing it already has
    nst._sub(page, 'ceph')
    page.wait_for_timeout(600)
    assert app.server.reads(nst.CEPH_STATUS) == 1
    _no_errors(app)


def test_runtime_the_first_visit_of_tasks_reads_once(opener):
    app = opener()
    page = app.page
    _open_tasks(page)
    page.wait_for_timeout(800)
    assert app.server.reads(TASKS) == 1
    _no_errors(app)


# --- failed node reads with a code -------------------------------------------------------------------------

def test_runtime_a_task_list_the_server_failed_is_said_in_words(opener):
    body = {'error': 'Could not read the task list of node pve1: unexpected answer', 'code': 'PVE_READ_FAILED', 'upstream_status': 500}
    app = opener(routes={('GET', TASKS): (502, body)})
    page = app.page
    _open_tasks(page, wait=False)
    err = page.locator('[data-cr-nt-error]')
    err.wait_for(timeout=8000)
    assert 'Proxmox VE could not answer it (HTTP 502)' in err.inner_text(), err.inner_text()
    _no_errors(app)


def test_runtime_an_empty_task_list_carries_no_doubt(opener):
    app = opener(routes={('GET', TASKS): (200, [])})
    page = app.page
    _open_tasks(page, wait=False)
    page.locator('[data-cr-nt][data-cr-nt-read="empty"]').wait_for(timeout=8000)
    text = page.locator('[data-cr-nt]').inner_text()
    assert 'No tasks reported for pve1.' in text and 'failed read' not in text, text
    _no_errors(app)
