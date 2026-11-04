"""The network of a node in Corporate Redesigned (Preview), in the browser.

Round 6 draws the Configure > Network sub tab of a Proxmox VE node in the preview from
web/src/cr_node.js: the interfaces grouped Physical, Bond, Bridge, VLAN and Other, each with its
role and what it is built from, the chains under each top interface (eno1 + eno2 -> bond0 ->
vmbr0), and what waits for Apply, read from GET .../network/changes (the diff Proxmox VE keeps
for interfaces.new, pegaprox/api/nodes.py get_node_network_changes_api). Apply opens a summary
with the waiting changes, a warning when they touch the interface that carries the address
PegaProx uses for the node, the plain statement that there is no automatic rollback and a
confirmation; Revert asks first too. Both then send exactly the classic request (PUT and DELETE
.../network, no body). The classic edit and create dialogs stay, classic Corporate is unchanged.

The pure parts (grouping, chains, the diff cut into interfaces, the management check) are
checked through window.PegaProxNodeNet. PEGAPROX_CR_BUNDLE=<file> serves another bundle (the
counterproof against the build before round 6). Skips without Playwright. LW Nov 2026
"""
import json
import os
import re

import pytest

from test_corp_redesigned_guard_ui import (CLUSTER, DETERMINISTIC, NODE_IP, NODE_NET, NODE_SUMMARY, _GuardApp,
                                           _GuardServer, _corp_cluster)

LAYOUT = 'corporate-redesigned'
_BUNDLE_FILE = os.environ.get('PEGAPROX_CR_BUNDLE')
BUNDLE = open(_BUNDLE_FILE, encoding='utf-8').read() if _BUNDLE_FILE else None

NODE = '/api/clusters/c1/nodes/pve1'
NET = NODE + '/network'
CHANGES = NET + '/changes'

# diff -b -N -u of interfaces against interfaces.new, the way PVE's INotify.pm makes it: the
# gateway of vmbr0 changes, vmbr0.20 is new, eno3 is removed
DIFF = '\n'.join([
    '--- /etc/network/interfaces\t2026-10-30 09:00:00.000000000 +0000',
    '+++ /etc/network/interfaces.new\t2026-11-01 10:00:00.000000000 +0000',
    '@@ -14,12 +14,16 @@',
    ' auto vmbr0',
    ' iface vmbr0 inet static',
    ' \taddress 10.0.0.11/24',
    '-\tgateway 10.0.0.253',
    '+\tgateway 10.0.0.254',
    ' \tbridge-ports bond0',
    ' \tbridge-stp off',
    ' \tbridge-fd 0',
    ' #management',
    ' ',
    '+auto vmbr0.20',
    '+iface vmbr0.20 inet static',
    '+\taddress 10.0.20.11/24',
    '+',
    ' auto vmbr1',
    ' iface vmbr1 inet manual',
    ' \tbridge-ports none',
    '@@ -30,9 +34,5 @@',
    ' \tbridge-fd 0',
    ' #guests only',
    ' ',
    '-auto eno3',
    '-iface eno3 inet manual',
    '-\tmtu 9000',
    '-',
    ' iface vlan30 inet manual',
    ' \tvlan-raw-device bond0',
    '',
])
# a change on vmbr1 only, which carries nothing PegaProx uses
DIFF_VMBR1 = '\n'.join([
    '--- /etc/network/interfaces\t2026-10-30 09:00:00.000000000 +0000',
    '+++ /etc/network/interfaces.new\t2026-11-01 10:00:00.000000000 +0000',
    '@@ -22,6 +22,7 @@',
    ' auto vmbr1',
    ' iface vmbr1 inet manual',
    ' \tbridge-ports none',
    '+\tmtu 9000',
    ' \tbridge-stp off',
    ' \tbridge-fd 0',
    ' #guests only',
    '',
])
# a hunk whose change sits before the first stanza line it shows: the block is not known
DIFF_UNTIED = '\n'.join([
    '--- /etc/network/interfaces\t2026-10-30 09:00:00.000000000 +0000',
    '+++ /etc/network/interfaces.new\t2026-11-01 10:00:00.000000000 +0000',
    '@@ -20,7 +20,7 @@',
    ' \tbridge-ports none',
    ' \tbridge-stp off',
    '-\tbridge-fd 0',
    '+\tbridge-fd 2',
    ' #guests only',
    ' ',
    ' iface vlan30 inet manual',
    '',
])
CLUSTER_ON_NODE = dict(CLUSTER, host='10.0.0.11')


class _NetServer(_GuardServer):
    """The guard fake with the node's network, its waiting changes and the classic writes; each
    answer settable while the page runs: a (code, body) pair, 'hold' or 'abort'."""

    def __init__(self, net=None, changes=None, apply=None, revert=None, ip=None, **kw):
        super().__init__(bundle=BUNDLE, **kw)
        self.routes = {
            ('GET', NET): net or (200, NODE_NET),
            ('GET', CHANGES): changes or (200, {'changes': DIFF}),
            ('GET', NODE + '/ip'): ip or (200, NODE_IP),
            ('GET', NODE + '/summary'): (200, NODE_SUMMARY),
            ('PUT', NET): apply or (200, {'message': 'Network configuration applied'}),
            ('DELETE', NET): revert or (200, {'message': 'Network changes reverted'}),
        }
        self.sent = []
        self.held = []

    def handle(self, route):
        req = route.request
        path = re.sub(r'^https?://[^/]+', '', req.url).split('?')[0]
        how = self.routes.get((req.method, path))
        if how is None and path.startswith(NET + '/') and req.method in ('PUT', 'POST', 'DELETE'):
            how = (200, {'message': 'ok'})
        if how is None:
            return super().handle(route)
        self.calls.append((req.method, path))
        if req.method != 'GET':
            self.sent.append((req.method, path, req.post_data))
        if how == 'abort':
            return route.abort('connectionrefused')
        if how == 'hold':
            self.held.append(route)
            return None
        code, data = how
        return route.fulfill(status=code, body=json.dumps(data), headers={'Content-Type': 'application/json'})

    def reads(self, path):
        return len([c for c in self.calls if c == ('GET', path)])


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

    def _open(layout=LAYOUT, viewport=(1600, 1000), br=None, clusters=None, **kw):
        server = _NetServer(layout=layout, **kw)
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


def _open_network(page, redesigned=True):
    _corp_cluster(page)
    page.locator('.corp-tree-child', has_text='pve1').first.click()
    if redesigned:
        page.locator('[data-cr-tabs="node"] [role="tab"]', has_text='Configure').click()
    else:
        page.locator('.corp-tab-strip button', has_text='Configure').first.click()


def _nn(page):
    page.locator('[data-cr-nn]').wait_for(timeout=8000)
    return page.locator('[data-cr-nn]')


def _settled_changes(page, state):
    page.locator(f'[data-cr-nn-pending="{state}"]').wait_for(timeout=8000)


def _confirm_apply(dlg, node='pve1'):
    # round 8 (R6-2): a change on the path PegaProx uses for the node is confirmed by typing its name,
    # every other one by the checkbox
    name = dlg.locator('[data-cr-nn-typename-input]')
    if name.count():
        name.fill(node)
    else:
        dlg.locator('[data-cr-nn-ack]').check()


# --- the pure parts -----------------------------------------------------------------------------

@pytest.fixture(scope='module')
def nn_page(browser):
    app = _GuardApp(browser, _NetServer(layout=LAYOUT))
    if not app.page.evaluate('() => !!window.PegaProxNodeNet'):
        app.close()
        pytest.fail('the bundle has no node network helpers (window.PegaProxNodeNet)')
    yield app.page
    app.close()


def _chain_text(page, rows, name):
    return page.evaluate('''([rows, name]) => {
        const N = window.PegaProxNodeNet;
        return N.chain(N.model(rows), name).map(x => x.k === 'if' ? x.name + (x.loop ? '!' : '')
            : x.k === 'plus' ? '+' : x.k === 'arrow' ? '->' : x.k === 'open' ? '(' : ')').join(' ');
    }''', [rows, name])


def test_rules_groups_by_kind(nn_page):
    kinds = {'eth': 'physical', 'bond': 'bond', 'OVSBond': 'bond', 'bridge': 'bridge', 'OVSBridge': 'bridge',
             'vlan': 'vlan', 'OVSIntPort': 'other', 'OVSPort': 'other', 'alias': 'other', 'unknown': 'other', '': 'other'}
    got = nn_page.evaluate('(kinds) => Object.keys(kinds).map(k => window.PegaProxNodeNet.group({type: k}))', kinds)
    assert dict(zip(kinds, got)) == kinds
    groups = nn_page.evaluate('(rows) => { const g = window.PegaProxNodeNet.model(rows).groups; '
                              'return Object.fromEntries(Object.entries(g).map(([k, v]) => [k, v.map(r => r.iface)])); }', NODE_NET)
    assert groups == {'physical': ['eno1', 'eno2'], 'bond': ['bond0'], 'bridge': ['vmbr0', 'vmbr1'],
                      'vlan': ['vlan30', 'vmbr0.20'], 'other': []}


def test_rules_the_chain_comes_from_the_list_only(nn_page):
    assert nn_page.evaluate('(rows) => window.PegaProxNodeNet.model(rows).tops', NODE_NET) == ['vlan30', 'vmbr0.20']
    assert _chain_text(nn_page, NODE_NET, 'vmbr0.20') == 'eno1 + eno2 -> bond0 -> vmbr0 -> vmbr0.20'
    # a VLAN with vlan-raw-device sits on that device, not on a name it might look like
    assert _chain_text(nn_page, NODE_NET, 'vlan30') == 'eno1 + eno2 -> bond0 -> vlan30'
    mixed = NODE_NET + [{'iface': 'eno3', 'type': 'eth'},
                        {'iface': 'vmbr2', 'type': 'bridge', 'bridge_ports': 'bond0 eno3'}]
    assert _chain_text(nn_page, mixed, 'vmbr2') == '( eno1 + eno2 -> bond0 ) + eno3 -> vmbr2'
    # a loop in the config stops the walk instead of hanging the page
    loop = [{'iface': 'br-a', 'type': 'bridge', 'bridge_ports': 'br-b'}, {'iface': 'br-b', 'type': 'bridge', 'bridge_ports': 'br-a'}]
    assert '!' in _chain_text(nn_page, loop, 'br-a')
    # an OVS bridge lists its ports in ovs_ports, an OVS bond its members in ovs_bonds
    ovs = [{'iface': 'eno1', 'type': 'OVSPort', 'ovs_bridge': 'vmbr9'}, {'iface': 'eno2', 'type': 'eth'},
           {'iface': 'bond9', 'type': 'OVSBond', 'ovs_bonds': 'eno2 eno4', 'ovs_bridge': 'vmbr9'},
           {'iface': 'vmbr9', 'type': 'OVSBridge', 'ovs_ports': 'eno1 bond9'}]
    assert _chain_text(nn_page, ovs, 'vmbr9') == 'eno1 + ( eno2 + eno4 -> bond9 ) -> vmbr9'


def _parse(page, text):
    return page.evaluate('(t) => { const d = window.PegaProxNodeNet.parseDiff(t === null ? undefined : t); '
                         'return {known: d.known, empty: d.empty, untied: d.untied, added: d.added, removed: d.removed, '
                         'ifaces: Object.fromEntries(Object.entries(d.ifaces).map(([k, v]) => [k, [v.state, v.add, v.del]]))}; }', text)


def test_rules_the_diff_is_cut_into_interfaces(nn_page):
    d = _parse(nn_page, DIFF)
    assert d['known'] and not d['empty'] and d['untied'] == 0
    assert d['ifaces'] == {'vmbr0': ['changed', 1, 1], 'vmbr0.20': ['new', 3, 0], 'eno3': ['removed', 0, 3]}
    # the blank lines a stanza ends with are not a change of an interface
    assert (d['added'], d['removed']) == (4, 4)
    u = _parse(nn_page, DIFF_UNTIED)
    assert u['ifaces'] == {} and u['untied'] == 2
    assert _parse(nn_page, '') == {'known': True, 'empty': True, 'untied': 0, 'added': 0, 'removed': 0, 'ifaces': {}}
    # no answer is not "nothing waits"
    assert _parse(nn_page, None)['known'] is False


def _risk(page, rows, diff, node_ip='10.0.0.11', source='corosync', host='10.0.0.1'):
    return page.evaluate('''([rows, diff, ip, source, host]) => {
        const N = window.PegaProxNodeNet;
        const m = N.management(N.model(rows), {nodeIp: ip, nodeIpStandIn: /_fallback$/.test(source), clusterHost: host});
        const r = N.risk(m, N.parseDiff(diff === null ? undefined : diff));
        return {level: r.level, hits: r.hits.sort(), named: r.named, reasons: r.reasons, chain: [...m.chain].sort(),
                carriers: m.carriers.map(c => c.iface + '@' + c.addr + ':' + c.role)};
    }''', [rows, diff, node_ip, source, host])


def test_rules_the_management_interface_and_what_touches_it(nn_page):
    r = _risk(nn_page, NODE_NET, DIFF, host='10.0.0.11')
    assert r['carriers'] == ['vmbr0@10.0.0.11:both']
    assert r['chain'] == ['bond0', 'eno1', 'eno2', 'vmbr0']
    assert r['level'] == 'touch' and r['hits'] == ['vmbr0']
    # a change on vmbr1 is clear of it, as long as every address is placed and every line tied
    assert _risk(nn_page, NODE_NET, DIFF_VMBR1, host='10.0.0.11')['level'] == 'clear'
    # the API host on another node's address does not make this node's change unsure
    r = _risk(nn_page, NODE_NET, DIFF_VMBR1)
    assert r['level'] == 'clear' and r['reasons'] == [] and r['carriers'] == ['vmbr0@10.0.0.11:node']
    # the node's own address on no interface here: the page does not know where it is
    r = _risk(nn_page, NODE_NET, DIFF_VMBR1, node_ip='10.0.0.99', host='10.0.0.11')
    assert r['level'] == 'unsure' and r['reasons'] == ['unmatched']
    # a pending line that names the API host counts, wherever that address is
    assert _risk(nn_page, NODE_NET, DIFF_VMBR1.replace('mtu 9000', 'post-up ip route add 10.0.0.1/32 dev vmbr1'))['named'] == ['10.0.0.1']
    # a name, a stand-in node address, an unknown diff, a line without a block: each one unsure
    assert _risk(nn_page, NODE_NET, DIFF_VMBR1, host='pve.example.net')['reasons'] == ['hostname']
    assert 'nodeip' in _risk(nn_page, NODE_NET, DIFF_VMBR1, source='cluster_host_fallback', host='10.0.0.11')['reasons']
    assert _risk(nn_page, NODE_NET, None, host='10.0.0.11')['level'] == 'unsure'
    assert _risk(nn_page, NODE_NET, DIFF_UNTIED, host='10.0.0.11')['reasons'] == ['untied']
    # the address moves away: the list no longer has it, the removed line names it
    moved = [dict(r, cidr='10.0.0.12/24', address='10.0.0.12') if r['iface'] == 'vmbr0' else r for r in NODE_NET]
    diff = DIFF_VMBR1.replace(' \tbridge-ports none\n+\tmtu 9000', '-\taddress 10.0.0.11/24\n+\taddress 10.0.0.12/24')
    r = _risk(nn_page, moved, diff, host='10.0.0.11')
    assert r['level'] == 'touch' and r['named'] == ['10.0.0.11'], r
    # 10.0.0.1 is not 10.0.0.11
    assert _risk(nn_page, NODE_NET, DIFF_VMBR1.replace('mtu 9000', 'address 10.0.0.110/24'), host='10.0.0.11')['level'] == 'clear'


# the management bridge on one port, and a new bond that waits and takes that port
TAKE_ROWS = [
    {'iface': 'eno1', 'type': 'eth', 'active': 1},
    {'iface': 'eno2', 'type': 'eth', 'active': 1},
    {'iface': 'vmbr0', 'type': 'bridge', 'bridge_ports': 'eno1', 'cidr': '10.0.0.5/24', 'address': '10.0.0.5',
     'gateway': '10.0.0.1', 'active': 1},
    {'iface': 'bond0', 'type': 'bond', 'slaves': 'eno1 eno2', 'bond_mode': 'active-backup'},
]
DIFF_TAKE = '\n'.join([
    '--- /etc/network/interfaces\t2026-10-30 09:00:00.000000000 +0000',
    '+++ /etc/network/interfaces.new\t2026-11-01 10:00:00.000000000 +0000',
    '@@ -10,3 +10,9 @@',
    ' iface eno2 inet manual',
    ' ',
    '+auto bond0',
    '+iface bond0 inet manual',
    '+\tbond-slaves eno1 eno2',
    '+\tbond-miimon 100',
    '+\tbond-mode active-backup',
    '+',
    ' auto vmbr0',
    '',
])


def _takers(page, rows, diff, node_ip='10.0.0.5'):
    return page.evaluate('''([rows, diff, ip]) => {
        const N = window.PegaProxNodeNet;
        const m = N.management(N.model(rows), {nodeIp: ip, nodeIpStandIn: false, clusterHost: ip});
        const r = N.risk(m, N.parseDiff(diff));
        return {level: r.level, hits: r.hits, takers: r.takers || null};
    }''', [rows, diff, node_ip])


def test_rules_a_waiting_bond_or_bridge_that_takes_a_management_port_touches_it(nn_page):
    # bond0 is not on vmbr0 or under it, but it takes eno1, the port vmbr0 carries the node address over
    r = _takers(nn_page, TAKE_ROWS, DIFF_TAKE)
    assert r == {'level': 'touch', 'hits': [], 'takers': [{'iface': 'bond0', 'takes': ['eno1']}]}, r
    # a bridge that takes a member of the chain under the carrier counts the same
    rows = NODE_NET + [{'iface': 'vmbr9', 'type': 'bridge', 'bridge_ports': 'bond0'}]
    diff = DIFF_TAKE.replace('bond0', 'vmbr9').replace('bond-slaves eno1 eno2', 'bridge-ports bond0')
    r = _takers(nn_page, rows, diff, node_ip='10.0.0.11')
    assert r['level'] == 'touch' and r['takers'] == [{'iface': 'vmbr9', 'takes': ['bond0']}], r
    # a VLAN on a member of the chain sits on top of it and takes nothing
    rows = TAKE_ROWS[:3] + [{'iface': 'eno1.30', 'type': 'vlan'}]
    diff = DIFF_TAKE.replace('bond0', 'eno1.30').replace('\tbond-slaves eno1 eno2', '\tvlan-raw-device eno1')
    assert _takers(nn_page, rows, diff)['level'] == 'clear'
    # a bond on ports the connection does not run over is clear
    rows = TAKE_ROWS[:3] + [{'iface': 'eno3', 'type': 'eth'}, {'iface': 'bond0', 'type': 'bond', 'slaves': 'eno2 eno3'}]
    assert _takers(nn_page, rows, DIFF_TAKE.replace('bond-slaves eno1 eno2', 'bond-slaves eno2 eno3'))['level'] == 'clear'


# --- the page -----------------------------------------------------------------------------------

def test_runtime_interfaces_by_kind_with_role_and_chain(open_app):
    app = open_app()
    page = app.page
    _open_network(page)
    nn = _nn(page)
    _settled_changes(page, 'some')
    groups = nn.locator('tbody[data-cr-nn-group]')
    assert [groups.nth(i).get_attribute('data-cr-nn-group') for i in range(groups.count())] == \
        ['physical', 'bond', 'bridge', 'vlan', 'removed']
    rows = lambda g: [r.get_attribute('data-cr-nn-row') for r in nn.locator(f'tbody[data-cr-nn-group="{g}"] tr[data-cr-nn-row]').all()]
    assert rows('physical') == ['eno1', 'eno2'] and rows('bond') == ['bond0'] and rows('bridge') == ['vmbr0', 'vmbr1']
    assert rows('vlan') == ['vlan30', 'vmbr0.20'] and rows('removed') == ['eno3']
    role = lambda n: nn.locator(f'tr[data-cr-nn-row="{n}"] td').nth(1).inner_text().strip()
    assert role('eno1') == 'Member of bond0'
    assert role('bond0') == 'Bond, mode 802.3ad'
    assert role('vmbr0') == 'Bridge'
    assert role('vlan30') == 'VLAN 30 on bond0'
    assert role('vmbr0.20') == 'VLAN 20 on vmbr0'
    assert nn.locator('tr[data-cr-nn-row="bond0"] td').nth(2).inner_text().split('\n') == ['From eno1, eno2', 'Used by vlan30, vmbr0']
    assert nn.locator('tr[data-cr-nn-row="vmbr0"] td').nth(3).inner_text().split('\n') == ['10.0.0.11/24', 'via 10.0.0.254']
    chain = nn.locator('[data-cr-nn-chain="vmbr0.20"] [data-cr-nn-chip]')
    assert [c.get_attribute('data-cr-nn-chip') for c in chain.all()] == ['eno1', 'eno2', 'bond0', 'vmbr0', 'vmbr0.20']
    # an inactive interface is "not active", never a green state
    assert nn.locator('tr[data-cr-nn-row="vmbr1"] .cr-badge').inner_text().strip() == 'Not active'
    assert 'cr-badge-success' not in nn.locator('tr[data-cr-nn-row="vmbr1"] .cr-badge').get_attribute('class')
    _no_errors(app)


def test_runtime_pending_changes_are_marked_and_counted(open_app):
    app = open_app()
    page = app.page
    _open_network(page)
    nn = _nn(page)
    _settled_changes(page, 'some')
    assert app.server.reads(CHANGES) == 1 and app.server.reads(NET) == 1
    assert nn.locator('.cr-nc-head .cr-badge').inner_text().strip() == '3 waiting'
    marks = {n: nn.locator(f'tr[data-cr-nn-row="{n}"] [data-cr-nn-pend]').get_attribute('data-cr-nn-pend')
             for n in ('vmbr0', 'vmbr0.20', 'eno3')}
    assert marks == {'vmbr0': 'changed', 'vmbr0.20': 'new', 'eno3': 'removed'}
    for n in ('eno1', 'eno2', 'bond0', 'vmbr1', 'vlan30'):
        assert nn.locator(f'tr[data-cr-nn-row="{n}"] [data-cr-nn-pend]').count() == 0, n
    banner = page.locator('[data-cr-nn-pending="some"]')
    assert 'Interfaces with changes that wait for Apply: 3' in banner.inner_text()
    assert [li.get_attribute('data-cr-nn-change') for li in banner.locator('[data-cr-nn-change]').all()] == ['eno3', 'vmbr0', 'vmbr0.20']
    banner.locator('[data-cr-nn-diff-toggle]').click()
    diff = banner.locator('[data-cr-nn-diff]')
    assert diff.locator('.cr-nn-dl-add').count() == 5 and diff.locator('.cr-nn-dl-del').count() == 5
    assert '+\tgateway 10.0.0.254' in diff.inner_text()
    # the chips of the chain carry the marks too
    assert 'cr-nn-chip-pending' in nn.locator('[data-cr-nn-chain="vmbr0.20"] [data-cr-nn-chip="vmbr0"]').get_attribute('class')
    _no_errors(app)


def test_runtime_nothing_waiting_is_said(open_app):
    app = open_app(changes=(200, {'changes': ''}))
    _open_network(app.page)
    _settled_changes(app.page, 'none')
    assert app.page.locator('[data-cr-nn-pend]').count() == 0
    assert app.page.locator('[data-cr-nn-pending="none"]').inner_text().strip() == 'No changes wait for Apply.'


def test_runtime_a_failed_read_of_the_changes_is_said_not_given_as_nothing(open_app):
    app = open_app(changes=(502, {'error': 'Could not read the network configuration', 'upstream_status': 500}))
    page = app.page
    _open_network(page)
    _settled_changes(page, 'error')
    text = page.locator('[data-cr-nn-pending="error"]').inner_text()
    assert 'Could not read the network configuration (HTTP 502)' in text
    assert page.locator('[data-cr-nn-pending="none"]').count() == 0
    # Apply then says it does not know, and cannot rule out a lockout
    page.locator('[data-cr-nn-apply]').click()
    dlg = page.locator('[data-cr-upd-dialog="nn-apply"]')
    assert dlg.locator('[data-cr-nn-summary-state="unknown"]').count() == 1
    assert dlg.locator('[data-cr-nn-mgmt="unsure"]').count() == 1
    # retry reads again
    app.server.routes[('GET', CHANGES)] = (200, {'changes': DIFF})
    page.keyboard.press('Escape')
    page.locator('[data-cr-nn-pending="error"] button', has_text='Retry').click()
    _settled_changes(page, 'some')
    assert app.server.reads(CHANGES) == 2


def test_runtime_apply_shows_the_summary_and_confirms_before_the_classic_put(open_app):
    app = open_app(clusters=[CLUSTER_ON_NODE])
    page = app.page
    _open_network(page)
    _settled_changes(page, 'some')
    page.locator('[data-cr-nn-apply]').click()
    dlg = page.locator('[data-cr-upd-dialog="nn-apply"]')
    dlg.wait_for(timeout=5000)
    assert app.server.sent == []
    text = dlg.inner_text()
    assert 'Apply the network changes on pve1' in text
    assert 'Interfaces with waiting changes: 3. Lines added: 4, removed: 4.' in text
    assert [li.get_attribute('data-cr-nn-change') for li in dlg.locator('[data-cr-nn-change]').all()] == ['eno3', 'vmbr0', 'vmbr0.20']
    # the change on vmbr0 touches the address PegaProx uses, said prominently
    mg = dlg.locator('[data-cr-nn-mgmt="touch"]')
    assert mg.get_attribute('role') == 'alert'
    assert 'touches the connection PegaProx uses for pve1' in mg.inner_text() and '10.0.0.11' in mg.inner_text()
    assert 'vmbr0' in mg.inner_text()
    roll = dlg.locator('[data-cr-nn-norollback]').inner_text()
    assert 'No automatic rollback' in roll and 'can cut the node off from PegaProx' in roll
    go = dlg.locator('[data-cr-nn-apply-go]')
    assert go.is_disabled()
    _confirm_apply(dlg)
    assert go.is_enabled() and 'cr-btn-danger' in go.get_attribute('class')
    reads = app.server.reads(NET)
    go.click()
    dlg.wait_for(state='detached', timeout=5000)
    assert app.server.sent == [('PUT', NET, None)]
    # the list and what waits are read again
    page.wait_for_function('() => true')
    page.wait_for_timeout(500)
    assert app.server.reads(NET) > reads and app.server.reads(CHANGES) >= 2
    _no_errors(app)


def test_runtime_cancel_and_escape_send_nothing(open_app):
    app = open_app()
    page = app.page
    _open_network(page)
    _settled_changes(page, 'some')
    page.locator('[data-cr-nn-apply]').click()
    # vmbr0 carries the node's address only; the API host 10.0.0.1 is on another node
    touch = page.locator('[data-cr-upd-dialog="nn-apply"] [data-cr-nn-mgmt="touch"]').inner_text()
    assert 'vmbr0 carries 10.0.0.11, and' in touch and '10.0.0.1,' not in touch, touch
    _confirm_apply(page.locator('[data-cr-upd-dialog="nn-apply"]'))
    page.locator('[data-cr-upd-dialog="nn-apply"] footer button', has_text='Cancel').click()
    page.locator('[data-cr-nn-revert]').click()
    page.locator('[data-cr-upd-dialog="nn-revert"]').wait_for(timeout=5000)
    page.keyboard.press('Escape')
    page.locator('[data-cr-upd-dialog="nn-revert"]').wait_for(state='detached', timeout=5000)
    assert app.server.sent == []


def test_runtime_revert_asks_first_then_sends_the_classic_delete(open_app):
    app = open_app()
    page = app.page
    _open_network(page)
    _settled_changes(page, 'some')
    page.locator('[data-cr-nn-revert]').click()
    dlg = page.locator('[data-cr-upd-dialog="nn-revert"]')
    dlg.wait_for(timeout=5000)
    assert app.server.sent == []
    text = dlg.inner_text()
    assert 'Discard the network changes on pve1' in text and 'cannot be brought back' in text
    assert [li.get_attribute('data-cr-nn-change') for li in dlg.locator('[data-cr-nn-change]').all()] == ['eno3', 'vmbr0', 'vmbr0.20']
    dlg.locator('[data-cr-nn-revert-go]').click()
    dlg.wait_for(state='detached', timeout=5000)
    assert app.server.sent == [('DELETE', NET, None)]


def test_runtime_a_refused_apply_keeps_the_dialog_and_says_why(open_app):
    app = open_app(apply=(500, {'error': 'ifreload: vmbr0: bridge port bond9 does not exist'}))
    page = app.page
    _open_network(page)
    _settled_changes(page, 'some')
    page.locator('[data-cr-nn-apply]').click()
    dlg = page.locator('[data-cr-upd-dialog="nn-apply"]')
    _confirm_apply(dlg)
    dlg.locator('[data-cr-nn-apply-go]').click()
    err = dlg.locator('[data-cr-nn-error]')
    err.wait_for(timeout=5000)
    assert 'bridge port bond9 does not exist (HTTP 500)' in err.inner_text()
    assert app.server.sent == [('PUT', NET, None)]


def _classic_requests(browser, label):
    """The request the classic Corporate button sends."""
    app = _GuardApp(browser, _NetServer(layout='corporate'))
    try:
        page = app.page
        _open_network(page, redesigned=False)
        page.get_by_text('vmbr0.20', exact=True).first.wait_for(timeout=8000)
        with page.expect_request(lambda r: r.url.endswith('/nodes/pve1/network') and r.method in ('PUT', 'DELETE')) as req:
            page.locator('button', has_text=re.compile(rf'^\s*{label}\s*$')).first.click()
        r = req.value
        return r.method, re.sub(r'^https?://[^/]+', '', r.url), r.post_data, r.headers.get('content-type')
    finally:
        app.close()


def test_runtime_apply_and_revert_send_what_classic_sends(browser, open_app):
    classic = {'PUT': _classic_requests(browser, 'Apply'), 'DELETE': _classic_requests(browser, 'Revert')}
    app = open_app()
    page = app.page
    _open_network(page)
    _settled_changes(page, 'some')
    got = {}
    for method, opener, go in (('PUT', '[data-cr-nn-apply]', '[data-cr-nn-apply-go]'),
                               ('DELETE', '[data-cr-nn-revert]', '[data-cr-nn-revert-go]')):
        page.locator(opener).click()
        if method == 'PUT':
            _confirm_apply(page.locator('[data-cr-upd-dialog="nn-apply"]'))
        with page.expect_request(lambda r: r.url.endswith('/nodes/pve1/network') and r.method == method) as req:
            page.locator(go).click()
        r = req.value
        got[method] = (r.method, re.sub(r'^https?://[^/]+', '', r.url), r.post_data, r.headers.get('content-type'))
        page.locator('.cr-sb-layer').wait_for(state='detached', timeout=5000)
    assert got == classic, (got, classic)


def test_runtime_the_management_warning_follows_the_address(open_app):
    # only vmbr1 changes, the API host and the node address sit on vmbr0: clear, and said
    app = open_app(changes=(200, {'changes': DIFF_VMBR1}), clusters=[CLUSTER_ON_NODE])
    page = app.page
    _open_network(page)
    _settled_changes(page, 'some')
    line = page.locator('[data-cr-nn-mgmt-line]').inner_text()
    assert 'PegaProx reaches this node and the cluster API at 10.0.0.11, on vmbr0 (bond0, eno1, eno2).' in line
    for n in ('vmbr0', 'bond0', 'eno1', 'eno2'):
        assert page.locator(f'tr[data-cr-nn-row="{n}"] [data-cr-nn-mgmt-tag]').count() == 1, n
    assert page.locator('tr[data-cr-nn-row="vmbr1"] [data-cr-nn-mgmt-tag]').count() == 0
    page.locator('[data-cr-nn-apply]').click()
    dlg = page.locator('[data-cr-upd-dialog="nn-apply"]')
    assert dlg.locator('[data-cr-nn-mgmt="clear"]').count() == 1
    assert 'cr-btn-primary' in dlg.locator('[data-cr-nn-apply-go]').get_attribute('class')
    # still no rollback, still a confirmation
    assert dlg.locator('[data-cr-nn-norollback]').count() == 1 and dlg.locator('[data-cr-nn-apply-go]').is_disabled()


def test_runtime_a_stand_in_address_is_not_taken_for_the_node(open_app):
    app = open_app(changes=(200, {'changes': DIFF_VMBR1}), ip=(200, {'ip': '10.0.0.1', 'node': 'pve1', 'source': 'cluster_host_fallback'}))
    page = app.page
    _open_network(page)
    _settled_changes(page, 'some')
    assert 'The address of this node is not known.' in page.locator('[data-cr-nn-mgmt-line]').inner_text()
    page.locator('[data-cr-nn-apply]').click()
    assert page.locator('[data-cr-upd-dialog="nn-apply"] [data-cr-nn-mgmt="unsure"]').count() == 1


def test_runtime_the_classic_edit_and_create_dialogs_stay(open_app):
    app = open_app()
    page = app.page
    _open_network(page)
    _settled_changes(page, 'some')
    page.locator('[data-cr-nn-edit="vmbr0"]').click()
    page.get_by_text('Edit: vmbr0', exact=True).wait_for(timeout=5000)
    page.locator('button', has_text=re.compile(r'^\s*Cancel\s*$')).last.click()
    page.locator('[data-cr-nn-create]').click()
    page.locator('[data-cr-nn-create-type="bond"]').click()
    page.get_by_text('Create: Linux bond', exact=True).wait_for(timeout=5000)
    assert app.server.sent == []
    _no_errors(app)


def test_runtime_the_list_states(open_app):
    app = open_app(net=(200, []))
    _open_network(app.page)
    app.page.locator('[data-cr-nn-list="empty"]').wait_for(timeout=8000)
    # the route fails a failed read now, so an empty answer carries no doubt
    assert app.page.locator('[data-cr-nn-list="empty"]').inner_text().strip() == 'The answer lists no interfaces.'
    app2 = open_app(net=(500, {'error': 'boom'}))
    page = app2.page
    _open_network(page)
    page.locator('[data-cr-nn-list="error"]').wait_for(timeout=8000)
    assert app2.server.reads(CHANGES) == 0
    app2.server.routes[('GET', NET)] = (200, NODE_NET)
    page.locator('[data-cr-nn-list="error"] button', has_text='Retry').click()
    _settled_changes(page, 'some')


def test_runtime_while_the_changes_are_read(open_app):
    app = open_app(changes='hold')
    page = app.page
    _open_network(page)
    _settled_changes(page, 'loading')
    assert page.locator('[data-cr-nn-pend]').count() == 0
    route = app.server.held.pop()
    route.fulfill(status=200, body=json.dumps({'changes': DIFF}), headers={'Content-Type': 'application/json'})
    _settled_changes(page, 'some')


def test_runtime_a_new_bond_on_the_management_port_is_said_in_the_dialog(open_app):
    app = open_app(net=(200, TAKE_ROWS), changes=(200, {'changes': DIFF_TAKE}),
                   ip=(200, {'ip': '10.0.0.5', 'node': 'pve1', 'source': 'corosync'}))
    page = app.page
    _open_network(page)
    _settled_changes(page, 'some')
    assert page.locator('[data-cr-nn-pending="some"] [data-cr-nn-change="bond0"] [data-cr-nn-mgmt-tag="takes"]').count() == 1
    page.locator('[data-cr-nn-apply]').click()
    dlg = page.locator('[data-cr-upd-dialog="nn-apply"]')
    dlg.wait_for(timeout=5000)
    mg = dlg.locator('[data-cr-nn-mgmt="touch"]')
    assert mg.count() == 1 and mg.get_attribute('role') == 'alert'
    line = mg.locator('[data-cr-nn-taker="bond0"]').inner_text()
    assert 'bond0 waits and is built from eno1' in line and 'vmbr0' in line, line
    assert dlg.locator('[data-cr-nn-change="bond0"] [data-cr-nn-mgmt-tag]').count() == 1
    _confirm_apply(dlg)
    assert 'cr-btn-danger' in dlg.locator('[data-cr-nn-apply-go]').get_attribute('class')
    assert app.server.sent == []
    _no_errors(app)


def _answer_held(app, code, body):
    held, app.server.held[:] = list(app.server.held), []
    for route in held:
        route.fulfill(status=code, body=json.dumps(body), headers={'Content-Type': 'application/json'})


def test_runtime_the_confirmation_waits_for_the_summary_and_follows_it(open_app):
    app = open_app(changes='hold', clusters=[CLUSTER_ON_NODE])
    page = app.page
    _open_network(page)
    _settled_changes(page, 'loading')
    page.locator('[data-cr-nn-apply]').click()
    dlg = page.locator('[data-cr-upd-dialog="nn-apply"]')
    dlg.wait_for(timeout=5000)
    ack, go = dlg.locator('[data-cr-nn-ack]'), dlg.locator('[data-cr-nn-apply-go]')
    # while what waits is read, nothing can be confirmed
    assert ack.is_disabled() and go.is_disabled()
    _answer_held(app, 502, {'error': 'Could not read the network configuration'})
    dlg.locator('[data-cr-nn-summary-state="unknown"]').wait_for(timeout=5000)
    ack.check()
    assert go.is_enabled()
    # what waits is read again while the box is ticked: the tick does not carry over to the new summary
    app.server.routes[('GET', CHANGES)] = 'hold'
    page.locator('[data-cr-nn-pending="error"] button', has_text='Retry').dispatch_event('click')
    page.wait_for_function('() => document.querySelector("[data-cr-nn-ack]").disabled')
    assert not ack.is_checked() and go.is_disabled()
    _answer_held(app, 200, {'changes': DIFF})
    dlg.locator('[data-cr-nn-mgmt="touch"]').wait_for(timeout=5000)
    # the new summary touches the management path: the name is typed now, starting empty (round 8)
    name = dlg.locator('[data-cr-nn-typename-input]')
    assert name.is_enabled() and name.input_value() == '' and go.is_disabled() and ack.count() == 0
    name.fill('pve1')
    assert go.is_enabled() and 'cr-btn-danger' in go.get_attribute('class')
    assert app.server.sent == []
    _no_errors(app)


def test_runtime_a_failed_list_read_is_not_taken_for_reading(open_app):
    app = open_app(net=(500, {'error': 'boom'}))
    page = app.page
    _open_network(page)
    page.locator('[data-cr-nn-list="error"]').wait_for(timeout=8000)
    page.locator('[data-cr-nn-apply]').click()
    dlg = page.locator('[data-cr-upd-dialog="nn-apply"]')
    dlg.wait_for(timeout=5000)
    text = dlg.locator('[data-cr-nn-summary-state="unknown"]').inner_text()
    assert 'the interface list could not be read' in text and 'Reading' not in text, text
    # round 8 (R6-5): not reading, but locked until the list is read, with the reason and a Retry
    assert dlg.locator('[data-cr-nn-ack]').is_disabled() and dlg.locator('[data-cr-nn-apply-go]').is_disabled()
    assert dlg.locator('[data-cr-nn-apply-list="error"] [data-cr-nn-apply-retry]').count() == 1
    _no_errors(app)


def test_runtime_classic_corporate_is_unchanged(open_app):
    app = open_app(layout='corporate')
    page = app.page
    _open_network(page, redesigned=False)
    page.get_by_text('vmbr0.20', exact=True).first.wait_for(timeout=8000)
    page.wait_for_timeout(300)
    assert page.locator('[data-cr-nn]').count() == 0
    table = page.locator('.corp-datagrid').filter(has=page.get_by_text('vmbr0', exact=True))
    assert table.locator('thead th').count() == 7
    assert app.server.reads(CHANGES) == 0


def test_runtime_a_standby_cannot_apply_or_revert(open_app):
    app = open_app(role='standby')
    page = app.page
    _open_network(page)
    _settled_changes(page, 'some')
    assert page.locator('[data-cr-nn-apply]').is_disabled() and page.locator('[data-cr-nn-revert]').is_disabled()
    assert page.locator('[data-cr-nn-edit="vmbr0"]').is_disabled()


_NO_SIDEWAYS = '() => document.scrollingElement.scrollWidth <= window.innerWidth'


@pytest.mark.parametrize('engine,width', [('chromium', 1600), ('chromium', 1280), ('firefox', 1600), ('firefox', 1280)])
def test_runtime_layout_without_sideways_scroll(open_app, firefox, browser, engine, width):
    app = open_app(viewport=(width, 900), br=firefox if engine == 'firefox' else browser)
    page = app.page
    _open_network(page)
    _settled_changes(page, 'some')
    assert page.evaluate(_NO_SIDEWAYS)
    page.locator('[data-cr-nn-pending="some"] [data-cr-nn-diff-toggle]').click()
    assert page.evaluate(_NO_SIDEWAYS)
    page.locator('[data-cr-nn-apply]').click()
    dlg = page.locator('[data-cr-upd-dialog="nn-apply"]')
    dlg.locator('[data-cr-nn-diff-toggle]').click()
    box = dlg.bounding_box()
    assert box['x'] >= 0 and box['x'] + box['width'] <= width
    assert page.evaluate(_NO_SIDEWAYS)
    _no_errors(app)
