"""The topology of Corporate Redesigned (Preview) in the browser.

The preview draws TopologyView's own snapshot: a box per cluster, the node cards inside it, the
guests inside their node, linked backup servers in the box. Lines for storage, bridges and
affinity rules come only from the answers that name them. It opens fitted to the canvas, pans,
zooms, goes full screen, finds, filters by type, folds clusters, folds the guests of a busy
node, opens what is clicked and shows details on hover and focus. A node the global view only
invents while nothing is cached is never drawn, and 200 nodes with 10k guests stay small.
Classic Corporate and Modern draw the classic topology (the pixel guard pins them). Runs
against the fake server of tests/test_ha_ui.py and skips without Playwright. LW Oct 2026
"""
import re
import time

import pytest

from test_corp_redesigned_dashboard_ui import CLUSTERS, PROD, PROD_GUESTS, STATUS, _DashServer
from test_corp_redesigned_guard_ui import DETERMINISTIC, RESOURCES, VM, _GuardApp
from test_ha_ui import CLUSTER, NODE_METRICS, PBS

LAYOUT = 'corporate-redesigned'
GIB = 1024 ** 3
TIB = 1024 ** 4


def _node(cpu, mem, **kw):
    return dict(NODE_METRICS['pve1'], cpu_percent=float(cpu), mem_percent=float(mem), **kw)


LAB = {'id': 'c4', 'name': 'Lab', 'display_name': 'Lab', 'host': '10.0.4.1', 'connected': True,
       'status': 'running', 'cluster_type': 'proxmox', 'enabled': True}
DEV = {'id': 'c5', 'name': 'Dev', 'display_name': 'Dev', 'host': '10.0.5.1', 'connected': True,
       'status': 'running', 'cluster_type': 'proxmox', 'enabled': True}
# pve2 carries 21 guests, more than a node shows before it folds them (16)
BULK = [dict(VM, vmid=300 + i, name=f'bulk{i:02d}', node='pve2', status='running' if i % 2 else 'stopped')
        for i in range(20)]
TESTI_GUESTS = RESOURCES + BULK
TESTI_METRICS = {'pve1': _node(5, 20), 'pve2': _node(12, 35)}
PROD_METRICS = {'prod1': _node(40, 50), 'prod2': _node(91, 85), 'prod3': {'status': 'offline'}}
DEV_GUESTS = [dict(VM, vmid=500, name='dev01', node='devnode1'), dict(VM, vmid=501, name='dev02', node='devnode2', type='lxc')]
LAB_STATUS = dict(STATUS['c1'], nodes={'online': 2, 'offline': 1, 'total': 3})
NETWORKS = {'networks': [{'name': 'vmbr0', 'type': 'bridge', 'cidr': '10.0.0.0/24', 'gateway': '10.0.0.1',
                          'nodes': ['pve1', 'pve2'], 'vms': [{'vmid': 100}, {'vmid': 102}]},
                         {'name': 'vmbr9', 'type': 'bridge', 'nodes': ['pve2'], 'vms': []}],
            'storage_assignments': [{'storage': 'ceph-rbd', 'vms': [{'vmid': 100}, {'vmid': 102}]},
                                    {'storage': 'local-lvm', 'vms': [{'vmid': 100}]}]}
DATASTORES = {'shared': [{'storage': 'ceph-rbd', 'type': 'rbd', 'used_fraction': 0.42, 'total': 4 * TIB,
                          'used': int(1.68 * TIB), 'active_on': ['pve1', 'pve2']}],
              'local': {'pve1': [{'storage': 'local-lvm', 'type': 'lvmthin', 'used_fraction': 0.2,
                                  'total': 500 * GIB, 'used': 100 * GIB}]}}
AFFINITY = [{'id': 'r1', 'type': 'separate', 'vms': [100, 102]}]


class _TopoServer(_DashServer):
    """Testi with storage, networks and affinity rules, Prod with an offline node, Lab that
    only the datacenter status knows (the global view invents its nodes), Dev that only the
    guest list knows, Edge offline. A backup server linked to Testi."""

    def __init__(self, clusters=None, extra=None, **kw):
        reads = {
            ('GET', '/api/clusters/c1/metrics'): (200, TESTI_METRICS),
            ('GET', '/api/clusters/c2/metrics'): (200, PROD_METRICS),
            ('GET', '/api/clusters/c4/metrics'): (200, {}),
            ('GET', '/api/clusters/c4/resources'): (200, []),
            ('GET', '/api/clusters/c4/datacenter/status'): (200, LAB_STATUS),
            ('GET', '/api/clusters/c5/metrics'): (200, {}),
            ('GET', '/api/clusters/c5/resources'): (200, DEV_GUESTS),
            ('GET', '/api/clusters/c1/networks'): (200, NETWORKS),
            ('GET', '/api/clusters/c1/datastores'): (200, DATASTORES),
            ('GET', '/api/clusters/c1/affinity-rules'): (200, AFFINITY),
            ('GET', '/api/pbs'): (200, [dict(PBS, linked_clusters=['c1'])]),
        }
        reads.update(extra or {})
        super().__init__(extra=reads, resources=kw.pop('resources', TESTI_GUESTS),
                         clusters=CLUSTERS + [LAB, DEV] if clusters is None else clusters, **kw)


@pytest.fixture(scope='module')
def browser():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        pytest.skip('Playwright is not installed')
    try:
        pw = sync_playwright().start()
    except Exception as e:
        pytest.skip(f'Playwright does not start here: {e}')
    try:
        br = pw.chromium.launch(headless=True, args=DETERMINISTIC)
    except Exception as e:
        pw.stop()
        pytest.skip(f'no Chromium for Playwright: {e}')
    yield br
    br.close()
    pw.stop()


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(layout=LAYOUT, storage=None, viewport=(1600, 1000), server=None, **kw):
        app = _GuardApp(browser, server or _TopoServer(layout=layout, **kw), storage=storage, viewport=viewport)
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.close()


def _settle(page):
    page.wait_for_function('''() => {
        const g = document.querySelector('[data-cr-camera]');
        return g && /scale/.test(g.getAttribute('transform') || '');
    }''', timeout=15000)
    page.wait_for_timeout(500)


def _global(page):
    page.locator('[data-corp-tool="topology"]').first.click()
    page.locator('[data-cr-topo-root="multi"]').wait_for(timeout=15000)
    page.locator('[data-cr-topo="node"][data-k="n:c2:prod2"]').wait_for(timeout=15000)
    _settle(page)


def _cluster_topo(page):
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.locator('[data-cr-tab="resources"]').click()
    page.locator('.corp-tab-strip button', has_text='Topology').first.click()
    page.locator('[data-cr-topo-root="single"]').wait_for(timeout=15000)
    _settle(page)


def _cam(page):
    tr = page.locator('[data-cr-camera]').get_attribute('transform')
    x, y, k = map(float, re.match(r'translate\(([-\d.]+),([-\d.]+)\) scale\(([-\d.]+)\)', tr).groups())
    return x, y, k


def _keys(page, kind):
    return page.evaluate('(k) => Array.from(document.querySelectorAll(`[data-cr-topo="${k}"]`)).map(e => e.dataset.k)', kind)


def _box(page, sel):
    return page.locator(sel).first.bounding_box()


def _inside(inner, outer, slack=1):
    return (inner['x'] >= outer['x'] - slack and inner['y'] >= outer['y'] - slack
            and inner['x'] + inner['width'] <= outer['x'] + outer['width'] + slack
            and inner['y'] + inner['height'] <= outer['y'] + outer['height'] + slack)


def _canvas(page):
    return _box(page, '.cr-topo-canvas')


# a node card is covered by its fold row and guest rows below the head: point at the head
HEAD = {'x': 60, 'y': 14}


def _head(page, key):
    return page.locator(f'[data-k="{key}"]')


def _text(page, sel):
    # SVG text: the small details are display:none while zoomed out, textContent still has them
    return page.locator(sel).first.evaluate('e => e.textContent')


# --- what is drawn --------------------------------------------------------------------------

def test_runtime_the_global_view_opens_fitted_and_draws_only_what_the_data_has(open_app):
    app = open_app()
    page = app.page
    _global(page)
    # a box per connected cluster, none for the offline one
    boxes = page.evaluate('() => Array.from(document.querySelectorAll("[data-cr-topo-box]")).map(b => b.dataset.crTopoBox)')
    assert sorted(boxes) == ['c1', 'c2', 'c4', 'c5'], boxes
    nodes = _keys(page, 'node')
    assert {'n:c1:pve1', 'n:c1:pve2', 'n:c2:prod1', 'n:c2:prod2', 'n:c2:prod3'} <= set(nodes)
    # Lab: only the datacenter status knows it. The global view invents node-1..3 for it;
    # none of them is drawn, the box says how many there are
    assert not [k for k in nodes if k.startswith('n:c4:')]
    note = _text(page, '[data-cr-topo-box="c4"] [data-cr-topo-note="unknown"]')
    assert '3' in note and '2 online' in note, note
    # Dev: its node names come from the guest list, their state was never reported
    assert page.locator('[data-k="n:c5:devnode1"]').get_attribute('data-state') == 'unknown'
    assert page.locator('[data-k="n:c5:devnode1"] text', has_text='CPU').count() == 0
    assert page.locator('[data-k="n:c2:prod3"]').get_attribute('data-state') == 'offline'
    # every guest sits inside the card of its own node
    card = _box(page, '[data-k="n:c1:pve1"] .cr-topo-frame')
    for vmid in (100, 101):
        assert _inside(_box(page, f'[data-k="g:c1:{vmid}"]'), card), vmid
    # Prod's guests sit on prod1/prod2: placed, nothing left over
    assert page.locator('[data-cr-topo-box="c2"] [data-cr-topo-note="unplaced"]').count() == 0
    # the linked backup server sits in Testi's box, in no other
    assert _keys(page, 'pbs') == ['p:c1:p1']
    # zoom to fit: everything in view, not blown up past 125 %
    canvas = _canvas(page)
    for sel in ('[data-cr-topo-box="c1"] > rect', '[data-cr-topo-box="c2"] > rect', '[data-cr-topo-box="c4"] > rect', '[data-cr-topo-box="c5"] > rect'):
        assert _inside(_box(page, sel), canvas), sel
    assert _cam(page)[2] <= 1.25
    # no line is drawn until something is pointed at
    assert page.locator('[data-cr-topo-links]').count() == 0
    assert app.errors == []


def test_runtime_pan_zoom_fit_and_full_screen(open_app):
    app = open_app()
    page = app.page
    _global(page)
    x0, y0, k0 = _cam(page)
    canvas = _canvas(page)
    # the wheel zooms at the pointer: the point under it stays put
    px, py = canvas['x'] + 300, canvas['y'] + 200
    page.mouse.move(px, py)
    page.mouse.wheel(0, -240)
    page.wait_for_timeout(250)
    x1, y1, k1 = _cam(page)
    assert k1 > k0
    lx, ly = (px - canvas['x'] - x0) / k0, (py - canvas['y'] - y0) / k0
    assert abs((lx * k1 + x1) - (px - canvas['x'])) < 2 and abs((ly * k1 + y1) - (py - canvas['y'])) < 2
    assert page.locator('[data-cr-topo-pct]').get_attribute('data-cr-topo-pct') == str(round(k1 * 100))
    # dragging pans
    page.mouse.move(px, py)
    page.mouse.down()
    page.mouse.move(px + 120, py + 60, steps=6)
    page.mouse.up()
    page.wait_for_timeout(200)
    x2, y2, k2 = _cam(page)
    assert (round(x2 - x1), round(y2 - y1), k2) == (120, 60, k1)
    # the buttons and the keys
    page.locator('[data-cr-topo-zoom="in"]').click()
    page.wait_for_timeout(150)
    assert _cam(page)[2] > k2
    page.locator('[data-cr-topo-fit]').click()
    page.wait_for_timeout(150)
    assert _cam(page) == (x0, y0, k0)
    page.locator('.cr-topo-canvas').focus()
    page.keyboard.press('-')
    page.wait_for_timeout(150)
    assert _cam(page)[2] < k0
    page.keyboard.press('ArrowLeft')
    page.wait_for_timeout(150)
    page.keyboard.press('0')
    page.wait_for_timeout(150)
    assert _cam(page) == (x0, y0, k0)
    page.locator('[data-cr-topo-zoom="pct"]').click()
    page.wait_for_timeout(150)
    assert _cam(page)[2] == 1.0
    # full screen: the diagram takes the window and fits it again, the same button goes back
    page.locator('[data-cr-topo-full]').click()
    page.wait_for_function('() => document.querySelector(".cr-topo-full")', timeout=5000)
    page.wait_for_timeout(500)
    big = _canvas(page)
    assert big['width'] >= 1590 and big['height'] > canvas['height'] + 100, big
    assert page.locator('[data-cr-topo-full]').get_attribute('aria-pressed') == 'true'
    assert _inside(_box(page, '[data-cr-topo-box="c1"] > rect'), big)
    page.locator('[data-cr-topo-full]').click()
    # the class goes at once, the browser leaves real full screen a moment later
    page.wait_for_function('''(w) => !document.querySelector(".cr-topo-full") && !document.fullscreenElement
        && Math.abs(document.querySelector(".cr-topo-canvas").getBoundingClientRect().width - w) < 2''', arg=canvas['width'], timeout=8000)
    assert app.errors == []


def test_runtime_find_filter_and_fold(open_app):
    app = open_app()
    page = app.page
    _global(page)
    search = page.locator('[data-cr-topo-search]')
    search.fill('db01')
    page.wait_for_function('() => document.querySelector("[data-cr-topo-hits]")', timeout=5000)
    assert page.locator('[data-cr-topo-hits]').get_attribute('data-cr-topo-hits') == '1'
    # the node that holds it stays lit, the rest is dimmed
    assert page.locator('[data-k="n:c1:pve2"]').evaluate('e => e.parentElement.getAttribute("opacity")') == '1'
    assert page.locator('[data-k="n:c2:prod1"]').evaluate('e => e.parentElement.getAttribute("opacity")') == '0.28'
    # db01 sits in a node that folds its 21 guests: the fold row counts the find
    assert '1 found' in _text(page, '[data-k="f:c1:pve2"]')
    cam = _cam(page)
    search.press('Enter')
    page.wait_for_timeout(300)
    assert _cam(page) != cam
    assert _inside(_box(page, '[data-k="n:c1:pve2"] .cr-topo-frame'), _canvas(page))
    search.fill('')
    page.locator('[data-cr-topo-fit]').click()
    # by type: the containers go, the VMs stay, and the choice survives a reload
    assert 'g:c1:101' in _keys(page, 'guest')
    page.locator('[data-cr-topo-show="lxc"]').click()
    assert 'g:c1:101' not in _keys(page, 'guest') and 'g:c1:100' in _keys(page, 'guest')
    page.reload()
    _global(page)
    assert page.locator('[data-cr-topo-show="lxc"]').get_attribute('aria-pressed') == 'false'
    assert 'g:c1:101' not in _keys(page, 'guest')
    page.locator('[data-cr-topo-show="lxc"]').click()
    # one cluster folds by its own button, all of them by the toolbar
    fold = page.locator('[data-k="cf:c2"]')
    assert fold.get_attribute('aria-expanded') == 'true'
    fold.click()
    assert page.locator('[data-cr-topo-box="c2"]').get_attribute('data-folded') == '1'
    assert not [k for k in _keys(page, 'node') if k.startswith('n:c2:')]
    assert page.locator('[data-k="cf:c2"]').get_attribute('aria-expanded') == 'false'
    page.locator('[data-cr-topo-foldall]').click()
    assert page.evaluate('() => Array.from(document.querySelectorAll("[data-cr-topo-box]")).every(b => b.dataset.folded === "1")')
    assert page.locator('[data-cr-topo-foldall]').get_attribute('data-cr-topo-foldall') == 'open'
    page.locator('[data-cr-topo-foldall]').click()
    assert page.locator('[data-cr-topo-box="c2"]').get_attribute('data-folded') == '0'
    assert app.errors == []


def test_runtime_a_busy_node_folds_its_guests_and_opening_it_moves_no_other_card(open_app):
    app = open_app()
    page = app.page
    _global(page)
    guests = _keys(page, 'guest')
    # pve1 (2 guests) shows them, pve2 (21) folds them into one row
    assert {'g:c1:100', 'g:c1:101'} <= set(guests)
    assert not [k for k in guests if k.startswith('g:c1:3') or k == 'g:c1:102']
    row = page.locator('[data-k="f:c1:pve2"]')
    assert row.get_attribute('aria-expanded') == 'false'
    assert '21 guests, 10 running' in _text(page, '[data-k="f:c1:pve2"]')
    cards = '''() => Object.fromEntries(Array.from(document.querySelectorAll('[data-cr-topo-box="c1"] [data-cr-topo="node"]'))
        .map(e => [e.dataset.k, e.parentElement.getAttribute('transform')]))'''
    boxes = '() => Array.from(document.querySelectorAll("[data-cr-topo-box] > rect")).map(r => r.getAttribute("x"))'
    before, xs = page.evaluate(cards), page.evaluate(boxes)
    row.focus()
    page.keyboard.press('Enter')
    page.wait_for_timeout(200)
    assert page.locator('[data-k="f:c1:pve2"]').get_attribute('aria-expanded') == 'true'
    assert len([k for k in _keys(page, 'guest') if k.startswith('g:c1:3')]) == 20
    # the other cards of the cluster stay where they are, no box changes its column
    assert page.evaluate(cards) == before
    assert page.evaluate(boxes) == xs
    assert app.errors == []


def test_runtime_hover_and_focus_tell_the_details(open_app):
    app = open_app()
    page = app.page
    _global(page)
    _head(page, 'n:c2:prod2').hover(position=HEAD)
    tip = page.locator('[data-cr-topo-tip="n:c2:prod2"]')
    tip.wait_for(timeout=3000)
    text = tip.inner_text()
    assert 'prod2' in text and 'Prod' in text and '91%' in text and '85%' in text and 'Online' in text, text
    page.locator('[data-k="g:c1:100"]').hover()
    text = page.locator('[data-cr-topo-tip="g:c1:100"]').inner_text()
    assert 'web01' in text and '100' in text and 'pve1' in text and 'running' in text, text
    _head(page, 'n:c5:devnode1').hover(position=HEAD)
    text = page.locator('[data-cr-topo-tip="n:c5:devnode1"]').inner_text()
    assert 'State not reported' in text and 'CPU' not in text, text
    # the keyboard gets the same card
    page.mouse.move(2, 2)
    page.locator('[data-k="n:c1:pve1"]').focus()
    assert 'pve1' in page.locator('[data-cr-topo-tip="n:c1:pve1"]').inner_text()
    assert app.errors == []


@pytest.mark.parametrize('how', ['mouse', 'keyboard'])
def test_runtime_a_click_opens_what_it_points_at(open_app, how):
    app = open_app()
    page = app.page

    def act(sel):
        if how == 'mouse':
            page.locator(sel).first.click(position=HEAD if '"n:' in sel else None)
        else:
            page.locator(sel).first.focus()
            page.keyboard.press('Enter')

    _global(page)
    act('[data-k="g:c1:100"]')
    page.locator('[data-cr-objhead="vm"]').wait_for(timeout=8000)
    assert 'web01' in page.locator('[data-cr-objhead="vm"] .cr-objhead-name').inner_text()
    page.locator('[data-corp-tool="topology"]').first.click()
    page.locator('[data-k="n:c2:prod1"]').wait_for(timeout=8000)
    _settle(page)
    act('[data-k="n:c2:prod1"]')
    page.locator('[data-cr-objhead="node"]').wait_for(timeout=8000)
    assert 'prod1' in page.locator('[data-cr-objhead="node"] .cr-objhead-name').inner_text()
    page.locator('[data-corp-tool="topology"]').first.click()
    page.locator('[data-k="c:c2"]').wait_for(timeout=8000)
    _settle(page)
    act('[data-k="c:c2"]')
    page.locator('[data-cr-objhead="cluster"]').wait_for(timeout=8000)
    assert 'Prod' in page.locator('[data-cr-objhead="cluster"] .cr-objhead-name').inner_text()
    assert app.errors == []


def test_runtime_lines_come_only_from_the_answers(open_app):
    app = open_app()
    page = app.page
    _cluster_topo(page)
    assert page.locator('[data-cr-topo-root]').get_attribute('data-cr-topo-root') == 'single'
    page.locator('[data-cr-topo-show="storage"]').click()
    page.locator('[data-cr-topo-show="network"]').click()
    page.locator('[data-k="s:ceph-rbd"]').wait_for(timeout=8000)
    page.locator('[data-k="b:vmbr0"]').wait_for(timeout=8000)
    assert sorted(_keys(page, 'storage')) == ['s:ceph-rbd', 's:local-lvm@pve1']
    assert sorted(_keys(page, 'bridge')) == ['b:vmbr0', 'b:vmbr9']

    def links(sel):
        page.mouse.move(2, 2)
        page.wait_for_timeout(100)
        page.locator(sel).hover(position=HEAD if '"n:' in sel else None)
        page.wait_for_timeout(150)
        el = page.locator('[data-cr-topo-links]')
        return int(el.get_attribute('data-cr-topo-links')) if el.count() else 0

    # pve1 reaches ceph (active_on), its own local-lvm and vmbr0; pve2 reaches ceph, vmbr0 and vmbr9
    assert links('[data-k="n:c1:pve1"]') == 3
    assert links('[data-k="n:c1:pve2"]') == 3
    # web01 (100) uses ceph and local-lvm and sits on vmbr0; ct01 (101) is named by no answer
    assert links('[data-k="g:c1:100"]') == 3
    assert links('[data-k="g:c1:101"]') == 0
    # local-lvm of pve1: pve1 and web01, nothing on pve2
    assert links('[data-k="s:local-lvm@pve1"]') == 2
    # affinity: one rule keeps 100 and 102 apart, 102 is folded away until its node opens
    page.locator('[data-cr-topo-show="affinity"]').click()
    page.wait_for_timeout(500)
    assert page.locator('[data-cr-topo-affinity]').count() == 0
    page.locator('[data-k="f:c1:pve2"]').click()
    page.locator('[data-cr-topo-affinity="separate"]').wait_for(timeout=5000)
    assert page.locator('[data-cr-topo-affinity]').count() == 1
    assert ('GET', '/api/clusters/c1/affinity-rules') in app.server.calls
    assert app.errors == []


def test_runtime_light_theme_draws_with_the_light_tokens(open_app):
    app = open_app(storage={'corp-theme': 'light'})
    page = app.page
    _global(page)
    assert page.locator('.cr-topo-canvas').evaluate('e => getComputedStyle(e).backgroundColor') == 'rgb(238, 242, 245)'
    assert page.locator('[data-k="n:c1:pve1"] .cr-topo-frame').get_attribute('fill') == '#ffffff'
    assert app.errors == []


def test_runtime_classic_corporate_keeps_the_classic_topology(open_app):
    app = open_app(layout='corporate')
    page = app.page
    page.locator('[data-corp-tool="topology"]').first.click()
    page.locator('.corp-topo-frame svg').first.wait_for(timeout=15000)
    assert page.locator('[data-cr-topo-root]').count() == 0
    assert app.errors == []


def test_runtime_the_export_menu_saves_a_picture(open_app):
    app = open_app()
    page = app.page
    _global(page)
    page.locator('[data-cr-topo-export]').click()
    with page.expect_download(timeout=15000) as dl:
        page.locator('[data-cr-topo-format="png"]').click()
    assert dl.value.suggested_filename == 'topology-PegaProx.png'
    assert app.errors == []


# the SVG text the export draws its picture from
CATCH_EXPORT = '''() => {
    const own = XMLSerializer.prototype.serializeToString;
    XMLSerializer.prototype.serializeToString = function (n) {
        const s = own.call(this, n);
        if (n && n.nodeName === 'svg') window.__crExported = s;
        return s;
    };
}'''

# what that SVG shows on its own, the way the picture gets it: no stylesheet of the page
SHOWN_TEXT = '''(src) => {
    const doc = new DOMParser().parseFromString(src, 'image/svg+xml');
    const svg = document.body.appendChild(document.importNode(doc.documentElement, true));
    return Array.from(svg.querySelectorAll('text'))
        .filter(e => getComputedStyle(e).display !== 'none' && e.getBBox().width > 0)
        .map(e => [e.textContent.trim(), parseFloat(e.getAttribute('font-size'))]);
}'''


@pytest.mark.parametrize('zoom', ['fit', 'far'])
def test_runtime_the_exported_picture_has_no_big_names_over_the_cards(open_app, browser, zoom):
    """The big names of the zoomed-out view hide by the stylesheet. The export has none of it,
    so they must not be in the picture at all: drawn over the card text they covered the CPU
    and RAM rows."""
    app = open_app()
    page = app.page
    _cluster_topo(page)
    if zoom == 'far':
        page.locator('.cr-topo-canvas').focus()
        for _ in range(12):
            if _cam(page)[2] < 0.5:
                break
            page.keyboard.press('-')
            page.wait_for_timeout(60)
        page.wait_for_function('() => document.querySelector(".cr-topo-svg").classList.contains("cr-topo-far")', timeout=5000)
    page.evaluate(CATCH_EXPORT)
    page.locator('[data-cr-topo-export]').click()
    with page.expect_download(timeout=15000):
        page.locator('[data-cr-topo-format="png"]').click()
    exported = page.evaluate('() => window.__crExported')
    blank = browser.new_page()
    try:
        shown = blank.evaluate(SHOWN_TEXT, exported)
    finally:
        blank.close()
    names = [s for s, _ in shown]
    # the card text is all there, at its own size
    assert ['pve1', 12] in shown and ['pve2', 12] in shown and 'CPU' in names and 'RAM' in names, shown
    assert ['Testi', 13] in shown, shown
    # and nothing at the size of the zoomed-out names (24 and 28 px) sits over it
    assert [x for x in shown if x[1] >= 20] == []
    assert app.errors == []


# --- scale -------------------------------------------------------------------------------------

def _big(nodes=200, guests=10000):
    metrics = {f'pve{i + 1:03d}': _node((i * 7) % 95, (i * 11) % 95) for i in range(nodes)}
    res = [dict(VM, vmid=1000 + i, name=f'g{i:05d}', type='lxc' if i % 5 == 0 else 'qemu',
                node=f'pve{(i % nodes) + 1:03d}', status='running' if i % 3 else 'stopped') for i in range(guests)]
    return metrics, res


def test_runtime_200_nodes_and_10k_guests_stay_small_and_readable(open_app):
    metrics, res = _big()
    server = _DashServer(layout=LAYOUT, clusters=[CLUSTER], status={'c1': STATUS['c1']}, resources=res,
                         extra={('GET', '/api/clusters/c1/metrics'): (200, metrics)})
    app = open_app(server=server)
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.wait_for_timeout(2000)
    t0 = time.time()
    page.locator('[data-corp-tool="topology"]').first.click()
    page.wait_for_function('() => document.querySelectorAll("[data-cr-topo=node]").length === 200', timeout=60000)
    ready = time.time() - t0
    _settle(page)
    inside = page.evaluate('() => document.querySelector(".cr-topo").getElementsByTagName("*").length')
    # 50 guests a node: every node folds them, nothing per guest is in the page
    assert _keys(page, 'guest') == []
    assert inside < 6000, inside
    assert ready < 15, ready
    # fitted: all 200 cards in view, zoomed out far enough that the big names show
    canvas = _canvas(page)
    assert _inside(_box(page, '[data-cr-topo-box="c1"] > rect'), canvas)
    assert page.locator('svg.cr-topo-far').count() == 1
    assert page.locator('[data-k="n:c1:pve200"] .cr-topo-farname').is_visible()
    # finding one guest among 10k and zooming to it
    t0 = time.time()
    page.locator('[data-cr-topo-search]').fill('g04242')
    page.locator('[data-cr-topo-search]').press('Enter')
    page.wait_for_function('() => document.querySelector("[data-cr-topo-hits]")', timeout=10000)
    assert time.time() - t0 < 3
    node = f'n:c1:pve{(4242 % 200) + 1:03d}'
    assert _inside(_box(page, f'[data-k="{node}"] .cr-topo-frame'), _canvas(page))
    assert app.errors == []
