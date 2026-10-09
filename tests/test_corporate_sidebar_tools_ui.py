"""The Tools section of the corporate sidebar.

Topology, World Map, Automated Installations, Hypervisor Migration and Multi-Cluster
EVPN used to hang off All Clusters in corporate, indented as if they were its children
and 12px apart while the tree below them is compact. They now have a section of their
own under the clusters and above Backup Servers, like the other sections. The header looks like Backup Servers and ESXi
and folds the section away, remembered per browser. Modern keeps them where they were.

The runtime tests drive the built bundle in headless Chromium against the fake server
of tests/test_ha_ui.py; they skip where Playwright is not installed.
LW
"""
import re

import pytest

from test_ha_ui import (CLUSTER, LANGS, NODE_METRICS, VM, _App, _blocks, _classes,  # noqa: F401 (browser is a fixture)
                        _FakeServer, _read, browser)

XCP = {'id': 'x1', 'name': 'Pool1', 'display_name': 'Pool1', 'host': '10.0.0.5', 'connected': True,
       'status': 'running', 'cluster_type': 'xcpng', 'type': 'xcpng', 'enabled': True}
PVE2 = dict(CLUSTER, id='c2', name='Lab', display_name='Lab')
EDGE = dict(CLUSTER, id='c9', name='Edge', display_name='Edge')
# two of them, so a test can read the row pitch of the section below
PBS = [{'id': 'p1', 'name': 'pbs01', 'host': '10.0.0.9', 'port': 8007, 'connected': True},
       {'id': 'p2', 'name': 'pbs02', 'host': '10.0.0.10', 'port': 8007, 'connected': True}]
WITH_PBS = {('GET', '/api/pbs'): (200, PBS)}
GROUPS = [{'id': 'g1', 'name': 'Production', 'color': '#E86F2D', 'sort_order': 0, 'collapsed': 0},
          {'id': 'g2', 'name': 'Staging', 'color': '#49AFD9', 'sort_order': 1, 'collapsed': 0}]
# All Guests first: the table of every guest, a read on a standby as well
ORDER = ['guests', 'topology', 'worldmap', 'autoinstall', 'xhm', 'mcevpn']
# what each entry opens: the corporate header of its view
TITLES = {'guests': 'All Guests', 'topology': 'Topology', 'worldmap': 'World Map', 'autoinstall': 'Automated Installations',
          'xhm': 'Hypervisor Migration', 'mcevpn': 'Multi-Cluster EVPN'}
KEY = 'pegaprox_corp_tools_collapsed'


@pytest.fixture(scope='module')
def dash():
    return _read('web', 'src', 'dashboard.js')


@pytest.fixture(scope='module')
def section(dash):
    start = dash.index('{/* LW Oct 2026 - corporate: the global views get a section of their own')
    return dash[start:dash.index('{/* LW: Feb 2026 - Proxmox Backup Servers */}', start)]


@pytest.fixture(scope='module')
def row(dash):
    start = dash.index('function CorpSidebarToolRow(')
    return dash[start:dash.index('\n        }\n', start)]


# -- source ----------------------------------------------------------------------------------

@pytest.mark.parametrize('lang', LANGS)
def test_the_header_is_translated_once_per_language(lang):
    block = _blocks()[lang]
    assert len(re.findall(r"^ +sidebarToolsSection: '[^']+',$", block, re.M)) == 1
    if lang == 'de':
        assert "sidebarToolsSection: 'Werkzeuge'," in block


def test_the_collapsed_state_never_throws(dash):
    """Private windows and blocked site data throw on the accessor itself."""
    reads = [m.start() for m in re.finditer(re.escape(f"localStorage.getItem('{KEY}')"), dash)]
    writes = [m.start() for m in re.finditer(re.escape(f"localStorage.setItem('{KEY}'"), dash)]
    assert len(reads) == 1 and len(writes) == 1
    for at in reads + writes:
        line = dash[dash.rindex('\n', 0, at):dash.index('\n', at)]
        assert 'try {' in line and 'catch (_)' in line, line


def test_no_em_dash_and_every_class_ships(dash, section, row):
    assert '\u2014' not in section + row
    css = _read('static', 'css', 'tailwind.min.css') + _read('web', 'index.html.original')
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    names = _classes(section) | _classes(row)
    assert {'pl-3', 'mr-2', 'py-1', 'leading-5', 'mt-4', 'pt-4', 'border-t', 'gap-2', 'min-w-0', 'truncate',
            'flex-shrink-0', 'space-y-1.5'} <= names, sorted(names)
    # the padding that keeps 12px between cluster groups now that the corporate list has no gap
    assert "className={isCorporate ? 'space-y-2 pt-3' : 'space-y-2'}" in dash
    assert "'space-y-0 pt-3'" in dash
    names |= {'space-y-0', 'space-y-2', 'pt-3'}
    missing = sorted(n for n in names if n not in have)
    assert not missing, f'not in static/css/tailwind.min.css: {missing}'


def test_the_bundle_was_rebuilt():
    bundle = _read('web', 'index.html')
    for needle in ('function CorpSidebarToolRow(', 'sidebarToolsSection', KEY, 'data-corp-tools',
                   "'space-y-2 pt-3'", "'space-y-0 pt-3'"):
        assert needle in bundle, needle


# -- runtime ---------------------------------------------------------------------------------

@pytest.fixture
def open_app(browser):
    apps = []

    def _open(**kw):
        kw.setdefault('role', 'standalone')
        app = _App(browser, _FakeServer(**kw))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _corporate(open_app, clusters=(CLUSTER, XCP), **kw):
    kw.setdefault('autoinstall', 'manage')
    kw.setdefault('resources', [VM])
    app = open_app(layout='corporate', clusters=list(clusters), **kw)
    app.page.locator('[data-corp-tool="topology"]').wait_for(timeout=10000)
    return app


def _reload_with(app, storage):
    """Set localStorage keys the way a returning browser has them, then load again."""
    for k, v in storage.items():
        app.page.evaluate('([k, v]) => localStorage.setItem(k, v)', [k, v])
    app.page.reload(wait_until='load')
    app.wait_for_app()
    app.page.locator('[data-corp-tools]').wait_for(timeout=10000)
    app.page.wait_for_timeout(300)


def _tools(page):
    return page.evaluate('() => Array.from(document.querySelectorAll("[data-corp-tool]")).map(b => b.dataset.corpTool)')


def test_runtime_the_section_sits_under_the_clusters(open_app):
    app = _corporate(open_app, extra=WITH_PBS)
    page = app.page
    page.get_by_text('pbs02').first.wait_for(timeout=5000)
    geo = page.evaluate("""() => {
        const sb = document.querySelector('.pp-sidebar');
        const box = el => { const r = el.getBoundingClientRect(); return {top: r.top, bottom: r.bottom, left: r.left, right: r.right, height: r.height}; };
        const icon = el => box(el.querySelector('svg'));
        const h2s = Array.from(sb.querySelectorAll('h2'));
        const byText = t => h2s.find(h => h.innerText.trim().toUpperCase() === t);
        const tools = document.querySelector('[data-corp-tools]');
        const switcher = sb.querySelector('.corp-view-switcher');
        const clusters = Array.from(sb.querySelectorAll('.corp-tree-item'));
        const btn = t => Array.from(sb.querySelectorAll('button')).find(b => b.innerText.trim() === t);
        const all = btn('All Clusters'), pbs = [btn('pbs01'), btn('pbs02')];
        const backup = byText('BACKUP SERVERS');
        const plus = backup.parentElement.querySelector('button svg');
        const rows = Array.from(document.querySelectorAll('[data-corp-tool]'));
        const follows = (a, b) => !!(a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING);
        return {
            header: tools.querySelector('h2').innerText.trim(),
            order: [follows(switcher, byText('CLUSTER(S)')), follows(byText('CLUSTER(S)'), all),
                    follows(clusters[clusters.length - 1], tools), follows(tools, backup)],
            toolsBox: box(tools), lastCluster: box(clusters[clusters.length - 1]), backupBox: box(backup),
            dividedLikePbs: getComputedStyle(tools).borderTopWidth === getComputedStyle(backup.closest('.border-t')).borderTopWidth
                && getComputedStyle(tools).borderTopColor === getComputedStyle(backup.closest('.border-t')).borderTopColor,
            headerFont: [getComputedStyle(tools.querySelector('h2')).fontSize, getComputedStyle(tools.querySelector('button')).textTransform],
            clusterFont: [getComputedStyle(byText('CLUSTER(S)')).fontSize, getComputedStyle(byText('CLUSTER(S)')).textTransform],
            chevron: icon(tools.querySelector('h2')), plus: box(plus),
            all: box(all), c0: box(clusters[0]), c1: box(clusters[1]),
            pad: [getComputedStyle(all).paddingLeft, getComputedStyle(clusters[0]).paddingLeft],
            rows: rows.map(box), icons: rows.map(icon), pbs: pbs.map(box), pbsIcon: icon(pbs[0]),
        };
    }""")
    assert geo['header'].upper() == 'TOOLS'
    # switcher, filter and tree first, then the tools as a section of their own, then Backup Servers
    assert geo['order'] == [True, True, True, True], geo['order']
    assert geo['lastCluster']['bottom'] <= geo['toolsBox']['top'] < geo['toolsBox']['bottom'] <= geo['backupBox']['top']
    assert geo['dividedLikePbs']
    assert geo['headerFont'] == geo['clusterFont'] == ['14px', 'uppercase']
    # the chevron sits where the + of Backup Servers is
    centre = lambda b: (b['left'] + b['right']) / 2  # noqa: E731
    assert abs(centre(geo['chevron']) - centre(geo['plus'])) < 1, (geo['chevron'], geo['plus'])
    # All Clusters is the first row of the tree, as far in as a cluster row, no gap to the clusters under it
    assert geo['pad'][0] == geo['pad'][1], geo['pad']
    assert round(geo['c0']['top'] - geo['all']['bottom']) == round(geo['c1']['top'] - geo['c0']['bottom']) == 0
    # the tool rows: the height, icon column and pitch of the Backup Servers rows, 16px icons
    rows, icons, pbs = geo['rows'], geo['icons'], geo['pbs']
    pitch = pbs[1]['top'] - pbs[0]['top']
    assert round(pitch) == 30, pbs
    assert len(rows) == 6
    for i, r in enumerate(rows):
        assert round(r['height']) == round(pbs[0]['height']), (i, r, pbs[0])
        assert round(icons[i]['left']) == round(geo['pbsIcon']['left']), (i, icons[i], geo['pbsIcon'])
        assert round(icons[i]['height']) == 16, (i, icons[i])
        if i:
            assert round(r['top'] - rows[i - 1]['top']) == round(pitch), (i, rows)
    assert not app.errors, app.errors


def test_runtime_an_expanded_cluster_comes_before_the_section(open_app):
    """A cluster with 120 guests open in the tree: the tools follow its guests, as Backup
    Servers and ESXi do - the owner's choice over keeping them on the first screen."""
    nodes = {f'pve{i}': dict(NODE_METRICS['pve1']) for i in range(1, 4)}
    guests = [dict(VM, vmid=100 + i, name=f'vm-{i:03d}', node=f'pve{1 + i % 3}') for i in range(120)]
    app = _corporate(open_app, clusters=(CLUSTER, PVE2), resources=guests, metrics=nodes, extra=WITH_PBS)
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.get_by_text('vm-119').first.wait_for(timeout=10000)
    where = page.evaluate("""() => {
        const sc = document.querySelector('.pp-sidebar > div.sticky');
        const top = sc.getBoundingClientRect().top;
        const at = el => el.getBoundingClientRect().bottom - top + sc.scrollTop;
        const guest = Array.from(sc.querySelectorAll('*')).find(e => e.children.length === 0 && e.textContent.trim() === 'vm-119');
        return {view: sc.clientHeight, height: sc.scrollHeight, scroll: sc.scrollTop,
                tools: Array.from(sc.querySelectorAll('[data-corp-tool]')).map(at), guest: at(guest)};
    }""")
    # the tree is several screens long, the last guest is far below the fold
    assert where['height'] > 2 * where['view'] and where['guest'] > where['view'], where
    # the tools come after the last guest and stay reachable by scrolling the sidebar
    assert len(where['tools']) == 5, where
    assert all(where['guest'] < b <= where['height'] for b in where['tools']), where
    assert not app.errors, app.errors


def test_runtime_cluster_groups_keep_their_spacing(open_app):
    """12px between groups and above the ungrouped clusters, 8px under a group header, as before."""
    clusters = (dict(CLUSTER, group_id='g1'), dict(PVE2, group_id='g1'), dict(XCP, group_id='g2'), EDGE)
    app = _corporate(open_app, clusters=clusters, extra={('GET', '/api/cluster-groups'): (200, GROUPS)})
    page = app.page
    page.get_by_text('Staging').first.wait_for(timeout=5000)
    geo = page.evaluate("""() => {
        const sb = document.querySelector('.pp-sidebar');
        const box = el => { const r = el.getBoundingClientRect(); return {top: r.top, bottom: r.bottom}; };
        const btn = t => Array.from(sb.querySelectorAll('button')).find(b => b.innerText.trim() === t);
        const head = t => Array.from(sb.querySelectorAll('span')).find(s => s.textContent.trim() === t).closest('div.w-full');
        const item = t => Array.from(sb.querySelectorAll('.corp-tree-item')).find(e => e.innerText.trim().startsWith(t));
        const ungrouped = Array.from(sb.querySelectorAll('span')).find(s => s.textContent.trim() === 'Ungrouped').parentElement;
        return {all: box(btn('All Clusters')), production: box(head('Production')), testi: box(item('Testi')),
                lab: box(item('Lab')), staging: box(head('Staging')), pool: box(item('Pool1')),
                ungrouped: box(ungrouped), edge: box(item('Edge'))};
    }""")
    gap = lambda a, b: round(geo[b]['top'] - geo[a]['bottom'])  # noqa: E731
    assert [gap('all', 'production'), gap('production', 'testi'), gap('testi', 'lab'), gap('lab', 'staging'),
            gap('staging', 'pool'), gap('pool', 'ungrouped'), gap('ungrouped', 'edge')] == [12, 8, 0, 12, 8, 12, 0], geo
    assert not app.errors, app.errors


def test_runtime_every_tool_has_its_own_icon(open_app):
    app = _corporate(open_app)
    icons = app.page.evaluate("""() => Array.from(document.querySelectorAll('[data-corp-tool]'))
        .map(b => [b.dataset.corpTool, b.querySelector('svg').innerHTML, Math.round(b.querySelector('svg').getBoundingClientRect().width)])""")
    assert [i[0] for i in icons] == ORDER
    assert len({i[1] for i in icons}) == len(icons), [i[0] for i in icons]
    assert {i[2] for i in icons} == {16}, icons
    assert not app.errors, app.errors


@pytest.mark.parametrize('lang', LANGS)
def test_runtime_the_header_never_runs_into_its_chevron(open_app, lang):
    """At the narrowest sidebar the header text gives way, the chevron keeps its column."""
    app = _corporate(open_app, language=lang)
    _reload_with(app, {'corp-sidebar-w': '150'})
    geo = app.page.evaluate("""() => {
        const b = document.querySelector('[data-corp-tools] h2 button');
        const [text, chev] = b.children;
        const box = el => { const r = el.getBoundingClientRect(); return {left: r.left, right: r.right}; };
        return {sidebar: document.querySelector('.pp-sidebar').getBoundingClientRect().width,
                button: box(b), text: box(text), chev: box(chev), label: text.textContent,
                cut: text.scrollWidth > text.clientWidth};
    }""")
    assert round(geo['sidebar']) == 150, geo
    assert geo['chev']['left'] - geo['text']['right'] >= 7.5, geo
    assert round(geo['button']['right'] - geo['chev']['right']) == 8, geo
    assert geo['text']['left'] >= geo['button']['left'], geo
    assert not app.errors, app.errors


def test_runtime_a_cut_off_label_can_still_be_read(open_app):
    app = _corporate(open_app)
    _reload_with(app, {'corp-sidebar-w': '150'})
    rows = app.page.evaluate("""() => Array.from(document.querySelectorAll('[data-corp-tool]')).map(b => {
        // the label is the last child; World Map's icon has a span of its own
        const label = b.lastElementChild;
        return {id: b.dataset.corpTool, title: b.title, text: label.textContent, cut: label.scrollWidth > label.clientWidth};
    })""")
    assert any(r['cut'] for r in rows), rows
    assert all(r['title'] == r['text'] == TITLES[r['id']] for r in rows), rows
    assert not app.errors, app.errors


def _css_color(page, value):
    """What a colour like var(--corp-accent) computes to on this page."""
    return page.evaluate("""v => {
        const probe = document.createElement('span');
        probe.style.color = v;
        document.querySelector('.pp-sidebar').appendChild(probe);
        const c = getComputedStyle(probe).color;
        probe.remove();
        return c;
    }""", value)


def test_runtime_each_entry_opens_its_view(open_app):
    app = _corporate(open_app)
    page = app.page
    accent, muted = _css_color(page, 'var(--corp-accent)'), _css_color(page, 'var(--corp-text-muted)')
    assert accent != muted
    for tool in ORDER:
        page.locator(f'[data-corp-tool="{tool}"]').click()
        page.wait_for_function('t => document.querySelector(".corp-header-title")?.innerText.trim() === t',
                               arg=TITLES[tool], timeout=5000)
        state = page.evaluate("""() => Array.from(document.querySelectorAll('[data-corp-tool]')).map(b => ({
            id: b.dataset.corpTool, border: b.style.borderLeft, icon: getComputedStyle(b.querySelector('svg')).color}))""")
        # one row lit, with the accent border and icon, the others muted
        assert [s['id'] for s in state if s['border']] == [tool], (tool, state)
        assert {s['id']: s['icon'] for s in state} == {s['id']: accent if s['id'] == tool else muted for s in state}
        # All Clusters is not lit while a tool view is open
        assert page.evaluate("""() => Array.from(document.querySelectorAll('.pp-sidebar button'))
            .find(b => b.innerText.trim() === 'All Clusters').style.borderLeft""") == ''
    # back to the overview
    page.locator('.pp-sidebar button', has_text='All Clusters').first.click()
    page.wait_for_timeout(300)
    assert page.evaluate("() => Array.from(document.querySelectorAll('[data-corp-tool]')).every(b => !b.style.borderLeft)")
    assert not app.errors, app.errors


def test_runtime_hover_tints_a_row_that_is_not_selected(open_app):
    app = _corporate(open_app)
    page = app.page
    row = page.locator('[data-corp-tool="worldmap"]')
    row.hover()
    assert 'var(--color-hover)' in row.evaluate('b => b.style.background')
    page.mouse.move(900, 900)
    assert row.evaluate('b => b.style.background') == ''
    assert not app.errors, app.errors


def test_runtime_the_section_folds_and_stays_folded_after_a_reload(open_app):
    app = _corporate(open_app)
    page = app.page
    header = page.locator('[data-corp-tools] h2 button')
    assert header.get_attribute('aria-expanded') == 'true'
    header.click()
    page.wait_for_function('() => !document.querySelector("[data-corp-tool]")', timeout=3000)
    assert header.get_attribute('aria-expanded') == 'false'
    assert page.evaluate(f"() => localStorage.getItem('{KEY}')") == '1'
    # the header stays, so does the rest of the sidebar
    assert page.locator('[data-corp-tools] h2').inner_text().strip().upper() == 'TOOLS'
    assert page.locator('.corp-tree-item', has_text='Testi').count() == 1

    page.reload(wait_until='load')
    app.wait_for_app()
    page.locator('[data-corp-tools]').wait_for(timeout=10000)
    page.wait_for_timeout(300)
    assert page.locator('[data-corp-tool]').count() == 0
    assert page.locator('[data-corp-tools] h2 button').get_attribute('aria-expanded') == 'false'

    page.locator('[data-corp-tools] h2 button').click()
    page.locator('[data-corp-tool="topology"]').wait_for(timeout=3000)
    page.reload(wait_until='load')
    app.wait_for_app()
    page.locator('[data-corp-tool="topology"]').wait_for(timeout=10000)
    assert _tools(page) == ORDER
    assert not app.errors, app.errors


def test_runtime_folded_with_a_view_open_the_header_says_so(open_app):
    app = _corporate(open_app)
    page = app.page
    accent, muted = _css_color(page, 'var(--corp-accent)'), _css_color(page, 'var(--corp-text-muted)')
    header = page.locator('[data-corp-tools] h2 button')
    colours = """() => { const b = document.querySelector('[data-corp-tools] h2 button');
        return [getComputedStyle(b.children[0]).color, getComputedStyle(b.querySelector('svg')).color]; }"""

    def settled(expected):
        # corporate buttons fade their colour over 0.12s, on a busy machine a read can land mid-fade
        try:
            page.wait_for_function(f'exp => {{ const c = ({colours})(); return c[0] === exp[0] && c[1] === exp[1]; }}',
                                   arg=expected, timeout=3000)
        except Exception:
            pass
        return page.evaluate(colours)

    plain = page.evaluate(colours)
    assert plain[0] != accent and plain[1] == muted, plain

    page.locator('[data-corp-tool="topology"]').click()
    page.wait_for_function('() => document.querySelector(".corp-header-title")?.innerText.trim() === "Topology"', timeout=5000)
    # unfolded, the lit row says it, the header stays plain
    assert settled(plain) == plain
    header.click()
    page.wait_for_function('() => !document.querySelector("[data-corp-tool]")', timeout=3000)
    assert settled([accent, accent]) == [accent, accent]

    # nothing of it open: folded, the header is plain again
    page.locator('.pp-sidebar button', has_text='All Clusters').first.click()
    assert settled(plain) == plain
    assert not app.errors, app.errors


def test_runtime_blocked_storage_still_folds_for_the_session(open_app):
    app = _corporate(open_app)
    page = app.page
    # throws on our key only, as blocked site data does on every key
    app.ctx.add_init_script("""(() => {
        const get = Storage.prototype.getItem, set = Storage.prototype.setItem;
        Storage.prototype.getItem = function (k) { if (k === '%s') throw new Error('blocked'); return get.call(this, k); };
        Storage.prototype.setItem = function (k, v) { if (k === '%s') throw new Error('blocked'); return set.call(this, k, v); };
    })();""" % (KEY, KEY))
    page.reload(wait_until='load')
    app.wait_for_app()
    page.locator('[data-corp-tool="topology"]').wait_for(timeout=10000)
    page.locator('[data-corp-tools] h2 button').click()
    page.wait_for_function('() => !document.querySelector("[data-corp-tool]")', timeout=3000)
    assert not app.errors, app.errors


@pytest.mark.parametrize('case,kw,expected', [
    ('pve and xcp-ng', dict(clusters=(CLUSTER, XCP)), ORDER),
    ('one pve cluster', dict(clusters=(CLUSTER,)), ['guests', 'topology', 'worldmap', 'autoinstall']),
    ('two pve clusters', dict(clusters=(CLUSTER, PVE2)), ['guests', 'topology', 'worldmap', 'autoinstall', 'mcevpn']),
    ('view-only installs', dict(autoinstall='view'), ORDER),
    ('no install permission', dict(autoinstall=None), ['guests', 'topology', 'worldmap', 'xhm', 'mcevpn']),
    ('standby', dict(role='standby'), ['guests', 'topology', 'worldmap', 'xhm', 'mcevpn']),
])
def test_runtime_each_entry_shows_under_its_condition(open_app, case, kw, expected):
    app = _corporate(open_app, **kw)
    assert _tools(app.page) == expected, case
    assert not app.errors, app.errors


def test_runtime_no_section_before_the_first_cluster(open_app):
    app = open_app(layout='corporate', clusters=[], autoinstall='manage')
    page = app.page
    page.get_by_text('Add First Cluster').first.wait_for(timeout=5000)
    assert page.locator('[data-corp-tools]').count() == 0
    # the way in for a bare-metal start stays on the empty card
    assert page.locator('.pp-sidebar').get_by_text('No Proxmox VE yet? Install it automatically').count() == 1


def test_runtime_modern_keeps_the_entries_under_all_clusters(open_app):
    app = open_app(layout='modern', clusters=[CLUSTER, XCP], resources=[VM], autoinstall='manage')
    page = app.page
    page.get_by_text('Multi-Cluster EVPN').first.wait_for(timeout=10000)
    assert page.locator('[data-corp-tools]').count() == 0
    assert page.locator('[data-corp-tool]').count() == 0
    tops = page.evaluate("""() => {
        const sb = document.querySelector('.pp-sidebar');
        const at = t => { const el = Array.from(sb.querySelectorAll('button, h3')).find(e => e.innerText.trim().startsWith(t));
                          return el ? el.getBoundingClientRect().top : null; };
        return ['All Clusters', 'World Map', 'All Guests', 'Automated Installations', 'Hypervisor Migration', 'Multi-Cluster EVPN', 'Testi'].map(at);
    }""")
    assert None not in tops, tops
    assert tops == sorted(tops), tops
    # Topology has never been a Modern sidebar entry
    assert page.evaluate("() => Array.from(document.querySelectorAll('.pp-sidebar button')).some(b => b.innerText.trim() === 'Topology')") is False
    assert not app.errors, app.errors


def test_runtime_modern_groups_are_untouched(open_app):
    """The corporate padding on cluster groups stays out of Modern: 12px between groups, no padding."""
    clusters = (dict(CLUSTER, group_id='g1'), dict(XCP, group_id='g2'), EDGE)
    app = open_app(layout='modern', clusters=list(clusters), resources=[VM],
                   extra={('GET', '/api/cluster-groups'): (200, GROUPS)})
    page = app.page
    page.get_by_text('Staging').first.wait_for(timeout=10000)
    pads = page.evaluate("""() => Array.from(document.querySelectorAll('.pp-sidebar span'))
        .filter(s => ['Production', 'Staging', 'Ungrouped'].includes(s.textContent.trim()))
        .map(s => { let el = s; while (el && !(el.parentElement && el.parentElement.classList.contains('space-y-3'))) el = el.parentElement;
                    return el ? [getComputedStyle(el).paddingTop, getComputedStyle(el).marginTop] : null; })""")
    assert pads == [['0px', '12px']] * 3, pads
    assert not app.errors, app.errors
