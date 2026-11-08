"""The QDevice next to the nodes (#1137), in both layouts.

Where a cluster has a QDevice, the corporate tree lists it after the nodes and the modern
overview after the node cards, with a dot for its state. Clicking it opens a view like the
node details: QNetd host, model, algorithm, tie-breaker, state, last poll, echo reply, which
node answered, the state of the QDevice daemon on every node, and the note that the QNetd
host is no Proxmox node. It reads GET /api/clusters/<id>/qdevice and changes nothing,
on a standby neither. A read that fails keeps the last answer but no longer shows it as
the current state. The alert dialog offers the QDevice rule.

Source checks read web/src and the bundle; the runtime tests drive the built bundle in
headless Chromium against the fake server of tests/test_ha_ui.py, the way the other *_ui.py
tests do. They skip where Playwright is not installed.
LW Oct 2026
"""
import os
import re
import time

import pytest

from test_ha_ui import (CLUSTER, NODE_METRICS, SSE_TOKEN, VM, _App, _FakeServer, _classes,  # noqa: F401
                        _wait_for_call, browser)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHOTS = os.environ.get('PEGAPROX_SHOTS', '')
LANGS = ['de', 'en', 'zh', 'pl', 'fr', 'es', 'pt', 'ko', 'it']
KEYS = ['qdeviceTitle', 'qdeviceQnetdHost', 'qdeviceModel', 'qdeviceAlgorithm', 'qdeviceTieBreaker', 'qdeviceState',
        'qdeviceLastPoll', 'qdeviceEchoReply', 'qdeviceAnsweredBy', 'qdeviceApiHost', 'qdevicePerNode',
        'qdeviceNoDaemon', 'qdeviceNotAsked', 'qdeviceNoAnswer', 'qdeviceReadAt', 'qdeviceConnectedOf', 'qdeviceNote',
        'qdeviceAlertTitle', 'qdeviceAlertHelp', 'qdeviceAlertSummary', 'qdeviceStale']
NOTE_EN = ('The QNetd host is not a Proxmox node. PegaProx sees it only through the QDevice daemons of the '
           'cluster nodes: its connection state and answer times, not its own CPU, memory or updates.')
STALE_EN = 'Not readable right now - showing what was read last'


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def _between(src, start, end):
    s = src.index(start)
    return src[s:src.index(end, s)]


def _blocks():
    src = _read('web', 'src', 'translations.js')
    starts = [(m.start(), m.group(1)) for m in re.finditer(r'^ {12}([a-z]{2}): \{$', src, re.M)]
    return {lang: src[pos:(starts[i + 1][0] if i + 1 < len(starts) else len(src))]
            for i, (pos, lang) in enumerate(starts)}


def _detail():
    return _between(_read('web', 'src', 'node_modals.js'), 'function qdeviceTone(q)', '// Node Management Modal Component')


def _added_blocks():
    dash = _read('web', 'src', 'dashboard.js')
    return [
        _detail(),
        _between(dash, 'const qdeviceClustersRef = useRef([]);', 'const fetchClusterNetworks = async'),
        _between(dash, "{/* LW Oct 2026 (#1137) - the QDevice right after the nodes", '{/* Then VMs/CTs at same level */}'),
        _between(dash, "{/* LW Oct 2026 (#1137) - the QDevice next to the nodes, only", "{Object.keys(clusterMetrics).length === 0"),
        _between(dash, ') : isCorporate && selectedSidebarQdevice ? (', ') : ('),
    ]


# --- source --------------------------------------------------------------------------------

@pytest.mark.parametrize('lang', LANGS)
def test_every_new_string_is_in_every_language_once(lang):
    block = _blocks()[lang]
    for key in KEYS:
        n = len(re.findall(rf'^\s*{key}:', block, re.M))
        assert n == 1, f'{key} is {n} times in {lang} - the UI would show the key'


def test_every_new_key_is_used_and_nothing_else_was_defined():
    src = _read('web', 'src', 'dashboard.js') + _read('web', 'src', 'node_modals.js')
    used = set(re.findall(r"t\('(qdevice[A-Za-z]*)'\)", src)) - {'qdeviceDesc'}
    assert used == set(KEYS), (sorted(used - set(KEYS)), sorted(set(KEYS) - used))
    defined = set(re.findall(r'^\s*(qdevice[A-Za-z]*):', _blocks()['en'], re.M)) - {'qdeviceDesc'}
    assert defined == set(KEYS)


def test_the_note_says_what_was_agreed_and_placeholders_survive():
    blocks = _blocks()
    assert f'qdeviceNote: "{NOTE_EN}",' in blocks['en']
    for lang, block in blocks.items():
        value = re.search(r'^\s*qdeviceConnectedOf: "(.*)",$', block, re.M).group(1)
        assert sorted(re.findall(r'\{\w+\}', value)) == ['{n}', '{up}'], (lang, value)
        note = re.search(r'^\s*qdeviceNote: "(.*)",$', block, re.M).group(1)
        assert 'QNetd' in note and 'Proxmox' in note, lang
    assert "{ code: 'de', flag: '🇦🇹'" in _read('web', 'src', 'contexts.js')


def test_no_em_dash_in_what_this_change_added():
    for block in _added_blocks():
        assert '\u2014' not in block and '\u2013' not in block, block[:120]
    for block in _blocks().values():
        for line in block.splitlines():
            if re.match(r'^\s*qdevice(?!Desc)', line):
                assert '\u2014' not in line and '\u2013' not in line, line


def test_every_class_is_in_the_static_tailwind_build():
    css = _read('static', 'css', 'tailwind.min.css') + _read('web', 'index.html.original')
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    names = set()
    for block in _added_blocks():
        names |= _classes(block)
    missing = sorted(n for n in names if n not in have)
    assert not missing, f'not in the static CSS: {missing}'


def test_the_view_only_reads():
    """The details change nothing anywhere, on a standby neither: no request of their own, no
    method, and the one fetch is a GET of /qdevice."""
    detail = _detail()
    for word in ('fetch(', 'authFetch', 'method:', 'haReadOnly'):
        assert word not in detail, word
    fetcher = _between(_read('web', 'src', 'dashboard.js'), 'const fetchQdevice = async', 'const qdeviceSeenRef')
    assert fetcher.count('authFetch(') == 1 and '/qdevice`' in fetcher and 'method' not in fetcher
    # a cluster type without corosync, a cluster that is offline, an account without node.view: not asked
    assert "c.cluster_type === 'xcpng' || c.connected === false || !can('node.view')" in fetcher
    # a read that fails keeps the last answer, marked stale, and stale is no state at all
    assert 'stale: true' in fetcher
    assert 'q.stale' in detail and "t('qdeviceStale')" in detail


def test_both_layouts_render_it_next_to_the_nodes():
    dash = _read('web', 'src', 'dashboard.js')
    tree = _between(dash, 'const renderInlineNodeTree = (clusterId) => {', 'const renderPoolTree = (clusterId) => {')
    # after the nodes, before the guests, and only with a QDevice
    assert tree.index('filteredNodes.map(') < tree.index('data-qdevice-entry={clusterId}') < tree.index('filteredVms.map(')
    assert 'showNodes && qdeviceByCluster[clusterId]?.present &&' in tree
    overview = _between(dash, "{/* Modern: full node cards */}", "{Object.keys(clusterMetrics).length === 0")
    assert overview.index('<NodeCard') < overview.index('data-qdevice-entry={selectedCluster.id}')
    assert 'qdeviceByCluster[selectedCluster.id]?.present && (' in overview
    # the sidebar stays flat: nothing is nested under a node
    assert '<QdeviceDetail\n' in dash and dash.count('<QdeviceDetail') == 2


def test_the_rule_is_in_the_dialog():
    dash = _read('web', 'src', 'dashboard.js')
    assert "'clock_drift', 'restart_loop', 'qdevice'];" in dash
    assert '<option value="qdevice">{t(\'qdeviceAlertTitle\')}</option>' in dash
    assert "alertMetricSel !== 'qdevice' && <option value=\"vm\">" in dash
    assert "if (alert.metric === 'qdevice') return t('qdeviceAlertSummary');" in dash


def test_the_bundle_was_rebuilt():
    built = _read('web', 'index.html')
    for needle in ('function QdeviceDetail(', 'data-qdevice-entry', 'data-qdevice-note', '/qdevice`',
                   'React.createElement("option",{value:"qdevice"}', 'qdeviceAlertHelp', NOTE_EN[:60]):
        assert needle in built, needle


# --- runtime -------------------------------------------------------------------------------

QDEV = {
    'present': True, 'answered_by': 'pve1', 'state': 'Connected', 'qnetd_host': '10.0.0.9:5403', 'model': 'Net',
    'algorithm': 'Fifty-Fifty split', 'tie_breaker': 'Node with lowest node ID',
    'last_poll': '2026-10-08T09:12:01 (cast vote)', 'echo_reply': '2026-10-08T09:12:00 (1s)',
    'read_at': '2026-10-08T09:12:05+00:00',
    'nodes': [
        {'node': 'pve1', 'online': True, 'api_host': True, 'asked': True, 'answered': True, 'present': True,
         'connected': True, 'state': 'Connected', 'last_poll': '2026-10-08T09:12:01 (cast vote)',
         'echo_reply': '2026-10-08T09:12:00 (1s)', 'error': None},
        {'node': 'pve2', 'online': True, 'api_host': False, 'asked': True, 'answered': True, 'present': True,
         'connected': False, 'state': 'Connect failed', 'last_poll': None, 'echo_reply': None, 'error': None},
        {'node': 'pve3', 'online': True, 'api_host': False, 'asked': False, 'answered': False, 'present': None,
         'connected': None, 'state': None, 'last_poll': None, 'echo_reply': None, 'error': None},
    ],
}
QPATH = ('GET', '/api/clusters/c1/qdevice')
RULE = {'id': 'q1', 'name': 'QDevice', 'cluster_id': 'c1', 'metric': 'qdevice', 'operator': 'event', 'threshold': 0,
        'target_type': 'cluster', 'target_id': None, 'channels': [], 'enabled': True, 'notify_resolved': True,
        'severity': 'auto'}
ALERT_READS = {
    ('GET', '/api/clusters/c1/alerts'): (200, {'alerts': [RULE]}),
    ('GET', '/api/clusters/c1/active-alerts'): (200, {'active_alerts': []}),
    ('GET', '/api/clusters/c1/alert-mutes'): (200, {'mutes': []}),
    ('GET', '/api/alert-channels'): (200, []),
    ('GET', '/api/schedules'): (200, []),
    ('GET', '/api/clusters/c1/scripts'): (200, []),
    ('POST', '/api/clusters/c1/alerts'): (200, {'success': True, 'alert': {}}),
}


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(qdevice=(200, QDEV), clock=False, **kw):
        extra = dict(ALERT_READS)
        extra.update(SSE_TOKEN)
        if qdevice is not None:
            extra[QPATH] = qdevice
        kw.setdefault('role', 'standalone')
        app = _App(browser, _FakeServer(clusters=[CLUSTER], resources=[VM], metrics=NODE_METRICS, extra=extra, **kw),
                   clock=clock)
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _shot(page, name):
    if SHOTS:
        os.makedirs(SHOTS, exist_ok=True)
        page.screenshot(path=os.path.join(SHOTS, name), full_page=False)


def _select(app, layout):
    page = app.page
    if layout == 'corporate':
        page.locator('.corp-tree-item', has_text='Testi').first.click()
        page.locator('.corp-tree-child', has_text='pve1').first.wait_for(timeout=8000)
    else:
        page.get_by_text('Testi').first.click()
        page.locator('button[title="Node Configuration"]').first.wait_for(timeout=8000)
    assert _wait_for_call(app, QPATH, seconds=5) or layout == 'none'
    page.wait_for_timeout(400)
    return page


def _no_writes(app):
    return [c for c in app.server.calls if c[0] != 'GET' and c[1] not in ('/api/sse/token', '/api/sse/subscribe')]


def _check_view(view):
    text = view.inner_text()
    assert NOTE_EN in text
    for want in ('10.0.0.9:5403', 'Net', 'Fifty-Fifty split', 'Node with lowest node ID',
                 '2026-10-08T09:12:01 (cast vote)', '2026-10-08T09:12:00 (1s)'):
        assert want in text, want
    assert view.locator('[data-qdevice-field="answered_by"]').inner_text().strip().endswith('pve1')
    states = {n: view.locator(f'[data-qdevice-node="{n}"] [data-qdevice-node-state]').inner_text()
              for n in ('pve1', 'pve2', 'pve3')}
    assert states == {'pve1': 'Connected', 'pve2': 'Connect failed',
                      'pve3': 'Not asked: PegaProx has no address of its own for this node'}
    assert '(API host)' in view.locator('[data-qdevice-node="pve1"]').inner_text()


@pytest.mark.parametrize('role', ['standalone', 'standby'])
def test_runtime_modern_shows_the_qdevice_after_the_nodes_and_opens_it(open_app, role):
    app = open_app(layout='modern', role=role)
    page = _select(app, 'modern')
    entry = page.locator('[data-qdevice-entry="c1"]')
    entry.wait_for(timeout=5000)
    assert 'QDevice' in entry.inner_text() and '10.0.0.9:5403' in entry.inner_text()
    assert '1 of 2 nodes connected' in entry.inner_text()
    # one of two connected: the dot says so
    assert entry.locator('[data-qdevice-dot]').get_attribute('data-qdevice-dot') == 'warn'
    # next to the nodes: the same grid, after the node card
    assert page.evaluate("""() => {
        const e = document.querySelector('[data-qdevice-entry="c1"]');
        const card = document.querySelector('button[title="Node Configuration"]');
        return e.parentElement.contains(card) && !!(card.compareDocumentPosition(e) & Node.DOCUMENT_POSITION_FOLLOWING);
    }""")
    entry.scroll_into_view_if_needed()
    _shot(page, f'modern_qdevice_card_{role}.png')
    entry.click()
    view = page.locator('[data-qdevice-view]')
    view.wait_for(timeout=3000)
    _check_view(view)
    # nothing in it acts: the close button is the only one
    assert view.locator('button').count() == 1
    _shot(page, f'modern_qdevice_{role}.png')
    view.locator('button[title="Close"]').click()
    assert page.locator('[data-qdevice-view]').count() == 0
    assert not _no_writes(app), _no_writes(app)
    assert not app.errors, app.errors


@pytest.mark.parametrize('role', ['standalone', 'standby'])
def test_runtime_corporate_lists_it_in_the_tree_and_shows_it_like_a_node(open_app, role):
    app = open_app(layout='corporate', role=role)
    page = _select(app, 'corporate')
    entry = page.locator('.corp-inline-tree [data-qdevice-entry="c1"]')
    entry.wait_for(timeout=5000)
    # flat next to the nodes: after pve1, before the guests, at the same level
    order = page.evaluate("""() => Array.from(document.querySelector('.corp-inline-tree').children)
        .map(d => d.getAttribute('data-qdevice-entry') ? 'qdevice' : d.innerText.trim())""")
    assert order.index('pve1') < order.index('qdevice') < order.index('web01'), order
    assert entry.locator('[data-qdevice-dot]').get_attribute('data-qdevice-dot') == 'warn'
    entry.click()
    view = page.locator('[data-qdevice-view]')
    view.wait_for(timeout=3000)
    _check_view(view)
    assert 'Testi' in view.inner_text()
    assert view.locator('button').count() == 1      # back, nothing else
    # the breadcrumb names it as it names an open node
    assert page.locator('[data-qdevice-crumb]').inner_text().strip() == 'QDevice'
    _shot(page, f'corporate_qdevice_{role}.png')
    # a node opened from the tree takes its place
    page.locator('.corp-tree-child', has_text='pve1').first.click()
    page.locator('.corp-tab-strip').first.wait_for(timeout=5000)
    assert page.locator('[data-qdevice-view]').count() == 0
    entry.click()
    view.wait_for(timeout=3000)
    view.locator('button').first.click()
    assert page.locator('[data-qdevice-view]').count() == 0
    # and the tab segment of the breadcrumb leads back to the overview, as from a node
    entry.click()
    view.wait_for(timeout=3000)
    # the fake server has no event stream, so its reconnect bar lies over the breadcrumb
    page.locator('.corp-breadcrumb-segment', has_text='Overview').first.dispatch_event('click')
    page.wait_for_timeout(200)
    assert page.locator('[data-qdevice-view]').count() == 0 and page.locator('[data-qdevice-crumb]').count() == 0
    assert not _no_writes(app), _no_writes(app)
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_a_read_that_fails_does_not_keep_saying_connected(open_app, layout):
    """The cluster stops answering after a good read (503, or no answer in time): the entry
    keeps what it read last, but its dot no longer says connected and the view says why. The
    next good read brings the state back."""
    good = dict(QDEV, nodes=[dict(n, connected=True, state='Connected') if n['answered'] else dict(n)
                             for n in QDEV['nodes']])
    app = open_app(layout=layout, qdevice=(200, good), clock=True)
    page = _select(app, layout)
    entry = page.locator('[data-qdevice-entry="c1"]').first
    entry.wait_for(timeout=5000)
    dot = entry.locator('[data-qdevice-dot]')
    assert dot.get_attribute('data-qdevice-dot') == 'ok'

    def next_round(answer):
        app.server.extra[QPATH] = answer
        n = app.server.calls.count(QPATH)
        page.clock.run_for(31000)
        assert _wait_for_call_n(app, n + 1)
        page.wait_for_timeout(400)

    next_round((503, {'error': 'The cluster did not answer'}))
    assert dot.get_attribute('data-qdevice-dot') == 'none'
    assert dot.get_attribute('title') == STALE_EN
    if layout == 'modern':
        assert STALE_EN in entry.inner_text()
    entry.click()
    view = page.locator('[data-qdevice-view]')
    view.wait_for(timeout=3000)
    assert view.locator('[data-qdevice-stale]').inner_text().strip() == STALE_EN
    # what was read last is still there to see, next to the note
    assert '10.0.0.9:5403' in view.inner_text() and NOTE_EN in view.inner_text()
    _shot(page, f'{layout}_qdevice_stale.png')

    next_round((200, good))
    assert dot.get_attribute('data-qdevice-dot') == 'ok'
    assert page.locator('[data-qdevice-stale]').count() == 0
    assert not _no_writes(app), _no_writes(app)
    assert not app.errors, app.errors


def _wait_for_call_n(app, n, seconds=5):
    deadline = time.time() + seconds
    while time.time() < deadline and app.server.calls.count(QPATH) < n:
        app.page.wait_for_timeout(100)
    return app.server.calls.count(QPATH) >= n


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
@pytest.mark.parametrize('answer', [(200, {'present': False}), (403, {'error': 'Access denied'})])
def test_runtime_no_entry_without_a_qdevice(open_app, layout, answer):
    app = open_app(layout=layout, qdevice=answer)
    page = _select(app, layout)
    page.wait_for_timeout(500)
    assert page.locator('[data-qdevice-entry]').count() == 0
    # counterproof that the place is rendered: the node is there
    if layout == 'corporate':
        assert page.locator('.corp-inline-tree .corp-tree-child', has_text='pve1').count() == 1
    else:
        assert page.locator('button[title="Node Configuration"]').count() >= 1
    assert not app.errors, app.errors


def test_runtime_an_account_without_node_view_does_not_ask(open_app):
    app = open_app(layout='modern', admin=False, permissions=['vm.view'])
    page = app.page
    page.get_by_text('Testi').first.click()
    page.wait_for_timeout(1500)
    assert QPATH not in app.server.calls
    assert page.locator('[data-qdevice-entry]').count() == 0
    # counterproof: with node.view it does
    app2 = open_app(layout='modern', admin=False, permissions=['vm.view', 'node.view'])
    app2.page.get_by_text('Testi').first.click()
    assert _wait_for_call(app2, QPATH, seconds=5)


def test_runtime_it_speaks_german(open_app):
    app = open_app(layout='corporate', language='de')
    page = _select(app, 'corporate')
    page.locator('[data-qdevice-entry="c1"]').click()
    view = page.locator('[data-qdevice-view]')
    view.wait_for(timeout=3000)
    text = view.inner_text()
    assert 'Der QNetd-Host ist kein Proxmox-Node.' in text and 'QDevice-Dienst je Node' in text
    assert 'Nicht gefragt: PegaProx hat für diesen Node keine eigene Adresse' in text
    _shot(page, 'corporate_qdevice_de.png')
    assert not app.errors, app.errors


def _to_alerts(app):
    page = app.page
    page.get_by_text('Testi').first.click()
    page.locator('button', has_text=re.compile(r'^\s*(Automation|Automatisierung)\s*$')).first.click()
    page.get_by_role('button', name=re.compile(r'^\s*(Alerts|Alarme)\s*$')).first.click()
    page.locator('[data-alert-rule="q1"]').wait_for(timeout=8000)
    page.wait_for_timeout(300)
    return page


def test_runtime_the_rule_in_the_list_and_the_dialog(open_app):
    app = open_app(layout='modern')
    page = _to_alerts(app)
    assert 'QDevice daemon of a node not connected' in page.locator('[data-alert-rule="q1"]').inner_text()
    page.locator('button', has_text='New Alert').first.click()
    sel = page.locator('select[name="metric"]')
    sel.wait_for(timeout=3000)
    sel.select_option('qdevice')
    help_text = page.locator('[data-event-help]').inner_text()
    assert 'QNetd host itself is not a Proxmox node' in help_text and 'fallback hosts' in help_text
    # a node rule: no guest target, no number to set
    assert page.locator('select[name="target_type"] option').evaluate_all('o => o.map(x => x.value)') == [
        'cluster', 'node']
    assert page.locator('select[name="operator"]').count() == 0
    assert page.locator('input[name="threshold"], select[name="threshold"]').count() == 0
    assert page.locator('input[name="notify_resolved"]').is_checked()
    page.locator('input[name="name"]').fill('QDevice of Testi')
    _shot(page, 'modern_alerts_dialog_qdevice.png')
    page.locator('form button[type="submit"]').click()
    assert _wait_for_call(app, ('POST', '/api/clusters/c1/alerts'))
    # the list is read again on the same path right after, with no body
    body = [b for b in app.server.bodies['/api/clusters/c1/alerts'] if b][-1]
    for k, v in {'name': 'QDevice of Testi', 'metric': 'qdevice', 'operator': 'event', 'target_type': 'cluster',
                 'notify_resolved': True}.items():
        assert body.get(k) == v, (k, body)
    assert not app.errors, app.errors
