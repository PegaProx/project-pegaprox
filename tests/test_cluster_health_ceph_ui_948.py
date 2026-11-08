"""The Ceph status on the Cluster Health card of the overview (#948).

The card the report showed ("92 Excellent", 2/2 nodes online, Ceph in HEALTH_ERR) is the
ClusterHealth widget of the cluster overview, and its number is the load of the nodes.
It now takes the Ceph factor of /api/clusters/<id>/health: a HEALTH_WARN holds it at 75,
a HEALTH_ERR at 25, and the Ceph status, its checks and why the number is held show under
it. The pill in the Corporate header polls the same route; one request serves both.

The source checks read web/src and the bundle; the runtime tests drive the built bundle in
headless Chromium against the fake server of tests/test_ha_ui.py, in Modern and Corporate,
in English and German. They skip where Playwright is not installed. The route is tested in
tests/test_cluster_health_ceph_948.py.
NS Oct 2026
"""
import os
import re

import pytest

from test_ha_ui import CLUSTER, SSE_TOKEN, VM, NODE_METRICS, _App, _FakeServer, _classes, browser  # noqa: F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEYS = ('clusterHealthCephCap', 'clusterHealthCephUnknown', 'clusterHealthCephSilent')
HEALTH = ('GET', f"/api/clusters/{CLUSTER['id']}/health")


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def _block(src, start, end):
    at = src.index(start)
    return src[at:src.index(end, at)]


def _widget():
    return _block(_read('web', 'src', 'vm_modals.js'), '        // Cluster Health Widget',
                  '        // Create Snapshot Modal')


def _shared_read():
    return _block(_read('web', 'src', 'ui.js'), '        const _clusterHealthReads', '        // NS May 2026')


# --- source --------------------------------------------------------------------------------

@pytest.mark.parametrize('key', KEYS)
def test_every_new_string_is_in_every_language_once(key):
    found = len(re.findall(rf'^\s*{key}:', _read('web', 'src', 'translations.js'), re.M))
    assert found == 9, f'{key} is in {found} of 9 language blocks - the UI would show the key'


def test_both_keys_are_used_and_the_placeholders_survive_translation():
    used = set(re.findall(r"t\('(clusterHealthCeph[A-Za-z]*)'\)", _widget()))
    assert used == set(KEYS)
    values = re.findall(r"^\s*clusterHealthCephCap: '(.*)',$", _read('web', 'src', 'translations.js'), re.M)
    assert len(values) == 9 and all('{cap}' in v and '{status}' in v for v in values), values
    silent = re.findall(r"^\s*clusterHealthCephSilent: '(.*)',$", _read('web', 'src', 'translations.js'), re.M)
    assert len(silent) == 9 and all('{cap}' in v for v in silent), silent


def test_no_em_dash_in_what_this_change_added():
    tr = _read('web', 'src', 'translations.js')
    added = [_widget(), _shared_read()] + re.findall(r'^\s*clusterHealthCeph\w+: .*$', tr, re.M)
    for text in added:
        assert '\u2014' not in text and '\u2013' not in text, text[:120]


def test_every_class_is_in_the_static_tailwind_build_and_the_icon_takes_one():
    css = _read('static', 'css', 'tailwind.min.css') + _read('web', 'index.html.original')
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    missing = sorted(n for n in _classes(_widget()) if n not in have)
    assert not missing, f'not in static/css/tailwind.min.css: {missing}'
    icons = _read('web', 'src', 'icons.js')
    assert re.search(r'^\s{12}HardDrive: \(\{[^}]*className', icons, re.M)


def test_the_card_and_the_pill_share_one_read_of_the_route():
    assert _shared_read().count('authFetch(`${apiUrl}/clusters/${clusterId}/health`)') == 1
    ui = _read('web', 'src', 'ui.js')
    badge = _block(ui, 'function ClusterHealthBadge(', 'function ClusterHealthModal(')
    assert 'readClusterHealth(clusterId, authFetch, apiUrl, who)' in badge and '/health`' not in badge
    assert 'readClusterHealth(clusterId, authFetch, API_URL, who)' in _widget()
    mount = _block(_read('web', 'src', 'dashboard.js'), '<ClusterHealth metrics=', '/>')
    assert 'authFetch={authFetch}' in mount and 'selectedCluster.connected' in mount


def test_the_shared_read_is_kept_per_signed_in_account():
    # a logout does not reload the page, so an answer kept for 30s would reach the next account
    # to sign in, which may be one confined to a pool that must not see the Ceph factor
    read = _shared_read()
    assert 'function readClusterHealth(clusterId, authFetch, apiUrl, who)' in read
    key = re.search(r'const key = `([^`]*)`;', read).group(1)
    assert '${who' in key and '${clusterId}' in key and '${apiUrl}' in key, key
    badge = _block(_read('web', 'src', 'ui.js'), '        function ClusterHealthBadge(', '        try { window.')
    for name, body in (('card', _widget()), ('pill', badge)):
        assert "const who = user?.username || '';" in body, name
        assert re.search(r'readClusterHealth\(clusterId, authFetch, (apiUrl|API_URL), who\)', body), name


def test_the_bundle_was_rebuilt():
    built = _read('web', 'index.html')
    for needle in ('function readClusterHealth(', 'data-cluster-health-ceph', 'clusterHealthCephCap',
                   'clusterHealthCephUnknown', 'clusterHealthCephSilent'):
        assert needle in built, needle


# --- runtime -------------------------------------------------------------------------------

def _node(score, cpu, mem):
    return dict(NODE_METRICS['pve1'], score=score, cpu_percent=cpu, mem_percent=mem)


# the two nodes of the report: scores 11 and 20, the card said 92
METRICS = {'pve1': _node(11, 1.2, 6.3), 'pve2': _node(20, 1.8, 14.1)}


def _ceph(status, severity, cap, checks=(), delta=0):
    return {'key': 'ceph', 'label': 'Ceph', 'value': status or 'unknown', 'delta': delta,
            'severity': severity, 'status': status, 'checks': list(checks), 'cap': cap}


def _body(*extra):
    factors = [{'key': 'nodes', 'label': 'Nodes online', 'value': '2/2', 'delta': 0, 'severity': 'ok'}] + list(extra)
    score = max(0, 100 + sum(f['delta'] for f in factors))
    return {'score': score, 'band': 'critical' if score < 30 else 'good' if score < 90 else 'excellent',
            'factors': factors, 'issues': [], 'computed_at': '2026-10-29T08:00:00Z'}


ERR = _ceph('HEALTH_ERR', 'critical', 25, ('PG_DAMAGED', 'OSD_DOWN', 'OSD_HOST_DOWN'), delta=-75)
WARN = _ceph('HEALTH_WARN', 'warning', 75, ('OSD_NEARFULL',), delta=-25)
OK = _ceph('HEALTH_OK', 'ok', 100)
UNKNOWN = _ceph(None, 'unknown', 100)
# answered before, has not answered for longer than the server serves an old read
SILENT = dict(_ceph(None, 'warning', 75, delta=-25), value='not answering', silent=True)


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(health=None, layout='modern', language='en', clusters=None):
        extra = dict(SSE_TOKEN)
        if health is not None:
            extra[HEALTH] = health
        app = _App(browser, _FakeServer(role='standalone', layout=layout, language=language,
                                        clusters=clusters or [CLUSTER], resources=[VM], metrics=METRICS,
                                        extra=extra))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _card(app, layout):
    page = app.page
    if layout == 'corporate':
        page.locator('.corp-tree-item', has_text='Testi').first.click()
    else:
        page.get_by_text('Testi').first.click()
    card = page.locator('[data-cluster-health]')
    card.wait_for(timeout=10000)
    card.scroll_into_view_if_needed()
    return card


def _settle(app, call=HEALTH, seconds=4):
    """Until the route was asked and the card had a moment to show the answer."""
    for _ in range(seconds * 10):
        if call in app.server.calls:
            break
        app.page.wait_for_timeout(100)
    app.page.wait_for_timeout(400)


def _number(card, layout):
    sel = 'span.text-\\[13px\\]' if layout == 'corporate' else 'span.text-2xl'
    return card.locator(sel).first.inner_text().strip()


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_health_err_takes_the_card_out_of_excellent(open_app, layout):
    app = open_app(health=(200, _body(ERR)), layout=layout)
    card = _card(app, layout)
    _settle(app)
    text = card.inner_text()
    assert _number(card, layout) == '25' and 'Critical' in text and 'Excellent' not in text, text
    ceph = card.locator('[data-cluster-health-ceph="HEALTH_ERR"]')
    assert ceph.count() == 1
    assert 'HEALTH_ERR' in ceph.inner_text()
    assert 'Held at 25 while Ceph reports HEALTH_ERR' in text
    if layout == 'modern':
        assert 'PG_DAMAGED, OSD_DOWN, OSD_HOST_DOWN' in ceph.inner_text()
    else:
        assert ceph.get_attribute('title') == 'PG_DAMAGED, OSD_DOWN, OSD_HOST_DOWN'
    # what the card shows next to it is still the load of the nodes
    assert '2/2' in text
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_without_ceph_the_card_is_what_it_was(open_app, layout):
    app = open_app(health=(200, _body()), layout=layout)
    card = _card(app, layout)
    _settle(app)
    assert _number(card, layout) == '92' and 'Excellent' in card.inner_text()
    assert card.locator('[data-cluster-health-ceph]').count() == 0
    assert not app.errors, app.errors


def test_runtime_a_route_that_fails_leaves_the_card_as_it_was(open_app):
    app = open_app(health=(500, {'error': 'boom'}))
    card = _card(app, 'modern')
    _settle(app)
    assert _number(card, 'modern') == '92' and 'Excellent' in card.inner_text()
    assert card.locator('[data-cluster-health-ceph]').count() == 0


def test_runtime_health_warn_holds_it_at_good(open_app):
    app = open_app(health=(200, _body(WARN)))
    card = _card(app, 'modern')
    _settle(app)
    text = card.inner_text()
    assert _number(card, 'modern') == '75' and 'Good' in text
    assert 'Ceph HEALTH_WARN' in text and 'OSD_NEARFULL' in text
    assert 'Held at 75 while Ceph reports HEALTH_WARN' in text


def test_runtime_health_ok_and_unknown_change_nothing_but_show(open_app):
    app = open_app(health=(200, _body(OK)))
    card = _card(app, 'modern')
    _settle(app)
    text = card.inner_text()
    assert _number(card, 'modern') == '92' and 'Excellent' in text and 'Ceph HEALTH_OK' in text
    assert 'Held at' not in text

    app = open_app(health=(200, _body(UNKNOWN)))
    card = _card(app, 'modern')
    _settle(app)
    text = card.inner_text()
    assert _number(card, 'modern') == '92' and 'Excellent' in text
    assert card.locator('[data-cluster-health-ceph="unknown"]').inner_text().splitlines()[0].strip() == 'Ceph Unknown'
    assert 'No current Ceph status, not counted' in text


def test_runtime_a_ceph_gone_silent_holds_it_at_good(open_app):
    app = open_app(health=(200, _body(SILENT)))
    card = _card(app, 'modern')
    _settle(app)
    text = card.inner_text()
    assert _number(card, 'modern') == '75' and 'Good' in text and 'Excellent' not in text
    assert 'Ceph has not answered for minutes, held at 75' in text
    assert 'No current Ceph status' not in text


def test_runtime_the_corporate_pill_and_card_share_one_request(open_app):
    app = open_app(health=(200, _body(UNKNOWN)), layout='corporate')
    card = _card(app, 'corporate')
    _settle(app)
    app.page.wait_for_timeout(1500)
    assert app.server.calls.count(HEALTH) == 1, app.server.calls
    assert card.locator('[data-cluster-health-ceph="unknown"]').count() == 1
    # the pill's breakdown says '?' for a factor it has no status for, not 'ok'
    app.page.locator('.corp-content-header span', has_text='health').first.click()
    row = app.page.locator('div.flex.items-center.justify-between', has_text='Ceph').last
    row.wait_for(timeout=3000)
    assert row.inner_text().split() == ['Ceph', 'unknown', '?'], row.inner_text()
    assert not app.errors, app.errors


def test_runtime_a_disconnected_cluster_is_not_asked(open_app):
    app = open_app(health=(200, _body(ERR)), clusters=[dict(CLUSTER, connected=False)])
    page = app.page
    page.get_by_text('Testi').first.click()
    page.wait_for_timeout(2000)
    assert HEALTH not in app.server.calls
    assert not app.errors, app.errors


def test_runtime_it_speaks_german(open_app):
    app = open_app(health=(200, _body(ERR)), language='de')
    card = _card(app, 'modern')
    _settle(app)
    text = card.inner_text()
    assert _number(card, 'modern') == '25' and 'Kritisch' in text
    assert 'Auf 25 begrenzt, solange Ceph HEALTH_ERR meldet' in text
