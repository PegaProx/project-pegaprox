"""The drift list shows a scope on a node that did not answer as such (#968).

The scanner records it with diff op 'unknown' and the node in 'node-offline'. The list
used to print the raw op and strike the old value through, which reads as a removal.
Runtime tests drive the built bundle in headless Chromium against the fake server of
tests/test_ha_ui.py; they skip where Playwright is not installed.
LW Oct 2026
"""
import os
import re

import pytest

from test_ha_ui import CLUSTER, SSE_TOKEN, VM, _App, _FakeServer, browser  # noqa: F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def _drift_tab_src():
    src = _read('web', 'src', 'dashboard.js')
    start = src.index('function DriftTab(')
    return src[start:src.index('// MK May 2026', start)]


def test_the_label_reuses_a_key_every_language_has_once():
    assert "'unknown': t('nodeOffline')" in _drift_tab_src()
    found = len(re.findall(r'^\s*nodeOffline:', _read('web', 'src', 'translations.js'), re.M))
    assert found == 9


def test_no_em_dash_in_what_this_change_added():
    src = _drift_tab_src()
    start = src.index("// LW Oct 2026 - 'unknown'")
    block = src[start:src.index('const fmtVal', start)]
    row = src[src.index("d.op === 'unknown' && d['node-offline']"):src.index('{fmtVal(d.after)}')]
    for b in (block, row):
        assert '\u2014' not in b and '\u2013' not in b


def test_the_bundle_carries_it():
    assert "'unknown':t('nodeOffline')||'Node offline'" in _read('web', 'index.html')


# --- runtime ---------------------------------------------------------------------------------

UNKNOWN = {'id': 11, 'cluster_id': 'c1', 'kind': 'network', 'scope': 'pve2/vmbr0', 'severity': 'info',
           'summary': 'network pve2/vmbr0: on offline node pve2, presence unknown',
           'detected_at': '2026-10-05T10:00:00', 'status': 'open',
           'diff': [{'path': '*', 'op': 'unknown', 'before': {'iface': 'vmbr0', 'type': 'bridge'},
                     'after': None, 'node-offline': 'pve2'}]}
REMOVED = {'id': 12, 'cluster_id': 'c1', 'kind': 'vm_config', 'scope': 'qemu/205', 'severity': 'warning',
           'summary': 'vm_config qemu/205: object removed', 'detected_at': '2026-10-05T10:00:00',
           'status': 'open',
           'diff': [{'path': '*', 'op': 'removed', 'before': {'cores': 2}, 'after': None}]}
READS = {
    ('GET', '/api/clusters/c1/drift/status'): (200, {
        'cluster_id': 'c1', 'open_total': 2, 'baselines': 9, 'last_event_at': '2026-10-05T10:00:00',
        'by_kind': {'network': {'critical': 0, 'warning': 0, 'info': 1},
                    'vm_config': {'critical': 0, 'warning': 1, 'info': 0}},
        'by_severity': {'critical': 0, 'warning': 1, 'info': 1}}),
    ('GET', '/api/clusters/c1/drift/events'): (200, {'events': [UNKNOWN, REMOVED]}),
}
TAB = {'en': ('Compliance', 'Config Drift Detection'), 'pl': ('Zgodność', 'Wykrywanie zmian konfiguracji')}


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(**kw):
        extra = dict(SSE_TOKEN)
        extra.update(READS)
        kw.setdefault('role', 'standalone')
        app = _App(browser, _FakeServer(clusters=[CLUSTER], resources=[VM], extra=extra, **kw))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _open_drift(app, language='en'):
    page = app.page
    compliance, drift = TAB[language]
    page.get_by_text('Testi').first.click()
    page.locator('button', has_text=re.compile(rf'^\s*{compliance}\s*$')).first.click()
    page.locator('button', has_text=re.compile(rf'^\s*{drift}\s*$')).first.click()
    for scope in ('pve2/vmbr0', 'qemu/205'):
        page.get_by_text(scope).first.click()
    page.get_by_text('{"iface":"vmbr0","type":"bridge"}').first.wait_for(timeout=8000)
    return page


def _diff_rows(page):
    return page.evaluate('''() => Array.from(document.querySelectorAll('div.grid.grid-cols-12'))
        .filter(r => r.children.length === 4)
        .map(r => ({path: r.children[0].innerText.trim(), op: r.children[1].innerText.trim(),
                    struck: getComputedStyle(r.children[2]).textDecorationLine.includes('line-through'),
                    before: r.children[2].innerText.trim()}))''')


@pytest.mark.parametrize('language,label', [('en', 'Node offline'), ('pl', 'Węzeł offline')])
def test_runtime_a_scope_on_an_offline_node_reads_as_such(open_app, language, label):
    app = open_app(layout='modern', language=language)
    page = _open_drift(app, language)
    rows = {r['before']: r for r in _diff_rows(page)}
    unknown = rows['{"iface":"vmbr0","type":"bridge"}']
    assert (unknown['path'], unknown['op'], unknown['struck']) == ('pve2', label, False)
    # a real removal looks as it always did
    removed = rows['{"cores":2}']
    assert removed['path'] == '*' and removed['struck'] is True
    assert removed['op'] != label
    assert not app.errors, app.errors
