"""The Modern node card formats the score and draws CPU and RAM gauges for every node that
is not offline. An entry without those figures (the HA cache answer of /metrics had none)
threw in the render, first on the score and then in the Gauge, and with no error boundary
on that path the dashboard went white while the cluster was out of reach. The card now
shows '-' for a missing score and the gauge an empty ring with '-'.

The HA cache entries /metrics hands out now carry 0 for the score, CPU, RAM, disk and
network, which the card drew as a measured idle node. An entry marked from_ha_cache shows
'-' there too and leaves the disk lines out; a live node at 0 still reads 0. The node
row of classic Corporate (NodeCompactRow) reads the same mark.

ui.js and tables.js are compiled with the Babel the repo ships (static/js/babel.min.js) and
NodeCard and NodeCompactRow are drawn through a small hook runtime in node, the components
they use (Gauge, Sparkline) with them: hooks keep their slots, each child gets its own.
"""
import json
import os
import shutil
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BABEL = os.path.join(ROOT, 'static', 'js', 'babel.min.js')
TABLES = os.path.join(ROOT, 'web', 'src', 'tables.js')
UI = os.path.join(ROOT, 'web', 'src', 'ui.js')

HARNESS = r"""
const fs = require('fs');
const Babel = require(process.argv[2]);
const compile = f => Babel.transform(fs.readFileSync(f, 'utf-8'), { presets: ['react'], sourceType: 'script' }).code;
// ui.js before tables.js, as the bundle has them
const code = compile(process.argv[3]) + '\n' + compile(process.argv[4]);

function hookRuntime() {
    const st = { hooks: [], i: 0 };
    return {
        useState(init) { const k = st.i++; if (!(k in st.hooks)) st.hooks[k] = { v: typeof init === 'function' ? init() : init };
            const h = st.hooks[k]; return [h.v, nv => { h.v = typeof nv === 'function' ? nv(h.v) : nv; }]; },
        useRef(init) { const k = st.i++; if (!(k in st.hooks)) st.hooks[k] = { current: init }; return st.hooks[k]; },
        useEffect() { st.i++; },
        useMemo(fn) { st.i++; return fn(); },
        useCallback(fn) { st.i++; return fn; },
        useContext() { return null; },
        reset() { st.i = 0; },
    };
}
let hooks = hookRuntime();
const React = {
    Fragment: 'Fragment',
    createElement(type, props, ...children) { return { type, props: Object.assign({}, props, { children: children.flat(Infinity) }) }; },
    createContext: () => ({ Provider: 'Provider', Consumer: 'Consumer' }),
    memo: c => c, forwardRef: c => c,
};
for (const n of ['useState', 'useRef', 'useEffect', 'useMemo', 'useCallback', 'useContext'])
    React[n] = (...a) => hooks[n](...a);
// anything another bundle file defines (Icons, ...) is an inert stand-in
const stub = new Proxy(function Stub() {}, {
    get: (t, p) => (p === Symbol.toPrimitive ? () => '' : p === 'then' ? undefined : stub),
    apply: () => stub,
    set: () => true,
});
const provided = { React, useState: React.useState, useRef: React.useRef, useEffect: React.useEffect,
    useMemo: React.useMemo, useCallback: React.useCallback, useContext: React.useContext,
    useTranslation: () => ({ t: k => k }),
    useAuth: () => ({ getAuthHeaders: () => ({}), haReadOnly: false }), API_URL: '/api',
    fetch: () => new Promise(() => {}) };
const scope = new Proxy({}, {
    has: (t, k) => typeof k === 'string' && (k in provided || !(k in globalThis)),
    get: (t, k) => (k === Symbol.unscopables ? undefined : (k in provided ? provided[k] : stub)),
    set: (t, k, v) => { provided[k] = v; return true; },
});
const { NodeCard, NodeCompactRow } = new Function('__scope', 'with (__scope) {\n' + code + '\n;return { NodeCard, NodeCompactRow };\n}')(scope);

// the bundle's own components are drawn too, each with its own hooks
function deep(n) {
    if (Array.isArray(n)) return n.map(deep);
    if (!n || typeof n !== 'object' || !n.props) return n;
    if (typeof n.type === 'function' && n.type !== stub) {
        const outer = hooks;
        hooks = hookRuntime();
        try { return deep(n.type(n.props)); } finally { hooks = outer; }
    }
    return { type: n.type, props: Object.assign({}, n.props, { children: deep(n.props.children) }) };
}
function walk(n, fn) {
    if (!n || typeof n !== 'object') return;
    if (Array.isArray(n)) { n.forEach(c => walk(c, fn)); return; }
    fn(n);
    if (n.props) walk(n.props.children, fn);
}
const textOf = n => (n.props.children || []).map(c => (typeof c === 'string' || typeof c === 'number') ? String(c) : '').join('').trim();
const allText = n => Array.isArray(n) ? n.map(allText).join('')
    : (typeof n === 'string' || typeof n === 'number') ? String(n)
    : (n && typeof n === 'object' && n.props) ? allText(n.props.children || []) : '';
// the label/value lines of the card, by the key of their label
const ROWS = ['ramUsage', 'disk', 'diskUsage', 'networkIn', 'networkOut'];
const draw = (metrics, expand) => {
    hooks = hookRuntime();
    const card = hooks;
    const props = { name: 'pve1', metrics, index: 0, clusterId: 'c1' };
    let tree;
    try {
        tree = deep(NodeCard(props));
        if (expand) {
            // open the details and draw again on the same hooks
            let more = null;
            walk(tree, n => { if (!more && n.type === 'button' && textOf(n) === 'showMore') more = n; });
            more.props.onClick();
            hooks = card; card.reset();
            tree = deep(NodeCard(props));
        }
    }
    catch (e) { return { threw: e.message }; }
    let score = null;
    const gauges = [];
    const rows = {};
    walk(tree, n => {
        const cls = typeof n.props.className === 'string' ? n.props.className : '';
        if (score === null && cls.includes('font-mono font-bold text-lg')) score = { text: textOf(n), cls };
        if (n.type === 'text' && cls.includes('gauge-text')) gauges.push(textOf(n));
        const parts = (n.props.children || []).filter(c => c && typeof c === 'object' && c.props);
        if (n.type === 'div' && parts.length >= 2 && parts[0].type === 'span') {
            const label = allText(parts[0]).trim();
            if (ROWS.includes(label)) rows[label] = allText(parts[parts.length - 1]).trim();
        }
    });
    return { score, gauges, rows };
};
// the classic Corporate row, opened like a click on it does
const drawRow = metrics => {
    hooks = hookRuntime();
    const row = hooks;
    const props = { name: 'pve1', metrics, clusterId: 'c1' };
    let tree;
    try {
        tree = deep(NodeCompactRow(props));
        let head = null;
        walk(tree, n => { if (!head && n.type === 'div' && typeof n.props.onClick === 'function') head = n; });
        head.props.onClick();
        hooks = row; row.reset();
        tree = deep(NodeCompactRow(props));
    }
    catch (e) { return { threw: e.message }; }
    const out = { percents: [], bars: [], score: null, disk: null };
    walk(tree, n => {
        const cls = typeof n.props.className === 'string' ? n.props.className : '';
        const style = n.props.style || {};
        if (n.type === 'span' && cls === 'w-12 text-right') out.percents.push(allText(n).trim());
        if (n.type === 'div' && cls === 'h-full' && ['#49afd9', '#9b59b6'].includes(style.background)) out.bars.push(style.width);
        if (n.type === 'span' && cls === 'ml-3 w-16') out.score = allText(n).trim();
        if (cls === 'corp-node-detail-card') {
            const parts = (n.props.children || []).filter(c => c && typeof c === 'object' && c.props);
            if (allText(parts[0]).trim() === 'disk') out.disk = allText(parts[1]).trim();
        }
    });
    return out;
};
const live = { status: 'online', cpu_percent: 12, mem_percent: 40, mem_used: 4, mem_total: 10, disk_percent: 5,
    disk_used: 1, disk_total: 20, netin: 0, netout: 0, uptime: 100, offline: false };
console.log(JSON.stringify({
    // GET /metrics from the HA cache, as the route built it
    haRoute: draw({ status: 'online', cpu: 0, memory: { used: 0, total: 0 }, disk: { used: 0, total: 0 }, from_ha_cache: true }),
    // the HA cache entries of get_node_status(), which the route hands out now
    haManager: draw(Object.assign({}, live, { cpu_percent: 0, mem_percent: 0, mem_used: 0, mem_total: 0, score: 0,
                                              disk_percent: 0, disk_used: 0, disk_total: 0, from_ha_cache: true }), true),
    // the mark decides, not the zeros
    haWithFigures: draw(Object.assign({}, live, { score: 120, from_ha_cache: true })),
    // a live node that is idle: real zeros
    idle: draw(Object.assign({}, live, { cpu_percent: 0, mem_percent: 0, score: 0, disk_percent: 0 }), true),
    nullScore: draw(Object.assign({}, live, { score: null })),
    zero: draw(Object.assign({}, live, { score: 0 })),
    mid: draw(Object.assign({}, live, { score: 123.4 }), true),
    high: draw(Object.assign({}, live, { score: 170 })),
    text: draw(Object.assign({}, live, { score: '42.6' })),
    rowLive: drawRow(Object.assign({}, live, { score: 123.4 })),
    rowIdle: drawRow(Object.assign({}, live, { cpu_percent: 0, mem_percent: 0, score: 0, disk_percent: 0 })),
    rowHa: drawRow(Object.assign({}, live, { cpu_percent: 0, mem_percent: 0, mem_used: 0, mem_total: 0, score: 0,
                                            disk_percent: 0, disk_used: 0, disk_total: 0, from_ha_cache: true })),
}));
"""


@pytest.fixture(scope='module')
def cards(tmp_path_factory):
    if not shutil.which('node'):
        pytest.skip('needs node')
    js = tmp_path_factory.mktemp('nodecard') / 'nodecard.js'
    js.write_text(HARNESS, encoding='utf-8')
    out = subprocess.run(['node', str(js), BABEL, UI, TABLES], capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout.strip().splitlines()[-1])


def test_a_node_without_its_figures_is_drawn(cards):
    got = cards['haRoute']
    assert 'threw' not in got, got
    assert got['score']['text'] == '-' and got['gauges'] == ['-', '-'], got
    assert cards['nullScore']['score']['text'] == '-', cards['nullScore']
    # a score sent as text is a number all the same, as in the compact row
    assert cards['text']['score']['text'] == '43', cards['text']


def test_a_node_with_its_figures_reads_as_before(cards):
    assert cards['zero']['score']['text'] == '0' and 'text-green-400' in cards['zero']['score']['cls'], cards
    assert cards['mid']['score']['text'] == '123' and 'text-yellow-400' in cards['mid']['score']['cls'], cards
    assert cards['high']['score']['text'] == '170' and 'text-red-400' in cards['high']['score']['cls'], cards
    assert cards['mid']['gauges'] == ['12.0%', '40.0%'], cards['mid']
    # a live node at 0 is drawn as 0
    assert cards['idle']['score']['text'] == '0' and cards['idle']['gauges'] == ['0.0%', '0.0%'], cards['idle']


def test_the_details_of_a_live_node_read_as_before(cards):
    assert cards['mid']['rows'] == {'ramUsage': '4.0 B / 10.0 B', 'disk': '5.0%', 'diskUsage': '1.0 B / 20.0 B',
                                    'networkIn': '0.0 MB/s', 'networkOut': '0.0 MB/s'}, cards['mid']
    # a live disk at 0 keeps its line
    assert cards['idle']['rows']['disk'] == '0.0%', cards['idle']


def test_an_ha_cache_entry_shows_no_figures_it_did_not_read(cards):
    # what the route answers from the HA cache now: zeros that nobody measured
    got = cards['haManager']
    assert 'threw' not in got, got
    assert got['score']['text'] == '-' and got['gauges'] == ['-', '-'], got
    got = cards['haWithFigures']
    assert got['score']['text'] == '-' and got['gauges'] == ['-', '-'], got


def test_an_ha_cache_entry_has_no_ram_disk_or_network_figures(cards):
    got = cards['haManager']
    assert 'threw' not in got, got
    assert got['rows'] == {'ramUsage': '-', 'networkIn': '-', 'networkOut': '-'}, got


def test_no_score_is_not_coloured_as_a_load(cards):
    # undefined < 100 and < 150 are both false, which drew a missing score in the red of a busy node
    for case in ('haRoute', 'haManager', 'nullScore'):
        cls = cards[case]['score']['cls']
        assert not any(c in cls for c in ('text-green-400', 'text-yellow-400', 'text-red-400')), (case, cls)


def test_the_classic_corporate_row_of_a_live_node_reads_as_before(cards):
    got = cards['rowLive']
    assert got == {'percents': ['12.0%', '40.0%'], 'bars': ['12%', '40%'], 'score': 'score: 123.4', 'disk': '5.0%'}, got
    got = cards['rowIdle']
    assert got == {'percents': ['0.0%', '0.0%'], 'bars': ['0%', '0%'], 'score': 'score: 0.0', 'disk': '0.0%'}, got


def test_the_classic_corporate_row_of_an_ha_cache_entry_shows_no_figures(cards):
    got = cards['rowHa']
    assert 'threw' not in got, got
    assert got == {'percents': ['-', '-'], 'bars': ['0%', '0%'], 'score': None, 'disk': '-'}, got
