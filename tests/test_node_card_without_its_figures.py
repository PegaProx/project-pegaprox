"""The Modern node card formats the score and draws CPU and RAM gauges for every node that
is not offline. An entry without those figures (the HA cache answer of /metrics had none)
threw in the render, first on the score and then in the Gauge, and with no error boundary
on that path the dashboard went white while the cluster was out of reach. The card now
shows '-' for a missing score and the gauge an empty ring with '-'.

ui.js and tables.js are compiled with the Babel the repo ships (static/js/babel.min.js) and
NodeCard is drawn through a small hook runtime in node, the components it uses (Gauge,
Sparkline) with it: hooks keep their slots, each child gets its own.
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
const { NodeCard } = new Function('__scope', 'with (__scope) {\n' + code + '\n;return { NodeCard };\n}')(scope);

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
const draw = metrics => {
    hooks = hookRuntime();
    let tree;
    try { tree = deep(NodeCard({ name: 'pve1', metrics, index: 0, clusterId: 'c1' })); }
    catch (e) { return { threw: e.message }; }
    let score = null;
    const gauges = [];
    walk(tree, n => {
        const cls = typeof n.props.className === 'string' ? n.props.className : '';
        if (score === null && cls.includes('font-mono font-bold text-lg')) score = { text: textOf(n), cls };
        if (n.type === 'text' && cls.includes('gauge-text')) gauges.push(textOf(n));
    });
    return { score, gauges };
};
const live = { status: 'online', cpu_percent: 12, mem_percent: 40, mem_used: 4, mem_total: 10, disk_percent: 5,
    disk_used: 1, disk_total: 20, netin: 0, netout: 0, uptime: 100, offline: false };
console.log(JSON.stringify({
    // GET /metrics from the HA cache, as the route built it
    haRoute: draw({ status: 'online', cpu: 0, memory: { used: 0, total: 0 }, disk: { used: 0, total: 0 }, from_ha_cache: true }),
    // the HA cache entries of get_node_status(), which the route hands out now
    haManager: draw(Object.assign({}, live, { cpu_percent: 0, mem_percent: 0, mem_used: 0, mem_total: 0, score: 0,
                                              from_ha_cache: true })),
    nullScore: draw(Object.assign({}, live, { score: null })),
    zero: draw(Object.assign({}, live, { score: 0 })),
    mid: draw(Object.assign({}, live, { score: 123.4 })),
    high: draw(Object.assign({}, live, { score: 170 })),
    text: draw(Object.assign({}, live, { score: '42.6' })),
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
    # what the route answers from the HA cache now: zeros, drawn as zeros
    assert cards['haManager']['score']['text'] == '0' and cards['haManager']['gauges'] == ['0.0%', '0.0%'], cards


def test_no_score_is_not_coloured_as_a_load(cards):
    # undefined < 100 and < 150 are both false, which drew a missing score in the red of a busy node
    for case in ('haRoute', 'nullScore'):
        cls = cards[case]['score']['cls']
        assert not any(c in cls for c in ('text-green-400', 'text-yellow-400', 'text-red-400')), (case, cls)
