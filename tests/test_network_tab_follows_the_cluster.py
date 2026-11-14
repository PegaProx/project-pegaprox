"""The Networks tab shows the networks of the cluster it is on, with one of them picked.

After a cluster switch the load still saw the network picked on the cluster before and
kept that name, so a cluster without a network of that name drew an empty detail pane. A
refresh after the picked network went away did the same. And an answer that came in late
filled the tab whatever it was for: the answer of the cluster before a switch, arriving
after the new one, put that cluster's networks under the new one.

networking.js is compiled with the Babel the repo ships (static/js/babel.min.js) and
NetworkTab is drawn through a small hook runtime in node, with a /networks that answers
when the test says so.
"""
import json
import os
import shutil
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BABEL = os.path.join(ROOT, 'static', 'js', 'babel.min.js')
NETWORKING = os.path.join(ROOT, 'web', 'src', 'networking.js')

HARNESS = r"""
const fs = require('fs');
const Babel = require(process.argv[2]);
const code = Babel.transform(fs.readFileSync(process.argv[3], 'utf-8'), { presets: ['react'], sourceType: 'script' }).code;

function miniReact() {
    const st = { hooks: [], i: 0, effects: [], cleanups: {} };
    const changed = (prev, deps) => !prev || !deps || deps.length !== prev.deps.length || deps.some((d, j) => !Object.is(d, prev.deps[j]));
    const R = {
        Fragment: 'Fragment',
        createElement(type, props, ...children) { return { type, props: Object.assign({}, props, { children: children.flat(Infinity) }) }; },
        useState(init) { const k = st.i++; if (!(k in st.hooks)) st.hooks[k] = { v: typeof init === 'function' ? init() : init };
            const h = st.hooks[k]; return [h.v, nv => { h.v = typeof nv === 'function' ? nv(h.v) : nv; }]; },
        useRef(init) { const k = st.i++; if (!(k in st.hooks)) st.hooks[k] = { current: init }; return st.hooks[k]; },
        useEffect(fn, deps) { const k = st.i++; if (changed(st.hooks[k], deps)) { st.hooks[k] = { deps }; st.effects.push([k, fn]); } },
        useMemo(fn, deps) { const k = st.i++; if (changed(st.hooks[k], deps)) st.hooks[k] = { deps, v: fn() }; return st.hooks[k].v; },
    };
    R.render = (Comp, props) => {
        st.i = 0; st.effects = [];
        const out = Comp(props);
        for (const [k, fn] of st.effects) { const c = st.cleanups[k]; if (typeof c === 'function') c(); st.cleanups[k] = fn(); }
        return out;
    };
    return R;
}
const stub = new Proxy(function Stub() {}, {
    get: (t, p) => (p === Symbol.toPrimitive ? () => '' : p === 'then' ? undefined : stub),
    apply: () => stub,
});
function texts(node, out = []) {
    if (Array.isArray(node)) { node.forEach(n => texts(n, out)); return out; }
    if (!node || typeof node !== 'object') return out;
    (node.props.children || []).forEach(c => { if (typeof c === 'string') out.push(c); else texts(c, out); });
    return out;
}
function find(node, pred) {
    if (Array.isArray(node)) { for (const n of node) { const hit = find(n, pred); if (hit) return hit; } return null; }
    if (!node || typeof node !== 'object') return null;
    if (pred(node)) return node;
    return find(node.props.children || [], pred);
}
const tick = () => new Promise(r => setTimeout(r, 0));
const net = name => ({ name, type: 'bridge', active: 1, vms: [], nodes: ['pve1'] });

function tab(isCorporate) {
    const R = miniReact();
    const pending = [];
    const provided = { React: R, useState: R.useState, useRef: R.useRef, useEffect: R.useEffect, useMemo: R.useMemo,
        API_URL: '/api', useTranslation: () => ({ t: k => k }),
        useAuth: () => ({ getAuthHeaders: () => ({}), isAdmin: true }), useLayout: () => ({ isCorporate }),
        fetch: url => new Promise(res => pending.push({ url, res })) };
    const scope = new Proxy({}, {
        has: (t, k) => typeof k === 'string' && (k in provided || !(k in globalThis)),
        get: (t, k) => (k === Symbol.unscopables ? undefined : (k in provided ? provided[k] : stub)),
    });
    const NetworkTab = new Function('__scope', 'with (__scope) {\n' + code + '\n;return NetworkTab;\n}')(scope);
    let tree, cluster;
    const me = {
        show(clusterId) { cluster = clusterId; tree = R.render(NetworkTab, { clusterId }); return me; },
        // the oldest open /networks call of that cluster answers
        async answer(clusterId, names) {
            const i = pending.findIndex(p => p.url === `/api/clusters/${clusterId}/networks`);
            if (i < 0) throw new Error('no open call for ' + clusterId);
            pending.splice(i, 1)[0].res({ ok: true, json: async () => ({ networks: names.map(net), storage_assignments: [] }) });
            await tick();
            return me.show(cluster);
        },
        pick(name) {
            find(tree, n => n.props.onClick && String(n.props.className || '').includes('cursor-pointer')
                && texts(n).includes(name)).props.onClick();
            return me.show(cluster);
        },
        refresh() { find(tree, n => n.type === 'button' && n.props.title === 'refreshData').props.onClick(); return me.show(cluster); },
        // the networks listed and the one the detail pane shows (corporate)
        state() {
            const header = find(tree, n => n.props.className === 'corp-content-header');
            const listed = [];
            const rows = n => { if (Array.isArray(n)) return n.forEach(rows); if (!n || typeof n !== 'object') return;
                if (n.props.className === 'flex-1 truncate' || n.props.className === 'font-medium text-white') listed.push(texts(n).join(''));
                rows(n.props.children || []); };
            rows(tree);
            return { listed: [...new Set(listed)], selected: header ? texts(header).join('') : null };
        },
    };
    return me;
}

(async () => {
    const out = {};

    // picked on c1, then a switch to a cluster without that network
    let t = tab(true).show('c1');
    await t.answer('c1', ['vmbr0', 'vmbr9']);
    out.firstLoad = t.state();
    t.pick('vmbr9');
    out.picked = t.state();
    t.show('c2');
    await t.answer('c2', ['vmbr0', 'vmbr1']);
    out.switchedAway = t.state();

    // the same with a cluster that has a network of that name
    t = tab(true).show('c1');
    await t.answer('c1', ['vmbr0', 'vmbr9']);
    t.pick('vmbr9');
    t.show('c3');
    await t.answer('c3', ['vmbr1', 'vmbr9']);
    out.switchedToSameName = t.state();

    // a refresh that still lists the pick, and one that does not
    t = tab(true).show('c1');
    await t.answer('c1', ['vmbr0', 'vmbr9']);
    t.pick('vmbr9');
    t.refresh();
    await t.answer('c1', ['vmbr0', 'vmbr9']);
    out.refreshKeeps = t.state();
    t.refresh();
    await t.answer('c1', ['vmbr0', 'vmbr5']);
    out.refreshPickGone = t.state();

    // the answer of the cluster before the switch comes in after the new one
    for (const [layout, corp] of [['corporate', true], ['modern', false]]) {
        t = tab(corp).show('c1');
        t.show('c2');
        await t.answer('c2', ['vmbr20', 'vmbr21']);
        out['lateAnswer_' + layout] = t.state();
        await t.answer('c1', ['vmbr10', 'vmbr11']);
        out['lateAnswerAfter_' + layout] = t.state();
    }
    console.log(JSON.stringify(out));
})().catch(e => { console.error(e && e.stack || e); process.exit(3); });
"""


@pytest.fixture(scope='module')
def tabs(tmp_path_factory):
    if not shutil.which('node'):
        pytest.skip('needs node')
    js = tmp_path_factory.mktemp('networktabswitch') / 'networktabswitch.js'
    js.write_text(HARNESS, encoding='utf-8')
    out = subprocess.run(['node', str(js), BABEL, NETWORKING], capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout.strip().splitlines()[-1])


def test_the_first_load_and_a_pick_select_as_before(tabs):
    assert tabs['firstLoad']['selected'] == 'vmbr0', tabs['firstLoad']
    assert tabs['picked']['selected'] == 'vmbr9', tabs['picked']


def test_a_switch_to_a_cluster_without_the_picked_network_selects_its_first(tabs):
    got = tabs['switchedAway']
    assert 'vmbr0' in got['listed'] and 'vmbr1' in got['listed'], got
    assert got['selected'] == 'vmbr0', got


def test_a_switch_keeps_a_pick_the_new_cluster_has_too(tabs):
    assert tabs['switchedToSameName']['selected'] == 'vmbr9', tabs['switchedToSameName']


def test_a_refresh_keeps_the_pick_while_the_list_has_it(tabs):
    assert tabs['refreshKeeps']['selected'] == 'vmbr9', tabs['refreshKeeps']
    got = tabs['refreshPickGone']
    assert got['selected'] == 'vmbr0', got


@pytest.mark.parametrize('layout', ['corporate', 'modern'])
def test_a_late_answer_of_the_cluster_before_is_dropped(tabs, layout):
    before = tabs['lateAnswer_' + layout]
    after = tabs['lateAnswerAfter_' + layout]
    assert 'vmbr20' in before['listed'], before
    assert after['listed'] == before['listed'], (before, after)
    assert not any(n.startswith('vmbr1') for n in after['listed']), after
    if layout == 'corporate':
        assert after['selected'] == 'vmbr20', after
