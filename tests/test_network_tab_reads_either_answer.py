"""The Networks tab lists the networks of an XCP-ng pool.

The tab read data.networks only, and an XCP-ng pool answered /networks with the bare list,
so it drew "no network data" for every pool. The server answers {'networks': [...]} now;
the tab takes either shape, so an answer in the old one still lists.

networking.js is compiled with the Babel the repo ships (static/js/babel.min.js) and
NetworkTab is drawn through a small hook runtime in node, once in the corporate and once
in the modern layout.
"""
import json
import os
import shutil
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BABEL = os.path.join(ROOT, 'static', 'js', 'babel.min.js')
NETWORKING = os.path.join(ROOT, 'web', 'src', 'networking.js')
POOL_NET = 'Pool-wide network associated with eth0'

HARNESS = r"""
const fs = require('fs');
const Babel = require(process.argv[2]);
const code = Babel.transform(fs.readFileSync(process.argv[3], 'utf-8'), { presets: ['react'], sourceType: 'script' }).code;
const payloads = JSON.parse(process.argv[4]);

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
async function draw(payload, isCorporate) {
    const R = miniReact();
    const provided = { React: R, useState: R.useState, useRef: R.useRef, useEffect: R.useEffect, useMemo: R.useMemo,
        API_URL: '/api', useTranslation: () => ({ t: k => k }),
        useAuth: () => ({ getAuthHeaders: () => ({}), isAdmin: true }), useLayout: () => ({ isCorporate }),
        fetch: async () => ({ ok: true, json: async () => payload }) };
    const scope = new Proxy({}, {
        has: (t, k) => typeof k === 'string' && (k in provided || !(k in globalThis)),
        get: (t, k) => (k === Symbol.unscopables ? undefined : (k in provided ? provided[k] : stub)),
    });
    const NetworkTab = new Function('__scope', 'with (__scope) {\n' + code + '\n;return NetworkTab;\n}')(scope);
    R.render(NetworkTab, { clusterId: 'c1' });
    await new Promise(r => setTimeout(r, 30));     // the /networks answer
    const shown = texts(R.render(NetworkTab, { clusterId: 'c1' }));
    return { empty: shown.includes('noNetworkData'), shown };
}
(async () => {
    const out = {};
    for (const [name, payload] of Object.entries(payloads))
        out[name] = { corporate: await draw(payload, true), modern: await draw(payload, false) };
    console.log(JSON.stringify(out));
})().catch(e => { console.error(e && e.stack || e); process.exit(3); });
"""

XCP_ROW = {'name': POOL_NET, 'bridge': 'xenbr0', 'uuid': 'u1', 'vif_count': 3, 'pif_count': 2, 'mtu': 1500}
PAYLOADS = {
    # what XcpngManager.get_cluster_networks answers now
    'xcpng': {'networks': [dict(XCP_ROW, active=1, nodes=[], vms=[])], 'storage_assignments': []},
    # the bare list it answered before
    'xcpngBareList': [XCP_ROW],
    'proxmox': {'networks': [{'name': 'vmbr0', 'type': 'bridge', 'active': 1, 'vms': [], 'nodes': ['pve1']}],
                'storage_assignments': []},
    'nothing': {'networks': []},
}


@pytest.fixture(scope='module')
def drawn(tmp_path_factory):
    if not shutil.which('node'):
        pytest.skip('needs node')
    js = tmp_path_factory.mktemp('networktab') / 'networktab.js'
    js.write_text(HARNESS, encoding='utf-8')
    out = subprocess.run(['node', str(js), BABEL, NETWORKING, json.dumps(PAYLOADS)],
                         capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout.strip().splitlines()[-1])


@pytest.mark.parametrize('layout', ['corporate', 'modern'])
def test_the_tab_draws_a_proxmox_cluster_and_says_when_there_is_nothing(drawn, layout):
    assert not drawn['proxmox'][layout]['empty'] and 'vmbr0' in drawn['proxmox'][layout]['shown']
    assert drawn['nothing'][layout]['empty']


@pytest.mark.parametrize('layout', ['corporate', 'modern'])
@pytest.mark.parametrize('answer', ['xcpng', 'xcpngBareList'])
def test_the_tab_lists_the_networks_of_an_xcpng_pool(drawn, answer, layout):
    got = drawn[answer][layout]
    assert not got['empty'], (answer, layout, got)
    assert POOL_NET in got['shown'], (answer, layout, got)
