"""The world map keeps its pan inside the map in the state, not only on screen.

A drag stored the pan as it was dragged and only the drawing clamped it, so after a drag
past an edge the state lay beyond it: the map stood still at the edge, and the drag back
moved nothing until that overshoot was used up. A zoom out (button or wheel) at an edge
left the same overshoot behind.

worldmap.js is compiled with the Babel the repo ships (static/js/babel.min.js) and
WorldMap is driven through a small hook runtime in node. Every case drags 100 px back
from an edge and expects the map to follow at once.
"""
import json
import os
import shutil
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BABEL = os.path.join(ROOT, 'static', 'js', 'babel.min.js')
WORLDMAP = os.path.join(ROOT, 'web', 'src', 'worldmap.js')

HARNESS = r"""
const fs = require('fs');
const Babel = require(process.argv[2]);
const code = Babel.transform(fs.readFileSync(process.argv[3], 'utf-8'), { presets: ['react'], sourceType: 'script' }).code;
const rect = { left: 0, top: 0, width: 1000, height: 500 };
const listeners = {};
// the container div: React hands it to the ref before the effects run
const element = { getBoundingClientRect: () => rect, addEventListener: (t, fn) => { listeners[t] = fn; }, removeEventListener() {} };

function miniReact() {
    const st = { hooks: [], i: 0, effects: [], cleanups: {} };
    const changed = (prev, deps) => !prev || !deps || deps.length !== prev.deps.length || deps.some((d, j) => !Object.is(d, prev.deps[j]));
    const R = {
        Fragment: 'Fragment',
        createElement(type, props, ...children) {
            if (props && props.ref && typeof props.ref === 'object' && !props.ref.current) props.ref.current = element;
            return { type, props: Object.assign({}, props, { children: children.flat(Infinity) }) };
        },
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
const R = miniReact();
const provided = { React: R, useState: R.useState, useRef: R.useRef, useEffect: R.useEffect, useMemo: R.useMemo,
    useTranslation: () => ({ t: k => k }),
    fetch: async () => ({ ok: true, text: async () => '<svg viewBox="0 0 1000 500"></svg>' }) };
const scope = new Proxy({}, {
    has: (t, k) => typeof k === 'string' && (k in provided || !(k in globalThis)),
    get: (t, k) => (k === Symbol.unscopables ? undefined : (k in provided ? provided[k] : stub)),
});
const WorldMap = new Function('__scope', 'with (__scope) {\n' + code + '\n;return WorldMap;\n}')(scope);

let tree;
const draw = () => { tree = R.render(WorldMap, { clusters: [] }); };
const find = pred => { let hit = null; const walk = n => { if (!n || typeof n !== 'object' || hit) return;
    if (Array.isArray(n)) return n.forEach(walk); if (pred(n)) hit = n; walk(n.props.children); }; walk(tree); return hit; };
const view = () => find(n => n.type === 'svg' && n.props.viewBox).props.viewBox.split(' ').map(Number);
const click = title => { find(n => n.type === 'button' && n.props.title === title).props.onClick(); draw(); };
const drag = (from, to) => {
    tree.props.onMouseDown({ clientX: from, clientY: 250 }); draw();
    tree.props.onMouseMove({ clientX: to, clientY: 250 }); draw();
    tree.props.onMouseUp(); draw();
};
// 100 px back to the left from where the map stands, and how far its view moved
const dragBack = () => { const [x0, , w] = view(); drag(500, 400); return { want: 100 / rect.width * w, moved: view()[0] - x0 }; };

(async () => {
    draw();
    await new Promise(r => setTimeout(r, 30));     // the country SVG arrives
    draw();
    const out = {};
    click('zoomIn');                               // 1.5x
    out.control = dragBack();                      // inside the bounds
    click('resetZoom'); click('zoomIn');
    drag(500, 1000);                               // half the width past the left edge
    out.afterDragPastEdge = dragBack();
    click('resetZoom'); click('zoomIn'); click('zoomIn');   // 2.25x
    drag(500, 1125);                               // exactly onto the left edge
    click('zoomOut');                              // 1.5x: the edge comes nearer
    out.afterZoomOut = dragBack();
    click('resetZoom'); click('zoomIn'); click('zoomIn');
    drag(500, 1125);
    listeners.wheel({ deltaY: 100, clientX: 1000, clientY: 250, preventDefault() {} });   // wheel out at the far side
    draw();
    out.afterWheelOut = dragBack();
    console.log(JSON.stringify(out));
})().catch(e => { console.error(e && e.stack || e); process.exit(3); });
"""


@pytest.fixture(scope='module')
def moves(tmp_path_factory):
    if not shutil.which('node'):
        pytest.skip('needs node')
    js = tmp_path_factory.mktemp('worldmap') / 'worldmap.js'
    js.write_text(HARNESS, encoding='utf-8')
    out = subprocess.run(['node', str(js), BABEL, WORLDMAP], capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout.strip().splitlines()[-1])


def _follows(case):
    return case['want'] > 0 and abs(case['moved'] - case['want']) < 1e-6


def test_a_drag_inside_the_bounds_moves_the_map(moves):
    assert _follows(moves['control']), moves['control']


@pytest.mark.parametrize('case', ['afterDragPastEdge', 'afterZoomOut', 'afterWheelOut'])
def test_the_drag_back_from_an_edge_moves_at_once(moves, case):
    assert _follows(moves[case]), (case, moves[case])
