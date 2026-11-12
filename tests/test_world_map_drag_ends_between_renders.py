"""A drag of the world map that ends before its last move was rendered.

The drag updater read the drag start from dragRef when React ran it. The app mounts with
ReactDOM.render, which renders each mousemove at the end of its own event, so the ref was
still set then. A deferred render, as a createRoot root does, can run the updater after the
mouseup has set the ref to null, and the render threw. The handler reads the start once now
and the updater only uses that, so it no longer depends on when it is run.

worldmap.js is compiled with the Babel the repo ships (static/js/babel.min.js) and
WorldMap is driven through a small hook runtime in node. It defers renders like a
createRoot root: the first set after a render is worked out at once, every further one
waits for the next render.
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
const element = { getBoundingClientRect: () => rect, addEventListener() {}, removeEventListener() {} };

function miniReact() {
    const st = { hooks: [], i: 0, effects: [], cleanups: {} };
    const changed = (prev, deps) => !prev || !deps || deps.length !== prev.deps.length || deps.some((d, j) => !Object.is(d, prev.deps[j]));
    const R = {
        Fragment: 'Fragment',
        createElement(type, props, ...children) {
            if (props && props.ref && typeof props.ref === 'object' && !props.ref.current) props.ref.current = element;
            return { type, props: Object.assign({}, props, { children: children.flat(Infinity) }) };
        },
        // deferred like a createRoot root: the first set after a render is worked out at
        // once, every further one waits in the queue and the next render runs it
        useState(init) {
            const k = st.i++;
            if (!(k in st.hooks)) st.hooks[k] = { v: typeof init === 'function' ? init() : init, queue: [] };
            const h = st.hooks[k];
            for (const u of h.queue.splice(0)) h.v = typeof u === 'function' ? u(h.v) : u;
            return [h.v, nv => {
                if (!st.pending && typeof nv === 'function') nv = nv(h.v);
                st.pending = true;
                h.queue.push(nv);
            }];
        },
        useRef(init) { const k = st.i++; if (!(k in st.hooks)) st.hooks[k] = { current: init }; return st.hooks[k]; },
        useEffect(fn, deps) { const k = st.i++; if (changed(st.hooks[k], deps)) { st.hooks[k] = { deps }; st.effects.push([k, fn]); } },
        useMemo(fn, deps) { const k = st.i++; if (changed(st.hooks[k], deps)) st.hooks[k] = { deps, v: fn() }; return st.hooks[k].v; },
    };
    R.render = (Comp, props) => {
        st.i = 0; st.effects = []; st.pending = false;
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
const viewX = () => Number(find(n => n.type === 'svg' && n.props.viewBox).props.viewBox.split(' ')[0]);
const viewW = () => Number(find(n => n.type === 'svg' && n.props.viewBox).props.viewBox.split(' ')[2]);
const click = title => { find(n => n.type === 'button' && n.props.title === title).props.onClick(); draw(); };

// press at 500, move to each x without a render in between, let go, then render once
function drag(moves, renderEachMove) {
    const x0 = viewX(), w = viewW();
    tree.props.onMouseDown({ clientX: 500, clientY: 250 }); draw();
    for (const x of moves) {
        tree.props.onMouseMove({ clientX: x, clientY: 250 });
        if (renderEachMove) draw();
    }
    tree.props.onMouseUp();
    try { draw(); } catch (e) { return { threw: String(e && e.message || e) }; }
    return { want: (500 - moves[moves.length - 1]) / rect.width * w, moved: viewX() - x0 };
}

(async () => {
    draw();
    await new Promise(r => setTimeout(r, 30));     // the country SVG arrives
    draw();
    const out = {};
    click('zoomIn');                               // 1.5x, room to drag both ways
    out.renderedEachMove = drag([460, 420], true);
    click('resetZoom'); click('zoomIn');
    out.twoMovesThenUp = drag([460, 420], false);
    click('resetZoom'); click('zoomIn');
    out.oneMoveThenUp = drag([440], false);
    // a move after the mouseup is no drag
    const x0 = viewX();
    tree.props.onMouseMove({ clientX: 100, clientY: 250 });
    draw();
    out.moveAfterUp = { moved: viewX() - x0 };
    console.log(JSON.stringify(out));
})().catch(e => { console.error(e && e.stack || e); process.exit(3); });
"""


@pytest.fixture(scope='module')
def drags(tmp_path_factory):
    if not shutil.which('node'):
        pytest.skip('needs node')
    js = tmp_path_factory.mktemp('worldmapdrag') / 'worldmapdrag.js'
    js.write_text(HARNESS, encoding='utf-8')
    out = subprocess.run(['node', str(js), BABEL, WORLDMAP], capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout.strip().splitlines()[-1])


def _follows(case):
    return 'threw' not in case and case['want'] > 0 and abs(case['moved'] - case['want']) < 1e-6


def test_a_drag_rendered_move_by_move_follows_the_mouse(drags):
    assert _follows(drags['renderedEachMove']), drags['renderedEachMove']


@pytest.mark.parametrize('case', ['twoMovesThenUp', 'oneMoveThenUp'])
def test_a_drag_that_ends_before_the_render_draws_its_last_move(drags, case):
    got = drags[case]
    assert 'threw' not in got, (case, got)
    assert _follows(got), (case, got)


def test_a_move_after_the_mouseup_leaves_the_map(drags):
    assert drags['moveAfterUp']['moved'] == 0, drags['moveAfterUp']
