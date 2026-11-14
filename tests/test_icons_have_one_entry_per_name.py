"""Every icon in web/src/icons.js has one entry. Network and ChevronDown were each defined
twice in the Icons object; the later entry won, so the first ones were never drawn. They
are gone, and what the screen shows stays the same: the entries that are left are the ones
that won, and they take a className and a style.

The object is parsed with the Babel the repo ships (static/js/babel.min.js) and the icons
are called in node.
"""
import json
import os
import shutil
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BABEL = os.path.join(ROOT, 'static', 'js', 'babel.min.js')
ICONS = os.path.join(ROOT, 'web', 'src', 'icons.js')
WIFI_ARCS = 'M8.111 16.404a5.5 5.5 0 017.778 0'

HARNESS = r"""
const fs = require('fs');
const Babel = require(process.argv[2]);
const src = fs.readFileSync(process.argv[3], 'utf-8');
const { ast, code } = Babel.transform(src, { presets: ['react'], sourceType: 'script', ast: true });
const dups = [];
(function walk(n) {
    if (!n || typeof n.type !== 'string') return;
    if (n.type === 'ObjectExpression') {
        const seen = {};
        for (const p of n.properties) {
            const k = p.key && (p.key.name || p.key.value);
            if (!k) continue;
            if (seen[k]) dups.push({ key: k, lines: [seen[k], p.loc.start.line] }); else seen[k] = p.loc.start.line;
        }
    }
    for (const f of Object.keys(n)) { if (f === 'loc') continue; const v = n[f];
        if (Array.isArray(v)) v.forEach(walk); else if (v && typeof v.type === 'string') walk(v); }
})(ast.program);
const React = { createElement: (type, props, ...children) => ({ type, props: Object.assign({}, props, { children }) }) };
const Icons = new Function('React', code + '\n;return Icons;')(React);
const drawn = name => {
    const svg = Icons[name]({ className: 'w-10 h-10', style: { color: 'red' } });
    return { className: svg.props.className, style: svg.props.style, d: svg.props.children[0].props.d };
};
console.log(JSON.stringify({ dups, network: drawn('Network'), chevron: drawn('ChevronDown'),
                             plain: Icons.Network().props.className }));
"""


@pytest.fixture(scope='module')
def icons(tmp_path_factory):
    if not shutil.which('node'):
        pytest.skip('needs node')
    js = tmp_path_factory.mktemp('icons') / 'icons.js'
    js.write_text(HARNESS, encoding='utf-8')
    out = subprocess.run(['node', str(js), BABEL, ICONS], capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout.strip().splitlines()[-1])


def test_no_icon_is_defined_twice(icons):
    assert not icons['dups'], f"defined more than once, the last one wins: {icons['dups']}"


def test_the_icons_on_screen_stay_as_they_were(icons):
    net = icons['network']
    assert net['className'] == 'w-10 h-10' and net['style'] == {'color': 'red'}, net
    assert net['d'].startswith(WIFI_ARCS), net
    assert icons['plain'] == 'w-4 h-4'
    assert icons['chevron']['className'] == 'w-10 h-10' and icons['chevron']['d'] == 'M19 9l-7 7-7-7'
