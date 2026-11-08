"""#743 - a "System" entry in the theme picker that follows the OS
light/dark preference and switches live, without a reload.

The shape is the reporter's: `system` is an ordinary theme value, so the server
whitelist, session restore and the picker need no special casing, and it resolves
to a concrete palette in exactly ONE place. Corporate resolves to
corporateLight/corporateDark; every other layout to corporateLight/proxmoxDark,
because corporateLight is the only light palette the frontend defines.

These tests execute the SHIPPED functions out of index.html.original in node,
against a fake matchMedia/localStorage/document. Retyping the resolution here
would pass against a broken build, which is the one thing the test must not do.
"""
import json
import os
import shutil
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHELL = os.path.join(ROOT, 'web', 'index.html.original')
BUILT = os.path.join(ROOT, 'web', 'index.html')

HARNESS = r"""
const fs = require('fs');
const src = fs.readFileSync(process.argv[2], 'utf-8');

// the shipped pieces: the palette table, the resolver, applyTheme and the boot
// block that subscribes to the media query
function slice(startMark, endMark) {
    const a = src.indexOf(startMark);
    if (a < 0) throw new Error('not found: ' + startMark);
    const b = src.indexOf(endMark, a);
    if (b < 0) throw new Error('no end for: ' + startMark);
    return src.slice(a, b + endMark.length);
}
const themes   = slice('const PEGAPROX_THEMES = {', '\n        };\n');
const hexToRgb = slice('function hexToRgb(hex) {', '\n        }\n');
const resolver = slice('function resolveSystemTheme() {', '\n        }\n');
const apply    = slice('function applyTheme(themeName) {', '\n        }\n');
const boot     = slice("(function() {\n            const saved = localStorage.getItem('pegaprox-theme')",
                       '\n        })();\n');

const jobs = JSON.parse(process.argv[3]);
const out = {};
for (const [name, job] of Object.entries(jobs)) {
    const store = Object.assign({}, job.store || {});
    const body = {classList: {_s: new Set(),
                              add(c) { this._s.add(c); }, remove(c) { this._s.delete(c); },
                              has(c) { return this._s.has(c); }},
                  dataset: {layout: job.layout || 'modern'}};
    const rootStyle = {_p: {}, setProperty(k, v) { this._p[k] = v; }};
    // a real media state the fake queries read on every call, so a later flip is
    // visible to code that re-queries - which is what resolveSystemTheme does
    const media = {light: !!job.prefersLight, none: !!job.noPreference};
    const listeners = [];
    const win = {
        matchMedia: (q) => {
            const wantsLight = q.indexOf('light') >= 0;
            return {
                get matches() {
                    if (media.none) return false;           // browser has no preference
                    return wantsLight ? media.light : !media.light;
                },
                addEventListener: (_e, fn) => listeners.push(fn),
                addListener: (fn) => listeners.push(fn),
            };
        },
    };
    const doc = {body, documentElement: {style: rootStyle}, readyState: 'complete',
                 addEventListener: () => {}};
    const ls = {getItem: (k) => (k in store ? store[k] : null),
                setItem: (k, v) => { store[k] = String(v); },
                removeItem: (k) => { delete store[k]; }};
    const con = {log(){}, warn(){}, error(){}};

    const source = themes + '\n' + hexToRgb + '\n' + resolver + '\n' + apply +
                   (job.boot ? '\n' + boot : '') +
                   '\nreturn {applyTheme, resolveSystemTheme, THEMES: PEGAPROX_THEMES};';
    const api = new Function('window', 'document', 'localStorage', 'console', source)(win, doc, ls, con);
    if (job.apply !== undefined) api.applyTheme(job.apply);

    const snap = () => ({
        resolved: api.resolveSystemTheme(),
        stored: store['pegaprox-theme'] === undefined ? null : store['pegaprox-theme'],
        primary: rootStyle._p['--color-primary'] || null,
        darker: rootStyle._p['--color-darker'] || null,
        light: body.classList.has('light-theme'),
        dark: body.classList.has('dark-theme'),
        corpTheme: body.dataset.corpTheme === undefined ? '<unset>' : body.dataset.corpTheme,
        inPicker: Object.prototype.hasOwnProperty.call(api.THEMES, 'system'),
        cardColors: api.THEMES.system ? !!(api.THEMES.system.colors || {}).darker : false,
    });
    const before = snap();
    let after = null;
    if (job.flipTo !== undefined) {
        media.light = !!job.flipTo;
        media.none = false;
        listeners.forEach(fn => fn({matches: media.light}));
        after = snap();
    }
    out[name] = Object.assign(before, {subscribers: listeners.length, after});
}
console.log(JSON.stringify(out));
"""


@pytest.fixture(scope='module')
def run():
    if not shutil.which('node'):
        pytest.skip('node is needed to run the shipped theme code')
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '_theme743_harness.js')
    with open(path, 'w', encoding='utf-8') as fh:
        fh.write(HARNESS)

    def _run(jobs, source=SHELL):
        p = subprocess.run(['node', path, source, json.dumps(jobs)],
                           capture_output=True, text=True, timeout=30)
        assert p.returncode == 0, p.stderr
        return json.loads(p.stdout)
    try:
        yield _run
    finally:
        os.remove(path)


# --- the resolution ----------------------------------------------------------

def test_a_light_desktop_gets_the_light_palette(run):
    got = run({'modern': {'prefersLight': True, 'layout': 'modern', 'apply': 'system'},
               'corp':   {'prefersLight': True, 'layout': 'corporate', 'apply': 'system'}})
    assert got['modern']['resolved'] == 'corporateLight'
    assert got['corp']['resolved'] == 'corporateLight'
    assert got['modern']['light'] is True and got['modern']['dark'] is False


def test_a_dark_desktop_keeps_each_layout_on_its_own_dark_palette(run):
    """corporateDark for Corporate, proxmoxDark everywhere else - swapping those
    two would hand Corporate the orange chrome it deliberately does not use."""
    got = run({'modern': {'prefersLight': False, 'layout': 'modern', 'apply': 'system'},
               'cloud':  {'prefersLight': False, 'layout': 'cloud', 'apply': 'system'},
               'corp':   {'prefersLight': False, 'layout': 'corporate', 'apply': 'system'}})
    assert got['modern']['resolved'] == 'proxmoxDark'
    assert got['cloud']['resolved'] == 'proxmoxDark'
    assert got['corp']['resolved'] == 'corporateDark'
    assert got['corp']['dark'] is True and got['corp']['light'] is False


def test_no_preference_at_all_stays_dark(run):
    """A browser that answers neither query must not flip the app to light."""
    got = run({'none': {'noPreference': True, 'layout': 'modern', 'apply': 'system'}})
    assert got['none']['resolved'] == 'proxmoxDark', got


def test_the_palette_really_lands_on_the_page(run):
    """Resolving is not enough - the CSS variables have to be the resolved ones."""
    light = run({'x': {'prefersLight': True, 'layout': 'modern', 'apply': 'system'}})['x']
    dark = run({'x': {'prefersLight': False, 'layout': 'modern', 'apply': 'system'}})['x']
    assert light['darker'] == '#ffffff', light
    assert dark['darker'] != light['darker'], dark


# --- what gets remembered ----------------------------------------------------

def test_the_choice_is_remembered_as_system_not_as_what_it_resolved_to(run):
    """Storing the resolved palette would freeze the app at whatever the OS was
    on the day the user picked it - the next OS switch would do nothing."""
    got = run({'x': {'prefersLight': True, 'layout': 'modern', 'apply': 'system'}})['x']
    assert got['stored'] == 'system', got


def test_an_explicit_theme_is_still_stored_as_itself(run):
    got = run({'x': {'prefersLight': True, 'layout': 'modern', 'apply': 'forest'}})['x']
    assert got['stored'] == 'forest'


def test_an_unknown_theme_falls_back_without_storing_nonsense(run):
    got = run({'x': {'prefersLight': False, 'layout': 'modern', 'apply': 'nope'}})['x']
    assert got['stored'] == 'proxmoxDark'


# --- the picker --------------------------------------------------------------

def test_system_is_an_ordinary_entry_in_the_theme_table(run):
    """Both pickers iterate PEGAPROX_THEMES and read theme.colors for the swatch;
    an entry without colours would throw while rendering the grid."""
    got = run({'x': {'prefersLight': False, 'layout': 'modern'}})['x']
    assert got['inPicker'] is True
    assert got['cardColors'] is True


def test_the_card_previews_what_it_would_resolve_to(run):
    light = run({'x': {'prefersLight': True, 'layout': 'modern'}})['x']
    dark = run({'x': {'prefersLight': False, 'layout': 'modern'}})['x']
    assert light['cardColors'] and dark['cardColors']
    # and the two differ, otherwise the card is lying to one of them
    l = run({'x': {'prefersLight': True, 'layout': 'modern', 'apply': 'system'}})['x']
    d = run({'x': {'prefersLight': False, 'layout': 'modern', 'apply': 'system'}})['x']
    assert l['darker'] != d['darker']


# --- live switching + the built bundle ---------------------------------------

def test_a_later_os_switch_repaints_without_a_reload(run):
    """The boot block is executed here, its media listener is fired, and the palette
    is read again. Grepping for addEventListener would pass against a subscription
    that is registered and never called."""
    got = run({'x': {'prefersLight': False, 'layout': 'modern', 'boot': True,
                     'store': {'pegaprox-theme': 'system'}, 'flipTo': True}})['x']
    assert got['subscribers'] >= 1, 'nothing subscribed to the media query'
    assert got['darker'] != got['after']['darker'], (
        f"palette unchanged after the OS flipped: {got['darker']} -> {got['after']['darker']}")
    assert got['after']['light'] is True
    assert got['after']['stored'] == 'system'


def test_an_explicit_theme_is_not_yanked_around_by_the_os(run):
    """Only a stored `system` may repaint. Someone who picked Forest keeps Forest
    when their desktop switches at sunset."""
    got = run({'x': {'prefersLight': False, 'layout': 'modern', 'boot': True,
                     'store': {'pegaprox-theme': 'forest'}, 'flipTo': True}})['x']
    assert got['darker'] == got['after']['darker'], got
    assert got['after']['stored'] == 'forest'

def test_the_shipped_bundle_carries_it_too():
    built = open(BUILT, encoding='utf-8').read()
    assert 'resolveSystemTheme' in built, 'web/index.html was not rebuilt'


def test_corporate_gets_its_light_gate_set_when_the_os_is_light(run):
    """data-corp-theme gates EVERY light override in the corporate stylesheet (#296).
    Painting the light variables without setting it leaves every component dark-on-light,
    and the OS-change listener has no other way to set it - it does not go through the
    header toggle."""
    got = run({'x': {'prefersLight': True, 'layout': 'corporate', 'apply': 'system'}})['x']
    assert got['resolved'] == 'corporateLight'
    assert got['corpTheme'] == 'light', got


def test_corporate_clears_the_light_gate_again_when_the_os_goes_dark(run):
    got = run({'x': {'prefersLight': False, 'layout': 'corporate', 'apply': 'system'}})['x']
    assert got['corpTheme'] == '', got


def test_a_non_corporate_layout_is_left_alone(run):
    """Only Corporate reads data-corp-theme; setting it elsewhere would be noise."""
    got = run({'x': {'prefersLight': True, 'layout': 'modern', 'apply': 'system'}})['x']
    assert got['corpTheme'] == '<unset>', got


# --- the server side ---------------------------------------------------------
#
# "system" is only an ordinary theme value if the server treats it as one. Three
# separate whitelists guard the two places a theme can be set (a user's own
# preference, and the default handed to new users), and they have drifted before -
# `cloud` is in one of the three and missing from the other two.

def test_a_user_can_choose_the_system_theme(api, seed):
    user = seed.user('dana', role='user')
    r = api.as_user(user).put('/api/user/preferences', json={'theme': 'system'})
    assert r.status_code == 200, r.data
    assert api.app  # harness sanity
    r2 = api.as_user(user).get('/api/user/preferences')
    assert r2.get_json().get('theme') == 'system', r2.data


def test_a_made_up_theme_is_still_refused(api, seed):
    """The whitelist has to stay a whitelist - this is the counter-test for the
    one above, otherwise 'accepted' would prove nothing."""
    user = seed.user('eve', role='user')
    api.as_user(user).put('/api/user/preferences', json={'theme': 'ponies'})
    r = api.as_user(user).get('/api/user/preferences')
    assert r.get_json().get('theme') != 'ponies', r.data


def test_every_theme_whitelist_knows_the_same_themes():
    """Three hand-written copies of the same list. When they drift, a theme is
    choosable in one place and silently dropped in another - which is exactly
    what happened to `cloud`."""
    import ast
    import inspect
    import pegaprox.api.settings as settingsmod
    import pegaprox.api.users as usersmod

    lists = []
    for mod in (settingsmod, usersmod):
        tree = ast.parse(inspect.getsource(mod))
        for node in ast.walk(tree):
            if (isinstance(node, ast.Assign)
                    and any(getattr(t, 'id', None) == 'allowed_themes' for t in node.targets)
                    and isinstance(node.value, ast.List)):
                lists.append(set(ast.literal_eval(node.value)))
    assert len(lists) >= 3, f'expected three whitelists, found {len(lists)}'
    for got in lists:
        assert 'system' in got, 'a theme whitelist does not accept "system"'


# --- the frontend wiring -----------------------------------------------------

def _src(name):
    return open(os.path.join(ROOT, 'web', 'src', name), encoding='utf-8').read()


def test_corporate_does_not_overrule_a_system_choice_on_restore():
    """Three places force Corporate to corporateLight/corporateDark from the local
    toggle. All three run after login or on a layout change, so a single one left
    unguarded turns "follow my desktop" back into whatever the toggle last was."""
    body = _src('contexts.js')
    import re
    guards = re.findall(r"ui_layout === 'corporate'[^\n]*", body)
    assert len(guards) >= 2, guards
    for g in guards:
        assert "!== 'system'" in g, f'unguarded corporate override: {g}'
    assert "localStorage.getItem('pegaprox-theme') === 'system'" in body, \
        'the layout effect still forces a corporate palette over a system choice'


def test_the_corporate_header_button_can_reach_the_new_option():
    """Corporate hides the theme grid (#742), so without this the option is
    unreachable for exactly the users who asked for it."""
    body = _src('dashboard.js')
    assert "{ system: 'light', light: 'dark', dark: 'system' }" in body, \
        'the corporate toggle is still two-state'
    assert 'Icons.Monitor' in body


@pytest.mark.parametrize('key', ['lightMode', 'darkMode', 'followSystem'])
def test_the_new_strings_exist_in_every_language(key):
    """t() falls back to the key itself, so a missing string shows up as raw
    'followSystem' on screen rather than as an empty tooltip."""
    body = _src('translations.js')
    import re
    assert len(re.findall(rf'^\s*{key}:', body, re.M)) == 9, \
        f'{key} is not in all nine language blocks'
