"""#959 - pasting into the console typed US symbols on a Spanish keyboard.

The paste path emulates a keyboard: for every shifted symbol it holds Shift_L and taps
the *base* key of the US layout (MK added that for #653, where symbols arrived unshifted).
That emulation is only correct while the datacenter runs a US keymap. With `keyboard: es`
configured, qemu translates keysyms itself, so Shift+<the key left of 3> is the Spanish
quote - the reporter typed '@' and got '"'.

Dropping the US emulation was not enough: qemu never presses a modifier for a keysym, so
a bare '@' reached a Spanish guest as a plain 2. Paste now types like a hand on the
datacenter's keyboard - the physical key with Shift and/or AltGr held - for de, es, fr,
it, pt, pl and en-gb, and the tests below pin those sequences. What the guest finally
types needs a live VM and is not checked here.

These tests run the SHIPPED function. The bundle is one concatenated React file, so the
two pieces are sliced out of the source text and executed in node rather than re-typed
here; a copy of the logic would pass against the broken code, which is the whole point of
the exercise.
"""
import json
import os
import shutil
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUNDLE = os.path.join(ROOT, 'web', 'src', 'node_modals.js')

HARNESS = r"""
const fs = require('fs');
const src = fs.readFileSync(process.argv[2], 'utf-8');
const start = src.indexOf('const SHIFTED_US = {');
const fnStart = src.indexOf('const typeTextToVM =', start);
const endMark = '\n            };\n';
const end = src.indexOf(endMark, fnStart) + endMark.length;
if (start < 0 || fnStart < 0 || end < endMark.length) {
    console.error('could not slice typeTextToVM out of the bundle');
    process.exit(2);
}
const typeTextToVM = new Function(src.slice(start, end) + '\nreturn typeTextToVM;')();
const jobs = JSON.parse(process.argv[3]);
const out = {};
for (const [name, [text, keymap]] of Object.entries(jobs)) {
    const keys = [];
    typeTextToVM({ sendKey: (ks, code, down) => keys.push([ks, code === undefined ? null : code,
                                                            down === undefined ? null : down]) },
                 text, keymap);
    out[name] = keys;
}
console.log(JSON.stringify(out));
"""

SHIFT_L = 0xFFE1


@pytest.fixture(scope='module')
def press():
    """press({'name': (text, keymap)}) -> {'name': [[keysym, code, down], ...]}"""
    if not shutil.which('node'):
        pytest.skip('node is needed to run the shipped paste helper')
    harness = os.path.join(os.path.dirname(os.path.abspath(__file__)), '_kb959_harness.js')
    with open(harness, 'w', encoding='utf-8') as fh:
        fh.write(HARNESS)

    def _run(jobs):
        p = subprocess.run(['node', harness, BUNDLE, json.dumps(jobs)],
                           capture_output=True, text=True, timeout=30)
        assert p.returncode == 0, p.stderr
        return json.loads(p.stdout)
    try:
        yield _run
    finally:
        os.remove(harness)


SHIFT = (SHIFT_L, 'ShiftLeft')
ALTGR = (0xFE03, 'AltRight')   # ISO_Level3_Shift on the right Alt key, as noVNC sends AltGraph
SPACE = [0x20, 'Space', None]


def _shift_dance(keys):
    """True when the helper held Shift and tapped some other key underneath."""
    return len(keys) == 3 and keys[0][0] == SHIFT_L and keys[2][0] == SHIFT_L


def _tap(keysym, code, *mods):
    """What a hand does: modifiers down in order, the key, modifiers up in reverse."""
    return ([[m[0], m[1], True] for m in mods] + [[keysym, code, None]]
            + [[m[0], m[1], False] for m in reversed(mods)])


# --- the bug -----------------------------------------------------------------

def test_the_reported_characters_hold_altgr_and_shift_on_spanish(press):
    """The reported case: '@' and '#' are AltGr+2/3 on a Spanish keyboard, '"', '(' and
    '_' are Shift+2, Shift+8 and Shift+<the key right of the full stop>."""
    keys = press({'pw': ('@#"(_', 'es')})['pw']
    assert keys == (_tap(0x40, 'Digit2', ALTGR) + _tap(0x23, 'Digit3', ALTGR)
                    + _tap(0x22, 'Digit2', SHIFT) + _tap(0x28, 'Digit8', SHIFT)
                    + _tap(0x5F, 'Slash', SHIFT)), keys


def test_a_spanish_keymap_never_gets_the_us_shift_dance(press):
    """Shift + a bare US base keysym is what turned '@' into '"' in the first place."""
    got = press({ch: (ch, 'es') for ch in '!@#$%^&*()_+{}|:"<>?~'})
    offenders = [ch for ch, keys in got.items()
                 if any(k[1] is None for k in keys) and keys[0][0] == SHIFT_L]
    assert not offenders, f"US shift emulation on keymap es: {''.join(sorted(offenders))}"


@pytest.mark.parametrize('keymap,ch,expected', [
    # German: Y and Z swap, the braces and the @ live on AltGr
    ('de', 'z', _tap(0x7A, 'KeyY')),
    ('de', 'Z', _tap(0x5A, 'KeyY', SHIFT)),
    ('de', '"', _tap(0x22, 'Digit2', SHIFT)),
    ('de', '{', _tap(0x7B, 'Digit7', ALTGR)),
    ('de', '@', _tap(0x40, 'KeyQ', ALTGR)),
    ('de', '\\', _tap(0x5C, 'Minus', ALTGR)),
    ('de', '|', _tap(0x7C, 'IntlBackslash', ALTGR)),
    ('de', '€', _tap(0x10020AC, 'KeyE', ALTGR)),
    # Spanish
    ('es', '\\', _tap(0x5C, 'Backquote', ALTGR)),
    ('es', '[', _tap(0x5B, 'BracketLeft', ALTGR)),
    ('es', '}', _tap(0x7D, 'Backslash', ALTGR)),
    ('es', 'ñ', _tap(0xF1, 'Semicolon')),
    # French AZERTY: digits are shifted, letters move
    ('fr', 'a', _tap(0x61, 'KeyQ')),
    ('fr', 'm', _tap(0x6D, 'Semicolon')),
    ('fr', '1', _tap(0x31, 'Digit1', SHIFT)),
    ('fr', '!', _tap(0x21, 'Slash')),
    ('fr', '@', _tap(0x40, 'Digit0', ALTGR)),
    ('fr', '#', _tap(0x23, 'Digit3', ALTGR)),
    # Italian: the braces need AltGr AND Shift
    ('it', '@', _tap(0x40, 'Semicolon', ALTGR)),
    ('it', '#', _tap(0x23, 'Quote', ALTGR)),
    ('it', '[', _tap(0x5B, 'BracketLeft', ALTGR)),
    ('it', '{', _tap(0x7B, 'BracketLeft', ALTGR, SHIFT)),
    # Portuguese
    ('pt', '@', _tap(0x40, 'Digit2', ALTGR)),
    ('pt', '{', _tap(0x7B, 'Digit7', ALTGR)),
    ('pt', '"', _tap(0x22, 'Digit2', SHIFT)),
    # Polish programmer: US symbols, the national letters on AltGr with Latin-2 keysyms
    ('pl', '@', _tap(0x40, 'Digit2', SHIFT)),
    ('pl', 'ł', _tap(0x1B3, 'KeyL', ALTGR)),
    ('pl', 'Ż', _tap(0x1AF, 'KeyZ', ALTGR, SHIFT)),
    # UK: '"' and '@' trade places with the US, '#' and '\' have keys of their own
    ('en-gb', '"', _tap(0x22, 'Digit2', SHIFT)),
    ('en-gb', '@', _tap(0x40, 'Quote', SHIFT)),
    ('en-gb', '#', _tap(0x23, 'Backslash')),
    ('en-gb', '\\', _tap(0x5C, 'IntlBackslash')),
    ('en-gb', '£', _tap(0xA3, 'Digit3', SHIFT)),
])
def test_each_layout_types_the_key_a_hand_would_press(press, keymap, ch, expected):
    keys = press({'k': (ch, keymap)})['k']
    assert keys == expected, (keymap, ch, keys)


@pytest.mark.parametrize('keymap,ch,first', [
    ('de', '^', [0xFE52, 'Backquote', None]),
    ('de', '`', [0xFE50, 'Equal', None]),
    ('es', '`', [0xFE50, 'BracketLeft', None]),
    ('fr', '^', [0xFE52, 'BracketLeft', None]),
    ('pt', '~', [0xFE53, 'Backslash', None]),
])
def test_a_dead_key_is_followed_by_a_space(press, keymap, ch, first):
    """Dead key then Space is how a hand types the accent itself on these layouts."""
    keys = press({'k': (ch, keymap)})['k']
    assert first in keys and keys[-1] == SPACE, (keymap, ch, keys)
    assert keys.index(first) < len(keys) - 1


def test_a_key_that_is_only_dead_on_windows_gets_no_space(press):
    """The Spanish '~' (AltGr+4) composes on Linux right away; a Space would be typed."""
    assert press({'k': ('~', 'es')})['k'] == _tap(0x7E, 'Digit4', ALTGR)


@pytest.mark.parametrize('keymap', ['de', 'es', 'fr', 'it', 'pt', 'pl', 'en-gb'])
def test_no_modifier_is_left_held_after_any_character(press, keymap):
    text = ''.join(chr(c) for c in range(0x21, 0x7F)) + 'äñçèł£€'
    got = press({ch: (ch, keymap) for ch in text})
    for ch, keys in got.items():
        held = {}
        for ks, code, down in keys:
            if down is not None:
                held[code] = held.get(code, 0) + (1 if down else -1)
        assert all(v == 0 for v in held.values()), (keymap, ch, keys)


def test_a_character_the_layout_cannot_type_goes_over_as_its_keysym(press):
    """'é' has no key of its own on a German keyboard - the old Unicode keysym stays."""
    assert press({'k': ('é', 'de')})['k'] == [[0x01000000 + 0xE9, None, None]]


def test_a_keymap_without_a_table_keeps_the_plain_keysyms(press):
    """Swiss German is not in the tables: 81028d2's behaviour, no US dance, no guessing."""
    got = press({'at': ('@', 'de-ch'), 'brace': ('{', 'sv')})
    assert got['at'] == [[0x40, None, None]]
    assert got['brace'] == [[0x7B, None, None]]


# --- what must not regress ---------------------------------------------------

def test_the_us_table_from_653_still_fires_on_a_us_keymap(press):
    """#653: without this, '@' arrives as a bare '2'."""
    keys = press({'at': ('@', 'en-us')})['at']
    assert _shift_dance(keys), "#653 is back: no Shift held around the base key"
    assert keys[1][0] == 0x32, keys


def test_an_unconfigured_keymap_keeps_todays_behaviour(press):
    """qemu assumes en-us when the datacenter sets no keymap, so #653's remedy
    still applies - and a cluster we could not ask must not change behaviour."""
    for km in ('', None):
        keys = press({'at': ('@', km)})['at']
        assert _shift_dance(keys), f"keymap {km!r} must stay on the US path"


def test_letters_digits_and_control_keys(press):
    got = press({
        'lower_us': ('a', 'en-us'), 'lower_es': ('a', 'es'),
        'upper_us': ('A', 'en-us'), 'upper_es': ('A', 'es'),
        'digit_us': ('5', 'en-us'), 'digit_es': ('5', 'es'),
        'enter_es': ('\n', 'es'), 'tab_es': ('\t', 'es'),
    })
    assert got['lower_us'] == [[0x61, None, None]]
    assert got['upper_us'] == [[0x41, None, None]]
    assert got['digit_us'] == [[0x35, None, None]]
    # on a mapped layout a capital is Shift + its key, like any other shifted character
    assert got['lower_es'] == _tap(0x61, 'KeyA')
    assert got['upper_es'] == _tap(0x41, 'KeyA', SHIFT)
    assert got['digit_es'] == _tap(0x35, 'Digit5')
    assert got['enter_es'] == [[0xFF0D, None, None]]
    assert got['tab_es'] == [[0xFF09, None, None]]


def test_a_whole_password_survives_a_spanish_keymap(press):
    keys = press({'pw': ('aB3$@_x', 'es')})['pw']
    assert keys == (_tap(0x61, 'KeyA') + _tap(0x42, 'KeyB', SHIFT) + _tap(0x33, 'Digit3')
                    + _tap(0x24, 'Digit4', SHIFT) + _tap(0x40, 'Digit2', ALTGR)
                    + _tap(0x5F, 'Slash', SHIFT) + _tap(0x78, 'KeyX')), keys


# --- the wiring --------------------------------------------------------------

def test_no_call_site_still_pastes_without_a_layout():
    body = open(BUNDLE, encoding='utf-8').read()
    import re
    bad = re.findall(r'typeTextToVM\(\s*conn\s*,\s*text\s*\)', body)
    assert not bad, f"{len(bad)} call site(s) still hand the paste helper no keymap"


def test_the_layout_comes_from_the_console_answer():
    body = open(BUNDLE, encoding='utf-8').read()
    assert 'keymap' in body, 'the console modal never reads a keymap'


# --- the backend side --------------------------------------------------------
#
# The browser can only gate on the layout if somebody tells it the layout. These drive the
# real console route through the full stack, with the PVE session faked at the transport.

from unittest.mock import MagicMock


def _pve_manager(keyboard='es', status=200):
    mgr = MagicMock(name='FakeManager[cluster_1]')
    mgr.cluster_id = 'cluster_1'
    mgr.cluster_type = 'proxmox'
    mgr.name = 'cluster_1'
    mgr.online = True
    mgr.host = '10.0.0.9'
    mgr.api_port = 8006
    mgr.get_vnc_ticket.return_value = {'success': True, 'ticket': 'PVEVNC:abc',
                                       'port': '5900', 'host': '10.0.0.9'}
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = {'data': {'keyboard': keyboard} if keyboard else {}}
    mgr._create_session.return_value.get.return_value = resp
    return mgr


@pytest.fixture(autouse=True)
def _clean_keymap_cache():
    from pegaprox.api import vms
    vms._dc_keymap_cache.clear()
    yield
    vms._dc_keymap_cache.clear()


def test_the_console_answer_carries_the_datacenter_keymap(api, seed):
    root = seed.user('root', role='admin')
    api.set_manager('cluster_1', _pve_manager(keyboard='es'))
    r = api.as_user(root).get('/api/clusters/cluster_1/vms/pve1/qemu/100/console')
    assert r.status_code == 200, r.data
    assert r.get_json().get('keymap') == 'es'


def test_a_datacenter_without_a_keymap_reports_an_empty_one(api, seed):
    root = seed.user('root', role='admin')
    api.set_manager('cluster_1', _pve_manager(keyboard=None))
    r = api.as_user(root).get('/api/clusters/cluster_1/vms/pve1/qemu/100/console')
    assert r.status_code == 200, r.data
    assert r.get_json().get('keymap') == ''


def test_a_console_still_opens_when_the_keymap_cannot_be_read(api, seed):
    """A keymap is a nicety. Losing it must not cost anyone their console."""
    root = seed.user('root', role='admin')
    mgr = _pve_manager()
    mgr._create_session.return_value.get.side_effect = OSError('connection reset')
    api.set_manager('cluster_1', mgr)
    r = api.as_user(root).get('/api/clusters/cluster_1/vms/pve1/qemu/100/console')
    assert r.status_code == 200, r.data
    assert r.get_json()['ticket'] == 'PVEVNC:abc'
    assert r.get_json().get('keymap') == ''


def test_a_failed_lookup_is_not_remembered():
    """Otherwise one timeout pins the wrong answer on that cluster for five minutes."""
    from pegaprox.api.vms import _datacenter_keymap, _dc_keymap_cache
    mgr = _pve_manager()
    mgr._create_session.return_value.get.side_effect = OSError('down')
    assert _datacenter_keymap('cluster_1', mgr) == ''
    assert 'cluster_1' not in _dc_keymap_cache


def test_the_lookup_does_not_run_on_every_console_open():
    """Console latency is its own long-running ticket - this must not add a round trip."""
    from pegaprox.api.vms import _datacenter_keymap
    mgr = _pve_manager(keyboard='de')
    assert _datacenter_keymap('cluster_1', mgr) == 'de'
    assert _datacenter_keymap('cluster_1', mgr) == 'de'
    assert _datacenter_keymap('cluster_1', mgr) == 'de'
    assert mgr._create_session.return_value.get.call_count == 1


def test_the_cache_is_kept_apart_per_cluster():
    from pegaprox.api.vms import _datacenter_keymap
    assert _datacenter_keymap('cluster_1', _pve_manager(keyboard='de')) == 'de'
    assert _datacenter_keymap('cluster_2', _pve_manager(keyboard='fr')) == 'fr'


def test_a_non_proxmox_cluster_is_never_asked_for_pve_options():
    """XCP-ng has no /cluster/options; asking would be a wasted round trip and a log line."""
    from pegaprox.api.vms import _datacenter_keymap
    mgr = _pve_manager()
    mgr.cluster_type = 'xcpng'
    assert _datacenter_keymap('cluster_1', mgr) == ''
    assert mgr._create_session.call_count == 0


def test_a_non_200_from_pve_is_not_remembered_either():
    from pegaprox.api.vms import _datacenter_keymap, _dc_keymap_cache
    assert _datacenter_keymap('cluster_1', _pve_manager(status=500)) == ''
    assert 'cluster_1' not in _dc_keymap_cache
