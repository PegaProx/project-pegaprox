"""#959 (grupoaxium) - pasting into the console typed US symbols on a Spanish keyboard.

The paste path emulates a keyboard: for every shifted symbol it holds Shift_L and taps
the *base* key of the US layout (MK added that for #653, where symbols arrived unshifted).
That emulation is only correct while the datacenter runs a US keymap. With `keyboard: es`
configured, qemu translates keysyms itself, so Shift+<the key left of 3> is the Spanish
quote - the reporter typed '@' and got '"'.

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


def _shift_dance(keys):
    """True when the helper held Shift and tapped some other key underneath."""
    return len(keys) == 3 and keys[0][0] == SHIFT_L and keys[2][0] == SHIFT_L


# --- the bug -----------------------------------------------------------------

def test_a_spanish_datacenter_does_not_get_the_us_shift_dance(press):
    """The reported case. Shift + the US '2' key is '"' on a Spanish keyboard."""
    keys = press({'at': ('@', 'es')})['at']
    assert not _shift_dance(keys), (
        "still emulating a US keyboard on a Spanish keymap - this is exactly what "
        "turns the reporter's '@' into '\"'")
    assert keys == [[0x40, None, None]], keys


def test_every_symbol_of_the_us_table_goes_over_plainly_on_a_foreign_keymap(press):
    jobs = {ch: (ch, 'es') for ch in '!@#$%^&*()_+{}|:"<>?~'}
    got = press(jobs)
    offenders = [ch for ch, keys in got.items() if _shift_dance(keys)]
    assert not offenders, f"still shift-emulated on keymap es: {''.join(sorted(offenders))}"


def test_a_german_keymap_is_not_us_either(press):
    """'{' is AltGr+7 on a German keyboard, nowhere near Shift+[."""
    assert not _shift_dance(press({'brace': ('{', 'de')})['brace'])


def test_en_gb_counts_as_foreign(press):
    """Shift+2 is '"' on en-gb as well - only en-us has '@' there."""
    assert not _shift_dance(press({'at': ('@', 'en-gb')})['at'])


# --- what must not regress ---------------------------------------------------

def test_the_us_table_from_653_still_fires_on_a_us_keymap(press):
    """#653 (dcodner24): without this, '@' arrives as a bare '2'."""
    keys = press({'at': ('@', 'en-us')})['at']
    assert _shift_dance(keys), "#653 is back: no Shift held around the base key"
    assert keys[1][0] == 0x32, keys


def test_an_unconfigured_keymap_keeps_todays_behaviour(press):
    """qemu assumes en-us when the datacenter sets no keymap, so #653's remedy
    still applies - and a cluster we could not ask must not change behaviour."""
    for km in ('', None):
        keys = press({'at': ('@', km)})['at']
        assert _shift_dance(keys), f"keymap {km!r} must stay on the US path"


def test_letters_digits_and_control_keys_ignore_the_layout(press):
    got = press({
        'lower_us': ('a', 'en-us'), 'lower_es': ('a', 'es'),
        'upper_us': ('A', 'en-us'), 'upper_es': ('A', 'es'),
        'digit_us': ('5', 'en-us'), 'digit_es': ('5', 'es'),
        'enter_es': ('\n', 'es'), 'tab_es': ('\t', 'es'),
    })
    assert got['lower_us'] == got['lower_es'] == [[0x61, None, None]]
    assert got['upper_us'] == got['upper_es'] == [[0x41, None, None]]
    assert got['digit_us'] == got['digit_es'] == [[0x35, None, None]]
    assert got['enter_es'] == [[0xFF0D, None, None]]
    assert got['tab_es'] == [[0xFF09, None, None]]


def test_a_whole_password_survives_a_spanish_keymap(press):
    keys = press({'pw': ('aB3$@_x', 'es')})['pw']
    assert [k[0] for k in keys] == [0x61, 0x42, 0x33, 0x24, 0x40, 0x5F, 0x78], keys


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
