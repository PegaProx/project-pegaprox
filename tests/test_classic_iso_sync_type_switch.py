"""The classic ISO Sync sub tab lists the files of the type its select shows.

The select set the new type and asked for the status 50 ms later through the closure of the
render it came from, which still held the old type: ISOs picked, the table listed the
templates (or the other way round), and a row's Sync posted the new content_type with a
file of the other type. The timer after Sync All and the poll after a Sync did the same
after a switch.

The state, the status read and the select's handler are taken from storage.js and run in
node through a small hook runtime (no JSX in them).
"""
import json
import os
import re
import shutil
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _src():
    with open(os.path.join(ROOT, 'web', 'src', 'storage.js'), encoding='utf-8') as fh:
        return fh.read()


def _parts():
    src = _src()
    start = src.index("const [syncContentType, setSyncContentType] = useState('iso');")
    state = src[start:src.index('const [syncingFiles, setSyncingFiles]', start)]
    refresh = re.search(r'const refreshSyncStatus = \(\) => \{.*?\n            \};', src, re.S)
    assert refresh, 'no status read in storage.js'
    change = re.search(r'<select value=\{syncContentType\} onChange=\{(e => \{.*?\n\s*\})\}', src, re.S)
    assert change, 'no type select in the classic sync tab'
    return state, refresh.group(0), change.group(1)


HARNESS = r"""
const hooks = []; let slot = 0;
const useState = init => { const k = slot++; if (!(k in hooks)) hooks[k] = { v: init };
    const h = hooks[k]; return [h.v, nv => { h.v = typeof nv === 'function' ? nv(h.v) : nv; }]; };
const useRef = init => { const k = slot++; if (!(k in hooks)) hooks[k] = { current: init }; return hooks[k]; };
const API_URL = '/api', clusterId = 'c1';
const asked = [];      // [url, resolve]
const authFetch = url => new Promise(res => asked.push([url, res]));
const answer = (i, files) => asked[i][1]({ json: async () => ({ files }) });
function SyncTab() {
    const [syncStatus, setSyncStatus] = useState(null);
    const [syncLoading, setSyncLoading] = useState(false);
    %(state)s
    %(refresh)s
    return { onChange: %(change)s, refresh: refreshSyncStatus, syncContentType, syncStatus };
}
const render = () => { slot = 0; return SyncTab(); };
const tick = ms => new Promise(r => setTimeout(r, ms));
(async () => {
    const out = {};
    render().refresh();                           // the tab opens on ISOs
    answer(0, ['debian.iso']); await tick(5);
    const beforeSwitch = render();
    out.opened = beforeSwitch.syncStatus && beforeSwitch.syncStatus.files;
    beforeSwitch.refresh();                       // a Refresh whose answer is slow
    beforeSwitch.onChange({ target: { value: 'vztmpl' } });
    let view = render();                          // React draws the state change
    out.drawn = { type: view.syncContentType, rows: view.syncStatus && view.syncStatus.files };
    await tick(120);                              // past any short timer of the handler
    out.afterSwitch = asked.slice(2).map(a => a[0]);
    // a timer set before the switch (Sync All, the poll after a Sync) fires now
    beforeSwitch.refresh();
    await tick(5);
    out.lateTimer = asked[asked.length - 1][0];
    // the templates come, then the slow ISO answer of the Refresh
    asked.forEach((a, i) => { if (i > 1 && a[0].endsWith('content=vztmpl')) answer(i, ['alpine.tar.zst']); });
    await tick(5);
    answer(1, ['debian.iso']);
    await tick(5);
    view = render();
    out.shown = { type: view.syncContentType, rows: view.syncStatus && view.syncStatus.files };
    console.log(JSON.stringify(out));
})().catch(e => { console.error(e && e.stack || e); process.exit(3); });
"""


def _run():
    state, refresh, change = _parts()
    js = HARNESS.replace('%(state)s', state).replace('%(refresh)s', refresh).replace('%(change)s', change)
    out = subprocess.run(['node', '-e', js], capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout.strip().splitlines()[-1])


needs_node = pytest.mark.skipif(not shutil.which('node'), reason='needs node')


@needs_node
def test_a_switch_asks_for_the_type_it_switched_to():
    got = _run()
    assert got['opened'] == ['debian.iso'], got          # the harness draws the first read
    assert got['afterSwitch'] == ['/api/clusters/c1/iso-sync/status?content=vztmpl'], got


@needs_node
def test_the_rows_of_the_old_type_are_gone_once_the_type_changes():
    got = _run()
    # until the templates come, no ISO row offers a Sync under the template type
    assert got['drawn'] == {'type': 'vztmpl', 'rows': None}, got


@needs_node
def test_a_timer_from_before_the_switch_reads_the_type_shown():
    got = _run()
    assert got['lateTimer'].endswith('content=vztmpl'), got
    # and the ISO answer of a Refresh from before the switch does not replace the templates
    assert got['shown'] == {'type': 'vztmpl', 'rows': ['alpine.tar.zst']}, got


def test_the_row_sync_posts_the_type_the_rows_came_for():
    src = _src()
    trigger = src[src.index('const triggerSync = async ('):src.index('const triggerSyncAll = async (')]
    assert 'content_type: syncContentType' in trigger
    # the classic select has no delayed read of its own any more
    _, _, change = _parts()
    assert 'setTimeout' not in change
