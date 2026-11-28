"""A console window closed while its secure socket was still connecting leaves nothing open.

The stable console waits for window.connectVnc, which takes seconds when the websocket leg
times out and the polling fallback takes over. When the window closed in that time, the
cleanup found no RFB to end; the socket came after it, got an RFB on the gone canvas and kept
its PVE session (and the polling loop) going behind the closed window. The shipped block runs
in node here with a connectVnc that answers after the close.

LW Nov 2026
"""
import json
import os
import shutil
import subprocess

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_HARNESS = r"""
const fs = require('fs');
const src = fs.readFileSync(process.argv[2], 'utf-8');
const start = src.indexOf('let refused = false;');
const handler = src.indexOf("rfbInstance.addEventListener('disconnect'", start);
const endMark = '\n                        });\n';
const end = src.indexOf(endMark, handler) + endMark.length;
if (start < 0 || handler < 0 || end < endMark.length) { console.error('no block'); process.exit(2); }
const block = src.slice(start, end);

class Sock {
    constructor(url) { this.url = url; this.closed = 0; }
    addEventListener() {}
    close() { this.closed++; }
}
let rfbs = 0;
class RFB {
    constructor() { rfbs++; }
    addEventListener() {}
}

async function run(closeWhileConnecting) {
    rfbs = 0;
    let cancelled = false;
    const sock = new Sock('secure');
    // the window closes while connectVnc is still on its way (the cleanup sets the flag)
    const window = { RFB, connectVnc: async () => { if (closeWhileConnecting) cancelled = true; return sock; } };
    const WebSocket = Sock;
    const ACCOUNT_FULL_CLOSE = 4429;
    const statuses = [];
    const setRefusedWhy = () => {};
    const setConnectionStatus = (s) => statuses.push(s);
    const retryCount = { current: 0 }, maxRetries = 8, retryDelayMs = () => 0;
    const rfbRef = { current: null }, canvasRef = { current: {} };
    const startVNC = () => {};
    const stableHandle = { key_b64: 'k', session_id: 's' };
    const wsUrl = 'wss://pegaprox/vnc', vncPassword = 'pw';
    const API_URL = '', clusterId = 'c', vm = { node: 'n', type: 'qemu', vmid: 100 };
    const getAuthHeaders = () => ({});
    const console = { log() {}, error() {} };
    await eval('(async () => {' + block + '})()');
    return { closed: sock.closed, rfbs, statuses };
}

(async () => {
    console.log(JSON.stringify({ closed_early: await run(true), open: await run(false) }));
})();
"""


def test_a_console_closed_while_connecting_closes_its_socket_and_starts_no_rfb(tmp_path):
    if not shutil.which('node'):
        pytest.skip('node is needed to run the shipped console block')
    harness = tmp_path / 'closed_while_connecting.js'
    harness.write_text(_HARNESS, encoding='utf-8')
    p = subprocess.run(['node', str(harness), os.path.join(REPO, 'web/src/node_modals.js')],
                       capture_output=True, text=True, timeout=30)
    assert p.returncode == 0, p.stderr
    got = json.loads(p.stdout)
    assert got['closed_early'] == {'closed': 1, 'rfbs': 0, 'statuses': []}, got
    # a window still open gets its console as before
    assert got['open']['closed'] == 0 and got['open']['rfbs'] == 1, got
