"""Stable Mode's HTTP-polling fallback starts once, and settles when it cannot start.

connectVnc gives a WSS 4 s to open and then falls back to polling. The timer closes the
hanging WSS, and closing a WebSocket that is still CONNECTING fires its close event, whose
listener started the fallback a second time: two console tickets, two vncproxy sessions on
one VM (PVE 9.1.x does not take that - it is why the ticket is fetched lazily) and a second
poll socket nobody held, long-polling until the page was reloaded.

When the console ticket for the fallback could not be had (an HTTP error, no stable handle),
the promise never settled, and the console sat on 'Connecting...' with no error.

These run the shipped web/src/vnc_secure_socket.js in node with a WSS that never opens - the
black-holed upgrade the timer exists for - and a fake vnc-poll endpoint.
"""
import json
import os
import shutil
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, 'web', 'src', 'vnc_secure_socket.js')

HARNESS = r"""
const fs = require('fs');
globalThis.window = globalThis;
globalThis.CloseEvent = class CloseEvent extends Event {
    constructor(type, init) { super(type); Object.assign(this, init || {}); }
};
const sleep = ms => new Promise(r => setTimeout(r, ms));
const sockets = [];
// a WSS upgrade a middlebox swallows: never opens. close() on a CONNECTING socket fails it,
// which a browser reports as error + close 1006
let closeStops = true;
globalThis.WebSocket = class FakeWebSocket {
    constructor(url) { this.url = url; this.l = {}; sockets.push(this); }
    addEventListener(t, fn) { (this.l[t] = this.l[t] || []).push(fn); }
    fire(t, ev) { (this.l[t] || []).forEach(fn => fn(ev)); }
    send() {}
    close() {
        if (!closeStops) return;
        setTimeout(() => { this.fire('error', {}); this.fire('close', { code: 1006, reason: '', wasClean: false }); }, 0);
    }
};
const posts = [];
let openDelay = 20;
globalThis.fetch = async (url, opts) => {
    const body = JSON.parse(opts.body);
    posts.push(body);
    if (body.action === 'open') {
        const id = 'p' + posts.filter(p => p.action === 'open').length;
        await sleep(openDelay);
        return { ok: true, json: async () => ({ ok: true, poll_id: id }) };
    }
    if (body.action === 'recv') { await sleep(30); return { ok: true, json: async () => ({ ok: true, chunks_b64: [] }) }; }
    return { ok: true, json: async () => ({ ok: true }) };
};
eval(fs.readFileSync(process.argv[2], 'utf-8'));
const keyB64 = Buffer.from(globalThis.crypto.getRandomValues(new Uint8Array(32))).toString('base64');
const settled = (p, ms) => Promise.race([p.then(s => ({ state: 'resolved', s }), e => ({ state: 'rejected', why: String(e && e.message || e) })),
                                         sleep(ms).then(() => ({ state: 'pending' }))]);
const opened = () => posts.filter(p => p.action === 'open').length;
const closedIds = () => posts.filter(p => p.action === 'close').map(p => p.poll_id);

const scenarios = {
    // the WSS hangs at the upgrade: one ticket, one poll session, and closing the console ends it
    async blackholed() {
        let tickets = 0, transport = null;
        const getPollHandle = async () => { tickets++; await sleep(30); return { key_b64: keyB64, session_id: 's' + tickets }; };
        const p = window.connectVnc({ wsUrl: 'wss://pp/vnc', pollUrl: 'https://pp/vnc-poll', wsKey: keyB64,
                                      getPollHandle, wsTimeoutMs: 50, onTransport: t => { transport = t; } });
        const r = await settled(p, 1500);
        await sleep(200);
        const before = { tickets, opens: opened(), transport, state: r.state };
        if (r.s) r.s.close();          // the console closes: rfb.disconnect() closes the socket it was given
        const mark = posts.length;
        await sleep(400);
        const recvAfter = [...new Set(posts.slice(mark).filter(p => p.action === 'recv').map(p => p.poll_id))];
        return { ...before, recvAfterClose: recvAfter };
    },
    // the console ticket for the fallback fails, the way fetchPollHandle throws on a 500
    async ticketFails() {
        const getPollHandle = async () => { throw new Error('console ticket http=500'); };
        const r = await settled(window.connectVnc({ wsUrl: 'wss://pp/vnc', pollUrl: 'https://pp/vnc-poll', wsKey: keyB64,
                                                    getPollHandle, wsTimeoutMs: 50 }), 1500);
        return { state: r.state, why: r.why || '', opens: opened() };
    },
    async noUsableHandle() {
        const getPollHandle = async () => ({ key_b64: keyB64 });
        const r = await settled(window.connectVnc({ wsUrl: 'wss://pp/vnc', pollUrl: 'https://pp/vnc-poll', wsKey: keyB64,
                                                    getPollHandle, wsTimeoutMs: 50 }), 1500);
        return { state: r.state, opens: opened() };
    },
    async forcedWithoutHandle() {
        const r = await settled(window.connectVnc({ pollUrl: 'https://pp/vnc-poll', forcePolling: true }), 1500);
        return { state: r.state, opens: opened() };
    },
    // a WSS that opens after all while the poll session is being opened: the WSS is handed
    // out, the poll session must not stay behind
    async wssWinsLate() {
        closeStops = false;
        openDelay = 120;
        const getPollHandle = async () => { await sleep(10); return { key_b64: keyB64, session_id: 's1' }; };
        const p = window.connectVnc({ wsUrl: 'wss://pp/vnc', pollUrl: 'https://pp/vnc-poll', wsKey: keyB64,
                                      getPollHandle, wsTimeoutMs: 50 });
        for (let i = 0; i < 50 && !sockets.length; i++) await sleep(5);
        await sleep(100);              // the fallback has its ticket and is opening its poll session
        sockets[0].fire('open', new Event('open'));
        const r = await settled(p, 1500);
        await sleep(300);
        const mark = posts.length;
        await sleep(300);
        return { state: r.state, isWss: !!(r.s && r.s instanceof window.SecureVncSocket), opens: opened(),
                 closed: closedIds(), recvLater: posts.slice(mark).filter(p => p.action === 'recv').length };
    },
};

(async () => {
    const out = await scenarios[process.argv[3]]();
    console.log(JSON.stringify(out));
    process.exit(0);
})().catch(e => { console.error(e && e.stack || e); process.exit(3); });
"""


@pytest.fixture(scope='module')
def run(tmp_path_factory):
    if not shutil.which('node'):
        pytest.skip('node is needed to run the shipped socket wrapper')
    harness = tmp_path_factory.mktemp('vncfallback') / 'harness.js'
    harness.write_text(HARNESS, encoding='utf-8')
    # the WebCrypto globals came with Node 20, Node 18 keeps them behind a flag
    major = int(subprocess.run(['node', '-p', 'process.versions.node.split(".")[0]'], capture_output=True,
                               text=True, timeout=60, check=True).stdout)
    flags = ['--experimental-global-webcrypto'] if major < 20 else []

    def _run(scenario):
        p = subprocess.run(['node', *flags, str(harness), SRC, scenario], capture_output=True, text=True,
                           timeout=60)
        assert p.returncode == 0, p.stderr
        return json.loads(p.stdout.strip().splitlines()[-1])
    return _run


def test_a_hanging_wss_falls_back_once(run):
    got = run('blackholed')
    assert got['state'] == 'resolved' and got['transport'] == 'poll', got
    assert (got['tickets'], got['opens']) == (1, 1), (
        f"one timed-out WSS fetched {got['tickets']} console tickets and opened {got['opens']} poll sessions")


def test_closing_the_console_ends_every_poll_session(run):
    got = run('blackholed')
    assert got['recvAfterClose'] == [], f"after the console closed the page still long-polls {got['recvAfterClose']}"


def test_a_failed_fallback_ticket_settles_the_connect(run):
    """node_modals awaits connectVnc; only a settled promise gets it to its error state."""
    got = run('ticketFails')
    assert got['state'] == 'rejected', f"connectVnc is {got['state']} after the ticket failed"
    assert 'http=500' in got['why'], got
    assert got['opens'] == 0


def test_a_fallback_without_a_usable_handle_settles_the_connect(run):
    assert run('noUsableHandle') == {'state': 'rejected', 'opens': 0}


def test_forced_polling_without_a_ticket_source_settles_the_connect(run):
    assert run('forcedWithoutHandle') == {'state': 'rejected', 'opens': 0}


def test_a_poll_session_that_lost_to_the_wss_is_closed(run):
    got = run('wssWinsLate')
    assert got['state'] == 'resolved' and got['isWss'], got
    assert got['opens'] == 1, got
    assert got['closed'] == ['p1'], f"the poll session nobody holds was left open: {got}"
    assert got['recvLater'] == 0, got
