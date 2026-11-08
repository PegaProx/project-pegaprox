"""Stable Mode must not tear down a healthy console because two frames arrived close together.

SecureVncSocket's message listener was async on its own, one call per frame. The sequence
number was checked before the decrypt's await and advanced after it, so a second frame that
arrived while the first was still in crypto.subtle was checked against the old number,
thrown out as 'out-of-order', and the socket closed with 4099 - reported on a token-only
cluster once the console finally connected (#955). The send side had the same shape: the
frame number is taken before the encrypt's await and the frame goes out after it, in
whatever order WebCrypto settles, and the server checks that order too.

These run the shipped web/src/vnc_secure_socket.js in node against a fake WebSocket, with
crypto.subtle slowed down so that the first frame finishes last - the order WebCrypto is
free to pick. MK Oct 2026
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
const sockets = [];
globalThis.WebSocket = class FakeWebSocket {
    constructor(url) { this.url = url; this.sent = []; this.closed = []; this.l = {}; sockets.push(this); }
    addEventListener(t, fn) { (this.l[t] = this.l[t] || []).push(fn); }
    fire(t, ev) { (this.l[t] || []).forEach(fn => fn(ev)); }
    send(f) { this.sent.push(new Uint8Array(f)); }
    close(code, reason) { this.closed.push([code, reason]); }
};
eval(fs.readFileSync(process.argv[2], 'utf-8'));

const subtle = globalThis.crypto.subtle;
const sleep = ms => new Promise(r => setTimeout(r, ms));
const N = 8;
// the first call settles last. WebCrypto copies its byte arguments on the call, so this does too
const snap = (v) => ArrayBuffer.isView(v) ? new Uint8Array(v.buffer.slice(v.byteOffset, v.byteOffset + v.byteLength))
    : (v && typeof v === 'object' && !(v instanceof CryptoKey)) ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, snap(x)]))
    : v;
const slowly = (fn) => { let n = 0; return (...a) => { const d = (N - n++) * 15; const args = a.map(snap);
    return sleep(Math.max(d, 0)).then(() => fn(...args)); }; };

(async () => {
    const raw = globalThis.crypto.getRandomValues(new Uint8Array(32));
    const keyB64 = Buffer.from(raw).toString('base64');
    const key = await subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);

    // what pegaprox/utils/vnc_crypto.py puts on the wire: seq | iv(seq + 8 random) | ct+tag
    const frame = async (seq, text) => {
        const s = new Uint8Array(4); new DataView(s.buffer).setUint32(0, seq, false);
        const iv = new Uint8Array(12); iv.set(s); globalThis.crypto.getRandomValues(iv.subarray(4));
        const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: s,
                                                         tagLength: 128 }, key, new TextEncoder().encode(text)));
        const out = new Uint8Array(16 + ct.length); out.set(s, 0); out.set(iv, 4); out.set(ct, 16);
        return out.buffer;
    };
    const frames = [];
    for (let i = 0; i < N; i++) frames.push(await frame(i, 'frame-' + i));

    const sock = new window.SecureVncSocket('wss://pegaprox/vnc', keyB64);
    const delivered = [], integrity = [];
    sock.onmessage = (ev) => delivered.push(new TextDecoder().decode(ev.data));
    sock.addEventListener('integrityerror', (ev) => integrity.push(String(ev.data)));
    for (let i = 0; i < 50 && !sockets.length; i++) await sleep(5);
    const ws = sockets[0];
    ws.fire('open', new Event('open'));

    const realDecrypt = subtle.decrypt.bind(subtle);
    const realEncrypt = subtle.encrypt.bind(subtle);
    subtle.decrypt = slowly(realDecrypt);
    subtle.encrypt = slowly(realEncrypt);

    // all of them in one go, the way a burst of framebuffer updates arrives
    for (const f of frames) ws.fire('message', { data: f });
    // and the input the way noVNC sends it: a view on ONE buffer it rewrites for the next message
    const sQ = new Uint8Array(64);
    for (let i = 0; i < N; i++) {
        const msg = new TextEncoder().encode('input-' + i);
        sQ.set(msg);
        sock.send(new Uint8Array(sQ.buffer, 0, msg.length));
    }
    await sleep(N * 15 * N + 400);
    subtle.decrypt = realDecrypt;

    const sentSeq = ws.sent.map(f => new DataView(f.buffer, f.byteOffset, 4).getUint32(0, false));
    const sentText = [];
    for (const f of ws.sent) {
        const pt = await subtle.decrypt({ name: 'AES-GCM', iv: f.subarray(4, 16), additionalData: f.subarray(0, 4),
                                          tagLength: 128 }, key, f.subarray(16));
        sentText.push(new TextDecoder().decode(pt));
    }
    console.log(JSON.stringify({ delivered, integrity, closed: ws.closed, sentSeq, sentText }));
})().catch(e => { console.error(e && e.stack || e); process.exit(3); });
"""


@pytest.fixture(scope='module')
def run(tmp_path_factory):
    if not shutil.which('node'):
        pytest.skip('node is needed to run the shipped socket wrapper')
    harness = tmp_path_factory.mktemp('vss955') / 'harness.js'
    harness.write_text(HARNESS, encoding='utf-8')
    # the WebCrypto globals came with Node 20, Node 18 keeps them behind a flag
    major = int(subprocess.run(['node', '-p', 'process.versions.node.split(".")[0]'], capture_output=True,
                               text=True, timeout=60, check=True).stdout)
    flags = ['--experimental-global-webcrypto'] if major < 20 else []
    p = subprocess.run(['node', *flags, str(harness), SRC], capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, p.stderr
    return json.loads(p.stdout.strip().splitlines()[-1])


def test_a_burst_of_frames_does_not_close_the_console(run):
    assert run['integrity'] == [], (
        f"a healthy stream was reported as tampered with: {run['integrity'][:2]}")
    assert [c for c in run['closed'] if c[0] == 4099] == [], run['closed']


def test_every_frame_reaches_novnc_in_the_order_it_arrived(run):
    """RFB is a byte stream: a frame handed over early corrupts the picture even when
    nothing is thrown."""
    assert run['delivered'] == [f'frame-{i}' for i in range(8)], run['delivered']


def test_input_leaves_in_the_order_it_was_typed(run):
    """The server's VncCryptoSession.decrypt refuses any frame but the next one."""
    assert run['sentSeq'] == list(range(8)), run['sentSeq']


def test_each_frame_carries_the_message_it_was_sent_with(run):
    """noVNC hands over a view on its send buffer and rewrites that buffer for the next
    message. Whatever orders the frames must not read the bytes later than send() did."""
    assert run['sentText'] == [f'input-{i}' for i in range(8)], run['sentText']
