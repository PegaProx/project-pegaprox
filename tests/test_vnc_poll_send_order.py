"""The polling console's input reaches the server in the order noVNC sent it.

PollingVncSocket took the frame number in its encrypt and then POSTed the frame without
waiting for the POST before it. noVNC sends several messages in one tick (SetPixelFormat,
SetEncodings and the first update request right after ServerInit, a key down and up, a
paste in chunks), so several send POSTs were out at once, and which one the server saw
first was up to the connections and the greenlets serving them - or to WebCrypto, which may
settle its promises in any order. The server's VncCryptoSession refuses every frame but the
next number and does not move on, so after one swap it refused everything after it: input
and update requests alike, the console froze with nothing on screen to say so.

These run the shipped web/src/vnc_secure_socket.js in node against a fake vnc-poll endpoint
that takes each frame when its request arrives, and hand what arrived to the real
pegaprox/utils/vnc_crypto.py in that order.
"""
import base64
import json
import os
import shutil
import subprocess

import pytest

from pegaprox.utils import vnc_crypto

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, 'web', 'src', 'vnc_secure_socket.js')

HARNESS = r"""
const fs = require('fs');
globalThis.window = globalThis;
globalThis.CloseEvent = class CloseEvent extends Event {
    constructor(type, init) { super(type); Object.assign(this, init || {}); }
};
const sleep = ms => new Promise(r => setTimeout(r, ms));
const mode = process.argv[3];
const arrived = [];                 // data_b64 in the order the server got the requests
let inflight = 0, maxInflight = 0, nSend = 0;
globalThis.fetch = async (url, opts) => {
    const body = JSON.parse(opts.body);
    if (body.action === 'open') return { ok: true, json: async () => ({ ok: true, poll_id: 'p1' }) };
    if (body.action === 'recv') return new Promise(() => {});      // a parked long poll
    if (body.action === 'send') {
        inflight++; maxInflight = Math.max(maxInflight, inflight);
        // 'network' and 'paste': the first request takes the slowest connection
        const lat = mode !== 'webcrypto' ? Math.max(5, 60 - 12 * nSend++) : 10;
        await sleep(lat);
        arrived.push(body.data_b64);
        await sleep(5);
        inflight--;
        return { ok: true, json: async () => ({ ok: true }) };
    }
    return { ok: true, json: async () => ({ ok: true }) };
};
eval(fs.readFileSync(process.argv[2], 'utf-8'));

(async () => {
    const raw = globalThis.crypto.getRandomValues(new Uint8Array(32));
    const keyB64 = Buffer.from(raw).toString('base64');
    const ps = new window.PollingVncSocket('https://pp/vnc-poll', keyB64, 'sid', {});
    await new Promise(r => ps.addEventListener('open', r));
    if (mode === 'webcrypto') {
        // the first call settles last, an order WebCrypto is free to pick. It copies its
        // byte arguments on the call, so this does too
        const subtle = globalThis.crypto.subtle;
        const real = subtle.encrypt.bind(subtle);
        let n = 0;
        subtle.encrypt = (alg, key, data) => {
            const d = Math.max(0, (8 - n++) * 15);
            const a = { ...alg, iv: new Uint8Array(alg.iv), additionalData: new Uint8Array(alg.additionalData) };
            const copy = new Uint8Array(ArrayBuffer.isView(data) ? data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) : data);
            return sleep(d).then(() => real(a, key, copy));
        };
    }
    // the way noVNC sends: a view on ONE buffer that it rewrites for the next message
    const sQ = new Uint8Array(64);
    if (mode === 'paste') {
        // the Paste button: a key down and up per character, all in one tick
        const keys = [];
        for (let i = 0; i < 10000; i++) {
            const keysym = 0x61 + i % 26;
            for (const down of [1, 0]) {
                sQ.set([4, down, 0, 0, 0, 0, 0, keysym]);
                keys.push(...sQ.subarray(0, 8));
                ps.send(new Uint8Array(sQ.buffer, 0, 8));
            }
        }
        await sleep(1500);
        // a pipe takes this much only in parts, exit once it is out
        const out = JSON.stringify({ keyB64, arrived, sent: Buffer.from(keys).toString('base64'), maxInflight });
        process.stdout.write(out + '\n', () => process.exit(0));
        return;
    }
    const sent = [];
    const push = (text) => {
        const m = new TextEncoder().encode(text);
        sQ.set(m);
        sent.push(text);
        ps.send(new Uint8Array(sQ.buffer, 0, m.length));
    };
    push('SetPixelFormat;'); push('SetEncodings;'); push('FBUpdateRequest;');   // one tick
    // then typing, slower than one round trip and faster than two
    for (let i = 0; i < 8; i++) { await sleep(i < 4 ? 4 : 30); push('key' + i + ';'); }
    await sleep(1500);
    console.log(JSON.stringify({ keyB64, arrived, sent: sent.join(''), maxInflight }));
    process.exit(0);
})().catch(e => { console.error(e && e.stack || e); process.exit(3); });
"""


@pytest.fixture(scope='module')
def run(tmp_path_factory):
    if not shutil.which('node'):
        pytest.skip('node is needed to run the shipped socket wrapper')
    harness = tmp_path_factory.mktemp('vncpollsend') / 'harness.js'
    harness.write_text(HARNESS, encoding='utf-8')
    # the WebCrypto globals came with Node 20, Node 18 keeps them behind a flag
    major = int(subprocess.run(['node', '-p', 'process.versions.node.split(".")[0]'], capture_output=True,
                               text=True, timeout=60, check=True).stdout)
    flags = ['--experimental-global-webcrypto'] if major < 20 else []
    cache = {}

    def _run(mode):
        if mode not in cache:
            p = subprocess.run(['node', *flags, str(harness), SRC, mode], capture_output=True, text=True,
                               timeout=60)
            assert p.returncode == 0, p.stderr
            cache[mode] = json.loads(p.stdout.strip().splitlines()[-1])
        return cache[mode]
    return _run


def _server_reads(got):
    """What vms.py vnc-poll send does with each frame, in the order the requests arrived."""
    server = vnc_crypto.VncCryptoSession(base64.b64decode(got['keyB64']))
    out, refused = b'', []
    for i, b64 in enumerate(got['arrived']):
        try:
            out += server.decrypt(base64.b64decode(b64))
        except vnc_crypto.VncCryptoError as e:
            refused.append((i, str(e)))
    return out, refused


@pytest.mark.parametrize('mode', ['network', 'webcrypto'])
def test_the_server_takes_every_frame(run, mode):
    out, refused = _server_reads(run(mode))
    assert refused == [], f'{mode}: the server refused {len(refused)} frames, first {refused[:1]}'


@pytest.mark.parametrize('mode', ['network', 'webcrypto'])
def test_the_input_arrives_whole_and_in_order(run, mode):
    """noVNC rewrites its send buffer for the next message: nothing may read it later."""
    got = run(mode)
    out, _ = _server_reads(got)
    assert out.decode('latin-1') == got['sent'], out


def test_one_send_post_at_a_time(run):
    got = run('network')
    assert got['maxInflight'] == 1, f"{got['maxInflight']} send POSTs were out at once"
    assert len(got['arrived']) >= 3, 'the run never got past one batch'


# pve-http-server websocket_proxy: $max_payload_size = 128 * 1024, it refuses a bigger client
# frame. vnc-poll send hands each POST to PVE as one frame
PVE_MAX_FRAME = 128 * 1024


def test_a_long_paste_goes_in_frames_pve_takes(run):
    """10000 pasted characters are 20000 key events in one tick, 160000 bytes: more than one frame."""
    got = run('paste')
    sizes = [len(base64.b64decode(b)) - vnc_crypto.MIN_FRAME_BYTES for b in got['arrived']]
    assert max(sizes) <= PVE_MAX_FRAME, f'a frame of {max(sizes)} bytes for PVE, it takes {PVE_MAX_FRAME}'
    out, refused = _server_reads(got)
    assert refused == [], f'the server refused {len(refused)} frames, first {refused[:1]}'
    assert out == base64.b64decode(got['sent']), 'the paste did not arrive whole and in order'
    assert got['maxInflight'] == 1, f"{got['maxInflight']} send POSTs were out at once"
