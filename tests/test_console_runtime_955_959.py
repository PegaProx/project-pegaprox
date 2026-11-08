"""The console in a real browser, from the shipped web/index.html: paste on a Spanish keymap
(#959) and Stable Mode under a burst of frames (#955).

The unit tests run the two helpers out of web/src in node. This holds the built page to the
same: the standalone console view, real noVNC from static/, Chromium's WebCrypto, and a
QEMU VNC server played here - RFB 3.8, no authentication, QEMU extended key events
announced so noVNC sends scancodes the way it does against PVE, and in Stable Mode every
frame through pegaprox.utils.vnc_crypto, the server's own code, which checks the order.
The page's websocket for the console is a thin stand-in that hands each frame to this file
and the answers back, several at once when there are several. What a guest then types is
the one thing nothing here can show.

MK Oct 2026
"""
import base64
import re
import struct

import pytest

from pegaprox.utils.vnc_crypto import VncCryptoSession
import test_ha_ui as ha_ui
from test_ha_ui import _App, _FakeServer, browser  # noqa: F401  (browser is a fixture)

CONSOLE = '/api/clusters/c1/vms/pve1/qemu/100/console'
CLUSTERS = [{'id': 'c1', 'name': 'c1', 'host': '10.0.0.9', 'connected': True}]
KEY = bytes(range(32))

# the console's websocket only; anything else the page opens keeps the real one
SOCKET = r"""
(() => {
    const Native = window.WebSocket;
    const b64 = (u8) => { let s = ''; for (let i = 0; i < u8.length; i += 0x8000)
        s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000)); return btoa(s); };
    const unb64 = (s) => Uint8Array.from(atob(s), c => c.charCodeAt(0));
    window.__vncClosed = [];
    class QemuVncSocket {
        static get CONNECTING() { return 0; }
        static get OPEN() { return 1; }
        static get CLOSING() { return 2; }
        static get CLOSED() { return 3; }
        constructor(url, protocols) {
            if (!/\/vncwebsocket/.test(String(url))) return new Native(url, protocols);
            this.url = url; this.binaryType = 'blob';
            this.onopen = null; this.onmessage = null; this.onclose = null; this.onerror = null;
            this._ready = 0; this._l = {};
            setTimeout(() => { this._ready = 1; this._emit('open', new Event('open')); this._toServer(null); }, 0);
        }
        get readyState() { return this._ready; }
        get protocol() { return ''; }
        addEventListener(t, fn) { (this._l[t] = this._l[t] || []).push(fn); }
        removeEventListener(t, fn) { const a = this._l[t] || []; const i = a.indexOf(fn); if (i >= 0) a.splice(i, 1); }
        _emit(t, ev) { (this._l[t] || []).forEach(fn => fn(ev));
                       const on = this['on' + t]; if (typeof on === 'function') on(ev); }
        _toServer(u8) {
            window.__vncToServer(u8 ? b64(u8) : null).then((frames) => {
                for (const f of frames) {           // back to back, as TCP hands a burst over
                    if (this._ready !== 1) return;
                    this._emit('message', new MessageEvent('message', { data: unb64(f).buffer }));
                }
            });
        }
        send(data) {
            const u8 = data instanceof ArrayBuffer ? new Uint8Array(data)
                     : new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
            this._toServer(new Uint8Array(u8));
        }
        close(code, reason) {
            if (this._ready === 3) return;
            this._ready = 3;
            window.__vncClosed.push([code || 1000, reason || '']);
            this._emit('close', new CloseEvent('close', { code: code || 1000, reason: reason || '', wasClean: true }));
        }
    }
    window.WebSocket = QemuVncSocket;
})();
"""


@pytest.fixture
def secure_origin(monkeypatch):
    """WebCrypto only exists in a secure context. The harness intercepts every request
    anyway, so the same fake answers on https and nothing has to hold a certificate."""
    monkeypatch.setattr(ha_ui, 'BASE', 'https://pegaprox.test')
    return ha_ui.BASE


class _QemuVnc:
    """Speaks RFB 3.8 to noVNC and records each key the console sends."""

    def __init__(self, key=None, burst=0):
        self.crypto = VncCryptoSession(key) if key else None
        self.burst = burst
        self.keys = []            # (down, keysym, rfb keycode) - keycode None for a plain KeyEvent
        self.bad_frames = []
        self.stage = 'version'
        self._buf = b''
        self._out = []

    def feed(self, data_b64):
        """One frame from the browser in, whatever the server answers out."""
        if data_b64 is None:
            self._send(b'RFB 003.008\n')
        else:
            msg = base64.b64decode(data_b64)
            if self.crypto:
                try:
                    msg = self.crypto.decrypt(msg)
                except Exception as e:
                    self.bad_frames.append(str(e))
                    msg = b''
            self._buf += msg
            self._advance()
        out, self._out = self._out, []
        return [base64.b64encode(f).decode() for f in out]

    def _send(self, data):
        self._out.append(self.crypto.encrypt(data) if self.crypto else data)

    def _take(self, n):
        if len(self._buf) < n:
            return None
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def _advance(self):
        while True:
            if self.stage == 'version':
                if self._take(12) is None:
                    return
                self._send(b'\x01\x01')                     # one security type: None
                self.stage = 'security'
            elif self.stage == 'security':
                if self._take(1) is None:
                    return
                self._send(b'\x00\x00\x00\x00')             # SecurityResult OK
                self.stage = 'init'
            elif self.stage == 'init':
                if self._take(1) is None:
                    return
                name = b'pve1 qemu 100'
                self._send(struct.pack('>HH', 640, 480)
                           + struct.pack('>BBBBHHHBBB3x', 32, 24, 0, 1, 255, 255, 255, 16, 8, 0)
                           + struct.pack('>I', len(name)) + name)
                # QEMU extended key events, the pseudo-encoding PVE's QEMU announces
                self._send(struct.pack('>BxH', 0, 1) + struct.pack('>HHHHi', 0, 0, 0, 0, -258))
                for _ in range(self.burst):                 # empty updates, each its own frame
                    self._send(struct.pack('>BxH', 0, 0))
                self.stage = 'normal'
            else:
                if not self._buf:
                    return
                t = self._buf[0]
                size = {0: 20, 3: 10, 4: 8, 5: 6, 255: 12}.get(t)
                if t == 2:
                    if len(self._buf) < 4:
                        return
                    size = 4 + 4 * struct.unpack('>H', self._buf[2:4])[0]
                elif t == 6:
                    if len(self._buf) < 8:
                        return
                    size = 8 + struct.unpack('>I', self._buf[4:8])[0]
                if size is None:
                    self._buf = b''                         # nothing we announced
                    return
                m = self._take(size)
                if m is None:
                    return
                if t == 4:
                    self.keys.append((bool(m[1]), struct.unpack('>I', m[4:8])[0], None))
                elif t == 255 and m[1] == 0:
                    down, keysym, code = struct.unpack('>HII', m[2:12])
                    self.keys.append((bool(down), keysym, code))


def _open_console(browser, vnc, stable=False):
    console = {'success': True, 'ticket': 'PVEVNC:runtime', 'port': 5900, 'host': '10.0.0.9',
               'keymap': 'es'}
    if stable:
        console['stable'] = {'session_id': 'enc-runtime', 'key_b64': base64.b64encode(KEY).decode(),
                             'frame_format': 'aes256-gcm-seq32-iv96', 'protocol_version': 1}
    server = _FakeServer(role='standalone', clusters=CLUSTERS, extra={
        ('GET', CONSOLE): (200, console),
        ('POST', '/api/ws/token'): (200, {'token': 'ws-runtime'}),
    })
    app = _App(browser, server)
    app.ctx.add_init_script(SOCKET)
    if stable:
        app.ctx.add_init_script("try { localStorage.setItem('pegaprox-vnc-stable-mode', '1'); } catch (e) {}")
    app.page.expose_function('__vncToServer', vnc.feed)
    app.page.goto(ha_ui.BASE + '/?console=c1:qemu:100:pve1', wait_until='load')
    return app


def _errors(app):
    # on https the page registers its service worker, which the harness does not serve
    return [e for e in app.errors if 'fetching the script' not in e]


def _paste_button(app):
    return app.page.get_by_role('button', name=re.compile('Paste'))


def _wait_connected(app, vnc):
    for _ in range(150):
        if vnc.stage == 'normal' and _paste_button(app).count():
            return
        app.page.wait_for_timeout(100)
    raise AssertionError(f'the console never connected: stage={vnc.stage} errors={app.errors[:3]}')


def _paste(app, vnc, text, keys_expected):
    app.page.once('dialog', lambda d: d.accept(text))
    _paste_button(app).first.click()
    for _ in range(50):
        if len(vnc.keys) >= keys_expected:
            break
        app.page.wait_for_timeout(100)


ALTGR, SHIFT = (0xFE03, 0xB8), (0xFFE1, 0x2A)


def _press(keysym, code, *mods):
    seq = [(True, m[0], m[1]) for m in mods]
    seq += [(True, keysym, code), (False, keysym, code)]
    seq += [(False, m[0], m[1]) for m in reversed(mods)]
    return seq


def test_paste_on_a_spanish_keymap_holds_altgr_and_shift(browser, secure_origin):  # noqa: F811
    vnc = _QemuVnc()
    app = _open_console(browser, vnc)
    try:
        _wait_connected(app, vnc)
        _paste(app, vnc, '@#"(_', 20)
        # scancodes as noVNC puts them on the wire: AltRight 0xb8, ShiftLeft 0x2a, the 2 key
        # 0x03, 3 0x04, 8 0x09, and 0x35 for the key right of the full stop
        assert vnc.keys == (_press(0x40, 0x03, ALTGR) + _press(0x23, 0x04, ALTGR)
                            + _press(0x22, 0x03, SHIFT) + _press(0x28, 0x09, SHIFT)
                            + _press(0x5F, 0x35, SHIFT)), vnc.keys
        assert not _errors(app), _errors(app)
    finally:
        app.ctx.close()


def test_stable_mode_survives_a_burst_of_frames(browser, secure_origin):  # noqa: F811
    """Thirty framebuffer updates right behind the server init, each its own encrypted
    frame - the second used to be checked against a sequence number the first had not
    advanced yet, and the console closed with 4099."""
    vnc = _QemuVnc(key=KEY, burst=30)
    app = _open_console(browser, vnc, stable=True)
    try:
        _wait_connected(app, vnc)
        app.page.wait_for_timeout(1000)
        closed = app.page.evaluate('window.__vncClosed')
        assert not [c for c in closed if c[0] == 4099], closed
        assert not [e for e in _errors(app) if 'integrity' in e.lower() or 'out-of-order' in e], _errors(app)
        assert _paste_button(app).count(), 'the console dropped'
        # what the browser sends has to arrive in order too: vnc_crypto checks every number
        _paste(app, vnc, 'ab', 4)
        assert vnc.bad_frames == [], vnc.bad_frames
        assert [k[1] for k in vnc.keys] == [0x61, 0x61, 0x62, 0x62], vnc.keys
    finally:
        app.ctx.close()
