// MK Apr 2026 — SecureVncSocket: WebSocket-compatible wrapper that does
// AES-256-GCM authenticated encryption around the wire payload.
//
// Why: enterprise TLS-inspection middleboxes (CrowdStrike Falcon Network
// Filter, Palo Alto SSL Decryption, Zscaler, …) re-encrypt the outer TLS,
// inspect the cleartext inside, and sometimes mangle bytes (especially with
// binary protocols they pattern-match as RAT traffic). The byte-mangling
// breaks RFB's DES challenge-response, surfacing as "Authentication failed"
// in the browser. With this wrapper, the WebSocket payload is OUR ciphertext
// — the inspection engine decrypts the outer TLS but only sees opaque AES-GCM
// bytes, so it leaves them alone, so the inner RFB stays byte-perfect.
//
// Frame format (matches pegaprox/utils/vnc_crypto.py):
//   [4 bytes seq big-endian][12 bytes IV (=seq||8 random)][N bytes ciphertext+16 bytes GCM tag]
//
// API: looks like a normal WebSocket from noVNC's perspective. addEventListener
// + onmessage / onopen / onclose / onerror, send(), close(), readyState,
// binaryType. noVNC's Websock.attach() works on either a real WebSocket or any
// object that exposes that surface.

(function () {
    'use strict';

    function _b64ToU8(b64) {
        const bin = atob(b64);
        const out = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
        return out;
    }

    function _u8(buf) {
        return buf instanceof Uint8Array ? buf
             : ArrayBuffer.isView(buf)   ? new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength)
             : buf instanceof ArrayBuffer ? new Uint8Array(buf)
             : new Uint8Array(buf);
    }

    class SecureVncSocket {
        // mirror native WebSocket constants
        static get CONNECTING() { return 0; }
        static get OPEN()       { return 1; }
        static get CLOSING()    { return 2; }
        static get CLOSED()     { return 3; }

        constructor(url, keyB64) {
            // public WebSocket-API surface
            this.binaryType = 'arraybuffer';
            this._readyState = 0;
            this.onopen = null;
            this.onmessage = null;
            this.onclose = null;
            this.onerror = null;
            this._listeners = { open: [], message: [], close: [], error: [], integrityerror: [] };
            this.url = url;

            // crypto state
            this._keyP = window.crypto.subtle.importKey(
                'raw', _b64ToU8(keyB64),
                { name: 'AES-GCM' }, false,
                ['encrypt', 'decrypt']
            );
            this._key = null;
            this._sendSeq = 0;
            this._recvSeq = 0;
            this._sendQueue = [];   // queued plaintext sends while crypto warms up

            // open the underlying WebSocket once the key is ready, so we never
            // accept inbound frames before we can decrypt them
            this._keyP.then((k) => {
                this._key = k;
                this._openSocket();
            }).catch((e) => {
                this._readyState = 3;
                this._dispatch('error', new Event('error'));
                console.error('[SecureVncSocket] importKey failed:', e);
            });
        }

        get readyState() { return this._readyState; }
        get protocol()   { return ''; }   // noVNC checks this; empty = no subprotocol
        get extensions() { return ''; }

        addEventListener(type, fn)    { (this._listeners[type] || (this._listeners[type] = [])).push(fn); }
        removeEventListener(type, fn) {
            const arr = this._listeners[type];
            if (!arr) return;
            const i = arr.indexOf(fn);
            if (i >= 0) arr.splice(i, 1);
        }
        _dispatch(type, ev) {
            // call addEventListener-registered first, then on* handler
            (this._listeners[type] || []).forEach(fn => { try { fn(ev); } catch (e) { console.error(e); } });
            const on = this['on' + type];
            if (typeof on === 'function') { try { on(ev); } catch (e) { console.error(e); } }
        }

        _openSocket() {
            this._ws = new WebSocket(this.url);
            this._ws.binaryType = 'arraybuffer';

            this._ws.addEventListener('open', () => {
                this._readyState = 1;
                this._dispatch('open', new Event('open'));
                // flush any queued sends now that we're open
                while (this._sendQueue.length) {
                    this._encryptAndSend(this._sendQueue.shift());
                }
            });

            this._ws.addEventListener('message', async (e) => {
                try {
                    const plain = await this._decrypt(e.data);
                    // synthesize a MessageEvent so noVNC sees `event.data`
                    const ev = new MessageEvent('message', { data: plain });
                    this._dispatch('message', ev);
                } catch (err) {
                    console.error('[SecureVncSocket] integrity check FAILED:', err);
                    this._dispatch('integrityerror', new MessageEvent('integrityerror', { data: String(err) }));
                    // closing with code 4099 (private range) so the app-level
                    // disconnect handler can recognize this as our integrity-fail signal
                    try { this._ws.close(4099, 'integrity_check_failed'); } catch (_) {}
                }
            });

            this._ws.addEventListener('close', (e) => {
                this._readyState = 3;
                const ev = new CloseEvent('close', {
                    code: e.code, reason: e.reason, wasClean: e.wasClean
                });
                this._dispatch('close', ev);
            });

            this._ws.addEventListener('error', () => {
                this._dispatch('error', new Event('error'));
            });
        }

        async _encrypt(plaintext) {
            const seq = this._sendSeq;
            this._sendSeq = (this._sendSeq + 1) >>> 0;   // wrap at 2^32

            const seqBytes = new Uint8Array(4);
            new DataView(seqBytes.buffer).setUint32(0, seq, false);   // big-endian

            const iv = new Uint8Array(12);
            iv.set(seqBytes);
            window.crypto.getRandomValues(iv.subarray(4));

            const ct = await window.crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: iv, additionalData: seqBytes, tagLength: 128 },
                this._key, plaintext
            );

            const ctU8 = new Uint8Array(ct);
            const frame = new Uint8Array(4 + 12 + ctU8.length);
            frame.set(seqBytes, 0);
            frame.set(iv, 4);
            frame.set(ctU8, 16);
            return frame;
        }

        async _decrypt(data) {
            const u8 = _u8(data);
            if (u8.length < 4 + 12 + 16) {
                throw new Error('frame too short: ' + u8.length + ' bytes');
            }
            const seqBytes = u8.subarray(0, 4);
            const iv = u8.subarray(4, 16);
            const ct = u8.subarray(16);

            const seq = new DataView(seqBytes.buffer, seqBytes.byteOffset, 4).getUint32(0, false);
            const expected = this._recvSeq >>> 0;
            if (seq !== expected) {
                throw new Error(`out-of-order frame: got seq=${seq}, expected ${expected}`);
            }

            // crypto.subtle.decrypt throws on auth-tag mismatch
            const pt = await window.crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: iv, additionalData: seqBytes, tagLength: 128 },
                this._key, ct
            );

            this._recvSeq = (this._recvSeq + 1) >>> 0;
            return pt;
        }

        async _encryptAndSend(plaintext) {
            try {
                const frame = await this._encrypt(plaintext);
                this._ws.send(frame);
            } catch (err) {
                console.error('[SecureVncSocket] encrypt failed:', err);
            }
        }

        send(data) {
            // noVNC may send a string OR a Uint8Array OR an ArrayBuffer
            const u8 = (typeof data === 'string')
                ? new TextEncoder().encode(data)
                : _u8(data);

            if (this._readyState !== 1 || !this._key) {
                // queue until open + key imported
                this._sendQueue.push(u8);
                return;
            }
            this._encryptAndSend(u8);
        }

        close(code, reason) {
            try {
                this._readyState = 2;
                if (this._ws) this._ws.close(code, reason);
            } catch (_) {}
        }
    }

    // ────────────────────────────────────────────────────────────────────
    // PollingVncSocket — HTTPS POST/GET-based fallback transport. Same
    // crypto + same WebSocket-shaped interface, no WS upgrade. Used when
    // the WSS leg between browser and PegaProx is killed by a security
    // middlebox (CrowdStrike WS DPI, Zscaler strict, etc.). Goes through
    // anything that allows plain HTTPS — at the cost of higher latency
    // (~30-80ms per round-trip vs ~1ms for WSS).
    //
    // MK Apr 2026 — third defensive layer alongside Stable Mode + SSH tunnel.
    class PollingVncSocket {
        static get CONNECTING() { return 0; }
        static get OPEN()       { return 1; }
        static get CLOSING()    { return 2; }
        static get CLOSED()     { return 3; }

        // pollUrl: https://.../api/clusters/.../vnc-poll
        // keyB64:  AES-256 session key (base64)
        // encSid:  enc_session id from /console?stable=1 (server claims & stashes for this poll session)
        // opts.pveTicket / opts.pvePort: optional — JS-issued vncproxy ticket+port to reuse
        //   on the server side (avoids the PVE 9.1.x password-mismatch issue, #352).
        constructor(pollUrl, keyB64, encSid, opts) {
            this.binaryType = 'arraybuffer';
            this._readyState = 0;
            this.onopen = null;
            this.onmessage = null;
            this.onclose = null;
            this.onerror = null;
            this._listeners = { open: [], message: [], close: [], error: [], integrityerror: [] };
            this.url = pollUrl;
            this._encSid = encSid;
            this._pveTicket = (opts && opts.pveTicket) || null;
            this._pvePort = (opts && opts.pvePort) || null;
            this._pollId = null;
            this._closed = false;
            this._sendSeq = 0;
            this._recvSeq = 0;
            this._recvLoopP = null;

            this._keyP = window.crypto.subtle.importKey(
                'raw', _b64ToU8(keyB64), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']
            );
            this._key = null;

            this._keyP.then(async (k) => {
                this._key = k;
                try {
                    await this._open();
                } catch (e) {
                    console.error('[PollingVncSocket] open failed:', e);
                    this._readyState = 3;
                    this._dispatch('error', new Event('error'));
                    this._dispatch('close', new CloseEvent('close', { code: 1006, reason: 'open_failed', wasClean: false }));
                }
            });
        }

        get readyState() { return this._readyState; }
        get protocol()   { return ''; }
        get extensions() { return ''; }

        addEventListener(type, fn)    { (this._listeners[type] || (this._listeners[type] = [])).push(fn); }
        removeEventListener(type, fn) {
            const arr = this._listeners[type];
            if (!arr) return;
            const i = arr.indexOf(fn);
            if (i >= 0) arr.splice(i, 1);
        }
        _dispatch(type, ev) {
            (this._listeners[type] || []).forEach(fn => { try { fn(ev); } catch (e) { console.error(e); } });
            const on = this['on' + type];
            if (typeof on === 'function') { try { on(ev); } catch (e) { console.error(e); } }
        }

        async _post(body) {
            const r = await fetch(this.url, {
                method: 'POST',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body),
            });
            if (!r.ok) throw new Error(`HTTP ${r.status}`);
            return r.json();
        }

        async _open() {
            const openBody = { action: 'open', enc_session: this._encSid };
            if (this._pveTicket && this._pvePort) {
                openBody.pve_ticket = this._pveTicket;
                openBody.pve_port = this._pvePort;
            }
            const r = await this._post(openBody);
            if (!r.ok || !r.poll_id) throw new Error('open: ' + JSON.stringify(r));
            this._pollId = r.poll_id;
            this._readyState = 1;
            this._dispatch('open', new Event('open'));
            this._recvLoopP = this._recvLoop();
        }

        async _recvLoop() {
            while (!this._closed) {
                let r;
                try {
                    r = await this._post({ action: 'recv', poll_id: this._pollId, max_wait: 5.0 });
                } catch (e) {
                    if (this._closed) return;
                    console.warn('[PollingVncSocket] recv error, retrying in 1s:', e);
                    await new Promise(res => setTimeout(res, 1000));
                    continue;
                }
                if (!r.ok) break;
                for (const c64 of (r.chunks_b64 || [])) {
                    const ct = _b64ToU8(c64);
                    try {
                        const plain = await this._decrypt(ct);
                        this._dispatch('message', new MessageEvent('message', { data: plain }));
                    } catch (err) {
                        console.error('[PollingVncSocket] integrity check FAILED:', err);
                        this._dispatch('integrityerror', new MessageEvent('integrityerror', { data: String(err) }));
                        this.close(4099, 'integrity_check_failed');
                        return;
                    }
                }
                if (r.closed) break;
            }
            if (!this._closed) {
                this._readyState = 3;
                this._closed = true;
                this._dispatch('close', new CloseEvent('close', { code: 1000, reason: 'remote_closed', wasClean: true }));
            }
        }

        async _encrypt(plaintext) {
            const seq = this._sendSeq;
            this._sendSeq = (this._sendSeq + 1) >>> 0;
            const seqBytes = new Uint8Array(4);
            new DataView(seqBytes.buffer).setUint32(0, seq, false);
            const iv = new Uint8Array(12);
            iv.set(seqBytes);
            window.crypto.getRandomValues(iv.subarray(4));
            const ct = await window.crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: iv, additionalData: seqBytes, tagLength: 128 },
                this._key, plaintext
            );
            const ctU8 = new Uint8Array(ct);
            const frame = new Uint8Array(4 + 12 + ctU8.length);
            frame.set(seqBytes, 0);
            frame.set(iv, 4);
            frame.set(ctU8, 16);
            return frame;
        }

        async _decrypt(data) {
            const u8 = _u8(data);
            if (u8.length < 4 + 12 + 16) throw new Error('frame too short: ' + u8.length);
            const seqBytes = u8.subarray(0, 4);
            const iv = u8.subarray(4, 16);
            const ct = u8.subarray(16);
            const seq = new DataView(seqBytes.buffer, seqBytes.byteOffset, 4).getUint32(0, false);
            const expected = this._recvSeq >>> 0;
            if (seq !== expected) throw new Error(`out-of-order frame: got ${seq}, expected ${expected}`);
            const pt = await window.crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: iv, additionalData: seqBytes, tagLength: 128 },
                this._key, ct
            );
            this._recvSeq = (this._recvSeq + 1) >>> 0;
            return pt;
        }

        async _bufToB64(u8) {
            // bigger buffers in chunks to avoid stack issues
            let s = '';
            for (let i = 0; i < u8.length; i += 0x8000) {
                s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
            }
            return btoa(s);
        }

        async send(data) {
            if (this._closed || this._readyState !== 1 || !this._key || !this._pollId) {
                // could queue, but in practice noVNC waits for `open` event
                return;
            }
            const u8 = (typeof data === 'string') ? new TextEncoder().encode(data) : _u8(data);
            try {
                const frame = await this._encrypt(u8);
                const b64 = await this._bufToB64(frame);
                await this._post({ action: 'send', poll_id: this._pollId, data_b64: b64 });
            } catch (err) {
                console.error('[PollingVncSocket] send failed:', err);
                this._dispatch('error', new Event('error'));
            }
        }

        close(code, reason) {
            if (this._closed) return;
            this._closed = true;
            this._readyState = 2;
            const pid = this._pollId;
            if (pid) {
                // fire-and-forget close on the server
                this._post({ action: 'close', poll_id: pid }).catch(() => {});
            }
            this._readyState = 3;
            this._dispatch('close', new CloseEvent('close', { code: code || 1000, reason: reason || '', wasClean: true }));
        }
    }

    // ────────────────────────────────────────────────────────────────────
    // connectVnc(opts) — unified socket factory with auto-fallback.
    //
    // opts:
    //   wsUrl           — wss://… (Stable-Mode WebSocket)
    //   pollUrl         — https://…/vnc-poll   (HTTP-polling fallback)
    //   wsKey           — base64 AES key for wsUrl
    //   getPollHandle   — async () => {key_b64, session_id}  — called LAZILY,
    //                     only if WS actually needs to fall back. Issues a fresh
    //                     console?stable=1 ticket when invoked. We do this lazy
    //                     rather than pre-fetching because PVE 9.1.x (issue #352
    //                     follow-up) doesn't tolerate two concurrent vncproxy
    //                     sessions on the same VM — the second call interferes
    //                     with the first and produces a recv=60B short session.
    //   wsTimeoutMs     — how long to wait for WS `open` before falling back (default 4000)
    //   onTransport(t)  — called with 'ws' or 'poll' when committed
    //   forcePolling    — skip WS, go straight to polling (debug)
    //
    // Returns a Promise resolving to the chosen socket-shaped object.
    function connectVnc(opts) {
        return new Promise((resolve) => {
            const {
                wsUrl, pollUrl, wsKey, getPollHandle,
                wsTimeoutMs = 4000, onTransport, forcePolling,
            } = opts;

            let committed = false;
            const commit = (sock, kind) => {
                if (committed) return;
                committed = true;
                if (typeof onTransport === 'function') { try { onTransport(kind); } catch(_){} }
                resolve(sock);
            };

            const goPolling = async (reason) => {
                if (committed) return;
                console.warn('[connectVnc] falling back to HTTP-polling:', reason);
                if (typeof getPollHandle !== 'function') {
                    console.error('[connectVnc] no getPollHandle provided — cannot fall back');
                    return;
                }
                let handle;
                try { handle = await getPollHandle(); }
                catch (e) { console.error('[connectVnc] getPollHandle failed:', e); return; }
                if (committed) return;
                if (!handle || !handle.key_b64 || !handle.session_id) {
                    console.error('[connectVnc] getPollHandle returned no usable handle');
                    return;
                }
                const ps = new PollingVncSocket(pollUrl, handle.key_b64, handle.session_id, {
                    pveTicket: handle.pve_ticket, pvePort: handle.pve_port,
                });
                ps.addEventListener('open', () => commit(ps, 'poll'));
                ps.addEventListener('close', () => {
                    if (!committed) commit(ps, 'poll');
                });
            };

            if (forcePolling) {
                goPolling('forcePolling=true');
                return;
            }

            const ws = new SecureVncSocket(wsUrl, wsKey);
            const failTimer = setTimeout(() => {
                try { ws.close(4090, 'timeout_falling_back'); } catch(_){}
                goPolling('WSS open timed out after ' + wsTimeoutMs + 'ms');
            }, wsTimeoutMs);
            ws.addEventListener('open', () => {
                clearTimeout(failTimer);
                commit(ws, 'ws');
            });
            ws.addEventListener('close', (e) => {
                clearTimeout(failTimer);
                if (!committed) goPolling('WSS closed before open: code=' + e.code);
            });
            ws.addEventListener('error', () => {
                // wait for `close` to follow
            });
        });
    }

    // expose globally — concat'd into compiled bundle, picked up by node_modals.js
    window.SecureVncSocket = SecureVncSocket;
    window.PollingVncSocket = PollingVncSocket;
    window.connectVnc = connectVnc;
})();
