# -*- coding: utf-8 -*-
"""
Web Push (browser notifications) — MK May 2026.

Implements VAPID auth manually using `cryptography` so we don't pull in
pywebpush as a dep. We use the "wake-up" pattern:

  push provider --[empty body]--> service worker
  service worker --GET /api/push/inbox--> server
  service worker --showNotification--> user

This means the push provider never sees alert payloads, and the SW always
fetches the freshest data — old wake-ups can't show stale alerts.

VAPID key is generated once and stashed in server_settings.

Endpoints:
  GET    /api/push/vapid-key       -> public key (b64url)
  POST   /api/push/subscribe       -> save subscription
  POST   /api/push/unsubscribe     -> drop subscription
  POST   /api/push/test            -> send wake-up to caller's subs
  GET    /api/push/inbox           -> recent items for caller (since=<ts>)
  POST   /api/push/inbox/clear     -> mark all read

Notification handler is registered into alerts._notification_handlers via
register_alert_handler() (called from app.py).
"""
import os
import json
import time
import base64
import logging
import urllib.parse
from datetime import datetime, timedelta
from flask import Blueprint, jsonify, request
from concurrent.futures import ThreadPoolExecutor

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.backends import default_backend

from pegaprox.utils.auth import require_auth
from pegaprox.core.db import get_db

bp = Blueprint('push', __name__)

_VAPID_KEY_NAME = 'webpush_vapid_keypair'
_VAPID_SUBJECT = 'mailto:admin@pegaprox.local'

# Push send pool — non-blocking, alerts thread shouldn't wait on HTTPS round-trips
_send_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix='push-send')


# ──────────────────────────────────────────────────────────────────────────
# VAPID key management
# ──────────────────────────────────────────────────────────────────────────

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode('ascii').rstrip('=')


def _b64url_decode(s: str) -> bytes:
    pad = '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def _current_user():
    """Return the logged-in username string. PegaProx stores user in
    request.session (populated by @require_auth), NOT Flask's flask.session."""
    try:
        u = request.session.get('user') if hasattr(request, 'session') else ''
        if isinstance(u, dict):
            return u.get('username', '') or ''
        return u or ''
    except Exception:
        return ''



def _generate_vapid_keypair():
    priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode('ascii')
    pub_numbers = priv.public_key().public_numbers()
    # uncompressed point: 0x04 || X(32) || Y(32)
    pub_raw = b'\x04' + pub_numbers.x.to_bytes(32, 'big') + pub_numbers.y.to_bytes(32, 'big')
    pub_b64 = _b64url(pub_raw)
    return {'private_pem': priv_pem, 'public_b64': pub_b64}


def _load_vapid():
    """Get VAPID keys; generate + persist on first call.

    MK May 2026 (audit fix M-1) — private key is now stored encrypted at rest
    using db._encrypt(), matching the pattern used by smtp_password,
    ldap_bind_password and oidc_client_secret. Old plaintext entries are
    re-encrypted in-place on first load.
    """
    db = get_db()
    c = db.conn.cursor()
    try:
        c.execute('SELECT value FROM server_settings WHERE key = ?', (_VAPID_KEY_NAME,))
        r = c.fetchone()
        if r and r['value']:
            try:
                stored = json.loads(r['value'])
                priv_pem_field = stored.get('private_pem', '')
                # detect already-encrypted vs legacy plaintext PEM
                if priv_pem_field.startswith(('aes256:', 'enc:')):
                    decrypted = db._decrypt(priv_pem_field)
                    if decrypted:
                        return {'private_pem': decrypted, 'public_b64': stored['public_b64']}
                    # fall through and regen if decrypt failed
                    logging.warning("[push] VAPID decrypt failed, regenerating keypair")
                else:
                    # Legacy plaintext — usable as-is, but rewrite encrypted
                    if '-----BEGIN' in priv_pem_field:
                        try:
                            enc = db._encrypt(priv_pem_field)
                            c.execute(
                                'INSERT OR REPLACE INTO server_settings (key, value) VALUES (?, ?)',
                                (_VAPID_KEY_NAME, json.dumps({
                                    'private_pem': enc,
                                    'public_b64': stored['public_b64'],
                                }))
                            )
                            db.conn.commit()
                            logging.info("[push] migrated VAPID private key to encrypted storage")
                        except Exception as e:
                            logging.warning(f"[push] VAPID re-encrypt failed (continuing with plaintext): {e}")
                        return stored
            except Exception:
                pass
    except Exception as e:
        logging.warning(f"[push] vapid load failed: {e}")

    kp = _generate_vapid_keypair()
    try:
        enc = db._encrypt(kp['private_pem'])
        c.execute(
            'INSERT OR REPLACE INTO server_settings (key, value) VALUES (?, ?)',
            (_VAPID_KEY_NAME, json.dumps({
                'private_pem': enc,
                'public_b64': kp['public_b64'],
            }))
        )
        db.conn.commit()
        logging.info("[push] generated new VAPID keypair (encrypted at rest)")
    except Exception as e:
        logging.error(f"[push] vapid persist failed: {e}")
    return kp


def _vapid_jwt(audience: str) -> str:
    """Sign a VAPID JWT for one push-service origin. ES256."""
    kp = _load_vapid()
    priv = serialization.load_pem_private_key(
        kp['private_pem'].encode('ascii'), password=None, backend=default_backend()
    )
    header = {'typ': 'JWT', 'alg': 'ES256'}
    claims = {
        'aud': audience,
        'exp': int(time.time()) + 12 * 3600,
        'sub': _VAPID_SUBJECT,
    }
    h = _b64url(json.dumps(header, separators=(',', ':')).encode('ascii'))
    p = _b64url(json.dumps(claims, separators=(',', ':')).encode('ascii'))
    signing_input = f"{h}.{p}".encode('ascii')
    der_sig = priv.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)
    raw_sig = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
    return f"{h}.{p}.{_b64url(raw_sig)}"


# ──────────────────────────────────────────────────────────────────────────
# Inbox (push_inbox in-memory queue + DB-backed for resilience after restart)
# Kept tiny — drops anything older than 24h.
# ──────────────────────────────────────────────────────────────────────────

def _ensure_inbox_table():
    try:
        c = get_db().conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS push_inbox (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                title TEXT NOT NULL,
                body TEXT DEFAULT '',
                severity TEXT DEFAULT 'info',
                url TEXT DEFAULT '',
                tag TEXT DEFAULT '',
                created_at TEXT NOT NULL,
                read_at TEXT
            )
        ''')
        c.execute('CREATE INDEX IF NOT EXISTS idx_push_inbox_user ON push_inbox(username, created_at DESC)')
        get_db().conn.commit()
    except Exception as e:
        logging.warning(f"[push] inbox table ensure failed: {e}")


_ensure_inbox_table()


def _push_to_inbox(username, title, body='', severity='info', url='', tag=''):
    try:
        c = get_db().conn.cursor()
        c.execute('''
            INSERT INTO push_inbox (username, title, body, severity, url, tag, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (username, title, body, severity, url, tag, datetime.now().isoformat()))
        get_db().conn.commit()
    except Exception as e:
        logging.warning(f"[push] inbox insert failed: {e}")


def _trim_inbox():
    """Drop entries older than 24h. Cheap, called from inbox endpoint."""
    try:
        cutoff = (datetime.now() - timedelta(hours=24)).isoformat()
        c = get_db().conn.cursor()
        c.execute('DELETE FROM push_inbox WHERE created_at < ?', (cutoff,))
        get_db().conn.commit()
    except Exception:
        pass


# ──────────────────────────────────────────────────────────────────────────
# Wake-up push send
# ──────────────────────────────────────────────────────────────────────────

def _send_one(endpoint: str, sub_id: int):
    """Fire one wake-up push (no payload) to the given subscription."""
    try:
        import urllib.request
        parsed = urllib.parse.urlparse(endpoint)
        audience = f"{parsed.scheme}://{parsed.netloc}"
        jwt = _vapid_jwt(audience)
        kp = _load_vapid()

        req = urllib.request.Request(
            endpoint,
            data=b'',
            method='POST',
            headers={
                'Authorization': f"vapid t={jwt}, k={kp['public_b64']}",
                'TTL': '60',
                'Urgency': 'normal',
                'Content-Length': '0',
            }
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            code = resp.getcode()
            if 200 <= code < 300:
                # success — reset failure counter
                try:
                    c = get_db().conn.cursor()
                    c.execute('UPDATE push_subscriptions SET failures = 0, last_used_at = ? WHERE id = ?',
                              (datetime.now().isoformat(), sub_id))
                    get_db().conn.commit()
                except Exception: pass
                return True
            logging.warning(f"[push] sub {sub_id} got {code}")
            return False
    except Exception as e:
        msg = str(e)
        logging.info(f"[push] sub {sub_id} send failed: {msg[:200]}")
        # 410 Gone → push provider says subscription is dead, drop it
        try:
            if '410' in msg or '404' in msg:
                c = get_db().conn.cursor()
                c.execute('DELETE FROM push_subscriptions WHERE id = ?', (sub_id,))
                get_db().conn.commit()
                logging.info(f"[push] dropped stale sub {sub_id}")
            else:
                c = get_db().conn.cursor()
                c.execute('UPDATE push_subscriptions SET failures = COALESCE(failures,0)+1 WHERE id = ?', (sub_id,))
                # auto-prune after 5 consecutive failures
                c.execute('DELETE FROM push_subscriptions WHERE id = ? AND failures >= 5', (sub_id,))
                get_db().conn.commit()
        except Exception: pass
        return False


def _wake_user(username: str):
    """Fan out wake-up pushes to all subs of a user."""
    try:
        c = get_db().conn.cursor()
        c.execute('SELECT id, endpoint FROM push_subscriptions WHERE username = ?', (username,))
        rows = list(c.fetchall())
    except Exception as e:
        logging.warning(f"[push] sub lookup failed: {e}")
        return
    for r in rows:
        _send_pool.submit(_send_one, r['endpoint'], r['id'])


def _wake_all():
    """Wake every subscriber (used for global cluster alerts)."""
    try:
        c = get_db().conn.cursor()
        c.execute('SELECT id, endpoint, username FROM push_subscriptions')
        rows = list(c.fetchall())
    except Exception as e:
        logging.warning(f"[push] sub-all lookup failed: {e}")
        return
    for r in rows:
        _send_pool.submit(_send_one, r['endpoint'], r['id'])


# ──────────────────────────────────────────────────────────────────────────
# Alert handler hook — registered into background.alerts._notification_handlers
# ──────────────────────────────────────────────────────────────────────────

def _alert_handler(alert_data: dict):
    """Receives every alert from background/alerts.py. Stores in inbox per
    *all* admin users (since alerts aren't user-scoped today) and sends
    a wake-up push to every registered subscription."""
    try:
        title = alert_data.get('alert_name') or 'PegaProx Alert'
        body = alert_data.get('message') or ''
        sev = alert_data.get('severity', 'info')
        cid = alert_data.get('cluster_id', '')
        url = f"/?cluster={cid}#alerts" if cid else '/'
        tag = f"alert-{alert_data.get('alert_name','')}"

        # fan out to any user that has a subscription
        try:
            c = get_db().conn.cursor()
            c.execute('SELECT DISTINCT username FROM push_subscriptions')
            users = [r['username'] for r in c.fetchall()]
        except Exception:
            users = []

        for u in users:
            _push_to_inbox(u, title, body, sev, url, tag)
        _wake_all()
    except Exception as e:
        logging.debug(f"[push] alert_handler swallowed: {e}")


def register_alert_handler():
    """Attaches _alert_handler to alerts._notification_handlers if not already."""
    try:
        from pegaprox.background import alerts as alerts_mod
        if _alert_handler not in alerts_mod._notification_handlers:
            alerts_mod._notification_handlers.append(_alert_handler)
            logging.info("[push] alert handler registered")
    except Exception as e:
        logging.warning(f"[push] could not register alert handler: {e}")


# ──────────────────────────────────────────────────────────────────────────
# Endpoints
# ──────────────────────────────────────────────────────────────────────────

@bp.route('/api/push/vapid-key', methods=['GET'])
@require_auth()
def vapid_key():
    kp = _load_vapid()
    return jsonify({'public_key': kp['public_b64']})


def _is_internal_or_metadata_host(host):
    """Block RFC1918 / loopback / link-local / cloud metadata endpoints.
    MK May 2026 (audit fix M-12) — even though wake-up pushes carry no body,
    a malicious subscriber could turn the SIEM-style queue into a port-scan
    or metadata-fetch oracle by registering an internal endpoint and watching
    /api/siem/targets-style status fields. Blocking at subscribe time makes
    the attack surface basically nil."""
    import ipaddress, socket
    if not host:
        return True
    # strip :port if present
    h = host.split(':', 1)[0].strip('[]')
    # quick string checks
    if h in ('localhost', '0.0.0.0', '::', '::1'):
        return True
    if h.endswith('.local') or h.endswith('.internal') or h.endswith('.localdomain'):
        return True
    # parse as IP
    try:
        ip = ipaddress.ip_address(h)
        # block private + loopback + link-local + multicast + unspecified +
        # carrier-grade NAT (100.64/10) + AWS/GCP metadata (169.254.169.254)
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_unspecified or ip.is_reserved):
            return True
        if str(ip).startswith('100.'):  # CGN range — too coarse but safer
            try:
                if ipaddress.ip_address('100.64.0.0') <= ip <= ipaddress.ip_address('100.127.255.255'):
                    return True
            except Exception:
                pass
    except ValueError:
        # not an IP — try DNS resolution to catch hostnames pointing internal
        try:
            resolved = socket.gethostbyname(h)
            return _is_internal_or_metadata_host(resolved)
        except Exception:
            # can't resolve — let it through (offline DNS shouldn't deny)
            return False
    return False


@bp.route('/api/push/subscribe', methods=['POST'])
@require_auth()
def subscribe():
    body = request.get_json(silent=True) or {}
    endpoint = body.get('endpoint')
    keys = body.get('keys') or {}
    p256dh = keys.get('p256dh')
    auth = keys.get('auth')
    ua = (request.headers.get('User-Agent') or '')[:200]
    if not endpoint or not p256dh or not auth:
        return jsonify({'error': 'endpoint, keys.p256dh, keys.auth required'}), 400

    # MK May 2026 (audit fix M-12) — endpoint URL validation. Must be HTTPS,
    # must point at a reachable public host (or, for self-hosted push services,
    # at least not a local/RFC1918/metadata address).
    try:
        u = urllib.parse.urlparse(endpoint)
    except Exception:
        u = None
    if (not u or u.scheme != 'https' or not u.hostname):
        return jsonify({'error': 'endpoint must be a valid https URL'}), 400
    if _is_internal_or_metadata_host(u.hostname):
        logging.warning(f"[push] subscribe rejected — internal/metadata host: {u.hostname}")
        return jsonify({'error': 'endpoint host is not allowed'}), 400

    user = _current_user()
    if not user:
        return jsonify({'error': 'session missing'}), 401

    try:
        c = get_db().conn.cursor()
        c.execute('''
            INSERT INTO push_subscriptions (username, endpoint, p256dh, auth, user_agent, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(endpoint) DO UPDATE SET
                username=excluded.username,
                p256dh=excluded.p256dh,
                auth=excluded.auth,
                user_agent=excluded.user_agent,
                failures=0
        ''', (user, endpoint, p256dh, auth, ua, datetime.now().isoformat()))
        get_db().conn.commit()
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/push/unsubscribe', methods=['POST'])
@require_auth()
def unsubscribe():
    body = request.get_json(silent=True) or {}
    endpoint = body.get('endpoint')
    if not endpoint:
        return jsonify({'error': 'endpoint required'}), 400
    try:
        c = get_db().conn.cursor()
        c.execute('DELETE FROM push_subscriptions WHERE endpoint = ?', (endpoint,))
        get_db().conn.commit()
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/push/subscriptions', methods=['GET'])
@require_auth()
def list_subs():
    user = _current_user()
    try:
        c = get_db().conn.cursor()
        c.execute('''SELECT id, endpoint, user_agent, created_at, last_used_at, failures
                     FROM push_subscriptions WHERE username = ? ORDER BY created_at DESC''', (user,))
        out = []
        for r in c.fetchall():
            d = dict(r)
            # truncate endpoint URL for display privacy
            ep = d.get('endpoint', '')
            d['endpoint_short'] = (ep[:32] + '…' + ep[-12:]) if len(ep) > 50 else ep
            out.append(d)
        return jsonify({'subscriptions': out})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/push/test', methods=['POST'])
@require_auth()
def send_test():
    user = _current_user()
    if not user:
        return jsonify({'error': 'session missing'}), 401
    _push_to_inbox(user,
                   'PegaProx — Test Push',
                   'If you see this, browser notifications are working.',
                   'info', '/', 'test-push')
    _wake_user(user)
    return jsonify({'ok': True})


@bp.route('/api/push/inbox', methods=['GET'])
@require_auth()
def inbox():
    user = _current_user()
    if not user:
        return jsonify({'items': []})
    _trim_inbox()
    since = request.args.get('since', '')  # iso timestamp
    only_unread = request.args.get('unread', '').lower() in ('1', 'true', 'yes')
    try:
        c = get_db().conn.cursor()
        q = 'SELECT * FROM push_inbox WHERE username = ?'
        params = [user]
        if since:
            q += ' AND created_at > ?'
            params.append(since)
        if only_unread:
            q += ' AND read_at IS NULL'
        q += ' ORDER BY created_at DESC LIMIT 50'
        c.execute(q, params)
        rows = [dict(r) for r in c.fetchall()]
        return jsonify({'items': rows})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/push/inbox/clear', methods=['POST'])
@require_auth()
def inbox_clear():
    user = _current_user()
    try:
        c = get_db().conn.cursor()
        c.execute('UPDATE push_inbox SET read_at = ? WHERE username = ? AND read_at IS NULL',
                  (datetime.now().isoformat(), user))
        get_db().conn.commit()
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
