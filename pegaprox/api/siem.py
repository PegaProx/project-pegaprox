# -*- coding: utf-8 -*-
"""
SIEM Forwarder — MK May 2026.

Pushes audit log events out to one or more SIEM-style targets so customers
can ingest them into their existing Splunk / Elastic / Loki / syslog pipeline
without polling our /api/audit endpoint on a cron.

Architecture:
  log_audit() → db.add_audit_entry() → enqueue() → background worker thread
  → fan-out to every enabled target → format per type → send → retry on fail

Supported target types:
  syslog_udp  — RFC 5424 over UDP, host:port
  syslog_tcp  — RFC 5424 over TCP, host:port
  http_json   — POST JSON body to endpoint (Loki/Promtail, generic webhook)
  splunk_hec  — Splunk HTTP Event Collector with token auth
  elastic     — POST to Elasticsearch _doc endpoint with optional Basic auth
  generic     — POST text body to endpoint (for curl-able dump targets)

Settings JSON shape varies per type:
  syslog_*    : {facility: 'local0', host_override: ''}
  http_json   : {headers: {...}, label_field: 'pegaprox_audit'}
  splunk_hec  : {token: '...', sourcetype: 'pegaprox', index: 'main'}
  elastic     : {username: '', password: '', index: 'pegaprox-audit'}
  generic     : {headers: {...}}

Each delivery attempt is non-blocking; failures bump error_count on the
target row but don't block the queue or the next event.
"""
import os
import json
import time
import socket
import uuid
import base64
import logging
import threading
import urllib.request
import urllib.parse
from queue import Queue, Empty
from datetime import datetime
from flask import Blueprint, jsonify, request, session

from pegaprox.utils.auth import require_auth
from pegaprox.core.db import get_db
from pegaprox.models.permissions import ROLE_ADMIN

bp = Blueprint('siem', __name__)


# ── In-process queue + worker thread ──────────────────────────────────────
_queue = Queue(maxsize=10000)
_worker_running = False
_worker_lock = threading.Lock()
TYPES = {'syslog_udp', 'syslog_tcp', 'http_json', 'splunk_hec', 'elastic', 'generic'}


def enqueue(event: dict):
    """Hand off an audit event to the SIEM queue. Non-blocking; drops on
    overflow rather than backing up the audit write path."""
    try:
        _queue.put_nowait(event)
    except Exception:
        # Queue full — log once at WARNING then move on. The audit DB is
        # still authoritative, so SIEM gaps aren't catastrophic.
        logging.warning("[siem] queue full, dropping event")


def _current_user():
    try:
        u = request.session.get('user') if hasattr(request, 'session') else ''
        if isinstance(u, dict):
            return u.get('username', '') or ''
        return u or ''
    except Exception:
        return ''


def _row_to_target(row):
    try:
        settings = json.loads(row['settings'] or '{}')
    except Exception:
        settings = {}
    return {
        'id': row['id'],
        'name': row['name'],
        'type': row['type'],
        'endpoint': row['endpoint'],
        'format': row['format'] or 'json',
        'enabled': bool(row['enabled']),
        'settings': settings,
        'last_status': row['last_status'] or '',
        'last_ok_at': row['last_ok_at'],
        'last_error_at': row['last_error_at'],
        'last_error': row['last_error'] or '',
        'sent_count': row['sent_count'] or 0,
        'error_count': row['error_count'] or 0,
        'created_at': row['created_at'],
        'created_by': row['created_by'] or '',
    }


def _list_enabled():
    try:
        c = get_db().conn.cursor()
        c.execute('SELECT * FROM siem_targets WHERE enabled = 1')
        return [_row_to_target(r) for r in c.fetchall()]
    except Exception as e:
        logging.debug(f"[siem] list_enabled failed: {e}")
        return []


def _record_result(target_id, ok, msg=''):
    try:
        c = get_db().conn.cursor()
        now = datetime.now().isoformat()
        if ok:
            c.execute('''UPDATE siem_targets
                         SET last_ok_at = ?, last_status = 'ok',
                             sent_count = COALESCE(sent_count,0) + 1
                         WHERE id = ?''', (now, target_id))
        else:
            c.execute('''UPDATE siem_targets
                         SET last_error_at = ?, last_status = 'error',
                             last_error = ?,
                             error_count = COALESCE(error_count,0) + 1
                         WHERE id = ?''', (now, str(msg)[:500], target_id))
        get_db().conn.commit()
    except Exception:
        pass


# ── Formatters ────────────────────────────────────────────────────────────

def _to_syslog_5424(event, app='pegaprox', facility='local0'):
    """Build an RFC 5424 syslog line. PRI = facility*8 + severity."""
    fac_map = {'kern': 0, 'user': 1, 'mail': 2, 'daemon': 3, 'auth': 4,
               'syslog': 5, 'lpr': 6, 'news': 7, 'uucp': 8, 'cron': 9,
               'authpriv': 10, 'ftp': 11,
               'local0': 16, 'local1': 17, 'local2': 18, 'local3': 19,
               'local4': 20, 'local5': 21, 'local6': 22, 'local7': 23}
    fac = fac_map.get(facility, 16)
    sev = {'critical': 2, 'warning': 4, 'info': 6}.get(event.get('severity', 'info'), 6)
    pri = fac * 8 + sev
    ts = event.get('timestamp', datetime.now().isoformat())
    host = socket.gethostname() or '-'
    msgid = event.get('action', '-').replace(' ', '_')[:32] or '-'
    sd = '-'
    msg = (
        f"user={event.get('user', '-')} "
        f"action={event.get('action', '-')} "
        f"cluster={event.get('cluster', '') or '-'} "
        f"ip={event.get('ip_address', '') or '-'} "
        f"details={(event.get('details') or '').replace(chr(10), ' ')[:400]}"
    )
    return f"<{pri}>1 {ts} {host} {app} - {msgid} {sd} {msg}"


def _to_json_line(event):
    """Plain JSON dict for HTTP-JSON / Splunk / Elastic / generic webhook bodies."""
    return {
        'timestamp': event.get('timestamp'),
        'user': event.get('user', ''),
        'action': event.get('action', ''),
        'severity': event.get('severity', 'info'),
        'cluster': event.get('cluster', ''),
        'ip': event.get('ip_address', ''),
        'details': event.get('details', ''),
        'source': 'pegaprox',
    }


# ── Senders per target type ───────────────────────────────────────────────

def _send_syslog(target, event, proto='udp'):
    settings = target.get('settings', {})
    ep = target['endpoint']
    if ':' not in ep:
        raise ValueError('endpoint must be host:port')
    host, port = ep.rsplit(':', 1)
    port = int(port)
    line = _to_syslog_5424(event, facility=settings.get('facility', 'local0'))
    if proto == 'udp':
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        try:
            sock.sendto(line.encode('utf-8'), (host, port))
        finally:
            sock.close()
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            sock.connect((host, port))
            # RFC 6587 octet-counting framing for TCP syslog
            data = line.encode('utf-8')
            sock.sendall(f"{len(data)} ".encode('ascii') + data)
        finally:
            sock.close()


def _verify_tls_for(target):
    """settings.verify_tls — default True (MK May 2026 audit fix M-4)."""
    return bool((target.get('settings') or {}).get('verify_tls', True))


def _http_post(url, body_bytes, headers, timeout=10, verify_tls=True):
    """Plain urllib HTTPS POST. MK May 2026 — TLS verification on by default;
    admins opt out per target if they're shipping to a self-signed SIEM."""
    import ssl
    req = urllib.request.Request(url, data=body_bytes, method='POST', headers=headers)
    if verify_tls:
        ctx = ssl.create_default_context()
    else:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        code = resp.getcode()
        if not (200 <= code < 300):
            raise RuntimeError(f"HTTP {code}")
        return code


def _send_http_json(target, event):
    settings = target.get('settings') or {}
    headers = {'Content-Type': 'application/json'}
    headers.update(settings.get('headers') or {})
    body = json.dumps(_to_json_line(event)).encode('utf-8')
    _http_post(target['endpoint'], body, headers, verify_tls=_verify_tls_for(target))


def _send_splunk_hec(target, event):
    settings = target.get('settings') or {}
    token = settings.get('token')
    if not token:
        raise ValueError('splunk_hec target needs settings.token')
    headers = {
        'Authorization': f'Splunk {token}',
        'Content-Type': 'application/json',
    }
    payload = {
        'event': _to_json_line(event),
        'sourcetype': settings.get('sourcetype', 'pegaprox:audit'),
        'source': 'pegaprox',
    }
    if settings.get('index'):
        payload['index'] = settings['index']
    _http_post(target['endpoint'], json.dumps(payload).encode('utf-8'), headers,
               verify_tls=_verify_tls_for(target))


def _send_elastic(target, event):
    settings = target.get('settings') or {}
    index = settings.get('index', 'pegaprox-audit')
    base = target['endpoint'].rstrip('/')
    url = f"{base}/{index}/_doc"
    headers = {'Content-Type': 'application/json'}
    user = settings.get('username')
    pw = settings.get('password')
    if user and pw is not None:
        token = base64.b64encode(f"{user}:{pw}".encode('utf-8')).decode('ascii')
        headers['Authorization'] = f"Basic {token}"
    body = json.dumps(_to_json_line(event)).encode('utf-8')
    _http_post(url, body, headers, verify_tls=_verify_tls_for(target))


def _send_generic(target, event):
    """Plain webhook — POST JSON body, no auth assumptions."""
    settings = target.get('settings') or {}
    headers = {'Content-Type': 'application/json'}
    headers.update(settings.get('headers') or {})
    _http_post(target['endpoint'], json.dumps(_to_json_line(event)).encode('utf-8'),
               headers, verify_tls=_verify_tls_for(target))


_DISPATCH = {
    'syslog_udp': lambda t, e: _send_syslog(t, e, 'udp'),
    'syslog_tcp': lambda t, e: _send_syslog(t, e, 'tcp'),
    'http_json':  _send_http_json,
    'splunk_hec': _send_splunk_hec,
    'elastic':    _send_elastic,
    'generic':    _send_generic,
}


def _deliver_one(target, event):
    """Try once. Updates last_ok / last_error stats."""
    fn = _DISPATCH.get(target['type'])
    if not fn:
        _record_result(target['id'], False, f"unknown type {target['type']}")
        return False
    try:
        fn(target, event)
        _record_result(target['id'], True)
        return True
    except Exception as e:
        _record_result(target['id'], False, e)
        return False


def _worker_loop():
    """Drain queue forever. Doesn't retry forever — one shot, fail loudly in
    the target's last_error field, move on."""
    while _worker_running:
        try:
            evt = _queue.get(timeout=2)
        except Empty:
            continue
        try:
            for t in _list_enabled():
                _deliver_one(t, evt)
        except Exception as e:
            logging.debug(f"[siem] dispatch loop err: {e}")
        finally:
            _queue.task_done()


def start_worker():
    global _worker_running
    with _worker_lock:
        if _worker_running:
            return
        _worker_running = True
    t = threading.Thread(target=_worker_loop, daemon=True, name='siem-forwarder')
    t.start()
    logging.info("[siem] forwarder thread started")


# ── Endpoints ─────────────────────────────────────────────────────────────

@bp.route('/api/siem/targets', methods=['GET'])
@require_auth(roles=[ROLE_ADMIN])
def list_targets():
    try:
        c = get_db().conn.cursor()
        c.execute('SELECT * FROM siem_targets ORDER BY created_at DESC')
        return jsonify({'targets': [_row_to_target(r) for r in c.fetchall()]})
    except Exception as e:
        logging.exception('handler error in siem.py'); return jsonify({'error': 'internal error'}), 500


@bp.route('/api/siem/targets', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def create_target():
    body = request.get_json(silent=True) or {}
    name = (body.get('name') or '').strip()[:80]
    typ = (body.get('type') or '').strip()
    endpoint = (body.get('endpoint') or '').strip()[:300]
    fmt = (body.get('format') or 'json').strip()[:20]
    enabled = 1 if body.get('enabled', True) else 0
    settings = body.get('settings') or {}

    if not name or typ not in TYPES or not endpoint:
        return jsonify({'error': f'name, type ({", ".join(sorted(TYPES))}), endpoint required'}), 400

    tid = uuid.uuid4().hex[:12]
    try:
        c = get_db().conn.cursor()
        c.execute('''
            INSERT INTO siem_targets (id, name, type, endpoint, format, enabled,
                                      settings, created_at, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (tid, name, typ, endpoint, fmt, enabled,
              json.dumps(settings), datetime.now().isoformat(), _current_user()))
        get_db().conn.commit()
        c.execute('SELECT * FROM siem_targets WHERE id = ?', (tid,))
        return jsonify({'target': _row_to_target(c.fetchone())})
    except Exception as e:
        logging.exception('handler error in siem.py'); return jsonify({'error': 'internal error'}), 500


@bp.route('/api/siem/targets/<tid>', methods=['PUT'])
@require_auth(roles=[ROLE_ADMIN])
def update_target(tid):
    body = request.get_json(silent=True) or {}
    fields = []
    params = []
    for key in ('name', 'endpoint', 'format'):
        if key in body:
            fields.append(f'{key} = ?')
            params.append(str(body[key])[:300])
    if 'type' in body:
        if body['type'] not in TYPES:
            return jsonify({'error': 'invalid type'}), 400
        fields.append('type = ?'); params.append(body['type'])
    if 'enabled' in body:
        fields.append('enabled = ?'); params.append(1 if body['enabled'] else 0)
    if 'settings' in body:
        fields.append('settings = ?'); params.append(json.dumps(body['settings']))
    if not fields:
        return jsonify({'error': 'no fields to update'}), 400
    params.append(tid)
    try:
        c = get_db().conn.cursor()
        c.execute(f"UPDATE siem_targets SET {', '.join(fields)} WHERE id = ?", params)
        get_db().conn.commit()
        if c.rowcount == 0:
            return jsonify({'error': 'not found'}), 404
        c.execute('SELECT * FROM siem_targets WHERE id = ?', (tid,))
        row = c.fetchone()
        return jsonify({'target': _row_to_target(row) if row else None})
    except Exception as e:
        logging.exception('handler error in siem.py'); return jsonify({'error': 'internal error'}), 500


@bp.route('/api/siem/targets/<tid>', methods=['DELETE'])
@require_auth(roles=[ROLE_ADMIN])
def delete_target(tid):
    try:
        c = get_db().conn.cursor()
        c.execute('DELETE FROM siem_targets WHERE id = ?', (tid,))
        get_db().conn.commit()
        if c.rowcount == 0:
            return jsonify({'error': 'not found'}), 404
        return jsonify({'ok': True})
    except Exception as e:
        logging.exception('handler error in siem.py'); return jsonify({'error': 'internal error'}), 500


@bp.route('/api/siem/targets/<tid>/test', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def test_target(tid):
    """Fire a synthetic audit event to one specific target."""
    try:
        c = get_db().conn.cursor()
        c.execute('SELECT * FROM siem_targets WHERE id = ?', (tid,))
        row = c.fetchone()
        if not row:
            return jsonify({'error': 'not found'}), 404
        target = _row_to_target(row)
        evt = {
            'id': 0,
            'timestamp': datetime.now().isoformat(),
            'user': _current_user() or 'pegaprox',
            'action': 'siem.test',
            'severity': 'info',
            'cluster': '',
            'ip_address': request.remote_addr or '',
            'details': f'Test event from PegaProx for target {target["name"]}',
        }
        ok = _deliver_one(target, evt)
        c.execute('SELECT * FROM siem_targets WHERE id = ?', (tid,))
        return jsonify({'ok': ok, 'target': _row_to_target(c.fetchone())})
    except Exception as e:
        logging.exception('handler error in siem.py'); return jsonify({'error': 'internal error'}), 500


@bp.route('/api/siem/types', methods=['GET'])
@require_auth(roles=[ROLE_ADMIN])
def types():
    """List supported types so the UI dropdown stays in sync with the backend."""
    return jsonify({
        'types': [
            {'id': 'syslog_udp', 'label': 'Syslog (UDP)', 'endpoint_hint': 'host:514',
             'settings_fields': ['facility']},
            {'id': 'syslog_tcp', 'label': 'Syslog (TCP)', 'endpoint_hint': 'host:514',
             'settings_fields': ['facility']},
            {'id': 'http_json',  'label': 'HTTP JSON (Loki / generic)', 'endpoint_hint': 'https://loki:3100/loki/api/v1/push',
             'settings_fields': ['headers', 'verify_tls']},
            {'id': 'splunk_hec', 'label': 'Splunk HEC', 'endpoint_hint': 'https://splunk:8088/services/collector',
             'settings_fields': ['token', 'sourcetype', 'index', 'verify_tls']},
            {'id': 'elastic',    'label': 'Elasticsearch', 'endpoint_hint': 'https://es:9200',
             'settings_fields': ['username', 'password', 'index', 'verify_tls']},
            {'id': 'generic',    'label': 'Generic webhook', 'endpoint_hint': 'https://example.com/audit',
             'settings_fields': ['headers', 'verify_tls']},
        ]
    })
