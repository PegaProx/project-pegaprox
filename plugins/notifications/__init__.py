"""
Push Notifications Plugin — Ntfy + Apprise integration
MK: Apr 2026 — requested in #213

Sends PegaProx alerts to Ntfy (self-hosted or ntfy.sh) and optionally
through Apprise (80+ notification services: Slack, Discord, Telegram, etc.)

Apprise is optional — install with: pip install apprise
"""
import os
import json
import logging
import requests
from datetime import datetime
from flask import request

from pegaprox.api.plugins import register_plugin_route
from pegaprox.globals import _notification_handlers

PLUGIN_DIR = os.path.dirname(os.path.abspath(__file__))

# try loading apprise — not required
_apprise_available = False
try:
    import apprise
    _apprise_available = True
except ImportError:
    pass


def _load_config():
    try:
        with open(os.path.join(PLUGIN_DIR, 'config.json')) as f:
            return json.load(f)
    except:
        return {'ntfy_enabled': False, 'apprise_enabled': False}

def _save_config(cfg):
    with open(os.path.join(PLUGIN_DIR, 'config.json'), 'w') as f:
        json.dump(cfg, f, indent=4)


def _require_admin():
    from pegaprox.utils.auth import load_users
    from pegaprox.models.permissions import ROLE_ADMIN
    username = request.session.get('user', '')
    users = load_users()
    if users.get(username, {}).get('role') != ROLE_ADMIN:
        return {'error': 'Admin access required'}, 403
    return None


# ─── Ntfy sender ───

def _send_ntfy(alert_data, cfg):
    topic = cfg.get('ntfy_topic', '')
    if not topic:
        return False, 'No ntfy topic configured'
    url = f"{cfg.get('ntfy_url', 'https://ntfy.sh').rstrip('/')}/{topic}"
    prio_map = cfg.get('ntfy_priority_map', {})
    priority = prio_map.get(alert_data.get('severity', 'info'), 'default')

    headers = {
        'Priority': priority,
        'Title': f"PegaProx: {alert_data.get('alert_name', 'Alert')}",
        'Tags': f"pegaprox,{alert_data.get('severity', 'info')},{alert_data.get('metric', '')}",
    }
    token = cfg.get('ntfy_token', '')
    # MK: security audit — token may be encrypted, try decrypting
    if token:
        try:
            from pegaprox.core.db import get_db
            decrypted = get_db()._decrypt(token)
            if decrypted:
                token = decrypted
        except: pass
        headers['Authorization'] = f"Bearer {token}"

    try:
        # NS May 2026 — SSRF guard: ntfy URLs are admin-supplied and could
        # accidentally (or maliciously) point at metadata / internal services.
        try:
            from pegaprox.utils.url_security import sanitize_outbound_url, SsrfError
            sanitize_outbound_url(url, allowed_schemes=('https', 'http'))
        except SsrfError as guard_err:
            return False, f"ntfy URL rejected: {guard_err}"
        r = requests.post(url, data=alert_data.get('message', ''), headers=headers, timeout=10)
        if r.status_code in (200, 201):
            return True, None
        return False, f"ntfy returned {r.status_code}"
    except Exception as e:
        return False, str(e)


# ─── Apprise sender ───

def _send_apprise(alert_data, cfg):
    if not _apprise_available:
        return False, 'apprise not installed'
    urls = cfg.get('apprise_urls', [])
    if not urls:
        return False, 'No apprise URLs configured'
    # NS Jul 2026 (CodeAnt SSRF) — the prefix blocklist missed decimal/hex/IPv6/metadata-by-
    # hostname encodings; run the real SSRF guard on http(s) apprise targets (other apprise
    # schemes like discord://, tgram:// go to provider APIs, not arbitrary IPs, so leave them).
    from pegaprox.utils.url_security import sanitize_outbound_url, SsrfError
    try:
        ap = apprise.Apprise()
        for u in urls:
            _ul = str(u).lower()
            if _ul.startswith('file://'):
                logging.warning("[Notifications] Blocked file:// apprise URL")
                continue
            if _ul.startswith(('http://', 'https://')):
                try:
                    sanitize_outbound_url(u, allowed_schemes=('http', 'https'), allow_private=False)
                except SsrfError as _se:
                    logging.warning(f"[Notifications] Blocked SSRF apprise URL: {_se}")
                    continue
            ap.add(u)
        ok = ap.notify(
            title=f"PegaProx: {alert_data.get('alert_name', 'Alert')}",
            body=alert_data.get('message', ''),
            notify_type=apprise.NotifyType.WARNING if alert_data.get('severity') == 'warning'
                else apprise.NotifyType.FAILURE if alert_data.get('severity') == 'critical'
                else apprise.NotifyType.INFO,
        )
        return ok, None
    except Exception as e:
        return False, str(e)


# ─── Alert handler (called by PegaProx alert system) ───

def _notification_handler(alert_data):
    cfg = _load_config()

    if cfg.get('ntfy_enabled') and cfg.get('ntfy_topic'):
        ok, err = _send_ntfy(alert_data, cfg)
        if ok:
            logging.info(f"[Notifications] ntfy sent: {alert_data.get('alert_name')}")
        elif err:
            logging.warning(f"[Notifications] ntfy failed: {err}")

    if cfg.get('apprise_enabled') and cfg.get('apprise_urls'):
        ok, err = _send_apprise(alert_data, cfg)
        if ok:
            logging.info(f"[Notifications] apprise sent: {alert_data.get('alert_name')}")
        elif err:
            logging.warning(f"[Notifications] apprise failed: {err}")


# ─── API routes ───

def _get_config():
    err = _require_admin()
    if err: return err
    cfg = _load_config()
    cfg['apprise_available'] = _apprise_available
    return cfg

def _update_config():
    err = _require_admin()
    if err: return err
    data = request.get_json() or {}
    cfg = _load_config()
    for k in ['ntfy_enabled', 'ntfy_url', 'ntfy_topic', 'ntfy_token',
              'ntfy_priority_map', 'apprise_enabled', 'apprise_urls']:
        if k in data:
            cfg[k] = data[k]
    _save_config(cfg)
    return {'success': True}

def _send_test():
    """Send a test notification to verify config works"""
    err = _require_admin()
    if err: return err
    cfg = _load_config()
    test_alert = {
        'alert_name': 'Test Notification',
        'metric': 'test',
        'operator': '>',
        'threshold': 0,
        'current_value': 42.0,
        'target_type': 'system',
        'target_name': 'PegaProx',
        'cluster_id': 'test',
        'severity': 'info',
        'timestamp': datetime.now().isoformat(),
        'message': 'This is a test notification from PegaProx. If you see this, notifications are working!',
    }
    results = {}
    if cfg.get('ntfy_enabled') and cfg.get('ntfy_topic'):
        ok, err_msg = _send_ntfy(test_alert, cfg)
        results['ntfy'] = {'success': ok, 'error': err_msg}
    else:
        results['ntfy'] = {'success': False, 'error': 'Not enabled or no topic'}

    if cfg.get('apprise_enabled') and cfg.get('apprise_urls'):
        ok, err_msg = _send_apprise(test_alert, cfg)
        results['apprise'] = {'success': ok, 'error': err_msg}
    else:
        results['apprise'] = {'success': False, 'error': 'Not enabled or no URLs'}

    return results

def _get_status():
    err = _require_admin()
    if err: return err
    cfg = _load_config()
    return {
        'ntfy_enabled': cfg.get('ntfy_enabled', False),
        'ntfy_topic': cfg.get('ntfy_topic', ''),
        'apprise_enabled': cfg.get('apprise_enabled', False),
        'apprise_available': _apprise_available,
        'apprise_url_count': len(cfg.get('apprise_urls', [])),
        'handler_registered': _notification_handler in _notification_handlers,
    }


def register(app):
    register_plugin_route('notifications', 'config', _get_config)
    register_plugin_route('notifications', 'config/update', _update_config)
    register_plugin_route('notifications', 'test', _send_test)
    register_plugin_route('notifications', 'status', _get_status)

    # register as alert handler
    if _notification_handler not in _notification_handlers:
        _notification_handlers.append(_notification_handler)

    logging.info(f"[PLUGINS] Push Notifications plugin registered (ntfy + apprise{'=available' if _apprise_available else '=not installed'})")
