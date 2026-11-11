"""
Push Notifications Plugin — Ntfy + Apprise integration
MK: Apr 2026 — requested in #213

Sends PegaProx alerts to Ntfy (self-hosted or ntfy.sh) and optionally
through Apprise (80+ notification services: Slack, Discord, Telegram, etc.)

Apprise is optional — install with: pip install apprise
"""
import os
import re
import json
import errno
import hashlib
import hmac
import logging
import secrets
import requests
from datetime import datetime
from flask import request

from pegaprox.api.plugins import register_plugin_route, _config_generation, _config_written, _login_masked
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
            cfg = json.load(f)
    except:
        cfg = None
    # a file that holds a list or a number is no config either
    return cfg if isinstance(cfg, dict) else {'ntfy_enabled': False, 'apprise_enabled': False}

def _save_config(cfg):
    # the token and the apprise urls are credentials of their own: owner only
    path = os.path.join(PLUGIN_DIR, 'config.json')
    # MK Nov 2026 - with O_TRUNC the file was empty before fchmod ran, and a config.json
    # of another owner (EPERM) stayed empty. Mode first, then the content.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
    with os.fdopen(fd, 'w') as f:
        try:
            os.fchmod(f.fileno(), 0o600)    # O_CREAT's mode does nothing for a file that exists
        except OSError as e:
            if e.errno != errno.EPERM:
                raise
            logging.warning(f"[Notifications] {path} belongs to another user, its mode stays as it is")
        f.truncate(0)
        json.dump(cfg, f, indent=4)
    _config_written(_PLUGIN)    # the handles read before this write find nothing now


# MK Nov 2026 - the config route handed the ntfy token and every apprise url back as
# stored, and an apprise url carries its service login (tgram://<bot token>/...,
# discord://<webhook id>/<token>, mailto://user:pass@...). They are write-only now
# like the SMTP password in the settings: a masked value sent back keeps what is stored.
_MASK = '********'
_SCHEME = re.compile(r'^[A-Za-z][A-Za-z0-9+.-]*$')
_HANDLE = re.compile(r'#([0-9a-f]{16})([0-9a-f]{16})$')
# without the database key a handle holds for this process only
_PROCESS_KEY = secrets.token_bytes(32)
# the config editor in the settings gives out the same handles for this list
_PLUGIN, _URLS = 'notifications', 'apprise_urls'
# a stored entry can be null, so a handle that finds nothing gets this instead
_NOT_STORED = object()


def _entry_key():
    try:
        from pegaprox.core.db import get_db
        return get_db().aes_key or _PROCESS_KEY
    except Exception:
        return _PROCESS_KEY


def _url_list(v):
    if isinstance(v, list):
        return v
    return [v] if v else []


def _url_mask(u):
    u = str(u)
    scheme = u.split('://', 1)[0] if '://' in u else ''
    return f"{scheme + '://' if _SCHEME.match(scheme) else ''}{_MASK}"


def _entry_fp(plugin, lpath, o, key):
    msg = b'\x00'.join((b'plugin-config-entry', plugin.encode(), _config_generation(plugin).encode(),
                        lpath.encode(), json.dumps(o).encode()))
    return hmac.new(key, msg, hashlib.sha256).digest()[:8]


def _entry_pad(nonce, key):
    return hmac.new(key, b'plugin-config-pad\x00' + nonce, hashlib.sha256).digest()[:8]


def _entry_handle(plugin, lpath, o, key):
    """MK Nov 2026 - a masked url was put back by its place in the list, so deleting the
    first of two telegram urls kept the first one. Each carries a handle of its own: a
    random nonce and a print of the url keyed with the server's key, under a pad of that
    nonce. Equal urls never show the same handle, and until config.json is written again a
    handle finds a stored copy of its url however many copies there are."""
    nonce = secrets.token_bytes(8)
    pad = _entry_pad(nonce, key)
    return '#' + nonce.hex() + bytes(a ^ b for a, b in zip(_entry_fp(plugin, lpath, o, key), pad)).hex()


def _handle_fp(text, key):
    m = _HANDLE.search(text)
    if not m:
        return None, None
    nonce, blob = bytes.fromhex(m.group(1)), bytes.fromhex(m.group(2))
    return m.start(), bytes(a ^ b for a, b in zip(blob, _entry_pad(nonce, key)))


def _masked_urls(urls, key):
    return [_url_mask(u) + _entry_handle(_PLUGIN, _URLS, u, key) for u in urls]


def _keep_stored_urls(new_urls, stored, key):
    """new_urls with each masked url back to the stored one it stands for, and the
    places of masks that stand for none."""
    if not isinstance(new_urls, list):
        return stored, []
    kept, unknown, table = [], [], None
    for i, u in enumerate(new_urls):
        if isinstance(u, str) and _MASK in u:
            # a stored url with the value of the handle, wherever it sits now
            hit, (at, fp) = _NOT_STORED, _handle_fp(u, key)
            if fp is not None:
                if table is None:
                    table = {_entry_fp(_PLUGIN, _URLS, v, key): v for v in stored}
                hit = table.get(fp, _NOT_STORED)
                if hit is not _NOT_STORED and _url_mask(hit) != u[:at]:
                    hit = _NOT_STORED
            if hit is _NOT_STORED:
                unknown.append(f'apprise_urls[{i}]')
                continue
            u = hit
        kept.append(u)
    return kept, unknown


def _ntfy_base(u):
    return str(u if u is not None else 'https://ntfy.sh').strip().rstrip('/').lower()


def _ntfy_url_shown(u):
    # a login in ntfy_url (https://user:pass@ntfy.example) shows masked, as in the config editor
    return _login_masked(u) or u


def _require_admin():
    # sec (audit): the STORED role, so an admin-owned but viewer-scoped API token passed this
    # admin check with its owner's rights. build_authz_user carries the token-floored
    # effective_role, which is what every gate in the core uses.
    # NS Oct 2026 (#1028) - and an admin a tenant override lowers where they live is not one
    # here either: these are the targets every tenant's alerts are sent to
    from pegaprox.utils.auth import build_authz_user
    from pegaprox.utils.rbac import acts_as_admin
    username = request.session.get('user', '')
    if not acts_as_admin(build_authz_user(username, request.session)):
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
            from pegaprox.utils.url_security import resolve_and_pin_url, SsrfError
            # GHSA-hmcf-9q7f-vx35 — pin the vetted IP so requests can't re-resolve to an internal
            # address between the check and the POST.
            url = resolve_and_pin_url(url, allowed_schemes=('https', 'http'))
        except SsrfError as guard_err:
            return False, f"ntfy URL rejected: {guard_err}"
        # MK Nov 2026 - no redirect: its Location never went through the guard above, and
        # a 307 posted the alert there once more. A 3xx is no delivery.
        r = requests.post(url, data=alert_data.get('message', ''), headers=headers, timeout=10,
                          allow_redirects=False)
        if r.status_code in (200, 201):
            return True, None
        if 300 <= r.status_code < 400:
            return False, f"ntfy returned {r.status_code}, redirect not followed"
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
    from pegaprox.utils.url_security import resolve_and_pin_url, SsrfError
    try:
        ap = apprise.Apprise()
        for u in urls:
            _ul = str(u).lower()
            if _ul.startswith('file://'):
                logging.warning("[Notifications] Blocked file:// apprise URL")
                continue
            if _ul.startswith(('http://', 'https://')):
                try:
                    # GHSA-hmcf-9q7f-vx35 — pin the vetted IP so apprise's own fetch can't be
                    # DNS-rebound to an internal address (http pinned; verified https stays a hostname).
                    u = resolve_and_pin_url(u, allowed_schemes=('http', 'https'), allow_private=False)
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


# MK Nov 2026 - the config.json we shipped had ntfy on with the topic "pegaprox-test" on
# ntfy.sh, a public topic anyone can subscribe to, so enabling the plugin sent every
# alert there before anything was set. An update keeps config.json (#1134), so that
# pair without a token of its own counts as not set.
_SHIPPED_EXAMPLE = ('https://ntfy.sh', 'pegaprox-test')


def _ntfy_ready(cfg):
    if not (cfg.get('ntfy_enabled') and cfg.get('ntfy_topic')):
        return False
    url = str(cfg.get('ntfy_url') or 'https://ntfy.sh').rstrip('/').lower()
    return bool(cfg.get('ntfy_token')) or (url, str(cfg['ntfy_topic'])) != _SHIPPED_EXAMPLE


# ─── Alert handler (called by PegaProx alert system) ───

def _notification_handler(alert_data):
    cfg = _load_config()

    if _ntfy_ready(cfg):
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
    if cfg.get('ntfy_token'):
        cfg['ntfy_token'] = _MASK
    if cfg.get('ntfy_url'):
        cfg['ntfy_url'] = _ntfy_url_shown(cfg['ntfy_url'])
    key = _entry_key()
    cfg['apprise_urls'] = _masked_urls(_url_list(cfg.get('apprise_urls')), key)
    cfg['apprise_available'] = _apprise_available
    return cfg

def _update_config():
    err = _require_admin()
    if err: return err
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return {'error': 'Expected a JSON object'}, 400
    cfg = _load_config()
    if data.get('ntfy_token') == _MASK:
        data.pop('ntfy_token')
    # a masked login keeps the stored url only where the rest of it is the same
    if isinstance(data.get('ntfy_url'), str) and _MASK in data['ntfy_url']:
        if data['ntfy_url'] != _ntfy_url_shown(cfg.get('ntfy_url')):
            return {'error': f"Type the login of ntfy_url instead of {_MASK}, or reload the config: "
                             "the masked login stands for nothing stored.",
                    'code': 'CREDENTIAL_REQUIRED', 'fields': ['ntfy_url']}, 400
        data['ntfy_url'] = cfg.get('ntfy_url')
    # MK Nov 2026 - the stored token went along to whatever server the same save set, and
    # the next alert posted it there. It is for the server it was typed for.
    if cfg.get('ntfy_token') and 'ntfy_token' not in data and 'ntfy_url' in data \
            and _ntfy_base(data['ntfy_url']) != _ntfy_base(cfg.get('ntfy_url')):
        return {'error': 'Re-enter the ntfy token to change the ntfy server.',
                'code': 'CREDENTIAL_REQUIRED', 'fields': ['ntfy_token']}, 400
    if 'apprise_urls' in data:
        urls, unknown = _keep_stored_urls(data['apprise_urls'], _url_list(cfg.get('apprise_urls')), _entry_key())
        if unknown:
            # a stale or unknown handle is neither saved as a target nor dropped with the url it stood for
            return {'error': f"Type the url of {', '.join(unknown)} instead of {_MASK}, or reload the "
                             "config: the masked url stands for nothing stored.",
                    'code': 'CREDENTIAL_REQUIRED', 'fields': unknown}, 400
        data['apprise_urls'] = urls
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
    if _ntfy_ready(cfg):
        ok, err_msg = _send_ntfy(test_alert, cfg)
        results['ntfy'] = {'success': ok, 'error': err_msg}
    elif cfg.get('ntfy_enabled') and cfg.get('ntfy_topic'):
        results['ntfy'] = {'success': False, 'error': 'pegaprox-test on ntfy.sh is the old example topic, set a topic of your own'}
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
