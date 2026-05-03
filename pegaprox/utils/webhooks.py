# -*- coding: utf-8 -*-
"""
MK Apr 2026 — Webhook alert dispatcher for Slack / Discord / Teams / ntfy /
generic JSON endpoints.

A single channel config looks like::

    {
        "id": "short-uuid",
        "name": "Ops Slack",
        "type": "slack" | "discord" | "teams" | "ntfy" | "generic",
        "url": "https://hooks.slack.com/services/...",
        "token": "",            # ntfy — if the topic requires auth
        "topic": "",            # ntfy — topic, if url is the server base only
        "enabled": true
    }

send_to_channels(alert) loops enabled channels and POSTs a provider-shaped body.
Short timeout + per-channel try/except so one dead webhook can't block the rest.
"""
import json
import logging
import re
import uuid
from datetime import datetime

try:
    import requests
except ImportError:
    requests = None


def _severity_color(sev):
    """Returns hex color for Slack/Discord embed side-stripe."""
    return {'critical': '#f54f47', 'warning': '#efc006'}.get((sev or '').lower(), '#60b515')


# MK May 2026 (audit fix M-11) — Slack/Discord/Teams/HEC webhook URLs embed
# their secret as part of the path. `requests` exceptions render either the
# full URL or just the path-only fragment (e.g. "with url: /services/..."),
# both of which end up in our log file. Redact both shapes.
_WEBHOOK_URL_RE = re.compile(
    r'https?://[A-Za-z0-9_.\-:]+/('
    r'services/[A-Za-z0-9/_=?&.-]+'
    r'|api/webhooks/[A-Za-z0-9/_=?&.-]+'
    r'|webhook[A-Za-z0-9/_=?&.-]+'
    r'|services/collector[A-Za-z0-9/_=?&.-]*'
    r')',
    re.IGNORECASE,
)
# detached path-only patterns: appear when requests stringifies certain
# exceptions as "...url: /services/T01.../B02.../SECRET..." without the
# leading scheme/host. Three or more slash-separated segments → secret token.
_WEBHOOK_PATH_ONLY_RE = re.compile(
    r'(/(?:services|api/webhooks|webhook[^\s/]*|services/collector)/[A-Za-z0-9/_.=?&-]+)',
    re.IGNORECASE,
)


def _redact_webhook_url(s):
    """Strip secret-bearing webhook URL paths from a string before logging."""
    if not s: return s
    s = _WEBHOOK_URL_RE.sub('[REDACTED-WEBHOOK-URL]', str(s))
    s = _WEBHOOK_PATH_ONLY_RE.sub('[REDACTED-WEBHOOK-PATH]', s)
    return s


def _ntfy_priority(sev):
    """ntfy uses 1-5 where 5 is urgent. Map severities."""
    return {'critical': 5, 'warning': 4, 'info': 3}.get((sev or '').lower(), 3)


def _build_slack(alert):
    title = alert.get('alert_name') or 'PegaProx alert'
    message = alert.get('message', '')
    color = _severity_color(alert.get('severity'))
    return {
        'attachments': [{
            'color': color,
            'title': f":rotating_light: {title}",
            'text': message,
            'fields': [
                {'title': 'Severity', 'value': alert.get('severity', 'info'), 'short': True},
                {'title': 'Target', 'value': f"{alert.get('target_type', '')}: {alert.get('target_name', '')}", 'short': True},
                {'title': 'Metric', 'value': f"{alert.get('metric', '')} = {alert.get('current_value', '')}", 'short': True},
                {'title': 'Cluster', 'value': alert.get('cluster_id', '-'), 'short': True},
            ],
            'footer': 'PegaProx',
            'ts': int(datetime.now().timestamp()),
        }]
    }


def _build_discord(alert):
    title = alert.get('alert_name') or 'PegaProx alert'
    color_hex = _severity_color(alert.get('severity'))
    try:
        color_int = int(color_hex.lstrip('#'), 16)
    except Exception:
        color_int = 0xe57000
    return {
        'embeds': [{
            'title': f"🚨 {title}",
            'description': alert.get('message', ''),
            'color': color_int,
            'fields': [
                {'name': 'Severity', 'value': alert.get('severity', 'info'), 'inline': True},
                {'name': 'Target', 'value': f"{alert.get('target_type', '')}: {alert.get('target_name', '')}", 'inline': True},
                {'name': 'Metric', 'value': f"{alert.get('metric', '')} = {alert.get('current_value', '')}", 'inline': True},
            ],
            'footer': {'text': 'PegaProx'},
            'timestamp': datetime.now().isoformat(),
        }]
    }


def _build_teams(alert):
    # MS Teams MessageCard (legacy but still works everywhere). Adaptive Cards
    # need an auth-token dance that ops teams rarely bother with.
    title = alert.get('alert_name') or 'PegaProx alert'
    return {
        '@type': 'MessageCard',
        '@context': 'http://schema.org/extensions',
        'themeColor': _severity_color(alert.get('severity')).lstrip('#'),
        'summary': title,
        'title': title,
        'text': alert.get('message', ''),
        'sections': [{
            'facts': [
                {'name': 'Severity', 'value': alert.get('severity', 'info')},
                {'name': 'Target', 'value': f"{alert.get('target_type', '')}: {alert.get('target_name', '')}"},
                {'name': 'Metric', 'value': f"{alert.get('metric', '')} = {alert.get('current_value', '')}"},
                {'name': 'Cluster', 'value': alert.get('cluster_id', '-')},
            ],
        }],
    }


def _post_ntfy(channel, alert):
    """ntfy wants a plaintext body + headers. Different shape from JSON webhooks."""
    if not requests:
        return False, 'requests not available'
    url = channel.get('url', '').rstrip('/')
    topic = (channel.get('topic') or '').strip()
    if topic:
        url = f"{url}/{topic}"
    headers = {
        'Title': (alert.get('alert_name') or 'PegaProx alert')[:200],
        'Priority': str(_ntfy_priority(alert.get('severity'))),
        'Tags': alert.get('severity', 'info'),
    }
    token = channel.get('token')
    if token:
        headers['Authorization'] = f'Bearer {token}'
    body = alert.get('message', '')
    try:
        r = requests.post(url, data=body.encode('utf-8'), headers=headers, timeout=6)
        return 200 <= r.status_code < 300, f'HTTP {r.status_code}'
    except Exception as e:
        return False, _redact_webhook_url(str(e))


def send_to_channel(channel, alert):
    """Fire one alert to one channel. Returns (success, detail)."""
    if not requests:
        return False, 'requests library not installed'
    if not channel.get('enabled', True):
        return False, 'disabled'
    url = (channel.get('url') or '').strip()
    if not url:
        return False, 'no url'
    ctype = (channel.get('type') or 'generic').lower()

    if ctype == 'ntfy':
        return _post_ntfy(channel, alert)

    if ctype == 'slack':
        body = _build_slack(alert)
    elif ctype == 'discord':
        body = _build_discord(alert)
    elif ctype == 'teams':
        body = _build_teams(alert)
    else:
        # generic — raw alert payload; caller-side webhook can map as needed
        body = {'alert': alert, 'source': 'pegaprox', 'timestamp': datetime.now().isoformat()}

    try:
        r = requests.post(url, json=body, timeout=6)
        return 200 <= r.status_code < 400, f'HTTP {r.status_code}'
    except Exception as e:
        return False, _redact_webhook_url(str(e))


def send_to_channels(alert, channel_ids=None):
    """Fire an alert to webhook channels.

    channel_ids: optional iterable of channel IDs to restrict dispatch to.
    If None (default) ALL enabled channels fire (pre-#213 behaviour).
    Pass `[]` to fire nothing.
    """
    try:
        from pegaprox.api.helpers import load_server_settings
        channels = (load_server_settings() or {}).get('alert_webhooks') or []
    except Exception as e:
        logging.debug(f"[webhooks] could not load channels: {e}")
        return
    if channel_ids is not None:
        wanted = {str(c) for c in channel_ids}
        channels = [c for c in channels if str(c.get('id')) in wanted]
    for ch in channels:
        try:
            ok, detail = send_to_channel(ch, alert)
            # MK May 2026 (M-11) — detail comes from send_to_channel which already
            # redacts; redact again on outer dispatch-error to be defensive.
            if ok:
                logging.info(f"[webhooks] → {ch.get('name', ch.get('id'))}: {detail}")
            else:
                logging.warning(f"[webhooks] → {ch.get('name', ch.get('id'))}: FAILED ({detail})")
        except Exception as e:
            logging.debug(f"[webhooks] channel {ch.get('id')} dispatch error: {_redact_webhook_url(str(e))}")


def new_channel(payload):
    """Normalize admin-submitted channel data — strips unknown fields, assigns id."""
    allowed = {'name', 'type', 'url', 'token', 'topic', 'enabled'}
    out = {k: v for k, v in (payload or {}).items() if k in allowed}
    out.setdefault('enabled', True)
    out.setdefault('type', 'generic')
    out['id'] = (payload or {}).get('id') or uuid.uuid4().hex[:12]
    return out
