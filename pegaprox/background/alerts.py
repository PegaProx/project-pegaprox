# -*- coding: utf-8 -*-
"""
PegaProx Alert Monitoring - Layer 7
Background alert checking and notification.
"""

import os
import time
import json
import logging
import threading
import uuid
from datetime import datetime

from pegaprox.constants import (
    ALERTS_CONFIG_FILE, GITHUB_VERSION_URL, MIRROR_VERSION_URL,
    PEGAPROX_VERSION,
)
from pegaprox.globals import (
    cluster_managers, _alert_running, _alert_last_sent, _alert_thread,
    _notification_handlers,
)
from pegaprox.core.db import get_db
from pegaprox.api.helpers import load_server_settings, save_server_settings
from pegaprox.utils.email import send_email

def load_alerts_config():
    """Load alerts configuration from SQLite database.

    NS May 2026 — Cluster-level alerts (created via the per-cluster UI under
    Automation → Alerts) live in the `cluster_alerts` table. The legacy `alerts`
    table contains old global-style rows. The background check loop used to
    only read `alerts`, which is why nothing ever fired for users who created
    alerts in the new UI. Now we read both, prefer cluster_alerts, and inject
    `cluster_id` from the table column when missing in the JSON config.
    """
    defaults = {'alerts': [], 'enabled': True}
    out = []
    seen_ids = set()

    # Primary source — cluster_alerts (populated by /api/clusters/<id>/alerts)
    try:
        db = get_db()
        cur = db.conn.cursor()
        cur.execute('SELECT cluster_id, alert_type, config, enabled '
                    'FROM cluster_alerts')
        for row in cur.fetchall():
            try:
                cfg = json.loads(row['config'] or '{}')
            except Exception:
                continue
            if not cfg:
                continue
            cfg.setdefault('id', row['alert_type'])
            cfg.setdefault('cluster_id', row['cluster_id'])
            # row['enabled'] wins over a stale config payload
            cfg['enabled'] = bool(row['enabled']) and cfg.get('enabled', True)
            if not cfg.get('metric'):
                continue  # incomplete row — skip
            out.append(cfg)
            seen_ids.add(cfg.get('id'))
    except Exception as e:
        logging.debug(f"[alerts] cluster_alerts read failed: {e}")

    # Legacy source — `alerts` table. Only include rows that look fully
    # populated (skip the empty-`type` stubs from old migrations).
    try:
        db = get_db()
        legacy = db.get_all_alerts() or {}
        for aid, a in legacy.items():
            if aid in seen_ids:
                continue
            metric = a.get('metric') or a.get('type')
            if not metric:
                continue
            a.setdefault('id', aid)
            a.setdefault('metric', metric)
            out.append(a)
    except Exception as e:
        logging.error(f"Error loading alerts from database: {e}")
        if os.path.exists(ALERTS_CONFIG_FILE):
            try:
                with open(ALERTS_CONFIG_FILE, 'r') as f:
                    return {**defaults, **json.load(f)}
            except Exception:
                pass

    return {'alerts': out, 'enabled': True}


def save_alerts_config(config):
    """Save alerts configuration to SQLite database
    
    SQLite migration
    """
    try:
        db = get_db()
        
        # Convert alerts list to dict format for database
        alerts_dict = {}
        for alert in config.get('alerts', []):
            alert_id = alert.get('id', str(uuid.uuid4()))
            alerts_dict[alert_id] = alert
        
        db.save_all_alerts(alerts_dict)
        return True
    except Exception as e:
        logging.error(f"Error saving alerts config: {e}")
        return False

_last_eval = {}  # alert_id -> dict with ts/cluster/metric/value/triggered/reason
_last_tick_at = 0.0


def _record_eval(alert_id, **fields):
    """NS May 2026 — keep the last evaluation per alert so the diagnostics
    endpoint can show *why* something fired (or didn't). Customer-facing —
    saves us a round-trip when triaging 'no alerts arrive' tickets."""
    snap = {'ts': time.time(), 'alert_id': alert_id}
    snap.update(fields)
    _last_eval[alert_id] = snap


def check_and_send_alerts():
    """Check all alert conditions and send notifications.

    LW: This runs periodically in a background thread
    Checks CPU, RAM, Disk usage against thresholds
    """
    global _last_tick_at
    _last_tick_at = time.time()
    config = load_alerts_config()
    if not config.get('enabled'):
        return

    settings = load_server_settings()
    recipients = settings.get('alert_email_recipients', [])
    cooldown = settings.get('alert_cooldown', 300)

    # NS Apr 2026 (#213) — don't bail just because email isn't configured.
    # Webhook-only setups (ntfy, slack) were silently skipped because of this.
    current_time = time.time()
    alerts_list = config.get('alerts', [])
    logging.info(f"[AlertCheck] tick: {len(alerts_list)} alert(s), {len(cluster_managers)} cluster(s) loaded, recipients={len(recipients)}")

    for alert in alerts_list:
        alert_id = alert.get('id', '')
        if not alert.get('enabled', True):
            _record_eval(alert_id, reason='disabled')
            continue

        cluster_id = alert.get('cluster_id', '')
        metric = alert.get('metric', '')  # cpu, memory, disk
        threshold = alert.get('threshold', 80)
        operator = alert.get('operator', '>')  # >, <, =
        target_type = alert.get('target_type', 'cluster')  # cluster, node, vm
        target_id = alert.get('target_id', '')  # node name or vmid

        # Check cooldown
        # NS May 2026: include alert_id so a warning rule and a critical rule
        # on the same metric don't poison each other's cooldown.
        alert_key = f"{alert_id}:{cluster_id}:{target_type}:{target_id}:{metric}"
        if alert_key in _alert_last_sent:
            if current_time - _alert_last_sent[alert_key] < cooldown:
                _record_eval(alert_id, reason=f'cooldown ({int(current_time - _alert_last_sent[alert_key])}s of {cooldown}s)',
                             cluster_id=cluster_id, metric=metric)
                continue

        # Get current value
        current_value = None
        target_name = target_id

        if cluster_id not in cluster_managers:
            _record_eval(alert_id, reason=f"cluster '{cluster_id}' not loaded (have: {sorted(cluster_managers.keys())})",
                         cluster_id=cluster_id, metric=metric, target_type=target_type)
            logging.info(f"[AlertCheck]   skip {alert_id}: cluster '{cluster_id}' not in cluster_managers")
            continue

        if cluster_id in cluster_managers:
            manager = cluster_managers[cluster_id]

            # NS May 2026 — guard the metric lookup. The old code called
            # `manager.get_cluster_summary()` and `manager.get_resources()` —
            # neither method exists on PegaProxManager. Cluster + VM targets
            # have been raising AttributeError since this was written.
            try:
                if target_type == 'cluster':
                    # Aggregate cluster CPU/mem/disk from per-node status
                    per_node = manager.get_node_status() or {}
                    online = [n for n in per_node.values()
                              if (n.get('status') or '').lower() == 'online']
                    if metric == 'cpu' and online:
                        current_value = sum(n.get('cpu_percent', 0) for n in online) / len(online)
                    elif metric == 'memory':
                        used = sum(n.get('mem_used', 0) for n in online)
                        total = sum(n.get('mem_total', 0) for n in online)
                        if total > 0:
                            current_value = used / total * 100
                    elif metric == 'disk':
                        used = sum(n.get('disk_used', 0) for n in online)
                        total = sum(n.get('disk_total', 0) for n in online)
                        if total > 0:
                            current_value = used / total * 100
                    elif metric in ('backup_sla_breached_pct', 'backup_sla_compliance_pct'):
                        # MK May 2026 — Backup SLA-aware alerts. Run the same
                        # eval as the /backup-sla endpoint and feed the % into
                        # the alerting pipeline. Threshold direction depends on
                        # which metric: breached_pct >= X (warn when too many
                        # behind), compliance_pct <= Y (warn when below floor).
                        try:
                            from pegaprox.api.clusters import get_backup_sla as _ignored  # ensure import resolves
                            # We can't call the Flask endpoint directly from a thread.
                            # Inline the same evaluation: threshold + storage scan.
                            import time as _t
                            max_age = int(getattr(manager.config, 'backup_sla_max_age_hours', 0) or 0)
                            if max_age > 0:
                                _now = int(_t.time())
                                _max_s = max_age * 3600
                                vms = manager.get_vm_resources() or []
                                last_bk = {}
                                try:
                                    sess = manager._create_session()
                                    nr = sess.get(f"https://{manager.host}:8006/api2/json/nodes", timeout=10)
                                    nodes = [n['node'] for n in (nr.json().get('data') or [])
                                             if n.get('status') == 'online'] if nr.status_code == 200 else []
                                    seen = set()
                                    for nd in nodes:
                                        sr = sess.get(f"https://{manager.host}:8006/api2/json/nodes/{nd}/storage", timeout=10)
                                        if sr.status_code != 200: continue
                                        for st in sr.json().get('data') or []:
                                            if 'backup' not in (st.get('content') or ''): continue
                                            sname = st.get('storage')
                                            if not sname or (nd, sname) in seen: continue
                                            seen.add((nd, sname))
                                            try:
                                                cr = sess.get(f"https://{manager.host}:8006/api2/json/nodes/{nd}/storage/{sname}/content",
                                                              params={'content': 'backup'}, timeout=(5, 30))
                                            except Exception:
                                                continue
                                            if cr.status_code != 200: continue
                                            for it in cr.json().get('data') or []:
                                                ts = int(it.get('ctime') or 0)
                                                vmid = str(it.get('vmid') or '')
                                                if not ts or not vmid: continue
                                                volid = it.get('volid') or ''
                                                vt = 'qemu' if 'qemu' in volid or '/vm/' in volid else \
                                                     'lxc' if 'lxc' in volid or '/ct/' in volid else ''
                                                if not vt: continue
                                                k = (vt, vmid)
                                                if k not in last_bk or ts > last_bk[k]:
                                                    last_bk[k] = ts
                                except Exception:
                                    pass
                                breached = 0
                                ok_cnt = 0
                                total = 0
                                for r in vms:
                                    if r.get('type') not in ('qemu', 'lxc'): continue
                                    total += 1
                                    ts = last_bk.get((r.get('type'), str(r.get('vmid', ''))), 0)
                                    if not ts or (_now - ts) >= _max_s:
                                        breached += 1
                                    else:
                                        ok_cnt += 1
                                if total > 0:
                                    if metric == 'backup_sla_breached_pct':
                                        current_value = round(100 * breached / total, 1)
                                    else:
                                        current_value = round(100 * ok_cnt / total, 1)
                        except Exception as _e:
                            logging.debug(f"[AlertCheck] backup_sla eval failed: {_e}")
                    try:
                        target_name = manager.config.name
                    except Exception:
                        target_name = cluster_id

                elif target_type == 'node':
                    node_summary = manager.get_node_summary(target_id) or {}
                    if metric == 'cpu':
                        current_value = node_summary.get('cpu', 0) * 100
                    elif metric == 'memory':
                        mem = node_summary.get('memory', {}) or {}
                        if mem.get('total', 0) > 0:
                            current_value = (mem.get('used', 0) / mem.get('total', 1)) * 100
                    elif metric == 'disk':
                        rootfs = node_summary.get('rootfs', {}) or {}
                        if rootfs.get('total', 0) > 0:
                            current_value = (rootfs.get('used', 0) / rootfs.get('total', 1)) * 100

                elif target_type == 'vm':
                    # MK: was `manager.get_resources()` which doesn't exist; the
                    # actual VM enumerator on PegaProxManager is get_vm_resources()
                    fetch = getattr(manager, 'get_vm_resources', None)
                    vms = fetch() if callable(fetch) else []
                    for res in (vms or []):
                        if str(res.get('vmid')) == str(target_id):
                            if metric == 'cpu':
                                current_value = res.get('cpu', 0) * 100
                            elif metric == 'memory':
                                if res.get('maxmem', 0) > 0:
                                    current_value = (res.get('mem', 0) / res.get('maxmem', 1)) * 100
                            elif metric == 'disk':
                                if res.get('maxdisk', 0) > 0:
                                    current_value = (res.get('disk', 0) / res.get('maxdisk', 1)) * 100
                            target_name = res.get('name', target_id)
                            break
            except Exception as e:
                logging.warning(f"[AlertCheck]   alert {alert_id} metric lookup raised: {e}")
                _record_eval(alert_id, reason=f'metric lookup error: {e}',
                             cluster_id=cluster_id, metric=metric, target_type=target_type)
                continue
        
        if current_value is None:
            _record_eval(alert_id, reason=f"metric '{metric}' returned no value for {target_type} '{target_id}'",
                         cluster_id=cluster_id, metric=metric, target_type=target_type, target_id=target_id)
            logging.info(f"[AlertCheck]   skip {alert_id}: {target_type} '{target_id}' / {metric} → no value")
            continue

        # Check condition
        triggered = False
        if operator == '>' and current_value > threshold:
            triggered = True
        elif operator == '<' and current_value < threshold:
            triggered = True
        elif operator == '>=' and current_value >= threshold:
            triggered = True
        elif operator == '<=' and current_value <= threshold:
            triggered = True

        if not triggered:
            _record_eval(alert_id, reason=f'below threshold ({metric}={current_value:.1f}% {operator} {threshold}% → false)',
                         cluster_id=cluster_id, metric=metric, current_value=round(current_value, 1),
                         threshold=threshold, operator=operator, triggered=False)

        if triggered:
            # Send alert
            alert_name = alert.get('name', f'{metric} Alert')
            subject = f"[PegaProx Alert] {alert_name}"
            body = f"""
Alert: {alert_name}
Target: {target_type.capitalize()} - {target_name}
Metric: {metric.upper()}
Condition: {metric} {operator} {threshold}%
Current Value: {current_value:.1f}%
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Cluster: {cluster_id}

This is an automated alert from PegaProx.
"""
            html_body = f"""
<h2 style="color: #e74c3c;">⚠️ PegaProx Alert: {alert_name}</h2>
<table style="border-collapse: collapse; width: 100%; max-width: 500px;">
<tr><td style="padding: 8px; border: 1px solid #ddd;"><strong>Target</strong></td><td style="padding: 8px; border: 1px solid #ddd;">{target_type.capitalize()} - {target_name}</td></tr>
<tr><td style="padding: 8px; border: 1px solid #ddd;"><strong>Metric</strong></td><td style="padding: 8px; border: 1px solid #ddd;">{metric.upper()}</td></tr>
<tr><td style="padding: 8px; border: 1px solid #ddd;"><strong>Condition</strong></td><td style="padding: 8px; border: 1px solid #ddd;">{metric} {operator} {threshold}%</td></tr>
<tr style="background-color: #fee2e2;"><td style="padding: 8px; border: 1px solid #ddd;"><strong>Current Value</strong></td><td style="padding: 8px; border: 1px solid #ddd;"><strong>{current_value:.1f}%</strong></td></tr>
<tr><td style="padding: 8px; border: 1px solid #ddd;"><strong>Time</strong></td><td style="padding: 8px; border: 1px solid #ddd;">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</td></tr>
</table>
<p style="color: #666; font-size: 12px; margin-top: 20px;">This is an automated alert from PegaProx.</p>
"""
            
            # NS Apr 2026 (#213) — honour the per-rule channel selection.
            # `channels` (new, list) takes precedence; fall back to legacy `action`.
            sel = alert.get('channels')
            if isinstance(sel, list):
                selected = [str(s) for s in sel]
            else:
                legacy = (alert.get('action') or 'log').lower()
                if legacy == 'email':
                    selected = ['email']
                elif legacy == 'all':
                    # old "fire everything" — keep broadcast (None = all webhooks)
                    selected = ['email', '__all_webhooks__']
                else:  # 'log' or anything unknown
                    selected = []

            want_email = 'email' in selected
            webhook_ids = [s for s in selected if s not in ('email', 'log', '__all_webhooks__')]
            fire_all_webhooks = '__all_webhooks__' in selected

            sent_anywhere = False
            email_status = 'not selected'
            if want_email and not recipients:
                email_status = 'no recipients configured'
                logging.warning(f"[AlertCheck]   alert {alert_id} wants email but no alert_email_recipients set")
            elif want_email and recipients:
                success, error = send_email(recipients, subject, body, html_body)
                if success:
                    sent_anywhere = True
                    email_status = f'ok → {len(recipients)} recipient(s)'
                    logging.info(f"[AlertCheck]   alert {alert_id} email → ok ({len(recipients)})")
                elif error:
                    email_status = f'failed: {error}'
                    logging.warning(f"[AlertCheck]   alert {alert_id} email → FAILED: {error}")

            severity = 'critical' if current_value > 90 else 'warning' if current_value > 70 else 'info'
            alert_data = {
                'alert_name': alert_name,
                'metric': metric,
                'operator': operator,
                'threshold': threshold,
                'current_value': round(current_value, 1),
                'target_type': target_type,
                'target_name': target_name,
                'cluster_id': cluster_id,
                'severity': severity,
                'timestamp': datetime.now().isoformat(),
                'message': f"{target_type.capitalize()} {target_name}: {metric} is {current_value:.1f}% (threshold: {operator} {threshold}%)",
            }
            if _notification_handlers:
                for handler in _notification_handlers:
                    try:
                        handler(alert_data)
                    except Exception as he:
                        logging.debug(f"Notification handler error: {he}")

            webhook_status = 'no webhook channels selected'
            if webhook_ids or fire_all_webhooks:
                try:
                    from pegaprox.utils.webhooks import send_to_channels
                    send_to_channels(alert_data, channel_ids=None if fire_all_webhooks else webhook_ids)
                    sent_anywhere = True
                    webhook_status = f'dispatched to {webhook_ids or "all webhooks"}'
                    logging.info(f"[AlertCheck]   alert {alert_id} webhooks → {webhook_status}")
                except Exception as he:
                    webhook_status = f'dispatch error: {he}'
                    logging.warning(f"[AlertCheck]   alert {alert_id} webhooks → FAILED: {he}")

            _record_eval(alert_id, triggered=True, current_value=round(current_value, 1),
                         threshold=threshold, operator=operator, metric=metric,
                         cluster_id=cluster_id, target_type=target_type, target_id=target_id,
                         severity=severity, email=email_status, webhooks=webhook_status,
                         sent=sent_anywhere)

            # bump cooldown only if at least one destination ran (email OR webhook)
            # purely "log" rules should still respect cooldown, but we don't dedupe them
            if sent_anywhere or not selected:
                _alert_last_sent[alert_key] = current_time


# Alert check thread
_alert_thread = None
_alert_running = False

# NS Apr 2026 (#331) — throttle the version poll. The main alert loop ticks every 60s
# but hitting GitHub that often would be silly. Keep a module-level timestamp and
# skip until `UPDATE_CHECK_INTERVAL` has passed.
# NS 2026-04-24: bumped to 24h after user feedback — once a day is plenty and keeps
# us well clear of any rate-limit suspicion from upstream mirrors.
UPDATE_CHECK_INTERVAL = 24 * 60 * 60  # 24 hours
_FIRST_CHECK_DELAY = 15 * 60  # wait 15min after process start before the first poll
_last_update_check_at = 0.0
_process_started_at = time.time()


def _parse_ver(v):
    try:
        parts = str(v).replace('Alpha ', '').replace('Beta ', '').split('.')
        return tuple(int(p) for p in parts if p.isdigit())
    except Exception:
        return (0, 0)


def check_update_available_alert():
    """Poll version.json and send an email when a new release appears.

    Fires at most once per *new* version (dedup via server_settings.alert_last_notified_version).
    No-op when `alert_update_available` is False or there are no recipients.
    """
    global _last_update_check_at
    now = time.time()
    # don't hammer the mirror right on startup (server restarts shouldn't refire the poll)
    if _last_update_check_at == 0.0 and (now - _process_started_at) < _FIRST_CHECK_DELAY:
        return
    if now - _last_update_check_at < UPDATE_CHECK_INTERVAL:
        return
    _last_update_check_at = now

    try:
        settings = load_server_settings()
    except Exception as e:
        logging.debug(f"[update-alert] cannot load settings: {e}")
        return

    if not settings.get('alert_update_available'):
        return
    recipients = settings.get('alert_email_recipients') or []
    if not recipients:
        return

    remote = None
    try:
        import requests  # local import — background threads shouldn't block module load
        for url in (GITHUB_VERSION_URL, MIRROR_VERSION_URL):
            try:
                r = requests.get(url, timeout=10)
                if r.status_code == 200:
                    remote = r.json()
                    break
            except Exception:
                continue
    except Exception as e:
        logging.debug(f"[update-alert] fetch failed: {e}")
        return
    if not remote:
        return

    latest = remote.get('version', '')
    if not latest:
        return
    if _parse_ver(latest) <= _parse_ver(PEGAPROX_VERSION):
        return  # already on latest

    last_notified = settings.get('alert_last_notified_version') or ''
    if last_notified == latest:
        return  # already told the user about this one

    # compose + send
    release_date = remote.get('release_date') or ''
    changelog = remote.get('changelog', []) or []
    subject = f"[PegaProx] Update available — {latest}"
    body_lines = [
        f"A new PegaProx release is available: {latest}",
        f"Current version: {PEGAPROX_VERSION}",
        f"Released: {release_date}" if release_date else '',
        '',
        'Changelog:',
    ]
    body_lines += [f"  - {line}" for line in changelog[:10]]
    body_lines += ['', f"Download: {remote.get('download_url', '')}"]
    body = '\n'.join([ln for ln in body_lines if ln is not None])
    html_items = ''.join(f"<li>{c}</li>" for c in changelog[:10])
    html_body = (
        f"<h2>PegaProx update available</h2>"
        f"<p>A new release <b>{latest}</b> is available.</p>"
        f"<p>Current: <code>{PEGAPROX_VERSION}</code>"
        + (f" · Released: {release_date}" if release_date else '') + "</p>"
        f"<ul>{html_items}</ul>"
        f"<p><a href=\"{remote.get('download_url','')}\">Release page</a></p>"
    )

    ok, err = send_email(recipients, subject, body, html_body)
    if ok:
        settings['alert_last_notified_version'] = latest
        try:
            save_server_settings(settings)
        except Exception as e:
            # non-fatal — we'll just re-notify next cycle
            logging.debug(f"[update-alert] could not persist last_notified_version: {e}")
        logging.info(f"[update-alert] sent notification for {latest}")
    elif err:
        logging.warning(f"[update-alert] email failed: {err}")


# NS 2026-04-24 (#213) — node up/down watcher. Background thread compares
# the current node status per cluster to the previous tick and fires an alert
# on transition. A small streak counter keeps short flaps (single missed poll)
# from spamming the on-call channel — default 3 consecutive misses = ~3 min.
_node_last_status = {}   # (cluster_id, node_name) -> 'online' | 'offline'
_node_offline_streak = {}  # (cluster_id, node_name) -> int
_NODE_OFFLINE_FLAP_THRESHOLD = 3


def check_node_status_transitions():
    try:
        settings = load_server_settings() or {}
    except Exception:
        settings = {}
    if not settings.get('alert_node_status', True):
        return  # disabled by admin

    threshold = int(settings.get('alert_node_status_flap_threshold') or _NODE_OFFLINE_FLAP_THRESHOLD)
    recipients = settings.get('alert_email_recipients') or []

    for cluster_id, mgr in list(cluster_managers.items()):
        try:
            if not getattr(mgr, 'is_connected', False):
                continue
            statuses = mgr.get_node_status() or {}
        except Exception as e:
            logging.debug(f"[NodeWatch] {cluster_id}: status fetch failed: {e}")
            continue

        for node, info in statuses.items():
            status = (info.get('status') or '').lower()
            if status not in ('online', 'offline'):
                continue
            key = (cluster_id, node)
            prev = _node_last_status.get(key)

            # track streak
            if status == 'offline':
                _node_offline_streak[key] = _node_offline_streak.get(key, 0) + 1
            else:
                _node_offline_streak[key] = 0

            # online -> offline: only fire once the streak crosses the flap threshold
            if prev == 'online' and status == 'offline' and _node_offline_streak[key] >= threshold:
                _emit_node_status_event(cluster_id, node, 'offline',
                                         f"Node {node} is offline on cluster {cluster_id}",
                                         'critical', recipients)
                _node_last_status[key] = 'offline'
                continue

            # offline -> online recovery
            if prev == 'offline' and status == 'online':
                _emit_node_status_event(cluster_id, node, 'online',
                                         f"Node {node} recovered on cluster {cluster_id}",
                                         'info', recipients)
                _node_last_status[key] = 'online'
                continue

            # first time we see this node — seed without firing
            if prev is None:
                # treat initial offline as "unseen yet" — don't spam on startup
                _node_last_status[key] = status


def _emit_node_status_event(cluster_id, node, new_status, message, severity, recipients):
    alert_data = {
        'alert_name': f"Node {node} {'DOWN' if new_status == 'offline' else 'recovered'}",
        'metric': 'node_status',
        'target_type': 'node',
        'target_name': node,
        'cluster_id': cluster_id,
        'severity': severity,
        'current_value': new_status,
        'timestamp': datetime.now().isoformat(),
        'message': message,
    }
    logging.warning(f"[NodeWatch] {message} (severity={severity})")

    if recipients:
        try:
            subject = f"[PegaProx] {alert_data['alert_name']}"
            body = f"{message}\n\nCluster: {cluster_id}\nNode: {node}\nTime: {alert_data['timestamp']}\n"
            html = f"<h2>{alert_data['alert_name']}</h2><p>{message}</p><p><b>Cluster:</b> {cluster_id}<br><b>Time:</b> {alert_data['timestamp']}</p>"
            send_email(recipients, subject, body, html)
        except Exception as e:
            logging.debug(f"[NodeWatch] email failed: {e}")

    try:
        from pegaprox.utils.webhooks import send_to_channels
        send_to_channels(alert_data)
    except Exception as e:
        logging.debug(f"[NodeWatch] webhook dispatch failed: {e}")


_SESSION_CLEANUP_INTERVAL = 6 * 60 * 60   # every 6 hours
_last_session_cleanup_at = 0.0


def _periodic_session_cleanup():
    """NS Apr 2026 — expire stale sessions in the background. Was called on boot only,
    which left tokens alive for the full timeout (default 8h) after a logout/crash.
    Piggy-backs on the alert loop so we don't spawn yet another thread."""
    global _last_session_cleanup_at
    now = time.time()
    if now - _last_session_cleanup_at < _SESSION_CLEANUP_INTERVAL:
        return
    _last_session_cleanup_at = now
    try:
        from pegaprox.utils.auth import cleanup_expired_sessions
        cleanup_expired_sessions()
    except Exception as e:
        logging.debug(f"[SessionCleanup] background pass failed: {e}")


def alert_check_loop():
    """Background thread that checks alerts periodically"""
    global _alert_running
    _alert_running = True

    while _alert_running:
        try:
            check_and_send_alerts()
        except Exception as e:
            logging.error(f"Alert check error: {e}")
        try:
            check_node_status_transitions()
        except Exception as e:
            logging.debug(f"Node status watcher error: {e}")
        try:
            check_update_available_alert()
        except Exception as e:
            logging.debug(f"Update alert check error: {e}")
        try:
            _periodic_session_cleanup()
        except Exception as e:
            logging.debug(f"session cleanup tick error: {e}")

        # Check every 60 seconds
        time.sleep(60)

def start_alert_thread():
    global _alert_thread
    if _alert_thread is None or not _alert_thread.is_alive():
        _alert_thread = threading.Thread(target=alert_check_loop, daemon=True)
        _alert_thread.start()
        logging.info("Alert monitoring thread started")



