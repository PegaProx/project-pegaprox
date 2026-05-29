"""
Public Status Page Plugin — Cluster health for monitoring screens
NS: Apr 2026, MK: Apr 2026 - incident tracking + uptime

Public endpoint with URL auth key, no login required.
Designed for IT monitoring dashboards (like PRTG status pages).
"""
import os
import json
import hmac
import logging
import uuid
import sqlite3  # kept for Row + type re-exports
from datetime import datetime, timedelta
from flask import request, jsonify, send_file, Response

from pegaprox.api.plugins import register_plugin_route
# MK May 2026 — plugins must route DB connections through dbcrypto so SQLCipher
# unlocks the encrypted DB. Direct sqlite3.connect() will fail once encryption
# is active.
from pegaprox.core import dbcrypto
from pegaprox.globals import cluster_managers, pbs_managers
from pegaprox.constants import CONFIG_DIR

PLUGIN_NAME = "Public Status Page"
PLUGIN_DIR = os.path.dirname(os.path.abspath(__file__))

def _load_config():
    cfg_path = os.path.join(PLUGIN_DIR, 'config.json')
    try:
        with open(cfg_path) as f:
            return json.load(f)
    except Exception:
        return {"auth_key": "", "refresh_interval": 30}

def _save_config(cfg):
    cfg_path = os.path.join(PLUGIN_DIR, 'config.json')
    with open(cfg_path, 'w') as f:
        json.dump(cfg, f, indent=4)


def _check_key():
    """Validate URL auth key — returns error tuple or None if OK"""
    cfg = _load_config()
    expected = cfg.get('auth_key', '')
    if not expected:
        return {'error': 'Status page not configured. Set an auth key in plugin settings.'}, 403
    key = request.args.get('key', '')
    if not hmac.compare_digest(key, expected):
        return {'error': 'Invalid or missing auth key'}, 401
    return None


def _require_admin():
    """Check if current user is admin — returns error tuple or None"""
    from pegaprox.utils.auth import load_users
    from pegaprox.models.permissions import ROLE_ADMIN
    username = request.session.get('user', '')
    users = load_users()
    user = users.get(username, {})
    if user.get('role') != ROLE_ADMIN:
        return {'error': 'Admin access required'}, 403
    return None


def _get_config():
    """Return full config including auth key (admin only)"""
    err = _require_admin()
    if err:
        return err
    cfg = _load_config()
    return {
        # MK: security audit — mask key in API response, only show last 4 chars
        'auth_key': ('*' * 20 + cfg.get('auth_key', '')[-4:]) if cfg.get('auth_key') else '',
        'page_title': cfg.get('page_title', 'System Status'),
        'refresh_interval': cfg.get('refresh_interval', 30),
        'show_node_details': cfg.get('show_node_details', True),
        'show_vm_summary': cfg.get('show_vm_summary', True),
        'show_storage': cfg.get('show_storage', True),
        'show_cluster_name': cfg.get('show_cluster_name', True),
        'show_pbs_backups': cfg.get('show_pbs_backups', True),
        'pbs_stale_hours': cfg.get('pbs_stale_hours', 48),
        'theme_color': cfg.get('theme_color', '#e57000'),
        'custom_logo_url': cfg.get('custom_logo_url', ''),
        'status_url': f"/status?key={cfg.get('auth_key', '')}",
    }


def _update_config():
    """Update config (admin only)"""
    err = _require_admin()
    if err:
        return err
    data = request.get_json() or {}
    cfg = _load_config()
    for k in ['page_title', 'refresh_interval', 'show_node_details', 'show_vm_summary',
              'show_storage', 'show_cluster_name', 'theme_color', 'custom_logo_url',
              'show_pbs_backups', 'pbs_stale_hours']:
        if k in data:
            val = data[k]
            # MK May 2026 - numeric fields get rendered into status.html; clamp before
            # store so a future template change without escapeHtml can't leak a payload.
            if k == 'pbs_stale_hours':
                try:
                    val = int(val)
                    if val < 1 or val > 8760:
                        val = 48
                except (ValueError, TypeError):
                    val = 48
            elif k == 'refresh_interval':
                try:
                    val = int(val)
                    if val < 5 or val > 3600:
                        val = 30
                except (ValueError, TypeError):
                    val = 30
            cfg[k] = val
    _save_config(cfg)
    return {'success': True}


def _generate_key():
    """Generate a new auth key (admin only)"""
    err = _require_admin()
    if err:
        return err
    cfg = _load_config()
    cfg['auth_key'] = uuid.uuid4().hex[:24]
    _save_config(cfg)
    logging.info(f"[PLUGINS] Status page auth key regenerated")
    return {'success': True, 'auth_key': cfg['auth_key']}


def _collect_pbs_backup_health(max_stale_hours=48):
    """MK #309 — compact backup health snapshot per PBS.
    One call for datastores, two per store (status + groups). Avoids listing every
    snapshot because that's expensive at any scale — PBS already stores the last-backup
    timestamp per group so we lean on that.
    Returns a list of PBS dicts with datastore usage + stale-group counts.
    """
    result = []
    now_ts = datetime.now().timestamp()
    for pid, pmgr in pbs_managers.items():
        entry = {
            'id': pid,
            'name': getattr(pmgr, 'name', '') or pid,
            'host': getattr(pmgr, 'host', '') or '',
            'connected': bool(getattr(pmgr, 'connected', False)),
            'datastores': [],
            'stale_groups': [],
            'total_groups': 0,
            'stale_count': 0,
            'failed_verifications': 0,
        }
        if not entry['connected']:
            result.append(entry); continue

        try:
            ds_resp = pmgr.get_datastores() or {}
            ds_list = ds_resp.get('data') if isinstance(ds_resp, dict) else ds_resp
        except Exception as e:
            entry['error'] = f"datastores: {e}"
            result.append(entry); continue

        for ds in (ds_list or []):
            name = ds.get('name') if isinstance(ds, dict) else None
            if not name:
                continue
            ds_info = {'name': name, 'used': None, 'total': None, 'percent': None,
                       'snapshots': 0, 'groups': 0, 'stale_groups': 0, 'latest_backup': None}
            # usage / counts
            try:
                st = pmgr.get_datastore_status(name) or {}
                d = st.get('data') or {}
                ds_info['used'] = d.get('used')
                ds_info['total'] = d.get('total')
                if ds_info['total']:
                    ds_info['percent'] = round((ds_info['used'] or 0) / ds_info['total'] * 100, 1)
                # snapshot count sometimes reported here
                counts = d.get('counts') or {}
                if 'vm' in counts or 'ct' in counts or 'host' in counts:
                    snap_sum = 0
                    for k in ('vm', 'ct', 'host'):
                        v = counts.get(k) or {}
                        if isinstance(v, dict):
                            snap_sum += v.get('snapshots', 0)
                    ds_info['snapshots'] = snap_sum
            except Exception:
                pass
            # groups — for freshness + failed-verification counts
            try:
                gr = pmgr.get_groups(name) or {}
                groups = gr.get('data') if isinstance(gr, dict) else gr
                ds_info['groups'] = len(groups or [])
                latest_group_ts = None
                for g in (groups or []):
                    last_ts = g.get('last-backup')
                    if last_ts:
                        if latest_group_ts is None or last_ts > latest_group_ts:
                            latest_group_ts = last_ts
                        age_h = (now_ts - last_ts) / 3600 if isinstance(last_ts, (int, float)) else None
                        if age_h is not None and age_h > max_stale_hours:
                            ds_info['stale_groups'] += 1
                            label = f"{g.get('backup-type', '?')}/{g.get('backup-id', '?')}"
                            entry['stale_groups'].append({
                                'store': name, 'group': label,
                                'last_backup_ts': last_ts,
                                'age_hours': round(age_h, 1),
                            })
                    # rough failed-verification signal
                    if (g.get('last-verify-state') or g.get('verification', {}).get('state')) == 'failed':
                        entry['failed_verifications'] += 1
                if latest_group_ts:
                    ds_info['latest_backup'] = latest_group_ts
                entry['total_groups'] += ds_info['groups']
            except Exception:
                pass

            entry['datastores'].append(ds_info)

        entry['stale_count'] = len(entry['stale_groups'])
        # cap the per-server stale list — the UI doesn't need 500 entries
        entry['stale_groups'] = entry['stale_groups'][:20]
        result.append(entry)

    return result


def _public_status():
    """Public health endpoint — validated by URL key, no session needed.
    This is called directly, NOT through the plugin proxy (which requires auth).
    """
    err = _check_key()
    if err:
        return err

    cfg = _load_config()
    clusters = []

    for cid, mgr in cluster_managers.items():
        cluster_info = {
            'id': cid,
            'name': mgr.config.name if cfg.get('show_cluster_name', True) else 'Cluster',
            'connected': mgr.is_connected,
            'nodes': [],
            'vm_summary': {},
            'storage': [],
        }

        if not mgr.is_connected:
            cluster_info['status'] = 'offline'
            clusters.append(cluster_info)
            continue

        cluster_info['status'] = 'online'

        # node health
        if cfg.get('show_node_details', True):
            try:
                node_status = mgr.get_node_status()
                for name, info in (node_status or {}).items():
                    cluster_info['nodes'].append({
                        'name': name,
                        'online': not info.get('offline', False),
                        'cpu_percent': round(info.get('cpu_percent', 0), 1),
                        'mem_percent': round(info.get('mem_percent', 0), 1),
                        'uptime': info.get('uptime', 0),
                    })
            except Exception:
                pass

        # VM summary
        if cfg.get('show_vm_summary', True):
            try:
                vms = mgr.get_vm_resources()
                running = sum(1 for v in vms if v.get('status') == 'running')
                stopped = sum(1 for v in vms if v.get('status') == 'stopped')
                total = len(vms)
                qemu = sum(1 for v in vms if v.get('type') == 'qemu')
                lxc = sum(1 for v in vms if v.get('type') == 'lxc')
                cluster_info['vm_summary'] = {
                    'total': total, 'running': running, 'stopped': stopped,
                    'qemu': qemu, 'lxc': lxc,
                }
            except Exception:
                pass

        # storage (aggregate per cluster, no per-node breakdown)
        if cfg.get('show_storage', True):
            try:
                # get storage from first online node
                for n in (cluster_info['nodes'] or [{'name': ''}]):
                    if not n.get('online', True):
                        continue
                    node_name = n['name']
                    if not node_name:
                        continue
                    storages = mgr.get_storage_list(node_name)
                    seen = set()
                    for s in (storages or []):
                        sid = s.get('storage', '')
                        if sid in seen:
                            continue
                        seen.add(sid)
                        total_bytes = s.get('total', 0)
                        used_bytes = s.get('used', 0)
                        if total_bytes > 0:
                            cluster_info['storage'].append({
                                'name': sid,
                                'type': s.get('type', ''),
                                'total': total_bytes,
                                'used': used_bytes,
                                'percent': round(used_bytes / total_bytes * 100, 1),
                            })
                    break  # one node is enough for shared storage
            except Exception:
                pass

        clusters.append(cluster_info)

    # fetch recent incidents for the public page
    incidents = _get_recent_incidents(14)

    # record uptime snapshot
    for c in clusters:
        _record_uptime(c['id'], c.get('status', 'offline'), c.get('nodes', []))

    # uptime percentages (30 day)
    uptime_map = {}
    for c in clusters:
        uptime_map[c['id']] = _calc_uptime(c['id'], 30)

    # MK #309 — PBS backup health, only when enabled in config
    pbs_backups = []
    if cfg.get('show_pbs_backups', True):
        try:
            pbs_backups = _collect_pbs_backup_health(cfg.get('pbs_stale_hours', 48))
        except Exception as e:
            logging.warning(f"[status_page] pbs backup collection failed: {e}")

    return {
        'clusters': clusters,
        'incidents': incidents,
        'uptime': uptime_map,
        'pbs_backups': pbs_backups,
        'config': {
            'page_title': cfg.get('page_title', 'System Status'),
            'refresh_interval': cfg.get('refresh_interval', 30),
            'show_node_details': cfg.get('show_node_details', True),
            'show_vm_summary': cfg.get('show_vm_summary', True),
            'show_storage': cfg.get('show_storage', True),
            'show_pbs_backups': cfg.get('show_pbs_backups', True),
            'pbs_stale_hours': cfg.get('pbs_stale_hours', 48),
            'theme_color': cfg.get('theme_color', '#e57000'),
            'custom_logo_url': cfg.get('custom_logo_url', ''),
            'maintenance_message': cfg.get('maintenance_message', ''),
            'maintenance_start': cfg.get('maintenance_start', ''),
            'maintenance_end': cfg.get('maintenance_end', ''),
            'components': cfg.get('components', []),
        },
    }


# ─── Incident CRUD (admin) ───

def _get_db():
    # MK May 2026: route via dbcrypto so the SQLCipher handshake runs first.
    db_path = os.path.join(CONFIG_DIR, 'pegaprox.db')
    conn = dbcrypto.connect(db_path, timeout=5)
    conn.row_factory = dbcrypto.Row
    return conn

def _get_recent_incidents(days=14):
    try:
        conn = _get_db()
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()
        rows = conn.execute(
            "SELECT * FROM status_incidents WHERE started_at >= ? ORDER BY started_at DESC LIMIT 50", (cutoff,)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except:
        return []

def _record_uptime(cluster_id, status, nodes):
    """Store a single uptime data point"""
    try:
        conn = _get_db()
        online = sum(1 for n in nodes if n.get('online'))
        total = len(nodes)
        conn.execute(
            "INSERT INTO status_uptime (cluster_id, timestamp, status, nodes_online, nodes_total) VALUES (?,?,?,?,?)",
            (cluster_id, datetime.now().isoformat(), status, online, total)
        )
        # keep last 90 days only
        cutoff = (datetime.now() - timedelta(days=90)).isoformat()
        conn.execute("DELETE FROM status_uptime WHERE timestamp < ?", (cutoff,))
        conn.commit()
        conn.close()
    except:
        pass

def _calc_uptime(cluster_id, days=30):
    """Calculate uptime percentage over N days"""
    try:
        conn = _get_db()
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()
        rows = conn.execute(
            "SELECT status FROM status_uptime WHERE cluster_id = ? AND timestamp >= ?",
            (cluster_id, cutoff)
        ).fetchall()
        conn.close()
        if not rows:
            return None
        up = sum(1 for r in rows if r['status'] == 'online')
        return round(up / len(rows) * 100, 2)
    except:
        return None


def _list_incidents():
    err = _require_admin()
    if err: return err
    return _get_recent_incidents(90)


def _create_incident():
    err = _require_admin()
    if err: return err
    data = request.get_json() or {}
    iid = uuid.uuid4().hex[:12]
    now = datetime.now().isoformat()
    try:
        conn = _get_db()
        conn.execute(
            "INSERT INTO status_incidents (id, title, status, severity, message, components, started_at, created_by, updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (iid, data.get('title', 'Incident'), data.get('status', 'investigating'),
             data.get('severity', 'minor'), data.get('message', ''),
             json.dumps(data.get('components', [])), data.get('started_at', now),
             request.session.get('user', 'admin'), now)
        )
        conn.commit()
        conn.close()
        return {'success': True, 'id': iid}
    except Exception as e:
        return {'error': str(e)}, 500


def _update_incident():
    err = _require_admin()
    if err: return err
    data = request.get_json() or {}
    iid = data.get('id')
    if not iid:
        return {'error': 'id required'}, 400
    now = datetime.now().isoformat()
    sets, vals = [], []
    for k in ['title', 'status', 'severity', 'message', 'components', 'resolved_at']:
        if k in data:
            val = json.dumps(data[k]) if k == 'components' else data[k]
            sets.append(f"{k} = ?")
            vals.append(val)
    if data.get('status') == 'resolved' and 'resolved_at' not in data:
        sets.append("resolved_at = ?")
        vals.append(now)
    sets.append("updated_at = ?")
    vals.append(now)
    vals.append(iid)
    try:
        conn = _get_db()
        conn.execute(f"UPDATE status_incidents SET {', '.join(sets)} WHERE id = ?", vals)
        conn.commit()
        conn.close()
        return {'success': True}
    except Exception as e:
        return {'error': str(e)}, 500


def _delete_incident():
    err = _require_admin()
    if err: return err
    data = request.get_json() or {}
    iid = data.get('id')
    if not iid:
        return {'error': 'id required'}, 400
    try:
        conn = _get_db()
        conn.execute("DELETE FROM status_incidents WHERE id = ?", (iid,))
        conn.commit()
        conn.close()
        return {'success': True}
    except Exception as e:
        return {'error': str(e)}, 500


def _uptime_history():
    """Return 90-day uptime data for the uptime bar visualization"""
    err = _check_key()
    if err: return err
    try:
        conn = _get_db()
        cutoff = (datetime.now() - timedelta(days=90)).isoformat()
        rows = conn.execute(
            "SELECT cluster_id, date(timestamp) as day, "
            "ROUND(AVG(CASE WHEN status='online' THEN 1.0 ELSE 0.0 END)*100, 1) as uptime_pct "
            "FROM status_uptime WHERE timestamp >= ? GROUP BY cluster_id, day ORDER BY day",
            (cutoff,)
        ).fetchall()
        conn.close()
        result = {}
        for r in rows:
            cid = r['cluster_id']
            if cid not in result: result[cid] = []
            result[cid].append({'day': r['day'], 'pct': r['uptime_pct']})
        return result
    except:
        return {}


# NS: SVG status badge — embeddable in README/docs
def _status_badge():
    err = _check_key()
    if err: return err

    all_online = all(mgr.is_connected for mgr in cluster_managers.values()) if cluster_managers else False
    any_online = any(mgr.is_connected for mgr in cluster_managers.values()) if cluster_managers else False

    if all_online:
        label, color = 'operational', '#3fb950'
    elif any_online:
        label, color = 'partial outage', '#d29922'
    else:
        label, color = 'major outage', '#da3633'

    text_w = len(label) * 6.5 + 12
    total_w = 70 + text_w
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="{total_w}" height="20">
  <rect width="70" height="20" rx="3" fill="#555"/>
  <rect x="70" width="{text_w}" height="20" rx="3" fill="{color}"/>
  <rect width="{total_w}" height="20" rx="3" fill="url(#g)"/>
  <defs><linearGradient id="g" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient></defs>
  <text x="35" y="14" fill="#fff" text-anchor="middle" font-family="Verdana,sans-serif" font-size="11">status</text>
  <text x="{70 + text_w/2}" y="14" fill="#fff" text-anchor="middle" font-family="Verdana,sans-serif" font-size="11">{label}</text>
</svg>'''
    return Response(svg, mimetype='image/svg+xml', headers={'Cache-Control': 'no-cache, max-age=0'})


def register(app):
    """Register plugin routes"""
    # Admin routes (through plugin proxy, requires auth)
    register_plugin_route('status_page', 'config', _get_config)
    register_plugin_route('status_page', 'config/update', _update_config)
    register_plugin_route('status_page', 'generate-key', _generate_key)

    # Incident management (admin)
    register_plugin_route('status_page', 'incidents', _list_incidents)
    register_plugin_route('status_page', 'incidents/create', _create_incident)
    register_plugin_route('status_page', 'incidents/update', _update_incident)
    register_plugin_route('status_page', 'incidents/delete', _delete_incident)

    # Public routes (key-auth only)
    register_plugin_route('status_page', 'public', _public_status)
    register_plugin_route('status_page', 'uptime-history', _uptime_history)
    register_plugin_route('status_page', 'badge', _status_badge)

    logging.info("[PLUGINS] Public Status Page plugin registered")
