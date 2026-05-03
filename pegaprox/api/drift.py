# -*- coding: utf-8 -*-
"""
Config Drift Detection — NS May 2026.

Snapshots core cluster configuration on a schedule, compares against an
admin-set baseline, emits drift events when something changed.

Categories tracked:
  - vm_config       per-VM `qm config` (qemu) / `pct config` (lxc)
  - storage         /etc/pve/storage.cfg (via /api2/json/storage)
  - network         per-node /etc/network/interfaces (via /api2/json/nodes/<n>/network)
  - cluster_options /etc/pve/datacenter.cfg (via /api2/json/cluster/options)

Workflow:
  1. Admin clicks "Set baseline" — current state stored in drift_baselines.
  2. Background scanner (every 6h) and manual trigger compute current state,
     diff against baseline, write drift_events.
  3. UI shows open events with diff. Admin "Acknowledge" or "Promote diff
     to new baseline" (latter rebases so the change is no longer flagged).

Diff is a list of {path, op, before, after} entries. Keeps it explainable.

Drift events also fan out via the alerts notification handlers, so the same
Slack/Discord/ntfy/web-push channels users have configured for alerts also
get drift notifications without extra plumbing.
"""
import json
import time
import uuid
import logging
import threading
from datetime import datetime
from flask import Blueprint, jsonify, request

from pegaprox.globals import cluster_managers
from pegaprox.utils.auth import require_auth
from pegaprox.api.helpers import check_cluster_access
from pegaprox.core.db import get_db
from pegaprox.models.permissions import ROLE_ADMIN

bp = Blueprint('drift', __name__)


# ──────────────────────────────────────────────────────────────────────────
# Snapshot fetchers — return (kind, scope, dict) tuples
# scope is a sub-identifier (e.g. vmid for vm_config, node name for network)
# ──────────────────────────────────────────────────────────────────────────

# Keys whose change should NOT count as drift (volatile bookkeeping)
_VM_VOLATILE_KEYS = {'meta', 'lock', 'parent', 'snapshot', 'snapstate',
                     'lastsnapshot', 'pending', 'running-machine', 'running-qemu',
                     'digest'}
_NETWORK_VOLATILE = {'active'}

# NS: PVE returns these comma-separated lists in non-deterministic order (e.g.
# `content` on storages, `tags` on VMs). Without sorting them we'd flood the
# admin with bogus drift events. Sort once at fetch time, the diff becomes
# stable.
_CSV_NORMALIZE_KEYS = {'content', 'tags', 'nodes'}


def _strip_volatile(d, volatile_keys):
    if not isinstance(d, dict): return d
    out = {}
    for k, v in d.items():
        if k in volatile_keys: continue
        if k in _CSV_NORMALIZE_KEYS and isinstance(v, str) and ',' in v:
            parts = [p.strip() for p in v.split(',') if p.strip()]
            v = ','.join(sorted(parts))
        out[k] = v
    return out


def _fetch_state(mgr, cluster_id):
    """Return list of (kind, scope, snapshot_dict). Robust to per-call fails;
    a single dead node shouldn't poison the whole snapshot."""
    out = []
    host = mgr.host

    # cluster options
    try:
        r = mgr._api_get(f"https://{host}:8006/api2/json/cluster/options")
        if r is not None and getattr(r, 'status_code', 0) == 200:
            data = r.json().get('data') or {}
            out.append(('cluster_options', 'global', data))
    except Exception as e:
        logging.debug(f"[drift] cluster/options fetch failed: {e}")

    # storage configs (cluster-wide)
    try:
        r = mgr._api_get(f"https://{host}:8006/api2/json/storage")
        if r is not None and getattr(r, 'status_code', 0) == 200:
            for s in (r.json().get('data') or []):
                sid = s.get('storage')
                if not sid: continue
                # _strip_volatile sorts comma-list fields like `content`, `nodes`
                # which Proxmox returns in non-deterministic order
                out.append(('storage', sid, _strip_volatile(s, set())))
    except Exception as e:
        logging.debug(f"[drift] storage fetch failed: {e}")

    # per-node network state
    try:
        nodes = (mgr.nodes or {}).keys()
    except Exception:
        nodes = []
    for node in nodes:
        try:
            r = mgr._api_get(f"https://{host}:8006/api2/json/nodes/{node}/network")
            if r is None or getattr(r, 'status_code', 0) != 200:
                continue
            for nic in (r.json().get('data') or []):
                iface = nic.get('iface')
                if not iface: continue
                clean = _strip_volatile(nic, _NETWORK_VOLATILE)
                out.append(('network', f"{node}/{iface}", clean))
        except Exception as e:
            logging.debug(f"[drift] network/{node} fetch failed: {e}")

    # per-VM/CT configs
    try:
        for r in (mgr.get_vm_resources() or []):
            t = r.get('type')
            vmid = r.get('vmid')
            node = r.get('node')
            if t not in ('qemu', 'lxc') or not vmid or not node:
                continue
            url = f"https://{host}:8006/api2/json/nodes/{node}/{t}/{vmid}/config"
            try:
                resp = mgr._api_get(url)
                if resp is None or getattr(resp, 'status_code', 0) != 200:
                    continue
                cfg = resp.json().get('data') or {}
                clean = _strip_volatile(cfg, _VM_VOLATILE_KEYS)
                out.append(('vm_config', f"{t}/{vmid}", clean))
            except Exception:
                continue
    except Exception as e:
        logging.debug(f"[drift] vm enumeration failed: {e}")

    return out


# ──────────────────────────────────────────────────────────────────────────
# Diff
# ──────────────────────────────────────────────────────────────────────────

def _flat_diff(baseline, current):
    """Compare two dicts, return list of {path, op, before, after}.
    Top-level keys only — Proxmox configs are flat enough that this is fine
    and produces much more readable output than recursive deep-diffs."""
    if not isinstance(baseline, dict): baseline = {}
    if not isinstance(current, dict): current = {}
    keys = set(baseline.keys()) | set(current.keys())
    diffs = []
    for k in sorted(keys):
        b, c = baseline.get(k), current.get(k)
        if b == c: continue
        if k in baseline and k not in current:
            diffs.append({'path': k, 'op': 'removed', 'before': b, 'after': None})
        elif k not in baseline and k in current:
            diffs.append({'path': k, 'op': 'added', 'before': None, 'after': c})
        else:
            diffs.append({'path': k, 'op': 'changed', 'before': b, 'after': c})
    return diffs


def _severity_for(kind, diffs):
    """Heuristic — VM disks/network changes are louder than e.g. description edits."""
    paths = {d['path'] for d in diffs}
    sensitive_vm = {'scsi0', 'sata0', 'virtio0', 'ide0', 'net0', 'net1', 'net2',
                    'memory', 'cores', 'cpu', 'ostype', 'boot', 'bootdisk',
                    'cipassword', 'sshkeys'}
    sensitive_storage = {'shared', 'export', 'server', 'username', 'content', 'pool'}
    sensitive_network = {'address', 'netmask', 'gateway', 'bridge_ports', 'type',
                         'bond_slaves', 'vlan-raw-device'}
    if kind == 'cluster_options':
        return 'warning'
    if kind == 'vm_config' and (paths & sensitive_vm):
        return 'warning'
    if kind == 'storage' and (paths & sensitive_storage):
        return 'warning'
    if kind == 'network' and (paths & sensitive_network):
        return 'critical'
    return 'info'


def _short_summary(kind, scope, diffs):
    keys = ', '.join(d['path'] for d in diffs[:4])
    if len(diffs) > 4:
        keys += f", +{len(diffs) - 4} more"
    return f"{kind} {scope}: {keys}"


# ──────────────────────────────────────────────────────────────────────────
# Persistence helpers
# ──────────────────────────────────────────────────────────────────────────

def _baseline_key(cluster_id, kind, scope):
    return f"{cluster_id}:{kind}:{scope}"


def _load_baselines(cluster_id):
    try:
        c = get_db().conn.cursor()
        c.execute(
            "SELECT id, kind, scope, snapshot, created_at, created_by "
            "FROM drift_baselines WHERE cluster_id = ?",
            (cluster_id,)
        )
        out = {}
        for r in c.fetchall():
            try:
                snap = json.loads(r['snapshot'])
            except Exception:
                snap = {}
            out[(r['kind'], r['scope'])] = {
                'id': r['id'],
                'snapshot': snap,
                'created_at': r['created_at'],
                'created_by': r['created_by'] or '',
            }
        return out
    except Exception as e:
        logging.warning(f"[drift] baseline load failed: {e}")
        return {}


def _set_baseline(cluster_id, kind, scope, snapshot, user):
    try:
        c = get_db().conn.cursor()
        # one baseline per (cluster,kind,scope) — replace
        c.execute(
            "DELETE FROM drift_baselines WHERE cluster_id=? AND kind=? AND scope=?",
            (cluster_id, kind, scope)
        )
        c.execute('''
            INSERT INTO drift_baselines (id, cluster_id, kind, scope, snapshot, created_at, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (uuid.uuid4().hex[:12], cluster_id, kind, scope,
              json.dumps(snapshot), datetime.now().isoformat(), user))
        get_db().conn.commit()
    except Exception as e:
        logging.warning(f"[drift] set_baseline failed: {e}")


def _record_event(cluster_id, kind, scope, diffs, severity, summary):
    try:
        c = get_db().conn.cursor()
        c.execute('''
            INSERT INTO drift_events (cluster_id, kind, scope, severity,
                                      summary, diff, detected_at, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'open')
        ''', (cluster_id, kind, scope, severity, summary,
              json.dumps(diffs), datetime.now().isoformat()))
        eid = c.lastrowid
        get_db().conn.commit()
        return eid
    except Exception as e:
        logging.warning(f"[drift] record_event failed: {e}")
        return None


def _current_user():
    try:
        u = request.session.get('user') if hasattr(request, 'session') else ''
        if isinstance(u, dict):
            return u.get('username', '') or ''
        return u or ''
    except Exception:
        return ''


# ──────────────────────────────────────────────────────────────────────────
# Scan
# ──────────────────────────────────────────────────────────────────────────

def _scan_cluster(cluster_id, autobaseline=False):
    """Snapshot + diff for one cluster. Returns dict with counts/events.
    If autobaseline=True and no baseline exists yet, set one without firing
    drift events (initial seeding behavior)."""
    if cluster_id not in cluster_managers:
        return {'error': 'cluster not found'}
    mgr = cluster_managers[cluster_id]
    if not getattr(mgr, 'is_connected', False):
        return {'error': 'cluster offline', 'status': 'skipped'}

    state = _fetch_state(mgr, cluster_id)
    baselines = _load_baselines(cluster_id)

    new_events = []
    seeded = 0
    seen_keys = set()
    for kind, scope, snap in state:
        seen_keys.add((kind, scope))
        bk = baselines.get((kind, scope))
        if not bk:
            if autobaseline:
                _set_baseline(cluster_id, kind, scope, snap, 'system')
                seeded += 1
            continue
        diffs = _flat_diff(bk['snapshot'], snap)
        if not diffs: continue
        sev = _severity_for(kind, diffs)
        summary = _short_summary(kind, scope, diffs)
        eid = _record_event(cluster_id, kind, scope, diffs, sev, summary)
        new_events.append({'id': eid, 'kind': kind, 'scope': scope,
                           'severity': sev, 'summary': summary})

    # detect deletions: baseline keys that are no longer in current state
    removed = []
    for (kind, scope), bk in baselines.items():
        if (kind, scope) in seen_keys:
            continue
        diffs = [{'path': '*', 'op': 'removed', 'before': bk['snapshot'], 'after': None}]
        summary = f"{kind} {scope}: object removed"
        sev = 'warning' if kind in ('vm_config', 'storage') else 'info'
        eid = _record_event(cluster_id, kind, scope, diffs, sev, summary)
        new_events.append({'id': eid, 'kind': kind, 'scope': scope,
                           'severity': sev, 'summary': summary})
        removed.append(scope)

    # fire alert handler so configured Slack/Discord/etc. + push pick it up
    if new_events:
        try:
            from pegaprox.background import alerts as alerts_mod
            count = len(new_events)
            top_sev = 'critical' if any(e['severity'] == 'critical' for e in new_events) \
                else 'warning' if any(e['severity'] == 'warning' for e in new_events) \
                else 'info'
            payload = {
                'alert_name': 'Config Drift',
                'severity': top_sev,
                'cluster_id': cluster_id,
                'message': f"{count} config drift event(s) detected",
                'metric': 'drift',
                'target_type': 'cluster',
                'target_name': cluster_id,
                'timestamp': datetime.now().isoformat(),
            }
            for h in alerts_mod._notification_handlers:
                try: h(payload)
                except Exception: pass
        except Exception:
            pass

    return {
        'ok': True,
        'cluster_id': cluster_id,
        'events_count': len(new_events),
        'seeded_baselines': seeded,
        'removed': removed,
        'events': new_events,
    }


# ──────────────────────────────────────────────────────────────────────────
# Background scanner — every 6h. Also runs on first call after import.
# ──────────────────────────────────────────────────────────────────────────

_scanner_running = False
_scanner_lock = threading.Lock()
SCAN_INTERVAL = 6 * 3600


def _scanner_loop():
    while _scanner_running:
        try:
            for cid in list(cluster_managers.keys()):
                try:
                    _scan_cluster(cid, autobaseline=True)
                except Exception as e:
                    logging.debug(f"[drift] scan {cid} failed: {e}")
        except Exception as e:
            logging.warning(f"[drift] scanner iteration failed: {e}")
        # break sleep into 1-sec chunks so shutdown is responsive
        for _ in range(SCAN_INTERVAL):
            if not _scanner_running:
                return
            time.sleep(1)


def start_scanner():
    global _scanner_running
    with _scanner_lock:
        if _scanner_running:
            return
        _scanner_running = True
    t = threading.Thread(target=_scanner_loop, daemon=True, name='drift-scanner')
    t.start()
    logging.info("[drift] scanner thread started (6h cadence)")


# ──────────────────────────────────────────────────────────────────────────
# Endpoints
# ──────────────────────────────────────────────────────────────────────────

@bp.route('/api/clusters/<cluster_id>/drift/status', methods=['GET'])
@require_auth(perms=['cluster.view'])
def drift_status(cluster_id):
    """Counts of open events grouped by kind + severity."""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    try:
        c = get_db().conn.cursor()
        c.execute('''
            SELECT kind, severity, COUNT(*) AS n
            FROM drift_events
            WHERE cluster_id = ? AND status = 'open'
            GROUP BY kind, severity
        ''', (cluster_id,))
        by_kind = {}
        total = 0
        sev_total = {'critical': 0, 'warning': 0, 'info': 0}
        for r in c.fetchall():
            d = by_kind.setdefault(r['kind'], {'critical': 0, 'warning': 0, 'info': 0})
            d[r['severity']] = r['n']
            sev_total[r['severity']] = sev_total.get(r['severity'], 0) + r['n']
            total += r['n']

        # baseline count
        c.execute("SELECT COUNT(*) AS n FROM drift_baselines WHERE cluster_id=?", (cluster_id,))
        baseline_count = c.fetchone()['n']

        # last scan: pick max(detected_at) from events, fallback to baseline created_at
        c.execute("SELECT MAX(detected_at) AS t FROM drift_events WHERE cluster_id=?", (cluster_id,))
        last_event_t = c.fetchone()['t']

        return jsonify({
            'cluster_id': cluster_id,
            'open_total': total,
            'by_kind': by_kind,
            'by_severity': sev_total,
            'baselines': baseline_count,
            'last_event_at': last_event_t,
        })
    except Exception as e:
        logging.exception('handler error in drift.py'); return jsonify({'error': 'internal error'}), 500


@bp.route('/api/clusters/<cluster_id>/drift/events', methods=['GET'])
@require_auth(perms=['cluster.view'])
def list_events(cluster_id):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    status = request.args.get('status', 'open')
    limit = max(1, min(int(request.args.get('limit', '100')), 500))
    try:
        c = get_db().conn.cursor()
        if status == 'all':
            c.execute('''SELECT * FROM drift_events WHERE cluster_id=?
                         ORDER BY detected_at DESC LIMIT ?''',
                      (cluster_id, limit))
        else:
            c.execute('''SELECT * FROM drift_events WHERE cluster_id=? AND status=?
                         ORDER BY detected_at DESC LIMIT ?''',
                      (cluster_id, status, limit))
        out = []
        for r in c.fetchall():
            d = dict(r)
            try:
                d['diff'] = json.loads(d['diff'])
            except Exception:
                pass
            out.append(d)
        return jsonify({'events': out})
    except Exception as e:
        logging.exception('handler error in drift.py'); return jsonify({'error': 'internal error'}), 500


@bp.route('/api/drift/events/<int:eid>/acknowledge', methods=['POST'])
@require_auth(perms=['admin.audit'])
def acknowledge_event(eid):
    """Mark event acknowledged. If body has promote=true, also rebase the
    baseline so the same change won't trigger again next scan."""
    body = request.get_json(silent=True) or {}
    promote = bool(body.get('promote', False))
    user = _current_user()
    try:
        c = get_db().conn.cursor()
        c.execute('SELECT * FROM drift_events WHERE id=?', (eid,))
        ev = c.fetchone()
        if not ev:
            return jsonify({'error': 'not found'}), 404
        c.execute('''UPDATE drift_events SET status='acknowledged',
                     acknowledged_at=?, acknowledged_by=? WHERE id=?''',
                  (datetime.now().isoformat(), user, eid))

        if promote:
            # re-fetch the live state for that scope and store as new baseline
            cid = ev['cluster_id']
            mgr = cluster_managers.get(cid)
            if mgr:
                state = _fetch_state(mgr, cid)
                for kind, scope, snap in state:
                    if kind == ev['kind'] and scope == ev['scope']:
                        _set_baseline(cid, kind, scope, snap, user)
                        break
        get_db().conn.commit()
        return jsonify({'ok': True})
    except Exception as e:
        logging.exception('handler error in drift.py'); return jsonify({'error': 'internal error'}), 500


@bp.route('/api/clusters/<cluster_id>/drift/scan', methods=['POST'])
@require_auth(perms=['admin.audit'])
def manual_scan(cluster_id):
    """Trigger immediate scan. Body: {seed: bool} — if true and no baseline
    exists, write current state as baseline silently (initial setup)."""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    body = request.get_json(silent=True) or {}
    seed = bool(body.get('seed', False))
    return jsonify(_scan_cluster(cluster_id, autobaseline=seed))


@bp.route('/api/clusters/<cluster_id>/drift/baseline', methods=['POST'])
@require_auth(perms=['admin.audit'])
def reset_baseline(cluster_id):
    """Reset all baselines for the cluster from current state. Drops outstanding
    open events implicitly (they reference old baselines)."""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'cluster not found'}), 404
    mgr = cluster_managers[cluster_id]
    user = _current_user()
    state = _fetch_state(mgr, cluster_id)
    try:
        c = get_db().conn.cursor()
        c.execute('DELETE FROM drift_baselines WHERE cluster_id=?', (cluster_id,))
        c.execute("UPDATE drift_events SET status='superseded' WHERE cluster_id=? AND status='open'",
                  (cluster_id,))
        for kind, scope, snap in state:
            c.execute('''
                INSERT INTO drift_baselines (id, cluster_id, kind, scope, snapshot, created_at, created_by)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (uuid.uuid4().hex[:12], cluster_id, kind, scope,
                  json.dumps(snap), datetime.now().isoformat(), user))
        get_db().conn.commit()
        return jsonify({'ok': True, 'baselines': len(state)})
    except Exception as e:
        logging.exception('handler error in drift.py'); return jsonify({'error': 'internal error'}), 500
