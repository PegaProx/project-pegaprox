# -*- coding: utf-8 -*-
"""
Cross-cluster EVPN SDN orchestration (#612, Phase 1) — MK Jul 2026.

PVE has no cross-cluster SDN primitive: each cluster's /etc/pve/sdn config is
entirely local (distributed only within that cluster's pmxcfs). To make one
logical EVPN vNet "span" several clusters that share a BGP ASN, PegaProx has to
create the *same* EVPN controller (asn/peers), the *same* EVPN zone (vrf-vxlan),
and the *same* vnet (tag/VNI/alias) on **every** member cluster and apply each.

This blueprint composes the existing per-cluster SDN passthrough (api/datacenter.py
→ PVE /cluster/sdn/*) into a multi-cluster create/read layer, and keeps the
authoritative record PDM lacks in the `multi_cluster_vnets` table.

Phase 1 = create + read across clusters, with collision pre-flight, bounded
concurrent fan-out, per-cluster status, and atomic rollback on partial failure.
Phase 2 (edit/alias fan-out + a background drift-detect/reconcile scanner) is
intentionally out of scope here.

Blast-radius note: `PUT /cluster/sdn` (apply) is a cluster-wide reload of ALL SDN
on every node of that cluster, not just our vnet. Doing it across N clusters is a
real blast radius, so the write routes are gated on sdn.manage + admin.settings.

We DO NOT build the physical underlay (BGP-EVPN peering / route reflectors between
clusters) — that is the operator's network. We orchestrate the SDN config objects
and assume the shared-ASN fabric already peers.
"""
import ipaddress
import json
import logging
import re
import threading
import time
import uuid
from datetime import datetime
from urllib.parse import quote

from flask import Blueprint, jsonify, request

from pegaprox.globals import cluster_managers
from pegaprox.core.db import get_db
from pegaprox.utils.auth import require_auth
from pegaprox.utils.audit import log_audit
from pegaprox.utils.concurrent import run_per_node
from pegaprox.api.helpers import require_unconfined, check_cluster_access, parse_pve_error, load_server_settings

bp = Blueprint('multi_sdn', __name__)

# PVE SDN id constraints. Zone + vnet ids are limited to 8 alphanumerics (PVE
# schema); controllers are looser. We validate strictly at the boundary — these
# ids are also interpolated into PVE API paths, so a strict allowlist doubles as
# an injection guard even though the bodies are form-encoded, not shelled.
_ID8_RE = re.compile(r'^[A-Za-z][A-Za-z0-9]{0,7}$')          # zone / vnet
_IDLONG_RE = re.compile(r'^[A-Za-z][A-Za-z0-9_-]{0,62}$')    # controller
_VNI_MAX = 16777215      # 24-bit VXLAN VNI
_ASN_MAX = 4294967295    # 32-bit BGP ASN


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------
def _sdn_base(mgr):
    return f"https://{mgr.host}:{mgr.api_port}/api2/json/cluster/sdn"


def _resolve_member(cid):
    """(mgr, reason). reason is None if usable, else 'not_found' / 'offline'."""
    mgr = cluster_managers.get(cid)
    if mgr is None:
        return None, 'not_found'
    if not getattr(mgr, 'is_connected', False):
        return None, 'offline'
    return mgr, None


def _require_members_access(cluster_ids, mutating=False):
    """Gate every member cluster the operation touches; return the first deny's
    Flask error response, or None if the caller may reach them all. Modeled on
    dr_drill._require_plan_access — a caller who can reach cluster A but not B
    must not be able to mutate/read B's SDN through the aggregate.

    MK Sep 2026 - `mutating` is the missing half. check_cluster_access answers
    REACHABILITY, and by design its #248/#555 fallbacks admit a caller whose only
    claim on the cluster is a VM-ACL row or a pool grant, deferring the real
    decision downstream. For SDN there is no downstream: a vnet, a zone or an EVPN
    controller is cluster-wide plumbing with no per-object notion, so creating,
    editing, applying or deleting one is a whole-cluster act. A portal user with one
    VM ACL was reaching every one of those routes. require_unconfined is the guard
    the rest of the codebase already uses for exactly this shape.
    """
    for cid in cluster_ids:
        if not cid:
            continue
        ok, err = check_cluster_access(cid)
        if not ok:
            return err
        if mutating:
            _uerr = require_unconfined(cid)
            if _uerr:
                return _uerr
    return None


def _sdn_list(mgr, suffix):
    """GET a /cluster/sdn/<suffix> collection → (list, err). 501 => SDN not
    installed on this cluster (err='sdn_not_installed')."""
    try:
        resp = mgr._api_get(f"{_sdn_base(mgr)}/{suffix}", timeout=10)
    except Exception as e:
        return None, f"request failed: {e}"
    if resp.status_code == 501:
        return None, 'sdn_not_installed'
    if resp.status_code != 200:
        return None, parse_pve_error(resp.text)
    try:
        return (resp.json().get('data') or []), None
    except Exception as e:
        return None, f"bad response: {e}"


def _sdn_post(mgr, suffix, body):
    """POST a create; (ok, err). 200/201 => ok."""
    try:
        resp = mgr._api_post(f"{_sdn_base(mgr)}/{suffix}", data=body, timeout=15)
    except Exception as e:
        return False, f"request failed: {e}"
    if resp.status_code == 501:
        return False, 'sdn_not_installed'
    if resp.status_code in (200, 201):
        return True, None
    return False, parse_pve_error(resp.text)


def _sdn_delete(mgr, suffix):
    try:
        resp = mgr._api_delete(f"{_sdn_base(mgr)}/{suffix}", timeout=15)
    except Exception as e:
        return False, f"request failed: {e}"
    if resp.status_code in (200, 201):
        return True, None
    return False, parse_pve_error(resp.text)


def _sdn_put(mgr, suffix, body):
    """PUT an update on a /cluster/sdn/<suffix> object; (ok, err). 200 => ok.
    PVE partial-updates: only the keys in `body` change. Last-write-wins (no digest,
    matching the existing single-cluster SDN routes)."""
    try:
        resp = mgr._api_put(f"{_sdn_base(mgr)}/{suffix}", data=body, timeout=15)
    except Exception as e:
        return False, f"request failed: {e}"
    if resp.status_code == 501:
        return False, 'sdn_not_installed'
    if resp.status_code in (200, 201):
        return True, None
    return False, parse_pve_error(resp.text)


def _sdn_apply(mgr):
    """PUT /cluster/sdn — cluster-wide SDN reload (slow, 30s). No body, no digest."""
    try:
        resp = mgr._api_put(_sdn_base(mgr), timeout=30)
    except Exception as e:
        return False, f"request failed: {e}"
    if resp.status_code == 200:
        return True, None
    return False, parse_pve_error(resp.text)


# ---------------------------------------------------------------------------
# validation + desired-state
# ---------------------------------------------------------------------------
def _validate_definition(body):
    """Return (defn, error_message). defn is the normalized cross-cluster vnet
    definition; error_message is a user-facing string on invalid input."""
    name = str(body.get('name', '')).strip()
    zone = str(body.get('zone', '')).strip()
    controller = str(body.get('controller', '')).strip()
    alias = str(body.get('alias', '')).strip()

    if not _ID8_RE.match(name):
        return None, "vnet name must start with a letter and be 1–8 alphanumeric chars"
    if not _ID8_RE.match(zone):
        return None, "zone id must start with a letter and be 1–8 alphanumeric chars"
    if not _IDLONG_RE.match(controller):
        return None, "controller id must start with a letter (letters, digits, - and _; max 63)"

    def _int(field, lo, hi, required=True, default=None):
        raw = body.get(field, None)
        if raw in (None, ''):
            if required:
                return None, f"{field} is required"
            return default, None
        try:
            v = int(raw)
        except (ValueError, TypeError):
            return None, f"{field} must be an integer"
        if not (lo <= v <= hi):
            return None, f"{field} must be between {lo} and {hi}"
        return v, None

    vni, err = _int('vni', 1, _VNI_MAX)
    if err:
        return None, err
    asn, err = _int('asn', 1, _ASN_MAX)
    if err:
        return None, err
    # vrf_vxlan (zone L3 VNI) defaults to the vnet VNI when unset.
    vrf_vxlan, err = _int('vrf_vxlan', 1, _VNI_MAX, required=False, default=vni)
    if err:
        return None, err

    # peers: optional comma/space-separated IPs (EVPN controller BGP peers).
    peers_raw = str(body.get('peers', '') or '').strip()
    peers = []
    for tok in re.split(r'[\s,]+', peers_raw):
        if not tok:
            continue
        try:
            ipaddress.ip_address(tok)
        except ValueError:
            return None, f"invalid peer IP: {tok}"
        peers.append(tok)

    # subnets: optional list of CIDRs (with optional per-subnet gateway/snat).
    subnets = []
    for s in (body.get('subnets') or []):
        if isinstance(s, str):
            s = {'cidr': s}
        if not isinstance(s, dict):
            return None, "each subnet must be a CIDR string or an object with a 'cidr' field"
        cidr = str(s.get('cidr', '')).strip()
        try:
            ipaddress.ip_network(cidr, strict=False)
        except (ValueError, TypeError):
            return None, f"invalid subnet CIDR: {cidr!r}"
        entry = {'cidr': cidr}
        gw = str(s.get('gateway', '') or '').strip()
        if gw:
            try:
                ipaddress.ip_address(gw)
            except ValueError:
                return None, f"invalid subnet gateway: {gw}"
            entry['gateway'] = gw
        if s.get('snat'):
            entry['snat'] = True
        subnets.append(entry)

    members = [str(c).strip() for c in (body.get('cluster_ids') or []) if str(c).strip()]
    # de-dupe, preserve order
    members = list(dict.fromkeys(members))
    if len(members) < 1:
        return None, "at least one member cluster is required"

    defn = {
        'name': name, 'zone': zone, 'controller': controller, 'alias': alias,
        'vni': vni, 'asn': asn, 'vrf_vxlan': vrf_vxlan, 'peers': peers,
        'subnets': subnets, 'member_clusters': members,
    }
    return defn, None


def _controller_body(defn):
    b = {'controller': defn['controller'], 'type': 'evpn', 'asn': defn['asn']}
    if defn['peers']:
        b['peers'] = ','.join(defn['peers'])
    return b


def _zone_body(defn):
    return {'zone': defn['zone'], 'type': 'evpn',
            'controller': defn['controller'], 'vrf-vxlan': defn['vrf_vxlan']}


def _vnet_body(defn):
    b = {'vnet': defn['name'], 'zone': defn['zone'], 'tag': defn['vni']}
    if defn['alias']:
        b['alias'] = defn['alias']
    return b


# ---------------------------------------------------------------------------
# per-cluster: collision pre-flight, apply (idempotent), rollback, live read
# ---------------------------------------------------------------------------
def _collisions_on_cluster(mgr, defn):
    """Return (conflicts, err). conflicts is a list of human strings for objects
    that already exist with a DIFFERENT definition (or a VNI/ASN clash). An object
    that already exists with the SAME definition is fine (idempotent create)."""
    conflicts = []
    controllers, err = _sdn_list(mgr, 'controllers')
    if err:
        return None, err
    zones, err = _sdn_list(mgr, 'zones')
    if err:
        return None, err
    vnets, err = _sdn_list(mgr, 'vnets')
    if err:
        return None, err

    # controller id already used?
    for c in controllers:
        if c.get('controller') == defn['controller']:
            if str(c.get('type')) != 'evpn' or str(c.get('asn')) != str(defn['asn']):
                conflicts.append(
                    f"controller '{defn['controller']}' exists with a different type/ASN "
                    f"(type={c.get('type')}, asn={c.get('asn')})")
    # an EVPN controller on a DIFFERENT id but same-ASN is fine (shared ASN is the point);
    # but a different controller carrying our ASN is not a conflict per se — skip.

    # zone id already used with different controller/vrf-vxlan?
    for z in zones:
        if z.get('zone') == defn['zone']:
            zc = str(z.get('controller') or '')
            zv = str(z.get('vrf-vxlan') or z.get('vrfvxlan') or '')
            if str(z.get('type')) != 'evpn' or (zc and zc != defn['controller']) or (zv and zv != str(defn['vrf_vxlan'])):
                conflicts.append(
                    f"zone '{defn['zone']}' exists with a different definition "
                    f"(type={z.get('type')}, controller={zc}, vrf-vxlan={zv})")

    # vnet id used with different zone/tag, OR our VNI(tag) used by a DIFFERENT vnet?
    for v in vnets:
        same_name = v.get('vnet') == defn['name']
        vtag = str(v.get('tag') or '')
        if same_name:
            if (str(v.get('zone') or '') not in ('', defn['zone'])) or (vtag and vtag != str(defn['vni'])):
                conflicts.append(
                    f"vnet '{defn['name']}' exists with a different zone/tag "
                    f"(zone={v.get('zone')}, tag={vtag})")
        elif vtag and vtag == str(defn['vni']):
            conflicts.append(
                f"VNI {defn['vni']} is already used by a different vnet '{v.get('vnet')}'")

    return conflicts, None


def _apply_on_cluster(cid, defn):
    """Idempotently build the EVPN controller → zone → vnet → subnet(s) on ONE
    cluster, then apply. Returns a per-cluster status dict. Runs inside a greenlet
    (run_per_node) — no Flask context, PVE calls only."""
    result = {'cluster_id': cid, 'status': 'failed', 'steps': [], 'error': None, 'created': []}
    mgr, reason = _resolve_member(cid)
    if reason:
        result['status'] = 'offline' if reason == 'offline' else 'not_found'
        result['error'] = reason
        return result

    # snapshot existing objects once so we skip re-creating what's already there
    controllers, err = _sdn_list(mgr, 'controllers')
    if err:
        result['error'] = f"read controllers: {err}"
        return result
    zones, err = _sdn_list(mgr, 'zones')
    if err:
        result['error'] = f"read zones: {err}"
        return result
    vnets, err = _sdn_list(mgr, 'vnets')
    if err:
        result['error'] = f"read vnets: {err}"
        return result
    have_ctrl = any(c.get('controller') == defn['controller'] for c in controllers)
    have_zone = any(z.get('zone') == defn['zone'] for z in zones)
    have_vnet = any(v.get('vnet') == defn['name'] for v in vnets)

    # track whether we ACTUALLY created anything this pass — only then do we run the
    # (disruptive, cluster-wide) apply. A pure re-assert where everything already exists
    # must NOT trigger a needless SDN reload — that's the over-broad-blast-radius fix.
    changed = False

    def _step(label, ok, e=None):
        result['steps'].append({'step': label, 'ok': ok, 'error': e})
        return ok

    # 1) controller
    if have_ctrl:
        _step('controller (exists)', True)
    else:
        ok, e = _sdn_post(mgr, 'controllers', _controller_body(defn))
        if not _step('controller', ok, e):
            result['error'] = f"controller: {e}"
            return result
        changed = True
        result['created'].append('controller')
    # 2) zone (depends on controller)
    if have_zone:
        _step('zone (exists)', True)
    else:
        ok, e = _sdn_post(mgr, 'zones', _zone_body(defn))
        if not _step('zone', ok, e):
            result['error'] = f"zone: {e}"
            return result
        changed = True
        result['created'].append('zone')
    # 3) vnet (depends on zone)
    if have_vnet:
        _step('vnet (exists)', True)
    else:
        ok, e = _sdn_post(mgr, 'vnets', _vnet_body(defn))
        if not _step('vnet', ok, e):
            result['error'] = f"vnet: {e}"
            return result
        changed = True
        result['created'].append('vnet')
    # 4) subnets (nested under vnet) — best-effort idempotent
    if defn['subnets']:
        existing_subs, _serr = _sdn_list(mgr, f"vnets/{defn['name']}/subnets")
        # Compare by CANONICAL network equality, not substring — a bare string test
        # false-positives (e.g. desired '10.0.0.0/2' is a substring of existing
        # '10.0.0.0/24') and would silently skip creating a subnet that isn't there.
        existing_networks = set()
        for es in (existing_subs or []):
            raw = str(es.get('cidr') or es.get('subnet') or '')
            try:
                existing_networks.add(str(ipaddress.ip_network(raw, strict=False)))
            except (ValueError, TypeError):
                # PVE subnet ids can be "<zone>-<cidr>" (slash→dash), not a bare CIDR — skip
                pass
        for sub in defn['subnets']:
            if str(ipaddress.ip_network(sub['cidr'], strict=False)) in existing_networks:
                _step(f"subnet {sub['cidr']} (exists)", True)
                continue
            body = {'subnet': sub['cidr'], 'type': 'subnet'}
            if sub.get('gateway'):
                body['gateway'] = sub['gateway']
            if sub.get('snat'):
                body['snat'] = 1
            ok, e = _sdn_post(mgr, f"vnets/{defn['name']}/subnets", body)
            if not _step(f"subnet {sub['cidr']}", ok, e):
                result['error'] = f"subnet {sub['cidr']}: {e}"
                return result
            changed = True
    # 5) apply (cluster-wide reload) — ONLY if we actually created something this pass
    if changed:
        ok, e = _sdn_apply(mgr)
        if not _step('apply', ok, e):
            result['error'] = f"apply: {e}"
            return result
    else:
        _step('apply (skipped — nothing to change)', True)

    result['status'] = 'applied'
    return result


# NS Aug 2026 (Aikido pentest, TOCTOU) — create builds the physical zone/controller/vnet on
# every member BEFORE its aggregate DB row exists, so a concurrent purge-delete's
# _shared_infra_on_cluster (which only reads the DB) can miss the in-flight span and rip out a
# zone/controller the create is actively building on. Creates advertise their (zone, controller,
# clusters) here for the duration of the fan-out; the shared-infra check folds these in so it
# treats in-flight infra as shared. Entries carry a TTL so a create that dies mid-flight (skipping
# its explicit unregister) self-heals, and the fail direction is SAFE (over-keep, never over-tear).
_provisioning_lock = threading.Lock()
_provisioning_spans = {}          # token -> {'clusters': set, 'zone': str, 'controller': str, 'expires': float}
_PROVISIONING_TTL = 240           # seconds; the create fan-out itself times out at 180s


def _register_provisioning(members, defn):
    tok = uuid.uuid4().hex
    with _provisioning_lock:
        _provisioning_spans[tok] = {
            'clusters': set(members), 'zone': defn.get('zone'),
            'controller': defn.get('controller'), 'expires': time.time() + _PROVISIONING_TTL,
        }
    return tok


def _unregister_provisioning(tok):
    if not tok:
        return
    with _provisioning_lock:
        _provisioning_spans.pop(tok, None)


def _provisioning_shares(cid, zone, ctrl):
    """(zone_shared, ctrl_shared) contributed by not-yet-persisted in-flight creates on `cid`."""
    zs = cs = False
    now = time.time()
    with _provisioning_lock:
        for rec in list(_provisioning_spans.values()):
            if rec['expires'] < now or cid not in rec['clusters']:
                continue
            if zone and rec.get('zone') == zone:
                zs = True
            if ctrl and rec.get('controller') == ctrl:
                cs = True
    return zs, cs


def _shared_infra_on_cluster(vid, cid, defn):
    """(zone_shared, controller_shared) — does ANY OTHER aggregate span that also spans
    cluster `cid` reuse this span's zone / controller name? EVPN zones (and their
    controllers) routinely host many vnets, so a purge-delete must NOT blindly tear the
    zone/controller down on a cluster where a co-tenant span still depends on it. Fails
    SAFE: on any DB/parse error it reports both as shared so we only remove the vnet."""
    zone, ctrl = defn.get('zone'), defn.get('controller')
    if not zone and not ctrl:
        return (False, False)
    try:
        rows = get_db().query('SELECT * FROM multi_cluster_vnets WHERE id != ?', (vid,)) or []
    except Exception:
        return (True, True)   # can't tell → keep the shared infra
    zone_shared = ctrl_shared = False
    for row in rows:
        try:
            other = _row_to_dict(row)
        except Exception:
            return (True, True)
        if cid not in (other.get('member_clusters') or []):
            continue
        od = other.get('desired_state') or {}
        if zone and od.get('zone') == zone:
            zone_shared = True
        if ctrl and od.get('controller') == ctrl:
            ctrl_shared = True
        if zone_shared and ctrl_shared:
            break
    # fold in any in-flight create advertising the same zone/controller on this cluster
    pzs, pcs = _provisioning_shares(cid, zone, ctrl)
    return (zone_shared or pzs, ctrl_shared or pcs)


def _purge_span_on_cluster(vid, cid, defn):
    """Purge a WHOLE span from ONE cluster on a full delete: always remove the vnet, and
    remove the zone/controller ONLY when no other span on that cluster still uses them
    (see _shared_infra_on_cluster). Reverse dependency order, single apply. Never raises."""
    zone_shared, ctrl_shared = _shared_infra_on_cluster(vid, cid, defn)
    created = ['vnet']
    if not zone_shared:
        created.append('zone')
    if not ctrl_shared:
        created.append('controller')
    out = _teardown_created_on_cluster(cid, defn, created)
    if zone_shared:
        out.setdefault('kept', []).append('zone (shared)')
    if ctrl_shared:
        out.setdefault('kept', []).append('controller (shared)')
    return out


def _teardown_created_on_cluster(cid, defn, created):
    """Delete EXACTLY the objects a just-failed _apply_on_cluster reported it freshly
    created (`created` list of 'controller'/'zone'/'vnet'), in reverse dependency order,
    then apply. Used to unwind a mid-build add failure WITHOUT touching a pre-existing
    zone/controller a co-tenant span on that cluster may share. Never raises."""
    out = {'cluster_id': cid, 'deleted': [], 'errors': []}
    mgr, reason = _resolve_member(cid)
    if reason:
        out['errors'].append(reason)
        return out
    suffix_by = {'vnet': f"vnets/{defn['name']}", 'zone': f"zones/{defn['zone']}",
                 'controller': f"controllers/{defn['controller']}"}
    for label in ('vnet', 'zone', 'controller'):   # reverse dependency order
        if label not in (created or []):
            continue
        ok, e = _sdn_delete(mgr, suffix_by[label])
        if ok:
            out['deleted'].append(label)
        elif e and 'does not exist' not in str(e).lower():
            out['errors'].append(f"{label}: {e}")
    _sdn_apply(mgr)
    return out


# Per-record mutation lock — serialize the read-modify-write of one aggregate vnet's
# authoritative fields (member_clusters / desired_state / subnets) so two concurrent
# admins (gevent greenlets) can't lose an update. Different vids run in parallel.
_vnet_locks = {}
_vnet_locks_guard = threading.Lock()


def _get_vnet_lock(vid):
    with _vnet_locks_guard:
        lk = _vnet_locks.get(vid)
        if lk is None:
            lk = threading.Lock()
            _vnet_locks[vid] = lk
        return lk


def _purge_vnet_only_on_cluster(cid, defn):
    """Remove ONLY this vnet (and its subnets, which cascade) from ONE cluster, then
    apply — deliberately NOT the zone/controller, which another cross-cluster span on
    the same cluster may share. Used when a cluster is dropped from a span (#612 P3).
    Never raises."""
    out = {'cluster_id': cid, 'deleted': [], 'errors': []}
    mgr, reason = _resolve_member(cid)
    if reason:
        out['errors'].append(reason)
        return out
    ok, e = _sdn_delete(mgr, f"vnets/{defn['name']}")
    if ok:
        out['deleted'].append('vnet')
    elif e and 'does not exist' not in str(e).lower():
        out['errors'].append(f"vnet: {e}")
    _sdn_apply(mgr)
    return out


def _canon_net(cidr):
    """Canonical network string for equality compares; passthrough on unparseable."""
    try:
        return str(ipaddress.ip_network(str(cidr), strict=False))
    except (ValueError, TypeError):
        return str(cidr)


def _live_status_on_cluster(cid, defn):
    """Read live SDN state on ONE cluster and classify vs the desired definition. The
    result uses the same 'status' key as _apply_on_cluster so both feed per_cluster_status
    and the same UI badge: in_sync / drift / missing / offline / not_found /
    sdn_not_installed / error. 'detail' explains a drift."""
    st = {'cluster_id': cid, 'status': 'error', 'detail': '', 'error': None}
    mgr, reason = _resolve_member(cid)
    if reason:
        st['status'] = 'offline' if reason == 'offline' else 'not_found'
        return st
    vnets, err = _sdn_list(mgr, 'vnets')
    if err == 'sdn_not_installed':
        st['status'] = 'sdn_not_installed'
        return st
    if err:
        st['error'] = err
        return st
    v = next((x for x in vnets if x.get('vnet') == defn['name']), None)
    if not v:
        st['status'] = 'missing'
        return st
    diffs = []
    if str(v.get('zone') or '') not in ('', defn['zone']):
        diffs.append(f"zone={v.get('zone')}≠{defn['zone']}")
    if str(v.get('tag') or '') not in ('', str(defn.get('vni'))):
        diffs.append(f"tag={v.get('tag')}≠{defn.get('vni')}")
    if str(v.get('alias') or '') != str(defn.get('alias') or ''):
        diffs.append(f"alias='{v.get('alias')}'≠'{defn.get('alias')}'")
    st['status'] = 'drift' if diffs else 'in_sync'
    st['detail'] = '; '.join(diffs)
    return st


def _edit_on_cluster(cid, defn, changes):
    """Apply an EDIT (alias change + subnet add/remove) to ONE member's EVPN vnet, then
    apply. `changes` = {'alias': <str|None=unchanged>, 'add_subnets': [{cidr,gateway,snat}],
    'del_cidrs': [cidr,...]}. Best-effort per step; one apply at the end if anything changed."""
    result = {'cluster_id': cid, 'status': 'failed', 'steps': [], 'error': None}
    mgr, reason = _resolve_member(cid)
    if reason:
        result['status'] = 'offline' if reason == 'offline' else 'not_found'
        result['error'] = reason
        return result

    def _step(label, ok, e=None):
        result['steps'].append({'step': label, 'ok': ok, 'error': e})
        return ok

    changed = False
    if changes.get('alias') is not None:
        body = {'alias': changes['alias']} if changes['alias'] else {'delete': 'alias'}
        ok, e = _sdn_put(mgr, f"vnets/{defn['name']}", body)
        if not _step('alias', ok, e):
            result['error'] = f"alias: {e}"
            return result
        changed = True
    for sub in changes.get('add_subnets', []):
        body = {'subnet': sub['cidr'], 'type': 'subnet'}
        if sub.get('gateway'):
            body['gateway'] = sub['gateway']
        if sub.get('snat'):
            body['snat'] = 1
        ok, e = _sdn_post(mgr, f"vnets/{defn['name']}/subnets", body)
        if not ok and e and 'already exist' in str(e).lower():
            ok = True   # idempotent add
        if not _step(f"add subnet {sub['cidr']}", ok, e):
            result['error'] = f"add subnet {sub['cidr']}: {e}"
            return result
        changed = True
    if changes.get('del_cidrs'):
        existing, _e = _sdn_list(mgr, f"vnets/{defn['name']}/subnets")
        want = {_canon_net(c) for c in changes['del_cidrs']}
        for es in (existing or []):
            sid = str(es.get('subnet') or '')
            if _canon_net(es.get('cidr') or '') in want and sid:
                # subnet id is "<zone>-<cidr>" and carries a '/', so URL-encode it fully
                ok, e = _sdn_delete(mgr, f"vnets/{defn['name']}/subnets/{quote(sid, safe='')}")
                _step(f"del subnet {es.get('cidr')}", ok, e)
                changed = True
    if changed:
        ok, e = _sdn_apply(mgr)
        if not _step('apply', ok, e):
            result['error'] = f"apply: {e}"
            return result
    result['status'] = 'applied'
    return result


def _reconcile_on_cluster(cid, defn):
    """Re-assert the desired definition on ONE member: create anything missing (idempotent,
    via _apply_on_cluster) and fix a drifted alias with a PUT. Structural drift (tag/zone
    mismatch) is reported by the scanner but NOT auto-changed here — that would be a
    disruptive rebuild, out of Phase-2 scope."""
    base = _apply_on_cluster(cid, defn)
    if base['status'] != 'applied':
        return base
    mgr, reason = _resolve_member(cid)
    if reason:
        return base
    vnets, err = _sdn_list(mgr, 'vnets')
    if err:
        return base
    v = next((x for x in vnets if x.get('vnet') == defn['name']), None)
    if v is not None and str(v.get('alias') or '') != str(defn.get('alias') or ''):
        body = {'alias': defn['alias']} if defn.get('alias') else {'delete': 'alias'}
        ok, e = _sdn_put(mgr, f"vnets/{defn['name']}", body)
        base['steps'].append({'step': 'reassert-alias', 'ok': ok, 'error': e})
        if ok:
            _sdn_apply(mgr)
    return base


# ---------------------------------------------------------------------------
# record helpers
# ---------------------------------------------------------------------------
def _row_to_dict(row):
    d = dict(row)
    for k, default in (('member_clusters', '[]'), ('subnets', '[]'),
                       ('desired_state', '{}'), ('per_cluster_status', '{}')):
        try:
            d[k] = json.loads(d.get(k) or default)
        except (json.JSONDecodeError, TypeError):
            d[k] = json.loads(default)
    d['enabled'] = bool(d.get('enabled', 1))
    return d


def _caller_can_access_all(member_ids):
    for cid in member_ids:
        ok, _err = check_cluster_access(cid)
        if not ok:
            return False
    return True


def _rollup_status(per_cluster):
    """Roll up per-cluster status. Accepts both apply-results ('applied') and drift-scan
    results ('in_sync'), which both count as good; any 'drift' → partial (amber)."""
    states = [v.get('status') for v in per_cluster.values()]
    if not states:
        return 'pending'
    good = [s for s in states if s in ('applied', 'in_sync')]
    if len(good) == len(states):
        return 'applied'
    if any(s == 'drift' for s in states):
        return 'partial'
    if not good:
        return 'failed'
    return 'partial'


# ---------------------------------------------------------------------------
# routes
# ---------------------------------------------------------------------------
@bp.route('/api/multi-sdn/vnets', methods=['GET'])
@require_auth(perms=['node.view'])
def list_multi_vnets():
    """List cross-cluster EVPN vnets the caller can reach (must be able to access
    ALL member clusters — it's a cross-cluster object)."""
    db = get_db()
    rows = db.query('SELECT * FROM multi_cluster_vnets ORDER BY created_at DESC')
    out = []
    for row in rows:
        rec = _row_to_dict(row)
        if _caller_can_access_all(rec.get('member_clusters', [])):
            out.append(rec)
    return jsonify(out)


@bp.route('/api/multi-sdn/vnets/<vid>', methods=['GET'])
@require_auth(perms=['node.view'])
def get_multi_vnet(vid):
    """Detail for one aggregate vnet. ?refresh=1 re-reads live per-cluster state."""
    db = get_db()
    row = db.query_one('SELECT * FROM multi_cluster_vnets WHERE id = ?', (vid,))
    if not row:
        return jsonify({'error': 'not found'}), 404
    rec = _row_to_dict(row)
    members = rec.get('member_clusters', [])
    # deny → 404 (don't confirm existence of a record on clusters you can't see)
    if not _caller_can_access_all(members):
        return jsonify({'error': 'not found'}), 404

    if request.args.get('refresh') in ('1', 'true', 'yes'):
        defn = rec.get('desired_state') or {}
        if defn:
            # a handful of quick GETs per member — read them sequentially
            rec['live_status'] = {cid: _live_status_on_cluster(cid, defn) for cid in members}
    return jsonify(rec)


@bp.route('/api/multi-sdn/vnets/validate', methods=['POST'])
@require_auth(perms=['sdn.manage'])
def validate_multi_vnet():
    """Dry pre-flight: validate the definition + check every member for
    reachability and collisions. No writes. Feeds the wizard's preview step."""
    body = request.get_json(force=True, silent=True) or {}
    defn, err = _validate_definition(body)
    if err:
        return jsonify({'ok': False, 'error': err}), 400
    denied = _require_members_access(defn['member_clusters'])
    if denied:
        return denied

    plan = {}
    reachable = True
    for cid in defn['member_clusters']:
        mgr, reason = _resolve_member(cid)
        if reason:
            plan[cid] = {'reachable': False, 'reason': reason, 'conflicts': []}
            reachable = False
            continue
        conflicts, cerr = _collisions_on_cluster(mgr, defn)
        if cerr == 'sdn_not_installed':
            plan[cid] = {'reachable': True, 'sdn_installed': False, 'conflicts': []}
            reachable = False
        elif cerr:
            plan[cid] = {'reachable': True, 'error': cerr, 'conflicts': []}
            reachable = False
        else:
            plan[cid] = {'reachable': True, 'sdn_installed': True, 'conflicts': conflicts}
    has_conflicts = any(p.get('conflicts') for p in plan.values())
    return jsonify({'ok': reachable and not has_conflicts, 'defn': defn, 'plan': plan})


@bp.route('/api/multi-sdn/vnets', methods=['POST'])
@require_auth(perms=['sdn.manage', 'admin.settings'])
def create_multi_vnet():
    """Create a cross-cluster EVPN vnet: validate → per-member collision + reach
    pre-flight → concurrent fan-out (controller→zone→vnet→subnets→apply) → record.

    Body: name, zone, controller, vni, asn[, vrf_vxlan, alias, peers, subnets],
          cluster_ids[]; optional atomic (default true) = roll back all members on
          any failure so you never get a half-built L2 span.
    """
    body = request.get_json(force=True, silent=True) or {}
    defn, err = _validate_definition(body)
    if err:
        return jsonify({'error': err}), 400
    members = defn['member_clusters']
    denied = _require_members_access(members, mutating=True)
    if denied:
        return denied
    atomic = body.get('atomic', True) is not False

    # --- pre-flight: every member must be reachable, SDN-installed, conflict-free.
    # A create must not build a partial/inconsistent span, so bail before writing.
    preflight = {}
    for cid in members:
        mgr, reason = _resolve_member(cid)
        if reason:
            return jsonify({'error': f"member cluster '{cid}' is {reason}; "
                            f"cannot build a consistent span", 'cluster_id': cid}), 409
        conflicts, cerr = _collisions_on_cluster(mgr, defn)
        if cerr == 'sdn_not_installed':
            return jsonify({'error': f"SDN is not installed on member cluster '{cid}'",
                            'cluster_id': cid}), 409
        if cerr:
            return jsonify({'error': f"pre-flight read failed on '{cid}': {cerr}",
                            'cluster_id': cid}), 502
        if conflicts:
            return jsonify({'error': f"conflicting SDN objects on '{cid}'",
                            'cluster_id': cid, 'conflicts': conflicts}), 409
        preflight[cid] = 'ok'

    # NS Aug 2026 (Aikido pentest) — advertise this span's zone/controller as in-flight so a
    # concurrent purge-delete's shared-infra check keeps them up while we build (TOCTOU). The
    # matching _unregister runs after the DB row lands; failure paths rely on the entry's TTL.
    _prov_tok = _register_provisioning(members, defn)
    # --- fan out (bounded concurrency); each member builds sequentially internally
    results = run_per_node(
        {cid: (lambda c=cid: _apply_on_cluster(c, defn)) for cid in members},
        max_concurrent=8, timeout=180) or {}
    per_cluster = {}
    for cid in members:
        r = results.get(cid)
        per_cluster[cid] = r if isinstance(r, dict) else {
            'cluster_id': cid, 'status': 'failed', 'error': 'no result (timeout?)', 'steps': []}
    rollup = _rollup_status(per_cluster)

    user = getattr(request, 'session', {}).get('user', 'system')

    # --- atomic: on any non-'applied' member, tear the successful ones back down
    #     and do NOT persist a record (no half-built span left behind).
    if atomic and rollup != 'applied':
        # Roll back what THIS create freshly built on each member — including a member that
        # failed mid-build (e.g. controller + zone created, then the vnet POST failed), which
        # is the one most likely to hold orphans. Use `_apply_on_cluster`'s reported `created`
        # set so we tear down ONLY objects this call made and never a pre-existing controller/
        # zone that a co-tenant span on that cluster reused idempotently. Best-effort, ignores
        # "does not exist" — a member that created nothing is a harmless no-op.
        rollbacks = {c: _teardown_created_on_cluster(c, defn, (per_cluster.get(c) or {}).get('created', []))
                     for c in members}
        log_audit(user, 'multi_sdn.vnet_create_failed',
                  f"Cross-cluster EVPN vnet '{defn['name']}' failed ({rollup}); "
                  f"rolled back all {len(members)} member(s)")
        return jsonify({'error': 'fan-out failed; rolled back (atomic)',
                        'status': rollup, 'per_cluster': per_cluster,
                        'rolled_back': rollbacks}), 502

    # --- persist the authoritative record. Take a name-scoped lock + re-check for an
    # existing record with the same name so two admins racing the same name don't end up
    # with two aggregate records pointing at one EVPN span (#612 review). The vnet name IS
    # the SDN vnet id, so it's meant to be unique here; the fan-out above is idempotent.
    vid = str(uuid.uuid4())[:8]
    now = datetime.now().isoformat()
    db = get_db()
    with _get_vnet_lock('name:' + defn['name']):
        dup = db.query_one('SELECT id FROM multi_cluster_vnets WHERE name = ?', (defn['name'],))
        if dup:
            return jsonify({'error': f"a cross-cluster vnet named '{defn['name']}' already exists",
                            'existing_id': dict(dup).get('id')}), 409
        db.execute('''
            INSERT INTO multi_cluster_vnets
            (id, name, alias, zone, vni, asn, vrf_vxlan, controller, peers,
             member_clusters, subnets, desired_state, per_cluster_status, status,
             enabled, created_by, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
        ''', (
            vid, defn['name'], defn['alias'], defn['zone'], defn['vni'], defn['asn'],
            defn['vrf_vxlan'], defn['controller'], ','.join(defn['peers']),
            json.dumps(members), json.dumps(defn['subnets']), json.dumps(defn),
            json.dumps(per_cluster), rollup, user, now, now,
        ))
    _unregister_provisioning(_prov_tok)   # DB row now authoritative; drop the in-flight advert
    log_audit(user, 'multi_sdn.vnet_created',
              f"Cross-cluster EVPN vnet '{defn['name']}' (VNI {defn['vni']}, ASN "
              f"{defn['asn']}) across {len(members)} clusters → {rollup}")
    row = db.query_one('SELECT * FROM multi_cluster_vnets WHERE id = ?', (vid,))
    return jsonify(_row_to_dict(row)), 201


@bp.route('/api/multi-sdn/vnets/<vid>/apply', methods=['POST'])
@require_auth(perms=['sdn.manage', 'admin.settings'])
def reapply_multi_vnet(vid):
    """Re-apply (retry) the vnet on members that aren't yet 'applied' — idempotent,
    so it's safe to re-run after fixing an offline member. Refreshes the record's
    per-cluster status + rollup."""
    db = get_db()
    row = db.query_one('SELECT * FROM multi_cluster_vnets WHERE id = ?', (vid,))
    if not row:
        return jsonify({'error': 'not found'}), 404
    rec = _row_to_dict(row)
    members = rec.get('member_clusters', [])
    denied = _require_members_access(members, mutating=True)
    if denied:
        return denied
    defn = rec.get('desired_state') or {}
    if not defn:
        return jsonify({'error': 'record has no stored definition'}), 500

    prev = rec.get('per_cluster_status', {})
    # 'in_sync' (from a drift scan) is as healthy as 'applied' — don't re-apply it and
    # trigger a needless cluster-wide reload. Only members that are actually off get redone.
    todo = [c for c in members if (prev.get(c) or {}).get('status') not in ('applied', 'in_sync')]
    if not todo:
        todo = members  # allow a full re-apply if everything already applied
    results = run_per_node(
        {cid: (lambda c=cid: _apply_on_cluster(c, defn)) for cid in todo},
        max_concurrent=8, timeout=180) or {}
    merged = dict(prev)
    for cid in todo:
        r = results.get(cid)
        merged[cid] = r if isinstance(r, dict) else {
            'cluster_id': cid, 'status': 'failed', 'error': 'no result', 'steps': []}
    rollup = _rollup_status({c: merged.get(c, {}) for c in members})
    now = datetime.now().isoformat()
    db.execute('UPDATE multi_cluster_vnets SET per_cluster_status = ?, status = ?, updated_at = ? WHERE id = ?',
               (json.dumps(merged), rollup, now, vid))
    log_audit(getattr(request, 'session', {}).get('user', 'system'),
              'multi_sdn.vnet_reapplied', f"Re-applied cross-cluster vnet '{rec.get('name')}' → {rollup}")
    row = db.query_one('SELECT * FROM multi_cluster_vnets WHERE id = ?', (vid,))
    return jsonify(_row_to_dict(row))


@bp.route('/api/multi-sdn/vnets/<vid>', methods=['DELETE'])
@require_auth(perms=['sdn.manage', 'admin.settings'])
def delete_multi_vnet(vid):
    """Remove the aggregate record. Default only forgets our bookkeeping and leaves
    the SDN objects on the clusters intact; ?purge=1 ALSO tears the vnet/zone/
    controller down on every member (delete fan-out + apply)."""
    db = get_db()
    row = db.query_one('SELECT * FROM multi_cluster_vnets WHERE id = ?', (vid,))
    if not row:
        return jsonify({'error': 'not found'}), 404
    rec = _row_to_dict(row)
    members = rec.get('member_clusters', [])
    denied = _require_members_access(members, mutating=True)
    if denied:
        return denied
    purge = request.args.get('purge') in ('1', 'true', 'yes')
    purged = {}
    if purge:
        defn = rec.get('desired_state') or {}
        if defn:
            # SECURITY (pentest 2026-07-25): purge the vnet on every member, but only
            # tear down that member's zone/controller when no OTHER span on the same
            # cluster still shares them — otherwise a full-delete purge would collapse
            # a co-tenant cross-cluster span that reuses the EVPN zone/controller.
            purged = {c: _purge_span_on_cluster(vid, c, defn) for c in members}
    db.execute('DELETE FROM multi_cluster_vnets WHERE id = ?', (vid,))
    log_audit(getattr(request, 'session', {}).get('user', 'system'),
              'multi_sdn.vnet_deleted',
              f"Deleted cross-cluster vnet record '{rec.get('name')}'"
              + (f" + purged from {len(members)} clusters" if purge else " (record only)"))
    return jsonify({'ok': True, 'purged': purged})


# ---------------------------------------------------------------------------
# Phase 2 — edit (alias/subnets), reconcile, drift scan
# ---------------------------------------------------------------------------
def _merge_status_write(vid, fresh_per_cluster, defn_updates=None):
    """Persist per-cluster results under the per-vid lock (#612 review): re-read the
    CURRENT row, MERGE the fresh results into the stored per_cluster_status instead of
    replacing it from a pre-fan-out snapshot, drop statuses for members no longer in
    the span, recompute the rollup, and write. defn_updates (edit only) folds alias/
    subnets into the stored desired_state while PRESERVING its current member_clusters,
    so a concurrent add/remove-member can't be clobbered. Returns the fresh row dict,
    or None if the record was deleted meanwhile."""
    db = get_db()
    with _get_vnet_lock(vid):
        cur = db.query_one('SELECT * FROM multi_cluster_vnets WHERE id = ?', (vid,))
        if not cur:
            return None
        rec = _row_to_dict(cur)
        cur_members = rec.get('member_clusters', []) or []
        merged = dict(rec.get('per_cluster_status') or {})
        merged.update(fresh_per_cluster)
        merged = {c: merged[c] for c in cur_members if c in merged}
        rollup = _rollup_status(merged)
        now = datetime.now().isoformat()
        if defn_updates is not None:
            new_defn = dict(rec.get('desired_state') or {})
            new_defn.update(defn_updates)
            new_defn['member_clusters'] = cur_members   # never let an edit revert a concurrent member change
            db.execute('UPDATE multi_cluster_vnets SET alias = ?, subnets = ?, desired_state = ?, '
                       'per_cluster_status = ?, status = ?, updated_at = ? WHERE id = ?',
                       (new_defn.get('alias', ''), json.dumps(new_defn.get('subnets') or []),
                        json.dumps(new_defn), json.dumps(merged), rollup, now, vid))
        else:
            db.execute('UPDATE multi_cluster_vnets SET per_cluster_status = ?, status = ?, '
                       'updated_at = ? WHERE id = ?', (json.dumps(merged), rollup, now, vid))
        row = db.query_one('SELECT * FROM multi_cluster_vnets WHERE id = ?', (vid,))
        return _row_to_dict(row)


@bp.route('/api/multi-sdn/vnets/<vid>', methods=['PUT'])
@require_auth(perms=['sdn.manage', 'admin.settings'])
def edit_multi_vnet(vid):
    """Edit a cross-cluster EVPN vnet: alias + subnet add/remove, fanned out to every
    member. Structural fields (name/zone/vni/asn/controller) are IMMUTABLE here — changing
    them would rebuild the whole span, so delete + recreate instead."""
    db = get_db()
    row = db.query_one('SELECT * FROM multi_cluster_vnets WHERE id = ?', (vid,))
    if not row:
        return jsonify({'error': 'not found'}), 404
    rec = _row_to_dict(row)
    members = rec.get('member_clusters', [])
    denied = _require_members_access(members, mutating=True)
    if denied:
        return denied
    defn = rec.get('desired_state') or {}
    if not defn:
        return jsonify({'error': 'record has no stored definition'}), 500

    body = request.get_json(force=True, silent=True) or {}
    for f in ('name', 'zone', 'vni', 'asn', 'controller'):
        if f in body and str(body[f]).strip() not in ('', str(defn.get(f, ''))):
            return jsonify({'error': f"'{f}' is structural and cannot be edited — "
                            f"delete and recreate the vNet to change it"}), 400

    changes = {'alias': None, 'add_subnets': [], 'del_cidrs': []}
    if 'alias' in body:
        changes['alias'] = str(body.get('alias') or '').strip()
    for s in (body.get('add_subnets') or []):
        cidr = str((s.get('cidr') if isinstance(s, dict) else s) or '').strip()
        try:
            ipaddress.ip_network(cidr, strict=False)
        except (ValueError, TypeError):
            return jsonify({'error': f'invalid subnet CIDR: {cidr!r}'}), 400
        entry = {'cidr': cidr}
        if isinstance(s, dict):
            gw = str(s.get('gateway', '') or '').strip()
            if gw:
                try:
                    ipaddress.ip_address(gw)
                except ValueError:
                    return jsonify({'error': f'invalid gateway: {gw}'}), 400
                entry['gateway'] = gw
            if s.get('snat'):
                entry['snat'] = True
        changes['add_subnets'].append(entry)
    for c in (body.get('del_subnets') or []):
        cc = str((c.get('cidr') if isinstance(c, dict) else c) or '').strip()
        try:
            ipaddress.ip_network(cc, strict=False)
        except (ValueError, TypeError):
            return jsonify({'error': f'invalid subnet CIDR: {cc!r}'}), 400
        changes['del_cidrs'].append(cc)
    if changes['alias'] is None and not changes['add_subnets'] and not changes['del_cidrs']:
        return jsonify({'error': 'nothing to change (alias / add_subnets / del_subnets)'}), 400

    results = run_per_node(
        {cid: (lambda c=cid: _edit_on_cluster(c, defn, changes)) for cid in members},
        max_concurrent=8, timeout=120) or {}
    per_cluster = {cid: (results.get(cid) if isinstance(results.get(cid), dict) else {
        'cluster_id': cid, 'status': 'failed', 'error': 'no result', 'steps': []}) for cid in members}

    # recompute the subnet set (add - del, deduped) to fold into desired_state
    subs = [dict(x) for x in (defn.get('subnets') or [])]
    del_nets = {_canon_net(c) for c in changes['del_cidrs']}
    subs = [x for x in subs if _canon_net(x.get('cidr')) not in del_nets]
    have = {_canon_net(x.get('cidr')) for x in subs}
    for a in changes['add_subnets']:
        cn = _canon_net(a['cidr'])
        if cn not in have:
            subs.append(a)
            have.add(cn)   # update as we go so duplicates within add_subnets don't double-insert
    defn_updates = {'subnets': subs}
    if changes['alias'] is not None:
        defn_updates['alias'] = changes['alias']
    out = _merge_status_write(vid, per_cluster, defn_updates=defn_updates)
    if out is None:
        return jsonify({'error': 'not found'}), 404
    log_audit(getattr(request, 'session', {}).get('user', 'system'),
              'multi_sdn.vnet_edited', f"Edited cross-cluster vnet '{rec.get('name')}' → {out.get('status')}")
    return jsonify(out)


@bp.route('/api/multi-sdn/vnets/<vid>/reconcile', methods=['POST'])
@require_auth(perms=['sdn.manage', 'admin.settings'])
def reconcile_multi_vnet(vid):
    """Re-assert the stored desired definition on every member (create anything missing +
    fix alias drift) + apply. Manual, always available — independent of the auto-reconcile
    setting. Structural drift (tag/zone) is reported but not auto-changed."""
    db = get_db()
    row = db.query_one('SELECT * FROM multi_cluster_vnets WHERE id = ?', (vid,))
    if not row:
        return jsonify({'error': 'not found'}), 404
    rec = _row_to_dict(row)
    members = rec.get('member_clusters', [])
    denied = _require_members_access(members, mutating=True)
    if denied:
        return denied
    defn = rec.get('desired_state') or {}
    if not defn:
        return jsonify({'error': 'record has no stored definition'}), 500
    results = run_per_node(
        {cid: (lambda c=cid: _reconcile_on_cluster(c, defn)) for cid in members},
        max_concurrent=8, timeout=180) or {}
    per_cluster = {cid: (results.get(cid) if isinstance(results.get(cid), dict) else {
        'cluster_id': cid, 'status': 'failed', 'error': 'no result', 'steps': []}) for cid in members}
    out = _merge_status_write(vid, per_cluster)
    if out is None:
        return jsonify({'error': 'not found'}), 404
    log_audit(getattr(request, 'session', {}).get('user', 'system'),
              'multi_sdn.vnet_reconciled', f"Reconciled cross-cluster vnet '{rec.get('name')}' → {out.get('status')}")
    return jsonify(out)


@bp.route('/api/multi-sdn/vnets/<vid>/scan', methods=['POST'])
@require_auth(perms=['sdn.manage', 'admin.settings'])
def scan_multi_vnet(vid):
    """Read live per-member SDN state and persist the drift status. Detect-only — no writes
    to any cluster, but it DOES overwrite the shared aggregate drift snapshot other users see,
    so it's gated like the rest of the span writers (#612 review: was node.view)."""
    db = get_db()
    row = db.query_one('SELECT * FROM multi_cluster_vnets WHERE id = ?', (vid,))
    if not row:
        return jsonify({'error': 'not found'}), 404
    rec = _row_to_dict(row)
    members = rec.get('member_clusters', [])
    denied = _require_members_access(members)
    if denied:
        return denied
    defn = rec.get('desired_state') or {}
    live = {cid: _live_status_on_cluster(cid, defn) for cid in members}
    out = _merge_status_write(vid, live)
    if out is None:
        return jsonify({'error': 'not found'}), 404
    return jsonify(out)


# ---------------------------------------------------------------------------
# Phase 3 — expand / shrink the span (add / remove a member cluster)
# ---------------------------------------------------------------------------
def _persist_members(db, vid, defn, new_members, per_cluster, user):
    """Write a member-list change consistently across all three copies: the
    member_clusters column (what every route reads), desired_state['member_clusters']
    (kept honest), and per_cluster_status; refresh the rollup + updated_at."""
    new_defn = dict(defn)
    new_defn['member_clusters'] = new_members
    now = datetime.now().isoformat()
    db.execute('UPDATE multi_cluster_vnets SET member_clusters = ?, desired_state = ?, '
               'per_cluster_status = ?, status = ?, updated_at = ? WHERE id = ?',
               (json.dumps(new_members), json.dumps(new_defn), json.dumps(per_cluster),
                _rollup_status(per_cluster), now, vid))


@bp.route('/api/multi-sdn/vnets/<vid>/members', methods=['POST'])
@require_auth(perms=['sdn.manage', 'admin.settings'])
def add_multi_vnet_member(vid):
    """Add a cluster to an existing span: collision + reachability pre-flight on the NEW
    cluster, then build the same EVPN controller/zone/vnet on it and append it. Body:
    {cluster_id}. The new cluster must share the span's ASN/VNI (collision pre-flight
    enforces it) and the caller must have access to it too."""
    db = get_db()
    row = db.query_one('SELECT * FROM multi_cluster_vnets WHERE id = ?', (vid,))
    if not row:
        return jsonify({'error': 'not found'}), 404
    rec = _row_to_dict(row)
    members = rec.get('member_clusters', [])
    new_cid = str((request.get_json(force=True, silent=True) or {}).get('cluster_id', '')).strip()
    if not new_cid:
        return jsonify({'error': 'cluster_id is required'}), 400
    if new_cid in members:
        return jsonify({'error': f"cluster '{new_cid}' is already a member"}), 409
    # gate on ALL members INCLUDING the new one — a caller who can't reach it can't add it
    denied = _require_members_access(members + [new_cid], mutating=True)
    if denied:
        return denied
    defn = rec.get('desired_state') or {}
    if not defn:
        return jsonify({'error': 'record has no stored definition'}), 500

    # pre-flight the new cluster exactly like create does per-member
    mgr, reason = _resolve_member(new_cid)
    if reason:
        return jsonify({'error': f"cluster '{new_cid}' is {reason}", 'cluster_id': new_cid}), 409
    conflicts, cerr = _collisions_on_cluster(mgr, defn)
    if cerr == 'sdn_not_installed':
        return jsonify({'error': f"SDN is not installed on '{new_cid}'", 'cluster_id': new_cid}), 409
    if cerr:
        return jsonify({'error': f"pre-flight read failed on '{new_cid}': {cerr}", 'cluster_id': new_cid}), 502
    if conflicts:
        return jsonify({'error': f"conflicting SDN objects on '{new_cid}'",
                        'cluster_id': new_cid, 'conflicts': conflicts}), 409

    result = _apply_on_cluster(new_cid, defn)
    if result.get('status') != 'applied':
        # don't half-add: tear down EXACTLY what this build freshly created (not a
        # pre-existing zone/controller a co-tenant span may share), leave membership as-is
        _teardown_created_on_cluster(new_cid, defn, result.get('created'))
        return jsonify({'error': f"failed to build the vnet on '{new_cid}'",
                        'cluster_id': new_cid, 'result': result}), 502

    # serialize the authoritative-record write + re-read under the lock so a concurrent
    # add/remove on the same span can't lose this update
    user = getattr(request, 'session', {}).get('user', 'system')
    with _get_vnet_lock(vid):
        row = db.query_one('SELECT * FROM multi_cluster_vnets WHERE id = ?', (vid,))
        if not row:
            return jsonify({'error': 'not found'}), 404
        rec = _row_to_dict(row)
        cur_members = rec.get('member_clusters', [])
        if new_cid not in cur_members:   # skip if a concurrent add already appended it
            per_cluster = dict(rec.get('per_cluster_status', {}))
            per_cluster[new_cid] = result
            _persist_members(db, vid, rec.get('desired_state') or defn, cur_members + [new_cid], per_cluster, user)
        row = db.query_one('SELECT * FROM multi_cluster_vnets WHERE id = ?', (vid,))
    log_audit(user, 'multi_sdn.member_added',
              f"Added cluster '{new_cid}' to cross-cluster vnet '{rec.get('name')}'")
    return jsonify(_row_to_dict(row)), 201


@bp.route('/api/multi-sdn/vnets/<vid>/members/<cid>', methods=['DELETE'])
@require_auth(perms=['sdn.manage', 'admin.settings'])
def remove_multi_vnet_member(vid, cid):
    """Drop a cluster from a span. Keeps >=1 member. ?purge=1 also removes the vNet from
    that cluster (vnet-only — the zone/controller are left, since another span on that
    cluster may share them)."""
    db = get_db()
    row = db.query_one('SELECT * FROM multi_cluster_vnets WHERE id = ?', (vid,))
    if not row:
        return jsonify({'error': 'not found'}), 404
    rec = _row_to_dict(row)
    members = rec.get('member_clusters', [])
    denied = _require_members_access(members, mutating=True)
    if denied:
        return denied
    if cid not in members:
        return jsonify({'error': f"cluster '{cid}' is not a member"}), 404
    if len(members) <= 1:
        return jsonify({'error': 'cannot remove the last member — delete the vNet instead'}), 409

    defn = rec.get('desired_state') or {}
    purge = request.args.get('purge') in ('1', 'true', 'yes')
    purged = None
    if purge and defn:
        purged = _purge_vnet_only_on_cluster(cid, defn)

    user = getattr(request, 'session', {}).get('user', 'system')
    with _get_vnet_lock(vid):
        row = db.query_one('SELECT * FROM multi_cluster_vnets WHERE id = ?', (vid,))
        if not row:
            return jsonify({'error': 'not found'}), 404
        rec = _row_to_dict(row)
        cur_members = rec.get('member_clusters', [])
        new_members = [m for m in cur_members if m != cid]
        if not new_members:   # a concurrent remove already got the others — never orphan-empty
            return jsonify({'error': 'cannot remove the last member — delete the vNet instead'}), 409
        per_cluster = {k: v for k, v in rec.get('per_cluster_status', {}).items() if k != cid}
        _persist_members(db, vid, rec.get('desired_state') or defn, new_members, per_cluster, user)
        row = db.query_one('SELECT * FROM multi_cluster_vnets WHERE id = ?', (vid,))
    log_audit(user, 'multi_sdn.member_removed',
              f"Removed cluster '{cid}' from cross-cluster vnet '{rec.get('name')}'"
              + (" (purged the vnet from it)" if purge else " (left the vnet in place)"))
    out = _row_to_dict(row)
    out['purged'] = purged
    return jsonify(out)


# ---------------------------------------------------------------------------
# Phase 2 — background drift scanner (detect-only by default)
# ---------------------------------------------------------------------------
# Mirrors api/drift.py: module-level running flag + lock, chunked sleep, plain daemon
# Thread. Started once from api/__init__.register_blueprints(). Every tick it reads live
# per-member SDN state for each aggregate vnet and persists the drift status. It only
# WRITES to clusters (auto-reconcile) when the global opt-in setting
# `multi_sdn_drift_reconcile` is on — off by default, so the scanner is detect-only and
# never touches a production SDN uninvited.
_msdn_scanner_running = False
_msdn_scanner_lock = threading.Lock()
MSDN_SCAN_INTERVAL = 6 * 3600  # 6h, same cadence as the config-drift scanner


def _msdn_scan_once():
    """One scan pass over all aggregate vnets. Extracted so tests can call it directly."""
    try:
        reconcile_on = bool(load_server_settings().get('multi_sdn_drift_reconcile', False))
    except Exception:
        reconcile_on = False
    db = get_db()
    rows = db.query('SELECT * FROM multi_cluster_vnets') or []
    for row in rows:
        try:
            rec = _row_to_dict(row)
            if not rec.get('enabled', True):
                continue
            defn = rec.get('desired_state') or {}
            members = rec.get('member_clusters', [])
            if not defn or not members:
                continue
            prior = rec.get('per_cluster_status', {}) or {}   # last pass, for the debounce
            live = {cid: _live_status_on_cluster(cid, defn) for cid in members}
            if reconcile_on:
                # Reconcile ONLY the members that are actually off — never touch an in-sync
                # member (each _reconcile is a cluster-wide SDN reload, so fanning it across
                # the whole span for one drifted member is over-broad blast radius).
                # A 'drift' (alias mismatch) is a cheap safe PUT → fix on first sight.
                # A 'missing' member means a full recreate, so DEBOUNCE it: only recreate if
                # the previous pass ALSO saw it non-healthy — a transient partial SDN read (or
                # a deliberate out-of-band teardown between two 6h scans) then won't trigger an
                # unattended resurrection of infrastructure.
                to_fix = [cid for cid in members
                          if live[cid].get('status') == 'drift'
                          or (live[cid].get('status') == 'missing'
                              and (prior.get(cid) or {}).get('status') in ('missing', 'drift'))]
                if to_fix:
                    recreated = [cid for cid in to_fix if live[cid].get('status') == 'missing']
                    for cid in to_fix:
                        try:
                            _reconcile_on_cluster(cid, defn)
                        except Exception as e:
                            logging.debug(f"[multi_sdn] auto-reconcile {cid} failed: {e}")
                    live = {cid: _live_status_on_cluster(cid, defn) for cid in members}
                    # unattended cluster mutation → leave an audit-DB trail, not just a log line
                    log_audit('system', 'multi_sdn.vnet_auto_reconciled',
                              f"Auto-reconciled cross-cluster vnet '{rec.get('name')}' on {to_fix}"
                              + (f" (re-created on {recreated})" if recreated else "")
                              + f" → {_rollup_status(live)}")
            # #612 P3 — operator alert on a healthy→drift transition. Edge-triggered off
            # `prior` (already loaded), computed from the FINAL live status (after any
            # auto-reconcile above), so a fixed member never false-alerts and a member that
            # stays drifted across 6h ticks alerts ONCE, not every tick.
            newly_off = [cid for cid in members
                         if live[cid].get('status') in ('drift', 'missing')
                         and (prior.get(cid) or {}).get('status') not in ('drift', 'missing')]
            if newly_off:
                try:
                    from pegaprox.background import alerts as alerts_mod
                    handlers = list(getattr(alerts_mod, '_notification_handlers', []) or [])
                    # One alert PER drifted member, each anchored to its OWN cluster_id, so
                    # push fan-out reaches every affected tenant (a single anchor would only
                    # wake the tenant that owns the first drifted member on a cross-tenant span).
                    for off_cid in newly_off:
                        payload = {
                            'alert_name': 'Cross-cluster SDN Drift',
                            'severity': 'warning',
                            'cluster_id': off_cid,
                            'message': f"EVPN vNet '{rec.get('name')}' drifted on cluster '{off_cid}'",
                            'metric': 'multi_sdn_drift',
                            'target_type': 'cluster',
                            'target_name': rec.get('name'),
                            'timestamp': datetime.now().isoformat(),
                        }
                        for h in handlers:
                            try:
                                h(payload)
                            except Exception:
                                pass
                        # same gap as #815 on the config-drift side: handlers are the
                        # plugin hook, the configured webhook channels are a separate
                        # dispatch that nobody here was calling.
                        try:
                            from pegaprox.utils.webhooks import send_to_channels
                            send_to_channels(payload)
                        except Exception as _we:
                            logging.warning(f"[multi_sdn] webhook dispatch failed: {_we}")
                except Exception as e:
                    logging.debug(f"[multi_sdn] drift alert emit failed: {e}")

            rollup = _rollup_status(live)
            db.execute('UPDATE multi_cluster_vnets SET per_cluster_status = ?, status = ?, updated_at = ? WHERE id = ?',
                       (json.dumps(live), rollup, datetime.now().isoformat(), rec['id']))
        except Exception as e:
            logging.debug(f"[multi_sdn] scan vnet failed: {e}")


def _msdn_scanner_loop():
    while _msdn_scanner_running:
        try:
            _msdn_scan_once()
        except Exception as e:
            logging.warning(f"[multi_sdn] scanner iteration failed: {e}")
        # break the sleep into 1-sec chunks so shutdown is responsive (drift.py pattern)
        for _ in range(MSDN_SCAN_INTERVAL):
            if not _msdn_scanner_running:
                return
            time.sleep(1)


def start_scanner():
    global _msdn_scanner_running
    with _msdn_scanner_lock:
        if _msdn_scanner_running:
            return
        _msdn_scanner_running = True
    t = threading.Thread(target=_msdn_scanner_loop, daemon=True, name='multi-sdn-drift-scanner')
    t.start()
    logging.info("[multi_sdn] drift scanner thread started (6h cadence, detect-only unless opted in)")
