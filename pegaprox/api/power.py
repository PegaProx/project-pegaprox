# -*- coding: utf-8 -*-
"""
Power & Carbon Tracking — MK May 2026.

Estimates kWh + €/month + kg CO₂/month per VM and per cluster, based on
the same `metrics_history` snapshots that Insights + Cost Dashboard use.

Model (kept linear + explainable; nothing fancier holds up to scrutiny).
#965 - computed per host and per snapshot interval, then handed down to the
guests that ran on that host during the interval:

    host_w  = idle_w + (max_w - idle_w) × host_cpu_util
            + host_mem_used_gb × mem_w_per_gb      (only for an inherited profile;
                                                    a per-host profile is whole-system)
    guest share of host_w:
        idle_w                 by the guest's vCPUs among the guests running there
        (max_w - idle_w)/cores per core the guest actually used
        mem_w_per_gb           per GB the guest actually used
    what no guest explains (an empty host, host overhead) stays "unallocated",
    so guests + unallocated = hosts = cluster total.

    pue     = data-center power usage effectiveness multiplier (1.0 = no
              cooling / racks already accounted; 1.5 = typical enterprise;
              2.0 = older facilities)
    kwh     = W × pue × interval_h / 1000
    cost    = kwh × kwh_price
    co2_kg  = kwh × kg_co2_per_kwh

Each snapshot stands for the time up to the next one (capped, so a gap where
PegaProx was down is not bridged). The monthly figure extrapolates from the
hours actually covered and says how many were missing.

Default rates (admin-editable):
    node_idle_w     = 80   W  (typical 1U server idle)
    node_max_w      = 300  W  (typical full-load CPU+RAM, ignoring storage)
    mem_w_per_gb    = 0.3  W
    pue             = 1.5
    kwh_price       = 0.30 EUR
    kg_co2_per_kwh  = 0.40  (DE 2024 grid average; FR ~0.05, PL ~0.7, etc.)
"""
import json
import logging
import math
import re
from datetime import datetime, timedelta
from functools import reduce
from itertools import chain, compress, repeat
from operator import add, mul, truediv
from flask import Blueprint, jsonify, request

from pegaprox.globals import cluster_managers
from pegaprox.utils.auth import require_auth
from pegaprox.api.helpers import (check_cluster_access, load_metrics_window, scope_vm_rows, require_unconfined,
                                  history_report, history_version, report_owner, run_off_hub, _history_stride)
from pegaprox.background.metrics_store import need, guest_columns, FT, HERE, RUN, ELIGIBLE
from pegaprox.utils.audit import log_audit
from pegaprox.core.db import get_db
from pegaprox.models.permissions import ROLE_ADMIN

bp = Blueprint('power', __name__)


_DEFAULT = {
    'node_idle_w': 80.0,
    'node_max_w': 300.0,
    'mem_w_per_gb': 0.3,
    'pue': 1.5,
    'kwh_price': 0.30,
    'kg_co2_per_kwh': 0.40,
    'currency': 'EUR',
    'notes': '',
}


def _row_to_rates(r):
    return {
        'cluster_id': r['cluster_id'],
        'node_idle_w': float(r['node_idle_w'] or 0),
        'node_max_w': float(r['node_max_w'] or 0),
        'mem_w_per_gb': float(r['mem_w_per_gb'] or 0),
        'pue': float(r['pue'] or 1.0),
        'kwh_price': float(r['kwh_price'] or 0),
        'kg_co2_per_kwh': float(r['kg_co2_per_kwh'] or 0),
        'currency': r['currency'] or 'EUR',
        'notes': r['notes'] or '',
        'updated_at': r['updated_at'],
        'updated_by': r['updated_by'] or '',
    }


def _get_rates(cluster_id):
    db = get_db()
    c = db.conn.cursor()
    try:
        c.execute("SELECT * FROM power_rates WHERE cluster_id IN ('__default__', ?)", (cluster_id,))
        rows = {r['cluster_id']: r for r in c.fetchall()}
    except Exception:
        rows = {}
    if cluster_id in rows: return _row_to_rates(rows[cluster_id])
    if '__default__' in rows: return _row_to_rates(rows['__default__'])
    return {**_DEFAULT, 'cluster_id': '__default__'}


def _current_user():
    try:
        u = request.session.get('user') if hasattr(request, 'session') else ''
        if isinstance(u, dict): return u.get('username', '') or ''
        return u or ''
    except Exception:
        return ''


def _load_history(cluster_id, days=30):
    # fetch+parse off-hub in load_metrics_window, one cluster (shared w/ insights/costs)
    try:
        return load_metrics_window(days, cluster_id)
    except Exception:
        return []


_GIB = 1024 ** 3
_PCT_GIB = 100.0 * _GIB  # a percentage of bytes, in GB
_MEM_TABLES = 256        # _compute_power_cols: lookup tables kept for that many memory sizes


def _get_host_profiles(cluster_id):
    """{node: profile} for the hosts that have one of their own."""
    try:
        c = get_db().conn.cursor()
        c.execute('SELECT * FROM power_host_profiles WHERE cluster_id=?', (cluster_id,))
        return {r['node']: {'idle_w': float(r['idle_w'] or 0), 'max_w': float(r['max_w'] or 0),
                            'notes': r['notes'] or '', 'updated_at': r['updated_at'],
                            'updated_by': r['updated_by'] or ''} for r in c.fetchall()}
    except Exception:
        return {}


def _host_profile(node, profiles, rates):
    """(idle_w, max_w, custom) for a host - its own profile, else the cluster's."""
    p = profiles.get(node)
    if p:
        return p['idle_w'], max(p['max_w'], p['idle_w']), True
    return rates['node_idle_w'], max(rates['node_max_w'], rates['node_idle_w']), False


def _intervals(snapshots, step=300):
    """Hours each snapshot stands for: up to the next one, at most 3 steps of the
    cadence they were read at, so a gap (PegaProx down, collector stuck) counts as
    missing instead of bridged. The cadence is the caller's, not taken from the
    data: in a sparse history a long gap would be the typical step."""
    ts = [s[0] for s in snapshots]
    cap = 3 * step
    out = [min(max(b - a, 0), cap) / 3600.0 for a, b in zip(ts, ts[1:])]
    if ts:
        out.append(step / 3600.0)
    return out


def _live_names(resources):
    live_node, name_by_vmid = {}, {}
    for r in resources:
        vid = str(r.get('vmid') or '')
        if vid:
            name_by_vmid[vid] = r.get('name', '')
            live_node[vid] = r.get('node', '')
    return live_node, name_by_vmid


def _compute_power(snapshots, resources, rates, profiles, step=300):
    """kWh per guest and per host over the snapshots; `resources` is the live guest list
    (names, and today's host for history from before #965).

    Returns {'rows': [...], 'hosts': {node: {...}}, 'covered_h': float}. Host kWh stay
    unrounded so the totals add up before anything is rounded for display.
    MK Oct 2026 - a window whose guests are all stored in columns, with the host sums of
    pass 1 written alongside, goes to _compute_power_cols: the same figures without a dict
    per guest and sample."""
    cols = guest_columns(snapshots, hosts=True)
    if cols is not None:
        return _compute_power_cols(cols, resources, rates, profiles, step)
    snapshots = need(snapshots, 'nodes', 'vms')
    # NOTE: _compute_power_cols below replays pass 1 and 3 on the column store, and
    # metrics_store.host_sums is pass 1 as written with each snapshot. All three have to give
    # the very same floats (tests/test_metrics_column_engines.py): a change here goes there.
    live_node, name_by_vmid = _live_names(resources)
    # per guest, a list (this loop runs guests x snapshots - 7M times at 10k guests/30d):
    # type, samples, running samples, running h, cpu % sum, mem % sum, vcpus, mem bytes,
    # {node: kwh}, samples without a recorded host, last host
    by_vm, hosts = {}, {}
    dts = _intervals(snapshots, step)

    for (ts, cd), dt_h in zip(snapshots, dts):
        nodes = cd.get('nodes') or {}  # online hosts only
        # pass 1 - who ran where, and what that adds up to per host. Flat lists, not a
        # tuple per guest: millions of small containers set the cyclic GC walking the
        # whole cached history over and over, which doubled the run time at scale.
        p_kwh, p_node, p_vcpus, p_cores, p_gb = [], [], [], [], []
        per_host = {}
        for vmid, v in (cd.get('vms') or {}).items():
            e = by_vm.get(vmid)
            if e is None:
                e = by_vm[vmid] = [v.get('t'), 0, 0, 0.0, 0.0, 0.0, 0, 0, {}, 0, '']
            e[1] += 1
            maxcpu = v.get('maxcpu') or 0
            maxmem = v.get('maxmem') or 0
            if maxcpu > e[6]:
                e[6] = maxcpu
            if maxmem > e[7]:
                e[7] = maxmem
            if not v.get('r'):
                continue
            cpu_pct = v.get('cpu') or 0
            mem_pct = v.get('mem') or 0
            e[2] += 1
            e[3] += dt_h
            e[4] += cpu_pct
            e[5] += mem_pct
            n = v.get('n')
            if not n:
                # a snapshot from before #965 has no host - take today's placement
                n = live_node.get(vmid, '')
                e[9] += 1
            if n not in nodes:
                continue
            e[10] = n
            vcpus = maxcpu or 1
            cores_used = cpu_pct * vcpus / 100.0
            mem_gb = mem_pct * maxmem / _PCT_GIB
            p_kwh.append(e[8])
            p_node.append(n)
            p_vcpus.append(vcpus)
            p_cores.append(cores_used)
            p_gb.append(mem_gb)
            s = per_host.get(n)
            if s is None:
                per_host[n] = [vcpus, cores_used, mem_gb]
            else:
                s[0] += vcpus
                s[1] += cores_used
                s[2] += mem_gb

        # pass 2 - host power, and what it pays per vCPU / used core / used GB
        rate = _host_rates(nodes, per_host, dt_h, rates, profiles, hosts)

        # pass 3 - each guest's share of its host
        for by_node, n, vcpus, cores_used, mem_gb in zip(p_kwh, p_node, p_vcpus, p_cores, p_gb):
            r_vcpu, r_core, r_gb = rate[n]
            by_node[n] = by_node.get(n, 0.0) + r_vcpu * vcpus + r_core * cores_used + r_gb * mem_gb

    return _power_rows(by_vm, hosts, dts, live_node, name_by_vmid, rates)


def _host_rates(nodes, per_host, dt_h, rates, profiles, hosts):
    """Pass 2 of one snapshot: what each online host drew over dt_h, added to `hosts`, and
    what it pays per vCPU / used core / used GB, {host: (kWh, kWh, kWh)}. per_host is pass 1
    of that snapshot, {host: [vcpus, cores used, GB used]}."""
    k = rates['pue'] * dt_h / 1000.0
    mem_w_per_gb = rates['mem_w_per_gb']
    rate = {}
    for n, h in nodes.items():
        idle, mx, custom = _host_profile(n, profiles, rates)
        util = min(max((h.get('cpu') or 0) / 100.0, 0.0), 1.0)
        active_w = (mx - idle) * util
        # a per-host profile is whole-system power, RAM included
        mem_w = 0.0 if custom else (
            (h.get('mem_percent') or 0) * (h.get('maxmem') or 0) / _PCT_GIB * mem_w_per_gb)
        vcpus, used_cores, used_gb = per_host.get(n) or (0, 0.0, 0.0)
        per_vcpu = idle / vcpus if vcpus else 0.0
        cores = h.get('maxcpu') or 0
        per_core = (mx - idle) / cores if cores else 0.0
        # guest samples can run a little ahead of the host's - never hand out more than it drew
        if used_cores * per_core > active_w:
            per_core = active_w / used_cores
        per_gb = 0.0 if custom else mem_w_per_gb
        if used_gb * per_gb > mem_w:
            per_gb = mem_w / used_gb
        # already in kWh for this interval
        rate[n] = (per_vcpu * k, per_core * k, per_gb * k)
        total_w = idle + active_w + mem_w
        given_w = per_vcpu * vcpus + per_core * used_cores + per_gb * used_gb
        hs = hosts.get(n)
        if hs is None:
            hs = hosts[n] = {'kwh': 0.0, 'kwh_unallocated': 0.0, 'online_h': 0.0}
        hs['kwh'] += total_w * k
        hs['kwh_unallocated'] += max(total_w - given_w, 0.0) * k
        hs['online_h'] += dt_h
    return rate


def _compute_power_cols(cols, resources, rates, profiles, step=300):
    """_compute_power on a metrics_store.GuestColumns with the host sums of every snapshot.

    Pass 2 is _host_rates per snapshot, from the host sums pass 1 wrote with it. Per guest,
    the sums pass 1 and 3 build with `+=` are built here in the same order from the same
    operands: e[3] to e[5] start at 0.0 and add each running sample in turn (a cpu or mem
    that was None or 0 adds 0.0 here and int 0 there, which leaves a float sum as it is),
    and by_node[host] adds rate * vcpus, rate * cores used, rate * GB used per sample, in
    that order. functools.reduce(add) does that left to right; sum() would not (it
    compensates from 3.12 on)."""
    live_node, name_by_vmid = _live_names(resources)
    dts = _intervals(cols.rows, step)
    S, U = cols.S, cols.U
    names, maxcpu, maxmem, host, snap_k = cols.names, cols.maxcpu, cols.maxmem, cols.host, cols.snap_k
    hcode = {n: i for i, n in enumerate(names)}
    # the rates of each host per snapshot, by the window's host code
    rv = [[0.0] * S for _ in names]
    rc = [[0.0] * S for _ in names]
    rg = [[0.0] * S for _ in names]
    hosts = {}
    for s, (nodes, per_host, dt_h) in enumerate(zip(cols.nodes, cols.host_sums, dts)):
        for n, (a, b, c) in _host_rates(nodes, per_host, dt_h, rates, profiles, hosts).items():
            h = hcode.get(n)
            if h is not None:
                rv[h][s], rc[h][s], rg[h][s] = a, b, c

    # rate * vCPUs per host and core count, and what a stored tenth gives as cores used or GB
    # used for a guest of that size (the codes run to the window's top one; the last entry is
    # the int 0 of code -1). Memory sizes vary more than core counts: past _MEM_TABLES of them
    # a guest's GB are worked out on the spot, the same way.
    per_vcpus, core_tabs, gb_tabs = {}, {}, {}
    top = max(max(cols.cpu, default=0), max(cols.mem, default=0)) + 1
    by_vm, run_hours = {}, {}
    for vmid, g in cols.order:
        fl = cols.flags_of(g)
        here, run, elig = fl.translate(HERE), fl.translate(RUN), fl.translate(ELIGIBLE)
        rs = run.count(1)
        running_h = run_hours.get(run)
        if running_h is None:
            running_h = run_hours[run] = reduce(add, compress(dts, run), 0.0)
        by_node = {}
        e = by_vm[vmid] = [cols.kind(g, here.find(1)), here.count(1), rs, running_h, 0.0, 0.0,
                           max(chain((0,), cols.values(maxcpu, g))), max(chain((0,), cols.values(maxmem, g))),
                           by_node, 0, '']
        if not rs:
            continue
        cpu, mem = cols.cpu_of(g), cols.mem_of(g)
        if rs == S:
            # running all along: every sample counts, no need to pick them out
            e[4] = reduce(add, map(FT.__getitem__, cpu), 0.0)
            e[5] = reduce(add, map(FT.__getitem__, mem), 0.0)
        else:
            e[4] = reduce(add, map(FT.__getitem__, compress(cpu, run)), 0.0)
            e[5] = reduce(add, map(FT.__getitem__, compress(mem, run)), 0.0)
        n_elig = elig.count(1)
        if not n_elig:
            continue
        # where the guest ran with the same host, vCPUs and memory all along (most do), its
        # share is three products per sample, worked out a column at a time. Eligible in
        # every snapshot, it is in every roster of the window (each is some snapshot's), and
        # its K values per column tell at once
        if n_elig == S:
            hk, ck, mk = host[g::U], maxcpu[g::U], maxmem[g::U]
            same = {(hk[0], ck[0], mk[0])} if (hk.count(hk[0]) == ck.count(ck[0]) == mk.count(mk[0])
                                               == len(hk)) else ()
        else:
            ks = set(compress(snap_k, elig))
            same = {(host[k * U + g], maxcpu[k * U + g], maxmem[k * U + g]) for k in ks}
        if len(same) == 1:
            h, vc, mm = same.pop()
            vcpus = vc or 1
            a = per_vcpus.get((h, vcpus))
            if a is None:
                a = per_vcpus[h, vcpus] = list(map(mul, rv[h], repeat(vcpus)))
            cores = core_tabs.get(vcpus)
            if cores is None:
                cores = core_tabs[vcpus] = [x * vcpus / 100.0 for x in FT[:top]] + [FT[-1] * vcpus / 100.0]
            gbs = gb_tabs.get(mm)
            if gbs is None and len(gb_tabs) < _MEM_TABLES:
                gbs = gb_tabs[mm] = [x * mm / _PCT_GIB for x in FT[:top]] + [FT[-1] * mm / _PCT_GIB]
            if n_elig == S:
                pick = _all
            else:
                def pick(seq, elig=elig):
                    return compress(seq, elig)
            if gbs is not None:
                used_gb = map(gbs.__getitem__, pick(mem))
            else:
                used_gb = map(truediv, map(mul, map(FT.__getitem__, pick(mem)), repeat(mm)), repeat(_PCT_GIB))
            # ((kwh + a) + b) + c sample after sample: the three terms interleaved, added up
            # left to right
            terms = [0.0] * (3 * n_elig)
            terms[0::3] = pick(a)
            terms[1::3] = map(mul, pick(rc[h]), map(cores.__getitem__, pick(cpu)))
            terms[2::3] = map(mul, pick(rg[h]), used_gb)
            by_node[names[h]] = reduce(add, terms, 0.0)
            e[10] = names[h]
            continue
        # moved, resized, or ran on a host that was not online: sample by sample, as written
        for s in compress(range(S), elig):
            k = snap_k[s] * U + g
            h = host[k]
            n = names[h]
            vcpus = maxcpu[k] or 1
            cores_used = FT[cpu[s]] * vcpus / 100.0
            mem_gb = FT[mem[s]] * maxmem[k] / _PCT_GIB
            by_node[n] = by_node.get(n, 0.0) + rv[h][s] * vcpus + rc[h][s] * cores_used + rg[h][s] * mem_gb
            e[10] = n
    return _power_rows(by_vm, hosts, dts, live_node, name_by_vmid, rates)


def _all(seq):
    return seq


def _power_rows(by_vm, hosts, dts, live_node, name_by_vmid, rates):
    price, co2 = rates['kwh_price'], rates['kg_co2_per_kwh']
    rows = []
    for vmid, (vtype, samples, rs, running_h, cpu_sum, mem_sum, maxcpu, maxmem,
               by_node, guessed, last_node) in by_vm.items():
        kwh = sum(by_node.values())
        rows.append({
            'vmid': vmid,
            'name': name_by_vmid.get(vmid, vmid),
            'node': live_node.get(vmid) or last_node,
            'type': vtype,
            'avg_cpu_pct': round(cpu_sum / rs, 1) if rs else 0,
            'avg_mem_pct': round(mem_sum / rs, 1) if rs else 0,
            'cores': maxcpu or 1,
            'memory_gb': round(maxmem / _GIB, 2),
            'running_h': round(running_h, 1),
            'kwh': round(kwh, 2),
            'cost': round(kwh * price, 2),
            'kg_co2': round(kwh * co2, 2),
            'low_data': samples < 12,
            # kWh per host it ran on - more than one when it migrated in the window
            'by_node': {n: round(v, 3) for n, v in by_node.items()},
            # its host was not recorded for some samples (history from before #965)
            'node_estimated': guessed > 0,
            'kwh_exact': kwh,
        })
    rows.sort(key=lambda r: r['kwh_exact'], reverse=True)
    return {'rows': rows, 'hosts': hosts, 'covered_h': sum(dts)}


# ── Endpoints ────────────────────────────────────────────────────────────

@bp.route('/api/power/rates', methods=['GET'])
@require_auth()
def list_rates():
    try:
        c = get_db().conn.cursor()
        c.execute('SELECT * FROM power_rates ORDER BY cluster_id')
        rows = [_row_to_rates(r) for r in c.fetchall()]
        # NS Aug 2026 (Aikido IDOR) — scope rows to the caller's reachable clusters; was
        # leaking every cluster's rates to any authenticated user. Always keep the shared
        # '__default__' fallback row (every cluster reads it when it has no own row).
        from pegaprox.utils.rbac import get_user_clusters
        from pegaprox.api.helpers import acting_user
        # NS Aug 2026 — honour a token's floored effective_role (not the owner's account role),
        # so an admin-owned but scoped token can't enumerate every cluster's rates.
        # NS Oct 2026 - next to the owner's role, not in place of it (see costs.list_rates)
        allowed = get_user_clusters(acting_user())
        if allowed is not None:
            rows = [r for r in rows if r['cluster_id'] == '__default__' or r['cluster_id'] in allowed]
        return jsonify({'rates': rows})
    except Exception:
        logging.exception('list power rates')
        return jsonify({'error': 'internal error'}), 500


@bp.route('/api/power/rates/<cluster_id>', methods=['GET'])
@require_auth()
def get_one(cluster_id):
    # NS Jul 2026 (CodeAnt IDOR) — tenant gate (skip the __default__ pseudo-cluster, no owner)
    if cluster_id != '__default__':
        from pegaprox.api.helpers import check_cluster_access
        ok, err = check_cluster_access(cluster_id)
        if not ok:
            return err
    return jsonify(_get_rates(cluster_id))


@bp.route('/api/power/rates/<cluster_id>', methods=['PUT'])
@require_auth(perms=['cluster.config'])
def upsert(cluster_id):
    if cluster_id != '__default__':
        from pegaprox.api.helpers import check_cluster_access
        ok, err = check_cluster_access(cluster_id)
        if not ok:
            return err
        # sec (audit): the tariff is cluster-wide and feeds every tenant's cost reporting —
        # no per-object notion, so a confined caller has no business rewriting it.
        _cerr = require_unconfined(cluster_id)
        if _cerr:
            return _cerr
    # NS Aug 2026 (Aikido pentest) — __default__ is the shared fallback row for every cluster;
    # only a global admin may overwrite it (a cluster.config holder edits only its own cluster).
    # effective_role, not the raw role, so an admin-owned scoped token can't do it either.
    elif request.session.get('effective_role', request.session.get('role')) != ROLE_ADMIN:
        return jsonify({'error': 'Only a global admin can edit the default power rates'}), 403
    body = request.get_json(silent=True) or {}
    try:
        f = {k: float(body.get(k, _DEFAULT[k])) for k in
             ('node_idle_w', 'node_max_w', 'mem_w_per_gb', 'pue', 'kwh_price', 'kg_co2_per_kwh')}
    except (TypeError, ValueError):
        return jsonify({'error': 'rates must be numeric'}), 400
    # MK Oct 2026 - as for a host profile: 1e999 went in as inf and came back as Infinity,
    # which is no JSON, and every power and cost page of the cluster failed on it
    if not all(math.isfinite(v) and v >= 0 for v in f.values()):
        return jsonify({'error': 'rates must be finite and not negative'}), 400
    if f['pue'] < 1:
        return jsonify({'error': 'pue must be at least 1'}), 400
    if max(f['node_idle_w'], f['node_max_w']) > _MAX_HOST_W:
        return jsonify({'error': f'watts must be between 0 and {int(_MAX_HOST_W)}'}), 400
    cur = (body.get('currency') or 'EUR').strip()[:8]
    notes = (body.get('notes') or '').strip()[:500]
    try:
        c = get_db().conn.cursor()
        c.execute('''INSERT INTO power_rates
            (cluster_id, node_idle_w, node_max_w, mem_w_per_gb, pue, kwh_price,
             kg_co2_per_kwh, currency, notes, updated_at, updated_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cluster_id) DO UPDATE SET
                node_idle_w=excluded.node_idle_w,
                node_max_w=excluded.node_max_w,
                mem_w_per_gb=excluded.mem_w_per_gb,
                pue=excluded.pue,
                kwh_price=excluded.kwh_price,
                kg_co2_per_kwh=excluded.kg_co2_per_kwh,
                currency=excluded.currency,
                notes=excluded.notes,
                updated_at=excluded.updated_at,
                updated_by=excluded.updated_by
        ''', (cluster_id, f['node_idle_w'], f['node_max_w'], f['mem_w_per_gb'],
              f['pue'], f['kwh_price'], f['kg_co2_per_kwh'], cur, notes,
              datetime.now().isoformat(), _current_user()))
        get_db().conn.commit()
        return jsonify({'ok': True, 'rates': _get_rates(cluster_id)})
    except Exception:
        logging.exception('upsert power rates')
        return jsonify({'error': 'internal error'}), 500


@bp.route('/api/power/rates/<cluster_id>', methods=['DELETE'])
@require_auth(perms=['cluster.config'])
def delete_rate(cluster_id):
    if cluster_id == '__default__':
        return jsonify({'error': 'cannot delete defaults'}), 400
    from pegaprox.api.helpers import check_cluster_access
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    _cerr = require_unconfined(cluster_id)
    if _cerr:
        return _cerr
    try:
        c = get_db().conn.cursor()
        c.execute('DELETE FROM power_rates WHERE cluster_id=?', (cluster_id,))
        get_db().conn.commit()
        return jsonify({'ok': True})
    except Exception:
        logging.exception('delete power rates')
        return jsonify({'error': 'internal error'}), 500


def _days_arg():
    try:
        return max(1, min(int(request.args.get('days', 30)), 30))
    except Exception:
        return 30


def _cluster_nodes(mgr):
    nodes = getattr(mgr, 'nodes', None)
    return nodes if isinstance(nodes, dict) else {}


def _caller_scoped(cluster_id):
    from pegaprox.api.helpers import caller_is_scoped
    from pegaprox.utils.auth import build_authz_user
    return caller_is_scoped(build_authz_user(request.session.get('user', ''), request.session), cluster_id)


# The page asks for the summary and the per-VM table at once, and both need the same run
# over the whole history - so it runs once, off the hub (helpers.history_report). Keyed on
# what goes into it besides the history; the result is shared, callers must not change it.
def _cached_power(cluster_id, days, snaps, rates, profiles):
    mgr = cluster_managers[cluster_id]
    # the same manager too: a reconnected cluster gets a new one, with its own guests
    key = ('power', cluster_id, days, report_owner(mgr), tuple(sorted(rates.items())),
           tuple(sorted((n, p['idle_w'], p['max_w']) for n, p in profiles.items())))

    def build():
        try:
            resources = mgr.get_vm_resources(max_age=15) or []
        except Exception:
            resources = []
        # the names and hosts copied here: the manager's own rows may change under a
        # thread that is still reading them
        live = [{'vmid': r.get('vmid'), 'name': r.get('name', ''), 'node': r.get('node', '')}
                for r in resources]
        # the collector writes every 5 min, a long window reads every n-th row of it
        return run_off_hub(_compute_power, snaps, live, rates, profiles, 300 * _history_stride(days))

    return history_report(key, history_version(snaps), build, rows=lambda res: len(res['rows']))


def _named_now(cluster_id, rows):
    """The kept rows with the names and hosts of now, read live for every request as before;
    the kWh are the kept run's. A changed row is a copy, the kept one stays as it is."""
    try:
        live = {str(r.get('vmid') or ''): r for r in
                cluster_managers[cluster_id].get_vm_resources(max_age=15) or []}
    except Exception:
        return rows
    out = []
    for r in rows:
        lv = live.get(r['vmid'])
        if lv is not None:
            name, node = lv.get('name', ''), lv.get('node', '') or r['node']
            if name != r['name'] or node != r['node']:
                r = dict(r, name=name, node=node)
        out.append(r)
    return out


def _report(cluster_id, days):
    """(rates, snapshots, result, rows, scoped, stamp) for the summary and per-VM routes;
    result is None when there is no history. rows are the result's, scoped to the caller
    (#773); stamp says when the result was worked out."""
    rates = _get_rates(cluster_id)
    snaps = _load_history(cluster_id, days=days)
    if not snaps:
        return rates, snaps, None, [], False, {}
    res, stamp = _cached_power(cluster_id, days, snaps, rates, _get_host_profiles(cluster_id))
    rows = scope_vm_rows(cluster_id, _named_now(cluster_id, res['rows']))
    # a confined caller sees their guests' share only, not what the hosts drew in total
    scoped = len(rows) != len(res['rows']) or _caller_scoped(cluster_id)
    return rates, snaps, res, rows, scoped, stamp


def _monthly_factor(covered_h):
    return 720.0 / covered_h if covered_h > 0 else 0.0


@bp.route('/api/clusters/<cluster_id>/power/summary', methods=['GET'])
@require_auth(perms=['cluster.view'])
def cluster_summary(cluster_id):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'cluster not found'}), 404

    days = _days_arg()
    rates, snaps, res, rows, scoped, stamp = _report(cluster_id, days)
    if res is None:
        return jsonify({'enough_data': False, 'cluster_id': cluster_id, 'rates': rates, 'days': days})

    covered_h = res['covered_h']
    factor = _monthly_factor(covered_h)
    price, co2 = rates['kwh_price'], rates['kg_co2_per_kwh']

    def money(kwh):
        return {'kwh': round(kwh, 2), 'cost': round(kwh * price, 2), 'kg_co2': round(kwh * co2, 2)}

    allocated = sum(r['kwh_exact'] for r in rows)
    out = {
        'enough_data': True,
        'cluster_id': cluster_id,
        'days': days,
        'snapshots_count': len(snaps),
        'rates': rates,
        'scoped': scoped,
        'coverage': {
            'window_h': days * 24,
            'covered_h': round(covered_h, 1),
            'missing_h': round(max(days * 24 - covered_h, 0.0), 1),
            # guests whose host is a guess for part of the window (history from before #965)
            'node_estimated_vms': sum(1 for r in rows if r['node_estimated']),
        },
        'top_consumers': [{k: v for k, v in r.items() if k != 'kwh_exact'} for r in rows[:10]],
        'vm_count': len(rows),
    }

    if scoped:
        by_node = {}
        for r in rows:
            for n, kwh in r['by_node'].items():
                by_node[n] = by_node.get(n, 0.0) + kwh
        total = allocated
    else:
        nodes = _cluster_nodes(cluster_managers[cluster_id])
        profiles = _get_host_profiles(cluster_id)
        by_node, hosts = {}, []
        # every host PegaProx knows, plus any that only shows up in the history
        for n in sorted(set(nodes) | set(res['hosts'])):
            h = res['hosts'].get(n) or {'kwh': 0.0, 'kwh_unallocated': 0.0, 'online_h': 0.0}
            idle, mx, custom = _host_profile(n, profiles, rates)
            by_node[n] = h['kwh']
            hosts.append({
                'node': n,
                'status': (nodes.get(n) or {}).get('status', 'unknown'),
                'profile': 'host' if custom else 'cluster',
                'idle_w': idle, 'max_w': mx,
                'online_h': round(h['online_h'], 1),
                # what the estimate says it drew at the wall on average, before PUE -
                # the number to hold a power meter against
                'avg_w': round(h['kwh'] * 1000.0 / rates['pue'] / h['online_h'], 1)
                         if h['online_h'] and rates['pue'] else 0.0,
                'monthly': money(h['kwh'] * factor),
                'monthly_unallocated': money(h['kwh_unallocated'] * factor),
            })
        total = sum(h['kwh'] for h in res['hosts'].values())
        out['hosts'] = hosts
        out['allocated'] = {'window': money(allocated), 'monthly': money(allocated * factor)}
        out['unallocated'] = {'window': money(total - allocated), 'monthly': money((total - allocated) * factor)}

    out['window'] = money(total)
    out['monthly'] = money(total * factor)
    out['by_node'] = {n: money(kwh * factor) for n, kwh in by_node.items()}
    out.update(stamp)
    return jsonify(out)


@bp.route('/api/clusters/<cluster_id>/power/per-vm', methods=['GET'])
@require_auth(perms=['cluster.view'])
def per_vm(cluster_id):
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'cluster not found'}), 404
    days = _days_arg()
    rates, _snaps, res, scoped_rows, _scoped, stamp = _report(cluster_id, days)
    if res is None:
        return jsonify({'enough_data': False, 'rates': rates, 'rows': []})
    factor = _monthly_factor(res['covered_h'])
    rows = []
    for r in scoped_rows:
        r = dict(r)  # the result is shared with the next request
        kwh = r.pop('kwh_exact', r['kwh']) * factor
        r['monthly_kwh'] = round(kwh, 2)
        r['monthly_cost'] = round(kwh * rates['kwh_price'], 2)
        r['monthly_co2'] = round(kwh * rates['kg_co2_per_kwh'], 2)
        rows.append(r)
    return jsonify({'enough_data': True, 'cluster_id': cluster_id, 'days': days,
                    'rates': rates, 'rows': rows, **stamp})


# ── #965 per-host power profiles ─────────────────────────────────────────

_NODE_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9.\-]{0,62}$')
_MAX_HOST_W = 100000.0


@bp.route('/api/clusters/<cluster_id>/power/hosts', methods=['GET'])
@require_auth(perms=['cluster.view'])
def list_host_profiles(cluster_id):
    """Every host of the cluster with the power profile it is costed with."""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    # the profiles are whole-host settings; a confined caller sees their guests' share only
    _cerr = require_unconfined(cluster_id)
    if _cerr:
        return _cerr
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'cluster not found'}), 404
    rates = _get_rates(cluster_id)
    profiles = _get_host_profiles(cluster_id)
    nodes = _cluster_nodes(cluster_managers[cluster_id])
    hosts = []
    # a profile of a host that has left the cluster stays listed, so it can be removed
    for n in sorted(set(nodes) | set(profiles)):
        nd = nodes.get(n) or {}
        p = profiles.get(n)
        idle, mx, custom = _host_profile(n, profiles, rates)
        hosts.append({
            'node': n,
            'in_cluster': n in nodes,
            'status': nd.get('status', 'unknown'),
            'cores': nd.get('maxcpu') or 0,
            'memory_gb': round((nd.get('maxmem') or 0) / _GIB, 1),
            'profile': 'host' if custom else 'cluster',
            'idle_w': idle, 'max_w': mx,
            'notes': p['notes'] if p else '',
            'updated_at': p['updated_at'] if p else None,
            'updated_by': p['updated_by'] if p else '',
        })
    return jsonify({'cluster_id': cluster_id,
                    'cluster_profile': {'idle_w': rates['node_idle_w'], 'max_w': rates['node_max_w']},
                    'hosts': hosts})


def _cluster_name(cluster_id):
    name = getattr(getattr(cluster_managers.get(cluster_id), 'config', None), 'name', None)
    return name if isinstance(name, str) and name else cluster_id


def _host_write_gate(cluster_id, node):
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    # the profile prices a whole host for every tenant on it - same rule as the tariff
    _cerr = require_unconfined(cluster_id)
    if _cerr:
        return _cerr
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'cluster not found'}), 404
    if not _NODE_RE.match(node or ''):
        return jsonify({'error': 'invalid node name'}), 400
    return None


@bp.route('/api/clusters/<cluster_id>/power/hosts/<node>', methods=['PUT'])
@require_auth(perms=['cluster.config'])
def upsert_host_profile(cluster_id, node):
    gate = _host_write_gate(cluster_id, node)
    if gate:
        return gate
    if node not in _cluster_nodes(cluster_managers[cluster_id]):
        return jsonify({'error': 'node is not part of this cluster'}), 404
    body = request.get_json(silent=True) or {}
    try:
        idle = float(body.get('idle_w'))
        mx = float(body.get('max_w'))
    except (TypeError, ValueError):
        return jsonify({'error': 'idle_w and max_w must be numeric'}), 400
    if not (math.isfinite(idle) and math.isfinite(mx)) or idle < 0 or mx > _MAX_HOST_W:
        return jsonify({'error': f'watts must be between 0 and {int(_MAX_HOST_W)}'}), 400
    if mx < idle:
        return jsonify({'error': 'max_w must not be below idle_w'}), 400
    notes = str(body.get('notes') or '').strip()[:500]
    try:
        c = get_db().conn.cursor()
        c.execute('''INSERT INTO power_host_profiles
            (cluster_id, node, idle_w, max_w, notes, updated_at, updated_by)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cluster_id, node) DO UPDATE SET
                idle_w=excluded.idle_w,
                max_w=excluded.max_w,
                notes=excluded.notes,
                updated_at=excluded.updated_at,
                updated_by=excluded.updated_by
        ''', (cluster_id, node, idle, mx, notes, datetime.now().isoformat(), _current_user()))
        get_db().conn.commit()
        log_audit(_current_user(), 'power.host_profile_set',
                  f'Power profile for host {node}: {idle:g} W idle, {mx:g} W full load',
                  cluster=_cluster_name(cluster_id), cluster_id=cluster_id)
        return jsonify({'ok': True, 'node': node, 'idle_w': idle, 'max_w': mx, 'notes': notes})
    except Exception:
        logging.exception('upsert power host profile')
        return jsonify({'error': 'internal error'}), 500


@bp.route('/api/clusters/<cluster_id>/power/hosts/<node>', methods=['DELETE'])
@require_auth(perms=['cluster.config'])
def delete_host_profile(cluster_id, node):
    """Drop a host's own profile - it inherits the cluster's again."""
    gate = _host_write_gate(cluster_id, node)
    if gate:
        return gate
    try:
        c = get_db().conn.cursor()
        c.execute('DELETE FROM power_host_profiles WHERE cluster_id=? AND node=?', (cluster_id, node))
        get_db().conn.commit()
        removed = c.rowcount > 0
        if removed:
            log_audit(_current_user(), 'power.host_profile_removed',
                      f'Power profile for host {node} removed, it uses the cluster rates again',
                      cluster=_cluster_name(cluster_id), cluster_id=cluster_id)
        return jsonify({'ok': True, 'removed': removed})
    except Exception:
        logging.exception('delete power host profile')
        return jsonify({'error': 'internal error'}), 500
