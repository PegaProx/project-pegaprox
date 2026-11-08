# -*- coding: utf-8 -*-
"""Recovery assurance: how much of what matters is proven recoverable, and what is missing.

Built on the recovery report (core/recovery.py): per guest the last passed restore test, what
it checked, the newest backup. This module adds

  criticality   a guest is critical when it carries one of the cluster's critical tags
                (recovery_targets, cluster row, critical_tags; default 'critical').
  proof         a guest is 'proven' when a restore test passed within the period AND its
                guest agent check passed AND at least one application check (a port or the
                check command) passed. Anything else, a guest nothing is known of included,
                is 'not_proven'. A manual confirmation never changes that.
  gaps          what keeps a guest from being proven, plus Site Recovery plans whose target
                cluster cannot be reached or that leave a member guest without replication.
  confirmations an admin's note per guest (recovery_confirmations), kept and shown apart.
  evidence      the facts above per guest, automatic ones apart from confirmations, signed
                with the field key and tied to the head of the audit chain.

MK Oct 2026
"""

import hashlib
import hmac
import json
import time
import uuid
from datetime import datetime

from pegaprox.constants import PEGAPROX_VERSION
from pegaprox.core import recovery
from pegaprox.core.db import get_db

GAPS_MAX = 2000                # gaps one response lists; the counts cover all
CONFIRM_TEXT_MAX = 500
CONFIRM_DAYS_MAX = 3650
CONFIRM_ROWS_MAX = 20000
EVIDENCE_FORMAT = 'pegaprox-recovery-evidence/1'
_SIG_DOMAIN = b'pegaprox-recovery-evidence\x00'

GAP_KINDS = ('restore_failing', 'app_failing', 'agent_failing', 'never_tested', 'no_agent_check',
             'no_app_checks', 'rto_missed', 'test_stale', 'backup_old', 'no_backup',
             'plan_target_unreachable', 'plan_no_replication')


# ---------------------------------------------------------------------------
# proof and gaps per guest
# ---------------------------------------------------------------------------

def _passed(checks, kinds):
    return any(isinstance(c, dict) and c.get('check') in kinds and c.get('ok') is True for c in checks or [])


def assess(rows, settings):
    """Annotate the rows of recovery.cluster_report in place: critical, agent_ok, app_ok,
    proof, missing (what a proven guest would have) and gaps (kinds, see GAP_KINDS)."""
    crit = set(settings.get('critical_tags') or [])
    for r in rows:
        checks = r.get('last_checks') or []
        state = r['state']
        in_period = bool(r.get('last_success_at')) and state in ('ok', 'rto_missed')
        agent_ok = in_period and _passed(checks, ('agent',))
        app_ok = in_period and _passed(checks, ('port', 'command'))
        missing = []
        if not in_period:
            missing.append('restore_test')
        if not agent_ok:
            missing.append('agent_check')
        if not app_ok:
            missing.append('application_check')
        cause = (r.get('last_failure_cause') or '').lower()
        gaps = []
        if state == 'failing':
            if cause.startswith(('port ', 'check command')):
                gaps.append('app_failing')
            elif cause.startswith('guest agent'):
                gaps.append('agent_failing')
            else:
                gaps.append('restore_failing')
        elif state == 'never' and r['rpo_state'] != 'no_backup':
            gaps.append('never_tested')
        elif state == 'stale':
            gaps.append('test_stale')
        elif state == 'rto_missed':
            gaps.append('rto_missed')
        if r.get('last_success_at') and state != 'failing':
            if not _passed(checks, ('agent',)):
                gaps.append('no_agent_check')
            if not _passed(checks, ('port', 'command')):
                gaps.append('no_app_checks')
        if r['rpo_state'] == 'breached':
            gaps.append('backup_old')
        elif r['rpo_state'] == 'no_backup':
            gaps.append('no_backup')
        r['critical'] = bool(crit & set(r.get('tags') or []))
        r['agent_ok'], r['app_ok'] = agent_ok, app_ok
        r['proof'] = 'proven' if not missing else 'not_proven'
        r['missing'] = missing
        r['gaps'] = gaps
    return rows


def coverage(rows):
    """Share of guests proven, over the critical ones and over all of them. A row that was not
    assessed counts as not proven."""
    def part(sel):
        total = len(sel)
        proven = sum(1 for r in sel if r.get('proof') == 'proven')
        return {'total': total, 'proven': proven, 'not_proven': total - proven,
                'percent': round(100.0 * proven / total, 1) if total else None}
    return {'critical': part([r for r in rows if r.get('critical')]), 'all': part(list(rows))}


def gap_list(rows, cluster_label=None):
    """(gaps, counts, truncated): one entry per guest and kind, worst kinds first."""
    order = {k: i for i, k in enumerate(GAP_KINDS)}
    found = []
    for r in rows:
        for k in r.get('gaps') or []:
            found.append({'kind': k, 'vmid': r['vmid'], 'name': r.get('name') or '',
                          'critical': bool(r.get('critical')),
                          'cluster_id': r.get('cluster_id'),
                          'cluster_name': r.get('cluster_name') or cluster_label})
    counts = {}
    for g in found:
        counts[g['kind']] = counts.get(g['kind'], 0) + 1
    found.sort(key=lambda g: (order.get(g['kind'], 99), not g['critical'], g['vmid']))
    return found[:GAPS_MAX], counts, len(found) > GAPS_MAX


def plan_gaps(cluster_id, state_of, reaches=None):
    """Gaps of the Site Recovery plans that protect guests of `cluster_id`, from what is
    stored and the connection state of the clusters: `state_of(cluster_id)` returns 'ok',
    'offline' or 'missing'; `reaches(cluster_id)`, when given, leaves out the plans whose
    target it says no to. Returns [{'kind', 'plan_id', 'plan', 'vmid', ...}]; a plan whose
    target cannot be reached has one gap without a vmid."""
    conn = get_db().conn
    out = []
    plans = conn.execute('SELECT id, name, target_cluster FROM site_recovery_plans WHERE source_cluster = ? '
                         'LIMIT 1000', (cluster_id,)).fetchall()
    for p in plans:
        pid, name, target = p['id'], p['name'], p['target_cluster']
        if reaches is not None and not reaches(target):
            continue
        st = state_of(target)
        if st != 'ok':
            out.append({'kind': 'plan_target_unreachable', 'plan_id': pid, 'plan': name, 'vmid': None,
                        'target_cluster': target, 'detail': 'target cluster ' + ('is not connected' if st == 'offline'
                                                                              else 'does not exist')})
        for v in conn.execute("SELECT vmid, vm_name FROM site_recovery_vms WHERE plan_id = ? "
                              "AND COALESCE(replication_job_id, '') = '' LIMIT 5000", (pid,)).fetchall():
            out.append({'kind': 'plan_no_replication', 'plan_id': pid, 'plan': name, 'vmid': int(v['vmid']),
                        'name': v['vm_name'] or '', 'target_cluster': target,
                        'detail': 'no replication job for this guest'})
    return out


# ---------------------------------------------------------------------------
# manual confirmations
# ---------------------------------------------------------------------------

def _conf_view(r, now):
    exp = r['expires_at']
    return {'id': r['id'], 'cluster_id': r['cluster_id'], 'vmid': int(r['vmid']), 'text': r['text'],
            'confirmed_by': r['confirmed_by'], 'confirmed_at': recovery._iso(r['confirmed_at']),
            'expires_at': recovery._iso(exp), 'revoked_at': recovery._iso(r['revoked_at']),
            'revoked_by': r['revoked_by'] or None,
            'active': r['revoked_at'] is None and (exp is None or exp > now)}


def load_confirmations(cluster_id, now=None):
    """{vmid: newest active confirmation} of one cluster. Raises when the table cannot be read."""
    now = time.time() if now is None else now
    rows = get_db().conn.execute(
        'SELECT * FROM recovery_confirmations WHERE cluster_id = ? AND revoked_at IS NULL '
        'AND (expires_at IS NULL OR expires_at > ?) ORDER BY confirmed_at DESC LIMIT ?',
        (cluster_id, now, CONFIRM_ROWS_MAX)).fetchall()
    # newest first: past the cap the oldest drop out, and each guest keeps its newest
    out = {}
    for r in rows:
        out.setdefault(int(r['vmid']), _conf_view(r, now))
    return out


def clean_confirmation(body, now=None):
    """(fields, None) or (None, why it is refused). expires_days is optional."""
    now = time.time() if now is None else now
    if not isinstance(body, dict):
        return None, 'the request body must be a JSON object'
    unknown = sorted(k for k in body if k not in ('vmid', 'text', 'expires_days'))
    if unknown:
        return None, f"not a field here: {', '.join(unknown)}"
    vmid = recovery._whole(body.get('vmid'), 100, 999999999)
    if vmid is None:
        return None, 'vmid is the ID of a guest'
    text = body.get('text')
    if not isinstance(text, str) or not text.strip() or len(text.strip()) > CONFIRM_TEXT_MAX \
            or recovery._CTRL_RE.search(text.replace('\n', ' ')):
        return None, f'text says what was confirmed, up to {CONFIRM_TEXT_MAX} characters'
    expires = None
    if body.get('expires_days') not in (None, ''):
        days = recovery._whole(body['expires_days'], 1, CONFIRM_DAYS_MAX)
        if days is None:
            return None, f'expires_days is a whole number from 1 to {CONFIRM_DAYS_MAX}'
        expires = now + days * 86400
    return {'vmid': vmid, 'text': text.strip(), 'expires_at': expires}, None


def add_confirmation(cluster_id, fields, user, now=None):
    now = time.time() if now is None else now
    conn = get_db().conn
    cid = uuid.uuid4().hex[:16]
    conn.execute('INSERT INTO recovery_confirmations (id, cluster_id, vmid, text, confirmed_by, '
                 'confirmed_at, expires_at) VALUES (?,?,?,?,?,?,?)',
                 (cid, cluster_id, fields['vmid'], fields['text'], str(user or '')[:64], now,
                  fields['expires_at']))
    conn.commit()
    return cid


def revoke_confirmation(cluster_id, conf_id, user, now=None):
    """The confirmation that was revoked, None when there was no such open one."""
    now = time.time() if now is None else now
    conn = get_db().conn
    row = conn.execute('SELECT * FROM recovery_confirmations WHERE id = ? AND cluster_id = ? '
                       'AND revoked_at IS NULL', (conf_id, cluster_id)).fetchone()
    if row is None:
        return None
    conn.execute('UPDATE recovery_confirmations SET revoked_at = ?, revoked_by = ? WHERE id = ?',
                 (now, str(user or '')[:64], conf_id))
    conn.commit()
    return _conf_view(dict(row, revoked_at=now, revoked_by=str(user or '')[:64]), now)


# ---------------------------------------------------------------------------
# evidence: facts per guest, signed, tied to the audit chain
# ---------------------------------------------------------------------------

def passed_runs(cluster_id):
    """{vmid: (run id, completed_at)} of the newest passed restore test per guest that this
    instance ran; the history is local, a guest tested elsewhere has none here."""
    out = {}
    try:
        rows = get_db().conn.execute(
            "SELECT id, vmid, completed_at FROM backup_verifications WHERE cluster_id = ? "
            "AND status = 'passed' ORDER BY started_at DESC LIMIT 50000", (cluster_id,)).fetchall()
    except Exception:
        return out
    for r in rows:
        out.setdefault(int(r['vmid']), (r['id'], r['completed_at']))
    return out


def evidence_guest(r, marks, runs, confirmation):
    """One guest of the evidence: automatic facts and manual confirmation, kept apart."""
    mark = (marks or {}).get(r['vmid']) or {}
    run = (runs or {}).get(r['vmid'])
    checks = [{'check': c.get('check'), 'target': c.get('target') if c.get('check') == 'port' else '',
               'ok': c.get('ok')} for c in (r.get('last_checks') or []) if isinstance(c, dict)]
    return {
        'cluster_id': r.get('cluster_id'), 'vmid': r['vmid'], 'name': r.get('name') or '',
        'type': r.get('type'), 'critical': bool(r.get('critical')),
        'proof': r.get('proof', 'not_proven'), 'missing': r.get('missing') or [],
        'gaps': r.get('gaps') or [],
        'automatic': {
            'last_test': {'run_id': mark.get('last_task') or None, 'at': r.get('last_test_at'),
                          'result': r.get('last_result')},
            'last_success': {'run_id': run[0] if run else None, 'at': r.get('last_success_at'),
                             'backup_at': r.get('tested_backup_at'),
                             'measured_seconds': r.get('measured_seconds'),
                             'rto_seconds': r.get('rto_seconds'), 'rto_state': r.get('rto_state'),
                             'checks': checks} if r.get('last_success_at') else None,
            'last_failure': {'at': r.get('last_failure_at'), 'cause': r.get('last_failure_cause')}
                            if r.get('last_failure_at') else None,
            'newest_backup_at': r.get('newest_backup_at'), 'sla_hours': r.get('sla_hours'),
            'rpo_state': r.get('rpo_state'),
        },
        'manual': {'confirmation': confirmation},
    }


def _canonical(doc):
    body = {k: v for k, v in doc.items() if k != 'signature'}
    return json.dumps(body, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def sign(doc):
    """Set doc['signature'] (HMAC-SHA256 with the field key over the rest of the document).
    Without a key the document says so and carries no signature value."""
    key = get_db().aes_key
    if not key:
        doc['signature'] = {'alg': 'HMAC-SHA256', 'value': None}
        return doc
    doc['signature'] = {'alg': 'HMAC-SHA256',
                        'value': hmac.new(key, _SIG_DOMAIN + _canonical(doc), hashlib.sha256).hexdigest()}
    return doc


def verify(doc):
    """{'signature_valid', 'audit_chain'}: whether this instance signed the document as it
    stands, and whether the chain head it names is in this instance's audit chain
    ('present', 'absent' or 'none' when the document names none). The latter says the
    evidence belongs to this audit log, not that it is current."""
    if not isinstance(doc, dict) or doc.get('format') != EVIDENCE_FORMAT:
        return None
    sig = doc.get('signature') if isinstance(doc.get('signature'), dict) else {}
    key = get_db().aes_key
    value = sig.get('value')
    # the block is the one part the signature does not cover: a note in it, or another
    # algorithm named, came out of here as valid (as for the flight recorder bundle)
    valid = bool(key and isinstance(value, str) and set(sig) == {'alg', 'value'}
                 and sig['alg'] == 'HMAC-SHA256'
                 and hmac.compare_digest(value, hmac.new(key, _SIG_DOMAIN + _canonical(doc),
                                                         hashlib.sha256).hexdigest()))
    head = doc.get('audit_head') if isinstance(doc.get('audit_head'), dict) else None
    chain = 'none'
    if head and head.get('chain_seq') is not None:
        chain = 'present' if get_db().audit_chain_has(head.get('chain_seq'), head.get('hash') or '') else 'absent'
    return {'signature_valid': valid, 'audit_chain': chain}


def verify_body(raw):
    """verify() for a body as it was sent, None when it is no JSON object. MK Oct 2026 -
    parsed with the flight recorder's check for a key that appears twice: request.get_json
    keeps the last one, so a coverage put in front of the signed one verified while a
    reader that keeps the first (or anyone reading the file) saw it."""
    from pegaprox.core.flight_recorder import _once, _Twice
    try:
        doc = json.loads(raw, object_pairs_hook=_once)
    except _Twice:
        return {'signature_valid': False, 'audit_chain': 'none',
                'reason': 'a key appears twice in one object, so what a reader sees need not be what was signed'}
    except (ValueError, RecursionError):
        return None
    return verify(doc)


def build_evidence(scope_kind, scope_id, days, clusters, rows, gaps, plan_gap_rows, cov, confined=False):
    """The evidence document, signed. `rows` are assessed rows each with the evidence_guest
    entry under row['_evidence'] (the caller has scoped them already). confined: the caller
    sees only some guests of the scope, and the signed scope says so."""
    scope = {'kind': scope_kind, 'id': scope_id}
    if confined:
        scope['confined'] = True
    doc = {
        'format': EVIDENCE_FORMAT,
        'generated_at': datetime.now().isoformat(timespec='seconds'),
        'pegaprox_version': PEGAPROX_VERSION,
        'scope': scope,
        'period_days': days,
        'clusters': clusters,
        'coverage': cov,
        'gaps': gaps,
        'plan_gaps': plan_gap_rows,
        'guests': [r['_evidence'] for r in rows],
        'audit_head': get_db().audit_chain_head(),
        'notes': ['automatic holds what PegaProx measured, manual what an administrator confirmed; '
                  'a confirmation does not make a guest proven',
                  'verify with POST /api/recovery-evidence/verify on the instance that '
                  'signed it; a field key rotation voids earlier signatures'],
    }
    return sign(doc)


EVIDENCE_CSV_COLUMNS = ('cluster', 'vmid', 'name', 'critical', 'proof', 'missing', 'gaps', 'last_test_run',
                        'last_test_at', 'last_success_run', 'last_success_at', 'rpo_state',
                        'manual_confirmation', 'manual_by', 'manual_at', 'manual_expires')


def evidence_csv(doc):
    import csv
    import io
    from pegaprox.utils.sanitization import sanitize_csv_field as san
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(('# format', doc['format'], 'generated_at', doc['generated_at'], 'version',
                doc['pegaprox_version'], 'audit_chain_seq', (doc.get('audit_head') or {}).get('chain_seq', ''),
                'audit_hash', (doc.get('audit_head') or {}).get('hash', ''),
                'signature', (doc.get('signature') or {}).get('value') or ''))
    w.writerow(EVIDENCE_CSV_COLUMNS)
    for g in doc['guests']:
        a, c = g['automatic'], g['manual']['confirmation'] or {}
        ok = a['last_success'] or {}
        w.writerow([san(g['cluster_id'] or ''), g['vmid'], san(g['name']), g['critical'], g['proof'],
                    ' '.join(g['missing']), ' '.join(g['gaps']), a['last_test']['run_id'] or '',
                    a['last_test']['at'] or '', ok.get('run_id') or '', ok.get('at') or '',
                    a['rpo_state'] or '', san(c.get('text') or ''), san(c.get('confirmed_by') or ''),
                    c.get('confirmed_at') or '', c.get('expires_at') or ''])
    return buf.getvalue()
