# -*- coding: utf-8 -*-
"""The evidence bundle of the flight recorder: a time window of the timeline, the audit rows
of it and where the audit chain stood, signed so that a changed copy shows.

NS Oct 2026 - the signature is the HMAC of the recovery evidence (core/assurance.py) with the
same field key, but over a domain of its own: a recovery evidence document never verifies
as a bundle, and a bundle never verifies as one of those, whatever its format field says.
"""

import hashlib
import hmac
import json
from datetime import timedelta

from pegaprox.core import timeline as tl
from pegaprox.core.assurance import _canonical
from pegaprox.core.db import get_db

FORMAT = 'pegaprox-flight-recorder'
VERSION = 1
EVENTS_MAX = 20000
AUDIT_MAX = 20000
CLUSTERS_MAX = 50
_SIG_DOMAIN = b'pegaprox-flight-recorder\x00'
# what of an audit row leaves with the bundle: the stored signature stays on the instance
_AUDIT_COLUMNS = ('id', 'timestamp', 'user', 'action', 'details', 'ip_address', 'cluster', 'cluster_id',
                  'severity', 'chain_seq', 'prev_hash')


def _mac(key, doc):
    return hmac.new(key, _SIG_DOMAIN + _canonical(doc), hashlib.sha256).hexdigest()


def sign(doc):
    """Set doc['signature']. Without a field key the document says so and carries no value."""
    key = get_db().aes_key
    doc['signature'] = {'alg': 'HMAC-SHA256', 'value': _mac(key, doc) if key else None}
    return doc


def verify(doc):
    """{'valid', 'reason'}: whether this instance signed the bundle as it stands. None when
    the body is no JSON object at all."""
    if not isinstance(doc, dict):
        return None
    if doc.get('format') != FORMAT:
        return {'valid': False, 'reason': 'not a flight recorder bundle'}
    sig = doc.get('signature') if isinstance(doc.get('signature'), dict) else {}
    value = sig.get('value')
    if not isinstance(value, str) or not value:
        return {'valid': False, 'reason': 'the bundle carries no signature'}
    # the block is the one part the signature does not cover: a note in it, or another
    # algorithm named, would come out of here under "valid"
    if set(sig) != {'alg', 'value'} or sig['alg'] != 'HMAC-SHA256':
        return {'valid': False, 'reason': 'the signature block is not the one this instance writes'}
    key = get_db().aes_key
    if not key:
        return {'valid': False, 'reason': 'this instance has no signing key'}
    try:
        good = hmac.compare_digest(value, _mac(key, doc))
    except (TypeError, ValueError):
        good = False
    if not good:
        return {'valid': False, 'reason': 'the signature does not match: the bundle was changed, or '
                                          'another instance (or key) signed it'}
    return {'valid': True, 'reason': 'signed by this instance and unchanged'}


class _Twice(ValueError):
    pass


def _once(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise _Twice(k)
        out[k] = v
    return out


def verify_body(raw):
    """verify() for a body as it was sent, None when it is no JSON object.

    NS Oct 2026 - parsed here, not with request.get_json: that keeps the last of two equal
    keys, so a forged value put in front of the signed one verified, while a reader that
    keeps the first one (or anyone reading the file) saw the forged one."""
    try:
        doc = json.loads(raw, object_pairs_hook=_once)
    except _Twice:
        return {'valid': False, 'reason': 'a key appears twice in one object, so what a reader sees '
                                          'need not be what was signed'}
    except (ValueError, RecursionError):
        return None
    return verify(doc)


def audit_rows(cluster_ids, since, until, cap=None):
    """(rows, truncated): the audit rows of the window that belong to one of `cluster_ids`,
    oldest first, as stored (with the signature, see public_rows). One more than `cap` is
    read to tell whether the rest was cut."""
    cap = AUDIT_MAX if cap is None else cap
    ids = list(cluster_ids)
    if not ids:
        return [], False
    lo, hi = tl.bound(since), tl.bound(until + timedelta(seconds=1))
    marks = ','.join('?' * len(ids))
    rows = get_db().query(
        f'SELECT * FROM audit_log WHERE cluster_id IN ({marks}) AND timestamp >= ? AND timestamp < ? '
        f'ORDER BY timestamp, id LIMIT ?', (*ids, lo, hi, cap + 1))
    rows = [dict(r) for r in rows]
    return rows[:cap], len(rows) > cap


def public_rows(rows):
    return [{k: r.get(k) for k in _AUDIT_COLUMNS} for r in rows]


def chain_report(rows):
    """The audit chain as the bundle states it: the head now, and for the rows exported
    their own signatures, the links between neighbours and the walk of the chain over the
    stretch they come from (the existing verification, bounded to that stretch)."""
    db = get_db()
    head = db.audit_chain_head()
    out = {'head': head, 'rows': len(rows), 'first_seq': None, 'last_seq': None,
           'rows_verified': 0, 'rows_failed': 0, 'links_checked': 0, 'links_broken': 0, 'walk': None}
    for r in rows:
        if db._verify_audit_hmac(r):
            out['rows_verified'] += 1
        else:
            out['rows_failed'] += 1
    chained = sorted((r for r in rows if r.get('chain_seq') is not None), key=lambda r: r['chain_seq'])
    prev = None
    for r in chained:
        if prev is not None and r['chain_seq'] == prev['chain_seq'] + 1:
            out['links_checked'] += 1
            if (r.get('prev_hash') or '') != db._audit_row_hash(prev):
                out['links_broken'] += 1
        prev = r
    if chained:
        out['first_seq'], out['last_seq'] = chained[0]['chain_seq'], chained[-1]['chain_seq']
        if head:
            span = max(1, int(head['chain_seq']) - int(out['first_seq']) + 1)
            res = db.verify_audit_log_integrity(limit=span)
            ch = res.get('chain') or {}
            out['walk'] = {'intact': bool(res.get('intact')), 'scanned_rows': ch.get('rows'),
                           'edited': ch.get('edited'), 'missing': ch.get('missing'),
                           'broken_links': ch.get('broken_links'), 'truncated': ch.get('truncated')}
    return out
