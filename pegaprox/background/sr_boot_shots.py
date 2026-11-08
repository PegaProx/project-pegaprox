# Boot screenshots for the evidence of a DR test failover - MK Oct 2026
#
# A test failover clones the replicas on the target and starts the clones. Its event
# says which were started; whether each one came up is what gets asked next, and the
# answer is a picture of its console after boot. This takes one per guest with the
# grab the console tile uses (api/vms.py grab_vm_frame: screendump, one RFB frame as the
# fallback) and keeps it with the event.
#
# Bounded on every side, it runs after every test: at most SHOT_CAP guests, SHOT_PARALLEL
# at a time, SHOT_TIMEOUT each, SHOT_MAX_BYTES a picture, and the pictures of the last
# KEEP_TESTS tests of a plan. A guest that cannot be grabbed is listed with why. Nothing
# here changes the outcome of the test, which is decided before the first picture.

import io
import json
import logging
import time
from datetime import datetime, timezone

from pegaprox.core.db import get_db

logger = logging.getLogger('pegaprox.site_recovery')

SHOT_CAP = 20
SHOT_PARALLEL = 3
SHOT_TIMEOUT = 45
# how long a guest gets to boot before its picture is taken, counted from its start
BOOT_SETTLE = 60
SHOT_MAX_WIDTH = 640
SHOT_MAX_BYTES = 256 * 1024
KEEP_TESTS = 5


def booted(vm, test_vmid, vm_type, node):
    """What the test failover notes about a clone it started."""
    return {'vmid': int(vm['vmid']), 'test_vmid': int(test_vmid), 'vm_type': vm_type or 'qemu',
            'vm_name': vm.get('vm_name') or '', 'node': node, 'started': time.monotonic()}


def pending(guests):
    """What the event says while the pictures are taken. None when nothing booted."""
    if not guests:
        return None
    return {'state': 'capturing', 'cap': SHOT_CAP, 'guests': []}


def _ms(since):
    return int((time.monotonic() - since) * 1000)


def _row(g, status, reason=''):
    return {'vmid': g['vmid'], 'test_vmid': g['test_vmid'], 'vm_name': g['vm_name'],
            'status': status, 'reason': reason}


def _fit(png):
    """At most SHOT_MAX_BYTES. A busy desktop packs worse than a login prompt, so a
    picture over it is taken smaller until it fits."""
    if len(png) <= SHOT_MAX_BYTES:
        return png
    from PIL import Image
    img = Image.open(io.BytesIO(png))
    img.load()
    while len(png) > SHOT_MAX_BYTES and img.width > 160:
        img = img.resize((img.width * 3 // 4, max(1, img.height * 3 // 4)), Image.BILINEAR)
        out = io.BytesIO()
        img.save(out, format='PNG', optimize=True)
        png = out.getvalue()
    if len(png) > SHOT_MAX_BYTES:
        raise IOError(f'larger than {SHOT_MAX_BYTES // 1024} KB even at {img.width} px wide')
    return png


def _take(tgt_mgr, g):
    """One guest: wait out its boot, then at most SHOT_TIMEOUT for the picture."""
    import gevent
    from pegaprox.api.vms import grab_vm_frame
    wait = g['started'] + BOOT_SETTLE - time.monotonic()
    if wait > 0:
        time.sleep(wait)
    t0 = time.monotonic()
    # a Timeout is no Exception: grab_vm_frame's fallback cannot swallow it and start
    # the RFB leg on time that is already up
    timer = gevent.Timeout(SHOT_TIMEOUT)
    timer.start()
    try:
        png = _fit(grab_vm_frame(tgt_mgr, g['node'], 'qemu', g['test_vmid'], max_width=SHOT_MAX_WIDTH))
    except gevent.Timeout as fired:
        if fired is not timer:
            raise
        return {'status': 'failed', 'reason': f'no picture within {SHOT_TIMEOUT}s', 'ms': _ms(t0)}
    except Exception as e:
        return {'status': 'failed', 'reason': (str(e) or type(e).__name__)[:200], 'ms': _ms(t0)}
    finally:
        timer.close()
    return {'status': 'ok', 'png': png, 'bytes': len(png), 'ms': _ms(t0),
            'after_boot_s': int(time.monotonic() - g['started']),
            'captured_at': datetime.now(timezone.utc).isoformat()}


def _store(plan_id, event_id, g, row, png):
    try:
        get_db().execute(
            'INSERT OR REPLACE INTO site_recovery_screenshots '
            '(event_id, plan_id, vmid, test_vmid, captured_at, duration_ms, image) '
            'VALUES (?, ?, ?, ?, ?, ?, ?)',
            (event_id, plan_id, g['vmid'], g['test_vmid'], row.get('captured_at'),
             int(row.get('ms') or 0), png))
        return True
    except Exception as e:
        logger.warning(f"[SR] boot screenshot of test VM {g['test_vmid']} not stored: {e}")
        return False


def capture(tgt_mgr, plan_id, event_id, guests, console_vmids):
    """Take the pictures of the booted clones and keep them. `console_vmids` are the
    plan's guests the caller who started the test may see the console of; None means
    nobody said so and no picture is taken. Returns the summary for the event."""
    t0 = time.monotonic()
    allowed = {int(v) for v in (console_vmids or [])}
    proxmox = getattr(tgt_mgr, 'cluster_type', 'proxmox') == 'proxmox'
    rows, todo = [], []
    for g in guests:
        if g['vm_type'] != 'qemu':
            rows.append(_row(g, 'skipped', 'a container has no display to take'))
        elif not proxmox:
            rows.append(_row(g, 'skipped', 'screenshots need a Proxmox target'))
        elif g['vmid'] not in allowed:
            rows.append(_row(g, 'skipped', 'no console permission for this guest'))
        elif len(todo) >= SHOT_CAP:
            rows.append(_row(g, 'skipped', f'over the limit of {SHOT_CAP} per test'))
        else:
            row = _row(g, 'failed')
            rows.append(row)
            todo.append((g, row))

    if todo:
        # the fan-out helper of the multi-node reads: bounded, and each task carries the
        # job mark of the test failover (#625)
        from pegaprox.utils.concurrent import run_per_node
        tasks = {str(g['test_vmid']): (lambda _key, g=g: _take(tgt_mgr, g)) for g, _r in todo}
        rounds = -(-len(todo) // SHOT_PARALLEL)
        got = run_per_node(tasks, max_concurrent=SHOT_PARALLEL,
                           timeout=BOOT_SETTLE + rounds * SHOT_TIMEOUT + 15)
        for g, row in todo:
            res = dict(got.get(str(g['test_vmid'])) or {})
            png = res.pop('png', None)
            row.update(res or {'reason': f'no answer within {SHOT_TIMEOUT}s'})
            if png is not None and not _store(plan_id, event_id, g, row, png):
                row.update(status='failed', reason='taken but could not be stored')

    states = [r['status'] for r in rows]
    return {'state': 'done', 'taken': states.count('ok'), 'failed': states.count('failed'),
            'skipped': states.count('skipped'), 'cap': SHOT_CAP, 'parallel': SHOT_PARALLEL,
            'timeout_s': SHOT_TIMEOUT, 'settle_s': BOOT_SETTLE, 'total_ms': _ms(t0),
            'guests': rows}


def _prune(plan_id):
    """The pictures of a plan's newest KEEP_TESTS test failovers stay, older ones go."""
    try:
        get_db().execute(
            'DELETE FROM site_recovery_screenshots WHERE plan_id = ? AND event_id NOT IN '
            '(SELECT id FROM site_recovery_events WHERE plan_id = ? AND event_type = ? '
            'ORDER BY started_at DESC LIMIT ?)', (plan_id, plan_id, 'test', KEEP_TESTS))
    except Exception as e:
        logger.warning(f"[SR] old boot screenshots of plan {plan_id} not pruned: {e}")


def note(event_id, summary):
    """The summary into the event's details, next to the results it belongs to."""
    db = get_db()
    row = db.query_one('SELECT details FROM site_recovery_events WHERE id = ?', (event_id,))
    if not row:
        return
    try:
        details = json.loads(row['details'] or '{}')
    except Exception:
        details = {}
    if not isinstance(details, dict):
        details = {}
    details['screenshots'] = summary
    db.execute('UPDATE site_recovery_events SET details = ? WHERE id = ?',
               (json.dumps(details), event_id))


def run(tgt_mgr, plan_id, event_id, guests, console_vmids):
    """capture(), prune and note. Never raises: the evidence is extra, the test is done."""
    try:
        summary = capture(tgt_mgr, plan_id, event_id, guests, console_vmids)
    except Exception as e:
        logger.exception(f"[SR] boot screenshots of event {event_id} failed")
        summary = {'state': 'done', 'taken': 0, 'failed': len(guests), 'skipped': 0,
                   'cap': SHOT_CAP, 'error': (str(e) or type(e).__name__)[:200], 'guests': []}
    _prune(plan_id)
    try:
        note(event_id, summary)
    except Exception as e:
        logger.warning(f"[SR] boot screenshot summary of event {event_id} not saved: {e}")
    return summary


def load(event_id, vmid):
    """(test_vmid, png) of one guest of a test, (None, None) when there is none."""
    row = get_db().query_one('SELECT test_vmid, image FROM site_recovery_screenshots '
                             'WHERE event_id = ? AND vmid = ?', (event_id, int(vmid)))
    if not row or row['image'] is None:
        return None, None
    return row['test_vmid'], bytes(row['image'])


def mark_interrupted():
    """At boot: a test whose pictures a restart cut short says so, not 'capturing' for
    ever. The test itself had finished. Returns how many."""
    db = get_db()
    rows = db.query("SELECT id, details FROM site_recovery_events WHERE event_type = 'test' "
                    "AND details LIKE ?", ('%"state": "capturing"%',)) or []
    n = 0
    for r in rows:
        try:
            details = json.loads(r['details'] or '{}')
        except Exception:
            continue
        shots = details.get('screenshots') if isinstance(details, dict) else None
        if isinstance(shots, dict) and shots.get('state') == 'capturing':
            shots['state'] = 'interrupted'
            db.execute('UPDATE site_recovery_events SET details = ? WHERE id = ?',
                       (json.dumps(details), r['id']))
            n += 1
    return n
