# -*- coding: utf-8 -*-
"""
PegaProx Cross-Cluster Replication Scheduler - Layer 7
Background thread that runs snapshot-based replication jobs on schedule.

MK: Feb 2026 - cron-like scheduler for cross-cluster replication.
The actual replication logic lives in api/vms.py (_execute_replication),
this just decides *when* to call it based on the schedule field.
"""

import time
import logging
import threading
from datetime import datetime

from pegaprox.core.db import get_db

logger = logging.getLogger('pegaprox.xcrepl')

_xcrepl_thread = None
_xcrepl_running = False

# MK May 2026 (#455 @DarmokNoob) — track jobs that are mid-flight so the
# scheduler doesn't fire a duplicate while the previous run is still going.
# Manual-trigger endpoint consults the same set to return 409 on collision.
# (Set + lock live here because both the loop and the API blueprint need them.)
_xcrepl_inflight = set()
_xcrepl_inflight_lock = threading.Lock()


def is_job_inflight(job_id):
    """True if the given replication job is currently executing."""
    with _xcrepl_inflight_lock:
        return job_id in _xcrepl_inflight


def _claim_job(job_id):
    """Atomically claim a job for execution. Returns False if already running."""
    with _xcrepl_inflight_lock:
        if job_id in _xcrepl_inflight:
            return False
        _xcrepl_inflight.add(job_id)
        return True


def _release_job(job_id):
    with _xcrepl_inflight_lock:
        _xcrepl_inflight.discard(job_id)


def _tracked_run(handler, job):
    """Wrapper that releases the in-flight slot when the handler returns or raises."""
    try:
        handler(job)
    finally:
        _release_job(job['id'])


def _parse_interval_seconds(schedule):
    """
    Parse a cron-like schedule into an interval in seconds.

    LW: We only need the common patterns here since the UI only offers
    a handful of presets. Full cron parsing would be overkill.

    Supported:
      '0 */N * * *'  -> every N hours
      '*/N * * * *'  -> every N minutes
      '0 H * * *'    -> daily at hour H (treated as 24h interval)
    """
    parts = schedule.strip().split()
    if len(parts) != 5:
        return 6 * 3600  # fallback: 6h

    minute, hour = parts[0], parts[1]

    # every N hours: '0 */6 * * *'
    if hour.startswith('*/'):
        try:
            n = int(hour[2:])
            return max(n, 1) * 3600
        except ValueError:
            return 6 * 3600

    # every N minutes: '*/30 * * * *'
    if minute.startswith('*/'):
        try:
            n = int(minute[2:])
            return max(n, 5) * 60  # minimum 5 min to be safe
        except ValueError:
            return 6 * 3600

    # fixed daily: '0 2 * * *' -> 24h
    if hour.isdigit() and minute.isdigit():
        return 24 * 3600

    # anything else -> 6h default
    return 6 * 3600


def _xcrepl_loop():
    """Main loop - checks enabled jobs every 60s."""
    global _xcrepl_running
    _xcrepl_running = True

    # NS: lazy import to avoid circular dependency at module load time
    from pegaprox.api.vms import _execute_replication, _execute_local_replication

    while _xcrepl_running:
        try:
            db = get_db()
            jobs = db.query('SELECT * FROM cross_cluster_replications WHERE enabled = 1')

            if jobs:
                now = time.time()
                for job in jobs:
                    job = dict(job)
                    interval = _parse_interval_seconds(job.get('schedule', '0 */6 * * *'))
                    last_run = job.get('last_run', '')

                    # figure out seconds since last run
                    if last_run:
                        try:
                            last_dt = datetime.fromisoformat(last_run)
                            elapsed = now - last_dt.timestamp()
                        except (ValueError, TypeError):
                            elapsed = interval + 1  # force run if parse fails
                    else:
                        elapsed = interval + 1  # never ran before -> run now

                    if elapsed >= interval:
                        # MK May 2026 (#455) — skip the tick if this job is still
                        # running from a previous fire. Real-world LXC migrations
                        # take 2-5 min, our tick is 60s, without this guard the
                        # second run kills the first via cleanup of the "stale"
                        # target replica.
                        if not _claim_job(job['id']):
                            logger.debug(f"[XCREPL] Job {job['id']} (VM {job['vmid']}) still in-flight, skipping this tick")
                            continue

                        # NS: same-cluster uses local replication (no remote-migrate)
                        is_local = job.get('source_cluster') == job.get('target_cluster')
                        handler = _execute_local_replication if is_local else _execute_replication
                        logger.info(f"[XCREPL] Scheduling {'local' if is_local else 'cross-cluster'} job {job['id']} (VM {job['vmid']})")
                        try:
                            # run in own thread so one slow job doesn't block others
                            threading.Thread(
                                target=_tracked_run,
                                args=(handler, job),
                                daemon=True
                            ).start()
                        except Exception as e:
                            logger.error(f"[XCREPL] Failed to start job {job['id']}: {e}")
                            _release_job(job['id'])  # didn't actually start, free the slot

        except Exception as e:
            logger.error(f"[XCREPL] Scheduler loop error: {e}")

        time.sleep(60)


def start_cross_cluster_replication_thread():
    global _xcrepl_thread
    if _xcrepl_thread is None or not _xcrepl_thread.is_alive():
        _xcrepl_thread = threading.Thread(target=_xcrepl_loop, daemon=True)
        _xcrepl_thread.start()
        logging.info("Cross-cluster replication scheduler started")


def stop_cross_cluster_replication_thread():
    global _xcrepl_running
    _xcrepl_running = False
