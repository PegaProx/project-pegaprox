# -*- coding: utf-8 -*-
"""
PegaProx Concurrency Helpers - Layer 2
"""

import logging
from typing import Dict

GEVENT_AVAILABLE = False
GEVENT_PATCHED = False
GEVENT_POOL = None

try:
    from gevent.pool import Pool as GeventPool
    GEVENT_POOL = GeventPool(size=50)
    GEVENT_AVAILABLE = True
    # Check if gevent has actually monkey-patched the socket module
    import gevent.monkey
    GEVENT_PATCHED = gevent.monkey.is_module_patched('socket')
except ImportError:
    pass

def get_paramiko():
    """lazy import for paramiko, its optional"""
    # MK: paramiko takes forever to import so we only do it when needed
    try:
        import paramiko
        return paramiko
    except ImportError:
        return None


# ============================================
# Concurrent API Helpers - added late 2025
# Use gevent pool for parallel requests when available
# MK: This made the dashboard like 5x faster, totally worth it
# ============================================

def run_concurrent(tasks: list, timeout: float = 30.0) -> list:
    """Run tasks concurrently with gevent pool"""
    # NS: chatgpt helped with this one, i was mass confused about greenlets
    # TODO: maybe add retry logic? - MK
    #
    # MK 2026-05-31 — CRITICAL FIX. The original check `if GEVENT_POOL and
    # GEVENT_AVAILABLE` was always-False on entry: gevent.pool.Pool overrides
    # __bool__ to len() == 0. So every call silently fell through to the
    # sequential branch from day one. The "5x faster" comment above was
    # aspiration, not reality. Switching to `is not None` actually wires up
    # the parallel path the helper was designed for.
    if not tasks:
        return []

    if GEVENT_POOL is not None and GEVENT_AVAILABLE:
        # Use gevent pool for concurrent execution
        try:
            greenlets = [GEVENT_POOL.spawn(task) for task in tasks]
            # Wait for all with timeout
            from gevent import joinall
            joinall(greenlets, timeout=timeout)
            
            results = []
            for g in greenlets:
                try:
                    results.append(g.value if g.successful() else None)
                except Exception as e:
                    logging.error(f"Concurrent task failed: {e}")
                    results.append(None)
            return results
        except Exception as e:
            logging.error(f"Concurrent execution failed: {e}")
            # Fall through to sequential execution
    
    # Fallback: sequential execution (when gevent not available)
    results = []
    for task in tasks:
        try:
            results.append(task())
        except Exception as e:
            logging.error(f"Task failed: {e}")
            results.append(None)
    return results


def run_concurrent_dict(tasks: dict, timeout: float = 30.0) -> dict:
    """same as run_concurrent but takes/returns a dict of {key: callable} -> {key: result}"""
    if not tasks:
        return {}
    
    keys = list(tasks.keys())
    callables = [tasks[k] for k in keys]
    results = run_concurrent(callables, timeout)
    
    return dict(zip(keys, results))


# MK: exponential backoff helper for retryable SSH/API ops
# used by predictive analysis engine and cross-cluster sync
def retry_with_backoff(fn, max_retries=3, base_delay=0.5, jitter=True):
    """Retry a callable with exponential backoff. Returns (success, result)."""
    import time, random
    last_err = None
    for attempt in range(max_retries):
        try:
            result = fn()
            return True, result
        except Exception as e:
            last_err = e
            delay = base_delay * (2 ** attempt)
            if jitter:
                delay += random.uniform(0, delay * 0.3)
            # NS: don't log first attempt failure, its noisy
            if attempt > 0:
                logging.debug(f"retry_with_backoff attempt {attempt+1}/{max_retries}: {e}")
            time.sleep(delay)
    return False, last_err


# NS Apr 2026 — SSH-aware multi-node fanout for big clusters (15+ nodes).
# Bounded concurrency so we don't open 30 simultaneous SSH connections (which
# triggers AccountLockFailures on hardened nodes — we hit this on ESXi already).
#
# CRITICAL: This helper is for NEW multi-node fanouts only (custom-scripts on
# many nodes, hardening-multi, compliance-dashboard backend aggregation).
# HA SSH paths (HA monitor, fence operations, evacuation) MUST NOT go through
# this — they have their own latency requirements and bypass any throttle.
# That's why it lives next to run_concurrent and not in ssh.py.
#
# Uses gevent pool (size-bounded) when gevent is available, otherwise falls
# back to a thread pool with a Semaphore.
def run_per_node(node_callables, max_concurrent=8, timeout=120):
    """Fan out per-node callables with bounded concurrency.

    Args:
        node_callables: dict {node_name: callable(node_name) -> any}
        max_concurrent: hard ceiling on parallel SSH workers (default 8).
            Tuned conservatively — going higher than 8 risks per-host SSH
            rate-limits on busier nodes. Per-cluster, NOT global.
        timeout: per-task wall-clock timeout in seconds.

    Returns:
        dict {node_name: result_or_None}. Failed/timed-out tasks return None,
        the exception is logged at debug level.
    """
    if not node_callables:
        return {}
    # Cap concurrency at the lesser of node count and max_concurrent
    n = len(node_callables)
    workers = max(1, min(int(max_concurrent), n))

    # Path 1: gevent pool — preferred since pegaprox is gevent-monkey-patched
    if GEVENT_AVAILABLE:
        try:
            from gevent.pool import Pool as GP
            pool = GP(size=workers)
            jobs = {}
            for node, fn in node_callables.items():
                # bind node name into the closure so the callable receives it
                jobs[node] = pool.spawn(_run_node_safe, node, fn)
            from gevent import joinall
            joinall(list(jobs.values()), timeout=timeout)
            results = {}
            for node, g in jobs.items():
                try:
                    results[node] = g.value if g.successful() else None
                except Exception as e:
                    logging.debug(f"run_per_node[{node}] failed: {e}")
                    results[node] = None
            return results
        except Exception as e:
            logging.warning(f"run_per_node gevent path failed, falling back: {e}")

    # Path 2: stdlib threading + Semaphore — fallback when gevent isn't available
    import threading
    sem = threading.BoundedSemaphore(workers)
    results = {}
    threads = []
    lock = threading.Lock()

    def _worker(node, fn):
        with sem:
            r = _run_node_safe(node, fn)
        with lock:
            results[node] = r

    for node, fn in node_callables.items():
        t = threading.Thread(target=_worker, args=(node, fn), daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join(timeout=timeout)
    # Any thread still alive after timeout → that node is None
    for node in node_callables:
        results.setdefault(node, None)
    return results


def _run_node_safe(node, fn):
    """Internal wrapper: invoke fn(node), swallow exceptions, return result or None."""
    try:
        return fn(node)
    except Exception as e:
        logging.debug(f"_run_node_safe[{node}] exception: {e}")
        return None

