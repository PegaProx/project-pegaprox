# -*- coding: utf-8 -*-
"""
PegaProx Concurrency Helpers - Layer 2
"""

import os
import logging
from typing import Dict

GEVENT_AVAILABLE = False
GEVENT_PATCHED = False
GEVENT_POOL = None

# NS 2026-06-05 — env-tunable (was hard 50). Default raised to 100 now that
# managers reuse keep-alive sessions (#528): the fd pressure that forced 100→50
# on the old fresh-session-per-call model is gone since connections are pooled.
_NODE_POOL_SIZE = int(os.environ.get('PEGAPROX_NODE_POOL_SIZE', '100'))
try:
    from gevent.pool import Pool as GeventPool
    GEVENT_POOL = GeventPool(size=_NODE_POOL_SIZE)
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



# ============================================
# asyncio interop under gevent
# ============================================

def gevent_to_thread(fn, /, *args, **kwargs):
    """asyncio.to_thread equivalent that actually delivers under gevent.

    Under monkey.patch_all() the worker that asyncio.to_thread and
    loop.run_in_executor rely on is a greenlet, not an OS thread, and the loop
    only observes the finished future once some unrelated timer wakes it.
    Measured on Python 3.14 with gevent: a call doing 1s of work resolved after
    exactly the caller's timeout (8.01s via to_thread, and via run_in_executor
    with both the default and an explicit ThreadPoolExecutor), while a plain
    greenlet plus loop.call_soon_threadsafe resolved in 1.00s. So the wake-up
    path is intact and only the executor path is broken.

    Same contract as asyncio.to_thread: returns an awaitable, keeps the event
    loop free (verified: 95 loop iterations during a 1s blocking call) and
    preserves concurrency (5 parallel TLS handshakes in 0.05s).
    """
    import asyncio

    if not GEVENT_PATCHED:
        return asyncio.to_thread(fn, *args, **kwargs)

    import gevent

    loop = asyncio.get_running_loop()
    future = loop.create_future()

    def _runner():
        try:
            result = fn(*args, **kwargs)
        except BaseException as exc:  # noqa: BLE001 - relayed to the awaiter
            loop.call_soon_threadsafe(
                lambda e=exc: None if future.done() else future.set_exception(e))
        else:
            loop.call_soon_threadsafe(
                lambda r=result: None if future.done() else future.set_result(r))

    gevent.spawn(_runner)
    return future


_TO_THREAD_INSTALLED = False


def install_gevent_to_thread():
    """Route asyncio.to_thread through gevent_to_thread when gevent is patched.

    The console proxy offloads every PVE-side socket call with
    asyncio.to_thread; under gevent none of them ever deliver, so the handshake
    burns its connect timeout instead of connecting and the browser reports a
    timed-out console. Replacing the function once is what gevent itself does
    to socket and threading, and it covers every call site without touching
    them. No-op without gevent, and safe to call more than once.
    """
    global _TO_THREAD_INSTALLED
    if _TO_THREAD_INSTALLED or not GEVENT_PATCHED:
        return False

    import asyncio

    asyncio.to_thread = gevent_to_thread
    _TO_THREAD_INSTALLED = True
    logging.info("asyncio.to_thread routed through gevent (executor path is "
                 "unreliable under monkey-patched threading)")
    return True
