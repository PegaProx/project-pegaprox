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

            # Capture whatever finished within `timeout` (an unfinished greenlet isn't
            # successful() → None) BEFORE reaping, so the result never depends on kill timing.
            results = []
            for g in greenlets:
                try:
                    results.append(g.value if g.successful() else None)
                except Exception as e:
                    logging.error(f"Concurrent task failed: {e}")
                    results.append(None)

            # #777 (Frisch12) — reap stragglers. joinall returns at `timeout` but leaves any
            # unfinished greenlets RUNNING in the shared GEVENT_POOL; their results are already
            # discarded above, yet each keeps holding a pool slot, so every later fan-out through
            # this pool (including ones issued from request handlers) queues behind work nobody will
            # read — until the pool is full and the whole instance stalls. The caller has given up at
            # `timeout`, so kill the unfinished ones and hand their slots back.
            for g in greenlets:
                if not g.ready():
                    g.kill(block=False)
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
            # #777 — NB: deliberately NOT reaping stragglers here. run_per_node uses a LOCAL,
            # bounded pool (not the shared GEVENT_POOL that caused the outage), so a straggler
            # can't exhaust the request pool; and some callers (multi_sdn writes) do remote
            # mutations under this fan-out where a GreenletExit mid-write could orphan objects
            # the atomic rollback can't see. A straggler here just completes or times out on its
            # own SSH/TCP deadline. The shared-pool reap lives in run_concurrent above.
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
# asyncio <-> gevent interop for the in-process console (noVNC) proxy — MK Aug 2026 (#740)
# ============================================
#
# The VNC console runs an asyncio websocket server inside the gevent worker. Under
# monkey.patch_all() on Python >= 3.13, two things break: websockets.serve() never binds, and the
# offloaded PVE socket calls (asyncio.to_thread) never deliver, so the handshake burns
# VNC_PVE_CONNECT_TIMEOUT instead of connecting. These helpers work around both; all no-ops when
# gevent isn't patched in, and py<=3.12 (which binds and offloads natively) is left untouched.

def gevent_to_thread(fn, *args, **kwargs):
    """asyncio.to_thread that actually delivers under gevent. The executor worker asyncio.to_thread
    relies on is a greenlet under monkey.patch_all(), and the loop only observes the finished future
    when an unrelated timer wakes it. Run fn in a greenlet and hand the result back via
    call_soon_threadsafe, which does wake the loop. Same awaitable contract; straight through to the
    stdlib when gevent isn't patched in."""
    import asyncio
    if not GEVENT_PATCHED:
        return asyncio.to_thread(fn, *args, **kwargs)

    import gevent
    loop = asyncio.get_running_loop()
    future = loop.create_future()

    def _run():
        try:
            result = fn(*args, **kwargs)
        except BaseException as exc:  # relayed to the awaiter, not swallowed
            loop.call_soon_threadsafe(lambda e=exc: future.done() or future.set_exception(e))
        else:
            loop.call_soon_threadsafe(lambda v=result: future.done() or future.set_result(v))

    gl = gevent.spawn(_run)
    # a caller that times out / is cancelled must not leave the blocking call running behind it
    future.add_done_callback(lambda f: gl.kill(block=False) if f.cancelled() else None)
    return future


_TO_THREAD_INSTALLED = False


def install_gevent_to_thread():
    """Point asyncio.to_thread at gevent_to_thread process-wide — the same trick gevent uses on
    socket/threading, so every console call site is covered without being touched. Gated to Python
    3.13+, where the executor path is actually broken; py<=3.12 delivers natively and is left alone.
    Idempotent, no-op without gevent. Call once after monkey.patch_all()."""
    global _TO_THREAD_INSTALLED
    import sys
    if _TO_THREAD_INSTALLED or not GEVENT_PATCHED or sys.version_info < (3, 13):
        return False
    import asyncio
    asyncio.to_thread = gevent_to_thread
    _TO_THREAD_INSTALLED = True
    logging.info("[console] asyncio.to_thread routed through gevent (executor path unreliable under "
                 "monkey-patched threading on Python >= 3.13)")
    return True


def gevent_listen_socket(host, port, backlog=100):
    """A bound, non-blocking listening socket built from the ORIGINAL (un-patched) socket, ready to
    hand to websockets.serve(sock=...). Works around websockets.serve() not binding under gevent on
    Python >= 3.13. An empty host binds dual-stack IPv6 (also serving IPv4), matching asyncio's
    bind-all default; a given host resolves its own family."""
    import socket
    try:
        from gevent.monkey import get_original
        sock_cls = get_original('socket', 'socket')
    except Exception:
        sock_cls = socket.socket

    if not host:
        try:
            sock = sock_cls(socket.AF_INET6, socket.SOCK_STREAM)
            try:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            except OSError:
                pass
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('', port))
        except OSError:
            try:
                sock.close()
            except Exception:
                pass
            sock = sock_cls(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('0.0.0.0', port))
    else:
        family = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)[0][0]
        sock = sock_cls(family, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))

    sock.listen(backlog)
    sock.setblocking(False)
    return sock

