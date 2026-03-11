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
    if not tasks:
        return []
    
    if GEVENT_POOL and GEVENT_AVAILABLE:
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

