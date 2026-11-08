"""The two things that make a console drop, and the mouse feel wrong.

Mouse: the #713 lock funnels SSL_read and SSL_write through one mutex, and the
reader's recv slice is what stops it starving the writer. At 50ms that slice was
also the worst-case delay an outbound pointer event inherited — on an idle screen
nothing arrives to cut the wait short, so motion arrived in 50ms steps.

Drops: the greenlet pool issues up to PEGAPROX_NODE_POOL_SIZE node calls at once,
but the HTTPS keep-alive pool was hardcoded at 64. With pool_block=False the
excess opens a throwaway connection that can never be returned, so every sweep
left (fanout - 64) fresh TLS handshakes on the node's pveproxy — and the VNC
session rides that same pveproxy. Measured: exactly 36 at 100-way fan-out. MK
"""
import pytest


def test_the_relay_slice_is_short_enough_for_pointer_input():
    from pegaprox.constants import VNC_PVE_RECV_SLICE

    assert VNC_PVE_RECV_SLICE <= 0.015, (
        f'{VNC_PVE_RECV_SLICE*1000:.0f}ms of input lag is visible as pointer jitter')
    assert VNC_PVE_RECV_SLICE > 0, 'a zero slice busy-waits the hub'


def test_every_vnc_leg_uses_the_shared_slice():
    """Four legs carried their own copy of the number; three were plain 0.05."""
    vms = open('pegaprox/api/vms.py').read()
    poll = open('pegaprox/utils/vnc_polling.py').read()

    assert 'settimeout(0.05)' not in vms and 'settimeout(0.05)' not in poll
    assert vms.count('VNC_PVE_RECV_SLICE') >= 3
    assert 'VNC_PVE_RECV_SLICE' in poll


def test_the_https_pool_matches_the_fanout():
    """The drift between these two numbers IS the connection churn."""
    from pegaprox.core.manager import NODE_FANOUT_CONCURRENCY
    src = open('pegaprox/core/manager.py').read()

    assert 'pool_maxsize=NODE_FANOUT_CONCURRENCY' in src, 'pool_maxsize is hardcoded again'
    assert 'GeventPool(size=NODE_FANOUT_CONCURRENCY)' in src, 'the fan-out pool drifted off it'
    assert NODE_FANOUT_CONCURRENCY >= 64


def test_the_fanout_constant_honours_the_documented_env_var(monkeypatch):
    """Operators tune PEGAPROX_NODE_POOL_SIZE; both pools must follow it together."""
    import importlib, os
    monkeypatch.setenv('PEGAPROX_NODE_POOL_SIZE', '160')
    import pegaprox.core.manager as m
    importlib.reload(m)
    try:
        assert m.NODE_FANOUT_CONCURRENCY == 160
    finally:
        monkeypatch.delenv('PEGAPROX_NODE_POOL_SIZE', raising=False)
        importlib.reload(m)


def test_a_pool_smaller_than_the_fanout_really_does_churn():
    """Guards the guard: proves the mechanism the fix removes, without a server."""
    import urllib3
    pool = urllib3.HTTPConnectionPool('127.0.0.1', maxsize=2, block=False)
    conns = [pool._get_conn() for _ in range(4)]

    discarded = 0
    for c in conns:
        before = pool.pool.qsize()
        pool._put_conn(c)
        if pool.pool.qsize() == before:
            discarded += 1

    assert discarded == 2, f'expected 4-2 discards, got {discarded}'


# ── the estate-sized sweep must not hold the shared pool ─────────────────────

def test_the_ip_sweep_has_its_own_bounded_pool():
    """Every other fan-out is bounded by NODE count. This one is bounded by GUEST count —
    up to two calls per running guest — so on a 10k estate it would occupy all 100 shared
    slots for the length of the sweep, and the broadcast tick, UI requests and opening a
    console all queue behind it."""
    import inspect
    from pegaprox.core.manager import (PegaProxManager, IP_SWEEP_CONCURRENCY,
                                       NODE_FANOUT_CONCURRENCY)

    live = ''.join(inspect.getsourcelines(PegaProxManager.refresh_ip_cache)[0])
    assert 'pool=IP_SWEEP_POOL' in live, 'the sweep is back on the shared pool'
    assert 0 < IP_SWEEP_CONCURRENCY < NODE_FANOUT_CONCURRENCY, 'it must be a strict subset'


def test_run_concurrent_still_defaults_to_the_shared_pool():
    """Only the estate-sized sweep opts out; nothing else changes behaviour."""
    import inspect
    from pegaprox.core import manager as m

    src = inspect.getsource(m.run_concurrent)
    assert 'pool=None' in src
    assert '_pool = pool if pool is not None else GEVENT_POOL' in src


def test_the_sweep_pool_is_tunable(monkeypatch):
    import importlib
    monkeypatch.setenv('PEGAPROX_IP_SWEEP_CONCURRENCY', '12')
    import pegaprox.core.manager as m
    importlib.reload(m)
    try:
        assert m.IP_SWEEP_CONCURRENCY == 12
    finally:
        monkeypatch.delenv('PEGAPROX_IP_SWEEP_CONCURRENCY', raising=False)
        importlib.reload(m)


def test_no_shadowed_methods_in_the_manager_class():
    """Four methods were defined twice in PegaProxManager — the earlier copies are dead,
    and reading one of them is how the IP sweep got analysed as half its real size."""
    import ast, collections, pathlib

    tree = ast.parse(pathlib.Path('pegaprox/core/manager.py').read_text())
    shadowed = {}
    for cls in [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]:
        seen = collections.defaultdict(list)
        for fn in cls.body:
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                seen[fn.name].append(fn.lineno)
        for name, lines in seen.items():
            if len(lines) > 1:
                shadowed[f'{cls.name}.{name}'] = lines

    assert not shadowed, f'dead duplicate definitions: {shadowed}'
