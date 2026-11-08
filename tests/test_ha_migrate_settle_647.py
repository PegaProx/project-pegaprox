"""An HA migrate that reported failure was judged before the guest had moved (#647).

`ha-manager migrate` exits once the CRM has accepted the request, not once the guest
has relocated. The recovery check — "the task failed, but did it move anyway?" — ran
the instant the task returned, so it read the guest still sitting on its source node
and declared a failed evacuation for a migration that then completed fine.

From the report: migration started 09:24:06.904, task failed 09:24:10.957. Four
seconds. The operator saw "Failed to evacuate" on a host that had in fact drained,
and that had been happening on roughly half the hosts of every rolling update. MK
"""
import time

import pytest

from pegaprox.constants import HA_MIGRATE_SETTLE_SECONDS, HA_MIGRATE_SETTLE_POLL


def test_the_settle_window_outlasts_the_reported_gap():
    """Four seconds in the report; anything near that is not a window at all."""
    assert HA_MIGRATE_SETTLE_SECONDS >= 30
    assert HA_MIGRATE_SETTLE_POLL <= 5
    assert HA_MIGRATE_SETTLE_SECONDS / HA_MIGRATE_SETTLE_POLL >= 5, "too few looks to matter"


def _reload_with(monkeypatch, **env):
    import importlib
    import pegaprox.constants as c
    for k in ('PEGAPROX_HA_MIGRATE_SETTLE', 'PEGAPROX_HA_MIGRATE_SETTLE_POLL'):
        monkeypatch.delenv(k, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    importlib.reload(c)
    return c


@pytest.fixture(autouse=True)
def _restore_constants():
    yield
    import importlib
    import pegaprox.constants as c
    importlib.reload(c)


def test_both_are_tunable_from_the_environment(monkeypatch):
    """A cluster with a slower CRM must be able to widen this without a patch."""
    c = _reload_with(monkeypatch, PEGAPROX_HA_MIGRATE_SETTLE='210',
                     PEGAPROX_HA_MIGRATE_SETTLE_POLL='7')
    assert c.HA_MIGRATE_SETTLE_SECONDS == 210
    assert c.HA_MIGRATE_SETTLE_POLL == 7


def test_a_typo_does_not_stop_the_service_from_starting(monkeypatch):
    """These are read at import time. A bare float() would raise there, so
    PEGAPROX_HA_MIGRATE_SETTLE=90s wouldn't misconfigure the settle window — it would
    stop PegaProx booting at all, which is a poor trade for a stray unit."""
    c = _reload_with(monkeypatch, PEGAPROX_HA_MIGRATE_SETTLE='90s')
    assert c.HA_MIGRATE_SETTLE_SECONDS == 90.0


def test_an_empty_value_falls_back(monkeypatch):
    """Half-written unit files and `Environment=VAR=` both produce this."""
    c = _reload_with(monkeypatch, PEGAPROX_HA_MIGRATE_SETTLE='')
    assert c.HA_MIGRATE_SETTLE_SECONDS == 90.0


def test_a_zero_poll_cannot_become_a_busy_loop(monkeypatch):
    """The poll is slept on inside the settle loop. A 0 there would turn a 90-second
    window into 90 seconds of asking /cluster/resources as fast as it answers."""
    c = _reload_with(monkeypatch, PEGAPROX_HA_MIGRATE_SETTLE_POLL='0')
    assert c.HA_MIGRATE_SETTLE_POLL >= 0.5


def test_a_negative_poll_is_clamped_too(monkeypatch):
    c = _reload_with(monkeypatch, PEGAPROX_HA_MIGRATE_SETTLE_POLL='-5')
    assert c.HA_MIGRATE_SETTLE_POLL >= 0.5


def test_an_absurd_window_is_capped(monkeypatch):
    """Nobody meant to hold an evacuation open for eleven days."""
    c = _reload_with(monkeypatch, PEGAPROX_HA_MIGRATE_SETTLE='999999')
    assert c.HA_MIGRATE_SETTLE_SECONDS <= 3600


def _settle(seen_nodes, source, deadline_s, poll_s, now):
    """The loop as written in manager.py, lifted so it can be driven deterministically."""
    actual = None
    deadline = now() + deadline_s
    while True:
        actual = seen_nodes.pop(0) if seen_nodes else actual
        if actual and actual != source:
            break
        if now() >= deadline:
            break
        time.sleep(poll_s)
    return actual


def test_a_guest_that_moves_late_is_still_counted_as_evacuated(monkeypatch):
    monkeypatch.setattr(time, 'sleep', lambda *_: None)
    clock = {'t': 0.0}
    def now():
        clock['t'] += 3
        return clock['t']
    # still on pve3 for three looks, then the CRM finishes and it shows up on pve2
    got = _settle(['pve3', 'pve3', 'pve3', 'pve2'], 'pve3', 90, 3, now)
    assert got == 'pve2'


def test_a_guest_that_never_moves_is_still_a_failure(monkeypatch):
    """The window must not turn genuine failures into successes."""
    monkeypatch.setattr(time, 'sleep', lambda *_: None)
    clock = {'t': 0.0}
    def now():
        clock['t'] += 10
        return clock['t']
    got = _settle(['pve3'] * 50, 'pve3', 90, 3, now)
    assert got == 'pve3', "a guest that stayed put must not be reported as evacuated"


def test_the_loop_terminates_even_if_the_lookup_keeps_failing(monkeypatch):
    """A cluster that stops answering must not hang the evacuation forever."""
    monkeypatch.setattr(time, 'sleep', lambda *_: None)
    clock = {'t': 0.0}
    def now():
        clock['t'] += 10
        return clock['t']
    got = _settle([], 'pve3', 90, 3, now)   # lookup never yields anything
    assert got is None


def test_the_recovery_path_is_wired_into_the_evacuation():
    """Guards the call site: the settle loop has to sit in the task-failed branch,
    not somewhere the happy path reaches."""
    import ast, io
    src = io.open('pegaprox/core/manager.py', encoding='utf-8').read()
    tree = ast.parse(src)

    # the function holding the recovery log line — find it by the message, not by
    # string offsets. (An index() on the constant name finds the IMPORT first, which
    # is how the first version of this test passed for the wrong reason.)
    def _mentions(node, text):
        return any(isinstance(n, ast.Constant) and isinstance(n.value, str) and text in n.value
                   for n in ast.walk(node))

    owners = [n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef)
              and _mentions(n, 'Migration task reported failure')]
    assert owners, "the recovery branch is gone"
    fn = owners[0]
    names = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name)}
    assert 'HA_MIGRATE_SETTLE_SECONDS' in names, \
        f"the settle window is not used inside {fn.name} — the check is immediate again"


@pytest.mark.parametrize('raw', ['nan', 'NaN', 'inf', '-inf', 'Infinity'])
def test_a_non_finite_value_cannot_hang_the_settle_loop(monkeypatch, raw):
    """float() accepts all of these. NaN is the dangerous one: every comparison against
    it is False, so it walks through a `val < lo or val > hi` range check untouched, and
    `time.time() + nan` is nan — which makes the loop's `time.time() >= deadline` false
    forever. The evacuation would never return and would poll the cluster until the
    process died, in the very change meant to poll more patiently."""
    import math
    c = _reload_with(monkeypatch, PEGAPROX_HA_MIGRATE_SETTLE=raw,
                     PEGAPROX_HA_MIGRATE_SETTLE_POLL=raw)
    assert math.isfinite(c.HA_MIGRATE_SETTLE_SECONDS)
    assert math.isfinite(c.HA_MIGRATE_SETTLE_POLL)
    assert c.HA_MIGRATE_SETTLE_POLL >= 0.5


def test_a_nan_window_would_have_produced_an_endless_deadline():
    """Pins why the guard above exists, so nobody removes it as paranoia."""
    import math, time
    deadline = time.time() + float('nan')
    assert math.isnan(deadline)
    assert not (time.time() >= deadline), "the loop's only exit would never fire"
