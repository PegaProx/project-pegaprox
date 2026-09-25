"""A limiter keyed by something the caller picks must not be a way to exhaust us.

Seven of these were written out longhand in the tree, and they shared two problems.

The obvious one: the map is keyed by a remote IP, a username, an (ip, cluster) pair -
values the caller chooses - and entries were only ever added. An IPv6 /64 costs nothing,
so a rotating source grows the map until the process dies. The thing meant to protect
the service was the way to take it down.

The subtler one is what makes a naive fix useless. app.py had grown a sweep that fired
whenever the map passed a threshold and removed only EXPIRED windows. Keep the map just
above the threshold with LIVE windows and every single request does a full scan that
frees nothing: O(n) per request with n still climbing. That is a better attack than the
one the sweep was added to stop.

Aikido ai_pentest 700489071 / 700487897 / 700489681. MK
"""
import time

import pytest

from pegaprox.utils.ratelimit import SlidingWindow


# --- the budget it is actually for -------------------------------------------------

def test_requests_inside_the_budget_are_allowed():
    w = SlidingWindow(limit=3, window=60)

    assert [w.allow('a') for _ in range(3)] == [True, True, True]


def test_the_one_over_the_budget_is_not():
    w = SlidingWindow(limit=3, window=60)
    for _ in range(3):
        w.allow('a')

    assert w.allow('a') is False


def test_keys_do_not_share_a_budget():
    w = SlidingWindow(limit=1, window=60)
    w.allow('a')

    assert w.allow('b') is True


def test_the_window_slides():
    w = SlidingWindow(limit=1, window=0.05)
    assert w.allow('a') is True
    assert w.allow('a') is False
    time.sleep(0.08)

    assert w.allow('a') is True


def test_a_refusal_does_not_extend_the_lockout():
    """Counting refused attempts into the window would let an attacker keep a real user
    locked out forever by hammering them."""
    w = SlidingWindow(limit=2, window=0.05)
    w.allow('a'); w.allow('a')
    for _ in range(20):
        w.allow('a')                      # all refused
    time.sleep(0.08)

    assert w.allow('a') is True


# --- the attack --------------------------------------------------------------------

def test_rotating_keys_cannot_grow_the_map():
    w = SlidingWindow(limit=100, window=60, max_keys=64)

    for i in range(5000):
        w.allow(f'2001:db8::{i}')

    assert len(w) <= 64, f'{len(w)} keys retained from 5000 distinct sources'


def test_the_ceiling_holds_even_with_every_window_live():
    """Expiry-only sweeping is what failed before: none of these have expired."""
    w = SlidingWindow(limit=100, window=3600, max_keys=32)

    for i in range(2000):
        w.allow(f'ip-{i}')

    assert len(w) <= 32


def test_eviction_takes_the_least_recently_seen():
    """An evicted key just starts its window again, so drop the ones least likely to be
    a real caller mid-burst."""
    w = SlidingWindow(limit=100, window=3600, max_keys=3)
    for k in ('old1', 'old2', 'old3'):
        w.allow(k)
        time.sleep(0.005)
    w.allow('old3')                        # refresh it
    time.sleep(0.005)
    for i in range(10):
        w.allow(f'new-{i}')

    assert 'old1' not in w._hits


def test_the_sweep_does_not_run_on_every_call():
    """The quadratic half of the finding: a size-triggered sweep scans the whole map per
    request and frees nothing when nothing has expired."""
    w = SlidingWindow(limit=10_000, window=30, max_keys=100_000)
    sweeps = []
    real = w._sweep
    w._sweep = lambda now: (sweeps.append(now), real(now))[1]

    for i in range(5000):
        w.allow(f'ip-{i % 200}')

    assert len(sweeps) <= 2, f'{len(sweeps)} sweeps for 5000 calls'


def test_a_brand_new_key_over_the_ceiling_is_collected_at_once():
    """The clock sweep can be a whole window away; the ceiling must not drift up in
    the meantime."""
    w = SlidingWindow(limit=100, window=3600, max_keys=10)

    for i in range(200):
        w.allow(f'ip-{i}')

    assert len(w) <= 11, len(w)


# --- housekeeping ------------------------------------------------------------------

def test_reset_forgets_one_key():
    w = SlidingWindow(limit=1, window=60)
    w.allow('a')
    w.reset('a')

    assert w.allow('a') is True


def test_reset_forgets_everything():
    w = SlidingWindow(limit=1, window=60)
    w.allow('a'); w.allow('b')
    w.reset()

    assert len(w) == 0


# --- the call sites ----------------------------------------------------------------

@pytest.mark.parametrize('module,attr', [
    ('pegaprox.api.auth', '_setup_attempts_by_ip'),
    ('pegaprox.api.clusters', '_location_put_attempts'),
    ('pegaprox.globals', 'api_rate_window'),
])
def test_the_longhand_limiters_are_gone(module, attr):
    import importlib
    obj = getattr(importlib.import_module(module), attr)

    assert isinstance(obj, SlidingWindow), f'{module}.{attr} is still a {type(obj).__name__}'


def test_the_api_limiter_is_the_shared_one():
    """app.py had its own copy of the sweep; the stats endpoint counted the old dict."""
    import inspect
    import pegaprox.app as app

    body = inspect.getsource(app._check_api_rate_limit)
    assert 'api_rate_window.allow(' in body
    assert 'api_request_counts' not in body


# --- the auth-action limiter (found by the 19.09. scan, not by the first sweep) ------

def test_the_auth_action_limiter_is_bounded():
    """check_auth_action_rate_limit was the ninth copy and the only one reachable
    WITHOUT a session: /api/webauthn/auth/begin keys it by raw client IP. A rotating
    source therefore grew the map for free, which is the exact thing SlidingWindow
    exists to stop.

    Deliberately measured as a PROPERTY of the module rather than by reaching for a
    known attribute: the first version of this asserted on the new store's name, so it
    went red against the old code with an AttributeError instead of on the leak, which
    proves nothing about the leak."""
    import pegaprox.utils.ssh as sshmod

    def retained():
        """Total keys the module is holding, whatever it keeps them in."""
        total = 0
        for value in vars(sshmod).values():
            if isinstance(value, dict):
                for inner in list(value.values()) + [value]:
                    if isinstance(inner, SlidingWindow):
                        total += len(inner)
                if value and all(isinstance(v, list) for v in value.values()):
                    total += len(value)          # the longhand key -> [timestamps] map
        return total

    before = retained()
    for n in range(9000):
        sshmod.check_auth_action_rate_limit(f'webauthn_begin:2001:db8::{n:x}',
                                            max_attempts=20, window=300)

    grew_by = retained() - before
    assert grew_by < 9000, (
        f'9000 distinct anonymous keys added {grew_by} retained entries - the limiter '
        'still grows without bound')


def test_the_budget_itself_is_unchanged():
    """Tightening the store must not tighten the policy - the callers rely on these
    exact budgets (5/300 for password change, 3/120 for TOTP, 20/300 for webauthn)."""
    import pegaprox.utils.ssh as sshmod
    sshmod._auth_action_windows.clear()

    assert all(sshmod.check_auth_action_rate_limit('pwd_change:bob', 5, 300)
               for _ in range(5))
    assert not sshmod.check_auth_action_rate_limit('pwd_change:bob', 5, 300)
    # a different principal is untouched
    assert sshmod.check_auth_action_rate_limit('pwd_change:alice', 5, 300)


def test_the_buckets_do_not_bleed_into_each_other():
    """Three call sites, three (max_attempts, window) pairs. A TOTP attempt must not
    spend the password-change budget for the same username."""
    import pegaprox.utils.ssh as sshmod
    sshmod._auth_action_windows.clear()

    for _ in range(3):
        sshmod.check_auth_action_rate_limit('totp_verify:bob', 3, 120)
    assert not sshmod.check_auth_action_rate_limit('totp_verify:bob', 3, 120)
    assert sshmod.check_auth_action_rate_limit('pwd_change:bob', 5, 300)


def test_the_shadowed_global_is_gone():
    """ssh.py imported _auth_action_attempts from globals and then redefined it one
    screen later, so the two names pointed at different dicts and utils/auth.py held a
    reference to the dead one. Nothing should import it any more."""
    import pegaprox.utils.ssh as sshmod

    assert not hasattr(sshmod, '_auth_action_attempts')


def test_the_bucket_registry_is_bounded_too():
    """Found by the 20.09. scan, on the fix from the 19.09. scan. The registry is keyed
    by the budget the CALLER passes, and each entry owns a 4096-key window - so a call
    site that ever derives a budget from a request leaks worse than the map this
    replaced. All four call sites pass literals today; the ceiling makes that structural
    rather than a convention the next person has to notice."""
    import pegaprox.utils.ssh as sshmod

    sshmod._auth_action_windows.clear()
    for n in range(200):
        sshmod.check_auth_action_rate_limit('someone', max_attempts=5, window=60 + n)

    # Deliberately NOT asserted against the new ceiling constant by name: that makes the
    # test go red against the old code with an AttributeError, which says nothing about
    # the leak. Same mistake as the sibling test above, caught the same way.
    held = len(sshmod._auth_action_windows)
    assert held < 200, (
        f'200 distinct budgets left {held} windows behind - the registry grows with '
        'whatever the caller asks for, and each entry owns a 4096-key window')


def test_the_real_call_sites_still_get_their_own_window():
    """The ceiling must not start evicting the budgets we actually use - three pairs,
    well under it."""
    import pegaprox.utils.ssh as sshmod

    sshmod._auth_action_windows.clear()
    sshmod.check_auth_action_rate_limit('pwd_change:bob', 5, 300)
    sshmod.check_auth_action_rate_limit('totp_verify:bob', 3, 120)
    sshmod.check_auth_action_rate_limit('webauthn_begin:1.2.3.4', 20, 300)

    assert set(sshmod._auth_action_windows) == {(5, 300), (3, 120), (20, 300)}


def test_the_integration_harness_starts_each_test_with_a_clean_window(api):
    """The harness looks like ONE client to a limiter budgeted at 1200 requests per
    60 seconds, and nothing used to clear it between tests. A long run therefore
    spent the budget partway through and every later integration test failed with a
    429 instead of whatever it was asserting — which is how Testing CI went red on
    ae8674d while the same tree was green on a slower machine. The `api` fixture now
    resets it; this pins that so the next person to grow the suite does not spend an
    afternoon on it. MK"""
    import pegaprox.globals as ppglobals
    assert len(ppglobals.api_rate_window) == 0
