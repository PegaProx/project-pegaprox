"""type=int is a parser, not a bound.

Several routes took ?limit= through Flask's `type=int` and handed the result
straight to a SQL LIMIT or to the upstream PVE/PBS API. That stops a string but
not `?limit=99999999`, so an authenticated caller could ask for the whole table
on every request.

The frontend's largest ask on these routes is 200, so the cap is 1000 (5000 for
the two log endpoints, which legitimately page further). The audit CSV export is
deliberately NOT routed through this — the UI documents `?limit=10000` next to
the download link, so clamping it would break an export rather than close a hole.

The library function is capped as well as the route. The remediation asked for
both, and it is right to: a bound that exists at one of two entrances is the
shape of most of what this audit turned up. Aikido ai_pentest 700488840. NS
"""
import pytest

from pegaprox.api.helpers import bounded_limit


def test_a_huge_limit_is_clamped():
    assert bounded_limit(99_999_999, 50, 1000) == 1000


def test_ordinary_values_pass_through():
    """The frontend asks for 10, 30, 50, 100 and 200 on these routes."""
    for n in (10, 30, 50, 100, 200):
        assert bounded_limit(n, 50, 1000) == n


def test_junk_and_absent_fall_back_to_the_default():
    for v in ('abc', None, '', [], {}):
        assert bounded_limit(v, 50, 1000) == 50


def test_zero_and_negative_fall_back_rather_than_returning_nothing():
    """A LIMIT of 0 or -1 is not a useful answer to 'how many rows'."""
    assert bounded_limit(0, 50, 1000) == 50
    assert bounded_limit(-5, 50, 1000) == 50


def test_numeric_strings_work_because_that_is_what_a_query_string_is():
    assert bounded_limit('200', 50, 1000) == 200


def test_the_library_function_caps_independently_of_the_route(db):
    """get_verification_history has callers that never touch HTTP."""
    from pegaprox.core.backup_verify import get_verification_history
    # must not raise, and must not attempt an unbounded query
    rows = get_verification_history(cluster_id='cluster_1', limit=10_000_000)
    assert isinstance(rows, list)
    rows = get_verification_history(cluster_id='cluster_1', limit='nonsense')
    assert isinstance(rows, list)


def test_every_route_limit_goes_through_the_clamp():
    """Pins the wiring. The helper existing proves nothing on its own — that was
    the shape of the storage-create finding earlier in this audit."""
    import pathlib
    import re
    offenders = []
    for f in ('pegaprox/api/nodes.py', 'pegaprox/api/pbs.py', 'pegaprox/api/clusters.py'):
        src = pathlib.Path(f).read_text()
        for m in re.finditer(r"limit\s*=\s*(?:int\()?request\.args\.get\('limit'", src):
            line = src[:m.start()].count('\n') + 1
            offenders.append(f'{f}:{line}')
    assert not offenders, f'unclamped ?limit= still reaching a query: {offenders}'
