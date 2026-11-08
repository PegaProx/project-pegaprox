"""An open SSE stream has to notice when a cluster is taken away.

allowed_clusters is resolved once when the stream token is minted and the stream copies it
at connect. The re-authorization tick that runs every 30 seconds already refreshed the
role and the admin flag - taking a cluster away from a tenant did nothing at all to an
open dashboard, and the frames kept arriving until the user happened to reconnect.

The list is refreshed in the same tick now, by intersection rather than replacement: the
client subscribed to a subset and that choice is theirs to keep. Widening a stream because
its owner gained a cluster is not this loop's job.

Aikido ai_pentest 700487120. MK
"""
import inspect

import pytest

import pegaprox.api.realtime as rt


def _reauthz_block():
    """The part of generate() that runs on the re-authorization tick."""
    src = inspect.getsource(rt)
    i = src.index('if time.monotonic() >= _next_authz:')
    j = src.index('except GeneratorExit:', i)
    return src[i:j]


def test_the_tick_refreshes_the_cluster_set():
    body = _reauthz_block()
    assert 'get_user_clusters(' in body, 'the cluster scope is still never re-resolved'


# --- the narrowing rule itself, as behaviour ---------------------------------

def test_a_lost_cluster_leaves_the_stream():
    assert rt.narrow_stream_scope(['a', 'b'], ['a']) == ['a']


def test_the_clients_own_subset_is_not_widened():
    """Their owner gained cluster c; the client did not ask for it and does not get it."""
    assert rt.narrow_stream_scope(['a'], ['a', 'b', 'c']) == ['a']


def test_an_unrestricted_owner_leaves_the_subset_alone():
    """None means admin. Replacing with None here would turn a two-cluster dashboard
    into an all-cluster one mid-stream."""
    assert rt.narrow_stream_scope(['a', 'b'], None) == ['a', 'b']


def test_a_previously_unrestricted_stream_becomes_restricted():
    """Demoted from admin while watching: the stream has to narrow to what is left."""
    assert rt.narrow_stream_scope(None, ['a']) == ['a']


def test_an_unresolvable_scope_empties_the_stream():
    """[] is what the caller passes when the lookup failed. Could-not-tell is not
    permission - and an empty result closes the stream one line later."""
    assert rt.narrow_stream_scope(['a', 'b'], []) == []


def test_losing_everything_gives_an_empty_list_not_none():
    """None would read as 'unrestricted' to every consumer of this field."""
    assert rt.narrow_stream_scope(['a'], ['b']) == []


def test_both_unrestricted_stays_unrestricted():
    assert rt.narrow_stream_scope(None, None) is None


def test_an_unresolvable_scope_narrows_rather_than_widens():
    """Same rule as everywhere else tonight: could-not-tell is not permission."""
    body = _reauthz_block()
    i = body.index('cannot refresh cluster scope')
    assert '_fresh_allowed = []' in body[i:i + 300]


def test_a_stream_with_nothing_left_in_scope_is_closed():
    body = _reauthz_block()
    assert 'no cluster left in scope' in body
    i = body.index('no cluster left in scope')
    assert 'return' in body[i:i + 200]


def test_the_role_refresh_that_was_already_there_still_happens():
    """The invariant - this tick had a job before and must keep doing it."""
    body = _reauthz_block()
    assert "_ci['effective_role']" in body
    assert "_ci['is_admin']" in body


def test_the_token_floor_is_applied_to_the_fresh_lookup():
    """Resolving against the raw account would hand a scoped token its owner's clusters."""
    body = _reauthz_block()
    assert '_floor_by_token_role(' in body


def test_the_interval_is_short_enough_to_matter():
    assert rt.SSE_REAUTHZ_INTERVAL <= 60
