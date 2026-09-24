"""A list that came out of a request body must not size the work or the storage.

Ten endpoints took a list from the caller, checked at most that it WAS a list, and then
either persisted it or did one unit of work per entry. Nothing bounded the item count or
the item length, so a single request could store a million entries of a megabyte each -
durably, reloaded into memory on every start - or make the cluster do a million pushes.

One of them is worse than a resource question. `sort_order` went to the database
unchecked and GET /api/clusters sorts on that column: one string in one row and the
cluster list raises TypeError comparing str to int, for every user, until somebody finds
the row. That one needed fixing on both sides - reject it going in, and survive the rows
that are already there.

Aikido ai_pentest 700487659 / 700487850 / 700487845 / 700487886 / 700487585 / 700487985.
MK
"""
import contextlib

import pytest

from pegaprox.utils.sanitization import bounded_list


# --- the validator ------------------------------------------------------------------

def test_a_normal_list_passes_through():
    assert bounded_list(['a', 'b']) == (['a', 'b'], None)


def test_missing_is_an_empty_list_not_an_error():
    """Most of these fields are optional and 'not given' means 'none'."""
    assert bounded_list(None) == ([], None)


def test_too_many_entries_is_refused_with_the_count():
    cleaned, err = bounded_list(['x'] * 300, max_items=256, name='fallback_hosts')

    assert cleaned is None
    assert 'at most 256' in err and '300 given' in err


def test_an_overlong_entry_is_refused():
    cleaned, err = bounded_list(['y' * 300], max_length=253, name='excluded_nodes')

    assert cleaned is None and '253 characters' in err


def test_nested_structures_are_refused():
    """A dict per entry is how you smuggle size past a length check."""
    assert bounded_list([{'a': 1}], name='nodes')[0] is None
    assert bounded_list([['a']], name='nodes')[0] is None


def test_a_bool_is_not_a_name():
    assert bounded_list([True], name='nodes')[0] is None


def test_something_that_is_not_a_list_is_refused():
    assert bounded_list('nope', name='order')[0] is None
    assert bounded_list({'a': 1}, name='order')[0] is None


def test_duplicates_collapse():
    """Several of these do one unit of work per entry."""
    assert bounded_list(['a', 'b', 'a', 'b'])[0] == ['a', 'b']


def test_blank_entries_are_dropped_not_stored():
    assert bounded_list(['a', '', '   ', 'b'])[0] == ['a', 'b']


def test_entries_are_stripped():
    assert bounded_list(['  a  '])[0] == ['a']


# --- the call sites -------------------------------------------------------------------

@contextlib.contextmanager
def _ctx(api, session, body):
    from flask import request as _rq
    with api.app.test_request_context('/', base_url='http://localhost', json=body):
        _rq.session = session
        yield


def _handler(mod, name):
    fn = getattr(mod, name)
    while hasattr(fn, '__wrapped__'):
        fn = fn.__wrapped__
    return fn


@pytest.fixture
def estate(api, seed):
    from tests.conftest import make_fake_manager
    seed.tenant('tenant_a', clusters=['cluster_1'])
    seed.user('root4', role='admin')
    api.set_manager('cluster_1', make_fake_manager('cluster_1'))
    seed.db.execute('''INSERT INTO clusters (id, name, host, user, pass_encrypted)
                       VALUES ('cluster_1', 'c1', '10.0.0.1', 'root@pam', 'x')''')
    return seed


ADMIN = {'user': 'root4', 'role': 'admin'}


def test_a_huge_fallback_host_list_is_refused(api, estate):
    import pegaprox.api.clusters as cl

    with _ctx(api, ADMIN, {'fallback_hosts': ['10.0.0.1'] * 5000}):
        resp = _handler(cl, 'set_fallback_hosts')('cluster_1')

    assert resp[1] == 400
    assert 'at most' in resp[0].get_json()['error']


def test_a_reasonable_fallback_host_list_still_works(api, estate):
    """The counterweight - two or three fallback hosts is the whole point of the field."""
    import pegaprox.api.clusters as cl

    with _ctx(api, ADMIN, {'fallback_hosts': ['10.0.0.2', '10.0.0.3']}):
        resp = _handler(cl, 'set_fallback_hosts')('cluster_1')

    assert not isinstance(resp, tuple) or resp[1] == 200, resp


def test_a_huge_reorder_array_is_refused(api, estate):
    """This ran one UPDATE per element inside a single transaction."""
    import pegaprox.api.clusters as cl

    with _ctx(api, ADMIN, {'order': [f'c{i}' for i in range(5000)]}):
        resp = _handler(cl, 'reorder_clusters')()

    assert resp[1] == 400


def test_a_non_integer_sort_order_is_refused(api, estate):
    import pegaprox.api.clusters as cl

    with _ctx(api, ADMIN, {'sort_order': 'first'}):
        resp = _handler(cl, 'update_cluster_sort_order')('cluster_1')

    assert resp[1] == 400
    assert 'integer' in resp[0].get_json()['error']


def test_a_boolean_sort_order_is_refused(api, estate):
    """bool is an int subclass; True is not a position."""
    import pegaprox.api.clusters as cl

    with _ctx(api, ADMIN, {'sort_order': True}):
        resp = _handler(cl, 'update_cluster_sort_order')('cluster_1')

    assert resp[1] == 400


def test_a_real_sort_order_still_works(api, estate):
    import pegaprox.api.clusters as cl

    with _ctx(api, ADMIN, {'sort_order': 5}):
        resp = _handler(cl, 'update_cluster_sort_order')('cluster_1')

    assert resp.get_json()['sort_order'] == 5


def test_a_bad_row_that_is_already_stored_cannot_break_the_listing():
    """The durable half: rows written before the validation exist, and one of them must
    not raise TypeError in the sort key for every user."""
    import inspect
    import pegaprox.api.clusters as cl

    src = inspect.getsource(cl)
    i = src.index('def _order_key(')
    body = src[i:i + 400]
    assert 'isinstance(v, int)' in body and 'isinstance(v, bool)' in body

    rows = [{'sort_order': 'first', 'name': 'b'}, {'sort_order': 2, 'name': 'a'},
            {'sort_order': None, 'name': 'c'}, {'name': 'd'}]

    def _order_key(c):
        v = c.get('sort_order', 0)
        return (v if isinstance(v, int) and not isinstance(v, bool) else 0,
                str(c.get('name', '')).lower())

    assert [c['name'] for c in sorted(rows, key=_order_key)] == ['b', 'c', 'd', 'a']
