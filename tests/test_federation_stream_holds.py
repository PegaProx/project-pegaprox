"""Linked mode: an open live feed decides as the account stands now, and a feed that is
stopped gives its place back at once.

The site that leads a cluster registers a member's feed as an SSE client of its own. Its
30 s re-check narrowed the clusters only and kept the admin flag and the role the feed
opened with, so an account demoted at its home kept the whole inventory of an open feed.
And a feed stopped by a change of the stream's selection held its connection, and a slot
of the site, until the site's next line: one account switching to and fro took every
slot. MK Nov 2026
"""
import json
import queue
import threading
import time

import pytest

from pegaprox.core import federation as fed
from pegaprox.core import federation_relay as relay
from pegaprox.core import federation_stream as fstream
from tests.test_federation import (  # noqa: F401 - fixtures by name
    _add_local_user, _db_of, _defaults_out_of_the_config_dir, _fresh_budgets, _map, _pull,
    _set, at, iid)
from tests.test_federation_relay import CID, _fresh_relay, linked  # noqa: F401
from tests.test_federation_stream import (  # noqa: F401
    _feed_into_browser, _fresh_streams, _open, _principal)


_SECRET_GUEST = [{'vmid': 101, 'type': 'qemu', 'node': 'n1', 'name': 'payroll-db',
                  'status': 'running'}]


def _custom_role(side, name, perms):
    from pegaprox.utils import rbac
    conn = _db_of(side).conn
    conn.execute("INSERT OR REPLACE INTO custom_roles (name, permissions, description, "
                 "tenant_id, created_at) VALUES (?, ?, ?, '', '2026-01-01T00:00:00')",
                 (name, json.dumps(perms), name))
    conn.commit()
    rbac.invalidate_roles_cache()


def _fed_entries():
    from pegaprox.utils.realtime import sse_clients, sse_clients_lock
    with sse_clients_lock:
        return {k: dict(v) for k, v in sse_clients.items() if k.startswith('fed-')}


def _resources_of(line):
    line = line.decode() if isinstance(line, bytes) else line
    frame = json.loads(line.split(' ', 2)[2])
    assert frame['type'] == 'resources' and frame['cluster_id'] == CID
    return frame['data']


@pytest.fixture(autouse=True)
def _roles_cache_reset():
    from pegaprox.utils import rbac
    rbac.invalidate_roles_cache()
    yield
    rbac.invalidate_roles_cache()


def test_an_open_feed_drops_the_admin_view_of_a_demoted_account(linked, monkeypatch):
    a, b = linked
    from pegaprox.core.db import get_db
    from pegaprox.utils.realtime import broadcast_sse
    # b's admin maps the home's 'helpdesk' role onto a role of b without vm.view
    # (the role is in use at the home already, so b has mapped it)
    _custom_role(a, 'helpdesk', ['cluster.view'])
    _custom_role(b, 'helpdesk-b', ['cluster.view'])
    _add_local_user(a, 'hd1', role='helpdesk')
    _pull(b, a)
    _map(b, a, 'role', 'helpdesk', 'helpdesk-b')
    # every pass of the feed's loop is a re-check, so the test does not wait 30 s
    monkeypatch.setattr(fstream, 'RECHECK', 0)
    monkeypatch.setattr(fstream, 'KEEPALIVE', 3600)

    # alice (admin) opens a feed of b's cluster from a
    resp, nonce, rid = _open(a, b)
    assert resp.status_code == 200
    it = iter(resp.response)
    with at(b):
        opening = next(it)
    (entry,) = _fed_entries().values()
    assert entry['is_admin'] is True

    # her home demotes her; b pulls the account as it does every minute
    _set(a, 'alice', role='helpdesk')
    _pull(b, a)
    with at(b):
        assert get_db().get_user('alice')['role'] == 'helpdesk-b'

    lines = [opening]
    with at(b):
        # one frame to step the feed's loop once: the re-check runs right after it
        broadcast_sse('metrics', {'nodes': {'n1': {'cpu': 0.1}}}, CID)
        lines.append(next(it))
        # the next broadcast arrives while the loop waits for its queue, after the re-check
        timer = threading.Timer(0.5, broadcast_sse, args=('resources', _SECRET_GUEST, CID))
        timer.start()
        lines.append(next(it))
        timer.join()
        (entry,) = _fed_entries().values()
    resp.close()

    # the re-check kept the feed (the cluster stays in scope) and took the role it has now
    assert entry['clusters'] == [CID]
    assert entry['is_admin'] is False and entry['effective_role'] == 'helpdesk-b'
    # so the per-guest filter runs: the guest is no longer sent
    assert _resources_of(lines[2]) == []

    # as a feed opened now does
    resp2, _n2, _r2 = _open(a, b)
    assert resp2.status_code == 200
    it2 = iter(resp2.response)
    with at(b):
        next(it2)
        (fresh,) = _fed_entries().values()
        assert fresh['is_admin'] is False
        broadcast_sse('resources', _SECRET_GUEST, CID)
        line = next(it2)
    resp2.close()
    assert _resources_of(line) == []


def test_an_open_feed_of_a_viewer_takes_its_new_role(linked, monkeypatch):
    """The same for an account that was never an admin: the filter decides with the role
    the account has now, not with the one the feed opened with."""
    a, b = linked
    from pegaprox.core.db import get_db
    from pegaprox.utils.realtime import broadcast_sse
    from tests.test_federation_stream import _principal
    _custom_role(a, 'helpdesk', ['cluster.view'])
    _custom_role(b, 'helpdesk-b', ['cluster.view'])
    _add_local_user(a, 'hd1', role='helpdesk')
    _pull(b, a)
    _map(b, a, 'role', 'helpdesk', 'helpdesk-b')
    monkeypatch.setattr(fstream, 'RECHECK', 0)
    monkeypatch.setattr(fstream, 'KEEPALIVE', 3600)

    resp, nonce, rid = _open(a, b, principal=_principal(a, user='vic'))
    assert resp.status_code == 200
    it = iter(resp.response)
    with at(b):
        next(it)
    (entry,) = _fed_entries().values()
    assert entry['is_admin'] is False and entry['effective_role'] == 'viewer'

    _set(a, 'vic', role='helpdesk')
    _pull(b, a)
    with at(b):
        assert get_db().get_user('vic')['role'] == 'helpdesk-b'
        broadcast_sse('metrics', {'nodes': {'n1': {'cpu': 0.1}}}, CID)
        next(it)
        timer = threading.Timer(0.5, broadcast_sse, args=('resources', _SECRET_GUEST, CID))
        timer.start()
        leaked = next(it)
        timer.join()
        (entry,) = _fed_entries().values()
    resp.close()
    assert entry['clusters'] == [CID] and entry['effective_role'] == 'helpdesk-b'
    assert _resources_of(leaked) == []

    # as a feed opened now does
    resp2, _n2, _r2 = _open(a, b, principal=_principal(a, user='vic'))
    assert resp2.status_code == 200
    it2 = iter(resp2.response)
    with at(b):
        next(it2)
        (fresh,) = _fed_entries().values()
        assert fresh['effective_role'] == 'helpdesk-b'
        broadcast_sse('resources', _SECRET_GUEST, CID)
        line = next(it2)
    resp2.close()
    assert _resources_of(line) == []


SLOTS = 4


@pytest.fixture
def quiet_site(monkeypatch):
    """The other site as a quiet cluster looks on the wire: it answers the stream request
    and then sends nothing until the connection is closed. Records who connected."""
    release = threading.Event()
    connected = []

    def hook(url, path, headers):
        env = json.loads(relay._unb64(headers[relay.ENVELOPE_HEADER]))
        if CID not in env['query'].split('=', 1)[1].split(','):
            # as the site answers a feed of no cluster the account may see there
            return 403, None, None
        connected.append(env['principal']['user'])
        closed = threading.Event()

        def lines():
            while not closed.is_set() and not release.is_set():
                closed.wait(0.05)
            return
            yield  # noqa: unreachable - a generator that sends nothing until closed

        return 200, lines(), closed.set

    monkeypatch.setattr(fstream, '_streams_out', relay._Budget(SLOTS * 2, SLOTS))
    monkeypatch.setattr(fstream, 'RETRY_FIRST', 30)
    yield hook, release, connected
    release.set()


def _browser_stream(client_id, user):
    from pegaprox.utils.realtime import sse_clients, sse_clients_lock
    with sse_clients_lock:
        sse_clients[client_id] = {'queue': queue.Queue(), 'user': user, 'clusters': []}


def _wait(cond, seconds=3.0):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.02)
    return cond()


def _run(a, b, quiet_site, toggles):
    hook, release, connected = quiet_site
    site = iid(b)
    with at(a):
        fed._runtime['stream'] = hook
        _browser_stream('test-vic', 'vic')
        _browser_stream('test-alice', 'alice')
        # two selections that both name the one cluster vic may see there
        one, two = [f'{CID}~{site}'], [f'{CID}~{site}', f'pve2~{site}']
        fstream.watch('test-vic', one, _principal(a, user='vic'))
        assert _wait(lambda: connected.count('vic') == 1)
        # the viewer changes the selection of its one stream, back and forth
        for n in range(toggles):
            fstream.watch('test-vic', two if n % 2 == 0 else one, _principal(a, user='vic'))
            assert _wait(lambda: connected.count('vic') == n + 2)
        # vic still has one registered feed of the site, as the cap wants
        with fstream._feeds_lock:
            registered = sum(1 for v in fstream._feeds.values() for f in v.values()
                             if f.principal['user'] == 'vic')
        _wait(lambda: fstream._streams_out._per.get(site, 0) <= 1, 1.0)
        held_by_vic = fstream._streams_out._per.get(site, 0)
        # another account of this site opens its live view of the same site
        fstream.watch('test-alice', one, _principal(a))
        alice_connected = _wait(lambda: 'alice' in connected, 1.5)
        release.set()
    return registered, held_by_vic, alice_connected


def test_switching_the_selection_to_and_fro_holds_one_slot(linked, quiet_site):
    a, b = linked
    registered, held_by_vic, alice_connected = _run(a, b, quiet_site, toggles=6)
    assert registered == 1
    # a stopped feed closed its connection and gave its slot back
    assert held_by_vic <= 2
    assert alice_connected is True


def test_without_switching_both_get_their_feed(linked, quiet_site):
    a, b = linked
    registered, held_by_vic, alice_connected = _run(a, b, quiet_site, toggles=0)
    assert registered == 1 and held_by_vic == 1
    assert alice_connected is True
