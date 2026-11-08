"""An SSE stream must filter as the role it was MINTED with, not as its owner.

The connect path already floors an admin-owned but viewer-scoped API token to the
token's role and stores is_admin=False, which is what switches the per-frame
filters on. But every filter then rebuilt the identity from the stored account
record — where the role is still the owner's `admin` — so each one hit the admin
fast-return in user_can_access_vm and passed the whole inventory through anyway.
The floor was captured at connect and thrown away one level down. MK
"""
import json
import queue

import pytest

import pegaprox.utils.realtime as rt


CLUSTER = 'cluster_1'
MINE, THEIRS = 100, 200
ROWS = [{'vmid': MINE, 'type': 'qemu', 'name': 'app-01'},
        {'vmid': THEIRS, 'type': 'qemu', 'name': 'finance-01'}]


@pytest.fixture
def owner(db, seed):
    """An ADMIN account that also holds a VM ACL on exactly one guest.

    The ACL is what makes the difference visible: read as the stored admin role the
    filter fast-returns everything; read as the token's viewer role, scope-wins
    confines it to the one guest."""
    seed.tenant('acme', clusters=[CLUSTER])
    seed.user('tokenowner', role='admin', tenant_id='acme')
    seed.vm_acl(CLUSTER, MINE, ['tokenowner'], permissions=['vm.view'])
    return 'tokenowner'


@pytest.fixture
def stream():
    """Register one SSE client and hand back its queue."""
    saved = dict(rt.sse_clients)
    rt.sse_clients.clear()

    def _mk(user, is_admin, effective_role):
        q = queue.Queue()
        rt.sse_clients[f'c-{user}-{effective_role}'] = {
            'queue': q, 'clusters': [CLUSTER], 'user': user,
            'is_admin': is_admin, 'effective_role': effective_role,
        }
        return q

    try:
        yield _mk
    finally:
        rt.sse_clients.clear()
        rt.sse_clients.update(saved)


def _vmids(q):
    return [r['vmid'] for r in json.loads(q.get_nowait())['data']]


def test_viewer_scoped_token_is_filtered_despite_an_admin_owner(owner, stream):
    q = stream(owner, is_admin=False, effective_role='viewer')

    rt.broadcast_sse('resources', ROWS, CLUSTER)

    assert _vmids(q) == [MINE], 'the stream filtered as its owner, not as its token'


def test_a_real_admin_stream_is_still_unfiltered(owner, stream):
    q = stream(owner, is_admin=True, effective_role='admin')

    rt.broadcast_sse('resources', ROWS, CLUSTER)

    assert _vmids(q) == [MINE, THEIRS]


def test_a_session_stream_with_no_token_role_behaves_as_before(db, seed, stream):
    """effective_role=None is the ordinary browser session: fall back to the stored role."""
    seed.tenant('acme', clusters=[CLUSTER])
    seed.user('plainviewer', role='viewer', tenant_id='acme', permissions=['vm.view'])
    q = stream('plainviewer', is_admin=False, effective_role=None)

    rt.broadcast_sse('resources', ROWS, CLUSTER)

    assert _vmids(q) == [MINE, THEIRS], 'an unscoped viewer must keep the whole cluster'


def test_two_streams_of_one_account_do_not_share_a_filter_decision(owner, stream):
    """The per-broadcast caches key on the user; two streams of the same account can be
    floored differently, so the key has to carry the role as well."""
    scoped = stream(owner, is_admin=False, effective_role='viewer')
    unscoped = stream(owner, is_admin=True, effective_role='admin')

    rt.broadcast_sse('resources', ROWS, CLUSTER)

    assert _vmids(scoped) == [MINE]
    assert _vmids(unscoped) == [MINE, THEIRS]


def test_object_frames_use_the_floored_role_too(owner, stream, monkeypatch):
    """_sse_may_see_object_frame had its own copy of the admin fast-return, reading
    user['role'] directly."""
    seen = {}

    def _spy(user, cid, vmid, permission='vm.view', vm_type=None):
        seen['effective_role'] = user.get('effective_role')
        return False
    monkeypatch.setattr('pegaprox.utils.rbac.user_can_access_vm', _spy)
    monkeypatch.setattr(rt, '_xhm_reachable_ids', None, raising=False)

    q = stream(owner, is_admin=False, effective_role='viewer')
    rt.broadcast_sse('xhm_migration', {'id': 'nope'})

    assert q.empty(), 'a migration frame reached a stream that cannot see the guest'
    assert seen.get('effective_role', 'viewer') == 'viewer'
