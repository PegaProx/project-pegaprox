# #736 (rebuild) — the SSE 'resources' frame carries the whole cluster VM list. A client with
# cluster access but pool-/VM-scoped rights must not receive VMs it can't view over SSE (REST
# already filters per-VM; the stream previously did not). Our rebuild filters per non-admin client,
# caches per distinct user, and — unlike the original PR — NEVER calls load_users() in the hot path.

import json
import queue
import pegaprox.utils.realtime as rt


def _fake_db(users):
    class _DB:
        def get_user(self, u):
            return users.get(u)
    return _DB()


def test_admin_frame_includes_all_vms(monkeypatch):
    # admin -> user_can_access_vm short-circuits True -> no VMs dropped
    monkeypatch.setattr('pegaprox.core.db.get_db',
                        lambda: _fake_db({'root': {'role': 'admin', 'username': 'root'}}))
    resources = [{'vmid': 1, 'type': 'qemu'}, {'vmid': 2, 'type': 'lxc'}]
    data = json.loads(rt._filtered_resources_frame(resources, 'cl1', 'root', 'ts'))['data']
    assert [r['vmid'] for r in data] == [1, 2]


def test_scoped_frame_keeps_only_authorized(monkeypatch):
    monkeypatch.setattr('pegaprox.core.db.get_db',
                        lambda: _fake_db({'bob': {'role': 'viewer', 'username': 'bob'}}))

    def only_vm1(user, cluster_id, vmid, permission='vm.view', vm_type=None):
        assert user['username'] == 'bob' and cluster_id == 'cl1' and permission == 'vm.view'
        return vmid == 1
    monkeypatch.setattr('pegaprox.utils.rbac.user_can_access_vm', only_vm1)
    resources = [{'vmid': 1, 'type': 'qemu'}, {'vmid': 2, 'type': 'lxc'}]
    data = json.loads(rt._filtered_resources_frame(resources, 'cl1', 'bob', 'ts'))['data']
    assert [r['vmid'] for r in data] == [1]


def test_unknown_user_frame_is_none_fail_closed(monkeypatch):
    monkeypatch.setattr('pegaprox.core.db.get_db', lambda: _fake_db({}))
    assert rt._filtered_resources_frame([{'vmid': 1}], 'cl1', 'ghost', 'ts') is None


def test_no_load_users_in_sse_hot_path():
    # the PR's version called load_users() (loads+decrypts ALL users) per client per broadcast —
    # the documented hot-path landmine. Guard against it coming back. AST-based so the word
    # appearing in a docstring/comment doesn't false-positive; we only flag a real call/import.
    import ast
    import inspect
    for fn in (rt._filtered_resources_frame, rt.broadcast_sse):
        tree = ast.parse(inspect.getsource(fn))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'load_users':
                assert False, f"{fn.__name__} calls load_users() — SSE hot-path landmine (#736)"
            if isinstance(node, ast.ImportFrom) and any(a.name == 'load_users' for a in node.names):
                assert False, f"{fn.__name__} imports load_users (#736)"


def test_broadcast_filters_scoped_client_but_not_admin(monkeypatch):
    monkeypatch.setattr('pegaprox.core.db.get_db',
                        lambda: _fake_db({'bob': {'role': 'viewer', 'username': 'bob'}}))
    monkeypatch.setattr('pegaprox.utils.rbac.user_can_access_vm',
                        lambda user, cid, vmid, permission='vm.view', vm_type=None: vmid == 1)
    admin_q, bob_q = queue.Queue(), queue.Queue()
    saved = dict(rt.sse_clients)
    rt.sse_clients.clear()
    # is_admin is now captured at registration (api/realtime.py) from the real role — the loop
    # must gate on it, NOT on clusters==None (which is also true for default-tenant scoped users).
    rt.sse_clients['admin1'] = {'queue': admin_q, 'clusters': None, 'user': 'root', 'is_admin': True}
    rt.sse_clients['bob1'] = {'queue': bob_q, 'clusters': ['cl1'], 'user': 'bob', 'is_admin': False}
    try:
        rt.broadcast_sse('resources', [{'vmid': 1, 'type': 'qemu'}, {'vmid': 2, 'type': 'qemu'}], 'cl1')
        admin_msg = json.loads(admin_q.get_nowait())
        bob_msg = json.loads(bob_q.get_nowait())
        assert [r['vmid'] for r in admin_msg['data']] == [1, 2]   # admin: unfiltered
        assert [r['vmid'] for r in bob_msg['data']] == [1]        # scoped: only his VM
        assert admin_q.empty() and bob_q.empty()
    finally:
        rt.sse_clients.clear()
        rt.sse_clients.update(saved)


def test_broadcast_filters_default_tenant_scoped_user_with_subscribed_none(monkeypatch):
    # THE EXPLOIT (found by the Aug-30 pentest): a default-tenant, non-admin, pool-/VM-scoped user
    # gets allowed_clusters=None from get_user_clusters() (rbac.py:347) -> registered with
    # clusters=None, exactly like an admin. The old filter gate `subscribed is not None` therefore
    # SKIPPED filtering and streamed the FULL cluster inventory to her ~1x/sec. She must be filtered.
    monkeypatch.setattr('pegaprox.core.db.get_db',
                        lambda: _fake_db({'eve': {'role': 'viewer', 'username': 'eve'}}))
    monkeypatch.setattr('pegaprox.utils.rbac.user_can_access_vm',
                        lambda user, cid, vmid, permission='vm.view', vm_type=None: vmid == 1)
    eve_q = queue.Queue()
    saved = dict(rt.sse_clients)
    rt.sse_clients.clear()
    rt.sse_clients['eve1'] = {'queue': eve_q, 'clusters': None, 'user': 'eve', 'is_admin': False}
    try:
        rt.broadcast_sse('resources', [{'vmid': 1, 'type': 'qemu'}, {'vmid': 2, 'type': 'qemu'}], 'cl1')
        eve_msg = json.loads(eve_q.get_nowait())
        assert [r['vmid'] for r in eve_msg['data']] == [1]   # only her VM, NOT the full inventory
        assert eve_q.empty()
    finally:
        rt.sse_clients.clear()
        rt.sse_clients.update(saved)


def test_broadcast_missing_is_admin_flag_fails_closed(monkeypatch):
    # A client registered before the flag existed (or any code path that forgets it) must be
    # treated as NON-admin and filtered, never leaked to.
    monkeypatch.setattr('pegaprox.core.db.get_db',
                        lambda: _fake_db({'mallory': {'role': 'viewer', 'username': 'mallory'}}))
    monkeypatch.setattr('pegaprox.utils.rbac.user_can_access_vm',
                        lambda user, cid, vmid, permission='vm.view', vm_type=None: vmid == 1)
    q = queue.Queue()
    saved = dict(rt.sse_clients)
    rt.sse_clients.clear()
    rt.sse_clients['m1'] = {'queue': q, 'clusters': None, 'user': 'mallory'}   # no is_admin key
    try:
        rt.broadcast_sse('resources', [{'vmid': 1, 'type': 'qemu'}, {'vmid': 2, 'type': 'qemu'}], 'cl1')
        msg = json.loads(q.get_nowait())
        assert [r['vmid'] for r in msg['data']] == [1]
    finally:
        rt.sse_clients.clear()
        rt.sse_clients.update(saved)
