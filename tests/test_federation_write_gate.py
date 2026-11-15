"""The federation's cluster write gate sits at the exits.

Every write to a cluster leaves this process through an exit of core/ha_transport.py: a
guarded requests session, a guarded paramiko client, node_cmd. With the federation
switched on, each exit that names its cluster asks federation.guard_exit() before the
call goes out, whatever route or worker sends it: a cluster this instance enrolled is
written only while it holds a live lease on it. Reads, consoles and logins always pass,
an unenrolled cluster costs the cached switch and one dict lookup, and a refusal comes
after the route's own login and permission checks (the route answers 401 or 403 first;
an after-request hook turns a refused write into 409 FED_NO_LEASE).

What keeps the gate honest over time is the inventory below: every call of an exit hook
in pegaprox/ names its cluster or is reviewed as one that talks to no cluster of the
federation, and every write route outside /api/clusters/<cluster_id>/ that names
clusters in its body checks the lease before a multi-step operation starts.

Each refusal here runs the same call once more with a live lease and shows it goes out:
a test that passed because nothing ever went out would prove nothing.

MK Nov 2026
"""
import ast
import inspect
import os
import re
from unittest.mock import MagicMock

import pytest

from pegaprox.core import federation
from pegaprox.core import federation_lease as fl

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
START = 'https://10.0.0.8:8006/api2/json/nodes/n1/qemu/100/status/start'


@pytest.fixture
def fed_on(monkeypatch):
    monkeypatch.setenv(federation.ENV_SWITCH, '1')


def _row(db, cid, owner):
    db.execute("INSERT OR REPLACE INTO clusters (id, name, host, user, pass_encrypted, fed_owner) "
               "VALUES (?, ?, '10.0.0.8', 'root@pam', 'x', ?)", (cid, cid, owner))
    fl.drop_owner_cache()


def _grant(cid, seconds=20):
    """A live lease on `cid`, as a round that a majority backed leaves it."""
    def go(st):
        st['my_leases'][cid] = {'expires': fl._lease_now() + seconds, 'since': fl._lease_now(),
                                'votes': 2, 'needed': 2, 'released': False,
                                'adopted': False, 'lost_to': '', 'refusals': {}}
        return True
    federation._mutate_leases(go)


def _stub_session(sent):
    import requests

    class Stub(requests.adapters.BaseAdapter):
        def send(self, request, **kwargs):
            sent.append((request.method, request.url))
            resp = requests.Response()
            resp.status_code, resp._content, resp.request = 200, b'{"data": "UPID:x"}', request
            return resp

        def close(self):
            pass
    s = requests.Session()
    s.mount('https://', Stub())
    return s


@pytest.fixture
def led(db, fed_on):
    """This instance's identity and one cluster row it enrolled, one of its own and one
    another member leads."""
    me = federation.ensure_identity()
    _row(db, 'c-led', me)
    _row(db, 'c-local', '')
    _row(db, 'c-foreign', 'f' * 32)
    return me


# --- the exit itself ----------------------------------------------------------------------

def test_a_write_without_a_lease_is_refused_at_the_exit(led):
    from pegaprox.core import ha_transport
    sent = []
    s = ha_transport.guard_session(_stub_session(sent), cluster_id='c-led')
    with pytest.raises(federation.LeaseRefused):
        s.post(START)
    assert sent == []
    # a read, a console ticket and a login go out whatever the lease says
    s.get('https://10.0.0.8:8006/api2/json/nodes')
    s.post('https://10.0.0.8:8006/api2/json/nodes/n1/qemu/100/vncproxy')
    s.post('https://10.0.0.8:8006/api2/json/access/ticket')
    assert [m for m, _u in sent] == ['GET', 'POST', 'POST']
    # counterproof: with a live lease the same write goes out
    _grant('c-led')
    s.post(START)
    assert sent[-1] == ('POST', START)


def test_another_members_cluster_is_never_written(led):
    from pegaprox.core import ha_transport
    sent = []
    s = ha_transport.guard_session(_stub_session(sent), cluster_id='c-foreign')
    _grant('c-foreign')
    with pytest.raises(federation.LeaseRefused):
        s.post(START)
    assert sent == []


def test_an_unenrolled_cluster_write_goes_out(led):
    from pegaprox.core import ha_transport
    sent = []
    s = ha_transport.guard_session(_stub_session(sent), cluster_id='c-local')
    s.post(START)
    s.delete('https://10.0.0.8:8006/api2/json/nodes/n1/qemu/100')
    assert [m for m, _u in sent] == ['POST', 'DELETE']


def test_reads_consoles_and_logins_pass(led):
    for kind in ('console', 'login'):
        federation.guard_exit('c-led', 'POST /x', kind)
    from pegaprox.core import ha
    with ha.reading():
        federation.guard_exit('c-led', 'SSH n1 cat', 'ssh')
    with pytest.raises(federation.LeaseRefused):
        federation.guard_exit('c-led', 'SSH n1 rm', 'ssh')


def test_an_ssh_exit_and_a_node_command_ask_the_lease(led, monkeypatch):
    from pegaprox.core import ha_transport
    ran = []
    client = MagicMock()
    client.exec_command.side_effect = lambda *a, **k: ran.append(a[0])
    ha_transport.guard_client(client, 'n1', cluster_id='c-led')
    with pytest.raises(federation.LeaseRefused):
        client.exec_command('qm start 100')
    monkeypatch.setattr(ha_transport.subprocess, 'run', lambda argv, **kw: ran.append(argv))
    with pytest.raises(federation.LeaseRefused):
        ha_transport.node_cmd(['ssh', 'root@n1', 'reboot'], timeout=5, host='n1',
                              cluster_id='c-led')
    # a read passes the node command, and a live lease opens both
    ha_transport.node_cmd(['ipmitool', 'power', 'status'], timeout=5, read=True,
                          cluster_id='c-led')
    _grant('c-led')
    client.exec_command('qm start 100')
    ha_transport.node_cmd(['ssh', 'root@n1', 'reboot'], timeout=5, host='n1', cluster_id='c-led')
    assert ran == [['ipmitool', 'power', 'status'], 'qm start 100', ['ssh', 'root@n1', 'reboot']]


def test_an_unreadable_owner_table_refuses_the_write(led, monkeypatch):
    class Broken:
        @property
        def conn(self):
            raise RuntimeError('the disk is gone')
    fl.drop_owner_cache()
    monkeypatch.setattr(federation, '_db', lambda: Broken())
    with pytest.raises(federation.LeaseRefused):
        federation.guard_exit('c-local', 'POST /x')
    # the worker check says no as well, and the strict one raises
    assert federation.worker_takes_writes_for('c-local') is False
    with pytest.raises(federation.FederationError):
        federation.takes_writes_for('c-local')


def test_an_unenrolled_write_asks_nothing_but_the_cache(led, monkeypatch):
    """The gate costs a write on an unenrolled cluster the cached switch and one dict
    lookup: no database query, no token check, no file read."""
    import pegaprox.utils.auth as auth_mod
    federation.guard_exit('c-local', 'POST /x')         # warms the owner cache
    asked = []
    monkeypatch.setattr(federation, '_db', lambda: asked.append('db'))
    monkeypatch.setattr(auth_mod, 'validate_api_token', lambda *a: asked.append('token'))
    monkeypatch.setattr(federation, '_load_lease_file', lambda p: asked.append('file'))
    for _ in range(200):
        federation.guard_exit('c-local', 'POST /x')
    assert asked == []


# --- through the routes -------------------------------------------------------------------

def _guarded_manager(api, cid, sent):
    """A stand-in manager whose vm_action sends its POST through a session guarded for
    `cid`, as the real manager's session is."""
    from pegaprox.core import ha_transport
    s = ha_transport.guard_session(_stub_session(sent), cluster_id=cid)

    def vm_action(node, vmid, vm_type, action, force=False):
        resp = s.post(f'https://10.0.0.8:8006/api2/json/nodes/{node}/{vm_type}/{vmid}/status/{action}')
        return {'success': resp.status_code == 200, 'data': 'UPID:x'}
    m = api.make_fake_manager(cid)
    m.vm_action.side_effect = vm_action
    m.config.name = cid
    return api.set_manager(cid, m)


def test_an_owner_without_a_live_lease_gets_fed_no_lease(api, seed, led):
    """The route catches the refusal like any failed cluster call and answers 500; the
    after-request hook answers what the exit said instead."""
    admin = api.as_user(seed.user('root', role='admin'))
    sent = []
    _guarded_manager(api, 'c-led', sent)
    r = admin.post('/api/clusters/c-led/vms/n1/qemu/100/start', json={})
    assert r.status_code == 409, r.data
    assert r.get_json()['code'] == 'FED_NO_LEASE' and r.get_json()['cluster'] == 'c-led'
    assert sent == []
    # counterproof: with a live lease the same request starts the guest
    _grant('c-led')
    r = admin.post('/api/clusters/c-led/vms/n1/qemu/100/start', json={})
    assert r.status_code == 200, r.data
    assert sent and sent[-1][0] == 'POST'


def test_a_write_to_an_unenrolled_cluster_passes_the_route(api, seed, led):
    admin = api.as_user(seed.user('root', role='admin'))
    sent = []
    _guarded_manager(api, 'c-local', sent)
    r = admin.post('/api/clusters/c-local/vms/n1/qemu/100/start', json={})
    assert r.status_code == 200, r.data
    assert len(sent) == 1


def test_an_anonymous_write_gets_401_not_a_federation_answer(api, led):
    sent = []
    _guarded_manager(api, 'c-led', sent)
    r = api.anon().post('/api/clusters/c-led/vms/n1/qemu/100/start', json={})
    assert r.status_code == 401
    assert 'FED_' not in str(r.get_json(silent=True))


def test_a_user_without_access_gets_the_routes_403(api, seed, led):
    """Nobody learns from the gate who leads a cluster: a user who may not touch it gets
    the route's own refusal, the federation is never asked."""
    seed.tenant('acme', ['c-other'])
    viewer = api.as_user(seed.user('vic', role='user', tenant_id='acme'))
    sent = []
    _guarded_manager(api, 'c-led', sent)
    r = viewer.post('/api/clusters/c-led/vms/n1/qemu/100/start', json={})
    assert r.status_code == 403, r.data
    assert 'FED_' not in str(r.get_json(silent=True)) and sent == []


def test_the_ha_monitor_does_not_fence_without_a_lease(led, monkeypatch):
    from pegaprox.core import manager as mgr_mod
    monkeypatch.setattr(mgr_mod.time, 'sleep', lambda s: None)

    def run_once():
        fake = MagicMock()
        fake.id = 'c-led'
        fake.ha_enabled = True
        fake._ha_interval.return_value = 1
        fake.stop_event.is_set.side_effect = [False, True, True, True]
        fake._ha_agent_members_changed.return_value = False
        mgr_mod.PegaProxManager._ha_monitor_loop(fake)
        return fake
    assert run_once()._ha_check_nodes.call_count == 0
    # counterproof: the lease is here, the same loop checks its nodes
    _grant('c-led')
    assert run_once()._ha_check_nodes.call_count == 1


def test_a_route_outside_the_cluster_prefix_is_refused(api, seed, led):
    """A planned failover names its clusters in a plan, not in the path: the handler
    checks the lease of both before anything starts."""
    db = seed.db
    _row(db, 'c-src', '')
    db.execute("INSERT INTO site_recovery_plans (id, group_id, name, source_cluster, "
               "target_cluster, status) VALUES ('p1', 'g1', 'plan', 'c-src', 'c-led', 'ready')")
    src = api.set_manager('c-src', api.make_fake_manager('c-src'))
    tgt = api.set_manager('c-led', api.make_fake_manager('c-led'))
    admin = api.as_user(seed.user('root', role='admin'))
    r = admin.post('/api/site-recovery/plans/p1/failover', json={})
    assert r.status_code == 409, r.data
    assert r.get_json()['code'] == 'FED_NO_LEASE' and r.get_json()['cluster'] == 'c-led'
    status = db.conn.execute("SELECT status FROM site_recovery_plans WHERE id = 'p1'").fetchone()[0]
    assert status == 'ready'
    assert not src.method_calls and not tgt.method_calls
    # counterproof: with the lease the handler goes on (to its own next refusal: no guests)
    _grant('c-led')
    r = admin.post('/api/site-recovery/plans/p1/failover', json={})
    assert (r.get_json(silent=True) or {}).get('code') != 'FED_NO_LEASE', r.data


# --- the inventories ---------------------------------------------------------------------------

# the exit hooks and the SSH factories that hand a cluster id on to one
EXIT_CALLS = {'guard_session', 'guard_client', 'node_cmd', 'guard_ssh', 'secure_ssh_client',
              '_ssh_exec', '_connect_ssh'}
_PBS = 'a Proxmox Backup Server: no cluster of the federation'
_ESXI = 'the ESXi source host of a migration'
REVIEWED_NO_CLUSTER = {
    ('pegaprox/core/pbs.py', 'PBSManager.__init__', 'guard_session'): _PBS,
    ('pegaprox/core/pbs.py', 'PBSManager._perform_update', 'guard_ssh'): _PBS,
    ('pegaprox/core/pbs.py', 'PBSManager._ssh_connect', 'guard_client'): _PBS,
    ('pegaprox/core/qnetd.py', 'SshTransport._connect', 'secure_ssh_client'):
        'a QNetd host, outside every cluster',
    ('pegaprox/core/xcpng.py', 'XcpngManager._ssh_connect', 'guard_client'):
        'an XCP-ng pool, which cannot be enrolled',
    ('pegaprox/core/v2p.py', '_ssh_esxi_exec', 'node_cmd'): _ESXI,
    ('pegaprox/core/v2p.py', '_delta_sync_blocks', '_ssh_exec'): _ESXI,
    ('pegaprox/core/v2p.py', '_do_sshfs_boot_migration', '_ssh_exec'): _ESXI,
    ('pegaprox/core/v2p.py', '_full_check_disk', '_ssh_exec'): _ESXI,
    ('pegaprox/core/v2p.py', '_full_check_disk._esxi_side', '_ssh_exec'): _ESXI,
    ('pegaprox/core/v2p.py', '_qemu_img_ssh_copy', '_ssh_exec'): _ESXI,
    ('pegaprox/core/v2p.py', '_run_v2p_migration', '_ssh_exec'): _ESXI,
    ('pegaprox/core/v2p.py', '_setup_temp_ssh_key', '_ssh_exec'): _ESXI,
    ('pegaprox/core/v2p.py', '_ssh_pipe_transfer', '_ssh_exec'): _ESXI,
}


def _exit_calls():
    found = {}
    for d, dirs, names in os.walk(os.path.join(ROOT, 'pegaprox')):
        dirs[:] = [n for n in dirs if n != '__pycache__']
        for n in names:
            if not n.endswith('.py') or n.startswith('.'):
                continue
            rel = os.path.relpath(os.path.join(d, n), ROOT)
            if rel == os.path.join('pegaprox', 'core', 'ha_transport.py'):
                continue
            with open(os.path.join(d, n), encoding='utf-8') as fh:
                tree = ast.parse(fh.read())

            def walk(node, prefix, rel=rel):
                for ch in ast.iter_child_nodes(node):
                    if isinstance(ch, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                        walk(ch, prefix + ch.name + '.')
                        continue
                    if isinstance(ch, ast.Call):
                        f = ch.func
                        name = f.id if isinstance(f, ast.Name) else getattr(f, 'attr', None)
                        own_method = isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) \
                            and f.value.id == 'self' and name in ('_ssh_exec',)
                        if name in EXIT_CALLS and not own_method:
                            named = any(k.arg == 'cluster_id' for k in ch.keywords)
                            key = (rel, prefix.rstrip('.'), name)
                            found[key] = found.get(key, True) and named
                    walk(ch, prefix)
            walk(tree, '')
    return found


def test_every_cluster_exit_names_its_cluster():
    found = _exit_calls()
    # counterproof that the walk sees them: the manager's own session factory names its
    # cluster, PBS's does not
    assert found[('pegaprox/core/manager.py', 'PegaProxManager._create_session',
                  'guard_session')] is True
    assert found[('pegaprox/core/pbs.py', 'PBSManager.__init__', 'guard_session')] is False
    unnamed = sorted(k for k, named in found.items() if not named and k not in REVIEWED_NO_CLUSTER)
    assert not unnamed, (
        'An exit to a cluster, a node or a BMC does not say which cluster it writes to: '
        f'{unnamed}. Pass cluster_id= (the federation fences the writes of an enrolled '
        'Proxmox VE cluster there), or list it in REVIEWED_NO_CLUSTER with the reason it '
        'reaches no cluster of the federation.')
    gone = sorted(k for k in REVIEWED_NO_CLUSTER if k not in found)
    assert not gone, f'reviewed exits that are gone - take them out: {gone}'
    named_anyway = sorted(k for k in REVIEWED_NO_CLUSTER if found.get(k))
    assert not named_anyway, f'reviewed exits that name a cluster now - take them out: {named_anyway}'


# the write routes outside /api/clusters/<cluster_id>/ that act on clusters named in their
# body or a plan: each checks the lease of every one before a multi-step operation starts
_FED_BODY_CLUSTER_WRITES = {
    ('POST', '/api/xhm/migrate'),
    ('POST', '/api/site-recovery/plans/<plan_id>/failover'),
    ('POST', '/api/multi-sdn/vnets/<vid>/apply'),
    ('POST', '/api/qnetd/hosts/<host_id>/bulk-setup'),
    ('POST', '/api/cross-cluster-migrate'),
    ('POST', '/api/vmware/<vmware_id>/vms/<vm_id>/migrate'),
    ('POST', '/api/vmware/<vmware_id>/bulk-migrate'),
}
# what the scan below finds and needs no early check, with the reason
_REVIEWED_BODY_WRITES = {
    ('POST', '/api/clusters'): 'adds a cluster: a new row, never enrolled',
    ('POST', '/api/config/restore'): 'this instance\'s configuration, no cluster call',
    ('POST', '/api/cross-cluster-migrate/preflight'): 'reads only',
    ('POST', '/api/cross-cluster-replications'): 'stores a job; the replication loop checks '
                                                 'the lease of both clusters on every run',
    ('POST', '/api/cross-cluster-replications/preflight'): 'reads only',
    ('POST', '/api/drift/events/<int:eid>/acknowledge'): 'this instance\'s database only',
    ('POST', '/api/pbs/<pbs_id>/auto-storage'): 'one write per cluster, each fenced at its exit',
    ('POST', '/api/site-recovery/plans'): 'stores a plan; the failover checks the lease',
    ('POST', '/api/snapshots/delete'): 'one write per snapshot, each fenced at its exit',
    ('POST', '/api/snapshots/overview'): 'reads only',
    ('POST', '/api/sse/subscribe'): 'a subscription of this browser',
    ('PUT', '/api/ha/members/<instance_id>/agent-vmid'): 'a setting of the HA group',
}


def _body_named_writes(app):
    out = {}
    for rule in app.url_map.iter_rules():
        r = rule.rule
        if not r.startswith('/api/') or r.startswith('/api/clusters/<cluster_id>'):
            continue
        fn = app.view_functions.get(rule.endpoint)
        try:
            src = inspect.getsource(inspect.unwrap(fn))
        except (TypeError, OSError):
            continue
        for method in sorted(rule.methods - {'GET', 'HEAD', 'OPTIONS'}):
            out[(method, r)] = src
    return out


def test_every_body_named_cluster_write_is_checked_early(api):
    routes = _body_named_writes(api.app)
    for key in sorted(_FED_BODY_CLUSTER_WRITES):
        assert key in routes, f'{key} is gone - take it out of _FED_BODY_CLUSTER_WRITES'
        assert 'refuse_unleased(' in routes[key], \
            f'{key} acts on clusters named in its body without checking the lease first'
    suspicious = []
    for key, src in routes.items():
        touches = 'cluster_managers' in src or 'get_cluster(' in src
        body = re.search(r"request\.(json|get_json)|_body\(|data\.get\(", src)
        keyed = re.search(r"""(data|body|payload|req)\.get\(\s*['"](\w*cluster\w*)['"]|"""
                          r"""\[\s*['"](\w*cluster\w*)['"]\s*\]""", src)
        if touches and body and keyed:
            suspicious.append(key)
    # counterproof that the scan sees such routes at all
    assert ('POST', '/api/xhm/migrate') in suspicious
    unknown = sorted(k for k in suspicious
                     if k not in _FED_BODY_CLUSTER_WRITES and k not in _REVIEWED_BODY_WRITES)
    assert not unknown, (
        f'Write routes that name clusters in their body: {unknown}. Check the lease of each '
        'with api.federation.refuse_unleased() before the operation starts and list it in '
        '_FED_BODY_CLUSTER_WRITES, or list it in _REVIEWED_BODY_WRITES with the reason.')
    gone = sorted(k for k in _REVIEWED_BODY_WRITES if k not in routes)
    assert not gone, f'reviewed routes that are gone - take them out: {gone}'
