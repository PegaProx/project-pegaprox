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
import time
from unittest.mock import MagicMock

import pytest

from pegaprox.core import federation
from pegaprox.core import federation_lease as fl

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
START = 'https://10.0.0.8:8006/api2/json/nodes/n1/qemu/100/status/start'


@pytest.fixture
def fed_on(monkeypatch):
    monkeypatch.setenv(federation.ENV_SWITCH, '1')
    monkeypatch.setenv(federation.DR_ENV_SWITCH, '1')


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


class _Popen:
    """A node command that never leaves: records its argv (without the start gate and the
    `timeout` wrapper) and ends at once. Its pid is past any pid_max, so no kill can reach a
    real process. `gate` keeps a copy of the gate's read end: what came through it."""
    ran = None
    gates = None

    def __init__(self, argv, **kw):
        self.pid, self.returncode = 4194304 + 777, 0
        argv = list(argv)
        if argv[:2] == ['/bin/sh', '-c'] and kw.get('pass_fds'):
            if _Popen.gates is not None:
                self.gate = os.dup(kw['pass_fds'][-1])
                _Popen.gates.append(self)
            argv = argv[4:]
        if argv and os.path.basename(argv[0]) == 'timeout':
            argv = argv[4:]
        _Popen.ran.append(argv)

    def came_through(self):
        """What the command was let through with; None while the gate is still held open.
        gevent's os.close lets the hub close the fd, so the hub runs once first."""
        import gevent
        gevent.sleep(0.05)
        os.set_blocking(self.gate, False)
        try:
            return os.read(self.gate, 64)
        except BlockingIOError:
            return None
        finally:
            os.close(self.gate)

    def communicate(self, data=None, timeout=None):
        return '', ''

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        return self.returncode


def test_an_ssh_exit_and_a_node_command_ask_the_lease(led, monkeypatch):
    from pegaprox.core import ha_transport
    ran = []
    client = MagicMock()
    client.exec_command.side_effect = lambda *a, **k: ran.append(a[0])
    ha_transport.guard_client(client, 'n1', cluster_id='c-led')
    with pytest.raises(federation.LeaseRefused):
        client.exec_command('qm start 100')
    monkeypatch.setattr(ha_transport.subprocess, 'run', lambda argv, **kw: ran.append(argv))
    # a command on an enrolled cluster runs in a process group of its own
    _Popen.ran = ran
    monkeypatch.setattr(ha_transport.subprocess, 'Popen', _Popen)
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


def test_a_refused_deep_scan_closes_its_client(api, seed, led, monkeypatch):
    """A storage rescan with deep_scan on c-led: the first command of its client is
    refused at the exit, and the client it connected is closed all the same, not left to
    the node to drop. Counterproof: with the lease the command goes out."""
    import threading
    import types
    import paramiko
    import pegaprox.utils.ssh_security as sec
    from pegaprox import globals as _g
    from test_ha_guard_rounds import pve
    sent, closed = [], []

    def exec_command(self, cmd, *a, **k):
        sent.append(cmd)
        raise RuntimeError('stopped by the test')
    monkeypatch.setattr(paramiko.SSHClient, 'connect', lambda self, *a, **k: None)
    monkeypatch.setattr(paramiko.SSHClient, 'exec_command', exec_command)
    monkeypatch.setattr(paramiko.SSHClient, 'close', lambda self: closed.append(self))
    monkeypatch.setattr(sec, 'persist_host_keys', lambda c: None)
    monkeypatch.setattr(_g, '_ssh_semaphore', threading.BoundedSemaphore(4))
    m = pve()
    m.id = 'c-led'
    m._get_node_ip = lambda n: '10.0.0.11'

    class _Sess:
        def get(self, url, **k):
            if url.endswith('/storage/lvm1'):
                return types.SimpleNamespace(status_code=200, json=lambda: {'data': {
                    'type': 'lvm', 'vgname': 'vg1', 'nodes': 'pve1'}})
            return types.SimpleNamespace(status_code=200, json=lambda: {'data': [
                {'node': 'pve1', 'status': 'online'}]})
    m._create_session = lambda: _Sess()
    api.set_manager('c-led', m)
    admin = api.as_user(seed.user('root', role='admin'))
    for lease in (False, True):
        if lease:
            _grant('c-led')
        closed.clear()
        admin.post('/api/clusters/c-led/datacenter/storage/lvm1/rescan',
                   json={'deep_scan': True, 'pvresize': True, 'nodes': ['pve1']})
        assert len(sent) == int(lease) and len(closed) == 1, (lease, sent, closed)


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
              '_ssh_exec', '_connect_ssh', 'guard_write'}
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
            rel = os.path.relpath(os.path.join(d, n), ROOT).replace(os.sep, '/')
            if rel == 'pegaprox/core/ha_transport.py':
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
    ('POST', '/api/site-recovery/plans/<plan_id>/emergency'),
    ('POST', '/api/site-recovery/plans/<plan_id>/test'),
    ('POST', '/api/site-recovery/plans/<plan_id>/test/cleanup'),
    ('POST', '/api/site-recovery/plans/<plan_id>/failback'),
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
        assert 'refuse_unleased(' in routes[key] or '_refuse_unleased(' in routes[key], \
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


# --- a connection that comes up after the lease ran out ---------------------------------------

def _lapse(cid):
    def go(st):
        st['my_leases'][cid]['expires'] = fl._lease_now() - 1
        return True
    federation._mutate_leases(go)


@pytest.mark.parametrize('scheme', ['http', 'https'])
def test_a_lease_that_runs_out_while_the_connection_comes_up_stops_the_write(led, monkeypatch,
                                                                             scheme):
    """The check before send() saw a live lease; the connect then stalls (a dark host, a
    slow handshake) and the lease runs out meanwhile. The write is checked again once the
    connection is up and does not go out. Counterproof: with the lease still live after
    the connect, it does."""
    import requests
    import urllib3
    from pegaprox.core import ha_transport
    _grant('c-led')
    sent, lapse = [], {'on': True}

    def stalled_connect(conn):
        if lapse['on']:
            _lapse('c-led')
        conn.sock = MagicMock()

    def request(self, method, url, *a, **k):
        sent.append(f'{method} {url}')
        raise requests.exceptions.ConnectionError('stub: nothing listens')
    monkeypatch.setattr(urllib3.connection.HTTPConnection, 'connect',
                        lambda self: stalled_connect(self))
    monkeypatch.setattr(urllib3.connectionpool.HTTPSConnectionPool, '_validate_conn',
                        lambda self, conn: stalled_connect(conn))
    monkeypatch.setattr(urllib3.connection.HTTPConnection, 'request', request)
    s = ha_transport.guard_session(requests.Session(), cluster_id='c-led')
    url = f'{scheme}://10.0.0.8:8006/api2/json/nodes/n1/qemu/100/status/start'
    with pytest.raises(federation.LeaseRefused):
        s.post(url, timeout=5, verify=False)
    assert sent == []
    _grant('c-led')
    lapse['on'] = False
    with pytest.raises(requests.exceptions.ConnectionError):
        s.post(url, timeout=5, verify=False)
    assert sent == ['POST /api2/json/nodes/n1/qemu/100/status/start']


# --- a thaw undoes a freeze ---------------------------------------------------------------------

def test_a_thaw_passes_the_fence(led):
    """The lease ran out between the freeze and the thaw of a snapshot: the thaw still goes
    out, refused it would leave the guest's file systems frozen. The freeze does not."""
    from pegaprox.core import ha_transport
    sent = []
    s = ha_transport.guard_session(_stub_session(sent), cluster_id='c-led')
    base = 'https://10.0.0.8:8006/api2/json/nodes/n1/qemu/100/agent'
    with pytest.raises(federation.LeaseRefused):
        s.post(f'{base}/fsfreeze-freeze')
    s.post(f'{base}/fsfreeze-thaw')
    assert sent == [('POST', f'{base}/fsfreeze-thaw')]


def _thaws_without_freeze(src):
    """(function, line) of each thaw of the guest agent in `src` that no freeze earlier in
    the same function goes before."""
    tree = ast.parse(src)
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        own = {n for child in fn.body for n in ast.walk(child)}
        for inner in [n for n in own if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
            own -= set(ast.walk(inner)) - {inner}
        said = [(n.lineno, n.value) for n in own
                if isinstance(n, ast.Constant) and isinstance(n.value, str)]
        freezes = [line for line, text in said if 'fsfreeze-freeze' in text]
        for line, text in said:
            if text.endswith('/agent/fsfreeze-thaw') and not any(f < line for f in freezes):
                out.append((fn.name, line))
    return out


def test_every_thaw_follows_a_freeze_of_its_own():
    """The thaw passes the fence (above) because every one in pegaprox/ follows a freeze in
    the same function, and that freeze needed the lease: what is thawed is a guest this
    instance froze. A new thaw sender turns this red until it is looked at."""
    found, bare = 0, []
    for folder, _dirs, files in os.walk(os.path.join(ROOT, 'pegaprox')):
        for name in files:
            if not name.endswith('.py'):
                continue
            path = os.path.join(folder, name)
            with open(path, encoding='utf-8') as fh:
                src = fh.read()
            if 'fsfreeze-thaw' not in src:
                continue
            rel = os.path.relpath(path, ROOT).replace(os.sep, '/')
            found += src.count('/agent/fsfreeze-thaw')
            bare += [f'{rel}:{line} {fn}' for fn, line in _thaws_without_freeze(src)]
    assert found >= 3, found
    assert not bare, bare


def test_the_thaw_inventory_flags_a_lone_thaw():
    src = '''
def lone(mgr, url):
    mgr._api_post(f"{url}/agent/fsfreeze-thaw")

def paired(mgr, url):
    mgr._api_post(f"{url}/agent/fsfreeze-freeze")
    mgr._api_post(f"{url}/agent/fsfreeze-thaw")

def backwards(mgr, url):
    mgr._api_post(f"{url}/agent/fsfreeze-thaw")
    mgr._api_post(f"{url}/agent/fsfreeze-freeze")

def outer(mgr, url):
    mgr._api_post(f"{url}/agent/fsfreeze-freeze")
    def inner():
        mgr._api_post(f"{url}/agent/fsfreeze-thaw")
'''
    assert sorted(fn for fn, _line in _thaws_without_freeze(src)) == ['backwards', 'inner', 'lone']


# --- what is under way when the lease goes --------------------------------------------------------

def _sleeping(ha_transport, cid, out):
    import time as _time
    started = _time.monotonic()
    try:
        out['rc'] = ha_transport.node_cmd(['sleep', '30'], timeout=60, host='n1',
                                          cluster_id=cid).returncode
    finally:
        out['took'] = _time.monotonic() - started


def _wait_tracked(ha_transport, cid):
    import time as _time
    for _ in range(200):
        if ha_transport._groups.get(cid):
            return True
        _time.sleep(0.02)
    return False


def _no_watch(monkeypatch, ha_transport):
    """The watch stops nothing (a watch thread of an earlier test may still be running):
    what stops a call here is the hand-over itself."""
    monkeypatch.setattr(ha_transport, '_tracked', lambda: set())


@pytest.mark.parametrize('how', ['hand over', 'lease runs out'])
def test_a_node_command_under_way_stops_when_the_lease_goes(led, monkeypatch, how):
    """A long node command (a dist-upgrade, a copy) on an enrolled cluster was let out with
    a live lease. A hand-over stops it before the voters hear of it, with no watch; a lease
    that runs out stops it within a watch tick. Without that it would go on writing while
    another site adopts the cluster."""
    import threading
    from pegaprox.core import ha_transport
    if how == 'hand over':
        _no_watch(monkeypatch, ha_transport)
    else:
        monkeypatch.setattr(ha_transport, 'WATCH_EVERY', 0.05)
    _grant('c-led', seconds=60)
    out = {}
    t = threading.Thread(target=_sleeping, args=(ha_transport, 'c-led', out))
    t.start()
    try:
        assert _wait_tracked(ha_transport, 'c-led')
        if how == 'hand over':
            fl.release('c-led')
        else:
            _lapse('c-led')
        t.join(10)
        assert not t.is_alive() and out['took'] < 10, out
        assert out['rc'] != 0
    finally:
        ha_transport.cut_cluster('c-led')
        t.join(5)


def test_an_unenroll_stops_nothing_under_way(led, monkeypatch):
    """An unenroll makes the cluster this instance's alone: a node command under way on it
    goes on while the releases are out (one slow voter) and the watch looks every tick,
    and a switch-off after it stops nothing of it either. It stays kept all the same:
    enrolled again and handed over, the cluster may be adopted elsewhere, and then the
    command stops."""
    import threading
    import time
    from pegaprox.core import ha_transport
    monkeypatch.setattr(ha_transport, 'WATCH_EVERY', 0.05)
    real_send = fl._send_releases_many

    def slow(taken, to=None):
        time.sleep(0.5)
        return real_send(taken, to=to)
    monkeypatch.setattr(fl, '_send_releases_many', slow)
    _grant('c-led', seconds=60)
    out = {}
    t = threading.Thread(target=_sleeping, args=(ha_transport, 'c-led', out))
    t.start()
    try:
        assert _wait_tracked(ha_transport, 'c-led')
        fl._finish_unenroll(['c-led'])
        assert fl.cluster_owner('c-led') == ''
        t.join(1.5)
        assert t.is_alive(), out
        monkeypatch.setenv(federation.ENV_SWITCH, '0')
        t.join(0.5)
        assert t.is_alive(), out
        monkeypatch.setenv(federation.ENV_SWITCH, '1')
        _grant('c-led', seconds=60)
        fl._set_owner('c-led', led)
        fl.release('c-led')
        t.join(10)
        assert not t.is_alive() and out['took'] < 10 and out['rc'] != 0, out
    finally:
        ha_transport.cut_cluster('c-led')
        t.join(5)


def test_a_command_on_an_unenrolled_cluster_is_left_alone(led, monkeypatch):
    """Counterproof: the same command on a cluster no federation owns is not kept, and a
    lease that goes elsewhere stops nothing of it."""
    import threading
    from pegaprox.core import ha_transport
    monkeypatch.setattr(ha_transport, 'WATCH_EVERY', 0.05)
    ran = []
    _Popen.ran = ran
    monkeypatch.setattr(ha_transport.subprocess, 'run', lambda argv, **kw: ran.append(argv))
    ha_transport.node_cmd(['ssh', 'root@n1', 'true'], timeout=5, host='n1', cluster_id='c-local')
    assert ran == [['ssh', 'root@n1', 'true']] and 'c-local' not in ha_transport._groups


def test_a_node_command_that_went_out_as_a_read_is_left_alone(led, monkeypatch):
    """A command ha.reading() let out without the lease runs as it did before, kept
    nowhere: the watch would kill it the moment no lease is held. Counterproof: as a
    write under a live lease it runs in a process group of its own, which is kept."""
    from pegaprox.core import ha, ha_transport
    ran, grouped = [], []
    monkeypatch.setattr(ha_transport.subprocess, 'run', lambda argv, **kw: ran.append(argv))
    _Popen.ran = grouped
    monkeypatch.setattr(ha_transport.subprocess, 'Popen', _Popen)
    with ha.reading():
        ha_transport.node_cmd(['ssh', 'root@n1', 'pvecm status'], timeout=5, host='n1',
                              cluster_id='c-led')
    assert ran == [['ssh', 'root@n1', 'pvecm status']] and grouped == []
    _grant('c-led')
    ha_transport.node_cmd(['ssh', 'root@n1', 'pvecm status'], timeout=5, host='n1',
                          cluster_id='c-led')
    assert grouped == [['ssh', 'root@n1', 'pvecm status']]


def test_an_ssh_client_of_the_cluster_is_closed_when_the_lease_goes(led, monkeypatch):
    """A client a write went out through is closed by the hand-over, its channels with it.
    One of a cluster no federation owns is left alone."""
    from pegaprox.core import ha_transport
    _no_watch(monkeypatch, ha_transport)
    _grant('c-led', seconds=60)
    client, other = MagicMock(), MagicMock()
    ha_transport.guard_client(client, 'n1', cluster_id='c-led')
    ha_transport.guard_client(other, 'n1', cluster_id='c-local')
    client.exec_command('qm start 100')
    other.exec_command('qm start 100')
    try:
        fl.release('c-led')
        assert client.close.called
        assert not other.close.called
    finally:
        ha_transport.cut_cluster('c-led')


@pytest.mark.parametrize('how', ['reading', 'GET'])
def test_a_client_that_only_read_stays_open_when_the_lease_runs_out(led, monkeypatch, how):
    """guard_exit lets an SSH read out without the lease: inside ha.reading(), and in a GET
    this instance answers. A client that carried nothing else is not kept, or the watch
    would cut the read the moment no lease is held. Counterproof: the client next to it
    that carried a write is closed within a tick."""
    import time as _time
    from flask import Flask
    from pegaprox.core import ha, ha_transport
    monkeypatch.setattr(ha_transport, 'WATCH_EVERY', 0.05)
    reader, writer = MagicMock(), MagicMock()
    ha_transport.guard_client(reader, 'n1', cluster_id='c-led')
    ha_transport.guard_client(writer, 'n1', cluster_id='c-led')
    _grant('c-led', seconds=60)
    reads = ha.reading() if how == 'reading' else \
        Flask('reads').test_request_context('/api/clusters/c-led/nodes', method='GET')
    try:
        with reads:
            reader.exec_command('cat /etc/pve/.members')
        writer.exec_command('qm start 100')
        _lapse('c-led')
        for _ in range(100):
            if writer.close.called:
                break
            _time.sleep(0.02)
        _time.sleep(0.2)
        assert writer.close.called
        assert not reader.close.called
    finally:
        ha_transport.cut_cluster('c-led')


@pytest.mark.parametrize('cmd', ['write', 'read'])
def test_a_client_of_ssh_exec_is_closed_when_the_lease_goes(led, monkeypatch, cmd):
    """_ssh_exec logs in with a client of its own (no guard_client) and keeps it, once the
    command it sends is a write, for the hand-over to close: a command under way stops
    with it instead of running on while another site adopts the cluster. A read (inside
    ha.reading()) passed without the lease and is left to finish."""
    import socket
    import threading
    import paramiko
    from pegaprox.core import ha, ha_transport
    from pegaprox.utils import ssh as ssh_mod
    _no_watch(monkeypatch, ha_transport)
    started, made = threading.Event(), []

    class _Hanging:
        def __init__(self):
            self.closed = threading.Event()
            made.append(self)

        def load_host_keys(self, *a):
            pass

        def set_missing_host_key_policy(self, *a):
            pass

        def connect(self, hostname, **kw):
            pass

        def exec_command(self, cmd, timeout=None):
            started.set()
            closed = self.closed

            class _Out:
                channel = MagicMock()

                def read(self, n=-1):
                    closed.wait(10)
                    return b''
            return None, _Out(), _Out()

        def close(self):
            self.closed.set()

    def no_tcp(addr, timeout=None, **kw):
        raise OSError('no network in a test')
    monkeypatch.setattr(socket, 'create_connection', no_tcp)
    monkeypatch.setattr(paramiko, 'SSHClient', _Hanging)
    monkeypatch.setattr(ssh_mod, 'persist_host_keys', lambda client: None)
    _grant('c-led', seconds=60)

    def run():
        if cmd == 'read':
            with ha.reading():
                ssh_mod._ssh_exec('10.0.0.7', 'root', 'pw', 'cat /etc/pve/.members',
                                  cluster_id='c-led')
        else:
            ssh_mod._ssh_exec('10.0.0.7', 'root', 'pw', 'qm migrate 100 n2', cluster_id='c-led')
    t = threading.Thread(target=run, daemon=True)
    t.start()
    try:
        assert started.wait(10)
        fl.release('c-led')
        assert made[-1].closed.is_set() is (cmd == 'write')
        made[-1].closed.set()
        t.join(5)
        assert not t.is_alive()
    finally:
        for client in made:
            client.closed.set()
        t.join(5)


def test_a_cluster_that_becomes_a_mirror_closes_its_clients(led, monkeypatch):
    """The cluster led here became another member's mirror (it was adopted while this
    instance was cut off): note_lost stops what is under way on it at once, not at the
    next watch tick."""
    from pegaprox.core import ha_transport
    _no_watch(monkeypatch, ha_transport)
    _grant('c-led', seconds=60)
    client = MagicMock()
    ha_transport.guard_client(client, 'n1', cluster_id='c-led')
    client.exec_command('qm start 100')
    try:
        fl.note_lost('c-led', 'f' * 32)
        assert client.close.called
    finally:
        ha_transport.cut_cluster('c-led')


def test_a_step_down_stops_what_runs_before_the_row_moves(led, monkeypatch):
    """The other site of a federation of two took the cluster over by hand, and this
    instance hears of it: a node command under way and a client a write went out through
    are stopped while the row still says this instance, and only then does the row become
    the new owner's copy. Nothing goes out beside the new owner once the row names it."""
    import threading
    import time as _time
    from pegaprox.core import ha_transport
    _no_watch(monkeypatch, ha_transport)
    _grant('c-led', seconds=60)
    seen = []
    client = MagicMock()
    client.close.side_effect = lambda: seen.append(federation.cluster_owner('c-led'))
    ha_transport.guard_client(client, 'n1', cluster_id='c-led')
    client.exec_command('qm start 100')
    out = {}
    t = threading.Thread(target=_sleeping, args=(ha_transport, 'c-led', out))
    t.start()
    rec = {'cluster_id': 'c-led', 'gen': 2, 'kind': 'takeover', 'owner': 'f' * 32,
           'from': led, 'at': int(_time.time()), 'by': 'admin:root', 'sig': 'x'}
    try:
        assert _wait_tracked(ha_transport, 'c-led')
        assert fl._step_down('c-led', rec) is True
        t.join(10)
        assert not t.is_alive() and out['rc'] != 0, out
        assert seen and seen[0] == led
        assert federation.cluster_owner('c-led') == 'f' * 32
        assert fl.takes_writes_for('c-led') is False
    finally:
        ha_transport.cut_cluster('c-led')
        t.join(5)


def _handed_over_after(monkeypatch, ha_transport, name, nth=1):
    """ha_transport.<name> answers as before, and the cluster is handed over right after
    its nth answer: the window between asking for a write and the write going out."""
    real, asks = getattr(ha_transport, name), []

    def answer(*a, **kw):
        out = real(*a, **kw)
        asks.append(out)
        if len(asks) == nth:
            fl.release('c-led')
        return out
    monkeypatch.setattr(ha_transport, name, answer)
    return asks


def test_a_hand_over_after_the_ask_stops_the_write_of_a_client(led, monkeypatch):
    """The lease was asked for a write and the cluster is handed over before the client is
    kept: the hand-over finds nothing to close, so the client asks once more after it is
    kept and the write never goes out."""
    from pegaprox.core import ha_transport
    _no_watch(monkeypatch, ha_transport)
    _grant('c-led', seconds=60)
    _handed_over_after(monkeypatch, ha_transport, '_fed_guard')
    client = MagicMock()
    sent = client.exec_command
    ha_transport.guard_client(client, 'n1', cluster_id='c-led')
    try:
        with pytest.raises(federation.LeaseRefused):
            client.exec_command('qm start 100')
        assert not sent.called
    finally:
        ha_transport.cut_cluster('c-led')


def test_a_hand_over_after_the_last_ask_of_ssh_exec_closes_its_client(led, monkeypatch):
    """_ssh_exec keeps its client before it asks the second time, so a hand-over right
    after that ask closes the client the command then goes out on."""
    import socket
    import paramiko
    from pegaprox.core import ha_transport
    from pegaprox.utils import ssh as ssh_mod
    _no_watch(monkeypatch, ha_transport)
    order, made = [], []

    class _Client:
        def __init__(self):
            self.closed = False
            made.append(self)

        def load_host_keys(self, *a):
            pass

        def set_missing_host_key_policy(self, *a):
            pass

        def connect(self, hostname, **kw):
            pass

        def exec_command(self, cmd, timeout=None):
            order.append('sent on a closed client' if self.closed else 'sent on an open client')
            raise OSError('closed')

        def close(self):
            self.closed = True

    def no_tcp(addr, timeout=None, **kw):
        raise OSError('no network in a test')
    monkeypatch.setattr(socket, 'create_connection', no_tcp)
    monkeypatch.setattr(paramiko, 'SSHClient', _Client)
    monkeypatch.setattr(ssh_mod, 'persist_host_keys', lambda client: None)
    _grant('c-led', seconds=60)
    _handed_over_after(monkeypatch, ha_transport, 'guard_ssh', nth=2)
    try:
        try:
            ssh_mod._ssh_exec('10.0.0.7', 'root', 'pw', 'qm migrate 100 n2', cluster_id='c-led')
        except Exception:
            pass
        assert order == ['sent on a closed client'], order
    finally:
        ha_transport.cut_cluster('c-led')


def test_a_hand_over_after_the_ask_kills_the_node_command(led, monkeypatch):
    """node_cmd keeps the process group of a write once it started and asks again: a
    hand-over since the first ask is refused there and the group is killed before the
    command got far."""
    from pegaprox.core import ha_transport
    _no_watch(monkeypatch, ha_transport)
    killed = []

    class _Running(_Popen):
        def poll(self):
            return None
    _Popen.ran = ran = []
    monkeypatch.setattr(_Popen, 'gates', [])
    gates = _Popen.gates
    monkeypatch.setattr(ha_transport.subprocess, 'Popen', _Running)
    monkeypatch.setattr(ha_transport, '_kill_group', killed.append)
    _grant('c-led', seconds=60)
    _handed_over_after(monkeypatch, ha_transport, '_fed_guard')
    with pytest.raises(federation.LeaseRefused):
        ha_transport.node_cmd(['ssh', 'root@n1', 'qm start 100'], timeout=5, host='n1',
                              cluster_id='c-led')
    assert ran == [['ssh', 'root@n1', 'qm start 100']]
    # the group waited at its gate, and the refusal shut it: the command itself never ran
    assert [g.came_through() for g in gates] == [b'']
    assert killed == [4194304 + 777] and not ha_transport._groups.get('c-led')


def _late_track(monkeypatch, ha_transport):
    """_track_group answers 0.2 s late, as under gevent where Popen yields to the hub: the
    child is exec'd long before the second ask."""
    real = ha_transport._track_group

    def late(cid, pgid):
        time.sleep(0.2)
        return real(cid, pgid)
    monkeypatch.setattr(ha_transport, '_track_group', late)


def test_a_command_refused_at_the_second_ask_never_runs(led, monkeypatch, tmp_path):
    """A real process: handed over between the first ask and the second, the command
    writes nothing, however late the second ask comes. Killing the group after the refusal
    would be too late for an ssh whose exec request already went out."""
    from pegaprox.core import ha_transport
    _no_watch(monkeypatch, ha_transport)
    _late_track(monkeypatch, ha_transport)
    _grant('c-led', seconds=60)
    _handed_over_after(monkeypatch, ha_transport, '_fed_guard')
    wrote = tmp_path / 'wrote'
    with pytest.raises(federation.LeaseRefused):
        ha_transport.node_cmd(['sh', '-c', f'echo x > {wrote}'], timeout=5, host='n1',
                              cluster_id='c-led')
    time.sleep(0.2)
    assert not wrote.exists()


def test_a_command_with_the_lease_runs_through_the_gate(led, monkeypatch, tmp_path):
    """Counterproof: with the lease kept the gate opens, the command runs and its input
    and output pass as with subprocess.run."""
    from pegaprox.core import ha_transport
    _no_watch(monkeypatch, ha_transport)
    _late_track(monkeypatch, ha_transport)
    _grant('c-led', seconds=60)
    wrote = tmp_path / 'wrote'
    r = ha_transport.node_cmd(['sh', '-c', f'echo x > {wrote}; cat'], timeout=5, host='n1',
                              cluster_id='c-led', input='in\n', capture_output=True, text=True)
    assert r.returncode == 0 and r.stdout == 'in\n' and wrote.exists()
    assert not ha_transport._groups.get('c-led')


# --- the poison pill and a recovery that waited past the lease ----------------------------------

def test_the_poison_pill_needs_the_lease(led, tmp_path):
    """A file on shared storage that makes the node's agent stop every guest: an exit like
    any other, refused without the federation's lease on the cluster."""
    from pegaprox.core.manager import PegaProxManager
    (tmp_path / '.pegaprox').mkdir()
    fake = MagicMock()
    fake.id = 'c-led'
    fake.ha_config = {'poison_pill_enabled': True, 'storage_heartbeat_path': str(tmp_path)}
    pill = tmp_path / '.pegaprox' / 'poison_n1'
    # a refusal, not a pill that failed: the recovery worker marks the node for later
    with pytest.raises(federation.LeaseRefused):
        PegaProxManager._ha_write_poison_pill(fake, 'n1', 'test')
    assert not pill.exists()
    _grant('c-led')
    assert PegaProxManager._ha_write_poison_pill(fake, 'n1', 'test') is True
    assert pill.exists()


def test_a_recovery_that_waited_past_the_lease_does_nothing(led, monkeypatch):
    import threading
    from pegaprox.core import ha
    from pegaprox.core import manager as mgr_mod
    monkeypatch.setattr(mgr_mod.time, 'sleep', lambda s: None)
    monkeypatch.setattr(ha, 'is_active', lambda: True)
    monkeypatch.setattr(ha, 'recovery_begin', lambda *a, **k: 'run')
    monkeypatch.setattr(ha, 'recovery_end', lambda *a, **k: [])

    def run():
        fake = MagicMock()
        fake.id = 'c-led'
        fake.ha_config = {}
        fake.ha_lock = threading.Lock()
        fake.ha_node_status = {'n1': {'status': 'offline', 'last_seen': 5}}
        fake.ha_recovery_in_progress = {'n1': True}
        fake._ha_fence_timing.return_value = {'wait': 0}
        fake._ha_recovery_allowed.return_value = None
        mgr_mod.PegaProxManager._ha_recovery_worker(fake, 'n1')
        return fake
    dropped = run()
    assert dropped._ha_recovery_allowed.call_count == 0
    # the node stays down: marked, so a pass tries it again once the lease is back here
    assert [c.args for c in dropped._ha_retry_recovery.call_args_list] == [('n1',)]
    _grant('c-led')
    went = run()
    assert went._ha_recovery_allowed.call_count == 1
    assert went._ha_retry_recovery.call_args_list == []


def _lose(cid):
    def go(st):
        st['my_leases'].pop(cid, None)
        return True
    federation._mutate_leases(go)


@pytest.fixture
def recovery(led, monkeypatch):
    """The real recovery worker, guest start, config move, SSH stop and poison pill, bound
    to a stand-in manager of c-led whose node n1 is offline with guests 100 to 102 on shared
    storage, n2 the target. Every exit is the real one: the starts go through a guarded
    session (what went out lands in `sent`), the SSH commands through guard_ssh. The lease
    is live when the recovery starts; `lose` says what takes it away: the look right after
    the wait (once the worker checked it), the first config move once it went through, or
    nothing. `auto`: this site is in an automatic HA group, which starts no guest whose
    config did not move. `journal`, a list: the run is written down, its steps land there
    as (step, vmid, done)."""
    import threading
    from pegaprox.core import ha, ha_transport
    from pegaprox.core import manager as mgr_mod
    M = mgr_mod.PegaProxManager
    monkeypatch.setattr(mgr_mod.time, 'sleep', lambda s: None)
    monkeypatch.setattr(ha, 'is_active', lambda: True)
    monkeypatch.setattr(ha, 'confirm_step', lambda *a, **k: True)
    for name in ('recovery_step', 'recovery_clear'):
        monkeypatch.setattr(ha, name, lambda *a, **k: None)
    monkeypatch.setattr(ha, 'recovery_begin', lambda *a, **k: None)
    monkeypatch.setattr(ha, 'recovery_end', lambda *a, **k: [])

    def run(sent, ha_config=None, lose='after the wait', allowed=None, auto=False,
            journal=None):
        _grant('c-led', seconds=60)
        monkeypatch.setattr(ha, 'lease_in_force', lambda: auto)
        if journal is not None:
            monkeypatch.setattr(ha, 'recovery_begin', lambda *a, **k: 'run-1')
            monkeypatch.setattr(ha, 'recovery_step', lambda run, cid, node, step, vmid=None,
                                done=False: journal.append((step, vmid, done)))
        fake = MagicMock()
        fake.id, fake.host, fake.api_port = 'c-led', '10.0.0.8', 8006
        fake.ha_config = ha_config or {}
        fake.ha_lock = threading.Lock()
        fake.ha_node_status = {'n1': {'status': 'offline', 'last_seen': 5}}
        fake.ha_recovery_in_progress = {'n1': True}
        fake.ha_recovery_locks = {}
        fake.config.ssh_key = ''
        fake.ssh_password_to_offer.return_value = None
        fake._ha_fence_timing.return_value = {'wait': 0}

        def recovery_allowed(node):
            if allowed is not None:
                raise allowed
            if lose == 'after the wait':
                _lose('c-led')
            return []
        fake._ha_recovery_allowed.side_effect = recovery_allowed
        fake._create_session.side_effect = lambda: ha_transport.guard_session(
            _stub_session(sent), cluster_id='c-led')
        fake._ha_fence_node.return_value = False
        fake._ha_get_vms_on_node.return_value = [{'vmid': v, 'type': 'qemu', 'name': f'g{v}'}
                                                 for v in (100, 101, 102)]
        fake._ha_get_available_nodes.return_value = ['n2']
        fake._ha_check_vm_storage.return_value = 'shared'
        fake._ha_select_target_node.return_value = 'n2'
        fake._ha_node_back.return_value = False
        # a truthy stand-in here takes the split-brain or the moved branch
        fake._ha_node_listed_online.return_value = False
        fake._ha_check_node_via_ssh.return_value = {'reachable': False}
        fake._ha_check_node_agent_heartbeat.return_value = {'alive': False}
        fake._ha_clear_vm_lock.return_value = True
        # the config sits where the move put it (an automatic group looks before the start)
        fake._ha_vm_is_on.return_value = True
        fake._ha_get_node_ip.return_value = '10.0.0.9'
        fake._ha_claimed.side_effect = lambda cmd, exact=True: cmd
        fake._ssh_run_command.side_effect = lambda host, user, cmd, **k: \
            ha_transport.guard_ssh(host, cmd, cluster_id='c-led') or True
        for name in ('_ha_start_vm_on_node', '_ha_write_poison_pill',
                     '_ha_ssh_stop_vms_on_node'):
            getattr(fake, name).side_effect = (
                lambda real: lambda *a, **k: real(fake, *a, **k))(getattr(M, name))

        def move(*a):
            out = M._ha_move_vm_config(fake, *a)
            if lose == 'at the move':
                _lose('c-led')
            return out
        fake._ha_move_vm_config.side_effect = move
        M._ha_recovery_worker(fake, 'n1')
        return fake
    return run


def _marked(fake):
    return [c.args for c in fake._ha_retry_recovery.call_args_list]


def _starts(sent):
    return [u for m, u in sent if m == 'POST']


@pytest.mark.parametrize('group', ['manual', 'automatic'])
def test_a_recovery_that_lost_the_lease_half_way_is_tried_again(recovery, group):
    """The lease goes once the worker checked it: the first config move is refused at its
    exit, the worker gives up on the node and marks it, so a pass tries again once the
    lease is back. Nothing was started, and the next guests are not tried one by one.
    Counterproofs: with the lease kept all three start and nothing is marked; another error
    marks nothing."""
    sent = []
    fake = recovery(sent, auto=group == 'automatic')
    assert _marked(fake) == [('n1',)]
    assert fake._ha_start_vm_on_node.call_count == 1 and _starts(sent) == []
    assert fake._ha_refuse.call_args_list == []
    kept = []
    fake = recovery(kept, lose='nothing')
    assert len(_starts(kept)) == 3 and _marked(fake) == []
    assert _marked(recovery([], allowed=RuntimeError('the node said no'))) == []


def test_a_guest_moved_when_the_lease_went_is_named(recovery):
    """The lease goes between the config move and the start: the guest sits stopped on
    the target, where a retried run does not list it, so it is named for an admin, and the
    node is marked. Counterproof: the lease kept, the guest starts and nobody is told."""
    sent = []
    fake = recovery(sent, lose='at the move')
    assert _marked(fake) == [('n1',)] and _starts(sent) == []
    (action, text), kw = fake._ha_refuse.call_args
    assert action == 'ha.recovery_refused' and kw == {'node': 'n1'}
    assert text.startswith('qemu/100 was moved to n2 and not started')
    fake = recovery([], lose='nothing')
    assert fake._ha_refuse.call_args_list == [] and _marked(fake) == []


def test_a_guest_moved_when_the_lease_went_is_named_once_in_a_journal_run(recovery):
    """The same in an automatic HA group, whose recovery is written down: the start of the
    guest is begun and never done, which is what the end of the run names it by
    (ha.recovery_interrupted), so the start does not name it a second time. Counterproof:
    named here as well, the admin reads of one guest twice."""
    journal = []
    fake = recovery([], lose='at the move', auto=True, journal=journal)
    assert _marked(fake) == [('n1',)]
    assert ('start', 100, False) in journal and ('start', 100, True) not in journal
    assert fake._ha_refuse.call_args_list == []


def _on_storage(path, pill_dir=True):
    """Strict fencing with the storage heartbeat and the poison pill under `path`."""
    if pill_dir:
        (path / '.pegaprox').mkdir(parents=True, exist_ok=True)
    return {'strict_fencing': True, 'storage_heartbeat_enabled': True,
            'poison_pill_enabled': True, 'storage_heartbeat_path': str(path)}


@pytest.mark.parametrize('reach', ['ssh', 'storage heartbeat'])
def test_a_strict_recovery_whose_lease_went_before_the_stop_is_tried_again(recovery, tmp_path,
                                                                           monkeypatch, reach):
    """Strict fencing, n1 is alive behind a partition with a guest running, and the lease
    goes before its guests are stopped: the stop over SSH, or the poison pill, is refused
    at its exit. That is no stop that failed - the worker marks the node for a retry once
    the lease is back, instead of the strict abort that leaves it for good. Counterproof:
    the lease kept and the pill failing for another reason, the strict abort marks
    nothing."""
    from pegaprox.core.manager import PegaProxManager
    real_worker = PegaProxManager._ha_recovery_worker

    def alive(fake, node):
        fake._ha_acquire_recovery_lock.return_value = True
        if reach == 'ssh':
            fake._ha_check_node_via_ssh.return_value = {
                'reachable': True, 'running_vms': [100], 'running_cts': [],
                'reachable_ips': ['10.0.0.9']}
        else:
            fake._ha_check_node_agent_heartbeat.return_value = {
                'alive': True, 'age_seconds': 1.0, 'running_vms': [100], 'running_cts': []}
        return real_worker(fake, node)
    monkeypatch.setattr(PegaProxManager, '_ha_recovery_worker', alive)
    pill = tmp_path / '.pegaprox' / 'poison_n1'
    fake = recovery([], {'strict_fencing': True} if reach == 'ssh' else _on_storage(tmp_path))
    assert _marked(fake) == [('n1',)]
    assert not pill.exists() and fake._ha_start_vm_on_node.call_count == 0
    if reach == 'storage heartbeat':
        fake = recovery([], _on_storage(tmp_path / 'other', pill_dir=False), lose='nothing')
        assert _marked(fake) == [] and fake._ha_start_vm_on_node.call_count == 0


def test_the_config_move_lets_a_lease_refusal_through(led):
    """A config move refused for the lease is no move that failed: the worker marks the
    node, as for a refused start, also when this site is in an automatic HA group and
    starts nothing whose config did not move."""
    from pegaprox.core import ha_transport
    from pegaprox.core.manager import PegaProxManager
    fake = MagicMock()
    fake.id = 'c-led'
    fake._ha_get_node_ip.return_value = '10.0.0.9'
    fake.ssh_password_to_offer.return_value = None
    fake._ha_claimed.side_effect = lambda cmd, exact=True: cmd
    fake._ssh_run_command.side_effect = lambda host, user, cmd, **k: \
        ha_transport.guard_ssh(host, cmd, cluster_id='c-led') or True
    with pytest.raises(federation.LeaseRefused):
        PegaProxManager._ha_move_vm_config(fake, 100, 'qemu', 'n1', 'n2')
    _grant('c-led')
    assert PegaProxManager._ha_move_vm_config(fake, 100, 'qemu', 'n1', 'n2') is True


# --- the routes that start a run of a plan ----------------------------------------------------------

def _plan(api, seed):
    db = seed.db
    _row(db, 'c-src', '')
    db.execute("INSERT INTO site_recovery_plans (id, group_id, name, source_cluster, "
               "target_cluster, status) VALUES ('p1', 'g1', 'plan', 'c-src', 'c-led', 'ready')")
    src = api.set_manager('c-src', api.make_fake_manager('c-src'))
    tgt = api.set_manager('c-led', api.make_fake_manager('c-led'))
    return db, src, tgt


@pytest.mark.parametrize('path', ['emergency', 'test', 'test/cleanup', 'failback'])
def test_every_run_of_a_plan_checks_the_lease_first(api, seed, led, path, monkeypatch):
    """Emergency failover, test failover, its cleanup and the failback write on the target
    (the failback on the source as well): without the lease the route answers 409 before
    it marks the plan running and reports a start."""
    import pegaprox.api.site_recovery as sr_api
    started = []
    monkeypatch.setattr(sr_api, '_safe_spawn_failover', lambda *a, **k: started.append(a) or True)
    db, src, tgt = _plan(api, seed)
    admin = api.as_user(seed.user('root', role='admin'))
    r = admin.post(f'/api/site-recovery/plans/p1/{path}', json={})
    assert r.status_code == 409, r.data
    assert r.get_json()['code'] == 'FED_NO_LEASE' and r.get_json()['cluster'] == 'c-led'
    status = db.conn.execute("SELECT status FROM site_recovery_plans WHERE id = 'p1'").fetchone()[0]
    assert status == 'ready' and started == []
    _grant('c-led')
    r = admin.post(f'/api/site-recovery/plans/p1/{path}', json={})
    assert (r.get_json(silent=True) or {}).get('code') != 'FED_NO_LEASE', r.data


# --- a multi-cluster vnet retried on one member ---------------------------------------------------

def test_a_vnet_retry_asks_only_the_members_it_writes(api, seed, led, monkeypatch):
    """c-led applied the vnet before and has no lease now; c-local failed. The retry writes
    c-local alone and is not refused for c-led. Counterproof: with c-led to write again,
    the retry is refused."""
    import json as _json
    import pegaprox.api.multi_sdn as msdn
    from datetime import datetime
    now = datetime.now().isoformat()
    seed.db.execute(
        'INSERT INTO multi_cluster_vnets (id,name,alias,zone,vni,asn,vrf_vxlan,controller,'
        'peers,member_clusters,subnets,desired_state,per_cluster_status,status,enabled,'
        'created_by,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,?,?,?)',
        ('v1', 'evx', '', 'z', 100, 65001, None, 'ctl', '', _json.dumps(['c-led', 'c-local']),
         '[]', _json.dumps({'name': 'evx'}),
         _json.dumps({'c-led': {'status': 'applied'}, 'c-local': {'status': 'failed'}}),
         'partial', 'tester', now, now))
    for cid in ('c-led', 'c-local'):
        api.set_manager(cid, api.make_fake_manager(cid))
    written = []
    monkeypatch.setattr(msdn, '_apply_on_cluster',
                        lambda cid, defn: written.append(cid) or {'cluster_id': cid,
                                                                  'status': 'applied',
                                                                  'steps': []})
    admin = api.as_user(seed.user('root', role='admin'))
    r = admin.post('/api/multi-sdn/vnets/v1/apply', json={})
    assert r.status_code == 200, r.data
    assert written == ['c-local']
    seed.db.execute("UPDATE multi_cluster_vnets SET per_cluster_status = ? WHERE id = 'v1'",
                    (_json.dumps({'c-led': {'status': 'failed'}, 'c-local': {'status': 'applied'}}),))
    r = admin.post('/api/multi-sdn/vnets/v1/apply', json={})
    assert r.status_code == 409 and r.get_json()['cluster'] == 'c-led', r.data
    assert written == ['c-local']


# --- a dry run of a cross-cluster migration -----------------------------------------------------------

def test_a_dry_run_cross_cluster_migration_needs_no_lease(api, seed, led, monkeypatch):
    """A dry run only reads: it answers with the preflight's plan, lease or not. The real
    migration is refused."""
    import pegaprox.api.vms as vms_api
    for cid in ('c-local', 'c-led'):
        api.set_manager(cid, api.make_fake_manager(cid))
    planned = []

    def preflight(data, *a, **k):
        planned.append(bool(data.get('dry_run')))
        return {'steps': []}, (vms_api.jsonify({'dry_run': True, 'steps': []}), 200)
    monkeypatch.setattr(vms_api, '_cross_preflight_for', preflight)
    monkeypatch.setattr(vms_api, '_require_vm_access', lambda *a, **k: None)
    admin = api.as_user(seed.user('root', role='admin'))
    body = {'source_cluster': 'c-local', 'target_cluster': 'c-led', 'vmid': 100,
            'source_node': 'n1', 'target_node': 'n2', 'dry_run': True}
    r = admin.post('/api/cross-cluster-migrate', json=body)
    assert r.status_code == 200 and r.get_json()['dry_run'] is True, r.data
    assert planned == [True]
    r = admin.post('/api/cross-cluster-migrate', json=dict(body, dry_run=False))
    assert r.status_code == 409 and r.get_json()['code'] == 'FED_NO_LEASE', r.data
    assert planned == [True]


# --- a deleted enrolled cluster ----------------------------------------------------------------------

def test_deleting_an_enrolled_cluster_keeps_it_on_record(api, seed, led, monkeypatch):
    """The cluster route deletes c-led, which this instance leads: the id stays on record
    as this instance's, so its vote backs no stale former owner's ask for it."""
    import pegaprox.api.clusters as clusters_api
    fake = api.make_fake_manager('c-led')
    fake.config.api_token_user = ''
    api.set_manager('c-led', fake)
    monkeypatch.setattr(clusters_api, '_retire_cluster_claim', lambda mgr: None)
    admin = api.as_user(seed.user('root', role='admin'))
    r = admin.delete('/api/clusters/c-led')
    assert r.status_code == 200, r.data
    assert federation.dropped_records().get('c-led') == led


@pytest.mark.parametrize('fails', ['cluster_owner', 'forget_deleted_cluster'])
def test_a_federation_step_of_a_delete_that_fails_says_so(api, seed, led, monkeypatch, caplog,
                                                         fails):
    """The delete goes through whatever the federation's part of it does, but a part that
    fails is logged: without the owner no record is kept, and a lease not given back is
    left to run out at the voters."""
    import logging
    import pegaprox.api.clusters as clusters_api
    fake = api.make_fake_manager('c-led')
    fake.config.api_token_user = ''
    api.set_manager('c-led', fake)
    monkeypatch.setattr(clusters_api, '_retire_cluster_claim', lambda mgr: None)

    def broken(*a, **kw):
        raise RuntimeError('database is locked')
    monkeypatch.setattr(federation, fails, broken)
    admin = api.as_user(seed.user('root', role='admin'))
    with caplog.at_level(logging.WARNING):
        r = admin.delete('/api/clusters/c-led')
    assert r.status_code == 200, r.data
    said = [m for m in caplog.messages if m.startswith('[FED]') and 'c-led' in m]
    assert said and 'database is locked' in said[0], caplog.messages
