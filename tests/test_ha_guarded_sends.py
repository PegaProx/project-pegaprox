"""Sends the transport guard did not see (#625 stage 2, design 5.3; what the round-two
attack on slice S4 found).

  * the routes that remove a node, join one and rescan a storage built bare paramiko
    clients, and the node reboot sent its shutdown on a channel of the client's
    transport: a former leader back from a pause that held its clocks sent them without
    a round. Their clients are guarded now and the channel asks guard_ssh first
  * behind an HTTP(S)_PROXY from the environment requests connects through a manager of
    its own, and a lease that ran out while the connection came up was not seen
  * the progress probes of an ESXi import run in a plain thread of the import job and
    were refused in an automatic group: they only read, and say so

MK Oct 2026 (#625)
"""
import socket
import subprocess
import threading
import time
import types
from unittest.mock import MagicMock

import paramiko
import pytest
import urllib3.connection
import urllib3.connectionpool

from pegaprox.core import ha as _ha
from pegaprox.core import ha_transport as hx
from test_ha_members import IDS, group  # noqa: F401
from _ha_lease_harness import T, auto  # noqa: F401
from test_ha_guard_rounds import _calls_from, _other_leader, pve

# what this file tests is the refusal itself
pytestmark = pytest.mark.guard_refusals


class _Sent(Exception):
    pass


def _recording(sent):
    def exec_command(self, cmd, *a, **k):
        sent.append(cmd)
        raise _Sent(cmd)
    return exec_command


def _fake_manager():
    m = pve()
    m.nodes_in_maintenance = {}

    class _Sess:
        def get(self, url, **k):
            return types.SimpleNamespace(status_code=200, json=lambda: {'data': [
                {'node': 'pve1', 'status': 'online'}, {'node': 'pve2', 'status': 'online'}]})
    m._create_session = lambda: _Sess()
    m._get_node_ip = lambda n: {'pve1': '10.0.0.11', 'pve2': '10.0.0.12'}.get(n)
    return m


def _paused_leader_back(auto, seed):
    """'a' was paused with its clocks held, another member leads now, 'a' runs again and
    believes its lease still runs."""
    auto.form(seed)
    auto.pause('a', freeze=True)
    auto.run(240, dt=1.0, members='bc', until=lambda: _other_leader(auto) is not None)
    other = _other_leader(auto)
    assert other is not None, 'nobody took over'
    auto.resume('a')
    _ha._guard_said.clear()
    return other


# --- the routes' own SSH ------------------------------------------------------------------

def test_a_former_leader_does_not_remove_a_node(auto, seed, monkeypatch):
    """DELETE .../cluster-membership reaches 'a' (its write gate reads is_active() on the
    held clock). `pvecm delnode` goes through a guarded client now: its round tells 'a'
    that another member leads, and nothing is sent."""
    import pegaprox.api.vms as vms_api
    from pegaprox.globals import cluster_managers
    other = _paused_leader_back(auto, seed)
    sent = []
    monkeypatch.setattr(paramiko.SSHClient, 'connect', lambda self, *a, **k: None)
    monkeypatch.setattr(paramiko.SSHClient, 'exec_command', _recording(sent))
    monkeypatch.setattr(vms_api, 'persist_host_keys', lambda c: None)
    monkeypatch.setitem(cluster_managers, 'c1', _fake_manager())
    mark = len(auto.g.calls)
    with auto.at('a') as ha:
        assert ha.is_active(), 'as a sees it, its lease runs'
        r = auto.admin.delete('/api/clusters/c1/nodes/pve2/cluster-membership', json={'confirm': True})
        asked = _calls_from(auto, 'a', mark)
        said = {why for _a, why in ha._guard_said}
    assert sent == [], (r.status_code, r.data[:300])
    assert asked, 'no round was asked'
    # what the caller hears is the write gate's answer (tests/test_ha_guard_answers.py)
    assert r.status_code == 503 and r.get_json()['code'] == 'HA_NO_LEASE'
    assert _ha.GUARD_UNCONFIRMED in said
    with auto.at(other) as ha:
        assert ha.is_active()


def test_a_former_leader_does_not_join_a_node(auto, seed, monkeypatch):
    """POST .../nodes/join: `pvecm add` goes out on a shell of a guarded client, which
    asks before the shell opens."""
    import pegaprox.api.vms as vms_api
    from pegaprox.globals import cluster_managers
    _paused_leader_back(auto, seed)
    shells = []
    monkeypatch.setattr(paramiko.SSHClient, 'connect', lambda self, *a, **k: None)
    monkeypatch.setattr(paramiko.SSHClient, 'invoke_shell', lambda self, *a, **k: shells.append(1) or MagicMock())
    monkeypatch.setattr(vms_api, 'persist_host_keys', lambda c: None)
    monkeypatch.setattr(vms_api.time, 'sleep', lambda s: None)
    m = _fake_manager()

    class _Sess:
        def get(self, url, **k):
            return types.SimpleNamespace(status_code=200, json=lambda: {'data': {
                'nodelist': [{'pve_fp': 'AA:BB', 'ring0_addr': '10.0.0.11'}]}})
    m._create_session = lambda: _Sess()
    monkeypatch.setitem(cluster_managers, 'c1', m)
    mark = len(auto.g.calls)
    with auto.at('a') as ha:
        assert ha.is_active()
        r = auto.admin.post('/api/clusters/c1/nodes/join',
                            json={'node_ip': '10.0.0.13', 'password': 'pw'})
        asked = _calls_from(auto, 'a', mark)
        said = {why for _a, why in ha._guard_said}
    assert shells == [], (r.status_code, r.data[:300])
    assert asked and _ha.GUARD_UNCONFIRMED in said


def test_a_former_leader_does_not_rescan_a_storage(auto, seed, monkeypatch):
    """POST .../storage/<id>/rescan with deep_scan and pvresize: the SCSI rescan and the
    pvresize go through a guarded client, the first command asks and is refused."""
    from pegaprox.globals import cluster_managers
    import pegaprox.api.storage as storage_api
    import pegaprox.utils.ssh_security as sec
    from pegaprox import globals as _g
    _paused_leader_back(auto, seed)
    sent = []
    monkeypatch.setattr(paramiko.SSHClient, 'connect', lambda self, *a, **k: None)
    monkeypatch.setattr(paramiko.SSHClient, 'exec_command', _recording(sent))
    monkeypatch.setattr(sec, 'persist_host_keys', lambda c: None)
    m = _fake_manager()

    class _Sess:
        def get(self, url, **k):
            if url.endswith('/storage/lvm1'):
                return types.SimpleNamespace(status_code=200, json=lambda: {'data': {
                    'type': 'lvm', 'vgname': 'vg1', 'nodes': 'pve1'}})
            return types.SimpleNamespace(status_code=200, json=lambda: {'data': [
                {'node': 'pve1', 'status': 'online'}]})

        def post(self, url, **k):
            raise AssertionError('no API write expected in this test')
    m._create_session = lambda: _Sess()
    m.session = _Sess()
    monkeypatch.setitem(cluster_managers, 'c1', m)
    monkeypatch.setattr(storage_api, 'get_connected_manager', lambda cid: (m, None), raising=False)
    monkeypatch.setattr(_g, '_ssh_semaphore', threading.BoundedSemaphore(4))
    mark = len(auto.g.calls)
    with auto.at('a') as ha:
        assert ha.is_active()
        r = auto.admin.post('/api/clusters/c1/datacenter/storage/lvm1/rescan',
                            json={'deep_scan': True, 'pvresize': True})
        asked = _calls_from(auto, 'a', mark)
        said = {why for _a, why in ha._guard_said}
    assert sent == [], (r.status_code, r.data[:1400])
    assert asked and _ha.GUARD_UNCONFIRMED in said


def test_the_reboot_of_a_node_asks_before_its_shutdown_goes_out(auto, seed, monkeypatch):
    """POST .../nodes/<n>/action/reboot: `id -u` goes through the guarded client and asks
    its round. The lease ends right after; the shutdown that follows goes on a channel of
    the transport, and guard_ssh() before it refuses it."""
    from pegaprox.globals import cluster_managers
    import pegaprox.api.vms as vms_api
    auto.form(seed)
    sent = []

    class _Chan:
        def get_pty(self):
            pass

        def settimeout(self, t):
            pass

        def exec_command(self, cmd):
            sent.append(cmd)

        def recv(self, n):
            return b''

        def close(self):
            pass

    class _Out:
        channel = types.SimpleNamespace(recv_exit_status=lambda: 0)

        def __init__(self):
            self.done = False

        def read(self, *a):
            if self.done:
                return b''
            self.done = True
            return b'0\n'

    class _Client:
        def exec_command(self, cmd, *a, **k):
            sent.append(cmd)
            # the lease of 'a' ends right after the round this command asked for
            auto.isolate('a')
            _ha._rts[IDS['a']].node.lease_until = _ha.ha_clock() - 1
            return None, _Out(), _Out()

        def get_transport(self):
            return types.SimpleNamespace(open_session=lambda: _Chan(),
                                         getpeername=lambda: ('10.0.0.11', 22))

        def close(self):
            pass
    m = _fake_manager()
    m.nodes_in_maintenance = {'pve1': types.SimpleNamespace(status='completed')}
    m._ssh_connect = lambda ip, **k: hx.guard_client(_Client(), ip)
    monkeypatch.setitem(cluster_managers, 'c1', m)
    monkeypatch.setattr(vms_api.time, 'sleep', lambda s: None)
    _ha._guard_said.clear()
    with auto.at('a') as ha:
        r = auto.admin.post('/api/clusters/c1/nodes/pve1/action/reboot')
        said = {why for _a, why in ha._guard_said}
    assert sent == ['id -u'], (sent, r.data[:300])
    assert r.status_code == 503 and r.get_json()['code'] == 'HA_NO_LEASE'
    assert _ha.GUARD_NO_LEASE in said


def test_in_a_manual_group_the_reboot_goes_out_as_before(api, seed, monkeypatch):
    """The counterproof outside an automatic group: the same route sends its shutdown and
    asks for no round."""
    import pegaprox.api.vms as vms_api
    sent = []
    chan = types.SimpleNamespace(get_pty=lambda: None, settimeout=lambda t: None, recv=lambda n: b'',
                                 close=lambda: None, exec_command=sent.append)
    replies = [b'0\n', b'']
    out = types.SimpleNamespace(read=lambda *a: replies.pop(0) if replies else b'',
                                channel=types.SimpleNamespace(recv_exit_status=lambda: 0))
    client = types.SimpleNamespace(exec_command=lambda cmd, *a, **k: sent.append(cmd) or (None, out, out),
                                   get_transport=lambda: types.SimpleNamespace(open_session=lambda: chan),
                                   close=lambda: None)
    m = _fake_manager()
    m.nodes_in_maintenance = {'pve1': types.SimpleNamespace(status='completed')}
    m._ssh_connect = lambda ip, **k: hx.guard_client(client, ip)
    api.set_manager('c1', m)
    monkeypatch.setattr(vms_api.time, 'sleep', lambda s: None)
    rounds = []
    monkeypatch.setattr(_ha, 'confirm_lease', lambda *a, **k: rounds.append(a) or True)
    r = api.as_user(seed.user('root1', role='admin')).post('/api/clusters/c1/nodes/pve1/action/reboot')
    assert r.status_code == 200, r.data
    assert sent == ['id -u', 'shutdown -r now'] and rounds == []


# --- behind a proxy from the environment ---------------------------------------------------

@pytest.mark.parametrize('proxy', [False, True], ids=['no proxy', 'HTTPS_PROXY set'])
def test_a_lease_that_ends_while_the_connection_comes_up_stops_the_call(auto, seed, monkeypatch, proxy):
    """ha_transport.http() (the ESXi REST client, the XCP-ng uploads) and the PBS session
    keep requests' trust_env. With HTTPS_PROXY set requests sends through
    adapter.proxy_manager_for(), a manager of its own: its pools ask again once the
    connection is up now, as the adapter's own pools do."""
    auto.form(seed)
    if proxy:
        monkeypatch.setenv('HTTPS_PROXY', 'http://10.9.9.9:3128')
        monkeypatch.delenv('NO_PROXY', raising=False)
        monkeypatch.delenv('no_proxy', raising=False)
    sent = []

    def slow_connect(self, conn):
        # a dark host or a slow proxy: the lease of 'a' ends while it connects
        _ha._rts[IDS['a']].node.lease_until = _ha.ha_clock() - 1
        conn.sock = MagicMock()

    def request(self, method, url, *a, **k):
        sent.append(f'{method} {url}')
        raise _Sent(url)
    monkeypatch.setattr(urllib3.connectionpool.HTTPSConnectionPool, '_validate_conn', slow_connect)
    # through a proxy urllib3 connects (and tunnels) in _prepare_proxy
    monkeypatch.setattr(urllib3.connectionpool.HTTPSConnectionPool, '_prepare_proxy', slow_connect)
    monkeypatch.setattr(urllib3.connection.HTTPConnection, 'request', request)
    monkeypatch.setattr(urllib3.connection.HTTPConnection, '_tunnel', lambda self: None, raising=False)
    _ha._guard_said.clear()
    with auto.at('a') as ha:
        assert ha.confirm_lease()
        with pytest.raises(ha.GuardRefused) as e:
            hx.http('POST', 'https://10.0.0.30/api/vcenter/vm/vm-12/power/stop', timeout=5, verify=False)
    assert sent == [] and e.value.why == _ha.GUARD_NO_LEASE


def test_the_proxy_manager_of_an_adapter_gets_pools_that_ask(monkeypatch):
    """Whatever pools the proxy manager uses, those of a socks:// proxy as well, ask once
    their connection is up; asking the adapter again does not stack another layer."""
    import requests
    adapter = hx.guard_adapter(requests.adapters.HTTPAdapter())
    manager = adapter.proxy_manager_for('http://10.9.9.9:3128')
    pools = manager.pool_classes_by_scheme
    assert pools == hx.GUARDED_POOLS
    assert adapter.proxy_manager_for('http://10.9.9.9:3128').pool_classes_by_scheme == pools

    class _Conn(urllib3.connection.HTTPConnection):
        pass

    class _SocksPool(urllib3.connectionpool.HTTPConnectionPool):
        ConnectionCls = _Conn
    asking = hx._asking_pool(_SocksPool)
    assert issubclass(asking, _SocksPool) and issubclass(asking.ConnectionCls, _Conn)
    assert hx._asking_pool(asking) is asking and hx._asking_pool(_SocksPool) is asking
    asked = []
    monkeypatch.setattr(hx, '_asked_up', lambda conn, method, url: asked.append((method, url)))
    monkeypatch.setattr(_Conn, 'request', lambda self, method, url, *a, **k: 'sent')
    assert asking.ConnectionCls('10.0.0.30').request('POST', '/x') == 'sent'
    assert asked == [('POST', '/x')]


# --- the progress of an ESXi import ----------------------------------------------------------

@pytest.fixture
def wire(monkeypatch):
    """Every call that reaches a transport is recorded and raises _Sent."""
    sent = []

    def hit(kind, what):
        sent.append((kind, what))
        raise _Sent(f'{kind} {what}')
    monkeypatch.setattr(urllib3.connection.HTTPConnection, 'request',
                        lambda self, method, url, *a, **k: hit('http', f'{method} {self.host}{url}'))
    monkeypatch.setattr(urllib3.connectionpool.HTTPSConnectionPool, '_validate_conn', lambda self, conn: None)
    for cls in (urllib3.connection.HTTPConnection, urllib3.connection.HTTPSConnection):
        monkeypatch.setattr(cls, 'connect', lambda self: setattr(self, 'sock', object()))
    for name in ('Popen', 'run', 'call', 'check_call', 'check_output'):
        monkeypatch.setattr(subprocess, name, lambda argv, *a, **k: hit('proc', ' '.join(map(str, argv))[-120:]))
    monkeypatch.setattr(paramiko.SSHClient, 'connect',
                        lambda self, hostname=None, *a, **k: hit('tcp', f'{hostname}:22'))
    monkeypatch.setattr(socket, 'create_connection', lambda addr, *a, **k: hit('tcp', f'{addr[0]}:{addr[1]}'))
    return sent


def test_the_progress_probes_of_an_import_go_out_in_an_automatic_group(auto, seed, wire):
    """The import job (ha.as_job) starts _monitor_disk_write in a plain thread. Its
    probes (stat, lvs, the dd log over _pve_node_exec) only read, and say so: they reach
    the node, nothing is refused for want of a token."""
    from pegaprox.core import v2p
    auto.form(seed)
    m = pve()
    m._is_node_blocked = lambda node: (False, 0)
    m._get_node_ip = lambda node: '10.0.0.11'
    m._register_node_failure = lambda node: None
    # its node list, fresh: _pve_node_exec runs commands on a listed node only (#1224)
    m._cached_node_dict, m._nodes_cache_time = {'pve1': {'node': 'pve1'}}, time.time()
    task = types.SimpleNamespace(id='t1', log=lambda s: None, update_progress=lambda *a: None)
    stop = threading.Event()
    seen = []
    _ha._guard_said.clear()
    with auto.at('a') as ha:
        def job():
            t = threading.Thread(target=v2p._monitor_disk_write, daemon=True,
                                 args=(m, 'pve1', '/var/lib/vz/images/100/a.raw', 10 << 30, task,
                                       'disk0', stop))
            t.start()
            time.sleep(1.0)            # one pass of its loop
            stop.set()
            t.join(10)
            seen.append(t.is_alive())
        runner = threading.Thread(target=ha.as_job(job, 'ESXi import'))
        runner.start()
        runner.join(15)
        said = {why for _a, why in ha._guard_said}
    assert seen == [False]
    assert ('http', 'POST 10.0.0.1/api2/json/nodes/pve1/execute') in wire, wire
    assert _ha.GUARD_NO_TOKEN not in said, said
