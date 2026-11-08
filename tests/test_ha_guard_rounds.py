"""A round before every call, and the calls that go out again (#625 stage 2, design 5.3,
5.4 and 5.6; what the review of slice S4 found).

  * in an automatic group a call that changes something goes out only after a majority
    round that started after it was asked for: the confirm of a step covers its first
    call, every further call gets a round of its own, shared with whoever waits, and so
    does every call of a user job and every write of a request to the leader. A former
    leader back from a pause that held its clocks learns from that round that another
    one leads, and sends nothing
  * a step that sends many commands does not run out of lease while the lease is held
  * a clock jump the lease loop saw voids what was confirmed before it
  * a call sent once more (ESXi REST after a 401, XenAPI after SESSION_INVALID, the
    sshpass fallback of _ssh_exec) and a connection that came up late are checked again
  * a recovery cut short with a guest moved and not started stays listed and is said
  * the members that serve users read over SSH in a GET and open ESXi console tickets,
    and still refuse every write
  * what a task confirmed does not serve the next task of the same worker
  * in a manual group and on an instance of its own none of this asks anything

MK Oct 2026 (#625)
"""
import shutil
import socket
import subprocess
import threading
import time as _time
import types
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import MagicMock

import pytest
import requests

from pegaprox.core import ha as _ha
from pegaprox.core import ha_transport as hx
from test_ha_members import IDS, group  # noqa: F401
from _ha_lease_harness import T, auto  # noqa: F401

START = 'https://10.0.0.1:8006/api2/json/nodes/pve1/qemu/101/status/start'


class Reached(Exception):
    """The call got to the transport."""


def _refused(fn, *args, **kwargs):
    with pytest.raises(_ha.GuardRefused) as e:
        fn(*args, **kwargs)
    return str(e.value)


def _rounds(monkeypatch, ha):
    """The need of every confirm_lease() from here on, the guard's own included."""
    asked = []
    real = ha.confirm_lease
    monkeypatch.setattr(ha, 'confirm_lease', lambda need=ha.NEED_STEP: asked.append(need) or real(need))
    return asked


def _other_leader(auto):
    for n in 'bc':
        with auto.at(n) as ha:
            if ha.is_active():
                return n
    return None


def _calls_from(auto, n, since):
    return [c for c in auto.g.calls[since:] if c[0] == n]


def pve():
    """A PegaProxManager without a network: a ticket, an SSH password, one host."""
    from pegaprox.core.manager import PegaProxManager
    m = PegaProxManager.__new__(PegaProxManager)
    m.id, m.logger = 'c1', MagicMock()
    m._api_token, m._ticket, m._csrf_token, m._ssl_verify = None, 't', 'c', False
    m.config = types.SimpleNamespace(host='10.0.0.1', user='root@pam', pass_='pw', name='c1',
                                     ssh_user='root', ssh_key='', ssh_port=22, fallback_hosts=[],
                                     ssh_disabled=False)
    m.current_host = '10.0.0.1'
    m.is_connected = True
    m.api_timeout = 10
    m.ha_config = {}
    m.ha_lock = threading.Lock()
    m.ha_node_status = {}
    m._no_agent_vms = set()
    m._using_api_token = False
    return m


def _esxi():
    from pegaprox.core.vmware import VMwareManager
    v = VMwareManager('v1', {'host': '10.0.0.30', 'password': 'pw'})
    v.session_id = 'sid'
    return v


def _no_sleep(monkeypatch, module):
    monkeypatch.setattr(module, 'time', types.SimpleNamespace(
        sleep=lambda s: None, time=_time.time, monotonic=_time.monotonic,
        strftime=_time.strftime, perf_counter=_time.perf_counter))


def _done(argv, out='OK\n'):
    return types.SimpleNamespace(pid=4242, returncode=0, poll=lambda: 0, wait=lambda: 0,
                                 communicate=lambda data=None, timeout=None: (out, ''))


class _Node:
    """ssh to a node: every command takes `took` seconds of lease time, and the lease loop
    of 'a' renews in the meantime."""

    def __init__(self, auto, took=1.5, after=None):
        self.auto, self.took, self.after, self.cmds = auto, took, after, []

    def _ran(self, argv):
        self.cmds.append(str(argv[-1]))
        self.auto.advance(self.took)
        self.auto.step('a')
        if self.after:
            self.after(self)

    def popen(self, argv, **kw):
        self._ran(argv)
        return _done(argv)

    def run(self, argv, **kw):
        self._ran(argv)
        return subprocess.CompletedProcess(argv, 0, 'OK\n', '')


def _stops(cmds):
    return [c.split()[2] for c in cmds if c.startswith('qm stop')]


# --- a round before every call (the decision on the review) -----------------------------

@pytest.mark.guard_refusals
def test_a_job_back_from_a_pause_that_held_its_clocks_sends_nothing_while_another_leads(auto, seed):
    """A QEMU pause that holds the guest's clocks: the lease of 'a' still runs as 'a' sees
    it. Its job asks the voters before its next call, hears of the newer leader and sends
    nothing."""
    auto.form(seed)
    with auto.at('a') as ha:
        ha._guard_tls.job = 'evacuation of pve1'
        hx.guard_http('POST', START)
    auto.pause('a', freeze=True)
    auto.run(240, dt=1.0, members='bc', until=lambda: _other_leader(auto) is not None)
    other = _other_leader(auto)
    assert other is not None, 'nobody took over'
    auto.resume('a')
    mark = len(auto.g.calls)
    with auto.at('a') as ha:
        assert ha.is_active()
        why = _refused(hx.guard_http, 'POST', START.replace('101', '102'))
        ha._guard_tls.job = None
    assert _ha.GUARD_UNCONFIRMED in why
    assert _calls_from(auto, 'a', mark), 'it sent without asking the voters'
    with auto.at(other) as ha:
        assert ha.is_active()


@pytest.mark.guard_refusals
def test_a_request_on_a_leader_back_from_such_a_pause_sends_nothing(auto, seed):
    auto.form(seed)
    auto.pause('a', freeze=True)
    auto.run(240, dt=1.0, members='bc', until=lambda: _other_leader(auto) is not None)
    other = _other_leader(auto)
    assert other is not None
    auto.resume('a')
    mark = len(auto.g.calls)
    with auto.at('a') as ha, auto.g.api.app.test_request_context('/', method='POST'):
        assert ha.is_active()
        _refused(hx.guard_http, 'POST', START)
        _refused(hx.guard_ssh, '10.0.0.11', 'qm stop 101')
    assert _calls_from(auto, 'a', mark)
    with auto.at(other) as ha:
        assert ha.is_active()


def test_every_write_of_a_step_a_job_and_a_request_comes_after_a_round_of_its_own(auto, seed, monkeypatch):
    """Three writes each way, three rounds each way, and what it costs: printed for the
    slice report. In this harness a round runs both voters' routes in this process; the
    lease clock moves 100 ms per wait for a round, the shortest spacing of two."""
    auto.form(seed)
    said = []
    with auto.at('a') as ha:
        rounds = _rounds(monkeypatch, ha)
        for label in ('step', 'job', 'request'):
            rounds.clear()
            ha._guard_tls.token = None
            ha._guard_tls.job = 'a job' if label == 'job' else None
            ctx = auto.g.api.app.test_request_context('/', method='POST') if label == 'request' else None
            if ctx is not None:
                ctx.push()
            try:
                t0, c0 = _time.perf_counter(), ha.ha_clock()
                if label == 'step':
                    assert ha.confirm_step('three migrations')
                for vmid in (101, 102, 103):
                    hx.guard_http('POST', START.replace('101', str(vmid)))
                wall, lease = _time.perf_counter() - t0, ha.ha_clock() - c0
            finally:
                if ctx is not None:
                    ctx.pop()
            assert len(rounds) == 3, (label, rounds)
            said.append(f'{label}: {wall / 3 * 1e3:.1f} ms and {lease / 3:.2f} s of lease clock per write')
        ha._guard_tls.job = None
    print('\n' + '; '.join(said))


# --- a step of many commands while the lease is held -------------------------------------

def test_the_ssh_stop_of_a_cut_off_nodes_guests_stops_every_guest(auto, seed, monkeypatch):
    """30 guests on a node that is cut off and still answers SSH, 1.5 s each: 45 s, longer
    than any one round's lease. The first stop goes out on the confirm of the step, each
    further one after a round of its own, and every guest is stopped."""
    auto.form(seed)
    node = _Node(auto)
    monkeypatch.setattr(subprocess, 'Popen', node.popen)
    monkeypatch.setattr(subprocess, 'run', node.run)
    m = pve()
    vmids = list(range(101, 131))
    with auto.at('a') as ha:
        rounds = _rounds(monkeypatch, ha)
        assert ha.confirm_step('stopping the guests on pve2', ha.NEED_SAME_GOAL)
        ok = m._ha_ssh_stop_vms_on_node('pve2', vmids=vmids, reachable_ips=['10.0.0.12'])
        assert ha.is_active()
    assert ok is True and _stops(node.cmds) == [str(v) for v in vmids]
    assert len(rounds) == len(vmids) and set(rounds) == {_ha.NEED_SAME_GOAL}


def test_fencing_the_nodes_outside_fences_every_one(auto, seed, monkeypatch):
    """Three nodes behind slow BMCs (3 s a call) before quorum is forced, all under the one
    confirm before the fencing: each power-off after a round of its own."""
    import pegaprox.core.manager as mgr_mod
    _no_sleep(monkeypatch, mgr_mod)
    auto.form(seed)
    reads = {}

    class _Bmc(_Node):
        def popen(self, argv, **kw):
            self._ran(argv)
            host = argv[argv.index('-H') + 1]
            out = ''
            if argv[-1] == 'status':
                reads[host] = reads.get(host, 0) + 1
                out = 'Chassis Power is off' if reads[host] >= 2 else 'Chassis Power is on'
            return _done(argv, out)
    bmc = _Bmc(auto, took=3.0)
    monkeypatch.setattr(subprocess, 'Popen', bmc.popen)
    m = pve()
    m.ha_config = {'fencing': {n: {'type': 'ipmi', 'host': f'10.0.1.{i}', 'password': 'pw'}
                               for i, n in enumerate(('pve2', 'pve3', 'pve4'), start=2)}}
    m._ha_refuse = MagicMock()
    with auto.at('a') as ha:
        assert ha.confirm_step('fencing pve2', ha.NEED_SAME_GOAL)
        assert m._ha_fence_outside('pve2', ['pve2', 'pve3', 'pve4']) is True
        assert ha.is_active()
    assert [c for c in bmc.cmds if c == 'off'] == ['off'] * 3


@pytest.mark.guard_refusals
def test_a_further_command_of_a_step_is_not_sent_without_a_majority(auto, seed, monkeypatch):
    """The other side: the link to every voter goes after the first stop. The next stop
    asks, finds no majority, and is not sent; nor is anything after it in that step."""
    auto.form(seed)

    def cut(n):
        if _stops(n.cmds):
            auto.isolate('a')
    node = _Node(auto, after=cut)
    monkeypatch.setattr(subprocess, 'Popen', node.popen)
    monkeypatch.setattr(subprocess, 'run', node.run)
    m = pve()
    with auto.at('a') as ha:
        assert ha.confirm_step('stopping the guests on pve2', ha.NEED_SAME_GOAL)
        ok = m._ha_ssh_stop_vms_on_node('pve2', vmids=[101, 102, 103], reachable_ips=['10.0.0.12'])
        said = {why for _a, why in ha._guard_said}
    assert ok is False and _stops(node.cmds) == ['101']
    assert _ha.GUARD_UNCONFIRMED in said


# --- a clock jump --------------------------------------------------------------------------

def test_a_clock_jump_the_loop_saw_voids_the_token_from_before_it(auto, seed, monkeypatch):
    """Design 4.2: a step of the wall clock against the lease clock forces a round before
    any step goes out. The token from before the step is not used, the call waits for a
    round that started after it."""
    auto.form(seed)
    with auto.at('a') as ha:
        assert ha.confirm_lease()
        tok = ha._guard_tls.token
        node = ha._rts[IDS['a']].node
    auto.skew['a'] = 90.0                          # NTP steps the wall clock of 'a'
    with auto.at('a') as ha:
        ha.lease_step()                            # one pass of its loop
        assert node._jump_at > float('-inf'), 'the loop did not see the step'
        assert not ha._token_fits(ha._load(), tok)
        rounds = _rounds(monkeypatch, ha)
        hx.guard_http('POST', START)
        assert not tok.used and len(rounds) == 1
        assert node._last_round_t0 >= node._jump_at


# --- interrupted recoveries (5.6) ------------------------------------------------------------

def _worker_fake(monkeypatch, moved, started):
    """A manager for _ha_recovery_worker: pve2 failed and is unreachable, one guest (101)
    on shared storage, pve1 the target. The config move and the start are recorded."""
    from pegaprox.core.manager import PegaProxManager
    import pegaprox.core.manager as mgr_mod
    _no_sleep(monkeypatch, mgr_mod)
    f = MagicMock()
    f.id = 'c1'
    f.logger = MagicMock()
    f.ha_config = {'quorum_enabled': False, 'verify_network_before_recovery': False}
    f.ha_lock = threading.Lock()
    f.ha_node_status = {}
    f.ha_recovery_in_progress = {'pve2': True}
    f.current_host, f.is_connected, f.session = '10.0.0.1', True, object()
    f.host, f.api_port = '10.0.0.1', 8006
    f.config = types.SimpleNamespace(user='root@pam', host='10.0.0.1', name='c1')
    f._using_api_token = False
    f._ha_fence_timing.return_value = {'wait': 0}
    f._ha_recovery_allowed.return_value = []
    f._ha_check_node_via_ssh.return_value = {'reachable': False}
    f._ha_fence_verified.return_value = False
    f._ha_fence_node.return_value = True
    f._ha_get_vms_on_node.return_value = [{'vmid': 101, 'type': 'qemu', 'name': 'web'}]
    f._ha_get_available_nodes.return_value = ['pve1']
    f._ha_check_vm_storage.return_value = 'shared'
    f._ha_select_target_node.return_value = 'pve1'
    f._ha_may_force_quorum.return_value = True
    f._ha_clear_vm_lock.return_value = True
    f._ha_vm_is_on.return_value = True
    # pve2 stays down while it is recovered (the looks of the recovery worker)
    f._ha_node_back.return_value = False
    f._ha_node_listed_online.return_value = False
    f._ha_guests_now.return_value = None
    f._ha_move_vm_config.side_effect = lambda *a: moved.append(a[0]) or True
    f._create_session.return_value.post.side_effect = \
        lambda url, **k: started.append(url) or types.SimpleNamespace(status_code=200, text='')
    f._ha_start_vm_on_node.side_effect = lambda *a: PegaProxManager._ha_start_vm_on_node(f, *a)
    return f


def test_one_failed_confirm_between_the_move_and_the_start_keeps_the_run_and_says_so(
        auto, seed, db, monkeypatch):
    """The round before the start of 101 finds no majority, the lease itself still runs.
    101 sits moved and stopped on pve1 and pve2 holds no guest any more: the run stays in
    the journal, is listed here at once and is said as interrupted."""
    from pegaprox.core.manager import PegaProxManager
    auto.form(seed)
    moved, started = [], []
    f = _worker_fake(monkeypatch, moved, started)
    real = _ha.confirm_step

    def blip(what, need=_ha.NEED_STEP):
        if what.startswith('starting 101'):
            auto.isolate('a')
            try:
                return real(what, need)
            finally:
                auto.heal()
        return real(what, need)
    monkeypatch.setattr(_ha, 'confirm_step', blip)
    with auto.at('a') as ha:
        PegaProxManager._ha_recovery_worker(f, 'pve2')
        assert ha.is_active()
        left = ha.recovery_leftovers('c1')
    assert moved == [101] and started == []
    assert len(left) == 1 and left[0]['moved'] == [101] and left[0]['node'] == 'pve2'
    said = [c.args for c in f._ha_refuse.call_args_list if c.args[0] == 'ha.recovery_interrupted']
    assert len(said) == 1 and 'pve2' in said[0][1] and '101' in said[0][1]


def test_a_lease_lost_between_the_move_and_the_start_keeps_the_run_for_the_next_leader(
        auto, seed, db, monkeypatch):
    from pegaprox.core.manager import PegaProxManager
    auto.form(seed)
    moved, started = [], []
    f = _worker_fake(monkeypatch, moved, started)
    real_move = f._ha_move_vm_config.side_effect

    def move_then_lose(*a):
        out = real_move(*a)
        auto.isolate('a')
        auto.advance(T.L + 5)                     # the lease of 'a' runs out
        return out
    f._ha_move_vm_config.side_effect = move_then_lose
    with auto.at('a') as ha:
        PegaProxManager._ha_recovery_worker(f, 'pve2')
        assert not ha.is_active()
        ha._recovery_live.clear()                 # what a restart or a new leader sees
        left = ha.recovery_leftovers('c1')
    assert moved == [101] and started == []
    assert len(left) == 1 and left[0]['moved'] == [101]
    # said by the next leader, not by the one that lost the lease
    assert not [c for c in f._ha_refuse.call_args_list if c.args[0] == 'ha.recovery_interrupted']


# --- calls that go out again -----------------------------------------------------------------

def _adapter_send(monkeypatch, sent, first=401, on_first=None, body=b'{"value": "ok"}'):
    def send(self, request, **kw):
        sent.append(f'{request.method} {request.url}')
        r = requests.Response()
        r.request, r.encoding = request, 'utf-8'
        if len(sent) == 1:
            r.status_code, r._content = first, b''
            if on_first:
                on_first()
        else:
            r.status_code, r._content = 200, body
        return r
    monkeypatch.setattr(requests.adapters.HTTPAdapter, 'send', send)


@pytest.mark.guard_refusals
def test_esxi_rest_posts_again_after_a_401_only_while_the_lease_holds(auto, seed, monkeypatch):
    """api_post logs in again after a 401 and sends the POST once more: checked again, on
    the token the first one went out on, no round of its own. The lease ran out while the
    first one was out: the second does not go."""
    auto.form(seed)
    sent = []
    _adapter_send(monkeypatch, sent)
    v = _esxi()
    monkeypatch.setattr(v, 'connect', lambda: True)
    with auto.at('a') as ha:
        rounds = _rounds(monkeypatch, ha)
        assert ha.confirm_lease()
        assert v.vm_power_action('vm-12', 'stop') == {'data': {'value': 'ok'}}
        assert len(sent) == 2 and len(rounds) == 1
    sent.clear()

    def gone():
        _ha._rts[IDS['a']].node.lease_until = _ha.ha_clock() - 1
    _adapter_send(monkeypatch, sent, on_first=gone)
    with auto.at('a') as ha:
        assert ha.confirm_lease()
        out = v.vm_power_action('vm-12', 'stop')
        assert not ha.is_active()
    assert len(sent) == 1 and 'refused' in out['error']


@pytest.mark.guard_refusals
def test_xapi_sends_a_write_again_after_a_new_login_only_while_the_lease_holds(auto, seed, monkeypatch):
    """XenAPI sends a call again after a new login when the pool says SESSION_INVALID. Each
    send on the wire is checked: with the lease gone during the first send and the login,
    the write does not go out a second time."""
    import xmlrpc.client
    import XenAPI
    auto.form(seed)
    sent = []
    lose = {'on': False}

    def request(self, host, handler, body, verbose=False):
        params, name = xmlrpc.client.loads(body)
        sent.append(name)
        if name == 'session.login_with_password':
            return ({'Status': 'Success', 'Value': 'OpaqueRef:s2'},)
        if name == 'VM.hard_shutdown' and sent.count(name) == 1:
            if lose['on']:
                _ha._rts[IDS['a']].node.lease_until = _ha.ha_clock() - 1
            return ({'Status': 'Failure', 'ErrorDescription': ['SESSION_INVALID', 'OpaqueRef:s1']},)
        return ({'Status': 'Success', 'Value': 'OpaqueRef:task'},)
    monkeypatch.setattr(xmlrpc.client.Transport, 'request', request)
    for gone in (False, True):
        sent.clear()
        lose['on'] = gone
        session = hx.guard_xapi(XenAPI.Session('https://10.0.0.40', ignore_ssl=True))
        with auto.at('a') as ha:
            session.xenapi.login_with_password('root', 'pw', '1.0', 'PegaProx')
            assert ha.confirm_lease()
            if gone:
                _refused(session.xenapi.VM.hard_shutdown, 'OpaqueRef:vm')
            else:
                assert session.xenapi.VM.hard_shutdown('OpaqueRef:vm') == 'OpaqueRef:task'
        twice = ['session.login_with_password', 'VM.hard_shutdown', 'session.login_with_password']
        assert sent == (twice if gone else twice + ['VM.hard_shutdown']), sent


@pytest.mark.guard_refusals
def test_a_direct_request_whose_connection_comes_up_late_is_checked_again(auto, seed, monkeypatch):
    """The ESXi REST client and the XCP-ng uploads have no session of their own: they go
    out through ha_transport.http, whose connection asks again once it is up. A TLS
    connect that hangs past the lease stops the request there."""
    import urllib3.connection
    import urllib3.connectionpool
    auto.form(seed)
    sent = []
    hang = {'on': True}

    def validate(self, conn):
        if hang['on']:
            _ha._rts[IDS['a']].node.lease_until = _ha.ha_clock() - 1

    def connect(self):
        self.sock = object()

    def request(self, method, url, *a, **k):
        sent.append(f'{method} {self.host}{url}')
        raise Reached(url)
    monkeypatch.setattr(urllib3.connectionpool.HTTPSConnectionPool, '_validate_conn', validate)
    monkeypatch.setattr(urllib3.connection.HTTPSConnection, 'connect', connect)
    monkeypatch.setattr(urllib3.connection.HTTPConnection, 'request', request)
    with auto.at('a') as ha:
        node = ha._rts[IDS['a']].node
        keep = node.lease_until
        assert ha.confirm_lease()
        out = _esxi().vm_power_action('vm-12', 'stop')
        assert sent == [] and 'refused' in out['error']
        # the positive control: the lease back, a fresh round, the request reaches the wire
        node.lease_until, hang['on'] = keep, False
        assert ha.is_active() and ha.confirm_lease()
        _esxi().vm_power_action('vm-12', 'stop')
    assert sent == ['POST 10.0.0.30/api/vcenter/vm/vm-12/power/stop']


@pytest.mark.guard_refusals
def test_a_plain_http_connection_is_asked_again_once_it_is_up(auto, seed, monkeypatch):
    """Plain HTTP connects inside request(): the guarded connection connects first and
    asks after it, so a connect that stalls past the lease is caught too."""
    import urllib3.connection
    auto.form(seed)
    sent = []

    def connect(self):
        _ha._rts[IDS['a']].node.lease_until = _ha.ha_clock() - 1
        self.sock = object()
    monkeypatch.setattr(urllib3.connection.HTTPConnection, 'connect', connect)
    monkeypatch.setattr(urllib3.connection.HTTPConnection, 'request',
                        lambda self, method, url, *a, **k: sent.append(url))
    conn = hx._GuardedHTTPConnection('10.0.0.40', 80)
    with auto.at('a') as ha:
        assert ha.confirm_lease()
        hx.guard_http('PUT', '/import_raw_vdi')    # the ask before the send, as a session makes it
        why = _refused(conn.request, 'PUT', '/import_raw_vdi')
    assert sent == [] and _ha.GUARD_NO_LEASE in why


def _ssh_exec_world(monkeypatch, auto, delay):
    """paramiko that fails (after `delay` seconds of lease time per try) and a recorded
    Popen; returns (popen calls, registered process groups, exec_command calls). A
    subprocess.run() outside node_cmd fails the test: the fallback is a node command."""
    import paramiko
    import pegaprox.utils.ssh as ssh_mod
    popen, registered, execs = [], [], []
    # gevent's subprocess.run has a Popen of its own: stopped here as well
    monkeypatch.setattr(subprocess, 'run', lambda argv, **kw: pytest.fail(f'ran outside node_cmd: {argv[-1]}'))

    def tcp(addr, timeout=None, *a, **k):
        auto.advance(delay['tcp'])
        raise socket.timeout('timed out')

    def connect(self, *a, **k):
        auto.advance(delay['connect'])
        if delay.get('connects'):
            return None
        raise socket.timeout('timed out')
    monkeypatch.setattr(socket, 'create_connection', tcp)
    monkeypatch.setattr(paramiko.SSHClient, 'connect', connect)
    monkeypatch.setattr(paramiko.SSHClient, 'exec_command', lambda self, cmd, *a, **k: execs.append(cmd))
    monkeypatch.setattr(ssh_mod, 'persist_host_keys', lambda c: None)
    monkeypatch.setattr(subprocess, 'Popen', lambda argv, **kw: popen.append((argv, kw)) or _done(argv, 'ok'))
    monkeypatch.setattr(_ha, 'register_child_group', registered.append)
    return popen, registered, execs


@pytest.mark.guard_refusals
def test_the_sshpass_fallback_of_ssh_exec_is_asked_again_and_runs_bounded(auto, seed, monkeypatch):
    from pegaprox.utils.ssh import _ssh_exec
    auto.form(seed)
    delay = {'tcp': 0.0, 'connect': 0.0}
    popen, registered, _execs = _ssh_exec_world(monkeypatch, auto, delay)
    cmd = 'vim-cmd vmsvc/power.off 12'
    # paramiko fails at once and the lease holds: the fallback runs as a node command,
    # under `timeout -k 2 <bound>` in a session of its own, its group registered
    with auto.at('a') as ha:
        assert ha.confirm_lease()
        assert _ssh_exec('10.0.0.30', 'root', 'pw', cmd)[0] == 0
    assert len(popen) == 1 and registered == [4242]
    argv, kw = popen[0]
    assert argv[:4] == [shutil.which('timeout'), '-k', '2', '30'] and argv[-1] == cmd
    assert kw.get('start_new_session') is True
    # three tries of 8 s each, past the lease: the fallback is not started
    popen.clear()
    registered.clear()
    delay.update(tcp=8.0, connect=8.0)
    with auto.at('a') as ha:
        assert ha.confirm_lease()
        _refused(_ssh_exec, '10.0.0.30', 'root', 'pw', cmd)
    assert popen == [] and registered == []


@pytest.mark.guard_refusals
def test_ssh_exec_asks_again_before_the_command_once_paramiko_got_through(auto, seed, monkeypatch):
    from pegaprox.utils.ssh import _ssh_exec
    auto.form(seed)
    # the password login of the third try takes 25 s: the lease of 'a' ran out by then
    delay = {'tcp': 0.0, 'connect': 25.0, 'connects': True}
    popen, _registered, execs = _ssh_exec_world(monkeypatch, auto, delay)
    with auto.at('a') as ha:
        assert ha.confirm_lease()
        _refused(_ssh_exec, '10.0.0.30', 'root', 'pw', 'vim-cmd vmsvc/power.off 12')
    assert execs == [] and popen == []


# --- members that serve users ---------------------------------------------------------------

@pytest.mark.guard_refusals
def test_a_serving_member_opens_an_esxi_console_ticket(auto, seed, monkeypatch):
    """POST .../console/tickets of the ESXi REST API is a console ticket like vncproxy: a
    member that serves users gets the WebMKS ticket itself, so does the leader, and
    neither asks for a round."""
    auto.form(seed)
    asked = []

    def send(self, request, **kw):
        asked.append(request.url)
        r = requests.Response()
        r.request, r.encoding, r.status_code = request, 'utf-8', 200
        r._content = b'{"value": {"ticket": "T1", "host": "esx", "port": 443}}'
        return r
    monkeypatch.setattr(requests.adapters.HTTPAdapter, 'send', send)
    out = {}
    for n in 'ab':
        with auto.at(n) as ha, auto.g.api.app.test_request_context('/', method='POST'):
            rounds = _rounds(monkeypatch, ha)
            out[n] = _esxi().get_vm_console_ticket('vm-12')['data']
            assert rounds == []
    assert {n: (d['type'], d['ticket']) for n, d in out.items()} == {'a': ('WEBMKS', 'T1'),
                                                                      'b': ('WEBMKS', 'T1')}
    assert len(asked) == 2


@pytest.mark.guard_refusals
def test_a_serving_member_reads_a_node_over_ssh_in_a_get(auto, seed, monkeypatch):
    """A GET that reads a node over SSH (the SMBIOS auto-config status) runs on the member
    itself: in a GET an SSH command is the read, on the leader and on every member."""
    import paramiko
    import pegaprox.utils.ssh_security as sec
    from pegaprox import globals as _g
    from pegaprox.globals import cluster_managers
    hits = []
    monkeypatch.setattr(paramiko.SSHClient, 'connect', lambda self, *a, **k: None)

    def exec_command(self, cmd, *a, **k):
        hits.append(cmd)
        raise Reached(cmd)
    monkeypatch.setattr(paramiko.SSHClient, 'exec_command', exec_command)
    monkeypatch.setattr(sec, 'persist_host_keys', lambda c: None)
    monkeypatch.setattr(_g, '_ssh_semaphore', threading.BoundedSemaphore(4))
    auto.form(seed)
    m = pve()
    m._get_node_ip = lambda node: '10.0.0.11'
    monkeypatch.setitem(cluster_managers, 'c1', m)
    for n in 'ab':
        hits.clear()
        with auto.at(n) as ha:
            auto.admin.get('/api/clusters/c1/nodes/pve1/smbios-autoconfig/status')
            said = {why for _a, why in ha._guard_said}
        assert hits, f'{n}: the read never reached the node'
        assert _ha.GUARD_NO_LEASE not in said


@pytest.mark.guard_refusals
def test_a_member_still_refuses_every_write(auto, seed):
    auto.form(seed)
    with auto.at('b') as ha:
        assert not ha.is_active()
        with auto.g.api.app.test_request_context('/', method='POST'):
            assert ha.GUARD_NO_LEASE in _refused(hx.guard_ssh, '10.0.0.11', 'qm stop 101')
            _refused(hx.guard_http, 'POST', START)
        with auto.g.api.app.test_request_context('/'):
            # a GET makes an SSH command a read, not an HTTP write
            hx.guard_ssh('10.0.0.11', 'cat /etc/pve/qemu-server/101.conf')
            _refused(hx.guard_http, 'POST', START)
        _refused(hx.guard_ssh, '10.0.0.11', 'qm list')


# --- tasks of a long-lived worker ------------------------------------------------------------

@pytest.mark.guard_refusals
def test_what_a_task_confirmed_does_not_serve_the_next_task_of_its_worker(auto, seed):
    """A worker of a pool runs many tasks in one thread. A token one task left (its round
    confirmed, nothing sent on it) is gone when the task ends, for a task run through a
    pool helper (ha.carry) and for a job (ha.as_job) alike."""
    auto.form(seed)
    with auto.at('a') as ha:
        def confirmed():
            return ha.confirm_lease()

        def unconfirmed_write():
            try:
                hx.guard_http('DELETE', 'https://10.0.0.1:8006/api2/json/nodes/pve1/qemu/101')
                return 'sent'
            except ha.GuardRefused:
                return 'refused'
        with ThreadPoolExecutor(max_workers=1) as pool:
            assert pool.submit(ha.carry(confirmed)).result() is True
            assert pool.submit(unconfirmed_write).result() == 'refused'
            assert pool.submit(ha.as_job(confirmed, 'a job')).result() is True
            assert pool.submit(unconfirmed_write).result() == 'refused'
        # inline in this thread: the same
        assert ha.as_job(confirmed, 'a job')() is True
        assert unconfirmed_write() == 'refused'


# --- manual mode and an instance of its own ---------------------------------------------------

def test_in_a_manual_group_and_on_an_instance_of_its_own_none_of_this_asks(auto, seed, monkeypatch):
    """The new ways out are what they replaced: requests.request() for a call without a
    session, the XAPI send as it was, the sshpass fallback as subprocess.run() with the
    same arguments, no round, no token, nothing kept in a journal."""
    import xmlrpc.client
    import paramiko
    import XenAPI
    import pegaprox.utils.ssh as ssh_mod
    from pegaprox.utils.ssh import _ssh_exec
    calls, ran, wire = [], [], []
    monkeypatch.setattr(requests, 'request', lambda method, url, **kw: calls.append((method, url, sorted(kw))) or 'r')
    monkeypatch.setattr(subprocess, 'run', lambda argv, **kw: ran.append((argv, sorted(kw))) or
                        subprocess.CompletedProcess(argv, 0, 'ok', ''))
    monkeypatch.setattr(xmlrpc.client.Transport, 'request', lambda self, host, handler, body, verbose=False:
                        wire.append(xmlrpc.client.loads(body)[1]) or ({'Status': 'Success', 'Value': 'ok'},))

    def tcp(addr, timeout=None, *a, **k):
        raise socket.timeout('timed out')
    monkeypatch.setattr(socket, 'create_connection', tcp)
    monkeypatch.setattr(paramiko.SSHClient, 'connect', lambda self, *a, **k: tcp(None))
    monkeypatch.setattr(ssh_mod, 'persist_host_keys', lambda c: None)

    def each_way(ha):
        for seen in (calls, ran, wire):
            seen.clear()
        assert not ha.guard_on()
        assert hx.http('POST', START, json={'a': 1}, verify=False, timeout=60) == 'r'
        assert calls == [('POST', START, ['json', 'timeout', 'verify'])]
        session = hx.guard_xapi(XenAPI.Session('https://10.0.0.40', ignore_ssl=True))
        session._session = 'OpaqueRef:s'
        assert session.xenapi.VM.hard_shutdown('OpaqueRef:vm') == 'ok' and wire == ['VM.hard_shutdown']
        assert _ssh_exec('10.0.0.30', 'root', 'pw', 'vim-cmd vmsvc/power.off 12')[0] == 0
        assert [kw for _argv, kw in ran] == [['capture_output', 'env', 'text', 'timeout']]
        assert ran[0][0][0] == 'sshpass' and ran[0][0][-1] == 'vim-cmd vmsvc/power.off 12'
        assert hx.http_action('POST', '/api/vcenter/vm/vm-12/console/tickets')[1] == 'console'
        assert ha.recovery_end(None) is None
        assert getattr(ha._guard_tls, 'token', None) is None
    monkeypatch.setattr(_ha, '_lease_wait', lambda done, s: pytest.fail('waited for a round'))
    assert _ha.role() == _ha.ROLE_STANDALONE
    each_way(_ha)
    auto.pair(seed)
    for n in 'ab':
        with auto.at(n) as ha, auto.g.api.app.test_request_context('/', method='POST'):
            assert ha.mode() == 'manual'
            each_way(ha)
