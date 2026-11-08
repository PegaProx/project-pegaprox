"""A node that is back while its guests are recovered, and a node that is back
for a moment while its recovery waits (#625).

Both are older than the safety rules of S6:

1. The recovery worker decided once, after its wait, that the node was gone, then
   moved the guests one by one and never looked at the node again. A node that is
   back in the middle of that and runs its guests (no agent, the agent before v2,
   a v2 node a leader holds up, a node that rebooted and started them) got the
   next config moved away from under a running guest, and the guest started a
   second time elsewhere.
2. The wait of a recovery was not ended by a pass that saw the node online. The
   node is back for a pass and offline again: the recovery of the first outage
   went ahead on its count from back then, while the node's agent counts its
   fence delay from the moment it lost quorum the second time.

And what came after the first answer to them:

3. With the storage recovery lock on, the recovery of that second outage found
   the lock still held by the first one and gave up, and the first then
   cancelled: the node was never recovered. It is tried again now.
4. A return that only a monitor pass saw, while the worker sat in a fence over
   SSH or a slow config move, did not count: the guests the node started were
   started elsewhere as well.
5. The report named the guests left with a node that is back by their numbers
   only. Each is named with how the node reports it now, and one that is stopped
   is for an admin to start (the push is critical): the worker starts nothing on
   the node it recovers from. Starting them there ran into the node's agent, into
   a guest an admin had stopped, and into the next recovery. That next recovery
   moves only what it finds running, so it names them again while they are down.
6. A node that flaps in step with the watch held the recovery as long as it
   flapped.
7. A node back for the worker's looks only and gone again was tried again on a
   count from its first outage, before its agent could fence a second time.
8. A node back before a slow config move ran, with no pass in between, got the
   guest it had started from the config started elsewhere as well.

The monitor loop, its passes, the trigger and the worker are the real ones, in
threads of their own, on a clock of the test's (VirtualTime). The cluster is a
stand-in for pve1's API and for SSH (Pve) that keeps apart where each guest's
config is and where it runs, with pve2's self-fence agent as a model.

MK Oct 2026
"""
import os
import re
import threading
import time
import types
from unittest.mock import MagicMock

import pytest

import pegaprox.core.manager as manager_mod
from pegaprox.core import ha
from pegaprox.core.manager import PegaProxManager
from test_ha_agent_script import World, _script

IPS = {'pve1': '10.9.0.1', 'pve2': '10.9.0.2', 'pve3': '10.9.0.3'}
FENCE_DELAY, MARGIN = PegaProxManager.FENCE_AGENT_T_SF, PegaProxManager.FENCE_AGENT_MARGIN
NEVER = float('inf')
GUESTS = (100, 101, 102)
UNREACHABLE = {'reachable': False, 'reachable_ips': [], 'running_vms': [], 'running_cts': []}
# corosync as the last look found it: three votes, nothing forced
THREE_VOTES = {'strategy': 'quorum', 'expected_votes': 3, 'has_qdevice': False, 'two_node_flag': False,
               'detection_reason': 'detected'}
AGENTS = {
    'none': {},
    # pings one PegaProx address and never fences while that answers
    'v1': {'fence_agent_versions': {'pve2': 1}},
    # v2 on a setup that kept the old way: a leader that answers holds the node up
    'v2-held': {'fence_agent_versions': {'pve2': 2}, 'force_quorum_on_failure': True,
                'unsafe_two_node_recovery': True},
    # v2 that stops its guests fence_delay after it lost quorum, whoever answers
    'v2': {'fence_agent_versions': {'pve2': 2}, 'fence_strategy': THREE_VOTES},
}
RUNS_ITS_GUESTS = ['none', 'v1', 'v2-held']


# --- the clock ----------------------------------------------------------------------

class VirtualTime:
    """time.sleep, time.monotonic and time.time for manager.py, on a clock of the
    test's. The threads that use it take turns: one runs at a time, and the clock
    moves only when every one of them sleeps, on to the earliest wake-up (of two
    that are due together, the one that went to sleep first). A thread takes part
    from join() on. One that a taking part thread starts is announced with
    expect() before, so the clock waits for it to join."""

    def __init__(self, horizon):
        self.now = 0.0
        self.horizon = horizon
        self.cv = threading.Condition()
        self.asleep = {}            # thread -> (wake-up, order)
        self.members = set()
        self.expected = 0
        self.turn = None
        self.order = 0
        self.errors = []
        self.at_horizon = []

    def monotonic(self):
        return self.now

    def time(self):
        return 1_790_000_000.0 + self.now

    def _hand_on(self):
        self.turn = None
        if not self.expected and self.asleep:
            who, (wake, _order) = min(self.asleep.items(), key=lambda kv: kv[1])
            self.now = max(self.now, wake)
            self.turn = who
        self.cv.notify_all()

    def _until_my_turn(self, me):
        stuck = 0
        while self.turn is not me:
            if not self.cv.wait(timeout=1):
                stuck += 1
                if stuck > 60:
                    raise RuntimeError(f'{me.name}: no turn on the virtual clock for a minute')
        del self.asleep[me]

    def _asleep_until(self, me, wake):
        self.order += 1
        self.asleep[me] = (wake, self.order)

    def sleep(self, seconds):
        me = threading.current_thread()
        with self.cv:
            if me not in self.members:
                raise AssertionError(f'{me.name} sleeps on the virtual clock without taking part')
            self._asleep_until(me, self.now + seconds)
            self._hand_on()
            self._until_my_turn(me)
            due, self.at_horizon = (self.at_horizon, []) if self.now >= self.horizon else ([], self.at_horizon)
        for fn in due:
            fn()

    def expect(self):
        with self.cv:
            self.expected += 1

    def join(self):
        me = threading.current_thread()
        with self.cv:
            self.expected -= 1
            self.members.add(me)
            self._asleep_until(me, self.now)
            if self.turn is None:
                self._hand_on()
            self._until_my_turn(me)

    def leave(self):
        me = threading.current_thread()
        with self.cv:
            self.members.discard(me)
            if self.turn is me:
                self._hand_on()

    def take_part(self, fn, *args):
        self.join()
        try:
            fn(*args)
        except BaseException as e:      # a thread of the test that died fails the test
            self.errors.append(e)
        finally:
            self.leave()

    def start(self, *fns):
        for _ in fns:
            self.expect()
        for fn in fns:
            threading.Thread(target=self.take_part, args=(fn,), daemon=True).start()

    def wait_done(self, timeout=120):
        deadline = time.monotonic() + timeout
        with self.cv:
            while self.members or self.expected:
                if time.monotonic() > deadline:
                    raise AssertionError(f'still running at {self.now}: {sorted(t.name for t in self.members)}')
                self.cv.wait(timeout=1)
        if self.errors:
            raise self.errors[0]


# --- the cluster ----------------------------------------------------------------------

def _answer(data, code=200, text=''):
    return types.SimpleNamespace(status_code=code, json=lambda: {'data': data}, text=text)


class Pve:
    """pve1's API and SSH as the recovery meets them, at the time of the clock.

    pve2 is out of the cluster in the intervals of `out`, [from, to). Where a
    guest's config is and where it runs are kept apart: a config moved away from a
    guest that runs leaves it running. pve2's agent: only 'v2' stops its guests,
    fence_delay after pve2 lost quorum, and they count as running until the margin
    for the stops is over as well. With `reboot` each outage is a crash (or the
    outages of those numbers, from 0), and on its return pve2 starts the guests it
    still has the config of (onboot, unless `onboot` is off). Any other outage is
    a loss of quorum, its guests go on running. While pve2 is out, the API shows
    its guests as pve2 last reported them."""

    def __init__(self, clock, out, agent='none', reboot=False, onboot=True):
        self.clock, self.agent, self.reboot, self.onboot = clock, agent, reboot, onboot
        self.out = [list(o) for o in out]
        self.conf = {v: 'pve2' for v in GUESTS}
        self.runs = {v: {'pve2'} for v in GUESTS}
        self.frozen = {}
        self.done = set()
        self.events = []            # (time, what)
        self.twice = []             # (time, vmid, nodes it runs on)
        self.moved_while_back = []  # configs that left pve2 while it was listed online
        self.calls = []
        self.on = {}                # event -> what happens with it
        self.slow = {}              # vmid -> (seconds before the mv, seconds after it, goes through)
        self.lock = threading.Lock()

    def online(self, node, t=None):
        t = self.clock.now if t is None else t
        return node != 'pve2' or not any(a <= t < b for a, b in self.out)

    def back_at(self, t):
        for o in self.out:
            if o[0] <= self.clock.now < o[1]:
                o[1] = t

    def gone_at(self, t):
        self.out.append([t, NEVER])

    def _note(self, what, t=None):
        self.events.append((self.clock.now if t is None else t, what))
        hook = self.on.pop(what, None)
        if hook:
            hook()

    def _status(self, v, node):
        return 'running' if node in self.runs[v] else 'stopped'

    def _run(self, v, node, t):
        if self.runs[v] - {node}:
            self.twice.append((t, v, sorted(self.runs[v] | {node})))
        self.runs[v].add(node)

    def _catch_up(self):
        due = []
        for i, (a, b) in enumerate(self.out):
            due.append((a, 0, 'leave', i))
            if self.agent == 'v2' and a + FENCE_DELAY < b:
                due.append((a + FENCE_DELAY + MARGIN, 1, 'fenced', i))
            if b != NEVER:
                due.append((b, 2, 'back', i))
        for t, _order, what, i in sorted(due):
            if t > self.clock.now or (what, i) in self.done:
                continue
            self.done.add((what, i))
            crash = self.reboot is True or i in (self.reboot or ())
            if what == 'leave':
                self.frozen = {v: self._status(v, 'pve2') for v, n in self.conf.items() if n == 'pve2'}
                if crash:
                    for nodes in self.runs.values():
                        nodes.discard('pve2')
            elif what == 'fenced':
                for nodes in self.runs.values():
                    nodes.discard('pve2')
                self.events.append((t, 'pve2 fenced'))
            else:
                self.events.append((t, 'pve2 back'))
                if crash and self.onboot:
                    for v, n in sorted(self.conf.items()):
                        if n == 'pve2':
                            self._run(v, 'pve2', t)

    def get(self, url, params=None, timeout=10, **kw):
        path = url.split('/api2/json', 1)[1]
        with self.lock:
            self._catch_up()
            self.calls.append((self.clock.now, 'GET', path))
            if path == '/nodes':
                return _answer([{'node': n, 'status': 'online' if self.online(n) else 'offline'} for n in IPS])
            if path == '/cluster/status':
                return _answer([{'type': 'cluster', 'name': 'lab', 'quorate': 1, 'nodes': 3}]
                               + [{'type': 'node', 'name': n, 'online': int(self.online(n)), 'ip': IPS[n]}
                                  for n in IPS])
            if path == '/cluster/resources':
                return _answer([{'vmid': v, 'node': n, 'type': 'qemu', 'name': f'g{v}',
                                 'status': self._status(v, n) if self.online(n) else self.frozen.get(v, 'unknown')}
                                for v, n in sorted(self.conf.items())])
            if re.fullmatch(r'/nodes/\w+/qemu/\d+/config', path):
                return _answer({})
        raise AssertionError(url)

    def post(self, url, data=None, timeout=15, **kw):
        m = re.search(r'/nodes/(\w+)/qemu/(\d+)/status/start$', url)
        assert m, url
        node, v = m.group(1), int(m.group(2))
        with self.lock:
            self._catch_up()
            self.calls.append((self.clock.now, 'POST', f'start {v} on {node}'))
            if self.conf[v] != node:
                return _answer(None, 500, f"Configuration file 'nodes/{node}/qemu-server/{v}.conf' does not exist")
            self._run(v, node, self.clock.now)
            self._note(f'start {v} on {node}')
        return _answer('UPID:pve1:start')

    def ssh(self, host, user, command, *a, **kw):
        moved = re.match(r'(mv|cp) /etc/pve/nodes/(\w+)/qemu-server/(\d+)\.conf /etc/pve/nodes/(\w+)/', command)
        if moved:
            return self._move(int(moved.group(3)), moved.group(2), moved.group(4))
        if command.startswith('pvecm expected'):
            with self.lock:
                self._catch_up()
                self._note(f'{host}: {command}')
            return True
        raise AssertionError(command)

    def _move(self, v, src, dst):
        before, after, goes = self.slow.get(v, (0, 0, True))
        if before:
            self.clock.sleep(before)
        with self.lock:
            self._catch_up()
            went = goes and self.conf[v] == src
            if went:
                self.conf[v] = dst
                if self.online('pve2'):
                    self.moved_while_back.append(v)
            self._note(f'config {v} moved {src} -> {dst}' if went else f'config {v} not moved')
        if after:
            self.clock.sleep(after)
        return went

    def ssh_stop(self, node, vmids=None, ctids=None, reachable_ips=None):
        with self.lock:
            self._catch_up()
            for v in vmids or ():
                self.runs[int(v)].discard(node)
            self._note(f'stopped over SSH on {node}: {sorted(int(v) for v in vmids or ())}')
        return True

    def happened(self, *prefixes):
        return [(t, e) for t, e in self.events if e.startswith(prefixes)]

    def moves(self):
        return [e for _t, e in self.happened('config')]


class Log:
    def __init__(self, clock):
        self.clock, self.lines = clock, []

    def __getattr__(self, level):
        return lambda msg, *a, **kw: self.lines.append((self.clock.now, level, str(msg)))

    def said(self, text):
        return [t for t, _l, msg in self.lines if text in msg]


# --- one cluster with a node that fails --------------------------------------------------

def _run(monkeypatch, out, agent='none', reboot=False, horizon=400, setup=None, probes=(), onboot=True,
         **ha_config):
    """pve2 fails as `out` says and the HA monitor of PegaProx runs until `horizon`,
    with every recovery it starts. `setup` gets the cluster and the manager before
    the clock starts; `probes` are (time, fn) to look at the manager then. What
    the HA status was pushed is in .pushed."""
    clock = VirtualTime(horizon)
    pve = Pve(clock, out, agent, reboot, onboot)
    monkeypatch.setattr(manager_mod, 'time', types.SimpleNamespace(sleep=clock.sleep, monotonic=clock.monotonic,
                                                                    time=clock.time))
    pushed = []
    monkeypatch.setattr(manager_mod, 'broadcast_sse',
                        lambda event, data, *a, **kw: pushed.append((clock.now, event, data)))
    monkeypatch.setattr(ha, 'is_active', lambda: True)
    audits = []
    import pegaprox.utils.audit as audit
    monkeypatch.setattr(audit, 'log_audit',
                        lambda user, action, details=None, **kw: audits.append((clock.now, action, details)))

    m = PegaProxManager.__new__(PegaProxManager)
    m.id = 'c1'
    m.logger = Log(clock)
    m.config = types.SimpleNamespace(name='lab', user='root@pam', pass_='pw', ssh_key='', host=IPS['pve1'],
                                     api_port=8006, ha_settings={}, fallback_hosts=[], ha_enabled=True)
    m.current_host = IPS['pve1']
    m.ha_config = dict({'recovery_delay': 30, 'quorum_enabled': True, 'verify_network_before_recovery': True},
                       **AGENTS[agent], **ha_config)
    m.ha_failure_threshold = 3
    m.ha_check_interval = 10
    m.ha_lock = threading.Lock()
    m.is_connected, m.session, m.ha_enabled = True, True, True
    m.stop_event = threading.Event()
    m.nodes_in_maintenance = set()
    m.ha_recovery_in_progress = {}
    m.ha_recovery_locks = {}
    m.ha_node_status = {n: {'status': 'online', 'consecutive_failures': 0, 'last_seen': None,
                            'last_status': 'online'} for n in IPS}
    m._create_session = lambda: pve
    m._ha_get_node_ip = IPS.get
    m._ha_check_node_via_ssh = lambda node: dict(UNREACHABLE)
    m._ha_ssh_stop_vms_on_node = pve.ssh_stop
    m._ha_check_node_agent_heartbeat = lambda node: {'alive': False, 'age_seconds': None}
    m._ha_check_vm_storage = lambda vmid, vm_type, node: 'shared'
    m._ha_check_quorum = lambda: True
    m._ha_verify_network = lambda: True
    m._ha_redeploy_in_background = lambda *a, **kw: None
    m._ha_update_fallback_hosts = lambda: None
    m.get_node_status = lambda: {'pve1': {'score': 5}, 'pve3': {'score': 50}, 'pve2': {'score': 60}}
    m._ssh_run_command = pve.ssh
    m._ssh_run_command_with_password = lambda host, user, command, password, **kw: pve.ssh(host, user, command)

    # every recovery the monitor starts is a thread on the clock
    workers = []

    def trigger(node):
        clock.expect()
        workers.append(clock.now)
        PegaProxManager._ha_trigger_recovery(m, node)
    m._ha_trigger_recovery = trigger
    m._ha_recovery_worker = lambda node: clock.take_part(PegaProxManager._ha_recovery_worker, m, node)
    if setup:
        setup(pve, m)

    seen = {}

    def probe(t, fn):
        def look():
            clock.sleep(t)
            seen[t] = fn(m)
        return look
    clock.at_horizon.append(lambda: setattr(m, 'ha_enabled', False))
    clock.start(m._ha_monitor_loop, *(probe(t, fn) for t, fn in probes))
    clock.wait_done()
    return types.SimpleNamespace(clock=clock, pve=pve, m=m, audits=audits, workers=workers, seen=seen,
                                 log=m.logger, pushed=[p for p in pushed if p[1] == 'ha_status'])


def _back_with(pve, event, after=0, gone_after=None):
    """pve2 is back `after` seconds after `event`, and gone again `gone_after`
    seconds after that."""
    def hook():
        back = pve.clock.now + after
        pve.back_at(back)
        if gone_after is not None:
            pve.gone_at(back + gone_after)
    pve.on[event] = hook


def _first_pass_after_last_online(run, before):
    """The time of the first monitor pass (every 10 s from 0) that saw pve2
    offline after the last pass before `before` that saw it online."""
    online = [t for t in range(0, int(before), 10) if run.pve.online('pve2', t)]
    return online[-1] + 10


# --- 1. the node is back in the middle of its recovery -------------------------------------

@pytest.mark.parametrize('strict', [False, True], ids=['', 'strict-fencing'])
@pytest.mark.parametrize('agent', RUNS_ITS_GUESTS)
def test_a_node_back_in_the_middle_of_its_recovery_keeps_the_guests_it_still_runs(monkeypatch, agent, strict):
    """pve2 falls out of the cluster with 100, 101 and 102 running, and nothing on
    it stops them. It cannot be reached over SSH, so its recovery goes ahead: 100
    is moved to pve1 and started there. Then pve2 is back. The worker moved 101
    from under the running guest and started it on pve1 as well."""
    run = _run(monkeypatch, [(5, NEVER)], agent, strict_fencing=strict,
               setup=lambda pve, m: _back_with(pve, 'start 100 on pve1'))
    pve = run.pve

    assert pve.moves() == ['config 100 moved pve2 -> pve1']
    assert [e for _t, e in pve.happened('start')] == ['start 100 on pve1']
    assert pve.moved_while_back == []
    assert pve.conf[101] == pve.conf[102] == 'pve2' and pve.runs[101] == pve.runs[102] == {'pve2'}
    # 100 was moved while pve2 was out of reach and still ran it: the risk of
    # recovering a node that never fences, which the SSH check is there for
    assert not [x for x in pve.twice if x[1] != 100]
    # said once, in the log, the audit trail and the HA status, each guest with how
    # pve2 reports it now
    details = ('pve2 is back online: its recovery stopped after 1 guest(s). Recovered: 100 on pve1. '
               'Left on pve2: 101 (running), 102 (running)')
    assert [(a, d) for _t, a, d in run.audits] == [('ha.recovery_node_back', f'Cluster lab: {details}')]
    assert len(run.log.said(details)) == 1
    assert [(d['node'], d['message'], d['severity']) for _t, _e, d in run.pushed
            if d['event'] == 'ha.recovery_node_back'] == [('pve2', details, 'warning')]
    assert run.log.said('HA RECOVERY ENDED') and not run.log.said('HA RECOVERY COMPLETE')
    # and let go of like a recovery that is done: the flag after the cooldown, the
    # mark to try again by the pass that saw pve2 online
    assert run.m.ha_recovery_in_progress == {} and len(run.workers) == 1
    assert 'pve2' not in run.m.__dict__.get('_ha_recovery_retry', set())


@pytest.mark.parametrize('strict', [False, True], ids=['', 'strict-fencing'])
@pytest.mark.parametrize('agent', RUNS_ITS_GUESTS + ['v2'])
def test_a_node_that_stays_down_is_recovered_as_before(monkeypatch, agent, strict):
    """The counterproof, the same in the tree before the change: same guests, same
    order, same times, no audit line."""
    run = _run(monkeypatch, [(5, NEVER)], agent, strict_fencing=strict)
    pve, m = run.pve, run.m

    first = 10 + m._ha_fence_timing('pve2')['earliest_recovery']
    forced = 3 if agent == 'v2-held' else 0     # `pvecm expected 1` and its 3 s per guest
    moves = [(t, e) for t, e in pve.happened('config', 'start')]
    assert [e for _t, e in moves] == ['config 100 moved pve2 -> pve1', 'start 100 on pve1',
                                      'config 101 moved pve2 -> pve1', 'start 101 on pve1',
                                      'config 102 moved pve2 -> pve1', 'start 102 on pve1']
    step = 4 + forced
    assert [t for t, _e in moves] == [first + forced + k * step + d for k in range(3) for d in (0, 2)]
    assert run.audits == [] and run.pushed == [] and run.log.said('HA RECOVERY COMPLETE')
    assert m.ha_recovery_in_progress == {} and len(run.workers) == 1
    if agent == 'v2':
        assert pve.twice == []


@pytest.mark.parametrize('lock', [False, True], ids=['', 'storage-lock'])
@pytest.mark.parametrize('back', [False, True], ids=['stays-down', 'back'])
def test_the_recovery_lock_is_given_back_once_either_way(monkeypatch, back, lock):
    """Taken once and given back once, by the end of the worker, whether the
    recovery is done or ends because pve2 is back."""
    taken = []

    def setup(pve, m):
        m._ha_acquire_recovery_lock = lambda node: taken.append(('take', node)) or True
        m._ha_release_recovery_lock = lambda node: taken.append(('give', node))
        if back:
            _back_with(pve, 'start 100 on pve1')

    run = _run(monkeypatch, [(5, NEVER)], storage_heartbeat_enabled=lock, setup=setup)

    assert taken == ([('take', 'pve2'), ('give', 'pve2')] if lock else [])
    assert len(run.pve.moves()) == (1 if back else 3)


def test_a_node_that_rebooted_and_started_its_guests_keeps_them(monkeypatch):
    """pve2 crashed, so its guests are down and 100 is recovered. It comes back
    from the reboot and starts 101 and 102 itself (onboot): their configs are
    still there. The worker moved 101 and started it on pve1 a second time."""
    run = _run(monkeypatch, [(5, NEVER)], reboot=True,
               setup=lambda pve, m: _back_with(pve, 'start 100 on pve1'))

    assert run.pve.twice == [] and run.pve.moves() == ['config 100 moved pve2 -> pve1']
    assert run.pve.runs == {100: {'pve1'}, 101: {'pve2'}, 102: {'pve2'}}


# --- what 'back' means for a node whose v2 agent fences on its own -------------------------

def test_a_self_fencing_node_that_is_back_for_good_keeps_its_fenced_guests_for_an_admin(monkeypatch):
    """Its agent stopped 100, 101 and 102 a fence delay after pve2 lost quorum, and
    starts none of them. pve2 is back after 100 was recovered. pve2 reports 101
    stopped, so there is no second copy to wait out a fence delay for: the worker
    waits one turn of the agent (2 x its check interval), moves nothing meanwhile,
    and leaves 101 and 102 to pve2, stopped. It starts nothing there, as the agent
    does not: the audit line and the critical push name them for an admin."""
    run = _run(monkeypatch, [(5, NEVER)], 'v2', setup=lambda pve, m: _back_with(pve, 'start 100 on pve1'))
    pve = run.pve
    (back, _e), = pve.happened('pve2 back')
    turn = 2 * PegaProxManager.FENCE_AGENT_INTERVAL

    assert pve.moves() == ['config 100 moved pve2 -> pve1'] and pve.twice == []
    assert pve.runs == {100: {'pve1'}, 101: set(), 102: set()}
    assert [what for _t, how, what in pve.calls if how == 'POST'] == ['start 100 on pve1']
    looks = [t for t, how, path in pve.calls if path == '/nodes' and t > back and t % 10 != 0]
    assert looks == [back + 2, back + 2 + turn, back + 2 + turn]
    (said, action, details), = run.audits
    assert action == 'ha.recovery_node_back' and said == back + 2 + turn
    why = 'stopped - start it by hand once pve2 is in order'
    assert details.endswith(f'Recovered: 100 on pve1. Left on pve2: 101 ({why}), 102 ({why})')
    assert [d['severity'] for _t, _e, d in run.pushed] == ['critical']
    # the passes saw it back while the worker looked: nothing is left to try again
    assert 'pve2' not in run.m.__dict__.get('_ha_recovery_retry', set())
    assert run.m.ha_recovery_in_progress == {} and len(run.workers) == 1


def test_a_self_fencing_node_back_from_a_reboot_gets_no_config_moved_while_it_is_listed(monkeypatch):
    """The reason nothing is moved while the worker looks: a node back from a reboot
    starts its onboot guests right away, its v2 agent with them (a fresh agent has
    nothing to fence). Going on with 101 there started it twice."""
    run = _run(monkeypatch, [(5, NEVER)], 'v2', reboot=True,
               setup=lambda pve, m: _back_with(pve, 'start 100 on pve1'))

    assert run.pve.twice == [] and run.pve.moved_while_back == []
    assert run.pve.runs == {100: {'pve1'}, 101: {'pve2'}, 102: {'pve2'}}


@pytest.mark.parametrize('gone_after', [5, 13], ids=['gone-before-its-agent-is-in-order', 'gone-after-that'])
def test_a_self_fencing_node_online_for_a_moment_does_not_end_the_recovery_its_guests_need(monkeypatch,
                                                                                         gone_after):
    """pve2 is online for a few seconds after 100 was recovered, then gone again.
    Its guests were stopped by its fence and are shown stopped from then on: a
    recovery that ended there left them down. Gone again within one turn of its
    agent, nothing changed for them: the worker goes on once the floor is over.
    Still there after that turn, pve2 is back, and they are left to it, named for
    an admin: the recovery of the outage after it (a pass saw pve2 online) finds
    nothing that runs on pve2."""
    run = _run(monkeypatch, [(5, NEVER)], 'v2',
               setup=lambda pve, m: _back_with(pve, 'start 100 on pve1', gone_after=gone_after))
    pve = run.pve

    assert pve.twice == [] and pve.moved_while_back == []
    assert not pve.happened('start 101 on pve2', 'start 102 on pve2')
    if gone_after == 5:
        assert pve.moves() == [f'config {v} moved pve2 -> pve1' for v in GUESTS]
        assert pve.runs == {v: {'pve1'} for v in GUESTS}
        assert run.audits == [] and len(run.workers) == 1
    else:
        assert pve.moves() == ['config 100 moved pve2 -> pve1']
        assert pve.runs == {100: {'pve1'}, 101: set(), 102: set()}
        (_t, action, details), again = run.audits
        why = 'stopped - start it by hand once pve2 is in order'
        assert action == 'ha.recovery_node_back' and details.endswith(f'Left on pve2: 101 ({why}), 102 ({why})')
        assert len(run.workers) == 2 and run.log.said('No VMs found on failed node pve2')
        # the next recovery finds nothing running and says the left guests once more
        assert again[1] == 'ha.recovery_left_guests' and 'still stopped: 101, 102 - start them' in again[2]


@pytest.mark.parametrize('gone_after', [5, 13], ids=['between-two-passes', 'seen-by-a-pass'])
def test_a_self_fencing_node_back_from_a_reboot_and_gone_again_is_fenced_before_the_next_move(monkeypatch,
                                                                                              gone_after):
    """pve2 crashed, 100 is recovered. Back from the reboot it starts 101 and 102
    (onboot) and loses quorum again a few seconds later, its guests running. Its
    agent stops them a fence delay after that, and the margin later they are down.
    The worker that went on at the look that found pve2 gone moved 101 from under
    the running guest and started it on pve1 as well. Nothing moves before fence
    delay + margin from that look."""
    run = _run(monkeypatch, [(5, NEVER)], 'v2', reboot=(0,), horizon=500,
               setup=lambda pve, m: _back_with(pve, 'start 100 on pve1', gone_after=gone_after))
    pve = run.pve
    (back, _e), = pve.happened('pve2 back')
    gone = back + gone_after
    (fenced, _e), = [(t, e) for t, e in pve.happened('pve2 fenced') if t > back]

    assert fenced == gone + FENCE_DELAY + MARGIN
    assert pve.twice == [] and pve.moved_while_back == []
    assert all(t >= fenced for t, _e in pve.happened('config 101', 'config 102'))
    gone_look = min(t for t, how, path in pve.calls if path == '/nodes' and t > gone and t % 10 != 0)
    assert run.log.said('pve2 is gone again') == [gone_look]
    assert pve.runs == {v: {'pve1'} for v in GUESTS} and run.audits == []


def test_any_other_node_back_for_a_moment_is_tried_again_when_it_is_gone(monkeypatch):
    """No agent: pve2 may run what is left, so the worker leaves it the moment it is
    listed online. Gone again before any pass saw it, it is marked like a refusal
    that can pass: once this recovery has cooled down the monitor starts the next,
    which recovers 101 and 102 after its wait."""
    run = _run(monkeypatch, [(5, NEVER)], 'none',
               setup=lambda pve, m: _back_with(pve, 'start 100 on pve1', gone_after=3))
    pve = run.pve

    assert pve.moves() == [f'config {v} moved pve2 -> pve1' for v in GUESTS]
    assert pve.moved_while_back == []
    assert len(run.workers) == 2 and run.log.said('is still offline, trying its recovery again')
    (_t, action, details), = run.audits
    assert details.endswith('Left on pve2: 101 (running), 102 (running)')
    second = [t for t, e in pve.happened('config 101')][0]
    assert second >= run.workers[1] + run.m._ha_fence_timing('pve2')['wait']


@pytest.mark.parametrize('agent', RUNS_ITS_GUESTS)
def test_a_crashed_node_back_for_one_look_gets_nothing_started_for_the_next_recovery(monkeypatch, agent):
    """pve2 crashed (its guests went down with it), 100 is recovered. Back from the
    reboot it starts nothing (not onboot); the worker sees it listed at one look
    and leaves 101 and 102 with it. 3 s later pve2 loses quorum again, before any
    pass saw it. The worker had started both on pve2, and the next recovery found
    them running there as pve2 last reported them, out of reach, and started them
    on pve1 as well. They stay stopped now, named for an admin, and the next
    recovery finds nothing that runs on pve2."""
    run = _run(monkeypatch, [(5, NEVER)], agent, reboot=(0,), onboot=False, horizon=500,
               setup=lambda pve, m: _back_with(pve, 'start 100 on pve1', gone_after=3))
    pve = run.pve

    assert pve.twice == [] and not pve.happened('start 101', 'start 102')
    assert pve.runs == {100: {'pve1'}, 101: set(), 102: set()}
    assert len(run.workers) == 2 and run.log.said('No VMs found on failed node pve2')
    why = 'stopped - start it by hand once pve2 is in order'
    assert run.audits[0][2].endswith(f'Left on pve2: 101 ({why}), 102 ({why})')


# --- what stays with the node, and what is said of it ------------------------------------------

@pytest.mark.parametrize('agent', RUNS_ITS_GUESTS + ['v2'])
def test_a_crashed_node_back_without_onboot_has_its_stopped_guests_named_for_an_admin(monkeypatch, agent):
    """pve2 crashed, its guests went down with it, and back from the reboot it
    starts none of them (not onboot). 100 was recovered before that. The audit
    line named 101 and 102 by their numbers only. Started on pve2 by the worker
    they ran into whatever stops guests there until it is in order: a v2 agent
    still in its fence loop, one a leader holds up that fenced because none
    answered. The worker starts nothing on the node it recovers from: they are
    named stopped, for an admin, and the push is critical."""
    run = _run(monkeypatch, [(5, NEVER)], agent, reboot=True, onboot=False,
               setup=lambda pve, m: _back_with(pve, 'start 100 on pve1'))
    pve = run.pve

    assert pve.moves() == ['config 100 moved pve2 -> pve1'] and pve.twice == []
    assert pve.runs == {100: {'pve1'}, 101: set(), 102: set()}
    assert [what for _t, how, what in pve.calls if how == 'POST'] == ['start 100 on pve1']
    why = 'stopped - start it by hand once pve2 is in order'
    (_t, _a, details), = run.audits
    assert details.endswith(f'Left on pve2: 101 ({why}), 102 ({why})')
    assert [(d['node'], d['severity']) for _t, _e, d in run.pushed
            if d.get('event') == 'ha.recovery_node_back'] == [('pve2', 'critical')]
    assert len(run.workers) == 1


@pytest.mark.parametrize('agent,at', [('none', 63), ('v2', 80)])
def test_a_guest_an_admin_stopped_on_the_node_that_is_back_is_not_started_again(monkeypatch, agent, at):
    """pve2 crashed, 100 is recovered, and pve2 is back from its reboot with 101 and
    102 running (onboot). The admin shuts 101 down on purpose before the worker
    reads what is left (v2: while it watches pve2 a fence delay long, as 101
    runs). The worker found 101 stopped on the node that holds its config and
    started it again."""
    box = {}

    def setup(pve, m):
        box['pve'] = pve
        _back_with(pve, 'start 100 on pve1', after=1)

    def admin_stops_101(m):
        pve = box['pve']
        with pve.lock:
            pve._catch_up()
            pve.runs[101].discard('pve2')

    run = _run(monkeypatch, [(5, NEVER)], agent, reboot=(0,), setup=setup, probes=[(at, admin_stops_101)])
    (back, _e), = run.pve.happened('pve2 back')
    (said, _a, details), = run.audits

    assert back <= at < said
    assert run.pve.runs == {100: {'pve1'}, 101: set(), 102: {'pve2'}}
    assert [what for _t, how, what in run.pve.calls if how == 'POST'] == ['start 100 on pve1']
    assert details.endswith('Left on pve2: 101 (stopped - start it by hand once pve2 is in order), 102 (running)')


def test_what_is_left_is_not_read_through_an_api_host_outside_the_quorate_part(monkeypatch):
    """The same, but by the time pve2 is back the API host does not report the
    cluster quorate: a node cut off from the others lists itself online, with the
    copy of /etc/pve from before the split. What it reports of the guests is not
    read; they are named as not known, and the push is critical."""
    def setup(pve, m):
        def back():
            pve.back_at(pve.clock.now)
            m._ha_cluster_quorum = lambda: (False, [])
        pve.on['start 100 on pve1'] = back

    run = _run(monkeypatch, [(5, NEVER)], reboot=True, onboot=False, setup=setup)
    (back, _e), = run.pve.happened('pve2 back')

    assert run.pve.runs == {100: {'pve1'}, 101: set(), 102: set()}
    assert [what for _t, how, what in run.pve.calls if how == 'POST'] == ['start 100 on pve1']
    assert not [t for t, how, path in run.pve.calls if path == '/cluster/resources' and t >= back]
    why = 'not known, 10.9.0.1 does not report the cluster quorate'
    assert run.audits[0][2].endswith(f'Left on pve2: 101 ({why}), 102 ({why})')
    assert [d['severity'] for _t, _e, d in run.pushed] == ['critical']


def test_a_node_that_flaps_in_step_with_the_watch_holds_the_recovery_a_few_rounds_only(monkeypatch):
    """v2 that fences on its own, quorum loss. After 100 is recovered pve2 is online
    for 4 s every 70 s, never at a pass, for 30 rounds: one turn of its agent and
    the floor make 70 s as well, so each look found it online and the next one
    gone, and the worker held the rest for as long as the flap went on. After
    NODE_BACK_RESTARTS rounds what is left stays with pve2, named for an admin:
    its agent fenced them."""
    cycles = 30
    out = [(5, 73)] + [(77 + 70 * k, 143 + 70 * k) for k in range(cycles)] + [(77 + 70 * cycles, NEVER)]
    run = _run(monkeypatch, out, 'v2', horizon=600)
    pve = run.pve
    rounds = PegaProxManager.NODE_BACK_RESTARTS + 1

    assert run.log.said('is listed online again') == [74 + 70 * k for k in range(rounds)]
    assert run.log.said('keeps coming back') == [74 + 70 * rounds]
    assert pve.moves() == ['config 100 moved pve2 -> pve1'] and pve.twice == []
    why = 'stopped - start it by hand once pve2 is in order'
    (said, _a, details), *again = run.audits
    assert said == 74 + 70 * rounds and details.endswith(f'Left on pve2: 101 ({why}), 102 ({why})')
    # a later recovery that finds nothing running names the left guests again, critical
    assert [a for _t, a, _d in again] in ([], ['ha.recovery_left_guests'])
    assert set(d['severity'] for _t, _e, d in run.pushed) == {'critical'}


# --- the guest of the moment ----------------------------------------------------------------

def test_a_node_back_while_the_next_guest_is_prepared_keeps_it(monkeypatch):
    """A setup on the old way forces quorum on pve1 for every guest (`pvecm expected
    1`, then 3 s for corosync). pve2 is back during those 3 s of 101: the look
    before the guest found it gone, the one right before the move does not."""
    run = _run(monkeypatch, [(5, NEVER)], 'v2-held',
               setup=lambda pve, m: _back_with(pve, 'start 100 on pve1', after=3))
    pve = run.pve
    (back, _e), = pve.happened('pve2 back')
    forced = [t for t, _e in pve.happened('10.9.0.1: pvecm expected 1')]

    assert forced[1] < back < forced[1] + 3
    assert pve.moves() == ['config 100 moved pve2 -> pve1'] and pve.moved_while_back == []
    assert pve.runs[101] == pve.runs[102] == {'pve2'}
    assert run.audits[0][2].endswith('Left on pve2: 101 (running), 102 (running)')


@pytest.mark.parametrize('agent', ['none', 'v2'])
@pytest.mark.parametrize('slow', [(3, 0, True), (0, 3, True), (0, 0, True)],
                         ids=['back-before-the-mv-ran', 'back-before-its-ssh-session-ended', 'back-while-pmxcfs-syncs'])
def test_a_guest_whose_config_moved_is_not_started_once_the_node_is_back(monkeypatch, agent, slow):
    """pve2 crashed, 100 is recovered. The SSH session of the mv of 101 hangs 3 s
    (key auth timing out), before or after the mv runs, and pve2 is back from its
    reboot inside those 3 s, before any pass saw it. Back before the mv ran, it
    started 101 from the config that was still there (onboot), and 101 was started
    on pve1 as well: the check after the move went by the passes only, and ran
    before the 2 s for pmxcfs. pve2 is looked at again right before the start now.
    Back once the mv ran, pve2 had no config of 101 left to start, but that cannot
    be told apart: 101 stays where its config is, not started, and the audit line
    and the critical push say so. 102 is left to pve2, which runs it."""
    def setup(pve, m):
        pve.slow[101] = slow
        _back_with(pve, 'start 100 on pve1', after=3)

    run = _run(monkeypatch, [(5, NEVER)], agent, reboot=(0,), horizon=500, setup=setup)
    pve = run.pve
    (back, _e), = pve.happened('pve2 back')
    (moved, _e), = pve.happened('config 101 moved')
    looked = min(t for t, how, path in pve.calls if path == '/nodes' and t >= back)

    # the look right before the start, 2 s after the mv returned, and no pass
    # between the return and it
    assert looked == moved + slow[1] + 2 and not [t for t in range(0, int(looked) + 1, 10) if t >= back]
    assert pve.twice == [] and not pve.happened('start 101')
    assert pve.conf[101] == 'pve1' and pve.runs[101] == ({'pve2'} if moved > back else set())
    assert pve.runs[102] == {'pve2'} and run.log.said('101 was moved to pve1 and is not started')
    details = run.audits[0][2]
    assert 'Recovered: 100 on pve1. Moved, not started: 101 to pve1 - ' in details
    assert details.endswith('Left on pve2: 102 (running)')
    assert [d['severity'] for _t, _e, d in run.pushed] == ['critical']


@pytest.mark.parametrize('back', [False, True], ids=['stays-down', 'back'])
def test_a_config_that_did_not_move_is_not_started_once_the_node_is_back(monkeypatch, back):
    """Every attempt of the move of 101 fails, 2 s each. Back meanwhile, pve2 keeps
    101 and nothing tries to start it on pve1. Down, the start is tried anyway as
    before (and fails), and the recovery goes on with 102."""
    def setup(pve, m):
        pve.slow[101] = (2, 0, False)
        if back:
            _back_with(pve, 'config 101 not moved', after=1)

    run = _run(monkeypatch, [(5, NEVER)], reboot=True, setup=setup)
    pve = run.pve
    tried = [what for _t, how, what in pve.calls if how == 'POST']

    if back:
        assert tried == ['start 100 on pve1'] and pve.conf[101] == pve.conf[102] == 'pve2'
        assert pve.twice == [] and run.audits[0][2].endswith('Left on pve2: 101 (running), 102 (running)')
    else:
        assert tried == ['start 100 on pve1', 'start 101 on pve1', 'start 102 on pve1']
        assert run.audits == [] and pve.conf == {100: 'pve1', 101: 'pve2', 102: 'pve1'}


def test_a_node_that_is_back_is_not_powered_off_for_the_next_guest(monkeypatch):
    """With a fence configured the start of each guest powers the failed node off
    first (_ha_fence_node, power off without reading it back). Asked only right
    before the move, a node that is back got its power cut for the next guest."""
    sent, clocks = [], []

    def ipmitool(argv, **kw):
        sent.append((clocks[0].now, ' '.join(argv[-2:])))
        return types.SimpleNamespace(returncode=0, stdout=b'', stderr=b'')
    monkeypatch.setattr(manager_mod.subprocess, 'run', ipmitool)

    def setup(pve, m):
        clocks.append(pve.clock)
        _back_with(pve, 'start 100 on pve1')

    run = _run(monkeypatch, [(5, NEVER)], setup=setup,
               fencing={'pve2': {'type': 'ipmi', 'host': '10.8.0.2', 'user': 'ADMIN', 'password': 'bmc-pw'}})
    (back, _e), = run.pve.happened('pve2 back')

    assert sent and all(what == 'power off' for _t, what in sent)
    assert max(t for t, _w in sent) < back
    assert run.pve.moves() == ['config 100 moved pve2 -> pve1']


def test_under_strict_fencing_guests_stopped_over_ssh_stay_with_the_node_that_is_back(monkeypatch):
    """pve2 is cut off from the cluster but answers SSH: its guests are stopped there
    first (strict fencing would end the recovery if that failed). pve2 is back
    after 100: 101 and 102 are not moved, and stay stopped on it, named for an
    admin in the audit line."""
    def setup(pve, m):
        m._ha_check_node_via_ssh = lambda node: {'reachable': True, 'reachable_ips': [IPS['pve2']],
                                                 'running_vms': ['100', '101', '102'], 'running_cts': []}
        _back_with(pve, 'start 100 on pve1')

    run = _run(monkeypatch, [(5, NEVER)], strict_fencing=True, setup=setup)

    assert run.pve.moves() == ['config 100 moved pve2 -> pve1'] and run.pve.twice == []
    assert run.pve.runs == {100: {'pve1'}, 101: set(), 102: set()}
    why = 'stopped - start it by hand once pve2 is in order'
    assert run.audits[0][2].endswith(f'Left on pve2: 101 ({why}), 102 ({why})')


def test_under_strict_fencing_a_stop_that_fails_still_ends_the_recovery(monkeypatch):
    def setup(pve, m):
        m._ha_check_node_via_ssh = lambda node: {'reachable': True, 'reachable_ips': [IPS['pve2']],
                                                 'running_vms': ['100'], 'running_cts': []}
        m._ha_ssh_stop_vms_on_node = lambda *a, **kw: False

    run = _run(monkeypatch, [(5, NEVER)], strict_fencing=True, setup=setup)

    assert run.pve.moves() == [] and run.audits == [] and run.log.said('STRICT MODE')


# --- a return only a monitor pass saw ------------------------------------------------------

def _ssh_fence(monkeypatch, clocks):
    """`ssh poweroff` of an ssh fence, timing out after 5 s on the clock of the test."""
    def ssh_poweroff(argv, **kw):
        clocks[0].sleep(5)
        return types.SimpleNamespace(returncode=255, stdout=b'', stderr=b'timeout')
    monkeypatch.setattr(manager_mod.subprocess, 'run', ssh_poweroff)


@pytest.mark.parametrize('agent', ['none', 'v2'])
def test_a_return_only_a_pass_saw_counts_like_one_the_worker_saw(monkeypatch, agent):
    """pve2 crashed, 100 is recovered. With an ssh fence configured the start of
    every guest first runs `ssh poweroff` against pve2, 5 s until it times out.
    Meanwhile pve2 is back from its reboot, starts 101 and 102 (onboot), a pass
    sees it online, and it loses quorum again before the look right before the
    move, its guests running. The worker never saw it online: it moved 101 from
    under the running guest and started it on pve1 as well. The pass counts now.
    pve2 without an agent is back then: the rest is left to it, and to the
    recovery of the outage that pass began. pve2 that fences itself gets the floor
    first, and is looked at again."""
    clocks = []
    _ssh_fence(monkeypatch, clocks)

    def setup(pve, m):
        clocks.append(pve.clock)
        _back_with(pve, 'start 100 on pve1', after=4, gone_after=11)

    run = _run(monkeypatch, [(5, NEVER)], agent, reboot=(0,), horizon=500, setup=setup,
               fencing={'pve2': {'type': 'ssh', 'host': IPS['pve2']}})
    pve = run.pve
    (back, _e), = pve.happened('pve2 back')
    passes = [t for t, how, path in pve.calls if path == '/nodes' and t % 10 == 0 and pve.online('pve2', t)]
    looks = [t for t, how, path in pve.calls if path == '/nodes' and t % 10 != 0 and back <= t]

    assert [t for t in passes if t > 0] and not [t for t in looks if pve.online('pve2', t)]
    assert pve.moved_while_back == []
    if agent == 'v2':
        (fenced, _e), = [(t, e) for t, e in pve.happened('pve2 fenced') if t > back]
        assert pve.twice == [] and all(t >= fenced for t, _e in pve.happened('config 101', 'config 102'))
        assert run.log.said('was seen online by a pass and is gone again')
    else:
        # the worker of the outage before leaves the rest; the one that pass began
        # recovers it after its own wait, as any recovery of a node that never fences
        (_w1, w2) = run.workers
        assert [e for t, e in pve.happened('config') if t < w2] == ['config 100 moved pve2 -> pve1']
        gone = 'not known, pve2 is offline again'
        assert run.audits[0][2].endswith(f'Left on pve2: 101 ({gone}), 102 ({gone})')
        assert 'pve2' not in run.m.__dict__.get('_ha_recovery_retry', set())


@pytest.mark.parametrize('agent', ['none', 'v2'])
def test_a_config_move_that_outlasts_a_pass_that_saw_the_node(monkeypatch, agent):
    """pve2 crashed, 100 is recovered. The SSH mv of 101 hangs 30 s (key auth timing
    out before the password goes through). Inside that pve2 is back from its
    reboot, starts 101 and 102, a pass sees it, and it loses quorum again 11 s
    later, its guests running. The look before the move had found it gone, and 101
    was started on pve1 next to the copy on pve2. last_seen is compared after the
    move as well now. pve2 that fences itself has stopped it a floor later, and
    the start waits for that. Any other node may run it: its config stays moved
    and it is not started, and the audit line and the push say so."""
    def setup(pve, m):
        pve.slow[101] = (30, 0, True)
        _back_with(pve, 'start 100 on pve1', after=5, gone_after=11)

    run = _run(monkeypatch, [(5, NEVER)], agent, reboot=(0,), horizon=500, setup=setup)
    pve = run.pve
    (back, _e), = pve.happened('pve2 back')
    (moved, _e), = pve.happened('config 101 moved')

    assert [t for t in range(0, int(moved), 10) if t > back and pve.online('pve2', t)]
    # whatever kind of agent: what pve2 started while its config went keeps running there
    # without a config, where its agent (qm list, qm stop) does not see it - not started
    assert not pve.happened('start 101 on pve1') and pve.conf[101] == 'pve1'
    if agent == 'v2':
        # a node without an agent never fences: a later recovery of it can still start a
        # guest it runs (the risk the SSH check is there for); a self-fencing one cannot
        assert pve.twice == []
    assert run.log.said('101 was moved to pve1 and is not started')
    details = run.audits[0][2]
    assert 'Recovered: 100 on pve1. Moved, not started: 101 to pve1 - pve2 was online while' in details
    assert 'may still run it without a config there: check pve2 before you start it by hand' in details
    assert [d['severity'] for _t, _e, d in run.pushed][0] == 'critical'


# --- 7. tried again after a return only the worker saw -------------------------------------

def _hand_start(pve, m):
    """The admin starts on pve2 what the report names stopped, the moment it is
    reported."""
    def leave(node, guests):
        states = PegaProxManager._ha_leave_to_node(m, node, guests)
        with pve.lock:
            pve._catch_up()
            for v, what in states:
                if what.startswith('stopped - '):
                    pve._run(v, node, pve.clock.now)
                    pve.events.append((pve.clock.now, f'admin starts {v} on {node}'))
        return states
    m._ha_leave_to_node = leave


@pytest.mark.parametrize('threshold,interval,delay,x,gone_after', [
    (4, 25, 0, 0, 16), (4, 25, 0, 0, 23), (4, 25, 0, 1, 15), (4, 25, 0, 1, 21), (4, 25, 0, 24, 17),
    (4, 25, 2, 22, 19), (4, 25, 2, 24, 21), (3, 40, 0, 6, 15), (3, 40, 0, 6, 23), (3, 40, 0, 39, 23),
    (3, 45, 0, 8, 23), (3, 45, 0, 16, 15), (3, 45, 0, 16, 23),
])
def test_a_retry_after_a_return_only_the_worker_saw_waits_for_the_agent(monkeypatch, threshold, interval, delay,
                                                                        x, gone_after):
    """v2 that fences on its own, quorum loss: its agent stopped 100-102. pve2 is
    back after 100 is recovered (whose move takes x s), reports 101 stopped and
    stays a turn of its agent: 101 and 102 are left to it and reported, and the
    admin starts them there. It loses quorum again gone_after s after its return,
    before any pass saw it online, and the worker marked it to be tried again.
    That retry counted its wait as for the outage before: with failure_threshold
    - 1 intervals at or above fence_delay + margin and a short recovery_delay it
    waited nothing, and started 101 on pve1 while pve2's agent was still counting.
    It is held now until fence_delay + margin after the first pass that finds pve2
    gone."""
    def setup(pve, m):
        m.ha_failure_threshold, m.ha_check_interval = threshold, interval
        if x:
            pve.slow[100] = (x, 0, True)
        _back_with(pve, 'start 100 on pve1', gone_after=gone_after)
        _hand_start(pve, m)

    run = _run(monkeypatch, [(interval / 2, NEVER)], 'v2', recovery_delay=delay, horizon=900, setup=setup)
    pve = run.pve
    (back, _e), = pve.happened('pve2 back')
    (retry,) = run.log.said('trying its recovery again')
    looks = sorted({t for t, how, path in pve.calls if path == '/nodes'})
    gone = min(t for t in looks if t > back and not pve.online('pve2', t))

    assert [e for _t, e in pve.happened('admin starts')] == ['admin starts 101 on pve2', 'admin starts 102 on pve2']
    assert len(run.workers) == 2 and retry >= gone + FENCE_DELAY + MARGIN
    assert pve.twice == [] and pve.runs == {v: {'pve1'} for v in GUESTS}


def test_a_retry_is_held_from_the_first_pass_that_finds_the_node_gone(monkeypatch):
    """_ha_retry_due as the monitor asks it, at every pass that finds the node
    offline. Held only where a recovery would wait for the v2 agent."""
    now = [100]
    monkeypatch.setattr(manager_mod, 'time', types.SimpleNamespace(monotonic=lambda: now[0]))
    m = PegaProxManager.__new__(PegaProxManager)
    m.ha_config = {'fence_agent_versions': {'pve2': 2, 'pve3': 2}}
    m.ha_failure_threshold, m.ha_check_interval = 4, 25

    m._ha_retry_recovery('pve2', held=True)
    m._ha_retry_recovery('pve3')
    m._ha_retry_recovery('pve4', held=True)
    assert [m._ha_retry_due(n) for n in ('pve2', 'pve3', 'pve4')] == [False, True, True]
    now[0] = 100 + FENCE_DELAY + MARGIN - 1
    assert m._ha_retry_due('pve2') is False
    now[0] += 1
    assert m._ha_retry_due('pve2') is True
    # taken off with the mark: by the pass that sees it online, or the recovery that goes ahead
    m._ha_retry_recovery('pve2', held=True)
    m._ha_recovery_settled('pve2')
    assert m._ha_retry_due('pve2') is True and m.__dict__['_ha_retry_holds'] == {'pve4': 100}


# --- 2. back for a pass while the recovery waits -----------------------------------------

@pytest.mark.parametrize('strict', [False, True], ids=['', 'strict-fencing'])
@pytest.mark.parametrize('agent', RUNS_ITS_GUESTS + ['v2'])
def test_a_recovery_counts_from_the_last_pass_that_saw_the_node_online(monkeypatch, agent, strict):
    """pve2 is offline at the passes of 10, 20 and 30 s and declared; its recovery
    waits recovery_delay (45 s). It is back at 33 s, the pass at 40 s sees it
    online, and from 42 s it is gone again: declared at 70 s, a second recovery.
    The first one woke at 75 s, found pve2 offline and went ahead on the count of
    the first outage. Under v2 the node's agent had not fenced (back at 33 s, 2 s
    short of its delay) and counts again from 42 s: 100 ran on two nodes."""
    run = _run(monkeypatch, [(5, 33), (42, NEVER)], agent, recovery_delay=45, strict_fencing=strict)
    pve, m = run.pve, run.m
    first_move = pve.happened('config')[0][0]

    assert run.workers == [30, 70]
    assert run.log.said('was back online during the wait - cancelling') == [75]
    assert first_move >= _first_pass_after_last_online(run, 70) + m._ha_fence_timing('pve2')['earliest_recovery']
    assert pve.moves() == [f'config {v} moved pve2 -> pve1' for v in GUESTS]
    if agent == 'v2':
        assert pve.twice == []


def test_the_first_recovery_leaves_the_flag_of_the_second_alone(monkeypatch):
    """The first recovery ends at 75 s and keeps its flag 60 s more. It took that
    off at 135 s while the second recovery (flag set at 70 s) was still at work,
    and the HA status showed none."""
    run = _run(monkeypatch, [(5, 33), (42, NEVER)], 'v2', recovery_delay=45,
               probes=[(136, lambda m: dict(m.ha_recovery_in_progress))])

    assert run.seen[136] == {'pve2': True}
    assert run.m.ha_recovery_in_progress == {}


@pytest.mark.parametrize('agent,delay,out', [
    ('v2', 45, [(5, 33), (42, NEVER)]),
    ('none', 60, [(5, 33), (42, NEVER)]),
    ('v1', 90, [(5, 45), (52, NEVER)]),
])
def test_a_recovery_that_meets_the_lock_of_the_one_before_is_tried_again(tmp_path, monkeypatch, agent, delay,
                                                                         out):
    """The same with the storage recovery lock on (start_ha_monitor turns it on
    wherever it finds a shared storage, the common setup). The second recovery
    found the lock still held by the first one, gave up (and the audit trail asked
    whether the cluster was added twice), and the first then cancelled: pve2 was
    never recovered. The second is marked to be tried again now, and the third
    recovers pve2 on a count from the last pass that saw it."""
    (tmp_path / '.pegaprox').mkdir()
    monkeypatch.setattr(ha, 'lock_holder', lambda: ('b' * 32, 1))
    run = _run(monkeypatch, out, agent, recovery_delay=delay, horizon=500,
               storage_heartbeat_enabled=True, storage_heartbeat_path=str(tmp_path))
    pve, m = run.pve, run.m
    (_w1, w2, w3) = run.workers

    assert run.log.said('An earlier recovery of pve2 still holds its lock') == [w2]
    assert run.log.said('is still offline, trying its recovery again') == [w3]
    assert pve.moves() == [f'config {v} moved pve2 -> pve1' for v in GUESTS]
    assert pve.happened('config')[0][0] >= _first_pass_after_last_online(run, w2) \
        + m._ha_fence_timing('pve2')['earliest_recovery']
    assert [a for _t, a, _d in run.audits if 'lock' in a] == []
    assert os.listdir(tmp_path / '.pegaprox' / 'recovery' / 'pve2') == []
    assert m.ha_recovery_locks == {} and m.ha_recovery_in_progress == {}
    assert not [k for k in manager_mod._recovery_lock_owners if k.endswith('pve2')]
    if agent == 'v2':
        assert pve.twice == []


@pytest.mark.parametrize('agent', RUNS_ITS_GUESTS + ['v2'])
def test_a_return_that_ends_before_the_wait_still_cancels_as_before(monkeypatch, agent):
    """The counterproof: back at the end of the wait, the recovery is cancelled as it
    was, and nothing is recovered while pve2 stays."""
    run = _run(monkeypatch, [(5, 45)], agent)

    assert run.pve.moves() == [] and len(run.workers) == 1
    assert run.log.said('came back online - cancelling recovery')


def test_the_v2_agent_counts_its_fence_delay_from_the_last_loss_of_quorum(tmp_path):
    """The other half of 2, which the recovery relies on: the agent as rendered
    starts its fence delay again after a return, however short. The world changes
    on what the agent logged, so a slow start of bash moves nothing."""
    t_sf = 1.5
    world = World(tmp_path)
    world.set(quorate=False, votes=(1, 3), curl='down')
    marks = {}

    def step():
        out, now = world.out(), time.monotonic()
        if 'back' not in marks and 'WARNING: not quorate' in out:
            world.set(quorate=True, votes=(3, 3))           # back before its fence
            marks['back'] = now
        elif 'again' not in marks and 'In order again' in out:
            assert world.stops() == []
            world.set(quorate=False, votes=(1, 3))
            marks['again'] = now
        if world.stops():
            marks.setdefault('stopped', now)
            return True
        return False

    log, _took = world.run(_script('quorum', t_sf=t_sf), until=step, seconds=3 * t_sf + 10)

    assert 'stopped' in marks and 'again' in marks, log
    assert log.count('WARNING: not quorate') == 2, log
    # /proc/uptime counts in hundredths: a few of them early, never more
    assert marks['stopped'] - marks['again'] >= t_sf - 0.05


# --- the rule, one look at a time -----------------------------------------------------------

def _looked_at(monkeypatch, answers, agent='none', status='offline', interval=10, looked=None, vmid=None,
               guests=500, passes=(), **ha_config):
    """_ha_node_back of a manager whose API host answers GET /nodes for pve2 with
    `answers` in turn: 'online', 'offline', a status code or an exception, and
    /cluster/resources with `guests` ({vmid: (node, status)}, or a status code).
    The last pass saw pve2 online at 'pass at 30'; `passes` names the looks after
    which a pass saw it online again. (result, the sleeps between the looks, the
    number of looks)."""
    slept, asked = [], []
    monkeypatch.setattr(manager_mod, 'time', types.SimpleNamespace(sleep=slept.append))
    m = PegaProxManager.__new__(PegaProxManager)
    m.id = 'c1'
    m.logger = MagicMock()
    m.config = types.SimpleNamespace(name='lab', host=IPS['pve1'], api_port=8006)
    m.current_host = IPS['pve1']
    m.ha_config = dict(AGENTS[agent], **ha_config)
    m.ha_failure_threshold = 3
    m.ha_check_interval = interval
    m.ha_lock = threading.Lock()
    m.ha_node_status = {'pve2': {'status': status, 'last_seen': 'pass at 30'}}
    answers = list(answers)

    def get(url, timeout=10, **kw):
        if url == 'https://10.9.0.1:8006/api2/json/cluster/resources':
            if isinstance(guests, int):
                return _answer(None, guests)
            return _answer([{'vmid': v, 'node': n, 'status': s} for v, (n, s) in guests.items()])
        assert url == 'https://10.9.0.1:8006/api2/json/nodes'
        asked.append(1)
        if len(asked) in passes:
            m.ha_node_status['pve2']['last_seen'] = f'pass after look {len(asked)}'
        a = answers.pop(0) if len(answers) > 1 else answers[0]
        if isinstance(a, Exception):
            raise a
        if isinstance(a, int):
            return _answer(None, a)
        return _answer([{'node': 'pve1', 'status': 'online'}, {'node': 'pve2', 'status': a}])
    m._create_session = lambda: types.SimpleNamespace(get=get)
    return m._ha_node_back('pve2', looked, vmid), slept, len(asked)


@pytest.mark.parametrize('agent', list(AGENTS))
def test_a_node_listed_offline_is_not_back(monkeypatch, agent):
    assert _looked_at(monkeypatch, ['offline'], agent) == (False, [], 1)


@pytest.mark.parametrize('agent', RUNS_ITS_GUESTS)
def test_a_node_that_may_run_its_guests_is_back_once_it_is_listed_online(monkeypatch, agent):
    assert _looked_at(monkeypatch, ['online'], agent) == (True, [], 1)


@pytest.mark.parametrize('seen,expected', [
    (dict(AGENTS['v2']), True),
    # quorum forced under the rules: a node without quorum still fences itself
    (dict(AGENTS['v2'], force_quorum_on_failure=True), True),
    (AGENTS['v2-held'], False),
    (dict(AGENTS['v2'], fence_strategy=dict(THREE_VOTES, two_node_flag=True)), False),
    (dict(AGENTS['v2'], fence_strategy=dict(THREE_VOTES, expected_votes=2)), False),
    # corosync never looked at: not known to fence on its own
    ({'fence_agent_versions': {'pve2': 2}}, False),
    ({'fence_agent_versions': {'pve2': 1}, 'fence_strategy': THREE_VOTES}, False),
    ({'fence_agent_versions': {'pve3': 2}, 'fence_strategy': THREE_VOTES}, False),
], ids=['v2', 'v2-quorum-forced-under-the-rules', 'v2-held-by-a-leader', 'two-node-flag', 'two-votes',
        'corosync-not-read', 'v1', 'v2-on-another-node'])
def test_the_timing_says_which_node_fences_on_its_own(seen, expected):
    m = PegaProxManager.__new__(PegaProxManager)
    m.ha_config = seen
    m.ha_failure_threshold = 3
    assert m._ha_fence_timing('pve2')['self_fences'] is expected


def test_a_self_fencing_node_is_back_after_a_fence_delay_of_looks(monkeypatch):
    assert _looked_at(monkeypatch, ['online'], 'v2') == (True, [10, 10, 10], 4)


@pytest.mark.parametrize('gone_at', [1, 2, 3])
def test_a_self_fencing_node_gone_at_any_look_is_not_back(monkeypatch, gone_at):
    """Not back, once fence delay + margin from the look that found it gone are over
    and it is still gone."""
    answers = ['online'] * gone_at + ['offline']
    assert _looked_at(monkeypatch, answers, 'v2') == (False, [10] * gone_at + [FENCE_DELAY + MARGIN],
                                                      gone_at + 2)


def test_a_self_fencing_node_online_again_after_that_is_looked_at_from_the_start(monkeypatch):
    answers = ['online', 'offline', 'online', 'online', 'online', 'online']
    assert _looked_at(monkeypatch, answers, 'v2') == (True, [10, FENCE_DELAY + MARGIN, 10, 10, 10], 6)


def test_a_self_fencing_node_that_keeps_coming_back_gets_nothing_moved_meanwhile(monkeypatch):
    """Online at every look after a floor, gone at the next: it is neither back nor
    gone, and the worker that asked stays. Ended here by a step-down, before the
    rounds run out."""
    active = iter([True, True, True, False])
    monkeypatch.setattr(ha, 'is_active', lambda: next(active))
    assert _looked_at(monkeypatch, ['online', 'offline'] * 4, 'v2') == (False, [10, FENCE_DELAY + MARGIN] * 4, 8)


def test_a_self_fencing_node_that_keeps_coming_back_is_left_the_rest_after_a_few_rounds(monkeypatch):
    """Not for as long as it flaps: after NODE_BACK_RESTARTS rounds it is taken as
    back, and what is left stays with it (and is reported by the worker)."""
    rounds = PegaProxManager.NODE_BACK_RESTARTS + 1
    assert _looked_at(monkeypatch, ['online', 'offline'] * (rounds + 1), 'v2') == (
        True, [10, FENCE_DELAY + MARGIN] * rounds, 2 * rounds + 1)


def test_the_last_round_takes_the_node_as_back_only_when_its_last_look_lists_it(monkeypatch):
    """The rounds ran out on a look that found the node gone (a pass had seen it in
    between, so the look did not end the watch): it is not back, and the recovery
    goes on with the next guest."""
    monkeypatch.setattr(PegaProxManager, 'NODE_BACK_RESTARTS', 0)
    looked = {'last_seen': 'pass at 30'}
    # the pass during the second look counts at the third (last_seen is read first)
    back, slept, looks = _looked_at(monkeypatch, ['online', 'offline', 'offline'], 'v2', looked=looked,
                                    passes=(2,))
    assert back is False and looks == 3 and slept == [10, FENCE_DELAY + MARGIN]
    assert looked['last_seen'] == 'pass after look 2'


@pytest.mark.parametrize('agent,expected', [('none', (True, [], 1)), ('v1', (True, [], 1)),
                                            ('v2', (False, [FENCE_DELAY + MARGIN], 2))])
def test_a_pass_that_saw_the_node_since_the_last_look_counts_like_a_look_that_did(monkeypatch, agent, expected):
    """Listed offline now, but a pass saw it online since the worker's last look:
    a node that may run its guests is back, one that fences itself gets the floor
    and is looked at again. What the look saw is the worker's from then on."""
    looked = {'last_seen': 'pass at 20'}
    assert _looked_at(monkeypatch, ['offline'], agent, looked=looked) == expected
    assert looked['last_seen'] == 'pass at 30'


@pytest.mark.parametrize('agent', list(AGENTS))
def test_no_pass_since_the_last_look_is_no_return(monkeypatch, agent):
    looked = {'last_seen': 'pass at 30'}
    assert _looked_at(monkeypatch, ['offline'], agent, looked=looked) == (False, [], 1)


def test_a_self_fencing_node_that_reports_the_guest_stopped_is_waited_one_turn_of_its_agent(monkeypatch):
    """No second copy to wait out a fence delay for: one turn of its agent, after
    which the agent is in order again, and the node is back."""
    turn = 2 * PegaProxManager.FENCE_AGENT_INTERVAL
    assert _looked_at(monkeypatch, ['online'], 'v2', vmid=101,
                      guests={101: ('pve2', 'stopped')}) == (True, [turn], 2)
    # gone by then: the floor as for any return
    assert _looked_at(monkeypatch, ['online', 'offline'], 'v2', vmid=101,
                      guests={101: ('pve2', 'stopped')}) == (False, [turn, FENCE_DELAY + MARGIN], 3)


@pytest.mark.parametrize('guests', [{101: ('pve2', 'running')}, 500, {101: ('pve2', 'unknown')}],
                         ids=['running', 'not-read', 'unknown'])
def test_a_guest_the_node_may_run_is_watched_a_fence_delay(monkeypatch, guests):
    assert _looked_at(monkeypatch, ['online'], 'v2', vmid=101, guests=guests) == (True, [10, 10, 10], 4)


@pytest.mark.parametrize('agent', list(AGENTS))
def test_what_is_left_is_named_as_the_node_reports_it(monkeypatch, agent):
    """One read of /cluster/resources while the node is listed online and the API
    host reports the cluster quorate: a guest it runs, one that went to another
    node meanwhile, one that is gone, and a container that is stopped. Nothing is
    posted, whatever agent the node runs."""
    m = PegaProxManager.__new__(PegaProxManager)
    m.logger = MagicMock()
    m.config = types.SimpleNamespace(name='lab', host=IPS['pve1'], api_port=8006)
    m.current_host = IPS['pve1']
    m.ha_config, m.ha_failure_threshold, m.ha_lock = dict(AGENTS[agent]), 3, threading.Lock()
    m.ha_node_status = {'pve2': {'status': 'offline'}}
    m._ha_cluster_quorum = lambda: (True, [])
    resources = [{'vmid': 101, 'node': 'pve2', 'status': 'running'},
                 {'vmid': 102, 'node': 'pve3', 'status': 'stopped'},
                 {'vmid': 300, 'node': 'pve2', 'status': 'stopped', 'type': 'lxc'}]

    def get(url, timeout=10, **kw):
        if url.endswith('/nodes'):
            return _answer([{'node': 'pve2', 'status': 'online'}])
        return _answer(resources)
    m._create_session = lambda: types.SimpleNamespace(get=get)
    guests = [{'vmid': 101, 'type': 'qemu'}, {'vmid': 102, 'type': 'qemu'}, {'vmid': 103, 'type': 'qemu'},
              {'vmid': 300, 'type': 'lxc'}]

    assert m._ha_leave_to_node('pve2', guests) == [
        (101, 'running'), (102, 'stopped on pve3'), (103, 'not found'),
        (300, 'stopped - start it by hand once pve2 is in order')]


@pytest.mark.parametrize('fence_delay,interval,sleeps', [(50, 10, [10] * 5), (30, 20, [20, 20]),
                                                         (30, 7, [7] * 5), (30, 30, [30])])
def test_the_looks_come_from_the_fence_timing_and_the_monitor_interval(monkeypatch, fence_delay, interval,
                                                                       sleeps):
    """A fence delay long, rounded up to whole looks of the monitor's interval."""
    monkeypatch.setattr(PegaProxManager, 'FENCE_AGENT_T_SF', fence_delay)
    assert _looked_at(monkeypatch, ['online'], 'v2', interval=interval) == (True, sleeps, len(sleeps) + 1)


@pytest.mark.parametrize('answer', [500, ConnectionError('no route to host')], ids=['500', 'no-answer'])
@pytest.mark.parametrize('status,expected', [('offline', False), ('online', True)])
def test_when_the_api_host_does_not_answer_the_last_pass_stands(monkeypatch, answer, status, expected):
    assert _looked_at(monkeypatch, [answer], 'none', status=status) == (expected, [], 1)


@pytest.mark.parametrize('answer,said', [
    ({101: 'stopped', 102: 'running'}, 'still stopped: 101 - start them'),
    ({101: 'running', 102: 'running'}, None),
    (500, 'maybe still stopped (the guests could not be read): 101, 102 - start them'),
])
def test_what_an_earlier_recovery_left_is_said_again_while_it_is_still_down(monkeypatch, answer, said):
    """Said once, by the next recovery of the node, and only for guests nobody has
    started since; a manager with nothing noted asks nothing."""
    audits, pushed, asked = [], [], []
    monkeypatch.setattr(manager_mod, 'broadcast_sse', lambda ev, data, cid=None: pushed.append(data))
    monkeypatch.setattr('pegaprox.utils.audit.log_audit',
                        lambda user, action, details=None, **kw: audits.append((action, details)))
    m = PegaProxManager.__new__(PegaProxManager)
    m.id, m.logger = 'c1', MagicMock()
    m.config = types.SimpleNamespace(name='lab', host=IPS['pve1'], api_port=8006)
    m.current_host = IPS['pve1']

    def get(url, **kw):
        asked.append(url)
        if isinstance(answer, int):
            return _answer(None, answer)
        return _answer([{'vmid': v, 'node': 'pve1', 'status': st} for v, st in answer.items()])
    m._create_session = lambda: types.SimpleNamespace(get=get)

    m._ha_say_left_again('pve2')
    assert asked == [] and audits == [] and pushed == []
    m._ha_left_guests = {'pve2': [101, 102]}
    m._ha_say_left_again('pve2')
    m._ha_say_left_again('pve2')
    assert len(asked) == 1 and m._ha_left_guests == {}
    if said is None:
        assert audits == [] and pushed == []
    else:
        (action, details), = audits
        assert action == 'ha.recovery_left_guests' and said in details
        assert [(p['event'], p['severity']) for p in pushed] == [('ha.recovery_left_guests', 'critical')]
