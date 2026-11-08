"""The self-fence agent v2 and its install commands (#625, stage two S6).

The agent is a shell script the manager renders and puts on every node. Here it is
rendered by the manager and run as it is, against stand-ins on PATH for the tools it
calls: corosync-quorumtool, pvecm, ping, curl, qm, pct. Nothing here touches a node.
Time is real: the scripts are rendered with a short T_SF and interval through the
same renderer, and the defaults are pinned in a test of their own.

The install, uninstall, start, stop and check commands run against a directory that
stands in for / (their `root` argument), with a systemctl that only writes down what
it was asked.

MK Oct 2026
"""
import base64
import hashlib
import hmac
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import types
from unittest.mock import MagicMock

import pytest

import pegaprox.core.manager as manager_mod
from pegaprox.core import ha
from pegaprox.core.manager import PegaProxManager

T_SF = 0.6
INTERVAL = 0.1
# the script counts in 1/100 s of /proc/uptime and the tests in wall time from before
# bash started: a fence may show a few hundredths early, never right away
EARLIEST = T_SF - 0.05
TOKEN = 'ab' * 32
LEADER = 'https://10.9.0.5:5000'
LEFT_BEHIND = 'pegaprox-fence-agent.stopped'

FAKES = {
    # "$FAKE/votes" holds "<total> <expected>": the votes corosync counts as present
    # and the votes it runs with, as `corosync-quorumtool -s` prints them
    'corosync-quorumtool': '''#!/bin/bash
echo "corosync-quorumtool $*" >> "$FAKE/calls"
read -r total expected < "$FAKE/votes"
votes() {
    printf '\\nVotequorum information\\n----------------------\\n'
    printf 'Expected votes:   %s\\nHighest expected: %s\\nTotal votes:      %s\\n' "$expected" "$expected" "$total"
}
if [ "$(cat "$FAKE/quorate")" = yes ]; then
    printf 'Quorum information\\n------------------\\nNodes:            %s\\nQuorate:          Yes\\n' "$total"
    votes
else
    printf 'Quorum information\\n------------------\\nNodes:            %s\\nQuorate:          No\\n' "$total"
    votes
    exit 1
fi
''',
    # `pvecm expected N` makes the node quorate with the votes it has, unless
    # "$FAKE/refuses" is there
    'pvecm': '''#!/bin/bash
echo "pvecm $*" >> "$FAKE/calls"
read -r total expected < "$FAKE/votes"
if [ "$1" = expected ]; then
    [ -e "$FAKE/refuses" ] && { echo "Unable to set expected votes: CS_ERR_INVALID_PARAM" >&2; exit 1; }
    echo "$total $2" > "$FAKE/.votes.forced" && mv "$FAKE/.votes.forced" "$FAKE/votes"
    printf yes > "$FAKE/.quorate.forced" && mv "$FAKE/.quorate.forced" "$FAKE/quorate"
    exit 0
fi
if [ "$(cat "$FAKE/quorate")" = yes ]; then
    printf 'Votequorum information\\nExpected votes:   %s\\nTotal votes:      %s\\nQuorate:          Yes\\n' "$expected" "$total"
else
    printf 'Votequorum information\\nExpected votes:   %s\\nTotal votes:      %s\\nQuorate:          No\\n' "$expected" "$total"
fi
''',
    'ping': '''#!/bin/bash
ip="${@: -1}"
echo "ping $ip" >> "$FAKE/calls"
grep -qx "$ip" "$FAKE/reachable"
''',
    # the leader question as the design states it, written a second time in shell: a
    # question the token does not sign gets no answer, like the 403 of the route
    'curl': '''#!/bin/bash
url="${@: -1}"
echo "curl $url" >> "$FAKE/calls"
mode=$(cat "$FAKE/curl")
[ "$mode" = down ] && exit 7
q="${url#*\\?}"
cluster=$(printf '%s' "$q" | sed -n 's/.*cluster=\\([^&]*\\).*/\\1/p')
nonce=$(printf '%s' "$q" | sed -n 's/.*nonce=\\([^&]*\\).*/\\1/p')
sig=$(printf '%s' "$q" | sed -n 's/.*sig=\\([^&]*\\).*/\\1/p')
token=$(cat "$FAKE/token")
mac() { printf '%s' "$1" | openssl dgst -sha256 -hmac "$token" | awk '{print $NF}'; }
[ "$sig" = "$(mac "pegaprox-agent ask $cluster $nonce")" ] || { echo forbidden; exit 0; }
case "$mode" in
    leader) echo "leader 7 $(mac "pegaprox-agent leader $cluster $nonce 7")" ;;
    standby) echo "standby" ;;
    forged) echo "leader 7 $(printf '%064d' 0)" ;;
    othernonce) echo "leader 7 $(mac "pegaprox-agent leader $cluster 00000000000000000000000000000000 7")" ;;
esac
''',
    # "$FAKE/vms" holds "<id> <status> [name]" per VM. The lines of `qm list` and
    # `pct list` are laid out by the printf formats of PVE's qm.pm and pct.pm; a VM
    # without a name is listed as "VM <id>", as qemu-server's vmstatus names it
    # The agent stops the guests side by side: the stand-ins change their file one at
    # a time (flock), or a stop is lost to the sed of another and comes a pass later
    'qm': '''#!/bin/bash
echo "qm $*" >> "$FAKE/calls"
gone() { echo "Configuration file 'nodes/pve1/qemu-server/$1.conf' does not exist" >&2; exit 2; }
case "$1" in
    list) printf '%10s %-20s %-10s %-10s %12s %-10s\\n' VMID NAME STATUS 'MEM(MB)' 'BOOTDISK(GB)' PID
          while read -r id st name; do
              [ "$st" = running ] && pid=4711 || pid=0
              printf '%10s %-20s %-10s %-10s %12.2f %-10s\\n' "$id" "${name:-VM $id}" "$st" 1024 8 "$pid"
          done < "$FAKE/vms" ;;
    stop) flock "$FAKE/.vms.lock" sed -i "s/^$2 running/$2 stopped/" "$FAKE/vms" ;;
    start) grep -q "^$2 " "$FAKE/vms" || gone "$2"
           flock "$FAKE/.vms.lock" sed -i "s/^$2 stopped/$2 running/" "$FAKE/vms" ;;
    status) grep -q "^$2 " "$FAKE/vms" || gone "$2"
            echo "status: $(awk -v id="$2" '$1 == id {print $2}' "$FAKE/vms")" ;;
esac
''',
    'pct': '''#!/bin/bash
echo "pct $*" >> "$FAKE/calls"
gone() { echo "Configuration file 'nodes/pve1/lxc/$1.conf' does not exist" >&2; exit 2; }
case "$1" in
    list) printf '%-10s %-10s %-12s %-20s\\n' VMID Status Lock Name
          while read -r id st name; do
              printf '%-10s %-10s %-12s %-20s\\n' "$id" "$st" '' "${name:-CT$id}"
          done < "$FAKE/cts" ;;
    stop) flock "$FAKE/.cts.lock" sed -i "s/^$2 running/$2 stopped/" "$FAKE/cts" ;;
    start) grep -q "^$2 " "$FAKE/cts" || gone "$2"
           flock "$FAKE/.cts.lock" sed -i "s/^$2 stopped/$2 running/" "$FAKE/cts" ;;
    status) grep -q "^$2 " "$FAKE/cts" || gone "$2"
            echo "status: $(awk -v id="$2" '$1 == id {print $2}' "$FAKE/cts")" ;;
esac
''',
    'systemctl': '''#!/bin/bash
echo "systemctl $*" >> "$FAKE/calls"
if [ "$1" = is-active ]; then
    if grep -qx "$2" "$FAKE/active" 2>/dev/null; then echo active; else echo inactive; exit 3; fi
fi
if [ "$1" = is-enabled ]; then
    if grep -qx "$2" "$FAKE/disabled" 2>/dev/null; then echo disabled; exit 1; else echo enabled; fi
fi
# "$FAKE/broken" names the units that do not start
if [ "$1" = start ] && grep -qx "$2" "$FAKE/broken" 2>/dev/null; then exit 1; fi
exit 0
''',
}


class World:
    """What the script sees: the stand-ins on PATH and the files they answer from."""

    def __init__(self, tmp_path, without=()):
        self.dir = tmp_path / 'world'
        self.bin = tmp_path / 'bin'
        self.dir.mkdir()
        self.bin.mkdir()
        for name, body in FAKES.items():
            if name in without:
                continue
            path = self.bin / name
            path.write_text(body)
            path.chmod(0o755)
        (self.dir / 'calls').write_text('')
        (self.dir / 'token').write_text(TOKEN)
        self.set(quorate=True, votes=(3, 3), reachable=[], curl='down', vms=['100 running', '101 running'],
                 cts=['200 running'])
        self.env = {'PATH': f'{self.bin}:/usr/bin:/bin', 'FAKE': str(self.dir), 'TMPDIR': str(self.dir),
                    'HOME': str(self.dir), 'LANG': 'C'}

    def set(self, quorate=None, reachable=None, curl=None, vms=None, cts=None, votes=None):
        """votes is (total, expected) as corosync reports them."""
        if votes is not None:
            self._write('votes', f'{votes[0]} {votes[1]}\n')
        if quorate is not None:
            self._write('quorate', 'yes' if quorate else 'no')
        if reachable is not None:
            self._write('reachable', '\n'.join(reachable) + '\n')
        if curl is not None:
            self._write('curl', curl)
        if vms is not None:
            self._write('vms', '\n'.join(vms) + '\n')
        if cts is not None:
            self._write('cts', '\n'.join(cts) + '\n')

    def _write(self, name, text):
        # replaced in one step: the script reads these while the test changes them
        tmp = self.dir / f'.{name}.new'
        tmp.write_text(text)
        os.replace(tmp, self.dir / name)

    def calls(self, prefix=''):
        return [line for line in (self.dir / 'calls').read_text().splitlines() if line.startswith(prefix)]

    def stops(self):
        return sorted(c for c in self.calls() if c.startswith(('qm stop', 'pct stop')))

    def starts(self):
        return [c for c in self.calls() if c.startswith(('qm start', 'pct start'))]

    def sh(self, cmd):
        """A command as it reaches this node over SSH. Its exit code."""
        return subprocess.run(['bash', '-c', cmd], env=self.env, capture_output=True, text=True).returncode

    def leave_behind(self, listed='qm 100\nqm 101\npct 200\n', go=None):
        """The files a development build of the agent kept under /run, which TMPDIR
        stood in for: the list of the guests it had stopped, what went with it, and
        PegaProx's go-ahead with the uptime of now in it. That build started the
        guests of the list on a node that had the three and was quorate."""
        if go is None:
            go = f'{float(open("/proc/uptime").read().split()[0]):.2f} 0.00\n'
        for end, text in (('', listed), ('.votes', '1\n'), ('.out', ''), ('.go', go)):
            self._write(LEFT_BEHIND + end, text)

    def left_behind(self):
        return {p.name: p.read_text() for p in self.dir.iterdir() if p.name.startswith(LEFT_BEHIND)}

    def guests(self):
        return (self.dir / 'vms').read_text().split() + (self.dir / 'cts').read_text().split()

    def out(self):
        return (self.dir / 'agent.out').read_text()

    def run(self, script, until=None, seconds=None):
        """Run the agent until `until()` holds or `seconds` are over, then kill it.
        Returns its output and how long it ran."""
        path = self.dir / 'agent.sh'
        path.write_text(script)
        log = self.dir / 'agent.out'
        started = time.monotonic()
        deadline = started + (seconds if seconds is not None else 3 * T_SF + 2)
        with open(log, 'w') as out:
            proc = subprocess.Popen(['bash', str(path)], stdout=out, stderr=subprocess.STDOUT,
                                    env=self.env, start_new_session=True, cwd=str(self.dir))
            try:
                while time.monotonic() < deadline and proc.poll() is None:
                    if until is not None and until():
                        break
                    time.sleep(0.03)
            finally:
                took = time.monotonic() - started
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait()
        return log.read_text(), took


@pytest.fixture
def world(tmp_path):
    return World(tmp_path)


def _mgr(cid='c1', **ha_config):
    m = PegaProxManager.__new__(PegaProxManager)
    m.id = cid
    m.config = types.SimpleNamespace(name='lab', ssh_user='root', ssh_key='', pass_='pw')
    m.ha_config = dict({'agent_token': TOKEN}, **ha_config)
    m.logger = MagicMock()
    return m


def _plan(mode, strategy='quorum', members=None, vmid='', votes=None, minority=False):
    """votes: what the cluster had at install time. Three where a node without quorum
    is the minority, two otherwise, unless the test says."""
    if members is None:
        members = [LEADER] if mode == 'tiebreak' or vmid else []
    if votes is None:
        votes = 3 if minority or mode == 'quorum' else 2
    return {'mode': mode, 'strategy': strategy, 'members': members, 'vmid': vmid,
            'expected_votes': votes, 'minority_fences': minority}


def _script(mode, **kw):
    t_sf = kw.pop('t_sf', T_SF)
    interval = kw.pop('interval', INTERVAL)
    return _mgr()._ha_render_fence_agent('pve1', _plan(mode, **kw), t_sf=t_sf, interval=interval)


ALL_STOPPED = ['pct stop 200 --timeout 30', 'qm stop 100 --timeout 30', 'qm stop 101 --timeout 30']
ALL_RUNNING = ['100', 'running', '101', 'running', '200', 'running']
ALL_DOWN = ['100', 'stopped', '101', 'stopped', '200', 'stopped']
# the one line a fence leaves about the guests it stopped, and the one when it is over
STOPPED_LINE = 'Stopped by this fence: qm 100 101, pct 200 - start them by hand once the node is in order again'
NOTHING_STARTED = 'Nothing is started automatically'


# --- rendering ---------------------------------------------------------------------

@pytest.mark.parametrize('mode', ['quorum', 'tiebreak', 'off'])
def test_every_mode_renders_to_a_script_bash_accepts(mode, tmp_path):
    script = _mgr()._ha_render_fence_agent('pve1', _plan(mode))
    path = tmp_path / 'agent.sh'
    path.write_text(script)

    assert subprocess.run(['bash', '-n', str(path)], capture_output=True).returncode == 0
    assert '__' not in script, [l for l in script.splitlines() if '__' in l]
    assert script.splitlines()[:2] == ['#!/bin/bash', PegaProxManager.FENCE_AGENT_MARKER]
    assert f'MODE="{mode}"' in script and 'AGENT_VERSION=2' in script
    assert chr(0x2014) not in script


def test_the_shipped_timings_are_thirty_seconds_and_five():
    script = _mgr()._ha_render_fence_agent('pve1', _plan('quorum'))

    assert 'T_SF_CS=3000 ' in script and 'CHECK_INTERVAL=5\n' in script
    assert PegaProxManager.FENCE_AGENT_T_SF == 30 and PegaProxManager.FENCE_AGENT_INTERVAL == 5
    assert PegaProxManager.FENCE_AGENT_MARGIN == 30


@pytest.mark.parametrize('threshold,delay', [(3, 30), (3, 0), (1, 5), (2, 45), (6, 120), (3, 10.5)])
def test_a_recovery_never_starts_before_the_v2_agent_had_its_time(threshold, delay):
    """The agent's fence delay and the recovery worker's wait were two numbers in two
    places (30 s in the script, recovery_delay in the settings) that happened to fit
    at their defaults. With recovery_delay turned down a node's guests were started
    elsewhere while its agent was still counting. Both come from _ha_fence_timing."""
    m = _mgr(recovery_delay=delay, fence_agent_versions={'pve2': 2, 'pve3': 1})
    m.ha_failure_threshold = threshold
    # the pass that first sees the node offline is check one of the threshold
    declared = (threshold - 1) * 10
    configured = declared + delay

    timing = m._ha_fence_timing('pve2')

    assert timing['earliest_recovery'] == max(configured, timing['fence_delay'] + timing['margin'])
    assert timing['wait'] == timing['earliest_recovery'] - declared and timing['wait'] >= delay
    # the delay the script is rendered with is the one the wait was worked out from
    assert f"T_SF_CS={timing['fence_delay'] * 100} " in m._ha_render_fence_agent('pve1', _plan('quorum'))
    # a node with the agent of an older PegaProx, or with none: what the admin set, as before
    for node in ('pve3', 'pve4'):
        assert m._ha_fence_timing(node)['wait'] == delay
        assert m._ha_fence_timing(node)['earliest_recovery'] == configured


def test_the_fence_delay_and_the_recovery_wait_move_together(monkeypatch):
    monkeypatch.setattr(PegaProxManager, 'FENCE_AGENT_T_SF', 50)
    m = _mgr(recovery_delay=30, fence_agent_versions={'pve2': 2})
    m.ha_failure_threshold = 3

    assert 'T_SF_CS=5000 ' in m._ha_render_fence_agent('pve1', _plan('quorum'))
    assert m._ha_fence_timing('pve2')['wait'] == 60      # 50 + the margin of 30 - the two intervals of 10 s
    assert m._ha_fence_agent_status()['fence_delay'] == 50


class _Clock:
    def __init__(self):
        self.now = 0.0

    def sleep(self, seconds):
        self.now += seconds


def _monitored(clock, threshold, delay, versions):
    """A manager whose monitor passes and recovery worker are the real ones, on
    `clock`. pve2 is the node that goes offline; `recovery_at` takes the time at
    which the worker's wait is over and it starts to act."""
    m = _mgr(recovery_delay=delay, fence_agent_versions=versions)
    m.config = types.SimpleNamespace(name='lab', user='root@pam', pass_='pw', ssh_key='', ha_settings={},
                                     host='10.9.0.1', api_port=8006)
    m.current_host = '10.9.0.1'
    m.ha_check_interval = 10
    m.ha_failure_threshold = threshold
    m.ha_lock = threading.Lock()
    m.is_connected = True
    m.nodes_in_maintenance = set()
    m.ha_recovery_in_progress = {}
    m.ha_node_status = {n: {'status': 'online', 'consecutive_failures': 0, 'last_seen': None,
                            'last_status': 'online'} for n in ('pve1', 'pve2')}
    m.status = {'pve2': 'online'}
    m._create_session = lambda: types.SimpleNamespace(get=lambda url, timeout=10: types.SimpleNamespace(
        status_code=200, json=lambda: {'data': [{'node': 'pve1', 'status': 'online'},
                                                {'node': 'pve2', 'status': m.status['pve2']}]}))
    m._ha_cluster_quorum = lambda: (True, [])
    m._ha_check_restore_quorum = lambda: None
    m.recovery_at = []

    def allowed(node):
        m.recovery_at.append(clock.now)
        return None
    m._ha_recovery_allowed = allowed
    # the worker is a thread that starts with the pass; here it runs right after it
    m.triggered = []
    m._ha_trigger_recovery = m.triggered.append
    return m


@pytest.mark.parametrize('threshold,delay', [(3, 30), (3, 0), (1, 5), (2, 10), (6, 120), (1, 0)])
@pytest.mark.parametrize('agent', [2, 1, None], ids=['v2', 'v1', 'no-agent'])
def test_the_recovery_starts_when_the_status_says_and_not_before_the_agent_is_done(monkeypatch, threshold,
                                                                                    delay, agent):
    """Measured on the monitor's own clock, not worked out a second time: passes
    every ha_check_interval seconds through the real _ha_check_nodes, then the real
    _ha_recovery_worker up to the end of its wait. The timing counted
    failure_threshold intervals up to the declaration, but the pass that first sees
    the node offline is already check one: the recovery of a v2 node began one
    interval before its agent had fence_delay + margin, and earliest_recovery in the
    status was ten seconds off what the worker did."""
    clock = _Clock()
    monkeypatch.setattr(manager_mod, 'broadcast_sse', lambda *a, **kw: None)
    monkeypatch.setattr(manager_mod.time, 'sleep', clock.sleep)
    monkeypatch.setattr(ha, 'is_active', lambda: True)
    m = _monitored(clock, threshold, delay, {'pve2': agent} if agent else {})
    timing = m._ha_fence_timing('pve2')

    m._ha_check_nodes()
    clock.sleep(10)
    m.status['pve2'] = 'offline'
    first_seen = None
    for _ in range(20):
        if first_seen is None:
            first_seen = clock.now          # this pass is the first to see it offline
        m._ha_check_nodes()
        if m.triggered:
            m._ha_recovery_worker(m.triggered[0])
            break
        clock.sleep(10)

    assert m.recovery_at, [c for c in m.logger.mock_calls if c[0] in ('error', 'critical')]
    acted = m.recovery_at[0] - first_seen
    assert acted == timing['earliest_recovery']
    if agent:
        assert m._ha_fence_agent_status()['nodes']['pve2']['earliest_recovery'] == acted
    if agent == 2:
        assert acted >= timing['fence_delay'] + timing['margin']
    else:
        # what the admin set, as before: the checks up to the declaration, then recovery_delay
        assert acted == (threshold - 1) * 10 + delay


@pytest.mark.parametrize('delay', ['soon', None, True, False, -1, float('nan'), float('inf'), [30]])
def test_a_recovery_delay_that_is_no_number_never_shortens_the_wait_of_a_v2_node(delay):
    """A value that cannot be counted with was handed on as it was, for every node. For
    a node with the v2 agent the wait is then fence delay + margin, whatever the
    threshold. A node without it gets the value as before."""
    m = _mgr(recovery_delay=delay, fence_agent_versions={'pve2': 2, 'pve3': 1})
    m.ha_failure_threshold = 3

    timing = m._ha_fence_timing('pve2')

    assert timing['wait'] == timing['fence_delay'] + timing['margin'] == 60
    assert timing['earliest_recovery'] == 80
    assert m._ha_fence_timing()['wait'] == 60
    old = m._ha_fence_timing('pve3')
    assert old['wait'] is delay or old['wait'] == delay
    if not isinstance(delay, (int, float)) or isinstance(delay, bool):
        assert old['earliest_recovery'] is None


class _LoopClock:
    """time.sleep for the monitor loop and the worker: it takes what time.sleep takes,
    a bool included, and raises where that raises."""

    def __init__(self):
        self.now = 0.0

    def sleep(self, seconds):
        if not isinstance(seconds, (int, float)):
            raise TypeError(f"'{type(seconds).__name__}' object cannot be interpreted as an integer or float")
        if seconds != seconds:
            raise ValueError('Invalid value NaN (not a number)')
        if seconds < 0:
            raise ValueError('sleep length must be non-negative')
        self.now += seconds


def _measured(monkeypatch, threshold, delay, versions, interval=10):
    """The real _ha_monitor_loop with its own sleeps, the real _ha_check_nodes and the
    real _ha_recovery_worker up to the end of its wait, on one clock. pve2 is offline
    from the first pass on. (seconds from that pass to the recovery acting, the timing
    the manager states); the seconds are None when no recovery came."""
    clock = _LoopClock()
    monkeypatch.setattr(manager_mod, 'broadcast_sse', lambda *a, **kw: None)
    monkeypatch.setattr(manager_mod.time, 'sleep', clock.sleep)
    monkeypatch.setattr(ha, 'is_active', lambda: True)
    m = _monitored(clock, threshold, delay, versions)
    m.ha_check_interval = interval
    m.ha_enabled = True
    m.stop_event = threading.Event()
    m.status['pve2'] = 'offline'
    m._ha_update_fallback_hosts = lambda: None
    m._ha_agent_members_changed = lambda: False
    triggered = []

    def trigger(node):
        # the worker is a thread that starts here: the loop ends with this pass, and
        # the worker runs on the same clock from this moment
        triggered.append(clock.now)
        m.ha_enabled = False
    m._ha_trigger_recovery = trigger
    passes = []
    check = m._ha_check_nodes

    def counted():
        passes.append(clock.now)
        if len(passes) > 400:
            m.ha_enabled = False
        return check()
    m._ha_check_nodes = counted

    timing = m._ha_fence_timing('pve2')
    m._ha_monitor_loop()
    if not triggered:
        return None, timing
    try:
        m._ha_recovery_worker('pve2')
    except Exception:
        return None, timing            # the worker dies in its thread
    return (m.recovery_at[0] - passes[0] if m.recovery_at else None), timing


@pytest.mark.parametrize('threshold,delay', [(3, False), (3, True), (True, 0), (True, 30), (False, 0),
                                             (True, False), (True, True)])
def test_a_json_true_or_false_does_not_take_the_floor_of_a_v2_node_away(monkeypatch, threshold, delay):
    """PUT .../ha/config stored recovery_delay and failure_threshold as they were sent.
    A bool is a number to time.sleep and to the monitor's >=, and no number to the
    timing, which handed the wait on as it was: the recovery of a v2 node began 0 to
    30 s after the first pass, with the status saying earliest_recovery: null. Measured
    on the loop's own clock."""
    need = PegaProxManager.FENCE_AGENT_T_SF + PegaProxManager.FENCE_AGENT_MARGIN

    took, timing = _measured(monkeypatch, threshold, delay, {'pve2': 2})

    assert took is not None and took >= need
    assert timing['earliest_recovery'] == took


@pytest.mark.parametrize('threshold,delay', [(3, '30'), (3, None), (3, [30]), ('3', 30), (None, 30),
                                             (3, float('nan')), (3, float('inf')), (3, -1), (7, -100)])
def test_no_value_in_the_settings_starts_the_recovery_of_a_v2_node_early(monkeypatch, threshold, delay):
    need = PegaProxManager.FENCE_AGENT_T_SF + PegaProxManager.FENCE_AGENT_MARGIN

    took, _ = _measured(monkeypatch, threshold, delay, {'pve2': 2})

    assert took is None or took >= need


@pytest.mark.parametrize('interval', [5, 10, 20, 30, 60, 20.7, 1.5, True, '20', None])
def test_the_monitor_sleeps_the_interval_the_timing_counts_with(monkeypatch, interval):
    """The loop slept a literal ten times one second while _ha_fence_timing read
    ha_check_interval. Nothing sets that to anything but 10 today; with 20 the timing
    took 2 x 20 s off the wait of a v2 node and the loop took 2 x 10 s to declare it,
    so its recovery began 20 s early. Both take it from _ha_interval, in whole
    seconds, which is what the loop can sleep."""
    need = PegaProxManager.FENCE_AGENT_T_SF + PegaProxManager.FENCE_AGENT_MARGIN

    took, timing = _measured(monkeypatch, 3, 0, {'pve2': 2}, interval=interval)

    assert took == timing['earliest_recovery'] and took >= need
    if type(interval) is int:
        assert took == 2 * interval + timing['wait']


@pytest.mark.parametrize('stored', [True, False, 0, 0.5, -5, '20', None, float('nan'), float('inf')])
def test_an_interval_that_is_no_whole_number_of_seconds_is_ten(stored):
    m = _mgr()
    m.ha_check_interval = stored
    assert m._ha_interval() == 10
    del m.ha_check_interval
    assert m._ha_interval() == 10


def test_no_single_manager_address_is_baked_in_any_more():
    """v1 carried MANAGER_IP and pinged it. A quorum cluster carries no PegaProx address
    at all now, a tiebreak cluster the list of instances and the key for the question."""
    quorum = _mgr()._ha_render_fence_agent('pve1', _plan('quorum'))
    tiebreak = _mgr()._ha_render_fence_agent('pve1', _plan('tiebreak', members=[LEADER, 'https://10.9.0.6:5000']))

    for script in (quorum, tiebreak):
        assert 'MANAGER_IP' not in script and 'can_reach_manager' not in script
        # and no peer to ping: what is there of the cluster is corosync's to say
        assert 'OTHER_NODES' not in script and 'ping -c' not in script
    assert 'MEMBERS=""' in quorum and 'AGENT_TOKEN=""' in quorum and 'CLUSTER_VOTES=3\n' in quorum
    assert f'MEMBERS="{LEADER} https://10.9.0.6:5000"' in tiebreak
    assert f'AGENT_TOKEN="{TOKEN}"' in tiebreak and 'CLUSTER_VOTES=2\n' in tiebreak


@pytest.mark.parametrize('members', [['https://x.example:5000"; rm -rf / #'], ['ftp://x'], ['https://a b'],
                                     ['$(id)'], ['https://x/`id`']])
def test_an_address_that_is_no_address_never_reaches_the_script(members):
    """Everything in the script runs as root on the node. A tiebreak cluster without one
    usable address gets no script rather than one that can never find a leader."""
    with pytest.raises(ValueError):
        _mgr()._ha_render_fence_agent('pve1', _plan('tiebreak', members=members))
    script = _mgr()._ha_render_fence_agent('pve1', _plan('tiebreak', members=members + [LEADER]))
    assert f'MEMBERS="{LEADER}"' in script


def test_a_member_address_that_spells_a_placeholder_is_refused(monkeypatch):
    """ha.valid_https_url lets a path carry "__". The script's placeholders are made
    of it, and a member under https://a/__AGENT_TOKEN__ got the key of the leader
    question filled into MEMBERS, an address every local user of the node can see in
    the process list of curl. Such an address is dropped like any other that cannot
    go into the script, and named once."""
    m = _mgr()
    monkeypatch.setattr(ha, 'own_url', lambda: LEADER)
    monkeypatch.setattr(ha, 'members', lambda: [{'url': 'https://a/__AGENT_TOKEN__'}, {'url': 'https://b/x__y'},
                                                {'url': 'https://c/x_y'}])

    assert m._ha_agent_members() == [LEADER, 'https://c/x_y']
    assert m._ha_agent_members() == [LEADER, 'https://c/x_y']
    said = [c[0][0] for c in m.logger.error.call_args_list]
    assert len(said) == 2 and '__AGENT_TOKEN__' in said[0] and 'x__y' in said[1]

    # a plan that carries one all the same: neither the script nor the check takes it
    hostile = [LEADER, 'https://a/__AGENT_TOKEN__', 'https://a/__CLUSTER_ID__']
    script = m._ha_render_fence_agent('pve1', _plan('tiebreak', members=hostile))
    assert f'MEMBERS="{LEADER}"' in script and script.count(TOKEN) == 1
    assert 'https://a/' not in PegaProxManager._agent_check_cmd(hostile)
    with pytest.raises(ValueError):
        m._ha_render_fence_agent('pve1', _plan('tiebreak', members=hostile[1:]))


def test_the_script_is_filled_in_one_pass():
    """One replace per placeholder, each over the result of the last, filled a value
    that spells a later placeholder in turn: a cluster id of __AGENT_TOKEN__ put the
    token where the id belongs."""
    script = _mgr(cid='__AGENT_TOKEN__')._ha_render_fence_agent('pve1', _plan('tiebreak'))

    assert 'CLUSTER_ID="__AGENT_TOKEN__"\n' in script
    assert script.count(TOKEN) == 1 and f'AGENT_TOKEN="{TOKEN}"\n' in script
    # and every placeholder of the template is one the renderer fills
    assert re.findall(r'__[A-Z_]+?__', script) == ['__AGENT_TOKEN__']


def test_other_values_are_coerced_too():
    m = _mgr(cid='c1"; reboot; "')
    with pytest.raises(ValueError):
        m._ha_render_fence_agent('pve1', _plan('quorum'))
    for votes in ('3; reboot', '$(id)', True, -1, 10 ** 6, None):
        plan = dict(_plan('quorum', vmid='100; reboot'), expected_votes=votes)
        script = _mgr()._ha_render_fence_agent('pve1', plan)
        assert 'PEGAPROX_VMID=""' in script and 'CLUSTER_VOTES=0\n' in script
    with pytest.raises(ValueError):
        _mgr()._ha_render_fence_agent('pve1', _plan('sideways'))
    with pytest.raises(ValueError):
        _mgr()._ha_render_fence_agent('pve1', _plan('quorum', strategy='$(id)'))


def _cluster_row(db, cid='c1', **ha_settings):
    db.save_cluster(cid, dict(name='lab', host='10.9.0.1', user='root@pam', ssl_verification=False,
                              fallback_hosts=[], ha_enabled=True, ha_settings=ha_settings, ssh_user='root',
                              ssh_key='', ssh_port=22, cluster_type='proxmox', api_port=8006,
                              **{'pass': 'pw'}))


def test_the_token_is_made_once_and_stored_before_a_script_carries_it(db):
    _cluster_row(db, recovery_delay=45)
    m = _mgr()
    m.ha_config.pop('agent_token')
    m.config.ha_settings = {'recovery_delay': 45}

    script = m._ha_render_fence_agent('pve1', _plan('tiebreak'))

    token = m.ha_config['agent_token']
    assert len(token) == 64 and f'AGENT_TOKEN="{token}"' in script
    assert db.get_cluster('c1')['ha_settings'] == {'recovery_delay': 45, 'agent_token': token}
    assert m.config.ha_settings['agent_token'] == token       # what save_config writes back
    assert m._ha_agent_token() == token
    m.ha_config['agent_token'] = 'not a token'
    assert m._ha_agent_token() not in ('not a token', token)


@pytest.mark.parametrize('why', ['no-row', 'standby'])
def test_a_token_that_cannot_be_stored_installs_no_agent(db, monkeypatch, why):
    """An agent whose key this instance does not know after a restart never hears a
    leader again, and a tiebreak node without a leader fences itself."""
    if why == 'standby':
        _cluster_row(db)
        monkeypatch.setattr(ha, 'is_active', lambda: False)
    m = _mgr()
    m.ha_config.pop('agent_token')
    sent = []
    monkeypatch.setattr(m, '_ha_agent_ssh', lambda ip, cmd, **kw: sent.append(cmd) or 'AGENT_INSTALLED\n',
                        raising=False)

    with pytest.raises(ValueError):
        m._ha_render_fence_agent('pve1', _plan('tiebreak'))
    assert m._ha_install_self_fence_agent('pve1', '10.9.0.1', _plan('tiebreak')) is False
    assert sent == [] and 'agent_token' not in m.ha_config

    # counterproof: a quorum cluster carries no token and installs all the same
    assert m._ha_install_self_fence_agent('pve1', '10.9.0.1', _plan('quorum')) is True


# --- quorum first: three or more votes ------------------------------------------------

def test_a_quorate_node_does_nothing_and_asks_nobody(world):
    """Quorate is all it takes: no PegaProx answers, no peer answers a ping, and still
    nothing is stopped. v1 stopped everything here once the manager and the peers were
    both gone from ICMP and pvecm was slow to say yes."""
    world.set(quorate=True, reachable=[], curl='down')

    log, _ = world.run(_script('quorum'), seconds=3 * T_SF)

    assert world.stops() == []
    assert world.calls('curl') == [] and world.calls('ping') == []
    assert len(world.calls('corosync-quorumtool')) >= 3, log


def test_a_node_that_lost_quorum_fences_itself_after_t_sf_whoever_answers(world):
    """The counterproof to v1's shortcut: there a reachable manager reset every counter
    before quorum was even looked at, so a node in the minority that still reached
    PegaProx kept its VMs while the majority recovered them."""
    world.set(quorate=False, reachable=['10.9.0.2'], curl='leader')
    # with a PegaProx VM configured the script does carry the instances, and the
    # leader would answer: it is not asked about fencing all the same
    script = _script('quorum', vmid='900', members=[LEADER])
    assert f'MEMBERS="{LEADER}"' in script

    log, took = world.run(script, until=lambda: len(world.stops()) == 3)

    assert world.stops() == ALL_STOPPED, log
    assert took >= EARLIEST, f'fenced after {took:.2f}s, before T_SF'
    assert 'not quorate' in log and 'ISOLATED! Self-fencing' in log
    assert world.calls('curl') == [] and world.calls('qm start') == []


def test_quorum_that_comes_back_within_t_sf_fences_nothing(world):
    world.set(quorate=False)
    back = []

    def flip():
        if not back and 'WARNING: not quorate' in (world.dir / 'agent.out').read_text():
            world.set(quorate=True)
            back.append(time.monotonic())
        return False

    log, _ = world.run(_script('quorum', t_sf=1.5), until=flip, seconds=3.5)

    assert back, log
    assert world.stops() == [] and 'In order again' in log


@pytest.mark.parametrize('mode', ['quorum', 'tiebreak'])
def test_the_fenced_node_keeps_its_guests_down_and_starts_nothing_when_the_others_are_back(world, mode):
    """Nothing comes up on a fenced node: 100 is brought up there and stopped again.
    Then the others are back and the node is quorate with every vote. It starts
    nothing by itself: PegaProx may have recovered its guests to the nodes that are
    back, or be at it, and a config moved from under a running guest runs it twice.
    The log names the guests the fence stopped, once, and says once that they are
    left to the admin. 102 was down before the fence and is in neither line."""
    world.set(quorate=False, votes=(1, 3), curl='leader', vms=['100 running', '101 running', '102 stopped'])
    seen = {}

    def step():
        out = world.out()
        if 'Waiting for recovery' in out and 'restarted' not in seen:
            # something brings a guest back up on the fenced node
            world.set(vms=['100 running', '101 stopped', '102 stopped'])
            seen['restarted'] = len(world.calls('qm stop 100'))
        elif 'restarted' in seen and 'quorate' not in seen and out.count('Stopped by this fence') == 2:
            # stopped a second time
            assert len(world.calls('qm stop 100')) > seen['restarted']
            world.set(quorate=True, votes=(3, 3))
            seen['quorate'] = time.monotonic()
        # and some passes more
        return 'quorate' in seen and NOTHING_STARTED in out and time.monotonic() - seen['quorate'] > 10 * INTERVAL

    log, _ = world.run(_script(mode, minority=True), until=step, seconds=10)

    assert seen.get('quorate'), log
    assert 'In order again, resuming' in log
    assert world.starts() == [], log
    assert world.guests() == ['100', 'stopped', '101', 'stopped', '102', 'stopped', '200', 'stopped']
    assert log.count(STOPPED_LINE) == 1
    # the guest that came up while the node was fenced, when it was stopped again
    assert log.count('Stopped by this fence: qm 100 - start them by hand') == 1
    assert log.count(NOTHING_STARTED) == 1
    assert world.left_behind() == {}


def test_pvecm_is_asked_where_there_is_no_quorumtool(tmp_path):
    world = World(tmp_path, without=('corosync-quorumtool',))
    world.set(quorate=False)

    log, _ = world.run(_script('quorum'), until=lambda: len(world.stops()) == 3)

    assert world.stops() == ALL_STOPPED, log
    assert world.calls('pvecm status') and not world.calls('corosync-quorumtool')


def test_wait_strategy_logs_and_keeps_the_guests(world):
    world.set(quorate=False)

    log, _ = world.run(_script('quorum', strategy='wait'),
                       until=lambda: 'Keeping VMs running' in (world.dir / 'agent.out').read_text())

    assert 'FENCE_STRATEGY=wait' in log and 'Keeping VMs running' in log
    assert world.stops() == []


def test_a_node_in_no_cluster_never_fences(world):
    world.set(quorate=False, reachable=[], curl='down')

    log, _ = world.run(_script('off'), seconds=3 * T_SF)

    assert world.stops() == [] and 'ISOLATED' not in log


# --- the tiebreak: two nodes, or quorum forced ------------------------------------------

def test_tiebreak_a_node_with_its_peer_and_quorum_asks_nobody(world):
    """Both votes of a two-vote cluster are there, as corosync counts them. Nothing
    answers a ping and no PegaProx answers: that is the management network, and
    it is not asked."""
    world.set(quorate=True, votes=(2, 2), reachable=[], curl='down')

    world.run(_script('tiebreak'), seconds=3 * T_SF)

    assert world.stops() == [] and world.calls('curl') == [] and world.calls('ping') == []


@pytest.mark.parametrize('setting', ['force_quorum_on_failure', 'two_node_mode'])
def test_a_management_network_outage_stops_no_guest_of_a_quorate_cluster(tmp_path, setting):
    """Three votes with force_quorum_on_failure or two_node_mode: a tiebreak cluster.
    corosync runs on its own link and still counts every member; the management
    network is down for longer than T_SF, so no peer answers a ping and no PegaProx
    answers. The agent took the peers for lost by ICMP to their management addresses,
    which fail together with the way to PegaProx: every node stopped all of its
    guests at once. The agent of 7525fce asked pvecm before it fenced and stayed up."""
    m = _mgr(fence_strategy={'strategy': 'quorum', 'expected_votes': 3, 'has_qdevice': False,
                             'two_node_flag': False, 'detection_reason': 'detected'}, **{setting: True})
    m._ha_agent_members = lambda: [LEADER]
    plan = m._ha_agent_plan(detect=False)
    assert (plan['mode'], plan['strategy'], plan['minority_fences']) == ('tiebreak', 'quorum', True)
    world = World(tmp_path)
    world.set(quorate=True, votes=(3, 3), reachable=[], curl='down')

    log, _ = world.run(m._ha_render_fence_agent('pve1', plan, t_sf=T_SF, interval=INTERVAL), seconds=4 * T_SF)

    assert world.stops() == [], log
    assert 'ISOLATED' not in log and 'WARNING' not in log
    assert len(world.calls('corosync-quorumtool')) >= 3
    assert world.calls('curl') == [] and world.calls('ping') == []


@pytest.mark.parametrize('votes,cluster', [((2, 3), 3), ((3, 5), 5), ((2, 2), 2), ((3, 3), 0)],
                         ids=['one-of-three-gone', 'two-of-five-gone', 'both-of-two', 'votes-not-known'])
def test_tiebreak_a_majority_of_the_cluster_is_in_order_without_a_leader(world, votes, cluster):
    """More than half of the cluster's votes are present: this is the side that goes
    on, whoever answers. A cluster whose votes were not known at install time goes by
    what corosync expects."""
    world.set(quorate=True, votes=votes, curl='down')

    log, _ = world.run(_script('tiebreak', votes=cluster), seconds=3 * T_SF)

    assert world.stops() == [] and world.calls('curl') == [], log


@pytest.mark.parametrize('quorate', [True, False], ids=['quorate', 'not-quorate'])
def test_tiebreak_the_side_that_reaches_the_leader_stays_up(world, quorate):
    """A cluster of two votes that lost one: with corosync's two_node option the node
    is still quorate, without it not, and neither says which side of a split this is."""
    world.set(quorate=quorate, votes=(1, 2), reachable=[], curl='leader')

    log, _ = world.run(_script('tiebreak'), seconds=3 * T_SF)

    assert world.stops() == [], log
    assert 'a PegaProx leader answers - staying up' in log
    asked = world.calls('curl')
    assert asked and all(c.startswith(f'curl {LEADER}/api/ha/agent?cluster=c1&nonce=') for c in asked)
    # a fresh nonce every time
    assert len({c.split('nonce=')[1].split('&')[0] for c in asked}) == len(asked)


@pytest.mark.parametrize('answer', ['down', 'standby', 'forged', 'othernonce'])
def test_tiebreak_the_side_without_a_leader_fences_itself(world, answer):
    """Quorate, as either half of a two_node cluster is: quorum settles nothing here.
    An instance that is not the leader, an answer whose mac is not ours and one made
    for another nonce are all no leader."""
    world.set(quorate=True, votes=(1, 2), reachable=[], curl=answer)

    log, took = world.run(_script('tiebreak'), until=lambda: len(world.stops()) == 3)

    assert world.stops() == ALL_STOPPED, log
    assert took >= EARLIEST
    assert 'no PegaProx leader answers' in log


def test_with_three_votes_a_node_without_quorum_fences_itself_whatever_the_leader_says(world):
    """A cluster of three or more votes where quorum gets forced on failure. A majority
    can exist on the other side, and the leader recovers this node's guests from there:
    a leader that still answers this node must not keep them running. The counterproof
    is the not-quorate case of the two-vote cluster above, which stays up."""
    world.set(quorate=False, votes=(1, 3), reachable=['10.9.0.2'], curl='leader')

    log, took = world.run(_script('tiebreak', minority=True), until=lambda: len(world.stops()) == 3)

    assert world.stops() == ALL_STOPPED, log
    assert took >= EARLIEST and 'not quorate' in log
    assert world.calls('curl') == []


@pytest.mark.parametrize('cluster,votes,minority', [(3, (1, 1), True), (3, (1, 1), False), (2, (1, 1), False),
                                                    (5, (2, 2), True)],
                         ids=['one-of-three', 'one-of-three-unsafe-setup', 'one-of-two', 'two-of-five'])
def test_a_node_that_quorum_was_forced_on_is_in_order_without_a_leader(world, cluster, votes, minority):
    """After `pvecm expected 1` the node that is left is quorate with one vote of the
    cluster's three: no majority, so the agent asked for the leader. A PegaProx that
    was away for the fence delay (a restart, an update, a leader change) then cost the
    only node left every one of its guests. The agent before v2 never fenced a
    quorate node. Fewer expected votes than the cluster has are `pvecm expected` and
    nothing else; the counterproof is the two-vote cluster above, which corosync still
    expects two votes of and which fences without a leader."""
    world.set(quorate=True, votes=votes, reachable=[], curl='down')

    log, _ = world.run(_script('tiebreak', votes=cluster, minority=minority), seconds=4 * T_SF)

    assert world.stops() == [], log
    assert 'WARNING' not in log and 'ISOLATED' not in log
    assert world.calls('curl') == []


def test_the_node_of_an_existing_setup_keeps_its_guests_over_a_pegaprox_restart(tmp_path):
    """The same through the plan of a stored row: three nodes, quorum forced on
    failure, the switch derived on, v2 installed by the admin. Two nodes are down and
    PegaProx forced quorum on the third. No instance answers for longer than the
    fence delay."""
    m = _setup_from_stored(force_quorum_on_failure=True)
    assert m._ha_unsafe_two_node() is True
    world = World(tmp_path)
    world.set(quorate=True, votes=(1, 1), reachable=[], curl='down')

    log, _ = world.run(m._ha_render_fence_agent('pve1', m._ha_agent_plan(detect=False),
                                                t_sf=T_SF, interval=INTERVAL), seconds=4 * T_SF)

    assert world.stops() == [] and 'ISOLATED' not in log, log


# what `corosync-quorumtool -s` prints, as corosync 3.1 lays it out (PVE 8 and 9 both
# ship 3.1.x); `pvecm status` puts the cluster block in front of the same text
def _quorum_text(nodes, expected, total, quorum, quorate, flags, qdevice=False, pvecm=False):
    head = ('Cluster information\n-------------------\nName:             lab\nConfig Version:   7\n'
            'Transport:        knet\nSecure auth:      on\n\n') if pvecm else ''
    members = ''.join(f'0x0000000{i}          1 {"   A,V,NMW " if qdevice else ""}10.9.0.{i}'
                      f'{" (local)" if i == 1 else ""}\n' for i in range(1, nodes + 1))
    if qdevice and total > nodes:
        members += '0x00000000          1            Qdevice\n'
    return (f'{head}Quorum information\n------------------\nDate:             Fri Oct  2 10:00:00 2026\n'
            f'Quorum provider:  corosync_votequorum\nNodes:            {nodes}\nNode ID:          0x00000001\n'
            f'Ring ID:          1.2a\nQuorate:          {"Yes" if quorate else "No"}\n\n'
            f'Votequorum information\n----------------------\nExpected votes:   {expected}\n'
            f'Highest expected: {expected}\nTotal votes:      {total}\n'
            f'Quorum:           {quorum} {" " if quorate else "Activity blocked"}\nFlags:            {flags} \n\n'
            f'Membership information\n----------------------\n'
            f'    Nodeid      Votes {"   Qdevice " if qdevice else ""}Name\n{members}')


@pytest.mark.parametrize('tool', ['corosync-quorumtool', 'pvecm'])
@pytest.mark.parametrize('cluster,text,reads', [
    # three nodes, all there
    (3, dict(nodes=3, expected=3, total=3, quorum=2, quorate=True, flags='Quorate'),
     'quorate=0 total=3 expected=3 forced=no majority=yes'),
    # two of them gone and `pvecm expected 1` run on the third
    (3, dict(nodes=1, expected=1, total=1, quorum=1, quorate=True, flags='Quorate'),
     'quorate=0 total=1 expected=1 forced=yes majority=no'),
    # the same node before quorum was forced
    (3, dict(nodes=1, expected=3, total=1, quorum=2, quorate=False, flags=''),
     'quorate=1 total=1 expected=3 forced=no majority=no'),
    # two nodes and a qdevice: three votes
    (3, dict(nodes=2, expected=3, total=3, quorum=2, quorate=True, flags='Quorate Qdevice', qdevice=True),
     'quorate=0 total=3 expected=3 forced=no majority=yes'),
    # one node and the qdevice are a majority of them
    (3, dict(nodes=1, expected=3, total=2, quorum=2, quorate=True, flags='Quorate Qdevice', qdevice=True),
     'quorate=0 total=2 expected=3 forced=no majority=yes'),
    # the qdevice is gone too and quorum was forced
    (3, dict(nodes=1, expected=1, total=1, quorum=1, quorate=True, flags='Quorate Qdevice', qdevice=True),
     'quorate=0 total=1 expected=1 forced=yes majority=no'),
    # corosync's two_node with one node left: quorate, still two expected votes
    (2, dict(nodes=1, expected=2, total=1, quorum=1, quorate=True, flags='2Node Quorate WaitForAll'),
     'quorate=0 total=1 expected=2 forced=no majority=no'),
    # the votes were not known at install time: nothing counts as forced
    (0, dict(nodes=1, expected=1, total=1, quorum=1, quorate=True, flags='Quorate'),
     'quorate=0 total=1 expected=1 forced=no majority=yes'),
])
def test_the_votes_are_read_from_what_corosync_prints(tmp_path, tool, cluster, text, reads):
    """The functions of the script as rendered, without its loop, against the full
    output of either tool: the membership table, the "Highest expected" line and the
    qdevice column are in it and are not what is read."""
    world = World(tmp_path, without=('corosync-quorumtool',) if tool == 'pvecm' else ())
    (world.dir / 'status.txt').write_text(_quorum_text(pvecm=tool == 'pvecm', **text))
    fake = world.bin / tool
    fake.write_text(f'#!/bin/bash\ncat "$FAKE/status.txt"\n{"" if text["quorate"] else "exit 2"}\n')
    fake.chmod(0o755)
    functions = _script('tiebreak', votes=cluster).split('\nlog "PegaProx Self-Fence Agent v', 1)[0]
    probe = world.dir / 'probe.sh'
    probe.write_text(functions + '''
is_quorate; q=$?
forced=no; quorum_forced && forced=yes
majority=no; majority_present && majority=yes
echo "quorate=$q total=$TOTAL_VOTES expected=$EXPECTED_VOTES forced=$forced majority=$majority"
''')

    r = subprocess.run(['bash', str(probe)], capture_output=True, text=True, env=world.env)

    assert r.stdout.strip() == reads, r.stderr


def _setup_from_stored(votes=3, **stored):
    """The manager a start builds from a stored row, with corosync read as `votes`.
    A row from before the safety rules carries no unsafe_two_node_recovery."""
    m = _mgr()
    m._apply_ha_settings(dict(stored, agent_token=TOKEN))
    m.ha_config['fence_strategy'] = {'strategy': 'quorum', 'expected_votes': votes, 'has_qdevice': False,
                                     'two_node_flag': False, 'detection_reason': 'detected'}
    m._ha_agent_members = lambda: [LEADER]
    return m


@pytest.mark.parametrize('setting', ['force_quorum_on_failure', 'two_node_mode'])
def test_the_last_node_of_an_existing_force_quorum_setup_keeps_its_guests(tmp_path, setting):
    """Three nodes, quorum forced on failure, a setup from before the update (the unsafe
    switch is derived as on). Two nodes die. PegaProx reaches the survivor and forces
    quorum there once failure_threshold x 10 s + recovery_delay are over; the agent's
    fence delay is shorter. v2 stopped the survivor's own guests in between, with the
    leader answering all the time, and nothing started them again once the node was
    quorate. The agent before v2 kept them (manager reachable). On such a setup the
    leader breaks the tie for a node without quorum."""
    m = _setup_from_stored(**{setting: True})
    assert m._ha_unsafe_two_node() is True
    plan = m._ha_agent_plan(detect=False)
    assert (plan['mode'], plan['strategy'], plan['minority_fences']) == ('tiebreak', 'quorum', False)
    # the shipped numbers: the agent's delay is over before quorum is forced
    timing = m._ha_fence_timing()
    assert timing['fence_delay'] < timing['earliest_recovery']

    world = World(tmp_path)
    world.set(quorate=False, votes=(1, 3), reachable=[], curl='leader')
    script = m._ha_render_fence_agent('pve1', plan, t_sf=T_SF, interval=INTERVAL)
    began, forced = time.monotonic(), []

    def step():
        if not forced and time.monotonic() - began > 3 * T_SF:
            world.set(quorate=True, votes=(1, 1))       # PegaProx ran `pvecm expected 1`
            forced.append(len(world.stops()))
        return False

    log, _ = world.run(script, until=step, seconds=6 * T_SF)

    assert forced == [0], log
    assert world.stops() == [], log
    assert (world.dir / 'vms').read_text().split() == ['100', 'running', '101', 'running']
    assert 'a PegaProx leader answers - staying up' in log and 'ISOLATED' not in log
    assert world.calls('curl')


def test_that_node_fences_itself_when_no_leader_answers_as_the_old_agent_did(tmp_path):
    """The counterproof: the same setup and the same node, cut off from PegaProx too.
    That is the isolated side, and it stops its guests after the fence delay."""
    m = _setup_from_stored(force_quorum_on_failure=True)
    world = World(tmp_path)
    world.set(quorate=False, votes=(1, 3), reachable=[], curl='down')

    log, took = world.run(m._ha_render_fence_agent('pve1', m._ha_agent_plan(detect=False),
                                                   t_sf=T_SF, interval=INTERVAL),
                          until=lambda: len(world.stops()) == 3)

    assert world.stops() == ALL_STOPPED, log
    assert took >= EARLIEST and 'no PegaProx leader answers' in log


IPMI = {n: {'type': 'ipmi', 'host': f'10.9.1.{i}', 'user': 'ADMIN', 'password': 'x'}
        for i, n in enumerate(('pve1', 'pve2', 'pve3'), 1)}


def _fenced(world):
    """The agent stopped every guest and waits."""
    return 'Waiting for recovery' in world.out() and 'running' not in world.guests()


def _by_pegaprox(m, world):
    """PegaProx forces quorum on the node: _ha_try_force_quorum as it is, with what it
    sends run on the node. It knows the node to run the v2 agent."""
    m.config = types.SimpleNamespace(name='lab', user='root@pam', pass_='pw', ssh_key='')
    m.ha_config['fence_agent_versions'] = {'pve1': 2}
    m._ha_get_node_ip = lambda node: '10.9.0.1'
    m._ssh_run_command = lambda host, user, cmd, *a, **kw: world.sh(cmd) == 0
    m._ssh_run_command_with_password = lambda host, user, cmd, password, **kw: world.sh(cmd) == 0
    return m._ha_try_force_quorum('pve1')


@pytest.mark.parametrize('setting', ['force_quorum_on_failure', 'two_node_mode'])
def test_under_the_rules_the_last_node_keeps_its_own_guests_down_when_quorum_is_forced(tmp_path, setting):
    """Three nodes, quorum forced on failure, IPMI fences, the unsafe switch off: the
    setup the HA settings recommend. Two nodes die. The node that is left has no
    quorum and stops its own guests after the fence delay (MINORITY_FENCES=1, which
    the recovery from a quorate side relies on). PegaProx powers the two off, reads
    that back and forces quorum, which comes later than the fence delay.

    The node is in order again and starts nothing. A development build of the agent
    started what it had stopped here, and every way it had of telling this case from
    the others let a guest run on two nodes in some order of events. The guests of
    the dead nodes come back through the recovery. This node's own stay down until
    an admin starts them, and the HA status says so. 102 was down before the fence
    and is not named."""
    m = _setup_from_stored(**{setting: True, 'unsafe_two_node_recovery': False, 'fencing': IPMI})
    assert m._ha_unsafe_two_node() is False and m._ha_has_verifiable_fence()
    plan = m._ha_agent_plan(detect=False)
    assert (plan['mode'], plan['minority_fences']) == ('tiebreak', True)
    timing = m._ha_fence_timing()
    assert timing['fence_delay'] < timing['earliest_recovery']
    script = m._ha_render_fence_agent('pve1', plan, t_sf=T_SF, interval=INTERVAL)
    world = World(tmp_path)
    world.set(quorate=False, votes=(1, 3), reachable=[], curl='down',
              vms=['100 running', '101 running', '102 stopped'])
    seen = {}

    def step():
        out = world.out()
        if 'forced' not in seen and 'Waiting for recovery' in out:
            seen['fenced'] = world.guests()
            seen['forced'] = _by_pegaprox(m, world)
            seen['at'] = time.monotonic()
        # and a good many passes more
        return 'forced' in seen and NOTHING_STARTED in out and time.monotonic() - seen['at'] > 15 * INTERVAL

    log, _ = world.run(script, until=step, seconds=10)

    assert seen.get('forced') is True, log
    assert seen['fenced'] == ['100', 'stopped', '101', 'stopped', '102', 'stopped', '200', 'stopped']
    assert world.calls('pvecm expected') == ['pvecm expected 1']
    assert 'In order again, resuming' in log
    assert world.starts() == [], log
    assert world.guests() == seen['fenced']
    assert log.count(STOPPED_LINE) == 1 and log.count(NOTHING_STARTED) == 1
    assert world.left_behind() == {}
    assert "the last node's own guests stay stopped until an admin starts them" in m.FENCED_SURVIVOR_NOTE


# --- a node that fenced itself starts nothing ---------------------------------------------------

def _recovered_elsewhere(tmp_path):
    """The other side of the split, which holds the majority: once the isolated node's
    agent had its time, the PegaProx recovery moves the configs there and starts the
    guests. The isolated node's /etc/pve is the copy it had when it left."""
    side = tmp_path / 'pve2'
    side.mkdir()
    (side / 'vms').write_text('100 running\n101 running\n')
    (side / 'cts').write_text('200 running\n')
    return side


def _plan_of(kind):
    if kind == 'quorum':
        m = _setup_from_stored()                    # three votes, nothing forces quorum
    else:
        # the setup the HA settings recommend: quorum forced on failure, IPMI fences, the switch off
        m = _setup_from_stored(force_quorum_on_failure=True, unsafe_two_node_recovery=False, fencing=IPMI)
    return m, m._ha_agent_plan(detect=False)


@pytest.mark.parametrize('kind', ['quorum', 'tiebreak-under-the-rules'])
def test_quorum_forced_by_hand_on_a_node_that_is_cut_off_starts_nothing(tmp_path, kind):
    """Three nodes. pve1 loses its corosync link; pve2 and pve3 hold the majority.
    pve1's agent stops its guests after the fence delay, as the recovery counts on,
    and PegaProx recovers them to pve2.

    Then an admin runs `pvecm expected 1` on pve1 to get at its /etc/pve, the usual
    way to work on a node that fell out of a cluster. pve1 is quorate with the one
    vote it had. A development build of the agent took that for "PegaProx forced
    quorum here" and started every guest it had stopped: pve1's /etc/pve is its own
    last copy and still has the configs, so each guest ran on pve1 and on pve2. Where
    the leader is asked it answers (the management network is fine), and its answer
    says nothing about who lowered the expected votes."""
    m, plan = _plan_of(kind)
    assert plan['mode'] == ('quorum' if kind == 'quorum' else 'tiebreak') and plan['minority_fences'] is True
    world = World(tmp_path)
    world.set(quorate=False, votes=(1, 3), reachable=[], curl='leader')
    seen = {}

    def step():
        out = world.out()
        if 'fenced' not in seen and _fenced(world):
            seen['fenced'] = time.monotonic()
            seen['side'] = _recovered_elsewhere(tmp_path)
        elif 'fenced' in seen and 'by_hand' not in seen and time.monotonic() - seen['fenced'] > 10 * INTERVAL:
            assert world.sh('pvecm expected 1') == 0            # the admin
            seen['by_hand'] = time.monotonic()
        return 'by_hand' in seen and NOTHING_STARTED in out and time.monotonic() - seen['by_hand'] > 20 * INTERVAL

    log, _ = world.run(m._ha_render_fence_agent('pve1', plan, t_sf=T_SF, interval=INTERVAL),
                       until=step, seconds=14)

    assert 'by_hand' in seen and 'In order again, resuming' in log, log
    assert world.starts() == [], log
    assert world.guests() == ALL_DOWN
    assert log.count(STOPPED_LINE) == 1 and log.count(NOTHING_STARTED) == 1
    side = seen['side']
    assert (side / 'vms').read_text().split() + (side / 'cts').read_text().split() == ALL_RUNNING


@pytest.mark.parametrize('left', [False, True], ids=['nothing-under-run', 'files-left-under-run'])
@pytest.mark.parametrize('agent', ['runs-on', 'restarted-while-fenced', 'away-when-it-happens'])
@pytest.mark.parametrize('how', ['forced-by-pegaprox', 'forced-by-hand', 'the-others-are-back'])
def test_a_node_that_fenced_itself_starts_nothing_however_it_comes_back(tmp_path, how, agent, left):
    """The node is in order again because PegaProx forced quorum on it, because an
    admin did, or because the other nodes are back. The agent ran all the while, was
    restarted while the node was fenced (a new leader brings the script up to date,
    systemd restarts one that died), or was away when it happened.

    With and without the files a development build kept under /run, its go-ahead
    written at the very moment the node comes back: that build started the guests of
    the list then.

    In every one of them no guest is started, the guests are as the fence left them,
    and the files are where they were: nothing reads them."""
    m, plan = _plan_of('tiebreak-under-the-rules')
    script = m._ha_render_fence_agent('pve1', plan, t_sf=T_SF, interval=INTERVAL)
    world = World(tmp_path)
    world.set(quorate=False, votes=(1, 3), curl='leader')
    if left:
        world.leave_behind()
    seen = {}

    def back():
        if left:
            world.leave_behind()                    # the go-ahead is of this moment
        if how == 'forced-by-pegaprox':
            assert _by_pegaprox(m, world) is True
        elif how == 'forced-by-hand':
            assert world.sh('pvecm expected 1') == 0
        else:
            world.set(quorate=True, votes=(3, 3))
        seen['back'] = time.monotonic()

    def step():
        if 'back' not in seen and _fenced(world):
            back()
        # a good many passes after it, and the agent has said that it is in order
        return ('back' in seen and time.monotonic() - seen['back'] > 15 * INTERVAL
                and (agent == 'away-when-it-happens' or NOTHING_STARTED in world.out()))

    if agent == 'runs-on':
        log, _ = world.run(script, until=step, seconds=10)
    else:
        first, _ = world.run(script, until=lambda: _fenced(world), seconds=10)
        assert first.count(STOPPED_LINE) == 1, first
        if agent == 'away-when-it-happens':
            back()
        log, _ = world.run(script, until=step, seconds=10)

    assert 'back' in seen, log
    assert world.starts() == [], log
    assert world.guests() == ALL_DOWN
    assert world.stops() == ALL_STOPPED
    if agent == 'away-when-it-happens':
        # it came up on a node in order: nothing to do, and nothing to say
        assert 'ISOLATED' not in log and NOTHING_STARTED not in log, log
    else:
        assert log.count(NOTHING_STARTED) == 1, log
    kept = world.left_behind()
    assert set(kept) == ({LEFT_BEHIND + end for end in ('', '.votes', '.out', '.go')} if left else set())
    assert not left or kept[LEFT_BEHIND] == 'qm 100\nqm 101\npct 200\n'


def test_what_the_admin_left_off_stays_off_when_pegaprox_is_back(tmp_path):
    """Everything is down but pve1, PegaProx included (its VM was on a dead node). pve1
    fenced itself. The admin forces quorum by hand and starts what has to run: 100
    and 200. 101 he leaves off. A development build kept a list of what the fence had
    stopped and went by it when a PegaProx leader answered again, however much later:
    it started 101. Nothing is kept now, and a leader that answers starts nothing."""
    m, plan = _plan_of('tiebreak-under-the-rules')
    world = World(tmp_path)
    world.set(quorate=False, votes=(1, 3), reachable=[], curl='down')
    seen = {}

    def step():
        out = world.out()
        if 'by_hand' not in seen and _fenced(world):
            assert world.sh('pvecm expected 1') == 0            # the admin
            seen['by_hand'] = True
        elif 'by_hand' in seen and 'admin' not in seen and NOTHING_STARTED in out:
            world.set(vms=['100 running', '101 stopped'], cts=['200 running'])     # qm start 100, pct start 200
            seen['admin'] = time.monotonic()
        elif 'admin' in seen and 'leader' not in seen and time.monotonic() - seen['admin'] > 15 * INTERVAL:
            world.set(curl='leader')                            # PegaProx is back
            seen['leader'] = time.monotonic()
        return 'leader' in seen and time.monotonic() - seen['leader'] > 15 * INTERVAL

    log, _ = world.run(m._ha_render_fence_agent('pve1', plan, t_sf=T_SF, interval=INTERVAL),
                       until=step, seconds=16)

    assert 'leader' in seen, log
    assert world.starts() == [], log
    assert world.guests() == ['100', 'running', '101', 'stopped', '200', 'running']
    assert world.stops() == ALL_STOPPED                     # and what the admin started is left alone
    assert log.count(NOTHING_STARTED) == 1 and log.count('ISOLATED! Self-fencing') == 1


def test_a_node_the_leader_holds_up_starts_nothing_and_nothing_once_quorum_is_forced(world):
    """Two votes, one left, and the leader answers again: the node is held up without
    quorum, which is in order for the agent. It starts nothing then, and nothing when
    PegaProx forces quorum on it once the other node is fenced."""
    world.set(quorate=False, votes=(1, 2), curl='down')
    m = _mgr()
    seen = {}

    def step():
        out = world.out()
        if 'leader' not in seen and _fenced(world):
            world.set(curl='leader')
            seen['leader'] = True
        elif 'leader' in seen and 'forced' not in seen and NOTHING_STARTED in out:
            seen.setdefault('since', time.monotonic())
            if time.monotonic() - seen['since'] > 8 * INTERVAL:
                seen['held_up'] = (world.starts(), world.guests())
                seen['forced'] = _by_pegaprox(m, world)
                seen['at'] = time.monotonic()
        return 'forced' in seen and time.monotonic() - seen['at'] > 12 * INTERVAL

    log, _ = world.run(_script('tiebreak'), until=step, seconds=12)

    assert seen.get('forced') is True, log
    assert 'a PegaProx leader answers - staying up' in log
    assert seen['held_up'] == ([], ALL_DOWN)
    assert world.starts() == [] and world.guests() == ALL_DOWN, log
    assert log.count('ISOLATED! Self-fencing') == 1 and log.count(NOTHING_STARTED) == 1


def test_one_of_two_nodes_that_corosync_calls_quorate_never_starts_what_it_stopped(world):
    """corosync's two_node: either side of a split is quorate. The node fenced itself
    while no leader answered, and PegaProx may have recovered its guests to the other
    node since. A leader that answers again does not say the split is over: the node
    still sees the configs where they were, and a start would run the guests twice.

    Everything looked at here is written before the line the run waits for, or is
    never written at all."""
    world.set(quorate=True, votes=(1, 2), curl='down')
    seen = {}

    def step():
        out = world.out()
        if 'leader' not in seen and _fenced(world):
            world.set(curl='leader')
            seen['leader'] = time.monotonic()
        return 'leader' in seen and NOTHING_STARTED in out and time.monotonic() - seen['leader'] > 10 * INTERVAL

    log, _ = world.run(_script('tiebreak'), until=step, seconds=12)

    assert 'In order again, resuming' in log, log
    assert world.starts() == [] and world.stops() == ALL_STOPPED
    assert world.guests() == ALL_DOWN
    assert log.count(STOPPED_LINE) == 1 and log.count(NOTHING_STARTED) == 1
    assert world.left_behind() == {}


LINES = ['qm 100', 'pct 200', 'qm 100; touch PWNED', 'qm $(touch PWNED)', 'qm `touch PWNED`', 'qm 100 --skiplock 1',
         'rm -rf /', 'reboot 1', 'qm ../../100', 'pct 200 ; reboot', 'qm 100&&touch PWNED', '-n', '']


@pytest.mark.parametrize('go', [None, '$(touch PWNED) 0.00\n', '1; touch PWNED\n'])
def test_whatever_the_files_left_under_run_hold_nothing_of_it_reaches_a_command(world, tmp_path, go):
    """The list a development build kept went to qm and pct as root, line by line, and
    its go-ahead into shell arithmetic. Nothing reads either now: on a node in order
    no qm and no pct is run at all."""
    world.leave_behind(listed='\n'.join(LINES) + '\n', go=go)
    world.set(quorate=True, votes=(1, 1), vms=['100 stopped', '101 stopped'], cts=['200 stopped'])

    log, _ = world.run(_script('quorum'), seconds=3 * T_SF)

    assert len(world.calls('corosync-quorumtool')) >= 3, log
    assert [c for c in world.calls() if c.startswith(('qm', 'pct'))] == [], log
    assert not list(tmp_path.rglob('PWNED'))
    assert len(world.left_behind()) == 4


def test_the_agent_keeps_no_file_about_the_guests_it_stops_and_has_one_start_in_it(world):
    """What a fence stopped is in the log and nowhere else. The one start left in the
    script is the PegaProx VM's, which is no guest the list was about: only with a
    PegaProx VM configured, on a node in order, when no leader answers."""
    world.set(quorate=False, votes=(1, 3))
    script = _script('tiebreak', minority=True, vmid='900')

    log, _ = world.run(script, until=lambda: _fenced(world))

    assert log.count(STOPPED_LINE) == 1, log
    assert [p.name for p in world.dir.iterdir() if 'pegaprox' in p.name] == []
    assert '/run' not in script and LEFT_BEHIND not in script
    starts = [line.strip() for line in script.splitlines()
              if re.search(r'\bstart\b', line) and not line.lstrip().startswith(('#', 'log '))]
    assert starts == ['qm start $PEGAPROX_VMID 2>&1 | tee -a "$LOG_FILE" 2>/dev/null']


@pytest.mark.parametrize('leader', ['answers', 'is-silent'])
def test_the_pegaprox_vm_is_the_one_guest_a_node_that_fenced_itself_may_start(world, leader):
    """The PegaProx VM watch is from before the fence and was not taken out with the
    restart of the guests: on a node in order, with a PegaProx VM configured, while
    no leader answers. A node that fenced itself and is in order again is such a
    node, and the log says so in the line about what is started. 100 stays down
    either way."""
    world.set(quorate=False, votes=(1, 3), curl='down', vms=['100 running', '900 running'], cts=[])
    # a start shows as soon as it comes; that none comes takes a few fence delays to see
    patience = 3 * T_SF + 1 if leader == 'answers' else 10
    seen = {}

    def step():
        if 'back' not in seen and _fenced(world):
            world.set(quorate=True, votes=(3, 3), curl='leader' if leader == 'answers' else 'down')
            seen['back'] = time.monotonic()
        return 'back' in seen and (bool(world.starts()) or time.monotonic() - seen['back'] > patience)

    log, _ = world.run(_script('quorum', vmid='900', members=[LEADER]), until=step, seconds=14)

    assert 'back' in seen, log
    assert log.count('Stopped by this fence: qm 100 900 - start them by hand') == 1
    assert log.count('Nothing is started automatically (but the PegaProx VM 900, while no PegaProx leader '
                     'answers): the guests this fence stopped stay down') == 1, log
    assert world.starts() == ([] if leader == 'answers' else ['qm start 900']), log
    assert world.guests()[:2] == ['100', 'stopped']


@pytest.mark.parametrize('kind', ['quorum', 'tiebreak-under-the-rules'])
def test_a_quorum_forced_by_hand_does_not_start_the_pegaprox_vm(tmp_path, kind):
    """The node is still cut off, no PegaProx instance answers it, and an admin runs
    `pvecm expected 1` on it. Its /etc/pve is the copy from before the split: the
    PegaProx VM may run on the other side by now. The watch started it one fence delay
    later. On a quorum that was forced it starts nothing, and the log line about what
    is started no longer names the VM."""
    m, plan = _plan_of(kind)
    plan = dict(plan, vmid='900', members=[LEADER])
    world = World(tmp_path)
    world.set(quorate=False, votes=(1, 3), reachable=[], curl='down', vms=['100 running', '900 running'], cts=[])
    seen = {}

    def step():
        if 'by_hand' not in seen and _fenced(world):
            assert world.sh('pvecm expected 1') == 0            # the admin
            seen['by_hand'] = time.monotonic()
        return 'by_hand' in seen and (bool(world.starts()) or time.monotonic() - seen['by_hand'] > 5 * T_SF + 1)

    log, _ = world.run(m._ha_render_fence_agent('pve1', plan, t_sf=T_SF, interval=INTERVAL),
                       until=step, seconds=14)

    assert 'by_hand' in seen and 'In order again, resuming' in log, log
    assert world.starts() == [] and 'qm unlock 900' not in world.calls(), log
    assert world.guests() == ['100', 'stopped', '900', 'stopped']
    assert log.count('Nothing is started automatically: the guests this fence stopped stay down') == 1, log
    assert 'PEGAPROX DOWN' not in log


# --- which guests run: the status column -----------------------------------------------------

def test_a_guest_runs_by_its_status_column_and_not_by_its_name(world):
    """stop_all_vms and running_guests took every line of `qm list` and `pct list`
    that had "running" anywhere in it, the NAME column included. A stopped VM called
    long-running-jobs was "stopped" on every pass of the fence.

    101 has no name: qm lists it as "VM 101", two words, so the status is not the
    third word of its line. It is running and has to be stopped like the others."""
    world.set(quorate=False, votes=(1, 3),
              vms=['100 running web', '101 running', '102 stopped long-running-jobs', '103 stopped running',
                   '104 running stopped'],
              cts=['200 running', '201 stopped running-ct'])
    seen = {}

    def step():
        if 'Waiting for recovery' in world.out():
            seen.setdefault('since', time.monotonic())
        return 'since' in seen and time.monotonic() - seen['since'] > 8 * INTERVAL

    log, _ = world.run(_script('quorum'), until=step, seconds=12)

    assert 'since' in seen, log
    # nothing was "running" on the passes after the fence
    assert log.count('STOPPING ALL VMs AND CONTAINERS') == 1
    assert world.stops() == ['pct stop 200 --timeout 30', 'qm stop 100 --timeout 30', 'qm stop 101 --timeout 30',
                             'qm stop 104 --timeout 30']
    assert log.count('Stopped by this fence: qm 100 101 104, pct 200 - start them by hand') == 1
    assert (world.dir / 'vms').read_text().splitlines() == [
        '100 stopped web', '101 stopped', '102 stopped long-running-jobs', '103 stopped running',
        '104 stopped stopped']
    assert (world.dir / 'cts').read_text().splitlines() == ['200 stopped', '201 stopped running-ct']


def test_a_line_that_is_no_guest_does_not_end_the_reading_of_the_list(world):
    """The status is counted from the end of the line. A line that is too short for
    that (an empty one, a warning the tool printed) must not end awk with the guests
    behind it unread."""
    qm = world.bin / 'qm'
    qm.write_text(qm.read_text().replace(
        '    list) ', "    list) echo; echo running; echo 'x running'; echo '7 running running running'\n"
                      "          echo 'running running running running running running'\n          ", 1))
    world.set(quorate=False, votes=(1, 3))

    log, _ = world.run(_script('quorum'), until=lambda: _fenced(world))

    assert world.stops() == ALL_STOPPED, log
    assert log.count(STOPPED_LINE) == 1


@pytest.mark.parametrize('vms,cts,line', [
    (['100 running'], [], 'Stopped by this fence: qm 100 - start them by hand'),
    ([], ['200 running', '201 running'], 'Stopped by this fence: pct 200 201 - start them by hand'),
    (['100 stopped'], ['200 stopped'], None),
])
def test_the_line_names_what_the_fence_stopped_and_nothing_else(world, vms, cts, line):
    """VMs, containers, or neither: a fence that found nothing running names nothing."""
    world.set(quorate=False, votes=(1, 3), vms=vms, cts=cts)

    log, _ = world.run(_script('quorum'), until=lambda: 'Waiting for recovery' in world.out())

    assert 'ISOLATED! Self-fencing' in log
    if line:
        assert log.count(line) == 1, log
    assert log.count('Stopped by this fence') == (1 if line else 0), log


@pytest.mark.parametrize('stored,mode,minority', [
    ({'force_quorum_on_failure': True}, 'tiebreak', False),          # before the rules: the switch derived on
    ({'two_node_mode': True}, 'tiebreak', False),
    ({'two_node_mode': True, 'unsafe_two_node_recovery': True}, 'tiebreak', False),
    # under the rules quorum is forced only after a fence that was read back, and a
    # node without quorum is the minority side: it fences itself
    ({'force_quorum_on_failure': True, 'unsafe_two_node_recovery': False}, 'tiebreak', True),
    ({'two_node_mode': True, 'unsafe_two_node_recovery': False}, 'tiebreak', True),
    # nothing forces quorum: quorum first, whatever the switch says
    ({'unsafe_two_node_recovery': True}, 'quorum', True),
    ({}, 'quorum', True),
])
def test_quorum_first_stays_where_nothing_forces_quorum_without_a_fence(stored, mode, minority):
    m = _setup_from_stored(**stored)

    plan = m._ha_agent_plan(detect=False)

    assert (plan['mode'], plan['minority_fences']) == (mode, minority)
    assert f'MINORITY_FENCES="{1 if minority else 0}"' in m._ha_render_fence_agent('pve1', plan)


def test_tiebreak_every_instance_is_asked_and_one_leader_is_enough(world):
    world.set(quorate=True, votes=(1, 2), reachable=[], curl='leader')
    members = ['https://10.9.0.4:5000', LEADER, 'https://10.9.0.6:5000']

    world.run(_script('tiebreak', members=members), seconds=2 * T_SF)

    asked = {c.split('/api/')[0].split(' ')[1] for c in world.calls('curl')}
    assert asked == set(members) and world.stops() == []


def test_tiebreak_a_question_under_the_wrong_token_gets_no_leader(world):
    """The stand-in answers only a question the token signs, as the route does. An
    agent that signed with anything else would be left without a leader."""
    world.set(quorate=True, votes=(1, 2), reachable=[], curl='leader')
    (world.dir / 'token').write_text('cd' * 32)

    log, _ = world.run(_script('tiebreak'), until=lambda: len(world.stops()) == 3)

    assert world.stops() == ALL_STOPPED, log


def test_the_agent_token_is_on_no_command_line(tmp_path):
    """The key of the leader question went to `openssl dgst -hmac <key>`: an argument,
    and /proc/<pid>/cmdline shows it to every local user on the node, twice per
    instance and pass while the node asks. The IPMI password left the argv for the
    same reason (_ha_fence_node). It goes to perl in the environment now, and the
    leader is heard as before."""
    world = World(tmp_path)
    real = {}
    for tool in ('openssl', 'perl'):
        real[tool] = shutil.which(tool)
        assert real[tool], f'{tool} is needed for this test'
        wrapper = world.bin / tool
        wrapper.write_text(f'#!/bin/bash\necho "{tool} $*" >> "$FAKE/calls"\nexec {real[tool]} "$@"\n')
        wrapper.chmod(0o755)
    # the curl stand-in signs with openssl itself: it gets the real one, off the record
    (world.bin / 'curl').write_text(FAKES['curl'].replace('openssl dgst', f"{real['openssl']} dgst"))
    world.set(quorate=True, votes=(1, 2), reachable=[], curl='leader')

    log, _ = world.run(_script('tiebreak'), until=lambda: 'staying up' in (world.dir / 'agent.out').read_text(),
                       seconds=5)

    assert 'a PegaProx leader answers - staying up' in log, log
    assert world.calls('perl'), 'the question was signed'
    assert not [c for c in world.calls() if TOKEN in c]


def test_an_agent_that_cannot_sign_says_so(tmp_path):
    world = World(tmp_path)
    (world.bin / 'perl').write_text('#!/bin/bash\nexit 127\n')
    (world.bin / 'perl').chmod(0o755)
    world.set(quorate=True, votes=(2, 2))

    log, _ = world.run(_script('tiebreak'), seconds=T_SF)

    assert 'cannot sign the leader question' in log
    # counterproof: with perl there is nothing to say
    (tmp_path / 'again').mkdir()
    assert 'cannot sign' not in World(tmp_path / 'again').run(_script('tiebreak'), seconds=T_SF)[0]


def test_tiebreak_wait_strategy_keeps_the_guests(world):
    world.set(quorate=False, votes=(1, 2), reachable=[], curl='down')

    log, _ = world.run(_script('tiebreak', strategy='wait'),
                       until=lambda: 'Keeping VMs running' in (world.dir / 'agent.out').read_text())

    assert 'FENCE_STRATEGY=wait' in log and world.stops() == []


# --- the PegaProx VM (manual mode) -----------------------------------------------------

def test_the_pegaprox_vm_is_started_when_no_leader_answers_and_the_cluster_is_fine(world):
    world.set(quorate=True, reachable=['10.9.0.2'], curl='down', vms=['100 running', '900 stopped'])

    log, took = world.run(_script('quorum', vmid='900'), until=lambda: bool(world.calls('qm start')))

    assert world.calls('qm start') == ['qm start 900'], log
    assert took >= EARLIEST and world.stops() == []


def test_starting_the_pegaprox_vm_does_not_take_the_eyes_off_quorum(world):
    """v1 slept 30 s after the start to see whether the manager came back. A node that
    loses quorum in that time has T_SF to stop its guests, not T_SF plus the nap."""
    world.set(quorate=True, reachable=['10.9.0.2'], curl='down', vms=['100 running', '900 stopped'])
    state = {}

    def step():
        if 'started' not in state and world.calls('qm start'):
            state['started'] = time.monotonic()
            world.set(quorate=False)
        return bool(world.calls('qm stop 100'))

    log, _ = world.run(_script('quorum', vmid='900'), until=step, seconds=3 * T_SF + 4)

    assert world.calls('qm stop 100'), log
    assert time.monotonic() - state['started'] < T_SF + 3


@pytest.mark.parametrize('case', ['leader-answers', 'no-vm-configured', 'not-quorate'])
def test_the_pegaprox_vm_is_left_alone_otherwise(world, case):
    world.set(quorate=case != 'not-quorate', reachable=['10.9.0.2'],
              curl='leader' if case == 'leader-answers' else 'down', vms=['100 running', '900 stopped'])
    script = _script('quorum', vmid='' if case == 'no-vm-configured' else '900',
                     members=[LEADER])

    world.run(script, seconds=3 * T_SF)

    assert world.calls('qm start') == []
    # and a node that lost quorum fences instead, whatever the VM setting says
    assert (world.stops() != []) == (case == 'not-quorate')


def test_the_agent_and_the_route_speak_the_same_question(world, tmp_path):
    """The real route answers the agent: curl here hands the query to
    pegaprox.api.ha.agent_leader_check in a request context, and the agent takes its
    answer as a leader. The other tests use a second, independent implementation."""
    bridge = tmp_path / 'bridge.py'
    bridge.write_text(f'''
import sys, types
from urllib.parse import urlsplit
sys.path.insert(0, {str(os.getcwd())!r})
import flask
import pegaprox.globals as g
from pegaprox.core import ha
import pegaprox.api.ha as ha_api
ha.STATE_FILE = {str(tmp_path / 'no_state.json')!r}
g.cluster_managers['c1'] = types.SimpleNamespace(ha_config={{'agent_token': {TOKEN!r}}})
url = urlsplit(sys.argv[-1])
app = flask.Flask('bridge')
with app.test_request_context(url.path + '?' + url.query):
    resp = ha_api.agent_leader_check()
    sys.stdout.write(resp.get_data(as_text=True))
''')
    curl = world.bin / 'curl'
    curl.write_text(f'#!/bin/bash\necho "curl ${{@: -1}}" >> "$FAKE/calls"\n'
                    f'exec {sys.executable} {bridge} "${{@: -1}}"\n')
    world.set(quorate=True, votes=(1, 2), reachable=[])

    log, _ = world.run(_script('tiebreak', t_sf=30, interval=0.2),
                       until=lambda: 'staying up' in (world.dir / 'agent.out').read_text(), seconds=40)

    assert 'a PegaProx leader answers - staying up' in log, log
    assert world.stops() == []


# --- the route ------------------------------------------------------------------------

def _mac(token, text):
    return hmac.new(token.encode(), text.encode(), 'sha256').hexdigest()


def _ask(api, cluster='c1', nonce='0f' * 16, token=TOKEN, sig=None):
    sig = sig if sig is not None else _mac(token, f'pegaprox-agent ask {cluster} {nonce}')
    return api.anon().get(f'/api/ha/agent?cluster={cluster}&nonce={nonce}&sig={sig}')


@pytest.fixture
def agent_api(api, tmp_path, monkeypatch):
    monkeypatch.setattr(ha, 'STATE_FILE', str(tmp_path / 'ha_state.json'))
    ha.reset_for_tests()
    api.set_manager('c1', types.SimpleNamespace(ha_config={'agent_token': TOKEN}))
    yield api
    ha.reset_for_tests()


def _be(role, epoch=4):
    import json
    with open(ha.STATE_FILE, 'w') as fh:
        json.dump({'role': role, 'epoch': epoch, 'instance_id': 'a' * 32, 'interval': 30,
                   'peer': None, 'pairing': None, 'sync': {}}, fh)
    ha.reset_for_tests()


def test_the_acting_instance_answers_leader_with_a_mac_over_the_nonce(agent_api):
    _be('active', epoch=4)
    nonce = '1e' * 16

    r = _ask(agent_api, nonce=nonce)

    assert r.status_code == 200 and r.mimetype == 'text/plain'
    word, epoch, mac = r.get_data(as_text=True).split()
    assert (word, epoch) == ('leader', '4')
    assert mac == _mac(TOKEN, f'pegaprox-agent leader c1 {nonce} 4')
    assert TOKEN not in r.get_data(as_text=True)
    # another nonce, another mac: an answer cannot be kept for later
    assert _ask(agent_api, nonce='2e' * 16).get_data(as_text=True).split()[2] != mac


def test_a_standalone_instance_leads_and_a_standby_does_not(agent_api):
    assert _ask(agent_api).get_data(as_text=True).startswith('leader 0 ')
    _be('standby')
    assert _ask(agent_api).get_data(as_text=True) == 'standby\n'


@pytest.mark.parametrize('case', ['wrong-token', 'no-sig', 'unknown-cluster', 'cluster-without-token',
                                  'signed-with-the-stand-in-key'])
def test_a_question_the_token_does_not_sign_learns_nothing(agent_api, case):
    """Counterproof to the leader answer above: the same instance, the same moment."""
    _be('active')
    agent_api.set_manager('c2', types.SimpleNamespace(ha_config={}))
    if case == 'wrong-token':
        r = _ask(agent_api, token='cd' * 32)
    elif case == 'no-sig':
        r = _ask(agent_api, sig='0' * 64)
    elif case == 'unknown-cluster':
        r = _ask(agent_api, cluster='nope')
    elif case == 'signed-with-the-stand-in-key':
        # a cluster without a token is checked against a fixed key, for the timing
        # alone: a question signed with that key is still nobody's
        r = _ask(agent_api, cluster='c2', token='0' * 64)
    else:
        r = _ask(agent_api, cluster='c2', token='')

    assert r.status_code == 403
    assert 'leader' not in r.get_data(as_text=True) and 'standby' not in r.get_data(as_text=True)


@pytest.mark.parametrize('query', ['', '?cluster=c1', '?cluster=c1&nonce=zz&sig=' + '0' * 64,
                                   '?cluster=c1&nonce=' + '0f' * 16 + '&sig=short',
                                   '?cluster=c%201&nonce=' + '0f' * 16 + '&sig=' + '0' * 64])
def test_a_question_without_a_shape_is_a_400(agent_api, query):
    assert agent_api.anon().get('/api/ha/agent' + query).status_code == 400


# --- names: one script and one unit per agent -----------------------------------------------

V1_FENCE = '#!/bin/bash\n# PegaProx Self-Fence Agent\nMANAGER_IP="10.0.0.9"\nwhile true; do sleep 5; done\n'
# the unit 1.2.0 wrote next to it
V1_UNIT = '''[Unit]
Description=PegaProx Self-Fence Agent
After=network.target pve-cluster.service

[Service]
Type=simple
ExecStart=/usr/local/bin/pegaprox-agent.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
'''


class Root:
    """A directory that stands in for / on a node, and the systemctl of FAKES."""

    def __init__(self, tmp_path):
        self.world = World(tmp_path)
        self.root = tmp_path / 'root'
        (self.root / 'usr/local/bin').mkdir(parents=True)
        (self.root / 'etc/systemd/system').mkdir(parents=True)
        self.fence = self.root / 'usr/local/bin/pegaprox-fence-agent.sh'
        self.fence_unit = self.root / 'etc/systemd/system/pegaprox-fence-agent.service'
        self.shared = self.root / 'usr/local/bin/pegaprox-agent.sh'
        self.shared_unit = self.root / 'etc/systemd/system/pegaprox-agent.service'

    def put_shared(self, script, unit='[Unit]\nDescription=whatever ran here\n'):
        self.shared.write_text(script)
        self.shared_unit.write_text(unit)

    def sh(self, cmd):
        r = subprocess.run(['bash', '-c', cmd], capture_output=True, text=True, env=self.world.env)
        return r.stdout

    def systemctl(self):
        return self.world.calls('systemctl')


@pytest.fixture
def node(tmp_path):
    return Root(tmp_path)


def _b64(text):
    return base64.b64encode(text.encode()).decode()


def _node_agent_script():
    return PegaProxManager._NODE_AGENT_SCRIPT.replace('__STORAGE_PATH__', '/mnt/pve/hb') \
        .replace('__FENCE_STRATEGY__', 'quorum')


def _install_fence(node, script='#!/bin/bash\n# PegaProx Self-Fence Agent\nAGENT_VERSION=2\nMODE="quorum"\n'):
    return node.sh(PegaProxManager._fence_agent_install_cmd(
        _b64(script), _b64(PegaProxManager._FENCE_AGENT_SERVICE), root=str(node.root)))


def test_the_two_agents_have_their_own_names():
    M = PegaProxManager
    assert (M.FENCE_AGENT_PATH, M.FENCE_AGENT_UNIT) == ('/usr/local/bin/pegaprox-fence-agent.sh',
                                                        'pegaprox-fence-agent.service')
    assert (M.NODE_AGENT_PATH, M.NODE_AGENT_UNIT) == ('/usr/local/bin/pegaprox-agent.sh',
                                                      'pegaprox-agent.service')
    assert 'ExecStart=/usr/local/bin/pegaprox-fence-agent.sh' in M._FENCE_AGENT_SERVICE
    assert 'ExecStart=/usr/local/bin/pegaprox-agent.sh' in M._NODE_AGENT_SERVICE
    # the default commands name the real paths; they are only ever run with a root
    assert '/usr/local/bin/pegaprox-fence-agent.sh' in M._fence_agent_install_cmd('x', 'y')


def test_installing_the_fence_agent_leaves_a_node_agent_alone(node):
    """Before, both wrote pegaprox-agent.sh: the second install replaced the first."""
    node.put_shared(_node_agent_script())
    before = (node.shared.read_text(), node.shared_unit.read_text())

    out = _install_fence(node)

    assert 'AGENT_INSTALLED' in out and 'LEGACY_AGENT_REMOVED' not in out
    assert node.fence.exists() and node.fence_unit.exists()
    assert oct(node.fence.stat().st_mode & 0o777) == '0o700'      # it holds the agent token
    assert (node.shared.read_text(), node.shared_unit.read_text()) == before
    assert node.systemctl() == ['systemctl daemon-reload',
                                'systemctl enable pegaprox-fence-agent.service',
                                'systemctl restart pegaprox-fence-agent.service']


def test_an_old_self_fence_agent_under_the_shared_name_is_replaced(node):
    """The counterproof to the test above: the same install, and this time the script
    under the node agent's name carries the self-fence marker."""
    node.put_shared(V1_FENCE)

    out = _install_fence(node)

    assert 'AGENT_INSTALLED' in out and 'LEGACY_AGENT_REMOVED' in out
    assert node.fence.exists() and not node.shared.exists() and not node.shared_unit.exists()
    assert 'systemctl stop pegaprox-agent.service' in node.systemctl()
    assert 'systemctl disable pegaprox-agent.service' in node.systemctl()


def test_the_marker_is_a_whole_line(node):
    """The node agent script talks about the self-fence agent in its comments. Only the
    marker line on its own makes a script the old self-fence agent."""
    script = _node_agent_script()
    assert 'self-fence agent' in script and 'SELF_FENCE_AGENT_SCRIPT' in script
    node.put_shared(script + '\n# see: # PegaProx Self-Fence Agent (the other one)\n')

    _install_fence(node)

    assert node.shared.exists() and node.shared_unit.exists()


def test_installing_the_node_agent_leaves_the_fence_agent_alone(node):
    _install_fence(node)
    fence = (node.fence.read_text(), node.fence_unit.read_text())
    node.world._write('calls', '')

    out = node.sh(PegaProxManager._node_agent_install_cmd(
        _b64(_node_agent_script()), _b64(PegaProxManager._NODE_AGENT_SERVICE), root=str(node.root)))

    assert 'AGENT_INSTALLED_OK' in out and 'LEGACY_FENCE_AGENT' not in out
    assert (node.fence.read_text(), node.fence_unit.read_text()) == fence
    assert node.shared.read_text() == _node_agent_script()
    assert not any('fence' in c for c in node.systemctl())


def _install_node_agent(node):
    return node.sh(PegaProxManager._node_agent_install_cmd(
        _b64(_node_agent_script()), _b64(PegaProxManager._NODE_AGENT_SERVICE), root=str(node.root)))


def _old_agent_on(node, active=True, enabled=True):
    """A node as 1.2.0 left it: the v1 self-fence agent under the node agent's name."""
    node.put_shared(V1_FENCE + '# ══ a line no rewrite gets right by accident \t \n', V1_UNIT)
    node.shared.chmod(0o755)
    node.world._write('active', 'pegaprox-agent.service\n' if active else '')
    node.world._write('disabled', '' if enabled else 'pegaprox-agent.service\n')
    return node.shared.read_bytes(), node.shared_unit.read_bytes()


def test_the_node_agent_moves_an_old_self_fence_agent_to_its_own_name_as_it_is(node):
    """The node agent install runs on its own when the monitor starts. It was written
    over the old self-fence agent, and then v2 was installed in its place: an upgrade
    nobody asked for. The old agent moves to its own name instead, byte for byte, with
    its unit, and decides exactly as it did."""
    script, unit = _old_agent_on(node)

    out = _install_node_agent(node)

    assert 'LEGACY_AGENT_MOVED' in out and 'AGENT_INSTALLED_OK' in out
    assert node.fence.read_bytes() == script
    assert oct(node.fence.stat().st_mode & 0o777) == '0o755'
    assert b'AGENT_VERSION' not in node.fence.read_bytes()
    # the unit it had, with the new path and nothing else changed
    assert node.fence_unit.read_text() == V1_UNIT.replace('pegaprox-agent.sh', 'pegaprox-fence-agent.sh')
    assert node.shared.read_text() == _node_agent_script()
    assert node.shared_unit.read_text() == PegaProxManager._NODE_AGENT_SERVICE
    calls = node.systemctl()
    assert 'systemctl enable pegaprox-fence-agent.service' in calls
    # the same script under the new name only once the old one is stopped
    assert calls.index('systemctl stop pegaprox-agent.service') \
        < calls.index('systemctl start pegaprox-fence-agent.service') \
        < calls.index('systemctl restart pegaprox-agent')

    # and the check still calls it version 1
    node.world._write('active', 'pegaprox-fence-agent.service\npegaprox-agent.service\n')
    _curl_status(node, '400')
    found = _check(node)
    assert found['fence_agent'] == {'version': 1, 'mode': 'v1', 'active': True, 'legacy_shared_name': False,
                                    'sha256': hashlib.sha256(script).hexdigest()}
    assert found['node_agent'] == {'installed': True, 'active': True}


@pytest.mark.parametrize('active,enabled', [(False, True), (True, False), (False, False)])
def test_the_move_keeps_a_stopped_or_disabled_agent_stopped_or_disabled(node, active, enabled):
    """HA switched off stops the agents and leaves them installed. An agent that did
    not run does not start because its file moved."""
    script, _unit = _old_agent_on(node, active=active, enabled=enabled)

    out = _install_node_agent(node)

    assert 'LEGACY_AGENT_MOVED' in out and node.fence.read_bytes() == script
    calls = node.systemctl()
    assert ('systemctl start pegaprox-fence-agent.service' in calls) is active
    assert ('systemctl enable pegaprox-fence-agent.service' in calls) is enabled
    assert 'systemctl restart pegaprox-fence-agent.service' not in calls


def test_a_move_that_fails_puts_the_node_back_as_it_was(node):
    """The old agent does not come up under its new name: it runs under the old one
    again, the script and the unit are the ones from before, and the node agent is
    not written."""
    before = _old_agent_on(node)
    node.world._write('broken', 'pegaprox-fence-agent.service\n')

    out = _install_node_agent(node)

    assert 'LEGACY_MOVE_FAILED' in out and 'AGENT_INSTALLED_OK' not in out
    assert (node.shared.read_bytes(), node.shared_unit.read_bytes()) == before
    assert not node.fence.exists() and not node.fence_unit.exists()
    assert node.systemctl()[-1] == 'systemctl start pegaprox-agent.service'


def test_the_node_agent_is_not_written_over_an_old_agent_next_to_a_new_one(node):
    """Both on one node (a self-fence agent under its own name, and the old one still
    under the node agent's): nothing is moved over the new one and nothing written
    over the old one. The install from the HA settings takes the old one away."""
    _install_fence(node)
    fence = node.fence.read_bytes()
    before = _old_agent_on(node)
    node.world._write('calls', '')

    out = _install_node_agent(node)

    assert 'LEGACY_FENCE_AGENT' in out and 'AGENT_INSTALLED_OK' not in out
    assert (node.shared.read_bytes(), node.shared_unit.read_bytes()) == before
    assert node.fence.read_bytes() == fence and node.systemctl() == []


def _node_agent_mgr(node, monkeypatch, **ha_config):
    """A manager whose node agent install runs against the stand-in root of `node`."""
    m = _mgr(storage_heartbeat_path='/mnt/pve/hb', node_agent_installed={}, **ha_config)
    m.config.user = 'root@pam'
    m._ha_get_node_ip = lambda name: '10.9.0.1'
    m._ha_detect_fence_strategy = lambda: 'quorum'
    real = PegaProxManager._node_agent_install_cmd
    monkeypatch.setattr(PegaProxManager, '_node_agent_install_cmd',
                        classmethod(lambda cls, s, u, root='': real(s, u, root=str(node.root))))
    m._ssh_run_command_output = lambda ip, user, cmd, **kw: node.sh(cmd)
    return m


def test_the_manager_installs_the_node_agent_and_no_v2_agent_with_it(node, monkeypatch):
    """_ha_install_node_agent on a node that runs the old self-fence agent. It called
    _ha_install_self_fence_agent for the move, which renders and installs v2: on its
    own at the first monitor start after the update, for every setup with a storage
    heartbeat. The node keeps the agent it had."""
    script, _unit = _old_agent_on(node)
    m = _node_agent_mgr(node, monkeypatch, self_fence_installed=True, self_fence_nodes=['pve1'],
                        fence_agent_versions={'pve1': 1})
    m._ha_install_self_fence_agent = lambda *a, **kw: pytest.fail('installed the v2 self-fence agent')
    m._ha_agent_ssh = lambda *a, **kw: pytest.fail('went to the node for the self-fence agent')
    m._ha_agent_token = lambda: pytest.fail('made an agent token')

    assert m._ha_install_node_agent('pve1') is True

    assert node.fence.read_bytes() == script
    assert 'PegaProx Node Agent' in node.shared.read_text()
    assert m.ha_config['node_agent_installed'] == {'pve1': True}
    assert m.ha_config['fence_agent_versions'] == {'pve1': 1}       # still the old one, and on the books as that
    assert 'script unchanged' in m.logger.warning.call_args[0][0]

    # counterproof: a node without the old agent moves nothing
    node.world._write('calls', '')
    m.logger.reset_mock()
    assert m._ha_install_node_agent('pve1') is True
    assert node.fence.read_bytes() == script and not any('fence' in c for c in node.systemctl())
    m.logger.warning.assert_not_called()


def test_a_move_that_fails_leaves_the_old_self_fence_agent_running(node, monkeypatch):
    """The node then keeps the agent it had under the name it had, the node agent is
    not installed, and the install says so."""
    before = _old_agent_on(node)
    node.world._write('broken', 'pegaprox-fence-agent.service\n')
    m = _node_agent_mgr(node, monkeypatch, self_fence_installed=True, self_fence_nodes=['pve1'])
    sends = []
    m._ssh_run_command_output = lambda ip, user, cmd, **kw: sends.append(cmd) or node.sh(cmd)

    assert m._ha_install_node_agent('pve1') is False

    assert len(sends) == 1                      # asked once, not sent again after the move failed
    assert (node.shared.read_bytes(), node.shared_unit.read_bytes()) == before
    assert not node.fence.exists()
    assert m.ha_config['node_agent_installed'] == {}
    assert m.ha_config['self_fence_nodes'] == ['pve1']      # true: it still runs the old one
    assert 'install the self-fence agent again from the HA settings' in m.logger.error.call_args[0][0]


def test_uninstalling_the_fence_agent_keeps_the_node_agent(node):
    _install_fence(node)
    node.put_shared(_node_agent_script())

    out = node.sh(PegaProxManager._fence_agent_uninstall_cmd(root=str(node.root)))

    assert 'AGENT_UNINSTALLED' in out
    assert not node.fence.exists() and not node.fence_unit.exists()
    assert node.shared.exists() and node.shared_unit.exists()
    assert not any(c.endswith('pegaprox-agent.service') for c in node.systemctl())


def _left_under_run(node):
    """What a development build of the v2 agent kept under /run, next to two files
    that are not that."""
    run = node.root / 'run'
    run.mkdir()
    for end in ('', '.new', '.out', '.votes', '.go', '.go.new'):
        (run / (LEFT_BEHIND + end)).write_text('qm 100\n')
    for name in ('something-else', 'pegaprox-fence-agent.pid'):
        (run / name).write_text('not that\n')
    return run


def test_uninstalling_the_fence_agent_takes_what_a_development_build_left_under_run(node):
    """A development build of the v2 agent kept a list of the guests it had stopped
    under /run, with PegaProx's go-ahead next to it. No agent reads them any more, and
    a node that ran such a build does not keep them."""
    _install_fence(node)
    run = _left_under_run(node)

    assert 'AGENT_UNINSTALLED' in node.sh(PegaProxManager._fence_agent_uninstall_cmd(root=str(node.root)))

    assert sorted(p.name for p in run.iterdir()) == ['pegaprox-fence-agent.pid', 'something-else']
    # the path on a node
    assert PegaProxManager._fence_agent_leftovers_cmd() == 'rm -f /run/pegaprox-fence-agent.stopped* 2>/dev/null'
    assert PegaProxManager._fence_agent_leftovers_cmd() in PegaProxManager._fence_agent_uninstall_cmd().splitlines()


def test_installing_the_fence_agent_takes_them_too(node):
    """The install is what a node gets that runs a v2 agent already, when its script
    is brought up to date."""
    run = _left_under_run(node)

    out = _install_fence(node)

    assert 'AGENT_INSTALLED' in out and node.fence.exists() and node.fence_unit.exists()
    assert sorted(p.name for p in run.iterdir()) == ['pegaprox-fence-agent.pid', 'something-else']
    assert PegaProxManager._fence_agent_leftovers_cmd() in PegaProxManager._fence_agent_install_cmd('x', 'y').splitlines()


# --- forcing quorum: `pvecm expected 1` and nothing with it --------------------------------------

def _forcing(**ha_config):
    m = _mgr(**ha_config)
    m.config = types.SimpleNamespace(name='lab', user='root@pam', pass_='pw', ssh_key='')
    m._ha_get_node_ip = lambda node: '10.9.0.1'
    return m


@pytest.mark.parametrize('versions', [{'pve1': 2}, {'pve1': 1}, {}, {'pve2': 2}, None, ['pve1'], {'pve1': '2'},
                                      {'pve1': True}])
def test_forcing_quorum_sends_every_node_the_same_command(versions):
    """A development build sent a node it knew to run the v2 agent a go-ahead for the
    agent with it, written under /run. Every node gets `pvecm expected 1` and nothing
    else, as it always did."""
    m = _forcing(fence_agent_versions=versions)
    sent = []
    m._ssh_run_command = lambda host, user, cmd, *a, **kw: sent.append(cmd) or True

    assert m._ha_try_force_quorum('pve1') is True

    assert sent == ['pvecm expected 1']
    assert not hasattr(PegaProxManager, '_force_quorum_cmd')
    assert not hasattr(PegaProxManager, 'FENCE_AGENT_STOPPED')


def test_a_pvecm_that_fails_is_a_force_that_failed(node):
    """What the manager sends, run on a node whose corosync refuses it: the exit code
    is the one of pvecm, on every way in that is tried."""
    node.world.set(quorate=False, votes=(1, 3))
    (node.world.dir / 'refuses').write_text('')
    m = _forcing(fence_agent_versions={'pve1': 2})
    m._ssh_run_command = lambda host, user, cmd, *a, **kw: node.world.sh(cmd) == 0
    m._ssh_run_command_with_password = lambda host, user, cmd, password, **kw: node.world.sh(cmd) == 0

    assert m._ha_try_force_quorum('pve1') is False

    assert node.world.calls('pvecm') == ['pvecm expected 1'] * 2
    assert (node.world.dir / 'quorate').read_text() == 'no'
    # counterproof: the same node once corosync takes it
    (node.world.dir / 'refuses').unlink()
    assert m._ha_try_force_quorum('pve1') is True and (node.world.dir / 'quorate').read_text() == 'yes'


def test_uninstalling_the_fence_agent_takes_the_old_one_under_the_shared_name(node):
    node.put_shared(V1_FENCE)

    out = node.sh(PegaProxManager._fence_agent_uninstall_cmd(root=str(node.root)))

    assert 'AGENT_UNINSTALLED' in out
    assert not node.shared.exists() and not node.shared_unit.exists()
    assert 'systemctl stop pegaprox-agent.service' in node.systemctl()


def test_uninstalling_the_node_agent_keeps_both_kinds_of_fence_agent(node):
    _install_fence(node)
    node.put_shared(_node_agent_script())
    assert 'NODE_AGENT_REMOVED' in node.sh(PegaProxManager._node_agent_uninstall_cmd(root=str(node.root)))
    assert not node.shared.exists() and not node.shared_unit.exists()
    assert node.fence.exists() and node.fence_unit.exists()

    node.put_shared(V1_FENCE)
    assert 'NODE_AGENT_ABSENT' in node.sh(PegaProxManager._node_agent_uninstall_cmd(root=str(node.root)))
    assert node.shared.exists()


@pytest.mark.parametrize('shared', ['node-agent', 'old-fence-agent', 'nothing'])
def test_the_teardown_takes_both_agents_off(node, shared):
    """What disable_ha runs on every node. It used to run the self-fence uninstall alone,
    which was enough while both agents had one name."""
    _install_fence(node)
    if shared != 'nothing':
        node.put_shared(_node_agent_script() if shared == 'node-agent' else V1_FENCE)

    out = node.sh(PegaProxManager._fence_agent_uninstall_cmd(root=str(node.root))
                  + PegaProxManager._node_agent_uninstall_cmd(root=str(node.root)))

    assert 'AGENT_UNINSTALLED' in out and 'NODE_AGENT_REMOVED' in out
    left = sorted(p.name for p in (node.root / 'usr/local/bin').iterdir()) \
        + sorted(p.name for p in (node.root / 'etc/systemd/system').iterdir())
    assert left == []


@pytest.mark.parametrize('action', ['start', 'stop'])
def test_start_and_stop_reach_the_fence_agent_and_no_node_agent(node, action):
    node.put_shared(_node_agent_script())
    node.sh(PegaProxManager._fence_agent_ctl_cmd(action, root=str(node.root)))
    assert node.systemctl() == [f'systemctl {action} pegaprox-fence-agent.service']

    # a node that still runs the old agent under the shared name: that one too
    node.world._write('calls', '')
    node.put_shared(V1_FENCE)
    node.sh(PegaProxManager._fence_agent_ctl_cmd(action, root=str(node.root)))
    assert node.systemctl() == [f'systemctl {action} pegaprox-fence-agent.service',
                                f'systemctl {action} pegaprox-agent.service']


def test_ctl_takes_start_and_stop_only():
    with pytest.raises(ValueError):
        PegaProxManager._fence_agent_ctl_cmd('restart; reboot')


def test_the_manager_helpers_send_those_commands(monkeypatch):
    m = _mgr()
    sent = []
    monkeypatch.setattr(m, '_ha_node_ip_map', lambda: {'pve1': '10.9.0.1', 'pve2': '10.9.0.2', 'pve3': None},
                        raising=False)
    monkeypatch.setattr(m, '_ha_agent_ssh', lambda ip, cmd, **kw: sent.append((ip, cmd)) or 'AGENT_UNINSTALLED\n'
                        'NODE_AGENT_REMOVED\n', raising=False)

    m._ha_stop_self_fence_agents()
    m._ha_start_self_fence_agents()
    assert [c for _ip, c in sent] == [PegaProxManager._fence_agent_ctl_cmd('stop')] * 2 \
        + [PegaProxManager._fence_agent_ctl_cmd('start')] * 2

    sent.clear()
    m.ha_config['fence_agent_versions'] = {'pve1': 2, 'pve2': 2}
    assert m._ha_uninstall_self_fence_on_all_nodes() == {'pve1': True, 'pve2': True, 'pve3': False}
    assert {c for _ip, c in sent} == {PegaProxManager._fence_agent_uninstall_cmd()}
    assert m.ha_config['fence_agent_versions'] == {}

    sent.clear()
    assert m._ha_uninstall_agents_on_all_nodes() == {'pve1': True, 'pve2': True, 'pve3': False}
    assert {c for _ip, c in sent} == {PegaProxManager._fence_agent_uninstall_cmd()
                                     + PegaProxManager._node_agent_uninstall_cmd()}


@pytest.mark.parametrize('answer', ['AGENT_UNINSTALLED\n', 'NODE_AGENT_REMOVED\n', '', None])
def test_a_teardown_that_left_one_of_the_agents_is_not_a_success(monkeypatch, answer):
    m = _mgr()
    monkeypatch.setattr(m, '_ha_agent_ssh', lambda ip, cmd, **kw: answer, raising=False)
    assert m._ha_uninstall_all_agents('pve1', '10.9.0.1') is False


# --- the plan: which cluster decides how ------------------------------------------------

@pytest.mark.parametrize('votes,qdevice,flag,two_node,force,vmid,mode,asks,minority', [
    (3, False, False, False, False, '', 'quorum', False, True),
    (5, False, False, False, False, '', 'quorum', False, True),
    (3, True, False, False, False, '', 'quorum', False, True),       # two nodes and a qdevice
    (2, False, False, False, False, '', 'tiebreak', True, False),
    (2, False, True, False, False, '', 'tiebreak', True, False),     # corosync two_node: both halves quorate
    (3, False, True, False, False, '', 'tiebreak', True, False),
    (3, False, False, True, False, '', 'tiebreak', True, True),
    (3, False, False, False, True, '', 'tiebreak', True, True),      # quorum gets forced
    (3, False, False, False, False, '900', 'quorum', True, True),    # only to restart the PegaProx VM
    (1, False, False, False, False, '', 'off', False, False),
    (None, None, False, False, False, '', 'tiebreak', True, False),  # corosync not read, two nodes listed
])
def test_the_plan_follows_corosync_and_the_two_node_settings(monkeypatch, votes, qdevice, flag, two_node,
                                                              force, vmid, mode, asks, minority):
    m = _mgr(two_node_mode=two_node, force_quorum_on_failure=force, pegaprox_vmid=vmid)

    def detect():
        m.ha_config['fence_strategy'] = {'strategy': 'quorum', 'expected_votes': votes,
                                         'has_qdevice': qdevice, 'two_node_flag': flag,
                                         'detection_reason': 'detected' if votes else 'detection-skipped'}
        return 'quorum'
    monkeypatch.setattr(m, '_ha_detect_fence_strategy', detect, raising=False)
    monkeypatch.setattr(m, '_ha_node_names', lambda: ['pve1', 'pve2'], raising=False)
    monkeypatch.setattr(m, '_ha_agent_members', lambda: [LEADER], raising=False)

    plan = m._ha_agent_plan()

    assert plan['mode'] == mode
    assert plan['members'] == ([LEADER] if asks else [])
    assert plan['minority_fences'] is minority
    script = m._ha_render_fence_agent('pve1', plan)
    assert f'MINORITY_FENCES="{1 if minority else 0}"' in script
    # corosync not read: the two nodes the API lists
    assert f'CLUSTER_VOTES={votes or 2}\n' in script


PVECM_FORCED = '''Cluster information
-------------------
Name:             lab
Config Version:   3
Transport:        knet
Secure auth:      on

Quorum information
------------------
Date:             Fri Oct  2 10:00:00 2026
Quorum provider:  corosync_votequorum
Nodes:            1
Node ID:          0x00000001
Ring ID:          1.2a
Quorate:          Yes

Votequorum information
----------------------
Expected votes:   1
Highest expected: 1
Total votes:      1
Quorum:           1
Flags:            Quorate__QDEVICE__
'''


def _detecting(nodes, pvecm, **ha_config):
    """A manager whose look at corosync is the real one, fed `pvecm status` text."""
    m = _mgr(**ha_config)
    m.config.host, m.config.api_port, m.current_host = '10.9.0.1', 8006, None
    session = types.SimpleNamespace(get=lambda url, timeout=10: types.SimpleNamespace(
        status_code=200, json=lambda: {'data': [{'node': n} for n in nodes]}))
    m._create_session = lambda: session
    m._ha_get_node_ip = lambda name: f'10.9.0.{name[-1]}'
    m._ssh_run_command_with_key_output = lambda *a, **kw: None
    m._ssh_run_command_with_password_output = lambda ip, user, cmd, pw, **kw: pvecm
    m._ssh_run_command_output = lambda *a, **kw: None
    m._ha_agent_members = lambda: [LEADER]
    return m


@pytest.mark.parametrize('nodes,qdevice,forces,mode,votes', [
    (('pve1', 'pve2', 'pve3'), False, True, 'tiebreak', 3),
    (('pve1', 'pve2', 'pve3'), False, False, 'quorum', 3),
    (('pve1', 'pve2'), True, True, 'tiebreak', 3),          # two nodes and a qdevice
    (('pve1', 'pve2'), False, True, 'tiebreak', 2),
])
def test_an_install_while_quorum_is_forced_still_knows_the_cluster(nodes, qdevice, forces, mode, votes):
    """"Expected votes" in `pvecm status` is what corosync runs with, and PegaProx's own
    `pvecm expected 1` lowers it. An install or redeploy in that state read one vote,
    took the cluster for a node in no cluster and rendered MODE="off": an agent that
    never fences, also after the cluster was whole again, and the install check called
    it current. Every node the API lists has a vote."""
    m = _detecting(nodes, PVECM_FORCED.replace('__QDEVICE__', ' Qdevice' if qdevice else ''),
                   force_quorum_on_failure=forces)

    plan = m._ha_agent_plan()

    assert (plan['mode'], plan['expected_votes']) == (mode, votes)
    assert m.ha_config['fence_strategy']['runtime_expected_votes'] == 1
    script = m._ha_render_fence_agent('pve1', plan)
    assert f'MODE="{mode}"' in script and f'CLUSTER_VOTES={votes}\n' in script
    assert plan['minority_fences'] is (votes >= 3)
    # and the look that is kept says the same to the install check
    assert m._ha_agent_plan(detect=False)['mode'] == mode


def test_a_node_in_no_cluster_is_still_off():
    """The counterproof: one node listed, one vote. There is nothing to split from."""
    m = _detecting(('pve1',), PVECM_FORCED.replace('__QDEVICE__', ''))
    assert m._ha_agent_plan()['mode'] == 'off'


def test_the_members_are_this_instance_and_the_rest_of_its_group(monkeypatch):
    m = _mgr()
    monkeypatch.setattr(ha, 'own_url', lambda: 'https://a.example:5000')
    monkeypatch.setattr(ha, 'members', lambda: [{'url': 'https://b.example:5000'}, {'url': ''},
                                                {'url': 'https://c.example"; id; "'}])
    assert m._ha_agent_members() == ['https://a.example:5000', 'https://b.example:5000']
    # the one that is left out is named: the nodes will not ask that instance
    assert 'https://c.example' in m.logger.error.call_args[0][0]
    # sorted, whoever renders: every instance of a group gives the nodes the same script
    monkeypatch.setattr(ha, 'own_url', lambda: 'https://b.example:5000')
    monkeypatch.setattr(ha, 'members', lambda: [{'url': 'https://a.example:5000'}])
    assert m._ha_agent_members() == ['https://a.example:5000', 'https://b.example:5000']

    # an instance that never made a pairing code: the address the cluster reaches it at
    monkeypatch.setattr(ha, 'own_url', lambda: '')
    monkeypatch.setattr(ha, 'members', lambda: [])
    monkeypatch.setattr(m, '_get_pegaprox_server_ip', lambda: '10.9.0.5', raising=False)
    monkeypatch.setattr(manager_mod._g, 'SERVER_BIND_PORT', 5443)
    assert m._ha_agent_members() == ['https://10.9.0.5:5443']
    monkeypatch.setattr(m, '_get_pegaprox_server_ip', lambda: 'fd00::5', raising=False)
    assert m._ha_agent_members() == ['https://[fd00::5]:5443']


def test_a_member_address_with_a_path_is_asked_like_any_other(monkeypatch, tmp_path):
    """ha.valid_https_url, the rule for every member address, takes https://host/path
    (an instance behind a reverse proxy under a sub-path). The agent's own rule took
    no path and dropped such a member without a word: it was never asked for the
    leader, and as this instance's own address a tiebreak cluster got no agent at all."""
    behind = 'https://pega.example.com/pegaprox'
    assert ha.valid_https_url(behind + '/') == behind
    m = _mgr()
    monkeypatch.setattr(ha, 'own_url', lambda: LEADER)
    monkeypatch.setattr(ha, 'members', lambda: [{'url': behind}])
    assert m._ha_agent_members() == [LEADER, behind]

    monkeypatch.setattr(ha, 'own_url', lambda: behind)
    monkeypatch.setattr(ha, 'members', lambda: [])
    assert m._ha_agent_members() == [behind]
    script = m._ha_render_fence_agent('pve1', _plan('tiebreak', members=m._ha_agent_members()),
                                      t_sf=T_SF, interval=INTERVAL)
    assert f'MEMBERS="{behind}"' in script
    assert f"{behind}/api/ha/agent" in PegaProxManager._agent_check_cmd([behind])

    # and the node asks under that path
    world = World(tmp_path)
    world.set(quorate=True, votes=(1, 2), curl='leader')
    log, _ = world.run(script, until=lambda: 'staying up' in (world.dir / 'agent.out').read_text(), seconds=5)
    assert 'staying up' in log, log
    assert all(c.startswith(f'curl {behind}/api/ha/agent?cluster=c1&nonce=') for c in world.calls('curl'))


def test_own_url_is_the_address_of_the_last_pairing_code(tmp_path, monkeypatch):
    import json
    monkeypatch.setattr(ha, 'STATE_FILE', str(tmp_path / 'ha_state.json'))
    ha.reset_for_tests()
    assert ha.own_url() == ''

    with open(ha.STATE_FILE, 'w') as fh:
        json.dump({'role': 'active', 'epoch': 2, 'instance_id': 'a' * 32, 'interval': 30, 'peer': None,
                   'pairing': None, 'sync': {}, 'own_url': 'https://a.example:5000'}, fh)
    ha.reset_for_tests()
    try:
        assert ha.own_url() == 'https://a.example:5000'
    finally:
        os.unlink(ha.STATE_FILE)
        ha.reset_for_tests()


def test_corosync_two_node_is_read_from_the_flags(monkeypatch):
    m = _mgr()
    m.current_host = '10.9.0.1'
    session = MagicMock()
    session.get.return_value = MagicMock(status_code=200, json=lambda: {'data': [{'node': 'pve1'}]})
    monkeypatch.setattr(m, '_create_session', lambda: session, raising=False)
    monkeypatch.setattr(m, '_ha_get_node_ip', lambda node: '10.9.0.1', raising=False)
    monkeypatch.setattr(m, '_ha_persist_fence_strategy',
                        lambda decision, reason: m.ha_config.update(fence_strategy=dict(decision)), raising=False)
    out = 'Expected votes:   2\nFlags:            2Node Quorate WaitForAll\n'
    monkeypatch.setattr(m, '_ssh_run_command_with_password_output', lambda *a, **kw: out, raising=False)

    m._ha_detect_fence_strategy()

    assert m.ha_config['fence_strategy']['two_node_flag'] is True
    out = 'Expected votes:   3\nFlags:            Quorate\n'
    m._ha_detect_fence_strategy()
    assert m.ha_config['fence_strategy']['two_node_flag'] is False


def _sent_script(cmd):
    """The script an install command carries."""
    return base64.b64decode(cmd.split('echo "')[1].split('"')[0]).decode()


def test_installing_on_all_nodes_reads_corosync_once_and_every_node_gets_the_same_script(monkeypatch):
    m = _mgr(two_node_mode=True)
    looks, sent = [], {}
    monkeypatch.setattr(m, '_ha_node_ip_map', lambda: {'pve1': '10.9.0.1', 'pve2': '10.9.0.2'}, raising=False)

    def plan(detect=True):
        looks.append(detect)
        return {'mode': 'tiebreak', 'strategy': 'quorum', 'members': [LEADER], 'vmid': '', 'expected_votes': 3}
    monkeypatch.setattr(m, '_ha_agent_plan', plan, raising=False)

    def ssh(ip, cmd, **kw):
        sent[ip] = _sent_script(cmd)
        return 'AGENT_INSTALLED\n'
    monkeypatch.setattr(m, '_ha_agent_ssh', ssh, raising=False)

    assert m._ha_install_self_fence_on_all_nodes() == {'pve1': True, 'pve2': True}

    assert looks == [True]
    assert sent['10.9.0.1'] == sent['10.9.0.2'] and 'CLUSTER_VOTES=3\n' in sent['10.9.0.1']
    assert m.ha_config['fence_agent_versions'] == {'pve1': 2, 'pve2': 2}
    # which instances the nodes ask now: the monitor compares the group against it
    assert m.ha_config['fence_agent_members'] == [LEADER]


def test_a_node_whose_peer_has_no_known_address_gets_a_working_agent(monkeypatch, tmp_path):
    """The peer's management IP cannot be determined at install time (it is down for
    maintenance). The script carried the peers to ping, and with none it took them
    for lost for ever: a quorate, healthy node then depended on a PegaProx leader
    answering every pass, and a PegaProx restart longer than T_SF stopped all of its
    guests. The script carries no peer any more."""
    m = _mgr(two_node_mode=True, fence_strategy={'strategy': 'quorum', 'expected_votes': 3, 'has_qdevice': True,
                                                 'two_node_flag': False, 'detection_reason': 'detected'})
    m._ha_agent_members = lambda: [LEADER]
    m._ha_detect_fence_strategy = lambda: 'quorum'
    m._ha_node_ip_map = lambda: {'pve1': '10.9.0.1', 'pve2': None}
    sent = {}
    m._ha_agent_ssh = lambda ip, cmd, timeout=30: sent.update({ip: _sent_script(cmd)}) or 'AGENT_INSTALLED\n'

    assert m._ha_install_self_fence_on_all_nodes() == {'pve1': True, 'pve2': False}

    assert 'MODE="tiebreak"' in sent['10.9.0.1'] and 'OTHER_NODES' not in sent['10.9.0.1']
    # the same plan with the test timings: the peer is back, corosync counts it, PegaProx restarts
    script = m._ha_render_fence_agent('pve1', m._ha_agent_plan(detect=False), t_sf=T_SF, interval=INTERVAL)
    world = World(tmp_path)
    world.set(quorate=True, votes=(3, 3), reachable=['10.9.0.2'], curl='down')
    log, _ = world.run(script, seconds=4 * T_SF)
    assert world.stops() == [], log


def test_a_tiebreak_cluster_without_an_address_installs_nothing(monkeypatch):
    m = _mgr()
    sent = []
    monkeypatch.setattr(m, '_ha_agent_ssh', lambda ip, cmd, **kw: sent.append(cmd) or 'AGENT_INSTALLED\n',
                        raising=False)

    assert m._ha_install_self_fence_agent('pve1', '10.9.0.1', _plan('tiebreak', members=[])) is False
    assert sent == []


# --- the install check ---------------------------------------------------------------------

def _check(node, members=(LEADER,)):
    return PegaProxManager._parse_agent_check(
        node.sh(PegaProxManager._agent_check_cmd(members, root=str(node.root))))


def _curl_status(node, code):
    (node.world.bin / 'curl').write_text(f'#!/bin/bash\necho "curl $*" >> "$FAKE/calls"\nprintf {code}\n')


def test_the_check_tells_which_agent_version_a_node_runs(node):
    _curl_status(node, '400')
    assert _check(node)['fence_agent'] == {'version': 0, 'mode': '', 'active': False, 'sha256': '',
                                           'legacy_shared_name': False}

    script = _mgr()._ha_render_fence_agent('pve1', _plan('tiebreak'))
    _install_fence(node, script)
    node.world._write('active', 'pegaprox-fence-agent.service\n')
    found = _check(node)
    assert found['fence_agent'] == {'version': 2, 'mode': 'tiebreak', 'active': True,
                                    'sha256': hashlib.sha256(script.encode()).hexdigest(),
                                    'legacy_shared_name': False}
    assert found['node_agent'] == {'installed': False, 'active': False}


def test_the_check_sees_the_old_agent_and_the_node_agent_apart(node):
    _curl_status(node, '400')
    node.put_shared(V1_FENCE)
    node.world._write('active', 'pegaprox-agent.service\n')
    found = _check(node)
    assert found['fence_agent']['version'] == 1 and found['fence_agent']['legacy_shared_name']
    assert found['fence_agent']['active'] and found['fence_agent']['mode'] == 'v1'
    assert found['node_agent'] == {'installed': False, 'active': False}

    node.put_shared(_node_agent_script())
    found = _check(node)
    assert found['fence_agent']['version'] == 0 and not found['fence_agent']['active']
    assert found['node_agent'] == {'installed': True, 'active': True}


@pytest.mark.parametrize('code,reached', [('400', True), ('000', False), ('403', False), ('502', False),
                                          ('200', False)])
def test_the_check_names_the_instances_a_node_cannot_reach(node, code, reached):
    """Only the route itself answers a question without a shape with 400. No answer, a
    proxy's error and the refusal of the IP allow list are all 'cannot reach'."""
    _curl_status(node, code)

    found = _check(node, members=(LEADER, 'https://10.9.0.6:5000'))

    assert found['members_unreachable'] == ([] if reached else [LEADER, 'https://10.9.0.6:5000'])
    assert [c.split()[-1] for c in node.world.calls('curl')] == [f'{LEADER}/api/ha/agent',
                                                                 'https://10.9.0.6:5000/api/ha/agent']


def test_a_node_that_did_not_finish_the_check_is_no_answer():
    assert PegaProxManager._parse_agent_check(None) is None
    assert PegaProxManager._parse_agent_check('FENCE_VERSION=2\n') is None


def test_the_manager_check_reports_every_node_and_keeps_the_versions(monkeypatch):
    m = _mgr(fence_strategy={'strategy': 'quorum', 'expected_votes': 3, 'detection_reason': 'detected'})
    current = m._ha_render_fence_agent('pve1', _plan('quorum', minority=True))
    answers = {
        '10.9.0.1': f'FENCE_VERSION=2\nFENCE_MODE=quorum\nFENCE_SHA={hashlib.sha256(current.encode()).hexdigest()}\n'
                    'FENCE_ACTIVE=active\nSHARED=none\nSHARED_ACTIVE=inactive\nAGENT_CHECK_DONE\n',
        '10.9.0.2': 'FENCE_VERSION=2\nFENCE_MODE=tiebreak\nFENCE_SHA=' + '0' * 64 + '\nFENCE_ACTIVE=active\n'
                    'SHARED=none\nSHARED_ACTIVE=inactive\nAGENT_CHECK_DONE\n',
        '10.9.0.3': 'FENCE_VERSION=0\nFENCE_MODE=\nFENCE_SHA=\nFENCE_ACTIVE=inactive\nSHARED=fence\n'
                    'SHARED_ACTIVE=active\nAGENT_CHECK_DONE\n',
        '10.9.0.4': None,
    }
    monkeypatch.setattr(m, '_ha_node_ip_map', lambda: {f'pve{i}': f'10.9.0.{i}' for i in range(1, 5)},
                        raising=False)
    monkeypatch.setattr(m, '_ha_detect_fence_strategy', lambda: pytest.fail('looked at corosync again'),
                        raising=False)
    monkeypatch.setattr(m, '_ha_agent_ssh', lambda ip, cmd, **kw: answers[ip], raising=False)

    report = m._ha_check_agents()

    nodes = report['nodes']
    assert report['expected_version'] == 2 and report['mode'] == 'quorum'
    assert nodes['pve1']['fence_agent']['current'] is True
    assert nodes['pve2']['fence_agent']['current'] is False      # v2, but not the script of now
    assert nodes['pve3']['fence_agent']['version'] == 1 and nodes['pve3']['fence_agent']['current'] is False
    # per node: the one from before v2 is outdated, a v2 script that differs is not
    assert [nodes[n]['fence_agent']['outdated'] for n in ('pve1', 'pve2', 'pve3')] == [False, False, True]
    assert nodes['pve4'] is None
    assert m.ha_config['fence_agent_versions'] == {'pve1': 2, 'pve2': 2, 'pve3': 1}


@pytest.mark.parametrize('threshold,delay', [(3, 0), (1, 5), (2, 10)])
def test_the_agent_check_keeps_what_it_knew_of_a_node_that_did_not_answer(threshold, delay):
    """POST .../ha/agent-check while a node does not answer, which is the node in
    trouble. The check wrote the versions from the answers alone: the node fell out
    of the books, and from then on its recovery waited recovery_delay only while its
    v2 agent still needed the fence delay. A node that answers without an agent does
    leave the books."""
    m = _mgr(recovery_delay=delay, fence_agent_versions={'pve1': 1, 'pve2': 2, 'pve3': 2},
             fence_strategy={'strategy': 'quorum', 'expected_votes': 3, 'has_qdevice': False,
                             'two_node_flag': False, 'detection_reason': 'detected'})
    m.ha_failure_threshold = threshold
    m._ha_node_ip_map = lambda: dict(IPS)
    v2 = NO_AGENT.replace('FENCE_VERSION=0', 'FENCE_VERSION=2')
    m._ha_agent_ssh = lambda ip, cmd, timeout=30: {'10.9.0.1': v2, '10.9.0.2': None, '10.9.0.3': NO_AGENT}[ip]
    before = m._ha_fence_timing('pve2')
    assert before['wait'] > delay

    report = m._ha_check_agents()

    assert report['nodes']['pve2'] is None and report['nodes']['pve3']['fence_agent']['version'] == 0
    assert m.ha_config['fence_agent_versions'] == {'pve1': 2, 'pve2': 2}
    assert m._ha_fence_timing('pve2') == before
    assert m._ha_fence_timing('pve2')['earliest_recovery'] >= before['fence_delay'] + before['margin']
    assert m._ha_fence_timing('pve3')['wait'] == delay


# --- the redeploy: the script on the nodes follows the group -------------------------------

NEW = 'https://10.9.0.6:5000'      # a member that was paired after the install
IPS = {'pve1': '10.9.0.1', 'pve2': '10.9.0.2', 'pve3': '10.9.0.3'}
NO_AGENT = ('FENCE_VERSION=0\nFENCE_MODE=\nFENCE_SHA=\nFENCE_ACTIVE=inactive\nSHARED=none\n'
            'SHARED_ACTIVE=inactive\nAGENT_CHECK_DONE\n')
# the agent of an older PegaProx: under the node agent's name, or moved to its own
V1_AGENT = NO_AGENT.replace('SHARED=none', 'SHARED=fence').replace('SHARED_ACTIVE=inactive', 'SHARED_ACTIVE=active')
V1_MOVED = NO_AGENT.replace('FENCE_VERSION=0', 'FENCE_VERSION=1').replace('FENCE_ACTIVE=inactive',
                                                                          'FENCE_ACTIVE=active')


def _deployed(monkeypatch, members=(), **ha_config):
    """A tiebreak cluster with the agent installed on pve1 and pve2 by an instance whose
    group is `members`. The stand-in for SSH keeps the script each node runs."""
    m = _mgr(two_node_mode=True, self_fence_installed=True, self_fence_nodes=['pve1', 'pve2'],
             fence_strategy={'strategy': 'quorum', 'expected_votes': 3, 'has_qdevice': True,
                             'two_node_flag': False, 'detection_reason': 'detected'}, **ha_config)
    m._ha_detect_fence_strategy = lambda: 'quorum'
    m._ha_node_ip_map = lambda: dict(IPS)
    monkeypatch.setattr(ha, 'own_url', lambda: LEADER)
    monkeypatch.setattr(ha, 'members', lambda: [{'url': u} for u in members])
    m.scripts, m.installs, m.stored = {}, [], {}
    m._ha_store_settings = lambda **keys: m.stored.update(keys) or True

    def ssh(ip, cmd, timeout=30):
        if 'AGENT_CHECK_DONE' in cmd:
            if m.scripts.get(ip) is None:
                return NO_AGENT
            if m.scripts[ip] == 'v1':
                return V1_AGENT
            if m.scripts[ip] == 'v1-moved':
                return V1_MOVED
            sha = hashlib.sha256(m.scripts[ip].encode()).hexdigest()
            return NO_AGENT.replace('FENCE_VERSION=0', 'FENCE_VERSION=2').replace('FENCE_SHA=', f'FENCE_SHA={sha}')
        m.scripts[ip] = _sent_script(cmd)
        m.installs.append(ip)
        return 'AGENT_INSTALLED\n'
    m._ha_agent_ssh = ssh
    m._ha_install_self_fence_on_all_nodes()
    m.scripts.pop('10.9.0.3')           # pve3 never had the agent
    m.ha_config['fence_agent_versions'].pop('pve3')
    m.installs.clear()
    return m


def test_a_member_paired_after_the_install_reaches_the_nodes(monkeypatch, tmp_path):
    """The agents installed by instance A name A. A standby B is paired later and leads
    when A dies: B answers 'leader' and no node asks it, so a tiebreak node that lost
    its peer fences itself although a leader exists. The install ran from two places
    only (the install route, a change of the two-node settings); the script on the
    nodes follows the group now."""
    m = _deployed(monkeypatch, unsafe_two_node_recovery=True)
    before = m.scripts['10.9.0.1']
    assert f'MEMBERS="{LEADER}"' in before and m.ha_config['fence_agent_members'] == [LEADER]
    assert m._ha_agent_members_changed() is False

    monkeypatch.setattr(ha, 'members', lambda: [{'url': NEW}])
    assert m._ha_agent_members_changed() is True

    assert m._ha_redeploy_fence_agents('test') == {'pve1': True, 'pve2': True}

    assert sorted(m.installs) == ['10.9.0.1', '10.9.0.2'] and '10.9.0.3' not in m.scripts
    after = m.scripts['10.9.0.1']
    assert f'MEMBERS="{LEADER} {NEW}"' in after and m.scripts['10.9.0.2'] == after
    assert m._ha_agent_members_changed() is False
    assert m.stored == {'fence_agent_versions': {'pve1': 2, 'pve2': 2}}

    # A is dead and only B answers. The node lost its peers and has no quorum, on a
    # setup where the leader decides for it then: with the script of before it fences
    # itself, the one that was brought up to date stays up
    for name, script, fenced in (('old', before, True), ('new', after, False)):
        (tmp_path / name).mkdir()
        world = World(tmp_path / name)
        (world.bin / 'curl').write_text(FAKES['curl'].replace(
            'mode=$(cat "$FAKE/curl")', f'mode=$(cat "$FAKE/curl")\ncase "$url" in {NEW}/*) ;; *) exit 7 ;; esac'))
        world.set(quorate=False, votes=(1, 3), curl='leader')
        script = script.replace('T_SF_CS=3000 ', f'T_SF_CS={int(T_SF * 100)} ') \
            .replace('CHECK_INTERVAL=5\n', f'CHECK_INTERVAL={INTERVAL}\n')
        log, _ = world.run(script, until=lambda: len(world.stops()) == 3, seconds=4 * T_SF)
        assert (world.stops() == ALL_STOPPED) is fenced, log


def test_a_node_that_runs_the_script_of_now_is_left_alone(monkeypatch):
    """Only where the script differs: a second pass, and a pass with nothing changed,
    install nothing. A node without the agent gets none, one that does not answer is
    not counted either way."""
    m = _deployed(monkeypatch)

    assert m._ha_redeploy_fence_agents('test') == {} and m.installs == []

    answers = m._ha_agent_ssh
    m._ha_agent_ssh = lambda ip, cmd, timeout=30: None if ip == '10.9.0.2' else answers(ip, cmd)
    monkeypatch.setattr(ha, 'members', lambda: [{'url': NEW}])
    assert m._ha_redeploy_fence_agents('test') == {'pve1': True}
    assert m.installs == ['10.9.0.1']


def test_a_node_that_is_back_is_looked_at_on_its_own(monkeypatch):
    """It may have been down when the others got the new script. Only that node is
    asked, and what the monitor compares the group against stays as it was."""
    m = _deployed(monkeypatch)
    monkeypatch.setattr(ha, 'members', lambda: [{'url': NEW}])
    m._ha_detect_fence_strategy = lambda: pytest.fail('looked at corosync again')

    assert m._ha_redeploy_fence_agents('node back online', only='pve2') == {'pve2': True}

    assert m.installs == ['10.9.0.2'] and NEW in m.scripts['10.9.0.2'] and NEW not in m.scripts['10.9.0.1']
    assert m._ha_agent_members_changed() is True


@pytest.mark.parametrize('old', ['v1', 'v1-moved'])
def test_the_agent_of_an_older_pegaprox_is_not_brought_up_to_date(monkeypatch, old):
    """It was: every pass replaced it with v2, the one at the first monitor start
    after the update included. v2 decides differently (quorum first, no ping), so an
    existing setup changed its behaviour without anybody asking. The pass leaves it,
    under whichever name it runs, and says which node it is."""
    m = _deployed(monkeypatch)
    m.scripts['10.9.0.2'] = old
    monkeypatch.setattr(ha, 'members', lambda: [{'url': NEW}])     # every v2 script is stale now

    assert m._ha_redeploy_fence_agents('test') == {'pve1': True}

    assert m.installs == ['10.9.0.1'] and m.scripts['10.9.0.2'] == old
    assert m.ha_config['fence_agent_versions'] == {'pve1': 2, 'pve2': 1}
    assert m.stored == {'fence_agent_versions': {'pve1': 2, 'pve2': 1}}
    said = [c[0][0] for c in m.logger.warning.call_args_list]
    assert len(said) == 1 and 'on pve2 is version 1' in said[0] and 'keeps running as it is' in said[0]

    # the next pass has nothing to do and does not say it again
    assert m._ha_redeploy_fence_agents('test') == {} and m.installs == ['10.9.0.1']
    assert len(m.logger.warning.call_args_list) == 1


def test_a_cluster_with_the_old_agent_only_gets_a_look_and_nothing_else(monkeypatch):
    """An installation from before the update, at its first monitor start after it:
    the agents are installed, nothing is known about their version, there is no agent
    token. The pass reads what the nodes run. It makes no token, does not ask corosync
    and installs nothing, and the monitor does not come back every minute."""
    m = _mgr(two_node_mode=True, unsafe_two_node_recovery=True, self_fence_installed=True,
             self_fence_nodes=['pve1', 'pve2'])
    m.ha_config.pop('agent_token')
    m._ha_node_ip_map = lambda: dict(IPS)
    m._ha_detect_fence_strategy = lambda: pytest.fail('looked at corosync')
    m._ha_agent_token = lambda: pytest.fail('made an agent token')
    m._ha_install_self_fence_agent = lambda *a, **kw: pytest.fail('installed an agent')
    monkeypatch.setattr(ha, 'own_url', lambda: LEADER)
    monkeypatch.setattr(ha, 'members', lambda: [{'url': NEW}])
    sent, stored = [], {}
    m._ha_agent_ssh = lambda ip, cmd, timeout=30: sent.append(cmd) or (NO_AGENT if ip == '10.9.0.3' else V1_AGENT)
    m._ha_store_settings = lambda **keys: stored.update(keys) or True
    assert m._ha_agent_members_changed() is True        # not looked at yet

    assert m._ha_redeploy_fence_agents('the HA monitor started') == {}

    # one read per node, and what it reads changes nothing there
    assert sent == [PegaProxManager._agent_check_cmd()] * 3
    for word in ('systemctl restart', 'systemctl stop', 'systemctl enable', 'systemctl disable', 'rm ', 'mv ',
                 'base64'):
        assert word not in sent[0]
    assert m.ha_config['fence_agent_versions'] == {'pve1': 1, 'pve2': 1} == stored['fence_agent_versions']
    assert 'agent_token' not in m.ha_config and m._ha_agent_members_changed() is False

    status = m._ha_fence_agent_status()
    assert status['expected_version'] == 2 and status['versions'] == {'pve1': 1, 'pve2': 1}
    # two checks after the first, then recovery_delay: what the admin set, as before
    assert status['nodes'] == {n: {'version': 1, 'outdated': True, 'earliest_recovery': 50} for n in ('pve1', 'pve2')}
    assert status['outdated'] == ['pve1', 'pve2'] and status['unchecked'] == []
    assert 'on pve1, pve2 is version 1' in status['outdated_warning']
    assert 'Install the self-fence agent again from the HA settings' in status['outdated_warning']
    # saving a setting no longer installs on these nodes, and the status says what that means
    assert status['outdated_settings_warning'] == (
        'A change of the PegaProx VM ID or of the two-node settings does not reach the version 1 agent on '
        'pve1, pve2: it keeps the settings it was installed with until the self-fence agent is installed '
        'again from the HA settings.')


def _rooted(monkeypatch, node, *names):
    """The manager's node commands run against the stand-in root of `node`."""
    for name in names:
        real = getattr(PegaProxManager, name)
        monkeypatch.setattr(PegaProxManager, name, classmethod(
            lambda cls, *a, _real=real, **kw: _real(*a, root=str(node.root), **kw)))


def test_a_monitor_start_leaves_the_old_agent_on_the_node_byte_for_byte(node, monkeypatch):
    """The same through a shell: what the monitor does about the agents when it starts
    (_ha_bring_up_fence_agents), against a node as 1.2.0 left it. The script and the
    unit are the bytes from before and the agent is started as every monitor start
    did. The counterproof is the install route's call, which does put v2 there."""
    before = _old_agent_on(node)
    m = _mgr(self_fence_installed=True, self_fence_nodes=['pve1'], two_node_mode=True,
             unsafe_two_node_recovery=True,
             fence_strategy={'strategy': 'quorum', 'expected_votes': 3, 'has_qdevice': True,
                             'two_node_flag': False, 'detection_reason': 'detected'})
    m._ha_node_ip_map = lambda: {'pve1': '10.9.0.1'}
    m._ha_detect_fence_strategy = lambda: 'quorum'
    m._ha_agent_ssh = lambda ip, cmd, timeout=30: node.sh(cmd)
    m._ha_store_settings = lambda **keys: True
    monkeypatch.setattr(ha, 'own_url', lambda: LEADER)
    monkeypatch.setattr(ha, 'members', lambda: [])
    _rooted(monkeypatch, node, '_agent_check_cmd', '_fence_agent_install_cmd', '_fence_agent_ctl_cmd')

    m._ha_bring_up_fence_agents()

    assert (node.shared.read_bytes(), node.shared_unit.read_bytes()) == before
    assert not node.fence.exists() and not node.fence_unit.exists()
    assert [c for c in node.systemctl() if ' is-active ' not in c] == [
        'systemctl start pegaprox-fence-agent.service', 'systemctl start pegaprox-agent.service']
    assert m.ha_config['fence_agent_versions'] == {'pve1': 1}

    # the admin's install, what POST .../ha/install-self-fence runs
    assert m._ha_install_self_fence_on_all_nodes() == {'pve1': True}
    assert 'AGENT_VERSION=2' in node.fence.read_text() and not node.shared.exists()
    assert m.ha_config['fence_agent_versions'] == {'pve1': 2}


@pytest.mark.parametrize('why', ['standby', 'not-installed'])
def test_nothing_is_redeployed_by_a_standby_or_without_the_agents(monkeypatch, why):
    m = _deployed(monkeypatch)
    monkeypatch.setattr(ha, 'members', lambda: [{'url': NEW}])
    if why == 'standby':
        monkeypatch.setattr(ha, 'is_active', lambda: False)
    else:
        m.ha_config['self_fence_installed'] = False
        assert m._ha_agent_members_changed() is False

    assert m._ha_redeploy_fence_agents('test') == {} and m.installs == []


def test_the_monitor_brings_the_agents_up_to_date_when_it_starts(monkeypatch):
    """Every new leader starts the HA monitor: that is the pass "once after each new
    leader boots". It only ran `systemctl start` on the nodes."""
    started = []
    monkeypatch.setattr(manager_mod, 'threading', types.SimpleNamespace(
        Thread=lambda target=None, **kw: started.append(target) or MagicMock()))
    fake = MagicMock()
    fake.ha_thread = None
    fake.ha_config = {'storage_heartbeat_path': '/x', 'self_fence_installed': True}
    fake.config = types.SimpleNamespace(ha_settings={}, ha_enabled=False)
    fake._create_session.return_value.get.return_value.status_code = 500
    fake._ha_claim_enabled.return_value = False

    PegaProxManager.start_ha_monitor(fake)

    assert fake._ha_bring_up_fence_agents in started

    order = MagicMock()
    PegaProxManager._ha_bring_up_fence_agents(order)
    assert [c[0] for c in order.mock_calls] == ['_ha_start_self_fence_agents', '_ha_redeploy_fence_agents']


def test_the_monitor_looks_at_the_group_on_its_passes(monkeypatch):
    """A member paired or removed while the monitor runs: seen within a minute, without
    a word to a node until something changed."""
    monkeypatch.setattr(manager_mod, 'time', types.SimpleNamespace(sleep=lambda s: None))
    m = _mgr(self_fence_installed=True, fence_agent_members=[LEADER])
    monkeypatch.setattr(ha, 'own_url', lambda: LEADER)
    monkeypatch.setattr(ha, 'members', lambda: [])
    m.ha_enabled = True
    m.stop_event = types.SimpleNamespace(is_set=lambda: False)
    passes, redeployed = [], []

    def check():
        passes.append(1)
        if len(passes) == 7:
            monkeypatch.setattr(ha, 'members', lambda: [{'url': NEW}])
        m.ha_enabled = len(passes) < 18
    m._ha_check_nodes = check
    m._ha_update_fallback_hosts = lambda: None

    def redeploy(why):
        redeployed.append((len(passes), why))
        m.ha_config['fence_agent_members'] = m._ha_agent_members()
    m._ha_redeploy_in_background = redeploy

    m._ha_monitor_loop()

    # not on the first minute (nothing changed), once on the second, not again on the third
    assert len(passes) == 18 and redeployed == [(12, 'the PegaProx instances changed')]


# --- 5.5: the teardown keeps the recovery locks ------------------------------------------

def test_the_heartbeat_cleanup_leaves_a_recovery_lock_where_it_is(tmp_path):
    """The lock directory is per node name under .pegaprox, not per cluster. rm -rf on
    .pegaprox took the lock of a recovery that still ran, here or on another instance."""
    hb = tmp_path / 'shared' / '.pegaprox'
    (hb / 'recovery' / 'pve2').mkdir(parents=True)
    (hb / 'recovery' / 'pve3').mkdir()
    lock = hb / 'recovery' / 'pve2' / ('3-' + 'a' * 32)
    lock.write_text('{}')
    for name in ('heartbeat_node_pve1', 'poison_pve2', 'poison_ack_pve2', 'heartbeat_pegaprox_c1'):
        (hb / name).write_text('{}')

    out = subprocess.run(['bash', '-c', PegaProxManager._heartbeat_cleanup_cmd(str(hb))],
                         capture_output=True, text=True).stdout

    assert 'HEARTBEAT_DIR_CLEANED' in out
    assert lock.exists()
    assert sorted(p.name for p in hb.iterdir()) == ['recovery']
    assert sorted(p.name for p in (hb / 'recovery').iterdir()) == ['pve2']      # the empty one went

    # with the lock released nothing is left, the directory included
    lock.unlink()
    (hb / 'poison_pve2').write_text('{}')
    out = subprocess.run(['bash', '-c', PegaProxManager._heartbeat_cleanup_cmd(str(hb))],
                         capture_output=True, text=True).stdout
    assert 'HEARTBEAT_DIR_CLEANED' in out and not hb.exists()

    out = subprocess.run(['bash', '-c', PegaProxManager._heartbeat_cleanup_cmd(str(hb))],
                         capture_output=True, text=True).stdout
    assert 'HEARTBEAT_DIR_ABSENT' in out
