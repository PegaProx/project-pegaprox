"""What the ESXi import's planning step says about the target node (#1224).

  * a login the node refused came back as "qemu-img not detected": the tool check read
    every non-zero answer as a missing tool, and sent operators to apt instead of to SSH
  * the SSHFS mount runs on the node, and only PegaProx's own way to the ESXi host was
    tested; a firewall that let PegaProx in and not the node failed the mount much later
  * that mount failure did not say why: sshfs 3 sends the stderr of its ssh to /dev/null,
    and all that came back was "read: Connection reset by peer", or nothing at all when a
    filtered port outlasted the call's 30 s

These drive _run_v2p_migration with the hosts of tests/test_v2p_clone_delta_1124.py; the
node's commands that matter here run in a real bash on this machine. That harness holds the
clock (time.sleep and time.monotonic) while a run goes, and a child process is not waited
for under a held clock once gevent patched subprocess, so bash runs between two runs: the
first one hands over the commands, the second gets what bash answered to them.
MK
"""
import os
import shutil
import socket
import subprocess

import pytest

import pegaprox.core.v2p as v2p
from pegaprox.utils import ssh as ssh_mod
from test_v2p_clone_delta_1124 import Run


def _bash(cmd, timeout=30, path=None, cwd=None):
    env = dict(os.environ, LC_ALL='C')
    if path:
        env['PATH'] = f"{path}{os.pathsep}{env.get('PATH', '')}"
    p = subprocess.run(['bash', '-c', cmd], capture_output=True, text=True, timeout=timeout,
                       env=env, cwd=cwd)
    return p.returncode, p.stdout, p.stderr


def _closed_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Node:
    """The target node: the harness's answers, except for the commands a test takes over.
    `tool_probe`, `tcp_probe` and `mount` are callables (cmd, timeout) -> (rc, out, err)."""

    def __init__(self, run, tool_probe=None, tcp_probe=None, mount=None):
        self.run = run
        self.tool_probe, self.tcp_probe, self.mount = tool_probe, tcp_probe, mount
        self.sent = []

    def __call__(self, mgr, node, cmd, timeout=600, **kw):
        self.sent.append((node, cmd))
        if self.tool_probe and 'for d in /usr/local/sbin' in cmd:
            return self.tool_probe(cmd, timeout)
        if self.tcp_probe and '/dev/tcp/' in cmd:
            return self.tcp_probe(cmd, timeout)
        if self.mount and 'sshfs -o password_stdin' in cmd:
            return self.mount(cmd, timeout)
        return self.run.node(mgr, node, cmd, timeout, **kw)

    def count(self, needle):
        return sum(1 for _n, c in self.sent if needle in c)


def _sent_by_a_run(key, answer=(0, '', '')):
    """Every command a run sends for `key` ('tool_probe', 'tcp_probe', 'mount'), from a run
    of its own that gets `answer` to each."""
    sent = []
    with pytest.MonkeyPatch.context() as mp:
        _run(mp, **{key: lambda cmd, t: sent.append(cmd) or answer}).go()
    assert sent, f'no {key} was sent'
    return sent


def _run(monkeypatch, **node_kw):
    r = Run(monkeypatch)
    created = []
    real_post = r.pve._api_post

    def post(url, data=None, **kw):
        if url.endswith('/qemu'):
            created.append(url)
        return real_post(url, data=data, **kw)
    r.pve._api_post = post
    r.created = created
    r.target = Node(r, **node_kw)
    monkeypatch.setattr(v2p, '_pve_node_exec', r.target)
    return r


# --- the tool check ---------------------------------------------------------------------

REFUSED = ("cannot run node commands on 'pve1': the stored SSH key was refused for 'root' "
           "(Authentication failed.), and this cluster authenticates with an API token")


@pytest.mark.parametrize('answer', [
    (1, '', REFUSED),
    (255, '', 'root@10.0.0.7: Permission denied (publickey).'),
    (1, '', "node 'pve1' in circuit-breaker backoff (55s remaining)"),
])
def test_a_probe_that_never_ran_is_reported_as_ssh_and_not_as_a_missing_tool(monkeypatch, answer):
    r = _run(monkeypatch, tool_probe=lambda cmd, t: answer).go()
    assert r.task.status == 'failed'
    assert 'qemu-img not detected' not in r.task.error
    assert 'over SSH' in r.task.error and answer[2][:40] in r.task.error, r.task.error
    # one sentence ends once, also where the node's own answer ended in a full stop
    assert '..' not in r.task.error, r.task.error
    # one refused login is enough to know; the other three tools are not probed into it
    assert r.target.count('for d in /usr/local/sbin') == 1
    assert r.created == []


def test_the_tool_check_still_tells_a_missing_tool(monkeypatch):
    """The probe itself, run in bash: a qemu-img that is not there says so, the others are
    found. The same run with the node refusing the login is an SSH failure."""
    probe = _sent_by_a_run('tool_probe')[0]
    assert 'command -v qemu-img ' in probe
    missing = _bash(probe.replace('qemu-img', 'qemu-img-absent-1224'))
    r = _run(monkeypatch, tool_probe=lambda cmd, t: missing if 'qemu-img ' in cmd else (0, '', '')).go()
    assert r.task.status == 'failed'
    assert r.task.error.startswith('qemu-img not detected'), r.task.error
    assert any('Tools missing: qemu-img' in line for line in r.task.log_lines)

    refused = _run(monkeypatch, tool_probe=lambda cmd, t: (1, '', REFUSED)).go()
    assert 'qemu-img not detected' not in refused.task.error
    assert 'over SSH' in refused.task.error


def test_an_import_offers_the_stored_key_again_though_it_was_refused_a_minute_ago(monkeypatch):
    """A console tile saw the key refused and node commands skip it for five minutes. The
    operator fixes authorized_keys and starts the import: its first probe offers the key
    again instead of failing with 'offered again in 240s'."""
    seen = []

    def probe(cmd, t):
        seen.append(dict(ssh_mod._node_key_refused))
        return 0, '', ''
    r = _run(monkeypatch, tool_probe=probe)
    slot = (getattr(r.pve, 'id', None), 'pve1')
    monkeypatch.setattr(ssh_mod, '_node_key_refused',
                        {slot: (0.0, 'digest', 'Authentication failed.', '10.0.0.7'),
                         (slot[0], 'pve2'): (0.0, 'digest', 'Authentication failed.', '10.0.0.8')})
    r.go()
    assert seen, 'no tool probe ran'
    assert slot not in seen[0], 'the import started with the refusal of its target node still standing'
    # another node's refusal is no business of this import
    assert (slot[0], 'pve2') in seen[0]


# --- the node's way to the ESXi host ----------------------------------------------------------

def _tcp_to(port):
    """What the node's probe says in bash, aimed at a port on this machine."""
    probe = _sent_by_a_run('tcp_probe')[0]
    assert ' _ esx1.lab 22 ' in probe, probe
    answer = _bash(probe.replace(' _ esx1.lab 22 ', f' _ 127.0.0.1 {port} '))
    return lambda cmd, timeout: answer


def test_a_node_the_esxi_host_refuses_fails_the_planning_with_that_reason(monkeypatch):
    r = _run(monkeypatch, tcp_probe=_tcp_to(_closed_port())).go()
    assert r.task.status == 'failed'
    err = r.task.error
    assert 'pve1' in err and 'esx1.lab' in err and 'port 22' in err
    assert 'refused' in err.lower(), err
    # before anything was created or mounted
    assert r.created == [] and r.target.count('sshfs -o password_stdin') == 0
    # asked of the target node
    assert [n for n, c in r.target.sent if '/dev/tcp/' in c] == ['pve1']


def test_a_filtered_port_is_named_as_such(monkeypatch):
    """A port the ESXi firewall drops has no answer: coreutils' timeout ends the probe."""
    r = _run(monkeypatch, tcp_probe=lambda cmd, t: (0, 'V2P_TCP_RC=124\n', '')).go()
    assert r.task.status == 'failed'
    assert 'cannot reach esx1.lab on port 22 (no answer within 5s)' in r.task.error
    assert r.created == []


def test_a_reachable_port_lets_the_import_go_on(monkeypatch):
    srv = socket.socket()
    srv.bind(('127.0.0.1', 0))
    srv.listen(4)
    try:
        r = _run(monkeypatch, tcp_probe=_tcp_to(srv.getsockname()[1])).go()
    finally:
        srv.close()
    assert r.task.status == 'completed', r.task.error
    assert any('Port 22 of esx1.lab reachable from pve1' in line for line in r.task.log_lines)


@pytest.mark.parametrize('host', ['fe80::1%;touch pwned1224;', 'fe80::1%$(touch pwned1224)'])
def test_the_esxi_address_is_no_part_of_a_script_the_node_parses(monkeypatch, tmp_path, host):
    """The probe is a bash -c inside the node's own shell, so its script is parsed twice.
    An IPv6 zone id passes validate_host_address with any character in it; as an argument
    of the inner bash it stays an address that does not resolve."""
    from pegaprox.utils.sanitization import validate_host_address
    assert validate_host_address(host), 'the address no longer gets this far, the test proves nothing'
    ran = []

    def node(mgr, n, cmd, timeout=600, **kw):
        ran.append(cmd)
        return _bash(cmd, cwd=str(tmp_path))
    monkeypatch.setattr(v2p, '_pve_node_exec', node)
    why = v2p._node_cannot_reach(object(), 'pve1', host, 22, wait=2)
    assert ran
    assert not (tmp_path / 'pwned1224').exists(), f'the node ran what the address held: {ran[0]}'
    assert why, 'an address that does not resolve was taken as reachable'


# --- the SSHFS mount ---------------------------------------------------------------------

SSH_SAID = 'ssh: connect to host esx1.lab port 22: Connection timed out'

# sshfs 3.7.3 on FUSE 3 (Debian bookworm and trixie, so PVE 8 and 9), as it behaves against
# a host its ssh cannot reach: big_writes and large_read, which FUSE 3 dropped, end it at
# once; else the ssh it starts writes its reason to the file of its -E or to /dev/null,
# and sshfs itself says only that the channel went away
FAKE_SSHFS = r'''#!/bin/sh
log=
for a in "$@"; do
  case "$a" in
    *big_writes*|*large_read*) echo "fuse: unknown option(s): \`-o big_writes,large_read'" >&2; exit 1 ;;
    "ssh_command=ssh -E "*) log=${a#ssh_command=ssh -E } ;;
  esac
done
[ -n "$log" ] && echo "%s" >> "$log"
echo "read: Connection reset by peer" >&2
exit 1
''' % SSH_SAID


def _on_this_machine(cmd, tmp_path):
    """A mount command as it runs here: its mount point and its temp file under tmp_path."""
    assert '/tmp/v2p-m1124 ' in cmd and 'mktemp /tmp/' in cmd, cmd
    return (cmd.replace('/tmp/v2p-m1124', str(tmp_path / 'mnt'))
               .replace('mktemp /tmp/', f'mktemp {tmp_path}/'))


def _mount_answers(tmp_path, bin_dir=None, rewrite=lambda c: c):
    """What the node says to each of a run's three mount attempts, from bash."""
    sent = _sent_by_a_run('mount', answer=(1, '', ''))
    assert len(sent) == 3, sent
    return [_bash(rewrite(_on_this_machine(c, tmp_path)), path=bin_dir) for c in sent]


def _replay(monkeypatch, answers):
    it = iter(answers)
    return _run(monkeypatch, mount=lambda cmd, t: next(it)).go()


def test_the_mount_failure_says_why_ssh_on_the_node_gave_up(monkeypatch, tmp_path):
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir()
    (bin_dir / 'sshfs').write_text(FAKE_SSHFS)
    (bin_dir / 'sshfs').chmod(0o755)
    answers = _mount_answers(tmp_path, str(bin_dir))
    r = _replay(monkeypatch, answers)
    assert r.task.status == 'failed'
    assert r.task.error == f'SSHFS mount failed: {SSH_SAID}', r.task.error
    log = '\n'.join(r.task.log_lines)
    assert 'SSHFS mount attempt 1/3 failed, trying fewer options: fuse: unknown option' in log
    assert 'SSHFS mount attempt 2/3 failed, trying fewer options: fuse: unknown option' in log
    # ssh's file is gone again, the mount failed or not
    assert not list(tmp_path.glob('v2p-sshfs-*'))


@pytest.mark.skipif(not shutil.which('sshfs'), reason='sshfs is not installed here')
def test_the_mount_failure_says_why_with_the_real_sshfs(monkeypatch, tmp_path):
    """The same with the sshfs of this machine against a port nobody listens on."""
    port = _closed_port()
    answers = _mount_answers(tmp_path, rewrite=lambda c: c.replace(
        'root@esx1.lab:', f'-p {port} root@127.0.0.1:'))
    r = _replay(monkeypatch, answers)
    assert r.task.status == 'failed'
    assert r.task.error.startswith('SSHFS mount failed: '), r.task.error
    assert f'ssh: connect to host 127.0.0.1 port {port}: Connection refused' in r.task.error, r.task.error
    assert not list(tmp_path.glob('v2p-sshfs-*'))


def test_each_mount_attempt_logs_its_own_answer(monkeypatch):
    """The ESXi login refused, then a last attempt that says nothing: the log has each
    answer, and the failure keeps the one that named the cause."""
    answers = iter([(1, '', 'read: Connection reset by peer\nroot@esx1.lab: Permission denied (keyboard-interactive).'),
                    (1, '', 'fuse: bad mount point'),
                    (1, '', '')])
    r = _run(monkeypatch, mount=lambda cmd, t: next(answers)).go()
    log = '\n'.join(r.task.log_lines)
    assert 'SSHFS mount attempt 1/3 failed, trying fewer options: root@esx1.lab: Permission denied' in log
    assert 'SSHFS mount attempt 2/3 failed, trying fewer options: fuse: bad mount point' in log
    assert r.task.error == 'SSHFS mount failed: fuse: bad mount point'
