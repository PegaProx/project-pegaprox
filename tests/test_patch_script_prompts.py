"""web/Dev/patch.sh asks its questions on the terminal when it is piped into bash.

Its usage line is `curl -sSL .../patch.sh | sudo bash`. There bash reads the script from
stdin, so the read for the install directory found the end of the script, failed, and set -e
ended the run with exit 1 and no message before anything was patched. The prompts read from
/dev/tty now; with no terminal at all the script says to use --force instead of stopping
without a word.

The script is piped into bash as in its usage line, on a pseudo terminal, as root of a user
namespace (it refuses anyone else), with systemctl and the package tools stubbed. Every run
here ends at the directory check or with "n" at the confirmation, before the first change.

NS Nov 2026
"""
import os
import pty
import select
import shutil
import subprocess
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, 'web', 'Dev', 'patch.sh')
TOOLS = ('systemctl', 'apt-get', 'useradd', 'chown', 'sqlite3')


def _userns_root():
    if not shutil.which('unshare'):
        return False
    p = subprocess.run(['unshare', '-r', 'bash', '-c', 'echo $EUID'], capture_output=True, text=True)
    return p.returncode == 0 and p.stdout.strip() == '0'


pytestmark = pytest.mark.skipif(not _userns_root(), reason='needs unshare -r')


@pytest.fixture
def env(tmp_path):
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    log = tmp_path / 'calls.log'
    for tool in TOOLS:
        # systemctl is-active answers "inactive"; any other call is written down
        (bindir / tool).write_text(f'#!/bin/sh\necho "{tool} $*" >> "{log}"\n'
                                   + ('[ "$1" = is-active ] && exit 3\n' if tool == 'systemctl' else '')
                                   + 'exit 0\n')
        os.chmod(bindir / tool, 0o755)
    return {**os.environ, 'PATH': f'{bindir}:{os.environ["PATH"]}', 'TERM': 'dumb'}, log


def _piped(args):
    """`cat patch.sh | sudo bash -s -- args`, with root from a user namespace."""
    return ['bash', '-c', 'cat "$0" | unshare -r bash -s -- "$@"', SCRIPT, *args]


def _on_a_terminal(argv, env, answers, timeout=30):
    """Runs argv with a pseudo terminal as its controlling terminal and types each answer once
    its prompt shows. Returns the exit code and what the terminal showed."""
    pid, fd = pty.fork()
    if pid == 0:
        try:
            os.execvpe(argv[0], argv, env)
        finally:
            os._exit(127)
    out, typed = b'', 0
    pending = list(answers)
    deadline = time.monotonic() + timeout
    try:
        while time.monotonic() < deadline:
            ready, _, _ = select.select([fd], [], [], 0.2)
            if not ready:
                continue
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            out += chunk
            if pending and pending[0][0].encode() in out[typed:]:
                typed = len(out)
                os.write(fd, pending.pop(0)[1].encode() + b'\n')
    finally:
        os.close(fd)
    for _ in range(100):
        done, status = os.waitpid(pid, os.WNOHANG)
        if done:
            return os.waitstatus_to_exitcode(status), out.decode(errors='replace')
        time.sleep(0.05)
    os.kill(pid, 9)
    os.waitpid(pid, 0)
    pytest.fail(f'patch.sh did not end: {out[-500:]!r}')


def test_the_install_directory_is_asked_on_the_terminal(env, tmp_path):
    env, log = env
    inst = tmp_path / 'PegaProx'
    inst.mkdir()
    rc, shown = _on_a_terminal(_piped([]), env, [('Enter path [/opt/PegaProx]: ', str(inst))])
    assert f'Using: \x1b[0;36m{inst}' in shown, shown
    # an empty directory is no install, the run ends there
    assert f'PegaProx main file not found: {inst}/pegaprox_multi_cluster.py' in shown
    assert rc == 1
    assert not log.exists()


def test_the_confirmation_is_asked_on_the_terminal(env, tmp_path):
    env, log = env
    inst = tmp_path / 'PegaProx'
    inst.mkdir()
    (inst / 'pegaprox_multi_cluster.py').write_text('')
    rc, shown = _on_a_terminal(_piped([f'--dir={inst}']), env, [('Apply patch? [Y/n]: ', 'n')])
    assert 'Aborted.' in shown, shown
    assert rc == 0
    assert log.read_text().splitlines() == ['systemctl is-active --quiet pegaprox']


def _no_terminal(args, env):
    return subprocess.run(_piped(args), env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                          timeout=60, start_new_session=True)


NO_TERMINAL = 'No terminal to ask on - run it with --force (and --dir=PATH)'


def test_without_a_terminal_it_says_so_instead_of_asking_for_the_directory(env):
    env, log = env
    p = _no_terminal([], env)
    assert p.returncode == 1
    assert NO_TERMINAL in p.stdout, p.stdout + p.stderr
    assert 'Using:' not in p.stdout
    assert not log.exists()


def test_without_a_terminal_it_says_so_instead_of_asking_to_confirm(env, tmp_path):
    env, log = env
    inst = tmp_path / 'PegaProx'
    inst.mkdir()
    (inst / 'pegaprox_multi_cluster.py').write_text('')
    p = _no_terminal([f'--dir={inst}'], env)
    assert p.returncode == 1
    assert NO_TERMINAL in p.stdout, p.stdout + p.stderr
    assert log.read_text().splitlines() == ['systemctl is-active --quiet pegaprox']
