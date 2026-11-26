# The temporary key a migration puts on ESXi is taken away again with grep -v and a swap of the
# file. grep -v answers 1 when no line is left, and no line is left when our key was the only
# one in the file, which it is on an ESXi host nobody put a key on: the swap was chained with
# && and never ran. The key stayed authorized, its filtered copy stayed next to it, and the
# run said CLEANED anyway, so nothing warned.
#
# A bulk run migrates up to five VMs of one host at once. Two removals read the file, the first
# moved its copy over it, the second moved its own copy (still holding the first key) over that:
# the first key was authorized again, after its run had said CLEANED. A key added between the
# read and the move of a removal was lost the same way. Both now wait for a lock on ESXi.
#
# The removal runs here in a real shell against real files, the way the ESXi shell runs it.

import logging
import os
import re
import shutil
import subprocess
import threading
import time

import pytest

from pegaprox.core import v2p

KEY_ID = 'a1b2c3d4'
OURS = f'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOurs pegaprox-v2p-{KEY_ID}'
ADMIN = 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCadmin admin@laptop'
OTHER_RUN = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOther pegaprox-v2p-ffff0000'
LOCK = '/tmp/pegaprox-v2p-keys.lock'

# ESXi runs busybox ash; the system sh stands in where busybox is missing
SHELLS = [s for s in (('busybox', 'sh'), ('sh',)) if shutil.which(s[0])]


class Esxi:
    """A host root with /etc/ssh/keys-root, a home directory and a /tmp, and the cleanup (and the
    key deploy) run against it. `shims` is a directory put first on PATH; busybox sh runs its own
    applets, so only the system sh goes through it."""

    def __init__(self, tmp_path, monkeypatch, shell):
        self.root = tmp_path
        self.home = tmp_path / 'home'
        self.keys = tmp_path / 'etc' / 'ssh' / 'keys-root' / 'authorized_keys'
        self.dot = self.home / '.ssh' / 'authorized_keys'
        self.lock = tmp_path / 'tmp' / 'pegaprox-v2p-keys.lock'
        self.keys.parent.mkdir(parents=True)
        self.home.mkdir()
        self.lock.parent.mkdir()
        self.shell = shell
        self.shims = None
        self.output = None
        self.outputs = {}
        self.deployed = []
        monkeypatch.setattr(v2p, '_pve_node_exec', self._node)
        monkeypatch.setattr(v2p, '_ssh_exec', self._esxi_login)

    def _run(self, script):
        script = script.replace('/etc/ssh/', f'{self.root}/etc/ssh/').replace(LOCK, str(self.lock))
        path = os.environ['PATH'] if not self.shims else f'{self.shims}:{os.environ["PATH"]}'
        return subprocess.run([*self.shell, '-c', script], capture_output=True, text=True, timeout=30,
                              env={'HOME': str(self.home), 'PATH': path})

    def _node(self, mgr, node, cmd, timeout=600, **kw):
        if cmd.startswith('cat /tmp/v2p-key-') and cmd.endswith('.pub'):
            key_id = cmd[len('cat /tmp/v2p-key-'):-len('.pub')]
            return 0, f'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINew pegaprox-v2p-{key_id}\n', ''
        if not cmd.startswith('ssh '):
            return 0, '', ''      # the key files on the node: keygen, rm, the ssh config
        start = cmd.index("root@esxi.lab '") + len("root@esxi.lab '")
        script = cmd[start:cmd.rindex("' 2>&1")]
        p = self._run(script)
        out = p.stdout + p.stderr
        m = re.search(r'"pegaprox-v2p-([\w-]+)"', script)    # the lock is named pegaprox-v2p- too
        if m:
            self.output = self.outputs[m.group(1)] = out
        return p.returncode, p.stdout, p.stderr

    def _esxi_login(self, host, user, password, cmd, timeout=30, **kw):
        # the deploy logs in with the password (paramiko), the shell is the same
        if cmd == 'echo SSH_OK':
            return 0, 'SSH_OK\n', ''
        p = self._run(cmd)
        return p.returncode, p.stdout, p.stderr

    def clean(self, key_id=KEY_ID):
        v2p._cleanup_temp_ssh_key(None, 'pve1', f'/tmp/v2p-key-{key_id}', 'esxi.lab', 'root')

    def deploy(self):
        self.deployed.append(v2p._setup_temp_ssh_key(None, 'pve1', 'esxi.lab', 'root', 'pw'))

    def shim(self, name, body):
        if not self.shims:
            self.shims = self.root / 'shims'
            self.shims.mkdir()
        f = self.shims / name
        f.write_text('#!/bin/sh\n' + body)
        f.chmod(0o755)

    def leftovers(self):
        return sorted(str(p.relative_to(self.root)) for p in self.root.rglob(f'*.{KEY_ID}'))


def _in_thread(fn, *a):
    t = threading.Thread(target=fn, args=a, daemon=True)
    t.start()
    return t


@pytest.fixture(params=SHELLS, ids=[' '.join(s) for s in SHELLS])
def esxi(request, tmp_path, monkeypatch):
    return Esxi(tmp_path, monkeypatch, request.param)


def test_our_key_alone_in_the_file_is_taken_away(esxi, caplog):
    esxi.keys.write_text(OURS + '\n')
    with caplog.at_level(logging.WARNING):
        esxi.clean()
    assert f'pegaprox-v2p-{KEY_ID}' not in esxi.keys.read_text()
    assert esxi.leftovers() == []
    assert 'CLEANED' in esxi.output
    assert 'temporary migration key' not in caplog.text


def test_the_keys_of_others_stay_in_their_order(esxi):
    esxi.keys.write_text('\n'.join([ADMIN, OURS, OTHER_RUN]) + '\n')
    esxi.clean()
    assert esxi.keys.read_text() == ADMIN + '\n' + OTHER_RUN + '\n'
    assert esxi.leftovers() == []


def test_the_key_goes_from_both_places(esxi):
    esxi.keys.write_text(OURS + '\n')
    esxi.dot.parent.mkdir()
    esxi.dot.write_text(ADMIN + '\n' + OURS + '\n')
    esxi.clean()
    assert esxi.keys.read_text() == ''
    assert esxi.dot.read_text() == ADMIN + '\n'
    assert esxi.leftovers() == []
    assert 'CLEANED' in esxi.output


def test_a_host_without_the_files_has_nothing_to_take_away(esxi):
    esxi.clean()
    assert 'CLEANED' in esxi.output
    assert not esxi.keys.exists() and not esxi.dot.exists()


def test_a_key_that_stays_is_said_to_stay(esxi, caplog):
    """The filtered copy cannot be written (a directory sits on its name): the key is still
    there, so the run must not call it removed."""
    esxi.keys.write_text(ADMIN + '\n' + OURS + '\n')
    (esxi.keys.parent / f'authorized_keys.{KEY_ID}').mkdir()
    with caplog.at_level(logging.WARNING):
        esxi.clean()
    assert OURS in esxi.keys.read_text()
    assert 'CLEANED' not in esxi.output
    assert 'could not remove the temporary migration key' in caplog.text


@pytest.fixture
def dash_esxi(tmp_path, monkeypatch):
    """The system sh, which runs grep, rmdir and sleep from PATH, so a shim can slow them down."""
    return Esxi(tmp_path, monkeypatch, ('sh',))


def test_a_removal_waits_while_another_holds_the_lock(esxi):
    """Another run is between its read and its move: ours does not touch the file until the
    lock is given back, then takes it, removes the key and gives the lock back."""
    esxi.keys.write_text(ADMIN + '\n' + OURS + '\n')
    esxi.lock.mkdir()
    t = _in_thread(esxi.clean)
    time.sleep(2)
    assert esxi.keys.read_text() == ADMIN + '\n' + OURS + '\n', 'the removal wrote while the lock was held'
    assert t.is_alive()
    esxi.lock.rmdir()
    t.join(30)
    assert esxi.keys.read_text() == ADMIN + '\n'
    assert 'CLEANED' in esxi.output
    assert not esxi.lock.exists()


def test_two_removals_at_once_leave_neither_key(dash_esxi, caplog):
    """Both runs read the file before either moved its copy over it: the second copy still held
    the first key and put it back, after its run had said CLEANED."""
    e = dash_esxi
    real = shutil.which('grep')
    e.shim('grep', f'{real} "$@"; rc=$?\ncase "$1" in -v) sleep 1;; esac\nexit $rc\n')
    e.keys.write_text('\n'.join([ADMIN, OURS, OTHER_RUN]) + '\n')
    with caplog.at_level(logging.WARNING):
        first = _in_thread(e.clean, KEY_ID)
        time.sleep(0.2)
        second = _in_thread(e.clean, 'ffff0000')
        first.join(30)
        second.join(30)
    assert e.keys.read_text() == ADMIN + '\n'
    assert 'CLEANED' in e.outputs[KEY_ID] and 'CLEANED' in e.outputs['ffff0000']
    assert 'temporary migration key' not in caplog.text
    assert not e.lock.exists()


def test_a_key_added_during_a_removal_stays(dash_esxi):
    """A run starts on the host while another takes its key away: the append landed between the
    read and the move of the removal and went with the move, so the new run's key was gone."""
    e = dash_esxi
    real = shutil.which('grep')
    e.shim('grep', f'{real} "$@"; rc=$?\ncase "$1" in -v) sleep 1;; esac\nexit $rc\n')
    e.keys.write_text(ADMIN + '\n' + OURS + '\n')
    removal = _in_thread(e.clean, KEY_ID)
    time.sleep(0.2)
    deploy = _in_thread(e.deploy)
    removal.join(30)
    deploy.join(30)
    lines = e.keys.read_text().splitlines()
    assert e.deployed and e.deployed[0], 'the deploy did not finish'
    new_id = e.deployed[0][len('/tmp/v2p-key-'):]
    assert lines[0] == ADMIN and OURS not in lines
    assert any(line.endswith(f'pegaprox-v2p-{new_id}') for line in lines), lines
    assert 'CLEANED' in e.outputs[KEY_ID]
    assert not e.lock.exists()


def test_a_key_is_added_only_once_the_lock_is_free(esxi):
    esxi.keys.write_text(ADMIN + '\n')
    esxi.lock.mkdir()
    t = _in_thread(esxi.deploy)
    time.sleep(2)
    assert esxi.keys.read_text() == ADMIN + '\n', 'the key was added while the lock was held'
    esxi.lock.rmdir()
    t.join(30)
    assert esxi.deployed and esxi.deployed[0]
    lines = esxi.keys.read_text().splitlines()
    assert len(lines) == 2 and lines[1].startswith('ssh-ed25519 ') and 'pegaprox-v2p-' in lines[1]
    assert not esxi.lock.exists()


def test_a_lock_left_by_a_dead_shell_is_taken_over(esxi):
    esxi.keys.write_text(ADMIN + '\n' + OURS + '\n')
    esxi.lock.mkdir()
    old = time.time() - 300
    os.utime(esxi.lock, (old, old))
    t0 = time.monotonic()
    esxi.clean()
    assert time.monotonic() - t0 < 8
    assert esxi.keys.read_text() == ADMIN + '\n'
    assert 'CLEANED' in esxi.output
    assert not esxi.lock.exists()


def test_a_lock_nobody_gives_back_ends_the_wait_and_stays_theirs(dash_esxi):
    """The wait is about ten seconds. After it the key goes anyway, an authorized key left on
    ESXi is worse, and the lock of the other run is not ours to remove."""
    e = dash_esxi
    naps = e.root / 'naps'
    e.shim('sleep', f'echo "$1" >> {naps}\n')
    e.keys.write_text(ADMIN + '\n' + OURS + '\n')
    e.lock.mkdir()
    e.clean()
    waited = sum(float(x) for x in naps.read_text().split())
    assert 5 <= waited <= 15, waited
    assert e.keys.read_text() == ADMIN + '\n'
    assert 'CLEANED' in e.output
    assert e.lock.is_dir()


def test_cleaned_is_the_state_after_the_lock_is_given_back(dash_esxi, caplog):
    """Something puts our key back right after the lock is free (a removal of an older PegaProx,
    which takes no lock): the run must not call it removed."""
    e = dash_esxi
    real = shutil.which('rmdir')
    e.shim('rmdir', f'{real} "$@" || exit $?\n'
                    f'case "$1" in *pegaprox-v2p-keys.lock) echo "{OURS}" >> {e.keys};; esac\n')
    e.keys.write_text(ADMIN + '\n' + OURS + '\n')
    with caplog.at_level(logging.WARNING):
        e.clean()
    assert OURS in e.keys.read_text()
    assert 'CLEANED' not in e.output
    assert 'could not remove the temporary migration key' in caplog.text


def test_the_removal_is_one_argument_for_the_esxi_shell(monkeypatch):
    """The script travels to ESXi inside single quotes: none of its own may end them early."""
    cmds = []
    monkeypatch.setattr(v2p, '_pve_node_exec', lambda m, n, c, timeout=600, **k: cmds.append(c) or (0, 'CLEANED', ''))
    v2p._cleanup_temp_ssh_key(None, 'pve1', f'/tmp/v2p-key-{KEY_ID}', 'esxi.lab', 'root')
    ssh = [c for c in cmds if c.startswith('ssh ')][0]
    script = ssh[ssh.index("root@esxi.lab '") + len("root@esxi.lab '"):ssh.rindex("' 2>&1")]
    assert "'" not in script
    assert LOCK in script
