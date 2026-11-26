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
# The lock of a shell that died with it is taken over. That was "looks stale, rmdir": two
# waiters at the same dead lock, the first broke it and took a new one, the second's rmdir
# removed that new one and both rewrote at once. And a dead holder's lock younger than the stale
# age made every run wait ten seconds and rewrite without it. The holder's file in the lock now
# changes hands with one rename, and the removal never rewrites without the lock.
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
        self.env = {}           # key id -> extra environment of that removal's shell
        monkeypatch.setattr(v2p, '_pve_node_exec', self._node)
        monkeypatch.setattr(v2p, '_ssh_exec', self._esxi_login)

    def _run(self, script, extra=None):
        script = script.replace('/etc/ssh/', f'{self.root}/etc/ssh/').replace(LOCK, str(self.lock))
        path = os.environ['PATH'] if not self.shims else f'{self.shims}:{os.environ["PATH"]}'
        return subprocess.run([*self.shell, '-c', script], capture_output=True, text=True, timeout=120,
                              env={'HOME': str(self.home), 'PATH': path, **(extra or {})})

    def _node(self, mgr, node, cmd, timeout=600, **kw):
        if cmd.startswith('cat /tmp/v2p-key-') and cmd.endswith('.pub'):
            key_id = cmd[len('cat /tmp/v2p-key-'):-len('.pub')]
            return 0, f'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINew pegaprox-v2p-{key_id}\n', ''
        if not cmd.startswith('ssh '):
            return 0, '', ''      # the key files on the node: keygen, rm, the ssh config
        start = cmd.index("root@esxi.lab '") + len("root@esxi.lab '")
        script = cmd[start:cmd.rindex("' 2>&1")]
        m = re.search(r'"pegaprox-v2p-([\w-]+)"', script)    # the lock is named pegaprox-v2p- too
        key = m.group(1) if m else None
        p = self._run(script, self.env.get(key))
        out = p.stdout + p.stderr
        if key:
            self.output = self.outputs[key] = out
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

    def slow(self, name):
        """name does what it did, then naps $SLOW_<NAME> seconds when a run has that set and the
        call went to the lock and worked: the run acts on what it saw before the nap."""
        real = shutil.which(name)
        var = 'SLOW_' + name.upper()
        self.shim(name, f'{real} "$@"; rc=$?\n'
                        f'case "$*" in *pegaprox-v2p-keys.lock*) '
                        f'[ $rc -eq 0 ] && [ -n "${var}" ] && sleep "${var}";; esac\n'
                        'exit $rc\n')

    def clock(self, start, step):
        """date +%s gives start, then start+step, start+2*step, ... (step 0: the clock stands)."""
        tick = self.root / 'clock'
        tick.write_text(str(start))
        self.shim('date', f'case "$1" in +%s) ;; *) exec {shutil.which("date")} "$@";; esac\n'
                          f'n=$(cat {tick}); echo $((n+{step})) > {tick}; echo $n\n')

    def naps(self):
        """sleep returns at once and notes how long it was asked to take."""
        naps = self.root / 'naps'
        self.shim('sleep', f'echo "$1" >> {naps}\n')
        return lambda: sum(float(x) for x in naps.read_text().split()) if naps.exists() else 0.0

    def held_by(self, epoch, pid=99999):
        """The lock as a holder leaves it: the directory with the holder's file in it."""
        self.lock.mkdir()
        (self.lock / f'o.{epoch}.{pid}').write_text('')

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
    """An empty lock five minutes old: a shell died between its mkdir and its file."""
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


def test_the_lock_of_a_holder_that_died_with_it_changes_hands(esxi):
    """A shell died while it held the lock: its file is five minutes old. The lock passes to
    the removal at once instead of after a wait and a rewrite without it."""
    esxi.keys.write_text(ADMIN + '\n' + OURS + '\n')
    esxi.held_by(int(time.time()) - 300)
    t0 = time.monotonic()
    esxi.clean()
    assert time.monotonic() - t0 < 8
    assert esxi.keys.read_text() == ADMIN + '\n'
    assert 'CLEANED' in esxi.output
    assert not esxi.lock.exists()


def _slow_rewrite(e, seconds=1.5):
    real = shutil.which('grep')
    e.shim('grep', f'{real} "$@"; rc=$?\ncase "$1" in -v) sleep {seconds};; esac\nexit $rc\n')


def _late_then_early(e, caplog):
    """The removal of OTHER_RUN looks at the lock first and acts late, ours comes a moment
    later and acts at once."""
    with caplog.at_level(logging.WARNING):
        late = _in_thread(e.clean, 'ffff0000')
        time.sleep(0.15)
        early = _in_thread(e.clean, KEY_ID)
        late.join(60)
        early.join(60)
    assert not late.is_alive() and not early.is_alive()


def test_two_waiters_at_a_dead_lock_do_not_both_take_it(dash_esxi, caplog):
    """Both waiters see the same dead lock. Ours breaks it and takes a new one, the other acts
    on what it saw before its find came back: its rmdir removed our new lock, both rewrote at
    once, and the removed key was authorized again after both runs had said CLEANED."""
    e = dash_esxi
    e.slow('find')
    _slow_rewrite(e)
    e.keys.write_text('\n'.join([ADMIN, OURS, OTHER_RUN]) + '\n')
    e.lock.mkdir()
    old = time.time() - 300
    os.utime(e.lock, (old, old))
    e.env['ffff0000'] = {'SLOW_FIND': '0.5'}
    _late_then_early(e, caplog)
    assert e.keys.read_text() == ADMIN + '\n'
    assert 'CLEANED' in e.outputs[KEY_ID] and 'CLEANED' in e.outputs['ffff0000']
    assert 'temporary migration key' not in caplog.text
    assert not e.lock.exists()


def test_two_waiters_at_a_dead_holders_lock_hand_it_on_once(dash_esxi, caplog):
    """The holder died with the lock and its file names it. Both waiters see that file, only
    one rename can find it: the other waits for the new holder instead of rewriting next to it."""
    e = dash_esxi
    e.slow('ls')
    _slow_rewrite(e)
    e.keys.write_text('\n'.join([ADMIN, OURS, OTHER_RUN]) + '\n')
    e.held_by(int(time.time()) - 300)
    old = time.time() - 300
    os.utime(e.lock, (old, old))
    e.env['ffff0000'] = {'SLOW_LS': '0.5'}
    _late_then_early(e, caplog)
    assert e.keys.read_text() == ADMIN + '\n'
    assert 'CLEANED' in e.outputs[KEY_ID] and 'CLEANED' in e.outputs['ffff0000']
    assert 'temporary migration key' not in caplog.text
    assert not e.lock.exists()


def test_a_fresh_lock_before_its_file_is_written_is_not_shared(dash_esxi, caplog):
    """An empty dead lock is still taken away with rmdir, and that rmdir can meet the fresh lock
    of a waiter that has made its directory but not yet its file. Here ours is that slow waiter:
    the other one removes our directory and makes its own, our file lands next to its file, and
    we back off instead of rewriting at the same time."""
    e = dash_esxi
    e.slow('find')
    e.slow('mkdir')
    _slow_rewrite(e)
    e.keys.write_text('\n'.join([ADMIN, OURS, OTHER_RUN]) + '\n')
    e.lock.mkdir()
    old = time.time() - 300
    os.utime(e.lock, (old, old))
    e.env['ffff0000'] = {'SLOW_FIND': '0.5'}
    e.env[KEY_ID] = {'SLOW_MKDIR': '1'}
    _late_then_early(e, caplog)
    assert e.keys.read_text() == ADMIN + '\n'
    assert 'CLEANED' in e.outputs[KEY_ID] and 'CLEANED' in e.outputs['ffff0000']
    assert 'temporary migration key' not in caplog.text
    assert not e.lock.exists()


def test_a_dead_holders_young_lock_is_waited_out_not_skipped(dash_esxi):
    """The holder died a moment ago, its lock is younger than the stale age. Every removal
    waited ten seconds and then rewrote with that lock still in place. It now waits until the
    lock is past the stale age, takes it over, and only then rewrites. One clock second per
    round here, sleep returns at once."""
    e = dash_esxi
    now = int(time.time())
    e.clock(now, 1)
    waited = e.naps()
    seen = e.root / 'lock-during-rewrite'
    real = shutil.which('grep')
    e.shim('grep', f'{real} "$@"; rc=$?\ncase "$1" in -v) ls {e.lock} >> {seen} 2>&1;; esac\nexit $rc\n')
    e.keys.write_text(ADMIN + '\n' + OURS + '\n')
    e.held_by(now)
    e.clean()
    held = seen.read_text().split()
    assert len(held) == 1 and not held[0].endswith('.99999'), f'rewrote while the lock was {held}'
    assert re.fullmatch(r'o\.\d+\.\d+', held[0]), held
    assert int(held[0].split('.')[1]) - now > v2p._ESXI_KEYS_LOCK_STALE
    assert waited() >= 25
    assert e.keys.read_text() == ADMIN + '\n'
    assert 'CLEANED' in e.output
    assert not e.lock.exists()


def test_a_lock_held_through_the_whole_wait_leaves_the_key_and_says_so(dash_esxi, caplog):
    """Another run keeps the lock through the whole wait (the clock stands still here, so its
    lock never ages). The removal gave up after ten seconds and rewrote anyway, the race the lock
    is there for. It now waits past the stale age, leaves the files alone, and the run reports
    the key as maybe left; the lock stays the other run's."""
    e = dash_esxi
    now = int(time.time())
    e.clock(now, 0)
    waited = e.naps()
    e.keys.write_text(ADMIN + '\n' + OURS + '\n')
    e.held_by(now, 4242)
    with caplog.at_level(logging.WARNING):
        e.clean()
    assert e.keys.read_text() == ADMIN + '\n' + OURS + '\n', 'rewrote without the lock'
    assert 'CLEANED' not in e.output
    assert 'stays held by another run' in e.output
    assert 'could not remove the temporary migration key' in caplog.text
    assert waited() > v2p._ESXI_KEYS_LOCK_STALE
    assert os.listdir(e.lock) == [f'o.{now}.4242']
    assert e.leftovers() == []


def test_a_deploy_appends_once_the_wait_is_over(dash_esxi):
    """An append cannot bring a removed key back and no removal rewrites without the lock, so a
    deploy that could not have the lock within the wait adds its key all the same."""
    e = dash_esxi
    now = int(time.time())
    e.clock(now, 0)
    waited = e.naps()
    e.keys.write_text(ADMIN + '\n')
    e.held_by(now, 4242)
    e.deploy()
    assert e.deployed and e.deployed[0]
    lines = e.keys.read_text().splitlines()
    assert len(lines) == 2 and lines[0] == ADMIN and 'pegaprox-v2p-' in lines[1]
    assert waited() > v2p._ESXI_KEYS_LOCK_STALE
    assert os.listdir(e.lock) == [f'o.{now}.4242']


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
