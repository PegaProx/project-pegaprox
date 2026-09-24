"""A managed node must not be able to hand us its output until we run out of memory.

`stdout.read()` on a paramiko ChannelFile reads to EOF. Every SSH call in the tree did
that - 55 sites across ten files - so one runaway command, one enormous log, or one node
somebody else controls took the hub's memory with it. It copies on a greenlet that yields
to nobody while it runs, so at 100 nodes that is the whole process, not one request.

The cap keeps draining past the limit rather than stopping dead: a far end blocked writing
into a full pipe never exits, and recv_exit_status() would hang behind it. It gives up at
ten times the limit, where the command is pathological rather than chatty; the channel
timeout bounds the wall clock either way.

Aikido ai_pentest 700488504 / 700489243 / 700487220 and the rest of the SSH half of the
resource-exhaustion family. MK
"""
import importlib
import re

import pytest

from pegaprox.utils.ssh import read_capped


class _Stream:
    """A channel file that will happily talk forever."""

    def __init__(self, total=None, block=b'x' * 4096, fail_after=None):
        self.served = 0
        self.calls = 0
        self._total = total          # None = infinite
        self._block = block
        self._fail_after = fail_after

    def read(self, n=-1):
        self.calls += 1
        if self._fail_after is not None and self.served >= self._fail_after:
            raise OSError('channel closed under us')
        if self._total is not None and self.served >= self._total:
            return b''
        chunk = self._block[:n] if n and n > 0 else self._block
        if self._total is not None:
            chunk = chunk[:self._total - self.served]
        self.served += len(chunk)
        return chunk


def test_output_that_fits_comes_back_untouched():
    s = _Stream(total=2048)

    out = read_capped(s, limit=1024 * 1024)

    assert out == 'x' * 2048
    assert 'truncated' not in out


def test_output_past_the_cap_is_cut():
    s = _Stream(total=1024 * 1024)

    out = read_capped(s, limit=4096)

    body = out.split('\n[...')[0]
    assert len(body) == 4096


def test_the_cut_says_so_and_names_the_numbers():
    """An operator staring at a half-finished log needs to know it was us."""
    s = _Stream(total=100_000)

    out = read_capped(s, limit=4096)

    assert re.search(r'\[\.\.\. output truncated at 4096 of \d+\+ bytes \.\.\.\]', out), out


def test_a_real_command_is_drained_completely():
    """Stopping at the limit leaves the far end blocked on a full pipe, and
    recv_exit_status() hangs behind it. The biggest legitimate output in this tree is
    an apt log; with the shipped cap it has to run all the way to EOF."""
    import pegaprox.utils.ssh as sshmod
    s = _Stream(total=2 * 1024 * 1024)          # a fat but ordinary apt log

    read_capped(s, limit=sshmod._SSH_OUTPUT_CAP)

    assert s.served == 2 * 1024 * 1024, f'stopped reading after {s.served} bytes'


def test_output_far_past_the_cap_is_still_drained():
    """Over the cap but under the give-up point: memory is bounded, the channel is not
    left wedged."""
    s = _Stream(total=200_000)

    out = read_capped(s, limit=32_768)

    assert s.served == 200_000, f'stopped reading after {s.served} bytes'
    assert 'truncated' in out


def test_it_does_give_up_on_an_endless_talker():
    """Draining is not the same as reading forever. A channel object that never returns
    b'' and never times out must not hold the greenlet."""
    s = _Stream(total=None)

    out = read_capped(s, limit=4096)

    assert s.served <= 4096 * 10 + 65536, s.served
    assert 'truncated' in out


def test_a_broken_channel_returns_what_we_had():
    """Every caller wraps this in its own try; losing the connection mid-read must not
    turn a partial answer into an exception here."""
    s = _Stream(total=None, fail_after=8192)

    out = read_capped(s, limit=1024 * 1024)

    assert out.startswith('x' * 8192)


def test_undecodable_bytes_do_not_raise():
    s = _Stream(total=64, block=b'\xff\xfe' * 32)

    out = read_capped(s, limit=1024)

    assert isinstance(out, str)


def test_the_cap_is_configurable(monkeypatch):
    """An estate with genuinely huge legitimate output can raise it."""
    import pegaprox.utils.ssh as sshmod

    monkeypatch.setenv('PEGAPROX_SSH_OUTPUT_MB', '2')
    reloaded = importlib.reload(sshmod)
    try:
        assert reloaded._SSH_OUTPUT_CAP == 2 * 1024 * 1024
    finally:
        monkeypatch.delenv('PEGAPROX_SSH_OUTPUT_MB', raising=False)
        importlib.reload(sshmod)


def test_the_default_is_generous_enough_for_a_real_command():
    """The biggest legitimate output here is an apt log, a few hundred KB. A cap that
    bites those would be worse than no cap - people would raise it to infinity."""
    import pegaprox.utils.ssh as sshmod

    assert sshmod._SSH_OUTPUT_CAP >= 4 * 1024 * 1024


# --- the property, across the whole tree -------------------------------------------

def test_no_unbounded_channel_read_is_left_anywhere():
    """This is the kind of line that gets copy-pasted back in. 55 of them existed."""
    import pathlib

    root = pathlib.Path(__file__).resolve().parent.parent
    offenders = []
    for path in list((root / 'pegaprox').rglob('*.py')) + list((root / 'plugins').rglob('*.py')):
        for n, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith('#') or '`' in line:
                continue
            if re.search(r'std(?:out|err)\.read\(\)', line):
                offenders.append(f'{path.relative_to(root)}:{n}')

    assert offenders == [], offenders
