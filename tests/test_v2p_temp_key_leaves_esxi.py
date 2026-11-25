# The temporary key a migration puts on ESXi is taken away again with grep -v and a swap of the
# file. grep -v answers 1 when no line is left, and no line is left when our key was the only
# one in the file, which it is on an ESXi host nobody put a key on: the swap was chained with
# && and never ran. The key stayed authorized, its filtered copy stayed next to it, and the
# run said CLEANED anyway, so nothing warned.
#
# The removal runs here in a real shell against real files, the way the ESXi shell runs it.

import logging
import os
import shutil
import subprocess

import pytest

from pegaprox.core import v2p

KEY_ID = 'a1b2c3d4'
OURS = f'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOurs pegaprox-v2p-{KEY_ID}'
ADMIN = 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCadmin admin@laptop'
OTHER_RUN = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOther pegaprox-v2p-ffff0000'

# ESXi runs busybox ash; the system sh stands in where busybox is missing
SHELLS = [s for s in (('busybox', 'sh'), ('sh',)) if shutil.which(s[0])]


class Esxi:
    """A host root with /etc/ssh/keys-root and a home directory, and the cleanup run against it."""

    def __init__(self, tmp_path, monkeypatch, shell):
        self.root = tmp_path
        self.home = tmp_path / 'home'
        self.keys = tmp_path / 'etc' / 'ssh' / 'keys-root' / 'authorized_keys'
        self.dot = self.home / '.ssh' / 'authorized_keys'
        self.keys.parent.mkdir(parents=True)
        self.home.mkdir()
        self.shell = shell
        self.output = None
        monkeypatch.setattr(v2p, '_pve_node_exec', self._node)

    def _node(self, mgr, node, cmd, timeout=600, **kw):
        if not cmd.startswith('ssh '):
            return 0, '', ''      # the rm of the local key files on the node
        start = cmd.index("root@esxi.lab '") + len("root@esxi.lab '")
        script = cmd[start:cmd.rindex("' 2>&1")]
        script = script.replace('/etc/ssh/', f'{self.root}/etc/ssh/')
        p = subprocess.run([*self.shell, '-c', script], capture_output=True, text=True, timeout=30,
                           env={'HOME': str(self.home), 'PATH': os.environ['PATH']})
        self.output = p.stdout + p.stderr
        return p.returncode, p.stdout, p.stderr

    def clean(self):
        v2p._cleanup_temp_ssh_key(None, 'pve1', f'/tmp/v2p-key-{KEY_ID}', 'esxi.lab', 'root')

    def leftovers(self):
        return sorted(str(p.relative_to(self.root)) for p in self.root.rglob(f'*.{KEY_ID}'))


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
