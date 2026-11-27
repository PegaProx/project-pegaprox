"""The SSHFS mount of an ESXi migration hands its ssh options to ssh, and FUSE 3 refuses
none of its options.

Seen on a real PVE 9 node: the first two of the three mount attempts ended with "fuse:
unknown option(s)". The options for an older ESXi (host key, key exchange and cipher
lists) stood unquoted in the command, the node's shell split them into options of sshfs,
FUSE took their commas for separators and refused the algorithm names; a second
ssh_command after them would have replaced them anyway. big_writes and large_read, which
FUSE 3 dropped, ended the first two attempts on every PVE 8 and 9 node. The remount of
the Live Mirror built the same broken line.
"""
import inspect

import test_v2p_node_checks_1224 as nc
from pegaprox.core import v2p

# a sshfs that writes each argument it got on a line of its own and mounts
ARGV_SSHFS = r'''#!/bin/sh
for a in "$@"; do printf '%s\n' "$a" >> "$ARGV_LOG"; done
printf -- '--\n' >> "$ARGV_LOG"
exit 0
'''


def _argvs(tmp_path, cmd):
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir(exist_ok=True)
    (bin_dir / 'sshfs').write_text(ARGV_SSHFS)
    (bin_dir / 'sshfs').chmod(0o755)
    log = tmp_path / 'argv.log'
    run = nc._on_this_machine(cmd, tmp_path)
    rc, _out, err = nc._bash(f'export ARGV_LOG={log}; ' + run, path=str(bin_dir))
    assert rc == 0, err
    return [a for a in log.read_text().split('--\n')[0].splitlines()]


def _attempts():
    return nc._sent_by_a_run('mount', answer=(1, '', ''), mode='auto')


def test_the_first_attempt_hands_the_old_algorithms_to_ssh_in_one_argument(tmp_path):
    argv = _argvs(tmp_path, _attempts()[0])
    cmds = [a for a in argv if a.startswith('ssh_command=')]
    assert len(cmds) == 1, argv
    assert cmds[0].startswith('ssh_command=ssh -E ')
    # the commas reach FUSE escaped, which hands them on to ssh as commas
    assert cmds[0].endswith(v2p.SSHFS_LEGACY_SSH.replace('\\\\', '\\'))
    assert '-o HostKeyAlgorithms=+ssh-rsa\\,ssh-ed25519\\,ecdsa-sha2-nistp256' in cmds[0]
    assert not [a for a in argv if 'Algorithms' in a and not a.startswith('ssh_command=')], argv


def test_no_attempt_carries_an_option_fuse_3_refuses(tmp_path):
    for i, cmd in enumerate(_attempts()):
        argv = _argvs(tmp_path / str(i), cmd) if (tmp_path / str(i)).mkdir() is None else None
        bad = [a for a in argv if 'big_writes' in a or 'large_read' in a]
        assert not bad, (i, argv)
        assert sum(a.startswith('ssh_command=') for a in argv) == 1, (i, argv)


def test_the_later_attempts_go_without_the_old_algorithms(tmp_path):
    for i, cmd in enumerate(_attempts()[1:]):
        argv = _argvs(tmp_path / str(i), cmd) if (tmp_path / str(i)).mkdir() is None else None
        assert [a for a in argv if a.startswith('ssh_command=')][0].count(' -o ') == 0, argv


def test_the_live_mirror_remount_builds_the_same_mount_command():
    src = inspect.getsource(v2p._do_sshfs_boot_migration)
    assert '_sshfs_mount_cmd(' in src and 'ssh_opts=SSHFS_LEGACY_SSH' in src
    assert 'sshfs -o password_stdin' not in src
