"""The iSCSI CHAP secret must not reach the node's process table.

/api/clusters/<id>/nodes/<node>/iscsi/login interpolated the CHAP password into
the command string it hands to ssh.exec_command. That string is run by a shell on
the PVE node, and /proc/<pid>/cmdline is world-readable there — so the password sat
in `ps` output for every local account on the node, for as long as the attach took
(discovery + login + the persist write + a multipath reconfigure). shlex.quote was
already on it, but quoting stops injection, not disclosure; they are two different
problems on the same line.

The password now travels down the SSH channel on stdin and the shell picks it up
with `read`. iscsiadm itself still takes it as -v on its own argv for the single
call that writes the field — open-iscsi has no file or stdin form for -v — so the
window shrinks from the whole operation to one short-lived process.

The second test is the one that matters: it takes the command string the route
actually produced and runs it through a real /bin/sh with a stand-in iscsiadm on
PATH, so it proves both halves at once — the secret is absent from the command
line AND the shell still reconstructs it byte-for-byte for the field that needs it.

Aikido sast 700488632. MK
"""
import io
import os
import stat
import subprocess

import pytest

# every character here is inside _CHAP_PASS_RE, and the set is picked to break a
# naive quoting or word-splitting bug: / = : ! @ % ^ + . _ -
CHAP_PASS = 'p+a/s=s!@%^w.o_r-d:1'
CHAP_USER = 'chap.user_1'


class _Chan:
    def __init__(self):
        self.written = []
        self.write_closed = False

    def recv_exit_status(self):
        return 0

    def shutdown_write(self):
        self.write_closed = True


class _Stdin:
    def __init__(self, chan):
        self.channel = chan

    def write(self, data):
        self.channel.written.append(data)

    def flush(self):
        pass


class _Stdout(io.BytesIO):
    def __init__(self, chan):
        super().__init__(b'')
        self.channel = chan


class FakeSSH:
    """Records every command the route runs and whatever it fed them."""

    def __init__(self):
        self.calls = []          # list of (cmd, [chunks fed to stdin])

    def exec_command(self, cmd, timeout=None):
        chan = _Chan()
        self.calls.append((cmd, chan.written))
        return _Stdin(chan), _Stdout(chan), _Stdout(_Chan())

    def close(self):
        pass


@pytest.fixture
def attached(api, seed):
    """An unconfined admin, one cluster, one node, and a fake SSH on the far end."""
    seed.db.execute('''INSERT INTO clusters (id, name, host, user, pass_encrypted)
                       VALUES ('cluster_1', 'cluster_1', '10.0.0.1', 'root@pam', 'x')''')
    admin = seed.user('dana', role='admin')

    ssh = FakeSSH()
    m = api.make_fake_manager('cluster_1')
    m.config.name = 'cluster_1'
    m._api_get.return_value.status_code = 200
    m._api_get.return_value.json.return_value = {'data': [{'node': 'pve1'}]}
    m.member_node_ip.return_value = '10.0.0.9'
    m._ssh_connect.return_value = ssh
    api.set_manager('cluster_1', m)

    client = api.as_user(admin)
    resp = client.post('/api/clusters/cluster_1/nodes/pve1/iscsi/login', json={
        'portal': '10.0.0.50:3260',
        'target': 'iqn.2026-01.com.example:storage.lun01',
        'username': CHAP_USER,
        'password': CHAP_PASS,
    })
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert ssh.calls, 'the route never ran anything over SSH'
    return ssh


def _fed_command(ssh):
    """The one command the route handed a secret to, or a readable failure."""
    fed = [cmd for cmd, chunks in ssh.calls if chunks]
    assert fed, 'no command was fed anything on stdin — the secret went somewhere else'
    assert len(fed) == 1, fed
    return fed[0]


def test_the_chap_secret_is_in_none_of_the_command_lines(attached):
    leaking = [cmd for cmd, _ in attached.calls if CHAP_PASS in cmd]
    assert not leaking, f'CHAP password still interpolated into: {leaking}'


def test_the_secret_was_delivered_on_stdin_instead(attached):
    fed = [chunk for _, chunks in attached.calls for chunk in chunks]
    assert fed == [CHAP_PASS + '\n'], fed


def test_only_the_one_command_that_needs_it_is_fed(attached):
    """A password written to the wrong command's stdin would be a different bug."""
    with_feed = [cmd for cmd, chunks in attached.calls if chunks]
    assert len(with_feed) == 1, with_feed
    assert 'node.session.auth.password' in with_feed[0]


def test_the_username_is_still_on_the_command_line(attached):
    """The counterweight — this pass must not have quietly dropped CHAP setup."""
    assert any(CHAP_USER in cmd for cmd, _ in attached.calls)


def test_a_real_shell_reconstructs_the_secret_exactly(attached, tmp_path):
    """Run the route's own command string through /bin/sh with a fake iscsiadm.

    Without this the first two tests would also pass if the password were simply
    never delivered — the property is that it is absent from argv AND still lands
    in node.session.auth.password intact.
    """
    cmd = _fed_command(attached)

    log = tmp_path / 'argv.log'
    fake = tmp_path / 'iscsiadm'
    fake.write_text('#!/bin/sh\nprintf \'%s\\n\' "$@" >> "$ARGV_LOG"\n')
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    env = dict(os.environ, PATH=f'{tmp_path}:{os.environ["PATH"]}', ARGV_LOG=str(log))
    proc = subprocess.run(['/bin/sh', '-c', cmd], input=CHAP_PASS + '\n',
                          text=True, capture_output=True, env=env, timeout=30)
    assert proc.returncode == 0, proc.stderr

    argv = log.read_text().splitlines()
    # three iscsiadm invocations, chained on &&; the last one carries the secret
    assert argv.count('node.session.auth.password') == 1, argv
    value = argv[argv.index('node.session.auth.password') + 2]
    assert value == CHAP_PASS, f'shell handed iscsiadm {value!r}'
    assert argv.count(CHAP_USER) == 1, argv


def test_the_shell_refuses_when_nothing_arrives_on_stdin(attached, tmp_path):
    """If the feed ever breaks, the run must fail rather than silently configure
    CHAP with an empty password — `read` returning EOF is the guard."""
    cmd = _fed_command(attached)

    log = tmp_path / 'argv.log'
    fake = tmp_path / 'iscsiadm'
    fake.write_text('#!/bin/sh\nprintf \'%s\\n\' "$@" >> "$ARGV_LOG"\n')
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    env = dict(os.environ, PATH=f'{tmp_path}:{os.environ["PATH"]}', ARGV_LOG=str(log))
    proc = subprocess.run(['/bin/sh', '-c', cmd], input='', text=True,
                          capture_output=True, env=env, timeout=30)
    assert proc.returncode != 0
    assert not log.exists(), 'iscsiadm ran anyway with no password'
