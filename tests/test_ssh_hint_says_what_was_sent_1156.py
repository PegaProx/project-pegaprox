"""The SSH hint called a refused key login a rejected password (#1156).

'Permission denied (publickey,password).' lists what the node would accept, not what was
offered. The SSH ladders try the cluster's key, then the keys ssh finds itself (BatchMode,
never a password), then sshpass, and the hint said "SSH password rejected" for any of
them. A token cluster without a key, which never sends a password at all, got that line
once per node in its log. The hint now goes by the step that failed: 'key', 'password',
or a neutral line when the caller cannot tell. The other branches stay as they were.

The wire is stubbed (node_cmd), the steps and the log lines are the real ones.
"""
import subprocess
import types

import pytest

from pegaprox.core.manager import _ssh_auth_hint
from pegaprox.models.tasks import PegaProxConfig

BOTH = 'root@10.0.0.7: Permission denied (publickey,password).'
NODE_IP = '10.0.0.7'
SECRET = 'acct-91d2-a-real-login'


# -- the hint itself --------------------------------------------------------------------------

def test_a_refused_key_login_does_not_claim_a_password_was_rejected():
    h = _ssh_auth_hint(BOTH, tried='key')
    assert 'password rejected' not in h.lower()
    assert 'no password was sent' in h
    assert 'ssh key' in h.lower()


def test_a_refused_password_still_says_so():
    h = _ssh_auth_hint(BOTH, tried='password')
    assert 'password rejected' in h.lower()


def test_without_knowing_the_step_the_hint_claims_neither():
    h = _ssh_auth_hint(BOTH)
    assert 'password rejected' not in h.lower()
    assert 'no password was sent' not in h
    assert 'key or password' in h


@pytest.mark.parametrize('tried', [None, 'key', 'password'])
@pytest.mark.parametrize('stderr,expect', [
    ('root@node: Permission denied (publickey).', 'key auth only'),
    ('Load key "/tmp/k": invalid format\nroot@node: Permission denied (publickey).', 'invalid format'),
    ('Host key verification failed.', 'host key'),
    ('sudo: a password is required', 'passwordless'),
])
def test_the_other_branches_do_not_depend_on_the_step(stderr, expect, tried):
    assert expect in _ssh_auth_hint(stderr, tried=tried)


# -- what the ladders log and return ------------------------------------------------------------

class _Log:
    def __init__(self):
        self.lines = []

    def info(self, msg, *a, **k):
        self.lines.append(msg)

    def debug(self, *a, **k):
        pass

    warning = error = critical = debug


def _manager(password=None, key=''):
    from pegaprox.core.manager import PegaProxManager
    m = PegaProxManager.__new__(PegaProxManager)
    m.config = PegaProxConfig({'name': 'c', 'host': NODE_IP, 'user': 'root@pam',
                               'pass': password or '', 'ssh_key': key})
    m.id = 'c1'
    m.logger = _Log()
    m.ha_config = {}
    m._get_node_ip = lambda node: NODE_IP
    m.ssh_blocked_reason = lambda *a, **k: None
    m.ssh_password_to_offer = lambda host=None: password
    m._withheld_from_sshd = lambda pw: False
    m._step_password = lambda host, pw: pw
    return m


class _Node:
    """A node that takes neither our keys nor our password. `password_answer` None makes
    the sshpass step time out instead, so it leaves no stderr of its own."""

    def __init__(self, password_answer=BOTH):
        self.password_answer = password_answer
        self.sent = []

    def __call__(self, argv, **kw):
        via = 'password' if argv[:1] == ['sshpass'] else 'key'
        self.sent.append(via)
        if via == 'password' and self.password_answer is None:
            raise subprocess.TimeoutExpired(argv, kw.get('timeout', 30))
        return subprocess.CompletedProcess(argv, 255, '', BOTH if via == 'key' else self.password_answer)


@pytest.fixture
def node(monkeypatch):
    import pegaprox.core.manager as mgr_mod
    n = _Node()
    monkeypatch.setattr(mgr_mod, 'node_cmd', n)
    return n


def test_a_token_cluster_without_a_key_is_not_told_its_password_was_rejected(node):
    """The reporter's log: the sensor read (#601) on a cluster that has no key and sends
    no password. The line it logs once per node must not mention a rejected password."""
    m = _manager(password=None)
    assert m._ssh_read_output(NODE_IP, 'root', 'true') is None
    assert node.sent == ['key'], 'no password step may run on this cluster'
    hints = [ln for ln in m.logger.lines if ln.startswith('[SSH]')]
    assert len(hints) == 1 and hints[0].startswith(f'[SSH] {NODE_IP}: ')
    assert 'no password was sent' in hints[0]
    assert 'password rejected' not in hints[0].lower()


def test_a_refused_password_is_logged_as_one_next_to_the_key_line(node):
    m = _manager(password=SECRET)
    assert m._ssh_read_output(NODE_IP, 'root', 'true') is None
    assert node.sent == ['key', 'password']
    hints = [ln for ln in m.logger.lines if ln.startswith('[SSH]')]
    assert len(hints) == 2
    assert 'no password was sent' in hints[0]
    assert 'password rejected' in hints[1].lower()


def test_the_configured_key_step_counts_as_a_key_login(node):
    m = _manager(password=None, key='-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----\n')
    assert m._ssh_read_output(NODE_IP, 'root', 'true') is None
    assert node.sent == ['key', 'key']
    hints = [ln for ln in m.logger.lines if ln.startswith('[SSH]')]
    # the same hint for both key steps, said once
    assert len(hints) == 1 and 'no password was sent' in hints[0]


def test_the_reason_of_node_output_names_the_step_that_answered(node):
    m = _manager(password=None)
    out, reason = m._ssh_node_output_ex('pve1', 'true')
    assert out is None
    assert 'no password was sent' in reason

    m = _manager(password=SECRET)
    out, reason = m._ssh_node_output_ex('pve1', 'true')
    assert 'password rejected' in reason.lower()


def test_a_password_step_that_left_no_answer_is_not_blamed_for_the_key_steps_one(node):
    """Counterproof for the stderr handover: the sshpass step times out, so the last
    answer there is is still the key step's. Reading it as the password's would say
    'password rejected' for a password that never got an answer, and the key step's own
    wording would say no password was sent when one was."""
    node.password_answer = None
    m = _manager(password=SECRET)
    out, reason = m._ssh_node_output_ex('pve1', 'true')
    assert node.sent == ['key', 'password']
    assert 'key or password' in reason
    assert 'password rejected' not in reason.lower() and 'no password was sent' not in reason
