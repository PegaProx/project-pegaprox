"""An API-token cluster was offering its token secret to the node's sshd.

Reported by an operator whose security team saw SSH arriving at PVE nodes from a
cluster configured with an API token and nothing else (#941). Two problems, one
line apart.

_ssh_connect had no ssh_key, so it fell through to

    connect_kwargs['password'] = self.config.pass_

and on a cluster where the operator typed a token id as the username, pass_ IS
the token secret — connect() builds `PVEAPIToken=user@realm!tokenid=<secret>`
out of that exact field. Every attempt therefore handed the Proxmox API token to
sshd as a password: it lands in the node's auth log and is visible to whatever
sits in the PAM stack. The second problem is that it happened on plain browsing
at all — opening a VM runs the LVM snapshot probe, which reads the volume group
over SSH.

The marker is `'!' in config.user`, NOT `_using_api_token`: the latter is also
true for a cluster given a username and password where we minted our own token
on first connect (#110), and there pass_ really is the account password and
perfectly usable for SSH. test_a_password_cluster_that_auto_minted_a_token_still_
connects is that case, and it is the one a careless fix breaks.

The tests assert on what reaches paramiko, because "no connection was made" and
"a connection was made without the secret" are different outcomes and only one
of them is the fix. MK
"""
import types

import pytest

from pegaprox.models.tasks import PegaProxConfig


def _cfg(**kw):
    base = {'name': 'c', 'host': '10.0.0.1', 'user': 'root@pam', 'pass': 'secret-pw'}
    base.update(kw)
    return PegaProxConfig(base)


def _manager(cfg):
    """A bare manager carrying just what the SSH path touches. Building a real one
    would connect to Proxmox."""
    from pegaprox.core.manager import PegaProxManager
    m = PegaProxManager.__new__(PegaProxManager)
    m.config = cfg
    m.id = 'c1'
    m.logger = types.SimpleNamespace(
        info=lambda *a, **k: None, debug=lambda *a, **k: None,
        warning=lambda *a, **k: None, error=lambda *a, **k: None)
    m._last_ssh_block_logged = None
    # the capability probe asks these before it does anything; without them it dies on
    # an AttributeError and the counter-proof would be red for the harness, not the bug
    m.is_connected = False
    m.connect_to_proxmox = lambda: False
    return m


# ---------------------------------------------------------------- the reason

def test_a_token_cluster_with_no_key_is_blocked():
    m = _manager(_cfg(user='root@pam!automation', **{'pass': 'TOKEN-SECRET'}))
    assert m.ssh_blocked_reason() == 'SSH_NO_CREDENTIALS'


def test_a_password_cluster_is_not_blocked():
    assert _manager(_cfg()).ssh_blocked_reason() is None


def test_a_key_cluster_is_not_blocked():
    m = _manager(_cfg(user='root@pam!automation', ssh_key='-----BEGIN KEY-----'))
    assert m.ssh_blocked_reason() is None


def test_the_operator_switch_blocks_even_with_a_key():
    m = _manager(_cfg(ssh_key='-----BEGIN KEY-----', ssh_disabled=True))
    assert m.ssh_blocked_reason() == 'SSH_DISABLED'


# ------------------------------------------------- what reaches the network

def _spy_paramiko(monkeypatch):
    """Record every connect() paramiko is asked to make.

    Only SSHClient is swapped — everything else stays the real module, so the host-key
    policy and the exception classes behave as they do in production. A fully synthetic
    paramiko silently failed inside apply_host_key_policy and made the allow-path tests
    look like refusals, which is the wrong red.
    """
    import threading
    import pegaprox.globals as ppglobals
    real = pytest.importorskip('paramiko')

    if getattr(ppglobals, '_ssh_semaphore', None) is None:
        monkeypatch.setattr(ppglobals, '_ssh_semaphore', threading.Semaphore(4), raising=False)

    calls = []

    class _Client(real.SSHClient):
        def connect(self, **kw):
            calls.append(kw)

        def close(self):
            pass

    fake = types.SimpleNamespace(**{k: getattr(real, k) for k in dir(real)
                                    if not k.startswith('_')})
    fake.SSHClient = _Client
    monkeypatch.setattr('pegaprox.core.manager.get_paramiko', lambda: fake)
    return calls


def test_the_token_secret_never_reaches_paramiko(monkeypatch):
    """The property this whole ticket is about."""
    calls = _spy_paramiko(monkeypatch)
    m = _manager(_cfg(user='root@pam!automation', **{'pass': 'TOKEN-SECRET'}))

    result = m._ssh_connect('10.0.0.1')

    # the secret first: that is the disclosure, and it has to be the sentence in the
    # failure output. "a client was returned" is the lesser statement.
    assert 'TOKEN-SECRET' not in str(calls), \
        'the Proxmox API token secret was offered to sshd as a password'
    assert calls == [], f'a connection was attempted at all: {calls}'
    assert result is None


def test_the_operator_switch_stops_the_connection(monkeypatch):
    calls = _spy_paramiko(monkeypatch)
    m = _manager(_cfg(ssh_key='-----BEGIN KEY-----', ssh_disabled=True))

    assert m._ssh_connect('10.0.0.1') is None
    assert calls == []


def test_a_password_cluster_that_auto_minted_a_token_still_connects(monkeypatch):
    """The mirror, and the case a careless fix breaks. The operator gave a username
    and password; we minted our own API token on first connect (#110), which makes
    _using_api_token True while pass_ is still the account password. SSH must keep
    working for these — they are the ordinary setup."""
    calls = _spy_paramiko(monkeypatch)
    m = _manager(_cfg(user='root@pam', **{'pass': 'real-account-password'}))
    m._using_api_token = True          # exactly the #110 state

    m._ssh_connect('10.0.0.1')

    assert len(calls) == 1, 'SSH was refused for a plain password cluster'
    assert calls[0].get('password') == 'real-account-password'


def test_a_key_cluster_is_unaffected():
    """A stored key is a usable credential whatever the REST side authenticates with."""
    m = _manager(_cfg(user='root@pam!automation', ssh_key='-----BEGIN KEY-----'))
    assert m.ssh_blocked_reason() is None


# ------------------------------------------------------- the snapshot probe

def test_the_capability_probe_does_not_invent_a_volume_group_figure():
    """With no SSH there is nothing to measure. It used to leave vg_free_gb at its
    0.0 default and tell the user 'Not enough VG free space (0.0 GB free)' — a
    number we never read."""
    m = _manager(_cfg(user='root@pam!automation', **{'pass': 'TOKEN-SECRET'}))

    out = m.check_efficient_snapshot_capability('pve1', 100, 'qemu')

    assert out['eligible'] is False
    assert out['vg_free_gb'] == 0.0
    joined = ' '.join(out['warnings'])
    assert 'SSH' in joined, f'no reason given: {out["warnings"]}'
    assert 'Not enough VG free space' not in joined


# --------------------------------------------------- the switch has to survive

def test_the_off_switch_survives_a_round_trip(db):
    """A per-cluster flag has to reach eight places — the migration, get_all_clusters,
    get_cluster, save_cluster's column list AND its value list, PegaProxConfig, the
    config save dict and ALLOWED_CONFIG_FIELDS. Miss one and it reverts on the next
    reload with nothing to show for it; core/config.py carries a comment about the
    load-balancer settings that did exactly that (#364). So assert the round trip,
    not the setter."""
    db.save_cluster('c_ssh_off', {
        'name': 'locked-down', 'host': '10.0.0.9', 'user': 'root@pam!automation',
        'pass': 'TOKEN-SECRET', 'ssh_disabled': True,
    })

    assert db.get_cluster('c_ssh_off')['ssh_disabled'] is True
    assert db.get_all_clusters()['c_ssh_off']['ssh_disabled'] is True

    cfg = PegaProxConfig(db.get_cluster('c_ssh_off'))
    assert cfg.ssh_disabled is True
    assert _manager(cfg).ssh_blocked_reason() == 'SSH_DISABLED'


def test_the_default_is_unchanged_for_every_existing_cluster(db):
    """Off switch off. An installation upgrading into this column must not lose SSH."""
    db.save_cluster('c_normal', {'name': 'normal', 'host': '10.0.0.8',
                                 'user': 'root@pam', 'pass': 'pw'})

    cfg = PegaProxConfig(db.get_cluster('c_normal'))
    assert cfg.ssh_disabled is False
    assert _manager(cfg).ssh_blocked_reason() is None


def test_the_field_is_accepted_by_the_update_route():
    """ALLOWED_CONFIG_FIELDS is a whitelist — a field missing from it is dropped
    silently, which looks exactly like the revert above from the outside."""
    from pegaprox.api.clusters import ALLOWED_CONFIG_FIELDS
    assert 'ssh_disabled' in ALLOWED_CONFIG_FIELDS


# ------------------------------------------------- the SECOND ssh ladder

@pytest.mark.parametrize('method,args,expected', [
    ('_ssh_run_command_output',              ('h', 'u', 'cmd'),            None),
    ('_ssh_run_command_with_key_output',     ('h', 'u', 'cmd', 'KEY'),     None),
    ('_ssh_run_command_with_password_output',('h', 'u', 'cmd', 'PW'),      None),
    ('_ssh_run_command',                     ('h', 'u', 'cmd'),            False),
    ('_ssh_run_command_with_key',            ('h', 'u', 'cmd', 'KEY'),     False),
    ('_ssh_run_command_with_password',       ('h', 'u', 'cmd', 'PW'),      False),
])
def test_the_other_ssh_ladder_is_blocked_too(monkeypatch, method, args, expected):
    """_ssh_connect is not the only way out of this process.

    _ssh_node_output_ex has its own key/agent/password ladder built on these six, and
    none of them goes through _ssh_connect — so gating that one reached ONE of five
    ways to open SSH to a node. Three of these are handed self.config.pass_ by their
    callers, which on a token-auth cluster is the token secret, so the disclosure this
    ticket is about lived here as well.

    The live E2E is what caught it: the off switch read True in the cluster listing and
    the hardening report still came back with 44 real control results. Unit tests over
    _ssh_connect could not see it. This pins all six.
    """
    from pegaprox.core.manager import PegaProxManager
    m = _manager(_cfg(ssh_key='-----BEGIN KEY-----', ssh_disabled=True))

    # make the real implementation explode if the guard ever lets us reach it
    monkeypatch.setattr('pegaprox.core.manager.subprocess', _Exploding(), raising=False)

    assert getattr(PegaProxManager, method)(m, *args) is expected


class _Exploding:
    def __getattr__(self, _name):
        raise AssertionError('SSH was attempted while the switch was off')


def test_the_other_ladder_still_runs_when_ssh_is_allowed():
    """The mirror. With credentials and the switch off-by-default, the guard must not
    be what stops the call — anything after it is the real implementation's business."""
    from pegaprox.core.manager import PegaProxManager
    m = _manager(_cfg(ssh_key='-----BEGIN KEY-----'))
    assert m.ssh_blocked_reason() is None
