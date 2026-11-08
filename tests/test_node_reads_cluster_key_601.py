"""The node reads over SSH log in with the cluster's own credentials (#601).

The temperatures, the cluster health (corosync ring, quorum, services) and the per-NIC
counters ran `ssh -o BatchMode=yes` with nothing but the keys of the PegaProx process.
The key pasted into the cluster settings never went along. In the Docker image the
process has no keys of its own, so every one of these reads failed, while the sshd log of
the same node showed logins with that key from everything else PegaProx does.

The node here is a fake `node_cmd`: it lets in exactly the credential it is told to
accept - the configured key (read from the key file ssh gets at call time), the account
password (SSHPASS of an sshpass call), or the process's own keys - and refuses the rest
the way sshd does. So the tests measure what reaches the node, not which helper is
called. MK
"""
import types
from unittest.mock import MagicMock

import pytest

import pegaprox.core.manager as mgrmod
from pegaprox.models.tasks import PegaProxConfig

HOST = '192.0.2.11'
KEY = '-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAcluster-settings-key\n-----END OPENSSH PRIVATE KEY-----\n'
PROBE_JSON = '{"k10temp-pci-00c3":{"Adapter":"PCI adapter","Tctl":{"temp1_input":73.875}}}\n'
NET_DEV = ('Inter-|   Receive                                                |  Transmit\n'
           ' face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n'
           '  eno1: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0\n')


def _answer(command):
    if 'sensors -j' in command:
        return PROBE_JSON
    if command.startswith('cat /proc/net/dev'):
        return NET_DEV
    if command.startswith('corosync-cfgtool'):
        return 'LINK ID 0 udp\n\taddr\t= 192.0.2.11\n\tstatus:\n\t\tnodeid:   1:\tlocalhost\n'
    if command.startswith('pvecm status'):
        return 'Quorate:          Yes\n'
    if command.startswith('systemctl show'):
        return 'ActiveState=active\nSubState=running\nActiveEnterTimestamp=\nResult=success\n'
    return ''


@pytest.fixture
def node(monkeypatch):
    """The node: accepts what `node.accepts` names, records every login attempt as
    (how, argv) with how in key / password / own."""
    state = types.SimpleNamespace(accepts=set(), tries=[], secrets=[])

    def fake_node_cmd(argv, **kw):
        argv = list(argv)
        if argv[0] == 'sshpass':
            how = 'password'
            secret = (kw.get('env') or {}).get('SSHPASS')
            state.secrets.append(secret)
            ok = how in state.accepts and secret == 'account-pw'
        elif '-i' in argv:
            how = 'key'
            with open(argv[argv.index('-i') + 1]) as f:
                ok = how in state.accepts and f.read().strip() == KEY.strip()
        else:
            how = 'own'
            ok = how in state.accepts
        state.tries.append((how, argv))
        if not ok:
            return types.SimpleNamespace(returncode=255, stdout='',
                                         stderr=f'root@{HOST}: Permission denied (publickey,password).')
        return types.SimpleNamespace(returncode=0, stdout=_answer(argv[-1]), stderr='')

    monkeypatch.setattr(mgrmod, 'node_cmd', fake_node_cmd)
    # the password step looks for sshpass first; answer as if it is installed
    real_run = mgrmod.subprocess.run
    monkeypatch.setattr(mgrmod.subprocess, 'run',
                        lambda argv, *a, **k: types.SimpleNamespace(returncode=0)
                        if argv[:1] == ['which'] else real_run(argv, *a, **k))
    monkeypatch.setattr(mgrmod.node_creds, 'secrets_of', lambda cid: {})
    return state


def _mgr(**cfg):
    data = {'name': 'lab', 'host': HOST, 'user': 'root@pam', 'pass': 'account-pw'}
    data.update(cfg)
    m = mgrmod.PegaProxManager.__new__(mgrmod.PegaProxManager)
    m.id = 'c1'
    m.config = PegaProxConfig(data)
    m.ha_config = {}
    m.logger = MagicMock()
    m._last_ssh_block_logged = None
    m.is_connected = True
    m.connect_to_proxmox = lambda: True
    m._get_node_ip = lambda name: HOST
    return m


def _temps(res):
    return [r['value'] for r in res.get('sensors') or [] if r.get('kind') == 'temp']


# --- the key from the cluster settings ------------------------------------------------

def test_the_temperatures_come_in_over_the_key_from_the_cluster_settings(node):
    node.accepts = {'key'}
    res = _mgr(ssh_key=KEY).get_node_sensors('pve01')
    assert _temps(res) == [73.875], res


def test_the_cluster_health_comes_in_over_that_key(node):
    node.accepts = {'key'}
    res = _mgr(ssh_key=KEY).get_node_cluster_health('pve01')
    assert res.get('ssh_unavailable') is False, res
    assert res['pvecm'] is not None and res['corosync'] is not None
    assert all(s.get('active') is not None for s in res['services'])


def test_the_nic_counters_come_in_over_that_key(node):
    node.accepts = {'key'}
    res = _mgr(ssh_key=KEY).get_node_netstats('pve01')
    assert 'error' not in res, res
    assert [i['iface'] for i in res['interfaces']] == ['eno1']


def test_a_key_that_gets_in_is_the_only_login(node):
    """No extra logins on a node that takes the key: one try per read."""
    node.accepts = {'key'}
    _mgr(ssh_key=KEY).get_node_sensors('pve01')
    assert [how for how, _argv in node.tries] == ['key']


# --- the rest of the ladder -----------------------------------------------------------

def test_the_process_keys_still_work_without_a_configured_key(node):
    """A bare-metal install whose own key is on the nodes, as before."""
    node.accepts = {'own'}
    res = _mgr().get_node_sensors('pve01')
    assert _temps(res) == [73.875]
    assert [how for how, _argv in node.tries] == ['own']


def test_without_a_key_the_account_password_gets_the_read(node):
    node.accepts = {'password'}
    res = _mgr().get_node_sensors('pve01')
    assert _temps(res) == [73.875], res
    assert [how for how, _argv in node.tries] == ['own', 'password']


def test_a_refused_key_on_a_token_cluster_never_offers_the_token_secret(node):
    """The token secret in pass_ is no SSH password: after a refused key and refused own
    keys the read gives up instead of piping it to sshd."""
    node.accepts = {'password'}
    m = _mgr(user='root@pam!automation', **{'pass': 'token-secret-value'}, ssh_key=KEY)
    res = m.get_node_sensors('pve01')
    assert 'error' in res
    assert [how for how, _argv in node.tries] == ['key', 'own']
    assert node.secrets == []


def test_ssh_switched_off_sends_nothing(node):
    node.accepts = {'key', 'own', 'password'}
    res = _mgr(ssh_key=KEY, ssh_disabled=True).get_node_sensors('pve01')
    assert res.get('code') == 'SSH_DISABLED'
    assert node.tries == []
