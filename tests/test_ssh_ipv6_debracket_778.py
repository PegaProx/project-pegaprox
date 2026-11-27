# Regression test for #778: paramiko needs a bare host, but IPv6 addresses arrive bracketed
# ("[fe80::1]") from the node-IP cache. Without stripping the brackets, ssh.connect() fails for every
# IPv6-only node. The node shell de-brackets before connecting; since the SSH console server on
# port+2 is gone, the main port route is the one place left, and it is run here.
import paramiko
import pytest

import pegaprox.api.vms as vms
from test_node_shell_target_1143 import _cluster, _let_go, _shell, _token  # noqa: F401


def _debracket(h):
    # mirrors the inline expression in vms.py so its behavior is pinned directly
    return h[1:-1] if h and h.startswith('[') and h.endswith(']') else h


def test_debracket_logic():
    assert _debracket('[fe80::1]') == 'fe80::1'
    assert _debracket('[2001:db8::42]') == '2001:db8::42'
    assert _debracket('192.168.1.5') == '192.168.1.5'              # IPv4 untouched
    assert _debracket('node1.example.com') == 'node1.example.com'  # hostname untouched
    assert _debracket('') == ''
    assert _debracket(None) is None


@pytest.mark.parametrize('address,dialled_host', [
    ('[fd00::12]', 'fd00::12'),
    ('[2001:db8::42]', '2001:db8::42'),
    ('fd00::12', 'fd00::12'),
    ('10.0.0.12', '10.0.0.12'),
    ('pve2.lab.example', 'pve2.lab.example'),
])
def test_the_node_shell_hands_paramiko_the_bare_host(api, seed, monkeypatch, address, dialled_host):
    dialled = []

    class _Client:
        def connect(self, hostname=None, **kw):
            dialled.append(hostname)
            raise paramiko.AuthenticationException('stopped by the test')

        def close(self):
            pass

    monkeypatch.setattr(paramiko, 'SSHClient', _Client)
    monkeypatch.setattr(vms, 'apply_host_key_policy', lambda client, _p: client)
    monkeypatch.setattr(vms, 'persist_host_keys', lambda client: None)
    _cluster(api, addresses={'pve2': address})

    said = _shell(api, f'token={_token(api, seed.user("root", role="admin"))}')

    assert dialled == [dialled_host], said
    # the dialog shows the address as the cluster knows it
    assert [m['ip'] for m in said if m.get('status') == 'need_credentials'] == [address]
