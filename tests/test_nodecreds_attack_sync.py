"""Content sync must not hand one node's own root password to another node (#1136).

The node-to-node scp runs in a shell on the SOURCE node and reads the password for the
TARGET from stdin. With per-node passwords that puts node B's password on node A.
"""
import logging
import types

import pytest

from pegaprox.core import node_creds


CID = 'cluster_1'
A, B = '10.0.0.1', '10.0.0.2'
PW_B = 'pve2-own-root!'
MEMBERS = {'pve1': {'node': 'pve1', 'status': 'online'},
           'pve2': {'node': 'pve2', 'status': 'online'}}


@pytest.fixture(autouse=True)
def _fresh():
    def clean():
        node_creds.invalidate()
        with node_creds._lock:
            node_creds._addresses.clear()
            node_creds._absent.clear()
            node_creds._swept.clear()
    clean()
    yield
    clean()


class _Chan:
    def recv_exit_status(self):
        return 0

    def shutdown_write(self):
        pass


class _Stream:
    def __init__(self, sink=None, data=b''):
        self.sink, self.data, self.channel = sink, data, _Chan()

    def write(self, s):
        if self.sink is not None:
            self.sink.append(s)

    def flush(self):
        pass

    def read(self):
        return self.data


class _Client:
    def __init__(self, host, log):
        self.host, self.log = host, log

    def exec_command(self, cmd, timeout=None):
        written = []
        self.log.append((self.host, cmd, written))
        return _Stream(written), _Stream(data=b''), _Stream(data=b'')

    def close(self):
        pass


def _mgr():
    from pegaprox.core.manager import PegaProxManager
    m = PegaProxManager.__new__(PegaProxManager)
    m.config = types.SimpleNamespace(name='lab', host=A, user='root@pam', pass_='cluster-pw',
                                     ssh_user='root', ssh_key='', ssh_port=22, ssh_disabled=False,
                                     fallback_hosts=[B])
    m.id = CID
    m.logger = logging.getLogger('nodecreds-attack')
    m._cached_node_dict = dict(MEMBERS)
    m.is_connected = True
    m.current_host = None
    return m


def test_content_sync_does_not_put_node_b_password_on_node_a(db, monkeypatch):
    db.save_node_credential(CID, 'pve2', PW_B, 'alice')
    node_creds.note_address(CID, 'pve1', A)
    node_creds.note_address(CID, 'pve2', B)
    m = _mgr()
    assert m.ssh_password_to_offer(B) == PW_B      # precondition: B has its own

    log = []
    m._get_syncable_storage = lambda node, storage, ct: (None, None)
    m.get_node_status = lambda: dict(MEMBERS)
    m.member_node_ip = lambda n: {'pve1': A, 'pve2': B}.get(n)
    m._resolve_storage_path = lambda node, storage, ct='iso': '/var/lib/vz/template/iso'
    m._ssh_connect = lambda host, **kw: _Client(host, log)

    m.sync_content_to_nodes('pve1', 'local', 'debian.iso', 'iso', target_nodes=['pve2'])

    on_a = [w for host, _cmd, written in log if host == A for w in written]
    assert any('scp' in cmd for host, cmd, _w in log if host == A), 'scp did not run on the source'
    assert not any(PW_B in w for w in on_a), \
        "node pve2's own root password was written into a shell on node pve1"
