"""An rbd mirror action that rbd refused has not happened.

_rbd_cmd treats exit 22 as "mirroring is not enabled", which is right for a read that has nothing to show. For an action it answered
success too: a promote came back {'success': True} and wrote its "Promoted" audit line, so a failover looked done.
"""
from unittest.mock import MagicMock, patch

from pegaprox.api import ceph as ceph_mod

CID = 'cluster_1'
REFUSED = 'rbd: mirroring not enabled: (22) Invalid argument'


def _client(api, seed, monkeypatch, code, text):
    mgr = api.make_fake_manager(cluster_id=CID)
    mgr.host, mgr.api_port = 'pve.example', 8006
    mgr.config.name = CID
    mgr.is_connected = True
    out = MagicMock()
    out.channel.recv_exit_status.return_value = code
    ssh = MagicMock()
    ssh.exec_command.return_value = (MagicMock(), out, MagicMock())
    mgr._ssh_connect.return_value = ssh
    api.set_manager(CID, mgr)
    monkeypatch.setattr(ceph_mod, '_read_capped', lambda f: text)
    monkeypatch.setattr(ceph_mod, '_get_any_online_node', lambda m: ('pveA', None))
    monkeypatch.setattr(ceph_mod, '_resolve_node_ip', lambda m, n: '10.0.0.1')
    return api.as_user(seed.user('root', role='admin', tenant_id='default'))


def test_a_refused_promote_is_an_error_with_the_reason_and_no_audit(api, seed, monkeypatch):
    c = _client(api, seed, monkeypatch, 22, REFUSED)
    with patch.object(ceph_mod, 'log_audit') as audit:
        r = c.post(f'/api/clusters/{CID}/ceph/mirror/pool/rbd/image/vm-1/promote', json={'force': False})
    assert r.status_code == 500 and REFUSED in r.get_json()['error'], r.get_json()
    audit.assert_not_called()


def test_a_read_still_has_nothing_to_show(api, seed, monkeypatch):
    c = _client(api, seed, monkeypatch, 22, REFUSED)
    r = c.get(f'/api/clusters/{CID}/ceph/mirror/pool/rbd/status')
    assert r.status_code == 200, r.get_data(as_text=True)


def test_a_promote_that_worked_is_still_a_success(api, seed, monkeypatch):
    c = _client(api, seed, monkeypatch, 0, '')
    r = c.post(f'/api/clusters/{CID}/ceph/mirror/pool/rbd/image/vm-1/promote', json={'force': False})
    assert r.status_code == 200 and r.get_json() == {'success': True}
