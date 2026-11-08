"""A cluster edit that moves the endpoint drops the stored secrets nobody re-entered
(_config_edit_checks/_rebind). The per-node passwords of #1136 are stored secrets of the
same cluster and must follow the same rule.
"""
import types

import pytest

from pegaprox.core import node_creds


CID = 'cluster_1'
A, B, C = '10.0.0.1', '10.0.0.2', '10.0.0.3'
PW_B = 'pve2-own-root!'
MEMBERS = {'pve1': {'node': 'pve1', 'status': 'online'},
           'pve2': {'node': 'pve2', 'status': 'online'}}


@pytest.fixture(autouse=True)
def _fresh():
    node_creds.invalidate()
    yield
    node_creds.invalidate()


def _fake(api):
    fake = api.make_fake_manager(cluster_id=CID, cluster_type='proxmox')
    fake.config = types.SimpleNamespace(
        name=CID, host=A, user='root@pam', pass_='cluster-pw', ssh_user='', ssh_key='',
        ssh_port=22, ssh_disabled=False, ha_enabled=False, auto_migrate=False, dry_run=False,
        fallback_hosts=[B], api_token_user='', api_token_secret='', ssl_verification=False)
    fake.nodes = dict(MEMBERS)
    fake.is_connected = True
    fake.current_host = A
    return api.set_manager(CID, fake)


@pytest.mark.parametrize('body', [
    {'host': '192.0.2.50', 'pass': 'cluster-pw'},
    {'fallback_hosts': [B, '192.0.2.51'], 'pass': 'cluster-pw'},
], ids=['host', 'fallback_hosts'])
def test_moving_the_endpoint_does_not_carry_node_passwords_along(api, seed, db, monkeypatch, body):
    import pegaprox.api.clusters as clusters_api
    monkeypatch.setattr(clusters_api, 'save_config', lambda: None)
    _fake(api)
    db.save_node_credential(CID, 'pve2', PW_B, 'alice')
    admin = seed.user('root', role='admin')
    r = api.as_user(admin).put(f'/api/clusters/{CID}', json=body)
    assert r.status_code == 200, r.data
    # the cluster password had to be typed again for this edit; the node password of
    # pve2 was not, and still sits there to be offered wherever the cluster now points
    assert db.node_credential_secrets(CID) == {}, \
        'per-node passwords survived an endpoint change that required re-entering the credential'
