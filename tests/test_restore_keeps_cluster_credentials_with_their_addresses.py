"""A restore keeps a cluster's stored credentials only while the backup leaves its addresses.

A backup without secrets carries the cluster rows without their password, API token
secret and SSH key. An overwrite restore wrote that blank over the cluster's, so the
cluster lost its connection. A merge restore kept the cluster's for whatever host, fallback
host or SSH port the backup named, and the next reconnect handed the stored credential to
that address; the cluster edit asks for it again in that case (api/clusters.py
_config_edit_checks).

Both modes now keep them while the backup leaves the addresses as they are, and drop them
otherwise. A node address in the HA settings that the cluster does not have counts as well:
the HA node checks log in there with the cluster's root password. The nodes' own root
passwords go where the cluster says its nodes are, so a move
drops them as well, whatever the row carries, as the cluster edit does; those the backup
holds for the cluster are stored again. The answer names every cluster that ends up without
a password or token, and the nodes that lost their own. MK
"""
import io
import json

import pytest

from test_sec_low_migrations import _ADMIN_PW, _BACKUP_PW, _admin_with_password

ROW = dict(name='lab', host='10.0.0.1', fallback_hosts=['10.0.0.2'], user='root@pam', ssh_port=22,
           ssl_verification=True, api_token_user='pp@pve!t', ssh_key='SSH-KEY', **{'pass': 'root-pw'},
           api_token_secret='token-secret')
SECRETS = ('pass', 'api_token_secret', 'ssh_key')


@pytest.fixture
def admin(api, seed):
    seed.db.save_cluster('c1', dict(ROW))
    return _admin_with_password(api, seed)


def _without_secrets(**changes):
    """The row of c1 as an export without secrets holds it."""
    from pegaprox.core.db import get_db
    from pegaprox.api.settings import _strip_cluster_secrets
    row = _strip_cluster_secrets(get_db().get_all_clusters()['c1'])
    row.update(changes)
    return row


def _restore(client, clusters, mode, node_credentials=None, dry_run=False):
    import pegaprox.api.settings as settings_api
    data = {'version': 'test', 'export_date': '2026-11-01T10:00:00', 'clusters': clusters}
    if node_credentials is not None:
        data['node_credentials'] = node_credentials
    blob = settings_api._encrypt_backup(json.dumps(data), _BACKUP_PW)
    r = client.post('/api/config/restore', content_type='multipart/form-data',
                    data={'user_password': _ADMIN_PW, 'backup_password': _BACKUP_PW, 'mode': mode,
                          'dry_run': 'true' if dry_run else 'false',
                          'backup_file': (io.BytesIO(blob), 'x.pegabackup')})
    assert r.status_code == 200, r.get_data(as_text=True)
    res = r.get_json()
    assert not res['errors'], res
    return res


def _secrets(cid='c1'):
    from pegaprox.core.db import get_db
    row = get_db().get_cluster(cid)
    return {k: row[k] for k in SECRETS}


@pytest.mark.parametrize('mode', ['merge', 'overwrite'])
def test_a_backup_without_secrets_restored_here_keeps_the_cluster_credentials(admin, mode):
    row = _without_secrets()
    assert not any(row.get(k) for k in SECRETS)

    res = _restore(admin, {'c1': row}, mode)

    assert _secrets() == {'pass': 'root-pw', 'api_token_secret': 'token-secret', 'ssh_key': 'SSH-KEY'}
    assert 'secrets_to_enter' not in res, res


# a node address only the HA settings name
HA_NODE_ADDRESS = {'ha_settings': {'node_ips': {'pve2': '203.0.113.9'}}}


@pytest.mark.parametrize('mode', ['merge', 'overwrite'])
@pytest.mark.parametrize('change', [{'host': '10.9.9.9'}, {'fallback_hosts': ['10.0.0.2', '10.9.9.9']},
                                    {'ssh_port': 2222}, {'ssl_verification': False}, HA_NODE_ADDRESS],
                         ids=['host', 'fallback-host', 'ssh-port', 'no-certificate-check', 'ha-node-address'])
def test_a_backup_that_moves_the_cluster_takes_no_stored_credential_along(admin, mode, change):
    res = _restore(admin, {'c1': _without_secrets(**change)}, mode)

    assert _secrets() == {k: '' for k in SECRETS}
    assert res.get('secrets_to_enter') == [{'cluster': 'lab'}]


def test_a_host_it_already_falls_back_to_is_no_move(admin):
    """The counterweight, as in the cluster edit: the backup names the fallback host as the
    host, and the credential goes nowhere it did not go before."""
    _restore(admin, {'c1': _without_secrets(host='10.0.0.2', fallback_hosts=['10.0.0.1'])}, 'overwrite')

    assert _secrets()['pass'] == 'root-pw'


@pytest.mark.parametrize('mode', ['merge', 'overwrite'])
@pytest.mark.parametrize('typed', [{'pve1': '10.0.0.1', 'pve2': ['[10.0.0.2]', '']}, {'pve2': '10.0.5.2'},
                                   {'pve2': None}],
                         ids=['host-and-fallback', 'stored', 'empty'])
def test_a_node_address_the_credential_goes_to_already_is_no_move(admin, seed, mode, typed):
    """The counterweight: the cluster's own host and fallback host, the HA settings' stored
    address, and an empty one."""
    seed.db.save_cluster('c1', dict(ROW, ha_settings={'node_ips': {'pve2': '10.0.5.2'}}))

    res = _restore(admin, {'c1': _without_secrets(ha_settings={'node_ips': typed})}, mode)

    assert _secrets() == {'pass': 'root-pw', 'api_token_secret': 'token-secret', 'ssh_key': 'SSH-KEY'}
    assert 'secrets_to_enter' not in res, res


def test_a_cluster_this_instance_does_not_have_is_named(admin):
    row = dict(_without_secrets(), name='other')

    res = _restore(admin, {'c9': row}, 'merge')

    assert _secrets('c9') == {k: '' for k in SECRETS}
    assert res.get('secrets_to_enter') == [{'cluster': 'other'}]


@pytest.mark.parametrize('mode', ['merge', 'overwrite'])
def test_a_password_the_backup_carries_is_stored_for_a_new_host_too(admin, mode):
    """The counterweight: a backup with the secrets sets them, wherever the host is."""
    res = _restore(admin, {'c1': _without_secrets(host='10.9.9.9', **{'pass': 'new-pw'})}, mode)

    assert _secrets()['pass'] == 'new-pw'
    assert 'secrets_to_enter' not in res, res


# -- the nodes' own root passwords ------------------------------------------------------------

MOVES = pytest.mark.parametrize('change', [{'host': '10.9.9.9'}, {'fallback_hosts': ['10.0.0.2', '10.9.9.9']},
                                           {'ssh_port': 2222}, {'ssl_verification': False}, HA_NODE_ADDRESS],
                                ids=['host', 'fallback-host', 'ssh-port', 'no-certificate-check',
                                     'ha-node-address'])


@pytest.fixture
def nodes(admin, seed):
    """pve2 and pve3 of c1 with a root password of their own, pve1 with the cluster's."""
    seed.db.save_node_credential('c1', 'pve2', 'pve2-own-root', 'admin')
    seed.db.save_node_credential('c1', 'pve3', 'pve3-own-root', 'admin')
    return admin


def _node_passwords(cid='c1'):
    from pegaprox.core.db import get_db
    return get_db().node_credential_secrets(cid)


@MOVES
@pytest.mark.parametrize('carried', [{'pass': 'new-pw'}, {}], ids=['with-pass', 'without-secrets'])
@pytest.mark.parametrize('mode', ['merge', 'overwrite'])
def test_a_backup_that_moves_the_cluster_drops_the_nodes_own_passwords(nodes, mode, carried, change):
    res = _restore(nodes, {'c1': _without_secrets(**change, **carried)}, mode)

    assert _node_passwords() == {}
    assert {'cluster': 'lab', 'nodes': ['pve2', 'pve3']} in res.get('secrets_to_enter', [])
    from pegaprox.core.db import get_db
    audit = [r['details'] for r in get_db().query(
        "SELECT details FROM audit_log WHERE action = 'cluster.node_credential_removed'")]
    assert audit and 'pve2, pve3' in audit[-1] and 'own-root' not in audit[-1]


@pytest.mark.parametrize('mode', ['merge', 'overwrite'])
def test_a_backup_that_leaves_the_addresses_keeps_the_nodes_own_passwords(nodes, mode):
    """The counterweight: the same addresses, the same passwords for the nodes."""
    res = _restore(nodes, {'c1': _without_secrets()}, mode)

    assert _node_passwords() == {'pve2': 'pve2-own-root', 'pve3': 'pve3-own-root'}
    assert 'secrets_to_enter' not in res, res


@pytest.mark.parametrize('mode', ['merge', 'overwrite'])
def test_node_passwords_the_backup_carries_are_stored_for_the_moved_cluster(nodes, mode):
    res = _restore(nodes, {'c1': _without_secrets(host='10.9.9.9', **{'pass': 'new-pw'})}, mode,
                   node_credentials={'c1': {'pve2': 'pve2-new-root'}})

    assert _node_passwords() == {'pve2': 'pve2-new-root'}
    assert res['restored']['node_credentials'] == 1
    assert res.get('secrets_to_enter') == [{'cluster': 'lab', 'nodes': ['pve3']}]


def test_a_dry_run_names_the_nodes_and_keeps_their_passwords(nodes):
    res = _restore(nodes, {'c1': _without_secrets(host='10.9.9.9')}, 'merge', dry_run=True)

    assert res.get('secrets_to_enter') == [{'cluster': 'lab'}, {'cluster': 'lab', 'nodes': ['pve2', 'pve3']}]
    assert _node_passwords() == {'pve2': 'pve2-own-root', 'pve3': 'pve3-own-root'}
