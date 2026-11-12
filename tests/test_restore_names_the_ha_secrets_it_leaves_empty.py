"""A restore names the HA secrets of a cluster that it leaves empty.

The HA settings of a cluster hold the key its self-fence agents sign the leader question
with, and the BMC password of each node's fence. A backup without secrets leaves both
out (api/settings.py _strip_cluster_secrets). A merge restore keeps what the cluster has,
and so does an overwrite while the backup leaves the cluster's addresses. An overwrite
that moves the cluster writes the backup's HA settings as they are: the installed agents
are answered 403 from then on and the fences have nothing to log in with, and the answer
of the restore said nothing of it.

The answer names them now in secrets_to_enter, the dry run as well: the agent key of the
cluster, and the nodes whose fence the backup still has without its password. MK
"""
import io
import json

import pytest

from test_sec_low_migrations import _ADMIN_PW, _BACKUP_PW, _admin_with_password

TOKEN = 'ab' * 32
FENCES = {'pve1': {'type': 'ipmi', 'host': '10.0.1.1', 'user': 'admin', 'password': 'bmc-one'},
          'pve2': {'type': 'ipmi', 'host': '10.0.1.2', 'user': 'admin', 'password': 'bmc-two'}}
ROW = dict(name='lab', host='10.0.0.1', fallback_hosts=[], user='root@pam', ssh_port=22,
           ssl_verification=True, **{'pass': 'root-pw'},
           ha_settings={'agent_token': TOKEN, 'self_fence_installed': True, 'fencing': FENCES})


@pytest.fixture
def admin(api, seed):
    seed.db.save_cluster('c1', json.loads(json.dumps(ROW)))
    return _admin_with_password(api, seed)


def _row(secrets=False, **changes):
    """The row of c1 as an export holds it, with or without its secrets."""
    from pegaprox.core.db import get_db
    from pegaprox.api.settings import _strip_cluster_secrets
    row = get_db().get_all_clusters()['c1']
    row = row if secrets else _strip_cluster_secrets(row)
    row.update(changes)
    return row


def _restore(client, row, mode, dry_run=False):
    import pegaprox.api.settings as settings_api
    data = {'version': 'test', 'export_date': '2026-11-01T10:00:00', 'clusters': {'c1': row}}
    blob = settings_api._encrypt_backup(json.dumps(data), _BACKUP_PW)
    r = client.post('/api/config/restore', content_type='multipart/form-data',
                    data={'user_password': _ADMIN_PW, 'backup_password': _BACKUP_PW, 'mode': mode,
                          'dry_run': 'true' if dry_run else 'false',
                          'backup_file': (io.BytesIO(blob), 'x.pegabackup')})
    assert r.status_code == 200, r.get_data(as_text=True)
    res = r.get_json()
    assert not res['errors'], res
    return res


def _ha():
    from pegaprox.core.db import get_db
    return get_db().get_cluster('c1')['ha_settings']


@pytest.mark.parametrize('dry_run', [False, True], ids=['restore', 'dry-run'])
def test_an_overwrite_that_moves_the_cluster_names_the_agent_key_and_the_fences(admin, dry_run):
    res = _restore(admin, _row(host='10.9.9.9'), 'overwrite', dry_run=dry_run)

    assert res.get('secrets_to_enter') == [{'cluster': 'lab'},
                                           {'cluster': 'lab', 'agent_token': True},
                                           {'cluster': 'lab', 'fences': ['pve1', 'pve2']}]
    if not dry_run:
        # it names what the restore did
        assert not _ha().get('agent_token')
        assert [f.get('password') for f in _ha()['fencing'].values()] == [None, None]


def test_a_fence_the_backup_does_not_have_is_not_named(admin):
    row = _row(host='10.9.9.9')
    del row['ha_settings']['fencing']['pve2']

    res = _restore(admin, row, 'overwrite')

    assert {'cluster': 'lab', 'fences': ['pve1']} in res['secrets_to_enter']


def test_an_instance_whose_agents_have_no_key_names_none(admin, seed):
    seed.db.save_cluster('c1', dict(json.loads(json.dumps(ROW)), ha_settings={}))

    res = _restore(admin, _row(), 'overwrite')

    assert 'secrets_to_enter' not in res, res


def test_a_merge_keeps_them_and_names_none(admin):
    """The counterweight: a merge leaves the HA secrets as the cluster has them."""
    res = _restore(admin, _row(), 'merge')

    assert 'secrets_to_enter' not in res, res
    assert _ha()['agent_token'] == TOKEN
    assert {n: f['password'] for n, f in _ha()['fencing'].items()} == {'pve1': 'bmc-one', 'pve2': 'bmc-two'}


def test_an_overwrite_that_carries_them_names_none(admin):
    """The counterweight: a backup with its secrets writes them back."""
    res = _restore(admin, _row(secrets=True), 'overwrite')

    assert 'secrets_to_enter' not in res, res
    assert _ha()['agent_token'] == TOKEN
