"""A restore keeps a cluster's HA secrets while the backup leaves the cluster's addresses.

The HA settings of a cluster hold the key its self-fence agents sign the leader question
with, and the BMC password of each node's fence. A backup without secrets leaves both out.
An overwrite restore wrote the backup's HA settings as they were: every installed agent was
answered 403 from then on, and a tiebreak node that hears no leader fences itself.

An overwrite now keeps them by the rule of the cluster's own password (api/settings.py
_cluster_moves): a blank in the backup keeps what the cluster has while the backup names no
address the cluster does not have, and a fence's password while the fence keeps its type
and its BMC. A backup that moves the cluster takes none of them along, and the answer names
them. A backup that carries its own writes those. Anything in a secret's place that is not
a string counts as blank, as do a password of blanks only and an agent key the cluster
would not take as one. MK
"""
import hmac
import io
import json

import pytest

from test_sec_low_migrations import _ADMIN_PW, _BACKUP_PW, _admin_with_password

TOKEN = 'ab' * 32
FENCES = {'pve1': {'type': 'ipmi', 'host': '10.0.1.1', 'user': 'admin', 'password': 'bmc-one'},
          'pve2': {'type': 'ipmi', 'host': '10.0.1.2', 'user': 'admin', 'password': 'bmc-two'}}
ROW = dict(name='lab', host='10.0.0.1', fallback_hosts=['10.0.0.2'], user='root@pam', ssh_port=22,
           ssl_verification=True, **{'pass': 'root-pw'},
           ha_settings={'agent_token': TOKEN, 'self_fence_installed': True, 'fencing': FENCES})
MOVES = pytest.mark.parametrize('change', [{'host': '10.9.9.9'}, {'fallback_hosts': ['10.0.0.2', '10.9.9.9']},
                                           {'ssh_port': 2222}, {'ssl_verification': False}],
                                ids=['host', 'fallback-host', 'ssh-port', 'no-certificate-check'])


@pytest.fixture
def admin(api, seed, tmp_path, monkeypatch):
    from pegaprox.core import ha
    # a standalone instance: it leads, and answers the agents
    monkeypatch.setattr(ha, 'STATE_FILE', str(tmp_path / 'ha_state.json'))
    ha.reset_for_tests()
    seed.db.save_cluster('c1', json.loads(json.dumps(ROW)))
    yield _admin_with_password(api, seed)
    ha.reset_for_tests()


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


def _passwords():
    return {n: f.get('password') for n, f in _ha()['fencing'].items()}


def _started(api):
    """The manager the next start builds from the stored row, which the agents ask."""
    from pegaprox.core.manager import PegaProxManager
    m = PegaProxManager.__new__(PegaProxManager)
    m.id = 'c1'
    m._apply_ha_settings(_ha())
    return api.set_manager('c1', m)


def _agent_asks(api, token=TOKEN, nonce='0f' * 16):
    sig = hmac.new(token.encode(), f'pegaprox-agent ask c1 {nonce}'.encode(), 'sha256').hexdigest()
    return api.anon().get(f'/api/ha/agent?cluster=c1&nonce={nonce}&sig={sig}')


@pytest.mark.parametrize('mode', ['merge', 'overwrite'])
def test_a_backup_without_secrets_keeps_the_agent_key_and_the_fence_passwords(api, admin, mode):
    row = _row()
    assert 'agent_token' not in row['ha_settings']
    assert not any('password' in f for f in row['ha_settings']['fencing'].values())

    res = _restore(admin, row, mode)

    assert 'secrets_to_enter' not in res, res
    assert _ha()['agent_token'] == TOKEN
    assert _passwords() == {'pve1': 'bmc-one', 'pve2': 'bmc-two'}
    # the installed agents still hear their leader, and the fences can be read back
    m = _started(api)
    r = _agent_asks(api)
    assert r.status_code == 200 and r.get_data(as_text=True).startswith('leader ')
    assert m._ha_fence_readable('pve1') and m._ha_fence_readable('pve2')


def test_a_dry_run_of_it_names_nothing(admin):
    res = _restore(admin, _row(), 'overwrite', dry_run=True)

    assert 'secrets_to_enter' not in res, res


@MOVES
def test_an_overwrite_that_moves_the_cluster_takes_them_not_along(api, admin, change):
    res = _restore(admin, _row(**change), 'overwrite')

    assert not _ha().get('agent_token')
    assert _passwords() == {'pve1': None, 'pve2': None}
    assert {'cluster': 'lab', 'agent_token': True} in res['secrets_to_enter']
    assert {'cluster': 'lab', 'fences': ['pve1', 'pve2']} in res['secrets_to_enter']
    # the counterproof of the agent answer above
    _started(api)
    assert _agent_asks(api).status_code == 403


@pytest.mark.parametrize('fence', [{'host': '10.0.7.7'}, {'type': 'ssh'}, {'host': None}],
                         ids=['other-bmc', 'other-type', 'no-bmc'])
def test_a_fence_the_backup_points_elsewhere_loses_its_password(admin, fence):
    row = _row()
    row['ha_settings']['fencing']['pve2'].update(fence)

    res = _restore(admin, row, 'overwrite')

    assert _passwords() == {'pve1': 'bmc-one', 'pve2': None}
    assert _ha()['agent_token'] == TOKEN
    assert res.get('secrets_to_enter') == [{'cluster': 'lab', 'fences': ['pve2']}]


@pytest.mark.parametrize('moved', [{}, {'host': '10.9.9.9'}], ids=['same-cluster', 'moved'])
def test_a_backup_that_carries_its_own_writes_those(admin, moved):
    row = _row(secrets=True, **moved)
    row['ha_settings']['agent_token'] = 'cd' * 32
    row['ha_settings']['fencing']['pve1']['password'] = 'bmc-new'

    res = _restore(admin, row, 'overwrite')

    assert _ha()['agent_token'] == 'cd' * 32
    assert _passwords() == {'pve1': 'bmc-new', 'pve2': 'bmc-two'}
    assert not [s for s in res.get('secrets_to_enter', []) if 'agent_token' in s or 'fences' in s], res


@pytest.mark.parametrize('value', [[], {}, 0, 1234, True], ids=['list', 'dict', 'zero', 'number', 'true'])
def test_a_value_that_is_no_string_counts_as_blank(api, admin, value):
    row = _row()
    row['ha_settings']['agent_token'] = value
    row['ha_settings']['fencing']['pve1']['password'] = value

    res = _restore(admin, row, 'overwrite')

    assert 'secrets_to_enter' not in res, res
    assert _ha()['agent_token'] == TOKEN
    assert _passwords() == {'pve1': 'bmc-one', 'pve2': 'bmc-two'}
    _started(api)
    assert _agent_asks(api).status_code == 200


@pytest.mark.parametrize('value', [' ', 'zz', 'AB' * 32, 'ab' * 31],
                         ids=['blank', 'short', 'upper-case', 'too-short'])
def test_an_agent_key_the_cluster_would_not_take_counts_as_blank(api, admin, value):
    """The manager makes a new key for anything that is not 64 lower-case hex digits
    (core/manager.py _ha_agent_token), and every agent is answered 403 under it."""
    row = _row()
    row['ha_settings']['agent_token'] = value

    res = _restore(admin, row, 'overwrite')

    assert 'secrets_to_enter' not in res, res
    assert _ha()['agent_token'] == TOKEN
    _started(api)
    assert _agent_asks(api).status_code == 200


@pytest.mark.parametrize('value', [' ', '\t  '], ids=['blank', 'tab'])
def test_a_fence_password_of_blanks_only_counts_as_blank(admin, value):
    row = _row()
    row['ha_settings']['fencing']['pve1']['password'] = value

    res = _restore(admin, row, 'overwrite')

    assert 'secrets_to_enter' not in res, res
    assert _passwords() == {'pve1': 'bmc-one', 'pve2': 'bmc-two'}


def test_a_backup_that_moves_the_cluster_names_them_whatever_stands_in_their_place(admin):
    row = _row(host='10.9.9.9')
    row['ha_settings']['agent_token'] = 'zz'
    row['ha_settings']['fencing']['pve1']['password'] = ' '

    res = _restore(admin, row, 'overwrite')

    assert {'cluster': 'lab', 'agent_token': True} in res['secrets_to_enter']
    assert {'cluster': 'lab', 'fences': ['pve1', 'pve2']} in res['secrets_to_enter']


def test_a_row_without_ha_settings_keeps_the_agent_key(admin):
    """An older backup: the fences it does not have are gone, the agents keep their key."""
    row = _row()
    del row['ha_settings']

    res = _restore(admin, row, 'overwrite')

    assert _ha().get('agent_token') == TOKEN
    assert 'secrets_to_enter' not in res, res
