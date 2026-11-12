"""The config export reads include_secrets, include_users and include_audit as checkboxes.

The three flags were tested for truthiness. The UI sends booleans, but an API client that
sent the string "false" got the opposite: the cluster passwords, API token secrets and SSH
keys in clear, the nodes' own passwords and up to 10,000 audit rows. A string or number is
read the way a checkbox is (helpers._checkbox), and anything else is refused. MK
"""
import json

import pytest

from test_sec_low_migrations import _ADMIN_PW, _BACKUP_PW, _admin_with_password

ROOT_PW = 'cluster-root-pw'


@pytest.fixture
def admin(api, seed):
    seed.db.save_cluster('c1', {'name': 'lab', 'host': '10.0.0.1', 'user': 'root@pam', 'pass': ROOT_PW})
    client = _admin_with_password(api, seed)
    from pegaprox.utils.audit import log_audit
    log_audit('root', 'test.marker', 'an audit row the export may carry')
    return client


def _export(client, **flags):
    import pegaprox.api.settings as settings_api
    r = client.post('/api/config/backup', json=dict(user_password=_ADMIN_PW, backup_password=_BACKUP_PW, **flags))
    if r.status_code != 200:
        return r.status_code, r.get_json()
    return 200, json.loads(settings_api._decrypt_backup(r.get_data(), _BACKUP_PW))


@pytest.mark.parametrize('value', ['false', 'False', '0', 'no'])
def test_include_secrets_false_as_a_string_carries_no_secret(admin, value):
    status, backup = _export(admin, include_secrets=value)

    assert status == 200, backup
    assert 'pass' not in backup['clusters']['c1'] and ROOT_PW not in json.dumps(backup)
    assert 'node_credentials' not in backup


@pytest.mark.parametrize('value', ['false', '0'])
@pytest.mark.parametrize('field,key', [('include_users', 'users'), ('include_audit', 'audit_log')])
def test_the_other_two_read_false_the_same_way(admin, field, key, value):
    status, backup = _export(admin, **{field: value})

    assert status == 200, backup
    assert key not in backup


def test_true_as_a_string_still_asks_for_them(admin):
    """The counterweight: the strings a form sends for a ticked box."""
    status, backup = _export(admin, include_secrets='true', include_users='1', include_audit='yes')

    assert status == 200, backup
    assert backup['clusters']['c1']['pass'] == ROOT_PW
    assert 'root' in backup['users'] and backup['audit_log']


def test_left_out_or_null_they_keep_their_defaults(admin):
    status, backup = _export(admin, include_secrets=None)

    assert status == 200, backup
    assert 'pass' not in backup['clusters']['c1']
    assert 'users' in backup and 'audit_log' not in backup


@pytest.mark.parametrize('field', ['include_secrets', 'include_users', 'include_audit'])
def test_a_value_that_is_no_checkbox_is_refused(admin, field):
    status, body = _export(admin, **{field: 'maybe'})

    assert status == 400, body
    assert body['code'] == 'INVALID_FIELD' and body['field'] == field
