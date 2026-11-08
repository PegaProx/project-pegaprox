"""A PBS API token that always ended in "Ticket auth failed: HTTP 401" (#805).

PBSManager only used the token when BOTH dedicated fields were filled. Everything
else went to POST /access/ticket with user and password, and PBS refuses a token id
there. Three ways got a token into that path without a word:

- 'user@realm!tokenid' as the user name with the secret in the password field, the
  way the Add Cluster dialog takes it for a PVE cluster (its PBS tab had no token
  fields at all);
- the same user name with the secret in the secret field;
- the edit dialog's Test button, which sends '********' for every stored secret, so
  testing a saved server sent the mask to PBS as the password or token secret.

The PUT already filled the mask in from the stored server. The test route now does
the same, for the same host and port only, after the object check. MK
"""
from unittest.mock import MagicMock

import pytest

import pegaprox.api.pbs as pbs_api
import pegaprox.globals as ppglobals
from pegaprox.core.pbs import PBSManager

HOST = '10.0.0.5'
TOKEN_USER = 'root@pam!pegaprox'
FROM_FORM = 'value-from-form'
ON_FILE = 'value-on-file'


class _Resp:
    def __init__(self, status, data=None):
        self.status_code = status
        self._data = data or {}

    def json(self):
        return {'data': self._data}


class _Session:
    """What connect() touches: headers, cookies, get and post. Records every call."""

    def __init__(self, get_status=200, post_status=401):
        self.headers = {}
        self.cookies = MagicMock()
        self.gets, self.posts = [], []
        self.get_status, self.post_status = get_status, post_status

    def get(self, url, **kw):
        self.gets.append((url, dict(self.headers)))
        return _Resp(self.get_status, {'version': '4.0'})

    def post(self, url, data=None, **kw):
        self.posts.append((url, dict(data or {})))
        return _Resp(self.post_status, {'ticket': 't', 'CSRFPreventionToken': 'c'})


def _mgr(get_status=200, post_status=401, **cfg):
    m = PBSManager('p1', dict({'name': 'pbs', 'host': HOST}, **cfg))
    m._session = _Session(get_status, post_status)
    return m


# -- the manager -------------------------------------------------------------------------

def test_a_token_in_the_user_field_with_the_secret_as_password_uses_the_token():
    """The reporter's form, and the one the PVE tab of the same dialog asks for."""
    m = _mgr(user=TOKEN_USER, password=FROM_FORM)
    assert m.connect(), m.last_error
    assert m._session.posts == [], 'a token id went to the password login'
    (url, headers), = m._session.gets
    assert url.endswith('/version')
    assert headers['Authorization'] == f'PBSAPIToken={TOKEN_USER}:{FROM_FORM}'
    assert m.to_dict()['using_api_token'] is True


def test_a_token_in_the_user_field_with_the_secret_in_the_secret_field():
    m = _mgr(user=TOKEN_USER, password=ON_FILE, api_token_secret=FROM_FORM)
    assert m.connect(), m.last_error
    assert m._session.posts == []
    assert m._session.gets[0][1]['Authorization'] == f'PBSAPIToken={TOKEN_USER}:{FROM_FORM}'


def test_a_token_without_any_secret_says_so_instead_of_trying_a_password_login():
    m = _mgr(user=TOKEN_USER)
    assert m.connect() is False
    assert m.last_error == 'API token secret missing'
    assert m._session.posts == [] and m._session.gets == []


def test_the_stored_fields_stay_as_entered():
    """The edit dialog and save_pbs_server read these back; only the connection resolves."""
    m = _mgr(user=TOKEN_USER, password=FROM_FORM)
    assert (m.user, m.password, m.api_token_id, m.api_token_secret) == (TOKEN_USER, FROM_FORM, '', '')
    assert m.to_dict()['api_token_id'] == ''


def test_the_dedicated_fields_still_win():
    m = _mgr(user='root@pam', password=ON_FILE, api_token_id='svc@pbs!backup', api_token_secret=FROM_FORM)
    assert m.connect(), m.last_error
    assert m._session.posts == []
    assert m._session.gets[0][1]['Authorization'] == f'PBSAPIToken=svc@pbs!backup:{FROM_FORM}'


def test_a_plain_password_login_is_unchanged():
    m = _mgr(post_status=200, user='root@pam', password=ON_FILE)
    assert m.connect(), m.last_error
    (url, form), = m._session.posts
    assert url.endswith('/access/ticket')
    assert form == {'username': 'root@pam', 'password': ON_FILE}
    assert m.to_dict()['using_api_token'] is False


def test_a_token_id_without_its_secret_still_logs_in_with_the_password():
    """A config saved like that worked through the password, and keeps working."""
    m = _mgr(post_status=200, user='root@pam', password=ON_FILE, api_token_id='svc@pbs!backup')
    assert m.connect(), m.last_error
    assert m._session.posts[0][1]['password'] == ON_FILE


def test_when_that_password_login_fails_the_error_names_the_missing_secret():
    m = _mgr(user='root@pam', password='wrong', api_token_id='svc@pbs!backup')
    assert m.connect() is False
    assert m.last_error.startswith('Ticket auth failed: HTTP 401')
    assert 'no token secret' in m.last_error


def test_the_update_runner_logs_in_as_root_for_a_token_in_the_user_field(monkeypatch):
    """A token user has no unix account: the same fallback the dedicated fields get."""
    import paramiko
    client = MagicMock()
    client.connect.side_effect = OSError('refused')
    monkeypatch.setattr(paramiko, 'SSHClient', lambda: client)
    m = _mgr(user='svc@pbs!backup', password=FROM_FORM)
    m._ssh_connect()
    assert client.connect.call_args.kwargs['username'] == 'root'


# -- the routes --------------------------------------------------------------------------

class _Recorder:
    """Stands in for PBSManager in the routes: records the config it was built with."""
    built = []

    def __init__(self, pbs_id, config):
        type(self).built.append(dict(config))
        self.last_error = 'Ticket auth failed: HTTP 401'

    def connect(self):
        return False


@pytest.fixture
def stored(api, seed, monkeypatch):
    ppglobals.pbs_managers.clear()
    seed.tenant('tenant_a', clusters=['cluster_1'])
    m = MagicMock()
    m.host, m.port = HOST, 8007
    m.password, m.api_token_secret = ON_FILE, FROM_FORM
    m.linked_clusters = ['cluster_2']
    ppglobals.pbs_managers['p1'] = m
    _Recorder.built = []
    monkeypatch.setattr(pbs_api, 'PBSManager', _Recorder)
    try:
        yield m
    finally:
        ppglobals.pbs_managers.clear()


@pytest.fixture
def admin(api, seed):
    return api.as_user(seed.user('root_adm', role='admin'))


_FORM = {'name': 'pbs', 'host': HOST, 'port': 8007, 'user': 'root@pam', 'password': '********',
         'api_token_id': 'svc@pbs!backup', 'api_token_secret': '********', 'ssh_key': '********'}


def test_the_test_button_of_a_saved_server_never_sends_the_mask(stored, admin):
    r = admin.post('/api/pbs/p1/test', json=_FORM)
    assert r.status_code == 400   # the recorder refuses; what matters is what it got
    cfg, = _Recorder.built
    assert cfg['password'] == ON_FILE
    assert cfg['api_token_secret'] == FROM_FORM
    assert '********' not in (cfg['password'], cfg['api_token_secret'])


def test_a_secret_typed_in_the_edit_dialog_is_tested_as_typed(stored, admin):
    r = admin.post('/api/pbs/p1/test', json=dict(_FORM, api_token_secret='fresh-value'))
    assert r.status_code == 400
    cfg, = _Recorder.built
    assert cfg['api_token_secret'] == 'fresh-value'
    assert cfg['password'] == ON_FILE


def test_another_host_gets_no_stored_secret(stored, admin):
    """The cred-exfil rule of the PUT: a new endpoint gets only what was typed."""
    r = admin.post('/api/pbs/p1/test', json=dict(_FORM, host='10.9.9.9'))
    assert r.status_code == 400
    assert 'Re-enter' in r.get_json()['error']
    assert _Recorder.built == []


def test_another_port_gets_no_stored_secret(stored, admin):
    r = admin.post('/api/pbs/p1/test', json=dict(_FORM, port=8443))
    assert r.status_code == 400
    assert _Recorder.built == []


def test_a_caller_without_access_to_the_server_gets_no_stored_secret(stored, api, seed):
    outsider = api.as_user(seed.user('a_admin', role='user', tenant_id='tenant_a',
                                     permissions=['pbs.config']))
    r = outsider.post('/api/pbs/p1/test', json=_FORM)
    assert r.status_code == 403
    assert _Recorder.built == []


def test_a_server_that_is_not_loaded_has_no_stored_secret_to_give(stored, admin):
    ppglobals.pbs_managers.clear()
    r = admin.post('/api/pbs/p1/test', json=_FORM)
    assert r.status_code == 404
    assert _Recorder.built == []


def test_a_test_with_typed_credentials_is_unchanged(stored, admin):
    body = dict(_FORM, password='typed-pw', api_token_secret='', api_token_id='')
    r = admin.post('/api/pbs/p1/test', json=body)
    assert r.status_code == 400
    cfg, = _Recorder.built
    assert cfg['password'] == 'typed-pw'


def test_adding_with_only_the_token_fields_is_accepted(stored, admin):
    """The add route's own message says 'Username or API token is required'."""
    r = admin.post('/api/pbs', json={'name': 'pbs', 'host': HOST, 'user': '',
                                     'api_token_id': 'svc@pbs!backup', 'api_token_secret': FROM_FORM})
    assert 'required' not in (r.get_json() or {}).get('error', '')
    cfg, = _Recorder.built
    assert cfg['api_token_id'] == 'svc@pbs!backup'
