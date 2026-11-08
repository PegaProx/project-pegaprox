"""A PBS update starts from the stored server, not from the request body.

update_pbs_server handed the body to save_pbs_server, which keeps the encrypted
secrets and the link list when the body leaves them out, and then rebuilt the
live manager from the body alone. After any partial update the two disagreed:

- (#999) a PUT without linked_clusters left the running manager unlinked.
  check_pbs_access reads the manager, and an empty list lets every tenant in,
  until the next restart reloaded the row.
- (#1033) a PUT without the secrets emptied them in memory only. The
  host-change guard looked there, so a second PUT could move the server to
  another host without re-entering anything, and the row still held the real
  credentials for the next start to send there.

A real row and a real manager; only the login is stubbed, and it records where
it would have gone. MK
"""
import pytest

import pegaprox.globals as ppglobals
from pegaprox.core import pbs as corepbs


PBS_ID = 'pbs_shared'
URL = f'/api/pbs/{PBS_ID}'
HOST = 'pbs.example.com'
FP = ':'.join(['AB'] * 32)

# what the edit dialog sends back for a saved server (web/src/dashboard.js), less the
# link list - an API client is free to leave any field out
_EDIT = {'name': 'Shared', 'host': HOST, 'port': 8007, 'user': 'root@pam',
         'password': '********', 'api_token_id': '', 'api_token_secret': '',
         'fingerprint': FP, 'ssl_verify': True, 'notes': 'rack 4',
         'ssh_user': 'root', 'ssh_port': 22, 'ssh_key': '********'}


@pytest.fixture
def logins(monkeypatch):
    """(host, password, token secret, ssh key) of every login a manager tried."""
    seen = []

    def _connect(self):
        seen.append((self.host, self.password, self.api_token_secret, self.ssh_key))
        self.connected = False
        return False

    monkeypatch.setattr(corepbs.PBSManager, 'connect', _connect)
    return seen


@pytest.fixture
def shared_pbs(api, seed, logins):
    """One PBS for two tenants, stored the way add_pbs_server stores it."""
    ppglobals.pbs_managers.clear()
    seed.tenant('tenant_a', clusters=['cluster_1'])
    seed.tenant('tenant_b', clusters=['cluster_2'])
    seed.tenant('tenant_c', clusters=['cluster_3'])
    config = {'name': 'Shared', 'host': HOST, 'port': 8007, 'user': 'root@pam',
              'password': 'REAL-PASSWORD', 'fingerprint': FP, 'ssl_verify': True,
              'linked_clusters': ['cluster_1', 'cluster_2'], 'notes': 'rack 4',
              'ssh_user': 'root', 'ssh_key': 'REAL-KEY'}
    corepbs.save_pbs_server(PBS_ID, config)
    ppglobals.pbs_managers[PBS_ID] = corepbs.PBSManager(PBS_ID, config)
    try:
        yield
    finally:
        ppglobals.pbs_managers.clear()


@pytest.fixture
def tenant_admin(api, seed, shared_pbs):
    return api.as_user(seed.user('a_admin', role='user', tenant_id='tenant_a',
                                 permissions=['pbs.config', 'pbs.view']))


def _row(seed):
    r = seed.db.conn.execute("SELECT * FROM pbs_servers WHERE id = ?", (PBS_ID,)).fetchone()
    return dict(r)


def _live():
    return ppglobals.pbs_managers[PBS_ID]


# -- (#999) the link list ---------------------------------------------------------------

def test_an_update_without_the_link_list_keeps_the_running_server_linked(tenant_admin):
    r = tenant_admin.put(URL, json=_EDIT)

    assert r.status_code == 200, r.get_data(as_text=True)
    assert _live().linked_clusters == ['cluster_1', 'cluster_2'], \
        'the live manager was unlinked while the row kept the links'


def test_after_such_an_update_another_tenant_still_cannot_reach_the_server(api, seed, tenant_admin):
    """What the unlinked manager meant: check_pbs_access let every tenant in."""
    assert tenant_admin.put(URL, json=_EDIT).status_code == 200
    outsider = api.as_user(seed.user('c_viewer', role='viewer', tenant_id='tenant_c'))

    r = outsider.get(f'{URL}/status')

    assert r.status_code == 403, r.get_data(as_text=True)


def test_an_update_naming_one_field_leaves_the_rest_as_stored(tenant_admin, seed):
    r = tenant_admin.put(URL, json={'notes': 'rack 5'})

    row = _row(seed)
    assert row['host'] == HOST, 'the host was written empty'
    assert row['fingerprint'] == FP, 'the certificate pin was dropped'
    assert row['ssl_verify'] == 1
    assert row['notes'] == 'rack 5'
    assert r.status_code == 200, r.get_data(as_text=True)
    assert _live().fingerprint == FP and _live().ssl_verify is True


def test_a_host_the_manager_refuses_leaves_the_row_alone(tenant_admin, seed):
    r = tenant_admin.put(URL, json={**_EDIT, 'host': 'not a host/', 'password': 'NEW',
                                    'ssh_key': 'NEW-KEY'})

    assert r.status_code == 400, r.get_data(as_text=True)
    assert _row(seed)['host'] == HOST, 'the refused host was saved before it was checked'


# -- (#1033) the secrets ----------------------------------------------------------------

def test_an_update_without_the_secrets_keeps_them_in_the_live_manager(tenant_admin, logins):
    body = {k: v for k, v in _EDIT.items() if k not in ('password', 'ssh_key')}

    r = tenant_admin.put(URL, json=body)

    assert r.status_code == 200, r.get_data(as_text=True)
    assert _live().password == 'REAL-PASSWORD'
    assert _live().ssh_key == 'REAL-KEY'
    assert logins[-1] == (HOST, 'REAL-PASSWORD', '', 'REAL-KEY')


def test_dropping_the_secrets_first_does_not_open_a_host_change(tenant_admin, seed, logins):
    """The two-step: empty the secrets in memory, then move the host."""
    first = tenant_admin.put(URL, json={'name': 'Shared', 'host': HOST, 'port': 8007})
    assert first.status_code == 200, first.get_data(as_text=True)

    second = tenant_admin.put(URL, json={'name': 'Shared', 'host': 'collector.example.net',
                                         'port': 8007, 'fingerprint': ''})

    assert _row(seed)['host'] == HOST, 'the stored credentials now point at another host'
    assert second.status_code == 400, second.get_data(as_text=True)
    assert 're-enter' in second.get_data(as_text=True).lower()
    assert all(host == HOST for host, *_ in logins), logins


def test_a_secret_that_no_longer_decrypts_still_has_to_be_re_entered(tenant_admin, seed):
    """Held means the column is set. A secret we cannot read today may be readable after
    a key restore, and it would then go to the new host."""
    seed.db.conn.execute("UPDATE pbs_servers SET pass_encrypted = 'not-a-ciphertext' "
                         "WHERE id = ?", (PBS_ID,))
    seed.db.conn.commit()

    r = tenant_admin.put(URL, json={**_EDIT, 'host': 'collector.example.net',
                                    'ssh_key': 'NEW-KEY'})

    assert r.status_code == 400, r.get_data(as_text=True)


# -- what has to keep working -----------------------------------------------------------

def test_the_edit_dialog_round_trip_keeps_the_stored_secrets(api, seed, shared_pbs, logins):
    """The dialog sends the link list back as well, which only someone holding both
    clusters may do - the narrowing guard sees to that."""
    seed.tenant('tenant_ab', clusters=['cluster_1', 'cluster_2'])
    owner = api.as_user(seed.user('ab_admin', role='user', tenant_id='tenant_ab',
                                  permissions=['pbs.config']))

    r = owner.put(URL, json={**_EDIT, 'linked_clusters': ['cluster_1', 'cluster_2']})

    assert r.status_code == 200, r.get_data(as_text=True)
    assert logins[-1] == (HOST, 'REAL-PASSWORD', '', 'REAL-KEY')


def test_a_host_change_with_every_secret_re_entered_goes_through(tenant_admin, seed, logins):
    r = tenant_admin.put(URL, json={**_EDIT, 'host': 'pbs2.example.com', 'fingerprint': '',
                                    'password': 'NEW-PASSWORD', 'ssh_key': 'NEW-KEY'})

    assert r.status_code == 200, r.get_data(as_text=True)
    assert _row(seed)['host'] == 'pbs2.example.com'
    assert logins[-1] == ('pbs2.example.com', 'NEW-PASSWORD', '', 'NEW-KEY')
    assert _live().linked_clusters == ['cluster_1', 'cluster_2']


def test_a_global_admin_can_still_unlink_it(api, seed, shared_pbs):
    boss = api.as_user(seed.user('boss', role='admin'))

    r = boss.put(URL, json={**_EDIT, 'linked_clusters': []})

    assert r.status_code == 200, r.get_data(as_text=True)
    assert _live().linked_clusters == []
    assert _row(seed)['linked_clusters'] == '[]'


def test_the_row_and_the_manager_agree_after_an_update(tenant_admin):
    """The property itself: what runs now is what the next start would load."""
    assert tenant_admin.put(URL, json={'notes': 'rack 6', 'host': HOST}).status_code == 200
    live = _live()

    corepbs.load_pbs_servers(only=[PBS_ID])         # what a restart builds from the row
    reloaded = _live()

    assert reloaded is not live
    for key in ('host', 'port', 'user', 'password', 'api_token_secret', 'fingerprint',
                'ssl_verify', 'linked_clusters', 'notes', 'ssh_user', 'ssh_key'):
        assert getattr(live, key) == getattr(reloaded, key), key
