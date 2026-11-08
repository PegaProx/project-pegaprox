"""Pointing a cluster somewhere new needs its credential typed again.

The stored password (or token secret) of a cluster goes to its host and fallback hosts on
every reconnect and console ticket mint, over TLS verified or not as the cluster says.
PUT /api/clusters/<id>, PATCH /api/clusters/<id>/config and PUT .../fallback-hosts took a
new host, new fallback hosts or ssl_verification=false and kept the credential, so the
next connect logged in at the new address with it. A delegated cluster.config holder could
collect the cluster account that way.

Like PBS and the ESXi servers: an edit that adds an address, changes the SSH port or turns
verification off is refused unless the request carries the credential, and what goes to the
new address is only what that request typed. A rename and every other field edit work as
before.

Aikido 700487424.
"""
import types

import pytest

import pegaprox.api.clusters as clusters_api
import pegaprox.core.manager as mgrmod
from pegaprox.models.tasks import PegaProxConfig


OLD_HOST = '10.40.0.1'
FALLBACK = '10.40.0.2'
NEW_HOST = 'collector.example.net'
STORED_PW = 'stored-cluster-password'
STORED_TOKEN = 'stored-token-secret'


def _row(**over):
    row = dict(name='lab', host=OLD_HOST, user='root@pam', ssl_verification=True,
               fallback_hosts=[FALLBACK], ssh_user='', ssh_key='', ssh_port=22,
               cluster_type='proxmox', api_port=8006)
    row['pass'] = STORED_PW
    row.update(over)
    return row


@pytest.fixture
def env(api, seed, monkeypatch):
    """One stored password cluster, connected, with a real manager; save_config is a
    no-op (a standby would refuse it and there is no second instance here)."""
    monkeypatch.setattr(clusters_api, 'save_config', lambda: True)
    seed.db.save_cluster('c1', _row())
    m = mgrmod.PegaProxManager('c1', PegaProxConfig(seed.db.get_cluster('c1')))
    m.current_host = OLD_HOST
    m._original_host = OLD_HOST
    m.is_connected = True
    m._ticket = 'PVE:root@pam:TICKET'
    m._csrf_token = 'csrf'
    api.set_manager('c1', m)
    admin = seed.user('root', role='admin')
    return types.SimpleNamespace(api=api, seed=seed, mgr=m, c=api.as_user(admin), db=seed.db)


@pytest.fixture
def token_env(api, seed, monkeypatch):
    """A cluster that authenticates with an inline API token: pass_ is the token secret."""
    monkeypatch.setattr(clusters_api, 'save_config', lambda: True)
    row = _row(user='root@pam!ci')
    row['pass'] = STORED_TOKEN
    row['api_token_user'] = 'root@pam!ci'
    row['api_token_secret'] = STORED_TOKEN
    seed.db.save_cluster('c2', row)
    m = mgrmod.PegaProxManager('c2', PegaProxConfig(seed.db.get_cluster('c2')))
    m.current_host = OLD_HOST
    m.is_connected = True
    m._api_token = f'root@pam!ci={STORED_TOKEN}'
    api.set_manager('c2', m)
    admin = seed.user('root', role='admin')
    return types.SimpleNamespace(api=api, seed=seed, mgr=m, c=api.as_user(admin), db=seed.db)


def _status(r):
    return r.status_code


# --- the move must be refused when the credential would be carried along ------------

MOVES = [
    ('a new host', {'host': NEW_HOST}),
    ('new fallback hosts', {'fallback_hosts': [NEW_HOST]}),
    ('tls verification off', {'ssl_verification': False}),
    ('a new ssh port', {'ssh_port': 2200}),
]


@pytest.mark.parametrize('method,url', [('put', '/api/clusters/c1'),
                                        ('patch', '/api/clusters/c1/config')])
@pytest.mark.parametrize('label,body', MOVES, ids=[m[0] for m in MOVES])
def test_a_move_without_the_credential_is_refused(env, method, url, label, body):
    r = getattr(env.c, method)(url, json=body)
    assert _status(r) == 400, f'{label}: {r.get_data(as_text=True)}'
    assert r.get_json().get('code') == 'CREDENTIAL_REQUIRED'
    # nothing moved, the credential is untouched, the login still points where it was
    assert env.mgr.config.host == OLD_HOST
    assert list(env.mgr.config.fallback_hosts) == [FALLBACK]
    assert env.mgr.config.ssl_verification is True
    assert env.mgr.config.pass_ == STORED_PW
    assert env.mgr.current_host == OLD_HOST and env.mgr._ticket


def test_the_fallback_hosts_route_refuses_a_new_host_without_the_credential(env):
    r = env.c.put('/api/clusters/c1/fallback-hosts', json={'fallback_hosts': [NEW_HOST]})
    assert _status(r) == 400, r.get_data(as_text=True)
    assert list(env.mgr.config.fallback_hosts) == [FALLBACK]


def test_the_masking_sentinel_is_not_a_re_entry(env):
    r = env.c.put('/api/clusters/c1', json={'host': NEW_HOST, 'pass': '********'})
    assert _status(r) == 400, r.get_data(as_text=True)
    assert env.mgr.config.host == OLD_HOST


# --- the move goes through when the credential is re-entered, carrying only it ------

def test_a_host_change_with_the_password_re_entered_goes_through(env):
    r = env.c.put('/api/clusters/c1', json={'host': NEW_HOST, 'pass': 'fresh-password'})
    assert _status(r) == 200, r.get_data(as_text=True)
    assert env.mgr.config.host == NEW_HOST
    assert env.mgr.config.pass_ == 'fresh-password'
    # the old login is dropped so the next connect logs in afresh at the new host
    assert env.mgr.current_host is None and env.mgr._ticket is None
    assert env.mgr.is_connected is False


def test_a_token_cluster_moves_only_with_the_token_secret_re_entered(token_env):
    env = token_env
    r = env.c.patch('/api/clusters/c2/config', json={'host': NEW_HOST})
    assert _status(r) == 400, r.get_data(as_text=True)
    assert env.mgr.config.host == OLD_HOST and env.mgr.config.api_token_secret == STORED_TOKEN

    r = env.c.patch('/api/clusters/c2/config',
                    json={'host': NEW_HOST, 'api_token_secret': 'fresh-token-secret'})
    assert _status(r) == 200, r.get_data(as_text=True)
    assert env.mgr.config.host == NEW_HOST
    assert env.mgr.config.api_token_secret == 'fresh-token-secret'
    assert env.mgr._api_token is None


def test_turning_tls_verification_off_needs_the_credential(env):
    assert _status(env.c.patch('/api/clusters/c1/config', json={'ssl_verification': False})) == 400
    r = env.c.patch('/api/clusters/c1/config',
                    json={'ssl_verification': False, 'pass': 'fresh-password'})
    assert _status(r) == 200, r.get_data(as_text=True)
    assert env.mgr.config.ssl_verification is False


# --- what must keep working unchanged -----------------------------------------------

def test_a_rename_alone_is_not_a_move(env):
    r = env.c.put('/api/clusters/c1', json={'name': 'lab (EU)'})
    assert _status(r) == 200, r.get_data(as_text=True)
    assert env.mgr.config.name == 'lab (EU)'
    assert env.mgr.config.pass_ == STORED_PW
    # an edit that did not move the credential leaves the live login in place
    assert env.mgr.current_host == OLD_HOST and env.mgr._ticket


def test_ordinary_field_edits_without_a_move_still_work(env):
    r = env.c.patch('/api/clusters/c1/config',
                    json={'migration_threshold': 80, 'auto_migrate': True, 'ssh_user': 'pegaprox'})
    assert _status(r) == 200, r.get_data(as_text=True)
    assert env.mgr.config.migration_threshold == 80
    assert env.mgr.config.ssh_user == 'pegaprox'
    assert env.mgr.current_host == OLD_HOST


def test_the_same_host_and_a_turn_tls_on_are_not_moves(env):
    """Re-sending the stored host, and turning verification ON, carry no new risk."""
    r = env.c.put('/api/clusters/c1', json={'host': OLD_HOST, 'ssl_verification': True})
    assert _status(r) == 200, r.get_data(as_text=True)
    assert env.mgr.config.host == OLD_HOST


def test_re_sending_the_existing_fallback_hosts_is_not_a_move(env):
    r = env.c.put('/api/clusters/c1/fallback-hosts', json={'fallback_hosts': [FALLBACK]})
    assert _status(r) == 200, r.get_data(as_text=True)
    assert list(env.mgr.config.fallback_hosts) == [FALLBACK]


def test_setting_fallback_hosts_with_the_credential_moves_and_persists(env):
    r = env.c.put('/api/clusters/c1/fallback-hosts',
                  json={'fallback_hosts': [NEW_HOST], 'pass': 'fresh-password'})
    assert _status(r) == 200, r.get_data(as_text=True)
    assert list(env.mgr.config.fallback_hosts) == [NEW_HOST]
    assert env.mgr.config.pass_ == 'fresh-password'
