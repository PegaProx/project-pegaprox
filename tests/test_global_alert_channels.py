"""alert_webhooks is one installation-wide list, and alert.manage is a tenant permission.

A channel is where alerts are DELIVERED. The list is global - there is no per-tenant
channel store - while alert.manage is delegable and tenant-scoped, so a tenant delegate
could rewrite the URL of the channel another tenant receives their alerts on and point it
at their own endpoint, or simply delete it. The read path already drew this line for the
unmasked view; the write paths did not.

The second half is the id: new_channel() honoured a caller-supplied `id`, so submitting
somebody else's id produced two entries sharing it. Every lookup in this file takes the
first match, so the edit route would rewrite whichever one it found.

Aikido ai_pentest 700487278 / 700487580 / 700488090. MK
"""
import pytest

from pegaprox.utils.webhooks import new_channel


@pytest.fixture
def store(monkeypatch):
    """A settings store with one existing channel, owned by nobody in particular."""
    data = {'alert_webhooks': [{'id': 'existing', 'name': 'ops',
                                'url': 'https://hooks.example/T0/SECRET', 'token': 'tok'}]}
    import pegaprox.api.helpers as helpers_mod
    monkeypatch.setattr(helpers_mod, 'load_server_settings', lambda: data)
    monkeypatch.setattr(helpers_mod, 'save_server_settings', lambda s: data.update(s))
    return data


def _delegate(seed):
    """alert.manage, tenant-scoped - exactly what a delegated alert manager holds."""
    seed.tenant('acme', clusters=['cluster_1'])
    return seed.user('delegate', role='user', tenant_id='acme',
                     permissions=['alert.manage'])


def _settings_admin(seed):
    seed.tenant('acme', clusters=['cluster_1'])
    return seed.user('opsadmin', role='user', tenant_id='acme',
                     permissions=['alert.manage', 'admin.settings'])


# --- writing a global object needs settings-admin ----------------------------

def test_a_delegate_cannot_repoint_an_existing_channel(api, db, seed, store):
    """The sharp one: rewriting the URL redirects another tenant's alerts."""
    d = _delegate(seed)

    r = api.as_user(d).put('/api/alert-channels/existing',
                           json={'url': 'https://attacker.example/collect'})

    assert r.status_code == 403, r.get_data(as_text=True)
    assert store['alert_webhooks'][0]['url'] == 'https://hooks.example/T0/SECRET'


def test_a_delegate_cannot_delete_a_channel(api, db, seed, store):
    d = _delegate(seed)

    r = api.as_user(d).delete('/api/alert-channels/existing')

    assert r.status_code == 403, r.get_data(as_text=True)
    assert len(store['alert_webhooks']) == 1


def test_a_delegate_cannot_create_a_channel(api, db, seed, store):
    d = _delegate(seed)

    r = api.as_user(d).post('/api/alert-channels',
                            json={'name': 'mine', 'url': 'https://attacker.example/x'})

    assert r.status_code == 403, r.get_data(as_text=True)
    assert len(store['alert_webhooks']) == 1


def test_a_settings_admin_may_still_manage_channels(api, db, seed, store):
    """The invariant: this must not lock the people who own the setting out of it."""
    a = _settings_admin(seed)

    r = api.as_user(a).post('/api/alert-channels',
                            json={'name': 'new', 'url': 'https://hooks.example/new'})

    assert r.status_code == 200, r.get_data(as_text=True)
    assert len(store['alert_webhooks']) == 2


def test_a_delegate_can_still_read_the_masked_list(api, db, seed, store):
    """alert.manage keeps its read access - the secrets stay masked, as before."""
    d = _delegate(seed)

    r = api.as_user(d).get('/api/alert-channels')

    assert r.status_code == 200, r.get_data(as_text=True)
    assert 'SECRET' not in r.get_data(as_text=True)


# --- the id is the server's to assign ----------------------------------------

def test_a_submitted_id_is_ignored():
    """Two entries sharing an id means every first-match lookup is ambiguous."""
    ch = new_channel({'name': 'x', 'url': 'https://h/x', 'id': 'existing'})

    assert ch['id'] != 'existing'
    assert len(ch['id']) == 12


def test_two_channels_never_share_an_id():
    ids = {new_channel({'name': 'x', 'url': 'https://h/x'})['id'] for _ in range(20)}

    assert len(ids) == 20
