"""Repointing a VMware server must not carry its stored credential to the new host.

The row PegaProx keeps for a vCenter/ESXi server holds an encrypted password, and
save_vmware_server writes `pass_encrypted or <the stored one>` — so the stored secret is
carried forward whenever the incoming password is falsy. diagnose, Test Connection and the
boot-time auto-connect all read that row back and authenticate with it.

A guard for this has existed since #469: refuse a host change when the password came in as
the UI's ******** sentinel. It had two ways around it.

  1. The sentinel is not the only spelling of "keep it". An OMITTED or EMPTY password
     preserves the credential just as well, and only '********' was compared against.
  2. The guard hung off the in-memory vmware_managers dict, and load_vmware_servers only
     loads `enabled = 1`. A DISABLED server is not in that dict, so the block never ran for
     it: disable, repoint, re-enable, and the auto-connect does the exfiltration.

Either way the row ends up holding a real vCenter credential against a host the caller
chose. The comparison is against the stored row now, and all three spellings of "keep the
password" are treated the same.

Aikido ai_pentest 700489023. MK
"""
import contextlib

import pytest

import pegaprox.api.vmware as vmwareapi


SERVER_ID = 'vmw1'
OLD_HOST = 'vcenter.internal'
NEW_HOST = 'attacker.example.net'


def _handler(name):
    fn = getattr(vmwareapi, name)
    while hasattr(fn, '__wrapped__'):
        fn = fn.__wrapped__
    return fn


@contextlib.contextmanager
def _as_admin(api, body):
    from flask import request as _rq
    with api.app.test_request_context('/', base_url='http://localhost', json=body):
        _rq.session = {'user': 'dana', 'role': 'admin'}
        yield


@pytest.fixture
def stored(api, seed, monkeypatch):
    """One ENABLED-in-the-row server that is NOT in vmware_managers — the disabled /
    not-yet-loaded case, which is where the guard used to be absent entirely."""
    seed.db.execute('''CREATE TABLE IF NOT EXISTS vmware_servers (
        id TEXT PRIMARY KEY, name TEXT, host TEXT, port INTEGER, username TEXT,
        pass_encrypted TEXT, server_type TEXT, ssl_verify INTEGER, enabled INTEGER,
        linked_clusters TEXT, notes TEXT, created_at TEXT, updated_at TEXT)''')
    seed.db.execute('''INSERT OR REPLACE INTO vmware_servers
        (id, name, host, port, username, pass_encrypted, server_type, ssl_verify,
         enabled, linked_clusters, notes, created_at, updated_at)
        VALUES (?, 'prod vCenter', ?, 443, 'admin@vsphere.local', 'ENCRYPTED-SECRET',
                'vcenter', 1, 0, '[]', '', '2026-01-01', '2026-01-01')''',
        (SERVER_ID, OLD_HOST))
    monkeypatch.setattr(vmwareapi, 'check_vmware_access', lambda _id: (True, None))
    monkeypatch.setattr(vmwareapi, 'vmware_managers', {}, raising=False)

    saved = []
    monkeypatch.setattr(vmwareapi, 'save_vmware_server',
                        lambda vid, cfg: saved.append((vid, dict(cfg))))
    return saved


def _put(api, body):
    with _as_admin(api, body):
        return _handler('update_vmware_server')(SERVER_ID)


def _status(resp):
    return resp[1] if isinstance(resp, tuple) else resp.status_code


# --- the three spellings of "keep the password", against a changed host ------------

@pytest.mark.parametrize('body,label', [
    ({'host': NEW_HOST, 'password': '********'}, 'the masking sentinel'),
    ({'host': NEW_HOST}, 'an omitted password'),
    ({'host': NEW_HOST, 'password': ''}, 'an empty password'),
])
def test_a_host_change_is_refused_when_the_credential_would_be_kept(api, stored, body, label):
    resp = _put(api, body)
    assert _status(resp) == 400, f'{label} was accepted with a new host'
    assert not stored, f'{label}: the row was written anyway'


def test_a_port_change_counts_as_a_destination_change(api, stored):
    resp = _put(api, {'port': 8443})
    assert _status(resp) == 400
    assert not stored


# --- what must still work ----------------------------------------------------------

def test_a_host_change_with_a_real_new_password_goes_through(api, stored):
    resp = _put(api, {'host': NEW_HOST, 'password': 'a-freshly-typed-secret'})
    assert _status(resp) != 400, resp
    assert stored, 'the update was refused even though a new password was supplied'
    assert stored[0][1]['password'] == 'a-freshly-typed-secret'


def test_editing_something_else_without_touching_the_password_still_works(api, stored):
    """The common case: rename the server, keep host and credential."""
    resp = _put(api, {'name': 'prod vCenter (EU)', 'host': OLD_HOST})
    assert _status(resp) != 400, resp
    assert stored


def test_the_same_host_with_the_sentinel_is_not_a_rebind(api, stored):
    resp = _put(api, {'host': OLD_HOST, 'password': '********'})
    assert _status(resp) != 400, resp
    assert stored
