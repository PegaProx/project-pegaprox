"""The VMware host-change guard must refuse when it cannot read the current destination.

update_vmware_server decides whether a request moves the server by comparing the incoming
host/port against the STORED row — the row is what save_vmware_server reuses the credential
from, so it is the right authority. But "no row came back" was treated as "nothing changed":
host_changed stayed False, the preserved-credential refusal below never fired, and the
update went through with the stored secret attached to a destination nobody had checked.

The early 404 in that handler only runs when the id is ABSENT from vmware_managers, so an
entry that is in the dict without a matching row reaches the comparison and takes exactly
that path. Cannot-tell has to resolve as changed here; the cost is re-typing the password,
which is what the guard asks for anyway.

Same shape as the other fail-opens this campaign turned up — a failed read answering in the
caller's favour. Found by the daily CodeAnt pass pointing at the hydration below it. MK
"""
import contextlib

import pytest

import pegaprox.api.vmware as vmwareapi

SERVER_ID = 'vmw_ghost'


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


class _Mgr:
    """An in-memory manager with no row behind it."""
    name = 'ghost vCenter'
    host = 'vcenter.internal'
    port = 443
    password = 'the-real-secret'


@pytest.fixture
def manager_without_a_row(api, seed, monkeypatch):
    seed.db.execute('''CREATE TABLE IF NOT EXISTS vmware_servers (
        id TEXT PRIMARY KEY, name TEXT, host TEXT, port INTEGER, username TEXT,
        pass_encrypted TEXT, server_type TEXT, ssl_verify INTEGER, enabled INTEGER,
        linked_clusters TEXT, notes TEXT, created_at TEXT, updated_at TEXT)''')
    # deliberately NO row for SERVER_ID
    monkeypatch.setattr(vmwareapi, 'check_vmware_access', lambda _id: (True, None))
    monkeypatch.setattr(vmwareapi, 'vmware_managers', {SERVER_ID: _Mgr()}, raising=False)
    saved = []
    monkeypatch.setattr(vmwareapi, 'save_vmware_server',
                        lambda vid, cfg: saved.append((vid, dict(cfg))))
    return saved


def _put(api, body):
    with _as_admin(api, body):
        return _handler('update_vmware_server')(SERVER_ID)


def _status(resp):
    return resp[1] if isinstance(resp, tuple) else resp.status_code


@pytest.mark.parametrize('body,label', [
    ({'host': 'somewhere-else.invalid'}, 'omitted password'),
    ({'host': 'somewhere-else.invalid', 'password': ''}, 'empty password'),
    ({'host': 'somewhere-else.invalid', 'password': '********'}, 'the sentinel'),
    ({}, 'no host at all'),
])
def test_an_unreadable_row_refuses_a_preserved_credential(api, manager_without_a_row, body, label):
    resp = _put(api, body)
    assert _status(resp) == 400, f'{label} went through with an unknown destination'
    assert not manager_without_a_row, f'{label}: the row was written anyway'


def test_the_stored_secret_is_not_handed_to_the_unknown_destination(api, manager_without_a_row):
    """The thing that actually matters: the credential must not travel."""
    _put(api, {'host': 'somewhere-else.invalid'})
    written = [cfg.get('password') for _vid, cfg in manager_without_a_row]
    assert _Mgr.password not in written, 'the real credential was persisted anyway'


def test_supplying_a_real_password_still_works(api, manager_without_a_row):
    """The counterweight — the guard asks for a password, so giving one must suffice."""
    resp = _put(api, {'host': 'somewhere-else.invalid', 'password': 'freshly-typed'})
    assert _status(resp) != 400, resp
    assert manager_without_a_row, 'a fully specified update was refused'
    assert manager_without_a_row[0][1]['password'] == 'freshly-typed'
