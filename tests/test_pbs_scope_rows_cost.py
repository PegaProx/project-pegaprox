"""Scoping a PBS listing must cost one identity build, not one per row.

_scope_pbs_rows calls _authz_pbs_backup per row, and that used to open with
build_authz_user — which reads the whole users table and decrypts two TOTP
columns per account. A datastore listing is the entire install's backup
inventory: 10k guests at 30-day retention is ~300k rows, on a gevent greenlet
that yields to nobody while it runs. Same shape as the #773 pool-perm storm.

The listing itself is bounded by PBS, so the assertion here is on the shape of
the cost, not on wall-clock. MK
"""
import pytest

import pegaprox.api.pbs as pbsmod
import pegaprox.utils.auth as authmod
import pegaprox.globals as ppglobals


MINE = 100


@pytest.fixture
def counted(monkeypatch):
    """Count build_authz_user calls made through the module under test."""
    calls = []
    real = pbsmod_build = authmod.build_authz_user

    def _counting(username, session=None):
        calls.append(username)
        return real(username, session)

    monkeypatch.setattr(authmod, 'build_authz_user', _counting)
    return calls


def _rows(n):
    return [{'backup-type': 'vm', 'backup-id': str(MINE + i), 'backup-time': 1_756_000_000 + i}
            for i in range(n)]


@pytest.fixture
def scoped_request(api, seed):
    """A VM-ACL-confined caller, inside a request context so the route helpers work."""
    seed.tenant('tenant_a', clusters=['cluster_1'])
    seed.user('alice', role='user', tenant_id='tenant_a', permissions=['pbs.datastore.view'])
    seed.vm_acl('cluster_1', MINE, ['alice'], permissions=['vm.view'])
    api.set_manager('cluster_1', api.make_fake_manager('cluster_1', get_vm_resources=[]))

    from unittest.mock import MagicMock
    mgr = MagicMock()
    mgr.linked_clusters = ['cluster_1']
    return mgr


def _run(api, mgr, rows):
    from flask import request as _rq
    with api.app.test_request_context('/'):
        _rq.session = {'user': 'alice', 'role': 'user'}
        return pbsmod._scope_pbs_rows(mgr, rows)


@pytest.mark.parametrize('n', [1, 50, 500])
def test_identity_is_built_once_regardless_of_row_count(api, scoped_request, counted, n):
    _run(api, scoped_request, _rows(n))

    assert len(counted) == 1, f'{len(counted)} identity builds for {n} rows'


def test_scoping_still_filters(api, scoped_request, counted):
    kept = _run(api, scoped_request, _rows(5))

    assert [r['backup-id'] for r in kept] == [str(MINE)], kept


def test_the_counter_would_notice_a_per_row_build(api, scoped_request, counted):
    """Guards the guard: calling the un-hoisted path per row must move the count."""
    with api.app.test_request_context('/'):
        from flask import request as _rq
        _rq.session = {'user': 'alice', 'role': 'user'}
        for row in _rows(3):
            pbsmod._authz_pbs_backup(scoped_request, row['backup-type'], row['backup-id'])

    assert len(counted) == 3
