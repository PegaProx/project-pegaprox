"""A PBS that refuses is not a started task.

GC, verify, prune and deleting a snapshot handed PBS's refusal back under a 200, for example a datastore in maintenance or a
protected snapshot. The UI goes by the status and said "prune started on store".
"""
from unittest.mock import MagicMock, patch

import pytest

import pegaprox.globals as g

CALLS = [('start_gc', 'post', '/api/pbs/x/datastores/s/gc', {}),
         ('start_verify', 'post', '/api/pbs/x/datastores/s/verify', {}),
         ('prune_datastore', 'post', '/api/pbs/x/datastores/s/prune', {'dry_run': False}),
         ('delete_snapshot', 'delete', '/api/pbs/x/datastores/s/snapshots',
          {'backup_type': 'vm', 'backup_id': '100', 'backup_time': 1})]


@pytest.fixture
def client(api, seed, db):
    mgr = MagicMock()
    mgr.name = 'pbs'
    g.pbs_managers['x'] = mgr
    with patch('pegaprox.api.pbs.check_pbs_access', return_value=(True, None)), \
            patch('pegaprox.api.pbs.require_pbs_wide', return_value=None):
        yield api.as_user(seed.user('adm', role='admin')), mgr
    g.pbs_managers.pop('x', None)


@pytest.mark.parametrize('method,verb,url,body', CALLS)
def test_a_refusal_is_an_error_with_the_reason(client, method, verb, url, body):
    c, mgr = client
    getattr(mgr, method).return_value = {'error': 'datastore is in maintenance'}
    r = getattr(c, verb)(url, json=body)
    assert r.status_code == 502, r.get_json()
    assert r.get_json()['error'] == 'datastore is in maintenance'


@pytest.mark.parametrize('method,verb,url,body', CALLS)
def test_what_worked_is_as_it_was(client, method, verb, url, body):
    c, mgr = client
    getattr(mgr, method).return_value = {'data': 'UPID:pbs:1'}
    r = getattr(c, verb)(url, json=body)
    assert r.status_code == 200 and r.get_json() == {'data': 'UPID:pbs:1'}
