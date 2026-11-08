"""The drift STATUS counts are whole-cluster data, like the four routes around them.

drift.py has five routes. events, scan, baseline and acknowledge each decided — over
three separate passes, with the reasoning written next to each — that drift is a notion
about the whole cluster and that an ACL- or pool-confined caller has no scope to read or
act on it. drift_status kept only cluster.view, so the one route that was left open
handed a confined caller the per-kind and per-severity drift counts for the entire
cluster: how much of the storage, network and node configuration has moved, and when it
last did. Counts rather than diffs, but it is still the whole cluster's configuration
history, summarised.

The dashboard fetches /drift/status and /drift/events side by side into the same panel
and already catches a failure from either, so nothing that worked for these callers
stops working — /drift/events has refused them since the pass before this one.

Aikido ai_pentest 700489012. MK
"""
import pytest

CL = 'cluster_1'


@pytest.fixture
def mgr(api):
    m = api.make_fake_manager(CL)
    m.is_connected = True
    api.set_manager(CL, m)
    return m


@pytest.fixture
def estate(api, seed):
    seed.db.execute('''INSERT INTO clusters (id, name, host, user, pass_encrypted)
                       VALUES (?, ?, '10.0.0.1', 'root@pam', 'x')''', (CL, CL))
    seed.tenant('t', [CL])
    return seed


@pytest.fixture
def acled(api, estate):
    """A per-VM-ACL user: reaches the cluster, confined to one guest inside it."""
    u = estate.user('acl_user', role='user', tenant_id='t',
                    permissions=['cluster.view', 'vm.view'])
    estate.vm_acl(CL, 100, ['acl_user'], permissions=['vm.view'])
    return api.as_user(u)


@pytest.fixture
def operator(api, estate):
    """Same tenant, no ACL and no pool grant — not confined."""
    return api.as_user(estate.user('op', role='user', tenant_id='t',
                                   permissions=['cluster.view', 'vm.view']))


def _status(client):
    return client.get(f'/api/clusters/{CL}/drift/status')


def test_a_confined_caller_cannot_read_the_drift_counts(acled, mgr):
    assert _status(acled).status_code == 403


def test_an_unconfined_operator_still_can(operator, mgr):
    r = _status(operator)
    assert r.status_code == 200, r.get_data(as_text=True)[:300]
    assert 'by_kind' in r.get_json()


def test_the_confined_caller_is_refused_the_events_route_too(acled, mgr):
    """The sibling this one is being brought in line with."""
    assert acled.get(f'/api/clusters/{CL}/drift/events').status_code in (403, 404)
