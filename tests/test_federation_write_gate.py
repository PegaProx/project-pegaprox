"""The federation lease gate lets the read-only POSTs through (app.py).

The before_request gate in app.py holds every non-GET on /api/clusters/<id>/...
behind the federation lease - but a connection check, a pre-flight or a what-if
run changes nothing where it reads, and without an exemption each of them was a
409 on a cluster another member leads: a mirror no admin could even diagnose.
The exemptions are probes; a POST that ACTS on the cluster (backup-verify
restores and boots guests) stays behind the gate.

The rest of the gate's contract lives here too: PUT and DELETE are writes like
any POST, a GET is nobody's to refuse (the gate does not even run), a cluster
this instance never enrolled is its own to write on, and a federation state
that cannot be read fails the write closed (503) instead of opening the gate.
"""
import pytest


FOREIGN = 'a' * 32      # a member id this instance is not


@pytest.fixture(autouse=True)
def _state_in_tmp(tmp_path, monkeypatch):
    """The gate asks the federation state at request time; a fresh one per test,
    in the test's tmp dir, never the config directory the process started with
    (and no instance id cached from a test before)."""
    from pegaprox.core import federation
    monkeypatch.setitem(federation._runtime, 'file',
                        str(tmp_path / 'federation_state.json'))
    federation._runtime.pop('instance_id_cache', None)
    yield
    federation._runtime.pop('instance_id_cache', None)


@pytest.fixture
def foreign_row(seed):
    """One cluster row another member of the federation leads: everything on it
    is the gate's to refuse, read-only probes excepted."""
    seed.db.execute(
        "INSERT INTO clusters (id, name, host, user, pass_encrypted, fed_owner) "
        "VALUES ('c-foreign', 'gone', '10.0.0.9', 'root@pam', 'x', ?)",
        (FOREIGN,))
    return seed.db


@pytest.fixture
def local_row(seed):
    """One cluster row that is this instance's own: enrolled nowhere, no lease
    asked - the gate has nothing to say about a write on it."""
    seed.db.execute(
        "INSERT INTO clusters (id, name, host, user, pass_encrypted, fed_owner) "
        "VALUES ('c-local', 'ours', '10.0.0.8', 'root@pam', 'x', '')")
    return seed.db


@pytest.fixture
def admin(api, seed):
    return api.as_user(seed.user('root', role='admin'))


def _refused_by_gate(r):
    body = r.get_json(silent=True) or {}
    return r.status_code == 409 and body.get('code') == 'FED_FOREIGN'


@pytest.mark.parametrize('tail', (
    'connection-check',
    'transfer-network/check',
    'node-credentials/check',
    'ha/agent-check',
    'storage-preflight',
    'updates/check',
    'whatif',
    'whatif/ranking',
    'nodes/join/test',
    'migration-preflight',
))
def test_a_read_only_post_passes_the_lease_gate(admin, foreign_row, tail):
    """Whatever these answer (a missing manager says 404), the lease gate is not
    what stops them: the lease rules writes, not probes."""
    r = admin.post(f'/api/clusters/c-foreign/{tail}', json={})
    assert not _refused_by_gate(r), f'{tail} ran into the lease gate'


def test_a_nodes_bmc_endpoint_test_passes_the_lease_gate(admin, foreign_row):
    r = admin.post('/api/clusters/c-foreign/nodes/node1/bmc-endpoint/test',
                   json={})
    assert not _refused_by_gate(r)


def test_a_post_that_acts_stays_behind_the_gate(admin, foreign_row):
    """backup-verify restores, boots and cleans up guests: a write, lease-gated
    like one - the exemption list must never grow a route that acts."""
    r = admin.post('/api/clusters/c-foreign/backup-verify', json={})
    assert _refused_by_gate(r)


def test_a_put_on_a_foreign_cluster_is_refused(admin, foreign_row):
    """The gate holds every non-GET, not only POSTs: the cluster's own config
    route is a write like any other."""
    r = admin.put('/api/clusters/c-foreign', json={'name': 'renamed'})
    assert _refused_by_gate(r)


def test_a_delete_of_a_foreign_cluster_is_refused(admin, foreign_row):
    r = admin.delete('/api/clusters/c-foreign')
    assert _refused_by_gate(r)


def test_a_get_is_not_the_gate_s_to_refuse(admin, foreign_row):
    """The health read is served on a cluster another member leads: the gate
    does not run for a GET, so the route answers (404 here - no manager is
    standing in for the foreign cluster), never the gate's 409."""
    r = admin.get('/api/clusters/c-foreign/health')
    assert r.status_code == 404, (r.status_code, r.data)
    assert not _refused_by_gate(r)


def test_a_post_on_an_unenrolled_cluster_goes_through(admin, local_row):
    """A cluster this instance never enrolled is its own: the same backup-verify
    that a foreign row refuses passes the gate (the 404 is the route's - no
    manager stands in for this cluster either - and not the gate's)."""
    r = admin.post('/api/clusters/c-local/backup-verify', json={})
    assert not _refused_by_gate(r), r.data
    assert r.status_code == 404, (r.status_code, r.data)


def test_an_unreadable_federation_state_refuses_the_write(admin, foreign_row,
                                                          tmp_path):
    """Fail closed: a federation state that cannot be read is not 'no
    federation' - the gate cannot tell who may write, so the write is refused
    with 503 FED_UNAVAILABLE instead of passing as an unenrolled cluster."""
    from pegaprox.core import federation
    state = tmp_path / 'federation_state.json'
    state.write_text('not json', encoding='utf-8')
    federation._runtime.pop('instance_id_cache', None)
    r = admin.post('/api/clusters/c-foreign/backup-verify', json={})
    assert r.status_code == 503, (r.status_code, r.data)
    body = r.get_json(silent=True) or {}
    assert body.get('code') == 'FED_UNAVAILABLE', body
