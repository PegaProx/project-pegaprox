"""The federation lease gate lets the read-only POSTs through (app.py).

The before_request gate in app.py holds every non-GET on /api/clusters/<id>/...
behind the federation lease - but a connection check, a pre-flight or a what-if
run changes nothing where it reads, and without an exemption each of them was a
409 on a cluster another member leads: a mirror no admin could even diagnose.
The exemptions are probes; a POST that ACTS on the cluster (backup-verify
restores and boots guests) stays behind the gate.
"""
import pytest


FOREIGN = 'a' * 32      # a member id this instance is not


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
