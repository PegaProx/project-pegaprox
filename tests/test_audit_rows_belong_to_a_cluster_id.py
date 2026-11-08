"""Who may read an audit row is decided on the cluster id, never on a name (#1044, #1121).

#1044 - GET /api/audit was gated on admin.audit alone and answered with the whole
installation's trail. admin.audit is in the auditor and monitoring templates, so a
tenant's auditor read every other tenant's usernames, source IPs and actions. A caller
confined to some clusters now gets the rows of the clusters they see whole, plus their
own; an admin and a default-tenant account (both see every cluster) keep all of it.

#1121 - /api/clusters/<id>/audit picked rows by the cluster's display name. Any
cluster.config holder can rename their cluster, so a tenant admin who called theirs
"Beta" read tenant B's "Beta" trail. Rows carry the cluster id now; a row without one
(written before, or naming no cluster) is matched by name as before only for a caller
who sees every cluster.
"""
import pytest

import pegaprox.globals as ppglobals
from pegaprox.utils.audit import log_audit


def _mgr(api, cid, name):
    m = api.make_fake_manager(cluster_id=cid)
    m.config.name = name
    return api.set_manager(cid, m)


@pytest.fixture
def estate(api, seed):
    """Tenant A owns cluster_a "Alpha", tenant B owns cluster_b "Beta"; one row on each,
    one with no cluster at all."""
    seed.tenant('tenant_a', clusters=['cluster_a'])
    seed.tenant('tenant_b', clusters=['cluster_b'])
    _mgr(api, 'cluster_a', 'Alpha')
    _mgr(api, 'cluster_b', 'Beta')
    log_audit('alice', 'vm.start', 'Started VM 100', cluster='Alpha')
    log_audit('bob', 'vm.stop', 'Stopped VM 200', cluster='Beta')
    log_audit('root', 'settings.server_updated', 'Settings updated by root')
    return api


def _details(resp):
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    return ' | '.join(e.get('details') or '' for e in body)


# -- #1044: /api/audit -------------------------------------------------------------------

def test_a_tenants_auditor_does_not_read_another_tenants_trail(estate, seed):
    aud = seed.user('aud_a', role='viewer', tenant_id='tenant_a', permissions=['admin.audit'])
    got = _details(estate.as_user(aud).get('/api/audit'))

    assert 'Stopped VM 200' not in got, "tenant A's auditor read tenant B's audit rows"
    assert 'Settings updated by root' not in got, "a confined auditor read installation-wide rows"
    assert 'Started VM 100' in got, "the auditor lost their own tenant's rows"


def test_the_csv_export_is_scoped_the_same_way(estate, seed):
    aud = seed.user('aud_a', role='viewer', tenant_id='tenant_a', permissions=['admin.audit'])
    r = estate.as_user(aud).get('/api/audit?format=csv')
    assert r.status_code == 200
    text = r.get_data(as_text=True)
    assert 'Stopped VM 200' not in text and 'Started VM 100' in text


def test_a_confined_auditor_still_sees_their_own_rows(estate, seed):
    aud = seed.user('aud_a', role='viewer', tenant_id='tenant_a', permissions=['admin.audit'])
    log_audit('aud_a', 'user.login', 'Login of the auditor')
    assert 'Login of the auditor' in _details(estate.as_user(aud).get('/api/audit'))


def test_a_tenant_with_no_cluster_sees_only_its_own_rows(estate, seed):
    seed.tenant('tenant_empty', clusters=[])
    aud = seed.user('aud_e', role='viewer', tenant_id='tenant_empty', permissions=['admin.audit'])
    log_audit('aud_e', 'user.login', 'Login of the empty tenant')
    got = _details(estate.as_user(aud).get('/api/audit'))
    assert got == 'Login of the empty tenant', got


def test_an_admin_reads_the_whole_trail(estate, seed):
    root = seed.user('root', role='admin')
    got = _details(estate.as_user(root).get('/api/audit'))
    for row in ('Started VM 100', 'Stopped VM 200', 'Settings updated by root'):
        assert row in got, row


def test_a_default_tenant_auditor_reads_the_whole_trail(estate, seed):
    """The default tenant sees every cluster, so nothing changes for it."""
    aud = seed.user('aud_d', role='viewer', permissions=['admin.audit'])
    got = _details(estate.as_user(aud).get('/api/audit'))
    for row in ('Started VM 100', 'Stopped VM 200', 'Settings updated by root'):
        assert row in got, row


def test_the_limit_counts_the_rows_the_caller_gets(estate, seed):
    """Filtering after the LIMIT would hand a confined auditor an empty page whenever the
    newest rows are someone else's."""
    aud = seed.user('aud_a', role='viewer', tenant_id='tenant_a', permissions=['admin.audit'])
    for i in range(5):
        log_audit('bob', 'vm.stop', f'Stopped VM 3{i:02d}', cluster='Beta')
    body = estate.as_user(aud).get('/api/audit?limit=1').get_json()
    assert [e['details'] for e in body] == ['Started VM 100 [Alpha]'], body


# -- #1121: /api/clusters/<id>/audit -----------------------------------------------------

def _tenant_admin(seed):
    return seed.user('tadmin_a', role='viewer', tenant_id='tenant_a',
                     permissions=['cluster.view', 'cluster.config'])


def test_renaming_a_cluster_to_another_tenants_name_reads_nothing_of_theirs(estate, seed):
    ppglobals.cluster_managers['cluster_a'].config.name = 'Beta'   # PUT .../config {name: 'Beta'}
    got = _details(estate.as_user(_tenant_admin(seed)).get('/api/clusters/cluster_a/audit'))

    assert 'Stopped VM 200' not in got, "a renamed cluster read the other tenant's trail"
    assert 'Started VM 100' in got, "the cluster lost its own rows with the rename"


def test_the_old_name_of_a_renamed_cluster_reads_nothing_either(estate, seed):
    """No two clusters share a name at the time of the read, so a check for an ambiguous
    name does not help: tenant B renamed "Beta" to "Beta 2", tenant A takes "Beta"."""
    ppglobals.cluster_managers['cluster_b'].config.name = 'Beta 2'
    ppglobals.cluster_managers['cluster_a'].config.name = 'Beta'
    got = _details(estate.as_user(_tenant_admin(seed)).get('/api/clusters/cluster_a/audit'))
    assert 'Stopped VM 200' not in got


def test_the_owner_keeps_the_trail_across_a_rename(estate, seed):
    ppglobals.cluster_managers['cluster_b'].config.name = 'Beta 2'
    owner = seed.user('tadmin_b', role='viewer', tenant_id='tenant_b', permissions=['cluster.view'])
    assert 'Stopped VM 200' in _details(estate.as_user(owner).get('/api/clusters/cluster_b/audit'))


def test_an_admin_still_gets_rows_written_before_the_id(estate, seed, db):
    """A row from before the column has no id. It stays visible by name to a caller who sees
    every cluster, and to nobody else: a name cannot say which tenant it was."""
    db.add_audit_entry('carol', 'vm.start', 'Started VM 150 [Alpha]', '10.0.0.9', 'Alpha')
    root = seed.user('root', role='admin')
    assert 'Started VM 150' in _details(estate.as_user(root).get('/api/clusters/cluster_a/audit'))
    assert 'Started VM 150' not in _details(
        estate.as_user(_tenant_admin(seed)).get('/api/clusters/cluster_a/audit'))


def test_an_admin_does_not_get_another_clusters_rows_through_a_shared_name(estate, seed):
    ppglobals.cluster_managers['cluster_a'].config.name = 'Beta'
    root = seed.user('root', role='admin')
    assert 'Stopped VM 200' not in _details(estate.as_user(root).get('/api/clusters/cluster_a/audit'))


# -- how a row gets its id ---------------------------------------------------------------

def _row(db, action):
    return dict(db.query_one('SELECT cluster, cluster_id FROM audit_log WHERE action = ?', (action,)))


def test_a_name_two_clusters_share_gives_no_id_outside_a_route(estate, db):
    ppglobals.cluster_managers['cluster_a'].config.name = 'Beta'
    log_audit('bob', 'vm.reboot', 'Rebooted VM 200', cluster='Beta')
    assert _row(db, 'vm.reboot') == {'cluster': 'Beta', 'cluster_id': ''}


def test_inside_a_cluster_route_the_routes_cluster_wins(estate, db):
    ppglobals.cluster_managers['cluster_a'].config.name = 'Beta'
    with estate.app.test_request_context('/api/clusters/cluster_a/audit'):
        log_audit('alice', 'vm.reboot', 'Rebooted VM 100', cluster='Beta')
        log_audit('alice', 'cluster.config_changed', 'Cluster config updated')
    assert _row(db, 'vm.reboot')['cluster_id'] == 'cluster_a'
    assert _row(db, 'cluster.config_changed')['cluster_id'] == 'cluster_a'


def test_an_id_passed_as_the_cluster_is_kept(estate, db):
    log_audit('system', 'script.purged', 'Purged a script', cluster='cluster_b')
    assert _row(db, 'script.purged')['cluster_id'] == 'cluster_b'


def test_a_given_cluster_id_is_used_as_is(estate, db):
    ppglobals.cluster_managers['cluster_a'].config.name = 'Beta'
    log_audit('carl', 'portal.vm.start', 'Client portal: start VM 100', cluster='Beta',
              cluster_id='cluster_a')
    assert _row(db, 'portal.vm.start') == {'cluster': 'Beta', 'cluster_id': 'cluster_a'}


def test_portal_events_reach_the_right_feed_when_names_collide(estate):
    from pegaprox.background.broadcast import _get_recent_audit_tasks
    ppglobals.cluster_managers['cluster_a'].config.name = 'Beta'
    log_audit('carl', 'portal.vm.start', 'Client portal: start VM 100', cluster='Beta',
              cluster_id='cluster_a')
    assert [t['vmid'] for t in _get_recent_audit_tasks('cluster_a', 'Beta')] == [100]
    assert _get_recent_audit_tasks('cluster_b', 'Beta') == []


# -- the id is signed with the row -------------------------------------------------------

def test_the_cluster_id_is_part_of_the_signature(estate, db):
    row = dict(db.query_one("SELECT * FROM audit_log WHERE action = 'vm.stop'"))
    assert row['cluster_id'] == 'cluster_b' and db._verify_audit_hmac(row)
    db.conn.execute("UPDATE audit_log SET cluster_id = 'cluster_a' WHERE id = ?", (row['id'],))
    db.conn.commit()
    moved = dict(db.query_one('SELECT * FROM audit_log WHERE id = ?', (row['id'],)))
    assert not db._verify_audit_hmac(moved), 'a row moved to another cluster still verifies'


def test_rows_with_and_without_an_id_survive_a_key_rotation(estate, db):
    db.add_audit_entry('carol', 'vm.start', 'old row', '10.0.0.9', 'Alpha')
    res = db.rotate_encryption_key()
    assert not res.get('errors'), res
    bad = [dict(r)['details'] for r in db.query('SELECT * FROM audit_log')
           if not db._verify_audit_hmac(dict(r))]
    assert not bad, f'read as tampered after the rotation: {bad}'
