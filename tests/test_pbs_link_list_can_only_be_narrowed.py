"""linked_clusters is the PBS authorization list, and empty means everyone.

check_pbs_access grants access when a PBS server has NO linked clusters — the
backward-compatibility arm, so an unlinked server stays usable. That makes the
list authorization-bearing data: clearing it hands the whole backup server, and
every tenant's snapshots sitting on it, to every tenant.

save_pbs_server already learned half of this. It used to write
`config.get('linked_clusters', [])`, so an update that simply did not mention
the field cleared it by accident, and that arm carries its own comment. The
other half was still open: a caller who reached the server through one of its
own links could send the field EXPLICITLY empty and do it on purpose, in one
PUT, with pbs.config and nothing else.

A non-admin may now only narrow the list, and only to clusters they can reach
themselves — widening it is the same move at half speed, since it pulls in
tenants who could not see the server before. Global admins are untouched, which
is what the last two tests are for: the people who legitimately unlink a server
have to keep being able to. Aikido ai_pentest 700488086. MK
"""
import json
from unittest.mock import MagicMock

import pytest

import pegaprox.globals as ppglobals

PBS = '/api/pbs/pbs_shared'

# The rest of the body the route needs to get as far as saving. host/port match what the
# fixture stores, so the separate host-change credential guard stays out of the way.
_VALID = {'host': 'pbs.example.com', 'port': 8007, 'user': 'root@pam', 'password': '********'}


@pytest.fixture
def linked_pbs(api, seed):
    """A PBS server linked to two tenants' clusters — the case where clearing the
    list actually hands something over."""
    ppglobals.pbs_managers.clear()
    seed.tenant('tenant_a', clusters=['cluster_1'])
    seed.tenant('tenant_b', clusters=['cluster_2'])
    m = MagicMock()
    m.linked_clusters = ['cluster_1', 'cluster_2']
    m.host, m.port = 'pbs.example.com', 8007
    m.password, m.api_token_secret, m.ssh_key = '', '', ''
    ppglobals.pbs_managers['pbs_shared'] = m
    try:
        yield m
    finally:
        ppglobals.pbs_managers.clear()


@pytest.fixture
def tenant_a_admin(api, seed, linked_pbs):
    return api.as_user(seed.user('a_admin', role='user', tenant_id='tenant_a',
                                 permissions=['pbs.config']))


def _stored_links(seed):
    """What actually got written. The status code is not enough here: without the
    guard the handler runs save_pbs_server FIRST and only then trips a later host
    validation, so it answers 400 with the link list already cleared on disk. A
    test that only read the status would call that a pass."""
    row = seed.db.conn.execute(
        "SELECT linked_clusters FROM pbs_servers WHERE id = ?", ('pbs_shared',)).fetchone()
    if row is None:
        return None                      # never written — the guard fired first
    return json.loads(row[0] or '[]')


def test_a_tenant_caller_cannot_unlink_the_server_from_everything(tenant_a_admin, seed):
    r = tenant_a_admin.put(PBS, json={**_VALID, 'linked_clusters': []})

    assert _stored_links(seed) != [], 'the PBS server was opened to every tenant on disk'
    assert r.status_code == 403, f'and the caller was told it worked: {r.data}'


def test_a_tenant_caller_cannot_link_it_to_a_cluster_it_cannot_reach(tenant_a_admin, seed):
    r = tenant_a_admin.put(PBS, json={**_VALID,
                                      'linked_clusters': ['cluster_1', 'cluster_2', 'cluster_9']})

    assert 'cluster_9' not in (_stored_links(seed) or []), 'the foreign link was persisted'
    assert r.status_code == 403, r.data
    assert 'cluster_9' in r.get_data(as_text=True)


def test_a_tenant_caller_may_still_narrow_it_to_its_own_cluster(tenant_a_admin):
    """The mirror: removing a link is a reduction and has to keep working."""
    r = tenant_a_admin.put(PBS, json={**_VALID, 'linked_clusters': ['cluster_1']})
    assert r.status_code == 200, f'a legitimate narrowing was refused: {r.data}'


def test_an_update_that_does_not_mention_the_field_is_unaffected(tenant_a_admin):
    """The guard must not fire on every PUT — only on one that carries the field.
    save_pbs_server already preserves the stored list on omission."""
    r = tenant_a_admin.put(PBS, json={**_VALID, 'name': 'Shared backup'})
    assert r.status_code == 200, r.data


def test_a_global_admin_can_still_unlink(api, seed, linked_pbs):
    boss = api.as_user(seed.user('boss', role='admin'))
    r = boss.put(PBS, json={**_VALID, 'linked_clusters': []})
    assert r.status_code == 200, r.data
