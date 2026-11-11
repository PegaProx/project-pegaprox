"""The audit search and its facets answer whoever /api/audit answers, with the same rows.

/api/audit is gated on admin.audit, which the auditor and monitoring templates carry, and a
caller confined to some clusters reads the rows of the clusters they see whole plus their
own. /api/audit/search and /api/audit/facets were still on the admin role: an auditor got a
403 there and the audit tab, which reads the search, showed no entries at all.

Both now take admin.audit and filter in the query, the same way, so the total, the page and
the facet counts only hold rows the caller may read. An admin and a default tenant account
(both see every cluster) keep the whole trail.

MK Nov 2026
"""
import pytest

import pegaprox.utils.rbac as rbac
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


def _search(client, query=''):
    r = client.get('/api/audit/search' + query)
    assert r.status_code == 200, (r.status_code, r.get_data(as_text=True))
    return r.get_json()


def _details(body):
    return ' | '.join(e.get('details') or '' for e in body['entries'])


def _facets(client):
    r = client.get('/api/audit/facets')
    assert r.status_code == 200, (r.status_code, r.get_data(as_text=True))
    body = r.get_json()
    return ({f['user'] for f in body['users']}, {f['action'] for f in body['actions']},
            {f['cluster'] for f in body['clusters']})


def _tenant_a_auditor(seed):
    return seed.user('aud_a', role='viewer', tenant_id='tenant_a', permissions=['admin.audit'])


@pytest.mark.parametrize('template', ['auditor', 'monitoring'])
def test_a_template_holder_reads_search_and_facets(estate, seed, template):
    perms = list(rbac.ROLE_TEMPLATES[template]['permissions'])
    assert 'admin.audit' in perms
    holder = estate.as_user(seed.user('aud_' + template, role='viewer', permissions=perms))
    assert holder.get('/api/audit').status_code == 200

    got = _details(_search(holder))
    for row in ('Started VM 100', 'Stopped VM 200', 'Settings updated by root'):
        assert row in got, row
    users, actions, clusters = _facets(holder)
    assert {'alice', 'bob'} <= users and clusters == {'Alpha', 'Beta'}


def test_a_tenants_auditor_searches_only_what_the_audit_route_gives_them(estate, seed):
    aud = estate.as_user(_tenant_a_auditor(seed))
    body = _search(aud)
    got = _details(body)

    assert 'Stopped VM 200' not in got, "tenant A's auditor found tenant B's rows"
    assert 'Settings updated by root' not in got, 'a confined auditor found installation-wide rows'
    assert 'Started VM 100' in got
    assert body['total'] == 1 and body['has_more'] is False, body
    legacy = estate.as_user(_tenant_a_auditor(seed)).get('/api/audit').get_json()
    assert [e['details'] for e in body['entries']] == [e['details'] for e in legacy]


def test_a_query_for_another_tenants_rows_finds_nothing(estate, seed):
    aud = estate.as_user(_tenant_a_auditor(seed))
    for query in ('?q=Beta', '?user=bob', '?action=vm.stop', '?cluster=Beta', '?q=root'):
        body = _search(aud, query)
        assert body['entries'] == [] and body['total'] == 0, (query, body)


def test_the_total_and_the_page_count_the_callers_rows(estate, seed):
    """Filtering after the LIMIT would hand a confined auditor an empty page, and a total of
    someone else's rows, whenever the newest rows are someone else's."""
    for i in range(5):
        log_audit('bob', 'vm.stop', f'Stopped VM 3{i:02d}', cluster='Beta')
    body = _search(estate.as_user(_tenant_a_auditor(seed)), '?limit=1')
    assert [e['details'] for e in body['entries']] == ['Started VM 100 [Alpha]'], body
    assert body['total'] == 1 and body['has_more'] is False, body


def test_a_confined_auditor_finds_their_own_rows(estate, seed):
    aud = _tenant_a_auditor(seed)
    log_audit('aud_a', 'user.login', 'Login of the auditor')
    assert 'Login of the auditor' in _details(_search(estate.as_user(aud)))
    assert 'aud_a' in _facets(estate.as_user(aud))[0]


def test_a_tenant_with_no_cluster_searches_only_its_own_rows(estate, seed):
    seed.tenant('tenant_empty', clusters=[])
    aud = seed.user('aud_e', role='viewer', tenant_id='tenant_empty', permissions=['admin.audit'])
    log_audit('aud_e', 'user.login', 'Login of the empty tenant')
    body = _search(estate.as_user(aud))
    assert _details(body) == 'Login of the empty tenant' and body['total'] == 1, body
    assert _facets(estate.as_user(aud)) == ({'aud_e'}, {'user.login'}, set())


def test_the_facets_of_a_confined_auditor_name_nothing_of_another_tenant(estate, seed):
    users, actions, clusters = _facets(estate.as_user(_tenant_a_auditor(seed)))
    assert 'bob' not in users and 'root' not in users, users
    assert 'vm.stop' not in actions and 'settings.server_updated' not in actions, actions
    assert clusters == {'Alpha'}, clusters


def test_an_admin_keeps_the_whole_trail(estate, seed):
    root = estate.as_user(seed.user('root', role='admin'))
    body = _search(root)
    for row in ('Started VM 100', 'Stopped VM 200', 'Settings updated by root'):
        assert row in _details(body), row
    assert body['total'] == 3, body
    users, actions, clusters = _facets(root)
    assert {'alice', 'bob', 'root'} <= users and clusters == {'Alpha', 'Beta'}


def test_without_admin_audit_both_stay_closed(estate, seed):
    viewer = estate.as_user(seed.user('vic', role='viewer', permissions=['vm.view']))
    assert viewer.get('/api/audit/search').status_code == 403
    assert viewer.get('/api/audit/facets').status_code == 403
