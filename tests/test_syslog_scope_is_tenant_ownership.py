"""A pool grant on a foreign cluster does not open that cluster's node syslog (#1010).

/api/syslog/events confines a caller who does not see every cluster to the host names
of the clusters they reach. That list came from get_user_clusters with its default
include_pools=True, so an admin.audit holder of one tenant who also held a pool grant on
another tenant's cluster read every line that cluster's nodes logged. A pool grant
reaches the guests in that pool, never the hosts under them: the confinement is by the
clusters the caller's tenant owns.
"""
import pytest

import pegaprox.api.reports as reports
from test_syslog_scope_has_no_wildcards import _cluster, _hosts, syslog_rows  # noqa: F401 (fixture)


@pytest.fixture(autouse=True)
def _fresh_cache():
    reports._AMBIGUOUS_HOSTS['at'] = 0.0
    reports._AMBIGUOUS_HOSTS['tokens'] = frozenset()
    yield
    reports._AMBIGUOUS_HOSTS['at'] = 0.0
    reports._AMBIGUOUS_HOSTS['tokens'] = frozenset()


def _estate(api, seed, syslog_rows):
    seed.tenant('tenant_a', clusters=['cluster_a'])
    seed.tenant('tenant_b', clusters=['cluster_b'])
    _cluster(api, 'cluster_a', 'Alpha', 'pvea.a.example', 'pvea')
    _cluster(api, 'cluster_b', 'Beta', 'pve9.b.example', 'pve9')
    syslog_rows('pvea', 'pvea.a.example', 'pve9', 'pve9.b.example')


def test_a_pool_grant_elsewhere_reads_no_host_there(api, seed, syslog_rows):
    _estate(api, seed, syslog_rows)
    aud = seed.user('aud_a', role='viewer', tenant_id='tenant_a', permissions=['admin.audit'])
    seed.pool('cluster_b', 'shop', 'aud_a', ['vm.start', 'vm.stop'])

    got = _hosts(api.as_user(aud))

    assert 'pve9.b.example' not in got and 'pve9' not in got, \
        "a pool grant on cluster_b handed over its nodes' syslog"
    assert got == ['pvea', 'pvea.a.example']


def test_asking_for_that_cluster_by_id_reads_nothing_of_it_either(api, seed, syslog_rows, monkeypatch):
    """check_cluster_access admits the pool holder; the tenant confinement still applies."""
    _estate(api, seed, syslog_rows)
    monkeypatch.setattr(reports, 'load_server_settings', lambda: {'syslog_filter_by_selected_cluster': True})
    aud = seed.user('aud_a', role='viewer', tenant_id='tenant_a', permissions=['admin.audit'])
    seed.pool('cluster_b', 'shop', 'aud_a', ['vm.start'])

    r = api.as_user(aud).get('/api/syslog/events?cluster_id=cluster_b')

    assert r.status_code in (200, 403), r.get_data(as_text=True)
    if r.status_code == 200:
        assert r.get_json()['items'] == []


def test_the_own_tenant_and_an_admin_read_as_before(api, seed, syslog_rows):
    _estate(api, seed, syslog_rows)
    aud = seed.user('aud_a', role='viewer', tenant_id='tenant_a', permissions=['admin.audit'])
    assert _hosts(api.as_user(aud)) == ['pvea', 'pvea.a.example']
    # a default-tenant auditor with no cluster list sees every cluster, pool grant or not
    plain = seed.user('aud_all', role='viewer', permissions=['admin.audit'])
    seed.pool('cluster_b', 'shop', 'aud_all', ['vm.start'])
    assert _hosts(api.as_user(plain)) == ['pve9', 'pve9.b.example', 'pvea', 'pvea.a.example']
    assert _hosts(api.as_user(seed.user('root', role='admin'))) == \
        ['pve9', 'pve9.b.example', 'pvea', 'pvea.a.example']
