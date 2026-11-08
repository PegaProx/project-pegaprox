"""The syslog tenant gate matches host names, not patterns a tenant writes (#1119).

The gate turns each token of a cluster (its name, its host, its node names) into
`hostname = token OR hostname LIKE 'token.%'`, and the token went into the LIKE as it
was. Name and host are free text any cluster.config holder sets on their own cluster: a
cluster called '%' made the pattern '%.%', every host name with a dot in it, and its
tenant's admin.audit holder read every tenant's syslog from /api/syslog/events. '_'
did the same one character at a time.

Same gate, same kind of overreach without anyone asking for it: an IPv4 host gave the
short form "10", so LIKE '10.%' handed that tenant every sender in 10/8 that logs under
its address.
"""
import pytest

import pegaprox.api.reports as reports
from tests.conftest import make_fake_manager


@pytest.fixture(autouse=True)
def _fresh_cache():
    reports._AMBIGUOUS_HOSTS['at'] = 0.0
    reports._AMBIGUOUS_HOSTS['tokens'] = frozenset()
    yield
    reports._AMBIGUOUS_HOSTS['at'] = 0.0
    reports._AMBIGUOUS_HOSTS['tokens'] = frozenset()


@pytest.fixture
def syslog_rows(tmp_path, monkeypatch):
    import pegaprox.background.syslog_server as sl
    path = str(tmp_path / 'syslog.db')
    monkeypatch.setattr(sl, 'DB_FILE', path)
    monkeypatch.setattr(reports, 'DB_FILE', path)
    conn = sl._open_db()
    conn.execute('CREATE TABLE IF NOT EXISTS logs (id INTEGER PRIMARY KEY AUTOINCREMENT, '
                 'timestamp TEXT, source_ip TEXT, hostname TEXT, facility INTEGER, severity INTEGER, '
                 'severity_text TEXT, message TEXT, protocol TEXT)')

    def _add(*hostnames):
        for h in hostnames:
            conn.execute('INSERT INTO logs (timestamp, source_ip, hostname, facility, severity, '
                         'severity_text, message, protocol) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                         ('2026-10-06T10:00:00', '10.9.9.9', h, 3, 6, 'info', f'from {h}', 'UDP'))
        conn.commit()

    yield _add
    conn.close()


def _cluster(api, cid, name, host, *nodes):
    m = make_fake_manager(cid, get_node_status={n: {'status': 'online'} for n in nodes})
    m.host = host
    m.config.host = host
    m.config.name = name
    return api.set_manager(cid, m)


def _hosts(client):
    r = client.get('/api/syslog/events')
    assert r.status_code == 200, r.get_data(as_text=True)
    return sorted(i['hostname'] for i in r.get_json()['items'])


def _auditor(seed):
    seed.tenant('tenant_a', clusters=['cluster_a'])
    seed.tenant('tenant_b', clusters=['cluster_b'])
    return seed.user('aud_a', role='viewer', tenant_id='tenant_a', permissions=['admin.audit'])


@pytest.mark.parametrize('name', ['%', 'pve_', 'pve_.b.example'])
def test_a_cluster_name_is_not_a_pattern(api, seed, syslog_rows, name):
    aud = _auditor(seed)
    _cluster(api, 'cluster_a', name, 'pvea.a.example', 'pvea')
    _cluster(api, 'cluster_b', 'Beta', 'pve9.b.example', 'pve9')
    syslog_rows('pvea', 'pvea.a.example', 'pve9.b.example')

    got = _hosts(api.as_user(aud))

    assert 'pve9.b.example' not in got, f"a cluster named {name!r} read another tenant's syslog"
    assert got == ['pvea', 'pvea.a.example']


def test_an_ipv4_host_has_no_short_form(api, seed, syslog_rows):
    aud = _auditor(seed)
    _cluster(api, 'cluster_a', 'Alpha', '10.0.0.1', 'pvea')
    _cluster(api, 'cluster_b', 'Beta', 'pve9.b.example', 'pve9')
    syslog_rows('pvea', '10.0.0.1', '10.20.0.77')

    got = _hosts(api.as_user(aud))

    assert '10.20.0.77' not in got, "an address host matched every sender in 10/8"
    assert got == ['10.0.0.1', 'pvea']


def test_a_name_with_a_domain_keeps_its_short_form(api, seed, syslog_rows):
    """The short form still works for a host name: pvea is pvea.a.example's."""
    aud = _auditor(seed)
    _cluster(api, 'cluster_a', 'Alpha', 'pvea.a.example', 'pvea.a.example')
    _cluster(api, 'cluster_b', 'Beta', 'pve9.b.example', 'pve9')
    syslog_rows('pvea', 'pvea.mgmt.a.example', 'pve9')

    assert _hosts(api.as_user(aud)) == ['pvea', 'pvea.mgmt.a.example']


def test_an_admin_reads_every_host(api, seed, syslog_rows):
    _auditor(seed)
    _cluster(api, 'cluster_a', '%', 'pvea.a.example', 'pvea')
    _cluster(api, 'cluster_b', 'Beta', 'pve9.b.example', 'pve9')
    syslog_rows('pvea', 'pve9.b.example', 'elsewhere')

    assert _hosts(api.as_user(seed.user('root', role='admin'))) == ['elsewhere', 'pve9.b.example', 'pvea']
