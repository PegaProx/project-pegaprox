"""A node name two clusters share cannot say which tenant a log line belongs to.

The syslog scope gate derives a short form from every node name it knows ("pve1" out of
"pve1.a.example") and turns each token into `hostname = token OR hostname LIKE 'token.%'`.
The second half is the leak. Two providers' clusters both having a node called pve1 is
not exotic - it is the default PVE node name - and tenant A's token "pve1" then matched
tenant B's fully-qualified "pve1.b.example" rows. The bare "pve1" rows were ambiguous on
top of that, since neither side can prove a line is theirs.

A token more than one cluster claims is dropped now, in both places the gate is built.
Unique names keep the prefix match, which is what makes a short node name work when the
sender happens to spell out the domain.

Aikido ai_pentest 700488154. MK
"""
import pytest

import pegaprox.api.reports as reports
import pegaprox.globals as ppglobals
from tests.conftest import make_fake_manager


@pytest.fixture(autouse=True)
def _fresh_cache():
    reports._AMBIGUOUS_HOSTS['at'] = 0.0
    reports._AMBIGUOUS_HOSTS['tokens'] = frozenset()
    yield
    reports._AMBIGUOUS_HOSTS['at'] = 0.0
    reports._AMBIGUOUS_HOSTS['tokens'] = frozenset()


def _cluster(cid, *nodes, host='10.0.0.1'):
    m = make_fake_manager(cid, get_node_status={n: {'status': 'online'} for n in nodes})
    m.host = host
    m.config.host = host
    m.config.name = cid
    return m


@pytest.fixture
def estate(monkeypatch):
    def _install(**clusters):
        ppglobals.cluster_managers.clear()
        for cid, nodes in clusters.items():
            ppglobals.cluster_managers[cid] = _cluster(cid, *nodes, host=f'10.0.0.{len(cid)}')
        return ppglobals.cluster_managers

    try:
        yield _install
    finally:
        ppglobals.cluster_managers.clear()


def _clause(values):
    params = []
    return reports._syslog_host_clause(values, params), params


def test_a_name_two_clusters_share_is_ambiguous(estate):
    estate(cluster_a=['pve1.a.example'], cluster_b=['pve1.b.example'])

    assert 'pve1' in reports._syslog_ambiguous_hostnames()


def test_a_unique_name_is_not(estate):
    estate(cluster_a=['pve1.a.example'], cluster_b=['pve9.b.example'])

    ambiguous = reports._syslog_ambiguous_hostnames()
    assert 'pve1' not in ambiguous and 'pve9' not in ambiguous


def test_the_shared_short_name_never_reaches_the_query(estate):
    """This is the leak: LIKE 'pve1.%' matched the other tenant's fully-qualified rows."""
    estate(cluster_a=['pve1.a.example'], cluster_b=['pve1.b.example'])

    sql, params = _clause(reports._syslog_cluster_hostnames('cluster_a'))

    assert 'pve1.%' not in params
    assert 'pve1' not in params


def test_the_full_name_is_still_matched(estate):
    """Dropping the ambiguous short form must not cost the tenant their own logs."""
    estate(cluster_a=['pve1.a.example'], cluster_b=['pve1.b.example'])

    sql, params = _clause(reports._syslog_cluster_hostnames('cluster_a'))

    assert 'pve1.a.example' in params


def test_a_unique_short_name_keeps_its_prefix_match(estate):
    """A sender that spells out the domain when we only know the short name."""
    estate(cluster_a=['pve7'], cluster_b=['other'])

    sql, params = _clause(reports._syslog_cluster_hostnames('cluster_a'))

    assert 'pve7' in params and 'pve7.%' in params


def test_nothing_left_to_match_denies_rather_than_opens(estate):
    """An allow-list that filters down to nothing must not become an unfiltered query.
    (A cluster still contributes its own name and host, which are usually unique - this
    is the degenerate case where every token it had was shared.)"""
    estate(cluster_a=['pve1'], cluster_b=['pve1'])

    sql, params = _clause({'pve1'})

    assert sql == '1 = 0'
    assert params == []


def test_an_unrelated_unique_token_is_unaffected_by_a_shared_one(estate):
    """Dropping "pve1" must not drop the cluster's own name alongside it."""
    estate(cluster_a=['pve1'], cluster_b=['pve1'])

    sql, params = _clause(reports._syslog_cluster_hostnames('cluster_a'))

    assert 'pve1' not in params
    assert 'cluster_a' in params


def test_the_answer_is_memoised(estate, monkeypatch):
    """Working it out walks every cluster's node list, and the gate runs per query."""
    estate(cluster_a=['pve1'], cluster_b=['pve2'])
    calls = []
    real = reports._syslog_cluster_hostnames
    monkeypatch.setattr(reports, '_syslog_cluster_hostnames',
                        lambda cid: (calls.append(cid), real(cid))[1])

    for _ in range(10):
        reports._syslog_ambiguous_hostnames()

    assert len(calls) == 2, f'{len(calls)} cluster walks for 10 calls'


def test_no_pattern_the_gate_emits_can_match_another_clusters_node(estate):
    """States the leak itself rather than the mechanism: take tenant A's clause and check
    it against tenant B's real node names the way SQLite's LIKE would."""
    import fnmatch

    estate(cluster_a=['pve1.a.example', 'pve2.a.example'],
           cluster_b=['pve1.b.example', 'pve2.b.example'])
    theirs = {'pve1.b.example', 'pve2.b.example'}

    _, params = _clause(reports._syslog_cluster_hostnames('cluster_a'))

    matched = [h for h in theirs
               for p in params
               if h == p or fnmatch.fnmatchcase(h, str(p).replace('%', '*'))]
    assert matched == [], f"tenant A's filter reaches {matched}"
