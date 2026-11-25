"""The drift scan read every node-affinity rule as changed once a cluster reached PVE 9.3.

pve-ha-manager 5.2.5 gave node-affinity rules an optional `affinity` (positive or negative,
default positive), and GET /cluster/ha/rules fills in the default. Every rule a scan took as
its baseline before the upgrade came back with affinity=positive, a warning over all of them
with nothing changed, and during a rolling update the key came and went as the API host moved
between upgraded nodes and the others. The default is left out of the snapshot now; a negative
rule and a rule turned round still show, and resource-affinity rules keep theirs.
"""
import json

from pegaprox.api import drift
from test_drift_more_kinds import CL, _baselines, _events, pve  # noqa: F401 (pve is a fixture)


def _rules(fake):
    return fake.routes['/cluster/ha/rules']


def test_the_default_pve_9_3_fills_in_is_no_drift(pve, db):  # noqa: F811
    drift._scan_cluster(CL, autobaseline=True)
    for rule in _rules(pve):
        rule['affinity'] = 'positive'
    res = drift._scan_cluster(CL)
    assert res['events_count'] == 0, res['events']
    assert _events(db) == []
    # and back, as when the API host is a node not upgraded yet
    for rule in _rules(pve):
        rule.pop('affinity')
    assert drift._scan_cluster(CL)['events_count'] == 0


def test_a_rule_that_turns_negative_is_drift(pve, db):  # noqa: F811
    drift._scan_cluster(CL, autobaseline=True)
    _rules(pve)[0]['affinity'] = 'negative'
    res = drift._scan_cluster(CL)
    assert [(e['kind'], e['scope'], e['severity']) for e in res['events']] == [('ha_rules', 'rules', 'warning')]
    diff = json.loads(_events(db)[0]['diff'])
    assert diff[0]['path'] == 'r1' and diff[0]['after']['affinity'] == 'negative'


def test_a_negative_rule_turned_positive_is_drift_too(pve, db):  # noqa: F811
    _rules(pve)[0]['affinity'] = 'negative'
    drift._scan_cluster(CL, autobaseline=True)
    assert _baselines()[('ha_rules', 'rules')]['snapshot']['r1']['affinity'] == 'negative'
    _rules(pve)[0]['affinity'] = 'positive'
    assert drift._scan_cluster(CL)['events_count'] == 1


def test_a_resource_affinity_rule_keeps_its_affinity(pve, db):  # noqa: F811
    _rules(pve).append({'rule': 'together', 'type': 'resource-affinity', 'affinity': 'positive',
                        'resources': 'vm:101,vm:102'})
    drift._scan_cluster(CL, autobaseline=True)
    assert _baselines()[('ha_rules', 'rules')]['snapshot']['together']['affinity'] == 'positive'
