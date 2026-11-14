"""The Grafana dashboards in misc/grafana do what their panels and dropdowns say.

Checked against the dashboard JSON model of schemaVersion 39, the one the files declare: a
value mapping has to name its type. Grafana's resolver switches on it and passes over a
mapping without one, so Quorum OK showed 0/1 instead of a red NO and a green YES, and the
APT table showed numbers.

The overview had a cluster and a node dropdown that no query used, so picking a cluster
changed nothing. Its cluster, node and guest queries filter on them now, and All, the
default, still shows everything.

NS Nov 2026
"""
import json
import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GRAFANA = os.path.join(ROOT, 'misc', 'grafana')
DASHBOARDS = sorted(n for n in os.listdir(GRAFANA) if n.endswith('.json'))
OVERVIEW = ('pegaprox_grafana_dashboard_v1.0.json', 'pegaprox_grafana_dashboard_v1.1.json')
MAPPING_TYPES = {'value', 'range', 'regex', 'special'}


def _load(name):
    with open(os.path.join(GRAFANA, name), encoding='utf-8') as fh:
        return json.load(fh)


def _panel(name, title):
    [panel] = [p for p in _load(name)['panels'] if p['title'] == title]
    return panel


def test_there_are_dashboards_to_check():
    assert set(OVERVIEW) <= set(DASHBOARDS) and len(DASHBOARDS) >= 4


@pytest.mark.parametrize('name', DASHBOARDS)
def test_every_value_mapping_names_its_type(name):
    dash = _load(name)
    assert dash['schemaVersion'] == 39
    for panel in dash['panels']:
        for mapping in panel.get('fieldConfig', {}).get('defaults', {}).get('mappings', []):
            assert mapping.get('type') in MAPPING_TYPES, (panel['title'], mapping)
            if mapping['type'] == 'value':
                assert mapping['options'] and all('text' in r for r in mapping['options'].values())


@pytest.mark.parametrize('name', OVERVIEW)
def test_quorum_reads_yes_or_no(name):
    [mapping] = _panel(name, 'Quorum OK')['fieldConfig']['defaults']['mappings']
    assert mapping == {'type': 'value', 'options': {'0': {'text': 'NO', 'color': 'red'},
                                                    '1': {'text': 'YES', 'color': 'green'}}}


def test_the_apt_table_reads_words():
    [mapping] = _panel(OVERVIEW[1], 'Node APT Update Availability')['fieldConfig']['defaults']['mappings']
    assert mapping['type'] == 'value'
    assert {k: v['text'] for k, v in mapping['options'].items()} == {'0': 'No updates', '1': 'Updates available'}


def _exprs(name):
    return [t['expr'] for p in _load(name)['panels'] for t in p.get('targets', [])]


@pytest.mark.parametrize('name', OVERVIEW)
def test_the_cluster_node_and_guest_queries_follow_the_dropdowns(name):
    exprs = _exprs(name)
    seen = 0
    for expr in exprs:
        for m in re.finditer(r'\b(pegaprox_(cluster|node|guest)_\w+)(\{[^}]*\})?', expr):
            labels = m.group(3) or ''
            assert 'cluster=~"$cluster"' in labels, (m.group(1), expr)
            # a guest series carries the node it runs on
            if m.group(2) != 'cluster':
                assert 'node=~"$node"' in labels, (m.group(1), expr)
            seen += 1
    assert seen >= 10
    # sessions, users, PBS and ESXi have no cluster label and stay as they were
    rest = [e for e in exprs if re.search(r'pegaprox_(sessions|users|pbs|esxi)_', e)]
    assert rest and not [e for e in rest if '$' in e]


@pytest.mark.parametrize('name', OVERVIEW)
def test_all_is_the_default_and_selects_everything(name):
    variables = {v['name']: v for v in _load(name)['templating']['list']}
    assert set(variables) == {'cluster', 'node'}
    for v in variables.values():
        assert v['type'] == 'query' and v['includeAll'] is True and v['multi'] is True
        # .* and not the list of values: a guest without a node label still matches
        assert v['allValue'] == '.*'
        assert v['current']['value'] == ['$__all']
        assert v['definition'] == v['query']
    assert variables['cluster']['query'] == 'label_values(pegaprox_cluster_connected, cluster)'
    # the node list follows the clusters picked
    assert variables['node']['query'] == 'label_values(pegaprox_node_online{cluster=~"$cluster"}, node)'


@pytest.mark.parametrize('name', OVERVIEW)
def test_the_overview_queries_stay_well_formed(name):
    with open(os.path.join(GRAFANA, name), encoding='utf-8') as fh:
        text = fh.read()
    assert '\u2014' not in text and '\u2013' not in text
    for expr in _exprs(name):
        assert expr.count('(') == expr.count(')') and expr.count('{') == expr.count('}'), expr
        # the label matchers come before a range, never after it
        assert not re.search(r'\]\{', expr), expr
