"""The Grafana dashboards in misc/grafana do what their panels say.

Checked against the dashboard JSON model of schemaVersion 39, the one the files declare: a
value mapping has to name its type. Grafana's resolver switches on it and passes over a
mapping without one, so Quorum OK showed 0/1 instead of a red NO and a green YES, and the
APT table showed numbers.

NS Nov 2026
"""
import json
import os

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
