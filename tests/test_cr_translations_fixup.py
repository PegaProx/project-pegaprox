"""Translation fixes for Corporate Redesigned: Korean Insights keys and wrong duplicates.

The Korean block held Italian copies of the Insights keys after the Korean ones, and the
later copy wins at runtime. 'clusters' and the Portuguese 'renameCluster' were defined
twice with the second value a different word. 'clusters' keeps the count form that won so far,
classic Corporate and Modern write it next to numbers; the redesign's tile and table title
take crClusters. Source checks on web/src/translations.js.
LW Nov 2026
"""
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LANGS = ['de', 'en', 'zh', 'pl', 'fr', 'es', 'pt', 'ko', 'it', 'ru']
KEY = re.compile(r"^ {16}('?)([A-Za-z0-9_.]+)\1\s*:\s*(.*)$")
HANGUL = re.compile('[가-힣]')
INSIGHTS = ['topTalkers', 'topTalkersHint', 'memoryPercent', 'diskUsagePercent', 'rollups', 'byTag',
            'byPool', 'tag', 'sensors', 'hwEnable', 'bmcHost', 'guestDetail', 'configVersion']


def _blocks():
    with open(os.path.join(ROOT, 'web', 'src', 'translations.js'), encoding='utf-8') as fh:
        lines = fh.read().split('\n')
    starts = [(i, m.group(1)) for i, line in enumerate(lines)
              for m in [re.match(r'^ {12}([a-z]{2}): \{$', line)] if m]
    out = {}
    for n, (i, lang) in enumerate(starts):
        end = starts[n + 1][0] if n + 1 < len(starts) else len(lines)
        keys = {}
        for line in lines[i + 1:end]:
            m = KEY.match(line)
            if m:
                keys.setdefault(m.group(2), []).append(m.group(3))
        out[lang] = keys
    return out


def test_korean_insights_values_are_korean_whatever_wins():
    ko = _blocks()['ko']
    for key in INSIGHTS:
        for value in ko[key]:
            assert HANGUL.search(value), (key, value)


def test_clusters_and_rename_cluster_have_one_value_per_block():
    blocks = _blocks()
    for lang in LANGS:
        assert len(set(blocks[lang]['clusters'])) == 1, lang
    assert len(set(blocks['pt']['renameCluster'])) == 1

