"""The cloud layout strings exist in every language, not just German.

The cloud redesign added 383 keys with German values in mind; for a while
they were defined in de and en only (and some en values were the key name in
lowercase), so seven languages showed the raw key. The rebuild defines every
cloud key in all nine blocks. Source checks only; the global every-used-key
test lives in test_translation_backfill_ui.
LW Nov 2026
"""
import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LANGS = ['de', 'en', 'zh', 'pl', 'fr', 'es', 'pt', 'ko', 'it']
# a sample from each surface of the cloud layout: overview, operations
# center, config modal, storage workspace, updates, health/recovery
SAMPLE = [
    'cloud.loading', 'cloud.tabHealth', 'cloud.detOverview', 'cloud.consoleNoPreviewShort',
    'cloud.hcCheckNow', 'cloud.hcImpBackupC', 'cloud.hcMigrateSnaps', 'cloud.hcL3',
    'cloud.gap_no_backup', 'cloud.gap_rto_missed', 'cloud.raTechnical', 'cloud.raManualHint',
    'cloud.bakDeleteQ', 'cloud.snapRollbackQ', 'cloud.swSla', 'cloud.sbIntro',
    'cloud.sbPlanNote', 'cloud.slaNotEvaluated', 'cloud.slaOffNote', 'cloud.storageNote',
    'cloud.updConfirmHint', 'cloud.updCephStrict', 'cloud.updNoDataHint', 'cloud.updUpToDate',
    'cloudCfgApplied', 'cloudCfgPendingHint', 'cloudCfgSecConfigHint', 'cloudCfgTipResize',
    'cloudCfgExtern', 'cloudCfgUnsavedSec',
    'cloudNavAlerts', 'cloudNavTimeline', 'cloudNavPower',
]
KEY_LINE = re.compile(r"^ {16}'?([A-Za-z0-9_.]+)'?:")


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
            m = KEY_LINE.match(line)
            if m:
                keys.setdefault(m.group(1), []).append(line)
        out[lang] = keys
    return out


def test_the_sample_exists_in_every_language():
    blocks = _blocks()
    for key in SAMPLE:
        for lang in LANGS:
            assert len(blocks[lang].get(key, [])) == 1, \
                '%s is %d times in %s' % (key, len(blocks[lang].get(key, [])), lang)


def test_placeholders_survive_translation():
    blocks = _blocks()
    tokens = re.compile(r'\{[A-Za-z_]+\}')
    for key in ('cloud.hcMigrateSnaps',):
        want = tokens.findall(blocks['en'][key][0])
        assert want, key
        for lang in LANGS:
            got = tokens.findall(blocks[lang][key][0])
            assert got == want, (lang, key, got)


def test_no_unicode_dash_in_the_cloud_values():
    for lang, block in _blocks().items():
        for key in SAMPLE:
            assert not any('\u2010' <= ch <= '\u2015' or ch == '\u2212'
                           for ch in block[key][0]), (lang, key)
