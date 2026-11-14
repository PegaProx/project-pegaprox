"""The prerequisite panel of the cross-cluster EVPN wizard speaks every language.

The panel's eight strings started as hardcoded English inside the JSX (#1154);
they moved into translations.js as mcevpnPrereq* keys, and a key that is only
defined in some languages shows the raw key or English for everyone else.
Source checks only; the runtime bundle test lives in test_translation_backfill_ui.
LW Nov 2026
"""
import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LANGS = ['de', 'en', 'zh', 'pl', 'fr', 'es', 'pt', 'ko', 'it', 'ru']
KEYS = ['mcevpnPrereqTitle', 'mcevpnPrereqReady', 'mcevpnPrereqRun', 'mcevpnPrereqChecking',
        'mcevpnPrereqPickFirst', 'mcevpnPrereqFailed', 'mcevpnPrereqChecked', 'mcevpnPrereqHint',
        'mcevpnPrereqUseIps', 'mcevpnPrereqMgmtHint',
        'mcevpnPrereqMemberErr', 'mcevpnPrereqReplacePeers']


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
            m = re.match(r"^ {16}'?([A-Za-z0-9_.]+)'?\s*:", line)
            if m:
                keys.setdefault(m.group(1), []).append(line)
        out[lang] = keys
    return out


def test_the_panel_keys_are_used_by_the_wizard_code():
    code = ''
    src = os.path.join(ROOT, 'web', 'src')
    for name in sorted(os.listdir(src)):
        if name.endswith('.js') and name != 'translations.js':
            with open(os.path.join(src, name), encoding='utf-8') as fh:
                code += fh.read()
    for key in KEYS:
        assert ("t('%s')" % key) in code, '%s is not wired into the UI' % key


@pytest.mark.parametrize('lang', LANGS)
def test_every_panel_key_exists_once_per_language(lang):
    block = _blocks()[lang]
    for key in KEYS:
        assert len(block.get(key, [])) == 1, '%s is %d times in %s' % (key, len(block.get(key, [])), lang)


def test_no_unicode_dash_in_the_new_values():
    for lang, block in _blocks().items():
        for key in KEYS:
            assert not any('\u2010' <= ch <= '\u2015' or ch == '\u2212' for ch in block[key][0]), (lang, key)
