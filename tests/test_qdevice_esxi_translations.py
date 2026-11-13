"""The QDevice / QNetd and ESXi migration strings exist in every language.

Every key added for the QDevice setup, the QNetd hosts, the ESXi review step and the ESXi
bulk migration must occur exactly once per language block, and no value may carry an
em-dash.
LW Oct 2026
"""
import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EM_DASH = '\u2014'
LANGS = 10

with open(os.path.join(ROOT, 'web', 'src', 'translations.js'), encoding='utf-8') as fh:
    SRC = fh.read()

_en_start = SRC.index('            en: {')
_en_end = SRC.index('            zh: {')
EN = SRC[_en_start:_en_end]


def _new_keys():
    keys = []
    for pat in (r'^\s+(qdev[A-Z]\w*|qnetd[A-Z]\w*|v2p(?:Network|Job|Skip|Storage|Boot|Verify|Review|NoNics)\w*|esxiBulk\w*): ',):
        keys += re.findall(pat, EN, re.M)
    return sorted(set(keys))


KEYS = _new_keys()


def test_key_set_is_complete():
    # the families added by the QDevice and ESXi packages, not a stray handful
    assert len(KEYS) >= 240
    for k in ('qdevSetup', 'qnetdAlertSummary', 'v2pReviewError', 'esxiBulkRuns', 'v2pNoNicsOnSource'):
        assert k in KEYS


@pytest.mark.parametrize('key', KEYS)
def test_key_in_every_language(key):
    n = len(re.findall(r'^\s+%s: ' % re.escape(key), SRC, re.M))
    assert n == LANGS, '%s occurs %d times, expected %d' % (key, n, LANGS)


def test_no_em_dash_in_the_new_values():
    bad = []
    for m in re.finditer(r'^\s+((?:qdev|qnetd|esxiBulk|v2p(?:Network|Job|Skip|Storage|Boot|Verify|Review|NoNics))\w*): (.*)$', SRC, re.M):
        if EM_DASH in m.group(2):
            bad.append(m.group(1))
    assert not bad, bad


def test_placeholders_match_english():
    def table(block):
        return dict(re.findall(r"^\s+(\w+): '(.*)',$", block, re.M))
    en = table(EN)
    others = ('de', 'zh', 'pl', 'fr', 'es', 'pt', 'ko', 'it', 'ru')
    pos = [SRC.index('            %s: {' % lg) for lg in others]
    pos.append(len(SRC))
    for i in range(len(others)):
        tr = table(SRC[pos[i]:pos[i + 1]] if pos[i] != SRC.index('            de: {') else SRC[pos[i]:_en_start])
        for k in KEYS:
            if k in tr and k in en:
                assert sorted(re.findall(r'\{\w+\}', tr[k])) == sorted(re.findall(r'\{\w+\}', en[k])), k


def test_no_language_keeps_a_key_english_dropped():
    """A key the UI no longer uses goes from every block, not from two: the key set of
    a language is that of EN."""
    family = r'^\s+((?:qdev|qnetd)[A-Z]\w*): '
    en = set(re.findall(family, EN, re.M))
    dead = sorted({k for k in re.findall(family, SRC, re.M) if k not in en})
    assert dead == []
