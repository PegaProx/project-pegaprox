"""The snapshot policy form says what a keep count of 0 does (#1357).

A policy created with keep 0 now keeps 0 instead of turning it into 7, and save sends a blank
"Keep last N" as 0. With 0 days as well nothing is pruned: every snapshot the policy takes stays.
The days field said "(0=off)", the count field did not, and nothing on the form said that both
at 0 keep everything. The count label now names 0 as off the way the days label does, in every
language, and a short warning shows while both are 0 or blank and the policy creates snapshots.

Source checks of web/src; the condition is run by node against what save sends.
LW Nov 2026
"""
import json
import os
import re
import shutil
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LANGS = ['de', 'en', 'zh', 'pl', 'fr', 'es', 'pt', 'ko', 'it', 'ru']
DASHES = ('\u2013', '\u2014')


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def _blocks():
    src = _read('web', 'src', 'translations.js')
    starts = [(m.group(1), m.start()) for m in re.finditer(r'^            ([a-z]{2}): \{$', src, re.M)]
    ends = [pos for _, pos in starts[1:]] + [len(src)]
    return {lang: src[pos:end] for (lang, pos), end in zip(starts, ends)}


def _value(block, key):
    found = re.findall(r'^                %s: ([\'"])(.*)\1,$' % key, block, re.M)
    assert len(found) == 1, (key, found)
    return found[0][1]


def _form():
    dash = _read('web', 'src', 'dashboard.js')
    start = dash.index('function SnapshotPoliciesTab(')
    return dash[start:dash.index('\n        }\n', start)]


def test_the_count_label_names_0_as_off_as_the_days_label_does():
    blocks = _blocks()
    assert list(blocks) == LANGS
    for lang, block in blocks.items():
        days = _value(block, 'snapKeepDays')
        off = re.search(r'[(\uff08]0 ?= ?[^)\uff09]+[)\uff09]', days)
        assert off, (lang, days)
        assert _value(block, 'snapKeepCount').endswith(off.group(0)), (lang, _value(block, 'snapKeepCount'))
    assert "{t('snapKeepCount') || 'Keep last N (0=off)'}" in _form()


def test_the_warning_is_in_every_language_once_and_in_its_own_words():
    blocks = _blocks()
    en = _value(blocks['en'], 'snapKeepAll')
    for lang, block in blocks.items():
        text = _value(block, 'snapKeepAll')
        assert '0' in text and not any(d in text for d in DASHES), (lang, text)
        if lang != 'en':
            assert text != en, lang
    # it stands with the other keys of the form, far from the pinned end of each block
    for lang, block in blocks.items():
        lines = block.split('\n')
        at = next(i for i, ln in enumerate(lines) if ln.startswith('                snapKeepDays: '))
        assert lines[at + 1].startswith('                snapKeepAll: '), lang
    assert f"{{t('snapKeepAll') || '{en}'}}" in _form()


def _shown_and_sent(cases):
    form = _form()
    cond = re.search(r"\{(!editing\.prune_only && [^\n]*?) && \(\n\s*<p [^>]*data-snap-keep-all", form)
    assert cond, 'the warning is not where this test reads it'
    count = re.search(r'retention_count: (parseInt\(editing\.retention_count\)[^,]*),', form).group(1)
    days = re.search(r'retention_days: (parseInt\(editing\.retention_days\)[^,]*),', form).group(1)
    js = ("const out = %s.map(editing => [!!(%s), %s, %s]); process.stdout.write(JSON.stringify(out));"
          % (json.dumps(cases), cond.group(1), count, days))
    run = subprocess.run(['node', '-e', js], capture_output=True, text=True, timeout=30)
    assert run.returncode == 0, run.stderr[-500:]
    return json.loads(run.stdout)


@pytest.mark.skipif(not shutil.which('node'), reason='needs node')
def test_the_warning_shows_exactly_when_what_save_sends_prunes_nothing():
    cases = [
        {'retention_count': 0, 'retention_days': 0, 'prune_only': False},
        {'retention_count': '', 'retention_days': '', 'prune_only': False},
        {'retention_count': '0', 'retention_days': '0', 'prune_only': False},
        {'retention_count': '-1', 'retention_days': 0, 'prune_only': False},
        {'retention_count': 7, 'retention_days': 0, 'prune_only': False},
        {'retention_count': '', 'retention_days': '14', 'prune_only': False},
        {'retention_count': '3', 'retention_days': '', 'prune_only': False},
        # a prune only policy takes no snapshot, so nothing piles up
        {'retention_count': 0, 'retention_days': 0, 'prune_only': True},
    ]
    got = _shown_and_sent(cases)
    assert [shown for shown, _, _ in got] == [True, True, True, True, False, False, False, False], got
    for case, (shown, count, days) in zip(cases, got):
        assert shown == (count <= 0 and days <= 0 and not case['prune_only']), (case, shown, count, days)


def test_the_warning_uses_classes_the_static_build_has():
    p = re.search(r'<p className="([^"]+)" data-snap-keep-all', _form()).group(1)
    css = _read('static', 'css', 'tailwind.min.css') + _read('web', 'index.html.original')
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    assert [c for c in p.split() if c not in have] == [], p
