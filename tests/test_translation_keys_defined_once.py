"""A translation key is defined once per language.

In a JavaScript object literal the last of two equal keys wins and the first is dead text:
whoever corrects a wording there changes nothing on screen, and a second definition added for
another view silently replaces the first everywhere (#1244). The dead definitions are gone,
and this keeps new ones out.
"""
import collections
import os
import re

TR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'web', 'src', 'translations.js')


def test_no_key_is_defined_twice_in_a_language():
    lines = open(TR, encoding='utf-8').read().split('\n')
    starts = [(i, m.group(1)) for i, ln in enumerate(lines) if (m := re.match(r'^ {12}([a-z][a-z]): \{', ln))]
    assert len(starts) == 9
    twice = {}
    for n, (at, lang) in enumerate(starts):
        end = starts[n + 1][0] if n + 1 < len(starts) else len(lines)
        keys = collections.Counter(m.group(1) for ln in lines[at + 1:end] if (m := re.match(r'^ {16}(\w+): ', ln)))
        found = sorted(k for k, c in keys.items() if c > 1)
        if found:
            twice[lang] = found
    assert not twice, f'defined twice, the last one wins: {twice}'
