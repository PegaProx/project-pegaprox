"""The self-updater ships exactly what version.json's `update_files` lists.

A module that is imported by updated code but missing from the manifest does not
announce itself: the update succeeds, the app starts, and the feature the module
carries is quietly absent. Found by the 2026-09-29 scan - `pegaprox/utils/ws_sendall.py`
went in with #945.5 and never reached the manifest, so an in-app update would have
pulled the app.py that imports it and not the module (app.py catches the ImportError
and logs a warning, so nothing would have looked broken).
"""
import json
import os
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _manifest():
    with open(os.path.join(ROOT, 'version.json'), encoding='utf-8') as fh:
        return set(json.load(fh).get('update_files') or [])


def _tracked():
    out = subprocess.run(['git', 'ls-files'], cwd=ROOT, capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    return out.stdout.split()


def test_every_shipped_python_module_is_in_the_manifest():
    missing = sorted(f for f in _tracked()
                     if f.startswith('pegaprox/') and f.endswith('.py')
                     and f not in _manifest())
    assert not missing, (
        'these modules are in the tree but would not reach an in-app update: '
        + ', '.join(missing))


def test_the_generated_api_description_ships_too():
    """docs/openapi.json is the deliverable of #104/#693. Shipping only the
    README next to it would leave an updated install without the spec."""
    tracked = _tracked()
    if 'docs/openapi.json' not in tracked:
        pytest.skip('spec not generated in this tree')
    assert 'docs/openapi.json' in _manifest()


def test_tests_are_deliberately_not_shipped():
    """Counter-check: the rule above must not be read as 'everything ships'.
    If tests ever appear in the manifest, the first test is matching something
    other than what it means to."""
    shipped_tests = sorted(f for f in _manifest() if f.startswith('tests/'))
    assert not shipped_tests, shipped_tests
