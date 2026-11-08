"""The compliance audit report named the tool "PegaProx 0.9.x" on every export.

`web/src/dashboard.js` built that field from `window.PEGAPROX_VERSION`, but the constant is
declared as a plain `const` in constants.js and a const never becomes a property of window.
The lookup was therefore always undefined and the fallback won - so the version printed in a
document people hand to auditors was five releases behind, and had been since the fallback
was written.

Nico spotted it in an exported report. Checked in the built bundle rather than the source,
because the source is concatenated and the scope only exists after the build.
LW
"""
import pathlib
import re

import pytest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_BUNDLE = _ROOT / 'web' / 'index.html'
_DASH = _ROOT / 'web' / 'src' / 'dashboard.js'
_CONST = _ROOT / 'web' / 'src' / 'constants.js'


def test_the_report_does_not_read_the_version_off_window():
    src = _DASH.read_text(encoding='utf-8')
    code = '\n'.join(l for l in src.splitlines() if not l.strip().startswith('//'))
    assert 'window.PEGAPROX_VERSION' not in code, (
        "PEGAPROX_VERSION is a const - it is not on window, so this reads undefined and "
        "whatever fallback follows ends up in the report")


def test_no_stale_version_fallback_survives_in_the_report_builder():
    src = _DASH.read_text(encoding='utf-8')
    code = '\n'.join(l for l in src.splitlines() if not l.strip().startswith('//'))
    stale = re.findall(r"\|\|\s*'(0\.[0-9x.]+)'", code)
    assert not stale, f"hard-coded old version(s) still reachable as a fallback: {stale}"


@pytest.mark.skipif(not _BUNDLE.exists(), reason='bundle not built')
def test_the_constant_is_declared_before_the_report_uses_it():
    """The bare identifier only resolves because constants.js is concatenated first. If the
    order in build.sh ever flips, the typeof guard degrades instead of throwing - but the
    report would then say 'version unknown', so pin the order."""
    h = _BUNDLE.read_text(encoding='utf-8')
    decl = h.find('const PEGAPROX_VERSION=')
    use = h.find("'PegaProx '+(typeof PEGAPROX_VERSION")
    assert decl != -1, 'the version constant is not in the bundle at all'
    assert use != -1, 'the report no longer builds its tool field the expected way'
    assert decl < use, 'constants.js is concatenated after dashboard.js - the report would ' \
                       'fall back to "version unknown"'


@pytest.mark.skipif(not _BUNDLE.exists(), reason='bundle not built')
def test_the_bundle_carries_the_current_version():
    """Catches the other half: constants.js drifting behind version.json."""
    import json
    want = json.loads((_ROOT / 'version.json').read_text(encoding='utf-8'))['version']
    m = re.search(r'const PEGAPROX_VERSION="([^"]+)"', _BUNDLE.read_text(encoding='utf-8'))
    assert m, 'no version constant in the bundle'
    assert m.group(1) == want, (
        f"bundle says {m.group(1)}, version.json says {want} - the report would print the "
        f"stale one")
    src = _CONST.read_text(encoding='utf-8')
    assert f'"{want}"' in src, 'web/src/constants.js is behind version.json'


def test_every_place_that_carries_the_version_agrees_with_version_json():
    """version.json is the release; five other files repeat it and used to drift.

    The backend constant is the one that costs something. The update check compares
    PEGAPROX_VERSION from constants.py against the version.json served by the mirror, so
    if the constant is left behind at release time every install reports "update
    available" forever - including right after it updated. update.sh does not catch it
    either; its post-update check reads version.json, not the constant.

    1.1.1 shipped with PEGAPROX_BUILD still on 1.1.0's date for exactly this reason:
    nothing was watching. NS
    """
    import json
    want = json.loads((_ROOT / 'version.json').read_text(encoding='utf-8'))['version']

    backend = (_ROOT / 'pegaprox' / 'constants.py').read_text(encoding='utf-8')
    m = re.search(r'^PEGAPROX_VERSION\s*=\s*"([^"]+)"', backend, re.M)
    assert m, 'no PEGAPROX_VERSION in pegaprox/constants.py'
    assert m.group(1) == want, (
        f"pegaprox/constants.py says {m.group(1)}, version.json says {want} - the update "
        f"check would offer an update that is already installed")

    readme = (_ROOT / 'README.md').read_text(encoding='utf-8')
    badge = re.search(r'badge/version-([0-9][^-\s]*)-blue', readme)
    assert badge, 'no version badge in README.md'
    assert badge.group(1) == want, \
        f"README badge says {badge.group(1)}, version.json says {want}"
