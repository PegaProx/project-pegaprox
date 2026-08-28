"""The theme whitelists are GENERATED from the frontend registry.

PEGAPROX_THEMES in web/index.html.original is the single source of truth;
web/Dev/export-themes.js writes pegaprox/theme_registry.py at build time and
the backend imports its lists instead of keeping hand-maintained copies. These
tests pin the contract — and the deliberate departures from the old lists.
"""
from pegaprox.theme_registry import ALLOWED_THEMES, CORPORATE_THEMES, LIGHT_THEMES


def test_registry_has_the_core_themes():
    for theme in ('proxmoxDark', 'corporateDark', 'corporateLight', 'cloud'):
        assert theme in ALLOWED_THEMES


def test_corporate_set_matches_the_flagged_entries():
    # enterpriseBlue is deliberately corporate again: the backend always grouped
    # it with the corporate themes, but the old localStorage override meant the
    # Corporate layout never actually rendered it.
    # subset, not equality: the system-theme branch adds 'system' to the set
    assert {'corporateDark', 'corporateLight', 'enterpriseBlue'} <= set(CORPORATE_THEMES)
    assert set(CORPORATE_THEMES) <= set(ALLOWED_THEMES)


def test_light_set():
    assert set(LIGHT_THEMES) == {'corporateLight'}


def test_proxmox_light_is_gone():
    # proxmoxLight sat in the hand-maintained backend whitelist but was never
    # defined client-side — saving it silently rendered proxmoxDark. Generating
    # the whitelist from the registry removes it (review finding #9).
    assert 'proxmoxLight' not in ALLOWED_THEMES


def test_no_duplicates_and_stable_shape():
    assert len(ALLOWED_THEMES) == len(set(ALLOWED_THEMES))
    assert all(isinstance(t, str) and t for t in ALLOWED_THEMES)
