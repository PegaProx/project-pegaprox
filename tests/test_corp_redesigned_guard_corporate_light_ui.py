"""The pixel guard of tests/test_corp_redesigned_guard_ui.py for corporate-light, in a file of its own:
pytest-xdist's loadfile keeps a file on one worker, and together they set the length of the suite.
"""
import pytest

from test_corp_redesigned_guard_ui import VIEWS, browser, bundles, same_pixels  # noqa: F401 (fixtures)


@pytest.mark.parametrize('view', VIEWS)
def test_classic_corporate_light_renders_the_same_pixels(browser, bundles, view):  # noqa: F811
    same_pixels(browser, bundles, 'corporate-light', view)
