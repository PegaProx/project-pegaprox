"""The pixel guard of tests/test_corp_redesigned_guard_ui.py for cloud, in a file of its own:
pytest-xdist's loadfile keeps a file on one worker, and together they set the length of the suite.
"""
import pytest

from test_corp_redesigned_guard_ui import VIEWS, browser, bundles, same_pixels  # noqa: F401 (fixtures)


@pytest.mark.parametrize('view', VIEWS)
def test_cloud_renders_the_same_pixels(browser, bundles, view):  # noqa: F811
    same_pixels(browser, bundles, 'cloud', view)
