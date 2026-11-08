"""The rolling update calls enter_maintenance_mode with the same keyword arguments on every
cluster type. The XCP-ng manager did not take allow_local_disks, so each evacuating
rolling update on XCP-ng stopped with a TypeError at its first node.

MK Oct 2026
"""
import ast
import inspect
import os

from pegaprox.core.manager import PegaProxManager
from pegaprox.core.xcpng import XcpngManager

SETTINGS = os.path.join(os.path.dirname(__file__), '..', 'pegaprox', 'api', 'settings.py')


def _keywords_the_rolling_update_passes():
    tree = ast.parse(open(SETTINGS, encoding='utf-8').read())
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, 'attr', '') == 'enter_maintenance_mode':
            names |= {k.arg for k in node.keywords if k.arg}
    return names


def test_both_managers_take_every_keyword_the_xcpng_path_gets():
    passed = _keywords_the_rolling_update_passes()
    assert {'skip_evacuation', 'allow_local_disks'} <= passed, passed
    # migrate_templates is forced off on XCP-ng and never passed there (#763)
    for cls in (PegaProxManager, XcpngManager):
        inspect.signature(cls.enter_maintenance_mode).bind(
            None, 'node1', skip_evacuation=False, allow_local_disks=True)
