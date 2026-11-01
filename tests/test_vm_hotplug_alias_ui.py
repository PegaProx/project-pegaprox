"""The hotplug checkboxes read '1' the way PVE does, at runtime.

PVE takes hotplug '1' as an alias for its default network,disk,usb (QemuServer.pm
parse_hotplug_features); the Options tab showed memory and CPU hotplug as on, and a click
on one box wrote all five. Drives the built bundle in headless Chromium against the fake
server of tests/test_ha_ui.py. Skips where Playwright is not installed.
MK Nov 2026
"""
import copy
import re

import pytest

from test_ha_ui import VM_CONFIG
from test_vm_rng_ui import CFG, browser, open_app  # noqa: F401
from test_lxc_features_passthrough_ui import _open_config, _tab

BOXES = ('Disk', 'Network', 'USB', 'Memory', 'CPU')


def _serve(app, hotplug):
    cfg = copy.deepcopy(app.server.extra[('GET', CFG)][1])
    cfg['options'] = dict(VM_CONFIG['options'], hotplug=hotplug)
    cfg['raw'] = dict(cfg['raw'], hotplug=hotplug)
    app.server.extra[('GET', CFG)] = (200, cfg)


def _box(page, label):
    return page.locator('label', has=page.locator('input[type="checkbox"]'),
                        has_text=re.compile(rf'^\s*{label}\s*$')).last.locator('input')


def _states(page):
    return {b: _box(page, b).is_checked() for b in BOXES}


@pytest.mark.parametrize('hotplug,on', [
    ('1', {'Disk', 'Network', 'USB'}),
    ('0', set()),
    ('network,disk,usb,memory,cpu', set(BOXES)),
    ('disk,cpu', {'Disk', 'CPU'}),
], ids=['alias-1', 'off', 'all', 'some'])
def test_runtime_the_boxes_show_what_pve_runs(open_app, hotplug, on):
    app = open_app()
    _serve(app, hotplug)
    _open_config(app, 'web01')
    _tab(app, 'Options').click()
    page = app.page
    _box(page, 'Memory').wait_for(timeout=8000)
    assert _states(page) == {b: b in on for b in BOXES}


def test_runtime_one_click_on_the_alias_adds_only_that_feature(open_app):
    app = open_app()
    _serve(app, '1')
    _open_config(app, 'web01')
    _tab(app, 'Options').click()
    page = app.page
    _box(page, 'Memory').wait_for(timeout=8000)
    _box(page, 'Memory').check()
    assert _states(page) == {'Disk': True, 'Network': True, 'USB': True, 'Memory': True, 'CPU': False}
    page.get_by_role('button', name=re.compile(r'^\s*Save')).last.click()
    page.wait_for_function('() => true')
    page.wait_for_timeout(1200)
    puts = [c for c in app.server.calls if c[0] == 'PUT' and c[1] == CFG]
    assert puts, app.server.calls[-10:]
    assert app.server.vm_raw.get('hotplug') == 'disk,network,usb,memory'
