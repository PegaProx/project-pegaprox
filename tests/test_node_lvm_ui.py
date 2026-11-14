"""LVM and thin pools of a node read the shapes PVE sends, at runtime.

PVE answers disks/lvm as a tree ({leaf, children: [{name, size, free, children}]}) and the pages
read a list of {vg, size, free}: no volume group showed in either layout and the thin pool dialog
had none to pick. disks/lvmthin has used / lv_size, the pages read usage and metadata_usage.
Drives the built bundle in headless Chromium against the fake server of tests/test_ha_ui.py.
LW Nov 2026
"""
import re

import pytest  # noqa: F401

from test_ha_ui import CLUSTER, NODE_METRICS, NODE_PATH, NODE_READS, VM, _App, _FakeServer, browser  # noqa: F401

GIB = 1024 ** 3
LVM_TREE = {'leaf': 0, 'children': [
    {'leaf': 0, 'name': 'pve', 'size': 400 * GIB, 'free': 100 * GIB,
     'children': [{'leaf': 1, 'name': '/dev/sda3', 'size': 400 * GIB, 'free': 100 * GIB}]},
    {'leaf': 0, 'name': 'vgdata', 'size': 800 * GIB, 'free': 800 * GIB,
     'children': [{'leaf': 1, 'name': '/dev/sdb', 'size': 800 * GIB, 'free': 800 * GIB}]},
]}
THIN = [{'lv': 'data', 'vg': 'pve', 'lv_size': 200 * GIB, 'used': 122 * GIB,
         'metadata_size': 2 * GIB, 'metadata_used': GIB}]


def _server(layout):
    extra = dict(NODE_READS)
    extra[('GET', NODE_PATH + '/disks/lvm')] = (200, LVM_TREE)
    extra[('GET', NODE_PATH + '/disks/lvmthin')] = (200, THIN)
    return _FakeServer(role='active', layout=layout, clusters=[CLUSTER], resources=[VM],
                       metrics=NODE_METRICS, extra=extra)


def _corp_sub(page, label):
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.locator('.corp-tree-child', has_text='pve1').first.click()
    page.locator('.corp-tab-strip').last.get_by_text('Configure').click()
    page.locator('.corp-subnav-item', has_text=re.compile(rf'^{label}$')).first.click()


def _modern_storage(page):
    page.get_by_text('Testi').first.click()
    page.locator('button[title="Node Configuration"]').first.click()
    page.locator('button', has_text=re.compile(r'^\s*Disks\s*$')).last.click()


def _run(browser, layout, steps, server=None):
    app = _App(browser, (server or _server)(layout))
    try:
        steps(app.page, app.server)
        assert not [e for e in app.errors if 'pageerror' in e], app.errors
    finally:
        app.ctx.close()


def test_runtime_corporate_lists_the_volume_groups_of_the_tree(browser):
    def steps(page, server):
        _corp_sub(page, 'LVM')
        row = page.locator('.corp-datagrid tr', has_text='vgdata')
        row.wait_for(timeout=8000)
        assert '800' in row.inner_text()
        pve = page.locator('.corp-datagrid tr', has=page.locator('td', has_text=re.compile(r'^pve$'))).inner_text()
        assert '400' in pve and '100' in pve
        assert page.get_by_text('No LVM volumes').count() == 0
    _run(browser, 'corporate', steps)


def test_runtime_corporate_shows_the_data_share_a_thin_pool_uses(browser):
    def steps(page, server):
        _corp_sub(page, 'LVM-Thin')
        row = page.locator('.corp-datagrid tr', has=page.locator('td', has_text=re.compile(r'^data$')))
        row.wait_for(timeout=8000)
        assert row.locator('td').nth(3).inner_text().strip() == '61%'
    _run(browser, 'corporate', steps)


def test_runtime_modern_shows_the_groups_and_offers_them_for_a_thin_pool(browser):
    def steps(page, server):
        _modern_storage(page)
        page.get_by_text('vgdata').first.wait_for(timeout=8000)
        page.get_by_text('61% used').first.wait_for(timeout=8000)
        page.locator('button', has_text='Create LVM-Thin').first.click()
        options = page.locator('select option')
        page.locator('select option[value="vgdata"]').wait_for(state='attached', timeout=8000)
        values = [options.nth(i).get_attribute('value') for i in range(options.count())]
        assert 'pve' in values and 'vgdata' in values
    _run(browser, 'modern', steps)
