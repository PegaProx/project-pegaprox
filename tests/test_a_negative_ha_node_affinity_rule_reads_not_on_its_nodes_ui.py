"""A negative HA node affinity rule reads "not on: <nodes>", and the rule dialog offers one.

Proxmox VE 9.3 (pve-ha-manager 5.2.5) has node affinity rules with `affinity` negative: the
guests run on any node but the ones listed. The HA groups view of the Datacenter tab is built
from the node affinity rules and listed such a rule as a group of its nodes, so "keep-off-pve3 |
pve3 | Restricted" read as "only on pve3", the opposite of what PVE does. Its rows now carry
`affinity`, and a negative one says "not on: pve3". The Add dialog offers keep on or keep off;
only a negative rule sends `affinity` (positive is PVE's default), so what older clusters get
stays the same request as before.

Drives the built bundle in headless Chromium with the fake server of tests/test_ha_ui.py.
Skips where Playwright is not installed.
"""
import re

import pytest

from test_ha_ui import CLUSTER, LANGS, NODE_METRICS, SSE_TOKEN, VM, _App, _FakeServer, _read, browser  # noqa: F401

GROUPS = '/api/clusters/c1/proxmox-ha/groups'
# get_proxmox_ha_groups on a 9.3 cluster: the node affinity rules in the group shape
RULES = [{'group': 'keep-off-pve3', 'nodes': 'pve3', 'restricted': 1, 'nofailback': 0, 'affinity': 'negative',
          '_pve_rule_id': 'keep-off-pve3', '_pve_rule_resources': 'vm:100', '_pve_rule_disable': 0},
         {'group': 'prefer-pve1', 'nodes': 'pve1:2,pve2:1', 'restricted': 0, 'nofailback': 0, 'affinity': 'positive',
          '_pve_rule_id': 'prefer-pve1', '_pve_rule_resources': 'vm:101', '_pve_rule_disable': 0},
         # PVE 8: a group, no affinity at all
         {'group': 'legacy', 'nodes': 'pve2', 'restricted': 0, 'nofailback': 1}]
KEYS = ['haNotOnNodes', 'haAffinity', 'haAffinityPositive', 'haAffinityNegative', 'haAffinityNegativeHint']


def _ha(browser):  # noqa: F811
    app = _App(browser, _FakeServer(role='standalone', layout='modern', clusters=[CLUSTER], resources=[VM], metrics=NODE_METRICS, extra={
        **SSE_TOKEN, ('GET', GROUPS): (200, RULES), ('GET', '/api/clusters/c1/proxmox-ha/resources'): (200, []),
        ('POST', GROUPS): (200, {'success': True})}))
    page = app.page
    page.get_by_text('Testi').first.click()
    page.locator('button', has_text='Datacenter').first.click()
    page.locator('button', has_text='Proxmox Native HA').first.click()
    page.get_by_text('keep-off-pve3').first.wait_for(timeout=6000)
    return app, page


def _nodes_cell(page, group):
    """The Nodes column of a group's row."""
    return page.locator('tr', has=page.locator('td', has_text=re.compile('^' + re.escape(group) + '$'))).locator('td').nth(1)


def test_runtime_a_negative_rule_reads_not_on_its_nodes(browser):  # noqa: F811
    app, page = _ha(browser)
    try:
        cell = _nodes_cell(page, 'keep-off-pve3')
        assert cell.inner_text().strip() == 'not on: pve3'
        assert cell.get_attribute('data-ha-group-nodes') == 'negative'
        for group, nodes in (('prefer-pve1', 'pve1:2,pve2:1'), ('legacy', 'pve2')):
            cell = _nodes_cell(page, group)
            assert cell.inner_text().strip() == nodes
            assert cell.get_attribute('data-ha-group-nodes') == 'positive'
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


def _dialog(page):
    page.locator('h3', has_text='Groups').locator('xpath=..').locator('button', has_text='Add').click()
    dialog = page.locator('div.max-w-md', has_text='Add HA Group').last
    dialog.wait_for(timeout=3000)
    return dialog


def test_runtime_the_dialog_sends_affinity_only_for_a_negative_rule(browser):  # noqa: F811
    app, page = _ha(browser)
    try:
        dialog = _dialog(page)
        assert dialog.locator('[data-ha-affinity] option').all_inner_texts() == ['Keep on these nodes', 'Keep off these nodes']
        dialog.locator('input[placeholder="e.g. production"]').fill('prefer-pve2')
        dialog.locator('input[placeholder="node1:1,node2:2,node3:1"]').fill('pve2')
        dialog.locator('button', has_text='Create').click()
        page.locator('div.max-w-md', has_text='Add HA Group').wait_for(state='detached', timeout=3000)
        # what a positive rule sends is the request of before, older clusters see no new parameter
        assert app.server.bodies[GROUPS][-1] == {'group': 'prefer-pve2', 'nodes': 'pve2', 'restricted': 0, 'nofailback': 0}

        dialog = _dialog(page)
        dialog.locator('[data-ha-affinity]').select_option('negative')
        assert dialog.locator('input[placeholder="node3"]').count() == 1
        assert 'Needs Proxmox VE 9.3 or newer' in dialog.inner_text()
        dialog.locator('input[placeholder="e.g. production"]').fill('keep-off-pve2')
        dialog.locator('input[placeholder="node3"]').fill('pve2')
        dialog.locator('input[type="checkbox"]').first.check()
        dialog.locator('button', has_text='Create').click()
        page.locator('div.max-w-md', has_text='Add HA Group').wait_for(state='detached', timeout=3000)
        assert app.server.bodies[GROUPS][-1] == {'group': 'keep-off-pve2', 'nodes': 'pve2', 'restricted': 1, 'nofailback': 0,
                                                 'affinity': 'negative'}
        # the next rule starts as a positive one again
        dialog = _dialog(page)
        assert dialog.locator('[data-ha-affinity]').input_value() == 'positive'
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


def _blocks():
    src = _read('web', 'src', 'translations.js')
    starts = [(m.start(), m.group(1)) for m in re.finditer(r'^ {12}([a-z]{2}): \{$', src, re.M)]
    return {lang: src[pos:(starts[i + 1][0] if i + 1 < len(starts) else len(src))] for i, (pos, lang) in enumerate(starts)}


@pytest.mark.parametrize('lang', LANGS)
def test_every_new_key_is_there_once_per_language(lang):
    block = _blocks()[lang]
    for key in KEYS:
        found = re.findall(r'^ {16}' + key + r": '([^']*)'", block, re.M)
        assert len(found) == 1, (lang, key)
        if key == 'haNotOnNodes':
            assert '{nodes}' in found[0], lang
