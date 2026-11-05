"""The Corporate repository table reads the fields the repos route sends, at runtime.

The route (settings.py get_node_repos) sends name / enabled / uri in lower case; the table read
Name / Enabled / URIs, so every repo showed as disabled without a name and its button always sent
enabled: true. Drives the built bundle in headless Chromium against the fake server of
tests/test_ha_ui.py.
LW Nov 2026
"""
import re

from test_ha_ui import CLUSTER, NODE_METRICS, NODE_PATH, NODE_READS, VM, _App, _FakeServer, browser  # noqa: F401
from test_node_lvm_ui import _corp_sub, _run

REPOS = {'success': True, 'node': 'pve1', 'repositories': [
    {'id': 'pve-no-subscription', 'name': 'No-Subscription', 'file': '/etc/apt/sources.list.d/proxmox.sources',
     'enabled': True, 'exists': True, 'index': 0,
     'content': {'Types': ['deb'], 'URIs': ['http://download.proxmox.com/debian/pve'], 'Suites': ['trixie'],
                 'Components': ['pve-no-subscription'], 'Enabled': 1}},
    {'id': 'pve-enterprise', 'name': 'Enterprise', 'file': '/etc/apt/sources.list.d/pve-enterprise.sources',
     'enabled': False, 'exists': True, 'index': 0,
     'content': {'Types': ['deb'], 'URIs': ['https://enterprise.proxmox.com/debian/pve'], 'Suites': ['trixie'],
                 'Components': ['pve-enterprise'], 'Enabled': 0}},
]}


def _server(layout):
    extra = dict(NODE_READS)
    extra[('GET', NODE_PATH + '/repos')] = (200, REPOS)
    extra[('PUT', NODE_PATH + '/repos/pve-no-subscription')] = (200, {'success': True})
    extra[('PUT', NODE_PATH + '/repos/pve-enterprise')] = (200, {'success': True})
    return _FakeServer(role='active', layout=layout, clusters=[CLUSTER], resources=[VM],
                       metrics=NODE_METRICS, extra=extra)


def test_runtime_corporate_repositories_show_their_state_and_toggle_the_right_way(browser):
    def steps(page, server):
        _corp_sub(page, 'Repositories')
        nosub = page.locator('.corp-datagrid tr', has_text='No-Subscription')
        nosub.wait_for(timeout=8000)
        assert nosub.locator('.corp-badge').inner_text().strip().lower() == 'enabled'
        assert 'download.proxmox.com/debian/pve' in nosub.inner_text()
        ent = page.locator('.corp-datagrid tr', has_text='Enterprise')
        assert ent.locator('.corp-badge').inner_text().strip().lower() == 'disabled'
        nosub.get_by_role('button', name='Disable').click()
        page.wait_for_function('() => true')
        page.wait_for_timeout(800)
        assert server.bodies.get(NODE_PATH + '/repos/pve-no-subscription') == [{'enabled': False}]
        ent.get_by_role('button', name='Enable').click()
        page.wait_for_timeout(800)
        assert server.bodies.get(NODE_PATH + '/repos/pve-enterprise') == [{'enabled': True}]
    _run(browser, 'corporate', steps, _server)

