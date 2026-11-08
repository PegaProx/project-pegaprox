"""What the browser shows for a failed node DNS read, and its string in every language (#1163).
The route and the managers are in test_node_dns_read_1163.py."""

import os
import re

import pytest

from test_ha_ui import CLUSTER, NODE_METRICS, NODE_PATH, NODE_READS, VM, _App, _FakeServer, browser  # noqa: F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# --- the key, in every language ---

def _lang_blocks():
    with open(os.path.join(ROOT, 'web', 'src', 'translations.js'), encoding='utf-8') as fh:
        src = fh.read()
    starts = [(m.start(), m.group(1)) for m in re.finditer(r'^            ([a-z]{2}): \{$', src, re.M)]
    ends = [s for s, _ in starts[1:]] + [len(src)]
    return {lang: src[start:end] for (start, lang), end in zip(starts, ends)}


def test_the_dns_read_failure_key_is_in_every_language_once_with_its_placeholder():
    blocks = _lang_blocks()
    assert list(blocks) == ['de', 'en', 'zh', 'pl', 'fr', 'es', 'pt', 'ko', 'it']
    for lang, block in blocks.items():
        found = re.findall(r"^\s+dnsReadFailed: '([^']*)',$", block, re.M)
        assert len(found) == 1, lang
        assert '{reason}' in found[0], lang
        assert '\u2014' not in found[0] and '\u2013' not in found[0], lang


# --- what the browser shows ---

FAILED = (502, {'error': 'Proxmox VE answered HTTP 500', 'upstream_status': 500})
DNS_SHOWN = 'Could not read the DNS settings of this node: Proxmox VE answered HTTP 500'


def _open_dns(page, layout):
    if layout == 'modern':
        page.get_by_text('Testi').first.click()
        page.locator('button[title="Node Configuration"]').first.click()
        page.locator('button', has_text='System').last.click()
    else:
        page.locator('.corp-tree-item', has_text='Testi').first.click()
        page.locator('.corp-tree-child', has_text='pve1').first.click()
        page.locator('.corp-tab-strip').last.get_by_text('Configure').click()
        page.locator('.corp-subnav-item', has_text=re.compile(r'^DNS$')).first.click()


def _corp_dns_edit(page):
    return page.locator('span', has_text=re.compile(r'^DNS$')).locator('..').get_by_role('button', name='Edit')


def _dns_calls(server):
    return sum(1 for method, path in server.calls if method == 'GET' and path == NODE_PATH + '/dns')


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
@pytest.mark.parametrize('role', ['active', 'standby'])
def test_failed_dns_read_is_visible_locks_editing_and_retry_recovers(browser, layout, role):
    extra = dict(NODE_READS)
    extra[('GET', NODE_PATH + '/dns')] = FAILED
    server = _FakeServer(role=role, layout=layout, clusters=[CLUSTER], resources=[VM],
                         metrics=NODE_METRICS, extra=extra)
    app = _App(browser, server)
    try:
        page = app.page
        _open_dns(page, layout)
        alert = page.get_by_role('alert').filter(has_text=DNS_SHOWN)
        alert.wait_for(timeout=8000)

        if layout == 'modern':
            panel = page.locator('h4', has_text=re.compile(r'^DNS$')).locator('../..')
            inputs = panel.locator('input')
            assert inputs.count() == 3
            assert all(inputs.nth(i).is_disabled() for i in range(3))
            assert panel.get_by_role('button', name='Save').is_disabled()
        else:
            # no '-' rows that would read as a node without DNS, and nothing to edit
            assert page.locator('.corp-property-grid', has_text='Search Domain').count() == 0
            assert _corp_dns_edit(page).is_disabled()

        server.extra[('GET', NODE_PATH + '/dns')] = (200, {'search': 'corp.lan', 'dns1': '10.0.0.53'})
        retry = alert.get_by_role('button', name='Retry')
        assert retry.is_enabled()
        retry.click()
        alert.wait_for(state='hidden', timeout=8000)
        if layout == 'modern':
            assert inputs.nth(0).input_value() == 'corp.lan'
            assert inputs.nth(1).input_value() == '10.0.0.53'
            if role == 'active':
                assert not inputs.nth(0).is_disabled()
                assert not panel.get_by_role('button', name='Save').is_disabled()
        else:
            page.get_by_text('10.0.0.53').first.wait_for(timeout=5000)
            if role == 'active':
                assert not _corp_dns_edit(page).is_disabled()
        assert not [error for error in app.errors if 'pageerror' in error], app.errors
    finally:
        app.ctx.close()


def test_corporate_asks_again_when_the_dns_tab_is_reopened_after_a_failed_read(browser):
    extra = dict(NODE_READS)
    extra[('GET', NODE_PATH + '/dns')] = FAILED
    server = _FakeServer(role='active', layout='corporate', clusters=[CLUSTER], resources=[VM],
                         metrics=NODE_METRICS, extra=extra)
    app = _App(browser, server)
    try:
        page = app.page
        _open_dns(page, 'corporate')
        page.get_by_role('alert').filter(has_text=DNS_SHOWN).wait_for(timeout=8000)
        asked = _dns_calls(server)

        server.extra[('GET', NODE_PATH + '/dns')] = (200, {'search': 'corp.lan', 'dns1': '10.0.0.53'})
        # away to a tab outside the system group (its own load asks nothing of DNS) and back
        page.locator('.corp-subnav-item', has_text=re.compile(r'^Network$')).first.click()
        page.locator('.corp-subnav-item', has_text=re.compile(r'^DNS$')).first.click()
        page.get_by_text('10.0.0.53').first.wait_for(timeout=8000)
        assert _dns_calls(server) > asked
        assert page.get_by_role('alert').filter(has_text='DNS settings').count() == 0
    finally:
        app.ctx.close()


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_a_node_without_dns_still_reads_as_empty_and_stays_editable(browser, layout):
    from playwright.sync_api import expect
    extra = dict(NODE_READS)
    extra[('GET', NODE_PATH + '/dns')] = (200, {})
    server = _FakeServer(role='active', layout=layout, clusters=[CLUSTER], resources=[VM],
                         metrics=NODE_METRICS, extra=extra)
    app = _App(browser, server)
    try:
        page = app.page
        _open_dns(page, layout)
        if layout == 'modern':
            panel = page.locator('h4', has_text=re.compile(r'^DNS$')).locator('../..')
            inputs = panel.locator('input')
            expect(inputs.nth(0)).to_be_enabled(timeout=8000)
            assert [inputs.nth(i).input_value() for i in range(3)] == ['', '', '']
            assert not panel.get_by_role('button', name='Save').is_disabled()
        else:
            expect(_corp_dns_edit(page)).to_be_enabled(timeout=8000)
            grid = page.locator('.corp-property-grid', has_text='Search Domain')
            assert grid.locator('td', has_text=re.compile(r'^-$')).count() == 4
        assert page.get_by_role('alert').filter(has_text='DNS settings').count() == 0
        assert _dns_calls(server) >= 1
    finally:
        app.ctx.close()
