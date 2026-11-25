"""A firewall rule Proxmox VE 9.3 skips is shown as not applied, and a refused write says why.

pve-firewall 6.0.8 refuses an ICMP type given as a list, a range, a service name or a number
with a leading zero, and a GROUP name over 18 characters. Rules like that already in a config
stay there: GET .../firewall/rules hands them out with an `errors` object (field -> message),
and the firewall skips them. The tables showed them as normal enabled rules. Switching one
failed (PUT merges into the stored rule and checks the result), and the datacenter switch and
the datacenter Add dialog said nothing at all when PVE refused. The Dest. Port field took
'0,8' or '08' for ICMP as it takes a port list, which 9.3 refuses and older versions skipped
or read as another type.

Now such a rule carries an "Invalid, not applied" badge with PVE's reasons on hover and under
the row (datacenter and guest tables, Cloud), a refused switch or Add shows the error, and
with ICMP the field asks for one ICMP type, names to pick from, and keeps Add from sending
what PVE refuses.

PVE's update_rule checks the rule it would store, so an invalid rule takes no change that
leaves it invalid, switching it off included; delete_rule does not check it. The badge and
the line under the rule say so: edit it into a valid form in Proxmox VE, or delete it, and
delete works from every table. The protocol is compared as pve-firewall compares it ('ICMP'
is not ICMP to it), a type name goes out as 'icmp-type' as the rule editor of Proxmox VE sends
it (a number stays in dport, 'icmp-type' takes names only), and a rule made that way shows its
type under Port. The Cloud dialog stays open with what was typed until PVE took the rule.

Drives the built bundle in headless Chromium with the fake server of tests/test_ha_ui.py.
Skips where Playwright is not installed.
"""
import os
import re
import time

import pytest

from test_ha_ui import (CLUSTER, LANGS, NODE_METRICS, SSE_TOKEN, TOASTS_JS, VM, VM_CONFIG, _App, _FakeServer,  # noqa: F401
                        browser)
from test_lxc_features_passthrough_ui import _open_config, _tab

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DC = '/api/clusters/c1/datacenter/firewall/rules'
Q100 = '/api/clusters/c1/vms/pve1/qemu/100'
GUEST = Q100 + '/firewall/rules'
ZERO = "invalid icmp-type '010' - leading zeros are not allowed"
# the 400 of PVE's update_rule for {enable} on that rule, as the server passes it on
REFUSED = f'dport: {ZERO}'
FIX = ('Proxmox VE takes no change that leaves it invalid, not even switching it off: edit it into a valid form'
       ' in Proxmox VE, or delete it.')
RULES = [{'pos': 0, 'type': 'in', 'action': 'ACCEPT', 'proto': 'tcp', 'dport': '22', 'enable': 1, 'comment': 'ssh in'},
         {'pos': 1, 'type': 'in', 'action': 'ACCEPT', 'proto': 'icmp', 'dport': '010', 'enable': 1, 'comment': 'old ping',
          'errors': {'dport': ZERO}},
         # made in the rule editor of Proxmox VE: the type in its own property, no dport
         {'pos': 2, 'type': 'in', 'action': 'ACCEPT', 'proto': 'icmp', 'icmp-type': 'echo-request', 'enable': 1,
          'comment': 'ping from gui'}]
KEYS = ['fwRuleInvalid', 'fwRuleSkipped', 'fwRuleInvalidFix', 'fwIcmpType', 'fwIcmpTypePlaceholder', 'fwIcmpTypeHint',
        'fwIcmpTypeOne', 'fwIcmpTypeLeadingZero', 'fwIcmpTypeNumber']


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def _toast(page, text, timeout=4):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if any(text in x for x in page.evaluate(TOASTS_JS)):
            return
        page.wait_for_timeout(100)
    raise AssertionError(f'no toast saying {text!r}: {page.evaluate(TOASTS_JS)}')


def _app(browser, layout='modern', extra=None):  # noqa: F811
    return _App(browser, _FakeServer(role='standalone', layout=layout, clusters=[CLUSTER], resources=[VM],
                                     metrics=NODE_METRICS, extra={**SSE_TOKEN, **(extra or {})}))


def _marked(page, scope):
    """The badge and the line under the rule PVE skips, and none on the rule it applies."""
    bad = page.locator(f'{scope} tr', has_text='old ping').first
    badge = bad.locator('[data-fw-invalid]')
    assert badge.count() == 1, 'the rule PVE skips looks like any other'
    assert badge.inner_text().strip() == 'Invalid, not applied'
    # the reasons, then what can be done about it
    assert badge.get_attribute('title') == f'{REFUSED}\n{FIX}'
    why = page.locator(f'{scope} [data-fw-invalid-why="1"]')
    assert why.count() == 1 and why.inner_text().strip().startswith(f'Proxmox VE skips this rule: {REFUSED}')
    assert why.locator('[data-fw-invalid-fix]').inner_text().strip() == FIX
    assert page.locator(f'{scope} tr', has_text='ssh in').first.locator('[data-fw-invalid]').count() == 0
    assert page.locator(f'{scope} [data-fw-invalid-why="0"]').count() == 0
    # the type of a rule made with 'icmp-type' is under Port, not a blank
    assert 'echo-request' in page.locator(f'{scope} tr', has_text='ping from gui').first.inner_text()
    return bad


def _deleted(app, path):
    """The DELETE of the rule PVE skips went out: PVE's delete_rule does not check the rule."""
    deadline = time.time() + 4
    while time.time() < deadline and ('DELETE', path) not in app.server.calls:
        app.page.wait_for_timeout(100)
    assert ('DELETE', path) in app.server.calls


# -- Modern: the datacenter firewall -------------------------------------------------------------

def _dc(browser, extra=None):  # noqa: F811
    app = _app(browser, extra={('GET', DC): (200, RULES), **(extra or {})})
    page = app.page
    page.get_by_text('Testi').first.click()
    page.locator('button', has_text='Datacenter').first.click()
    page.locator('button', has_text='Firewall').first.click()
    page.get_by_text('old ping').first.wait_for(timeout=6000)
    return app, page


def test_runtime_the_datacenter_table_marks_the_rule_pve_skips(browser):  # noqa: F811
    app, page = _dc(browser, {('DELETE', DC + '/1'): (200, {'success': True})})
    page.on('dialog', lambda d: d.accept())
    try:
        bad = _marked(page, 'body')
        # its switch does not read as on: the config says enabled, the firewall skips it
        switch = bad.locator('button.rounded-full')
        assert 'bg-green-500' not in switch.get_attribute('class')
        assert 'bg-green-500' in page.locator('tr', has_text='ssh in').first.locator('button.rounded-full').get_attribute('class')
        bad.locator('td').last.locator('button').click()
        _deleted(app, DC + '/1')
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


def test_runtime_a_refused_datacenter_switch_says_why(browser):  # noqa: F811
    app, page = _dc(browser, {('PUT', DC + '/1'): (400, {'error': REFUSED})})
    try:
        page.locator('tr', has_text='old ping').first.locator('button.rounded-full').click()
        _toast(page, REFUSED)
        assert app.server.bodies[DC + '/1'] == [{'enable': 0}]
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


def _add_dialog(page):
    page.locator('h3', has_text='Firewall Rules').first.locator('xpath=..').locator('button').click()
    page.get_by_text('Add Firewall Rule').first.wait_for(timeout=3000)
    modal = page.locator('div.max-w-lg', has_text='Add Firewall Rule').last
    modal.locator('select').nth(3).select_option('icmp')
    return modal


def test_runtime_the_datacenter_dialog_takes_one_icmp_type(browser):  # noqa: F811
    fields = {'icmp-type': "invalid icmp-type 'timestamp-request'"}
    app, page = _dc(browser, {('POST', DC): (400, {'error': fields})})
    try:
        modal = _add_dialog(page)
        assert modal.get_by_text('ICMP type', exact=True).count() == 1
        field = modal.locator('input[list="dc-fw-icmp-types"]')
        assert field.get_attribute('placeholder') == 'e.g. echo-request or 8'
        names = page.locator('#dc-fw-icmp-types option').evaluate_all('os => os.map(o => o.value)')
        assert 'echo-request' in names and 'neighbor-solicitation' not in names
        add = modal.locator('button', has_text='Add').last
        for typed, why in (('0,8', 'fwIcmpTypeOne'), ('0:8', 'fwIcmpTypeOne'), ('ssh', 'fwIcmpTypeOne'),
                           ('08', 'fwIcmpTypeLeadingZero'), ('256', 'fwIcmpTypeNumber')):
            field.fill(typed)
            assert modal.locator('[data-fw-icmp-hint]').get_attribute('data-fw-icmp-hint') == why, typed
            assert add.is_disabled(), typed
        field.fill('0,8')
        assert 'Proxmox VE refuses lists, ranges and service names here' in modal.locator('[data-fw-icmp-hint]').inner_text()
        field.fill('08')
        assert modal.locator('[data-fw-icmp-hint]').inner_text().strip() == 'No leading zero: Proxmox VE refuses 08 or 010, write 8 or 10.'
        field.fill('8')
        assert modal.locator('[data-fw-icmp-hint]').get_attribute('data-fw-icmp-hint') == 'ok'
        assert not add.is_disabled()
        # ICMPv6 has its own names
        modal.locator('select').nth(3).select_option('icmpv6')
        field.fill('neighbor-solicitation')
        assert modal.locator('[data-fw-icmp-hint]').get_attribute('data-fw-icmp-hint') == 'ok'
        modal.locator('select').nth(3).select_option('icmp')
        assert modal.locator('[data-fw-icmp-hint]').get_attribute('data-fw-icmp-hint') == 'fwIcmpTypeOne'
        # a type PVE still refuses comes back in its words, and the dialog stays open
        field.fill('timestamp-request')
        add.click()
        _toast(page, "icmp-type: invalid icmp-type 'timestamp-request'")
        # a name goes out as 'icmp-type', as the rule editor of Proxmox VE sends it
        sent = app.server.bodies[DC][-1]
        assert sent['proto'] == 'icmp' and sent['icmp-type'] == 'timestamp-request' and 'dport' not in sent, sent
        assert page.get_by_text('Add Firewall Rule').first.is_visible()
        # a number stays in dport: 'icmp-type' takes names only
        field.fill('8')
        add.click()
        deadline = time.time() + 4
        while time.time() < deadline and len(app.server.bodies[DC]) < 2:
            page.wait_for_timeout(100)
        sent = app.server.bodies[DC][-1]
        assert sent['proto'] == 'icmp' and sent['dport'] == '8' and 'icmp-type' not in sent, sent
        # TCP keeps its port list
        modal.locator('select').nth(3).select_option('tcp')
        assert modal.locator('[data-fw-icmp-hint]').count() == 0
        assert modal.locator('input[placeholder="e.g. 22, 80, 443"]').count() == 1
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


# -- Modern: the firewall tab of a guest ---------------------------------------------------------

def _guest_extra(extra=None):
    return {('GET', f'{Q100}/config'): (200, dict(VM_CONFIG, status={'status': 'running'})),
            ('GET', f'{Q100}/firewall/options'): (200, {'enable': 1}),
            ('GET', GUEST): (200, RULES),
            ('GET', f'{Q100}/firewall/aliases'): (200, []),
            ('GET', f'{Q100}/firewall/ipset'): (200, []),
            ('GET', f'{Q100}/firewall/refs'): (200, []),
            **(extra or {})}


def test_runtime_the_guest_table_marks_the_rule_and_says_why_a_switch_failed(browser):  # noqa: F811
    app = _app(browser, extra=_guest_extra({('PUT', GUEST + '/1'): (400, {'error': REFUSED}),
                                            ('DELETE', GUEST + '/1'): (200, {'success': True}),
                                            ('POST', GUEST): (200, {'success': True})}))
    page = app.page
    page.on('dialog', lambda d: d.accept())
    try:
        _open_config(app, 'web01')
        _tab(app, 'Firewall').click()
        page.get_by_text('old ping').first.wait_for(timeout=6000)
        bad = _marked(page, 'body')
        assert 'bg-green-500' not in bad.locator('button.rounded-full').get_attribute('class')
        bad.locator('button.rounded-full').click()
        # PVE's reason, not a raw JSON body
        _toast(page, REFUSED)
        assert not any('{"errors"' in x for x in page.evaluate(TOASTS_JS))
        assert app.server.bodies[GUEST + '/1'] == [{'enable': 0}]
        bad.locator('td').last.locator('button').click()
        _deleted(app, GUEST + '/1')
        # the add dialog asks for one ICMP type as well
        page.locator('h3', has_text='Firewall Rules').last.locator('xpath=..').locator('button').click()
        modal = page.locator('div.max-w-lg', has_text='Add Firewall Rule').last
        modal.locator('select').nth(4).select_option('icmp')
        field = modal.locator('input[list="vm-fw-icmp-types"]')
        field.fill('0,8')
        assert modal.locator('[data-fw-icmp-hint]').get_attribute('data-fw-icmp-hint') == 'fwIcmpTypeOne'
        assert modal.locator('button', has_text='Add').last.is_disabled()
        field.fill('echo-request')
        assert not modal.locator('button', has_text='Add').last.is_disabled()
        modal.locator('button', has_text='Add').last.click()
        deadline = time.time() + 4
        while time.time() < deadline and not app.server.bodies.get(GUEST):
            page.wait_for_timeout(100)
        sent = app.server.bodies[GUEST][-1]
        assert sent['proto'] == 'icmp' and sent['icmp-type'] == 'echo-request' and 'dport' not in sent, sent
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


# -- Cloud -------------------------------------------------------------------------------------

def test_runtime_cloud_marks_the_rule_and_says_why_a_switch_failed(browser):  # noqa: F811
    app = _app(browser, layout='cloud', extra={('GET', DC): (200, RULES), ('PUT', DC + '/1'): (400, {'error': REFUSED}),
                                                ('DELETE', DC + '/1'): (200, {'success': True}),
                                                ('POST', DC): (400, {'error': {'icmp-type': "invalid icmp-type 'echo-request'"}})})
    page = app.page
    said = []

    def dialog(d):
        said.append(d.message)
        d.accept()
    page.on('dialog', dialog)
    try:
        page.locator('.cloud-nav-item', has_text='Firewall').first.click()
        page.get_by_text('old ping').first.wait_for(timeout=6000)
        bad = _marked(page, '.cloud-shell')
        bad.locator('button[title="Disable"]').click()
        deadline = time.time() + 4
        while time.time() < deadline and not said:
            page.wait_for_timeout(100)
        assert said == ['Action failed: ' + REFUSED], said
        # the new rule dialog: one ICMP type, and nothing sent while it is not one
        page.locator('.cloud-link-btn', has_text='New rule').first.click()
        modal = page.locator('.cloud-modal-footer').locator('xpath=../..')
        # pve-firewall compares the protocol as it is: 'ICMP' takes ports there, not an ICMP type
        modal.locator('input.cloud-input[placeholder="tcp"]').fill('ICMP')
        assert modal.locator('[data-fw-icmp-hint]').count() == 0
        assert modal.locator('input.cloud-input[placeholder="22"]').count() == 1
        modal.locator('input.cloud-input[placeholder="tcp"]').fill('icmp')
        field = modal.locator('input[list="cloud-fw-icmp-types"]')
        field.fill('0:8')
        assert modal.locator('[data-fw-icmp-hint]').get_attribute('data-fw-icmp-hint') == 'fwIcmpTypeOne'
        page.locator('.cloud-modal-footer button[type="submit"]').click()
        page.wait_for_timeout(400)
        assert ('POST', DC) not in app.server.calls
        field.fill('echo-request')
        page.locator('.cloud-modal-footer button[type="submit"]').click()
        deadline = time.time() + 4
        while time.time() < deadline and len(said) < 2:
            page.wait_for_timeout(100)
        assert app.server.bodies[DC][-1] == {'type': 'in', 'action': 'ACCEPT', 'enable': 1, 'proto': 'icmp',
                                             'icmp-type': 'echo-request'}
        # refused: PVE's words, and the dialog keeps what was typed
        assert said[-1] == "Action failed: icmp-type: invalid icmp-type 'echo-request'", said
        assert page.locator('.cloud-modal-footer').count() == 1
        assert modal.locator('input.cloud-input[placeholder="tcp"]').input_value() == 'icmp'
        assert field.input_value() == 'echo-request'
        # taken: the dialog closes, and opens empty again
        app.server.extra[('POST', DC)] = (200, {'success': True})
        page.locator('.cloud-modal-footer button[type="submit"]').click()
        page.locator('.cloud-modal-footer').wait_for(state='detached', timeout=4000)
        assert len(app.server.bodies[DC]) == 2
        page.locator('.cloud-link-btn', has_text='New rule').first.click()
        assert page.locator('.cloud-modal-footer').locator('xpath=../..').locator('input.cloud-input[placeholder="tcp"]').input_value() == ''
        page.locator('.cloud-modal-footer button', has_text='Cancel').click()
        # the rule PVE skips can be deleted
        bad.locator('button[title="Delete"]').click()
        _deleted(app, DC + '/1')
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


# -- source ------------------------------------------------------------------------------------

def _blocks():
    src = _read('web', 'src', 'translations.js')
    starts = [(m.start(), m.group(1)) for m in re.finditer(r'^ {12}([a-z]{2}): \{$', src, re.M)]
    return {lang: src[pos:(starts[i + 1][0] if i + 1 < len(starts) else len(src))] for i, (pos, lang) in enumerate(starts)}


@pytest.mark.parametrize('lang', LANGS)
def test_every_new_key_is_there_once_per_language(lang):
    block = _blocks()[lang]
    for key in KEYS:
        assert len(re.findall(r'^ {16}' + key + r': ', block, re.M)) == 1, (lang, key)


def test_the_icmp_types_are_the_ones_pve_firewall_knows():
    """The names PegaProx offers and accepts are pve-firewall's own lists, not a guess."""
    src = _read('web', 'src', 'datacenter.js')
    v4 = re.search(r'const FW_ICMP_TYPES = \[(.*?)\];', src, re.S).group(1)
    v6 = re.search(r'const FW_ICMPV6_TYPES = \[(.*?)\];', src, re.S).group(1)
    v4, v6 = re.findall(r"'([^']+)'", v4), re.findall(r"'([^']+)'", v6)
    assert len(v4) == 37 and len(set(v4)) == 37 and v4[0] == 'any' and v4[-1] == 'address-mask-reply'
    assert len(v6) == 25 and len(set(v6)) == 25 and 'any' not in v6 and 'neighbour-advertisement' in v6
    assert 'echo-request' in v4 and 'echo-request' in v6 and 'neighbor-solicitation' not in v4


def test_the_bundle_was_rebuilt():
    bundle = _read('web', 'index.html')
    for needle in ('function FwIcmpTypeHint(', 'function FwRuleInvalidBadge(', 'fwRuleProblems', 'said(body,fallback)',
                   'function fwIcmpTypeInBody(', 'fwRuleInvalidFix'):
        assert needle in bundle, needle
