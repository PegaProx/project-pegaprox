"""an account with ha.view alone - every live control in the HA settings, the HA
section of the cluster Settings tab and the HA page of the cloud layout.

LW Oct 2026 (#625)
"""
import re

import pytest

from test_ha_ui import browser, _App  # noqa: F401
from test_ha_node_ui import _NodeHaServer, _open_ha_settings, _wait_for, IPMI_PVE1, CHECK, OWN, _iso_ago

VIEW = ['cluster.view', 'node.view', 'vm.view', 'ha.view']
RES = {('GET', '/api/clusters/c1/proxmox-ha/resources'): (200, [{'sid': 'vm:100', 'max_restart': 3}])}

LIVE_JS = '''(root) => {
    const out = [];
    for (const el of root.querySelectorAll('button, input, select, textarea, [role=switch], .toggle-switch, summary')) {
        const fs = el.closest('fieldset');
        const disabled = el.disabled || (fs && fs.disabled && el.tagName !== 'SUMMARY');
        if (disabled) continue;
        const r = el.getBoundingClientRect();
        if (r.width === 0 && r.height === 0) continue;
        out.push((el.tagName + ' ' + (el.getAttribute('aria-label') || el.getAttribute('title') || el.innerText || el.className || '').trim()).slice(0, 80));
    }
    return out;
}'''


@pytest.fixture
def apps():
    out = []
    yield out
    for a in out:
        a.ctx.close()


def _writes(app):
    return [c for c in app.server.calls if c[0] not in ('GET', 'HEAD') and '/api/clusters/' in c[1]
            and not c[1].endswith('/updates/check')]


@pytest.mark.parametrize('installed', [True, False])
def test_live_controls_in_the_ha_settings_for_ha_view(browser, apps, installed):
    kw = dict(admin=False, permissions=VIEW, versions={'pve1': 2, 'pve2': 1}, fencing=IPMI_PVE1, check=CHECK,
              unsafe=True, claim={'enabled': True, 'state': 'ours', 'epoch': 2, 'instance': OWN,
                                  'checked_at': _iso_ago(5)}, extra=RES)
    if not installed:
        kw['installed'] = ()
    app = _App(browser, _NodeHaServer(**kw))
    apps.append(app)
    page = app.page
    modal = _open_ha_settings(app, wait='[data-ha-node-claim]')
    modal.locator('details summary').click()
    page.wait_for_timeout(300)
    live = modal.evaluate(LIVE_JS)
    print('installed', installed, 'live in modal:', live)
    allowed = re.compile(r'^(BUTTON (Copy|Cancel|Kopieren)?|SUMMARY .*|BUTTON\s*$)')
    bad = [x for x in live if not allowed.match(x)]
    # click every remaining live thing and watch for writes
    for el in modal.locator('button:not([disabled]), [role=switch]:not([disabled])').all():
        try:
            if el.is_visible() and el.is_enabled():
                txt = (el.inner_text() or '').strip()
                if txt in ('Cancel',):
                    continue
                el.click(timeout=1000)
                page.wait_for_timeout(150)
        except Exception:
            pass
    page.wait_for_timeout(500)
    print('writes after clicking all live:', _writes(app))
    assert not _writes(app), _writes(app)
    assert not bad, bad


def test_live_controls_in_the_cluster_settings_ha_section_for_ha_view(browser, apps):
    app = _App(browser, _NodeHaServer(admin=False, permissions=VIEW, versions={'pve1': 2, 'pve2': 2}, extra=RES))
    apps.append(app)
    page = app.page
    page.get_by_text('Testi').first.click()
    page.get_by_role('button', name='Settings', exact=True).first.click()
    page.get_by_text('High Availability (HA)').first.wait_for(timeout=5000)
    page.get_by_text('VM 100').first.wait_for(timeout=5000)
    sect = page.locator('div.pt-4', has=page.locator('h4', has_text='High Availability (HA)')).first
    native = page.locator('div.pt-4', has=page.locator('h4', has_text='Proxmox Native HA')).first
    live = {'ha section': sect.evaluate(LIVE_JS), 'native': native.evaluate(LIVE_JS)}
    print('live for ha.view:', live)
    # shown, but not live: the toggle takes no pointer, and a click sent to it anyway
    # changes nothing; there is no remove button at all
    assert sect.locator('[aria-disabled="true"]').count() >= 1
    sect.locator('.toggle-switch').first.dispatch_event('click')
    assert native.get_by_title('Remove from HA').count() == 0
    page.wait_for_timeout(800)
    print('writes:', _writes(app))
    assert not _writes(app), f'ha.view account sends HA writes from the Settings tab: {_writes(app)}'


def test_live_controls_on_the_cloud_ha_page_for_ha_view(browser, apps):
    app = _App(browser, _NodeHaServer(admin=False, permissions=VIEW, versions={'pve1': 2, 'pve2': 1}, unsafe=True,
                                      layout='cloud', extra=RES))
    apps.append(app)
    page = app.page
    page.get_by_text('High Availability', exact=True).first.click()
    page.locator('[data-ha-node-cloud]').wait_for(timeout=5000)
    root = page.locator('.cloud-mounted').first
    live = root.evaluate(LIVE_JS)
    print('cloud HA page live for ha.view:', live)
    if root.get_by_title('Remove from HA').count():
        root.get_by_title('Remove from HA').first.click()
        page.wait_for_timeout(800)
    print('writes:', _writes(app))
    assert not _writes(app), _writes(app)
