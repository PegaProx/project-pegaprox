"""The Info link of a container template only ever opens a web page.

Datastore > Templates lists the appliance index of the cluster (PVE's aplinfo), and each
entry's infopage became the href of an Info link as it came. React 18 renders a
javascript: href as it is, so whoever controls that answer chose what a click on Info
runs. Only http and https are linked now; an entry with anything else has no Info link.
Runs the built bundle (web/index.html) in headless Chromium against the fake server of
tests/test_ha_ui.py, skipped where Playwright is not installed.
NS Oct 2026
"""
import os
import re

import pytest

from test_ha_ui import CLUSTER, VM, SSE_TOKEN, _App, _FakeServer, browser  # noqa: F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

LOCAL = {'storage': 'local', 'type': 'dir', 'content': 'vztmpl,iso,backup', 'shared': 0,
         'total': 100 * 2 ** 30, 'used': 10 * 2 ** 30, 'avail': 90 * 2 ** 30, 'active': 1, 'enabled': 1,
         'node': 'pve1', 'used_fraction': 0.1}
DATASTORES = {'shared': [], 'local': {'pve1': [LOCAL]}, 'nodes': ['pve1']}


def _tmpl(package, infopage):
    return {'type': 'lxc', 'template': f'{package}_1.0_amd64.tar.zst', 'package': package,
            'headline': f'{package} headline', 'os': 'debian-12', 'version': '1.0', 'section': 'system',
            'infopage': infopage}


TEMPLATES = [
    _tmpl('safe-https', 'https://www.turnkeylinux.org/core'),
    _tmpl('safe-http', 'http://pve.proxmox.com/wiki/Linux_Container'),
    _tmpl('evil-js', 'javascript:alert(document.domain)'),
    _tmpl('evil-js-spaced', '  JavaScript:alert(1)'),
    _tmpl('evil-data', 'data:text/html,<script>alert(1)</script>'),
    _tmpl('no-page', None),
]

READS = {
    ('GET', '/api/clusters/c1/datastores'): (200, DATASTORES),
    ('GET', '/api/clusters/c1/datastores/local/content'): (200, []),
    ('GET', '/api/clusters/c1/storage-clusters'): (200, []),
    ('GET', '/api/clusters/c1/templates/available'): (200, TEMPLATES),
}


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(**kw):
        extra = dict(READS)
        extra.update(SSE_TOKEN)
        app = _App(browser, _FakeServer(clusters=[CLUSTER], resources=[VM], extra=extra, **kw))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _src(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def test_the_bundle_carries_the_scheme_check():
    for text in (_src('web', 'src', 'storage.js'), _src('web', 'index.html')):
        assert re.search(r"typeof tmpl\.infopage\s*===\s*'string'\s*&&\s*/\^https\?:", text)


def _open_templates(app):
    page = app.page
    page.get_by_text('Testi').first.click()
    page.locator('button', has_text=re.compile(r'^\s*Datastore\s*$')).first.click()
    page.locator('div.cursor-pointer', has_text='10.0 GB / 100.0 GB').first.click()
    page.locator('button', has_text=re.compile(r'^\s*Templates\s*$')).first.click()
    page.get_by_text('safe-https').first.wait_for(timeout=8000)
    page.wait_for_timeout(300)
    return page


def _info_links(page):
    """package -> the href of its Info link, None where the entry has none."""
    return page.evaluate('''() => {
        const out = {};
        for (const name of document.querySelectorAll('span.font-medium.text-white.truncate')) {
            const row = name.closest('.group');
            if (!row) continue;
            const a = Array.from(row.querySelectorAll('a')).find(x => x.textContent.trim() === 'Info');
            out[name.textContent.trim()] = a ? a.getAttribute('href') : null;
        }
        return out;
    }''')


def test_runtime_only_web_pages_become_an_info_link(open_app):
    app = open_app(role='standalone', layout='modern')
    page = _open_templates(app)
    links = _info_links(page)
    assert set(links) == {t['package'] for t in TEMPLATES}, links
    # what an operator needs keeps working
    assert links['safe-https'] == 'https://www.turnkeylinux.org/core'
    assert links['safe-http'] == 'http://pve.proxmox.com/wiki/Linux_Container'
    # and nothing else is an href
    for name in ('evil-js', 'evil-js-spaced', 'evil-data', 'no-page'):
        assert links[name] is None, (name, links[name])
    assert not page.locator('a[href^="javascript:" i], a[href*="javascript:" i], a[href^="data:" i]').count()
    # the rest of the entry is still shown
    row = page.locator('.group', has_text='evil-js-spaced').first
    assert 'evil-js-spaced headline' in row.inner_text()
    assert row.locator('button').count() == 1   # the download button
    assert not app.errors, app.errors
