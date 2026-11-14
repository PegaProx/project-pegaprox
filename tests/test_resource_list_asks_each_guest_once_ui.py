"""The IP column of the resource list asks the guest agent of each running VM once.

The lookup kept a guest whose agent answered without an address, or whose call failed, as
not asked yet, and every render of the list asked it again: one open tab sent about 15
requests a second, close to the per-IP rate limit, and a 429 kept the loop going. A guest
without an address is asked again after a minute now, a refused or failed call after five,
and a guest with an address shows it as before.

Drives the built bundle in headless Chromium with the fake server of the pixel guard. Its
clock stands still, so the tests move it on to let a minute pass; skips where Playwright or
the browser is not installed.
"""
import datetime
import re
import time

import pytest

from test_corp_redesigned_guard_ui import (CT, FIXED, VM, _corp_cluster, _exact, _GuardApp, _GuardServer,
                                           _modern_cluster, browser)  # noqa: F401


def _guest(vmid, name, node='pve1', **kw):
    return dict(VM, vmid=vmid, name=name, node=node, **kw)


# the agent of these answers, but without an address (not started yet, or not installed)
QUIET = [_guest(110, 'app01'), _guest(111, 'app02', node='pve2'), _guest(112, 'app03')]
# this one is refused by the rate limit
LIMITED = _guest(113, 'app04')
STOPPED = _guest(102, 'db01', node='pve2', status='stopped', cpu=0, cpu_percent=0, mem=0, mem_percent=0, uptime=0)
GUESTS = [VM, *QUIET, LIMITED, STOPPED, CT]


def _info(g):
    return f"/api/clusters/c1/vms/{g['node']}/qemu/{g['vmid']}/guest-info"


READS = {('GET', _info(VM)): (200, {'agent_running': True, 'ip_addresses': ['10.0.0.50', 'fe80::1']}),
         ('GET', _info(LIMITED)): (429, {'error': 'Rate limit exceeded. Please slow down.', 'retry_after': 60})}
READS.update({('GET', _info(g)): (200, {'agent_running': False, 'ip_addresses': []}) for g in QUIET})

# the IP cell of every row of the table view, by the guest's name
IPS = '''() => {
  const th = document.querySelector('th[data-col="ip"]');
  if (!th) return null;
  const cols = [...th.parentElement.children];
  const at = cols.indexOf(th), named = cols.indexOf(document.querySelector('th[data-col="name"]'));
  const out = {};
  for (const tr of th.closest('table').querySelectorAll('tbody tr')) {
    if (tr.children[at]) out[tr.children[named].innerText.trim().split('\\n')[0]] = tr.children[at].innerText.trim();
  }
  return out;
}'''


@pytest.fixture
def open_list(browser):  # noqa: F811
    apps = []

    def _open(layout):
        app = _GuardApp(browser, _GuardServer(layout=layout, resources=GUESTS, extra=READS))
        apps.append(app)
        page = app.page
        if layout == 'corporate':
            _corp_cluster(page)
        else:
            _modern_cluster(page)
        page.locator('button', has_text=_exact('Resources')).first.click()
        page.get_by_placeholder('Search by name or ID...').first.wait_for(timeout=8000)
        return app
    yield _open
    for app in apps:
        app.close()


def _asked(app):
    """guest-info requests per vmid, since the page was opened."""
    out = {}
    for method, path in app.server.calls:
        m = re.fullmatch(r'/api/clusters/c1/vms/[^/]+/qemu/(\d+)/guest-info', path)
        if m:
            out[int(m.group(1))] = out.get(int(m.group(1)), 0) + 1
    return out


def _rerender(page, seconds):
    """The list drawn again and again: a search that hides the guests and brings them back."""
    box = page.get_by_placeholder('Search by name or ID...').first
    end = time.time() + seconds
    while time.time() < end:
        box.fill('web01')
        page.wait_for_timeout(250)
        box.fill('')
        page.wait_for_timeout(250)


def _clock(app, seconds):
    app.ctx.clock.set_fixed_time(datetime.datetime.fromtimestamp(FIXED + seconds, tz=datetime.timezone.utc))


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_a_guest_without_an_address_is_asked_once(open_list, layout):
    app = open_list(layout)
    _rerender(app.page, 10)
    asked = _asked(app)
    # one request for each running VM in ten seconds of renders, a stopped one and the container none
    assert asked == {100: 1, 110: 1, 111: 1, 112: 1, 113: 1}, asked
    assert not app.errors, app.errors


def test_runtime_the_address_shows_as_before(open_list):
    app = open_list('corporate')
    page = app.page
    for _ in range(40):
        if (page.evaluate(IPS) or {}).get('web01') == '10.0.0.50':
            break
        page.wait_for_timeout(200)
    _rerender(page, 2)
    ips = page.evaluate(IPS)
    assert ips == {'web01': '10.0.0.50', 'app01': '-', 'app02': '-', 'app03': '-', 'app04': '-', 'db01': '-',
                   'ct01': '-'}, ips
    # sorted by IP, the guest with an address comes first and the blanks after it
    page.locator('th[data-col="ip"]').click()
    page.wait_for_timeout(300)
    assert list(page.evaluate(IPS))[0] == 'web01'
    assert not app.errors, app.errors


def test_runtime_a_guest_is_asked_again_after_a_while(open_list):
    app = open_list('modern')
    page = app.page
    _rerender(page, 2)
    assert _asked(app) == {100: 1, 110: 1, 111: 1, 112: 1, 113: 1}, _asked(app)
    # a minute on, the guests without an address are asked once more; the refused one waits longer
    _clock(app, 61)
    _rerender(page, 3)
    assert _asked(app) == {100: 1, 110: 2, 111: 2, 112: 2, 113: 1}, _asked(app)
    # five minutes on, the refused one is asked again too; the guest with an address never again
    _clock(app, 301)
    _rerender(page, 3)
    assert _asked(app) == {100: 1, 110: 3, 111: 3, 112: 3, 113: 2}, _asked(app)
    assert not app.errors, app.errors
