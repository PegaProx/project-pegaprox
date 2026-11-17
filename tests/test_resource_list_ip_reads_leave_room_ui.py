"""The IP column of the resource list leaves the browser's connections to the rest of the panel.

A browser opens six connections to this server, and the live stream holds one. The column
asked the guest agent of every running VM on the page at once, so a page of a cluster far
away on a lossy line held every connection for half a minute: the healthy clusters, the
overview and the cluster switch all waited behind it, and the panel looked dead. It asks two
at a time now, gives each 15 seconds, and leaves out a guest whose address the server's own
sweep already sent (ip) or that it knows runs without an agent (agent_running false).

Drives the built bundle in headless Chromium with the fake server of the pixel guard, which
holds the agent reads until the test lets them go.
"""
import re

import pytest

from test_corp_redesigned_guard_ui import (VM, _exact, _GuardApp, _GuardServer, _modern_cluster,
                                           browser)  # noqa: F401

WAITING = [dict(VM, vmid=200 + i, name=f'app{i:02d}') for i in range(12)]
KNOWN = dict(VM, vmid=300, name='known01', ip='10.9.8.7', ip_addresses=['10.9.8.7'])
NO_AGENT = dict(VM, vmid=301, name='plain01', agent_running=False)
GUESTS = [*WAITING, KNOWN, NO_AGENT]
INFO = re.compile(r'/api/clusters/c1/vms/[^/]+/qemu/(\d+)/guest-info')


class _HoldingServer(_GuardServer):
    """Agent reads are held until let go."""

    def __init__(self, **kw):
        super().__init__(**kw)
        self.held = []
        self.asked = []

    def handle(self, route):
        path = re.sub(r'^https?://[^/]+', '', route.request.url).split('?')[0]
        m = INFO.fullmatch(path)
        if m:
            self.asked.append(int(m.group(1)))
            self.held.append(route)
            return None
        return super().handle(route)

    def let_go(self, n):
        for route in self.held[:n]:
            try:
                route.fulfill(status=200, body='{"agent_running": true, "ip_addresses": []}',
                              headers={'Content-Type': 'application/json'})
            except Exception:
                pass          # given up by the page already
        self.held = self.held[n:]


@pytest.fixture
def opened(browser):  # noqa: F811
    apps = []

    def _open():
        app = _GuardApp(browser, _HoldingServer(layout='modern', resources=GUESTS))
        apps.append(app)
        _modern_cluster(app.page)
        app.page.locator('button', has_text=_exact('Resources')).first.click()
        app.page.get_by_placeholder('Search by name or ID...').first.wait_for(timeout=8000)
        return app
    yield _open
    for app in apps:
        app.close()


def _settle(app, ms=1500):
    app.page.wait_for_timeout(ms)


def test_runtime_two_agent_reads_at_a_time(opened):
    app = opened()
    _settle(app)
    # twelve guests wait for an address; two are asked, the others queue
    assert len(app.server.held) == 2, app.server.asked
    # the rest of the panel gets through meanwhile
    got = app.page.evaluate("""async () => { const t = performance.now();
        const r = await fetch('/api/clusters/c1/resources', {credentials: 'include'});
        return [r.status, performance.now() - t]; }""")
    assert got[0] == 200 and got[1] < 3000, got
    # as one answers, the next is asked; every guest once
    for _ in range(8):
        app.server.let_go(2)
        _settle(app, 600)
    assert sorted(app.server.asked) == [g['vmid'] for g in WAITING], app.server.asked
    assert not app.errors, app.errors


def test_runtime_a_guest_the_server_knows_is_not_asked(opened):
    app = opened()
    for _ in range(10):
        app.server.let_go(2)
        _settle(app, 500)
    # the address of the server's sweep is shown, and neither it nor the agent-less one is asked
    assert 300 not in app.server.asked and 301 not in app.server.asked, app.server.asked
    # the card of the guest the server knows shows its address (the only one with an address)
    assert '10.9.8.7' in app.page.inner_text('body')
    assert not app.errors, app.errors


def test_runtime_an_agent_read_that_hangs_gives_its_place_back(opened):
    app = opened()
    _settle(app)
    assert len(app.server.asked) == 2
    # nothing answers: after 15 s both are given up and the next two are asked
    app.page.wait_for_timeout(16500)
    assert len(app.server.asked) == 4, app.server.asked
    assert not [e for e in app.errors if 'guest-info' not in e], app.errors
