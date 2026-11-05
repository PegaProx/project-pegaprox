"""PBS datastore selections and pending reads retain their own UI lifetime."""

import json
import re
from urllib.parse import urlsplit

import pytest

from test_ha_ui import PBS, _App, _FakeServer, browser  # noqa: F401


class _DatastoreServer(_FakeServer):
    """Hold real browser fetches while other PBS reads keep responding."""

    def __init__(self, layout="modern"):
        """Expose two distinguishable servers and controllable datastore replies."""
        other = dict(PBS, id="p2", name="backup02")
        reads = {("GET", "/api/pbs"): (200, [PBS, other])}
        for pbs_id, name in [("p1", "alpha"), ("p2", "beta")]:
            reads[("GET", f"/api/pbs/{pbs_id}/datastores")] = (200, [{"name": name}])
            reads[("GET", f"/api/pbs/{pbs_id}/jobs")] = (200, {})
            reads[("POST", f"/api/pbs/{pbs_id}/datastores/{name}/prune")] = (
                200, {"data": "UPID:prune"})
        super().__init__(role="standalone", layout=layout, extra=reads)
        self.hold = set()
        self.pending = []
        self.datastore_reads = []
        self.status_reads = {"p1": 0, "p2": 0}

    def handle(self, route):
        """Record datastore requests and make each status poll observable in the UI."""
        path = urlsplit(route.request.url).path
        if route.request.method == "GET":
            for pbs_id in self.status_reads:
                if path == f"/api/pbs/{pbs_id}/status":
                    self.status_reads[pbs_id] += 1
                    version = f"4.0-{pbs_id}-{self.status_reads[pbs_id]}"
                    self.extra[("GET", path)] = (200, {"version": {"version": version}})
            if re.fullmatch(r"/api/pbs/[^/]+/datastores", path):
                self.datastore_reads.append(path)
                if path in self.hold:
                    self.calls.append(("GET", path))
                    self.pending.append((path, route))
                    return None
        return super().handle(route)

    def release(self, path, data, status=200):
        """Complete the oldest held request without completing later selections."""
        for index, (held_path, route) in enumerate(self.pending):
            if held_path == path:
                self.pending.pop(index)
                route.fulfill(status=status, body=json.dumps(data),
                              headers={"Content-Type": "application/json"})
                return
        raise AssertionError(f"No held datastore read for {path}")


    def close(self):
        """Abort held requests before destroying the browser context."""
        pending, self.pending = self.pending, []
        for _, route in pending:
            route.abort("aborted")


def _open(page, server, pbs_id="p1", event=False):
    """Select a server and wait for its new request and status render."""
    name = "backup01" if pbs_id == "p1" else "backup02"
    before = server.status_reads[pbs_id]
    with page.expect_request(f"**/api/pbs/{pbs_id}/datastores"):
        target = page.get_by_text(name, exact=True).first
        if event:
            target.dispatch_event("click")
        else:
            target.click()
    page.get_by_text(f"v4.0-{pbs_id}-{before + 1}", exact=True).wait_for(timeout=5000)


def _tick(page, server, pbs_id="p1"):
    """Advance one polling interval and confirm its independent status response."""
    before = server.status_reads[pbs_id]
    page.clock.run_for(30001)
    page.get_by_text(f"v4.0-{pbs_id}-{before + 1}", exact=True).wait_for(timeout=5000)


def _release(page, server, path, data):
    """Wait for a held response body and subsequent browser render turns."""
    with page.expect_response("**" + path) as response:
        server.release(path, data)
    response.value.finished()
    page.evaluate("() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))")


def _store_button(page, name="alpha"):
    """Locate a datastore card by its visible name."""
    return page.get_by_role("button", name=re.compile(rf"^{name}\b"))


def _prune_dialog(page):
    """Locate the open prune dialog by its heading."""
    return page.get_by_role("heading", name=re.compile(r"^Prune Datastore$", re.I))


@pytest.mark.parametrize("layout", ["modern", "corporate"])
def test_failed_background_read_closes_prune_and_retry_preserves_prune(browser, layout):
    """An invalid list closes pending actions; a valid retry can still preview pruning."""
    server = _DatastoreServer(layout)
    app = _App(browser, server, clock=True)
    try:
        page = app.page
        _open(page, server)
        page.get_by_role("button", name="Datastores", exact=True).click()
        _store_button(page).click()
        page.get_by_role("button", name="Prune", exact=True).click()
        _prune_dialog(page).wait_for(timeout=5000)
        server.extra[("GET", "/api/pbs/p1/datastores")] = (
            403, {"code": "PBS_FORBIDDEN", "error": "PBS denied the request"})

        _tick(page, server)
        page.get_by_role("alert").filter(
            has_text="Could not load all data: Datastores").wait_for(timeout=5000)
        assert _prune_dialog(page).count() == 0
        assert page.get_by_role("button", name="Preview Prune", exact=True).count() == 0
        assert ("POST", "/api/pbs/p1/datastores/alpha/prune") not in server.calls

        server.extra[("GET", "/api/pbs/p1/datastores")] = (200, [{"name": "alpha"}])
        page.get_by_role("button", name="Refresh", exact=True).click()
        page.get_by_role("button", name="Prune", exact=True).wait_for(timeout=5000)
        assert _prune_dialog(page).count() == 0
        page.get_by_role("button", name="Prune", exact=True).click()
        page.get_by_role("button", name="Preview Prune", exact=True).click()
        page.get_by_text(re.compile(r"prune started on alpha")).wait_for(timeout=5000)
        assert server.calls.count(("POST", "/api/pbs/p1/datastores/alpha/prune")) == 1
        assert server.bodies["/api/pbs/p1/datastores/alpha/prune"][0]["dry_run"] is True
        assert not app.errors, app.errors
    finally:
        server.close()
        app.ctx.close()


def test_server_selection_invalidates_an_open_prune_dialog(browser):
    """Changing context cannot direct an old dialog at a different PBS server."""
    server = _DatastoreServer()
    app = _App(browser, server)
    try:
        page = app.page
        _open(page, server)
        page.get_by_role("button", name="Datastores", exact=True).click()
        _store_button(page).click()
        page.get_by_role("button", name="Prune", exact=True).click()
        _prune_dialog(page).wait_for(timeout=5000)
        server.hold.add("/api/pbs/p2/datastores")

        # Dispatch the same sidebar navigation event while the modal is open.
        _open(page, server, "p2", event=True)
        assert _prune_dialog(page).count() == 0
        assert page.get_by_role("button", name="Preview Prune", exact=True).count() == 0
        assert not any(method == "POST" and path.endswith("/prune")
                       for method, path in server.calls)
        assert not app.errors, app.errors
    finally:
        server.close()
        app.ctx.close()


@pytest.mark.parametrize("layout", ["modern", "corporate"])
def test_same_server_return_ignores_old_reply_and_old_finally(browser, layout):
    """Returning to A needs a fresh read; an old A reply cannot release its new slot."""
    path_a, path_b = "/api/pbs/p1/datastores", "/api/pbs/p2/datastores"
    server = _DatastoreServer(layout)
    app = _App(browser, server, clock=True)
    try:
        page = app.page
        _open(page, server)
        page.get_by_text("alpha", exact=True).wait_for(timeout=5000)
        server.hold.update([path_a, path_b])
        with page.expect_request("**" + path_a):
            page.get_by_role("button", name="Refresh", exact=True).click()
        _open(page, server, "p2")
        _open(page, server, "p1")
        assert page.get_by_text("alpha", exact=True).count() == 0

        _release(page, server, path_a, [{"name": "old-alpha"}])
        _tick(page, server)
        assert server.datastore_reads.count(path_a) == 3
        assert page.get_by_text("old-alpha", exact=True).count() == 0

        _release(page, server, path_a, [{"name": "fresh-alpha"}])
        page.get_by_text("fresh-alpha", exact=True).wait_for(timeout=5000)
        _release(page, server, path_b, [{"name": "late-beta"}])
        assert page.get_by_text("late-beta", exact=True).count() == 0
        assert page.get_by_text("fresh-alpha", exact=True).count() == 1

        server.hold.remove(path_a)
        server.extra[("GET", path_a)] = (200, [{"name": "refreshed-alpha"}])
        page.get_by_role("button", name="Refresh", exact=True).click()
        page.get_by_text("refreshed-alpha", exact=True).wait_for(timeout=5000)
        assert not app.errors, app.errors
    finally:
        server.close()
        app.ctx.close()


@pytest.mark.parametrize("layout", ["modern", "corporate"])
def test_slow_datastore_read_survives_multiple_poll_intervals(browser, layout):
    """An in-flight read is neither overlapped nor discarded by the next poll."""
    path = "/api/pbs/p1/datastores"
    server = _DatastoreServer(layout)
    server.hold.add(path)
    app = _App(browser, server, clock=True)
    try:
        page = app.page
        _open(page, server)
        _tick(page, server)
        _tick(page, server)
        assert server.datastore_reads.count(path) == 1
        _release(page, server, path, [{"name": "slow-alpha"}])
        page.get_by_text("slow-alpha", exact=True).wait_for(timeout=5000)

        server.hold.remove(path)
        server.extra[("GET", path)] = (200, [{"name": "next-alpha"}])
        _tick(page, server)
        page.get_by_text("next-alpha", exact=True).wait_for(timeout=5000)
        assert not app.errors, app.errors
    finally:
        server.close()
        app.ctx.close()


def test_unmount_with_a_pending_datastore_read_is_safe(browser):
    """A late read cannot recreate a dashboard after its React root unmounts."""
    path = "/api/pbs/p1/datastores"
    server = _DatastoreServer()
    server.hold.add(path)
    app = _App(browser, server)
    try:
        page = app.page
        _open(page, server)
        assert page.evaluate("ReactDOM.unmountComponentAtNode(document.getElementById('root'))")
        _release(page, server, path, [{"name": "after-unmount"}])
        page.wait_for_timeout(100)
        assert page.locator("#root").inner_html() == ""
        assert not app.errors, app.errors
    finally:
        server.close()
        app.ctx.close()
