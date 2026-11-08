"""The live backup pane tails the task log and stops once the task has ended.

It read the log as an array the route never sent and asked a status route that did not
exist, so it showed 'Waiting for output' and polled a 404 every 2 s for as long as it
stayed open.
"""
from urllib.parse import quote

import pytest

from test_ha_ui import CLUSTER, VM, SSE_TOKEN, _App, _FakeServer, browser  # noqa: F401

UPID = 'UPID:pve1:0000ABCD:00000001:68AB1F00:vzdump:100:root@pam:'
TASK = f'/api/clusters/c1/nodes/pve1/tasks/{quote(UPID, safe="")}'
LINES = ['INFO: starting new backup job: vzdump 100 --storage local',
         'INFO: Starting Backup of VM 100 (qemu)',
         'INFO: transferred 1.2 GiB in 3 seconds (409.6 MiB/s)',
         'INFO: Finished Backup of VM 100 (00:00:04)']


@pytest.fixture
def app(browser):
    extra = dict(SSE_TOKEN)
    extra.update({('GET', TASK + '/log'): (200, {'log': '\n'.join(LINES), 'lines': LINES}),
                  ('GET', TASK + '/status'): (200, {'status': 'stopped', 'exitstatus': 'OK'})})
    a = _App(browser, _FakeServer(clusters=[CLUSTER], resources=[VM], extra=extra, role='standalone',
                                  layout='modern'))
    yield a
    a.ctx.close()


def test_runtime_the_pane_shows_the_log_and_the_end(app):
    page = app.page
    page.get_by_text('Testi').first.click()
    page.evaluate("""u => window.dispatchEvent(new CustomEvent('pegaprox-show-backup-progress',
                                                             {detail: {upid: u, node: 'pve1'}}))""", UPID)
    page.get_by_text('Backup completed').wait_for(timeout=8000)
    assert page.get_by_text('Finished Backup of VM 100 (00:00:04)').count() == 1
    assert page.get_by_text('Starting Backup of VM 100 (qemu)').count() == 1
    # the throughput read from the log, in the head of the pane
    assert page.get_by_text('peak 409.6').count() == 1
    # the task has ended: nothing is asked any more
    asked = [u for u in app.server.urls if '/tasks/' in u]
    assert [u.split('?')[0].rsplit('/', 1)[1] for u in asked] == ['log', 'status']
    page.wait_for_timeout(4500)
    assert [u for u in app.server.urls if '/tasks/' in u] == asked
    assert not app.errors, app.errors
