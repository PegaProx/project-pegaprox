"""Emptying an optional field of a backup job clears it on PVE. PVE keeps whatever a PUT does
not name, and takes a delete list for the rest, so "All Nodes" stayed on the old node."""
import re
from unittest.mock import MagicMock

import pytest

from test_ha_ui import CLUSTER, NODE_METRICS, SSE_TOKEN, VM, browser, _App, _FakeServer  # noqa: F401

CID = 'cluster_1'
URL = f'/api/clusters/{CID}/datacenter/backup/job-1'


def _manager(api):
    m = api.make_fake_manager(CID)
    m.is_connected = True
    m.host, m.api_port = 'pve', 8006
    m.config.name = CID
    put = m._create_session.return_value.put
    put.return_value = MagicMock(status_code=200, text='{}')
    api.set_manager(CID, m)
    return put


@pytest.mark.parametrize('body, sent', [
    ({'storage': 's1', 'node': '', 'mailto': 'a@example.org'},
     {'storage': 's1', 'mailto': 'a@example.org', 'delete': 'node'}),
    ({'storage': 's1', 'node': None, 'mailto': ''}, {'storage': 's1', 'delete': 'node,mailto'}),
    ({'storage': 's1', 'comment': '', 'delete': 'notes-template'}, {'storage': 's1', 'delete': 'notes-template,comment'}),
    ({'storage': 's1', 'mailto': 'a@example.org'}, {'storage': 's1', 'mailto': 'a@example.org'}),
    # these are not a request to remove anything
    ({'storage': '', 'schedule': '', 'vmid': '100'}, {'vmid': '100'}),
    ({'storage': 's1', 'vmid': '', 'all': 1}, {'storage': 's1', 'all': 1}),
    ({'storage': 's1', 'enabled': 0}, {'storage': 's1', 'enabled': 0}),
])
def test_what_reaches_pve(api, seed, body, sent):
    put = _manager(api)
    r = api.as_user(seed.user('adm', role='admin')).put(URL, json=body)
    assert r.status_code == 200
    got, want = dict(put.call_args.kwargs['data']), dict(sent)
    assert set(got.pop('delete', '').split(',')) == set(want.pop('delete', '').split(','))
    assert got == want


def test_a_scoped_caller_cannot_empty_the_guest_list_into_a_delete(api, seed):
    put = _manager(api)
    seed.tenant('acme', [CID])
    user = seed.user('scoped', role='viewer', tenant_id='acme', permissions=['backup.create', 'backup.schedule'])
    r = api.as_user(user).put(URL, json={'storage': 's1', 'vmid': ''})
    assert r.status_code == 403
    put.assert_not_called()


JOB = {'id': 'job-1', 'type': 'vzdump', 'storage': 's1', 'schedule': '02:00', 'node': 'n1', 'mailto': 'a@example.org',
       'vmid': '100', 'enabled': 1, 'mode': 'snapshot'}
BASE = '/api/clusters/c1/datacenter/backup'


def test_runtime_all_nodes_and_an_emptied_email_reach_the_route(browser):  # noqa: F811
    app = _App(browser, _FakeServer(role='standalone', layout='modern', clusters=[CLUSTER], resources=[VM],
                                    metrics=NODE_METRICS, extra={
        **SSE_TOKEN, ('GET', BASE): (200, [JOB]), ('GET', BASE + '/last-runs'): (200, {'jobs': {}}),
        ('PUT', BASE + '/job-1'): (200, {'success': True})}))
    page = app.page
    try:
        page.get_by_text('Testi').first.click()
        page.locator('button', has_text='Datacenter').first.click()
        page.locator('button', has_text=re.compile(r'^\s*Backup\s*$')).first.click()
        page.locator('button[title="Edit"]').first.click()
        dialog = page.locator('.max-w-2xl', has_text='Edit Backup Job')
        dialog.locator('select', has=page.locator('option', has_text='All Nodes')).select_option('')
        dialog.locator('input[value="a@example.org"]').fill('')
        dialog.locator('button').last.click()
        page.wait_for_timeout(500)
        assert ('PUT', BASE + '/job-1') in app.server.calls
        body = app.server.bodies[BASE + '/job-1'][-1]
        assert body['node'] == '' and body['mailto'] == ''
        assert body['vmid'] == '100'
        assert not app.errors, app.errors
    finally:
        app.ctx.close()
