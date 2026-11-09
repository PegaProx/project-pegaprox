"""What the clone dialog asks about Cloud-Init reaches the clone, or the user hears that it did not.

The dialog has the fields (#194) and the route applies them, but the one handler between them sent neither, so a clone never got
any of it. And the route ignored the answer: one refused value loses all of them in one request, under a 200.
"""
import types

import pytest

from test_ha_ui import CLUSTER, NODE_METRICS, SSE_TOKEN, VM, browser, _App, _FakeServer  # noqa: F401

PATH = '/api/clusters/c1/vms/pve1/qemu/100/clone'


def _route(api, seed, wait=True, status=200, error=None, xcp=False, text='ciuser: refused'):
    mgr = api.make_fake_manager(cluster_id='c1', cluster_type='xcpng' if xcp else 'proxmox',
                                clone_vm={'success': True, 'vmid': 200} if xcp else {'success': True, 'data': 'UPID:x'},
                                get_vm_resources=[{'vmid': 100, 'type': 'qemu', 'node': 'pve1', 'name': 'web'}])
    mgr.config = types.SimpleNamespace(name='c1')
    mgr.host = 'h'
    if xcp:
        del mgr.api_port        # an XCP-ng manager has none
    else:
        mgr.api_port = 8006
    mgr._wait_for_task = lambda *a, **k: wait
    sent = []

    def post(url, data=None, **kw):
        sent.append((url, data))
        if error:
            raise error
        return types.SimpleNamespace(status_code=status, text=text)
    mgr._api_post = post
    mgr.get_vm_config = lambda *a, **k: {'success': True, 'config': {}}
    api.set_manager('c1', mgr)
    return api.as_user(seed.user('adm', role='admin')), sent


def test_what_was_applied_says_nothing_extra(api, seed, db):
    c, sent = _route(api, seed)
    r = c.post(PATH, json={'newid': 200, 'name': 'x', 'ciuser': 'a'})
    assert r.status_code == 200 and 'cloudinit_warning' not in r.get_json(), r.get_json()
    assert sent[-1][1] == {'ciuser': 'a'}


def test_a_refused_config_is_a_warning_with_its_reason(api, seed, db):
    c, _ = _route(api, seed, status=400)
    r = c.post(PATH, json={'newid': 200, 'name': 'x', 'ciuser': 'a'})
    assert r.status_code == 200
    assert 'ciuser: refused' in r.get_json()['cloudinit_warning']


def test_a_clone_task_that_did_not_finish_is_a_warning_too(api, seed, db):
    c, sent = _route(api, seed, wait=False)
    r = c.post(PATH, json={'newid': 200, 'name': 'x', 'ciuser': 'a'})
    assert 'did not finish' in r.get_json()['cloudinit_warning']
    assert sent == []


def test_a_clone_without_cloud_init_is_as_it_was(api, seed, db):
    c, sent = _route(api, seed)
    r = c.post(PATH, json={'newid': 200, 'name': 'x'})
    assert r.status_code == 200 and 'cloudinit_warning' not in r.get_json()
    assert sent == []


def test_a_json_refusal_gives_its_reason_not_the_body(api, seed, db):
    c, _ = _route(api, seed, status=400, text='{"data":null,"errors":{"sshkeys":"invalid urlencoded string"}}')
    r = c.post(PATH, json={'newid': 200, 'name': 'x', 'ciuser': 'a'})
    warn = r.get_json()['cloudinit_warning']
    assert warn.endswith('sshkeys: invalid urlencoded string'), warn
    assert 'HTTP' not in warn and '{' not in warn, warn


def test_an_exception_does_not_name_its_host_to_the_caller(api, seed, db):
    c, _ = _route(api, seed, error=ConnectionError("HTTPSConnectionPool(host='10.9.8.7', port=8006): refused"))
    r = c.post(PATH, json={'newid': 200, 'name': 'x', 'ciuser': 'a'})
    warn = r.get_json()['cloudinit_warning']
    assert r.status_code == 200 and 'not applied' in warn
    assert '10.9.8.7' not in warn and '8006' not in warn, warn


def test_an_xcpng_clone_says_cloud_init_is_not_applied_there(api, seed, db):
    c, sent = _route(api, seed, xcp=True)
    r = c.post(PATH, json={'newid': 200, 'name': 'x', 'ciuser': 'a'})
    body = r.get_json()
    assert r.status_code == 200 and 'Proxmox clusters only' in body['cloudinit_warning'], body
    assert 'attribute' not in body['cloudinit_warning'] and sent == []


def _dialog(browser, answer):  # noqa: F811
    app = _App(browser, _FakeServer(role='standalone', layout='modern', clusters=[CLUSTER], resources=[VM], metrics=NODE_METRICS, extra={
        **SSE_TOKEN, ('POST', PATH): answer, ('GET', '/api/clusters/c1/nextid'): (200, {'vmid': 200})}))
    page = app.page
    page.get_by_text('Testi').first.click()
    page.locator('button', has_text='Resources').first.click()
    page.get_by_text('web01').first.wait_for(timeout=5000)
    page.wait_for_timeout(500)
    page.locator('button[title="More Actions"]').first.click()
    page.wait_for_timeout(300)
    page.locator('button', has_text='Clone').first.click()
    modal = page.locator('div.fixed', has_text='Target Node').last
    modal.wait_for(timeout=5000)
    modal.locator('button', has_text='Cloud-Init').first.click()
    modal.locator('input[placeholder="root"]').fill('ops')
    modal.locator('textarea[placeholder^="ssh-ed25519"]').fill('ssh-ed25519 AAAAC3Nz+a/b= ops@lab')
    modal.locator('input[placeholder="clone-name"]').fill('copy')
    page.wait_for_timeout(300)
    modal.locator('button', has_text='Clone').last.click()
    return app, page


def test_runtime_the_dialog_sends_what_was_filled_in(browser):  # noqa: F811
    app, page = _dialog(browser, (200, {'message': 'ok', 'newid': 200, 'data': 'UPID:x'}))
    try:
        page.wait_for_timeout(600)
        body = [b for b in app.server.bodies.get(PATH, []) if b][-1]
        # Proxmox refuses a space, + / = or a newline in sshkeys unless urlencoded
        assert body['ciuser'] == 'ops' and body['sshkeys'] == 'ssh-ed25519%20AAAAC3Nz%2Ba%2Fb%3D%20ops%40lab%0A', body
        assert 'cipassword' not in body and 'nameserver' not in body, body
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


def test_runtime_a_warning_from_the_route_is_shown_in_red(browser):  # noqa: F811
    app, page = _dialog(browser, (200, {'message': 'ok', 'newid': 200, 'data': 'UPID:x',
                                        'cloudinit_warning': 'its Cloud-Init settings were not applied: x'}))
    try:
        toast = page.locator('.toast-enter', has_text='not applied').first
        toast.wait_for(timeout=5000)
        assert 'text-red-400' in toast.get_attribute('class')
    finally:
        app.ctx.close()
