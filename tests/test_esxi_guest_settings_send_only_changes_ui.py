"""The settings tab of an ESXi guest saves what the user changed and nothing else.

The form started at empty notes and both hot-add switches off, whatever the guest had, and
a save sent all of it. Over SOAP (the usual connection of a standalone ESXi host) a CPU
change therefore wrote an empty annotation and switched hot-add off: the notes the tab
showed were gone. A save without any edit sent the same, so "No changes" never showed, and
what was typed for one guest stayed in the form and went out with the save of the next.

Now the tab shows what the guest has (the switches as well) under the user's changes, a
save sends only the fields that differ from the guest, nothing at all when none does, and
another guest starts with a clean form.

Drives the bundle in headless Chromium against the fake server of the pixel guard; skips
where Playwright is not installed. LW Nov 2026
"""
import pytest

from test_corp_redesigned_guard_ui import _GuardApp, _GuardServer, browser  # noqa: F401

ESXI = {'id': 'v1', 'name': 'esx01', 'host': '10.0.0.9', 'port': 443, 'server_type': 'esxi',
        'connected': True, 'status': 'connected', 'enabled': True}


def _guest(vm, name, cpu, mem, notes, cpu_hot, mem_hot):
    return {'vm': vm, 'name': name, 'power_state': 'POWERED_OFF', 'guest_OS': 'Ubuntu Linux (64-bit)',
            'cpu': {'count': cpu, 'sockets': 1, 'cores_per_socket': cpu, 'hot_add_enabled': cpu_hot},
            'memory': {'size_MiB': mem, 'hot_add_enabled': mem_hot}, 'notes': notes,
            'hardware': {'version': 'vmx-19'}, 'disks': {}, 'nics': []}


APP = _guest('vm-1', 'app01', 2, 4096, 'owner: ops, do not reboot', True, False)
DB = _guest('vm-2', 'db01', 4, 8192, 'nightly dump at 2', False, True)
ROW = {'vm-1': {'vm': 'vm-1', 'name': 'app01', 'power_state': 'POWERED_OFF', 'cpu_count': 2,
                'memory_size_MiB': 4096},
       'vm-2': {'vm': 'vm-2', 'name': 'db01', 'power_state': 'POWERED_OFF', 'cpu_count': 4,
                'memory_size_MiB': 8192}}


def _reads():
    reads = {('GET', '/api/vmware'): (200, [ESXI]), ('GET', '/api/pbs'): (200, []),
             ('GET', '/api/vmware/v1/vms'): (200, list(ROW.values()))}
    for what in ('hosts', 'datastores', 'networks', 'clusters'):
        reads[('GET', f'/api/vmware/v1/{what}')] = (200, [])
    for guest in (APP, DB):
        vm = guest['vm']
        reads[('GET', f'/api/vmware/v1/vms/{vm}')] = (200, {'data': guest})
        reads[('POST', f'/api/vmware/v1/vms/{vm}/watch')] = (200, {'success': True})
        reads[('DELETE', f'/api/vmware/v1/vms/{vm}/watch')] = (200, {'success': True})
        reads[('PUT', f'/api/vmware/v1/vms/{vm}/config')] = (200, {'message': 'VM configuration updated'})
    return reads


@pytest.fixture
def app(browser):
    a = _GuardApp(browser, _GuardServer(extra=_reads(), layout='modern'))
    yield a
    a.close()


def _open_settings(app, name):
    page = app.page
    page.get_by_text('esx01').first.click()
    page.get_by_text(name).first.wait_for(timeout=8000)
    page.get_by_text(name).first.click()
    page.get_by_text('Back to VM List').first.wait_for(timeout=8000)
    page.locator('button:text-is("Settings")').last.click()
    page.get_by_role('button', name='Save Changes').wait_for(timeout=5000)
    page.wait_for_timeout(300)
    return page


def _switch(page, label):
    return page.locator('label', has_text=label).locator('div').first


def _on(page, label):
    return 'bg-emerald-500' in (_switch(page, label).get_attribute('class') or '')


def _notes(page):
    return page.locator('textarea[placeholder="VM description / notes..."]')


def _saved(app, vm):
    return app.server.bodies.get(f'/api/vmware/v1/vms/{vm}/config', [])


def _save(app, vm):
    n = len(_saved(app, vm))
    app.page.get_by_role('button', name='Save Changes').click()
    for _ in range(30):
        if len(_saved(app, vm)) > n:
            break
        app.page.wait_for_timeout(100)
    return _saved(app, vm)[n:]


def test_runtime_the_tab_shows_what_the_guest_has(app):
    page = _open_settings(app, 'app01')
    assert _notes(page).input_value() == APP['notes']
    assert _on(page, 'CPU Hot-Add') is True, 'the guest has CPU hot-add on, the switch says off'
    assert _on(page, 'Memory Hot-Add') is False
    assert not app.errors, app.errors


def test_runtime_a_cpu_change_sends_the_cpu_and_nothing_else(app):
    page = _open_settings(app, 'app01')
    page.locator('input[type="number"][max="128"]').fill('4')
    assert _save(app, 'vm-1') == [{'cpu_count': 4}]
    assert not app.errors, app.errors


def test_runtime_the_notes_and_a_switch_go_out_on_their_own(app):
    page = _open_settings(app, 'app01')
    _notes(page).fill('')
    assert _notes(page).input_value() == '', 'cleared notes came back from the guest'
    _notes(page).fill('owner: ops')
    _switch(page, 'Memory Hot-Add').click()
    # switched there and back is no change
    _switch(page, 'CPU Hot-Add').click()
    _switch(page, 'CPU Hot-Add').click()
    assert _save(app, 'vm-1') == [{'notes': 'owner: ops', 'memory_hot_add': True}]


def test_runtime_a_save_without_an_edit_sends_nothing(app):
    page = _open_settings(app, 'app01')
    page.get_by_role('button', name='Save Changes').click()
    page.wait_for_timeout(1200)
    assert _saved(app, 'vm-1') == []
    assert page.get_by_text('No changes').count() > 0


def test_runtime_what_was_typed_for_one_guest_is_not_saved_on_the_next(app):
    page = _open_settings(app, 'app01')
    page.locator('input[type="number"][max="128"]').fill('8')
    _notes(page).fill('typed for app01')
    page.get_by_text('Back to VM List').first.click()
    page.get_by_text('db01').first.click()
    page.get_by_text('Back to VM List').first.wait_for(timeout=8000)
    page.locator('button:text-is("Settings")').last.click()
    page.get_by_role('button', name='Save Changes').wait_for(timeout=5000)
    page.wait_for_timeout(500)
    assert _notes(page).input_value() == DB['notes']
    assert page.locator('input[type="number"][max="128"]').input_value() == '4'
    assert _on(page, 'Memory Hot-Add') is True and _on(page, 'CPU Hot-Add') is False
    page.get_by_role('button', name='Save Changes').click()
    page.wait_for_timeout(1200)
    assert _saved(app, 'vm-2') == [] and _saved(app, 'vm-1') == []
