# An update, a rollback or the restart button restarted PegaProx three seconds after the
# files were in place, whatever ran. An ESXi migration lives in this process only: the
# restart ended it, with the source VM possibly stopped and the target half copied, and a bulk
# run lost every guest it had not started yet. These routes now answer 409 and name what runs;
# a caller that asks again with while_migrating goes ahead.

import types

import pytest

import pegaprox.api.settings as settings
import pegaprox.api.vmware as vmware_api
from pegaprox.core import esxi_bulk


@pytest.fixture(autouse=True)
def quiet(monkeypatch):
    """Registries of their own: other tests of the worker leave migrations and runs behind."""
    monkeypatch.setattr(vmware_api, '_vmware_migrations', {})
    monkeypatch.setattr(esxi_bulk, 'runs', lambda: [])


@pytest.fixture
def running(monkeypatch):
    """One ESXi migration that runs and one that is done."""
    vmware_api._vmware_migrations.update({
        'aa11': types.SimpleNamespace(status='running', vm_name='app01', vm_id='5'),
        'bb22': types.SimpleNamespace(status='completed', vm_name='old', vm_id='6')})


@pytest.fixture
def no_restart(monkeypatch):
    """What the routes would start after the answer: nothing restarts in a test."""
    started = []
    monkeypatch.setattr(settings.threading, 'Thread',
                        lambda target=None, **k: types.SimpleNamespace(start=lambda: started.append(target)))
    return started


def test_only_the_running_ones_count(running):
    assert vmware_api.migrations_a_restart_would_end() == ['app01 (aa11)']


def test_a_bulk_run_with_guests_still_waiting_counts(monkeypatch):
    run = types.SimpleNamespace(id='r1', state='running',
                                items=[{'state': esxi_bulk.WAITING}, {'state': 'done'}])
    monkeypatch.setattr(esxi_bulk, 'runs', lambda: [run])
    assert vmware_api.migrations_a_restart_would_end() == ['bulk run r1: 1 guest(s) not started yet']


@pytest.mark.parametrize('route,body', [
    ('/api/pegaprox/update', {}),
    ('/api/pegaprox/update/rollback', {'backup': 'pegaprox_backup_1.4.1'}),
    ('/api/settings/server/restart', None),
], ids=['update', 'rollback', 'restart'])
def test_a_restart_that_would_end_a_migration_is_refused(api, seed, running, no_restart, route, body):
    admin = api.as_user(seed.user('root', role='admin'))
    r = admin.post(route, json=body) if body is not None else admin.post(route)
    assert r.status_code == 409, r.get_data(as_text=True)
    j = r.get_json()
    assert j['migrations_running'] == ['app01 (aa11)']
    assert 'app01 (aa11)' in j['error'] and 'while_migrating' in j['error']
    assert no_restart == []


def test_the_restart_button_goes_ahead_when_asked_again(api, seed, running, no_restart):
    admin = api.as_user(seed.user('root', role='admin'))
    r = admin.post('/api/settings/server/restart', json={'while_migrating': True})
    assert r.status_code == 200, r.get_data(as_text=True)


def test_only_true_counts_as_asked_again(api, seed, running, no_restart):
    admin = api.as_user(seed.user('root', role='admin'))
    for value in ('true', 1, 'yes'):
        r = admin.post('/api/settings/server/restart', json={'while_migrating': value})
        assert r.status_code == 409, value


def test_listing_the_backups_is_no_rollback(api, seed, running, monkeypatch, tmp_path):
    monkeypatch.setattr(settings, 'CONFIG_DIR', str(tmp_path))
    admin = api.as_user(seed.user('root', role='admin'))
    r = admin.post('/api/pegaprox/update/rollback', json={})
    assert r.status_code != 409, r.get_data(as_text=True)


def test_nothing_running_restarts_as_before(api, seed, no_restart):
    admin = api.as_user(seed.user('root', role='admin'))
    r = admin.post('/api/settings/server/restart')
    assert r.status_code == 200, r.get_data(as_text=True)


def test_the_settings_dialog_asks_again_on_409():
    src = open(settings.__file__.replace('pegaprox/api/settings.py', 'web/src/settings_modal.js'),
               encoding='utf-8').read()
    helper = src[src.index('const postRestarting = async'):src.index('// Perform update')]
    assert 'r.status === 409' in helper and 'while_migrating: true' in helper
    assert "t('restartWhileMigrating')" in helper
    for url in ('/pegaprox/update`', '/pegaprox/update/rollback`', '/settings/server/restart`'):
        assert f'postRestarting(`${{API_URL}}{url}' in src, url
