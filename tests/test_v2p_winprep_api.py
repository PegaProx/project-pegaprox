"""The Windows preparation of an ESXi migration over the API (MK Nov 2026).

POST /api/vmware/<id>/vms/<vm_id>/migrate and the bulk route take the fields of the preparation
(install_virtio_drivers, two_stage_boot, guest_prep with guest_user / guest_password), the dry
run answers what will happen (windows_prep, two_stage, the virtio-win.iso download in the node
package plan), the script of the manual run is GET /api/vmware/guest-prep-script and a Windows
login is checked with POST .../guest-login. The login is never stored, logged or returned.
"""
import time
import types

import pytest

import pegaprox.core.v2p as v2p
from pegaprox.core import esxi_bulk as ebulk, v2p_guestprep
from test_esxi_mapping_verify import route  # noqa: F401 (fixture)
from test_esxi_bulk import env  # noqa: F401 (fixture)
from test_v2p_node_packages_1252 import probe, EVERY  # noqa: F401 (fixture)

PW = 'Gu3st-Pa55&"x'


def _windows(esxi):
    real = esxi.get_vm

    def get_vm(vm_id):
        d = real(vm_id)
        if 'data' in d:
            d['data']['guest_OS'] = 'Microsoft Windows Server 2019 (64-bit)'
            d['data']['guest_id'] = 'windows2019srv_64Guest'
        return d
    esxi.get_vm = get_vm


@pytest.fixture(autouse=True)
def fresh_login_limit(monkeypatch):
    # the limiters are process-wide, every test starts with its own
    import pegaprox.utils.ssh as ssh
    import pegaprox.api.vmware as vmware_api
    monkeypatch.setattr(ssh, '_auth_action_windows', {})
    vmware_api._guest_login_callers.reset()
    vmware_api._guest_login_guests.reset()


@pytest.fixture
def audits(route, monkeypatch):
    got = []
    monkeypatch.setattr(route.module, 'log_audit', lambda *a, **k: got.append(' '.join(str(x) for x in a)))
    return got


# --------------------------------------------------------------------------- the door

@pytest.mark.parametrize('extra,word', [
    ({'guest_prep': 'yes'}, 'guest_prep must be true or false'),
    ({'two_stage_boot': 'on'}, 'two_stage_boot must be true, false or null'),
    ({'guest_user': 'adm\nin'}, 'guest_user'),
    ({'guest_user': 'a' * 257}, 'guest_user'),
    ({'guest_password': 'x' * 1025}, 'guest_password'),
    ({'guest_password': 'a\x00b'}, 'guest_password'),
    ({'two_stage_boot': True, 'transfer_mode': 'sshfs_boot'}, 'Live Mirror'),
    ({'two_stage_boot': True, 'disk_bus': 'sata'}, 'SATA'),
    ({'two_stage_boot': True, 'scsihw': 'pvscsi'}, 'pvscsi'),
    ({'two_stage_boot': True, 'agent': False}, 'guest agent'),
    ({'two_stage_boot': True, 'install_virtio_drivers': False}, 'drivers'),
    ({'virtio_iso_path': 'relative/virtio.iso'}, 'virtio_iso_path'),
])
def test_the_windows_fields_are_checked_at_the_door(route, extra, word):
    for dry in (True, False):
        r = route.post(dry_run=dry, **extra)
        assert r.status_code == 400, r.get_data(as_text=True)
        assert word in r.get_json()['error']
    time.sleep(0.05)
    assert route.started == []


def test_the_login_is_needed_for_a_start_with_guest_prep_but_not_for_its_dry_run(route, probe, monkeypatch):
    monkeypatch.setattr(v2p, '_node_cannot_reach', lambda *a, **k: '')
    r = route.post(guest_prep=True, guest_user='Administrator')
    assert r.status_code == 400 and 'guest_user and guest_password are required' in r.get_json()['error']
    assert route.post(guest_prep=True, dry_run=True, esxi_password=None).status_code == 200


# --------------------------------------------------------------------------- the dry run

def test_the_dry_run_of_a_windows_guest_says_what_the_preparation_does(route, probe):
    _windows(route.esxi)
    probe.have = set(EVERY) - {'virtio-win.iso'}
    p = route.post(dry_run=True, esxi_password=None).get_json()
    assert p['ok'] is True, p['errors']
    wp = p['windows_prep']
    assert wp['windows'] is True and wp['offline'] is True and wp['guest_prep'] is False
    assert wp['scsihw'] == 'virtio-scsi-single' and wp['net_driver'] == 'virtio' and wp['iso'] == 'missing'
    assert p['two_stage']['on'] is True and p['two_stage']['first_bus'] == 'sata' and p['two_stage']['temp_disk'] is False
    pk = {it['package']: it for it in p['node_packages']['items']}
    assert {'python3-hivex', 'ntfs-3g', 'virtio-win.iso'} <= set(pk) and pk['virtio-win.iso']['needed'] is False
    assert any('downloads it from fedorapeople.org' in w for w in p['warnings'])


def test_a_dry_run_that_may_not_install_says_the_guest_keeps_the_source_controller(route, probe):
    _windows(route.esxi)
    probe.have = set(EVERY) - {'virtio-win.iso'}
    p = route.post(dry_run=True, esxi_password=None, allow_package_install=False).get_json()
    assert p['ok'] is True, 'a missing ISO never stops a run'
    assert any('may not download it' in w and 'disk controller and NICs of the source' in w for w in p['warnings'])


def test_the_dry_run_of_a_linux_guest_has_no_preparation(route, probe):
    p = route.post(dry_run=True, esxi_password=None).get_json()
    assert p['windows_prep']['windows'] is False and p['windows_prep']['on'] is False
    assert p['two_stage']['on'] is False
    assert {it['package'] for it in p['node_packages']['items']} == {'sshfs', 'sshpass'}


def test_the_dry_run_of_a_linux_guest_with_guest_prep_says_it_once_and_checks_nothing(route, probe, monkeypatch):
    # a lab bulk check of a Debian guest next to a Windows one warned "will fall back to the
    # offline preparation: the source VM is not running" next to "does not look like Windows"
    route.esxi.guest_state = lambda vm_id: {'data': {'power_state': 'POWERED_OFF', 'tools_running': False,
                                                     'ops_ready': False, 'family': 'linuxGuest',
                                                     'full_name': 'Debian GNU/Linux 12', 'soap': True}}
    asked = []
    monkeypatch.setattr(v2p, '_node_cannot_reach', lambda *a, **k: asked.append(a) or 'no answer within 5s')
    p = route.post(dry_run=True, esxi_password=None, guest_prep=True).get_json()
    assert p['ok'] is True, p['errors']
    assert 'guest_prep' not in p and asked == []
    assert not any('fall back to the offline preparation' in w for w in p['warnings']), p['warnings']
    assert [w for w in p['warnings'] if 'Windows' in w] == ['The guest does not look like Windows: the Windows '
                                                             'preparation does not run']


def test_an_explicit_two_stage_boot_for_a_guest_that_is_no_windows_is_an_error_of_the_plan(route, probe):
    p = route.post(dry_run=True, esxi_password=None, two_stage_boot=True).get_json()
    assert p['ok'] is False and any('two_stage_boot: not a Windows guest' in e for e in p['errors'])


def test_the_dry_run_of_the_in_guest_preparation_warns_and_never_blocks(route, probe, monkeypatch):
    _windows(route.esxi)
    route.esxi.guest_state = lambda vm_id: {'data': {'power_state': 'POWERED_ON', 'tools_running': False, 'ops_ready': False,
                                                     'family': 'windowsGuest', 'full_name': 'Windows', 'soap': True}}
    monkeypatch.setattr(v2p, '_node_cannot_reach', lambda *a, **k: 'no answer within 5s')
    p = route.post(dry_run=True, esxi_password=None, guest_prep=True).get_json()
    assert p['ok'] is True, p['errors']
    assert p['guest_prep']['tools_running'] is False and p['guest_prep']['reaches_esxi_443'] is False
    assert any('fall back to the offline preparation' in w and 'not running' in w for w in p['warnings'])
    assert any('cannot reach esx1.lab on port 443' in w for w in p['warnings'])
    assert 'curl' in {it['package'] for it in p['node_packages']['items']}


# --------------------------------------------------------------------------- the start

def test_a_start_hands_the_login_to_the_task_only_and_the_audit_names_the_preparation(route, audits):
    _windows(route.esxi)
    r = route.post(guest_prep=True, guest_user='CORP\\admin', guest_password=PW)
    assert r.status_code == 202, r.get_data(as_text=True)
    body = r.get_data(as_text=True)
    assert PW not in body and 'CORP' not in body
    task = route.wait_started()[0]
    assert task._guest_password == PW and task.guest_user == 'CORP\\admin' and task.guest_prep is True
    assert 'guest_password' not in task.config and 'guest_user' not in task.config
    line = [a for a in audits if 'vmware.migration.started' in a][0]
    assert ', Windows prepared automatically, guest preparation, two-stage boot' in line
    assert PW not in line and 'CORP' not in line


def test_a_start_with_the_preparation_off_says_so_in_nothing(route, audits):
    _windows(route.esxi)
    assert route.post(install_virtio_drivers=False).status_code == 202
    line = [a for a in audits if 'vmware.migration.started' in a][0]
    assert 'Windows prepared' not in line and 'two-stage' not in line


# --------------------------------------------------------------------------- the routes

def test_the_script_route_hands_out_the_bytes_the_guest_gets(route, seed):
    r = route.admin.get('/api/vmware/guest-prep-script')
    assert r.status_code == 200 and r.data == v2p_guestprep.script_bytes()
    assert r.headers['Content-Type'] == 'text/plain; charset=us-ascii'
    assert r.headers['Content-Disposition'] == 'attachment; filename="Prepare-KvmMigration.ps1"'
    assert r.headers['Cache-Control'] == 'no-store'


def test_the_script_route_needs_the_migrate_permission(route, api, seed):
    assert api.anon().get('/api/vmware/guest-prep-script').status_code == 401
    viewer = api.as_user(seed.user('vicky', role='viewer'))
    assert viewer.get('/api/vmware/guest-prep-script').status_code == 403


class _Sess:
    calls = []
    refuse = False

    def __init__(self, mgr, vm_id, user, password):
        _Sess.calls.append((vm_id, user, password))

    def validate(self):
        if _Sess.refuse:
            from pegaprox.core.esxi_guestops import GuestOpsError
            raise GuestOpsError('login', 'the guest refused the Windows login')

    def close(self):
        pass


def test_the_login_check_tries_once_per_call_and_at_most_five_times(route, monkeypatch):
    import pegaprox.core.esxi_guestops as go
    _Sess.calls, _Sess.refuse = [], True
    monkeypatch.setattr(go, 'GuestSession', _Sess)
    route.esxi.guest_state = lambda vm_id: {'data': {'power_state': 'POWERED_ON', 'tools_running': True, 'ops_ready': True,
                                                     'family': 'windowsGuest', 'full_name': 'Windows', 'soap': True}}
    body = {'guest_user': 'Administrator', 'guest_password': PW}
    for n in range(5):
        r = route.admin.post('/api/vmware/vw1/vms/vm-42/guest-login', json=body)
        assert r.status_code == 200
        d = r.get_json()
        assert d == {'ok': False, 'tools_running': True, 'windows': True, 'error': 'the guest refused the Windows login'}
        assert PW not in r.get_data(as_text=True)
    assert len(_Sess.calls) == 5
    r = route.admin.post('/api/vmware/vw1/vms/vm-42/guest-login', json=body)
    assert r.status_code == 429 and len(_Sess.calls) == 5


def test_the_login_check_says_ok_and_what_keeps_it_from_trying(route, monkeypatch):
    import pegaprox.core.esxi_guestops as go
    _Sess.calls, _Sess.refuse = [], False
    monkeypatch.setattr(go, 'GuestSession', _Sess)
    route.esxi.guest_state = lambda vm_id: {'data': {'power_state': 'POWERED_ON', 'tools_running': True, 'ops_ready': True,
                                                     'family': 'windowsGuest', 'full_name': 'Windows', 'soap': True}}
    assert route.admin.post('/api/vmware/vw1/vms/vm-42/guest-login',
                            json={'guest_user': 'Administrator', 'guest_password': PW}).get_json()['ok'] is True
    route.esxi.guest_state = lambda vm_id: {'data': {'power_state': 'POWERED_ON', 'tools_running': False, 'ops_ready': False,
                                                     'family': 'windowsGuest', 'full_name': 'Windows', 'soap': True}}
    d = route.admin.post('/api/vmware/vw1/vms/vm-42/guest-login',
                         json={'guest_user': 'Administrator', 'guest_password': PW}).get_json()
    assert d['ok'] is False and 'not running' in d['error'] and len(_Sess.calls) == 1
    assert route.admin.post('/api/vmware/vw1/vms/vm-42/guest-login', json={'guest_user': 'x'}).status_code == 400


def _windows_guest(vm_id):
    return {'data': {'power_state': 'POWERED_ON', 'tools_running': True, 'ops_ready': True,
                     'family': 'windowsGuest', 'full_name': 'Windows', 'soap': True}}


def test_made_up_guests_never_reach_the_auth_windows_and_a_caller_stops_at_fifteen(route, monkeypatch):
    # the password change window of the same size, exhausted: the login check must not be a way
    # to push it out (4096 fresh keys used to evict it) nor count in it
    import pegaprox.utils.ssh as ssh
    import pegaprox.api.vmware as vmware_api
    import pegaprox.core.esxi_guestops as go
    _Sess.calls, _Sess.refuse = [], True
    monkeypatch.setattr(go, 'GuestSession', _Sess)
    for _ in range(5):
        ssh.check_auth_action_rate_limit('pwd_change:admin', max_attempts=5, window=300)
    assert ssh.check_auth_action_rate_limit('pwd_change:admin', max_attempts=5, window=300) is False
    route.esxi.guest_state = lambda vm_id: {'error': f'no VM {vm_id}'}
    body = {'guest_user': 'x', 'guest_password': 'x'}
    codes = [route.admin.post(f'/api/vmware/vw1/vms/junk-{n}/guest-login', json=body).status_code for n in range(40)]
    assert codes == [200] * 15 + [429] * 25
    assert ssh.check_auth_action_rate_limit('pwd_change:admin', max_attempts=5, window=300) is False
    keys = [k for w in ssh._auth_action_windows.values() for k in w._hits]
    assert not [k for k in keys if 'guest_login' in k], keys
    # a guest ESXi does not know never gets a window of its own, and no login was tried
    assert len(vmware_api._guest_login_guests) == 0 and _Sess.calls == []


def test_a_caller_tries_at_most_fifteen_logins_over_all_guests(route, monkeypatch):
    import pegaprox.core.esxi_guestops as go
    _Sess.calls, _Sess.refuse = [], True
    monkeypatch.setattr(go, 'GuestSession', _Sess)
    route.esxi.guest_state = _windows_guest
    body = {'guest_user': 'CORP\\admin', 'guest_password': PW}
    codes = [route.admin.post(f'/api/vmware/vw1/vms/vm-{n}/guest-login', json=body).status_code for n in range(16)]
    assert codes == [200] * 15 + [429] and len(_Sess.calls) == 15


def test_only_a_guest_esxi_knows_counts_against_that_guest(route, monkeypatch):
    import pegaprox.core.esxi_guestops as go
    _Sess.calls, _Sess.refuse = [], True
    monkeypatch.setattr(go, 'GuestSession', _Sess)
    body = {'guest_user': 'Administrator', 'guest_password': PW}
    route.esxi.guest_state = lambda vm_id: {'error': 'not reachable'}
    for _ in range(5):
        assert route.admin.post('/api/vmware/vw1/vms/vm-42/guest-login', json=body).status_code == 200
    route.esxi.guest_state = _windows_guest
    codes = [route.admin.post('/api/vmware/vw1/vms/vm-42/guest-login', json=body).status_code for _ in range(6)]
    assert codes == [200] * 5 + [429] and len(_Sess.calls) == 5
    r = route.admin.post('/api/vmware/vw1/vms/vm-42/guest-login', json=body)
    assert 'for this guest' in r.get_json()['error']


# --------------------------------------------------------------------------- bulk

def _wait(env, n):
    deadline = time.time() + 5
    while time.time() < deadline and len(env.runner.names()) < n:
        env.runner.end_all() if len(env.runner.names()) else None
        time.sleep(0.02)
    return env.runner.names()


def test_the_bulk_route_takes_the_windows_settings_and_refuses_unknown_keys(env, probe):
    r = env.post(dry_run=True, esxi_password=None, guest_prep=True, two_stage_boot=None, install_virtio_drivers=True,
                 virtio_iso_path='/var/lib/vz/template/iso/virtio-win.iso', guest_user='Administrator')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert all('windows_prep' in it and 'two_stage' in it for it in r.get_json()['items'])
    assert env.post(dry_run=True, esxi_password=None, guest_flavour=1).status_code == 400
    assert env.post(dry_run=True, esxi_password=None, guest_prep='yes').status_code == 400


def test_a_guest_of_a_bulk_run_may_bring_its_own_login_both_parts_or_none(env, probe):
    r = env.post(dry_run=True, esxi_password=None, vms=[{'vm_id': 'vm-1', 'guest_user': 'a'}, 'vm-2'])
    assert r.status_code == 400 and 'together' in r.get_json()['error']
    r = env.post(dry_run=True, esxi_password=None, vms=[{'vm_id': 'vm-1', 'guest_user': 'a', 'guest_password': 'b'}, 'vm-2'])
    assert r.status_code == 200, r.get_data(as_text=True)


def test_a_bulk_start_with_guest_prep_needs_a_login_for_every_guest(env, probe):
    r = env.post(guest_prep=True, vms=[{'vm_id': 'vm-1', 'guest_user': 'a', 'guest_password': 'b'}, 'vm-2'])
    assert r.status_code == 400 and 'vm-2' in r.get_json()['error'] and 'vm-1' not in r.get_json()['error']


def test_each_guest_gets_its_own_login_or_the_runs_and_none_of_it_shows(env, probe):
    r = env.post(guest_prep=True, guest_user='RUN\\admin', guest_password=PW, width=2,
                 vms=[{'vm_id': 'vm-1', 'guest_user': 'own', 'guest_password': 'own-pw'}, 'vm-2'])
    assert r.status_code == 202, r.get_data(as_text=True)
    run_view = r.get_data(as_text=True)
    assert PW not in run_view and 'own-pw' not in run_view and 'RUN\\\\admin' not in run_view
    names = _wait(env, 2)
    assert sorted(names) == ['db01', 'web01']
    web, db = env.runner.task('web01'), env.runner.task('db01')
    assert (web.guest_user, web._guest_password) == ('own', 'own-pw')
    assert (db.guest_user, db._guest_password) == ('RUN\\admin', PW)
    run = ebulk.runs()[0]
    assert 'guest_password' not in run.settings and 'guest_user' not in run.settings
    for it in run.items_copy():
        assert '_guest_login' not in it
    # every guest started: the run drops the logins with the password
    deadline = time.time() + 5
    while time.time() < deadline and run._guest_login is not None:
        time.sleep(0.02)
    assert run._guest_login is None and all(it['_guest_login'] is None for it in run.items)
    assert env.admin.get(f'/api/vmware/bulk-migrate/{run.id}').get_json()['run']['holds_guest_login'] is False


def test_a_cancelled_or_abandoned_run_drops_the_logins(env):
    items = [ebulk.new_item('vm-1', 'web01', {}, {'guest_user': 'u', 'guest_password': 'p'})]
    run = ebulk.EsxiBulkRun('vw1', 'esx01', 'root', {}, '127.0.0.1', {'guest_prep': True, 'guest_password': 'x',
                                                                         'guest_user': 'y'}, 1, items, 'esxi-pw',
                            guest_login={'guest_user': 'RUN', 'guest_password': PW})
    assert run.settings == {'guest_prep': True}
    assert run.guest_login(items[0]) == {'guest_user': 'u', 'guest_password': 'p'}
    ebulk.register(run)
    ebulk.cancel(run, 'root')
    assert run._guest_login is None and items[0]['_guest_login'] is None and run.guest_login(items[0]) is None
    items2 = [ebulk.new_item('vm-3', 'app01', {}, None)]
    run2 = ebulk.EsxiBulkRun('vw1', 'esx01', 'root', {}, '127.0.0.1', {}, 1, items2, 'esxi-pw',
                             guest_login={'guest_user': 'RUN', 'guest_password': PW})
    ebulk.register(run2)
    ebulk.abandon(run2, 'test')
    assert run2._guest_login is None
