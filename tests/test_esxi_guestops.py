"""The guest operations of an ESXi host (core/esxi_guestops.py) and the ESXi client calls of the
Windows preparation (core/vmware.py guest_state, the tools installer).

MK Nov 2026 - the optional in-guest preparation runs programs and moves files in the running
source guest with a Windows login. SOAP only (the REST API has no guest operations), one login
attempt per check, the file transfer URLs aimed at the registered host and never anywhere else,
the login in no message. The SOAP objects are fakes, pyvmomi is not needed.
"""
import types

import pytest

from pegaprox.core import esxi_guestops as go
from pegaprox.core import ha_transport

SECRET = 'S3cr3t-Pw!'


def _fault(name):
    return type(name, (Exception,), {})


class Ops:
    def __init__(self, fail=None, url='https://*/guestFile?id=1&token=abc'):
        self.calls = []
        self.fail = fail or {}
        outer = self

        class _Mgr:
            def __init__(self, kind):
                self.kind = kind

            def __getattr__(self, name):
                def call(**kw):
                    outer.calls.append((name, kw))
                    if name in outer.fail:
                        raise outer.fail[name]
                    if name == 'InitiateFileTransferToGuest':
                        return url
                    if name == 'InitiateFileTransferFromGuest':
                        return types.SimpleNamespace(url=url)
                    if name == 'StartProgramInGuest':
                        return 4242
                    if name == 'ReadEnvironmentVariableInGuest':
                        return ['ProgramData=C:\\ProgramData', 'SystemRoot=C:\\Windows']
                    if name == 'ListProcessesInGuest':
                        return [types.SimpleNamespace(pid=4242, endTime='now', exitCode=0)]
                    if name == 'CreateTemporaryDirectoryInGuest':
                        return 'C:\\Users\\ADMINI~1\\AppData\\Local\\Temp\\pegaprox-1'
                    return None
                return call
        self.authManager, self.fileManager, self.processManager = _Mgr('auth'), _Mgr('file'), _Mgr('process')

    def names(self):
        return [c[0] for c in self.calls]


class Mgr:
    def __init__(self, ops, kind='soap', tools='guestToolsRunning', ready=True, host='esx1.lab'):
        self._connection_type = kind
        self.host, self.port, self.ssl_verify = host, 443, '/etc/ssl/esx.pem'
        self._soap_content = types.SimpleNamespace(guestOperationsManager=ops)
        self.vm = types.SimpleNamespace(guest=types.SimpleNamespace(toolsRunningStatus=tools, guestOperationsReady=ready))
        self.connected = True
        self.reconnects = 0

    def _soap_vm(self, vm_id):
        return self.vm, None

    def ensure_connected(self):
        self.reconnects += 1
        return True


@pytest.fixture(autouse=True)
def no_pyvmomi(monkeypatch):
    monkeypatch.setattr(go, '_auth', lambda u, p: ('auth', u, p))
    monkeypatch.setattr(go, '_program_spec', lambda prog, args, cwd: ('spec', prog, args, cwd))
    monkeypatch.setattr(go, '_file_attributes', lambda: 'attrs')


def _sess(ops=None, **kw):
    ops = ops or Ops()
    return go.GuestSession(Mgr(ops, **kw), 'vm-42', 'Administrator', SECRET), ops


def test_a_rest_connection_has_no_guest_operations():
    s, _ = _sess(kind='rest')
    with pytest.raises(go.GuestOpsError) as e:
        s.validate()
    assert e.value.kind == 'unavailable' and 'SOAP' in e.value.msg
    assert s.ready()[0] is False


@pytest.mark.parametrize('tools,ready,why', [('guestToolsNotRunning', True, 'not running'),
                                             ('guestToolsRunning', False, 'do not take guest operations')])
def test_ready_says_why_not(tools, ready, why):
    s, _ = _sess(tools=tools, ready=ready)
    ok, msg = s.ready()
    assert ok is False and why in msg


def test_validate_is_one_login_attempt_and_its_refusal_names_neither_account_nor_password():
    s, ops = _sess(Ops(fail={'ValidateCredentialsInGuest': _fault('InvalidGuestLogin')('denied')}))
    with pytest.raises(go.GuestOpsError) as e:
        s.validate()
    assert ops.names() == ['ValidateCredentialsInGuest']
    assert e.value.kind == 'login'
    assert SECRET not in e.value.msg and 'Administrator' not in e.value.msg


@pytest.mark.parametrize('fault,kind', [
    ('InvalidGuestLogin', 'login'), ('GuestAuthenticationChallenge', 'login'), ('GuestOperationsUnavailable', 'tools'),
    ('ToolsUnavailable', 'tools'), ('GuestComponentsOutOfDate', 'tools'), ('InvalidState', 'tools'),
    ('GuestPermissionDenied', 'permission'), ('OperationDisabledByGuest', 'unavailable'),
    ('FileNotFound', 'notfound'), ('SomethingElse', 'other'),
])
def test_the_faults_map_to_kinds(fault, kind):
    s, _ = _sess(Ops(fail={'StartProgramInGuest': _fault(fault)('x')}))
    with pytest.raises(go.GuestOpsError) as e:
        s.start('C:\\x.exe', '', 'C:\\')
    assert e.value.kind == kind
    assert SECRET not in str(e.value)


def test_an_expired_esxi_session_is_renewed_once():
    ops = Ops()
    seen = {'n': 0}
    real = ops.processManager.__getattr__('StartProgramInGuest')

    class Pm:
        def StartProgramInGuest(self, **kw):
            seen['n'] += 1
            if seen['n'] == 1:
                raise _fault('NotAuthenticated')('session gone')
            return real(**kw)
    ops.processManager = Pm()
    s = go.GuestSession(Mgr(ops), 'vm-42', 'Administrator', SECRET)
    assert s.start('C:\\x.exe', '', 'C:\\') == 4242
    assert seen['n'] == 2 and s.mgr.reconnects == 1


@pytest.mark.parametrize('url,host,want', [
    ('https://*/guestFile?id=1&token=a', 'esx1.lab', 'https://esx1.lab/guestFile?id=1&token=a'),
    ('https://*:443/guestFile?id=1', 'esx1.lab', 'https://esx1.lab:443/guestFile?id=1'),
    ('https://*/guestFile?id=1', 'fd00::5', 'https://[fd00::5]/guestFile?id=1'),
    ('https://ESX1.lab:8443/guestFile?id=1', 'esx1.lab', 'https://esx1.lab:8443/guestFile?id=1'),
])
def test_the_transfer_url_goes_to_the_registered_host(url, host, want):
    assert go.fix_transfer_url(url, host) == want


@pytest.mark.parametrize('url', ['https://evil.example/guestFile?id=1', 'http://*/guestFile?id=1', 'nonsense', ''])
def test_a_transfer_url_to_another_host_or_without_tls_is_refused(url):
    with pytest.raises(go.GuestOpsError):
        go.fix_transfer_url(url, 'esx1.lab')


class _Http:
    def __init__(self, status=200, body=b''):
        self.calls, self.status, self.body = [], status, body

    def __call__(self, method, url, **kw):
        self.calls.append((method, url, kw))
        body = self.body
        return types.SimpleNamespace(status_code=self.status, close=lambda: None,
                                     iter_content=lambda n: [body[i:i + n] for i in range(0, len(body), n)] or [b''])


def test_put_goes_through_the_guarded_transport_with_the_servers_tls_setting(monkeypatch):
    http = _Http()
    monkeypatch.setattr(ha_transport, 'http', http)
    s, ops = _sess()
    s.put('C:\\ProgramData\\KVMMigration\\go.flag', b'go')
    (method, url, kw), = http.calls
    assert method == 'PUT' and url == 'https://esx1.lab/guestFile?id=1&token=abc'
    assert kw['verify'] == '/etc/ssl/esx.pem' and kw['allow_redirects'] is False and kw['data'] == b'go'
    up = [c for c in ops.calls if c[0] == 'InitiateFileTransferToGuest'][0][1]
    assert up['overwrite'] is True and up['fileSize'] == 2


def test_a_put_the_guest_refuses_is_an_error(monkeypatch):
    monkeypatch.setattr(ha_transport, 'http', _Http(status=500))
    s, _ = _sess()
    with pytest.raises(go.GuestOpsError) as e:
        s.put('C:\\x', b'1')
    assert '500' in e.value.msg


def test_get_reads_at_most_the_cap_and_a_missing_file_is_none(monkeypatch):
    monkeypatch.setattr(ha_transport, 'http', _Http(body=b'x' * 200000))
    s, _ = _sess()
    assert len(s.get('C:\\big', 1000)) == 1000
    s, _ = _sess(Ops(fail={'InitiateFileTransferFromGuest': _fault('FileNotFound')('no')}))
    assert s.get('C:\\none', 10) is None


def test_after_close_nothing_more_runs_with_the_login():
    s, ops = _sess()
    s.close()
    with pytest.raises(go.GuestOpsError) as e:
        s.validate()
    assert e.value.kind == 'login' and ops.calls == []


def test_the_writes_of_the_guest_operations_ask_the_ha_guard_and_the_reads_do_not():
    for name in ('StartProgramInGuest', 'InitiateFileTransferToGuest', 'MakeDirectoryInGuest', 'DeleteDirectoryInGuest',
                 'CreateTemporaryDirectoryInGuest', 'MountToolsInstaller', 'UnmountToolsInstaller'):
        assert ha_transport.soap_action(name) == f'SOAP {name}'
    for name in ('ValidateCredentialsInGuest', 'InitiateFileTransferFromGuest', 'ListProcessesInGuest',
                 'ReadEnvironmentVariableInGuest'):
        assert ha_transport.soap_action(name) is None


# --------------------------------------------------------------------------- core/vmware.py

def _vmw(kind='soap'):
    from pegaprox.core.vmware import VMwareManager
    m = VMwareManager.__new__(VMwareManager)
    m._connection_type = kind
    calls = []
    vm = types.SimpleNamespace(
        runtime=types.SimpleNamespace(powerState='poweredOn', toolsInstallerMounted=False),
        guest=types.SimpleNamespace(toolsRunningStatus='guestToolsRunning', guestOperationsReady=True,
                                    guestFamily='windowsGuest', guestFullName='Microsoft Windows Server 2022'),
        MountToolsInstaller=lambda: calls.append('mount'), UnmountToolsInstaller=lambda: calls.append('unmount'))
    m._soap_vm = lambda vm_id: (vm, None) if kind == 'soap' else (None, 'only over SOAP')
    return m, calls


def test_guest_state_says_power_tools_and_whether_guest_operations_are_ready():
    m, _ = _vmw()
    assert m.guest_state('vm-1')['data'] == {'power_state': 'POWERED_ON', 'tools_running': True, 'ops_ready': True,
                                             'family': 'windowsGuest', 'full_name': 'Microsoft Windows Server 2022',
                                             'installer_mounted': False, 'soap': True}
    # whether the installer of the guest tools is in its drive: ESXi takes it out unused after 5 min
    m._soap_vm('vm-1')[0].runtime.toolsInstallerMounted = True
    assert m.guest_state('vm-1')['data']['installer_mounted'] is True


def test_the_tools_installer_is_mounted_and_unmounted_over_soap():
    m, calls = _vmw()
    assert m.mount_tools_installer('vm-1') == {'data': 'ok'} and m.unmount_tools_installer('vm-1') == {'data': 'ok'}
    assert calls == ['mount', 'unmount']
    m, calls = _vmw('rest')
    assert 'error' in m.mount_tools_installer('vm-1') and calls == []
