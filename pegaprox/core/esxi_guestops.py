# -*- coding: utf-8 -*-
"""The guest operations of an ESXi host: files into and out of a running guest, and
programs started inside it, with an account of the guest (vim.vm.guest.GuestOperationsManager).

MK Nov 2026 - the Windows preparation of an ESXi migration (core/v2p_guestprep.py) runs its
script in the source guest before the copy. The calls need the guest tools running in the
guest and the SOAP API of the host: the REST API has no guest operations, so a connection
that runs over REST is refused here, like change tracking is.

The guest login reaches nothing but the auth object of the SOAP calls. Neither the password
nor the account name is in an error text, a log line or a URL; close() drops the auth object,
the only reference.
The file transfer URLs ESXi hands out carry a one-time ticket and are never logged either.
"""

import base64
import hashlib
import socket
import ssl
import time
from urllib.parse import urlsplit, urlunsplit


class GuestOpsError(Exception):
    """kind: login | tools | permission | notfound | unavailable | exists | other"""

    def __init__(self, kind, msg):
        super().__init__(msg)
        self.kind = kind
        self.msg = msg


# the ESXi API faults of the guest operations, by the last part of their type name
_FAULT_KINDS = {
    'InvalidGuestLogin': 'login',
    'GuestAuthenticationChallenge': 'login',
    'GuestOperationsUnavailable': 'tools',
    'InvalidState': 'tools',
    'ToolsUnavailable': 'tools',
    'GuestComponentsOutOfDate': 'tools',
    'GuestPermissionDenied': 'permission',
    'OperationDisabledByGuest': 'unavailable',
    'FileNotFound': 'notfound',
    'FileAlreadyExists': 'exists',
    'NotAuthenticated': 'session',
}

_REST_REFUSAL = 'the guest operations are only reachable over the SOAP API of the host'


def _fault_kind(exc):
    for cls in type(exc).__mro__:
        kind = _FAULT_KINDS.get(cls.__name__.rsplit('.', 1)[-1])
        if kind:
            return kind
    return 'other'


def _fault_text(exc):
    # an ESXi API fault prints itself with every field; its msg is what ESXi said
    msg = getattr(exc, 'msg', None)
    if not isinstance(msg, str) or not msg.strip():
        msg = type(exc).__name__.rsplit('.', 1)[-1]
    return ' '.join(msg.split())[:300]


def _auth(user, password):
    from pyVmomi import vim
    return vim.vm.guest.NamePasswordAuthentication(username=user, password=password,
                                                   interactiveSession=False)


def _program_spec(program, args, cwd):
    from pyVmomi import vim
    return vim.vm.guest.ProcessManager.ProgramSpec(programPath=program, arguments=args,
                                                   workingDirectory=cwd)


def _file_attributes():
    from pyVmomi import vim
    return vim.vm.guest.FileManager.FileAttributes()


def fix_transfer_url(url, host):
    """The file transfer URL ESXi answered with, aimed at the registered host.

    ESXi names itself '*' there (sometimes with :443). '*' becomes `host` (an IPv6
    literal in brackets), the port stays; any other host than '*' or the registered one
    is refused, the ticket would go there."""
    from pegaprox.utils.ssh import bare_host, is_ipv6_literal
    try:
        parts = urlsplit(str(url or ''))
        port = parts.port
    except ValueError:
        raise GuestOpsError('other', 'ESXi answered the file transfer with no usable URL')
    if parts.scheme != 'https' or not parts.hostname:
        raise GuestOpsError('other', 'ESXi answered the file transfer with no usable URL')
    want = bare_host(host)
    named = parts.hostname
    if named != '*' and named.lower() != str(want).lower():
        raise GuestOpsError('other', 'ESXi named another host for the file transfer')
    netloc = f'[{want}]' if is_ipv6_literal(want) else want
    if port:
        netloc += f':{int(port)}'
    return urlunsplit(('https', netloc, parts.path, parts.query, ''))


def pinned_key(host, port=443, verify=False, timeout=15):
    """'sha256//<base64>' of the public key the TLS server at host:port shows, for curl's
    --pinnedpubkey on the node. One TLS connection, checked as the ESXi connection of
    PegaProx is checked (verify: on, off or a CA bundle path): with verification on, a
    chain that does not verify fails here as it would there."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from pegaprox.utils.ssh import bare_host
    addr = bare_host(host)
    if verify:
        ctx = ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)
        server_name = addr
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        server_name = None
    with socket.create_connection((addr, int(port or 443)), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=server_name) as tls:
            der = tls.getpeercert(binary_form=True)
    if not der:
        raise GuestOpsError('other', f'{addr}:{port} showed no certificate')
    spki = x509.load_der_x509_certificate(der).public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return 'sha256//' + base64.b64encode(hashlib.sha256(spki).digest()).decode('ascii')


class GuestSession:
    """The guest operations on one VM with one guest account."""

    def __init__(self, vmware_mgr, vm_id, user, password):
        self.mgr = vmware_mgr
        self.vm_id = vm_id
        self.user = str(user or '')
        self._auth_obj = _auth(self.user, password) if password else None

    # -- plumbing --------------------------------------------------------------------

    def _vm_and_ops(self):
        """(vm, guestOperationsManager), looked up again on every call: a reconnect in
        between replaces the service instance"""
        mgr = self.mgr
        if getattr(mgr, '_connection_type', '') != 'soap':
            raise GuestOpsError('unavailable', _REST_REFUSAL)
        vm, err = mgr._soap_vm(self.vm_id)
        if err:
            raise GuestOpsError('notfound' if 'not found' in str(err).lower() else 'unavailable', str(err))
        content = getattr(mgr, '_soap_content', None)
        ops = getattr(content, 'guestOperationsManager', None) if content is not None else None
        if ops is None:
            raise GuestOpsError('unavailable', 'the host offers no guest operations')
        return vm, ops

    def _call(self, what, fn):
        if self._auth_obj is None:
            raise GuestOpsError('login', 'no account for the guest is known (any more)')
        for attempt in (0, 1):
            try:
                vm, ops = self._vm_and_ops()
            except GuestOpsError as e:
                if attempt == 0 and e.kind == 'notfound' and self._reconnect():
                    continue
                raise
            try:
                return fn(vm, ops, self._auth_obj)
            except GuestOpsError:
                raise
            except Exception as e:
                kind = _fault_kind(e)
                # the ESXi session ran out: the call never reached the guest
                if kind == 'session' and attempt == 0 and self._reconnect():
                    continue
                raise self._error(kind, what, e)
        raise GuestOpsError('unavailable', f'{what}: the connection to ESXi did not come back')

    def _reconnect(self):
        try:
            self.mgr.connected = False
            return bool(self.mgr.ensure_connected())
        except Exception:
            return False

    def _error(self, kind, what, exc):
        if kind == 'login':
            return GuestOpsError('login', 'the guest refused the Windows login')
        if kind == 'session':
            kind = 'unavailable'
        if kind == 'tools':
            return GuestOpsError('tools', f'{what}: the guest tools do not take guest operations '
                                          f'now ({_fault_text(exc)})')
        if kind == 'permission':
            return GuestOpsError('permission', f'{what}: the account may not do that in the guest '
                                               f'({_fault_text(exc)})')
        return GuestOpsError(kind, f'{what}: {_fault_text(exc)}')

    # -- what the guest can do -------------------------------------------------------

    def ready(self):
        """(True, '') when the guest tools run and take guest operations, else (False, why)"""
        try:
            vm, _ops = self._vm_and_ops()
            g = vm.guest
            if str(getattr(g, 'toolsRunningStatus', '')) != 'guestToolsRunning':
                return False, 'the guest tools are not running in the guest'
            if not getattr(g, 'guestOperationsReady', False):
                return False, 'the guest tools do not take guest operations yet'
            return True, ''
        except GuestOpsError as e:
            return False, e.msg
        except Exception as e:
            return False, _fault_text(e)

    def validate(self):
        """One login attempt in the guest, never retried here: a wrong password tried in a
        loop locks the account"""
        self._call('the login check', lambda vm, ops, a: ops.authManager.ValidateCredentialsInGuest(vm=vm, auth=a))

    def env(self, *names):
        """{NAME: value} of the guest's environment, as the account sees it; keys upper case"""
        got = self._call('reading the environment', lambda vm, ops, a: ops.processManager.ReadEnvironmentVariableInGuest(
            vm=vm, auth=a, names=list(names)))
        out = {}
        for line in got or []:
            k, sep, v = str(line).partition('=')
            if sep:
                out[k.upper()] = v
        return out

    def temp_dir(self, prefix):
        return str(self._call('creating a temporary folder', lambda vm, ops, a:
                              ops.fileManager.CreateTemporaryDirectoryInGuest(vm=vm, auth=a, prefix=prefix,
                                                                              suffix='')))

    def mkdir(self, path):
        try:
            self._call('creating a folder', lambda vm, ops, a: ops.fileManager.MakeDirectoryInGuest(
                vm=vm, auth=a, directoryPath=path, createParentDirectories=True))
        except GuestOpsError as e:
            if e.kind != 'exists':
                raise

    def upload_ticket(self, path, size):
        """The URL one file of `size` bytes is PUT to, aimed at the registered host. A
        one-time ticket: never log it."""
        url = self._call('a file transfer into the guest', lambda vm, ops, a:
                         ops.fileManager.InitiateFileTransferToGuest(
                             vm=vm, auth=a, guestFilePath=path, fileAttributes=_file_attributes(),
                             fileSize=int(size), overwrite=True))
        return fix_transfer_url(url, self.mgr.host)

    def put(self, path, data):
        from pegaprox.core import ha_transport
        url = self.upload_ticket(path, len(data))
        try:
            r = ha_transport.http('PUT', url, data=data, verify=self.mgr.ssl_verify, timeout=120,
                                  allow_redirects=False)
        except Exception as e:
            raise GuestOpsError('other', f'the upload into the guest failed ({type(e).__name__})')
        if r.status_code not in (200, 201, 204):
            raise GuestOpsError('other', f'the upload into the guest answered HTTP {r.status_code}')

    def get(self, path, cap):
        """Up to `cap` bytes of a file in the guest, None when there is no such file"""
        from pegaprox.core import ha_transport
        try:
            info = self._call('a file transfer out of the guest', lambda vm, ops, a:
                              ops.fileManager.InitiateFileTransferFromGuest(vm=vm, auth=a, guestFilePath=path))
        except GuestOpsError as e:
            if e.kind == 'notfound':
                return None
            raise
        url = fix_transfer_url(getattr(info, 'url', ''), self.mgr.host)
        r = None
        try:
            r = ha_transport.http('GET', url, verify=self.mgr.ssl_verify, timeout=120, stream=True,
                                  allow_redirects=False)
            if r.status_code != 200:
                raise GuestOpsError('other', f'the download from the guest answered HTTP {r.status_code}')
            buf = bytearray()
            for chunk in r.iter_content(65536):
                buf += chunk
                if len(buf) >= cap:
                    break
            return bytes(buf[:cap])
        except GuestOpsError:
            raise
        except Exception as e:
            raise GuestOpsError('other', f'the download from the guest failed ({type(e).__name__})')
        finally:
            # MK Nov 2026 - a streamed answer holds its connection until it is closed: an error
            # answer or a download cut off kept it until the garbage collector came by
            if r is not None:
                r.close()

    def start(self, program, args, cwd):
        return int(self._call('starting a program in the guest', lambda vm, ops, a:
                              ops.processManager.StartProgramInGuest(vm=vm, auth=a,
                                                                     spec=_program_spec(program, args, cwd))))

    def exit_code(self, pid):
        """The exit code of a program started here once it ended, None while it runs"""
        got = self._call('reading a program state', lambda vm, ops, a:
                         ops.processManager.ListProcessesInGuest(vm=vm, auth=a, pids=[int(pid)]))
        for p in got or []:
            if int(getattr(p, 'pid', -1)) == int(pid) and getattr(p, 'endTime', None):
                code = getattr(p, 'exitCode', None)
                return int(code) if code is not None else -1
        return None

    def wait_exit(self, pid, seconds, poll=3):
        deadline = time.monotonic() + seconds
        while True:
            code = self.exit_code(pid)
            if code is not None:
                return code
            if time.monotonic() >= deadline:
                return None
            time.sleep(poll)

    def remove_dir(self, path):
        try:
            self._call('removing a folder', lambda vm, ops, a: ops.fileManager.DeleteDirectoryInGuest(
                vm=vm, auth=a, directoryPath=path, recursive=True))
        except Exception:
            pass

    def close(self):
        self._auth_obj = None
