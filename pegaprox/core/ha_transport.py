"""The exits: where a call leaves this process for a cluster, a node or a BMC (#625).

Every exit asks ha.guard() right before the call goes out (design 5.3). This module
holds the hooks for the kinds of exit there are:

  guard_session(session)   a requests session to a cluster API (PVE, PBS): asked once
                           before the request is sent and once more when its connection
                           is up, so a stall while connecting is caught as well
  http(method, url, ...)   the same for a call that has no session of its own (the ESXi
                           REST client, an upload into an XCP-ng pool)
  guard_http(method, url)  the guard for one request
  guard_xapi(session)      a XenAPI session (XCP-ng): every XAPI call goes through it, and
                           every send of it on the wire is checked again
  guard_soap(si)           a pyvmomi service instance (ESXi over SOAP)
  guard_client(client)     a paramiko SSH client: exec_command, invoke_shell, open_sftp
  guard_ssh(host, cmd)     an SSH command that leaves some other way
  node_cmd(argv, ...)      ssh, sshpass and ipmitool as subprocesses (design 5.4)

Anywhere but in an automatic group each of them is one look at the state and nothing
else: the call goes out as it did before, at the same moment. A read never asks. In an
automatic group a call is asked once, and a call that goes out again (a new login, a
fallback, a retry of urllib3) or whose connection comes up late is checked again on what
it went out on (again=True): no new round while that still fits (ha.guard).

MK Oct 2026 (#625)
"""
import os
import re
import shutil
import signal
import subprocess
import time
from urllib.parse import urlsplit

import requests
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool

from pegaprox.core import ha

WRITE_METHODS = frozenset(('POST', 'PUT', 'DELETE', 'PATCH'))
# the console proxies hand out a ticket for a console; they change nothing on the guest.
# So does the WebMKS ticket of the ESXi REST API (POST .../vm/<id>/console/tickets)
_CONSOLE_RE = re.compile(r'/(vncproxy|termproxy|spiceproxy|vncwebsocket|vncshell|spiceshell)/?$'
                         r'|/console/tickets/?$')
_LOGIN_RE = re.compile(r'/access/ticket/?$|/api/session/?$|/rest/com/vmware/cis/session/?$')
_TOKEN_RE = re.compile(r'/access/users/[^/]+/token/[^/]+/?$')
_NUMBER_RE = re.compile(r'(?<=/)\d+(?=/|$)')
# XAPI calls that only read; everything else changes the pool
_XAPI_READ_RE = re.compile(r'(get_|query_|compute_|assert_|retrieve_|check_)|get$|get_all')
_XAPI_READ_CLASSES = frozenset(('session', 'event'))
# vSphere methods outside the *_Task ones that change a guest
_SOAP_WRITES = frozenset(('ShutdownGuest', 'RebootGuest', 'StandbyGuest', 'MarkAsTemplate',
                          'MarkAsVirtualMachine', 'UnregisterVM', 'AnswerVM', 'RenameVM'))

# `timeout -k 2 <bound>` around a command on the way to a node: bounded even when this
# process is frozen (5.4)
KILL_AFTER = 2
_timeout_bin = {}


def _shape(path):
    """A path with its numbers taken out, so an exit is said once and not per guest."""
    return _NUMBER_RE.sub('N', path)[:160]


def http_action(method, url):
    """(action, kind) for a request through an exit, (None, None) for a read."""
    m = (method or 'GET').upper()
    if m not in WRITE_METHODS:
        return None, None
    path = urlsplit(url).path if '://' in str(url) else str(url).split('?', 1)[0]
    if _CONSOLE_RE.search(path):
        kind = 'console'
    elif _LOGIN_RE.search(path):
        kind = 'login'
    elif m == 'POST' and _TOKEN_RE.search(path):
        kind = 'cheap'
    else:
        kind = None
    return f'{m} {_shape(path)}', kind


def guard_http(method, url, again=False):
    """Ask the guard for one request; `again` for the same request once more. Raises
    ha.GuardRefused."""
    if (method or 'GET').upper() not in WRITE_METHODS or not ha.guard_on():
        return
    action, kind = http_action(method, url)
    ha.guard(action, kind, again=again)


def _asked_up(conn, method, url):
    """The request is about to go out on `conn`: asked again, and once more after the
    connection came up where it was not up yet (plain HTTP connects inside request()). A
    lease that ran out while it connected stops the request here."""
    if (method or 'GET').upper() not in WRITE_METHODS or not ha.guard_on():
        return
    guard_http(method, url, again=True)
    if getattr(conn, 'sock', None) is None:
        conn.connect()
        guard_http(method, url, again=True)


class _GuardedHTTPConnection(HTTPConnection):
    def request(self, method, url, *args, **kwargs):
        _asked_up(self, method, url)
        return super().request(method, url, *args, **kwargs)


class _GuardedHTTPSConnection(HTTPSConnection):
    def request(self, method, url, *args, **kwargs):
        _asked_up(self, method, url)
        return super().request(method, url, *args, **kwargs)


class _GuardedHTTPPool(HTTPConnectionPool):
    ConnectionCls = _GuardedHTTPConnection
    _ha_asks = True


class _GuardedHTTPSPool(HTTPSConnectionPool):
    ConnectionCls = _GuardedHTTPSConnection
    _ha_asks = True


GUARDED_POOLS = {'http': _GuardedHTTPPool, 'https': _GuardedHTTPSPool}
_ASKING_POOLS = {HTTPConnectionPool: _GuardedHTTPPool, HTTPSConnectionPool: _GuardedHTTPSPool}


def _asking_pool(pool_cls):
    """pool_cls with connections that ask again once they are up: the guarded pools above
    for urllib3's own, a subclass for any other (the SOCKS pools of a socks:// proxy)."""
    if getattr(pool_cls, '_ha_asks', False):
        return pool_cls
    if pool_cls not in _ASKING_POOLS:
        class _Asking(pool_cls.ConnectionCls):
            def request(self, method, url, *args, **kwargs):
                _asked_up(self, method, url)
                return super().request(method, url, *args, **kwargs)

        _ASKING_POOLS[pool_cls] = type(f'_Guarded{pool_cls.__name__}', (pool_cls,),
                                       {'ConnectionCls': _Asking, '_ha_asks': True})
    return _ASKING_POOLS[pool_cls]


def guard_adapter(adapter):
    """The pools a requests adapter opens from now on ask the guard once their
    connection is up, those behind a proxy as well: with HTTP(S)_PROXY in the
    environment requests sends through adapter.proxy_manager_for(), a manager of its
    own. While the guard is off the pools ask nothing (_asked_up). Returns the adapter."""
    manager = getattr(adapter, 'poolmanager', None)
    if manager is not None and hasattr(manager, 'pool_classes_by_scheme'):
        manager.pool_classes_by_scheme = dict(GUARDED_POOLS)
    real = getattr(adapter, 'proxy_manager_for', None)
    if real is not None and not getattr(real, '_ha_asks', False):
        def proxy_manager_for(proxy, **proxy_kwargs):
            got = real(proxy, **proxy_kwargs)
            classes = getattr(got, 'pool_classes_by_scheme', None)
            if isinstance(classes, dict):
                got.pool_classes_by_scheme = {k: _asking_pool(v) for k, v in classes.items()}
            return got
        proxy_manager_for._ha_asks = True
        adapter.proxy_manager_for = proxy_manager_for
    return adapter


def guard_session(session, again=False):
    """Every request of a requests session asks the guard before it is sent, and again
    once its connection is up. Mount adapters before this. `again` for a session of one
    call that sends a call once more (http). Returns the session."""
    send = getattr(session, 'send', None)
    if send is None or getattr(session, '_ha_guarded', False) is True:
        return session

    def guarded_send(request, **kwargs):
        guard_http(request.method, request.url, again=again)
        return send(request, **kwargs)
    session.send = guarded_send
    for adapter in list(getattr(session, 'adapters', {}).values()):
        guard_adapter(adapter)
    session._ha_guarded = True
    return session


def http(method, url, again=False, **kwargs):
    """requests.request() for a call that has no session of its own (the ESXi REST client,
    an upload into an XCP-ng pool). In an automatic group it goes out on a session of its
    own that asks the guard before the call is sent and again once its connection is up,
    as guard_session does; `again` for the same call sent once more after a new login.
    requests.request() itself anywhere else."""
    if not ha.guard_on():
        return requests.request(method, url, **kwargs)
    with requests.Session() as session:
        guard_session(session, again=again)
        return session.request(method, url, **kwargs)


def xapi_action(methodname):
    """The action of an XAPI call that changes the pool, None for a read and the login."""
    name = str(methodname or '')
    if name.startswith(('login', 'logout', 'slave_local')):
        return None
    parts = name.split('.')
    if parts and parts[0] == 'Async':
        parts = parts[1:]
    if len(parts) < 2:
        return None
    cls, meth = parts[0], parts[-1]
    if cls in _XAPI_READ_CLASSES or _XAPI_READ_RE.match(meth):
        return None
    return 'XAPI ' + '.'.join(parts)


def guard_xapi(session):
    """Every call of a XenAPI session asks the guard; reads pass. Returns the session."""
    real = getattr(session, 'xenapi_request', None)
    if real is None:
        return session

    def request(methodname, params):
        if ha.guard_on():
            action = xapi_action(methodname)
            if action:
                ha.guard(action)
        return real(methodname, params)
    # the dispatcher behind session.xenapi looks the method up on the instance first
    session.xenapi_request = request
    # XenAPI sends a call again after a new login when the pool says SESSION_INVALID, up
    # to three times: each send on the wire is checked, not only the first ask
    wire = getattr(session, '_ServerProxy__request', None)
    if wire is not None:
        def send(methodname, params):
            if ha.guard_on():
                action = xapi_action(methodname)
                if action:
                    ha.guard(action, again=True)
            return wire(methodname, params)
        session._ServerProxy__request = send
    return session


def soap_action(name):
    """The action of a vSphere SOAP method that changes something, None for a read."""
    name = str(name or '')
    if name.endswith('_Task') and not name.startswith(('SearchDatastore', 'QueryChangedDisk')):
        return f'SOAP {name}'
    if name in _SOAP_WRITES:
        return f'SOAP {name}'
    return None


def guard_soap(si):
    """Every call of a pyvmomi service instance asks the guard; reads pass."""
    stub = getattr(si, '_stub', None)
    real = getattr(stub, 'InvokeMethod', None)
    if real is None:
        return si

    def invoke(mo, info, args):
        if ha.guard_on():
            action = soap_action(getattr(info, 'wsdlName', None) or getattr(info, 'name', None))
            if action:
                ha.guard(action)
        return real(mo, info, args)
    stub.InvokeMethod = invoke
    return si


def _first_word(cmd):
    words = str(cmd or '').split()
    return os.path.basename(words[0])[:40] if words else ''


def guard_ssh(host, cmd='', again=False):
    """Ask the guard for one SSH command to `host`; `again` for the same command once
    more. Every SSH command counts as a change (5.3) except in a GET; a caller that only
    reads says so with ha.reading()."""
    if not ha.guard_on():
        return
    ha.guard(f'SSH {host} {_first_word(cmd)}'.strip(), kind='ssh', again=again)


def guard_client(client, host=''):
    """exec_command, invoke_shell and open_sftp of a paramiko client ask the guard first.
    Returns the client."""
    for name in ('exec_command', 'invoke_shell', 'open_sftp'):
        real = getattr(client, name, None)
        if real is None:
            continue

        def guarded(*args, _real=real, _name=name, **kwargs):
            if ha.guard_on():
                cmd = (args[0] if args else kwargs.get('command', '')) if _name == 'exec_command' else _name
                guard_ssh(host or _peer(client), cmd)
            return _real(*args, **kwargs)
        setattr(client, name, guarded)
    return client


def _peer(client):
    try:
        return str(client.get_transport().getpeername()[0])
    except Exception:
        return '?'


def _bounded(argv, bound):
    """argv under `timeout -k KILL_AFTER bound`, as it is where coreutils' timeout is."""
    if 'path' not in _timeout_bin:
        _timeout_bin['path'] = shutil.which('timeout')
    tb = _timeout_bin['path']
    if not tb:
        return list(argv), False
    return [tb, '-k', str(KILL_AFTER), f'{float(bound):g}'] + list(argv), True


def _kill_group(pgid):
    try:
        os.killpg(pgid, signal.SIGKILL)
    except OSError:
        pass


def node_cmd(argv, *, timeout, host='', read=False, need=None, again=False, **kwargs):
    """subprocess.run() for ssh, sshpass and ipmitool on the way to a node or a BMC
    (design 5.4).

    Anywhere but in an automatic group it is subprocess.run(argv, timeout=timeout,
    **kwargs) and nothing else. In an automatic group the guard is asked first (a read
    passes): the step that confirmed must leave its need of lease time, or `need` where
    the command asks for more (ha.NEED_STEP for a change inside /etc/pve or corosync);
    `again` for a command another way out asked for already (a fallback). The command
    then runs in a session of its own under `timeout -k 2 <timeout>`, so it is bounded
    even while this process is frozen, and its process group is registered: losing the
    lease kills it (ha.kill_children). A timeout raises subprocess.TimeoutExpired, as
    subprocess.run does."""
    if not ha.guard_on():
        return subprocess.run(argv, timeout=timeout, **kwargs)
    if not read:
        ha.guard(f'{os.path.basename(str(argv[0]))} {host} {_first_word(argv[-1]) if len(argv) > 1 else ""}'.strip(),
                 kind='ssh', need=need, again=again)
    full, wrapped = _bounded(argv, timeout)
    if kwargs.pop('capture_output', False):
        kwargs['stdout'] = kwargs['stderr'] = subprocess.PIPE
    data = kwargs.pop('input', None)
    if data is not None:
        kwargs['stdin'] = subprocess.PIPE
    started = time.monotonic()
    # Final lease check: the command was authorized, but the lease may have been lost
    # while preparing arguments. Verify we still hold authority before spawning.
    if not read and ha.guard_on():
        if not ha.is_active():
            raise ha.GuardRefused(f'{os.path.basename(str(argv[0]))} {host}'.strip(),
                                  'this instance lost the lease before the command could start')
    proc = subprocess.Popen(full, start_new_session=True, **kwargs)
    ha.register_child_group(proc.pid)
    try:
        try:
            out, err = proc.communicate(data, timeout=float(timeout) + KILL_AFTER + 1)
        except subprocess.TimeoutExpired:
            _kill_group(proc.pid)
            out, err = proc.communicate()
            raise subprocess.TimeoutExpired(argv, timeout, output=out, stderr=err)
    finally:
        if proc.poll() is None:
            _kill_group(proc.pid)
            proc.wait()
        ha.forget_child_group(proc.pid)
    if wrapped and proc.returncode in (124, 128 + signal.SIGKILL) \
            and time.monotonic() - started >= float(timeout):
        raise subprocess.TimeoutExpired(argv, timeout, output=out, stderr=err)
    return subprocess.CompletedProcess(argv, proc.returncode, out, err)
