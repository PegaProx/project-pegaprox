"""Every way out of this process, counted, and every step that needs a confirmed lease
(#625 stage 2, design 5.2 to 5.4, slice S4).

The transport guard only holds if every exit to a cluster, a node or a BMC goes through
it. So this file reads the source and fails when one does not:

  EXITS          every place a call leaves (a requests session or a direct request,
                 urllib, a websocket, a paramiko client or transport, an exec on one, a
                 subprocess, a XenAPI or pyvmomi session, SMTP, a raw socket), by file,
                 function and kind, how many, and why it is safe: guarded at the exit,
                 or a kind the guard is not for (a read, a login, a console, this host,
                 a service outside the clusters, the other members)
  AUTOMATIONS    every thread or greenlet started in the background, and whether its
                 steps confirm (CONFIRM_SITES) or it is a user job whose calls ask at the
                 exit (ha.as_job)
  CONFIRM_SITES  the steps of design 5.2: each call is preceded by ha.confirm_step() or
                 ha.confirm_lease() in the same block or around it, with no sleep between
  READ_SITES     every `with ha.reading()`: the background reads that pass the guard unasked
  NEED_SITES     the SSH steps inside /etc/pve or corosync, which ask for NEED_STEP at the
                 exit whatever confirmed before them (design 5.4)

A new exit, a new background start or a step that lost its confirm fails here with what
to do. The inventory with the reasoning is in the S4 report (s4_inventory.md).

What the scan sees: pegaprox/, plugins/ and whatever else the root of the checkout lets
the code import (a module or a package next to pegaprox/), the calls of a function
including those in its lambdas, an import under another name, a name assigned an exit (`send = requests.post`), getattr() with the
name spelled out, and requests, urllib, urllib3, http.client, websocket, paramiko,
subprocess, XenAPI, pyVmomi, smtplib and raw sockets. What it cannot see, and what holds
there instead:

  * an exit listed as no cluster's (external, read, local, ...) called with the address
    of a cluster, a webhook pointed at the PVE API for one: the scan sees the exit, not
    where its URL points
  * a call through a guarded exit from a site that confirmed nothing (the manager's
    session in a lambda handed to run_concurrent, a client of a guarded factory): no
    exit of its own; the guard refuses it at run time for want of a token, and a test
    that runs it fails (tests/conftest.py)
  * getattr() with a name worked out at run time, an exit kept in an attribute or a
    container (`self._post = requests.post`, functools.partial), importlib or
    __import__, exec and eval, and a module of the standard library or a package that
    is not in the list above (ftplib, asyncio streams, httpx, os.exec*)

MK Oct 2026 (#625)
"""
import ast
import os
from collections import Counter

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# --- the scan ---------------------------------------------------------------------------

_VERBS = {'get', 'post', 'put', 'delete', 'patch', 'head', 'request', 'options'}


# the modules an exit comes from: a name assigned one of theirs is that exit
_EXIT_MODULES = ('requests', 'urllib', 'urllib3', 'http', 'websocket', 'websockets', 'paramiko',
                 'subprocess', 'os', 'XenAPI', 'pyVim', 'smtplib', 'socket', 'gevent')


def _aliases(nodes, out=None):
    """{local name: module path} of the imports among `nodes` and below them:
    `import requests as _req` makes `_req.put(...)` a requests.put. Then the names
    assigned an exit by name: `send = requests.post` makes `send(...)` one too."""
    out = dict(out or {})
    assigns = []
    for top in nodes:
        for node in ast.walk(top):
            if isinstance(node, ast.Import):
                for a in node.names:
                    if a.asname:
                        out[a.asname] = a.name
            elif isinstance(node, ast.ImportFrom) and node.module:
                for a in node.names:
                    out[a.asname or a.name] = f'{node.module}.{a.name}'
            elif (isinstance(node, ast.Assign) and len(node.targets) == 1
                  and isinstance(node.targets[0], ast.Name)
                  and isinstance(node.value, (ast.Attribute, ast.Name))):
                assigns.append(node)
    for node in assigns:
        d = _dotted(node.value, out)
        if d.split('.', 1)[0] in _EXIT_MODULES and d != node.targets[0].id:
            out[node.targets[0].id] = d
    return out


def _scopes(tree):
    """{id(function): the aliases it sees}: the imports and exit names at module level, and
    those of the outermost function it sits in (a local `import requests as _r` in one
    function says nothing about a variable `_r` in another)."""
    imports, todo = [], list(tree.body)
    while todo:
        n = todo.pop()
        if isinstance(n, (ast.Import, ast.ImportFrom, ast.Assign)):
            imports.append(n)
        elif not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            todo.extend(ast.iter_child_nodes(n))
    module = _aliases(imports)
    out = {}

    def tops(node):
        for ch in ast.iter_child_nodes(node):
            if isinstance(ch, (ast.FunctionDef, ast.AsyncFunctionDef)):
                yield ch
            elif isinstance(ch, ast.ClassDef):
                yield from tops(ch)
    for top in tops(tree):
        seen = _aliases([top], module)
        for n in ast.walk(top):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                out[id(n)] = seen
    return module, out


def _dotted(node, aliases=None):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append((aliases or {}).get(node.id, node.id))
    elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'getattr'
          and len(node.args) >= 2 and isinstance(node.args[1], ast.Constant)
          and isinstance(node.args[1].value, str)):
        # getattr(requests, 'post') is requests.post
        parts.append(f'{_dotted(node.args[0], aliases)}.{node.args[1].value}')
    elif isinstance(node, ast.Call):
        parts.append(_dotted(node.func, aliases) + '()')
    return '.'.join(reversed(parts))


_URLLIB3 = {'urllib3.PoolManager', 'urllib3.ProxyManager', 'urllib3.HTTPConnectionPool',
            'urllib3.HTTPSConnectionPool', 'urllib3.connection_from_url', 'urllib3.request',
            'urllib3.poolmanager.PoolManager', 'urllib3.connectionpool.HTTPConnectionPool',
            'urllib3.connectionpool.HTTPSConnectionPool', 'urllib3.connection.HTTPConnection',
            'urllib3.connection.HTTPSConnection'}
_HTTP_CLIENT = {'http.client.HTTPConnection', 'http.client.HTTPSConnection'}


def _kind(call, aliases=None):
    d = _dotted(call.func, aliases)
    last = d.rsplit('.', 1)[-1]
    if d.endswith('ha_transport.http'):
        # the guarded way out for a call without a session of its own: it asks itself
        return 'http-guarded'
    if d in ('requests.Session', 'requests.session'):
        return 'http-session'
    if d.startswith('requests.') and last in _VERBS:
        return 'http-direct'
    if d in _URLLIB3:
        return 'http-urllib3'
    if d in _HTTP_CLIENT:
        return 'http-client'
    if last == 'urlopen' or d.endswith('opener.open'):
        return 'http-urllib'
    if d in ('websocket.create_connection', 'websockets.connect'):
        return 'ws'
    if d in ('paramiko.SSHClient', 'paramiko.Transport'):
        return 'ssh-paramiko'
    if last in ('exec_command', 'invoke_shell', 'open_sftp', 'open_channel'):
        return 'ssh-exec'
    if (d.startswith('subprocess.') or d in ('os.popen', 'os.system')) and \
            last in ('run', 'Popen', 'call', 'check_output', 'check_call', 'popen', 'system'):
        return 'subprocess'
    if d == 'XenAPI.Session':
        return 'xapi'
    if last == 'SmartConnect':
        return 'soap'
    if d in ('smtplib.SMTP', 'smtplib.SMTP_SSL'):
        return 'smtp'
    if d in ('socket.create_connection', 'socket.socket', 'gevent.socket.socket'):
        return 'socket'
    return None


def _files():
    """pegaprox/ and plugins/, and whatever else the root of the checkout lets the code
    import: a module next to pegaprox/ is a way out as much as one inside it, so is a
    package of its own. Not the tests, and not a virtualenv or a package build in the
    checkout (no __init__.py at their top)."""
    out, tops = [], ['pegaprox', 'plugins']
    for name in sorted(os.listdir(ROOT)):
        path = os.path.join(ROOT, name)
        if name.startswith('.') or name == 'tests':
            continue
        if name.endswith('.py') and os.path.isfile(path):
            out.append(name)
        elif name not in tops and os.path.isfile(os.path.join(path, '__init__.py')):
            tops.append(name)
    for base in tops:
        for d, dirs, names in os.walk(os.path.join(ROOT, base)):
            dirs[:] = [n for n in dirs if n != '__pycache__']
            out += [os.path.relpath(os.path.join(d, n), ROOT) for n in names if n.endswith('.py')]
    return sorted(out)


def _functions(tree):
    """(qualname, node) of every function, nested ones by their dotted path."""
    out = []

    def walk(node, prefix):
        for ch in ast.iter_child_nodes(node):
            if isinstance(ch, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                q = prefix + ch.name
                if not isinstance(ch, ast.ClassDef):
                    out.append((q, ch))
                walk(ch, q + '.')
            else:
                walk(ch, prefix)
    walk(tree, '')
    return out


def _own_calls(func, lambdas=False):
    """The calls of `func` itself, nested functions and classes left out; with `lambdas`
    those of the lambdas in it too (what it hands a pool runs in its name)."""
    todo, calls = list(ast.iter_child_nodes(func)), []
    while todo:
        node = todo.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) or (
                isinstance(node, ast.Lambda) and not lambdas):
            continue
        if isinstance(node, ast.Call):
            calls.append(node)
        todo.extend(ast.iter_child_nodes(node))
    return calls


_trees = {}


def _tree(rel):
    if rel not in _trees:
        with open(os.path.join(ROOT, rel), encoding='utf-8') as fh:
            _trees[rel] = ast.parse(fh.read())
    return _trees[rel]


def _scan():
    found = Counter()
    for rel in _files():
        tree = _tree(rel)
        module, scopes = _scopes(tree)
        funcs = _functions(tree)
        inside = set()
        for q, f in funcs:
            for c in _own_calls(f, lambdas=True):
                inside.add(id(c))
                k = _kind(c, scopes.get(id(f), module))
                if k:
                    found[(rel, q, k)] += 1
        for c in ast.walk(tree):
            if isinstance(c, ast.Call) and id(c) not in inside and _kind(c, module):
                found[(rel, '<module>', _kind(c, module))] += 1
    return found


GUARD_HOOKS = {'guard_session', 'guard_client', 'guard_xapi', 'guard_soap', 'guard_http',
               'guard_ssh', 'guard', 'node_cmd'}


def _callee(call):
    f = call.func
    return f.id if isinstance(f, ast.Name) else getattr(f, 'attr', None)


def _func(rel, qualname):
    for q, f in _functions(_tree(rel)):
        if q == qualname:
            return f
    raise AssertionError(f'{rel}: {qualname} is gone - update the inventory in {__file__}')


# --- the inventory: every exit ------------------------------------------------------------
#
# Verdicts:
#   guard     the exit itself asks the guard: the function calls one of GUARD_HOOKS
#   client    an exec on a paramiko client from a guarded factory (_ssh_connect of the
#             PVE, PBS and XCP-ng managers, xhm._connect_ssh, secure_ssh_client)
#   console   a console ticket, proxy or shell
#   login     a login, or the check of one
#   read      reads only
#   local     this host (systemctl, dpkg, ping, ip route, scp to here, a local convert)
#   external  not a cluster: the update server, webhooks, OIDC, ACME, SMTP, SIEM, push
#   peer      the other PegaProx members (signed peer calls, ha.py)
#   unused    no caller; the first one has to guard it

EXITS = {
    # PVE REST
    ('pegaprox/core/manager.py', 'PegaProxManager._create_session', 'http-session'): (1, 'guard'),
    ('pegaprox/core/manager.py', 'PegaProxManager.connect_to_proxmox', 'http-session'): (1, 'guard'),
    ('pegaprox/core/manager.py', 'PegaProxManager.create_privileged_session', 'http-session'): (1, 'guard'),
    ('pegaprox/core/manager.py', 'PegaProxManager.mint_console_auth_ticket', 'http-urllib'): (1, 'console'),
    ('pegaprox/core/manager.py', 'PegaProxManager.tls_fingerprint', 'socket'): (1, 'read'),
    # the connection check: GET /version per API address (the session only while it is
    # known good), and `sudo -n true` on a client from the guarded _ssh_connect
    ('pegaprox/core/conncheck.py', 'probe_host', 'http-session'): (1, 'read'),
    ('pegaprox/core/conncheck.py', 'probe_ssh', 'ssh-exec'): (1, 'client'),
    # PBS
    ('pegaprox/core/pbs.py', 'PBSManager.__init__', 'http-session'): (1, 'guard'),
    ('pegaprox/core/pbs.py', 'PBSManager._ssh_connect', 'ssh-paramiko'): (1, 'guard'),
    ('pegaprox/core/pbs.py', 'PBSManager._perform_update', 'ssh-exec'): (5, 'guard'),
    # ESXi
    ('pegaprox/core/vmware.py', 'VMwareManager.connect', 'http-direct'): (5, 'login'),
    ('pegaprox/core/vmware.py', 'VMwareManager.api_get', 'http-direct'): (2, 'read'),
    ('pegaprox/core/vmware.py', 'VMwareManager.api_post', 'http-guarded'): (2, 'guard'),
    ('pegaprox/core/vmware.py', 'VMwareManager.api_delete', 'http-guarded'): (1, 'guard'),
    ('pegaprox/core/vmware.py', 'VMwareManager.update_vm_config', 'http-guarded'): (1, 'guard'),
    ('pegaprox/core/vmware.py', 'VMwareManager._ping_session', 'http-direct'): (1, 'read'),
    ('pegaprox/core/vmware.py', 'VMwareManager._connect_soap', 'soap'): (1, 'guard'),
    ('pegaprox/core/vmware.py', 'VMwareManager._connect_soap', 'socket'): (1, 'read'),
    # a SOAP login and its logout, nothing else
    ('pegaprox/api/vmware.py', 'diagnose_vmware_connection', 'soap'): (1, 'login'),
    # XCP-ng
    ('pegaprox/core/xcpng.py', 'XcpngManager.connect', 'xapi'): (1, 'guard'),
    ('pegaprox/core/xcpng.py', 'XcpngManager.remote_migrate_vm', 'xapi'): (1, 'guard'),
    ('pegaprox/core/xcpng.py', 'XcpngManager._ssh_connect', 'ssh-paramiko'): (1, 'guard'),
    ('pegaprox/core/xcpng.py', 'XcpngManager._ssh_exec', 'ssh-exec'): (1, 'client'),
    ('pegaprox/core/xcpng.py', 'XcpngManager._perform_node_update', 'ssh-exec'): (3, 'client'),
    ('pegaprox/core/xcpng.py', 'XcpngManager._wait_for_host_online', 'socket'): (1, 'read'),
    # the HTTP side of XAPI: RRD reads, and uploads into an SR
    ('pegaprox/core/xcpng.py', 'XcpngManager._rrd_fetch', 'http-direct'): (1, 'read'),
    ('pegaprox/core/xcpng.py', 'XcpngManager.upload_to_storage', 'http-guarded'): (1, 'guard'),
    ('pegaprox/core/xhm.py', '_run_esxi_to_xcpng', 'http-guarded'): (1, 'guard'),
    ('pegaprox/core/xhm.py', '_run_pve_to_xcpng', 'http-guarded'): (1, 'guard'),
    # the way out of the calls above: a session of one call, asked before the send and
    # once its connection is up (requests.request itself outside an automatic group)
    ('pegaprox/core/ha_transport.py', 'http', 'http-direct'): (1, 'guard'),
    ('pegaprox/core/ha_transport.py', 'http', 'http-session'): (1, 'guard'),
    ('pegaprox/core/xhm.py', '_run_xcpng_to_pve', 'http-direct'): (1, 'read'),
    # PBS: the probes of a route that adds one
    ('pegaprox/api/pbs.py', 'probe_pbs_fingerprint', 'socket'): (1, 'read'),
    ('pegaprox/api/pbs.py', 'auto_attach_pbs_to_clusters', 'socket'): (1, 'read'),
    ('pegaprox/api/pbs.py', 'storage_preflight', 'socket'): (2, 'read'),
    ('pegaprox/api/pbs.py', 'storage_preflight', 'http-session'): (1, 'login'),
    # BMC
    ('pegaprox/core/redfish.py', 'read_node_bmc_redfish._get', 'http-direct'): (1, 'read'),
    # SSH to nodes: the subprocess ladder goes through node_cmd, the paramiko one through
    # the clients of _ssh_connect
    ('pegaprox/core/ha_transport.py', 'node_cmd', 'subprocess'): (2, 'guard'),
    ('pegaprox/core/manager.py', 'PegaProxManager._ssh_connect', 'ssh-paramiko'): (1, 'guard'),
    ('pegaprox/core/manager.py', 'PegaProxManager._ssh_execute', 'ssh-exec'): (1, 'client'),
    ('pegaprox/core/manager.py', 'PegaProxManager._perform_node_update', 'ssh-exec'): (4, 'guard'),
    ('pegaprox/core/manager.py', 'PegaProxManager.sync_content_to_nodes', 'ssh-exec'): (5, 'client'),
    ('pegaprox/core/manager.py', 'PegaProxManager._resolve_storage_path', 'ssh-exec'): (1, 'client'),
    ('pegaprox/core/manager.py', 'PegaProxManager._ssh_run_command_with_password', 'subprocess'): (1, 'local'),
    ('pegaprox/core/manager.py', 'PegaProxManager._ha_verify_network', 'subprocess'): (1, 'local'),
    ('pegaprox/core/manager.py', 'PegaProxManager._ha_ping_host', 'subprocess'): (1, 'local'),
    ('pegaprox/utils/ssh.py', '_ssh_exec', 'ssh-paramiko'): (5, 'guard'),
    ('pegaprox/utils/ssh.py', '_ssh_exec', 'ssh-exec'): (1, 'guard'),
    ('pegaprox/utils/ssh_security.py', 'secure_ssh_client', 'ssh-paramiko'): (1, 'guard'),
    ('pegaprox/utils/ssh_pool.py', 'get_pooled_transport', 'ssh-paramiko'): (1, 'unused'),
    # TCP probes of a node before the call, and the socket _ssh_exec connects with
    ('pegaprox/core/manager.py', 'PegaProxManager._get_node_ip_impl._quick_probe', 'socket'): (1, 'read'),
    ('pegaprox/core/manager.py', 'PegaProxManager._ha_get_node_ip', 'socket'): (1, 'read'),
    ('pegaprox/core/manager.py', 'PegaProxManager._ha_ping_host', 'socket'): (1, 'read'),
    ('pegaprox/utils/ssh.py', '_ssh_exec._make_sock', 'socket'): (1, 'guard'),
    ('pegaprox/core/xhm.py', '_connect_ssh', 'ssh-paramiko'): (3, 'guard'),
    ('pegaprox/core/xhm.py', '_run_xcpng_to_pve', 'ssh-exec'): (6, 'client'),
    ('pegaprox/core/xhm.py', '_run_pve_to_xcpng', 'ssh-exec'): (2, 'client'),
    ('pegaprox/core/xhm.py', '_run_esxi_to_pve', 'ssh-exec'): (14, 'client'),
    ('pegaprox/core/xhm.py', '_ssh_cleanup', 'ssh-exec'): (1, 'client'),
    ('pegaprox/core/xhm.py', '_run_esxi_to_xcpng', 'subprocess'): (2, 'local'),
    ('pegaprox/core/incremental_repl.py', '_relay_pipe', 'ssh-exec'): (2, 'client'),
    ('pegaprox/core/incremental_repl.py', '_relay_pipe._slurp', 'ssh-exec'): (1, 'client'),
    ('pegaprox/core/incremental_repl.py', 'rbd_snap_exists', 'ssh-exec'): (1, 'client'),
    ('pegaprox/core/incremental_repl.py', 'rbd_image_exists', 'ssh-exec'): (1, 'client'),
    ('pegaprox/core/incremental_repl.py', 'rbd_prune_snapshots', 'ssh-exec'): (2, 'client'),
    ('pegaprox/core/incremental_repl.py', 'zfs_snap_exists', 'ssh-exec'): (1, 'client'),
    ('pegaprox/core/incremental_repl.py', '_ssh_run', 'ssh-exec'): (1, 'client'),
    ('pegaprox/api/ceph.py', '_rbd_cmd', 'ssh-exec'): (1, 'client'),
    ('pegaprox/api/ceph.py', '_rbd_batch', 'ssh-exec'): (1, 'client'),
    ('pegaprox/api/datacenter.py', '_get_node_multipath_data.ssh_run', 'ssh-exec'): (1, 'client'),
    ('pegaprox/api/datacenter.py', 'setup_multipath._exec', 'ssh-exec'): (1, 'client'),
    ('pegaprox/api/datacenter.py', 'reconfigure_multipath', 'ssh-exec'): (1, 'client'),
    ('pegaprox/api/datacenter.py', 'login_iscsi_target._exec', 'ssh-exec'): (1, 'client'),
    ('pegaprox/api/nodes.py', '_ssh_sudo_prefix', 'ssh-exec'): (1, 'client'),
    ('pegaprox/api/nodes.py', '_ssh_run_script', 'ssh-exec'): (1, 'client'),
    ('pegaprox/api/nodes.py', '_ssh_run_checked', 'ssh-exec'): (1, 'client'),
    ('pegaprox/api/nodes.py', '_ssh_write_file', 'ssh-exec'): (8, 'client'),
    ('pegaprox/api/nodes.py', 'get_smbios_autoconfig_status', 'ssh-exec'): (3, 'client'),
    ('pegaprox/api/nodes.py', 'deploy_smbios_autoconfig', 'ssh-exec'): (2, 'client'),
    ('pegaprox/api/nodes.py', 'get_smbios_autoconfig_status_all', 'ssh-exec'): (2, 'client'),
    ('pegaprox/api/nodes.py', 'deploy_smbios_autoconfig_all', 'ssh-exec'): (1, 'client'),
    ('pegaprox/api/nodes.py', 'starlvm_plugin_status._probe', 'ssh-exec'): (1, 'client'),
    ('pegaprox/api/nodes.py', 'run_custom_script._exec_on_node', 'ssh-exec'): (3, 'client'),
    ('pegaprox/api/templates_lib.py', '_run_deploy.run', 'ssh-exec'): (1, 'client'),
    # the clients of routes, from secure_ssh_client
    ('pegaprox/api/storage.py', 'rescan_storage', 'ssh-exec'): (5, 'client'),
    ('pegaprox/api/vms.py', 'test_node_connection', 'ssh-paramiko'): (1, 'read'),
    ('pegaprox/api/vms.py', 'test_node_connection', 'ssh-exec'): (4, 'read'),
    ('pegaprox/api/vms.py', 'join_node_to_cluster', 'ssh-exec'): (2, 'client'),
    ('pegaprox/api/vms.py', 'remove_node_from_cluster', 'ssh-exec'): (3, 'client'),
    # a file from a backup into a running container, pct exec on stdin, on a client from
    # the guarded _ssh_connect at the node's own address (#1139)
    ('pegaprox/api/vms.py', 'restore_backup_file', 'ssh-exec'): (1, 'client'),
    # `id -u` on the guarded client, the shutdown on a channel of its transport after
    # guard_ssh (see test_a_channel_of_a_transport_asks_guard_ssh_first)
    ('pegaprox/api/vms.py', 'node_action_api', 'ssh-exec'): (5, 'guard'),
    # the join fingerprint is read through PegaProxManager.tls_fingerprint above (#1087)
    # consoles
    ('pegaprox/api/vms.py', 'node_shell_websocket_proxy', 'ssh-paramiko'): (1, 'console'),
    ('pegaprox/api/vms.py', 'node_shell_websocket_proxy', 'ssh-exec'): (1, 'console'),
    ('pegaprox/api/vms.py', 'vnc_poll', 'http-urllib'): (2, 'console'),
    ('pegaprox/api/vms.py', 'handle_vnc_websocket', 'http-urllib'): (2, 'console'),
    ('pegaprox/api/vms.py', 'handle_vnc_websocket', 'ws'): (1, 'console'),
    ('pegaprox/api/vms.py', 'vnc_websocket_proxy', 'http-urllib'): (2, 'console'),
    ('pegaprox/api/vms.py', 'vnc_websocket_proxy', 'ws'): (1, 'console'),
    ('pegaprox/api/vms.py', 'start_vnc_websocket_server.vnc_handler._do_urlopen', 'http-urllib'): (1, 'console'),
    ('pegaprox/api/vms.py', 'get_termproxy_ticket_api', 'http-urllib'): (2, 'console'),
    ('pegaprox/api/vms.py', 'start_vnc_websocket_server', 'subprocess'): (2, 'local'),
    ('pegaprox/api/vms.py', 'start_ssh_websocket_server', 'subprocess'): (3, 'local'),
    ('pegaprox/utils/vnc_tunnel.py', 'SshVncTunnelPool._get_or_create_client', 'ssh-paramiko'): (1, 'console'),
    ('pegaprox/utils/vnc_tunnel.py', 'TunnelEndpoint._accept_loop', 'ssh-exec'): (1, 'console'),
    ('pegaprox/utils/vnc_tunnel.py', '_ssh_server._serve_one', 'ssh-paramiko'): (1, 'console'),
    ('pegaprox/api/vms.py', '_screenshot_via_rfb', 'ws'): (1, 'console'),
    ('pegaprox/api/vms.py', 'vnc_poll', 'ws'): (1, 'console'),
    ('pegaprox/utils/vnc_tunnel.py', '<module>', 'socket'): (2, 'console'),
    ('pegaprox/utils/vnc_tunnel.py', 'SshVncTunnelPool.acquire', 'socket'): (1, 'console'),
    ('pegaprox/utils/vnc_tunnel.py', '_SshServer.check_channel_direct_tcpip_request', 'socket'): (1, 'console'),
    ('pegaprox/utils/vnc_tunnel.py', '_drive', 'socket'): (1, 'console'),
    ('pegaprox/utils/vnc_tunnel.py', '_echo_server', 'socket'): (1, 'console'),
    ('pegaprox/utils/vnc_tunnel.py', '_ssh_server', 'socket'): (1, 'console'),
    # this host
    ('pegaprox/api/settings.py', '_detect_install_method', 'subprocess'): (1, 'local'),
    ('pegaprox/api/settings.py', 'perform_pegaprox_update', 'subprocess'): (7, 'local'),
    # systemctl for the update, the rollback and the restart button
    ('pegaprox/api/settings.py', '_restart_through_systemd', 'subprocess'): (3, 'local'),
    ('pegaprox/api/settings.py', 'generate_support_bundle', 'subprocess'): (1, 'local'),
    ('plugins/client_portal/__init__.py', '_vm_snapshots', 'subprocess'): (1, 'local'),
    ('pegaprox/core/manager.py', 'PegaProxManager._get_pegaprox_server_ip', 'socket'): (1, 'local'),
    ('pegaprox/app.py', '_create_listener', 'socket'): (1, 'local'),
    ('pegaprox/app.py', '_start_http_redirect', 'socket'): (1, 'local'),
    ('pegaprox/app.py', '_test_ipv6_available', 'socket'): (1, 'local'),
    # the listening socket of the console websocket servers (`sock_cls = socket.socket`)
    ('pegaprox/utils/concurrent.py', 'gevent_listen_socket', 'socket'): (3, 'local'),
    ('pegaprox/background/syslog_server.py', '_tcp_listener', 'socket'): (1, 'local'),
    ('pegaprox/background/syslog_server.py', '_udp_listener', 'socket'): (1, 'local'),
    # outside the clusters
    ('pegaprox/api/settings.py', 'check_pegaprox_update', 'http-direct'): (1, 'external'),
    ('pegaprox/api/settings.py', 'perform_pegaprox_update', 'http-direct'): (5, 'external'),
    ('pegaprox/api/settings.py', 'get_pegaprox_changelog', 'http-direct'): (1, 'external'),
    ('pegaprox/api/settings.py', '_get_healed_sponsor', 'http-direct'): (1, 'external'),
    ('pegaprox/background/alerts.py', 'check_update_available_alert', 'http-direct'): (1, 'external'),
    ('pegaprox/background/site_recovery.py', '_fire_webhook', 'http-direct'): (1, 'external'),
    ('pegaprox/utils/webhooks.py', '_post_ntfy', 'http-direct'): (1, 'external'),
    ('pegaprox/utils/webhooks.py', 'send_to_channel', 'http-direct'): (1, 'external'),
    ('plugins/notifications/__init__.py', '_send_ntfy', 'http-direct'): (1, 'external'),
    ('pegaprox/utils/oidc.py', 'get_oidc_endpoints', 'http-direct'): (1, 'external'),
    ('pegaprox/utils/oidc.py', 'oidc_exchange_code', 'http-direct'): (1, 'external'),
    ('pegaprox/utils/oidc.py', 'oidc_get_user_info', 'http-direct'): (2, 'external'),
    ('pegaprox/utils/oidc.py', 'oidc_get_user_groups_ex', 'http-direct'): (1, 'external'),
    ('pegaprox/api/auth.py', 'oidc_test_connection', 'http-direct'): (2, 'external'),
    ('pegaprox/core/acme.py', '_signed_request', 'http-direct'): (1, 'external'),
    ('pegaprox/core/acme.py', '_get_nonce', 'http-direct'): (1, 'external'),
    ('pegaprox/core/acme.py', '_cloudflare_api', 'http-direct'): (1, 'external'),
    ('pegaprox/core/acme.py', '_create_order', 'http-direct'): (1, 'external'),
    ('pegaprox/api/siem.py', '_http_post', 'http-urllib'): (1, 'external'),
    ('pegaprox/api/push.py', '_send_one', 'http-urllib'): (1, 'external'),
    ('pegaprox/app.py', 'download_static_files', 'http-urllib'): (3, 'external'),
    ('pegaprox/utils/email.py', 'send_email', 'smtp'): (2, 'external'),
    ('pegaprox/api/siem.py', '_send_syslog', 'socket'): (2, 'external'),
    # the group, and the witness calling its members
    ('pegaprox/core/ha.py', '_new_session', 'http-session'): (1, 'peer'),
    # the kept connections of the lease calls (_LeaseLink), to members only
    ('pegaprox/core/ha.py', '_LeaseLink._connect', 'socket'): (1, 'peer'),
    ('pegaprox/witness.py', 'https_call', 'http-session'): (1, 'peer'),
    # the health check of a witness: its own port
    ('pegaprox/witness.py', 'cmd_health', 'socket'): (1, 'local'),
    # and its own port at the address it paired with (the other socket only binds, to
    # tell an address of this host)
    ('pegaprox/witness.py', '_dial_own', 'socket'): (2, 'local'),
}

VERDICTS = {'guard', 'client', 'console', 'login', 'read', 'local', 'external', 'peer', 'unused'}


def test_every_exit_is_in_the_inventory():
    found = _scan()
    new = sorted(k for k in found if k not in EXITS)
    assert not new, (
        'A call leaves this process where the inventory does not know it: '
        + '; '.join(f'{f}:{q} ({k}) x{found[(f, q, k)]}' for f, q, k in new)
        + '. If it can change a cluster, a node or a BMC, send it through a guarded exit '
          '(pegaprox/core/ha_transport.py: guard_session, guard_client, guard_xapi, '
          'guard_soap, guard_http, guard_ssh, node_cmd) and list it as "guard"; '
          'otherwise list it in EXITS with the verdict that says why it needs none.')
    gone = sorted(k for k in EXITS if k not in found)
    assert not gone, f'listed exits that are gone - take them out of EXITS: {gone}'


def test_the_count_of_each_exit_is_the_one_listed():
    found = _scan()
    moved = {k: (found[k], EXITS[k][0]) for k in EXITS if k in found and found[k] != EXITS[k][0]}
    assert not moved, (f'more or fewer calls than listed (found, listed): {moved} - check '
                       'each new one as the first one was checked, then fix the count')


def test_the_inventory_counts_what_the_report_says():
    assert {v for _n, v in EXITS.values()} <= VERDICTS
    by = Counter()
    for (_f, _q, kind), (n, verdict) in EXITS.items():
        by[verdict] += n
    # S4 with the witness and the lease link, and the connection check, the three restarts
    # asking systemctl in one helper, the join fingerprint read through tls_fingerprint:
    # 258 calls out of this process, 153 (function, kind) pairs in 139 functions; 46 of
    # them guarded at the exit and 85 execs on a client from a guarded factory. No route
    # relies on the write gate alone any more
    assert sum(n for n, _v in EXITS.values()) == 258 and len(EXITS) == 153
    assert len({(f, q) for f, q, _k in EXITS}) == 139
    assert by['guard'] == 46 and by['client'] == 85


@pytest.mark.parametrize('key', sorted(k for k, v in EXITS.items() if v[1] == 'guard'),
                         ids=lambda k: f'{k[1]}-{k[2]}')
def test_a_guarded_exit_asks_the_guard_in_the_same_function(key):
    rel, qualname, kind = key
    func = _func(rel, qualname)
    hooks = {_callee(c) for c in _own_calls(func)} & GUARD_HOOKS
    if qualname == 'node_cmd' or kind == 'http-guarded':
        hooks.add(kind)           # it is the guard
    if not hooks and '.' in qualname:
        # a helper nested in the exit (the socket _ssh_exec connects with): the function
        # around it asked before it runs
        outer = _func(rel, qualname.rsplit('.', 1)[0])
        hooks = {_callee(c) for c in _own_calls(outer)} & GUARD_HOOKS
    assert hooks, (f'{rel}:{qualname} is listed as guarded but asks no guard hook - put one of '
                   f'{sorted(GUARD_HOOKS)} in front of the {kind} call')


# the factories a "client" exec takes its client from; each hands out a guarded client
CLIENT_FACTORIES = (
    ('pegaprox/core/manager.py', 'PegaProxManager._ssh_connect'),
    ('pegaprox/core/pbs.py', 'PBSManager._ssh_connect'),
    ('pegaprox/core/xcpng.py', 'XcpngManager._ssh_connect'),
    ('pegaprox/core/xhm.py', '_connect_ssh'),
    ('pegaprox/utils/ssh_security.py', 'secure_ssh_client'),
)


@pytest.mark.parametrize('rel,qualname', CLIENT_FACTORIES)
def test_every_client_a_factory_hands_out_is_guarded(rel, qualname):
    func = _func(rel, qualname)
    returns = [n for n in _parents(func) if isinstance(n, ast.Return) and n.value is not None
               and not _nested(n, _parents(func), func)]
    handed = [r for r in returns if not (isinstance(r.value, ast.Constant) and r.value.value is None)
              and not (isinstance(r.value, ast.Tuple) and isinstance(r.value.elts[0], ast.Constant))]
    assert handed, f'{qualname} hands out nothing any more - update CLIENT_FACTORIES'
    for r in handed:
        value = r.value.elts[0] if isinstance(r.value, ast.Tuple) else r.value
        assert isinstance(value, ast.Call) and _callee(value) == 'guard_client', \
            f'{rel}:{qualname} line {r.lineno} hands out a client without ha_transport.guard_client()'


def test_a_channel_of_a_transport_asks_guard_ssh_first():
    """A channel opened on a client's transport (transport.open_session()) is not the
    client: what is sent on it goes past guard_client. The function asks guard_ssh()
    right before it opens one, with no sleep in between (a node reboot was sent on such
    a channel after the lease had ended)."""
    opens = [(rel, q, f, c) for rel in _files() for q, f in _functions(_tree(rel))
             for c in _own_calls(f) if _callee(c) == 'open_session']
    assert opens, 'no channel is opened on a transport any more - drop this rule'
    for rel, q, f, c in opens:
        assert _confirmed(c, _parents(f), f, {'guard_ssh'}), (
            f'{rel}:{q} line {c.lineno} opens a channel on a transport without '
            'ha_transport.guard_ssh() right before it: what it sends there goes out unasked')


def test_the_channel_rule_tells_an_asked_channel_from_one_that_is_not():
    """Counterproof for the rule above."""
    src = '''
def asked(ssh, ip):
    t = ssh.get_transport()
    ha_transport.guard_ssh(ip, 'shutdown')
    ch = t.open_session()
def asked_too_late(ssh, ip):
    ch = ssh.get_transport().open_session()
    ha_transport.guard_ssh(ip, 'shutdown')
def asked_before_a_sleep(ssh, ip):
    ha_transport.guard_ssh(ip, 'shutdown')
    time.sleep(2)
    ch = ssh.get_transport().open_session()
'''
    tree = ast.parse(src)
    got = {q: _confirmed(next(c for c in _own_calls(f) if _callee(c) == 'open_session'),
                         _parents(f), f, {'guard_ssh'}) for q, f in _functions(tree)}
    assert got == {'asked': True, 'asked_too_late': False, 'asked_before_a_sleep': False}


def test_the_scan_tells_an_exit_from_anything_else():
    """Counterproof: the scan finds what it is meant to find."""
    src = '''
import requests, subprocess, paramiko
def f(s):
    requests.post(u)
    s.post(u)
    subprocess.run(['ssh', 'h', 'x'])
    paramiko.SSHClient()
    c.exec_command('x')
    XenAPI.Session(u)
    SmartConnect(host=h)
    log.post_something()
'''
    tree = ast.parse(src)
    kinds = sorted(_kind(c) for c in ast.walk(tree) if isinstance(c, ast.Call) and _kind(c))
    assert kinds == ['http-direct', 'soap', 'ssh-exec', 'ssh-paramiko', 'subprocess', 'xapi']
    # an import under another name is still the same exit, in the function that imports
    # it, and a variable of that name elsewhere is none
    src = '''
import socket as _s
def g():
    import requests as _r
    _r.put(u)
    _s.socket()
def h(_r):
    _r.get('data')
'''
    tree = ast.parse(src)
    module, scopes = _scopes(tree)
    got = {}
    for q, f in _functions(tree):
        got[q] = sorted(_kind(c, scopes[id(f)]) for c in _own_calls(f) if _kind(c, scopes[id(f)]))
    assert got == {'g': ['http-direct', 'socket'], 'h': []}


def test_the_scan_sees_each_shape_of_a_write_an_attack_on_it_tried():
    """The review of S4 put unguarded writes into the code in shapes the first scan did not
    see. Each of these is found now, as the exit it is; what the scan still cannot see is
    in the docstring of this file (a getattr() whose name is worked out at run time
    stands for it here)."""
    src = '''
import urllib3
import http.client
import requests
from concurrent.futures import ThreadPoolExecutor
send = requests.post
def pool():
    urllib3.PoolManager(cert_reqs='CERT_NONE').request('POST', u)
def conn():
    http.client.HTTPSConnection('10.0.0.1', 8006).request('POST', p)
def by_name():
    getattr(requests, 'post')(u)
def assigned_at_module_level():
    send(u)
def assigned_here():
    put = requests.put
    put(u)
def in_a_lambda():
    import requests as _r
    ThreadPoolExecutor(2).submit(lambda: _r.post(u))
def by_a_name_worked_out(verb):
    getattr(requests, verb)(u)
'''
    tree = ast.parse(src)
    module, scopes = _scopes(tree)
    got = {q: sorted(k for k in (_kind(c, scopes[id(f)]) for c in _own_calls(f, lambdas=True)) if k)
           for q, f in _functions(tree)}
    assert got == {'pool': ['http-urllib3'], 'conn': ['http-client'], 'by_name': ['http-direct'],
                   'assigned_at_module_level': ['http-direct'], 'assigned_here': ['http-direct'],
                   'in_a_lambda': ['http-direct'], 'by_a_name_worked_out': []}
    # a module next to pegaprox/ is read as well; the tests and a virtualenv are not
    files = _files()
    assert 'pegaprox_multi_cluster.py' in files
    assert not [f for f in files if f.startswith(('tests/', 'venv/', '.'))]


# --- every background start ------------------------------------------------------------------

_STARTS = {'Thread', 'spawn', 'spawn_later', 'Timer', '_in_background', 'start_new_thread'}


def _starts():
    found = Counter()
    for rel in _files():
        tree = _tree(rel)
        inside = set()
        for q, f in _functions(tree):
            for c in _own_calls(f, lambdas=True):
                inside.add(id(c))
                if _callee(c) in _STARTS and _dotted(c.func) not in ('pool.spawn', '_pool.spawn',
                                                                     'GEVENT_POOL.spawn'):
                    found[(rel, q)] += 1
        for c in ast.walk(tree):
            if isinstance(c, ast.Call) and id(c) not in inside and _callee(c) in _STARTS:
                found[(rel, '<module>')] += 1
    return found


# Verdicts:
#   confirm  an automation; its steps are in CONFIRM_SITES (or it starts none itself)
#   job      a user job or a fan-out of HA agent work: started through ha.as_job, so each
#            call it sends asks for the lease at the exit
#   read     reads, DB, mail or the UI only; nothing it reaches changes a cluster
#   carry    a fan-out helper; it carries the caller's token (ha.carry)
#   console  a console
#   lease    the lease, the watch and the restart of ha.py itself
#   local    this host only (a restart of the service, syslog, the ACME loop)
AUTOMATIONS = {
    ('pegaprox/api/clusters.py', 'update_ha_config'): (2, 'job'),
    ('pegaprox/api/clusters.py', 'trigger_balance_now'): (1, 'confirm'),
    ('pegaprox/api/clusters.py', 'install_self_fence_agent'): (1, 'job'),
    ('pegaprox/api/clusters.py', 'uninstall_self_fence_agent'): (1, 'job'),
    ('pegaprox/api/dr_drill.py', 'start_drill'): (1, 'job'),
    ('pegaprox/api/drift.py', 'start_scanner'): (1, 'read'),
    # the replication and backup reads behind the Prometheus series, API GETs only
    ('pegaprox/api/metrics_exporter.py', '_spawn'): (1, 'read'),
    # the node network configs behind the transfer network view, API GETs only
    ('pegaprox/core/transfer_net.py', '_spawn'): (1, 'read'),
    ('pegaprox/api/groups.py', 'trigger_xclb_balance_now'): (1, 'confirm'),
    ('pegaprox/api/multi_sdn.py', 'start_scanner'): (1, 'confirm'),
    ('pegaprox/api/realtime.py', 'update_sse_subscription'): (1, 'read'),
    ('pegaprox/api/reports.py', '<module>'): (2, 'read'),
    ('pegaprox/api/schedules.py', 'execute_scheduled_rolling_update'): (1, 'job'),
    ('pegaprox/api/schedules.py', 'start_scheduler'): (1, 'confirm'),
    ('pegaprox/api/settings.py', 'perform_pegaprox_update'): (1, 'local'),
    ('pegaprox/api/settings.py', 'rollback_pegaprox_update'): (1, 'local'),
    ('pegaprox/api/settings.py', 'restart_server'): (1, 'local'),
    # the worker of a rolling update, for a start and for a Continue after a restart
    ('pegaprox/api/settings.py', '_launch_rolling_update'): (1, 'job'),
    ('pegaprox/api/siem.py', 'start_worker'): (1, 'read'),
    ('pegaprox/api/site_recovery.py', '_safe_spawn_failover'): (1, 'job'),
    ('pegaprox/api/snapshots.py', 'start_scheduler'): (1, 'confirm'),
    ('pegaprox/api/snapshots.py', 'run_policy_now'): (1, 'confirm'),
    ('pegaprox/api/storage.py', '<module>'): (1, 'confirm'),
    ('pegaprox/api/storage.py', 'iso_sync_trigger'): (1, 'job'),
    ('pegaprox/api/storage.py', 'iso_sync_all'): (1, 'job'),
    ('pegaprox/api/templates_lib.py', 'deploy'): (1, 'job'),
    ('pegaprox/api/oci_catalog.py', '_spawn'): (1, 'job'),
    ('pegaprox/api/vms.py', 'download_iso_from_url'): (1, 'read'),
    ('pegaprox/api/vms.py', 'join_node_to_cluster'): (1, 'read'),
    ('pegaprox/api/vms.py', 'remove_node_from_cluster'): (1, 'read'),
    ('pegaprox/api/vms.py', 'run_cross_cluster_replication'): (1, 'job'),
    ('pegaprox/api/vms.py', 'start_vnc_websocket_server'): (1, 'console'),
    ('pegaprox/api/vms.py', 'start_ssh_websocket_server'): (1, 'console'),
    ('pegaprox/api/vms.py', 'node_shell_websocket_proxy'): (1, 'console'),
    ('pegaprox/api/vms.py', 'handle_vnc_websocket'): (1, 'console'),
    ('pegaprox/api/vms.py', 'vnc_websocket_proxy'): (1, 'console'),
    ('pegaprox/app.py', '_start_gevent_server.signal_handler'): (1, 'local'),
    ('pegaprox/core/ha.py', 'pull_soon'): (1, 'peer'),
    # the lease loop, the etag tick and when_active (the deferred boot gates)
    ('pegaprox/core/ha.py', '_lease_spawn'): (1, 'lease'),
    ('pegaprox/api/vms.py', 'cross_cluster_migrate_api'): (1, 'job'),
    ('pegaprox/api/vmware.py', 'start_vmware_migration'): (1, 'job'),
    ('pegaprox/api/xhm.py', 'xhm_start'): (1, 'job'),
    ('pegaprox/app.py', 'main'): (3, 'local'),
    # the batch restore runs its restores in ha.as_job, like the server-side bulk migration
    ('pegaprox/core/batch_restore.py', 'launch'): (1, 'job'),
    ('pegaprox/background/alerts.py', 'start_alert_thread'): (1, 'read'),
    ('pegaprox/background/broadcast.py', 'broadcast_resources_loop'): (4, 'read'),
    ('pegaprox/background/broadcast.py', 'start_broadcast_thread'): (1, 'read'),
    ('pegaprox/background/cross_cluster_lb.py', 'run_cross_cluster_balance_check'): (1, 'job'),
    ('pegaprox/background/cross_cluster_lb.py', 'start_cross_cluster_lb_thread'): (1, 'confirm'),
    ('pegaprox/background/cross_cluster_replication.py', '_xcrepl_loop'): (1, 'job'),
    ('pegaprox/background/cross_cluster_replication.py', 'start_cross_cluster_replication_thread'): (1, 'confirm'),
    ('pegaprox/background/guest_index.py', 'start_guest_index_thread'): (1, 'read'),
    ('pegaprox/background/metrics.py', 'start_metrics_collector'): (1, 'read'),
    ('pegaprox/background/password_expiry.py', 'start_password_expiry_thread'): (1, 'read'),
    ('pegaprox/background/scheduler.py', 'start_scheduler_thread'): (1, 'confirm'),
    # the weekly restore tests: the loop confirms each test, the run is a job of its own
    ('pegaprox/background/restore_tests.py', 'start_restore_test_thread'): (1, 'confirm'),
    ('pegaprox/background/restore_tests.py', 'tick'): (1, 'job'),
    ('pegaprox/background/site_recovery.py', '_migrate_vm_cross_cluster'): (1, 'job'),
    ('pegaprox/background/site_recovery.py', 'start_heartbeat'): (1, 'confirm'),
    ('pegaprox/background/syslog_server.py', '_tcp_listener'): (1, 'local'),
    ('pegaprox/background/syslog_server.py', '_syslog_loop'): (3, 'local'),
    ('pegaprox/background/syslog_server.py', 'start_syslog_server'): (1, 'local'),
    ('pegaprox/core/backup_verify.py', 'start_verification'): (1, 'job'),
    # a bulk migration of a user, one guest after another (#952)
    ('pegaprox/core/bulk_migrate.py', 'launch'): (1, 'job'),
    # one SSH login per node after a cluster was added, `sudo -n true` at most (#1136)
    ('pegaprox/core/node_creds.py', 'check_in_background'): (1, 'read'),
    ('pegaprox/core/ha.py', '_later'): (1, 'lease'),
    ('pegaprox/core/ha.py', 'restart_process'): (1, 'lease'),
    ('pegaprox/core/ha.py', '_fan_out'): (1, 'peer'),
    ('pegaprox/core/ha.py', '_in_background'): (1, 'lease'),
    ('pegaprox/core/ha.py', 'start_loop'): (1, 'lease'),
    ('pegaprox/core/ha.py', '_lease_call_spawn'): (2, 'lease'),
    ('pegaprox/core/manager.py', 'PegaProxManager.enter_maintenance_mode'): (1, 'job'),
    ('pegaprox/core/manager.py', 'PegaProxManager.start_ha_monitor'): (4, 'job'),
    ('pegaprox/core/manager.py', 'PegaProxManager.stop_ha_monitor'): (1, 'job'),
    ('pegaprox/core/manager.py', 'PegaProxManager._ha_trigger_recovery'): (1, 'confirm'),
    ('pegaprox/core/manager.py', 'PegaProxManager._ha_redeploy_in_background'): (1, 'job'),
    ('pegaprox/core/manager.py', 'PegaProxManager._ha_storage_heartbeat_init'): (1, 'local'),
    ('pegaprox/core/manager.py', 'PegaProxManager._ha_acquire_recovery_lock'): (1, 'local'),
    ('pegaprox/core/manager.py', 'PegaProxManager.start_node_update'): (3, 'job'),
    ('pegaprox/core/manager.py', 'PegaProxManager._schedule_update_clear'): (2, 'read'),
    ('pegaprox/core/manager.py', 'PegaProxManager.start'): (2, 'confirm'),
    ('pegaprox/core/pbs.py', 'PBSManager.start_update'): (2, 'job'),
    ('pegaprox/core/v2p.py', '_ssh_pipe_transfer'): (1, 'read'),
    ('pegaprox/core/vmware.py', 'load_vmware_servers'): (1, 'read'),
    ('pegaprox/core/xcpng.py', 'XcpngManager.start'): (1, 'confirm'),
    ('pegaprox/core/xcpng.py', 'XcpngManager.start_node_update'): (1, 'job'),
    ('pegaprox/utils/concurrent.py', 'run_per_node'): (1, 'carry'),
    ('pegaprox/utils/concurrent.py', 'gevent_to_thread'): (1, 'console'),
    ('pegaprox/utils/rbac.py', 'get_pool_membership_cache'): (1, 'read'),
    ('pegaprox/utils/realtime.py', 'push_immediate_update'): (1, 'read'),
    ('pegaprox/utils/vnc_polling.py', 'VncPollSession.__init__'): (1, 'console'),
    ('pegaprox/utils/vnc_polling.py', '_start_reaper_once'): (1, 'console'),
    ('pegaprox/utils/vnc_tunnel.py', 'TunnelEndpoint.__init__'): (1, 'console'),
    ('pegaprox/utils/vnc_tunnel.py', '_echo_server'): (1, 'console'),
    ('pegaprox/utils/vnc_tunnel.py', '<module>'): (3, 'console'),
    ('pegaprox/utils/vnc_tunnel.py', '_ssh_server._serve_one'): (1, 'console'),
    ('pegaprox/utils/vnc_tunnel.py', '_ssh_server'): (1, 'console'),
    # the witness process stopping its own server on SIGTERM
    ('pegaprox/witness.py', 'serve.stop'): (1, 'local'),
    # and its upkeep: its own port for its health, the bundle from a member for an update
    ('pegaprox/witness.py', 'serve'): (1, 'peer'),
}


def test_every_background_start_is_in_the_inventory():
    found = _starts()
    new = sorted(k for k in found if k not in AUTOMATIONS)
    assert not new, (
        'A thread or greenlet is started where the inventory does not know it: '
        + '; '.join(f'{f}:{q} x{found[(f, q)]}' for f, q in new)
        + '. If what it runs changes a cluster, either confirm each step '
          '(ha.confirm_step, list the steps in CONFIRM_SITES) or start it through '
          'ha.as_job(fn, what) - then list it in AUTOMATIONS.')
    gone = sorted(k for k in AUTOMATIONS if k not in found)
    assert not gone, f'listed starts that are gone - take them out of AUTOMATIONS: {gone}'
    moved = {k: (found[k], AUTOMATIONS[k][0]) for k in AUTOMATIONS if found.get(k, 0) != AUTOMATIONS[k][0]}
    assert not moved, f'more or fewer starts than listed (found, listed): {moved}'


@pytest.mark.parametrize('key', sorted(k for k, v in AUTOMATIONS.items() if v[1] == 'job'),
                         ids=lambda k: k[1])
def test_a_user_job_is_started_through_as_job(key):
    rel, qualname = key
    calls = _own_calls(_func(rel, qualname))
    assert any(_callee(c) == 'as_job' for c in calls), \
        f'{rel}:{qualname} starts a job that is not wrapped in ha.as_job()'


# What a 'read' start sends to a node: an SSH command and POST /nodes/<n>/execute cannot
# say they only read, and a plain thread carries neither a token nor the job mark of
# whoever started it, so in an automatic group its first such call is refused. It says
# so with `with ha.reading()` around the call, or it is started on ha.carry(fn).
_NODE_SENDS = {'_pve_node_exec', '_node_ssh_exec', '_ssh_run_command', '_ssh_run_command_output',
               '_ssh_run_command_with_key', '_ssh_run_command_with_key_output',
               '_ssh_run_command_with_password', '_ssh_run_command_with_password_output',
               '_ssh_exec', '_ssh_execute', 'exec_command', 'invoke_shell', 'node_cmd', '_ha_agent_ssh'}


def _start_target(call):
    kw = {k.arg: k.value for k in call.keywords}
    name = _callee(call)
    if name == 'Thread':
        return kw.get('target')
    if name == 'Timer':
        return kw.get('function') or (call.args[1] if len(call.args) > 1 else None)
    if name == 'spawn_later':
        return call.args[1] if len(call.args) > 1 else None
    return call.args[0] if call.args else kw.get('target')


def _unread_sends(tree, scope, target, depth=3):
    """The node sends outside `with ha.reading()` that `target` (what a start in the
    function `scope` runs) reaches through the functions of its own file, up to `depth`
    calls down: [(function, call, line)]. None when it is started on ha.carry or
    ha.as_job. Another object's methods (mgr.x) are not followed."""
    by_name = {}
    for q, f in _functions(tree):
        by_name.setdefault(q.rsplit('.', 1)[-1], []).append((q, f))

    def resolve(expr, at):
        if isinstance(expr, ast.Lambda):
            return [('<lambda>', expr)]
        if isinstance(expr, ast.Name):
            named = by_name.get(expr.id, [])
            return ([x for x in named if x[0].startswith(at + '.')]
                    or [x for x in named if '.' not in x[0]] or named)
        if isinstance(expr, ast.Attribute) and isinstance(expr.value, ast.Name) and expr.value.id == 'self':
            return by_name.get(expr.attr, [])
        return []

    if isinstance(target, ast.Call) and _callee(target) in ('carry', 'as_job'):
        return None
    todo, seen, hits = [(q, f, 0) for q, f in resolve(target, scope)], set(), []
    while todo:
        q, f, d = todo.pop()
        if id(f) in seen:
            continue
        seen.add(id(f))
        lam = isinstance(f, ast.Lambda)
        parents = None if lam else _parents(f)
        calls = [n for n in ast.walk(f) if isinstance(n, ast.Call)] if lam else _own_calls(f, lambdas=True)
        for c in calls:
            name = _callee(c)
            if name in _NODE_SENDS:
                if lam or not _in_reading(c, parents, f):
                    hits.append((q, name, c.lineno))
            elif d < depth and (isinstance(c.func, ast.Name) or (
                    isinstance(c.func, ast.Attribute) and isinstance(c.func.value, ast.Name)
                    and c.func.value.id == 'self')):
                todo.extend((x[0], x[1], d + 1) for x in resolve(c.func, q))
    return hits


@pytest.mark.parametrize('key', sorted(k for k, v in AUTOMATIONS.items() if v[1] == 'read'),
                         ids=lambda k: k[1])
def test_a_read_in_the_background_says_it_reads(key):
    rel, qualname = key
    tree = _tree(rel)
    if qualname == '<module>':
        inside = {id(c) for _q, f in _functions(tree) for c in _own_calls(f, lambdas=True)}
        starts = [c for c in ast.walk(tree) if isinstance(c, ast.Call) and id(c) not in inside
                  and _callee(c) in _STARTS]
    else:
        starts = [c for c in _own_calls(_func(rel, qualname), lambdas=True) if _callee(c) in _STARTS]
    for c in starts:
        target = _start_target(c)
        hits = _unread_sends(tree, qualname, target) if target is not None else []
        assert not hits, (f'{rel}:{qualname} starts {ast.unparse(target)} as a read, and it sends to a '
                          f'node outside `with ha.reading()`: {hits} - an automatic leader refuses that '
                          'in a plain thread. Put the reads in ha.reading() (and in READ_SITES) or '
                          'start it on ha.carry(fn)')


def test_the_background_read_rule_finds_a_send_a_helper_makes():
    """Counterproof: a send one helper down is found; one in ha.reading() and a start on
    ha.carry are not."""
    src = '''
def probe(m):
    return _pve_node_exec(m, 'n1', 'stat x')
def watch(m):
    while True:
        probe(m)
def watch_reading(m):
    with ha.reading():
        _pve_node_exec(m, 'n1', 'stat x')
def start(m):
    threading.Thread(target=watch, args=(m,)).start()
    threading.Thread(target=watch_reading, args=(m,)).start()
    threading.Thread(target=ha.carry(watch), args=(m,)).start()
'''
    tree = ast.parse(src)
    func = dict(_functions(tree))['start']
    got = [_unread_sends(tree, 'start', _start_target(c))
           for c in sorted(_own_calls(func), key=lambda c: c.lineno) if _callee(c) == 'Thread']
    assert got == [[('probe', '_pve_node_exec', 3)], [], None]


# --- the steps of design 5.2 -------------------------------------------------------------------

CONFIRM = {'confirm_step', 'confirm_lease'}

# (file, function, the calls that are steps)
CONFIRM_SITES = [
    ('pegaprox/core/manager.py', 'PegaProxManager._ha_recovery_worker',
     ['_ha_ssh_stop_vms_on_node', '_ha_write_poison_pill', '_ha_fence_outside', '_ha_fence_node']),
    ('pegaprox/core/manager.py', 'PegaProxManager._ha_start_vm_on_node',
     ['_ha_try_force_quorum', '_ha_fence_node', '_ha_clear_vm_lock', '_ha_move_vm_config', 'post']),
    ('pegaprox/core/manager.py', 'PegaProxManager._ha_check_restore_quorum',
     ['_ssh_run_command_with_key', '_ssh_run_command', '_ssh_run_command_with_password']),
    ('pegaprox/core/manager.py', 'PegaProxManager.ha_start_moved_vms', ['post']),
    ('pegaprox/core/manager.py', 'PegaProxManager.run_balance_check', ['migrate_vm']),
    ('pegaprox/core/manager.py', 'PegaProxManager._enforce_affinity_rules', ['migrate_vm']),
    # the moves back onto a plb_pin_ node, from the balance cycle and the API (#811)
    ('pegaprox/core/manager.py', 'PegaProxManager.reconcile_proxlb_pins', ['migrate_vm']),
    # the Proxmox HA rules a rolling update switches off, and on again from the daemon loop (#954)
    ('pegaprox/core/manager.py', 'PegaProxManager.suspend_negative_ha_rules', ['_api_put']),
    ('pegaprox/core/manager.py', 'PegaProxManager.restore_suspended_ha_rules', ['_api_put']),
    ('pegaprox/core/manager.py', 'PegaProxManager.get_efficient_snapshots', ['_node_ssh_exec']),
    ('pegaprox/core/xcpng.py', 'XcpngManager.run_balance_check', ['_do_balance_migrate']),
    ('pegaprox/api/storage.py', 'run_auto_storage_balance', ['post']),
    ('pegaprox/background/scheduler.py', 'run_scheduled_tasks', ['execute_scheduled_task']),
    ('pegaprox/background/restore_tests.py', '_run_slot', ['run_verification']),
    ('pegaprox/api/schedules.py', 'check_schedules', ['execute_scheduled_action']),
    ('pegaprox/api/schedules.py', 'execute_scheduled_rolling_update.run_scheduled_update',
     ['enter_maintenance_mode', 'start_node_update']),
    ('pegaprox/api/settings.py', 'run_rolling_update.run_node',
     ['enter_maintenance_mode', 'start_node_update']),
    ('pegaprox/api/snapshots.py', '_execute_policy', ['create_snapshot']),
    ('pegaprox/api/snapshots.py', '_prune', ['delete_snapshot', '_api_delete']),
    ('pegaprox/background/site_recovery.py', 'execute_failover',
     ['_start_replicated_vm', '_migrate_vm_cross_cluster']),
    ('pegaprox/background/cross_cluster_replication.py', '_xcrepl_loop', ['Thread']),
    ('pegaprox/background/cross_cluster_lb.py', 'run_cross_cluster_balance_check',
     ['create_api_token', 'remote_migrate_vm']),
    ('pegaprox/api/multi_sdn.py', '_msdn_scan_once', ['_reconcile_on_cluster']),
]


def _has(node, names):
    return any(isinstance(n, ast.Call) and _callee(n) in names for n in ast.walk(node))


def _is_sleep(node):
    return any(isinstance(n, ast.Call) and _callee(n) == 'sleep' for n in ast.walk(node))


def _parents(func):
    parents, todo = {}, [func]
    while todo:
        node = todo.pop()
        for ch in ast.iter_child_nodes(node):
            parents[ch] = node
            if not isinstance(ch, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                todo.append(ch)
    return parents


def _nested(node, parents, func):
    """Whether `node` sits in a function defined inside `func`."""
    while node is not func:
        node = parents[node]
        if node is not func and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            return True
    return False


def _in_reading(node, parents, func):
    while node is not func:
        node = parents[node]
        if isinstance(node, ast.With) and any(
                isinstance(i.context_expr, ast.Call) and _callee(i.context_expr) == 'reading'
                for i in node.items):
            return True
    return False


def _confirmed(node, parents, func, names=CONFIRM):
    """A step is confirmed when, walking out from it: an `if` around it confirms in its
    test (the step in the body of a yes, or in the else of a `not`), or an earlier
    statement of a block around it confirms, with no sleep after that one. `names` are
    the calls that count as the confirm."""
    child = node
    while child is not func:
        parent = parents[child]
        if isinstance(parent, ast.If) and _has(parent.test, names):
            negated = isinstance(parent.test, ast.UnaryOp) and isinstance(parent.test.op, ast.Not)
            if (child in parent.orelse) if negated else (child in parent.body):
                return True
        for field in ('body', 'orelse', 'finalbody', 'handlers'):
            block = getattr(parent, field, None)
            if isinstance(block, list) and child in block:
                before = block[:block.index(child)]
                for i in range(len(before) - 1, -1, -1):
                    if _has(before[i], names):
                        if not any(_is_sleep(s) for s in before[i + 1:]):
                            return True
                        break
                    if _is_sleep(before[i]):
                        return False
        child = parent
    return False


@pytest.mark.parametrize('rel,qualname,steps', CONFIRM_SITES, ids=[s[1] for s in CONFIRM_SITES])
def test_each_step_of_5_2_asks_for_the_lease_first(rel, qualname, steps):
    func = _func(rel, qualname)
    parents = _parents(func)
    for name in steps:
        calls = [c for c in _own_calls(func) if _callee(c) == name and not _in_reading(c, parents, func)]
        assert calls, f'{qualname} no longer calls {name} - update CONFIRM_SITES'
        for c in calls:
            assert _confirmed(c, parents, func), (
                f'{rel}:{qualname}: {name}() on line {c.lineno} goes out without a confirmed '
                'lease - put `if not ha.confirm_step(...): return` (or break) right before it, '
                'with no sleep in between')


def test_the_recovery_confirms_again_after_each_of_its_waits():
    """Design 5.2: after the 30 s wait for the poison pill and the 10 s for the guests."""
    func = _func('pegaprox/core/manager.py', 'PegaProxManager._ha_recovery_worker')
    for block in (n for n in ast.walk(func) if hasattr(n, 'body') and isinstance(n.body, list)):
        for i, stmt in enumerate(block.body):
            if isinstance(stmt, ast.Expr) and _is_sleep(stmt) and isinstance(stmt.value.args[0], ast.Constant) \
                    and stmt.value.args[0].value in (10, 30):
                nxt = block.body[i + 1] if i + 1 < len(block.body) else None
                assert nxt is not None and _has(nxt, CONFIRM), \
                    f'the {stmt.value.args[0].value} s wait on line {stmt.lineno} is not followed by a confirm'


def test_the_confirm_check_itself_tells_confirmed_from_not():
    """Counterproof for the walker."""
    src = '''
def f():
    if not ha.confirm_step('a'):
        return
    step_a()
    ha.confirm_step('b')
    time.sleep(5)
    step_b()
    if x and ha.confirm_step('c'):
        step_c()
    if not ha.confirm_step('d'):
        pass
    else:
        step_d()
    step_e()
    with ha.reading():
        step_f()
'''
    func = ast.parse(src).body[0]
    parents = _parents(func)
    got = {_callee(c): _confirmed(c, parents, func) for c in _own_calls(func)
           if _callee(c).startswith('step_')}
    assert got == {'step_a': True, 'step_b': False, 'step_c': True, 'step_d': True,
                   'step_e': True, 'step_f': True}
    # step_e is confirmed by 'd' above it; a sleep in between would take that away
    reading = [c for c in _own_calls(func) if _callee(c) == 'step_f'][0]
    assert _in_reading(reading, parents, func)


# --- the reads that pass unasked -----------------------------------------------------------
#
# Every SSH command counts as a change at the exit (design 5.3): the guard cannot tell a
# read from a write. A background read that must not wait for a confirm says what it is
# with `with ha.reading()`, and that is a way past the guard - so each such block is
# listed here, with the calls it is for. A new one fails until it is looked at and added.

READ_SITES = [
    ('pegaprox/core/manager.py', 'PegaProxManager._ha_check_node_via_ssh._try_ssh_ip',
     {'_ssh_run_command_with_key_output': 1, '_ssh_run_command_output': 1,
      '_ssh_run_command_with_password_output': 1}),
    ('pegaprox/core/manager.py', 'PegaProxManager._ha_detect_fence_strategy',
     {'_ssh_run_command_with_key_output': 1, '_ssh_run_command_output': 1,
      '_ssh_run_command_with_password_output': 1}),
    ('pegaprox/core/manager.py', 'PegaProxManager._ha_check_agents.one', {'_ha_agent_ssh': 1}),
    ('pegaprox/core/manager.py', 'PegaProxManager._ha_redeploy_fence_agents.look', {'_ha_agent_ssh': 1}),
    ('pegaprox/core/manager.py', 'PegaProxManager.get_efficient_snapshots', {'_node_ssh_exec': 2}),
    ('pegaprox/core/manager.py', 'PegaProxManager.get_node_sensors', {'_ssh_run_command_output': 2}),
    # the `echo OK` that finds a working address before the guests are stopped
    ('pegaprox/core/manager.py', 'PegaProxManager._ha_ssh_stop_vms_on_node',
     {'_ssh_run_command_output': 1, '_ssh_run_command_with_key_output': 1,
      '_ssh_run_command_with_password_output': 1}),
    # cat of a failed node's guest configs in /etc/pve on another node, before its
    # recovery decides which of them can move
    ('pegaprox/core/manager.py', 'PegaProxManager._ha_read_guest_configs', {'_ssh_node_output': 1}),
    ('pegaprox/core/bmc.py', 'read_node_bmc_inband',
     {'_ssh_run_command_with_key_output': 1, '_ssh_run_command_output': 1,
      '_ssh_run_command_with_password_output': 1}),
    ('pegaprox/utils/vnc_grab.py', 'screendump_to_png', {'_pve_node_exec': 1}),
    # the login check of a cluster just added: a login and `sudo -n true` per node (#1136)
    ('pegaprox/core/node_creds.py', 'check_in_background.run', {'run_check': 1}),
    # the progress of an ESXi import: stat, lvs and the dd log of the target volume, from
    # a plain thread of the import job
    ('pegaprox/core/v2p.py', '_monitor_disk_write.probe', {'_pve_node_exec': 1}),
]


def _reading_blocks():
    found = set()
    for rel in _files():
        for q, f in _functions(_tree(rel)):
            parents = _parents(f)
            for n in parents:
                if isinstance(n, ast.With) and not _nested(n, parents, f) and any(
                        isinstance(i.context_expr, ast.Call) and _callee(i.context_expr) == 'reading'
                        for i in n.items):
                    found.add((rel, q))
    return found


def test_every_read_that_passes_the_guard_is_listed():
    found = _reading_blocks()
    listed = {(rel, q) for rel, q, _calls in READ_SITES}
    new = sorted(found - listed - {('pegaprox/core/ha.py', 'reading')})
    assert not new, (f'`with ha.reading()` in {new}: the calls inside it go out unasked in an '
                     'automatic group. Keep it to reads only and list it in READ_SITES')
    assert not listed - found, f'listed reads that are gone - take them out: {sorted(listed - found)}'


@pytest.mark.parametrize('rel,qualname,calls', READ_SITES, ids=[s[1] for s in READ_SITES])
def test_a_read_that_passes_the_guard_unasked_says_so(rel, qualname, calls):
    func = _func(rel, qualname)
    parents = _parents(func)
    for name, n in calls.items():
        inside = [c for c in _own_calls(func) if _callee(c) == name and _in_reading(c, parents, func)]
        assert len(inside) == n, (f'{rel}:{qualname}: {len(inside)} of the {n} {name}() reads listed sit '
                                  'in `with ha.reading()` - without it an automatic leader refuses them '
                                  'for want of a confirmed step')


# design 5.4: a change inside /etc/pve or corosync wants the lease time of a step left at
# the exit, whatever confirmed before it in the same thread (a same-goal step needs none)
NEED_SITES = [
    ('pegaprox/core/manager.py', 'PegaProxManager._ha_move_vm_config'),
    ('pegaprox/core/manager.py', 'PegaProxManager._ha_try_force_quorum'),
    ('pegaprox/core/manager.py', 'PegaProxManager._ha_check_restore_quorum'),
]
_SSH_STEPS = {'_ssh_run_command', '_ssh_run_command_with_key', '_ssh_run_command_with_password'}


@pytest.mark.parametrize('rel,qualname', NEED_SITES, ids=[s[1] for s in NEED_SITES])
def test_the_ssh_steps_inside_etc_pve_and_corosync_say_their_need(rel, qualname):
    calls = [c for c in _own_calls(_func(rel, qualname)) if _callee(c) in _SSH_STEPS]
    assert calls, f'{qualname} sends no SSH step any more - update NEED_SITES'
    for c in calls:
        need = [k for k in c.keywords if k.arg == 'need']
        assert need and ast.unparse(need[0].value) == 'ha.NEED_STEP', \
            f'{rel}:{qualname} line {c.lineno}: pass need=ha.NEED_STEP to {_callee(c)}()'
