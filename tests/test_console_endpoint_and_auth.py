"""What the console tells PVE: which port it dials, and whose credential it shows.

Four handlers build the same upgrade to PVE's vncwebsocket and all four had
drifted apart. Between them they carried three defects, reported separately:

  #945.1  the main-port handlers reassigned `port` to the vncproxy port and then
          used it as the URL authority, so the upgrade went to :5900
  #956    the standalone handler and the polling fallback hardcoded 8006 and
          ignored a cluster reachable on a forwarded API port
  #945.2  the upgrade always presented a freshly minted login cookie, even when
          reusing the ticket the browser obtained - PVE binds that ticket to the
          asker, so it answered "invalid PVEVNC ticket"
  #955    and on a token-only cluster there is no login to mint at all

They now share _pve_console_ws_path and _pve_console_ws_auth. These tests pin
what those two produce, because that is the part PVE sees.

MK Sep 2026
"""
import ast
import inspect

import pegaprox.api.vms as vms


class _TokenCluster:
    _using_api_token = True
    _api_token = 'root@pam!automation=1e9f0000-0000-0000-0000-00000000abcd'
    _ticket = None


class _PasswordCluster:
    _using_api_token = False
    _api_token = None
    _ticket = 'PVE:root@pam:68D0AA00::signature'


# ── the URL authority ────────────────────────────────────────────────────────

def test_the_vnc_port_stays_out_of_the_authority():
    """The VNC port belongs in the query string. Only there."""
    path = vms._pve_console_ws_path('pve1', 'qemu', 100, 5900, 'TICKET')

    assert path.startswith('/api2/json/nodes/pve1/qemu/100/vncwebsocket')
    assert 'port=5900' in path
    # the caller builds wss://host:<api port><path> - if the VNC port ever leaked
    # into the authority this is where it would show up
    assert not path.startswith('wss://')
    assert ':5900' not in path.split('?')[0]


def test_a_container_uses_the_lxc_endpoint():
    assert '/lxc/105/vncwebsocket' in vms._pve_console_ws_path('n1', 'lxc', 105, 5901, 'T')
    assert '/qemu/105/vncwebsocket' in vms._pve_console_ws_path('n1', 'qemu', 105, 5901, 'T')


def test_the_ticket_is_url_encoded():
    """PVE tickets carry / and + and they must survive the query string."""
    path = vms._pve_console_ws_path('n1', 'qemu', 100, 5900, 'PVEVNC:a/b+c=')
    assert 'vncticket=PVEVNC%3Aa%2Fb%2Bc%3D' in path


def test_no_console_path_hardcodes_the_api_port(_vms_source=None):
    """#956. The four console handlers must take the port from the cluster.

    Read as source rather than executed: these handlers need a live PVE to run,
    and the property is 'no literal 8006 in the URL the handler dials'.
    """
    src = inspect.getsource(vms)
    tree = ast.parse(src)
    offenders = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name not in ('vnc_handler', 'vnc_websocket_proxy',
                             'handle_vnc_websocket', 'vnc_poll', '_screenshot_via_rfb'):
            continue
        for sub in ast.walk(node):
            if isinstance(sub, ast.Constant) and sub.value == 8006:
                # the one allowed use is a defensive default when the manager has
                # no api_port attribute at all
                line = src.split('\n')[sub.lineno - 1]
                if 'getattr' in line:
                    continue
                offenders.append(f'{node.name}:{sub.lineno}')
    assert not offenders, f'console paths still hardcode 8006: {offenders}'


# ── whose credential goes on the wire ────────────────────────────────────────

def test_a_token_cluster_presents_its_token_when_reusing_the_browser_ticket():
    """#955. There is no password to log in with, and the vncproxy ticket the
    browser holds was minted under the token, so the token is what PVE expects."""
    h = vms._pve_console_ws_auth(_TokenCluster(), 'pve:8006',
                                 fresh_ticket=None, reuse_manager_auth=True)

    assert h['Authorization'] == f'PVEAPIToken={_TokenCluster._api_token}'
    assert 'Cookie' not in h, 'a token cluster must not fall back to a cookie'


def test_a_password_cluster_presents_the_managers_own_ticket_when_reusing():
    """#945.2. Not a freshly minted one - PVE bound the vncproxy ticket to the
    manager's session, and a second login produces a different one."""
    h = vms._pve_console_ws_auth(_PasswordCluster(), 'pve:8006',
                                 fresh_ticket='A-DIFFERENT-FRESH-TICKET',
                                 reuse_manager_auth=True)

    assert h['Cookie'] == f'PVEAuthCookie={_PasswordCluster._ticket}'
    assert 'A-DIFFERENT-FRESH-TICKET' not in h['Cookie']


def test_without_passthrough_the_fresh_ticket_is_the_right_one():
    """The counterweight: when WE issued the vncproxy call, our own ticket is
    exactly what PVE expects, and nothing here may break that."""
    h = vms._pve_console_ws_auth(_PasswordCluster(), 'pve:8006',
                                 fresh_ticket='OURS', reuse_manager_auth=False)
    assert h['Cookie'] == 'PVEAuthCookie=OURS'
    assert 'Authorization' not in h


def test_the_host_header_names_what_we_actually_dial():
    h = vms._pve_console_ws_auth(_TokenCluster(), '127.0.0.1:43111',
                                 fresh_ticket=None, reuse_manager_auth=True)
    assert h['Host'] == '127.0.0.1:43111'


def test_a_cluster_with_neither_token_nor_ticket_sends_no_credential():
    """Fail closed rather than inventing one. PVE answers 401 and the operator
    gets a real error instead of a confusing one."""
    class _Bare:
        _using_api_token = False
        _api_token = None
        _ticket = None
    h = vms._pve_console_ws_auth(_Bare(), 'pve:8006', fresh_ticket=None,
                                 reuse_manager_auth=True)
    assert 'Authorization' not in h and 'Cookie' not in h


# ── the invariant that actually broke ────────────────────────────────────────

def test_the_api_port_variable_is_never_reassigned_in_a_console_handler():
    """#945.1 in one line.

    Each console handler starts with `host, port = manager.host, manager.api_port`
    and then needs `port` to still mean that when it builds the URL authority,
    several dozen lines later. Two of them rebound it to the vncproxy port in
    between, so the upgrade was dialled against :5900.

    Asserted as "port is bound exactly once per handler", which is the property
    the bug violated, rather than by looking for the fix.
    """
    src = inspect.getsource(vms)
    tree = ast.parse(src)
    handlers = ('vnc_handler', 'vnc_websocket_proxy', 'handle_vnc_websocket', 'vnc_poll')
    rebinds = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name not in handlers:
            continue
        lines = [n.lineno for n in ast.walk(node)
                 if isinstance(n, ast.Name) and n.id == 'port'
                 and isinstance(n.ctx, ast.Store)]
        if len(lines) > 1:
            rebinds[node.name] = lines
    assert not rebinds, (
        'the API port is rebound inside a console handler, so whatever it means '
        f'at the URL is not manager.api_port any more: {rebinds}')


# --- #956, the half that lives in the terminal subprocess --------------------
#
# The VNC handlers were the visible part. The termproxy path builds its own PVE
# websocket URL inside the generated subprocess script, and that one still pinned
# 8006 - so on grupoaxium's tunnel (X:18006 open, X:8006 closed) the LXC terminal
# would keep failing after the console started working.

def _vms_source():
    import pegaprox.api.vms as vms
    import inspect
    return inspect.getsource(vms)


def test_the_termproxy_does_not_pin_8006_for_its_pve_upgrade():
    import re
    src = _vms_source()
    bad = re.findall(r'wss://\{[A-Za-z_]+\}:8006', src)
    assert not bad, f"termproxy still builds a fixed-port PVE url: {bad}"


def test_both_places_that_describe_a_cluster_to_the_subprocess_carry_the_port():
    """The subprocess learns about its cluster from cluster_context (ws-token flow)
    or from /api/internal/cluster-creds (legacy cookie flow). A port carried by only
    one of them is a bug that shows up on exactly one of the two login paths."""
    import inspect
    import pegaprox.api.auth as authmod
    import pegaprox.api.realtime as rt
    creds = inspect.getsource(authmod.get_cluster_creds_internal)
    assert "'api_port'" in creds, 'cluster-creds does not report the API port'
    assert "'api_port'" in inspect.getsource(rt), 'cluster_context does not carry the API port'


def test_cluster_creds_reports_the_port_the_cluster_is_actually_on(api, seed):
    # this endpoint authenticates off the session COOKIE (it is called by the
    # subprocess, which has no header to send), so it is driven directly here
    # instead of through the header-based client the other tests use
    seed.user('root', role='admin')
    mgr = api.make_fake_manager()
    mgr.host = '10.77.10.55'
    mgr.api_port = 18006
    mgr.get_nodes.return_value = {'success': True, 'nodes': []}
    mgr.config.ssh_port = 22
    mgr.mint_console_auth_ticket.return_value = None
    api.set_manager('cluster_1', mgr)

    from pegaprox.utils.auth import create_session
    with api.app.test_request_context('/'):
        sid = create_session('root', 'admin')
    client = api.app.test_client()
    client.set_cookie('session', sid, domain='localhost')
    r = client.get('/api/internal/cluster-creds/cluster_1')
    assert r.status_code == 200, r.data
    assert r.get_json().get('api_port') == 18006


def test_no_handler_reads_a_certificate_from_a_port_it_was_not_told_about():
    """#956 again, three floors down. get_join_info and join_node_to_cluster both
    unpack `manager.api_port` into `port`, use it for the HTTP call, and then open a
    TLS socket to the SAME host on a literal 8006 to read the fingerprint. On a
    cluster reached through a tunnel there is nothing on 8006, so the join flow has
    no fingerprint and `pvecm add --fingerprint` cannot be built."""
    import ast
    import inspect
    import pegaprox.api.vms as vms
    tree = ast.parse(inspect.getsource(vms))
    bad = []
    for fn in ast.walk(tree):
        if not isinstance(fn, ast.FunctionDef):
            continue
        binds_port = any(
            isinstance(n, ast.Assign) and 'api_port' in ast.unparse(n.value)
            for n in ast.walk(fn))
        if not binds_port:
            continue
        for call in ast.walk(fn):
            if (isinstance(call, ast.Call)
                    and isinstance(call.func, ast.Attribute)
                    and call.func.attr == 'create_connection'
                    and call.args
                    and '8006' in ast.unparse(call.args[0])):
                bad.append(f"{fn.name}: {ast.unparse(call.args[0])}")
    assert not bad, ('a literal 8006 where the cluster\'s own port is in scope: '
                     + '; '.join(bad))
