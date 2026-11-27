"""The PVE session ticket of the cluster account stays in this process, and a caller
confined to single VMs or a pool on a cluster gets no root shell on its nodes.

/api/ws/token/validate used to put a freshly minted ticket of the cluster's own account
(root@pam by default) into its answer for anyone holding a ws token, and any signed-in
account can mint one. Then only the SSH console server on port+2 got that cluster
context, proving itself with a per-start secret. The server is gone, the consoles are
routes of this app and mint the ticket next to the PVE socket, and validate hands the
context to nobody: it says whether the token is good, and nothing else.

The node shell had three exits besides /api/internal/cluster-creds (gone as well), and
only that one refused a caller who reaches the cluster through a VM ACL or a pool grant.

MK Oct 2026
"""
import json
import secrets

import pytest

TICKET = 'PVE:root@pam:65F00000::sig'


def _mgr(api):
    mgr = api.make_fake_manager('cluster_1')
    mgr.host = '10.0.0.1'
    mgr.api_port = 8006
    mgr.config.fallback_hosts = []
    mgr.config.ssh_port = 22
    mgr.config.name = 'c1'
    mgr._ssl_verify = False
    mgr.mint_console_auth_ticket.return_value = TICKET
    mgr.get_node_shell_ticket.return_value = {'success': True, 'ticket': 'PVEVNC:x', 'port': 5900}
    api.set_manager('cluster_1', mgr)
    return mgr


def _validate(api, token, extra='', headers=None):
    return api.anon().get(f'/api/ws/token/validate?token={token}&cluster_id=cluster_1{extra}',
                          headers=headers or {})


def _console_server():
    """The header the SSH console server sent with its secret. It opens nothing now."""
    return {'X-PegaProx-Console-Server': secrets.token_urlsafe(32)}


# --- the ticket ------------------------------------------------------------------------

@pytest.mark.parametrize('who', ['viewer', 'admin'])
def test_a_ws_token_alone_gets_no_ticket(api, seed, who):
    mgr = _mgr(api)
    user = seed.user('vic', role=who)
    tok = api.as_user(user).post('/api/ws/token', json={}).get_json()['token']
    r = _validate(api, tok)
    assert r.status_code == 200, r.data
    body = r.get_json()
    assert body['valid'] is True and 'cluster_context' not in body
    assert TICKET not in r.get_data(as_text=True)
    # and no PVE login was made for it
    mgr.mint_console_auth_ticket.assert_not_called()


@pytest.mark.parametrize('extra', ['', '&node=pve1&shell=node', '&console=term'])
@pytest.mark.parametrize('headers', [None, 'old-proof', 'empty-proof'])
def test_nobody_gets_the_cluster_context(api, seed, extra, headers):
    """Not even with the console server's header: no host, no node address, no ticket.
    The node shell and the guest terminal mint and resolve what they need themselves."""
    mgr = _mgr(api)
    c = api.as_user(seed.user('vic', role='admin'))
    sent = {None: None, 'old-proof': _console_server(),
            'empty-proof': {'X-PegaProx-Console-Server': ''}}[headers]
    r = _validate(api, c.post('/api/ws/token', json={}).get_json()['token'], extra, headers=sent)
    assert r.status_code == 200, r.data
    body = r.get_json()
    assert body['valid'] is True and 'cluster_context' not in body, body
    text = r.get_data(as_text=True)
    assert TICKET not in text and 'pve_auth_ticket' not in text and 'node_ips' not in text
    mgr.mint_console_auth_ticket.assert_not_called()
    mgr.member_node_ip.assert_not_called()


# --- the node shell ----------------------------------------------------------------------

def _confined(seed):
    """node.shell through a custom grant, a tenant that does not own cluster_1, and one
    VM ACL there: reach to the cluster, confined to that VM."""
    seed.tenant('t1', clusters=['other'])
    user = seed.user('ops', role='viewer', tenant_id='t1', permissions=['node.shell'])
    seed.vm_acl('cluster_1', 100, ['ops'])
    return user


def _portal(seed):
    """The tenant owns cluster_1, but the user holds a VM ACL there: confined as well."""
    seed.tenant('t2', clusters=['cluster_1'])
    user = seed.user('portal', role='viewer', tenant_id='t2', permissions=['node.shell'])
    seed.vm_acl('cluster_1', 101, ['portal'])
    return user


def _operator(seed):
    seed.tenant('t3', clusters=['cluster_1'])
    return seed.user('opr', role='viewer', tenant_id='t3', permissions=['node.shell'])


@pytest.mark.parametrize('make', [_confined, _portal])
def test_a_confined_caller_gets_no_node_shell_ticket(api, seed, make):
    mgr = _mgr(api)
    c = api.as_user(make(seed))
    r = c.post('/api/clusters/cluster_1/nodes/pve1/shell', json={})
    assert r.status_code == 403 and 'whole cluster' in r.get_json()['error'], r.data
    mgr.get_node_shell_ticket.assert_not_called()
    # nor through the validate call of a node shell, which still asks
    tok = c.post('/api/ws/token', json={}).get_json()['token']
    r = _validate(api, tok, '&node=pve1&shell=node')
    assert r.status_code == 403 and 'whole cluster' in r.get_json()['error'], r.data
    mgr.mint_console_auth_ticket.assert_not_called()


def test_a_cluster_operator_still_gets_the_node_shell(api, seed):
    """Counterproof: node.shell and a tenant that owns the cluster, no VM ACL or pool."""
    mgr = _mgr(api)
    c = api.as_user(_operator(seed))
    r = c.post('/api/clusters/cluster_1/nodes/pve1/shell', json={})
    assert r.status_code == 200, r.data
    tok = c.post('/api/ws/token', json={}).get_json()['token']
    r = _validate(api, tok, '&node=pve1&shell=node')
    assert r.status_code == 200 and r.get_json()['valid'] is True, r.data
    assert 'cluster_context' not in r.get_json()
    assert mgr.get_node_shell_ticket.call_count == 1
    mgr.mint_console_auth_ticket.assert_not_called()


class _WS:
    def __init__(self):
        self.sent = []

    def send(self, data):
        self.sent.append(json.loads(data))


def _shellws(api, user, monkeypatch):
    """The in-process shell WebSocket, called the way flask-sock does, up to the point
    where it would connect: a missing cluster stops it right after the access checks."""
    from pegaprox.globals import cluster_managers
    monkeypatch.delitem(cluster_managers, 'cluster_1', raising=False)
    rule = next(r for r in api.app.url_map.iter_rules()
                if r.rule == '/api/clusters/<cluster_id>/nodes/<node>/shellws')
    handler = api.app.view_functions[rule.endpoint].__wrapped__
    sid = api.as_user(user).session_id
    ws = _WS()
    with api.app.test_request_context(f'/api/clusters/cluster_1/nodes/pve1/shellws?session={sid}'):
        try:
            handler(ws, 'cluster_1', 'pve1')
        except Exception:
            # past the checks it goes on to connect, which this test does not provide
            pass
    return [m.get('message') for m in ws.sent]


@pytest.mark.parametrize('make', [_confined, _portal])
def test_the_shell_websocket_refuses_a_confined_caller(api, seed, monkeypatch, make):
    said = _shellws(api, make(seed), monkeypatch)
    assert said and said[0] in ('Access denied: this action affects the whole cluster',
                                'Access denied to this cluster'), said
    if make is _portal:
        # the tenant owns the cluster, so only the new check stops it
        assert said[0] == 'Access denied: this action affects the whole cluster'


def test_the_shell_websocket_lets_a_cluster_operator_on(api, seed, monkeypatch):
    """Counterproof: past every access check, to the cluster lookup this test leaves empty."""
    said = _shellws(api, _operator(seed), monkeypatch)
    assert said == ['Cluster not found'], said
