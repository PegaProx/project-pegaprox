"""Which SSH refusal of the hardening check stands for the whole cluster.

cluster_wide tells the compliance loader that every other node would answer the same,
so it stops asking and shows one callout for the cluster. SSH switched off is the
cluster's own switch, yet it came back cluster_wide false: the loader asked all 200
nodes one after the other and showed no callout. And "no credentials" came back
cluster_wide true even on a token cluster where other nodes have a root password of
their own (#1136), so the loader stopped before the nodes it could have read.

MK Nov 2026
"""
import pytest

CLUSTER = 'cluster_1'


@pytest.fixture
def admin(api, seed):
    return api.as_user(seed.user('root_admin', role='admin'))


def _mgr(api, **kw):
    from pegaprox.core.manager import PegaProxManager
    m = api.make_fake_manager(CLUSTER, check_node_hardening=None)
    m.is_connected = True
    m._is_node_blocked = lambda n: (False, 0)
    m.config.user = kw.get('user', 'root@pam')
    m.config.ssh_disabled = kw.get('ssh_disabled', False)
    m.config.ssh_key = kw.get('ssh_key', '')
    m.config.pass_ = kw.get('password', '')
    m.ssh_blocked_reason = PegaProxManager.ssh_blocked_reason.__get__(m, PegaProxManager)
    m.ssh_diagnose = PegaProxManager.ssh_diagnose.__get__(m, PegaProxManager)
    return api.set_manager(CLUSTER, m)


def _check(client, node):
    r = client.get(f'/api/clusters/{CLUSTER}/nodes/{node}/hardening?profile=cis-l1')
    return r.status_code, r.get_json()


def test_ssh_switched_off_is_cluster_wide(api, admin):
    _mgr(api, ssh_disabled=True, password='an-actual-ssh-password')
    status, body = _check(admin, 'pve1')
    assert (status, body['code']) == (412, 'SSH_DISABLED')
    assert body['cluster_wide'] is True


def test_a_token_cluster_without_any_credential_is_cluster_wide(api, admin):
    _mgr(api, user='root@pam!pegaprox', password='the-token-secret')
    status, body = _check(admin, 'pve1')
    assert (status, body['code'], body['cluster_wide']) == (412, 'SSH_NO_CREDENTIALS', True)


def test_a_node_without_its_own_password_is_not_the_whole_cluster(api, admin, monkeypatch):
    # pve2 has a root password of its own, pve1 has none: pve1 is refused, pve2 can be read
    import pegaprox.core.node_creds as node_creds
    monkeypatch.setattr(node_creds, 'secrets_of', lambda cid: {'pve2': 'pw-of-pve2'})
    _mgr(api, user='root@pam!pegaprox', password='the-token-secret')
    status, body = _check(admin, 'pve1')
    assert (status, body['code']) == (412, 'SSH_NO_CREDENTIALS')
    assert body['cluster_wide'] is False, 'the loader has to go on to pve2'


def test_a_connection_failure_is_never_cluster_wide(api, admin):
    _mgr(api, password='an-actual-ssh-password')
    status, body = _check(admin, 'pve1')
    assert (status, body['code'], body['cluster_wide']) == (502, 'SSH_FAILED', False)
