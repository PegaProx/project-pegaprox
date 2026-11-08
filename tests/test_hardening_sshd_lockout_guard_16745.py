# community-scripts/ProxmoxVE #16745 (B) — self-lockout guard on the hardening apply route.
# sshd_hardening sets PermitRootLogin=prohibit-password; on a cluster PegaProx reaches as root by
# password with NO ssh key, applying it severs PegaProx's own access (and rollback needs SSH too).
# The route must refuse sshd_hardening in that case unless the caller explicitly forces.

import types


def _mgr(api, ssh_key):
    fake = api.make_fake_manager('cluster_1')
    fake.is_connected = True
    fake.config = types.SimpleNamespace(name='cluster_1', ssh_key=ssh_key)
    # echo the controls the route actually forwarded, so we can tell block from apply
    fake.apply_node_hardening = lambda node, controls, params=None: {c: {'success': True} for c in controls}
    api.set_manager('cluster_1', fake)
    return fake


def test_sshd_hardening_blocked_when_no_key_and_no_force(api, seed):
    root = seed.user('root', role='admin', tenant_id='default')
    _mgr(api, ssh_key='')
    r = api.as_user(root).post('/api/clusters/cluster_1/nodes/pve1/hardening',
                               json={'controls': ['sshd_hardening']})
    assert r.status_code == 200, r.get_data(as_text=True)
    j = r.get_json()
    assert j['applied'] == 0
    res = j['results']['sshd_hardening']
    assert res.get('blocked') is True and res['success'] is False


def test_sshd_hardening_applied_with_force(api, seed):
    root = seed.user('root', role='admin', tenant_id='default')
    _mgr(api, ssh_key='')
    r = api.as_user(root).post('/api/clusters/cluster_1/nodes/pve1/hardening',
                               json={'controls': ['sshd_hardening'], 'force': True})
    assert r.status_code == 200, r.get_data(as_text=True)
    res = r.get_json()['results']['sshd_hardening']
    assert res['success'] is True and 'blocked' not in res   # forwarded to apply, not blocked


def test_sshd_hardening_not_blocked_when_key_present(api, seed):
    root = seed.user('root', role='admin', tenant_id='default')
    _mgr(api, ssh_key='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5')
    r = api.as_user(root).post('/api/clusters/cluster_1/nodes/pve1/hardening',
                               json={'controls': ['sshd_hardening']})
    assert r.status_code == 200, r.get_data(as_text=True)
    res = r.get_json()['results']['sshd_hardening']
    assert res['success'] is True and 'blocked' not in res


def test_other_controls_never_blocked_by_the_guard(api, seed):
    # the guard is scoped to sshd_hardening only; a normal control applies even on a keyless cluster
    root = seed.user('root', role='admin', tenant_id='default')
    _mgr(api, ssh_key='')
    r = api.as_user(root).post('/api/clusters/cluster_1/nodes/pve1/hardening',
                               json={'controls': ['default_umask']})
    assert r.status_code == 200, r.get_data(as_text=True)
    res = r.get_json()['results']['default_umask']
    assert res['success'] is True and 'blocked' not in res
