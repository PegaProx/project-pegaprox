# #717 — POST /api/clusters/<id>/ssh/repin-host-keys drops the pinned SSH host keys for a
# cluster whose node host key changed (CIS hardening / reinstall) so the next connect re-pins,
# without tearing the cluster down. cluster.config perm (admin). Mirrors the delete path's cleanup.


def test_repin_non_admin_forbidden_403(api, seed):
    user = seed.user('joe', role='user', tenant_id='default')
    api.set_manager('cluster_1', api.make_fake_manager())
    resp = api.as_user(user).post('/api/clusters/cluster_1/ssh/repin-host-keys', json={})
    assert resp.status_code == 403, resp.get_data(as_text=True)


def test_repin_admin_unknown_cluster_404(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    resp = api.as_user(admin).post('/api/clusters/ghost/ssh/repin-host-keys', json={})
    assert resp.status_code == 404, resp.get_data(as_text=True)


def test_repin_admin_clears_pins_200(api, seed, monkeypatch):
    admin = seed.user('root', role='admin', tenant_id='default')
    fake = api.make_fake_manager(cluster_id='cluster_1', get_nodes=[])
    fake.host = '203.0.113.10'          # real string so it joins the host set
    api.set_manager('cluster_1', fake)

    captured = {}

    def fake_remove(hosts, ports=()):
        captured['hosts'] = set(hosts)
        return 3

    # the handler does a call-time `from ... import remove_host_keys`, so patch the module attr
    monkeypatch.setattr('pegaprox.utils.ssh_security.remove_host_keys', fake_remove)

    resp = api.as_user(admin).post('/api/clusters/cluster_1/ssh/repin-host-keys', json={})
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body['success'] is True
    assert body['removed'] == 3
    # the configured host was handed to the cleanup
    assert '203.0.113.10' in captured['hosts']


def _shared_host_setup(api, monkeypatch, reachable):
    fake = api.make_fake_manager(cluster_id='cluster_1', get_nodes=[])
    fake.host = '203.0.113.10'
    other = api.make_fake_manager(cluster_id='cluster_2', get_nodes=[])
    other.host = '203.0.113.10'          # the same box, also reached by cluster_2
    api.set_manager('cluster_1', fake)
    api.set_manager('cluster_2', other)
    captured = {}

    def fake_remove(hosts, ports=()):
        captured['hosts'] = set(hosts)
        return 0

    monkeypatch.setattr('pegaprox.utils.ssh_security.remove_host_keys', fake_remove)
    monkeypatch.setattr('pegaprox.utils.rbac.get_user_clusters', lambda *a, **k: reachable)
    return captured


def test_repin_keeps_a_host_another_cluster_uses_when_caller_cannot_reach_it(api, seed, monkeypatch):
    admin = seed.user('root', role='admin', tenant_id='default')
    captured = _shared_host_setup(api, monkeypatch, reachable=['cluster_1'])
    resp = api.as_user(admin).post('/api/clusters/cluster_1/ssh/repin-host-keys', json={})
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert '203.0.113.10' not in captured['hosts']
    assert resp.get_json()['kept'] == 1


def test_repin_drops_a_shared_host_when_caller_reaches_every_cluster_using_it(api, seed, monkeypatch):
    admin = seed.user('root', role='admin', tenant_id='default')
    captured = _shared_host_setup(api, monkeypatch, reachable=['cluster_1', 'cluster_2'])
    resp = api.as_user(admin).post('/api/clusters/cluster_1/ssh/repin-host-keys', json={})
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert '203.0.113.10' in captured['hosts']
