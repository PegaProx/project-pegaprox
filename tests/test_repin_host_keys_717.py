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

    def fake_remove(hosts):
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
