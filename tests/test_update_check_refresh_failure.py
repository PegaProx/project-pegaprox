"""A failed apt refresh must not be reported as a successful update check.

check_cluster_updates POSTs an apt refresh per node and then reads the node's
update list. get_node_apt_updates answers out of whatever apt last wrote, so if
the refresh failed the read still succeeds and returns stale packages. That
result then goes out as success and is held by the 24h _update_check_cache, so
an operator sees "checked, all good" on a node that has not been checked in
days.

Measured through the real route, not on the helper: the property is what the
caller is told, not which branch ran.

MK Sep 2026
"""
import pegaprox.api.settings as settings_mod


STALE = [
    {'Package': 'openssl', 'Version': '3.0.15-1~deb12u1'},
    {'Package': 'curl', 'Version': '7.88.1-10+deb12u7'},
    {'Package': 'linux-image-amd64', 'Version': '6.1.99-1'},
]


def _node(api, cid, *, refresh, updates=STALE):
    """An XCP-ng-typed fake so the route takes get_nodes() instead of a raw session."""
    m = api.make_fake_manager(cluster_id=cid)
    m.is_connected = True
    m.cluster_type = 'xcpng'
    m.get_nodes.return_value = [{'node': 'pve1', 'status': 'online'}]
    m.refresh_node_apt.return_value = refresh
    m.get_node_apt_updates.return_value = updates
    return api.set_manager(cid, m)


def _check(api, seed, refresh):
    settings_mod._update_check_cache.clear()
    _node(api, 'cluster_1', refresh=refresh)
    admin = seed.user('opsadmin', role='admin')
    r = api.as_user(admin).post('/api/clusters/cluster_1/updates/check', json={'force': True})
    assert r.status_code == 200, r.data
    return r.get_json()['nodes']['pve1']


def test_a_refused_refresh_is_not_reported_as_a_clean_check(api, seed):
    node = _check(api, seed, {'success': False, 'error': 'repository unreachable'})

    assert node['success'] is False, \
        'a node whose apt refresh failed was reported as successfully checked'
    assert node['count'] == -1, f"expected the failed-check marker, got {node['count']}"
    assert node['updates'] == [], 'stale packages were handed out after a failed refresh'


def test_a_refresh_task_that_never_finished_is_not_reported_as_a_clean_check(api, seed):
    """The Proxmox leg: the POST is accepted, the task is not OK."""
    settings_mod._update_check_cache.clear()
    m = _node(api, 'cluster_1', refresh={'success': True, 'task': 'UPID:pve1:apt-update'})
    m._wait_for_task.return_value = False
    admin = seed.user('opsadmin2', role='admin')

    r = api.as_user(admin).post('/api/clusters/cluster_1/updates/check', json={'force': True})
    node = r.get_json()['nodes']['pve1']

    assert node['success'] is False, \
        'a node whose refresh task failed was reported as successfully checked'
    assert node['count'] == -1
    assert node['updates'] == []


def test_a_healthy_node_still_reports_its_updates(api, seed):
    """The counterweight. None of the above may turn a working check into a failure."""
    settings_mod._update_check_cache.clear()
    m = _node(api, 'cluster_1', refresh={'success': True, 'task': 'UPID:pve1:apt-update'})
    m._wait_for_task.return_value = True
    admin = seed.user('opsadmin3', role='admin')

    node = api.as_user(admin).post(
        '/api/clusters/cluster_1/updates/check', json={'force': True}).get_json()['nodes']['pve1']

    assert node['success'] is True, 'a healthy node stopped reporting its updates'
    assert node['count'] == 3
