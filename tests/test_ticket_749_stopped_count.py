# #749 (mikelawson68) — the group-status aggregate must count a guest as stopped only
# when its status is literally 'stopped'. The old `else` branch swept paused / suspended /
# templates into the stopped tally, so a six-cluster estate over-reported stopped guests.

def _seed_group(seed, gid):
    seed.db.execute(
        'INSERT INTO cluster_groups (id, name, description, color, tenant_id, sort_order, '
        'created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        (gid, 'G749', '', '#ffffff', None, 0, '2026-01-01T00:00:00', '2026-01-01T00:00:00'))


def test_group_status_stopped_counts_only_explicit_stopped(api, seed):
    root = seed.user('root', role='admin', tenant_id='default')
    gid = 'g-749'
    _seed_group(seed, gid)
    seed.db.save_cluster('cluster_1', {'name': 'c1', 'host': 'h', 'group_id': gid})

    vms = [
        {'vmid': 100, 'status': 'running'},
        {'vmid': 101, 'status': 'running'},
        {'vmid': 200, 'status': 'stopped'},
        {'vmid': 300, 'status': 'paused'},     # must NOT land in the stopped bucket
        {'vmid': 400, 'status': 'suspended'},  # ditto
        {'vmid': 500, 'status': 'template'},   # ditto
    ]
    api.set_manager('cluster_1', api.make_fake_manager(
        'cluster_1', get_vm_resources=vms, get_node_status={}))

    r = api.as_user(root).get(f'/api/cluster-groups/{gid}/status')
    assert r.status_code == 200, r.get_data(as_text=True)
    totals = r.get_json()['totals']
    assert totals['vms_running'] == 2, totals
    assert totals['vms_stopped'] == 1, totals   # only vmid 200, not the paused/suspended/template three
