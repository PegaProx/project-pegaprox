"""The template list for creating a guest keeps the container templates (storage content:
a volid, no vmid) and the XCP-ng templates (a uuid). The per-guest scoping of VM templates
dropped every row without a vmid, so no container template could be picked by anyone.

MK Oct 2026
"""
from test_audit_round5_batch13 import _pool_user

ROWS = [{'type': 'qemu', 'vmid': 100, 'name': 't100'},
        {'type': 'qemu', 'vmid': 101, 'name': 't101'},
        {'type': 'lxc', 'volid': 'local:vztmpl/debian-13-standard_13.1-2_amd64.tar.zst',
         'name': 'debian-13-standard_13.1-2_amd64.tar.zst'}]


def _manager(api, rows, cluster_type='proxmox'):
    m = api.make_fake_manager(cluster_id='cluster_1')
    m.is_connected = True
    m.cluster_type = cluster_type
    m.get_templates.return_value = rows
    api.set_manager('cluster_1', m)
    return m


def test_an_admin_gets_vm_and_container_templates(api, seed):
    _manager(api, ROWS)
    body = api.as_user(seed.user('root', role='admin')).get('/api/clusters/cluster_1/nodes/n1/templates').get_json()
    assert sorted(t.get('vmid', 0) for t in body) == [0, 100, 101]
    assert [t['volid'] for t in body if t.get('type') == 'lxc'] == [ROWS[2]['volid']]


def test_a_pool_user_keeps_the_container_templates_and_only_its_vm_template(api, seed):
    _manager(api, ROWS)
    body = api.as_user(_pool_user(seed)).get('/api/clusters/cluster_1/nodes/n1/templates').get_json()
    assert sorted(t['vmid'] for t in body if 'vmid' in t) == [100]
    assert [t['type'] for t in body if 'vmid' not in t] == ['lxc']


def test_xcpng_templates_without_a_vmid_stay(api, seed):
    _manager(api, [{'uuid': 'abc-123', 'name': 'Debian 12'}], cluster_type='xcpng')
    body = api.as_user(seed.user('root', role='admin')).get('/api/clusters/cluster_1/nodes/n1/templates').get_json()
    assert [t['uuid'] for t in body] == ['abc-123']
