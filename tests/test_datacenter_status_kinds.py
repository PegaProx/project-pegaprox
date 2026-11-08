"""The datacenter status route answers each kind of connection.

An ESXi connection ran into the Proxmox branch, failed on an attribute it does not have and
answered 500 on every poll of the overview.
"""
CID = 'esx1'


def test_an_esxi_connection_has_no_datacenter_status(api, seed):
    m = api.make_fake_manager(CID, cluster_type='esxi')
    m.is_connected = True
    del m.api_port
    api.set_manager(CID, m)
    r = api.as_user(seed.user('root', role='admin')).get(f'/api/clusters/{CID}/datacenter/status')
    assert r.status_code == 400 and r.get_json()['code'] == 'UNSUPPORTED'


def test_the_overview_poll_leaves_esxi_connections_out():
    import os
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, 'web', 'src', 'dashboard.js'), encoding='utf-8') as fh:
        src = fh.read()
    assert "data.filter(c => c.connected && c.cluster_type !== 'esxi')" in src
