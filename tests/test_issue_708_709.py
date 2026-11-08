# #708 — the datastore overview showed a storage that is enabled only on OTHER nodes (config `nodes`
#         restriction) as "unreachable" for a node it isn't on. Honor the node restriction.
# #709 — a DR test-failover of a RUNNING LXC failed with "Full clone of a running container is only
#         possible from a snapshot". Snapshot the replica, clone from it, then drop the snapshot.

from unittest.mock import MagicMock

import pegaprox.globals as ppglobals
import pegaprox.api.vms as vmsmod
import pegaprox.core.manager as mgrmod
import pegaprox.background.site_recovery as srmod
from pegaprox.models.tasks import PegaProxConfig


# ---------------------------------------------------------------------------
# #708 — node-restricted storage must not show for a node it isn't enabled on
# ---------------------------------------------------------------------------

def _fake_session(url_map):
    s = MagicMock()
    def _get(url, **kw):
        r = MagicMock()
        for suffix, (code, data) in url_map.items():
            if url.endswith(suffix) or suffix in url:
                r.status_code = code
                r.json.return_value = {'data': data}
                return r
        r.status_code = 200
        r.json.return_value = {'data': []}
        return r
    s.get.side_effect = _get
    return s


def test_708_node_restricted_local_storage_hidden(api, seed):
    seed.tenant('acme', clusters=['cluster_1'])
    root = seed.user('root', role='admin', tenant_id='default')
    fake = api.make_fake_manager('cluster_1')
    fake.is_connected = True
    fake.host = 'h'; fake.api_port = 8006
    fake.cluster_type = 'proxmox'
    fake._create_session.return_value = _fake_session({
        '/api2/json/storage': (200, [
            {'storage': 'localA', 'type': 'dir', 'nodes': 'nodeA', 'content': 'images'},  # restricted to nodeA
            {'storage': 'localall', 'type': 'dir', 'nodes': '', 'content': 'images'},      # all nodes
        ]),
        '/cluster/resources': (200, [{'node': 'nodeA', 'status': 'online'},
                                     {'node': 'nodeB', 'status': 'online'}]),
        '/nodes/nodeA/storage': (200, [{'storage': 'localA', 'type': 'dir', 'active': 1, 'enabled': 1},
                                       {'storage': 'localall', 'type': 'dir', 'active': 1, 'enabled': 1}]),
        # PVE lists the restricted storage on nodeB too, but inactive — the pre-fix bug rendered it "unreachable"
        '/nodes/nodeB/storage': (200, [{'storage': 'localA', 'type': 'dir', 'active': 0, 'enabled': 0},
                                       {'storage': 'localall', 'type': 'dir', 'active': 1, 'enabled': 1}]),
    })
    api.set_manager('cluster_1', fake)
    vmsmod._datastores_cache.clear()
    try:
        r = api.as_user(root).get('/api/clusters/cluster_1/datastores')
        assert r.status_code == 200, r.get_data(as_text=True)
        body = r.get_json()
        nodeB = {s['storage'] for s in body.get('local', {}).get('nodeB', [])}
        nodeA = {s['storage'] for s in body.get('local', {}).get('nodeA', [])}
        assert 'localA' not in nodeB      # restricted storage no longer shown on nodeB
        assert 'localall' in nodeB        # unrestricted storage still shown
        assert 'localA' in nodeA          # still shown on its own node (no over-hide)
    finally:
        vmsmod._datastores_cache.clear()


# ---------------------------------------------------------------------------
# #709 — clone_vm forwards snapname; test-failover snapshots a running LXC first
# ---------------------------------------------------------------------------

def test_709_clone_vm_forwards_snapname(monkeypatch):
    m = mgrmod.PegaProxManager('c1', PegaProxConfig({'name': 't', 'host': 'h', 'user': 'root@pam', 'pass': 'x'}))
    m.is_connected = True
    captured = {}
    def fake_post(self, url, data=None, **k):
        captured['data'] = data
        r = MagicMock(); r.status_code = 200; r.json.return_value = {'data': 'UPID:clone'}
        return r
    monkeypatch.setattr(mgrmod.PegaProxManager, '_api_post', fake_post)

    res = m.clone_vm('node1', 100, 'lxc', newid=190100, name='SR-TEST', snapname='srtest190100')
    assert res['success'] is True
    assert captured['data'].get('snapname') == 'srtest190100'   # clone-from-snapshot
    assert captured['data'].get('hostname') == 'SR-TEST'        # LXC uses hostname, not name

    m.clone_vm('node1', 100, 'lxc', newid=190101, name='X')     # no snapname → not sent
    assert 'snapname' not in captured['data']


def test_709_test_failover_snapshots_running_lxc(monkeypatch):
    # a running-LXC test-failover must: create a temp snapshot, clone FROM it, then delete it.
    plan = {'name': 'p', 'target_cluster': 'dr', 'test_disconnect_nics': False}
    monkeypatch.setattr(srmod, '_get_plan', lambda pid: plan)
    monkeypatch.setattr(srmod, '_get_plan_vms', lambda pid: [{'vmid': 100, 'vm_name': 'ct1', 'vm_type': 'lxc'}])
    monkeypatch.setattr(srmod, '_create_event', lambda *a, **k: 'evt1')
    monkeypatch.setattr(srmod, '_broadcast_progress', lambda *a, **k: None)

    tgt = MagicMock()
    tgt.get_node_status.return_value = {'nodeDR': {}}
    tgt.get_vms.return_value = [{'vmid': 100}]
    tgt.create_snapshot.return_value = {'success': True, 'task': 'UPID:snap'}
    tgt.clone_vm.return_value = {'success': True, 'data': 'UPID:clone'}
    tgt._wait_for_task.return_value = True
    tgt.delete_snapshot.return_value = {'success': True}
    tgt.vm_action.return_value = {'success': True}
    ppglobals.cluster_managers['dr'] = tgt
    try:
        srmod.execute_test_failover('plan1')
    finally:
        ppglobals.cluster_managers.pop('dr', None)

    # a temp snapshot was taken on the replica (100), cloned FROM it, then removed
    assert tgt.create_snapshot.called
    snap_name = tgt.create_snapshot.call_args.args[3]           # (node, vmid, vtype, snapname, ...)
    ck = tgt.clone_vm.call_args
    assert ck.kwargs.get('snapname') == snap_name               # cloned from the temp snapshot
    assert tgt.delete_snapshot.called                           # and cleaned it up
    assert tgt.delete_snapshot.call_args.args[3] == snap_name
