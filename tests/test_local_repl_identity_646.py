# #646 (@ripperrd) — local snapshot replication now preserves the source's MAC + hostname/name on
# the replica (like the cross-cluster path), forces onboot=0 so a host reboot can't bring the
# replica up alongside the still-running source (MAC/hostname/IP collision), and identifies old
# replicas by our job tag (keeping the legacy repl-<vmid>-<node> name for older replicas).

import re
from unittest.mock import MagicMock

import pegaprox.globals as ppglobals
import pegaprox.api.vms as vmsmod


def _resp(code, data=None, text=''):
    r = MagicMock(); r.status_code = code; r.json.return_value = {'data': data}; r.text = text
    return r


# ---------------------------------------------------------------------------
# _restore_vm_identity: onboot=0 + MAC swap + name/hostname
# ---------------------------------------------------------------------------

def test_restore_identity_qemu_swaps_mac_keeps_tokens_sets_onboot_off():
    mgr = MagicMock(); mgr.host = 'h'; mgr.api_port = 8006
    # replica currently has a FRESH MAC (from clone) + bridge/firewall tokens
    mgr._api_get.return_value = _resp(200, {'net0': 'virtio=AA:BB:CC:11:22:33,bridge=vmbr0,firewall=1'})
    mgr._api_put.return_value = _resp(200)
    identity = {'name': 'websrv', 'hostname': None, 'nets': {'net0': '52:54:00:AB:CD:EF'}}
    vmsmod._restore_vm_identity(mgr, 'node1', 200, 'qemu', identity, force_onboot_off=True)
    payload = mgr._api_put.call_args.kwargs['data']
    assert payload['onboot'] == 0
    assert payload['name'] == 'websrv'
    assert '52:54:00:AB:CD:EF' in payload['net0'].lower() or '52:54:00:ab:cd:ef' in payload['net0'].lower()
    assert 'bridge=vmbr0' in payload['net0'] and 'firewall=1' in payload['net0']   # tokens preserved


def test_restore_identity_lxc_uses_hostname():
    mgr = MagicMock(); mgr.host = 'h'; mgr.api_port = 8006
    mgr._api_get.return_value = _resp(200, {'net0': 'name=eth0,bridge=vmbr0,hwaddr=AA:BB:CC:11:22:33'})
    mgr._api_put.return_value = _resp(200)
    identity = {'name': None, 'hostname': 'ct-web', 'nets': {'net0': '52:54:00:11:22:33'}}
    vmsmod._restore_vm_identity(mgr, 'node1', 210, 'lxc', identity, force_onboot_off=True)
    payload = mgr._api_put.call_args.kwargs['data']
    assert payload['hostname'] == 'ct-web'
    assert payload['onboot'] == 0
    assert '52:54:00:11:22:33' in payload['net0']


def test_restore_identity_forces_onboot_off_even_without_identity():
    # a DR replica must be pinned onboot=0 regardless — the collision guard can't depend on the
    # config read succeeding.
    mgr = MagicMock(); mgr.host = 'h'; mgr.api_port = 8006
    mgr._api_put.return_value = _resp(200)
    vmsmod._restore_vm_identity(mgr, 'n', 1, 'qemu', {}, force_onboot_off=True)
    assert mgr._api_put.call_args.kwargs['data'] == {'onboot': 0}
    mgr._api_get.assert_not_called()   # no nets -> no config read


def test_restore_identity_without_onboot_flag_is_unchanged_for_xcrepl():
    # regression guard: the cross-cluster caller (no force_onboot_off) must NOT get onboot in the PUT
    mgr = MagicMock(); mgr.host = 'h'; mgr.api_port = 8006
    mgr._api_get.return_value = _resp(200, {'net0': 'virtio=AA:BB:CC:11:22:33,bridge=vmbr0'})
    mgr._api_put.return_value = _resp(200)
    vmsmod._restore_vm_identity(mgr, 'n', 2, 'qemu', {'name': 'x', 'nets': {'net0': '52:54:00:00:00:01'}})
    assert 'onboot' not in mgr._api_put.call_args.kwargs['data']


# ---------------------------------------------------------------------------
# _execute_local_replication end-to-end (stateful fake manager)
# ---------------------------------------------------------------------------

class _FakeMgr:
    """Minimal stateful PVE for the local-replication flow."""
    def __init__(self):
        self.host = 'h'; self.api_port = 8006; self.is_connected = True
        self.vms = {
            100: {'node': 'nodeA', 'name': 'websrv',
                  'net0': 'virtio=52:54:00:AB:CD:EF,bridge=vmbr0,firewall=1', 'tags': '', 'status': 'stopped'},
            # a replica from a PREVIOUS run: already carries the source name + our job tag
            900: {'node': 'nodeB', 'name': 'websrv',
                  'net0': 'virtio=52:54:00:AB:CD:EF,bridge=vmbr0', 'tags': 'pegaprox-replica;xcrepl-job-J1',
                  'status': 'stopped'},
        }
        self.deleted = []

    def _api_get(self, url, params=None):
        if 'cluster/resources' in url:
            return _resp(200, [{'vmid': v, 'node': d['node'], 'name': d['name'], 'status': d['status']}
                               for v, d in self.vms.items()])
        if 'cluster/nextid' in url:
            return _resp(200, 901)
        if url.endswith('/storage'):
            return _resp(200, [{'storage': 'local-lvm', 'type': 'lvmthin'}])
        m = re.search(r'/(\d+)/config$', url)
        if m:
            d = self.vms.get(int(m.group(1)), {})
            return _resp(200, {'name': d.get('name'), 'hostname': d.get('hostname'),
                               'net0': d.get('net0'), 'tags': d.get('tags', '')})
        return _resp(404)

    def _api_post(self, url, data=None):
        if '/snapshot' in url:
            return _resp(200, 'UPID:snap')
        if '/clone' in url:
            self.vms[901] = {'node': 'nodeA', 'name': data.get('name') or data.get('hostname'),
                             'net0': 'virtio=AA:BB:CC:11:22:33,bridge=vmbr0,firewall=1', 'tags': '', 'status': 'stopped'}
            return _resp(200, 'UPID:clone')
        return _resp(200, 'UPID:x')

    def _api_put(self, url, data=None):
        m = re.search(r'/(\d+)/config$', url)
        if m and int(m.group(1)) in self.vms:
            self.vms[int(m.group(1))].update(data)
        return _resp(200)

    def _api_delete(self, url):
        m = re.search(r'/(\d+)$', url)
        if m:
            self.deleted.append(int(m.group(1)))
        return _resp(200)

    def migrate_vm_manual(self, node, vmid, vm_type, target_node, online, options):
        if vmid in self.vms:
            self.vms[vmid]['node'] = target_node
        return {'success': True, 'task': 'UPID:mig'}

    def _get_vm_storage(self, node, vmid, vm_type):
        return 'local-lvm'


def test_local_replication_preserves_identity_onboot_and_reaps_old_replica(monkeypatch):
    fake = _FakeMgr()
    ppglobals.cluster_managers['c1'] = fake
    monkeypatch.setattr(vmsmod, '_wait_for_task', lambda *a, **k: (True, ''))
    monkeypatch.setattr(vmsmod, '_update_repl_status', lambda *a, **k: None)
    monkeypatch.setattr(vmsmod, '_cleanup_snapshot', lambda *a, **k: None)
    monkeypatch.setattr(vmsmod, 'get_db', lambda: MagicMock())
    try:
        vmsmod._execute_local_replication({
            'id': 'J1', 'vmid': 100, 'vm_type': 'qemu', 'source_cluster': 'c1',
            'target_node': 'nodeB', 'target_storage': 'local-lvm',
        })
        r = fake.vms[901]
        assert r['name'] == 'websrv'                              # #1 source name restored
        assert '52:54:00:AB:CD:EF' in r['net0']                    # #1 source MAC restored
        assert 'bridge=vmbr0' in r['net0'] and 'firewall=1' in r['net0']   # migration tokens kept
        assert r.get('onboot') == 0                                # #2 onboot forced off
        assert 'pegaprox-replica' in r['tags'] and 'xcrepl-job-J1' in r['tags']  # tagged
        assert 900 in fake.deleted                                 # previous replica reaped (by tag)
        assert 100 not in fake.deleted                             # source never touched
    finally:
        ppglobals.cluster_managers.pop('c1', None)
