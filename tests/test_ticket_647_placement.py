# #647 - the rolling-update evacuation picked its target from capacity, excluded nodes and
# ProxLB pins only. A guest under a strict HA node-affinity rule was sent to a node the rule
# forbids (ha-manager migrate exits 2, the run pauses on evacuation_failures), and nothing
# checked that the guest's storage exists on the target (storage.cfg nodes=). The target set
# is now limited by both, and a guest the CRM still moved after a failed migrate no longer
# counts as a failure.

from unittest.mock import MagicMock

from pegaprox.core.manager import PegaProxManager
from pegaprox.models.tasks import MaintenanceTask

# six nodes, pve5 is being evacuated; pve1 has the lowest score and wins when nothing limits
_NODES = {
    'pve1': {'status': 'online', 'score': 1},
    'pve2': {'status': 'online', 'score': 5},
    'pve3': {'status': 'online', 'score': 6},
    'pve4': {'status': 'online', 'score': 2},
    'pve5': {'status': 'online', 'score': 0, 'maintenance_mode': True},
    'pve6': {'status': 'online', 'score': 7},
}


def _resp(status, data=None):
    r = MagicMock()
    r.status_code = status
    r.json.return_value = {'data': data}
    r.text = ''
    return r


def _mgr(guests, api, migrate_ok=True, later=None):
    """api maps a path suffix to its data (missing = 404). later: vmid -> node the guest
    turns up on after its migrate, whatever the migrate returned."""
    m = PegaProxManager.__new__(PegaProxManager)
    m.current_host = None
    m.config = MagicMock(host='h', api_port=8006, dry_run=False, excluded_nodes=[])
    m.logger = MagicMock()
    m._rolling_update = {}
    m.get_node_status = lambda: _NODES
    m._derive_proxlb_tag_rules = lambda: {'pins': {}}
    m._count_vms_on_node = lambda node: 0
    state = {v['vmid']: v['node'] for v in guests}
    m.get_vm_resources = lambda *a, **k: [dict(v, node=state[v['vmid']]) for v in guests]
    sent = {}

    def migrate(vm, target, dry_run=False, wait_timeout=0):
        sent[vm['vmid']] = target
        state[vm['vmid']] = (later or {}).get(vm['vmid'], target if migrate_ok else vm['node'])
        return migrate_ok
    m.migrate_vm = migrate

    def get(url, **kw):
        path = url.split('/api2/json', 1)[1]
        return _resp(200, api[path]) if path in api else _resp(404)
    m._api_get = MagicMock(side_effect=get)
    return m, sent


def _evacuate(m):
    task = MaintenanceTask('pve5')
    PegaProxManager._evacuate_node(m, 'pve5', task)
    return task


def _vm(vmid, kind='qemu'):
    return {'vmid': vmid, 'name': f'g{vmid}', 'node': 'pve5', 'status': 'running', 'type': kind, 'mem': 1}


_STRICT_303 = {'rule': 'ha-rule-7b300e1a-c922', 'type': 'node-affinity', 'strict': 1,
               'resources': 'vm:303,vm:310', 'nodes': 'pve2:2,pve3,pve5:2,pve6'}


def test_a_strict_node_affinity_rule_keeps_the_guest_off_a_forbidden_node():
    m, sent = _mgr([_vm(303)], {'/cluster/ha/rules': [_STRICT_303],
                                '/cluster/ha/resources': [{'sid': 'vm:303'}]})
    task = _evacuate(m)
    assert sent[303] == 'pve2', f"303 went to {sent[303]}, its strict rule allows pve2/pve3/pve5/pve6"
    assert task.status == 'completed'


def test_a_guest_goes_only_where_all_its_storages_are():
    api = {
        '/storage': [{'storage': 'nfs-pbs', 'type': 'nfs', 'nodes': 'pve5,pve3,pve6'},
                     {'storage': 'san', 'type': 'lvm', 'shared': 1, 'nodes': 'pve3,pve4,pve5'},
                     {'storage': 'local', 'type': 'dir'}],
        '/nodes/pve5/qemu/294/config': {'scsi0': 'san:vm-294-disk-0,size=32G',
                                        'scsi1': 'nfs-pbs:294/vm-294-disk-1.qcow2,size=2T',
                                        'ide2': 'none,media=cdrom', 'scsihw': 'virtio-scsi-pci',
                                        'net0': 'virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0'},
    }
    m, sent = _mgr([_vm(294)], api)
    _evacuate(m)
    assert sent[294] == 'pve3', f"294 went to {sent[294]}; only pve3 has both nfs-pbs and san"


def test_a_container_mount_point_counts_as_storage():
    api = {'/storage': [{'storage': 'cephfs-a', 'type': 'cephfs', 'nodes': 'pve5,pve6'}],
           '/nodes/pve5/lxc/120/config': {'rootfs': 'local-lvm:vm-120-disk-0,size=8G',
                                          'mp0': 'cephfs-a:subvol-120-disk-1,mp=/data',
                                          'mp1': '/srv/host,mp=/host'}}
    m, sent = _mgr([_vm(120, 'lxc')], api)
    _evacuate(m)
    assert sent[120] == 'pve6'


def test_a_restricted_legacy_group_is_honoured():
    """PVE 8: no /cluster/ha/rules, the limit sits on the resource's restricted group."""
    api = {'/cluster/ha/groups': [{'group': 'db', 'nodes': 'pve3:1,pve6', 'restricted': 1},
                                  {'group': 'loose', 'nodes': 'pve2', 'restricted': 0}],
           '/cluster/ha/resources': [{'sid': 'vm:303', 'group': 'db'},
                                     {'sid': 'ct:304', 'group': 'loose'}]}
    m, sent = _mgr([_vm(303), _vm(304, 'lxc')], api)
    _evacuate(m)
    assert sent[303] == 'pve3'
    assert sent[304] == 'pve1', "an unrestricted group is a preference and must not limit"


def test_non_strict_and_disabled_rules_do_not_limit():
    rules = [dict(_STRICT_303, strict=0),
             dict(_STRICT_303, rule='off', resources='vm:305', disable=1)]
    m, sent = _mgr([_vm(303), _vm(305)], {'/cluster/ha/rules': rules})
    _evacuate(m)
    assert sent == {303: 'pve1', 305: 'pve1'}


def test_no_allowed_node_is_a_failure_not_a_forbidden_target():
    rule = dict(_STRICT_303, nodes='pve5')   # nowhere else to go
    m, sent = _mgr([_vm(303)], {'/cluster/ha/rules': [rule]})
    task = _evacuate(m)
    assert 303 not in sent, "a target outside the rule was still handed to the migrate"
    assert task.status == 'completed_with_errors'
    assert 'HA rule' in task.failed_vms[0]['error']


def test_placement_is_read_once_per_evacuation_not_per_guest():
    guests = [_vm(400 + i) for i in range(50)]
    m, sent = _mgr(guests, {'/cluster/ha/rules': [], '/storage': [{'storage': 'local', 'type': 'dir'}]})
    _evacuate(m)
    assert len(sent) == 50
    # rules, groups, storage - and no config read, since no storage is node-limited
    assert m._api_get.call_count == 3, [c.args[0] for c in m._api_get.call_args_list]


def test_a_guest_the_crm_moved_after_a_failed_migrate_is_not_a_failure():
    m, sent = _mgr([_vm(294), _vm(295)], {}, migrate_ok=False, later={294: 'pve2'})
    task = _evacuate(m)
    assert [f['vmid'] for f in task.failed_vms] == [295], "294 left pve5 and still counted as failed"
    assert task.migrated_vms == 1
    assert task.status == 'completed_with_errors'
