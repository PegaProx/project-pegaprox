"""Two evacuation options of the rolling update, both off by default.

#763 - templates. The evacuation takes the running guests of a node, and a template is
never running, so templates stayed behind and went down with the node. With the option
they move offline with the evacuation, each to a node that has every storage it uses. A
template that cannot move (its storage is on no other node, a CD/DVD image on local
storage) stays and is listed with the reason; it never pauses the run.

#954 - negative affinity. ha-manager refuses to migrate a guest onto a node that holds
another guest of a negative resource-affinity rule, so a rule over as many guests as the
cluster has nodes blocks every evacuation. With the option the run switches those rules
off before its first evacuation and on again when it ends; the list is in the database
before the first rule is touched, so a restart in between does not leave them off. The
balancer's own anti-affinity pass waits for the end of the run as well.

The plan route says ahead of the run what the two options would change.

MK Oct 2026
"""
import threading
import time
from unittest.mock import MagicMock

import pytest

import pegaprox.core.manager as mgrmod
from pegaprox.core import ha
from pegaprox.core.manager import PegaProxManager
from pegaprox.models.tasks import MaintenanceTask, UpdateTask

# pve5 is being evacuated; pve4 has the lowest score of the others
NODES = {
    'pve1': {'status': 'online', 'score': 3},
    'pve3': {'status': 'online', 'score': 6},
    'pve4': {'status': 'online', 'score': 2},
    'pve5': {'status': 'online', 'score': 0, 'maintenance_mode': True},
    'pve6': {'status': 'online', 'score': 7},
}


def _storage(node, name, shared=0, status='available'):
    return {'id': f'storage/{node}/{name}', 'type': 'storage', 'node': node, 'storage': name,
            'shared': shared, 'status': status}


# local-lvm and local everywhere, san on three nodes, local-zfs on pve5 only
STORAGES = ([_storage(n, 'local-lvm') for n in NODES] + [_storage(n, 'local') for n in NODES]
            + [_storage(n, 'san', shared=1) for n in ('pve3', 'pve4', 'pve5')]
            + [_storage('pve5', 'local-zfs')])


class _Resp:
    def __init__(self, status, data=None, text=''):
        self.status_code = status
        self._data = data
        self.text = text

    def json(self):
        return {'data': self._data}


class _Pve:
    """What the manager reads and sends: GET answers by path, PUTs and migrations recorded."""

    def __init__(self, reads=None):
        self.reads = dict(reads or {})
        self.gets, self.puts, self.migrations = [], [], []
        self.put_status = {}
        self.migrate_answer = {'success': True, 'task': 'UPID:pve5:1:2:3:qmigrate:9000:root@pam:'}
        self.task_ok = True
        self.on_put = None

    def get(self, url, **kw):
        path = url.split('/api2/json', 1)[1]
        if path == '/cluster/resources' and (kw.get('params') or {}).get('type') == 'storage':
            path = '/cluster/resources?type=storage'
        self.gets.append(path)
        if path not in self.reads:
            return _Resp(404, None, 'not found')
        value = self.reads[path]
        return value if isinstance(value, _Resp) else _Resp(200, value)

    def put(self, url, data=None, **kw):
        path = url.split('/api2/json', 1)[1]
        if self.on_put:
            self.on_put(path, data)
        self.puts.append((path, dict(data or {})))
        status = self.put_status.get(path, 200)
        return _Resp(status, None, '' if status == 200 else '{"data":null,"message":"permission denied\\n"}')

    def migrate(self, node, vmid, vm_type, target_node, online=True, options=None):
        self.migrations.append((node, vmid, vm_type, target_node, online))
        return dict(self.migrate_answer)


def _manager(pve, guests=(), cluster_id='cluster_1'):
    m = PegaProxManager.__new__(PegaProxManager)
    m.id = cluster_id
    m.current_host = None
    m.config = MagicMock(host='h', api_port=8006, dry_run=False, excluded_nodes=[], auto_migrate=True)
    m.config.name = 'Testi'
    m.logger = MagicMock()
    m._rolling_update = None
    m.is_connected = True
    m._no_agent_vms = set()
    m.get_node_status = lambda: NODES
    m._derive_proxlb_tag_rules = lambda *a, **k: {'rules': [], 'pins': {}, 'ignored': set()}
    m._count_vms_on_node = lambda node: 0
    m.get_vm_resources = lambda *a, **k: [dict(g) for g in guests]
    m._api_get = MagicMock(side_effect=pve.get)
    m._api_put = MagicMock(side_effect=pve.put)
    m.migrate_vm_manual = MagicMock(side_effect=pve.migrate)
    m._wait_for_task = MagicMock(side_effect=lambda node, upid, timeout=0: pve.task_ok)
    m.migrate_vm = MagicMock(return_value=True)
    return m


def _template(vmid, node='pve5', kind='qemu', name=None):
    return {'vmid': vmid, 'name': name or f'tpl{vmid}', 'node': node, 'type': kind,
            'status': 'stopped', 'template': 1, 'mem': 0}


def _running(vmid, node='pve5'):
    return {'vmid': vmid, 'name': f'g{vmid}', 'node': node, 'type': 'qemu', 'status': 'running', 'mem': 1}


def _evacuate(m, migrate_templates=True):
    task = MaintenanceTask('pve5')
    task.migrate_templates = migrate_templates
    PegaProxManager._evacuate_node(m, 'pve5', task)
    return task


def _reads(**configs):
    reads = {'/cluster/resources?type=storage': STORAGES}
    for vmid, cfg in configs.items():
        kind = 'lxc' if 'rootfs' in cfg else 'qemu'
        reads[f'/nodes/pve5/{kind}/{vmid[1:]}/config'] = cfg
    return reads


SAN_TEMPLATE = {'scsi0': 'san:base-9000-disk-0,size=32G', 'efidisk0': 'local-lvm:base-9000-disk-1,size=4M',
                'ide2': 'local-lvm:vm-9000-cloudinit,media=cdrom', 'net0': 'virtio=AA:BB:CC:DD:EE:01,bridge=vmbr0'}


# -- #763 templates -----------------------------------------------------------------------------

def test_a_template_moves_offline_to_a_node_with_all_its_storages():
    pve = _Pve(_reads(v9000=SAN_TEMPLATE))
    m = _manager(pve, [_running(100), _template(9000)])
    task = _evacuate(m)
    # san is on pve3/pve4/pve5 and local-lvm everywhere: pve4 has the lower score
    assert pve.migrations == [('pve5', 9000, 'qemu', 'pve4', False)], "a template goes offline, never live"
    assert task.templates_moved == [{'vmid': 9000, 'name': 'tpl9000', 'to': 'pve4'}]
    assert task.templates_left == []
    assert task.status == 'completed'
    # the running guest went the usual way
    assert m.migrate_vm.call_count == 1 and m.migrate_vm.call_args.args[0]['vmid'] == 100


def test_without_the_option_templates_stay_and_nothing_extra_is_read():
    pve = _Pve(_reads(v9000=SAN_TEMPLATE))
    m = _manager(pve, [_running(100), _template(9000)])
    task = _evacuate(m, migrate_templates=False)
    assert pve.migrations == []
    assert task.templates_moved == [] and task.templates_left == []
    assert '/cluster/resources?type=storage' not in pve.gets
    assert not any('/9000/' in p for p in pve.gets)
    assert task.status == 'completed'


def test_a_template_whose_storage_is_on_no_other_node_stays_with_the_reason():
    zfs = {'scsi0': 'local-zfs:base-9001-disk-0,size=8G'}
    pve = _Pve(_reads(v9001=zfs))
    m = _manager(pve, [_running(100), _template(9001)])
    task = _evacuate(m)
    assert pve.migrations == []
    assert task.templates_left == [{'vmid': 9001, 'name': 'tpl9001',
                                    'reason': 'no other node has storage local-zfs'}]
    assert task.status == 'completed', "a template that stays is no failed evacuation"
    assert task.failed_vms == []


def test_a_cd_image_on_local_storage_is_named_before_proxmox_refuses_it():
    iso = dict(SAN_TEMPLATE, ide2='local:iso/debian-12.iso,media=cdrom')
    pve = _Pve(_reads(v9000=iso))
    m = _manager(pve, [_template(9000)])
    task = _evacuate(m)
    assert pve.migrations == []
    assert task.templates_left[0]['reason'] == 'ide2 holds an image on local storage local - eject it first'
    row = m.template_placement([_template(9000)])[0]
    assert (row['code'], row['args']) == ('local_image', {'drive': 'ide2', 'storage': 'local'})


def test_templates_move_from_a_node_without_running_guests():
    ct = {'rootfs': 'san:base-9100-disk-0,size=4G', 'ostype': 'debian'}
    pve = _Pve(_reads(v9000=SAN_TEMPLATE, v9100=ct))
    m = _manager(pve, [_template(9000), _template(9100, kind='lxc')])
    task = _evacuate(m)
    assert sorted(pve.migrations) == [('pve5', 9000, 'qemu', 'pve4', False),
                                      ('pve5', 9100, 'lxc', 'pve4', False)]
    assert task.total_vms == 0 and task.status == 'completed'
    assert [t['vmid'] for t in task.templates_moved] == [9000, 9100]


def test_a_refused_or_failed_move_is_listed_and_the_evacuation_completes():
    pve = _Pve(_reads(v9000=SAN_TEMPLATE))
    pve.migrate_answer = {'success': False, 'error': '{"data":null,"message":"can\'t migrate VM which has linked clones\\n"}'}
    m = _manager(pve, [_running(100), _template(9000)])
    task = _evacuate(m)
    assert task.templates_left == [{'vmid': 9000, 'name': 'tpl9000',
                                    'reason': "Proxmox refused the migration: can't migrate VM which has linked clones"}]
    assert task.status == 'completed'

    pve = _Pve(_reads(v9000=SAN_TEMPLATE))
    pve.task_ok = False
    m = _manager(pve, [_template(9000)])
    task = _evacuate(m)
    assert task.templates_left[0]['reason'] == 'the migration task did not finish'
    assert task.status == 'completed'


def test_a_template_goes_to_a_node_the_run_is_done_with():
    """So a template on local storage is copied once and not again with the next node."""
    pve = _Pve(_reads(v9000=SAN_TEMPLATE))
    m = _manager(pve, [_template(9000)])
    # pve4 (lowest score) and pve3 are still to come, pve1 and pve6 are done
    m._rolling_update = {'status': 'running', 'nodes': ['pve1', 'pve6', 'pve5', 'pve4', 'pve3'], 'current_index': 2}
    lvm = {'scsi0': 'local-lvm:base-9000-disk-0,size=8G'}
    pve.reads['/nodes/pve5/qemu/9000/config'] = lvm
    _evacuate(m)
    assert pve.migrations == [('pve5', 9000, 'qemu', 'pve1', False)]
    # nothing settled among the candidates: the usual best node
    pve.migrations.clear()
    pve.reads['/nodes/pve5/qemu/9000/config'] = SAN_TEMPLATE
    _evacuate(m)
    assert pve.migrations == [('pve5', 9000, 'qemu', 'pve4', False)]


def test_an_unreadable_storage_list_moves_nothing():
    pve = _Pve({'/nodes/pve5/qemu/9000/config': SAN_TEMPLATE})
    m = _manager(pve, [_template(9000)])
    task = _evacuate(m)
    assert pve.migrations == []
    assert task.templates_left[0]['reason'] == 'the storage list of the cluster could not be read'


def test_enter_maintenance_mode_carries_the_option(monkeypatch):
    m = _manager(_Pve())
    m.maintenance_lock = threading.Lock()
    m.nodes_in_maintenance = {}
    m._set_ceph_maintenance_flags = lambda node: None
    m._try_native_ha_maintenance = lambda node, task: False
    started = []
    monkeypatch.setattr(m, '_evacuate_node', lambda node, task: started.append(task), raising=False)
    monkeypatch.setattr(mgrmod, 'get_db', lambda: MagicMock())
    task = PegaProxManager.enter_maintenance_mode(m, 'pve5', migrate_templates=True)
    deadline = time.time() + 5
    while not started and time.time() < deadline:
        time.sleep(0.01)
    assert task.migrate_templates is True and started == [task]
    m.nodes_in_maintenance.clear()
    assert PegaProxManager.enter_maintenance_mode(m, 'pve4').migrate_templates is False


# -- #954 negative affinity rules of Proxmox HA -------------------------------------------------

RULES = [
    {'rule': 'keep-apart', 'type': 'resource-affinity', 'affinity': 'negative', 'resources': 'vm:100,vm:101,vm:102'},
    {'rule': 'db-apart', 'type': 'resource-affinity', 'affinity': 'negative', 'resources': 'vm:200,ct:201'},
    {'rule': 'already-off', 'type': 'resource-affinity', 'affinity': 'negative', 'resources': 'vm:300,vm:301', 'disable': 1},
    {'rule': 'together', 'type': 'resource-affinity', 'affinity': 'positive', 'resources': 'vm:400,vm:401'},
    {'rule': 'pin-db', 'type': 'node-affinity', 'nodes': 'pve1', 'resources': 'vm:200', 'strict': 1},
    {'rule': 'bad id/../x', 'type': 'resource-affinity', 'affinity': 'negative', 'resources': 'vm:500,vm:501'},
]


def test_only_enabled_negative_resource_affinity_rules_are_switched_off_and_listed_first(db):
    pve = _Pve({'/cluster/ha/rules': RULES})
    m = _manager(pve)
    listed_before = []
    pve.on_put = lambda path, data: listed_before.append([r[0] for r in db.get_suspended_ha_rules('cluster_1')])
    off, failed = m.suspend_negative_ha_rules(who='admin')
    assert (off, failed) == (['keep-apart', 'db-apart'], [])
    assert pve.puts == [('/cluster/ha/rules/keep-apart', {'type': 'resource-affinity', 'disable': 1}),
                        ('/cluster/ha/rules/db-apart', {'type': 'resource-affinity', 'disable': 1})]
    # both in the database before the first PUT went out
    assert listed_before[0] == ['db-apart', 'keep-apart']
    assert [r[0] for r in db.get_suspended_ha_rules('cluster_1')] == ['db-apart', 'keep-apart']
    audit = db.conn.execute("SELECT user, details FROM audit_log WHERE action='ha.rules_suspended'").fetchall()
    assert len(audit) == 1 and audit[0][0] == 'admin' and 'keep-apart, db-apart' in audit[0][1]

    pve.puts.clear()
    on, left = m.restore_suspended_ha_rules(who='admin')
    assert (on, left) == (['db-apart', 'keep-apart'], [])
    assert pve.puts == [('/cluster/ha/rules/db-apart', {'type': 'resource-affinity', 'delete': 'disable'}),
                        ('/cluster/ha/rules/keep-apart', {'type': 'resource-affinity', 'delete': 'disable'})]
    assert db.get_suspended_ha_rules('cluster_1') == []
    assert db.conn.execute("SELECT COUNT(*) FROM audit_log WHERE action='ha.rules_restored'").fetchone()[0] == 1


def test_a_rule_proxmox_keeps_on_is_not_switched_on_later(db):
    pve = _Pve({'/cluster/ha/rules': RULES})
    pve.put_status['/cluster/ha/rules/db-apart'] = 403
    m = _manager(pve)
    off, failed = m.suspend_negative_ha_rules()
    assert (off, failed) == (['keep-apart'], ['db-apart'])
    assert [r[0] for r in db.get_suspended_ha_rules('cluster_1')] == ['keep-apart']


def test_a_rule_that_does_not_come_back_on_stays_listed_for_the_next_try(db):
    pve = _Pve({'/cluster/ha/rules': RULES})
    m = _manager(pve)
    m.suspend_negative_ha_rules()
    pve.put_status['/cluster/ha/rules/keep-apart'] = 500
    on, left = m.restore_suspended_ha_rules()
    assert (on, left) == (['db-apart'], ['keep-apart'])
    assert [r[0] for r in db.get_suspended_ha_rules('cluster_1')] == ['keep-apart']
    del pve.put_status['/cluster/ha/rules/keep-apart']
    assert m.restore_suspended_ha_rules() == (['keep-apart'], [])
    assert db.get_suspended_ha_rules('cluster_1') == []


def test_a_rule_deleted_meanwhile_leaves_the_list(db):
    db.save_suspended_ha_rules('cluster_1', ['gone'])
    m = _manager(_Pve())
    m._api_put = MagicMock(return_value=_Resp(500, None, '{"message":"no such ha rule \'gone\'\\n"}'))
    assert m.restore_suspended_ha_rules() == ([], [])
    assert db.get_suspended_ha_rules('cluster_1') == []


def test_a_cluster_without_ha_rules_has_nothing_to_switch(db):
    pve = _Pve({'/cluster/ha/rules': _Resp(501, None, "Method 'GET /cluster/ha/rules' not implemented")})
    m = _manager(pve)
    assert m.negative_ha_rules() == []
    assert m.suspend_negative_ha_rules() == ([], [])
    assert pve.puts == [] and db.get_suspended_ha_rules('cluster_1') == []
    # an unreadable answer is not "no rules"
    pve.reads['/cluster/ha/rules'] = _Resp(500, None, 'boom')
    assert m.negative_ha_rules() is None


def test_rules_left_off_by_a_run_that_died_go_back_on(db, monkeypatch):
    """The daemon loop: the process ended during the run, the rows survived it."""
    db.save_suspended_ha_rules('cluster_1', ['keep-apart'])
    pve = _Pve()
    m = _manager(pve)
    # a run that still holds them is left alone
    m._rolling_update = {'status': 'running', 'ha_rules_held': True}
    m._restore_suspended_ha_rules_if_due()
    assert pve.puts == []
    # a standby never acts
    m._rolling_update = None
    monkeypatch.setattr(ha, 'is_active', lambda: False)
    m._restore_suspended_ha_rules_if_due()
    assert pve.puts == []
    monkeypatch.setattr(ha, 'is_active', lambda: True)
    m._restore_suspended_ha_rules_if_due()
    assert pve.puts == [('/cluster/ha/rules/keep-apart', {'type': 'resource-affinity', 'delete': 'disable'})]
    assert db.get_suspended_ha_rules('cluster_1') == []
    # and with nothing listed it sends nothing
    m._restore_suspended_ha_rules_if_due()
    assert len(pve.puts) == 1


def test_the_rows_travel_to_the_standby():
    assert 'suspended_ha_rules' in ha.SYNC_TABLES


def _balancing_manager():
    m = PegaProxManager.__new__(PegaProxManager)
    m.id = 'cluster_1'
    m.config = MagicMock(auto_migrate=True, dry_run=False, excluded_nodes=[], migration_threshold=30,
                         check_interval=300, predictive_balancing=False)
    m.config.name = 'Testi'
    m.logger = MagicMock()
    m.get_node_status = lambda: {'pve1': {'status': 'online', 'score': 1}}
    m.check_balance_needed = lambda ns: (False, None, None)
    m._enforce_affinity_rules = MagicMock(return_value=0)
    return m


@pytest.mark.parametrize('state,enforced', [
    (None, True),
    ({'status': 'running'}, True),
    ({'status': 'running', 'relax_anti_affinity': True}, False),
    ({'status': 'paused', 'relax_anti_affinity': True}, False),
    ({'status': 'completed', 'relax_anti_affinity': True}, True),
])
def test_the_balancer_keeps_anti_affinity_guests_together_while_a_relaxed_run_runs(state, enforced):
    m = _balancing_manager()
    m._rolling_update = state
    PegaProxManager.run_balance_check(m)
    assert m._enforce_affinity_rules.called == enforced


# -- the rolling update route --------------------------------------------------------------------

class _FastTime:
    def __getattr__(self, name):
        return getattr(time, name)

    @staticmethod
    def sleep(_s):
        time.sleep(0.001)


def _cluster_manager(api, guests=(), cluster_type='proxmox', update_ok=True):
    fake = api.make_fake_manager('cluster_1', cluster_type=cluster_type)
    fake.config.name = 'Testi'
    fake.get_node_status.return_value = {'pve1': {'status': 'online'}, 'pve2': {'status': 'online'}}
    # the quorum gate before each node reads /cluster/status: three votes, one node may go
    fake._ha_cluster_status.return_value = [{'type': 'cluster', 'quorate': 1}] + [
        {'type': 'node', 'name': n, 'online': 1} for n in ('pve1', 'pve2', 'pve3')]
    fake.get_ceph_health_summary.return_value = None
    fake.get_vm_resources.return_value = [dict(g) for g in guests]
    fake.nodes_in_maintenance = {}
    fake.maintenance_lock = threading.Lock()
    fake._rolling_update = None
    order = []

    def enter(node, **kw):
        order.append(('enter', node, kw))
        t = MaintenanceTask(node)
        t.status = 'completed'
        if kw.get('migrate_templates'):
            t.templates_moved = [{'vmid': 9000, 'name': 'tpl9000', 'to': 'pve2'}]
            t.templates_left = [{'vmid': 9001, 'name': 'tpl9001', 'reason': 'no other node has storage local-zfs'}]
        fake.nodes_in_maintenance[node] = t
        return t

    def leave(node):
        order.append(('exit', node))
        return fake.nodes_in_maintenance.pop(node, None) is not None

    def update(node, reboot=False):
        order.append(('update', node))
        if not update_ok:
            return None
        t = UpdateTask(node, reboot=False)
        t.status, t.phase = 'completed', 'done'
        return t

    fake.enter_maintenance_mode.side_effect = enter
    fake.exit_maintenance_mode.side_effect = leave
    fake.start_node_update.side_effect = update
    fake.suspend_negative_ha_rules.side_effect = lambda who='system': (order.append(('rules off', who)) or (['keep-apart'], []))
    fake.restore_suspended_ha_rules.side_effect = lambda who='system': (order.append(('rules on', who)) or (['keep-apart'], []))
    api.set_manager('cluster_1', fake)
    return fake, order


def _start(api, seed, body, wait=True):
    root = seed.user('root', role='admin')
    c = api.as_user(root)
    r = c.post('/api/clusters/cluster_1/updates/rolling',
               json=dict({'include_reboot': False, 'skip_up_to_date': False}, **body))
    assert r.status_code == 200, r.data
    return c


def _finish(fake, seconds=20):
    deadline = time.time() + seconds
    while time.time() < deadline and (fake._rolling_update or {}).get('status') in ('running', 'paused'):
        time.sleep(0.02)
    return fake._rolling_update


@pytest.fixture
def fast(monkeypatch):
    import pegaprox.api.settings as settings_mod
    monkeypatch.setattr(settings_mod, 'time', _FastTime())


GUESTS = [{'vmid': 100, 'name': 'web', 'node': 'pve1', 'type': 'qemu', 'status': 'running'},
          {'vmid': 9000, 'name': 'tpl9000', 'node': 'pve1', 'type': 'qemu', 'status': 'stopped', 'template': 1}]


def test_a_relaxed_run_switches_the_rules_off_before_its_first_evacuation_and_on_at_its_end(api, seed, fast):
    fake, order = _cluster_manager(api, GUESTS)
    _start(api, seed, {'relax_anti_affinity': True})
    state = _finish(fake)
    assert state['status'] == 'completed', state['logs']
    steps = [o[0] if o[0].startswith('rules') else f'{o[0]} {o[1]}' for o in order]
    assert steps == ['rules off', 'enter pve1', 'update pve1', 'exit pve1',
                     'enter pve2', 'update pve2', 'exit pve2', 'rules on'], steps
    assert ('rules off', 'root') in order and ('rules on', 'root') in order
    logs = '\n'.join(state['logs'])
    assert 'relax_anti_affinity=True' in logs
    assert 'Negative affinity: 1 Proxmox HA rule(s) switched off until the run ends: keep-apart' in logs
    assert 'Negative affinity rules switched back on: keep-apart' in logs
    assert state['ha_rules_held'] is False


def test_a_default_run_touches_no_rule_and_moves_no_template(api, seed, fast):
    fake, order = _cluster_manager(api, GUESTS)
    _start(api, seed, {})
    state = _finish(fake)
    assert state['status'] == 'completed', state['logs']
    assert fake.suspend_negative_ha_rules.call_count == 0 and fake.restore_suspended_ha_rules.call_count == 0
    assert [o[2] for o in order if o[0] == 'enter'] == [{'skip_evacuation': False, 'allow_local_disks': False}] * 2
    logs = '\n'.join(state['logs'])
    assert 'migrate_templates=False, relax_anti_affinity=False' in logs
    # said either way: without the option the template goes down with the node
    assert 'template(s) staying here: tpl9000 (9000)' in logs
    assert 'pve1: 2 guests present (1 running, 1 stopped)' in logs


def test_the_template_option_reaches_the_evacuation_and_the_log(api, seed, fast):
    fake, order = _cluster_manager(api, GUESTS)
    _start(api, seed, {'migrate_templates': True})
    state = _finish(fake)
    assert [o[2].get('migrate_templates') for o in order if o[0] == 'enter'] == [True, True]
    logs = '\n'.join(state['logs'])
    assert 'template(s) to move: tpl9000 (9000)' in logs
    assert '✓ Template tpl9000 (9000) moved to pve2' in logs
    assert '⚠ Template tpl9001 (9001) stays on the node: no other node has storage local-zfs' in logs
    assert fake.suspend_negative_ha_rules.call_count == 0


def test_a_cancelled_run_switches_the_rules_back_on(api, seed, fast):
    fake, order = _cluster_manager(api, GUESTS, update_ok=False)
    c = _start(api, seed, {'relax_anti_affinity': True})
    deadline = time.time() + 10
    while time.time() < deadline and (fake._rolling_update or {}).get('status') != 'paused':
        time.sleep(0.02)
    assert fake._rolling_update['paused_reason'] == 'node_failure'
    assert ('rules on', 'root') not in order, "paused is still part of the run"
    assert c.delete('/api/clusters/cluster_1/updates/rolling').status_code == 200
    deadline = time.time() + 10
    while time.time() < deadline and ('rules on', 'root') not in order:
        time.sleep(0.02)
    assert ('rules on', 'root') in order


def test_a_run_whose_rules_stay_on_still_evacuates(api, seed, fast):
    fake, order = _cluster_manager(api, GUESTS)
    fake.suspend_negative_ha_rules.side_effect = lambda who='system': ([], ['keep-apart'])
    _start(api, seed, {'relax_anti_affinity': True})
    state = _finish(fake)
    assert state['status'] == 'completed'
    assert fake.restore_suspended_ha_rules.call_count == 0
    assert '⚠ Proxmox kept these rules on, their guests may still not move: keep-apart' in '\n'.join(state['logs'])


def test_xcpng_ignores_both_options(api, seed, fast):
    fake, order = _cluster_manager(api, GUESTS, cluster_type='xcpng')
    _start(api, seed, {'relax_anti_affinity': True, 'migrate_templates': True})
    state = _finish(fake)
    assert fake.suspend_negative_ha_rules.call_count == 0
    assert all('migrate_templates' not in o[2] for o in order if o[0] == 'enter')
    assert state['relax_anti_affinity'] is False and state['migrate_templates'] is False


def test_the_start_is_audited_with_its_options(api, seed, fast):
    fake, _order = _cluster_manager(api, GUESTS)
    _start(api, seed, {'migrate_templates': True, 'relax_anti_affinity': True})
    _finish(fake)
    rows = seed.db.conn.execute(
        "SELECT user, details FROM audit_log WHERE action='node.rolling_update_started'").fetchall()
    assert len(rows) == 1 and rows[0][0] == 'root'
    assert 'templates move with the evacuation; negative affinity rules give way until it ends' in rows[0][1]


# -- the plan ------------------------------------------------------------------------------------

PLAN_GUESTS = [
    _running(100, node='pve1'), _running(101, node='pve3'),
    _template(9000, node='pve5'), _template(9001, node='pve5', name='zfs-tpl'),
]


def _plan_manager(api, db):
    reads = _reads(v9000=SAN_TEMPLATE, v9001={'scsi0': 'local-zfs:base-9001-disk-0,size=8G'})
    reads['/cluster/ha/rules'] = RULES
    pve = _Pve(reads)
    m = _manager(pve, PLAN_GUESTS)
    api.set_manager('cluster_1', m)
    return m, pve


def test_the_plan_says_what_each_option_changes(api, seed, monkeypatch):
    m, pve = _plan_manager(api, seed.db)
    monkeypatch.setattr(m, '_derive_proxlb_tag_rules', lambda *a, **k: {'rules': [
        {'name': 'tagged anti-affinity: web', 'type': 'separate', 'vms': ['100', '101'], 'enabled': True, 'enforce': True},
        {'name': 'soft', 'type': 'separate', 'vms': ['1', '2'], 'enabled': True, 'enforce': False}]})
    seed.db.save_suspended_ha_rules('cluster_1', ['old-rule'])
    r = api.as_user(seed.user('root', role='admin')).get('/api/clusters/cluster_1/updates/rolling/plan')
    assert r.status_code == 200, r.data
    plan = r.get_json()
    assert plan['supported'] is True and plan['online_nodes'] == 5
    by_id = {t['vmid']: t for t in plan['templates']}
    assert by_id[9000]['targets'] == ['pve3', 'pve4'] and by_id[9000]['reason'] == ''
    assert by_id[9000]['storages'] == ['local-lvm', 'san']
    assert by_id[9001]['targets'] == [] and by_id[9001]['reason'] == 'no other node has storage local-zfs'
    # and for the dialog, to say it in its own language
    assert (by_id[9001]['code'], by_id[9001]['args']) == ('storage_missing', {'storages': 'local-zfs'})
    assert (by_id[9000]['code'], by_id[9000]['args']) == ('', {})
    assert [(x['rule'], x['resources'], x['blocks']) for x in plan['negative_rules']] == [
        ('keep-apart', ['vm:100', 'vm:101', 'vm:102'], False), ('db-apart', ['vm:200', 'ct:201'], False)]
    assert plan['own_rules'] == [{'name': 'tagged anti-affinity: web', 'guests': 2}]
    assert plan['balancer_separates'] is True
    assert plan['still_off'] == ['old-rule']
    # it reads and nothing else
    assert pve.puts == [] and pve.migrations == []


def test_the_plan_flags_a_rule_with_as_many_guests_as_nodes(api, seed):
    m, _pve = _plan_manager(api, seed.db)
    m.get_node_status = lambda: {n: d for n, d in NODES.items() if n in ('pve1', 'pve3', 'pve4')}
    plan = api.as_user(seed.user('root', role='admin')).get('/api/clusters/cluster_1/updates/rolling/plan').get_json()
    assert {x['rule']: x['blocks'] for x in plan['negative_rules']} == {'keep-apart': True, 'db-apart': False}


def test_the_plan_of_an_xcpng_pool_says_unsupported(api, seed):
    api.set_manager('cluster_1', api.make_fake_manager('cluster_1', cluster_type='xcpng'))
    r = api.as_user(seed.user('root', role='admin')).get('/api/clusters/cluster_1/updates/rolling/plan')
    assert r.get_json() == {'supported': False}


def _pool_user(seed, name, perms):
    import pegaprox.utils.rbac as rbac
    seed.tenant('tenant_x', clusters=['cluster_1'])
    u = seed.user(name, role='viewer', tenant_id='tenant_x', permissions=perms)
    seed.pool('cluster_1', 'pool_1', name, ['pool.view', 'vm.view'])
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache['cluster_1'] = {'data': {'100:qemu': 'pool_1'}, 'timestamp': time.time(),
                                                    'refreshing': False}
    return u


def test_nobody_confined_or_elsewhere_reads_the_plan(api, seed):
    m, pve = _plan_manager(api, seed.db)
    seed.tenant('globex', clusters=['cluster_2'])
    api.set_manager('cluster_2', api.make_fake_manager('cluster_2'))
    callers = {
        'confined admin': seed.user('gx', role='admin', tenant_id='globex',
                                    tenant_permissions={'globex': {'role': 'user'}}),
        'other tenant': seed.user('milton', role='user', tenant_id='globex', permissions=['node.update']),
        'pool-confined': _pool_user(seed, 'mallory', ['node.update', 'node.view', 'cluster.view']),
        'no node.update': seed.user('vic', role='viewer'),
    }
    for who, user in callers.items():
        r = api.as_user(user).get('/api/clusters/cluster_1/updates/rolling/plan')
        assert r.status_code == 403, (who, r.status_code, r.get_data(as_text=True))
    assert pve.gets == [], 'a refused caller made the manager read'
    # an operator of the whole cluster may
    ops = seed.user('ops', role='user', permissions=['node.update', 'node.view', 'cluster.view'])
    assert api.as_user(ops).get('/api/clusters/cluster_1/updates/rolling/plan').status_code == 200
