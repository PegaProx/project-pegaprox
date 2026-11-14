"""ESXi -> XCP-ng: a disk that does not attach is said, and a network map is what it says.

Once the disks were attached at all, a VBD.create that XAPI refused was still only a
warning, and the task ended "completed" with a guest that cannot start. A boot disk that
did not attach now fails the task and names the VDIs left on the pool; a data disk that
did not attach is said in the final line. The network map was sorted as text ('10' before
'2') and cut at four NICs without a word, and a map that was no dict ('x', a list, a
number) failed the task after the guest and its disks were made: the start route refuses
it, and the task takes only a dict. MK Nov 2026
"""
import types

import pytest

import pegaprox.core.xhm as xhm_core
import pegaprox.globals as ppglobals
from test_xhm_esxi_to_xcpng_attaches_disks import _run


def _refuse(xapi, devices):
    kept = xapi.vbds

    def create(rec):
        if rec['userdevice'] in devices:
            raise RuntimeError('DEVICE_ALREADY_EXISTS')
        kept.append(rec)
    xapi.VBD = types.SimpleNamespace(create=create)


def _no_uuid(u):
    raise LookupError(u)


def _runner(monkeypatch, refuse=(), networks=('net-0', 'net-1')):
    """Before _run of the attach test drives the runner: a VBD.create that refuses some
    devices, and the pool's networks found by their name."""
    real = xhm_core._run_esxi_to_xcpng
    seen = {}

    def run(task):
        xapi = ppglobals.cluster_managers[task.target_cluster]._api()
        _refuse(xapi, set(refuse))
        xapi.network = types.SimpleNamespace(get_all=lambda: list(networks), get_by_uuid=_no_uuid,
                                             get_record=lambda r: {'name_label': r, 'bridge': r})
        seen['xapi'] = xapi
        return real(task)
    monkeypatch.setattr(xhm_core, '_run_esxi_to_xcpng', run)
    return seen


@pytest.mark.parametrize('refuse', [('0',), ('0', '1')])
def test_a_boot_disk_that_did_not_attach_fails_the_migration(db, monkeypatch, tmp_path, refuse):
    seen = _runner(monkeypatch, refuse=refuse)
    task, _ = _run(monkeypatch, tmp_path)
    assert task.phase == 'failed', (task.phase, task.log_lines[-4:])
    assert 'left on the pool' in task.error and 'uuid-vdi-a' in task.error, task.error
    assert seen['xapi'].vifs == []
    assert not any('Migration complete' in line for line in task.log_lines)


def test_a_data_disk_that_did_not_attach_is_said_at_the_end(db, monkeypatch, tmp_path):
    seen = _runner(monkeypatch, refuse=('1',))
    task, _ = _run(monkeypatch, tmp_path)
    assert task.phase == 'completed', task.error
    assert [v['userdevice'] for v in seen['xapi'].vbds] == ['0']
    assert any('1 data disk(s) not attached' in line for line in task.log_lines), task.log_lines[-3:]
    assert any('disk 1 (VDI uuid-vdi-b)' in line for line in task.log_lines), task.log_lines[-4:]


def test_the_networks_go_in_the_numeric_order_of_their_nic_and_a_cut_is_said(db, monkeypatch, tmp_path):
    nets = ('net-0', 'net-1', 'net-2', 'net-10', 'net-11')
    seen = _runner(monkeypatch, networks=nets)
    task, _ = _run(monkeypatch, tmp_path, network_map={'11': 'net-11', '2': 'net-2', '10': 'net-10',
                                                         '0': 'net-0', '1': 'net-1'})
    assert task.phase == 'completed', task.error
    assert [(v['network'], v['device']) for v in seen['xapi'].vifs] == [
        ('net-0', '0'), ('net-1', '1'), ('net-2', '2'), ('net-10', '3')]
    assert any('5 networks mapped, the first 4 are attached' in line for line in task.log_lines)


@pytest.mark.parametrize('bad', ['x', ['a'], 5])
def test_a_task_takes_only_a_dict_as_its_network_map(bad):
    task = xhm_core.XHMigrationTask('t-nm', 'esxi_to_xcpng', 'esxi1', '', '5', 'xcp1', '', 'sr1',
                                    config={'network_map': bad})
    assert task.network_map == {}


@pytest.mark.parametrize('bad', ['x', ['a'], 5, {'0': 7}, {'0': ['net']}])
def test_the_start_route_refuses_a_network_map_that_is_no_map_of_names(api, seed, bad):
    root = api.as_user(seed.user('root', role='admin'))
    r = root.post('/api/xhm/migrate', json={'source_cluster': 'esxi1', 'source_vmid': '5',
                                            'target_cluster': 'xcp1', 'target_storage': 'sr1',
                                            'network_map': bad})
    assert r.status_code == 400 and r.get_json().get('field') == 'network_map', r.get_data(as_text=True)


def test_the_start_route_still_takes_a_map_of_names(api, seed):
    root = api.as_user(seed.user('root', role='admin'))
    r = root.post('/api/xhm/migrate', json={'source_cluster': 'esxi1', 'source_vmid': '5',
                                            'target_cluster': 'xcp1', 'target_storage': 'sr1',
                                            'network_map': {'0': 'net-1', 'VM Network': None}})
    # past the map check; the clusters of this test do not exist
    assert r.get_json().get('field') != 'network_map', r.get_data(as_text=True)


# --- the source NICs reach the dialog, and the template's own disks go first ------------------

SOAP_NICS = [{'type': 'VirtualVmxnet3', 'label': 'Network adapter 1', 'network': 'VM Network', 'mac_address': '00:50:56:aa:00:01'},
             {'type': 'VirtualE1000e', 'label': 'Network adapter 2', 'network': 'Backup LAN', 'mac_address': '00:50:56:aa:00:02'}]
REST_NICS = {'4001': {'label': 'Network adapter 2', 'mac_address': '00:50:56:aa:00:02',
                      'backing': {'type': 'STANDARD_PORTGROUP', 'network_name': 'Backup LAN'}},
             '4000': {'label': 'Network adapter 1', 'mac_address': '00:50:56:aa:00:01',
                      'backing': {'type': 'STANDARD_PORTGROUP', 'network_name': 'VM Network'}}}


@pytest.mark.parametrize('nics', [SOAP_NICS, REST_NICS], ids=['soap', 'rest'])
def test_the_export_info_carries_the_network_adapters_in_their_order(nics):
    from pegaprox.core.vmware import VMwareManager
    mgr = object.__new__(VMwareManager)
    mgr.get_vm = lambda vm_id: {'data': {'name': 'vm1', 'disks': {}, 'nics': nics}}
    got = mgr.get_vm_disks_for_export('5')['data']['nics']
    assert [(n['network'], n['mac_address']) for n in got] == [
        ('VM Network', '00:50:56:aa:00:01'), ('Backup LAN', '00:50:56:aa:00:02')]


def _plan(monkeypatch, nics):
    src = types.SimpleNamespace(cluster_type='esxi', is_connected=True,
                                get_vm_disks_for_export=lambda vmid: {'data': {
                                    'name': 'vm1', 'power_state': 'POWERED_OFF', 'guest_os': '', 'cpu_count': 2,
                                    'memory_mb': 2048, 'disks': [], 'nics': nics}})
    tgt = types.SimpleNamespace(cluster_type='xcpng', is_connected=True, id='xcp1', config=types.SimpleNamespace(name='pool'),
                                get_storages=lambda: [{'storage': 'sr1', 'uuid': 'u1', 'type': 'lvm'}],
                                get_networks=lambda: [{'name': 'net-a', 'uuid': 'na', 'iface': 'xenbr0'}])
    monkeypatch.setitem(xhm_core.cluster_managers, 'esxi1', src)
    monkeypatch.setitem(xhm_core.cluster_managers, 'xcp1', tgt)
    return xhm_core.plan_esxi_to_xcpng('esxi1', '5', 'xcp1')


def test_the_plan_offers_a_network_for_each_adapter_keyed_by_its_index(monkeypatch):
    nics = [{'label': 'Network adapter 1', 'network': 'VM Network', 'mac_address': 'm1'},
            {'label': 'Network adapter 2', 'network': '', 'mac_address': 'm2'}]
    plan = _plan(monkeypatch, nics)
    nets = plan['source']['networks']
    assert [n['network'] for n in nets] == ['VM Network', 'Network adapter 2']
    # the dialog keys the map by `bridge` when there is one, else by the NIC's index
    assert all('bridge' not in n for n in nets)


def test_a_disk_the_template_brought_goes_before_the_boot_disk(db, monkeypatch, tmp_path):
    real = xhm_core._run_esxi_to_xcpng
    seen, dropped = {}, []

    def run(task):
        xapi = ppglobals.cluster_managers[task.target_cluster]._api()
        attached = xapi.vbds
        xapi.VM.get_VBDs = lambda r: ['tpl-vbd', 'tpl-cd']
        xapi.VBD = types.SimpleNamespace(
            create=attached.append,
            get_record=lambda r: {'type': 'Disk' if r == 'tpl-vbd' else 'CD', 'VDI': 'tpl-vdi'},
            destroy=lambda r: dropped.append(('VBD', r, len(attached))))
        xapi.VDI.destroy = lambda r: dropped.append(('VDI', r, len(attached)))
        seen['xapi'] = xapi
        return real(task)
    monkeypatch.setattr(xhm_core, '_run_esxi_to_xcpng', run)
    task, _ = _run(monkeypatch, tmp_path)
    assert task.phase == 'completed', task.error
    # the template's disk and its VDI, not its CD drive, and before any disk of ours was attached
    assert dropped == [('VBD', 'tpl-vbd', 0), ('VDI', 'tpl-vdi', 0)]
    assert [v['userdevice'] for v in seen['xapi'].vbds] == ['0', '1']
