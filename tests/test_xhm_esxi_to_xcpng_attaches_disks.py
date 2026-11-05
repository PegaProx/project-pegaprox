"""ESXi -> XCP-ng migration attaches the disks it copied, and a network.

`_run_esxi_to_xcpng` has called `_xcpng_attach_vdi` and `_xcpng_attach_network` since
0.9.2. Neither was ever written. Each call sits in its own try, so the NameError was
logged as "Warning: attach VDI failed: name '_xcpng_attach_vdi' is not defined", the
network one was swallowed by a bare except, and the task ended "completed": a new VM
with no disk and no network, its copied VDIs left unattached on the SR. The PVE ->
XCP-ng leg of the same module attaches with VBD.create and `_xcp_attach_network`; this
leg now does the same.

The runner is driven to the end with the transfer faked (scp and qemu-img succeed, the
import answers 200) and a fake XAPI that records what is created.
"""
import subprocess
import types

import pegaprox.core.xhm as xhm_core
import pegaprox.globals as ppglobals

ESXI, TGT = 'esxi1', 'xcp1'
DISKS = {'data': {'name': 'vm1', 'memory_mb': 2048, 'cpu_count': 2, 'disks': [
    {'vmdk_file': '[ds1] vm1/vm1.vmdk', 'capacity_bytes': 1 << 20, 'capacity_gb': 1},
    {'vmdk_file': '[ds1] vm1/vm1_1.vmdk', 'capacity_bytes': 1 << 20, 'capacity_gb': 1}]}}


class _Xapi:
    """What the runner asks of XAPI, with every VBD and VIF it creates kept."""

    def __init__(self):
        self.vbds, self.vifs = [], []
        vdis = iter(['vdi-a', 'vdi-b'])
        self.SR = types.SimpleNamespace(get_all=lambda: ['sr'], get_record=lambda r: {'name_label': 'sr1'})
        self.VDI = types.SimpleNamespace(create=lambda rec: next(vdis), get_uuid=lambda r: f'uuid-{r}',
                                         destroy=lambda r: None)
        self.VM = types.SimpleNamespace(
            get_all=lambda: ['tpl'], get_is_a_template=lambda r: True,
            get_name_label=lambda r: 'Other install media', clone=lambda r, name: 'new-vm',
            set_is_a_template=lambda r, v: None, set_memory_limits=lambda *a: None,
            set_VCPUs_at_startup=lambda *a: None, set_VCPUs_max=lambda *a: None,
            get_platform=lambda r: {}, set_platform=lambda *a: None,
            get_VIFs=lambda r: [])
        self.VBD = types.SimpleNamespace(create=self.vbds.append)
        self.VIF = types.SimpleNamespace(create=self.vifs.append, get_device=lambda r: '0')
        self.network = types.SimpleNamespace(
            get_all=lambda: ['net-0', 'net-1'], get_uuid=lambda r: f'uuid-{r}',
            get_by_uuid=lambda u: u[len('uuid-'):], get_record=lambda r: {'name_label': r, 'bridge': r})


def _run(monkeypatch, tmp_path):
    def _proc(argv, **kw):
        # scp and qemu-img leave their output file behind, as the real ones do
        with open(argv[-1], 'wb') as fh:
            fh.write(b'\0' * 16)
        return types.SimpleNamespace(returncode=0, stderr=b'', stdout=b'')

    monkeypatch.setattr(subprocess, 'run', _proc)
    monkeypatch.setattr(xhm_core.ha_transport, 'http',
                        lambda *a, **k: types.SimpleNamespace(status_code=200))
    xapi = _Xapi()
    monkeypatch.setitem(ppglobals.cluster_managers, ESXI, types.SimpleNamespace(
        is_connected=True, host='10.0.0.5', config=types.SimpleNamespace(ssh_user='root', pass_='pw'),
        get_vm_disks_for_export=lambda vmid: DISKS))
    monkeypatch.setitem(ppglobals.cluster_managers, TGT, types.SimpleNamespace(
        is_connected=True, host='xcp', _api=lambda: xapi, _session=types.SimpleNamespace(_session='s'),
        config=types.SimpleNamespace(ssl_verification=False)))
    task = xhm_core.XHMigrationTask('t-attach', 'esxi_to_xcpng', ESXI, '', '5', TGT, '', 'sr1')
    task.scratch = str(tmp_path / 'scratch')
    xhm_core._run_esxi_to_xcpng(task)
    return task, xapi


def test_the_new_vm_gets_every_copied_disk(db, monkeypatch, tmp_path):
    task, xapi = _run(monkeypatch, tmp_path)

    assert [(v['VM'], v['VDI'], v['userdevice'], v['bootable'], v['type'], v['mode']) for v in xapi.vbds] == [
        ('new-vm', 'vdi-a', '0', True, 'Disk', 'RW'),
        ('new-vm', 'vdi-b', '1', False, 'Disk', 'RW'),
    ], f'the migrated VM got these disks: {xapi.vbds}; log: {task.log_lines[-4:]}'
    assert task.phase == 'completed', task.error


def test_the_new_vm_gets_a_network(db, monkeypatch, tmp_path):
    task, xapi = _run(monkeypatch, tmp_path)

    assert [(v['VM'], v['network'], v['device']) for v in xapi.vifs] == [('new-vm', 'net-0', '0')], (
        f'the migrated VM got these VIFs: {xapi.vifs}')
