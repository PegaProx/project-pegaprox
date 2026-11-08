"""A disk that could not be attached fails the migration, and the source stays.

Between XCP-ng and Proxmox these were warnings: the run went on to destroy the source and said completed, with
a target that had no disk. The volumes were only left behind on the storage.

On Proxmox the attach is the synchronous PUT: a POST answers 200 with a task that can still fail. The create
call answers with its task too, and until that task is through the new VM is locked, so the attach waits for it.
"""
import ast
import inspect
import types
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

import pegaprox.core.xhm as xhm

VOLS = [{'index': 0, 'vol_id': 'store:vm-200-disk-0'}, {'index': 1, 'vol_id': 'store:vm-200-disk-1'}]
UPID = 'UPID:pve1:0000ABCD:0001F00D:6729A000:qmcreate:200:root@pam:'


class _Answer:
    def __init__(self, status, body=None):
        self.status_code = status
        self._body = {'data': None} if body is None else body
        self.text = str(self._body)
        self.headers = {'content-type': 'application/json;charset=UTF-8'}

    def json(self):
        return self._body


def _attach(answers):
    logs, phases, sent, timeouts = [], [], [], []
    seen = iter(answers)

    def put(url, data=None, **kw):
        sent.append(data)
        timeouts.append(kw.get('timeout'))
        answer = next(seen)
        if isinstance(answer, Exception):
            raise answer
        return answer if isinstance(answer, _Answer) else _Answer(answer)
    mgr = SimpleNamespace(host='pve', api_port=8006, _api_put=put)
    task = SimpleNamespace(target_node='pve1', log=logs.append, set_phase=lambda *a: phases.append(a))
    done = xhm._attach_pve_volumes(mgr, task, 200, VOLS)
    assert timeouts == [60] * len(sent), timeouts
    return done, phases, sent


def test_every_disk_attached_goes_on():
    done, phases, sent = _attach([200, 200])
    assert done is True and phases == []
    assert sent == [{'scsi0': 'store:vm-200-disk-0'}, {'scsi1': 'store:vm-200-disk-1'}]


@pytest.mark.parametrize('answers,says', [([200, 500], 'scsi1: HTTP 500'), ([500, 200], 'scsi0: HTTP 500'),
                                          ([RuntimeError('gone'), 200], 'scsi0: gone')])
def test_one_that_did_not_fails_and_all_are_tried(answers, says):
    done, phases, sent = _attach(answers)
    assert done is False and len(sent) == 2
    assert phases[0][0] == 'failed' and says in phases[0][1] and 'source VM stays' in phases[0][1]


def test_it_attaches_with_the_synchronous_call():
    used = []
    mgr = SimpleNamespace(host='pve', api_port=8006,
                          _api_post=lambda url, data=None, **kw: used.append('POST') or _Answer(200, {'data': UPID}),
                          _api_put=lambda url, data=None, **kw: used.append('PUT') or _Answer(200))
    task = SimpleNamespace(target_node='pve1', log=lambda m: None, set_phase=lambda *a: None)
    assert xhm._attach_pve_volumes(mgr, task, 200, VOLS) is True
    assert used == ['PUT', 'PUT']


def test_the_reason_proxmox_gave_is_in_the_message():
    _, phases, _ = _attach([200, _Answer(500, {'data': None, 'message': 'VM is locked (create)\n'})])
    assert 'scsi1: HTTP 500 - VM is locked (create)' in phases[0][1], phases


def test_a_refused_parameter_names_it():
    _, phases, _ = _attach([_Answer(400, {'data': None, 'errors': {'scsi0': 'invalid format'}}), 200])
    assert 'scsi0: HTTP 400 - scsi0: invalid format' in phases[0][1], phases


def test_the_message_names_what_is_left():
    _, phases, _ = _attach([200, 500])
    said = phases[0][1]
    assert 'VM 200 on pve1' in said and all(v['vol_id'] in said for v in VOLS), said


# -- the create task -------------------------------------------------------------------------------

def _created(body, finished=True):
    waited, phases = [], []
    mgr = SimpleNamespace(_wait_for_task=lambda node, upid, timeout=600: waited.append((node, upid)) or finished)
    task = SimpleNamespace(target_node='pve1', set_phase=lambda *a: phases.append(a))
    return xhm._pve_create_done(mgr, task, _Answer(200, body), 200, VOLS), waited, phases


def test_the_create_task_is_waited_for_on_its_node():
    done, waited, phases = _created({'data': UPID})
    assert done is True and waited == [('pve1', UPID)] and phases == []


def test_a_create_task_that_did_not_finish_fails_the_run():
    done, _, phases = _created({'data': UPID}, finished=False)
    assert done is False and phases[0][0] == 'failed'
    assert 'source VM stays' in phases[0][1] and all(v['vol_id'] in phases[0][1] for v in VOLS), phases


@pytest.mark.parametrize('body', [{'data': None}, {'data': 'done'}, ['UPID:x']])
def test_an_answer_without_a_task_is_not_waited_for(body):
    done, waited, phases = _created(body)
    assert done is True and waited == [] and phases == []


# -- the legs --------------------------------------------------------------------------------------

def _guard(fn, helper):
    """The one `if not helper(...): return` in fn."""
    tree = ast.parse(inspect.getsource(fn))
    ifs = [n for n in ast.walk(tree) if isinstance(n, ast.If)
           and any(isinstance(c, ast.Call) and getattr(c.func, 'id', None) == helper for c in ast.walk(n.test))]
    assert len(ifs) == 1, f'{helper}: {len(ifs)} guards'
    test = ifs[0].test
    assert isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not), ast.dump(test)
    assert isinstance(test.operand, ast.Call) and getattr(test.operand.func, 'id', None) == helper, ast.dump(test)
    assert isinstance(ifs[0].body[0], ast.Return), ast.dump(ifs[0])
    return ifs[0]


@pytest.mark.parametrize('fn', [xhm._run_xcpng_to_pve, xhm._run_esxi_to_pve])
def test_the_paths_to_proxmox_stop_on_it(fn):
    created = _guard(fn, '_pve_create_done')
    attached = _guard(fn, '_attach_pve_volumes')
    assert created.lineno < attached.lineno


# ESXi to Proxmox, driven: a node shell that imports one disk, a Proxmox API that records what it is asked

class _Stream:
    def __init__(self, payload=b''):
        self._payload = payload
        self.channel = types.SimpleNamespace(recv_exit_status=lambda: 0)

    def read(self, *a):
        return self._payload


class _NodeShell:
    def exec_command(self, cmd, timeout=None, **kw):
        if cmd.lstrip().startswith('ls '):
            out = b'web01-flat.vmdk\n'
        elif cmd.startswith('pvesm alloc'):
            out = b"successfully created 'store:vm-900-disk-0'\n"
        elif cmd.startswith('pvesm path'):
            out = b'/dev/store/vm-900-disk-0\n'
        else:
            out = b''
        return _Stream(), _Stream(out), _Stream()

    def close(self):
        pass


class _Esxi:
    is_connected = True
    host = '10.0.0.5'
    api_port = 8006
    config = types.SimpleNamespace(ssh_user='root', pass_='pw', ssh_key='', ssh_port=22)

    def get_vm_disks_for_export(self, vmid):
        return {'data': {'name': 'web01', 'guest_os': 'ubuntu64Guest', 'memory_mb': 2048, 'cpu_count': 2,
                         'disks': [{'vmdk_file': '[datastore1] web01/web01.vmdk', 'capacity_bytes': 1 << 30,
                                    'capacity_gb': 1, 'label': 'Hard disk 1'}]}}


class _Pve(_Esxi):
    host = '10.0.0.9'

    def __init__(self, attach_status, create_finished=True):
        self.calls = []
        self._attach_status, self._create_finished = attach_status, create_finished

    def _api_post(self, url, data=None, **kw):
        self.calls.append(('create', url.rsplit('/api2/json', 1)[1]))
        return _Answer(200, {'data': UPID})

    def _wait_for_task(self, node, upid, timeout=600):
        self.calls.append(('wait', node, upid))
        return self._create_finished

    def _api_put(self, url, data=None, **kw):
        self.calls.append(('attach', data))
        return _Answer(self._attach_status, {'data': None, 'message': 'storage gone'} if self._attach_status != 200 else None)


def _esxi_to_pve(monkeypatch, pve):
    monkeypatch.setitem(xhm.cluster_managers, 'esxi1', _Esxi())
    monkeypatch.setitem(xhm.cluster_managers, 'pve1', pve)
    monkeypatch.setattr(xhm, '_resolve_pve_node_ip', lambda mgr, node: '10.0.0.9')
    monkeypatch.setattr(xhm, '_next_pve_vmid', lambda mgr: 900)
    monkeypatch.setattr(xhm, '_connect_ssh', lambda *a, **kw: _NodeShell())
    task = xhm.XHMigrationTask(mid='a77ac4ed', direction='esxi_to_pve', source_cluster='esxi1', source_node='esx-a',
                               source_vmid=42, target_cluster='pve1', target_node='pve-a', target_storage='store')
    xhm._run_esxi_to_pve(task)
    return task


def test_esxi_to_proxmox_attaches_after_the_create_task_and_completes(monkeypatch):
    pve = _Pve(200)
    task = _esxi_to_pve(monkeypatch, pve)
    assert task.phase == 'completed', task.error
    assert pve.calls == [('create', '/nodes/pve-a/qemu'), ('wait', 'pve-a', UPID),
                         ('attach', {'scsi0': 'store:vm-900-disk-0'})], pve.calls


def test_esxi_to_proxmox_fails_on_a_disk_it_could_not_attach(monkeypatch):
    task = _esxi_to_pve(monkeypatch, _Pve(500))
    assert task.phase == 'failed', task.phase
    assert 'scsi0: HTTP 500 - storage gone' in task.error and 'store:vm-900-disk-0' in task.error, task.error


def test_esxi_to_proxmox_does_not_attach_to_a_vm_whose_create_failed(monkeypatch):
    pve = _Pve(200, create_finished=False)
    task = _esxi_to_pve(monkeypatch, pve)
    assert task.phase == 'failed' and 'did not finish' in task.error, task.error
    assert [c[0] for c in pve.calls] == ['create', 'wait'], pve.calls


# Proxmox to XCP-ng, driven: an XAPI that refuses the disk, and the destroy that must not follow

_SRC_CFG = {'name': 'db01', 'memory': '2048', 'cores': '2', 'sockets': '1', 'ostype': 'l26',
            'scsi0': 'local-lvm:vm-100-disk-0,size=1G', 'smbios1': 'uuid=11111111-2222-3333-4444-555555555555'}


class _Export:
    def __init__(self):
        self.channel = types.SimpleNamespace(exit_status_ready=lambda: False, recv_exit_status=lambda: 0)
        self._left = [b'x' * 64]

    def read(self, n=-1):
        return self._left.pop() if self._left else b''


class _PveShell:
    def exec_command(self, cmd, timeout=None):
        return MagicMock(), _Export(), types.SimpleNamespace(read=lambda: b'')

    def close(self):
        pass


def _xapi():
    x = MagicMock(name='xapi')
    x.SR.get_all.return_value = ['sr']
    x.SR.get_record.return_value = {'name_label': 'sr1', 'uuid': 'sr-uuid'}
    x.VDI.create.return_value = 'vdi'
    x.VDI.get_uuid.return_value = 'vdi-uuid'
    x.VM.get_all.return_value = ['tpl']
    x.VM.get_is_a_template.return_value = True
    x.VM.get_name_label.return_value = 'Other install media'
    x.VM.clone.return_value = 'newvm'
    x.VM.get_VBDs.return_value = []
    x.VM.get_uuid.return_value = 'new-uuid'
    x.VBD.create.side_effect = RuntimeError('VBD refused')
    return x


def _pve_to_xcpng(monkeypatch):
    xapi = _xapi()
    src = types.SimpleNamespace(
        is_connected=True, id='pve1',
        config=types.SimpleNamespace(ssh_user='root', ssh_key='', ssh_port=22, pass_='pw', user='root@pam'),
        get_vm_config=lambda node, vmid, kind: {'success': True, 'config': {'raw': dict(_SRC_CFG)}})
    tgt = types.SimpleNamespace(is_connected=True, id='xcp1', host='xcp', _api=lambda: xapi,
                                _session=types.SimpleNamespace(_session='s'),
                                config=types.SimpleNamespace(ssl_verification=False))
    monkeypatch.setitem(xhm.cluster_managers, 'pve1', src)
    monkeypatch.setitem(xhm.cluster_managers, 'xcp1', tgt)
    node_cmds = []

    def node(mgr, node_name, cmd, timeout=600, **kw):
        node_cmds.append(cmd)
        return (0, '/dev/pve/vm-100-disk-0\n', '') if cmd.startswith('pvesm path') else (0, '', '')

    def upload(method, url, data=None, **kw):
        while data.read(1 << 20):
            pass
        return types.SimpleNamespace(status_code=200)

    monkeypatch.setattr(xhm, '_pve_node_exec', node)
    monkeypatch.setattr(xhm, '_resolve_pve_node_ip', lambda m, n: '10.0.0.9')
    monkeypatch.setattr(xhm, 'ssh_password_for', lambda c: 'pw')
    monkeypatch.setattr(xhm, '_connect_ssh', lambda *a, **k: _PveShell())
    monkeypatch.setattr(xhm.ha_transport, 'http', upload)
    monkeypatch.setattr(xhm.time, 'sleep', lambda s: None)
    task = xhm.XHMigrationTask('b0c4a7e1', 'pve_to_xcpng', 'pve1', 'pve-a', '100', 'xcp1', '', 'sr1',
                               config={'remove_source': True, 'start_after': True})
    xhm._run_pve_to_xcpng(task)
    return task, xapi, [c for c in node_cmds if 'qm destroy' in c]


def test_proxmox_to_xcpng_stops_before_it_starts_or_destroys(db, monkeypatch):
    task, xapi, destroys = _pve_to_xcpng(monkeypatch)
    assert xapi.VBD.create.called and 'attaching' in task.phase_times, task.log_lines[-5:]
    assert task.phase == 'failed', (task.phase, task.log_lines[-5:])
    assert destroys == [] and not xapi.Async.VM.start.called
    assert 'device 0: VBD refused' in task.error and 'source VM stays' in task.error, task.error
    assert 'new-uuid' in task.error and 'vdi-uuid' in task.error, task.error
