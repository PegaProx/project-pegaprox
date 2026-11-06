"""The source VM is only deleted once the target runs.

Three paths with remove_source started the target without reading the answer and then deleted the source
either way: snapshot-iterative, the pre-sync with delta, and the fallback behind it. A refused start left a stopped
copy on Proxmox and nothing on ESXi. The live clone already asked.
"""
import ast
import inspect
from types import SimpleNamespace

import pytest

import pegaprox.core.v2p as v2p


def _go(monkeypatch, states, **kw):
    seen = iter(states)
    monkeypatch.setattr(v2p, '_pve_vm_status', lambda mgr, node, vmid: next(seen, states[-1]))
    monkeypatch.setattr(v2p.time, 'sleep', lambda s: None)
    calls, logs = [], []
    esxi = SimpleNamespace(delete_vm=lambda vm: calls.append('delete'), vm_power_action=lambda vm, act: calls.append(act))
    task = SimpleNamespace(target_node='pve1', proxmox_vmid=100, vm_id='vm-1', log=logs.append)
    return v2p._remove_source_once_target_runs(SimpleNamespace(), esxi, task, wait=kw.pop('wait', 5), poll=0, **kw), calls, logs


def test_a_running_target_lets_the_source_go(monkeypatch):
    assert _go(monkeypatch, ['running'])[:2] == (True, ['delete'])


def test_a_target_still_on_its_way_up_is_waited_for(monkeypatch):
    assert _go(monkeypatch, ['stopped', '', 'running'])[:2] == (True, ['delete'])


@pytest.mark.parametrize('state', ['stopped', '', 'paused'])
def test_a_target_that_does_not_run_keeps_the_source(monkeypatch, state):
    done, calls, logs = _go(monkeypatch, [state], wait=0)
    assert (done, calls) == (False, [])
    assert any('stays on ESXi' in line for line in logs), logs


def test_it_powers_off_first_only_where_that_path_did(monkeypatch):
    assert _go(monkeypatch, ['running'], power_off=True)[1] == ['stop', 'delete']
    assert _go(monkeypatch, ['stopped'], power_off=True, wait=0)[1] == []


def test_a_failed_delete_is_said_and_not_raised(monkeypatch):
    monkeypatch.setattr(v2p, '_pve_vm_status', lambda *a: 'running')

    def boom(vm):
        raise RuntimeError('no')
    logs = []
    task = SimpleNamespace(target_node='pve1', proxmox_vmid=100, vm_id='vm-1', log=logs.append)
    assert v2p._remove_source_once_target_runs(SimpleNamespace(), SimpleNamespace(delete_vm=boom), task) is False
    assert any('cleanup failed: no' in line for line in logs), logs


def test_every_delete_of_the_source_asks():
    """The live clone keeps its own check on target_running, everything else goes through the helper."""
    tree = ast.parse(inspect.getsource(v2p))
    unguarded = []
    for fn in ast.walk(tree):
        if not isinstance(fn, ast.FunctionDef) or fn.name == '_remove_source_once_target_runs':
            continue
        for branch in ast.walk(fn):
            if not isinstance(branch, ast.If):
                continue
            test = ast.dump(branch.test)
            if 'remove_source' not in test or 'target_running' in test:
                continue
            for node in (n for stmt in branch.body for n in ast.walk(stmt)):
                if isinstance(node, ast.Call) and getattr(node.func, 'attr', '') == 'delete_vm':
                    unguarded.append(node.lineno)
    assert unguarded == []
