"""The source VM of an ESXi migration is shut down by its guest before the copy or the
switchover reads its disks, and powered off only where that does not work.

Seen on a real Windows guest: the offline copy powered it off, and it was off 2 s after
the request, a pulled plug. The copy held what a crash leaves: what Windows or a
database still held in memory was not on the disk. Only Snapshot-Iterative shut its
guest down; the offline copy, Live Clone, Auto and the Live Mirror powered off.
"""
import inspect

import pytest

import test_v2p_tpm_and_folder_copy as farm
from pegaprox.core import v2p


def _run(monkeypatch, mode, answer='ok', goes_off=True, **kw):
    r = farm.Run(monkeypatch, mode=mode, **kw)
    esxi = r.esxi

    def shutdown_guest(vm_id):
        esxi.log.append(('esxi_api', 'shutdown_guest', esxi.power))
        if answer != 'ok':
            return {'error': answer}
        if goes_off:
            esxi.power = 'POWERED_OFF'
        return {'data': 'ok'}
    esxi.shutdown_guest = shutdown_guest
    return r


def _power(r):
    return [e[1:3] for e in r.log if e[0] == 'esxi_api' and e[1] in ('shutdown_guest', 'power')]


SCENARIOS = {
    'offline': dict(mode='offline'),
    'live mirror': dict(mode='sshfs_boot', ndisks=1),
    'live clone': dict(mode='vmkfstools_clone'),
    'auto pre-sync': dict(mode='auto', clone_snap_fails=True),
}


@pytest.mark.parametrize('name', sorted(SCENARIOS))
def test_a_guest_with_running_tools_is_shut_down_not_powered_off(monkeypatch, name):
    r = _run(monkeypatch, **SCENARIOS[name]).go()
    assert r.task.status == 'completed', r.task.error
    calls = _power(r)
    assert ('shutdown_guest', 'POWERED_ON') in calls, calls
    assert ('power', 'stop') not in calls, calls
    assert any('The guest shut down' in l or 'Source VM is powered off' in l for l in r.task.log_lines)


@pytest.mark.parametrize('name', sorted(SCENARIOS))
def test_a_guest_without_tools_is_powered_off_and_the_log_says_why(monkeypatch, name):
    r = _run(monkeypatch, answer='the guest tools are not running', **SCENARIOS[name]).go()
    assert r.task.status == 'completed', r.task.error
    calls = _power(r)
    assert calls.index(('shutdown_guest', 'POWERED_ON')) < calls.index(('power', 'stop')), calls
    assert any('cannot be shut down from outside (the guest tools are not running)' in l for l in r.task.log_lines)


def test_a_guest_that_does_not_finish_is_powered_off_after_the_wait(monkeypatch):
    r = _run(monkeypatch, mode='offline', goes_off=False).go()
    assert r.task.status == 'completed', r.task.error
    calls = _power(r)
    assert calls.index(('shutdown_guest', 'POWERED_ON')) < calls.index(('power', 'stop')), calls
    assert any(f'did not shut down within {v2p.SI_GUEST_SHUTDOWN_SECONDS}s, powering it off' in l
               for l in r.task.log_lines)


def test_no_stop_of_the_source_powers_it_off_without_asking_the_guest_first():
    run = inspect.getsource(v2p._run_v2p_migration)
    # the only plain power-offs left: the forced one after a failed stop, and the clone
    # switchover's own after its guest shutdown answered no
    assert run.count('_stop_source(vmware_mgr, task') == 4
    assert "src_state == 'POWERED_ON' and _shut_down_guest(vmware_mgr, task)" in run
    assert '_iterative and src_state' not in run
