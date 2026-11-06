"""An update whose reboot could not be sent has failed.

sshd restarted by the upgrade or a flaky network: the second connection failed, the reboot was skipped, the wait saw the node online and the task said done, with the new kernel not running.
"""
import threading
import time
from unittest.mock import MagicMock

import pegaprox.core.manager as mm
from pegaprox.core.manager import PegaProxManager
from pegaprox.models.tasks import UpdateTask


def _ssh():
    s = MagicMock()
    s.exec_command.return_value = (MagicMock(), MagicMock(), MagicMock())
    return s


def _mgr(monkeypatch):
    monkeypatch.setattr(mm.time, 'sleep', lambda s: None)
    monkeypatch.setattr(mm, '_read_capped', lambda s, *a, **k: '0')
    m = PegaProxManager.__new__(PegaProxManager)
    m.logger = MagicMock()
    m.config = MagicMock()
    m.nodes_in_maintenance = {}
    m.maintenance_lock = threading.Lock()
    m._rolling_update = None
    m._get_node_ip = lambda node: '10.0.0.5'
    m._ssh_execute = lambda ssh, cmd, task=None: (1 if 'dpkg -s needrestart' in cmd else 0, '', '')
    m._schedule_update_clear = lambda node, task: None
    m.exit_maintenance_mode = MagicMock(return_value=True)
    m._wait_for_node_online = lambda node: True
    return m


def test_no_second_connection_is_a_failed_update(monkeypatch):
    m = _mgr(monkeypatch)
    calls = []

    def connect(ip, **kw):
        calls.append(ip)
        return _ssh() if len(calls) == 1 else None
    m._ssh_connect = connect
    task = UpdateTask('n1', reboot=True)
    m._perform_node_update('n1', task)
    assert task.status == 'failed' and 'reboot could not be sent' in task.error, (task.status, task.error)
    m.exit_maintenance_mode.assert_not_called()


def test_a_reboot_that_was_sent_goes_on_as_it_did(monkeypatch):
    m = _mgr(monkeypatch)
    m._ssh_connect = lambda ip, **kw: _ssh()
    task = UpdateTask('n1', reboot=True)
    m._perform_node_update('n1', task)
    assert task.status == 'completed' and task.back_online is True


def test_without_a_reboot_it_never_asks(monkeypatch):
    m = _mgr(monkeypatch)
    m._ssh_connect = lambda ip, **kw: _ssh()
    task = UpdateTask('n1', reboot=False)
    m._perform_node_update('n1', task)
    assert task.status == 'completed'
