"""PegaProxManager._wait_for_task reads the end of a Proxmox task.

A task that finished with warnings ends as "WARNINGS: 2", never as the bare word. The
check only knew 'OK' and 'WARNINGS', so such a task read as failed: a migration's disk
attach waited for its create task and then gave up on a VM that was there.
"""
import types

import pytest

from pegaprox.core.manager import PegaProxManager


class _Resp:
    status_code = 200

    def __init__(self, exitstatus):
        self._data = {'status': 'stopped', 'exitstatus': exitstatus}

    def json(self):
        return {'data': self._data}


def _mgr(exitstatus):
    m = PegaProxManager.__new__(PegaProxManager)
    m.current_host = 'pve1'
    m.config = types.SimpleNamespace(host='pve1', api_port=8006)
    m.logger = types.SimpleNamespace(warning=lambda *a, **k: None, error=lambda *a, **k: None)
    m._api_get = lambda url, **kw: _Resp(exitstatus)
    return m


@pytest.mark.parametrize('said,ok', [('OK', True), ('WARNINGS: 2', True), ('WARNINGS', True),
                                     ('job errors', False), ('unable to lock VM', False), ('', False)])
def test_a_finished_task_is_read_by_its_exit_status(said, ok):
    assert _mgr(said)._wait_for_task('pve1', 'UPID:pve1:x', timeout=5) is ok
