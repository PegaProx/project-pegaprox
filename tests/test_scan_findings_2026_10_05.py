"""What the daily scan of 2026-10-05 found in the new code, each pinned:

- a JSON body that is no object (a list, a string, a number) is a 400 at the connection
  check and the alert mutes, not a 500
- an event rule threshold of Infinity or 59.9 is refused, not a 500 or a silent 59
- the XCP-ng updater says that it rebooted and whether the host came back, so a rolling
  update waits for it (#715 made that wait depend on the task saying so)
- the witness installer takes a port from 1 to 65535, without leading zeros

MK Oct 2026
"""
import os
import subprocess
import types

import pytest

from test_alert_events import _store, routes  # noqa: F401
from test_connection_check import PATH, _fake, runs  # noqa: F401

ROOT = os.path.join(os.path.dirname(__file__), '..')


@pytest.mark.parametrize('body', [[1], 'x', 5])
def test_the_connection_check_refuses_a_body_that_is_no_object(api, seed, runs, body):  # noqa: F811
    _fake(api)
    r = api.as_user(seed.user('root', role='admin')).post(PATH, json=body)
    assert r.status_code == 400 and 'JSON object' in r.get_json()['error'], (r.status_code, r.data[:200])
    assert runs == []


@pytest.mark.parametrize('body', [[1], 'x'])
def test_an_alert_mute_refuses_a_body_that_is_no_object(routes, monkeypatch, body):  # noqa: F811
    _store(monkeypatch)
    r = routes.admin.post('/api/clusters/c1/alert-mutes', json=body)
    assert r.status_code == 400 and 'JSON object' in r.get_json()['error'], (r.status_code, r.data[:200])


@pytest.mark.parametrize('threshold', [float('inf'), 59.9])
def test_an_event_threshold_that_is_no_whole_number_is_refused(routes, monkeypatch, threshold):  # noqa: F811
    _store(monkeypatch)
    r = routes.admin.post('/api/clusters/c1/alerts', json={'name': 'r', 'metric': 'replication', 'threshold': threshold})
    assert r.status_code == 400 and 'threshold' in r.get_json()['error'].lower(), (r.status_code, r.data[:200])


def test_a_whole_float_threshold_still_counts():
    from pegaprox.background.alert_events import _int_in
    assert _int_in(60.0, 1, 100) == 60 and _int_in('60', 1, 100) == 60 and _int_in(True, 0, 1) is None


@pytest.mark.parametrize('online', [True, False])
def test_the_xcpng_update_says_it_rebooted_and_whether_the_host_came_back(monkeypatch, online):
    import pegaprox.core.xcpng as xcpng
    from pegaprox.models.tasks import UpdateTask
    monkeypatch.setattr(xcpng.time, 'sleep', lambda s: None)
    out = types.SimpleNamespace(read=lambda *a: b'', channel=types.SimpleNamespace(recv_exit_status=lambda: 0))
    sent = []
    ssh = types.SimpleNamespace(exec_command=lambda cmd, timeout=None: (sent.append(cmd), (None, out, out))[1],
                                close=lambda: None)
    mgr = types.SimpleNamespace(id='x1', _rolling_update={}, _get_host_ip=lambda n: '10.0.0.9',
                                _ssh_connect=lambda ip: ssh, _wait_for_host_online=lambda n, timeout=300: online)
    task = UpdateTask('h1', True)
    xcpng.XcpngManager._perform_node_update(mgr, 'h1', task)
    assert 'reboot' in sent and task.status == 'completed', (sent, task.status, task.error)
    assert task.reboot_issued is True and task.back_online is online


@pytest.mark.parametrize('port', ['0', '70000', '05005', '123456', '99999'])
def test_the_witness_installer_takes_a_port_from_1_to_65535(tmp_path, port):
    r = subprocess.run(['sh', os.path.join(ROOT, 'packaging', 'witness', 'install.sh'), '--port', port],
                       capture_output=True, text=True, timeout=60, cwd=str(tmp_path),
                       env={'PATH': os.environ.get('PATH', ''), 'HOME': str(tmp_path)})
    assert r.returncode != 0 and '--port takes a number from 1 to 65535' in r.stderr, (r.returncode, r.stderr[-300:])
