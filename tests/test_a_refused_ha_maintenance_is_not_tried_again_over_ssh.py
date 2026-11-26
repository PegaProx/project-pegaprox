"""ha-manager of PVE 9.3 refuses a maintenance request the CRM would ignore (pve-ha-manager
5.2.7): enable while HA is disarmed or the node is not online, enable or disable for a node
HA does not track yet. PUT /nodes/{node}/maintenance runs that command and answers the
refusal as a 500 with the reason in the status line and in the body's message.

PegaProx took any answer but 200 as "try SSH", ran the same command up to three times over
SSH, logged each as a failed command and kept PVE's reason in one INFO line. The refusal is
final now: no SSH, the reason is on the maintenance task and in the rolling update's log,
and PegaProx moves the guests itself as before. A refused disable for a node HA does not
track has no flag to take off. Every other answer (501, 403, another 500, none) still goes
the SSH way.
"""
import json
import types

import pytest
import requests

from pegaprox.models.tasks import MaintenanceTask
from test_maintenance_via_pve_api import URL, _manager
from test_rolling_templates_affinity_763_954 import GUESTS, _cluster_manager, _finish, _start, fast  # noqa: F401


def _refusal(text, status_line=True):
    """A 500 the way pveproxy sends a die of the handler: the first line of the message as the
    status line, the whole of it as the message of the JSON body."""
    r = requests.Response()
    r.status_code = 500
    r.reason = text if status_line else 'Internal Server Error'
    r.headers['Content-Type'] = 'application/json;charset=UTF-8'
    r._content = json.dumps({'data': None, 'message': text + '\n'}).encode()
    r.url = URL
    return r


def _answering(m, r):
    def put(url, **kw):
        m.puts.append((url, kw.get('data')))
        return r
    m._api_put = put
    return m


ENABLE_REFUSED = ['HA stack is disarmed', 'node is not online', 'not tracked by HA yet']


@pytest.mark.parametrize('why', ENABLE_REFUSED)
def test_a_refused_enable_is_not_sent_again_over_ssh(why):
    said = f"cannot enable maintenance mode for node 'pve1' - {why}"
    m = _answering(_manager(500), _refusal(said))
    task = MaintenanceTask('pve1')
    assert m._try_native_ha_maintenance('pve1', task) is False
    assert m.ssh == [], 'SSH runs the same ha-manager command and gets the same answer'
    assert m.puts == [(URL, {'maintenance-mode': 'enable'})]
    assert task.native_ha is False
    assert task.native_ha_refused == said
    assert task.to_dict()['native_ha_refused'] == said


def test_the_reason_is_found_in_the_body_when_the_status_line_does_not_carry_it():
    said = "cannot enable maintenance mode for node 'pve1' - HA stack is disarmed"
    m = _answering(_manager(500), _refusal(said, status_line=False))
    task = MaintenanceTask('pve1')
    assert m._try_native_ha_maintenance('pve1', task) is False
    assert m.ssh == [] and task.native_ha_refused == said


def test_a_refused_disable_for_a_node_ha_does_not_track_has_nothing_to_take_off():
    m = _answering(_manager(500), _refusal("cannot disable maintenance mode for node 'pve1' - not tracked by HA yet"))
    assert m._try_disable_native_ha_maintenance('pve1') is True
    assert m.ssh == []
    assert m.puts == [(URL, {'maintenance-mode': 'disable'})]


@pytest.mark.parametrize('mode,why,level', [('enable', 'not tracked by HA yet', 'info'),
                                             ('disable', 'not tracked by HA yet', 'info'),
                                             ('enable', 'HA stack is disarmed', 'warning'),
                                             ('enable', 'node is not online', 'warning')])
def test_a_node_ha_does_not_track_is_no_warning_in_the_log(mode, why, level):
    # a cluster without HA guests: every node answers "not tracked", HA has nothing to do there
    m = _answering(_manager(500), _refusal(f"cannot {mode} maintenance mode for node 'pve1' - {why}"))
    said = []
    m.logger = types.SimpleNamespace(**{lvl: (lambda lvl: lambda msg, *a, **k: said.append((lvl, msg)))(lvl)
                                        for lvl in ('debug', 'info', 'warning', 'error', 'critical')})
    if mode == 'enable':
        m._try_native_ha_maintenance('pve1', MaintenanceTask('pve1'))
    else:
        m._try_disable_native_ha_maintenance('pve1')
    assert [lvl for lvl, msg in said if why in msg] == [level], said


def test_another_500_still_goes_the_ssh_way():
    r = _refusal('Internal Server Error', status_line=False)
    r._content = b'{"data":null}'
    m = _answering(_manager(500), r)
    task = MaintenanceTask('pve1')
    assert m._try_native_ha_maintenance('pve1', task) is True
    assert m.ssh == ['ha-manager crm-command node-maintenance enable pve1']
    assert task.native_ha is True and task.native_ha_refused is None


def test_the_rolling_update_says_why_proxmox_ha_did_not_take_the_node(api, seed, fast):  # noqa: F811
    fake, order = _cluster_manager(api, GUESTS)
    enter = fake.enter_maintenance_mode.side_effect

    def refused(node, **kw):
        t = enter(node, **kw)
        t.native_ha_refused = f"cannot enable maintenance mode for node '{node}' - HA stack is disarmed"
        return t
    fake.enter_maintenance_mode.side_effect = refused
    _start(api, seed, {})
    state = _finish(fake)
    assert state['status'] == 'completed', state['logs']
    logs = '\n'.join(state['logs'])
    for node in ('pve1', 'pve2'):
        assert (f"Proxmox HA did not set its maintenance flag: cannot enable maintenance mode for node "
                f"'{node}' - HA stack is disarmed - PegaProx moves the guests itself") in logs, logs


def test_a_rolling_update_on_a_cluster_without_ha_says_nothing_about_the_flag(api, seed, fast):  # noqa: F811
    fake, order = _cluster_manager(api, GUESTS)
    enter = fake.enter_maintenance_mode.side_effect
    tasks = []

    def untracked(node, **kw):
        t = enter(node, **kw)
        t.native_ha_refused = f"cannot enable maintenance mode for node '{node}' - not tracked by HA yet"
        tasks.append(t)
        return t
    fake.enter_maintenance_mode.side_effect = untracked
    _start(api, seed, {})
    state = _finish(fake)
    assert state['status'] == 'completed', state['logs']
    logs = '\n'.join(state['logs'])
    assert 'Proxmox HA did not set' not in logs and 'not tracked by HA' not in logs, logs
    # the task still says it, for whoever asks
    assert len(tasks) == 2 and all('not tracked by HA yet' in t.native_ha_refused for t in tasks)


def test_a_rolling_update_without_a_refusal_logs_nothing_about_it(api, seed, fast):  # noqa: F811
    fake, order = _cluster_manager(api, GUESTS)
    _start(api, seed, {})
    state = _finish(fake)
    assert state['status'] == 'completed', state['logs']
    assert 'Proxmox HA did not set' not in '\n'.join(state['logs'])
