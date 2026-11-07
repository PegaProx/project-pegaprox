"""The audit says what a scheduled action did.

It said "executed" whatever Proxmox answered, a refused stop too, and a snapshot said nothing at all.
"""
import types
from unittest.mock import patch

import pytest

import pegaprox.api.schedules as sch


def _run(api, seed, action, status=200, boom=None):
    seed.user('adm', role='admin')
    mgr = api.make_fake_manager(cluster_id='c1', get_vm_resources=[{'vmid': 100, 'node': 'n1', 'type': 'qemu'}])
    mgr.is_connected = True
    mgr.host, mgr.api_port = 'h', 8006
    post = mgr._create_session.return_value.post
    if boom:
        post.side_effect = boom
    else:
        post.return_value = types.SimpleNamespace(status_code=status, text='VM is locked')
    api.set_manager('c1', mgr)
    with patch.object(sch, 'log_audit') as audit:
        sch.execute_scheduled_action({'id': 1, 'cluster_id': 'c1', 'vmid': 100, 'vm_type': 'qemu', 'action': action, 'created_by': 'adm'})
    return [(c.args[1], c.args[2]) for c in audit.call_args_list]


@pytest.mark.parametrize('action', ['start', 'stop', 'shutdown', 'reboot', 'snapshot'])
def test_what_went_through_says_executed(api, seed, db, action):
    assert _run(api, seed, action) == [(f'scheduled.{action}', f'Scheduled {action} executed on VM 100 in c1')]


@pytest.mark.parametrize('action', ['stop', 'snapshot'])
def test_a_refusal_says_failed_with_the_status(api, seed, db, action):
    got = _run(api, seed, action, status=500)
    assert len(got) == 1 and got[0][0] == f'scheduled.{action}.failed' and 'HTTP 500' in got[0][1], got


def test_an_exception_says_failed_too(api, seed, db):
    got = _run(api, seed, 'stop', boom=OSError('no route'))
    assert len(got) == 1 and got[0][0] == 'scheduled.stop.failed' and 'no route' in got[0][1], got
