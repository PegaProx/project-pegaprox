"""Two routes that create or connect on the caller's behalf without asking the usual question.

**Template deployment** (`POST /clusters/<id>/templates/deploy`) creates a guest, on a node
and under a VMID the caller picks, and asked neither question vms.py asks on create: a
caller confined to their own VMs by an ACL or a pool grant has no cluster-level standing
to place a new guest at all, and a tenant with a configured VMID range must not land
outside it. A collision there surfaces at restore time, long after anyone can work out
which guest was meant. The PBS restore-into-a-new-VMID path was closed the same way.

**The nested ESXi transfers** in the migration engine run sshfs and scp on the PVE node,
reaching the ESXi host from there, with StrictHostKeyChecking hardcoded to accept-new.
That is trust-on-first-use: with strict host keys switched on, every other SSH path in
the product refuses an unknown host and these two did not. The third transfer path a few
hundred lines below already read the setting.

Aikido ai_pentest 700489135 / 700489556. MK
"""
import contextlib
import inspect
import re

import pytest

import pegaprox.api.templates_lib as tpl
import pegaprox.core.xhm as xhm
from tests.conftest import make_fake_manager


@contextlib.contextmanager
def _ctx(api, session, body):
    from flask import request as _rq
    with api.app.test_request_context('/', base_url='http://localhost', json=body):
        _rq.session = session
        yield


def _handler(name):
    fn = getattr(tpl, name)
    while hasattr(fn, '__wrapped__'):
        fn = fn.__wrapped__
    return fn


def _body(vmid=150):
    return {'template_id': 'debian-12', 'node': 'pve1', 'storage': 'local', 'vmid': vmid}


@pytest.fixture
def estate(api, seed, monkeypatch):
    import pegaprox.utils.rbac as _rbac
    seed.db.save_tenant('tenant_a', {'id': 'tenant_a', 'name': 'Tenant A',
                                     'clusters': ['cluster_1'],
                                     'vmid_range_start': 200, 'vmid_range_end': 299})
    _rbac.invalidate_tenants_cache()
    api.set_manager('cluster_1', make_fake_manager('cluster_1'))
    monkeypatch.setattr(tpl, '_lookup_template',
                        lambda tid: {'name': 'Debian 12', 'distro': 'debian', 'version': '12'})
    monkeypatch.setattr(tpl.threading, 'Thread', lambda **kw: type(
        'T', (), {'start': lambda self: None})())
    return seed


# --- template deployment ---------------------------------------------------------

def test_a_vm_acl_scoped_caller_cannot_place_a_new_guest(api, estate):
    """They may operate the VMs they were given. Creating another one is not that."""
    estate.user('ann', role='user', tenant_id='tenant_a', permissions=['vm.create'])
    estate.vm_acl('cluster_1', 100, ['ann'], permissions=['vm.view'])

    with _ctx(api, {'user': 'ann', 'role': 'user'}, _body(vmid=250)):
        resp = _handler('deploy')('cluster_1')

    assert resp[1] == 403


def test_a_tenant_operator_cannot_deploy_outside_their_vmid_range(api, estate):
    estate.user('bob', role='user', tenant_id='tenant_a', permissions=['vm.create'])

    with _ctx(api, {'user': 'bob', 'role': 'user'}, _body(vmid=150)):
        resp = _handler('deploy')('cluster_1')

    assert resp[1] == 403


def test_a_tenant_operator_deploys_inside_their_range(api, estate):
    """The counterweight: the ordinary case has to keep working."""
    estate.user('bob', role='user', tenant_id='tenant_a', permissions=['vm.create'])

    with _ctx(api, {'user': 'bob', 'role': 'user'}, _body(vmid=250)):
        resp = _handler('deploy')('cluster_1')

    assert resp.get_json()['vmid'] == 250


def test_a_range_check_that_cannot_run_refuses_the_deploy(api, estate, monkeypatch):
    """CodeAnt, 18.09.: the except around check_tenant_vmid set (True, '') and deployed
    anyway, which undoes the guard above it. The range is what stops two tenants landing
    on the same id; a check that could not run has not cleared anything."""
    estate.user('bob', role='user', tenant_id='tenant_a', permissions=['vm.create'])
    import pegaprox.utils.rbac as _rbac
    monkeypatch.setattr(_rbac, 'check_tenant_vmid',
                        lambda *a, **kw: (_ for _ in ()).throw(RuntimeError('db gone')))

    with _ctx(api, {'user': 'bob', 'role': 'user'}, _body(vmid=250)):
        resp = _handler('deploy')('cluster_1')

    assert resp[1] == 403
    assert 'VMID range' in resp[0].get_json()['error']


def test_a_global_admin_is_not_held_to_a_tenant_range(api, estate):
    estate.user('root7', role='admin')

    with _ctx(api, {'user': 'root7', 'role': 'admin'}, _body(vmid=150)):
        resp = _handler('deploy')('cluster_1')

    assert resp.get_json()['vmid'] == 150


# --- the nested transfers --------------------------------------------------------

def test_the_nested_transfers_read_the_configured_host_key_policy():
    body = inspect.getsource(xhm._run_esxi_to_pve)

    assert 'StrictHostKeyChecking=accept-new' not in body, \
        'a transfer is still hardcoded to trust-on-first-use'
    assert 'strict_host_keys_enabled()' in body


def test_both_nested_commands_use_the_resolved_value():
    body = inspect.getsource(xhm._run_esxi_to_pve)

    assert len(re.findall(r'StrictHostKeyChecking=\{_hk\}', body)) == 2, body.count('StrictHost')


# The behavioural half of this - what StrictHostKeyChecking value actually reaches the
# node under each setting - lives in test_xhm_scratch_paths.py, where the recording-SSH
# harness for _run_esxi_to_pve already is.
