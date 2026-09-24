"""node.reboot is a permission this product defines - and enforced nowhere until now.

It is in PERMISSIONS, it is in the tenant-admin role template, and the permission editor
offers it. No route asked for it. Both paths that reboot a hypervisor node - the manual
rolling update and the scheduled one - gated on node.update alone, so an operator who
built a role with node.update and deliberately left node.reboot out still got their
nodes rebooted. A permission that does nothing is worse than one that does not exist:
somebody made a decision and the product quietly ignored it.

Asked for only when the run will actually reboot something, so an update-only rolling
pass still works on node.update alone.

Aikido ai_pentest 700489083. MK
"""
import contextlib

import pytest

import pegaprox.api.schedules as schedules
import pegaprox.api.settings as settings
from tests.conftest import make_fake_manager


@contextlib.contextmanager
def _ctx(api, session, body):
    from flask import request as _rq
    with api.app.test_request_context('/', base_url='http://localhost', json=body):
        _rq.session = session
        yield


def _handler(mod, name):
    fn = getattr(mod, name)
    while hasattr(fn, '__wrapped__'):
        fn = fn.__wrapped__
    return fn


NODE_PERMS = ['cluster.view', 'node.view', 'node.update', 'node.maintenance']


@pytest.fixture
def estate(api, seed):
    seed.tenant('tenant_a', clusters=['cluster_1'])
    api.set_manager('cluster_1', make_fake_manager('cluster_1', get_node_status={}))
    return seed


@pytest.fixture
def updater(estate):
    """Holds node.update. Not confined, so require_unconfined passes - this test is
    about the reboot permission and nothing else."""
    estate.user('ulla', role='user', tenant_id='tenant_a', permissions=NODE_PERMS)
    return {'user': 'ulla', 'role': 'user'}


@pytest.fixture
def rebooter(estate):
    estate.user('rick', role='user', tenant_id='tenant_a',
                permissions=NODE_PERMS + ['node.reboot'])
    return {'user': 'rick', 'role': 'user'}


# --- the scheduled path ----------------------------------------------------------

def _schedule(enabled=True, include_reboot=True):
    return {'enabled': enabled, 'include_reboot': include_reboot, 'time': '03:00'}


def test_scheduling_a_reboot_needs_the_reboot_permission(api, updater):
    with _ctx(api, updater, _schedule()):
        resp = _handler(schedules, 'set_update_schedule')('cluster_1')

    assert resp[1] == 403
    assert 'node.reboot' in resp[0].get_json()['error']


def test_scheduling_an_update_without_a_reboot_still_works(api, updater):
    """The counterweight - node.update alone must keep doing what it always did."""
    with _ctx(api, updater, _schedule(include_reboot=False)):
        resp = _handler(schedules, 'set_update_schedule')('cluster_1')

    assert resp.get_json()['success'] is True


def test_a_holder_of_both_can_schedule_the_reboot(api, rebooter):
    with _ctx(api, rebooter, _schedule()):
        resp = _handler(schedules, 'set_update_schedule')('cluster_1')

    assert resp.get_json()['success'] is True


def test_disabling_a_schedule_is_not_a_reboot(api, updater):
    """Turning it off must not need the permission to turn it on."""
    with _ctx(api, updater, _schedule(enabled=False)):
        resp = _handler(schedules, 'set_update_schedule')('cluster_1')

    assert resp.get_json()['success'] is True


# --- the manual path -------------------------------------------------------------

def test_a_manual_rolling_reboot_needs_the_reboot_permission(api, updater):
    with _ctx(api, updater, {'include_reboot': True}):
        resp = _handler(settings, 'start_rolling_update')('cluster_1')

    assert resp[1] == 403
    assert 'node.reboot' in resp[0].get_json()['error']


def test_the_permission_is_actually_defined_and_delegable(api):
    """If this ever stops being true the guards above become dead weight."""
    from pegaprox.models.permissions import PERMISSIONS, ROLE_PERMISSIONS, ROLE_ADMIN

    assert 'node.reboot' in PERMISSIONS
    assert 'node.reboot' in ROLE_PERMISSIONS[ROLE_ADMIN]
