"""Settings of the whole PBS need a caller who holds the whole PBS.

(#1012) check_pbs_access proves the caller reaches one of the server's linked
clusters. Notification targets and matchers, traffic control, a datastore's
configuration, sync/verify/prune jobs, running tasks, the subscription and the
upgrade status are not per tenant. On a PBS two tenants share, one of them could
redirect or delete the other's backup alerts, read the webhook URLs through
pbs.notifications.view (a default of the user and viewer roles), change the
retention of the shared datastore or stop the other's backup.

Garbage collection, prune, verify, creating and removing jobs and the upgrade
already asked require_pbs_wide. These routes ask it now as well: a global admin,
or a caller who holds every linked cluster and is confined on none. MK
"""
from unittest.mock import MagicMock

import pytest

import pegaprox.globals as ppglobals


PBS_ID = 'pbs_shared'
P = f'/api/pbs/{PBS_ID}'
UPID = 'UPID:pbs:0000A1B2:00003C4D:00005E6F:68AB1F00:backup:store1:vm/100/68ab1f00:root@pam:'

ALL_PERMS = ['pbs.view', 'pbs.notifications.view', 'pbs.notifications.manage',
             'pbs.traffic.manage', 'pbs.datastore.modify', 'pbs.jobs.modify',
             'pbs.tasks.stop', 'pbs.subscription.set', 'admin.settings']

# (method, path, body, the PBSManager call that does the work)
ROUTES = [
    ('get', f'{P}/notifications', None, 'get_notification_targets'),
    ('post', f'{P}/notifications/targets/webhook', {'name': 'ops', 'url': 'https://hook.example/x'},
     'create_notification_target'),
    ('put', f'{P}/notifications/targets/webhook/ops', {'url': 'https://elsewhere.example/y'},
     'update_notification_target'),
    ('delete', f'{P}/notifications/targets/webhook/ops', None, 'delete_notification_target'),
    ('post', f'{P}/notifications/matchers', {'name': 'all-backups'}, 'create_notification_matcher'),
    ('put', f'{P}/notifications/matchers/all-backups', {'mode': 'all'}, 'update_notification_matcher'),
    ('delete', f'{P}/notifications/matchers/all-backups', None, 'delete_notification_matcher'),
    ('post', f'{P}/traffic-control', {'name': 'slow', 'rate_in': '1MB'}, 'create_traffic_control'),
    ('put', f'{P}/traffic-control/slow', {'rate_in': '1KB'}, 'update_traffic_control'),
    ('delete', f'{P}/traffic-control/slow', None, 'delete_traffic_control'),
    ('put', f'{P}/datastores/store1/config', {'keep_last': 1}, 'update_datastore'),
    ('put', f'{P}/jobs/sync/nightly', {'schedule': 'monthly'}, 'update_sync_job'),
    ('delete', f'{P}/tasks/{UPID}', None, 'stop_task'),
    ('post', f'{P}/subscription', {'key': 'pbsc-0000000000'}, 'set_subscription'),
    ('delete', f'{P}/update', None, 'clear_update_status'),
]
_IDS = [f'{m.upper()} {p[len(P):]}' for m, p, _, _ in ROUTES]


@pytest.fixture
def pbs(api, seed):
    """A PBS linked to two tenants' clusters."""
    seed.tenant('tenant_a', clusters=['cluster_1'])
    seed.tenant('tenant_b', clusters=['cluster_2'])
    m = MagicMock()
    m.name = 'shared'
    m.linked_clusters = ['cluster_1', 'cluster_2']
    m.connected = True
    for _, _, _, call in ROUTES:
        getattr(m, call).return_value = {'data': None}
    m.get_notification_targets.return_value = {'data': [
        {'name': 'ops', 'type': 'webhook', 'url': 'https://hook.example/secret-token'}]}
    m.get_notification_matchers.return_value = {'data': []}
    m.clear_update_status.return_value = True
    ppglobals.pbs_managers.clear()
    ppglobals.pbs_managers[PBS_ID] = m
    try:
        yield m
    finally:
        ppglobals.pbs_managers.clear()


def _call(client, method, path, body):
    kw = {'json': body} if body is not None else {}
    return getattr(client, method)(path, **kw)


@pytest.mark.parametrize('method,path,body,call', ROUTES, ids=_IDS)
def test_one_tenant_cannot_touch_what_the_whole_server_shares(api, seed, pbs, method, path, body, call):
    tenant_op = api.as_user(seed.user('a_op', role='user', tenant_id='tenant_a',
                                      permissions=ALL_PERMS))

    r = _call(tenant_op, method, path, body)

    assert r.status_code == 403, f'{r.status_code}: {r.get_data(as_text=True)[:200]}'
    assert not getattr(pbs, call).called, f'{call} reached the PBS'
    assert 'secret-token' not in r.get_data(as_text=True)


@pytest.mark.parametrize('method,path,body,call', ROUTES, ids=_IDS)
def test_an_operator_holding_every_linked_cluster_keeps_them(api, seed, pbs, method, path, body, call):
    """The single-tenant install, which is most of them."""
    seed.tenant('tenant_ab', clusters=['cluster_1', 'cluster_2'])
    owner = api.as_user(seed.user('ab_op', role='user', tenant_id='tenant_ab',
                                  permissions=ALL_PERMS))

    r = _call(owner, method, path, body)

    assert r.status_code in (200, 201), f'{r.status_code}: {r.get_data(as_text=True)[:200]}'
    assert getattr(pbs, call).called


@pytest.mark.parametrize('method,path,body,call', ROUTES, ids=_IDS)
def test_a_global_admin_keeps_them(api, seed, pbs, method, path, body, call):
    boss = api.as_user(seed.user('boss', role='admin'))

    r = _call(boss, method, path, body)

    assert r.status_code in (200, 201), f'{r.status_code}: {r.get_data(as_text=True)[:200]}'
    assert getattr(pbs, call).called


def test_a_default_viewer_still_reads_the_notification_settings(api, seed, pbs):
    """pbs.notifications.view is a viewer default; a viewer who is confined nowhere keeps it."""
    viewer = api.as_user(seed.user('v', role='viewer'))

    r = viewer.get(f'{P}/notifications')

    assert r.status_code == 200, r.get_data(as_text=True)[:200]
    assert r.get_json()['targets'][0]['name'] == 'ops'


def test_a_confined_viewer_does_not_read_them(api, seed, pbs):
    """A portal user with one VM on a cluster of their own tenant: confined, so no."""
    seed.tenant('tenant_ab', clusters=['cluster_1', 'cluster_2'])
    portal = api.as_user(seed.user('portal', role='viewer', tenant_id='tenant_ab'))
    seed.vm_acl('cluster_1', 100, ['portal'], permissions=['vm.view'])

    r = portal.get(f'{P}/notifications')

    assert r.status_code == 403, r.get_data(as_text=True)[:200]
    assert 'secret-token' not in r.get_data(as_text=True)
