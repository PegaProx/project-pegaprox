"""Reads of the PBS host itself are not for a confined caller.

check_pbs_access proves the caller reaches one of the server's linked clusters,
and a pool grant on another tenant's cluster counts for that too. The snapshot,
group and task listings scope their rows per guest, but the server-level reads
beside them ran on that check alone: a portal user with one VM read the syslog
(every guest's backup task by name), the network and DNS setup, the disks, the
jobs, a datastore's config with its path, and the datastore list with usage and
GC counters.

Those reads now refuse a confined caller, as require_unconfined does on the PVE
side. The datastore list stays, reduced to the names, so the caller can still
open its own guests' backups, and so do the namespace list (without the comments)
and the server list (without the live host figures). An admin and an operator
confined nowhere get the same answers as before. MK
"""
from unittest.mock import MagicMock

import pytest

import pegaprox.globals as ppglobals
from pegaprox.utils.auth import create_api_token


PBS_ID = 'pbs_a'
P = f'/api/pbs/{PBS_ID}'
MINE, THEIRS = 100, 200

PERMS = ['pbs.view', 'pbs.datastore.view', 'pbs.jobs.view', 'pbs.disks.view',
         'pbs.disks.smart', 'pbs.subscription.view', 'pbs.traffic.view', 'pbs.tasks.view']

# (path, the PBSManager call that answers it)
ROUTES = [
    (f'{P}/status', 'get_server_status'),
    (f'{P}/apt/updates', 'get_apt_updates'),
    (f'{P}/update', 'get_update_status'),
    (f'{P}/jobs', 'get_sync_jobs'),
    (f'{P}/disks', 'get_disks'),
    (f'{P}/disks/sda/smart', 'get_disk_smart'),
    (f'{P}/remotes', 'get_remotes'),
    (f'{P}/subscription', 'get_subscription'),
    (f'{P}/traffic-control', 'get_traffic_control'),
    (f'{P}/syslog', 'get_syslog'),
    (f'{P}/rrd', 'get_node_rrd'),
    (f'{P}/datastores/store1/config', 'get_datastore_config'),
    (f'{P}/datastores/store1/rrd', 'get_datastore_rrd'),
    (f'{P}/network', 'get_network'),
    (f'{P}/dns', 'get_dns'),
    (f'{P}/time', 'get_time'),
    (f'{P}/health', 'get_datastores'),
    (f'{P}/capacity-forecast', 'get_datastores'),
]
_IDS = [p[len(P):] for p, _ in ROUTES]


def _snap(vmid):
    return {'backup-type': 'vm', 'backup-id': str(vmid), 'backup-time': 1_756_000_000 + vmid,
            'size': 1024, 'owner': 'root@pam', 'files': ['index.json.blob']}


@pytest.fixture
def pbs(api, seed):
    """A PBS backing up cluster_1, which tenant_a owns."""
    seed.tenant('tenant_a', clusters=['cluster_1'])
    seed.tenant('tenant_b', clusters=['cluster_2'])
    api.set_manager('cluster_1', api.make_fake_manager('cluster_1', get_vm_resources=[]))
    m = MagicMock()
    m.name = 'pbs-a'
    m.linked_clusters = ['cluster_1']
    m.connected = True
    m.get_server_status.return_value = {'data': {'cpu': 0.1, 'uptime': 3600}}
    m.get_version.return_value = {'data': {'version': '3.4'}}
    m.get_datastores.return_value = {'data': [
        {'name': 'store1', 'path': '/mnt/datastore/store1', 'gc-schedule': 'daily'}]}
    m.get_datastore_usage.return_value = {'data': [
        {'store': 'store1', 'total': 1000, 'used': 400, 'avail': 600, 'history': []}]}
    m.get_gc_jobs.return_value = {'data': []}
    m.get_datastore_status.return_value = {'data': {'counts': {'vm': {'groups': 2}}}}
    m.get_apt_updates.return_value = {'data': [{'Package': 'proxmox-backup-server'}]}
    m.get_update_status.return_value = None
    for kind in ('sync', 'verify', 'prune'):
        getattr(m, f'get_{kind}_jobs').return_value = {'data': [{'id': 'nightly', 'store': 'store1'}]}
    m.get_disks.return_value = {'data': [{'devpath': '/dev/sda'}]}
    m.get_disk_smart.return_value = {'data': {'health': 'PASSED'}}
    m.get_remotes.return_value = {'data': [{'name': 'offsite'}]}
    m.get_subscription.return_value = {'data': {'status': 'active'}}
    m.get_traffic_control.return_value = {'data': [{'name': 'slow'}]}
    m.get_syslog.return_value = {'data': [{'n': 1, 't': f'starting backup of vm/{THEIRS}'}]}
    m.get_node_rrd.return_value = {'data': [{'cpu': 0.1}]}
    m.get_datastore_config.return_value = {'data': {'name': 'store1', 'path': '/mnt/datastore/store1'}}
    m.get_datastore_rrd.return_value = {'data': [{'read': 1}]}
    m.get_network.return_value = {'data': [{'iface': 'eth0', 'cidr': '10.0.0.5/24'}]}
    m.get_dns.return_value = {'data': {'dns1': '10.0.0.1'}}
    m.get_time.return_value = {'data': {'timezone': 'Europe/Vienna'}}
    m.get_snapshots.return_value = {'data': [_snap(MINE), _snap(THEIRS)]}
    m.get_namespaces.return_value = {'data': [{'ns': 'prod', 'comment': 'customer billing, tier 1'}]}
    m.last_status = {'cpu': 0.25, 'memory': {'used': 512, 'total': 2048}, 'uptime': 3600}
    m.to_dict.return_value = {'id': PBS_ID, 'name': 'pbs-a', 'connected': True,
                              'linked_clusters': ['cluster_1']}
    ppglobals.pbs_managers.clear()
    ppglobals.pbs_managers[PBS_ID] = m
    try:
        yield m
    finally:
        ppglobals.pbs_managers.clear()


def _portal_user(api, seed):
    """tenant_a owns the cluster, but this user holds a VM ACL on one guest only."""
    u = seed.user('portal', role='user', tenant_id='tenant_a', permissions=PERMS)
    seed.vm_acl('cluster_1', MINE, ['portal'], permissions=['vm.view'])
    return api.as_user(u)


def _cross_tenant_pool_user(api, seed):
    """tenant_b's user with a pool grant on tenant_a's cluster."""
    u = seed.user('pooled', role='user', tenant_id='tenant_b', permissions=PERMS)
    seed.pool('cluster_1', 'pool_1', 'pooled', ['pool.view', 'vm.view'])
    return api.as_user(u)


def _default_tenant_pool_user(api, seed):
    u = seed.user('dpool', role='user', permissions=PERMS)
    seed.pool('cluster_1', 'pool_1', 'dpool', ['pool.view', 'vm.view'])
    return api.as_user(u)


def _own_tenant_pool_user(api, seed):
    """tenant_a owns the cluster, this user of tenant_a holds a pool grant on it."""
    u = seed.user('tpool', role='user', tenant_id='tenant_a', permissions=PERMS)
    seed.pool('cluster_1', 'pool_1', 'tpool', ['pool.view', 'vm.view'])
    return api.as_user(u)


CONFINED = [_portal_user, _cross_tenant_pool_user, _default_tenant_pool_user, _own_tenant_pool_user]
_CIDS = ['vm-acl', 'cross-tenant-pool', 'default-tenant-pool', 'own-tenant-pool']


def _admin(api, seed):
    return api.as_user(seed.user('boss', role='admin'))


def _operator(api, seed):
    """tenant_a's operator with no pool grant and no VM ACL: confined nowhere."""
    return api.as_user(seed.user('op', role='user', tenant_id='tenant_a', permissions=PERMS))


@pytest.mark.parametrize('who', CONFINED, ids=_CIDS)
@pytest.mark.parametrize('path,call', ROUTES, ids=_IDS)
def test_a_confined_caller_does_not_read_the_backup_server_itself(api, seed, pbs, who, path, call):
    client = who(api, seed)

    r = client.get(path)

    assert r.status_code == 403, f'{r.status_code}: {r.get_data(as_text=True)[:200]}'
    assert 'whole backup server' in r.get_json()['error']
    assert not getattr(pbs, call).called, f'{call} reached the PBS'


@pytest.mark.parametrize('who', [_admin, _operator], ids=['admin', 'tenant-operator'])
@pytest.mark.parametrize('path,call', ROUTES, ids=_IDS)
def test_an_admin_and_an_unconfined_operator_still_read_it(api, seed, pbs, who, path, call):
    client = who(api, seed)

    r = client.get(path)

    assert r.status_code == 200, f'{r.status_code}: {r.get_data(as_text=True)[:200]}'
    assert getattr(pbs, call).called


@pytest.mark.parametrize('who', [_admin, _operator], ids=['admin', 'tenant-operator'])
def test_the_full_answers_carry_what_the_server_holds(api, seed, pbs, who):
    client = who(api, seed)

    assert f'vm/{THEIRS}' in client.get(f'{P}/syslog').get_json()[0]['t']
    assert client.get(f'{P}/network').get_json()[0]['cidr'] == '10.0.0.5/24'
    assert client.get(f'{P}/datastores/store1/config').get_json()['path'] == '/mnt/datastore/store1'
    assert client.get(f'{P}/jobs').get_json()['sync'][0]['id'] == 'nightly'
    assert client.get(f'{P}/status').get_json()['server']['uptime'] == 3600


@pytest.mark.parametrize('who', CONFINED, ids=_CIDS)
def test_a_confined_caller_gets_only_the_datastore_names(api, seed, pbs, who):
    client = who(api, seed)

    r = client.get(f'{P}/datastores')

    assert r.status_code == 200, r.get_data(as_text=True)[:200]
    assert r.get_json() == [{'name': 'store1'}]
    assert not pbs.get_datastore_usage.called
    assert not pbs.get_datastore_status.called
    assert '/mnt/datastore' not in r.get_data(as_text=True)


@pytest.mark.parametrize('who', [_admin, _operator], ids=['admin', 'tenant-operator'])
def test_an_admin_and_an_unconfined_operator_keep_the_full_datastore_rows(api, seed, pbs, who):
    client = who(api, seed)

    r = client.get(f'{P}/datastores')

    assert r.status_code == 200, r.get_data(as_text=True)[:200]
    row = r.get_json()[0]
    assert row['name'] == 'store1'
    assert row['path'] == '/mnt/datastore/store1'
    assert row['used'] == 400 and row['total'] == 1000
    assert row['detail'] == {'counts': {'vm': {'groups': 2}}}


@pytest.mark.parametrize('who', CONFINED, ids=_CIDS)
def test_a_confined_caller_gets_the_namespaces_without_their_comments(api, seed, pbs, who):
    r = who(api, seed).get(f'{P}/datastores/store1/namespaces')

    assert r.status_code == 200, r.get_data(as_text=True)[:200]
    assert r.get_json() == [{'ns': 'prod'}]


@pytest.mark.parametrize('who', [_admin, _operator], ids=['admin', 'tenant-operator'])
def test_an_admin_and_an_unconfined_operator_keep_the_namespace_comments(api, seed, pbs, who):
    r = who(api, seed).get(f'{P}/datastores/store1/namespaces')

    assert r.status_code == 200, r.get_data(as_text=True)[:200]
    assert r.get_json() == [{'ns': 'prod', 'comment': 'customer billing, tier 1'}]


@pytest.mark.parametrize('who', CONFINED, ids=_CIDS)
def test_a_confined_caller_lists_the_server_without_its_live_figures(api, seed, pbs, who):
    r = who(api, seed).get('/api/pbs')

    assert r.status_code == 200, r.get_data(as_text=True)[:200]
    row = next(x for x in r.get_json() if x['id'] == PBS_ID)
    assert 'status' not in row
    assert row['name'] == 'pbs-a' and row['connected'] is True


@pytest.mark.parametrize('who', [_admin, _operator], ids=['admin', 'tenant-operator'])
def test_an_admin_and_an_unconfined_operator_keep_the_live_figures_in_the_list(api, seed, pbs, who):
    r = who(api, seed).get('/api/pbs')

    assert r.status_code == 200, r.get_data(as_text=True)[:200]
    row = next(x for x in r.get_json() if x['id'] == PBS_ID)
    assert row['status'] == {'cpu': 0.25, 'memory': {'used': 512, 'total': 2048}, 'uptime': 3600}


def test_an_operator_of_one_of_two_tenants_on_the_server_is_confined(api, seed, pbs):
    """Deliberate: the server also backs up tenant_b's cluster, so its log, network and
    usage are not tenant_a's alone. The operator owns cluster_1 outright and still gets
    the confined answers - the same rule require_pbs_wide keeps for the whole-server
    actions."""
    api.set_manager('cluster_2', api.make_fake_manager('cluster_2', get_vm_resources=[]))
    pbs.linked_clusters = ['cluster_1', 'cluster_2']
    client = _operator(api, seed)

    r = client.get(f'{P}/syslog')
    assert r.status_code == 403, r.get_data(as_text=True)[:200]
    assert not pbs.get_syslog.called
    assert client.get(f'{P}/datastores').get_json() == [{'name': 'store1'}]


def test_an_admin_on_a_server_of_two_tenants_reads_it_whole(api, seed, pbs):
    api.set_manager('cluster_2', api.make_fake_manager('cluster_2', get_vm_resources=[]))
    pbs.linked_clusters = ['cluster_1', 'cluster_2']
    client = _admin(api, seed)

    assert client.get(f'{P}/syslog').status_code == 200
    assert client.get(f'{P}/datastores').get_json()[0]['path'] == '/mnt/datastore/store1'


def _bearer(api, token, path):
    return api.anon().get(path, headers={'Authorization': f'Bearer {token}'})


def test_a_token_of_a_vm_acl_user_does_not_read_the_server_itself(api, seed, pbs):
    _portal_user(api, seed)
    res = create_api_token('portal', 'ci')
    assert res.get('token'), res

    r = _bearer(api, res['token'], f'{P}/syslog')

    assert r.status_code == 403, r.get_data(as_text=True)[:200]
    assert not pbs.get_syslog.called


def test_an_admins_viewer_token_reads_the_server_itself(api, seed, pbs):
    seed.user('boss', role='admin')
    res = create_api_token('boss', 'ci', role='viewer')
    assert res.get('token'), res

    r = _bearer(api, res['token'], f'{P}/syslog')

    assert r.status_code == 200, r.get_data(as_text=True)[:200]
    assert pbs.get_syslog.called


@pytest.mark.parametrize('who', [_portal_user, _admin], ids=['vm-acl', 'admin'])
def test_the_list_asks_for_the_caller_once_not_once_per_server(api, seed, pbs, who, monkeypatch):
    """/api/pbs is polled; the confinement check reuses the caller acting_user() already
    has instead of building it from the whole users table for every server."""
    import pegaprox.utils.auth as authmod
    for i in range(3):
        ppglobals.pbs_managers[f'pbs_{i}'] = pbs
    builds = []
    real = authmod.build_authz_user
    monkeypatch.setattr(authmod, 'build_authz_user',
                        lambda name, session=None: builds.append(name) or real(name, session))

    r = who(api, seed).get('/api/pbs')

    assert r.status_code == 200, r.get_data(as_text=True)[:200]
    assert len(builds) == 1, builds


@pytest.mark.parametrize('username,confined', [('ghost', True), ('boss', False)],
                         ids=['no-record', 'admin'])
def test_a_session_user_without_a_record_is_confined(api, seed, pbs, username, confined):
    import pegaprox.api.pbs as pbsmod
    from flask import request as _rq
    seed.user('boss', role='admin')
    with api.app.test_request_context('/'):
        _rq.session = {'user': username, 'role': 'admin'}
        assert pbsmod._confined_on_pbs(pbs) is confined


# GET routes under a server that answer a confined caller some other way than the gate
OTHERWISE = {
    '/api/pbs/<pbs_id>/datastores': 'names only',
    '/api/pbs/<pbs_id>/datastores/<store>/namespaces': 'ns only',
    '/api/pbs/<pbs_id>/datastores/<store>/snapshots': 'rows scoped per guest',
    '/api/pbs/<pbs_id>/datastores/<store>/groups': 'rows scoped per guest',
    '/api/pbs/<pbs_id>/tasks': 'rows scoped per guest',
    '/api/pbs/<pbs_id>/tasks/<path:upid>': 'authorized per guest',
    '/api/pbs/<pbs_id>/datastores/<store>/notes': 'authorized per guest',
    '/api/pbs/<pbs_id>/datastores/<store>/group-notes': 'authorized per guest',
    '/api/pbs/<pbs_id>/datastores/<store>/catalog': 'authorized per guest',
    '/api/pbs/<pbs_id>/datastores/<store>/file-download': 'authorized per guest',
    '/api/pbs/<pbs_id>/backup-diff': 'authorized per guest',
    '/api/pbs/<pbs_id>/reports/summary': 'rows scoped per guest',
    '/api/pbs/<pbs_id>/reports/inventory': 'rows scoped per guest',
    '/api/pbs/<pbs_id>/reports/protected-vms': 'rows scoped per guest',
    '/api/pbs/<pbs_id>/notifications': 'require_pbs_wide',
}


def test_every_server_read_is_gated_or_scoped_some_other_way(api):
    """A new GET route under a server lands in ROUTES (and the gate) or in OTHERWISE."""
    adapter = api.app.url_map.bind('localhost')
    gated = {adapter.match(path, method='GET', return_rule=True)[0].rule for path, _ in ROUTES}
    assert not gated & set(OTHERWISE)

    rules = {r.rule for r in api.app.url_map.iter_rules()
             if r.rule.startswith('/api/pbs/<') and r.rule.count('/') > 3 and 'GET' in r.methods}

    assert rules - gated - set(OTHERWISE) == set(), 'a GET route under a PBS answers on check_pbs_access alone'
    assert set(OTHERWISE) <= rules, 'a listed route is gone, drop it from OTHERWISE'


def test_a_confined_caller_still_lists_its_own_snapshots(api, seed, pbs):
    """The names are there to open a datastore; the snapshot listing scopes the rows."""
    client = _portal_user(api, seed)

    names = client.get(f'{P}/datastores').get_json()
    r = client.get(f'{P}/datastores/{names[0]["name"]}/snapshots')

    assert r.status_code == 200, r.get_data(as_text=True)[:200]
    assert {s['backup-id'] for s in r.get_json()} == {str(MINE)}
    assert client.get(f'{P}/datastores/store1/namespaces').status_code == 200


def test_an_unconfined_operator_lists_every_snapshot(api, seed, pbs):
    r = _operator(api, seed).get(f'{P}/datastores/store1/snapshots')

    assert r.status_code == 200, r.get_data(as_text=True)[:200]
    assert {s['backup-id'] for s in r.get_json()} == {str(MINE), str(THEIRS)}
