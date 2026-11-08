"""A backup on a shared PBS belongs to the cluster that writes it there.

(#1083) _authz_pbs_backup accepted vm/<id> when the caller could use that VMID on
ANY cluster linked to the PBS. Clusters number their guests from 100, so with VM
100 on cluster A a confined user, or an operator of A's tenant, listed, browsed,
downloaded and deleted cluster B's vm/100 backups on a datastore both write to.

PBS does not record the cluster. Each cluster's storage.cfg does say which
datastore and namespace its pbs storage writes to, and that decides the owner
now. A place no linked cluster claims needs the guest on every one of them.

The fixture is the usual multi-tenant layout: one datastore, a namespace per
tenant. Cluster B names the PBS by address and only its certificate matches. MK
"""
import time
from unittest.mock import MagicMock

import pytest

import pegaprox.api.pbs as pbsmod
import pegaprox.globals as ppglobals


PBS_ID = 'pbs_shared'
P = f'/api/pbs/{PBS_ID}'
HOST = 'pbs.example.com'
FP = ':'.join(['C3'] * 32)
VMID = 100
WHEN = 1_756_000_000

STORAGE_A = [{'storage': 'pbs-a', 'type': 'pbs', 'server': HOST, 'datastore': 'store1',
              'namespace': 'tenant-a', 'content': 'backup'},
             {'storage': 'pbs-a-archive', 'type': 'pbs', 'server': HOST, 'datastore': 'store2',
              'content': 'backup'},
             {'storage': 'local', 'type': 'dir', 'path': '/var/lib/vz'}]
STORAGE_B = [{'storage': 'pbs-b', 'type': 'pbs', 'server': '10.0.0.9', 'datastore': 'store1',
              'namespace': 'tenant-b', 'fingerprint': FP.lower(), 'content': 'backup'}]


def _resp(data, status=200):
    r = MagicMock()
    r.status_code = status
    r.json.return_value = {'data': data}
    return r


def _cluster(api, cid, storages, guest_name):
    cm = api.make_fake_manager(cid, get_vm_resources=[
        {'type': 'qemu', 'vmid': VMID, 'name': guest_name, 'node': f'{cid}-n1'}])
    cm.is_connected = True
    cm._api_get.side_effect = lambda url, *a, **k: (
        _resp(storages) if url.endswith('/storage') else _resp([]))
    return api.set_manager(cid, cm)


def _snap():
    return {'backup-type': 'vm', 'backup-id': str(VMID), 'backup-time': WHEN,
            'files': [], 'size': 1}


@pytest.fixture(autouse=True)
def _fresh_storage_reads():
    """What this file's clusters said about their storages must not reach the next test."""
    seen = getattr(pbsmod, '_pbs_storages_seen', {})
    seen.clear()
    yield
    seen.clear()
    pbsmod._backup_status_cache.clear()


@pytest.fixture
def clusters(api, seed):
    seed.tenant('tenant_a', clusters=['cluster_1'])
    seed.tenant('tenant_b', clusters=['cluster_2'])
    a = _cluster(api, 'cluster_1', STORAGE_A, 'a-web')
    b = _cluster(api, 'cluster_2', STORAGE_B, 'b-ledger')
    return a, b


@pytest.fixture
def pbs(api, clusters):
    m = MagicMock()
    m.name = 'shared'
    m.host, m.port, m.fingerprint = HOST, 8007, FP
    # B first: the old name lookup took the first cluster with the number
    m.linked_clusters = ['cluster_2', 'cluster_1']
    m.connected = True
    m.get_snapshots.side_effect = lambda store, ns=None, **kw: {'data': [_snap()]}
    m.get_groups.side_effect = lambda store, ns=None: {'data': [
        {'backup-type': 'vm', 'backup-id': str(VMID), 'last-backup': WHEN}]}
    m.get_datastores.return_value = {'data': [{'name': 'store1', 'store': 'store1'}]}
    m.get_namespaces.return_value = {'data': [{'ns': 'tenant-a'}, {'ns': 'tenant-b'}]}
    m.browse_catalog.return_value = {'data': [{'filename': 'etc', 'type': 'd'}]}
    m.delete_snapshot.return_value = {'data': None}
    m.get_snapshot_notes.return_value = {'data': 'ledger export'}
    ppglobals.pbs_managers.clear()
    ppglobals.pbs_managers[PBS_ID] = m
    try:
        yield m
    finally:
        ppglobals.pbs_managers.clear()


PERMS = ['pbs.view', 'pbs.datastore.view', 'pbs.snapshot.browse', 'pbs.snapshot.delete']


@pytest.fixture(params=['portal_user', 'tenant_operator'])
def tenant_a_caller(request, api, seed, pbs):
    """Both kinds the finding names: a VM-ACL-confined user with VM 100 on cluster A, and a
    plain operator of A's tenant - not confined on A, but B is not theirs."""
    if request.param == 'portal_user':
        u = seed.user('alice', role='user', tenant_id='tenant_a', permissions=PERMS)
        seed.vm_acl('cluster_1', VMID, ['alice'], permissions=['vm.view', 'vm.backup'])
    else:
        u = seed.user('bob', role='user', tenant_id='tenant_a', permissions=PERMS)
    return api.as_user(u)


# -- the other tenant's backups ---------------------------------------------------------

def test_the_other_tenants_namespace_lists_nothing(tenant_a_caller):
    r = tenant_a_caller.get(f'{P}/datastores/store1/snapshots?ns=tenant-b')

    assert r.status_code == 200, r.get_data(as_text=True)[:200]
    assert r.get_json() == [], 'cluster B\'s vm/100 was listed to cluster A\'s tenant'


def test_the_other_tenants_groups_list_nothing(tenant_a_caller):
    r = tenant_a_caller.get(f'{P}/datastores/store1/groups?ns=tenant-b')

    assert r.status_code == 200
    assert r.get_json() == []


def test_the_other_tenants_backup_cannot_be_deleted(tenant_a_caller, pbs):
    r = tenant_a_caller.delete(f'{P}/datastores/store1/snapshots', json={
        'backup_type': 'vm', 'backup_id': str(VMID), 'backup_time': WHEN, 'ns': 'tenant-b'})

    assert r.status_code == 403, r.get_data(as_text=True)[:200]
    assert not pbs.delete_snapshot.called


def test_a_place_nobody_claims_needs_the_guest_on_every_linked_cluster(tenant_a_caller, pbs):
    """store1's root namespace is in nobody's storage.cfg: it could be either VM 100."""
    r = tenant_a_caller.get(f'{P}/datastores/store1/catalog?backup-type=vm&backup-id={VMID}'
                            f'&backup-time={WHEN}&filepath=/')

    assert r.status_code == 403, r.get_data(as_text=True)[:200]
    assert not pbs.browse_catalog.called


def test_the_listing_names_the_guest_after_the_owner(tenant_a_caller):
    """The old lookup named cluster A's backup after cluster B's VM 100."""
    r = tenant_a_caller.get(f'{P}/datastores/store1/snapshots?ns=tenant-a')

    assert [s.get('vm_name') for s in r.get_json()] == ['a-web']


def test_the_inventory_report_leaves_the_other_tenants_namespace_out(tenant_a_caller):
    r = tenant_a_caller.get(f'{P}/reports/inventory')

    assert r.status_code == 200, r.get_data(as_text=True)[:200]
    places = sorted((e['namespace'], e['vm_name']) for e in r.get_json()['entries'])
    assert places == [('tenant-a', 'a-web')], places


def test_the_protected_report_does_not_count_the_other_tenants_backup(tenant_a_caller, pbs):
    """Cluster A's VM 100 has no backup; cluster B's VM 100 has one from a minute ago."""
    recent = int(time.time()) - 60
    pbs.get_snapshots.side_effect = lambda store, ns=None, **kw: {
        'data': [dict(_snap(), **{'backup-time': recent})] if ns == 'tenant-b' else []}

    r = tenant_a_caller.get(f'{P}/reports/protected-vms?cluster_id=cluster_1')

    assert r.status_code == 200, r.get_data(as_text=True)[:200]
    body = r.get_json()
    assert [e['vmid'] for e in body['unprotected']] == [str(VMID)], body
    assert 'tenant-b' not in r.get_data(as_text=True)


# -- what stays theirs ------------------------------------------------------------------

def test_their_own_namespace_still_lists(tenant_a_caller):
    r = tenant_a_caller.get(f'{P}/datastores/store1/snapshots?ns=tenant-a')

    assert r.status_code == 200
    assert len(r.get_json()) == 1


def test_their_own_backup_can_still_be_deleted(tenant_a_caller, pbs):
    r = tenant_a_caller.delete(f'{P}/datastores/store1/snapshots', json={
        'backup_type': 'vm', 'backup_id': str(VMID), 'backup_time': WHEN, 'ns': 'tenant-a'})

    assert r.status_code == 200, r.get_data(as_text=True)[:200]
    assert pbs.delete_snapshot.called


def test_a_root_namespace_their_cluster_alone_writes_to_still_browses(tenant_a_caller, pbs):
    r = tenant_a_caller.get(f'{P}/datastores/store2/catalog?backup-type=vm&backup-id={VMID}'
                            f'&backup-time={WHEN}&filepath=/')

    assert r.status_code == 200, r.get_data(as_text=True)[:200]


def test_an_operator_of_both_clusters_is_not_narrowed(api, seed, pbs):
    seed.tenant('tenant_ab', clusters=['cluster_1', 'cluster_2'])
    op = api.as_user(seed.user('ab_op', role='user', tenant_id='tenant_ab', permissions=PERMS))

    assert len(op.get(f'{P}/datastores/store1/snapshots?ns=tenant-b').get_json()) == 1
    assert op.get(f'{P}/datastores/store1/catalog?backup-type=vm&backup-id={VMID}'
                  f'&backup-time={WHEN}&filepath=/').status_code == 200


def test_an_admin_sees_every_namespace_with_the_right_names(api, seed, pbs):
    boss = api.as_user(seed.user('boss', role='admin'))

    a = boss.get(f'{P}/datastores/store1/snapshots?ns=tenant-a').get_json()
    b = boss.get(f'{P}/datastores/store1/snapshots?ns=tenant-b').get_json()

    assert [s['vm_name'] for s in a] == ['a-web']
    assert [s['vm_name'] for s in b] == ['b-ledger']


# -- the owner rules --------------------------------------------------------------------

def _owners(mgr):
    return pbsmod._BackupOwners(mgr)


def test_one_linked_cluster_owns_everything_without_reading_anything(api, clusters, pbs):
    a, b = clusters
    pbs.linked_clusters = ['cluster_1']

    assert _owners(pbs).of('store1', 'tenant-b') == ['cluster_1']
    assert not a._api_get.called and not b._api_get.called


def test_a_cluster_whose_storages_cannot_be_read_may_own_anything(api, clusters, pbs):
    a, b = clusters
    b._api_get.side_effect = lambda url, *a_, **k: _resp([], status=500)

    assert _owners(pbs).of('store1', 'tenant-a') == ['cluster_1', 'cluster_2']


def test_a_cluster_that_drops_offline_keeps_its_last_claims(api, clusters, pbs):
    a, b = clusters
    assert _owners(pbs).of('store1', 'tenant-b') == ['cluster_2']
    # an hour later B is gone
    for cid, (_, entries) in list(pbsmod._pbs_storages_seen.items()):
        pbsmod._pbs_storages_seen[cid] = (0.0, entries)
    b.is_connected = False

    assert _owners(pbs).of('store1', 'tenant-b') == ['cluster_2']
    assert _owners(pbs).of('store1', 'tenant-a') == ['cluster_1']


def test_two_clusters_writing_into_one_place_both_own_it(api, clusters, pbs):
    a, b = clusters
    shared = [{'storage': 'pbs', 'type': 'pbs', 'server': HOST, 'datastore': 'store1'}]
    a._api_get.side_effect = b._api_get.side_effect = lambda url, *a_, **k: _resp(shared)

    assert sorted(_owners(pbs).of('store1', '')) == ['cluster_1', 'cluster_2']


def test_a_storage_on_another_pbs_claims_nothing_here(api, clusters, pbs):
    a, b = clusters
    elsewhere = [{'storage': 'pbs-x', 'type': 'pbs', 'server': 'other-pbs.example.com',
                  'datastore': 'store1', 'namespace': 'tenant-a'}]
    a._api_get.side_effect = lambda url, *a_, **k: _resp(elsewhere)

    assert sorted(_owners(pbs).of('store1', 'tenant-a')) == ['cluster_1', 'cluster_2']


def test_a_listing_reads_each_storage_cfg_once_however_long_it_is(api, seed, clusters, pbs):
    a, b = clusters
    pbs.get_snapshots.side_effect = lambda store, ns=None, **kw: {'data': [
        dict(_snap(), **{'backup-id': str(VMID + i)}) for i in range(500)]}
    caller = api.as_user(seed.user('bob', role='user', tenant_id='tenant_a', permissions=PERMS))

    r = caller.get(f'{P}/datastores/store1/snapshots?ns=tenant-a')

    assert r.status_code == 200
    storage_reads = [c for c in a._api_get.call_args_list + b._api_get.call_args_list
                     if str(c.args[0]).endswith('/storage')]
    assert len(storage_reads) == 2, len(storage_reads)


@pytest.mark.parametrize('text,store', [
    ('store1:vm/100/68ab1f00', 'store1'),
    ('UPID:pbs:0000A1B2:00003C4D:00005E6F:68AB1F00:backup:store1:ct/205/68ab1f00:root@pam:', 'store1'),
    ('store1:ns/tenant-a/vm/100/68ab1f00', None),
    ('store1', None),
    (None, None),
])
def test_task_datastore_parsing(text, store):
    assert pbsmod._pbs_task_store(text) == store


# -- the backup pill on the guest list --------------------------------------------------

def test_the_guest_list_pill_does_not_count_another_clusters_root_namespace(api, clusters, pbs):
    """scan_backup_status reads the root namespace of each datastore and counts every vm/100
    in it as this cluster's VM 100. Here only cluster B writes to store1's root."""
    a, b = clusters
    b_root = [{'storage': 'pbs-b', 'type': 'pbs', 'server': HOST, 'datastore': 'store1'}]
    b._api_get.side_effect = lambda url, *a_, **k: (
        _resp(b_root) if url.endswith('/storage') else _resp([]))
    pbs.get_snapshots.side_effect = lambda store, ns=None, **kw: {'data': [
        dict(_snap(), **{'backup-time': int(time.time()) - 3600})]}

    rows_a = pbsmod.scan_backup_status('cluster_1', a)
    rows_b = pbsmod.scan_backup_status('cluster_2', b)

    assert rows_a == [], rows_a
    assert [r['vmid'] for r in rows_b] == [VMID]
