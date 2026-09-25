"""storage.py: whole-cluster actions on cluster reach, and a permission nobody asked for.

Six findings, four causes.

check_cluster_access gates REACHABILITY, and its #248 (VM-ACL) and #555 (pool)
fallbacks deliberately admit a confined caller so the real decision can happen
downstream. Several storage routes had no downstream: syncing ISO/template
content across every node of a cluster, and reading the registered ESXi
endpoints and their guest inventory. None of those has a per-object notion, so
require_unconfined is the question they should have been asking.

The permission one is its own kind of wrong. `storage.create` ("Add new storage")
has existed since the RBAC work and was enforced on no route at all — the create
route asked for `storage.config` ("Modify storage config"). Our own role
templates draw the distinction: `storage_admin` lists storage.create, the
tenant-admin template deliberately does not. Both could add storage anyway, so
the distinction was fiction. Same shape as node.reboot.

And the generic create route reaches the same PVE endpoint as the dedicated ESXi
route with type='esxi', while asking for far less than the cluster.admin that one
requires — so it was simply the cheaper way to register a foreign hypervisor.

Aikido ai_pentest 700489684 700489015 700489646 700489361 700488024 700489344
700489627. MK
"""
import pytest

from pegaprox.models.permissions import ROLE_PERMISSIONS, ROLE_USER

CLUSTER = 'cluster_1'
OWNER = 'acme'
OTHER = 'globex'


@pytest.fixture
def cluster(api, seed):
    seed.tenant(OWNER, clusters=[CLUSTER])
    seed.tenant(OTHER, clusters=['cluster_other'])
    api.set_manager(CLUSTER, api.make_fake_manager(CLUSTER))
    # Register an ESXi endpoint. Without one the inventory route answers 404 before it
    # ever reaches the enumeration, and a counter-proof against the unfixed tree would
    # be red for "not found" rather than for the disclosure it is supposed to catch.
    import pegaprox.api.storage as storagemod
    storagemod.esxi_storages[CLUSTER] = {
        'h1': {'storage_name': 'esx-store', 'host': '10.0.0.5'},
    }
    try:
        yield CLUSTER
    finally:
        storagemod.esxi_storages.pop(CLUSTER, None)


@pytest.fixture
def confined(api, seed, cluster):
    """Reaches the cluster only through a VM-ACL — the #248 fallback."""
    u = seed.user('portal', role='user', tenant_id=OTHER,
                  permissions=['storage.view', 'storage.upload', 'storage.config',
                               'storage.create', 'storage.download', 'cluster.view'])
    seed.vm_acl(CLUSTER, 100, users=['portal'])
    return api.as_user(u)


@pytest.fixture
def operator(api, seed, cluster):
    """Unconfined: their tenant owns the cluster, no pool or ACL grant."""
    return api.as_user(seed.user('operator', role='user', tenant_id=OWNER,
                                 permissions=['storage.view', 'storage.upload',
                                              'storage.config', 'storage.create',
                                              'storage.download', 'cluster.view']))


# ------------------------------------------------- cluster-wide content sync

def test_a_confined_caller_cannot_start_a_cluster_wide_iso_sync(confined, cluster):
    r = confined.post(f'/api/clusters/{cluster}/iso-sync',
                      json={'source_node': 'pve1', 'storage': 'local', 'filename': 'x.iso'})
    assert r.status_code == 403, r.data


def test_a_confined_caller_cannot_sync_everything(confined, cluster):
    r = confined.post(f'/api/clusters/{cluster}/iso-sync/all', json={})
    assert r.status_code == 403, r.data


def test_an_unconfined_operator_is_not_blocked_by_the_sync_gate(operator, cluster):
    r = operator.post(f'/api/clusters/{cluster}/iso-sync/all', json={})
    assert r.status_code != 403, r.data


# ------------------------------------------------------------ ESXi inventory

def test_a_confined_caller_cannot_list_the_esxi_endpoints(confined, cluster):
    assert confined.get(f'/api/clusters/{cluster}/esxi-hosts').status_code == 403


def test_a_confined_caller_cannot_enumerate_esxi_guests(confined, cluster):
    assert confined.get(f'/api/clusters/{cluster}/esxi-hosts/h1/vms').status_code == 403


def test_an_unconfined_operator_still_lists_the_esxi_endpoints(operator, cluster):
    r = operator.get(f'/api/clusters/{cluster}/esxi-hosts')
    assert r.status_code != 403, r.data


# ------------------------------------------------------- the permission split

def test_adding_storage_now_asks_for_storage_create(api, seed, cluster):
    """The tenant-admin template has storage.config and deliberately not
    storage.create. Before this it could add storage regardless."""
    u = seed.user('modifier', role='user', tenant_id=OWNER,
                  permissions=['storage.config', 'cluster.view'])   # no storage.create
    r = api.as_user(u).post(f'/api/clusters/{cluster}/datacenter/storage',
                            json={'type': 'dir', 'storage': 's1', 'path': '/mnt/x'})
    assert r.status_code == 403, r.data


def test_a_storage_admin_can_still_add_storage(operator, cluster):
    """The mirror — storage_admin holds storage.create and must keep working."""
    r = operator.post(f'/api/clusters/{cluster}/datacenter/storage',
                      json={'type': 'dir', 'storage': 's1', 'path': '/mnt/x'})
    assert r.status_code != 403, r.data


def test_registering_an_esxi_target_needs_cluster_admin(operator, cluster):
    """The dedicated ESXi route requires cluster.admin; the generic one reached the
    same PVE endpoint for less."""
    r = operator.post(f'/api/clusters/{cluster}/datacenter/storage',
                      json={'type': 'esxi', 'storage': 'esx1', 'server': '10.0.0.5'})
    assert r.status_code == 403, r.data
    assert 'cluster.admin' in r.get_data(as_text=True)


def test_a_cluster_admin_may_register_an_esxi_target(api, seed, cluster):
    u = seed.user('clusteradmin', role='user', tenant_id=OWNER,
                  permissions=['storage.create', 'cluster.admin', 'cluster.view'])
    r = api.as_user(u).post(f'/api/clusters/{cluster}/datacenter/storage',
                            json={'type': 'esxi', 'storage': 'esx1', 'server': '10.0.0.5'})
    assert r.status_code != 403, r.data


# -------------------------------------------------------- process-wide stats

def test_cache_statistics_are_scoped_to_the_cluster_asked_about():
    """The route is cluster-scoped; the numbers were installation-wide."""
    from pegaprox.core.cache import StorageDataCache
    c = StorageDataCache()
    c.set('cluster_a', 'k1', {'x': 1})
    c.set('cluster_b', 'k1', {'x': 1})
    c.set('cluster_b', 'k2', {'x': 1})

    scoped = c.get_stats('cluster_a')
    assert scoped['clusters_cached'] == 1
    assert scoped['total_entries'] == 1

    assert c.get_stats()['clusters_cached'] == 2   # the process-wide form still works


# ------------------------------------------ input that reaches a shared worker

def test_worker_integers_are_clamped_not_trusted():
    """max_concurrent and check_interval were stored exactly as submitted, and the
    shared auto-balance thread then does `len(active) >= max_concurrent` and sleeps
    on check_interval. A string or a negative from one storage.config holder raised
    inside that thread and stopped auto-balance for every cluster in the
    installation."""
    from pegaprox.api.storage import _bounded_worker_int as clamp

    assert clamp('not-a-number', 1, 1, 32) == 1
    assert clamp(None, 1, 1, 32) == 1
    assert clamp(-5, 1, 1, 32) == 1
    assert clamp(0, 1, 1, 32) == 1
    assert clamp(10_000, 1, 1, 32) == 32
    assert clamp('4', 1, 1, 32) == 4          # the UI posts strings
    assert clamp(8, 1, 1, 32) == 8            # ordinary values pass through


def test_a_hostile_max_concurrent_cannot_reach_the_worker(operator, cluster):
    """End to end: whatever is submitted, what gets stored is comparable with an int."""
    r = operator.post(f'/api/clusters/{cluster}/storage-clusters',
                      json={'name': 'sc1', 'storages': ['local', 'local-lvm'],
                            'max_concurrent': 'drop table', 'check_interval': -1})
    assert r.status_code in (200, 201), r.data

    import pegaprox.api.storage as storagemod
    sc = storagemod.storage_clusters_config[cluster]['clusters'][-1]
    assert isinstance(sc['max_concurrent'], int)
    assert sc['max_concurrent'] >= 1
    assert isinstance(sc['check_interval'], int)
    assert sc['check_interval'] >= 60
