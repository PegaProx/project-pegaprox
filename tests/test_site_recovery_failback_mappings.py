"""Failback has to read the plan's mappings backwards.

execute_failover() swaps src/tgt for failover_type='failback' but kept using the
plan's storage/network maps as authored, which are {production: DR}. Replayed on
the way home that puts every VM on the DR site's storage and bridge names — on
the production cluster. Usually the pre-flight catches it and the failback just
refuses to run; where a name exists on both sides it goes through and lands the
VM on the wrong tier / wrong VLAN with no error at all. MK
"""
import json
from unittest.mock import MagicMock

import pytest

import pegaprox.background.site_recovery as sr
import pegaprox.globals as ppglobals


PROD, DR = 'cluster_prod', 'cluster_dr'


def _mgr(storages, bridges):
    m = MagicMock()
    m.is_connected = True
    m.get_node_status.return_value = {'pve1': {'status': 'online'}}
    m.get_storage_list.return_value = [{'storage': s} for s in storages]
    m.get_network_list.return_value = [{'iface': b} for b in bridges]
    return m


@pytest.fixture
def plan(db):
    """One plan, prod → DR, with one VM in it. A failback moves only the guests that are
    failed over, so the failback tests make theirs one (failed_over='planned')."""
    def _make(storage_map, net_map, failed_over=''):
        db.execute(
            "INSERT INTO site_recovery_plans (id, group_id, name, source_cluster, "
            "target_cluster, network_mappings, storage_mappings, status) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ('plan_1', 'g1', 'DR Plan', PROD, DR,
             json.dumps(net_map), json.dumps(storage_map), 'running'))
        db.execute(
            "INSERT INTO site_recovery_vms (id, plan_id, vmid, vm_name, vm_type, boot_group, failed_over) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            ('vm_row_1', 'plan_1', 100, 'app-01', 'qemu', 0, failed_over))
        return 'plan_1'
    return _make


@pytest.fixture
def migrations(monkeypatch):
    """Record what _migrate_vm_cross_cluster was handed instead of migrating."""
    calls = []

    def _fake(src_mgr, tgt_mgr, vmid, vm_type, storage_map, net_map):
        calls.append({'vmid': vmid, 'storage_map': dict(storage_map or {}),
                      'net_map': dict(net_map or {})})
        return True, None

    monkeypatch.setattr(sr, '_migrate_vm_cross_cluster', _fake)
    monkeypatch.setattr(sr, '_target_vmid_exists', lambda *a, **kw: False)
    monkeypatch.setattr(sr, '_broadcast_progress', lambda *a, **kw: None)
    monkeypatch.setattr(sr, '_fire_webhook', lambda *a, **kw: None)
    return calls


@pytest.fixture
def clusters():
    ppglobals.cluster_managers.clear()
    try:
        yield ppglobals.cluster_managers
    finally:
        ppglobals.cluster_managers.clear()


def test_failback_reverses_the_mappings(db, plan, migrations, clusters):
    """Both sites use the same storage/bridge names, so the pre-flight can't save
    us — pre-fix this migrated the VM home onto 'dr-ssd'/'vmbr9'."""
    plan_id = plan({'prod-ssd': 'dr-ssd'}, {'vmbr0': 'vmbr9'}, failed_over='planned')
    both = ['prod-ssd', 'dr-ssd']
    clusters[PROD] = _mgr(both, ['vmbr0', 'vmbr9'])
    clusters[DR] = _mgr(both, ['vmbr0', 'vmbr9'])

    sr.execute_failover(plan_id, 'failback')

    assert len(migrations) == 1, migrations
    assert migrations[0]['storage_map'] == {'dr-ssd': 'prod-ssd'}, migrations[0]
    assert migrations[0]['net_map'] == {'vmbr9': 'vmbr0'}, migrations[0]


def test_failback_runs_when_only_the_production_names_exist_at_home(db, plan, migrations, clusters):
    """The common case: the DR storage name does not exist on the production
    cluster, so the forward map made the pre-flight abort every failback."""
    plan_id = plan({'prod-ssd': 'dr-ssd'}, {'vmbr0': 'vmbr9'}, failed_over='planned')
    clusters[PROD] = _mgr(['prod-ssd'], ['vmbr0'])
    clusters[DR] = _mgr(['dr-ssd'], ['vmbr9'])

    sr.execute_failover(plan_id, 'failback')

    assert len(migrations) == 1, 'pre-flight rejected the failback'
    assert migrations[0]['storage_map'] == {'dr-ssd': 'prod-ssd'}


def test_forward_failover_keeps_the_mappings_as_authored(db, plan, migrations, clusters):
    plan_id = plan({'prod-ssd': 'dr-ssd'}, {'vmbr0': 'vmbr9'})
    clusters[PROD] = _mgr(['prod-ssd'], ['vmbr0'])
    clusters[DR] = _mgr(['dr-ssd'], ['vmbr9'])

    sr.execute_failover(plan_id, 'planned')

    assert len(migrations) == 1, 'pre-flight rejected the failover'
    assert migrations[0]['storage_map'] == {'prod-ssd': 'dr-ssd'}
    assert migrations[0]['net_map'] == {'vmbr0': 'vmbr9'}


def test_failback_refuses_a_mapping_it_cannot_reverse(db, plan, migrations, clusters):
    """Two production tiers collapsed onto one DR tier: reversing it would have to
    guess which one the VM came from, so the plan fails pre-flight instead."""
    plan_id = plan({'prod-ssd': 'dr-ssd', 'prod-hdd': 'dr-ssd'}, {}, failed_over='planned')
    clusters[PROD] = _mgr(['prod-ssd', 'prod-hdd', 'dr-ssd'], ['vmbr0'])
    clusters[DR] = _mgr(['dr-ssd'], ['vmbr0'])

    sr.execute_failover(plan_id, 'failback')

    assert migrations == [], 'a non-reversible mapping must not move VMs'
    status = db.query_one("SELECT status FROM site_recovery_plans WHERE id = ?", (plan_id,))
    assert dict(status)['status'] == 'failed'


def test_reverse_mapping_helper():
    reversed_map, issues = sr._reverse_mapping({'a': 'x', 'b': 'y'}, 'Storage')
    assert reversed_map == {'x': 'a', 'y': 'b'}
    assert issues == []

    # empty targets are dropped, not reversed into a '' key
    reversed_map, issues = sr._reverse_mapping({'a': 'x', 'b': ''}, 'Storage')
    assert reversed_map == {'x': 'a'}
    assert issues == []

    reversed_map, issues = sr._reverse_mapping({'a': 'x', 'b': 'x'}, 'Network')
    assert len(issues) == 1 and issues[0]['severity'] == 'error'
    assert 'not reversible' in issues[0]['msg']
