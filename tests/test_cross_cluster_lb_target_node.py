"""The cross-cluster balancer passed the source node as its own target.

cross_cluster_lb picks a source node on the busiest cluster and a target node on
the quietest, then called

    hi_mgr.find_migration_candidate(source_node, source_node, ...)

Two gates inside that method are evaluated against target_node, and with the
source substituted neither could ever refuse:

  * plb_pin — "only pick this guest if the target is one of its pinned nodes".
    The guest's own node is always one of them, so a pinned guest was selected to
    be migrated off the very node it was pinned to.
  * the local-disk storage check — "does the target node have this storage".
    Asked of our own cluster about our own node, so always yes, and a local-disk
    guest could be sent to a cluster with no such storage.

The storage lookup also has to reach the OTHER cluster's API, which is what
target_mgr is for. MK
"""
from unittest.mock import MagicMock

import pytest

import pegaprox.background.cross_cluster_lb as xclb


def _mgr(host, node):
    m = MagicMock()
    m.host, m.api_port = host, 8006
    m.config.balance_local_disks = False
    return m


def test_the_balancer_passes_the_real_target_node(monkeypatch):
    """The regression itself: source and target must be different nodes."""
    calls = {}

    hi, lo = _mgr('hi.example', 'hi1'), _mgr('lo.example', 'lo1')

    def _find(source_node, target_node, **kw):
        calls['source'], calls['target'] = source_node, target_node
        calls['target_mgr'] = kw.get('target_mgr')
        return None
    hi.find_migration_candidate = _find

    monkeypatch.setattr(xclb, 'cluster_managers', {'hi': hi, 'lo': lo})
    monkeypatch.setattr(xclb, 'compute_cluster_score',
                        lambda m: 90.0 if m is hi else 10.0)
    monkeypatch.setattr(xclb, '_pick_node',
                        lambda m, highest: 'hi1' if m is hi else 'lo1')

    class _DB:
        def query(self, *a, **kw):
            return [{'id': 'hi'}, {'id': 'lo'}]
    monkeypatch.setattr(xclb, 'get_db', lambda: _DB())

    xclb.run_cross_cluster_balance_check({
        'id': 'g1', 'name': 'group', 'cross_cluster_threshold': 5,
        'cross_cluster_dry_run': 0, 'cross_cluster_include_containers': 0,
    })

    assert calls['source'] == 'hi1'
    assert calls['target'] == 'lo1', 'the source node was passed as its own target'
    assert calls['target_mgr'] is lo, 'the storage lookup must reach the target cluster'


@pytest.fixture
def candidate_mgr():
    """A stand-in `self` with exactly what find_migration_candidate reads, so the two gates
    can be exercised without a live cluster. host is a read-only property on the real
    manager, so call the method unbound rather than instantiating one."""
    import types
    return types.SimpleNamespace(
        host='src.example', api_port=8006,
        config=types.SimpleNamespace(balance_local_disks=False),
        logger=MagicMock(),
        _vm_migration_cooldown={},
        get_vm_resources=lambda: [
            {'vmid': 100, 'name': 'pinned', 'node': 'src1', 'status': 'running',
             'type': 'qemu', 'maxmem': 1 << 30, 'maxcpu': 2, 'pool': ''},
        ],
        get_balancing_excluded_vms=lambda: [],
        get_balancing_excluded_pools=lambda: [],
        get_proxmox_ha_resources=lambda *a, **kw: {},
        _derive_proxlb_tag_rules=lambda vms=None: {'ignored': set(), 'pins': {100: {'src1'}}},
        _api_get=lambda *a, **kw: None,
        _create_session=lambda: MagicMock(),
        _format_bytes=lambda n: str(n),
        _get_vm_storage=lambda *a, **kw: 'local-lvm',
        check_vm_storage_type=lambda *a, **kw: 'shared',
        _check_affinity_violation=lambda *a, **kw: {'violation': False},
        _check_cpu_compatibility=lambda *a, **kw: {'compatible': True},
    )


def _pick(mgr, source_node, target_node):
    from pegaprox.core.manager import PegaProxManager
    return PegaProxManager.find_migration_candidate(mgr, source_node, target_node)


def test_a_pinned_guest_is_not_picked_for_another_cluster(candidate_mgr):
    """plb_pin says "this guest belongs on src1". A cross-cluster move to lo1 is exactly what
    the pin forbids, and passing source as target made the gate agree to it."""
    assert _pick(candidate_mgr, 'src1', 'lo1') is None, \
        'a pinned guest was selected to be moved off its pin'


def test_the_same_guest_is_still_picked_for_its_pinned_node(candidate_mgr):
    """The behaviour we must not lose: a pin permits a move TO a pinned node."""
    picked = _pick(candidate_mgr, 'src1', 'src1')

    assert picked is not None and picked['vmid'] == 100
