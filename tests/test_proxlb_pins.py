# ProxLB pin enforcement.
#
# plb_pin_<node> was only ever a veto: it filtered guests out of migrations the
# balancer had already proposed, and nothing in a cycle proposes a move *towards*
# a pin. A guest that was on the wrong node — moved by hand in the PVE UI, failed
# over by HA, evacuated while the pinned node was down, or simply tagged after
# the fact — therefore stayed there forever, and the tag looked like it did
# nothing. These tests pin the reconciliation that closes that, and the guards
# around it: the operator opts in, dry_run and auto_migrate still win, and a
# guest that is also tagged plb_ignore is left alone.
#
# The node names are deliberately mixed-case: PVE lower-cases tag text, so the
# tag can never spell -th-A and the pin has to resolve case-insensitively.

import logging
import time
import types

from pegaprox.utils import rbac

from pegaprox.core.manager import PegaProxManager
from pegaprox.models.tasks import MaintenanceTask, PegaProxConfig

A1, A2 = 'pve-dmz-node01-th-A', 'pve-dmz-node02-th-A'
I1 = 'pve-dmz-node11-th-I'
ALL_NODES = [A1, A2, I1]

PIN_A1 = 'plb_pin_pve-dmz-node01-th-a'


def _guest(vmid=30021, node=I1, tags=PIN_A1, status='running', mem=1024):
    return {'vmid': vmid, 'node': node, 'name': f'guest{vmid}', 'status': status,
            'type': 'qemu', 'mem': mem, 'tags': tags}


def _manager(guests, tags_enabled=True, pins_auto=False, auto_migrate=True,
             dry_run=False, down=(), scores=None, excluded_vms=(),
             maintenance=(), pins_strict=False):
    """A real PegaProxManager with only the PVE-facing calls stubbed, so the
    logic under test is the production code path."""
    mgr = object.__new__(PegaProxManager)
    mgr.id = 'cluster_1'
    mgr.logger = logging.getLogger('test.proxlb_pins')
    mgr._vm_migration_cooldown = {}
    mgr.config = PegaProxConfig({
        'name': 'test', 'host': 'h', 'user': 'u',
        'proxlb_tags_enabled': tags_enabled,
        'proxlb_pins_auto_migrate': pins_auto,
        'proxlb_pins_strict': pins_strict,
        'auto_migrate': auto_migrate, 'dry_run': dry_run,
        'migration_threshold': 10, 'migration_tolerance': 0,
    })
    scores = scores or {}
    mgr.get_node_status = lambda: {
        n: {'status': 'offline' if n in down else 'online',
            'maintenance_mode': n in maintenance, 'score': scores.get(n, 50.0),
            'mem_used': 100 * 1024 ** 3, 'mem_total': 1000 * 1024 ** 3, 'mem_percent': 10.0}
        for n in ALL_NODES}
    mgr.get_vm_resources = lambda: list(guests)
    mgr.get_balancing_excluded_vms = lambda: list(excluded_vms)
    mgr.get_balancing_excluded_pools = lambda: []
    mgr.get_proxmox_ha_resources = lambda: []
    mgr._api_get = lambda *a, **k: None
    mgr.check_vm_storage_type = lambda *a, **k: 'shared'
    # The evacuator waits up to 5 min for stragglers; nothing in these tests is
    # asynchronous, so report the node empty and skip the sleep loop.
    mgr._count_vms_on_node = lambda node: 0
    mgr.migrated = []

    def _migrate(vm, target, dry_run=False, wait_timeout=None):
        mgr.migrated.append((vm['vmid'], target))
        vm['node'] = target
        return True

    mgr.migrate_vm = _migrate
    return mgr


# --------------------------------------------------------------------------
# detection
# --------------------------------------------------------------------------

def test_a_lowercase_tag_resolves_an_uppercase_node(db):
    # The tag can only ever be plb_pin_..-th-a; the node really is ..-th-A.
    mgr = _manager([_guest(node=A1)])
    assert mgr._derive_proxlb_tag_rules()['pins'] == {30021: {A1}}


def test_guest_on_its_pin_is_no_violation(db):
    assert _manager([_guest(node=A1)]).get_pin_violations() == []


def test_guest_off_its_pin_is_reported(db):
    v = _manager([_guest(node=I1)]).get_pin_violations()
    assert len(v) == 1
    assert (v[0]['vmid'], v[0]['node'], v[0]['pinned_nodes'], v[0]['reason']) == \
        (30021, I1, [A1], 'drift')


def test_feature_off_reports_nothing(db):
    assert _manager([_guest()], tags_enabled=False).get_pin_violations() == []


def test_a_typo_in_the_tag_is_not_a_violation(db):
    # An unresolvable node name never becomes a pin, so it must not turn into a
    # "this guest is in the wrong place" report either.
    assert _manager([_guest(tags='plb_pin_pve-dmz-node01-th-x')]).get_pin_violations() == []


def test_a_pin_naming_no_node_is_reported_as_unresolved(db):
    # The failure mode this exists for: the tag is there, the guest never moves,
    # and nothing anywhere says the node name does not exist.
    mgr = _manager([_guest(tags='plb_pin_pve-dmz-node21-th-d')])
    assert mgr.get_unresolved_pins() == [{'vmid': 30021, 'node': 'pve-dmz-node21-th-d'}]
    assert mgr.get_pin_violations() == []


def test_an_unresolved_pin_is_logged_once_not_every_cycle(db, caplog):
    mgr = _manager([_guest(tags='plb_pin_pve-dmz-node21-th-d')])
    with caplog.at_level(logging.WARNING, logger='test.proxlb_pins'):
        mgr._derive_proxlb_tag_rules()
        mgr._proxlb_derived_cache = None  # next cycle, cache expired
        mgr._derive_proxlb_tag_rules()
    hits = [r for r in caplog.records if 'no node of that name' in r.getMessage()]
    assert len(hits) == 1


def test_a_resolvable_pin_is_not_reported_as_unresolved(db):
    assert _manager([_guest(node=A1)]).get_unresolved_pins() == []


def test_untagged_guests_are_ignored(db):
    assert _manager([_guest(tags='production;linux')]).get_pin_violations() == []


def test_pinned_node_down_is_reported_but_not_as_drift(db):
    # Nothing to migrate back to — the guest is off its pin because that is the
    # only place it can run, which is not the same as someone ignoring the pin.
    v = _manager([_guest()], down=[A1]).get_pin_violations()
    assert len(v) == 1 and v[0]['reason'] == 'unavailable'


# --------------------------------------------------------------------------
# reconciliation
# --------------------------------------------------------------------------

def test_reconcile_is_report_only_by_default(db):
    mgr = _manager([_guest()])
    r = mgr.reconcile_proxlb_pins()
    assert mgr.migrated == []
    assert len(r['violations']) == 1 and r['auto_migrate'] is False


def test_reconcile_returns_the_guest_when_opted_in(db):
    mgr = _manager([_guest()], pins_auto=True)
    r = mgr.reconcile_proxlb_pins()
    assert mgr.migrated == [(30021, A1)]
    assert r['migrated'][0]['target'] == A1


def test_reconcile_only_ever_targets_a_pinned_node(db):
    # A2 is by far the cheapest node, and it is in the same site — the pin still
    # has to win, or "pinned" means nothing.
    mgr = _manager([_guest()], pins_auto=True, scores={A1: 90.0, A2: 1.0})
    mgr.reconcile_proxlb_pins()
    assert mgr.migrated == [(30021, A1)]


def test_a_multi_node_pin_picks_the_least_loaded_of_them(db):
    guests = [_guest(tags=f'{PIN_A1};plb_pin_pve-dmz-node02-th-a')]
    mgr = _manager(guests, pins_auto=True, scores={A1: 90.0, A2: 10.0})
    mgr.reconcile_proxlb_pins()
    assert mgr.migrated == [(30021, A2)]


def test_dry_run_reports_but_does_not_migrate(db):
    mgr = _manager([_guest()], pins_auto=True, dry_run=True)
    r = mgr.reconcile_proxlb_pins()
    assert mgr.migrated == [] and len(r['violations']) == 1


def test_auto_migrate_off_holds_the_reconciler_back(db):
    # The cluster's master switch for autonomous moves is not something a
    # per-feature opt-in gets to route around.
    mgr = _manager([_guest()], pins_auto=True, auto_migrate=False)
    r = mgr.reconcile_proxlb_pins()
    assert mgr.migrated == [] and r['auto_migrate'] is False


def test_force_is_the_manual_button_and_overrides_both_switches(db):
    mgr = _manager([_guest()], pins_auto=False, auto_migrate=False)
    mgr.reconcile_proxlb_pins(force=True)
    assert mgr.migrated == [(30021, A1)]


def test_force_still_refuses_under_dry_run(db):
    mgr = _manager([_guest()], dry_run=True)
    assert mgr.reconcile_proxlb_pins(force=True)['migrated'] == []
    assert mgr.migrated == []


def test_pinned_node_down_migrates_nothing(db):
    mgr = _manager([_guest()], pins_auto=True, down=[A1])
    r = mgr.reconcile_proxlb_pins()
    assert mgr.migrated == [] and r['failed'] == []


def test_plb_ignore_beats_the_pin(db):
    # Both tags are the operator's. "Never migrate this guest" is the stronger
    # statement, and it is the one that keeps a GPU/local-disk guest in place.
    mgr = _manager([_guest(tags=f'{PIN_A1};plb_ignore')], pins_auto=True)
    mgr.reconcile_proxlb_pins()
    assert mgr.migrated == []


def test_a_local_disk_guest_is_not_dragged_back_onto_its_pin(db):
    # PVE refuses a live migration of a local disk without --with-local-disks, so
    # this would fail on every cycle forever. The balancer skips these guests too.
    mgr = _manager([_guest()], pins_auto=True)
    mgr.check_vm_storage_type = lambda *a, **k: 'local'
    mgr.reconcile_proxlb_pins()
    assert mgr.migrated == []


def test_a_local_disk_guest_moves_when_the_operator_opted_in(db):
    mgr = _manager([_guest()], pins_auto=True)
    mgr.config.balance_local_disks = True
    mgr.check_vm_storage_type = lambda *a, **k: 'local'
    mgr.reconcile_proxlb_pins()
    assert mgr.migrated == [(30021, A1)]


def test_an_unknown_storage_type_is_left_alone(db):
    mgr = _manager([_guest()], pins_auto=True)
    mgr.check_vm_storage_type = lambda *a, **k: 'unknown'
    mgr.reconcile_proxlb_pins()
    assert mgr.migrated == []


def test_a_guest_excluded_from_balancing_is_left_alone(db):
    mgr = _manager([_guest()], pins_auto=True, excluded_vms=[30021])
    mgr.reconcile_proxlb_pins()
    assert mgr.migrated == []


def test_stopped_guests_are_not_moved(db):
    mgr = _manager([_guest(status='stopped')], pins_auto=True)
    mgr.reconcile_proxlb_pins()
    assert mgr.migrated == []


def test_a_returned_guest_gets_a_cooldown(db):
    # Otherwise the next balance round can pick it straight back up and the pin
    # and the balancer take turns moving the same guest.
    mgr = _manager([_guest()], pins_auto=True)
    mgr.reconcile_proxlb_pins()
    assert 30021 in mgr._vm_migration_cooldown


def test_nothing_to_do_is_cheap_and_silent(db):
    mgr = _manager([_guest(node=A1)], pins_auto=True)
    r = mgr.reconcile_proxlb_pins()
    assert r == {'violations': [], 'migrated': [], 'failed': [], 'deferred': [],
                 'auto_migrate': True}


# --------------------------------------------------------------------------
# the veto the pin always had must survive
# --------------------------------------------------------------------------

def test_the_balancer_still_refuses_to_move_a_guest_off_its_pin(db):
    mgr = _manager([_guest(node=A1)])
    assert mgr.find_migration_candidate(A1, I1) is None


def test_a_move_onto_the_pin_is_still_offered(db):
    # Guards the test above: the rejection has to come from the pin filter, not
    # from some unrelated gate rejecting every candidate.
    mgr = _manager([_guest(node=I1)])
    c = mgr.find_migration_candidate(I1, A1)
    assert c is not None and c['vmid'] == 30021


def test_reconcile_does_not_start_every_migration_at_once(db):
    # Switching the feature on for a cluster where a lot of guests had drifted
    # must not kick off one migration per guest in a single cycle — the balancer
    # caps itself the same way, and on a stretched cluster these cross sites.
    guests = [_guest(vmid=30000 + i) for i in range(6)]
    mgr = _manager(guests, pins_auto=True)
    r = mgr.reconcile_proxlb_pins()
    assert len(mgr.migrated) == 1  # 3 nodes online -> same cap the balancer uses
    assert len(r['deferred']) == 5


def test_a_refused_migration_still_counts_against_the_cap(db):
    # Every attempt blocks for up to wait_timeout. Counting successes only would
    # let one cycle keep trying guest after guest for hours.
    guests = [_guest(vmid=30000 + i) for i in range(6)]
    mgr = _manager(guests, pins_auto=True)
    mgr.migrate_vm = lambda vm, target, dry_run=False, wait_timeout=None: False
    r = mgr.reconcile_proxlb_pins()
    assert len(r['failed']) == 1
    assert len(r['deferred']) == 5


def test_a_skipped_guest_does_not_use_up_the_cap(db):
    # A local-storage guest was never going to move, so it must not eat the one
    # slot this cycle has, and it is not "deferred" either.
    # The local guest comes second, after the cycle's one slot is already spent:
    # the old gate ran before the storage check and filed it as deferred.
    guests = [_guest(vmid=30000), _guest(vmid=30001)]
    mgr = _manager(guests, pins_auto=True)
    mgr.check_vm_storage_type = lambda node, vmid, vtype: 'local' if vmid == 30001 else 'shared'
    r = mgr.reconcile_proxlb_pins()
    assert mgr.migrated == [(30000, A1)]
    assert r['deferred'] == []


def test_the_deferred_guests_come_back_next_cycle(db):
    guests = [_guest(vmid=30000 + i) for i in range(6)]
    mgr = _manager(guests, pins_auto=True)
    mgr.reconcile_proxlb_pins()
    first = len(mgr.migrated)
    mgr._proxlb_derived_cache = None
    mgr._vm_migration_cooldown = {}
    mgr.reconcile_proxlb_pins()
    assert len(mgr.migrated) > first


# --------------------------------------------------------------------------
# draining a node — a pin ranks the targets, it does not veto the drain
# --------------------------------------------------------------------------

def _drain(mgr, node):
    task = MaintenanceTask(node)
    mgr._evacuate_node(node, task)
    return task


def test_a_drain_sends_the_guest_to_its_other_pinned_node(db):
    # Two pins, one of them being drained: the guest belongs on the other one,
    # even though I1 is the cheapest node in the cluster by a mile.
    guests = [_guest(node=A1, tags=f'{PIN_A1};plb_pin_pve-dmz-node02-th-a')]
    mgr = _manager(guests, maintenance=[A1], scores={A2: 80.0, I1: 1.0})
    task = _drain(mgr, A1)
    assert mgr.migrated == [(30021, A2)]
    assert task.failed_vms == [] and task.off_pin_vms == []


def test_a_drain_falls_back_off_pin_when_no_pinned_node_can_take_it(db):
    # The single pinned node IS the node being drained. Leaving the guest on a
    # node that is about to reboot is the worse outcome, so it goes elsewhere.
    mgr = _manager([_guest(node=A1)], maintenance=[A1], scores={I1: 1.0})
    task = _drain(mgr, A1)
    assert mgr.migrated == [(30021, I1)]
    assert task.migrated_vms == 1 and task.failed_vms == []


def test_an_off_pin_evacuation_is_reported_on_the_task(db):
    # The operator has to be able to see which guests are now in the wrong
    # place without going through the log.
    mgr = _manager([_guest(node=A1)], maintenance=[A1], scores={I1: 1.0})
    task = _drain(mgr, A1)
    assert task.off_pin_vms == [{'vmid': 30021, 'name': 'guest30021',
                                 'target': I1, 'pinned_nodes': [A1]}]
    assert 'plb_pin_' in (task.note or '')
    assert task.to_dict()['off_pin_vms'][0]['vmid'] == 30021


def test_a_failed_off_pin_migration_is_not_reported_as_moved(db):
    # off_pin_vms is a record of where guests ended up, not of what was planned.
    mgr = _manager([_guest(node=A1)], maintenance=[A1])
    mgr.migrate_vm = lambda vm, target, dry_run=False, wait_timeout=None: False
    task = _drain(mgr, A1)
    assert task.off_pin_vms == [] and len(task.failed_vms) == 1


def test_strict_pins_keep_the_old_veto_and_fail_the_drain(db):
    # For pins that are hard constraints (licensing, passthrough, local disks)
    # a stranded guest is the correct outcome and the drain must say so.
    mgr = _manager([_guest(node=A1)], maintenance=[A1], pins_strict=True)
    task = _drain(mgr, A1)
    assert mgr.migrated == []
    assert len(task.failed_vms) == 1
    assert 'pinned to' in task.failed_vms[0]['error']


def test_strict_pins_still_use_a_second_pinned_node(db):
    # Strict is about never going off-pin, not about refusing to move at all.
    guests = [_guest(node=A1, tags=f'{PIN_A1};plb_pin_pve-dmz-node02-th-a')]
    mgr = _manager(guests, maintenance=[A1], pins_strict=True)
    _drain(mgr, A1)
    assert mgr.migrated == [(30021, A2)]


def test_an_untagged_guest_drains_exactly_as_before(db):
    mgr = _manager([_guest(node=A1, tags='production')], maintenance=[A1],
                   scores={A2: 80.0, I1: 1.0})
    task = _drain(mgr, A1)
    assert mgr.migrated == [(30021, I1)] and task.off_pin_vms == []


def test_the_balancer_target_pick_is_still_strict_by_default(db):
    # get_best_target_node has to keep vetoing for every caller that did not ask
    # for the drain behaviour — the balancer would otherwise quietly break pins.
    mgr = _manager([_guest(node=A1)], maintenance=[A1])
    assert mgr.get_best_target_node(exclude_nodes=[A1], vmid=30021) is None


def test_a_drained_guest_goes_home_when_the_node_comes_back(db):
    # The two halves have to meet: the drain puts the guest off-pin, and once
    # the node is out of maintenance reconciliation is what brings it back.
    guests = [_guest(node=A1)]
    mgr = _manager(guests, maintenance=[A1], pins_auto=True, scores={I1: 1.0})
    _drain(mgr, A1)
    assert guests[0]['node'] == I1
    # still off-pin, but not drift — there is nowhere to return it to yet
    assert mgr.get_pin_violations()[0]['reason'] == 'unavailable'
    assert mgr.reconcile_proxlb_pins()['migrated'] == []

    back = _manager(guests, pins_auto=True)  # A1 out of maintenance
    back.reconcile_proxlb_pins()
    assert back.migrated == [(30021, A1)]


# --------------------------------------------------------------------------
# the pre-flight has to simulate the placement the drain actually performs
# --------------------------------------------------------------------------

def test_the_capacity_preview_places_a_pinned_guest_on_its_pin(db):
    # Without this the preview projects the guest's memory onto the cheapest
    # node in the cluster, which is not where the evacuator will put it.
    guests = [_guest(node=A1, tags='plb_pin_pve-dmz-node02-th-a', mem=100 * 1024 ** 3)]
    mgr = _manager(guests, maintenance=[A1], scores={I1: 1.0})
    preview = mgr.maintenance_capacity_preview(A1)
    projected = {n['node']: n['projected_pct'] for n in preview['nodes']}
    assert projected[A2] > projected[I1]


def test_the_capacity_preview_skips_a_guest_a_strict_pin_will_strand(db):
    # Strict + nowhere to go = the evacuator leaves it, so it adds no load.
    mgr = _manager([_guest(node=A1, mem=100 * 1024 ** 3)], maintenance=[A1], pins_strict=True)
    preview = mgr.maintenance_capacity_preview(A1)
    assert all(n['projected_pct'] == n['current_pct'] for n in preview['nodes'])


# --------------------------------------------------------------------------
# the routes — reconciling migrates running guests, so it is not a read
# --------------------------------------------------------------------------

VIOLATIONS_ROUTE = '/api/clusters/cluster_1/proxlb-pins/violations'
RECONCILE_ROUTE = '/api/clusters/cluster_1/proxlb-pins/reconcile'


def _api_manager(api, **stubs):
    mgr = api.make_fake_manager('cluster_1', **stubs)
    mgr.config = types.SimpleNamespace(name='lab-cluster', proxlb_tags_enabled=True,
                                       proxlb_pins_auto_migrate=False)
    return api.set_manager('cluster_1', mgr)


def test_violations_route_rejects_anon(api, seed):
    _api_manager(api, get_pin_violations=[])
    assert api.anon().get(VIOLATIONS_ROUTE).status_code == 401


def test_a_viewer_may_read_the_violations(api, seed):
    viewer = seed.user('vicky', role='viewer', tenant_id='default')
    _api_manager(api, get_pin_violations=[], get_unresolved_pins=[])
    resp = api.as_user(viewer).get(VIOLATIONS_ROUTE)
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert resp.get_json()['violations'] == []


def test_the_violations_route_also_reports_unresolvable_pins(db, api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    dangling = [{'vmid': 30021, 'node': 'pve-dmz-node21-th-d'}]
    _api_manager(api, get_pin_violations=[], get_unresolved_pins=dangling)
    resp = api.as_user(admin).get(VIOLATIONS_ROUTE)
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert resp.get_json()['unresolved'] == dangling


def test_a_viewer_may_not_reconcile(api, seed):
    viewer = seed.user('vicky', role='viewer', tenant_id='default')
    mgr = _api_manager(api)
    assert api.as_user(viewer).post(RECONCILE_ROUTE, json={'force': True}).status_code == 403
    mgr.reconcile_proxlb_pins.assert_not_called()


def test_admin_can_force_a_reconcile(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    outcome = {'violations': [], 'migrated': [], 'failed': [], 'auto_migrate': True}
    mgr = _api_manager(api, reconcile_proxlb_pins=outcome)
    resp = api.as_user(admin).post(RECONCILE_ROUTE, json={'force': True})
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert resp.get_json() == outcome
    mgr.reconcile_proxlb_pins.assert_called_once_with(force=True)


def test_reconcile_is_denied_when_the_cluster_is_only_reachable_via_an_acl(api, seed):
    # Same class of hole as Aikido 469089250 on /balance-now: this moves guests
    # across the whole cluster, so a single VM-ACL grant must not unlock it.
    seed.tenant('tenant_b', clusters=['cluster_other'])
    bob = seed.user('bob', role='user', tenant_id='tenant_b')
    seed.vm_acl('cluster_1', 100, users=['bob'])
    mgr = _api_manager(api)
    r = api.as_user(bob).post(RECONCILE_ROUTE, json={'force': True})
    assert r.status_code == 403, r.get_data(as_text=True)
    mgr.reconcile_proxlb_pins.assert_not_called()


def _seed_pool_membership(cluster_id, mapping):
    data = {f"{vmid}:{vtype}": pool for vmid, (vtype, pool) in mapping.items()}
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache[cluster_id] = {
            'data': data, 'timestamp': time.time(), 'refreshing': False,
        }


def test_reconcile_is_denied_for_a_pool_scoped_caller(db, api, seed):
    # get_user_clusters() counts a pool grant as access, so the open-coded form
    # of this gate let a pool-scoped operator reconcile the entire cluster even
    # though their grant is one pool. require_unconfined is the correct question.
    seed.tenant('acme', clusters=['cluster_1'])
    mallory = seed.user('mallory', role='user', tenant_id='acme')
    seed.pool('cluster_1', 'pool_1', 'mallory', ['pool.view', 'vm.view'])
    mgr = _api_manager(api)
    r = api.as_user(mallory).post(RECONCILE_ROUTE, json={'force': True})
    assert r.status_code == 403, r.get_data(as_text=True)
    mgr.reconcile_proxlb_pins.assert_not_called()


def test_the_violations_route_confines_a_pool_scoped_caller(db, api, seed):
    # The rows carry vmid, name, node and pinned nodes for every guest on the
    # cluster. A caller whose grant is one pool must not read the rest.
    seed.tenant('acme', clusters=['cluster_1'])
    mallory = seed.user('mallory', role='viewer', tenant_id='acme')
    seed.pool('cluster_1', 'pool_1', 'mallory', ['pool.view', 'vm.view'])
    _seed_pool_membership('cluster_1', {100: ('qemu', 'pool_1')})
    rows = [{'vmid': 100, 'name': 'mine', 'type': 'qemu', 'node': I1,
             'pinned_nodes': [A1], 'reason': 'drift'},
            {'vmid': 200, 'name': 'someone-elses', 'type': 'qemu', 'node': I1,
             'pinned_nodes': [A1], 'reason': 'drift'}]
    _api_manager(api, get_pin_violations=rows,
                 get_unresolved_pins=[{'vmid': 200, 'node': 'pve-dmz-node99-th-x'}])
    resp = api.as_user(mallory).get(VIOLATIONS_ROUTE)
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert [v['vmid'] for v in body['violations']] == [100]
    assert body['unresolved'] == []


def test_reconcile_is_allowed_for_a_tenant_owned_cluster(api, seed):
    # Guards the test above against over-blocking.
    seed.tenant('acme', clusters=['cluster_1'])
    bob = seed.user('bob', role='user', tenant_id='acme')
    outcome = {'violations': [], 'migrated': [], 'failed': [], 'auto_migrate': False}
    _api_manager(api, reconcile_proxlb_pins=outcome)
    r = api.as_user(bob).post(RECONCILE_ROUTE, json={})
    assert r.status_code == 200, r.get_data(as_text=True)
