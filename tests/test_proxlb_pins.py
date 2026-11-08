# ProxLB pin enforcement.
#
# plb_pin_<node> was only ever a veto: it filtered guests out of migrations the
# balancer had already proposed, and nothing in a cycle proposes a move *towards*
# a pin. A guest that was on the wrong node - moved by hand in the PVE UI, failed
# over by HA, evacuated while the pinned node was down, or simply tagged after
# the fact - therefore stayed there forever, and the tag looked like it did
# nothing. These tests pin the reconciliation that closes that, and the guards
# around it: the operator opts in, dry_run and auto_migrate still win, and a
# guest that is also tagged plb_ignore is left alone.
#
# The node names are deliberately mixed-case: PVE lower-cases tag text, so the
# tag can never spell -site-A and the pin has to resolve case-insensitively.

import logging
import time
import types

from pegaprox.utils import rbac

from pegaprox.core.manager import PegaProxManager
from pegaprox.models.tasks import MaintenanceTask, PegaProxConfig

A1, A2 = 'pve-node-A01', 'pve-node-A02'
I1 = 'pve-node-I11'
ALL_NODES = [A1, A2, I1]

PIN_A1 = 'plb_pin_pve-node-a01'


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
    # The tag can only ever be plb_pin_..-site-a; the node really is ..-site-A.
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
    assert _manager([_guest(tags='plb_pin_pve-node-x01')]).get_pin_violations() == []


def test_a_pin_naming_no_node_is_reported_as_unresolved(db):
    # The failure mode this exists for: the tag is there, the guest never moves,
    # and nothing anywhere says the node name does not exist.
    mgr = _manager([_guest(tags='plb_pin_pve-node-d21')])
    assert mgr.get_unresolved_pins() == [{'vmid': 30021, 'node': 'pve-node-d21'}]
    assert mgr.get_pin_violations() == []


def test_an_unresolved_pin_is_logged_once_not_every_cycle(db, caplog):
    mgr = _manager([_guest(tags='plb_pin_pve-node-d21')])
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
    # Nothing to migrate back to - the guest is off its pin because that is the
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
    # A2 is by far the cheapest node, and it is in the same site - the pin still
    # has to win, or "pinned" means nothing.
    mgr = _manager([_guest()], pins_auto=True, scores={A1: 90.0, A2: 1.0})
    mgr.reconcile_proxlb_pins()
    assert mgr.migrated == [(30021, A1)]


def test_a_multi_node_pin_picks_the_least_loaded_of_them(db):
    guests = [_guest(tags=f'{PIN_A1};plb_pin_pve-node-a02')]
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
    # must not kick off one migration per guest in a single cycle - the balancer
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
# draining a node - a pin ranks the targets, it does not veto the drain
# --------------------------------------------------------------------------

def _drain(mgr, node):
    task = MaintenanceTask(node)
    mgr._evacuate_node(node, task)
    return task


def test_a_drain_sends_the_guest_to_its_other_pinned_node(db):
    # Two pins, one of them being drained: the guest belongs on the other one,
    # even though I1 is the cheapest node in the cluster by a mile.
    guests = [_guest(node=A1, tags=f'{PIN_A1};plb_pin_pve-node-a02')]
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
    guests = [_guest(node=A1, tags=f'{PIN_A1};plb_pin_pve-node-a02')]
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
    # for the drain behaviour - the balancer would otherwise quietly break pins.
    mgr = _manager([_guest(node=A1)], maintenance=[A1])
    assert mgr.get_best_target_node(exclude_nodes=[A1], vmid=30021) is None


def test_a_drained_guest_goes_home_when_the_node_comes_back(db):
    # The two halves have to meet: the drain puts the guest off-pin, and once
    # the node is out of maintenance reconciliation is what brings it back.
    guests = [_guest(node=A1)]
    mgr = _manager(guests, maintenance=[A1], pins_auto=True, scores={I1: 1.0})
    _drain(mgr, A1)
    assert guests[0]['node'] == I1
    # still off-pin, but not drift - there is nowhere to return it to yet
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
    guests = [_guest(node=A1, tags='plb_pin_pve-node-a02', mem=100 * 1024 ** 3)]
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
# the routes - reconciling migrates running guests, so it is not a read
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
    dangling = [{'vmid': 30021, 'node': 'pve-node-d21'}]
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


def test_a_string_force_is_rejected_not_coerced(api, seed):
    # bool("false") is True, so the old (request.json or {}).get('force') form
    # turned {"force": "false"} into a forced reconcile that skipped the
    # auto_migrate switch. force must be a real boolean or the route says 400.
    admin = seed.user('root', role='admin', tenant_id='default')
    mgr = _api_manager(api)
    resp = api.as_user(admin).post(RECONCILE_ROUTE, json={'force': 'false'})
    assert resp.status_code == 400, resp.get_data(as_text=True)
    mgr.reconcile_proxlb_pins.assert_not_called()


def test_a_non_object_body_is_rejected(api, seed):
    # A JSON array is not an object, so it must not slip through as an empty body
    admin = seed.user('root', role='admin', tenant_id='default')
    mgr = _api_manager(api)
    resp = api.as_user(admin).post(RECONCILE_ROUTE, json=['force'])
    assert resp.status_code == 400, resp.get_data(as_text=True)
    mgr.reconcile_proxlb_pins.assert_not_called()


def test_a_missing_body_reconciles_without_forcing(api, seed):
    # No JSON body must not 415 and must default to the honour-the-switch path
    admin = seed.user('root', role='admin', tenant_id='default')
    outcome = {'violations': [], 'migrated': [], 'failed': [], 'auto_migrate': True}
    mgr = _api_manager(api, reconcile_proxlb_pins=outcome)
    resp = api.as_user(admin).post(RECONCILE_ROUTE)
    assert resp.status_code == 200, resp.get_data(as_text=True)
    mgr.reconcile_proxlb_pins.assert_called_once_with(force=False)


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
                 get_unresolved_pins=[{'vmid': 200, 'node': 'pve-node-x99'}])
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


# --------------------------------------------------------------------------
# follow-up on #811: the pins next to #647, #625 and the rolling update
# --------------------------------------------------------------------------

def test_a_pin_on_a_node_the_ha_rule_forbids_does_not_block_the_drain(db):
    # #647: the HA rule (or the storage) lets this guest go to I1 only. Its other
    # pinned node A2 is up but forbidden, so the drain places it off-pin on I1
    # instead of narrowing to A2 first and then finding nothing at all.
    guests = [_guest(node=A1, tags=f'{PIN_A1};plb_pin_pve-node-a02')]
    mgr = _manager(guests, maintenance=[A1])
    mgr._evacuation_placement = lambda: ({30021: {I1}}, {})
    task = _drain(mgr, A1)
    assert mgr.migrated == [(30021, I1)]
    assert task.failed_vms == []
    assert [o['target'] for o in task.off_pin_vms] == [I1]


def test_a_strict_pin_on_a_node_the_ha_rule_forbids_still_stops(db):
    # the counterpart: strict never goes off-pin, and the failure names the pin
    guests = [_guest(node=A1, tags=f'{PIN_A1};plb_pin_pve-node-a02')]
    mgr = _manager(guests, maintenance=[A1], pins_strict=True)
    mgr._evacuation_placement = lambda: ({30021: {I1}}, {})
    task = _drain(mgr, A1)
    assert mgr.migrated == []
    assert 'pinned to' in task.failed_vms[0]['error']


def test_the_allowed_nodes_still_bound_a_pinned_guest(db):
    # allowed_nodes goes first now; the pin still ranks inside what it leaves
    mgr = _manager([_guest(node=A1, tags=f'{PIN_A1};plb_pin_pve-node-a02')],
                   maintenance=[A1], scores={I1: 1.0})
    assert mgr.get_best_target_node(exclude_nodes=[A1], vmid=30021,
                                    allowed_nodes={A2, I1}, pin_mode='prefer') == A2
    assert mgr.get_best_target_node(exclude_nodes=[A1], vmid=30021,
                                    allowed_nodes={A1}, pin_mode='prefer') is None


def test_a_reconcile_without_a_confirmed_lease_moves_nothing(db, monkeypatch):
    # #625: every other automatic migration of the balance cycle asks for the
    # lease first; a leader that lost it must not send the pin moves either
    import pegaprox.core.manager as mgrmod
    monkeypatch.setattr(mgrmod.ha, 'confirm_step', lambda what, *a, **k: False)
    mgr = _manager([_guest()], pins_auto=True)
    r = mgr.reconcile_proxlb_pins()
    assert mgr.migrated == [] and r['migrated'] == []


def test_the_reconcile_reads_no_guest_list_while_the_tags_are_off(db):
    # it runs in every balance cycle of every cluster; with the feature off the
    # /cluster/resources walk it used to start is pure cost
    mgr = _manager([_guest()], tags_enabled=False, pins_auto=True)
    calls = []
    mgr.get_vm_resources = lambda *a, **k: calls.append(1) or [_guest()]
    r = mgr.reconcile_proxlb_pins()
    assert calls == [] and r['violations'] == [] and mgr.migrated == []


def test_the_violation_scan_reads_the_guest_list_once(db):
    mgr = _manager([_guest()])
    calls = []
    mgr.get_vm_resources = lambda *a, **k: calls.append(1) or [_guest()]
    assert len(mgr.get_pin_violations()) == 1
    assert len(calls) == 1


def test_the_rolling_update_log_names_a_guest_placed_off_its_pin(db):
    # the drain did not stop, so the rolling update log is the place that says it
    from pegaprox.api.helpers import rolling_moved_templates
    task = MaintenanceTask(A1)
    task.off_pin_vms = [{'vmid': 30021, 'name': 'guest30021', 'target': I1, 'pinned_nodes': [A1]}]
    mgr = types.SimpleNamespace(_rolling_update={'logs': []})
    rolling_moved_templates(mgr, task)
    line = ' '.join(mgr._rolling_update['logs'])
    assert 'guest30021 (30021)' in line and I1 in line and A1 in line


def test_the_pin_switches_survive_a_save_and_a_restore_that_omits_them(db):
    from pegaprox.core.db import get_db
    base = {'name': 'c', 'host': 'h', 'user': 'u', 'pass': 'p', 'proxlb_tags_enabled': True,
            'proxlb_pins_auto_migrate': True, 'proxlb_pins_strict': True}
    get_db().save_cluster('cluster_1', base)
    cfg = PegaProxConfig(get_db().get_cluster('cluster_1'))
    assert (cfg.proxlb_pins_auto_migrate, cfg.proxlb_pins_strict) == (True, True)
    # an older backup without the keys keeps what is stored, an explicit False wins
    get_db().save_cluster('cluster_1', {k: v for k, v in base.items() if not k.startswith('proxlb_')})
    row = get_db().get_cluster('cluster_1')
    assert (row['proxlb_tags_enabled'], row['proxlb_pins_auto_migrate'], row['proxlb_pins_strict']) == \
        (True, True, True)
    get_db().save_cluster('cluster_1', dict(base, proxlb_pins_strict=False))
    assert get_db().get_cluster('cluster_1')['proxlb_pins_strict'] is False


def test_a_synced_pin_switch_reaches_the_running_manager(db, monkeypatch):
    # #625: a standby hands the synced row to its managers field by field; a field
    # missing from that list keeps the old value until the process restarts
    from pegaprox.core import ha
    import pegaprox.globals as g
    from pegaprox.core.db import get_db
    get_db().save_cluster('cluster_1', {'name': 'c', 'host': 'h', 'user': 'u', 'pass': 'p',
                                        'proxlb_pins_auto_migrate': True,
                                        'proxlb_pins_strict': True})
    cfg = PegaProxConfig({'name': 'c', 'host': 'h', 'user': 'u'})
    monkeypatch.setitem(g.cluster_managers, 'cluster_1', types.SimpleNamespace(config=cfg))
    ha._refresh_managers()
    assert (cfg.proxlb_pins_auto_migrate, cfg.proxlb_pins_strict) == (True, True)


def test_an_off_pin_guest_is_named_once_not_every_cycle(db, caplog):
    # report-only is the default, and the cycle runs every few minutes on every
    # cluster: the per-guest line comes once, and again after the guest moved
    guests = [_guest()]
    mgr = _manager(guests)

    def said():
        return [r for r in caplog.records if 'but pinned to' in r.getMessage()]
    with caplog.at_level(logging.WARNING, logger='test.proxlb_pins'):
        mgr.reconcile_proxlb_pins()
        mgr.reconcile_proxlb_pins()
        assert len(said()) == 1
        guests[0]['node'] = A2
        mgr.reconcile_proxlb_pins()
        assert len(said()) == 2


def test_the_drain_note_only_promises_the_way_back_where_it_runs(db):
    # report-only is the default: nothing moves the guest back then, and the note
    # must not say otherwise. The names are in off_pin_vms, not in the note.
    task = _drain(_manager([_guest(node=A1)], maintenance=[A1], scores={I1: 1.0}), A1)
    assert 'stay there' in task.note and 'guest30021' not in task.note
    task = _drain(_manager([_guest(node=A1)], maintenance=[A1], scores={I1: 1.0},
                           pins_auto=True), A1)
    assert 'returns them' in task.note


def test_a_confined_caller_does_not_get_the_off_pin_guests(api, seed):
    # the node progress of a maintenance hands a confined caller the progress,
    # not which guests are in it (#625); the off-pin list is such a guest list
    mgr = _manager([_guest(node=A1)], maintenance=[A1], scores={I1: 1.0})
    task = _drain(mgr, A1)
    # MK Nov 2026 - VM 100 on the drained node: a confined caller reads the nodes its guests run on
    api.set_manager('cluster_1', types.SimpleNamespace(
        cluster_type='proxmox', nodes_in_maintenance={A1: task}, nodes_updating={},
        get_vm_resources=lambda max_age=0: [{'vmid': 100, 'node': A1, 'type': 'qemu'}]))
    seed.tenant('acme', clusters=['cluster_1'])
    seed.tenant('globex', clusters=['other'])
    operator = api.as_user(seed.user('operator', role='user', tenant_id='acme',
                                     permissions=['cluster.view']))
    portal = api.as_user(seed.user('portal', role='user', tenant_id='globex',
                                   permissions=['cluster.view', 'vm.view']))
    seed.vm_acl('cluster_1', 100, users=['portal'])
    route = '/api/clusters/cluster_1/node-progress'
    full = operator.get(route).get_json()['nodes'][A1]['maintenance_task']
    assert full['off_pin_vms'][0]['vmid'] == 30021
    confined = portal.get(route).get_json()['nodes'][A1]['maintenance_task']
    assert 'off_pin_vms' not in confined
    assert 'guest30021' not in (confined.get('note') or '')


def test_the_pin_routes_answer_for_an_xcpng_pool(api, seed):
    # an XCP-ng manager has no plb_ tags and no get_pin_violations: an answer, no 500
    admin = api.as_user(seed.user('root', role='admin', tenant_id='default'))
    api.set_manager('cluster_1', types.SimpleNamespace(cluster_type='xcpng',
                                                       config=types.SimpleNamespace(name='pool')))
    r = admin.get(VIOLATIONS_ROUTE)
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['violations'] == [] and r.get_json()['enabled'] is False
    assert r.get_json()['can_reconcile'] is False
    r = admin.post(RECONCILE_ROUTE, json={'force': True})
    assert r.status_code == 400 and r.get_json()['code'] == 'PVE_ONLY'


# --------------------------------------------------------------------------
# can_reconcile: the "move back now" button of the cluster settings asks the
# reconcile route's own question. vm.migrate alone is not the answer, a pool
# or VM-ACL scoped caller holds it and is still turned away there.
# --------------------------------------------------------------------------

def _told(api, user, cluster_id='cluster_1'):
    _api_manager(api, get_pin_violations=[], get_unresolved_pins=[])
    resp = api.as_user(user).get(f'/api/clusters/{cluster_id}/proxlb-pins/violations')
    assert resp.status_code == 200, resp.get_data(as_text=True)
    return resp.get_json()['can_reconcile']


def _reconcile_status(api, user):
    outcome = {'violations': [], 'migrated': [], 'failed': [], 'deferred': [], 'auto_migrate': True}
    _api_manager(api, reconcile_proxlb_pins=outcome)
    return api.as_user(user).post(RECONCILE_ROUTE, json={'force': True}).status_code


def test_an_admin_is_told_he_may_move_the_guests_back(api, seed):
    root = seed.user('root', role='admin', tenant_id='default')
    assert _told(api, root) is True
    assert _reconcile_status(api, root) == 200


def test_a_viewer_is_told_he_may_not(api, seed):
    vicky = seed.user('vicky', role='viewer', tenant_id='default')
    assert _told(api, vicky) is False
    assert _reconcile_status(api, vicky) == 403


def test_an_operator_of_the_owning_tenant_is_told_he_may(api, seed):
    seed.tenant('acme', clusters=['cluster_1'])
    bob = seed.user('bob', role='user', tenant_id='acme')
    assert _told(api, bob) is True
    assert _reconcile_status(api, bob) == 200


def test_a_pool_scoped_operator_holds_vm_migrate_and_is_still_told_no(db, api, seed):
    seed.tenant('acme', clusters=['cluster_1'])
    mallory = seed.user('mallory', role='user', tenant_id='acme')
    seed.pool('cluster_1', 'pool_1', 'mallory', ['pool.view', 'vm.view', 'vm.migrate'])
    _seed_pool_membership('cluster_1', {100: ('qemu', 'pool_1')})
    assert _told(api, mallory) is False
    # what the route answers, so the flag and the route cannot drift apart
    assert _reconcile_status(api, mallory) == 403


def test_an_acl_scoped_operator_is_told_no(api, seed):
    seed.tenant('tenant_b', clusters=['cluster_other'])
    bob = seed.user('bob', role='user', tenant_id='tenant_b')
    seed.vm_acl('cluster_1', 100, users=['bob'])
    assert _told(api, bob) is False
    assert _reconcile_status(api, bob) == 403
