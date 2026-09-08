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
import types

from pegaprox.core.manager import PegaProxManager
from pegaprox.models.tasks import PegaProxConfig

A1, A2 = 'pve-dmz-node01-th-A', 'pve-dmz-node02-th-A'
I1 = 'pve-dmz-node11-th-I'
ALL_NODES = [A1, A2, I1]

PIN_A1 = 'plb_pin_pve-dmz-node01-th-a'


def _guest(vmid=30021, node=I1, tags=PIN_A1, status='running'):
    return {'vmid': vmid, 'node': node, 'name': f'guest{vmid}', 'status': status,
            'type': 'qemu', 'mem': 1024, 'tags': tags}


def _manager(guests, tags_enabled=True, pins_auto=False, auto_migrate=True,
             dry_run=False, down=(), scores=None, excluded_vms=()):
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
        'auto_migrate': auto_migrate, 'dry_run': dry_run,
        'migration_threshold': 10, 'migration_tolerance': 0,
    })
    scores = scores or {}
    mgr.get_node_status = lambda: {
        n: {'status': 'offline' if n in down else 'online',
            'maintenance_mode': False, 'score': scores.get(n, 50.0)}
        for n in ALL_NODES}
    mgr.get_vm_resources = lambda: list(guests)
    mgr.get_balancing_excluded_vms = lambda: list(excluded_vms)
    mgr.get_balancing_excluded_pools = lambda: []
    mgr.get_proxmox_ha_resources = lambda: []
    mgr._api_get = lambda *a, **k: None
    mgr.check_vm_storage_type = lambda *a, **k: 'shared'
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
    assert r == {'violations': [], 'migrated': [], 'failed': [], 'auto_migrate': True}


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
    _api_manager(api, get_pin_violations=[])
    resp = api.as_user(viewer).get(VIOLATIONS_ROUTE)
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert resp.get_json()['violations'] == []


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


def test_reconcile_is_allowed_for_a_tenant_owned_cluster(api, seed):
    # Guards the test above against over-blocking.
    seed.tenant('acme', clusters=['cluster_1'])
    bob = seed.user('bob', role='user', tenant_id='acme')
    outcome = {'violations': [], 'migrated': [], 'failed': [], 'auto_migrate': False}
    _api_manager(api, reconcile_proxlb_pins=outcome)
    r = api.as_user(bob).post(RECONCILE_ROUTE, json={})
    assert r.status_code == 200, r.get_data(as_text=True)
