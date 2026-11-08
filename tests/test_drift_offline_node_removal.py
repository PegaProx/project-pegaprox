"""An offline node's objects must not be reported as `removed` while it is down.

A PVE node that is powered off / rebooting does not answer its per-node reads
(`nodes/<n>/network`, `nodes/<n>/<t>/<vmid>/config`), so those scopes never
make it into the fetched state and the deletion-detection loop in
_scan_cluster reads their absence as "object removed" - one wave per scan
for objects that still exist (#968).

Fix (drift.py): when a missing scope's owning node is not online right now,
record it with severity info and a diff of op `unknown` carrying a
`node-offline` annotation instead of a removal. The row keeps its real kind.
A guest's owning node comes from the live guest list, which still lists an
offline node's guests. The baseline keeps the object, so if it is really
gone the first scan after the node returns raises the normal removal event -
the guard only delays a true-removal finding, it never erases one.

These tests stub the persistence helpers; the runs against a fake PVE and a
real database, including ack-promote through the route, are in
test_drift_offline_node_runtime.py.
"""
import json

import pytest

from pegaprox.api import drift as drift_mod
import pegaprox.globals as ppglobals

CL = 'c_drift'


def _nodes_status(**kwargs):
    """get_node_status() shaped like PegaProxManager's: node -> {status: ...}."""
    return kwargs


def _mk_mgr(monkeypatch, node_status, guests=()):
    mgr = type('Mgr', (), {})()
    mgr.is_connected = True
    if node_status is None:
        def _boom():
            raise RuntimeError('liveness read unavailable')
        mgr.get_node_status = _boom
    else:
        mgr.get_node_status = lambda: node_status
    # cluster/resources: where each guest lives (a guest config has no node key)
    mgr.get_vm_resources = lambda max_age=0.0: [dict(g) for g in guests]
    ppglobals.cluster_managers[CL] = mgr
    monkeypatch.setattr(drift_mod, '_record_event', lambda *a, **k: f'evt-{id(a)}')
    monkeypatch.setattr(drift_mod, '_set_baseline', lambda *a, **k: None)
    monkeypatch.setattr(drift_mod, '_open_unknown_events', lambda cid: {})
    monkeypatch.setattr(drift_mod, '_supersede_events', lambda ids: None)
    # keep the alert fan-out offline: several tests record events, which fires
    # the notification loop - it must not touch the real webhook/DB layer
    monkeypatch.setattr('pegaprox.utils.webhooks.send_to_channels',
                        lambda payload, **kw: None)
    return mgr


def _guest(t, vmid, node):
    return {'type': t, 'vmid': vmid, 'node': node}


def _teardown():
    ppglobals.cluster_managers.pop(CL, None)


@pytest.fixture(autouse=True)
def _cleanup():
    yield
    _teardown()


# A scope with no baseline: proves the API answered (an empty read is skipped as
# a whole) and raises no event of its own.
_ALIVE = ('network', 'pve-cl-09/vmbr0', {'iface': 'vmbr0'})


def _scan(monkeypatch, mgr, baselines, state):
    state = list(state) + [_ALIVE]
    monkeypatch.setattr(drift_mod, '_fetch_state', lambda m, cid: state)
    monkeypatch.setattr(drift_mod, '_load_baselines', lambda cid: baselines)
    return drift_mod._scan_cluster(CL)


def _baseline(snapshot):
    return {'snapshot': snapshot, 'created_at': '2026-09-29T00:00:00',
            'created_by': 'test', 'id': 'b1'}


# ── repro: offline node's scopes must not fire as removed ──

def test_offline_node_removals_become_unknown_with_annotation(monkeypatch):
    """pve-cl-01 down, its NICs + LXCs missing from live. Expect info events
    carrying the node-offline annotation - and NO 'removed' op on any of them."""
    mgr = _mk_mgr(monkeypatch, _nodes_status(
        **{'pve-cl-01': {'status': 'offline'}, 'pve-cl-03': {'status': 'online'}}),
        guests=[_guest('lxc', 150, 'pve-cl-01')])
    baselines = {
        ('network', 'pve-cl-01/vmbr0'): _baseline({'iface': 'vmbr0'}),
        ('vm_config', 'lxc/150'): _baseline({'hostname': 'a'}),
        # a cluster-wide kind on the same cluster: NOT node-owned, must stay
        # removal-detected (storage.cfg lives on pmxcfs, not on pve-cl-01)
        ('storage', 'local'): _baseline({'storage': 'local'}),
        ('network', 'pve-cl-03/vmbr0'): _baseline({'iface': 'vmbr0'}),
    }
    res = _scan(monkeypatch, mgr, baselines, state=[
        ('storage', 'different-one', {'storage': 'other'}),   # forces a real removal
        ('network', 'pve-cl-03/vmbr0', {'iface': 'vmbr0'}),   # accounted for: no event
    ])

    events = res['events']
    assert res['events_count'] >= 3, f"unexpected scan result: {res}"

    unknowns = [e for e in events if e.get('node_offline')]
    assert {(e['kind'], e['scope']) for e in unknowns} == {
        ('network', 'pve-cl-01/vmbr0'), ('vm_config', 'lxc/150')}, \
        f"offline-node scopes not all emitted as unknown: {events}"

    for e in unknowns:
        assert e['severity'] == 'info'
        assert e['node_offline'] == 'pve-cl-01'
        assert 'pve-cl-01' in e['summary'] and 'offline' in e['summary']

    # everything else is either the real storage removal or the accounted
    # pve-cl-03 scope (silent) - no network/vm_config 'removed' event exists
    removals = [e for e in events if not e.get('node_offline')]
    assert [e['kind'] for e in removals] == ['storage']
    removed_storage = removals[0]
    assert removed_storage['severity'] == 'warning'
    assert res['removed'] == ['local']  # baseline 'local' vanished from live: real removal

    # the scan result names the suppression count for operators
    assert res['suppressed_offline'] == 2


def test_offline_node_removal_diff_annotation_roundtrips(monkeypatch):
    """The node-offline annotation must survive json.dumps - _record_event
    stores the diff as JSON, the UI reads it back later."""
    mgr = _mk_mgr(monkeypatch, _nodes_status(**{'pve-cl-01': {'status': 'offline'}}))
    sent = []
    monkeypatch.setattr(drift_mod, '_record_event',   # after _mk_mgr: last patch wins
                        lambda cluster_id, kind, scope, diffs, severity, summary:
                        sent.append({'diffs': diffs, 'sev': severity}) or 'e1')
    monkeypatch.setattr(drift_mod, '_fetch_state', lambda m, cid: [_ALIVE])
    monkeypatch.setattr(drift_mod, '_load_baselines',
                        lambda cid: {('network', 'pve-cl-01/eno1'): _baseline({'iface': 'eno1'})})

    res = drift_mod._scan_cluster(CL)

    assert res['events_count'] == 1
    e = res['events'][0]
    assert e['kind'] == 'network' and e['node_offline'] == 'pve-cl-01'
    assert e['severity'] == 'info'
    d = json.loads(json.dumps(sent[0]['diffs']))
    assert d[0]['op'] == 'unknown'
    assert d[0]['node-offline'] == 'pve-cl-01'
    assert sent[0]['sev'] == 'info'


def test_unknown_events_never_go_critical(monkeypatch):
    """Severity floor: an offline-node wave must not page critical-adjacent."""
    mgr = _mk_mgr(monkeypatch, _nodes_status(**{'pve-cl-01': {'status': 'offline'}}))
    baselines = {
        ('network', 'pve-cl-01/eno1'): _baseline({'iface': 'eno1', 'address': 'x'}),
        ('network', 'pve-cl-01/enx0c'): _baseline({'iface': 'enx0c'}),
        ('network', 'pve-cl-01/vmbr0'): _baseline({'iface': 'vmbr0'}),
    }
    res = _scan(monkeypatch, mgr, baselines, state=[])
    assert res['events_count'] == 3
    assert all(e['severity'] == 'info' for e in res['events']), res


# ── regression: node online + real scope deletion still fires normally ──

def test_node_online_real_deletion_still_fires_removed(monkeypatch):
    mgr = _mk_mgr(monkeypatch, _nodes_status(**{'pve-cl-01': {'status': 'online'}}))
    baselines = {('network', 'pve-cl-01/vmbr1'): _baseline({'iface': 'vmbr1'})}
    res = _scan(monkeypatch, mgr, baselines, state=[])

    assert res['events_count'] == 1
    e = res['events'][0]
    assert e['kind'] == 'network'
    assert e['scope'] == 'pve-cl-01/vmbr1'
    assert e['severity'] in ('info', 'warning')
    assert res['removed'] == ['pve-cl-01/vmbr1']
    assert res['suppressed_offline'] == 0


def test_vm_config_removal_on_online_node_still_fires(monkeypatch):
    """The LXC side: vm_config scope unread while its node is online."""
    mgr = _mk_mgr(monkeypatch, _nodes_status(**{'pve-cl-01': {'status': 'online'}}),
                  guests=[_guest('lxc', 402, 'pve-cl-01')])
    baselines = {('vm_config', 'lxc/402'): _baseline({'hostname': 'ct402'})}
    res = _scan(monkeypatch, mgr, baselines, state=[])
    assert res['events_count'] == 1
    assert res['events'][0]['kind'] == 'vm_config'
    assert res['removed'] == ['lxc/402']


def test_cluster_wide_kinds_not_masked_even_when_some_node_is_offline(monkeypatch):
    """storage.cfg / datacenter.cfg live in pmxcfs on every node. An offline
    node must not suppress removal detection for cluster-wide kinds - the
    cluster-wide reads go through the online API host, so an absence is real."""
    mgr = _mk_mgr(monkeypatch, _nodes_status(**{'pve-cl-01': {'status': 'offline'}}))
    baselines = {
        ('storage', 'tank'): _baseline({'storage': 'tank'}),
        ('cluster_options', 'global'): _baseline({'keyboard': 'en-us'}),
    }
    res = _scan(monkeypatch, mgr, baselines, state=[])
    assert res['events_count'] == 2
    assert {e['kind'] for e in res['events']} == {'storage', 'cluster_options'}
    assert res['removed'] == ['tank', 'global']
    assert res['suppressed_offline'] == 0


def test_no_node_owner_means_no_masking(monkeypatch):
    """A guest the guest list no longer has (deleted, so no node owns it) must
    fall through to normal removal detection, even with a node offline."""
    mgr = _mk_mgr(monkeypatch, _nodes_status(**{'pve-cl-01': {'status': 'offline'}}),
                  guests=[_guest('lxc', 150, 'pve-cl-01')])
    baselines = {('vm_config', 'lxc/943'): _baseline({'hostname': 'deleted-guest'})}
    res = _scan(monkeypatch, mgr, baselines, state=[])
    assert res['events_count'] == 1
    assert res['events'][0]['kind'] == 'vm_config'
    assert res['removed'] == ['lxc/943']


# ── recovery: object masked while node down, gone for real afterwards ──

def test_recovery_node_returns_next_scan_emits_normal_removal(monkeypatch):
    """The safety argument end-to-end: an object genuinely destroyed while its
    node was down. Scan 1 (node offline) must show presence unknown and NOT
    delete/rebaseline anything; scan 2 (node back) must emit the normal
    removal event."""
    offline_nodes = _nodes_status(**{'pve-cl-01': {'status': 'offline'}})
    online_nodes = _nodes_status(**{'pve-cl-01': {'status': 'online'}})
    baselines = {('network', 'pve-cl-01/vmbr0'): _baseline({'iface': 'vmbr0'})}

    mgr = _mk_mgr(monkeypatch, offline_nodes)
    res1 = _scan(monkeypatch, mgr, baselines, state=[])
    assert res1['events'][0]['node_offline'] == 'pve-cl-01'
    assert res1['removed'] == []

    # node is back - but the NIC was really removed while it was down,
    # so the liveness read is needed on this scan
    called = []
    def _counting():
        called.append(1)
        return online_nodes
    mgr.get_node_status = _counting
    monkeypatch.setattr(drift_mod, '_fetch_state',
                        lambda m, cid: [('network', 'pve-cl-03/vmbr0', {'iface': 'vmbr0'})])
    monkeypatch.setattr(drift_mod, '_load_baselines',
                        lambda cid: {('network', 'pve-cl-01/vmbr0'): _baseline({'iface': 'vmbr0'}),
                                     ('network', 'pve-cl-03/vmbr0'): _baseline({'iface': 'vmbr0'})})
    res2 = drift_mod._scan_cluster(CL)

    assert res2['events_count'] == 1
    e = res2['events'][0]
    assert e['kind'] == 'network' and e['scope'] == 'pve-cl-01/vmbr0'
    assert res2['removed'] == ['pve-cl-01/vmbr0']
    assert res2['suppressed_offline'] == 0
    assert called, "liveness read missing on the recovery scan"


# ── fail-open: a liveness hiccup must not mask anything ──

def test_liveness_read_failure_fails_open(monkeypatch):
    mgr = _mk_mgr(monkeypatch, None)  # get_node_status raises
    baselines = {('network', 'pve-cl-01/vmbr0'): _baseline({'iface': 'vmbr0'})}
    res = _scan(monkeypatch, mgr, baselines, state=[])
    assert res['events_count'] == 1
    assert res['events'][0]['kind'] == 'network'
    assert res['removed'] == ['pve-cl-01/vmbr0']


def test_liveness_not_consulted_when_nothing_is_missing(monkeypatch):
    """The ordinary case (all scopes present) must not touch get_node_status
    or the guest list at all - zero new cost on the happy path. Counted, not
    raised: _offline_nodes swallows exceptions, so a raising stub would pass
    whether it was called or not."""
    mgr = _mk_mgr(monkeypatch, None)
    called = []
    mgr.get_node_status = lambda: called.append('status') or {}
    mgr.get_vm_resources = lambda max_age=0.0: called.append('guests') or []
    res = _scan(monkeypatch, mgr,
                {('network', 'pve-cl-01/vmbr0'): _baseline({'iface': 'vmbr0'}),
                 ('vm_config', 'qemu/101'): _baseline({'cores': 2})},
                state=[('network', 'pve-cl-01/vmbr0', {'iface': 'vmbr0'}),
                       ('vm_config', 'qemu/101', {'cores': 2})])
    assert res['events_count'] == 0
    assert called == []


# ── the diff loop itself only sees op 'unknown' for masked scopes ──

def test_masked_diff_is_recorded_not_removed(monkeypatch):
    """Direct check that the recorded diff for a masked scope carries op
    'unknown' + the annotation, while before/after preserve the old shape."""
    mgr = _mk_mgr(monkeypatch, _nodes_status(**{'pve-cl-01': {'status': 'offline'}}))
    sent = []
    monkeypatch.setattr(drift_mod, '_record_event',   # after _mk_mgr: last patch wins
                        lambda cluster_id, kind, scope, diffs, severity, summary:
                        sent.append(diffs) or 'e1')
    snap = {'iface': 'vmbr0', 'address': '10.0.0.1'}
    monkeypatch.setattr(drift_mod, '_fetch_state', lambda m, cid: [_ALIVE])
    monkeypatch.setattr(drift_mod, '_load_baselines',
                        lambda cid: {('network', 'pve-cl-01/vmbr0'): _baseline(snap)})

    drift_mod._scan_cluster(CL)

    d = sent[0][0]
    assert d['op'] == 'unknown'
    assert d['node-offline'] == 'pve-cl-01'
    assert d['before'] == snap and d['after'] is None


# Ack-promote of a presence-unknown row is driven through the route in
# test_drift_offline_node_runtime.py: the row keeps its real kind, so a
# guard on kind == 'unknown' never fired, and a test of the source shape
# could not see that.


# ── the ordinary no-drift path still looks the same ──

def test_all_online_scan_with_no_drift_still_emits_nothing(monkeypatch):
    """Deploy gate support: an all-online cluster with matching baselines must
    return events_count 0 and report no suppressions."""
    mgr = _mk_mgr(monkeypatch, _nodes_status(**{'pve-cl-01': {'status': 'online'}}))
    res = _scan(monkeypatch, mgr,
                {('network', 'pve-cl-01/vmbr0'): _baseline({'iface': 'vmbr0'}),
                 ('vm_config', 'qemu/101'): _baseline({'cores': 2})},
                state=[('network', 'pve-cl-01/vmbr0', {'iface': 'vmbr0'}),
                       ('vm_config', 'qemu/101', {'cores': 2})])
    assert res['events_count'] == 0
    assert res['removed'] == []
    assert res['suppressed_offline'] == 0


# ── helper contract ──

def test_owning_node_helper():
    assert drift_mod._owning_node('network', 'pve-cl-01/vmbr0') == 'pve-cl-01'
    assert drift_mod._owning_node('network', 'pve-cl-01/enx0c3796c1d74a') == 'pve-cl-01'
    assert drift_mod._owning_node('network', '/') is None
    on_01 = {'lxc/150': 'pve-cl-01', 'qemu/101': 'pve-cl-02'}
    assert drift_mod._owning_node('vm_config', 'lxc/150', on_01) == 'pve-cl-01'
    assert drift_mod._owning_node('vm_config', 'qemu/101', on_01) == 'pve-cl-02'
    assert drift_mod._owning_node('vm_config', 'lxc/150', None) is None
    assert drift_mod._owning_node('vm_config', 'lxc/943', on_01) is None
    assert drift_mod._owning_node('storage', 'local', on_01) is None
    assert drift_mod._owning_node('cluster_options', 'global', None) is None


def test_guest_nodes_come_from_the_guest_list_only():
    mgr = type('Mgr', (), {})()
    mgr.get_vm_resources = lambda max_age=0.0: [
        _guest('qemu', 101, 'pve-cl-01'), _guest('lxc', 150, 'pve-cl-02'),
        {'type': 'storage', 'storage': 'local', 'node': 'pve-cl-01'},
        {'type': 'qemu', 'vmid': 102}]
    assert drift_mod._guest_nodes(mgr) == {'qemu/101': 'pve-cl-01', 'lxc/150': 'pve-cl-02'}

    def _boom(max_age=0.0):
        raise RuntimeError('cluster/resources timed out')
    mgr.get_vm_resources = _boom
    assert drift_mod._guest_nodes(mgr) == {}
