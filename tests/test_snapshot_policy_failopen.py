"""A snapshot policy is authorized by walking its targets - so "no targets" meant
"nothing to deny".

Two fail-opens in the same feature:

  * _resolve_targets() swallowed an inventory-fetch failure and returned an empty
    list. Create and update authorize by listing the targets the caller may NOT
    touch, so an empty list authorized everything. The update handler's OFFLINE
    branch already fails closed for a scoped caller; the manager-is-here-but-did-
    not-answer case did not.
  * the scheduled run resolved the policy's creator and, when that account was
    gone, logged "per-VM authz not applied" and then ran over every target. An
    off-boarded account's policy kept snapshotting VMs its creator could not reach.

Aikido ai_pentest 700489481 / 700489402. MK
"""
import pytest

import pegaprox.api.snapshots as snaps


class _MgrThatCannotAnswer:
    def get_vm_resources(self):
        raise RuntimeError('cluster unreachable')


class _MgrWithNothing:
    def get_vm_resources(self):
        return []


class _MgrWithVms:
    def get_vm_resources(self):
        return [{'vmid': 100, 'type': 'qemu', 'node': 'pve1', 'tags': 'nightly'},
                {'vmid': 101, 'type': 'qemu', 'node': 'pve1', 'tags': 'other'}]


POLICY = {'target_type': 'tag', 'target_value': 'nightly', 'cluster_id': 'cluster_1'}


def test_an_unreachable_cluster_raises_instead_of_resolving_to_nothing():
    with pytest.raises(snaps.TargetResolutionFailed):
        snaps._resolve_targets(_MgrThatCannotAnswer(), POLICY)


def test_a_cluster_with_no_matching_vms_still_resolves_to_an_empty_list():
    """Empty must keep meaning "nothing matches" - that is a legitimate answer."""
    assert snaps._resolve_targets(_MgrWithNothing(), POLICY) == []


def test_matching_vms_are_still_resolved():
    assert snaps._resolve_targets(_MgrWithVms(), POLICY) == [('pve1', 100, 'qemu')]


def test_a_direct_vm_target_still_resolves():
    assert snaps._resolve_targets(
        _MgrWithVms(), {'target_type': 'vm', 'target_value': '101',
                        'cluster_id': 'cluster_1'}) == [('pve1', 101, 'qemu')]


def test_the_authorization_walk_cannot_silently_find_nothing_to_deny():
    """The shape the handlers use: `[... for t in _resolve_targets(...) if not allowed]`.
    With the old swallow this produced [] - an empty denial list - and the caller was
    let through. Now the comprehension never gets to run."""
    def _authorize():
        return [t for t in snaps._resolve_targets(_MgrThatCannotAnswer(), POLICY)
                if False]   # "nothing is allowed" - yet the old code returned []

    with pytest.raises(snaps.TargetResolutionFailed):
        _authorize()


# --- the property that matters, through the real handler ----------------------

def _scoped_user(seed):
    """A caller confined to VM 100 by a VM-ACL, with vm.snapshot in their role."""
    seed.tenant('tenant_x', clusters=['cluster_1'])
    u = seed.user('mallory', role='user', tenant_id='tenant_x',
                  permissions=['vm.snapshot', 'vm.view', 'snapshot.policy.manage'])
    seed.vm_acl('cluster_1', 100, ['mallory'])
    return u


def _policy_count(db):
    cur = db.conn.cursor()
    cur.execute('SELECT COUNT(*) FROM snapshot_policies')
    return cur.fetchone()[0]


def test_a_scoped_caller_cannot_create_a_policy_the_cluster_cannot_resolve(api, seed, db):
    """The finding, at the level a user experiences it: with the inventory fetch
    broken, a tag-targeted policy used to be created without a single per-VM check.

    Asserted on the stored rows, not on the status code, so this holds regardless of
    which error the handler chooses to return."""
    u = _scoped_user(seed)
    api.set_manager('cluster_1', _MgrThatCannotAnswer())

    api.as_user(u).post('/api/clusters/cluster_1/snapshot-policies',
                        json={'name': 'sweep-everything', 'target_type': 'tag',
                              'target_value': 'nightly', 'schedule': 'daily',
                              'schedule_at': '03:00'})

    assert _policy_count(db) == 0, "a policy was stored without its targets being checked"


def test_a_reachable_cluster_still_lets_an_in_scope_policy_through(api, seed, db):
    """The invariant: the fix must not block the legitimate case."""
    u = _scoped_user(seed)

    class _OnlyTheirVm:
        def get_vm_resources(self):
            return [{'vmid': 100, 'type': 'qemu', 'node': 'pve1', 'tags': 'nightly'}]
    api.set_manager('cluster_1', _OnlyTheirVm())

    r = api.as_user(u).post('/api/clusters/cluster_1/snapshot-policies',
                            json={'name': 'mine', 'target_type': 'tag',
                                  'target_value': 'nightly', 'schedule': 'daily',
                                  'schedule_at': '03:00'})

    assert r.status_code == 200, r.get_data(as_text=True)
    assert _policy_count(db) == 1


def test_a_scoped_caller_is_still_denied_a_foreign_target(api, seed, db):
    u = _scoped_user(seed)
    api.set_manager('cluster_1', _MgrWithVms())    # 100 is theirs, 101 is not

    r = api.as_user(u).post('/api/clusters/cluster_1/snapshot-policies',
                            json={'name': 'foreign', 'target_type': 'vm',
                                  'target_value': '101', 'schedule': 'daily',
                                  'schedule_at': '03:00'})

    assert r.status_code == 403, r.get_data(as_text=True)
    assert _policy_count(db) == 0


# --- the second fail-open: a policy outliving its creator ---------------------

class _SnapshotSpy:
    """Records every snapshot the policy tries to take."""
    def __init__(self):
        self.snapshotted = []

    def get_vm_resources(self):
        return [{'vmid': 100, 'type': 'qemu', 'node': 'pve1', 'tags': 'nightly'},
                {'vmid': 101, 'type': 'qemu', 'node': 'pve1', 'tags': 'nightly'}]

    def create_snapshot(self, *a, **kw):
        self.snapshotted.append(a)
        return {'success': True}

    def get_snapshots(self, *a, **kw):
        return []


def _seed_policy(db, pid, created_by):
    db.conn.execute(
        "INSERT INTO snapshot_policies (id, cluster_id, name, target_type, target_value, "
        "schedule, enabled, created_by, created_at) "
        "VALUES (?, 'cluster_1', 'nightly', 'tag', 'nightly', 'daily', 1, ?, "
        "'2026-01-01T00:00:00')", (pid, created_by))
    db.conn.commit()


def _run_status(db, pid):
    cur = db.conn.cursor()
    cur.execute('SELECT status, summary FROM snapshot_runs WHERE policy_id=? '
                'ORDER BY id DESC LIMIT 1', (pid,))
    r = cur.fetchone()
    return (r[0], r[1]) if r else (None, None)


def test_a_policy_whose_creator_was_deleted_does_not_run_unscoped(api, db, monkeypatch):
    """It used to log "per-VM authz not applied" and then snapshot every resolved
    target - an off-boarded account's policy kept reaching VMs its creator never
    could. require_auth() fails closed on a deleted account; so must this."""
    spy = _SnapshotSpy()
    api.set_manager('cluster_1', spy)
    _seed_policy(db, 'polGhost', created_by='someone_who_left')

    snaps._execute_policy('polGhost', force=True)

    assert spy.snapshotted == [], "the policy snapshotted VMs with no authorization at all"
    status, summary = _run_status(db, 'polGhost')
    assert status == 'failed'
    assert 'creator' in (summary or '')


def test_a_policy_whose_creator_is_present_still_runs(api, db, seed, monkeypatch):
    """The invariant: a live creator with access keeps their policy working."""
    seed.tenant('default', ['cluster_1'])
    seed.user('owner', role='admin')
    spy = _SnapshotSpy()
    api.set_manager('cluster_1', spy)
    _seed_policy(db, 'polLive', created_by='owner')

    snaps._execute_policy('polLive', force=True)

    assert len(spy.snapshotted) == 2, _run_status(db, 'polLive')
