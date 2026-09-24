"""A vmid is only unique while the guest exists.

Once a guest is gone the number comes back - PVE hands out the lowest free id, and our
XCP-ng mapping allocated MAX(vmid)+1 from a table it deleted the row from, so deleting
the highest-numbered VM handed that exact id to the next one created. A VM-ACL row or a
scheduled action left pointing at it then applies to whatever takes the number, possibly
another tenant's guest.

The client portal's teardown route has cleaned up after itself since #556. The ordinary
delete paths - the ones most deletions actually go through - did not.

Aikido ai_pentest 700487005. MK
"""
import pytest

import pegaprox.utils.rbac as rbac


def _acl_exists(db, cluster_id, vmid):
    cur = db.conn.cursor()
    cur.execute('SELECT 1 FROM vm_acls WHERE cluster_id=? AND vmid=?', (cluster_id, str(vmid)))
    return cur.fetchone() is not None


def _schedules(db, cluster_id, vmid):
    cur = db.conn.cursor()
    cur.execute('SELECT COUNT(*) FROM scheduled_actions WHERE cluster_id=? AND vmid=?',
                (cluster_id, int(vmid)))
    return cur.fetchone()[0]


def _seed_schedule(db, cluster_id, vmid):
    db.conn.execute(
        "INSERT INTO scheduled_actions (cluster_id, vmid, action, schedule_type, "
        "schedule_time, enabled) VALUES (?, ?, 'start', 'daily', '03:00', 1)",
        (cluster_id, int(vmid)))
    db.conn.commit()


# --- the purge itself ---------------------------------------------------------

def test_purging_removes_the_acl(db, seed):
    seed.vm_acl('cluster_1', 100, ['alice'])

    db.purge_vm_grants('cluster_1', 100)

    assert not _acl_exists(db, 'cluster_1', 100)


def test_purging_removes_scheduled_actions(db):
    _seed_schedule(db, 'cluster_1', 100)

    db.purge_vm_grants('cluster_1', 100)

    assert _schedules(db, 'cluster_1', 100) == 0


def test_purging_leaves_other_vms_alone(db, seed):
    seed.vm_acl('cluster_1', 100, ['alice'])
    seed.vm_acl('cluster_1', 200, ['bob'])
    _seed_schedule(db, 'cluster_1', 200)

    db.purge_vm_grants('cluster_1', 100)

    assert _acl_exists(db, 'cluster_1', 200)
    assert _schedules(db, 'cluster_1', 200) == 1


def test_purging_leaves_the_same_vmid_on_another_cluster_alone(db, seed):
    seed.vm_acl('cluster_1', 100, ['alice'])
    seed.vm_acl('cluster_2', 100, ['bob'])

    db.purge_vm_grants('cluster_1', 100)

    assert _acl_exists(db, 'cluster_2', 100)


def test_purging_a_vm_with_no_grants_is_a_no_op(db):
    assert db.purge_vm_grants('cluster_1', 999) == {'vm_acls': 0, 'scheduled_actions': 0}


# --- the xcpng allocator must not hand the number back ------------------------

def test_a_retired_xcpng_vmid_is_not_reissued(db):
    """The allocator reads MAX(vmid) from this table. Deleting the row lowers the
    high-water mark; blanking the uuid keeps the id spent."""
    first = db.xcpng_get_vmid('pool_1', 'uuid-aaa')
    second = db.xcpng_get_vmid('pool_1', 'uuid-bbb')
    assert second == first + 1

    # retire the higher one the way delete_vm now does
    db.xcpng_retire_vmid('pool_1', second)

    third = db.xcpng_get_vmid('pool_1', 'uuid-ccc')

    assert third != second, 'the retired id was handed to a new VM'
    assert third == second + 1


def test_a_retired_vmid_resolves_to_nothing(db):
    vmid = db.xcpng_get_vmid('pool_1', 'uuid-aaa')
    db.xcpng_retire_vmid('pool_1', vmid)

    assert db.xcpng_resolve_vmid('pool_1', vmid) is None


def test_a_live_vmid_still_resolves(db):
    vmid = db.xcpng_get_vmid('pool_1', 'uuid-aaa')

    assert db.xcpng_resolve_vmid('pool_1', vmid) == 'uuid-aaa'


def test_the_same_uuid_keeps_its_vmid(db):
    """The invariant: this mapping is supposed to be stable for a living VM."""
    first = db.xcpng_get_vmid('pool_1', 'uuid-aaa')

    assert db.xcpng_get_vmid('pool_1', 'uuid-aaa') == first
