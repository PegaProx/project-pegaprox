"""A DR drill skips a disabled replication job, also after a guest that failed.

The freshness check of a drill read `if worst_status != 'fail': worst_status = 'warn';
continue` as one if. Once an earlier guest of the plan had failed, a disabled job went
on to the age check: the drill's evidence said "replication disabled" and "last sync
... (>2x RPO)" or "never replicated" for the same guest, and rpo_breach_seconds counted
the age of a job that is switched off.
"""
from datetime import datetime, timedelta

import pytest

import pegaprox.api.dr_drill as drill


def _plan(db):
    db.execute("INSERT INTO site_recovery_plans (id, group_id, name, source_cluster, target_cluster) "
               "VALUES ('p1', 'g1', 'Plan p1', 'cluster_1', 'cluster_2')")
    # guest 100 is linked to a job that is gone, guest 101 to one that is switched off
    for vmid, job in ((100, 'jgone'), (101, 'joff')):
        db.execute("INSERT INTO site_recovery_vms (id, plan_id, vmid, vm_name, boot_group, replication_job_id) "
                   "VALUES (?, 'p1', ?, ?, 0, ?)", (f'p1-{vmid}', vmid, f'vm{vmid}', job))


@pytest.mark.parametrize('last_run', [timedelta(hours=10), None])
def test_a_disabled_job_after_a_failed_guest_is_no_rpo_breach(db, last_run):
    _plan(db)
    db.execute("INSERT INTO cross_cluster_replications (id, source_cluster, target_cluster, vmid, enabled, "
               "schedule, last_run, last_status) VALUES ('joff', 'cluster_1', 'cluster_2', 101, 0, "
               "'0 */6 * * *', ?, 'ok')",
               ((datetime.now() - last_run).isoformat() if last_run else None,))
    db.execute("INSERT INTO dr_drills (id, plan_id, plan_name, started_at, status, started_by) "
               "VALUES ('d1', 'p1', 'Plan p1', ?, 'running', 'root')", (datetime.now().isoformat(),))

    drill._execute_drill('d1')

    row = db.query_one("SELECT status, detail FROM dr_drill_checks WHERE drill_id = 'd1' "
                       "AND name = 'freshness_per_vm'")
    lines = row['detail'].split('\n')
    assert [ln for ln in lines if ln.startswith('vmid 101:')] == ['vmid 101: replication disabled'], lines
    assert row['status'] == 'fail'     # guest 100 still fails the check
    assert db.query_one("SELECT rpo_breach_seconds FROM dr_drills WHERE id = 'd1'")[0] == 0
