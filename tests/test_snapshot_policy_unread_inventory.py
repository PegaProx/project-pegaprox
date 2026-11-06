"""A snapshot policy that could not read the guest list has not run.

get_vm_resources() answers a timeout with an empty list that says so, and `or []` threw that away. The run ended completed with "0
targets" and stamped the policy, so a daily one was blocked for 23 hours and a weekly one for 6 days with nothing done.
"""
import pytest

import pegaprox.api.snapshots as snaps
from pegaprox.core.manager import UnreadList


def _policy(db, seed, schedule='daily'):
    seed.user('adm', role='admin')
    db.conn.execute("INSERT INTO snapshot_policies (id, cluster_id, name, target_type, target_value, schedule, enabled, created_by, "
                    "created_at) VALUES ('p1','c1','p','tag','prod',?,1,'adm','2026-01-01T00:00:00')", (schedule,))
    db.conn.commit()


def _run(api, db, answer):
    mgr = api.make_fake_manager(cluster_id='c1')
    mgr.get_vm_resources.return_value = answer
    api.set_manager('c1', mgr)
    snaps._execute_policy('p1')
    run = db.conn.execute("SELECT status, summary FROM snapshot_runs WHERE policy_id='p1'").fetchone()
    pol = db.conn.execute("SELECT last_run_at, last_run_status FROM snapshot_policies WHERE id='p1'").fetchone()
    return run, pol


def test_an_unread_list_is_a_failed_run_and_the_policy_stays_due(api, seed, db):
    _policy(db, seed)
    run, pol = _run(api, db, UnreadList())
    assert run['status'] == 'failed' and run['summary'] == 'target resolution failed'
    assert pol['last_run_status'] == 'failed' and not pol['last_run_at']


def test_an_empty_list_that_was_read_still_means_nothing_matches(api, seed, db):
    _policy(db, seed)
    run, pol = _run(api, db, [])
    assert run['status'] == 'completed'
    assert pol['last_run_at']


def test_a_once_policy_stays_used_up_as_it_was_decided(api, seed, db):
    """#586 stamps it first so that an early exit cannot fire it each minute. The failed run at least says so now."""
    _policy(db, seed, schedule='once')
    run, pol = _run(api, db, UnreadList())
    assert run['status'] == 'failed' and pol['last_run_at'] and pol['last_run_status'] == 'failed'
