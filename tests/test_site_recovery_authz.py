"""Site Recovery: the empty plan, the target cluster, and the VM added afterwards.

_authz_plan_vms walks the plan's VMs and asks user_can_access_vm about each. Three
things that walk did not cover:

  * an EMPTY plan walks out of the loop and answers "authorized". Every write route in
    the file gates on this helper, so an empty plan was editable by anyone - add VMs to
    it afterwards and the plan is yours.
  * every check asks about the SOURCE cluster. A failover starts these guests on the
    TARGET: it consumes that cluster's CPU, memory and storage. A caller confined on the
    target has no standing to place a workload there, however well they own the source.
  * the route authorizes a list and then spawns a greenlet that reads the list again
    from the database. Anything added in between was acted on unauthorized.

And in the heartbeat: "I cannot reach the source" was read as "the source is down".
Starting the replicas on the strength of that is how the same guest ends up running
twice, writing to two sets of disks.

Aikido ai_pentest 700487268 / 700487986 / 700487664 / 700489130. MK
"""
import inspect

import pytest

import pegaprox.api.site_recovery as sr
import pegaprox.background.site_recovery as srw


def _body(mod, fn):
    src = inspect.getsource(mod)
    i = src.index(f'def {fn}(')
    rest = src[i:]
    import re
    ends = [m.start() for m in re.finditer(r'\n@bp\.route|\ndef |\nclass ', rest[1:])]
    return rest[:min(ends) + 1] if ends else rest


def test_an_empty_plan_is_not_automatically_authorized():
    body = _body(sr, '_authz_plan_vms')
    assert 'if not _vms:' in body
    # and the deny has to be the confined caller's branch, not a blanket refusal
    i = body.index('if not _vms:')
    assert '_confined' in body[i:i + 300]


def test_an_unconfined_operator_may_still_hold_an_empty_plan():
    """An empty plan is a perfectly normal draft for a DR operator."""
    body = _body(sr, '_authz_plan_vms')
    i = body.index('if not _vms:')
    seg = body[i:i + 400]
    assert 'return True, None' in seg


def test_the_target_cluster_is_weighed_for_operations_that_start_guests():
    body = _body(sr, '_authz_plan_vms')
    assert 'target_cluster' in body
    assert 'starts_vms and _tgt' in body


def test_the_worker_accepts_an_approved_vm_set():
    assert 'authorized_vmids' in inspect.signature(srw.execute_failover).parameters


def test_the_worker_filters_to_the_approved_set():
    body = _body(srw, 'execute_failover')
    assert 'authorized_vmids is not None' in body
    assert '_approved' in body


def test_the_routes_hand_the_approved_set_over():
    src = inspect.getsource(sr)
    # the three failover spawns, not just one. Counting occurrences would also catch the
    # helper's own `return` line, so count the spawn calls themselves.
    spawns = [l for l in src.splitlines()
              if '_safe_spawn_failover(execute_failover' in l]
    assert len(spawns) == 3, spawns
    assert all('_approved_vmids(plan)' in l for l in spawns), spawns


def test_the_internal_caller_passes_nothing_and_is_not_filtered():
    """The heartbeat has no per-request authorization to carry; None must mean unfiltered."""
    src = inspect.getsource(srw)
    i = src.index("_safe_spawn_failover(execute_failover, plan_id, 'emergency')")
    assert '_approved_vmids' not in src[i:i + 120]


# --- the heartbeat tells isolation apart from failure ------------------------

def test_the_heartbeat_blocks_when_every_cluster_is_unreachable():
    body = inspect.getsource(srw)
    assert '_any_other_up' in body
    assert 'isolated' in body.lower()


def test_the_heartbeat_requires_a_reachable_target():
    body = inspect.getsource(srw)
    assert "the \ntarget cluster is not reachable" in body.replace('"', '').replace("'", '') or \
           'target cluster is not reachable' in body
