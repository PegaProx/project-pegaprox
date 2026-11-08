"""Three from the fail-open tier, each checked at the code rather than by sweep.

The shape is the same every time and it is the one this codebase keeps producing: an
operation that FAILS answers with the same value as an operation that found nothing, and
the caller reads that value as an answer.

  exclusions   an unreachable cluster enumerates zero VMs, and "zero VMs" was read as
               "they all went away" - deleting the operator's do-not-balance list.
  test NICs    isolation returned a bare count; 0 meant both "this guest has no NICs" and
               "we could not read its config", and the caller started the clone either way.
  status page  a DB exception was handed back over HTTP verbatim.

MK
"""
import logging
import types

import pytest


# --- balancing exclusions ------------------------------------------------------------

def test_a_cluster_that_enumerates_nothing_keeps_its_exclusions(monkeypatch):
    """XcpngManager.get_vms returns [] when _api() is unavailable - no exception. Read
    literally that is 'every VM is gone', and the next line deletes their exclusions."""
    import pegaprox.api.nodes as N

    deleted = []

    class _Cur:
        def execute(self, sql, params=None):
            if sql.strip().upper().startswith('DELETE'):
                deleted.append(params)
            self._rows = [{'cluster_id': 'c1', 'vmid': 100},
                          {'cluster_id': 'c1', 'vmid': 101}]
        def fetchall(self):
            return getattr(self, '_rows', [])

    class _Conn:
        def cursor(self): return _Cur()
        def commit(self): pass

    monkeypatch.setattr(N, 'get_db', lambda: types.SimpleNamespace(conn=_Conn()))
    mgr = types.SimpleNamespace(is_connected=True, get_vm_resources=lambda: [])
    monkeypatch.setattr(N, 'cluster_managers', {'c1': mgr})

    N.cleanup_orphaned_excluded_vms()

    assert not deleted, \
        f"an empty enumeration wiped {len(deleted)} exclusion(s) - a connection blip " \
        "undoes the operator's do-not-balance list"


def test_a_real_enumeration_still_removes_a_gone_vm(monkeypatch):
    """The mirror. Skipping on empty must not turn into never cleaning up."""
    import pegaprox.api.nodes as N

    deleted = []

    class _Cur:
        def execute(self, sql, params=None):
            if sql.strip().upper().startswith('DELETE'):
                deleted.append(params)
            self._rows = [{'cluster_id': 'c1', 'vmid': 999}]
        def fetchall(self): return getattr(self, '_rows', [])

    class _Conn:
        def cursor(self): return _Cur()
        def commit(self): pass

    monkeypatch.setattr(N, 'get_db', lambda: types.SimpleNamespace(conn=_Conn()))
    mgr = types.SimpleNamespace(is_connected=True,
                                get_vm_resources=lambda: [{'vmid': 100}, {'vmid': 101}])
    monkeypatch.setattr(N, 'cluster_managers', {'c1': mgr})

    N.cleanup_orphaned_excluded_vms()

    assert deleted, 'a genuinely orphaned exclusion was left behind'


# --- test-failover NIC isolation ------------------------------------------------------

def _mgr(config_result, toggle_ok=True):
    return types.SimpleNamespace(
        get_vm_config=lambda *a, **k: config_result,
        toggle_network_link=lambda *a, **k: {'success': toggle_ok},
    )


def test_unreadable_config_is_not_reported_as_isolated():
    from pegaprox.background.site_recovery import _disconnect_test_nics

    r = _disconnect_test_nics(_mgr({'success': False, 'error': 'node down'}), 'n1', 900)
    assert r['ok'] is False, "a config we could not read came back as a successful isolation"
    assert 'config' in r['error']


def test_a_nic_that_refuses_is_not_reported_as_isolated():
    from pegaprox.background.site_recovery import _disconnect_test_nics

    cfg = {'success': True, 'config': {'raw': {'net0': 'virtio=x', 'net1': 'virtio=y'}}}
    r = _disconnect_test_nics(_mgr(cfg, toggle_ok=False), 'n1', 900)
    assert r['ok'] is False
    assert r['disconnected'] == 0 and r['total'] == 2


def test_a_guest_with_no_nics_is_a_success_not_a_failure():
    """The mirror that matters most: a diskless-network guest must not block a test."""
    from pegaprox.background.site_recovery import _disconnect_test_nics

    r = _disconnect_test_nics(_mgr({'success': True, 'config': {'raw': {}}}), 'n1', 900)
    assert r['ok'] is True and r['total'] == 0


def test_a_container_says_it_cannot_and_does_not_claim_success_silently():
    from pegaprox.background.site_recovery import _disconnect_test_nics

    r = _disconnect_test_nics(_mgr({'success': True}), 'n1', 900, 'lxc')
    assert r['ok'] is True and r['unsupported'] is True


def test_a_failure_is_distinguishable_from_a_guest_with_no_nics():
    """The shape-agnostic one, and the only real counter-proof in this group.

    The four tests above subscript the new dict, so against the old code they die with a
    TypeError rather than showing the bug - which proves nothing, and is the same mistake
    I made three days running. This one only compares two return values. The old function
    answered 0 to both of these, which IS the defect: "we could not read the config" and
    "this guest has no NICs" were the same answer, and the caller started the clone on
    either."""
    from pegaprox.background.site_recovery import _disconnect_test_nics

    unreadable = _disconnect_test_nics(_mgr({'success': False, 'error': 'node down'}), 'n1', 900)
    no_nics = _disconnect_test_nics(_mgr({'success': True, 'config': {'raw': {}}}), 'n1', 901)

    assert unreadable != no_nics, (
        f"both answered {unreadable!r} - a failed isolation is indistinguishable from a "
        "guest that simply has no NICs, so the caller cannot tell them apart either")


def test_the_caller_treats_failed_isolation_as_a_reason_not_to_start():
    import inspect
    from pegaprox.background import site_recovery as SR

    body = inspect.getsource(SR.execute_test_failover) \
        if hasattr(SR, 'execute_test_failover') else inspect.getsource(SR)
    stripped = '\n'.join(l for l in body.split('\n') if not l.strip().startswith('#'))
    assert "_iso.get('ok')" in stripped, 'the isolation result is still thrown away'
    assert 'not started' in stripped


# --- status page ----------------------------------------------------------------------

def test_the_incident_handlers_do_not_hand_back_the_exception():
    import inspect
    import plugins.status_page as SP

    src = inspect.getsource(SP)
    stripped = '\n'.join(l for l in src.split('\n') if not l.strip().startswith('#'))
    assert "{'error': str(e)}, 500" not in stripped, \
        'a database exception still goes back over HTTP verbatim'


# --- HA disable: the bookkeeping must not contradict the audit line -------------------

def test_a_node_whose_teardown_failed_stays_marked_as_having_the_agent():
    """`_ha_uninstall_self_fence_on_all_nodes` returns {node: ok}. The handler already
    writes "manual cleanup required" into the audit entry for the failures - and then
    cleared the whole node_agent_installed map anyway, so our own state said the opposite.
    The next enable reads the state, not the audit log. A self-fence agent we believe is
    gone, still running, fences on heartbeat state nobody maintains any more."""
    import inspect
    import pegaprox.api.clusters as C

    body = inspect.getsource(C.disable_ha) if hasattr(C, 'disable_ha') else inspect.getsource(C)
    stripped = '\n'.join(l for l in body.split('\n') if not l.strip().startswith('#'))

    assert "node_agent_installed'] = {}" not in stripped, \
        'the whole map is still cleared, failures included'
    assert '_still_there' in stripped
