"""Portal audit events reach the task feed keyed on the cluster NAME.

audit_log.cluster stores manager.config.name and nothing makes that unique — the
clusters table has UNIQUE only on id. Two clusters named the same way therefore
published each other's portal activity (which user acted on which VMID) into the
other tenant's live task bar, which is the leak the Aug filter was added to close.
Fail closed on an ambiguous name until the rows carry the cluster id. MK
"""
from unittest.mock import MagicMock

import pegaprox.globals as ppglobals
from pegaprox.background.broadcast import _get_recent_audit_tasks
from pegaprox.utils.audit import log_audit


def _cluster(cluster_id, name):
    m = MagicMock()
    m.config.name = name
    ppglobals.cluster_managers[cluster_id] = m
    return m


def _portal_event(cluster_name, user='portal_alice', vmid=100):
    log_audit(user, 'portal.vm.start', f'Started VM {vmid}', cluster=cluster_name)


def test_events_reach_the_cluster_they_happened_on(db):
    ppglobals.cluster_managers.clear()
    try:
        _cluster('c_prod', 'Production')
        _cluster('c_dr', 'DR Site')
        _portal_event('Production')

        assert len(_get_recent_audit_tasks('c_prod', 'Production')) == 1
        assert _get_recent_audit_tasks('c_dr', 'DR Site') == []
    finally:
        ppglobals.cluster_managers.clear()


def test_duplicate_cluster_name_publishes_nothing(db):
    """Tenant A and tenant B both called their cluster 'Production'."""
    ppglobals.cluster_managers.clear()
    try:
        _cluster('c_tenant_a', 'Production')
        _cluster('c_tenant_b', 'Production')
        _portal_event('Production', user='alice_of_tenant_a', vmid=100)

        assert _get_recent_audit_tasks('c_tenant_a', 'Production') == []
        assert _get_recent_audit_tasks('c_tenant_b', 'Production') == []
    finally:
        ppglobals.cluster_managers.clear()


def test_unique_name_still_carries_the_details_the_task_bar_needs(db):
    ppglobals.cluster_managers.clear()
    try:
        _cluster('c_prod', 'Production')
        _portal_event('Production', user='portal_bob', vmid=204)

        task = _get_recent_audit_tasks('c_prod', 'Production')[0]

        assert task['type'] == 'portalstart'
        assert task['vmid'] == 204
        assert task['pegaprox_user'] == 'portal_bob'
        assert task['cluster_id'] == 'c_prod'
        assert task['_portal'] is True
    finally:
        ppglobals.cluster_managers.clear()
