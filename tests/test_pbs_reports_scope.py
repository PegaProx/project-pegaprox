"""PBS report endpoints must scope their rows to the caller's guests.

check_pbs_access proves the caller reaches ONE of the PBS's linked clusters — it
says nothing about which guests' backups they may read. A datastore is shared
across every VM on every linked cluster, and pbs.view is a builtin ROLE_USER /
ROLE_VIEWER permission, so /reports/summary and /reports/inventory handed a
VM-ACL-scoped user the whole install's backup inventory: every VMID, name,
datastore, namespace, owner, size and backup time.

The sibling routes already gate per guest (_authz_pbs_backup / _scope_pbs_rows,
and /reports/protected-vms via scope_vm_rows); these two never did. MK
"""
import time
from unittest.mock import MagicMock

import pegaprox.globals as ppglobals


MINE, THEIRS = 100, 200
# the report windows are relative to now, so the fixture rows have to be recent
# or they fall outside per_day and the chart assertions test nothing
YESTERDAY = int(time.time()) - 86400


def _snap(vmid, ts, store='store1'):
    return {'backup-type': 'vm', 'backup-id': str(vmid), 'backup-time': ts,
            'size': 1024, 'owner': 'root@pam', 'files': ['index.json.blob'],
            'verification': {'state': 'ok'}, 'protected': False, 'comment': ''}


def _inject_pbs(pbs_id='pbs_a', linked=('cluster_1',)):
    m = MagicMock()
    m.linked_clusters = list(linked)
    m.connected = True
    m.last_status = None
    m.get_datastores.return_value = {'data': [{'name': 'store1'}]}
    m.get_namespaces.return_value = {'data': []}
    m.get_snapshots.return_value = {'data': [_snap(MINE, YESTERDAY),
                                             _snap(THEIRS, YESTERDAY + 100)]}
    # one backup task per guest, in the PBS worker_id form "<store>:<type>/<id>/<hex>"
    m.get_tasks.return_value = {'data': [
        {'upid': 'UPID:pbs:1', 'worker_type': 'backup', 'status': 'OK',
         'starttime': YESTERDAY, 'endtime': YESTERDAY + 60,
         'worker_id': f'store1:vm/{MINE}/68ab1f00'},
        {'upid': 'UPID:pbs:2', 'worker_type': 'backup', 'status': 'OK',
         'starttime': YESTERDAY + 100, 'endtime': YESTERDAY + 160,
         'worker_id': f'store1:vm/{THEIRS}/68ab1f64'},
    ]}
    ppglobals.pbs_managers[pbs_id] = m
    return m


def _scoped_user(api, seed):
    """A user whose tenant owns cluster_1 but who only holds a VM ACL on MINE."""
    seed.tenant('tenant_a', clusters=['cluster_1'])
    alice = seed.user('alice', role='user', tenant_id='tenant_a', permissions=['pbs.view'])
    seed.vm_acl('cluster_1', MINE, ['alice'], permissions=['vm.view'])
    api.set_manager('cluster_1', api.make_fake_manager('cluster_1', get_vm_resources=[]))
    return api.as_user(alice)


def test_inventory_hides_other_guests_snapshots(api, seed):
    ppglobals.pbs_managers.clear()
    try:
        _inject_pbs()
        client = _scoped_user(api, seed)

        r = client.get('/api/pbs/pbs_a/reports/inventory')

        assert r.status_code == 200, r.get_data(as_text=True)[:300]
        vmids = {e['vmid'] for e in r.get_json()['entries']}
        assert vmids == {str(MINE)}, vmids
        assert r.get_json()['count'] == 1
    finally:
        ppglobals.pbs_managers.clear()


def test_summary_rollup_hides_other_guests(api, seed):
    ppglobals.pbs_managers.clear()
    try:
        _inject_pbs()
        client = _scoped_user(api, seed)

        r = client.get('/api/pbs/pbs_a/reports/summary?days=30')

        assert r.status_code == 200, r.get_data(as_text=True)[:300]
        body = r.get_json()
        assert {v['vmid'] for v in body['per_vm']} == {str(MINE)}, body['per_vm']
        # the aggregates are derived from the same rows, so they must not count
        # backups the caller cannot see
        assert body['inventory_snapshot_count'] == 1, body
        assert body['totals']['jobs'] == 1, body['totals']
        assert sum(d['success'] for d in body['per_day']) == 1, body['per_day']
    finally:
        ppglobals.pbs_managers.clear()


def test_admin_still_sees_the_whole_install(api, seed):
    """The gate must not narrow the reports for an unconfined caller."""
    ppglobals.pbs_managers.clear()
    try:
        _inject_pbs()
        root = api.as_user(seed.user('root_admin', role='admin'))

        inv = root.get('/api/pbs/pbs_a/reports/inventory')
        summary = root.get('/api/pbs/pbs_a/reports/summary?days=30')

        assert inv.status_code == 200, inv.get_data(as_text=True)[:300]
        assert {e['vmid'] for e in inv.get_json()['entries']} == {str(MINE), str(THEIRS)}
        assert summary.status_code == 200, summary.get_data(as_text=True)[:300]
        assert summary.get_json()['totals']['jobs'] == 2
    finally:
        ppglobals.pbs_managers.clear()


def test_plain_tenant_operator_keeps_the_whole_pbs(api, seed):
    """No pool grant and no VM ACL, tenant owns the cluster → not confined."""
    ppglobals.pbs_managers.clear()
    try:
        _inject_pbs()
        seed.tenant('tenant_a', clusters=['cluster_1'])
        bob = seed.user('bob', role='user', tenant_id='tenant_a', permissions=['pbs.view'])
        api.set_manager('cluster_1', api.make_fake_manager('cluster_1', get_vm_resources=[]))

        r = api.as_user(bob).get('/api/pbs/pbs_a/reports/inventory')

        assert r.status_code == 200, r.get_data(as_text=True)[:300]
        assert {e['vmid'] for e in r.get_json()['entries']} == {str(MINE), str(THEIRS)}
    finally:
        ppglobals.pbs_managers.clear()


def test_summary_rollup_resolves_the_pbs_worker_id(api, seed):
    """PBS reports worker_id as '<datastore>:<type>/<id>/<hex-time>'. Splitting on
    the first '/' produced type='store1:vm' and vmid='100/68ab1f00', so neither the
    snapshot nor the VM-name lookup ever matched and every rollup row came back
    with size 0 and an empty name."""
    ppglobals.pbs_managers.clear()
    try:
        _inject_pbs()
        root = api.as_user(seed.user('root_admin', role='admin'))

        body = root.get('/api/pbs/pbs_a/reports/summary?days=30').get_json()

        rows = {v['vmid']: v for v in body['per_vm']}
        assert set(rows) == {str(MINE), str(THEIRS)}, body['per_vm']
        assert all(v['type'] == 'vm' for v in rows.values()), body['per_vm']
        assert rows[str(MINE)]['size'] == 1024, rows[str(MINE)]
        assert rows[str(MINE)]['verified'] is True, rows[str(MINE)]
        assert rows[str(MINE)]['datastore'] == 'store1', rows[str(MINE)]
    finally:
        ppglobals.pbs_managers.clear()
